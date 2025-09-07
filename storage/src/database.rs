use anyhow::{Context, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::{Block, BlockHash, OutPoint, Transaction, TxOut, Txid};
use bitcoin_hashes::Hash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info};

/// Database column families
const CF_BLOCKS: &str = "blocks";
const CF_BLOCK_INDEX: &str = "block_index";
const CF_UTXO: &str = "utxo";
const CF_TRANSACTION: &str = "transactions";
const CF_UNDO: &str = "undo";
const CF_CHAIN_STATE: &str = "chain_state";
const CF_HEADERS: &str = "headers";

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub path: String,
    pub cache_size: usize,
    pub max_open_files: i32,
    pub block_cache_size: usize,
    pub write_buffer_size: usize,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "./data/bitcoin".to_string(),
            cache_size: 1024 * 1024 * 1024, // 1GB
            max_open_files: 1024,
            block_cache_size: 512 * 1024 * 1024,  // 512MB
            write_buffer_size: 128 * 1024 * 1024, // 128MB
        }
    }
}

/// Main database wrapper using sled
#[allow(dead_code)]
pub struct Database {
    db: Arc<sled::Db>,
    config: DatabaseConfig,
    blocks_tree: Arc<sled::Tree>,
    index_tree: Arc<sled::Tree>,
    utxo_tree: Arc<sled::Tree>,
    tx_tree: Arc<sled::Tree>,
    undo_tree: Arc<sled::Tree>,
    chain_tree: Arc<sled::Tree>,
    headers_tree: Arc<sled::Tree>,
}

impl Database {
    /// Create or open a database
    pub fn new(config: DatabaseConfig) -> Result<Self> {
        info!("Opening database at {}", config.path);

        // Open sled database
        let db = sled::Config::default()
            .path(&config.path)
            .cache_capacity(config.cache_size as u64)
            .open()
            .context("Failed to open sled database")?;

        // Open trees (similar to column families)
        let blocks_tree = db.open_tree(CF_BLOCKS)?;
        let index_tree = db.open_tree(CF_BLOCK_INDEX)?;
        let utxo_tree = db.open_tree(CF_UTXO)?;
        let tx_tree = db.open_tree(CF_TRANSACTION)?;
        let undo_tree = db.open_tree(CF_UNDO)?;
        let chain_tree = db.open_tree(CF_CHAIN_STATE)?;
        let headers_tree = db.open_tree(CF_HEADERS)?;

        info!("Database opened successfully");

        Ok(Self {
            db: Arc::new(db),
            config,
            blocks_tree: Arc::new(blocks_tree),
            index_tree: Arc::new(index_tree),
            utxo_tree: Arc::new(utxo_tree),
            tx_tree: Arc::new(tx_tree),
            undo_tree: Arc::new(undo_tree),
            chain_tree: Arc::new(chain_tree),
            headers_tree: Arc::new(headers_tree),
        })
    }

    /// Get raw database handle
    pub fn get_db(&self) -> Arc<sled::Db> {
        Arc::clone(&self.db)
    }

    // Block operations

    /// Store a block
    pub fn put_block(&self, hash: &BlockHash, block: &Block) -> Result<()> {
        let key = hash.to_byte_array();
        let value = bitcoin::consensus::encode::serialize(block);

        self.blocks_tree.insert(key, value)?;
        debug!("Stored block {}", hash);

        Ok(())
    }

    /// Get a block
    pub fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        let key = hash.to_byte_array();

        match self.blocks_tree.get(key)? {
            Some(data) => {
                let block = bitcoin::consensus::encode::deserialize(&data)
                    .context("Failed to deserialize block")?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Delete a block
    pub fn delete_block(&self, hash: &BlockHash) -> Result<()> {
        let key = hash.to_byte_array();
        self.blocks_tree.remove(key)?;

        debug!("Deleted block {}", hash);
        Ok(())
    }

    // Block header operations

    /// Store a block header
    pub fn put_header(&self, hash: &BlockHash, header: &BlockHeader, height: u32) -> Result<()> {
        let key = hash.to_byte_array();

        #[derive(Serialize, Deserialize)]
        struct HeaderData {
            header: Vec<u8>,
            height: u32,
        }

        let header_data = HeaderData {
            header: bitcoin::consensus::encode::serialize(header),
            height,
        };

        let value = bincode::serialize(&header_data)?;
        self.headers_tree.insert(key, value)?;

        debug!("Stored header {} at height {}", hash, height);
        Ok(())
    }

    /// Get a block header
    pub fn get_header(&self, hash: &BlockHash) -> Result<Option<(BlockHeader, u32)>> {
        let key = hash.to_byte_array();

        match self.headers_tree.get(key)? {
            Some(data) => {
                #[derive(Serialize, Deserialize)]
                struct HeaderData {
                    header: Vec<u8>,
                    height: u32,
                }

                let header_data: HeaderData = bincode::deserialize(&data)?;
                let header = bitcoin::consensus::encode::deserialize(&header_data.header)?;

                Ok(Some((header, header_data.height)))
            }
            None => Ok(None),
        }
    }

    // UTXO operations

    /// Store a UTXO
    pub fn put_utxo(&self, outpoint: &OutPoint, txout: &TxOut) -> Result<()> {
        let key = bitcoin::consensus::encode::serialize(outpoint);
        let value = bitcoin::consensus::encode::serialize(txout);

        self.utxo_tree.insert(key, value)?;
        Ok(())
    }

    /// Get a UTXO
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        let key = bitcoin::consensus::encode::serialize(outpoint);

        match self.utxo_tree.get(key)? {
            Some(data) => {
                let txout = bitcoin::consensus::encode::deserialize(&data)?;
                Ok(Some(txout))
            }
            None => Ok(None),
        }
    }

    /// Delete a UTXO
    pub fn delete_utxo(&self, outpoint: &OutPoint) -> Result<()> {
        let key = bitcoin::consensus::encode::serialize(outpoint);
        self.utxo_tree.remove(key)?;
        Ok(())
    }

    /// Batch write operations
    pub fn write_batch(&self, operations: Vec<BatchOperation>) -> Result<()> {
        // sled doesn't have native batch operations, process sequentially
        for op in operations {
            match op {
                BatchOperation::PutBlock(hash, block) => {
                    self.put_block(&hash, &block)?;
                }
                BatchOperation::DeleteBlock(hash) => {
                    self.delete_block(&hash)?;
                }
                BatchOperation::PutUtxo(outpoint, txout) => {
                    self.put_utxo(&outpoint, &txout)?;
                }
                BatchOperation::DeleteUtxo(outpoint) => {
                    self.delete_utxo(&outpoint)?;
                }
                BatchOperation::PutTransaction(txid, tx) => {
                    self.put_transaction(&txid, &tx)?;
                }
            }
        }
        Ok(())
    }

    // Transaction operations

    /// Store a transaction
    pub fn put_transaction(&self, txid: &Txid, tx: &Transaction) -> Result<()> {
        let key = txid.to_byte_array();
        let value = bitcoin::consensus::encode::serialize(tx);

        self.tx_tree.insert(key, value)?;
        Ok(())
    }

    /// Get a transaction
    pub fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>> {
        let key = txid.to_byte_array();

        match self.tx_tree.get(key)? {
            Some(data) => {
                let tx = bitcoin::consensus::encode::deserialize(&data)?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    // Chain state operations

    /// Store chain state
    pub fn put_chain_state(&self, key: &str, value: &[u8]) -> Result<()> {
        self.chain_tree.insert(key, value)?;
        Ok(())
    }

    /// Get chain state
    pub fn get_chain_state(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.chain_tree.get(key)?.map(|v| v.to_vec()))
    }

    /// Get best block hash
    pub fn get_best_block_hash(&self) -> Result<Option<BlockHash>> {
        match self.chain_tree.get("best_block")? {
            Some(data) => {
                let hash = BlockHash::from_byte_array(
                    data.to_vec()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid hash length"))?,
                );
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Set best block hash
    pub fn set_best_block_hash(&self, hash: &BlockHash) -> Result<()> {
        let bytes = hash.to_byte_array();
        self.chain_tree.insert("best_block", &bytes[..])?;
        Ok(())
    }

    /// Flush database to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }

    /// Get database statistics
    pub fn get_stats(&self) -> DatabaseStats {
        DatabaseStats {
            blocks_count: self.blocks_tree.len(),
            headers_count: self.headers_tree.len(),
            utxo_count: self.utxo_tree.len(),
            tx_count: self.tx_tree.len(),
            db_size: self.db.size_on_disk().unwrap_or(0),
        }
    }

    /// Get database size on disk in bytes
    pub async fn get_size(&self) -> Result<u64> {
        Ok(self.db.size_on_disk()?)
    }
}

/// Batch operation for atomic writes
#[derive(Debug)]
pub enum BatchOperation {
    PutBlock(BlockHash, Block),
    DeleteBlock(BlockHash),
    PutUtxo(OutPoint, TxOut),
    DeleteUtxo(OutPoint),
    PutTransaction(Txid, Transaction),
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub blocks_count: usize,
    pub headers_count: usize,
    pub utxo_count: usize,
    pub tx_count: usize,
    pub db_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let config = DatabaseConfig {
            path: "/tmp/test_bitcoin_db".to_string(),
            ..Default::default()
        };

        let db = Database::new(config).unwrap();
        let stats = db.get_stats();
        assert_eq!(stats.blocks_count, 0);
    }
}
