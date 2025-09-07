use anyhow::{Result, Context, bail};
use bitcoin::{BlockHash, Txid, OutPoint, TxOut, Transaction, Block, BlockHeader};
use rocksdb::{DB, Options, WriteBatch, IteratorMode};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};
use serde::{Serialize, Deserialize};

/// Database key prefixes
const PREFIX_UTXO: u8 = 0x00;
const PREFIX_BLOCK_HEADER: u8 = 0x01;
const PREFIX_BLOCK_HEIGHT: u8 = 0x02;
const PREFIX_BLOCK_DATA: u8 = 0x03;
const PREFIX_TX_INDEX: u8 = 0x04;
const PREFIX_UNDO_DATA: u8 = 0x05;
const PREFIX_CHAIN_STATE: u8 = 0x06;
const PREFIX_PEER: u8 = 0x07;
const PREFIX_MEMPOOL: u8 = 0x08;

/// UTXO entry in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub outpoint: OutPoint,
    pub output: TxOut,
    pub height: u32,
    pub is_coinbase: bool,
}

/// Block index entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockIndexEntry {
    pub hash: BlockHash,
    pub height: u32,
    pub header: BlockHeader,
    pub total_work: [u8; 32],
    pub file_number: u32,
    pub file_position: u64,
}

/// Undo data for reverting blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoData {
    pub spent_outputs: Vec<UtxoEntry>,
    pub created_outputs: Vec<OutPoint>,
}

/// Chain state metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    pub tip_hash: BlockHash,
    pub tip_height: u32,
    pub total_work: [u8; 32],
    pub utxo_count: u64,
}

/// Bitcoin Core database
pub struct CoreDatabase {
    db: Arc<DB>,
    config: DatabaseConfig,
}

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub cache_size: usize,
    pub max_open_files: i32,
    pub compression: bool,
    pub prune_height: Option<u32>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            cache_size: 512 * 1024 * 1024, // 512MB cache
            max_open_files: 1000,
            compression: true,
            prune_height: None,
        }
    }
}

impl CoreDatabase {
    /// Open or create database
    pub fn open(path: &Path, config: DatabaseConfig) -> Result<Self> {
        info!("Opening database at {:?}", path);
        
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_max_open_files(config.max_open_files);
        opts.set_db_write_buffer_size(config.cache_size);
        
        // Disable compression to avoid zstd build issues
        // if config.compression {
        //     opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        // }
        
        let db = DB::open(&opts, path)
            .context("Failed to open database")?;
        
        Ok(Self {
            db: Arc::new(db),
            config,
        })
    }
    
    /// Get UTXO by outpoint
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>> {
        let key = self.utxo_key(outpoint);
        
        match self.db.get(&key)? {
            Some(data) => {
                let entry = bincode::deserialize(&data)
                    .context("Failed to deserialize UTXO entry")?;
                Ok(Some(entry))
            }
            None => Ok(None)
        }
    }
    
    /// Store UTXO
    pub fn put_utxo(&self, entry: &UtxoEntry) -> Result<()> {
        let key = self.utxo_key(&entry.outpoint);
        let value = bincode::serialize(entry)
            .context("Failed to serialize UTXO entry")?;
        
        self.db.put(&key, &value)
            .context("Failed to store UTXO")?;
        
        Ok(())
    }
    
    /// Remove UTXO
    pub fn delete_utxo(&self, outpoint: &OutPoint) -> Result<()> {
        let key = self.utxo_key(outpoint);
        self.db.delete(&key)
            .context("Failed to delete UTXO")?;
        Ok(())
    }
    
    /// Batch update UTXOs (atomic operation)
    pub fn update_utxos(&self, to_add: Vec<UtxoEntry>, to_remove: Vec<OutPoint>) -> Result<()> {
        let mut batch = WriteBatch::default();
        
        // Add new UTXOs
        for entry in to_add {
            let key = self.utxo_key(&entry.outpoint);
            let value = bincode::serialize(&entry)
                .context("Failed to serialize UTXO")?;
            batch.put(&key, &value);
        }
        
        // Remove spent UTXOs
        for outpoint in to_remove {
            let key = self.utxo_key(&outpoint);
            batch.delete(&key);
        }
        
        self.db.write(batch)
            .context("Failed to write UTXO batch")?;
        
        Ok(())
    }
    
    /// Get block header by hash
    pub fn get_block_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>> {
        let key = self.block_header_key(hash);
        
        match self.db.get(&key)? {
            Some(data) => {
                let header = bincode::deserialize(&data)
                    .context("Failed to deserialize block header")?;
                Ok(Some(header))
            }
            None => Ok(None)
        }
    }
    
    /// Store block header
    pub fn put_block_header(&self, hash: &BlockHash, header: &BlockHeader) -> Result<()> {
        let key = self.block_header_key(hash);
        let value = bincode::serialize(header)
            .context("Failed to serialize block header")?;
        
        self.db.put(&key, &value)
            .context("Failed to store block header")?;
        
        Ok(())
    }
    
    /// Get block hash at height
    pub fn get_block_hash_at_height(&self, height: u32) -> Result<Option<BlockHash>> {
        let key = self.block_height_key(height);
        
        match self.db.get(&key)? {
            Some(data) => {
                let hash = BlockHash::from_slice(&data)
                    .context("Invalid block hash in database")?;
                Ok(Some(hash))
            }
            None => Ok(None)
        }
    }
    
    /// Store block height mapping
    pub fn put_block_height(&self, height: u32, hash: &BlockHash) -> Result<()> {
        let key = self.block_height_key(height);
        let value = hash.as_ref();
        
        self.db.put(&key, value)
            .context("Failed to store block height")?;
        
        Ok(())
    }
    
    /// Store complete block
    pub fn put_block(&self, hash: &BlockHash, block: &Block, height: u32) -> Result<()> {
        let mut batch = WriteBatch::default();
        
        // Store header
        let header_key = self.block_header_key(hash);
        let header_value = bincode::serialize(&block.header)?;
        batch.put(&header_key, &header_value);
        
        // Store height mapping
        let height_key = self.block_height_key(height);
        batch.put(&height_key, hash.as_ref());
        
        // Store block data
        let data_key = self.block_data_key(hash);
        let data_value = bitcoin::consensus::encode::serialize(block);
        batch.put(&data_key, &data_value);
        
        self.db.write(batch)?;
        
        Ok(())
    }
    
    /// Get block data
    pub fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        let key = self.block_data_key(hash);
        
        match self.db.get(&key)? {
            Some(data) => {
                let block = bitcoin::consensus::encode::deserialize(&data)
                    .context("Failed to deserialize block")?;
                Ok(Some(block))
            }
            None => Ok(None)
        }
    }
    
    /// Store undo data for a block
    pub fn put_undo_data(&self, hash: &BlockHash, undo_data: &UndoData) -> Result<()> {
        let key = self.undo_data_key(hash);
        let value = bincode::serialize(undo_data)?;
        
        self.db.put(&key, &value)?;
        
        Ok(())
    }
    
    /// Get undo data for a block
    pub fn get_undo_data(&self, hash: &BlockHash) -> Result<Option<UndoData>> {
        let key = self.undo_data_key(hash);
        
        match self.db.get(&key)? {
            Some(data) => {
                let undo = bincode::deserialize(&data)?;
                Ok(Some(undo))
            }
            None => Ok(None)
        }
    }
    
    /// Save chain state
    pub fn save_chain_state(&self, state: &ChainState) -> Result<()> {
        let key = [PREFIX_CHAIN_STATE];
        let value = bincode::serialize(state)?;
        
        self.db.put(&key, &value)?;
        
        info!("Saved chain state: tip={} height={}", state.tip_hash, state.tip_height);
        Ok(())
    }
    
    /// Load chain state
    pub fn load_chain_state(&self) -> Result<Option<ChainState>> {
        let key = [PREFIX_CHAIN_STATE];
        
        match self.db.get(&key)? {
            Some(data) => {
                let state = bincode::deserialize(&data)?;
                Ok(Some(state))
            }
            None => Ok(None)
        }
    }
    
    /// Iterate all UTXOs
    pub fn iter_utxos(&self) -> impl Iterator<Item = Result<UtxoEntry>> + '_ {
        let prefix = vec![PREFIX_UTXO];
        
        self.db.iterator(IteratorMode::From(&prefix, rocksdb::Direction::Forward))
            .take_while(move |(key, _)| key.starts_with(&prefix))
            .map(|(_, value)| {
                bincode::deserialize(&value)
                    .context("Failed to deserialize UTXO")
            })
    }
    
    /// Count total UTXOs
    pub fn count_utxos(&self) -> Result<u64> {
        let mut count = 0u64;
        let prefix = vec![PREFIX_UTXO];
        
        for item in self.db.iterator(IteratorMode::From(&prefix, rocksdb::Direction::Forward)) {
            let (key, _) = item;
            if !key.starts_with(&prefix) {
                break;
            }
            count += 1;
        }
        
        Ok(count)
    }
    
    /// Prune old blocks if configured
    pub fn prune_blocks(&self, keep_from_height: u32) -> Result<u64> {
        if let Some(prune_height) = self.config.prune_height {
            if keep_from_height <= prune_height {
                return Ok(0);
            }
            
            let mut pruned = 0u64;
            let mut batch = WriteBatch::default();
            
            for height in 0..keep_from_height.saturating_sub(prune_height) {
                if let Some(hash) = self.get_block_hash_at_height(height)? {
                    // Delete block data but keep headers
                    let data_key = self.block_data_key(&hash);
                    batch.delete(&data_key);
                    pruned += 1;
                }
            }
            
            self.db.write(batch)?;
            
            info!("Pruned {} blocks below height {}", pruned, keep_from_height - prune_height);
            Ok(pruned)
        } else {
            Ok(0)
        }
    }
    
    /// Compact database
    pub fn compact(&self) -> Result<()> {
        info!("Compacting database...");
        self.db.compact_range(None::<&[u8]>, None::<&[u8]>);
        info!("Database compaction complete");
        Ok(())
    }
    
    /// Get database statistics
    pub fn get_stats(&self) -> Result<DatabaseStats> {
        let utxo_count = self.count_utxos()?;
        let chain_state = self.load_chain_state()?;
        
        Ok(DatabaseStats {
            utxo_count,
            tip_height: chain_state.as_ref().map(|s| s.tip_height).unwrap_or(0),
            db_size: self.estimate_size()?,
        })
    }
    
    /// Estimate database size
    fn estimate_size(&self) -> Result<u64> {
        // This is a rough estimate - actual implementation would check file sizes
        Ok(0)
    }
    
    // Key generation helpers
    
    fn utxo_key(&self, outpoint: &OutPoint) -> Vec<u8> {
        let mut key = vec![PREFIX_UTXO];
        key.extend_from_slice(&outpoint.txid.as_ref());
        key.extend_from_slice(&outpoint.vout.to_le_bytes());
        key
    }
    
    fn block_header_key(&self, hash: &BlockHash) -> Vec<u8> {
        let mut key = vec![PREFIX_BLOCK_HEADER];
        key.extend_from_slice(hash.as_ref());
        key
    }
    
    fn block_height_key(&self, height: u32) -> Vec<u8> {
        let mut key = vec![PREFIX_BLOCK_HEIGHT];
        key.extend_from_slice(&height.to_be_bytes());
        key
    }
    
    fn block_data_key(&self, hash: &BlockHash) -> Vec<u8> {
        let mut key = vec![PREFIX_BLOCK_DATA];
        key.extend_from_slice(hash.as_ref());
        key
    }
    
    fn undo_data_key(&self, hash: &BlockHash) -> Vec<u8> {
        let mut key = vec![PREFIX_UNDO_DATA];
        key.extend_from_slice(hash.as_ref());
        key
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub utxo_count: u64,
    pub tip_height: u32,
    pub db_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use tempfile::TempDir;
    
    #[test]
    fn test_database_operations() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let db = CoreDatabase::open(temp_dir.path(), DatabaseConfig::default())?;
        
        // Test UTXO operations
        let outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };
        
        let utxo = UtxoEntry {
            outpoint,
            output: TxOut {
                value: bitcoin::Amount::from_sat(50000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            },
            height: 100,
            is_coinbase: true,
        };
        
        // Store and retrieve UTXO
        db.put_utxo(&utxo)?;
        let retrieved = db.get_utxo(&outpoint)?;
        assert!(retrieved.is_some());
        
        // Delete UTXO
        db.delete_utxo(&outpoint)?;
        let deleted = db.get_utxo(&outpoint)?;
        assert!(deleted.is_none());
        
        Ok(())
    }
    
    #[test]
    fn test_chain_state() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let db = CoreDatabase::open(temp_dir.path(), DatabaseConfig::default())?;
        
        let state = ChainState {
            tip_hash: BlockHash::from_byte_array([0u8; 32]),
            tip_height: 1000,
            total_work: [0; 32],
            utxo_count: 50000,
        };
        
        db.save_chain_state(&state)?;
        let loaded = db.load_chain_state()?;
        
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.tip_height, 1000);
        assert_eq!(loaded.utxo_count, 50000);
        
        Ok(())
    }
}