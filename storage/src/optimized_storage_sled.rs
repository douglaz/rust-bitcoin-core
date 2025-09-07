use anyhow::{bail, Context, Result};
use bincode;
use bitcoin::{Block, BlockHash, OutPoint, Transaction, TxOut, Txid};
use serde::{Deserialize, Serialize};
use sled::{Batch, Db, Tree};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info};

/// Tree names for organized storage
const TREE_BLOCKS: &str = "blocks";
const TREE_BLOCK_INDEX: &str = "block_index";
const TREE_TRANSACTIONS: &str = "transactions";
const TREE_UTXO_SET: &str = "utxo_set";
const TREE_CHAIN_STATE: &str = "chain_state";
const TREE_METADATA: &str = "metadata";
const TREE_UNDO_DATA: &str = "undo_data";

/// Optimized storage layer with Sled (pure Rust, musl-compatible)
pub struct OptimizedStorage {
    /// Sled database instance
    db: Arc<Db>,

    /// Trees for different data types
    blocks: Arc<Tree>,
    block_index: Arc<Tree>,
    transactions: Arc<Tree>,
    utxo_set: Arc<Tree>,
    chain_state: Arc<Tree>,
    metadata: Arc<Tree>,
    undo_data: Arc<Tree>,

    /// Write buffer for batching
    #[allow(dead_code)]
    write_buffer: Arc<Mutex<WriteBatch>>,

    /// Cache for frequently accessed data
    block_cache: Arc<RwLock<lru::LruCache<BlockHash, Block>>>,
    utxo_cache: Arc<RwLock<lru::LruCache<OutPoint, TxOut>>>,

    /// Statistics
    stats: Arc<RwLock<StorageStats>>,
}

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub cache_size: usize,
    pub flush_interval_ms: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            cache_size: 256 * 1024 * 1024, // 256MB
            flush_interval_ms: 5000,       // 5 seconds
        }
    }
}

/// Storage statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub blocks_written: u64,
    pub blocks_read: u64,
    pub transactions_written: u64,
    pub transactions_read: u64,
    pub utxos_written: u64,
    pub utxos_read: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bytes_written: u64,
    pub bytes_read: u64,
}

/// Write batch for atomic operations
pub struct WriteBatch {
    batches: HashMap<String, Batch>,
}

impl WriteBatch {
    fn new() -> Self {
        Self {
            batches: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    fn insert(&mut self, tree_name: &str, key: Vec<u8>, value: Vec<u8>) {
        self.batches
            .entry(tree_name.to_string())
            .or_default()
            .insert(key, value);
    }

    #[allow(dead_code)]
    fn remove(&mut self, tree_name: &str, key: Vec<u8>) {
        self.batches
            .entry(tree_name.to_string())
            .or_default()
            .remove(key);
    }
}

impl OptimizedStorage {
    /// Create new optimized storage
    pub async fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        info!("Opening optimized storage at {:?}", path);

        // Configure Sled
        let config = sled::Config::new()
            .path(path)
            .cache_capacity(256 * 1024 * 1024) // 256MB cache
            .flush_every_ms(Some(5000)) // Flush every 5 seconds
            .mode(sled::Mode::HighThroughput);

        let db = config.open().context("Failed to open Sled database")?;

        // Open trees
        let blocks = db.open_tree(TREE_BLOCKS)?;
        let block_index = db.open_tree(TREE_BLOCK_INDEX)?;
        let transactions = db.open_tree(TREE_TRANSACTIONS)?;
        let utxo_set = db.open_tree(TREE_UTXO_SET)?;
        let chain_state = db.open_tree(TREE_CHAIN_STATE)?;
        let metadata = db.open_tree(TREE_METADATA)?;
        let undo_data = db.open_tree(TREE_UNDO_DATA)?;

        // Initialize caches
        let block_cache = lru::LruCache::new(std::num::NonZeroUsize::new(100).unwrap());
        let utxo_cache = lru::LruCache::new(std::num::NonZeroUsize::new(10000).unwrap());

        Ok(Self {
            db: Arc::new(db),
            blocks: Arc::new(blocks),
            block_index: Arc::new(block_index),
            transactions: Arc::new(transactions),
            utxo_set: Arc::new(utxo_set),
            chain_state: Arc::new(chain_state),
            metadata: Arc::new(metadata),
            undo_data: Arc::new(undo_data),
            write_buffer: Arc::new(Mutex::new(WriteBatch::new())),
            block_cache: Arc::new(RwLock::new(block_cache)),
            utxo_cache: Arc::new(RwLock::new(utxo_cache)),
            stats: Arc::new(RwLock::new(StorageStats::default())),
        })
    }

    /// Store a block
    pub async fn store_block(&self, block: &Block, height: u32) -> Result<()> {
        let hash = block.block_hash();
        debug!("Storing block {} at height {}", hash, height);

        // Serialize block
        let block_bytes = bincode::serialize(block)?;

        // Create batch for atomic write
        let mut batch = Batch::default();

        // Store block data
        batch.insert(hash.to_string().into_bytes(), block_bytes.clone());

        // Store block index entry
        let index_key = format!("height:{:010}", height);
        batch.insert(index_key.as_bytes().to_vec(), hash.to_string().into_bytes());

        // Apply batch
        self.blocks.apply_batch(batch)?;

        // Store transactions
        for tx in &block.txdata {
            self.store_transaction(tx).await?;
        }

        // Update cache
        self.block_cache.write().await.put(hash, block.clone());

        // Update stats
        let mut stats = self.stats.write().await;
        stats.blocks_written += 1;
        stats.bytes_written += block_bytes.len() as u64;

        Ok(())
    }

    /// Get a block by hash
    pub async fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        // Check cache first
        if let Some(block) = self.block_cache.write().await.get(hash) {
            self.stats.write().await.cache_hits += 1;
            return Ok(Some(block.clone()));
        }

        self.stats.write().await.cache_misses += 1;

        // Load from database
        if let Some(bytes) = self.blocks.get(hash.to_string())? {
            let block: Block = bincode::deserialize(&bytes)?;

            // Update cache
            self.block_cache.write().await.put(*hash, block.clone());

            // Update stats
            let mut stats = self.stats.write().await;
            stats.blocks_read += 1;
            stats.bytes_read += bytes.len() as u64;

            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    /// Store a transaction
    pub async fn store_transaction(&self, tx: &Transaction) -> Result<()> {
        let txid = tx.compute_txid();
        let tx_bytes = bincode::serialize(tx)?;

        self.transactions
            .insert(txid.to_string().into_bytes(), tx_bytes.clone())?;

        let mut stats = self.stats.write().await;
        stats.transactions_written += 1;
        stats.bytes_written += tx_bytes.len() as u64;

        Ok(())
    }

    /// Get a transaction by ID
    pub async fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>> {
        if let Some(bytes) = self.transactions.get(txid.to_string())? {
            let tx: Transaction = bincode::deserialize(&bytes)?;

            let mut stats = self.stats.write().await;
            stats.transactions_read += 1;
            stats.bytes_read += bytes.len() as u64;

            Ok(Some(tx))
        } else {
            Ok(None)
        }
    }

    /// Store a UTXO
    pub async fn store_utxo(&self, outpoint: &OutPoint, output: &TxOut) -> Result<()> {
        let key = bincode::serialize(outpoint)?;
        let value = bincode::serialize(output)?;

        self.utxo_set.insert(key, value.clone())?;

        // Update cache
        self.utxo_cache.write().await.put(*outpoint, output.clone());

        let mut stats = self.stats.write().await;
        stats.utxos_written += 1;
        stats.bytes_written += value.len() as u64;

        Ok(())
    }

    /// Get a UTXO
    pub async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        // Check cache first
        if let Some(output) = self.utxo_cache.write().await.get(outpoint) {
            self.stats.write().await.cache_hits += 1;
            return Ok(Some(output.clone()));
        }

        self.stats.write().await.cache_misses += 1;

        // Load from database
        let key = bincode::serialize(outpoint)?;
        if let Some(bytes) = self.utxo_set.get(key)? {
            let output: TxOut = bincode::deserialize(&bytes)?;

            // Update cache
            self.utxo_cache.write().await.put(*outpoint, output.clone());

            let mut stats = self.stats.write().await;
            stats.utxos_read += 1;
            stats.bytes_read += bytes.len() as u64;

            Ok(Some(output))
        } else {
            Ok(None)
        }
    }

    /// Remove a UTXO
    pub async fn remove_utxo(&self, outpoint: &OutPoint) -> Result<()> {
        let key = bincode::serialize(outpoint)?;
        self.utxo_set.remove(key)?;

        // Remove from cache
        self.utxo_cache.write().await.pop(outpoint);

        Ok(())
    }

    /// Store chain state
    pub async fn store_chain_state(&self, key: &str, value: &[u8]) -> Result<()> {
        self.chain_state.insert(key.as_bytes(), value)?;
        Ok(())
    }

    /// Get chain state
    pub async fn get_chain_state(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.chain_state.get(key.as_bytes())?.map(|v| v.to_vec()))
    }

    /// Begin a write batch
    pub async fn begin_batch(&self) -> WriteBatch {
        WriteBatch::new()
    }

    /// Commit a write batch
    pub async fn commit_batch(&self, batch: WriteBatch) -> Result<()> {
        for (tree_name, tree_batch) in batch.batches {
            let tree = match tree_name.as_str() {
                TREE_BLOCKS => &self.blocks,
                TREE_BLOCK_INDEX => &self.block_index,
                TREE_TRANSACTIONS => &self.transactions,
                TREE_UTXO_SET => &self.utxo_set,
                TREE_CHAIN_STATE => &self.chain_state,
                TREE_METADATA => &self.metadata,
                TREE_UNDO_DATA => &self.undo_data,
                _ => bail!("Unknown tree: {}", tree_name),
            };

            tree.apply_batch(tree_batch)?;
        }

        Ok(())
    }

    /// Flush all pending writes
    pub async fn flush(&self) -> Result<()> {
        self.db.flush_async().await?;
        Ok(())
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> StorageStats {
        self.stats.read().await.clone()
    }

    /// Compact the database
    pub async fn compact(&self) -> Result<()> {
        info!("Starting database compaction");

        // Sled doesn't need manual compaction like RocksDB
        // But we can trigger a flush
        self.db.flush_async().await?;

        info!("Database compaction complete");
        Ok(())
    }

    /// Get database size
    pub async fn get_size(&self) -> Result<u64> {
        Ok(self.db.size_on_disk()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin_hashes::Hash;

    #[tokio::test]
    async fn test_block_storage() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let storage = OptimizedStorage::new(temp_dir.path()).await?;

        // Create a test block
        let block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata: vec![],
        };

        let hash = block.block_hash();

        // Store and retrieve
        storage.store_block(&block, 0).await?;
        let retrieved = storage.get_block(&hash).await?;

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().block_hash(), hash);

        Ok(())
    }
}
