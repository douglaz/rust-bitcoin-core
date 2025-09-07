use anyhow::{Context, Result};
use bitcoin::{Block, BlockHash, Txid};
use serde::{Deserialize, Serialize};
use sled::{Batch, Db, Tree};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Transaction index for fast lookups
pub struct TransactionIndex {
    /// Database handle
    db: Arc<Db>,

    /// Trees for different data
    tx_locations: Arc<Tree>,
    block_txs: Arc<Tree>,
    metadata: Arc<Tree>,

    /// Index configuration
    config: TxIndexConfig,

    /// Index statistics
    stats: Arc<RwLock<TxIndexStats>>,

    /// Cache for recent lookups
    cache: Arc<RwLock<lru::LruCache<Txid, TxLocation>>>,
}

/// Transaction index configuration
#[derive(Debug, Clone)]
pub struct TxIndexConfig {
    /// Enable transaction indexing
    pub enabled: bool,

    /// Index all transactions (not just wallet-related)
    pub index_all: bool,

    /// Cache size for recent lookups
    pub cache_size: usize,

    /// Batch size for writes
    pub batch_size: usize,

    /// Compact database periodically
    pub auto_compact: bool,
}

impl Default for TxIndexConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            index_all: true,
            cache_size: 10000,
            batch_size: 1000,
            auto_compact: true,
        }
    }
}

/// Transaction location in blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxLocation {
    /// Block hash containing the transaction
    pub block_hash: BlockHash,

    /// Block height
    pub block_height: u32,

    /// Transaction index within block
    pub tx_index: u32,

    /// Block timestamp
    pub block_time: u32,

    /// Transaction data (optional, for full index)
    pub tx_data: Option<Vec<u8>>,
}

/// Transaction index statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TxIndexStats {
    pub total_indexed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub db_reads: u64,
    pub db_writes: u64,
    pub last_indexed_height: u32,
    pub index_size_bytes: u64,
}

impl TransactionIndex {
    /// Create new transaction index
    pub fn new(path: impl AsRef<Path>, config: TxIndexConfig) -> Result<Self> {
        let path = path.as_ref();

        // Setup Sled database
        let db_config = sled::Config::new()
            .path(path)
            .cache_capacity(128 * 1024 * 1024) // 128MB cache
            .flush_every_ms(Some(5000));

        let db = db_config
            .open()
            .context("Failed to open transaction index database")?;

        // Open trees
        let tx_locations = db.open_tree("tx_locations")?;
        let block_txs = db.open_tree("block_txs")?;
        let metadata = db.open_tree("metadata")?;

        // Create cache
        let cache = lru::LruCache::new(std::num::NonZeroUsize::new(config.cache_size).unwrap());

        // Load stats from metadata
        let stats = if let Some(bytes) = metadata.get(b"stats")? {
            bincode::deserialize(&bytes)?
        } else {
            TxIndexStats::default()
        };

        Ok(Self {
            db: Arc::new(db),
            tx_locations: Arc::new(tx_locations),
            block_txs: Arc::new(block_txs),
            metadata: Arc::new(metadata),
            config,
            stats: Arc::new(RwLock::new(stats)),
            cache: Arc::new(RwLock::new(cache)),
        })
    }

    /// Index a block's transactions
    pub async fn index_block(&self, block: &Block, height: u32, block_time: u32) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let block_hash = block.block_hash();
        debug!(
            "Indexing {} transactions from block {}",
            block.txdata.len(),
            block_hash
        );

        let mut batch = Batch::default();
        let mut block_tx_list = Vec::new();

        for (tx_index, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid();
            block_tx_list.push(txid);

            // Create location entry
            let location = TxLocation {
                block_hash,
                block_height: height,
                tx_index: tx_index as u32,
                block_time,
                tx_data: if self.config.index_all {
                    Some(bincode::serialize(tx)?)
                } else {
                    None
                },
            };

            // Add to batch
            let location_bytes = bincode::serialize(&location)?;
            batch.insert(txid.to_string().into_bytes(), location_bytes);

            // Update cache
            self.cache.write().await.put(txid, location);
        }

        // Apply batch
        self.tx_locations.apply_batch(batch)?;

        // Store block's transaction list
        let list_bytes = bincode::serialize(&block_tx_list)?;
        self.block_txs
            .insert(block_hash.to_string().into_bytes(), list_bytes)?;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_indexed += block.txdata.len() as u64;
        stats.last_indexed_height = height;
        stats.db_writes += block.txdata.len() as u64;

        // Save stats periodically
        if stats.db_writes % 1000 == 0 {
            let stats_bytes = bincode::serialize(&*stats)?;
            self.metadata.insert(b"stats", stats_bytes)?;
        }

        Ok(())
    }

    /// Get transaction location
    pub async fn get_tx_location(&self, txid: &Txid) -> Result<Option<TxLocation>> {
        // Check cache first
        if let Some(location) = self.cache.write().await.get(txid) {
            let mut stats = self.stats.write().await;
            stats.cache_hits += 1;
            return Ok(Some(location.clone()));
        }

        // Check database
        if let Some(bytes) = self.tx_locations.get(txid.to_string())? {
            let location: TxLocation = bincode::deserialize(&bytes)?;

            // Update cache
            self.cache.write().await.put(*txid, location.clone());

            // Update stats
            let mut stats = self.stats.write().await;
            stats.cache_misses += 1;
            stats.db_reads += 1;

            Ok(Some(location))
        } else {
            Ok(None)
        }
    }

    /// Get transactions in a block
    pub async fn get_block_transactions(&self, block_hash: &BlockHash) -> Result<Vec<Txid>> {
        if let Some(bytes) = self.block_txs.get(block_hash.to_string())? {
            let txids: Vec<Txid> = bincode::deserialize(&bytes)?;

            let mut stats = self.stats.write().await;
            stats.db_reads += 1;

            Ok(txids)
        } else {
            Ok(Vec::new())
        }
    }

    /// Remove block from index (for reorgs)
    pub async fn remove_block(&self, block_hash: &BlockHash) -> Result<()> {
        // Get block's transactions
        let txids = self.get_block_transactions(block_hash).await?;

        // Remove each transaction
        let mut batch = Batch::default();
        for txid in &txids {
            batch.remove(txid.to_string().into_bytes());

            // Remove from cache
            self.cache.write().await.pop(txid);
        }

        // Apply batch
        self.tx_locations.apply_batch(batch)?;

        // Remove block's transaction list
        self.block_txs.remove(block_hash.to_string())?;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_indexed = stats.total_indexed.saturating_sub(txids.len() as u64);

        Ok(())
    }

    /// Get index statistics
    pub async fn get_stats(&self) -> TxIndexStats {
        let stats = self.stats.read().await.clone();
        stats
    }

    /// Compact the index
    pub async fn compact(&self) -> Result<()> {
        info!("Compacting transaction index");

        // Sled handles compaction automatically, but we can trigger a flush
        self.db.flush_async().await?;

        // Update size estimate
        let mut stats = self.stats.write().await;
        stats.index_size_bytes = self.db.size_on_disk()?;

        Ok(())
    }

    /// Check if index is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Transaction index builder for batch operations
pub struct TxIndexBuilder {
    locations: HashMap<Txid, TxLocation>,
    block_txs: HashMap<BlockHash, Vec<Txid>>,
}

impl Default for TxIndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TxIndexBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            locations: HashMap::new(),
            block_txs: HashMap::new(),
        }
    }

    /// Add block to builder
    pub fn add_block(&mut self, block: &Block, height: u32, block_time: u32) {
        let block_hash = block.block_hash();
        let mut tx_list = Vec::new();

        for (tx_index, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid();
            tx_list.push(txid);

            let location = TxLocation {
                block_hash,
                block_height: height,
                tx_index: tx_index as u32,
                block_time,
                tx_data: None,
            };

            self.locations.insert(txid, location);
        }

        self.block_txs.insert(block_hash, tx_list);
    }

    /// Build into index
    pub async fn build(self, index: &TransactionIndex) -> Result<()> {
        // Create batch for locations
        let mut batch = Batch::default();

        for (txid, location) in self.locations {
            let location_bytes = bincode::serialize(&location)?;
            batch.insert(txid.to_string().into_bytes(), location_bytes);
        }

        // Apply locations batch
        index.tx_locations.apply_batch(batch)?;

        // Store block transaction lists
        for (block_hash, tx_list) in self.block_txs {
            let list_bytes = bincode::serialize(&tx_list)?;
            index
                .block_txs
                .insert(block_hash.to_string().into_bytes(), list_bytes)?;
        }

        Ok(())
    }
}

/// Block provider trait for index builder
#[async_trait::async_trait]
pub trait BlockProvider: Send + Sync {
    /// Get block by hash
    async fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>>;

    /// Get block height
    async fn get_block_height(&self, hash: &BlockHash) -> Result<Option<u32>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_hashes::Hash;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_tx_index_creation() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = TxIndexConfig::default();

        let index = TransactionIndex::new(temp_dir.path(), config)?;

        assert!(index.is_enabled());

        let stats = index.get_stats().await;
        assert_eq!(stats.total_indexed, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_tx_location_storage() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = TxIndexConfig::default();

        let index = TransactionIndex::new(temp_dir.path(), config)?;

        // Create test transaction
        let txid = Txid::all_zeros();
        let location = TxLocation {
            block_hash: BlockHash::from_byte_array([0u8; 32]),
            block_height: 100,
            tx_index: 0,
            block_time: 1234567890,
            tx_data: None,
        };

        // Store location
        let location_bytes = bincode::serialize(&location)?;
        index
            .tx_locations
            .insert(txid.to_string().into_bytes(), location_bytes)?;

        // Retrieve location
        let retrieved = index.get_tx_location(&txid).await?;
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.block_height, 100);
        assert_eq!(retrieved.tx_index, 0);

        Ok(())
    }
}
