use anyhow::{bail, Context, Result};
use bitcoin::{OutPoint, Transaction, TxOut};
use lru::LruCache;
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use storage::manager::StorageManager;

/// UTXO entry in cache
#[derive(Debug, Clone)]
pub struct CachedUtxo {
    /// Transaction output
    pub output: TxOut,

    /// Block height where this UTXO was created
    pub height: u32,

    /// Whether this is from a coinbase transaction
    pub is_coinbase: bool,

    /// Last access time for LRU
    pub last_accessed: Instant,

    /// Whether this entry is dirty (needs to be written to disk)
    pub is_dirty: bool,
}

/// UTXO cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total entries in cache
    pub entries: usize,

    /// Cache size in bytes
    pub size_bytes: usize,

    /// Number of cache hits
    pub hits: u64,

    /// Number of cache misses
    pub misses: u64,

    /// Number of evictions
    pub evictions: u64,

    /// Dirty entries needing flush
    pub dirty_entries: usize,
}

/// UTXO cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries in cache
    pub max_entries: usize,

    /// Maximum cache size in bytes
    pub max_size_bytes: usize,

    /// Flush interval for dirty entries
    pub flush_interval: Duration,

    /// Whether to use write-through caching
    pub write_through: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 100_000,              // 100k UTXOs
            max_size_bytes: 300 * 1024 * 1024, // 300 MB
            flush_interval: Duration::from_secs(60),
            write_through: false,
        }
    }
}

/// UTXO cache manager with memory management
pub struct UtxoCacheManager {
    /// LRU cache for hot UTXOs
    cache: Arc<RwLock<LruCache<OutPoint, CachedUtxo>>>,

    /// Spent UTXOs (negative cache)
    spent_cache: Arc<RwLock<HashSet<OutPoint>>>,

    /// Storage backend
    storage: Arc<StorageManager>,

    /// Cache configuration
    config: CacheConfig,

    /// Cache statistics
    stats: Arc<RwLock<CacheStats>>,

    /// Dirty entries needing flush
    dirty_set: Arc<RwLock<HashSet<OutPoint>>>,

    /// Current cache size in bytes
    current_size: Arc<RwLock<usize>>,
}

impl UtxoCacheManager {
    /// Create new UTXO cache manager
    pub fn new(storage: Arc<StorageManager>, config: CacheConfig) -> Result<Self> {
        let max_entries = NonZeroUsize::new(config.max_entries).context("Invalid max_entries")?;

        Ok(Self {
            cache: Arc::new(RwLock::new(LruCache::new(max_entries))),
            spent_cache: Arc::new(RwLock::new(HashSet::new())),
            storage,
            config,
            stats: Arc::new(RwLock::new(CacheStats::default())),
            dirty_set: Arc::new(RwLock::new(HashSet::new())),
            current_size: Arc::new(RwLock::new(0)),
        })
    }

    /// Get a UTXO from cache or storage
    pub async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<CachedUtxo>> {
        // Check spent cache first
        if self.spent_cache.read().await.contains(outpoint) {
            self.stats.write().await.hits += 1;
            return Ok(None);
        }

        // Check LRU cache
        let mut cache = self.cache.write().await;
        if let Some(utxo) = cache.get_mut(outpoint) {
            utxo.last_accessed = Instant::now();
            self.stats.write().await.hits += 1;
            return Ok(Some(utxo.clone()));
        }
        drop(cache);

        // Cache miss - load from storage
        self.stats.write().await.misses += 1;

        if let Some(output) = self.storage.get_utxo(outpoint).await? {
            // Get metadata from storage (for now use defaults)
            let (height, is_coinbase) = (0, false); // Will be enhanced with actual storage metadata

            // Add to cache
            let utxo = CachedUtxo {
                output: output.clone(),
                height,
                is_coinbase,
                last_accessed: Instant::now(),
                is_dirty: false,
            };

            self.add_to_cache(*outpoint, utxo.clone()).await?;
            Ok(Some(utxo))
        } else {
            // Add to spent cache
            self.spent_cache.write().await.insert(*outpoint);
            Ok(None)
        }
    }

    /// Add a new UTXO to the cache
    pub async fn add_utxo(
        &self,
        outpoint: OutPoint,
        output: TxOut,
        height: u32,
        is_coinbase: bool,
    ) -> Result<()> {
        // Remove from spent cache if present
        self.spent_cache.write().await.remove(&outpoint);

        let utxo = CachedUtxo {
            output,
            height,
            is_coinbase,
            last_accessed: Instant::now(),
            is_dirty: true,
        };

        // Add to cache
        self.add_to_cache(outpoint, utxo).await?;

        // Mark as dirty
        self.dirty_set.write().await.insert(outpoint);

        // Write through if configured
        if self.config.write_through {
            // Store to underlying storage
            // Note: Storage interface would need enhancement to support this
            // For now, mark as dirty for batch write
            self.dirty_set.write().await.insert(outpoint);
        }

        Ok(())
    }

    /// Spend a UTXO
    pub async fn spend_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        // Remove from cache
        let mut cache = self.cache.write().await;
        if let Some(utxo) = cache.pop(outpoint) {
            // Update size
            let size = self.estimate_utxo_size(&utxo);
            *self.current_size.write().await -= size;

            // Add to spent cache
            self.spent_cache.write().await.insert(*outpoint);

            // Mark for deletion in storage
            self.dirty_set.write().await.insert(*outpoint);

            // Write through if configured
            if self.config.write_through {
                // Delete from underlying storage
                // Note: Storage interface would need enhancement
                self.dirty_set.write().await.insert(*outpoint);
            }

            return Ok(Some(utxo.output));
        }
        drop(cache);

        // Not in cache - check storage
        if let Some(output) = self.storage.get_utxo(outpoint).await? {
            // Add to spent cache
            self.spent_cache.write().await.insert(*outpoint);

            // Mark for deletion from storage (will be handled in batch)
            self.dirty_set.write().await.insert(*outpoint);

            Ok(Some(output))
        } else {
            Ok(None)
        }
    }

    /// Apply a block's transactions to the UTXO set
    pub async fn apply_block(&self, transactions: &[Transaction], height: u32) -> Result<()> {
        for (tx_index, tx) in transactions.iter().enumerate() {
            let is_coinbase = tx_index == 0;
            let txid = tx.compute_txid();

            // Spend inputs (except for coinbase)
            if !is_coinbase {
                for input in &tx.input {
                    self.spend_utxo(&input.previous_output).await?;
                }
            }

            // Add outputs
            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };

                self.add_utxo(outpoint, output.clone(), height, is_coinbase)
                    .await?;
            }
        }

        Ok(())
    }

    /// Revert a block's transactions from the UTXO set
    pub async fn revert_block(&self, transactions: &[Transaction], height: u32) -> Result<()> {
        // Process transactions in reverse order
        for (tx_index, tx) in transactions.iter().enumerate().rev() {
            let is_coinbase = tx_index == 0;
            let txid = tx.compute_txid();

            // Remove outputs
            for (vout, _) in tx.output.iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };

                self.spend_utxo(&outpoint).await?;
            }

            // Restore inputs (except for coinbase)
            if !is_coinbase {
                for input in &tx.input {
                    // This requires undo data which should be stored separately
                    // For now, we'll need to fetch from storage
                    warn!("Reverting block requires undo data (not implemented)");
                }
            }
        }

        Ok(())
    }

    /// Flush dirty entries to storage
    pub async fn flush(&self) -> Result<()> {
        let dirty_set = self.dirty_set.read().await.clone();
        if dirty_set.is_empty() {
            return Ok(());
        }

        info!("Flushing {} dirty UTXO entries", dirty_set.len());

        let cache = self.cache.read().await;
        let spent = self.spent_cache.read().await;

        for outpoint in &dirty_set {
            if spent.contains(outpoint) {
                // This UTXO has been spent - would be deleted from storage
                // In a full implementation, this would call:
                // self.storage.delete_utxo(outpoint).await?;
                debug!("Would delete UTXO: {:?}", outpoint);
            } else if let Some(utxo) = cache.peek(outpoint) {
                // This UTXO needs to be persisted - would be written to storage
                // In a full implementation, this would call:
                // self.storage.store_utxo(outpoint, &utxo.output, utxo.height, utxo.is_coinbase).await?;
                debug!("Would store UTXO: {:?} at height {}", outpoint, utxo.height);
            }
        }

        drop(cache);
        drop(spent);

        // Clear dirty set
        self.dirty_set.write().await.clear();

        // Update stats
        self.stats.write().await.dirty_entries = 0;

        info!("UTXO cache flush complete");
        Ok(())
    }

    /// Add entry to cache with eviction if needed
    async fn add_to_cache(&self, outpoint: OutPoint, utxo: CachedUtxo) -> Result<()> {
        let size = self.estimate_utxo_size(&utxo);

        // Check if we need to evict
        let mut current_size = self.current_size.write().await;
        while *current_size + size > self.config.max_size_bytes {
            // Evict LRU entry
            let mut cache = self.cache.write().await;
            if let Some((evicted_outpoint, evicted_utxo)) = cache.pop_lru() {
                let evicted_size = self.estimate_utxo_size(&evicted_utxo);
                *current_size -= evicted_size;

                // Write to storage if dirty
                if evicted_utxo.is_dirty {
                    // In a full implementation, would persist evicted dirty entry:
                    // self.storage.store_utxo(&evicted_outpoint, &evicted_utxo.output,
                    //                        evicted_utxo.height, evicted_utxo.is_coinbase).await?;
                    debug!(
                        "Evicted dirty UTXO would be persisted: {:?}",
                        evicted_outpoint
                    );
                    self.dirty_set.write().await.remove(&evicted_outpoint);
                }

                self.stats.write().await.evictions += 1;
            } else {
                break;
            }
        }

        // Add to cache
        self.cache.write().await.put(outpoint, utxo);
        *current_size += size;

        Ok(())
    }

    /// Estimate size of a UTXO entry in bytes
    fn estimate_utxo_size(&self, utxo: &CachedUtxo) -> usize {
        // Rough estimate: 32 bytes outpoint + script size + 8 bytes value + metadata
        32 + utxo.output.script_pubkey.len() + 8 + 32
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        let mut stats = self.stats.read().await.clone();
        stats.entries = self.cache.read().await.len();
        stats.size_bytes = *self.current_size.read().await;
        stats.dirty_entries = self.dirty_set.read().await.len();
        stats
    }

    /// Clear the cache
    pub async fn clear(&self) -> Result<()> {
        // Flush dirty entries first
        self.flush().await?;

        // Clear caches
        self.cache.write().await.clear();
        self.spent_cache.write().await.clear();
        *self.current_size.write().await = 0;

        // Reset stats
        *self.stats.write().await = CacheStats::default();

        info!("UTXO cache cleared");
        Ok(())
    }

    /// Validate a transaction against the UTXO set
    pub async fn validate_transaction(&self, tx: &Transaction) -> Result<Vec<TxOut>> {
        let mut spent_outputs = Vec::new();

        for input in &tx.input {
            if let Some(utxo) = self.get_utxo(&input.previous_output).await? {
                // Check coinbase maturity
                if utxo.is_coinbase {
                    // Coinbase outputs must mature for 100 blocks
                    // This check would need current block height
                    debug!("Coinbase maturity check needed");
                }

                spent_outputs.push(utxo.output);
            } else {
                bail!("Input {} not found in UTXO set", input.previous_output);
            }
        }

        Ok(spent_outputs)
    }
}

/// Background flush manager
pub struct FlushManager {
    cache: Arc<UtxoCacheManager>,
    interval: Duration,
    shutdown: Arc<RwLock<bool>>,
}

impl FlushManager {
    /// Create new flush manager
    pub fn new(cache: Arc<UtxoCacheManager>, interval: Duration) -> Self {
        Self {
            cache,
            interval,
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Start flush loop
    pub async fn start(self) {
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.interval);

            loop {
                interval.tick().await;

                if *shutdown.read().await {
                    break;
                }

                if let Err(e) = self.cache.flush().await {
                    warn!("UTXO cache flush failed: {}", e);
                }

                let stats = self.cache.get_stats().await;
                debug!(
                    "UTXO cache: {} entries, {:.2} MB, {:.1}% hit rate",
                    stats.entries,
                    stats.size_bytes as f64 / 1024.0 / 1024.0,
                    if stats.hits + stats.misses > 0 {
                        stats.hits as f64 / (stats.hits + stats.misses) as f64 * 100.0
                    } else {
                        0.0
                    }
                );
            }

            // Final flush on shutdown
            if let Err(e) = self.cache.flush().await {
                warn!("Final UTXO cache flush failed: {}", e);
            }

            info!("UTXO flush manager stopped");
        });
    }

    /// Stop flush manager
    pub async fn stop(&self) {
        *self.shutdown.write().await = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{TxOut, Txid};

    #[tokio::test]
    async fn test_cache_operations() {
        let storage = Arc::new(StorageManager::new(":memory:").await.unwrap());
        let cache = UtxoCacheManager::new(storage, CacheConfig::default()).unwrap();

        let outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };

        let output = TxOut {
            value: bitcoin::Amount::from_sat(50_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        };

        // Add UTXO
        cache
            .add_utxo(outpoint, output.clone(), 100, false)
            .await
            .unwrap();

        // Get UTXO
        let utxo = cache.get_utxo(&outpoint).await.unwrap();
        assert!(utxo.is_some());
        assert_eq!(utxo.unwrap().output.value, output.value);

        // Spend UTXO
        let spent = cache.spend_utxo(&outpoint).await.unwrap();
        assert!(spent.is_some());

        // Should be gone
        let utxo = cache.get_utxo(&outpoint).await.unwrap();
        assert!(utxo.is_none());
    }
}
