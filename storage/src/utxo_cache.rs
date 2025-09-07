use anyhow::Result;
use bitcoin::{OutPoint, TxOut};
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, trace, warn};

/// Optimized UTXO cache for fast lookups
pub struct UtxoCache {
    /// L1 cache - hot UTXOs in memory
    l1_cache: Arc<RwLock<LruCache<OutPoint, CachedUtxo>>>,

    /// L2 cache - recent UTXOs with larger capacity
    l2_cache: Arc<RwLock<LruCache<OutPoint, CachedUtxo>>>,

    /// Dirty UTXOs pending flush to disk
    dirty_set: Arc<RwLock<HashMap<OutPoint, DirtyEntry>>>,

    /// Cache configuration
    config: CacheConfig,

    /// Cache statistics
    stats: Arc<RwLock<CacheStats>>,

    /// Backend storage
    backend: Arc<dyn UtxoBackend>,
}

/// UTXO cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// L1 cache size (hot cache)
    pub l1_size: usize,

    /// L2 cache size (warm cache)
    pub l2_size: usize,

    /// Maximum dirty entries before forced flush
    pub max_dirty: usize,

    /// Batch size for database writes
    pub batch_size: usize,

    /// Enable prefetching
    pub prefetch_enabled: bool,

    /// Prefetch ahead count
    pub prefetch_ahead: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            l1_size: 100_000,   // 100k hot entries
            l2_size: 1_000_000, // 1M warm entries
            max_dirty: 50_000,  // 50k dirty entries
            batch_size: 10_000, // 10k per batch write
            prefetch_enabled: true,
            prefetch_ahead: 100, // Prefetch 100 UTXOs
        }
    }
}

/// Cached UTXO entry
#[derive(Debug, Clone)]
struct CachedUtxo {
    pub output: TxOut,
    #[allow(dead_code)]
    pub height: u32,
    #[allow(dead_code)]
    pub is_coinbase: bool,
    pub access_count: u32,
    pub last_access: std::time::Instant,
}

/// Dirty entry pending write
#[derive(Debug, Clone)]
enum DirtyEntry {
    Added(CachedUtxo),
    Removed,
    #[allow(dead_code)]
    Modified(CachedUtxo),
}

/// Cache statistics
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub l1_hits: u64,
    pub l1_misses: u64,
    pub l2_hits: u64,
    pub l2_misses: u64,
    pub backend_reads: u64,
    pub backend_writes: u64,
    pub evictions: u64,
    pub dirty_count: usize,
    pub flush_count: u64,
    pub prefetch_hits: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total_accesses = self.l1_hits + self.l1_misses;
        if total_accesses == 0 {
            0.0
        } else {
            (self.l1_hits as f64) / (total_accesses as f64)
        }
    }

    pub fn l2_hit_rate(&self) -> f64 {
        let l2_accesses = self.l2_hits + self.l2_misses;
        if l2_accesses == 0 {
            0.0
        } else {
            (self.l2_hits as f64) / (l2_accesses as f64)
        }
    }
}

/// Backend storage trait
#[async_trait::async_trait]
pub trait UtxoBackend: Send + Sync {
    /// Get UTXO from backend
    async fn get(&self, outpoint: &OutPoint) -> Result<Option<TxOut>>;

    /// Get multiple UTXOs
    async fn get_batch(&self, outpoints: &[OutPoint]) -> Result<HashMap<OutPoint, TxOut>>;

    /// Write UTXOs to backend
    async fn write_batch(&self, updates: HashMap<OutPoint, Option<TxOut>>) -> Result<()>;

    /// Get UTXO metadata
    async fn get_metadata(&self, outpoint: &OutPoint) -> Result<Option<UtxoMetadata>>;
}

/// UTXO metadata
#[derive(Debug, Clone)]
pub struct UtxoMetadata {
    pub height: u32,
    pub is_coinbase: bool,
}

impl UtxoCache {
    /// Create new UTXO cache
    pub fn new(config: CacheConfig, backend: Arc<dyn UtxoBackend>) -> Self {
        let l1_cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(config.l1_size).unwrap(),
        )));

        let l2_cache = Arc::new(RwLock::new(LruCache::new(
            NonZeroUsize::new(config.l2_size).unwrap(),
        )));

        Self {
            l1_cache,
            l2_cache,
            dirty_set: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(CacheStats::default())),
            backend,
        }
    }

    /// Get UTXO with multi-level cache lookup
    pub async fn get(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        // Check L1 cache
        {
            let mut l1 = self.l1_cache.write().await;
            if let Some(cached) = l1.get_mut(outpoint) {
                cached.access_count += 1;
                cached.last_access = std::time::Instant::now();

                let mut stats = self.stats.write().await;
                stats.l1_hits += 1;

                trace!("L1 cache hit for {:?}", outpoint);
                return Ok(Some(cached.output.clone()));
            }
        }

        // L1 miss
        {
            let mut stats = self.stats.write().await;
            stats.l1_misses += 1;
        }

        // Check L2 cache
        {
            let mut l2 = self.l2_cache.write().await;
            if let Some(cached) = l2.get(outpoint) {
                let mut stats = self.stats.write().await;
                stats.l2_hits += 1;

                // Clone the data we need before dropping the lock
                let cached_clone = cached.clone();
                let output = cached.output.clone();
                drop(l2);

                // Promote to L1
                self.promote_to_l1(outpoint, cached_clone).await;

                trace!("L2 cache hit for {:?}", outpoint);
                return Ok(Some(output));
            }
        }

        // L2 miss
        {
            let mut stats = self.stats.write().await;
            stats.l2_misses += 1;
        }

        // Check dirty set
        {
            let dirty = self.dirty_set.read().await;
            if let Some(entry) = dirty.get(outpoint) {
                match entry {
                    DirtyEntry::Added(cached) | DirtyEntry::Modified(cached) => {
                        trace!("Dirty cache hit for {:?}", outpoint);
                        return Ok(Some(cached.output.clone()));
                    }
                    DirtyEntry::Removed => {
                        trace!("UTXO {:?} marked as removed", outpoint);
                        return Ok(None);
                    }
                }
            }
        }

        // Read from backend
        let result = self.backend.get(outpoint).await?;

        {
            let mut stats = self.stats.write().await;
            stats.backend_reads += 1;
        }

        // Cache the result if found
        if let Some(ref output) = result {
            let metadata = self
                .backend
                .get_metadata(outpoint)
                .await?
                .unwrap_or(UtxoMetadata {
                    height: 0,
                    is_coinbase: false,
                });

            let cached = CachedUtxo {
                output: output.clone(),
                height: metadata.height,
                is_coinbase: metadata.is_coinbase,
                access_count: 1,
                last_access: std::time::Instant::now(),
            };

            // Add to L2 cache
            let mut l2 = self.l2_cache.write().await;
            l2.put(*outpoint, cached);
        }

        // Prefetch nearby UTXOs if enabled
        if self.config.prefetch_enabled && result.is_some() {
            self.prefetch_nearby(outpoint).await;
        }

        Ok(result)
    }

    /// Get multiple UTXOs efficiently
    pub async fn get_batch(&self, outpoints: &[OutPoint]) -> Result<HashMap<OutPoint, TxOut>> {
        let mut results = HashMap::new();
        let mut missing = Vec::new();

        // Check caches first
        for outpoint in outpoints {
            if let Some(output) = self.get_from_cache(outpoint).await {
                results.insert(*outpoint, output);
            } else {
                missing.push(*outpoint);
            }
        }

        // Batch fetch missing from backend
        if !missing.is_empty() {
            let backend_results = self.backend.get_batch(&missing).await?;

            {
                let mut stats = self.stats.write().await;
                stats.backend_reads += missing.len() as u64;
            }

            // Cache and return results
            for (outpoint, output) in backend_results {
                results.insert(outpoint, output.clone());

                // Add to L2 cache
                let cached = CachedUtxo {
                    output,
                    height: 0,
                    is_coinbase: false,
                    access_count: 1,
                    last_access: std::time::Instant::now(),
                };

                let mut l2 = self.l2_cache.write().await;
                l2.put(outpoint, cached);
            }
        }

        Ok(results)
    }

    /// Add or update UTXO
    pub async fn add(&self, outpoint: OutPoint, output: TxOut, height: u32, is_coinbase: bool) {
        let cached = CachedUtxo {
            output,
            height,
            is_coinbase,
            access_count: 0,
            last_access: std::time::Instant::now(),
        };

        // Add to L1 cache
        {
            let mut l1 = self.l1_cache.write().await;
            l1.put(outpoint, cached.clone());
        }

        // Mark as dirty
        {
            let mut dirty = self.dirty_set.write().await;
            dirty.insert(outpoint, DirtyEntry::Added(cached));

            // Check if we need to flush
            if dirty.len() >= self.config.max_dirty {
                drop(dirty);
                if let Err(e) = self.flush().await {
                    warn!("Auto-flush failed: {}", e);
                }
            }
        }
    }

    /// Remove UTXO
    pub async fn remove(&self, outpoint: &OutPoint) -> Result<()> {
        // Remove from caches
        {
            let mut l1 = self.l1_cache.write().await;
            l1.pop(outpoint);
        }

        {
            let mut l2 = self.l2_cache.write().await;
            l2.pop(outpoint);
        }

        // Mark as removed in dirty set
        {
            let mut dirty = self.dirty_set.write().await;
            dirty.insert(*outpoint, DirtyEntry::Removed);
        }

        Ok(())
    }

    /// Flush dirty entries to backend
    pub async fn flush(&self) -> Result<()> {
        let dirty_entries = {
            let mut dirty = self.dirty_set.write().await;
            let entries = dirty.clone();
            dirty.clear();
            entries
        };

        if dirty_entries.is_empty() {
            return Ok(());
        }

        info!("Flushing {} dirty UTXO entries", dirty_entries.len());

        // Convert to backend format
        let mut updates = HashMap::new();
        for (outpoint, entry) in dirty_entries {
            match entry {
                DirtyEntry::Added(cached) | DirtyEntry::Modified(cached) => {
                    updates.insert(outpoint, Some(cached.output));
                }
                DirtyEntry::Removed => {
                    updates.insert(outpoint, None);
                }
            }
        }

        // Write in batches
        for chunk in updates.chunks(self.config.batch_size) {
            let batch: HashMap<_, _> = chunk.iter().map(|(k, v)| (*k, v.clone())).collect();

            self.backend.write_batch(batch).await?;

            let mut stats = self.stats.write().await;
            stats.backend_writes += chunk.len() as u64;
        }

        {
            let mut stats = self.stats.write().await;
            stats.flush_count += 1;
        }

        Ok(())
    }

    /// Get from cache without backend lookup
    async fn get_from_cache(&self, outpoint: &OutPoint) -> Option<TxOut> {
        // Check L1
        {
            let mut l1 = self.l1_cache.write().await;
            if let Some(cached) = l1.get_mut(outpoint) {
                cached.access_count += 1;
                cached.last_access = std::time::Instant::now();
                return Some(cached.output.clone());
            }
        }

        // Check L2
        {
            let l2 = self.l2_cache.read().await;
            if let Some(cached) = l2.peek(outpoint) {
                return Some(cached.output.clone());
            }
        }

        // Check dirty set
        {
            let dirty = self.dirty_set.read().await;
            if let Some(entry) = dirty.get(outpoint) {
                match entry {
                    DirtyEntry::Added(cached) | DirtyEntry::Modified(cached) => {
                        return Some(cached.output.clone());
                    }
                    DirtyEntry::Removed => return None,
                }
            }
        }

        None
    }

    /// Promote entry from L2 to L1
    async fn promote_to_l1(&self, outpoint: &OutPoint, cached: CachedUtxo) {
        let mut l1 = self.l1_cache.write().await;

        // Check if eviction is needed
        if l1.len() >= l1.cap().get() {
            let mut stats = self.stats.write().await;
            stats.evictions += 1;
        }

        l1.put(*outpoint, cached);
    }

    /// Prefetch nearby UTXOs
    async fn prefetch_nearby(&self, _outpoint: &OutPoint) {
        // In a real implementation, this would:
        // 1. Predict likely next accesses based on patterns
        // 2. Batch fetch from backend
        // 3. Populate L2 cache

        let mut stats = self.stats.write().await;
        stats.prefetch_hits += 1;
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        self.stats.read().await.clone()
    }

    /// Clear all caches
    pub async fn clear(&self) {
        let mut l1 = self.l1_cache.write().await;
        l1.clear();

        let mut l2 = self.l2_cache.write().await;
        l2.clear();

        let mut dirty = self.dirty_set.write().await;
        dirty.clear();

        info!("UTXO cache cleared");
    }
}

/// Helper trait for chunking
trait ChunkExt<T> {
    fn chunks(&self, size: usize) -> Vec<Vec<T>>;
}

impl<K: Clone, V: Clone> ChunkExt<(K, V)> for HashMap<K, V> {
    fn chunks(&self, size: usize) -> Vec<Vec<(K, V)>> {
        let items: Vec<_> = self.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        items.chunks(size).map(|c| c.to_vec()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Amount;

    struct MockBackend {
        data: Arc<RwLock<HashMap<OutPoint, TxOut>>>,
    }

    #[async_trait::async_trait]
    impl UtxoBackend for MockBackend {
        async fn get(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
            let data = self.data.read().await;
            Ok(data.get(outpoint).cloned())
        }

        async fn get_batch(&self, outpoints: &[OutPoint]) -> Result<HashMap<OutPoint, TxOut>> {
            let data = self.data.read().await;
            let mut results = HashMap::new();
            for outpoint in outpoints {
                if let Some(output) = data.get(outpoint) {
                    results.insert(*outpoint, output.clone());
                }
            }
            Ok(results)
        }

        async fn write_batch(&self, updates: HashMap<OutPoint, Option<TxOut>>) -> Result<()> {
            let mut data = self.data.write().await;
            for (outpoint, output) in updates {
                if let Some(output) = output {
                    data.insert(outpoint, output);
                } else {
                    data.remove(&outpoint);
                }
            }
            Ok(())
        }

        async fn get_metadata(&self, _outpoint: &OutPoint) -> Result<Option<UtxoMetadata>> {
            Ok(Some(UtxoMetadata {
                height: 0,
                is_coinbase: false,
            }))
        }
    }

    #[tokio::test]
    async fn test_utxo_cache() {
        let backend = Arc::new(MockBackend {
            data: Arc::new(RwLock::new(HashMap::new())),
        });

        let config = CacheConfig {
            l1_size: 10,
            l2_size: 20,
            ..Default::default()
        };

        let cache = UtxoCache::new(config, backend);

        // Add UTXO
        let outpoint = OutPoint::null();
        let output = TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        };

        cache.add(outpoint, output.clone(), 100, false).await;

        // Get should hit cache
        let result = cache.get(&outpoint).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, Amount::from_sat(50000));

        // Check stats
        let stats = cache.get_stats().await;
        assert_eq!(stats.l1_hits, 1);
    }
}
