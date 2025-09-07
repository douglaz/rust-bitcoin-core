use anyhow::{Context, Result};
use bitcoin::{OutPoint, Transaction, TxOut};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::{debug, info, trace};

/// Statistics for the UTXO cache
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub size: usize,
    pub memory_usage: usize,
}

impl CacheStats {
    /// Calculate hit rate percentage
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// UTXO cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    output: TxOut,
    height: u32,
    is_coinbase: bool,
    /// Whether this entry is dirty (modified but not flushed)
    is_dirty: bool,
}

/// High-performance UTXO cache with LRU eviction
pub struct UtxoCache {
    /// LRU cache for recent UTXOs
    cache: Arc<RwLock<LruCache<OutPoint, CacheEntry>>>,

    /// Statistics
    stats: Arc<RwLock<CacheStats>>,

    /// Dirty entries that need to be flushed
    dirty_entries: Arc<Mutex<HashMap<OutPoint, CacheEntry>>>,

    /// Maximum memory usage in bytes
    max_memory: usize,

    /// Current memory usage estimate
    current_memory: Arc<RwLock<usize>>,
}

impl UtxoCache {
    /// Create a new UTXO cache
    pub fn new(max_entries: usize, max_memory_mb: usize) -> Result<Self> {
        let max_entries = NonZeroUsize::new(max_entries).context("Cache size must be non-zero")?;

        Ok(Self {
            cache: Arc::new(RwLock::new(LruCache::new(max_entries))),
            stats: Arc::new(RwLock::new(CacheStats::default())),
            dirty_entries: Arc::new(Mutex::new(HashMap::new())),
            max_memory: max_memory_mb * 1024 * 1024,
            current_memory: Arc::new(RwLock::new(0)),
        })
    }

    /// Get a UTXO from the cache
    pub fn get(&self, outpoint: &OutPoint) -> Option<TxOut> {
        let mut cache = self.cache.write();
        let mut stats = self.stats.write();

        if let Some(entry) = cache.get(outpoint) {
            stats.hits += 1;
            trace!("Cache hit for outpoint {:?}", outpoint);
            Some(entry.output.clone())
        } else {
            stats.misses += 1;
            trace!("Cache miss for outpoint {:?}", outpoint);
            None
        }
    }

    /// Add a UTXO to the cache
    pub fn insert(&self, outpoint: OutPoint, output: TxOut, height: u32, is_coinbase: bool) {
        let entry_size = Self::estimate_entry_size(&output);

        // Check if we need to evict based on memory
        let mut current_mem = self.current_memory.write();
        if *current_mem + entry_size > self.max_memory {
            // Trigger eviction
            drop(current_mem);
            self.evict_lru();
            current_mem = self.current_memory.write();
        }

        let entry = CacheEntry {
            output: output.clone(),
            height,
            is_coinbase,
            is_dirty: true,
        };

        let mut cache = self.cache.write();
        let mut stats = self.stats.write();

        // Check if this causes an eviction
        if cache.len() == cache.cap().get() {
            stats.evictions += 1;

            // Get the LRU item that will be evicted
            if let Some((evicted_outpoint, evicted_entry)) = cache.peek_lru() {
                let evicted_size = Self::estimate_entry_size(&evicted_entry.output);
                *current_mem = current_mem.saturating_sub(evicted_size);

                // If evicted entry is dirty, save it
                if evicted_entry.is_dirty {
                    let mut dirty = self.dirty_entries.lock();
                    dirty.insert(*evicted_outpoint, evicted_entry.clone());
                }
            }
        }

        // Insert new entry
        cache.put(outpoint, entry.clone());
        *current_mem += entry_size;
        stats.size = cache.len();
        stats.memory_usage = *current_mem;

        // Mark as dirty
        let mut dirty = self.dirty_entries.lock();
        dirty.insert(outpoint, entry);

        trace!(
            "Added UTXO to cache, size: {}, memory: {} bytes",
            stats.size,
            *current_mem
        );
    }

    /// Remove a UTXO from the cache (when spent)
    pub fn remove(&self, outpoint: &OutPoint) -> Option<TxOut> {
        let mut cache = self.cache.write();
        let mut stats = self.stats.write();

        if let Some(entry) = cache.pop(outpoint) {
            let entry_size = Self::estimate_entry_size(&entry.output);
            let mut current_mem = self.current_memory.write();
            *current_mem = current_mem.saturating_sub(entry_size);
            stats.size = cache.len();
            stats.memory_usage = *current_mem;

            // Mark as spent in dirty entries (for database deletion)
            let mut dirty = self.dirty_entries.lock();
            dirty.remove(outpoint);

            debug!("Removed UTXO from cache: {:?}", outpoint);
            Some(entry.output)
        } else {
            None
        }
    }

    /// Add UTXOs from a transaction
    pub fn add_transaction_outputs(&self, tx: &Transaction, tx_index: u32, height: u32) {
        let txid = tx.compute_txid();
        let is_coinbase = tx.is_coinbase();

        for (vout, output) in tx.output.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };

            self.insert(outpoint, output.clone(), height, is_coinbase);
        }

        debug!(
            "Added {} outputs from tx {} to cache",
            tx.output.len(),
            txid
        );
    }

    /// Spend transaction inputs
    pub fn spend_transaction_inputs(&self, tx: &Transaction) -> Vec<OutPoint> {
        let mut spent = Vec::new();

        if !tx.is_coinbase() {
            for input in &tx.input {
                if self.remove(&input.previous_output).is_some() {
                    spent.push(input.previous_output);
                }
            }
        }

        debug!("Spent {} inputs from tx {}", spent.len(), tx.compute_txid());
        spent
    }

    /// Evict least recently used entries
    fn evict_lru(&self) {
        let mut cache = self.cache.write();
        let mut stats = self.stats.write();
        let mut current_mem = self.current_memory.write();

        // Evict 10% of entries
        let to_evict = cache.len() / 10;
        let mut evicted = 0;

        while evicted < to_evict {
            if let Some((outpoint, entry)) = cache.pop_lru() {
                let entry_size = Self::estimate_entry_size(&entry.output);
                *current_mem = current_mem.saturating_sub(entry_size);

                // Save dirty entry
                if entry.is_dirty {
                    let mut dirty = self.dirty_entries.lock();
                    dirty.insert(outpoint, entry);
                }

                evicted += 1;
                stats.evictions += 1;
            } else {
                break;
            }
        }

        stats.size = cache.len();
        stats.memory_usage = *current_mem;

        debug!(
            "Evicted {} LRU entries, cache size: {}",
            evicted, stats.size
        );
    }

    /// Estimate memory usage of a cache entry
    fn estimate_entry_size(output: &TxOut) -> usize {
        // OutPoint: 32 (txid) + 4 (vout) = 36 bytes
        // TxOut: 8 (amount) + script_pubkey.len()
        // CacheEntry overhead: ~32 bytes
        36 + 8 + output.script_pubkey.len() + 32
    }

    /// Get dirty entries that need to be flushed
    pub fn get_dirty_entries(&self) -> HashMap<OutPoint, TxOut> {
        let dirty = self.dirty_entries.lock();
        dirty.iter().map(|(k, v)| (*k, v.output.clone())).collect()
    }

    /// Mark all entries as clean (after flush)
    pub fn mark_clean(&self) {
        let mut dirty = self.dirty_entries.lock();
        dirty.clear();

        // Mark cache entries as clean
        let mut cache = self.cache.write();
        for (_outpoint, entry) in cache.iter_mut() {
            entry.is_dirty = false;
        }

        debug!("Marked all cache entries as clean");
    }

    /// Clear the entire cache
    pub fn clear(&self) {
        let mut cache = self.cache.write();
        cache.clear();

        let mut stats = self.stats.write();
        stats.size = 0;
        stats.memory_usage = 0;

        let mut current_mem = self.current_memory.write();
        *current_mem = 0;

        let mut dirty = self.dirty_entries.lock();
        dirty.clear();

        info!("Cleared UTXO cache");
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        let stats = self.stats.read();
        stats.clone()
    }

    /// Prefetch UTXOs for a transaction (for validation)
    pub fn prefetch_for_transaction(
        &self,
        tx: &Transaction,
        fetch_fn: impl Fn(&OutPoint) -> Option<TxOut>,
    ) {
        if tx.is_coinbase() {
            return;
        }

        for input in &tx.input {
            // Check if already in cache
            if self.get(&input.previous_output).is_none() {
                // Fetch from database and add to cache
                if let Some(output) = fetch_fn(&input.previous_output) {
                    // Use height 0 and non-coinbase as defaults for prefetched
                    self.insert(input.previous_output, output, 0, false);
                }
            }
        }

        trace!("Prefetched {} inputs for transaction", tx.input.len());
    }
}

/// Thread-safe UTXO cache wrapper
pub struct ThreadSafeUtxoCache {
    inner: Arc<UtxoCache>,
}

impl ThreadSafeUtxoCache {
    pub fn new(max_entries: usize, max_memory_mb: usize) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(UtxoCache::new(max_entries, max_memory_mb)?),
        })
    }

    pub fn get(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.inner.get(outpoint)
    }

    pub fn insert(&self, outpoint: OutPoint, output: TxOut, height: u32, is_coinbase: bool) {
        self.inner.insert(outpoint, output, height, is_coinbase)
    }

    pub fn remove(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.inner.remove(outpoint)
    }

    pub fn get_stats(&self) -> CacheStats {
        self.inner.get_stats()
    }

    pub fn clone_inner(&self) -> Arc<UtxoCache> {
        Arc::clone(&self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, ScriptBuf, TxOut, Txid};

    fn create_test_output(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new(),
        }
    }

    fn create_test_outpoint(index: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([index as u8; 32]),
            vout: index,
        }
    }

    #[test]
    fn test_cache_basic_operations() {
        let cache = UtxoCache::new(100, 10).unwrap();

        let outpoint = create_test_outpoint(1);
        let output = create_test_output(1000);

        // Test insert
        cache.insert(outpoint, output.clone(), 100, false);

        // Test get
        assert_eq!(cache.get(&outpoint), Some(output.clone()));

        // Test remove
        assert_eq!(cache.remove(&outpoint), Some(output));
        assert_eq!(cache.get(&outpoint), None);
    }

    #[test]
    fn test_cache_statistics() {
        let cache = UtxoCache::new(100, 10).unwrap();

        // Insert some entries
        for i in 0..10 {
            let outpoint = create_test_outpoint(i);
            let output = create_test_output(1000 * (i as u64));
            cache.insert(outpoint, output, 100 + i, false);
        }

        // Test hits and misses
        cache.get(&create_test_outpoint(5)); // Hit
        cache.get(&create_test_outpoint(99)); // Miss

        let stats = cache.get_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate(), 50.0);
    }

    #[test]
    fn test_lru_eviction() {
        let cache = UtxoCache::new(3, 10).unwrap(); // Small cache

        // Fill cache
        for i in 0..3 {
            let outpoint = create_test_outpoint(i);
            let output = create_test_output(1000 * (i as u64));
            cache.insert(outpoint, output, 100, false);
        }

        // Insert one more, should evict the least recently used
        let outpoint = create_test_outpoint(3);
        let output = create_test_output(3000);
        cache.insert(outpoint, output, 100, false);

        // First entry should be evicted
        assert_eq!(cache.get(&create_test_outpoint(0)), None);

        // Others should still be there
        assert!(cache.get(&create_test_outpoint(1)).is_some());
        assert!(cache.get(&create_test_outpoint(2)).is_some());
        assert!(cache.get(&create_test_outpoint(3)).is_some());
    }
}
