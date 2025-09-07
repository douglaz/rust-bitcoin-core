use anyhow::{bail, Result};
use bitcoin::{OutPoint, TxOut};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Multi-level UTXO cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// L1 cache size (number of entries)
    pub l1_size: usize,
    /// L2 cache size (number of entries)
    pub l2_size: usize,
    /// Maximum memory for L1 cache in bytes
    pub l1_max_memory: usize,
    /// Maximum memory for L2 cache in bytes
    pub l2_max_memory: usize,
    /// Flush interval for dirty entries
    pub flush_interval: Duration,
    /// Promotion threshold (number of accesses)
    pub promotion_threshold: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            l1_size: 50_000,            // Optimized: 50k entries for L1 (hot)
            l2_size: 100_000,           // Optimized: 100k entries for L2 (warm)
            l1_max_memory: 200_000_000, // 200MB for L1
            l2_max_memory: 500_000_000, // 500MB for L2
            flush_interval: Duration::from_secs(60),
            promotion_threshold: 3,
        }
    }
}

/// UTXO cache entry with metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CacheEntry {
    /// The actual UTXO output
    pub output: TxOut,
    /// Block height where this UTXO was created
    pub height: u32,
    /// Whether this is from a coinbase transaction
    pub is_coinbase: bool,
    /// Number of times accessed
    pub access_count: u32,
    /// Last access timestamp
    #[serde(skip, default = "Instant::now")]
    pub last_accessed: Instant,
    /// Whether entry has been modified
    pub is_dirty: bool,
    /// Size in bytes (for memory accounting)
    pub size_bytes: usize,
}

impl CacheEntry {
    pub fn new(output: TxOut, height: u32, is_coinbase: bool) -> Self {
        let size_bytes =
            std::mem::size_of::<TxOut>() + output.script_pubkey.len() + std::mem::size_of::<Self>();

        Self {
            output,
            height,
            is_coinbase,
            access_count: 1,
            last_accessed: Instant::now(),
            is_dirty: false,
            size_bytes,
        }
    }

    pub fn access(&mut self) {
        self.access_count += 1;
        self.last_accessed = Instant::now();
    }

    pub fn mark_dirty(&mut self) {
        self.is_dirty = true;
    }
}

/// Level 1 Cache - Hot UTXOs (in-memory LRU)
pub struct L1Cache {
    cache: Mutex<LruCache<OutPoint, CacheEntry>>,
    memory_used: Arc<RwLock<usize>>,
    max_memory: usize,
    stats: Arc<RwLock<L1Stats>>,
}

#[derive(Debug, Default, Clone)]
pub struct L1Stats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub promotions: u64,
}

impl L1Cache {
    pub fn new(size: usize, max_memory: usize) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(size).unwrap())),
            memory_used: Arc::new(RwLock::new(0)),
            max_memory,
            stats: Arc::new(RwLock::new(L1Stats::default())),
        }
    }

    pub fn get(&self, outpoint: &OutPoint) -> Option<CacheEntry> {
        let mut cache = self.cache.lock();
        let mut stats = self.stats.write();

        if let Some(entry) = cache.get_mut(outpoint) {
            entry.access();
            stats.hits += 1;
            Some(entry.clone())
        } else {
            stats.misses += 1;
            None
        }
    }

    pub fn insert(&self, outpoint: OutPoint, mut entry: CacheEntry) -> Option<CacheEntry> {
        let mut cache = self.cache.lock();
        let mut memory = self.memory_used.write();

        // Check memory limit
        if *memory + entry.size_bytes > self.max_memory {
            // Evict entries until we have space
            while *memory + entry.size_bytes > self.max_memory && !cache.is_empty() {
                if let Some((_evicted_key, evicted_entry)) = cache.pop_lru() {
                    *memory = memory.saturating_sub(evicted_entry.size_bytes);
                    self.stats.write().evictions += 1;

                    if evicted_entry.is_dirty {
                        // Return dirty entry for write-back
                        return Some(evicted_entry);
                    }
                }
            }
        }

        entry.last_accessed = Instant::now();
        *memory += entry.size_bytes;

        // LRU cache push returns the old key-value pair if it existed
        if let Some((_old_key, old_value)) = cache.push(outpoint, entry) {
            *memory = memory.saturating_sub(old_value.size_bytes);
            if old_value.is_dirty {
                return Some(old_value);
            }
        }

        None
    }

    pub fn remove(&self, outpoint: &OutPoint) -> Option<CacheEntry> {
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.pop(outpoint) {
            *self.memory_used.write() = self.memory_used.read().saturating_sub(entry.size_bytes);
            Some(entry)
        } else {
            None
        }
    }

    pub fn get_dirty_entries(&self) -> Vec<(OutPoint, CacheEntry)> {
        let cache = self.cache.lock();
        cache
            .iter()
            .filter(|(_, entry)| entry.is_dirty)
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    pub fn mark_clean(&self, outpoint: &OutPoint) {
        if let Some(entry) = self.cache.lock().get_mut(outpoint) {
            entry.is_dirty = false;
        }
    }

    pub fn clear(&self) {
        self.cache.lock().clear();
        *self.memory_used.write() = 0;
    }

    pub fn stats(&self) -> L1Stats {
        self.stats.read().clone()
    }
}

/// Level 2 Cache - Warm UTXOs (memory-mapped file)
pub struct L2Cache {
    /// Memory-mapped storage
    mmap_storage: Arc<RwLock<MmapStorage>>,
    /// Index for fast lookup
    index: Arc<RwLock<HashMap<OutPoint, MmapEntry>>>,
    /// LRU tracking for eviction
    lru_tracker: Mutex<LruCache<OutPoint, ()>>,
    /// Statistics
    stats: Arc<RwLock<L2Stats>>,
    /// Configuration
    config: CacheConfig,
}

#[derive(Debug, Clone)]
struct MmapEntry {
    offset: usize,
    size: usize,
    access_count: u32,
    last_accessed: Instant,
}

#[derive(Debug, Default, Clone)]
pub struct L2Stats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub demotions: u64,
}

/// Memory-mapped storage backend
struct MmapStorage {
    /// The actual memory-mapped region
    mmap: memmap2::MmapMut,
    /// Current write position
    write_pos: usize,
    /// Free list for reuse
    free_list: Vec<(usize, usize)>, // (offset, size)
}

impl MmapStorage {
    fn new(size: usize) -> Result<Self> {
        use memmap2::MmapOptions;
        use std::fs::OpenOptions;
        use tempfile::tempdir;

        // Create a temporary file for memory mapping
        let dir = tempdir()?;
        let file_path = dir.path().join("l2_cache.dat");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&file_path)?;

        file.set_len(size as u64)?;

        let mmap = unsafe { MmapOptions::new().len(size).map_mut(&file)? };

        Ok(Self {
            mmap,
            write_pos: 0,
            free_list: Vec::new(),
        })
    }

    fn write(&mut self, data: &[u8]) -> Result<(usize, usize)> {
        let size = data.len();

        // Try to reuse space from free list
        if let Some(pos) = self.free_list.iter().position(|(_, s)| *s >= size) {
            let (offset, free_size) = self.free_list.remove(pos);

            // Write data
            self.mmap[offset..offset + size].copy_from_slice(data);

            // Add remaining space back to free list if significant
            if free_size > size + 64 {
                self.free_list.push((offset + size, free_size - size));
            }

            return Ok((offset, size));
        }

        // Allocate new space
        if self.write_pos + size > self.mmap.len() {
            bail!("L2 cache memory-mapped file is full");
        }

        let offset = self.write_pos;
        self.mmap[offset..offset + size].copy_from_slice(data);
        self.write_pos += size;

        Ok((offset, size))
    }

    fn read(&self, offset: usize, size: usize) -> Result<Vec<u8>> {
        if offset + size > self.mmap.len() {
            bail!("Invalid read offset/size");
        }
        Ok(self.mmap[offset..offset + size].to_vec())
    }

    fn free(&mut self, offset: usize, size: usize) {
        // Add to free list for reuse
        self.free_list.push((offset, size));

        // Coalesce adjacent free blocks
        self.free_list.sort_by_key(|(off, _)| *off);
        let mut i = 0;
        while i < self.free_list.len() - 1 {
            let (off1, size1) = self.free_list[i];
            let (off2, size2) = self.free_list[i + 1];

            if off1 + size1 == off2 {
                // Merge adjacent blocks
                self.free_list[i] = (off1, size1 + size2);
                self.free_list.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }
}

impl L2Cache {
    pub fn new(config: CacheConfig) -> Result<Self> {
        let mmap_storage = MmapStorage::new(config.l2_max_memory)?;

        Ok(Self {
            mmap_storage: Arc::new(RwLock::new(mmap_storage)),
            index: Arc::new(RwLock::new(HashMap::new())),
            lru_tracker: Mutex::new(LruCache::new(NonZeroUsize::new(config.l2_size).unwrap())),
            stats: Arc::new(RwLock::new(L2Stats::default())),
            config,
        })
    }

    pub fn get(&self, outpoint: &OutPoint) -> Option<CacheEntry> {
        let mut index = self.index.write();
        let mut stats = self.stats.write();

        if let Some(entry) = index.get_mut(outpoint) {
            entry.access_count += 1;
            entry.last_accessed = Instant::now();
            stats.hits += 1;

            // Update LRU
            self.lru_tracker.lock().get(outpoint);

            // Read from memory-mapped storage
            let storage = self.mmap_storage.read();
            if let Ok(data) = storage.read(entry.offset, entry.size) {
                // Deserialize entry
                if let Ok(cache_entry) = bincode::deserialize::<CacheEntry>(&data) {
                    return Some(cache_entry);
                }
            }
        }

        stats.misses += 1;
        None
    }

    pub fn insert(&self, outpoint: OutPoint, entry: CacheEntry) -> Result<Option<CacheEntry>> {
        // Serialize entry
        let data = bincode::serialize(&entry)?;

        // Check if we need to evict
        let mut lru = self.lru_tracker.lock();
        if lru.len() >= self.config.l2_size {
            // Evict LRU entry
            if let Some((evicted_outpoint, _)) = lru.pop_lru() {
                let mut index = self.index.write();
                if let Some(evicted_entry) = index.remove(&evicted_outpoint) {
                    // Free memory-mapped space
                    self.mmap_storage
                        .write()
                        .free(evicted_entry.offset, evicted_entry.size);
                    self.stats.write().evictions += 1;
                }
            }
        }

        // Write to memory-mapped storage
        let (offset, size) = self.mmap_storage.write().write(&data)?;

        // Update index
        let mmap_entry = MmapEntry {
            offset,
            size,
            access_count: 1,
            last_accessed: Instant::now(),
        };

        self.index.write().insert(outpoint, mmap_entry);
        lru.put(outpoint, ());

        Ok(None)
    }

    pub fn remove(&self, outpoint: &OutPoint) -> Option<CacheEntry> {
        let mut index = self.index.write();
        if let Some(entry) = index.remove(outpoint) {
            // Free memory-mapped space
            self.mmap_storage.write().free(entry.offset, entry.size);
            self.lru_tracker.lock().pop(outpoint);

            // Read and deserialize for return
            let storage = self.mmap_storage.read();
            if let Ok(data) = storage.read(entry.offset, entry.size) {
                if let Ok(cache_entry) = bincode::deserialize::<CacheEntry>(&data) {
                    return Some(cache_entry);
                }
            }
        }
        None
    }

    pub fn should_promote(&self, outpoint: &OutPoint) -> bool {
        self.index
            .read()
            .get(outpoint)
            .map(|e| e.access_count >= self.config.promotion_threshold)
            .unwrap_or(false)
    }

    pub fn stats(&self) -> L2Stats {
        self.stats.read().clone()
    }
}

/// Multi-level UTXO cache coordinator
pub struct MultiLevelCache {
    /// L1 cache (hot)
    l1: Arc<L1Cache>,
    /// L2 cache (warm)
    l2: Arc<L2Cache>,
    /// Storage manager for L3 (cold)
    storage: Arc<dyn UtxoStorage>,
    /// Configuration
    config: CacheConfig,
    /// Global statistics
    stats: Arc<RwLock<CacheStats>>,
    /// Background flush handle
    flush_handle: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub l1_hits: u64,
    pub l1_misses: u64,
    pub l2_hits: u64,
    pub l2_misses: u64,
    pub l3_hits: u64,
    pub l3_misses: u64,
    pub promotions: u64,
    pub demotions: u64,
    pub flushes: u64,
}

/// Trait for L3 storage backend
pub trait UtxoStorage: Send + Sync {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<(TxOut, u32, bool)>>;
    fn put(
        &self,
        outpoint: &OutPoint,
        output: &TxOut,
        height: u32,
        is_coinbase: bool,
    ) -> Result<()>;
    fn delete(&self, outpoint: &OutPoint) -> Result<()>;
    fn flush(&self) -> Result<()>;
}

impl MultiLevelCache {
    pub fn new(storage: Arc<dyn UtxoStorage>, config: CacheConfig) -> Result<Self> {
        let l1 = Arc::new(L1Cache::new(config.l1_size, config.l1_max_memory));
        let l2 = Arc::new(L2Cache::new(config.clone())?);

        let cache = Self {
            l1: l1.clone(),
            l2: l2.clone(),
            storage,
            config: config.clone(),
            stats: Arc::new(RwLock::new(CacheStats::default())),
            flush_handle: None,
        };

        // Start background flush task
        let flush_handle = cache.start_flush_task();

        Ok(Self {
            flush_handle: Some(flush_handle),
            ..cache
        })
    }

    /// Get a UTXO from the cache hierarchy
    pub async fn get(&self, outpoint: &OutPoint) -> Result<Option<CacheEntry>> {
        let mut stats = self.stats.write();

        // Check L1
        if let Some(entry) = self.l1.get(outpoint) {
            stats.l1_hits += 1;
            return Ok(Some(entry));
        }
        stats.l1_misses += 1;

        // Check L2
        if let Some(mut entry) = self.l2.get(outpoint) {
            stats.l2_hits += 1;

            // Check if should promote to L1
            if self.l2.should_promote(outpoint) {
                entry.access_count = 0; // Reset for L1
                if let Some(evicted) = self.l1.insert(*outpoint, entry.clone()) {
                    // Demote evicted entry to L2
                    self.l2.insert(*outpoint, evicted)?;
                    stats.demotions += 1;
                }
                stats.promotions += 1;
            }

            return Ok(Some(entry));
        }
        stats.l2_misses += 1;

        // Check L3 (storage)
        if let Some((output, height, is_coinbase)) = self.storage.get(outpoint)? {
            stats.l3_hits += 1;

            let entry = CacheEntry::new(output, height, is_coinbase);

            // Insert into L2 (or L1 if hot)
            self.l2.insert(*outpoint, entry.clone())?;

            return Ok(Some(entry));
        }
        stats.l3_misses += 1;

        Ok(None)
    }

    /// Insert or update a UTXO in the cache
    pub async fn put(
        &self,
        outpoint: OutPoint,
        output: TxOut,
        height: u32,
        is_coinbase: bool,
    ) -> Result<()> {
        let mut entry = CacheEntry::new(output, height, is_coinbase);
        entry.mark_dirty();

        // Insert into L1 (will cascade down if needed)
        if let Some(evicted) = self.l1.insert(outpoint, entry) {
            // Write evicted entry if dirty
            if evicted.is_dirty {
                self.write_to_storage(&outpoint, &evicted).await?;
            }
            // Insert into L2
            self.l2.insert(outpoint, evicted)?;
        }

        Ok(())
    }

    /// Remove a UTXO from all cache levels
    pub async fn remove(&self, outpoint: &OutPoint) -> Result<()> {
        // Remove from all levels
        self.l1.remove(outpoint);
        self.l2.remove(outpoint);
        self.storage.delete(outpoint)?;
        Ok(())
    }

    /// Flush all dirty entries to storage
    pub async fn flush(&self) -> Result<()> {
        let dirty_entries = self.l1.get_dirty_entries();

        for (outpoint, entry) in dirty_entries {
            self.write_to_storage(&outpoint, &entry).await?;
            self.l1.mark_clean(&outpoint);
        }

        self.storage.flush()?;
        self.stats.write().flushes += 1;

        Ok(())
    }

    async fn write_to_storage(&self, outpoint: &OutPoint, entry: &CacheEntry) -> Result<()> {
        self.storage
            .put(outpoint, &entry.output, entry.height, entry.is_coinbase)?;
        Ok(())
    }

    fn start_flush_task(&self) -> tokio::task::JoinHandle<()> {
        let l1 = self.l1.clone();
        let storage = self.storage.clone();
        let flush_interval = self.config.flush_interval;
        let stats = self.stats.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(flush_interval);

            loop {
                interval.tick().await;

                let dirty_entries = l1.get_dirty_entries();
                if dirty_entries.is_empty() {
                    continue;
                }

                debug!("Flushing {} dirty entries to storage", dirty_entries.len());

                for (outpoint, entry) in dirty_entries {
                    if let Err(e) =
                        storage.put(&outpoint, &entry.output, entry.height, entry.is_coinbase)
                    {
                        warn!("Failed to flush UTXO {}: {}", outpoint, e);
                    } else {
                        l1.mark_clean(&outpoint);
                    }
                }

                if let Err(e) = storage.flush() {
                    warn!("Failed to flush storage: {}", e);
                }

                stats.write().flushes += 1;
            }
        })
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let mut stats = self.stats.read().clone();
        let l1_stats = self.l1.stats();
        let l2_stats = self.l2.stats();

        stats.l1_hits = l1_stats.hits;
        stats.l1_misses = l1_stats.misses;
        stats.l2_hits = l2_stats.hits;
        stats.l2_misses = l2_stats.misses;

        stats
    }

    /// Clear all cache levels
    pub async fn clear(&self) -> Result<()> {
        self.flush().await?;
        self.l1.clear();
        // L2 clear would need implementation
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Amount;

    struct MockStorage {
        data: Arc<RwLock<HashMap<OutPoint, (TxOut, u32, bool)>>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                data: Arc::new(RwLock::new(HashMap::new())),
            }
        }
    }

    impl UtxoStorage for MockStorage {
        fn get(&self, outpoint: &OutPoint) -> Result<Option<(TxOut, u32, bool)>> {
            Ok(self.data.read().get(outpoint).cloned())
        }

        fn put(
            &self,
            outpoint: &OutPoint,
            output: &TxOut,
            height: u32,
            is_coinbase: bool,
        ) -> Result<()> {
            self.data
                .write()
                .insert(*outpoint, (output.clone(), height, is_coinbase));
            Ok(())
        }

        fn delete(&self, outpoint: &OutPoint) -> Result<()> {
            self.data.write().remove(outpoint);
            Ok(())
        }

        fn flush(&self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_l1_cache_basic() {
        let cache = L1Cache::new(10, 1_000_000);
        let outpoint = OutPoint::default();
        let output = TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        };

        let entry = CacheEntry::new(output.clone(), 100, false);

        // Insert and retrieve
        assert!(cache.insert(outpoint, entry.clone()).is_none());
        assert!(cache.get(&outpoint).is_some());

        // Check stats
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
    }

    #[tokio::test]
    async fn test_multi_level_cache() {
        let storage = Arc::new(MockStorage::new());
        let config = CacheConfig {
            l1_size: 5,
            l2_size: 10,
            ..Default::default()
        };

        let cache = MultiLevelCache::new(storage.clone(), config).unwrap();

        let outpoint = OutPoint::default();
        let output = TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        };

        // Insert into cache
        cache
            .put(outpoint, output.clone(), 100, false)
            .await
            .unwrap();

        // Should be in L1
        let entry = cache.get(&outpoint).await.unwrap();
        assert!(entry.is_some());

        let stats = cache.stats();
        assert_eq!(stats.l1_hits, 1);
        assert_eq!(stats.l1_misses, 0);
    }
}
