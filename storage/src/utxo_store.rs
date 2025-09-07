use anyhow::{bail, Context, Result};
use bitcoin::{Amount, OutPoint, TxOut, Txid};
use bitcoin_hashes::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, trace};

/// UTXO entry stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub output: TxOut,
    pub height: u32,
    pub is_coinbase: bool,
}

/// UTXO store for persistent UTXO set management
pub struct UtxoStore {
    db: Arc<sled::Tree>,
    cache: parking_lot::RwLock<HashMap<OutPoint, Option<UtxoEntry>>>,
    stats: parking_lot::RwLock<UtxoStats>,
}

/// UTXO statistics
#[derive(Debug, Default, Clone)]
pub struct UtxoStats {
    pub total_utxos: u64,
    pub total_amount: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub db_reads: u64,
    pub db_writes: u64,
}

impl UtxoStore {
    /// Create new UTXO store
    pub fn new(db: Arc<sled::Tree>) -> Self {
        Self {
            db,
            cache: parking_lot::RwLock::new(HashMap::new()),
            stats: parking_lot::RwLock::new(UtxoStats::default()),
        }
    }

    /// Get UTXO entry
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>> {
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(outpoint) {
                let mut stats = self.stats.write();
                stats.cache_hits += 1;
                return Ok(cached.clone());
            }
        }

        // Not in cache, read from database
        let mut stats = self.stats.write();
        stats.cache_misses += 1;
        stats.db_reads += 1;
        drop(stats);

        let key = self.encode_outpoint(outpoint);

        match self.db.get(key)? {
            Some(data) => {
                let entry: UtxoEntry =
                    bincode::deserialize(&data).context("Failed to deserialize UTXO entry")?;

                // Add to cache
                let mut cache = self.cache.write();
                cache.insert(*outpoint, Some(entry.clone()));

                Ok(Some(entry))
            }
            None => {
                // Add negative cache entry
                let mut cache = self.cache.write();
                cache.insert(*outpoint, None);

                Ok(None)
            }
        }
    }

    /// Add UTXO entry
    pub fn add_utxo(&self, outpoint: OutPoint, entry: UtxoEntry) -> Result<()> {
        let key = self.encode_outpoint(&outpoint);
        let value = bincode::serialize(&entry)?;

        self.db.insert(key, value)?;

        // Update cache
        let mut cache = self.cache.write();
        cache.insert(outpoint, Some(entry.clone()));

        // Update stats
        let mut stats = self.stats.write();
        stats.db_writes += 1;
        stats.total_utxos += 1;
        stats.total_amount += entry.output.value.to_sat();

        trace!("Added UTXO: {:?}", outpoint);
        Ok(())
    }

    /// Remove UTXO entry
    pub fn remove_utxo(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>> {
        let key = self.encode_outpoint(outpoint);

        // Get entry before removing
        let entry = self.get_utxo(outpoint)?;

        if entry.is_some() {
            self.db.remove(key)?;

            // Update cache
            let mut cache = self.cache.write();
            cache.insert(*outpoint, None);

            // Update stats
            let mut stats = self.stats.write();
            stats.db_writes += 1;
            stats.total_utxos = stats.total_utxos.saturating_sub(1);
            if let Some(ref e) = entry {
                stats.total_amount = stats.total_amount.saturating_sub(e.output.value.to_sat());
            }

            trace!("Removed UTXO: {:?}", outpoint);
        }

        Ok(entry)
    }

    /// Apply batch of UTXO changes
    pub fn apply_batch(&self, batch: UtxoBatch) -> Result<()> {
        // Group operations by type for efficiency
        let mut cache = self.cache.write();
        let mut stats = self.stats.write();

        // Process additions
        for (outpoint, entry) in &batch.additions {
            let key = self.encode_outpoint(outpoint);
            let value = bincode::serialize(&entry)?;

            self.db.insert(key, value)?;
            cache.insert(*outpoint, Some(entry.clone()));

            stats.total_utxos += 1;
            stats.total_amount += entry.output.value.to_sat();
            stats.db_writes += 1;
        }

        // Process removals
        for outpoint in &batch.removals {
            // Get entry for stats update
            if let Some(entry) = self.get_utxo_internal(outpoint)? {
                let key = self.encode_outpoint(outpoint);
                self.db.remove(key)?;
                cache.insert(*outpoint, None);

                stats.total_utxos = stats.total_utxos.saturating_sub(1);
                stats.total_amount = stats
                    .total_amount
                    .saturating_sub(entry.output.value.to_sat());
                stats.db_writes += 1;
            }
        }

        debug!(
            "Applied batch: {} additions, {} removals",
            batch.additions.len(),
            batch.removals.len()
        );

        Ok(())
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write();
        let size = cache.len();
        cache.clear();
        debug!("Cleared UTXO cache ({} entries)", size);
    }

    /// Get statistics
    pub fn get_stats(&self) -> UtxoStats {
        self.stats.read().clone()
    }

    /// Iterate over all UTXOs
    pub fn iter_utxos<F>(&self, mut f: F) -> Result<()>
    where
        F: FnMut(OutPoint, UtxoEntry) -> Result<bool>,
    {
        for item in self.db.iter() {
            let (key, value) = item?;

            let outpoint = self.decode_outpoint(&key)?;
            let entry: UtxoEntry = bincode::deserialize(&value)?;

            if !f(outpoint, entry)? {
                break;
            }
        }

        Ok(())
    }

    /// Get total UTXO count (expensive operation)
    pub fn count_utxos(&self) -> Result<u64> {
        Ok(self.db.len() as u64)
    }

    /// Calculate total value (expensive operation)
    pub fn calculate_total_value(&self) -> Result<Amount> {
        let mut total = 0u64;

        self.iter_utxos(|_, entry| {
            total += entry.output.value.to_sat();
            Ok(true)
        })?;

        Ok(Amount::from_sat(total))
    }

    /// Encode outpoint as database key
    fn encode_outpoint(&self, outpoint: &OutPoint) -> Vec<u8> {
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(&outpoint.txid.to_byte_array());
        key.extend_from_slice(&outpoint.vout.to_le_bytes());
        key
    }

    /// Decode database key to outpoint
    fn decode_outpoint(&self, key: &[u8]) -> Result<OutPoint> {
        if key.len() != 36 {
            bail!("Invalid outpoint key length");
        }

        let txid_bytes: [u8; 32] = key[0..32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid txid length"))?;
        let txid = Txid::from_byte_array(txid_bytes);
        let vout = u32::from_le_bytes([key[32], key[33], key[34], key[35]]);

        Ok(OutPoint { txid, vout })
    }

    /// Internal get without cache update
    fn get_utxo_internal(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>> {
        let key = self.encode_outpoint(outpoint);

        match self.db.get(key)? {
            Some(data) => {
                let entry: UtxoEntry = bincode::deserialize(&data)?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> Result<()> {
        debug!("Flushing UTXO store to disk");

        // Flush the sled database
        self.db.flush()?;

        debug!("UTXO store flushed successfully");
        Ok(())
    }

    /// Get cache size
    pub fn cache_size(&self) -> usize {
        self.cache.read().len()
    }

    /// Persist checkpoint metadata
    pub fn save_checkpoint(&self, height: u32, hash: &bitcoin::BlockHash) -> Result<()> {
        let checkpoint_key = b"checkpoint";
        let checkpoint_data = bincode::serialize(&(height, hash.to_byte_array()))?;
        self.db.insert(checkpoint_key, checkpoint_data)?;
        self.db.flush()?;
        debug!("Saved UTXO checkpoint at height {} ({})", height, hash);
        Ok(())
    }

    /// Load checkpoint metadata
    pub fn load_checkpoint(&self) -> Result<Option<(u32, bitcoin::BlockHash)>> {
        let checkpoint_key = b"checkpoint";
        match self.db.get(checkpoint_key)? {
            Some(data) => {
                let (height, hash_bytes): (u32, [u8; 32]) = bincode::deserialize(&data)?;
                let hash = bitcoin::BlockHash::from_byte_array(hash_bytes);
                Ok(Some((height, hash)))
            }
            None => Ok(None),
        }
    }
}

/// Batch of UTXO changes
pub struct UtxoBatch {
    pub additions: Vec<(OutPoint, UtxoEntry)>,
    pub removals: Vec<OutPoint>,
}

impl Default for UtxoBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl UtxoBatch {
    /// Create new empty batch
    pub fn new() -> Self {
        Self {
            additions: Vec::new(),
            removals: Vec::new(),
        }
    }

    /// Add UTXO to batch
    pub fn add(&mut self, outpoint: OutPoint, entry: UtxoEntry) {
        self.additions.push((outpoint, entry));
    }

    /// Remove UTXO from batch
    pub fn remove(&mut self, outpoint: OutPoint) {
        self.removals.push(outpoint);
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.additions.is_empty() && self.removals.is_empty()
    }

    /// Get batch size
    pub fn len(&self) -> usize {
        self.additions.len() + self.removals.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, ScriptBuf};
    use bitcoin_hashes::Hash;

    #[test]
    fn test_utxo_store() -> Result<()> {
        let db = sled::Config::new().temporary(true).open()?;
        let tree = db.open_tree("utxo")?;
        let store = UtxoStore::new(Arc::new(tree));

        // Create test UTXO
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };

        let entry = UtxoEntry {
            output: TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: ScriptBuf::new(),
            },
            height: 100,
            is_coinbase: false,
        };

        // Add UTXO
        store.add_utxo(outpoint, entry.clone())?;

        // Get UTXO
        let retrieved = store.get_utxo(&outpoint)?;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().height, 100);

        // Remove UTXO
        let removed = store.remove_utxo(&outpoint)?;
        assert!(removed.is_some());

        // Verify removed
        let retrieved = store.get_utxo(&outpoint)?;
        assert!(retrieved.is_none());

        Ok(())
    }

    #[test]
    fn test_utxo_batch() -> Result<()> {
        let db = sled::Config::new().temporary(true).open()?;
        let tree = db.open_tree("utxo")?;
        let store = UtxoStore::new(Arc::new(tree));

        let mut batch = UtxoBatch::new();

        // Add multiple UTXOs
        for i in 0..10 {
            let outpoint = OutPoint {
                txid: Txid::from_byte_array([i as u8; 32]),
                vout: 0,
            };

            let entry = UtxoEntry {
                output: TxOut {
                    value: Amount::from_sat(1000 * i as u64),
                    script_pubkey: ScriptBuf::new(),
                },
                height: i as u32,
                is_coinbase: false,
            };

            batch.add(outpoint, entry);
        }

        // Apply batch
        store.apply_batch(batch)?;

        // Verify all added
        let stats = store.get_stats();
        assert_eq!(stats.total_utxos, 10);

        Ok(())
    }
}
