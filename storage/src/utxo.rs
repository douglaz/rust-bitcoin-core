use anyhow::Result;
use bitcoin::{OutPoint, TxOut};
use lru::LruCache;
use parking_lot::RwLock;
use sled::{Db, Tree};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::debug;

pub struct UtxoSet {
    tree: Tree,
    cache: RwLock<LruCache<OutPoint, Option<TxOut>>>,
}

impl UtxoSet {
    pub fn new(db: Arc<Db>) -> Self {
        let tree = db.open_tree("utxo").expect("Failed to open utxo tree");
        let cache_size = NonZeroUsize::new(10000).unwrap();
        Self {
            tree,
            cache: RwLock::new(LruCache::new(cache_size)),
        }
    }

    pub fn add(&self, outpoint: OutPoint, output: TxOut) -> Result<()> {
        debug!("Adding UTXO: {:?}", outpoint);

        let key = self.serialize_outpoint(&outpoint);
        let value = bitcoin::consensus::encode::serialize(&output);

        self.tree.insert(key, value)?;

        // Update cache
        self.cache.write().put(outpoint, Some(output));

        Ok(())
    }

    pub fn spend(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        debug!("Spending UTXO: {:?}", outpoint);

        // Check cache first
        if let Some(cached) = self.cache.write().get(outpoint) {
            if cached.is_none() {
                return Ok(None); // Already spent
            }
        }

        let key = self.serialize_outpoint(outpoint);

        match self.tree.get(&key)? {
            Some(data) => {
                let output: TxOut = bitcoin::consensus::encode::deserialize(&data)?;

                // Remove from database
                self.tree.remove(key)?;

                // Update cache to mark as spent
                self.cache.write().put(*outpoint, None);

                Ok(Some(output))
            }
            None => Ok(None),
        }
    }

    pub fn get(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        // Check cache first
        if let Some(cached) = self.cache.write().get(outpoint) {
            return Ok(cached.clone());
        }

        let key = self.serialize_outpoint(outpoint);

        match self.tree.get(key)? {
            Some(data) => {
                let output: TxOut = bitcoin::consensus::encode::deserialize(&data)?;

                // Update cache
                self.cache.write().put(*outpoint, Some(output.clone()));

                Ok(Some(output))
            }
            None => {
                // Update cache
                self.cache.write().put(*outpoint, None);
                Ok(None)
            }
        }
    }

    // Async wrapper for compatibility
    pub async fn get_async(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        self.get(outpoint)
    }

    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.get(outpoint).unwrap_or(None).is_some()
    }

    pub fn flush(&self) -> Result<()> {
        // Cache is write-through, so just clear it
        self.cache.write().clear();
        Ok(())
    }

    fn serialize_outpoint(&self, outpoint: &OutPoint) -> Vec<u8> {
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(outpoint.txid.as_ref());
        key.extend_from_slice(&outpoint.vout.to_le_bytes());
        key
    }

    pub async fn get_stats(&self) -> Result<UtxoStats> {
        let mut total_count = 0u64;
        let mut total_amount = 0u64;

        // Iterate through all UTXOs to calculate stats
        for (_, value) in self.tree.iter().flatten() {
            if let Ok(output) = bitcoin::consensus::encode::deserialize::<TxOut>(&value) {
                total_count += 1;
                total_amount += output.value.to_sat();
            }
        }

        Ok(UtxoStats {
            count: total_count,
            total_amount,
            memory_usage: self.tree.len() as u64 * 100, // Rough estimate
        })
    }
}

/// UTXO set statistics
#[derive(Debug, Clone)]
pub struct UtxoStats {
    pub count: u64,
    pub total_amount: u64,
    pub memory_usage: u64,
}
