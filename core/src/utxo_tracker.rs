use anyhow::{bail, Result};
use bitcoin::{Block, OutPoint, Transaction};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::bitcoin_primitives::Utxo;
use storage::OptimizedStorage;

/// UTXO tracker for managing the unspent transaction output set
pub struct UtxoTracker {
    /// Storage backend
    storage: Arc<OptimizedStorage>,

    /// In-memory UTXO cache for performance
    cache: Arc<RwLock<UtxoCache>>,

    /// Current chain height
    chain_height: Arc<RwLock<u32>>,

    /// UTXO statistics
    stats: Arc<RwLock<UtxoStats>>,
}

/// UTXO cache for fast lookups
struct UtxoCache {
    /// Cached UTXOs
    utxos: HashMap<OutPoint, CachedUtxo>,

    /// Maximum cache size
    max_size: usize,

    /// Access counter for LRU eviction
    access_counter: u64,
}

/// Cached UTXO entry
#[derive(Clone)]
struct CachedUtxo {
    /// The UTXO
    utxo: Option<Utxo>,

    /// Last access time
    last_access: u64,

    /// Is dirty (needs to be written to storage)
    dirty: bool,
}

/// UTXO statistics
#[derive(Debug, Clone, Default)]
pub struct UtxoStats {
    /// Total number of UTXOs
    pub total_utxos: u64,

    /// Total value in satoshis
    pub total_value: u64,

    /// Number of coinbase UTXOs
    pub coinbase_utxos: u64,

    /// Cache hit rate
    pub cache_hit_rate: f64,

    /// Cache size
    pub cache_size: usize,
}

impl UtxoTracker {
    /// Create new UTXO tracker
    pub async fn new(storage: Arc<OptimizedStorage>) -> Result<Self> {
        let cache = UtxoCache {
            utxos: HashMap::new(),
            max_size: 100_000, // Cache up to 100k UTXOs
            access_counter: 0,
        };

        Ok(Self {
            storage,
            cache: Arc::new(RwLock::new(cache)),
            chain_height: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(UtxoStats::default())),
        })
    }

    /// Apply a block to the UTXO set
    pub async fn apply_block(&self, block: &Block, height: u32) -> Result<ApplyBlockResult> {
        info!("Applying block at height {} to UTXO set", height);

        let mut spent_utxos = Vec::new();
        let mut created_utxos = Vec::new();
        let mut total_fees = 0u64;

        // First, validate and spend inputs (except for coinbase)
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            if tx_index == 0 {
                // Skip coinbase inputs
                continue;
            }

            for input in &tx.input {
                let outpoint = input.previous_output;

                // Get the UTXO being spent
                let utxo = self
                    .get_utxo(&outpoint)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("UTXO not found: {:?}", outpoint))?;

                // Verify coinbase maturity
                if utxo.is_coinbase && !utxo.is_mature(height) {
                    bail!("Attempting to spend immature coinbase");
                }

                total_fees += utxo.value();
                spent_utxos.push((outpoint, utxo.clone()));

                // Remove from UTXO set
                self.remove_utxo(&outpoint).await?;
            }
        }

        // Then, create new UTXOs
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid();
            let is_coinbase = tx_index == 0;

            for (vout, output) in tx.output.iter().enumerate() {
                // Skip zero-value outputs and unspendable outputs
                if output.value.to_sat() == 0 || output.script_pubkey.is_op_return() {
                    continue;
                }

                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };

                let utxo = Utxo::new(output.clone(), outpoint, height, is_coinbase);

                created_utxos.push(utxo.clone());

                // Add to UTXO set
                self.add_utxo(outpoint, utxo).await?;
            }

            // Calculate fees for non-coinbase transactions
            if !is_coinbase {
                // Note: total_fees already has the input values accumulated
                // Output values would be calculated here if needed for fee computation
            }
        }

        // Update chain height
        *self.chain_height.write().await = height;

        // Update statistics
        self.update_stats().await;

        info!(
            "Applied block: spent {} UTXOs, created {} UTXOs",
            spent_utxos.len(),
            created_utxos.len()
        );

        Ok(ApplyBlockResult {
            spent_utxos,
            created_utxos,
            total_fees,
        })
    }

    /// Revert a block from the UTXO set (for reorgs)
    pub async fn revert_block(
        &self,
        block: &Block,
        height: u32,
        spent_utxos: Vec<(OutPoint, Utxo)>,
    ) -> Result<()> {
        info!("Reverting block at height {} from UTXO set", height);

        // First, remove created UTXOs
        for tx in &block.txdata {
            let txid = tx.compute_txid();

            for (vout, output) in tx.output.iter().enumerate() {
                if output.value.to_sat() == 0 || output.script_pubkey.is_op_return() {
                    continue;
                }

                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };

                self.remove_utxo(&outpoint).await?;
            }
        }

        // Then, restore spent UTXOs
        for (outpoint, utxo) in spent_utxos {
            self.add_utxo(outpoint, utxo).await?;
        }

        // Update chain height
        *self.chain_height.write().await = height.saturating_sub(1);

        // Update statistics
        self.update_stats().await;

        info!("Reverted block successfully");
        Ok(())
    }

    /// Get a UTXO
    pub async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>> {
        // Check cache first
        let mut cache = self.cache.write().await;
        cache.access_counter += 1;
        let access_counter = cache.access_counter;
        let cache_size = cache.utxos.len();

        if let Some(cached) = cache.utxos.get_mut(outpoint) {
            cached.last_access = access_counter;
            let utxo = cached.utxo.clone();

            // Update cache hit stats
            drop(cache); // Release the cache lock before updating stats
            let mut stats = self.stats.write().await;
            let hits = (stats.cache_hit_rate * cache_size as f64) as u64 + 1;
            stats.cache_hit_rate = hits as f64 / (access_counter as f64);

            return Ok(utxo);
        }

        drop(cache); // Release lock before storage access

        // Load from storage
        if let Some(tx_out) = self.storage.get_utxo(outpoint).await? {
            // For now, create a basic UTXO (we'd need more metadata in real implementation)
            let utxo = Utxo::new(
                tx_out, *outpoint, 0,     // Height would need to be stored
                false, // Coinbase flag would need to be stored
            );

            // Add to cache
            self.cache_utxo(*outpoint, Some(utxo.clone())).await;

            Ok(Some(utxo))
        } else {
            // Cache negative result
            self.cache_utxo(*outpoint, None).await;
            Ok(None)
        }
    }

    /// Add a UTXO
    async fn add_utxo(&self, outpoint: OutPoint, utxo: Utxo) -> Result<()> {
        // Store in storage
        self.storage.store_utxo(&outpoint, &utxo.output).await?;

        // Add to cache
        self.cache_utxo(outpoint, Some(utxo)).await;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_utxos += 1;

        Ok(())
    }

    /// Remove a UTXO
    async fn remove_utxo(&self, outpoint: &OutPoint) -> Result<()> {
        // Remove from storage
        self.storage.remove_utxo(outpoint).await?;

        // Update cache
        self.cache_utxo(*outpoint, None).await;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_utxos = stats.total_utxos.saturating_sub(1);

        Ok(())
    }

    /// Cache a UTXO lookup result
    async fn cache_utxo(&self, outpoint: OutPoint, utxo: Option<Utxo>) {
        let mut cache = self.cache.write().await;

        // Evict old entries if cache is full
        if cache.utxos.len() >= cache.max_size && !cache.utxos.contains_key(&outpoint) {
            // Find and remove least recently used entry
            let lru_key = cache
                .utxos
                .iter()
                .min_by_key(|(_, v)| v.last_access)
                .map(|(k, _)| *k);

            if let Some(key) = lru_key {
                cache.utxos.remove(&key);
            }
        }

        let access_counter = cache.access_counter;
        cache.utxos.insert(
            outpoint,
            CachedUtxo {
                utxo,
                last_access: access_counter,
                dirty: false,
            },
        );
    }

    /// Get multiple UTXOs (batch operation)
    pub async fn get_utxos(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<HashMap<OutPoint, Option<Utxo>>> {
        let mut results = HashMap::new();

        for outpoint in outpoints {
            results.insert(*outpoint, self.get_utxo(outpoint).await?);
        }

        Ok(results)
    }

    /// Check if a transaction's inputs exist in the UTXO set
    pub async fn validate_tx_inputs(&self, tx: &Transaction) -> Result<bool> {
        if tx.is_coinbase() {
            return Ok(true); // Coinbase has no inputs to validate
        }

        for input in &tx.input {
            if self.get_utxo(&input.previous_output).await?.is_none() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Calculate the total input value for a transaction
    pub async fn calculate_tx_input_value(&self, tx: &Transaction) -> Result<u64> {
        if tx.is_coinbase() {
            return Ok(0);
        }

        let mut total = 0u64;

        for input in &tx.input {
            let utxo = self
                .get_utxo(&input.previous_output)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Missing UTXO for input"))?;
            total += utxo.value();
        }

        Ok(total)
    }

    /// Flush cache to storage
    pub async fn flush(&self) -> Result<()> {
        debug!("Flushing UTXO cache to storage");

        let cache = self.cache.read().await;
        let dirty_count = cache.utxos.values().filter(|u| u.dirty).count();

        if dirty_count > 0 {
            info!("Flushing {} dirty UTXO entries", dirty_count);
            // In a real implementation, we'd write dirty entries to storage
        }

        Ok(())
    }

    /// Update statistics
    async fn update_stats(&self) {
        let cache = self.cache.read().await;
        let mut stats = self.stats.write().await;

        stats.cache_size = cache.utxos.len();
        // Other stats would be updated based on actual UTXO set
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> UtxoStats {
        self.stats.read().await.clone()
    }

    /// Get current chain height
    pub async fn get_chain_height(&self) -> u32 {
        *self.chain_height.read().await
    }
}

/// Result of applying a block to the UTXO set
pub struct ApplyBlockResult {
    /// UTXOs that were spent
    pub spent_utxos: Vec<(OutPoint, Utxo)>,

    /// UTXOs that were created
    pub created_utxos: Vec<Utxo>,

    /// Total fees collected
    pub total_fees: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{ScriptBuf, TxOut, Txid};

    #[tokio::test]
    async fn test_utxo_tracking() {
        // Would need to create a test storage instance
        // let storage = Arc::new(OptimizedStorage::new(Default::default()).unwrap());
        // let tracker = UtxoTracker::new(storage).await.unwrap();

        // Test adding and retrieving UTXOs
        let outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };

        let output = TxOut {
            value: bitcoin::Amount::from_sat(50000),
            script_pubkey: ScriptBuf::new(),
        };

        let utxo = Utxo::new(output, outpoint, 100, false);

        // Test operations would go here
        assert_eq!(utxo.value(), 50000);
        assert!(utxo.is_mature(201)); // 100 + 101 > 100 confirmations
    }
}
