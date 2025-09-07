use anyhow::{bail, Result};
use bitcoin::{Amount, Transaction, Txid};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info};

// Use the full-featured MempoolEntry from mempool_acceptance
use crate::mempool_acceptance::MempoolEntry;

/// Complete mempool manager with expiration and eviction
pub struct MempoolManager {
    /// Configuration
    config: MempoolManagerConfig,

    /// Transaction entries
    entries: Arc<RwLock<HashMap<Txid, MempoolEntry>>>,

    /// Fee-sorted index (fee rate -> txids)
    by_feerate: Arc<RwLock<BTreeMap<u64, HashSet<Txid>>>>,

    /// Time-sorted index (timestamp -> txids)
    by_time: Arc<RwLock<BTreeMap<u64, HashSet<Txid>>>>,

    /// Ancestor index (txid -> ancestor txids)
    ancestors: Arc<RwLock<HashMap<Txid, HashSet<Txid>>>>,

    /// Descendant index (txid -> descendant txids)
    descendants: Arc<RwLock<HashMap<Txid, HashSet<Txid>>>>,

    /// Total size in bytes
    total_size: Arc<RwLock<usize>>,

    /// Total fees
    total_fees: Arc<RwLock<Amount>>,

    /// Statistics
    stats: Arc<RwLock<MempoolStats>>,
}

/// Mempool statistics
#[derive(Debug, Default, Clone)]
pub struct MempoolStats {
    pub size: usize,
    pub bytes: usize,
    pub usage: usize,
    pub total_fee: Amount,
    pub mempoolminfee: Amount,
    pub minrelaytxfee: Amount,
    pub expired_count: u64,
    pub evicted_count: u64,
    pub replaced_count: u64,
}

/// Enhanced mempool manager configuration
#[derive(Debug, Clone)]
pub struct MempoolManagerConfig {
    /// Maximum mempool size in bytes
    pub max_size_bytes: usize,

    /// Maximum mempool size in memory usage
    pub max_memory_usage: usize,

    /// Transaction expiration time
    pub expiry_time: Duration,

    /// Minimum fee rate (sat/vB)
    pub min_fee_rate: u64,

    /// Maximum ancestors
    pub max_ancestors: usize,

    /// Maximum descendants
    pub max_descendants: usize,

    /// Maximum package size
    pub max_package_size: usize,

    /// Enable RBF
    pub enable_rbf: bool,

    /// Enable full RBF
    pub full_rbf: bool,
}

impl Default for MempoolManagerConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 300_000_000,                      // 300 MB
            max_memory_usage: 400_000_000,                    // 400 MB memory
            expiry_time: Duration::from_secs(14 * 24 * 3600), // 14 days
            min_fee_rate: 1,                                  // 1 sat/vB minimum
            max_ancestors: 25,
            max_descendants: 25,
            max_package_size: 101_000, // 101 KB
            enable_rbf: true,
            full_rbf: false,
        }
    }
}

impl MempoolManager {
    /// Create new mempool manager
    pub fn new(config: MempoolManagerConfig) -> Self {
        Self {
            config,
            entries: Arc::new(RwLock::new(HashMap::new())),
            by_feerate: Arc::new(RwLock::new(BTreeMap::new())),
            by_time: Arc::new(RwLock::new(BTreeMap::new())),
            ancestors: Arc::new(RwLock::new(HashMap::new())),
            descendants: Arc::new(RwLock::new(HashMap::new())),
            total_size: Arc::new(RwLock::new(0)),
            total_fees: Arc::new(RwLock::new(Amount::ZERO)),
            stats: Arc::new(RwLock::new(MempoolStats::default())),
        }
    }

    /// Add transaction to mempool
    pub async fn add_transaction(&self, tx: Transaction, fee: Amount, height: u32) -> Result<()> {
        let txid = tx.compute_txid();
        let size = tx.vsize();
        let fee_rate = (fee.to_sat() * 1000 / size as u64) / 1000; // sat/vB

        // Check minimum fee rate
        if fee_rate < self.config.min_fee_rate {
            bail!(
                "Transaction fee rate {} sat/vB below minimum {}",
                fee_rate,
                self.config.min_fee_rate
            );
        }

        // Check if already in mempool
        if self.contains(&txid).await {
            bail!("Transaction {} already in mempool", txid);
        }

        // Check mempool size limit
        let current_size = *self.total_size.read().await;
        if current_size + size > self.config.max_size_bytes {
            // Try to evict lower fee transactions
            if !self.try_evict_for_space(size, fee_rate).await? {
                bail!("Mempool full, transaction fee too low for eviction");
            }
        }

        // Find ancestors and descendants
        let (ancestors, descendants) = self.find_relatives(&tx).await?;

        // Check ancestor/descendant limits
        if ancestors.len() > self.config.max_ancestors {
            bail!("Transaction exceeds ancestor limit");
        }
        if descendants.len() > self.config.max_descendants {
            bail!("Transaction exceeds descendant limit");
        }

        // Create entry
        let entry = MempoolEntry {
            tx: tx.clone(),
            txid: tx.compute_txid(),
            wtxid: tx.compute_txid(), // MempoolEntry expects Txid type for wtxid
            fee: fee.to_sat(),
            vsize: tx.vsize(),
            weight: tx.weight().to_wu() as usize,
            fee_rate: fee_rate as f64,
            time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            height,
            ancestors: ancestors.clone(),
            descendants: descendants.clone(),
            rbf: tx.input.iter().any(|input| input.sequence.is_rbf()),
        };

        // Add to mempool
        {
            let mut entries = self.entries.write().await;
            entries.insert(txid, entry.clone());
        }

        // Update indices
        {
            let mut by_fee = self.by_feerate.write().await;
            by_fee
                .entry(fee_rate)
                .or_insert_with(HashSet::new)
                .insert(txid);
        }

        {
            let mut by_time = self.by_time.write().await;
            by_time
                .entry(entry.time)
                .or_insert_with(HashSet::new)
                .insert(txid);
        }

        // Update relationships
        {
            let mut anc = self.ancestors.write().await;
            anc.insert(txid, ancestors.clone());
        }

        {
            let mut desc = self.descendants.write().await;
            desc.insert(txid, descendants.clone());
        }

        // Update totals
        {
            let mut total_size = self.total_size.write().await;
            *total_size += size;
        }

        {
            let mut total_fees = self.total_fees.write().await;
            *total_fees += fee;
        }

        // Update stats
        self.update_stats().await;

        debug!(
            "Added transaction {} to mempool (fee rate: {} sat/vB)",
            txid, fee_rate
        );

        Ok(())
    }

    /// Remove transaction from mempool
    pub async fn remove_transaction(&self, txid: &Txid) -> Result<bool> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.remove(txid) {
            // Remove from indices
            {
                let mut by_fee = self.by_feerate.write().await;
                if let Some(set) = by_fee.get_mut(&(entry.fee_rate as u64)) {
                    set.remove(txid);
                    if set.is_empty() {
                        by_fee.remove(&(entry.fee_rate as u64));
                    }
                }
            }

            {
                let mut by_time = self.by_time.write().await;
                if let Some(set) = by_time.get_mut(&entry.time) {
                    set.remove(txid);
                    if set.is_empty() {
                        by_time.remove(&entry.time);
                    }
                }
            }

            // Remove relationships
            {
                let mut anc = self.ancestors.write().await;
                anc.remove(txid);
            }

            {
                let mut desc = self.descendants.write().await;
                desc.remove(txid);
            }

            // Update totals
            {
                let mut total_size = self.total_size.write().await;
                *total_size = total_size.saturating_sub(entry.tx.vsize());
            }

            {
                let mut total_fees = self.total_fees.write().await;
                *total_fees = total_fees
                    .checked_sub(Amount::from_sat(entry.fee))
                    .unwrap_or(Amount::ZERO);
            }

            debug!("Removed transaction {} from mempool", txid);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Expire old transactions
    pub async fn expire_transactions(&self) -> Result<Vec<Txid>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let expiry_time = self.config.expiry_time.as_secs();
        let cutoff = now.saturating_sub(expiry_time);

        let mut expired = Vec::new();

        // Find expired transactions
        {
            let by_time = self.by_time.read().await;
            for (&time, txids) in by_time.iter() {
                if time >= cutoff {
                    break; // Times are sorted, so we can stop here
                }
                expired.extend(txids.iter().copied());
            }
        }

        // Remove expired transactions
        for txid in &expired {
            self.remove_transaction(txid).await?;
        }

        if !expired.is_empty() {
            info!("Expired {} transactions from mempool", expired.len());

            let mut stats = self.stats.write().await;
            stats.expired_count += expired.len() as u64;
        }

        Ok(expired)
    }

    /// Evict transactions by fee rate to make space
    pub async fn try_evict_for_space(&self, needed_size: usize, min_fee_rate: u64) -> Result<bool> {
        let mut evicted = Vec::new();
        let mut freed_size = 0usize;

        // Get transactions sorted by fee rate (ascending)
        let by_fee = self.by_feerate.read().await;

        for (&fee_rate, txids) in by_fee.iter() {
            if fee_rate >= min_fee_rate {
                // Can't evict transactions with higher fee rate
                break;
            }

            for txid in txids {
                evicted.push(*txid);

                // Get size of transaction
                if let Some(entry) = self.entries.read().await.get(txid) {
                    freed_size += entry.tx.vsize();
                }

                if freed_size >= needed_size {
                    break;
                }
            }

            if freed_size >= needed_size {
                break;
            }
        }

        if freed_size < needed_size {
            return Ok(false); // Can't free enough space
        }

        // Remove evicted transactions
        for txid in &evicted {
            self.remove_transaction(txid).await?;
        }

        info!("Evicted {} transactions to make space", evicted.len());

        let mut stats = self.stats.write().await;
        stats.evicted_count += evicted.len() as u64;

        Ok(true)
    }

    /// Evict transactions by memory usage
    pub async fn evict_by_memory_usage(&self) -> Result<usize> {
        let current_usage = self.estimate_memory_usage().await;

        if current_usage <= self.config.max_memory_usage {
            return Ok(0);
        }

        let to_free = current_usage - self.config.max_memory_usage;
        let mut evicted = Vec::new();
        let mut freed = 0usize;

        // Evict lowest fee rate transactions first
        let by_fee = self.by_feerate.read().await;

        for (_, txids) in by_fee.iter() {
            for txid in txids {
                evicted.push(*txid);

                if let Some(entry) = self.entries.read().await.get(txid) {
                    freed += entry.tx.vsize() * 2; // Rough memory estimate
                }

                if freed >= to_free {
                    break;
                }
            }

            if freed >= to_free {
                break;
            }
        }

        // Remove evicted transactions
        for txid in &evicted {
            self.remove_transaction(txid).await?;
        }

        Ok(evicted.len())
    }

    /// Find ancestors and descendants of a transaction
    async fn find_relatives(&self, tx: &Transaction) -> Result<(HashSet<Txid>, HashSet<Txid>)> {
        let mut ancestors = HashSet::new();
        let mut descendants = HashSet::new();

        let entries = self.entries.read().await;

        // Find ancestors (transactions this tx depends on)
        for input in &tx.input {
            let parent_txid = input.previous_output.txid;
            if entries.contains_key(&parent_txid) {
                ancestors.insert(parent_txid);

                // Add ancestors of ancestors
                if let Some(parent_ancestors) = self.ancestors.read().await.get(&parent_txid) {
                    ancestors.extend(parent_ancestors);
                }
            }
        }

        // Find descendants (transactions that depend on this tx)
        let txid = tx.compute_txid();
        for (other_txid, entry) in entries.iter() {
            for input in &entry.tx.input {
                if input.previous_output.txid == txid {
                    descendants.insert(*other_txid);

                    // Add descendants of descendants
                    if let Some(child_descendants) = self.descendants.read().await.get(other_txid) {
                        descendants.extend(child_descendants);
                    }
                }
            }
        }

        Ok((ancestors, descendants))
    }

    /// Check if transaction is in mempool
    pub async fn contains(&self, txid: &Txid) -> bool {
        self.entries.read().await.contains_key(txid)
    }

    /// Get transaction from mempool
    pub async fn get_transaction(&self, txid: &Txid) -> Option<Transaction> {
        self.entries.read().await.get(txid).map(|e| e.tx.clone())
    }

    /// Get mempool size
    pub async fn size(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Get mempool size in bytes
    pub async fn size_bytes(&self) -> usize {
        *self.total_size.read().await
    }

    /// Estimate memory usage
    async fn estimate_memory_usage(&self) -> usize {
        let entries = self.entries.read().await;
        let base = entries.len() * std::mem::size_of::<MempoolEntry>();
        let tx_data = *self.total_size.read().await;
        base + tx_data * 2 // Rough estimate including indices
    }

    /// Update statistics
    async fn update_stats(&self) {
        let mut stats = self.stats.write().await;
        stats.size = self.entries.read().await.len();
        stats.bytes = *self.total_size.read().await;
        stats.usage = self.estimate_memory_usage().await;
        stats.total_fee = *self.total_fees.read().await;

        // Calculate minimum fee rate
        if let Some((&min_rate, _)) = self.by_feerate.read().await.iter().next() {
            stats.mempoolminfee = Amount::from_sat(min_rate);
        }
        stats.minrelaytxfee = Amount::from_sat(self.config.min_fee_rate);
    }

    /// Get mempool statistics
    pub async fn get_stats(&self) -> MempoolStats {
        self.stats.read().await.clone()
    }

    /// Clear entire mempool
    pub async fn clear(&self) {
        self.entries.write().await.clear();
        self.by_feerate.write().await.clear();
        self.by_time.write().await.clear();
        self.ancestors.write().await.clear();
        self.descendants.write().await.clear();
        *self.total_size.write().await = 0;
        *self.total_fees.write().await = Amount::ZERO;

        info!("Mempool cleared");
    }

    /// Get transactions for block template
    pub async fn select_transactions_for_block(&self, max_weight: usize) -> Vec<Transaction> {
        let mut selected = Vec::new();
        let mut total_weight = 0usize;

        let entries = self.entries.read().await;
        let by_fee = self.by_feerate.read().await;

        // Select highest fee rate transactions first
        for (_, txids) in by_fee.iter().rev() {
            for txid in txids {
                if let Some(entry) = entries.get(txid) {
                    let weight = entry.tx.weight().to_wu() as usize;

                    if total_weight + weight <= max_weight {
                        selected.push(entry.tx.clone());
                        total_weight += weight;
                    }

                    if total_weight >= max_weight {
                        break;
                    }
                }
            }

            if total_weight >= max_weight {
                break;
            }
        }

        selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Transaction;

    #[tokio::test]
    async fn test_mempool_expiration() -> Result<()> {
        let mut config = MempoolManagerConfig::default();
        config.expiry_time = Duration::from_secs(1); // 1 second for testing

        let mempool = MempoolManager::new(config);

        // Add a transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        mempool
            .add_transaction(tx.clone(), Amount::from_sat(1000), 100)
            .await?;
        assert_eq!(mempool.size().await, 1);

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Expire transactions
        let expired = mempool.expire_transactions().await?;
        assert_eq!(expired.len(), 1);
        assert_eq!(mempool.size().await, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_mempool_eviction() -> Result<()> {
        let mut config = MempoolManagerConfig::default();
        config.max_size_bytes = 1000; // Small size for testing

        let mempool = MempoolManager::new(config);

        // Add high fee transaction with realistic inputs
        let tx1 = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        mempool
            .add_transaction(tx1, Amount::from_sat(5000), 100)
            .await?;

        // Try to add low fee transaction with huge size (should fail)
        let mut large_outputs = vec![];
        for _ in 0..50 {
            large_outputs.push(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            });
        }

        let tx2 = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: {
                        use bitcoin::hashes::Hash;
                        bitcoin::Txid::from_raw_hash(
                            bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]),
                        )
                    },
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: large_outputs,
        };

        let result = mempool
            .add_transaction(tx2, Amount::from_sat(100), 101)
            .await;
        assert!(result.is_err()); // Should fail due to low fee

        assert_eq!(mempool.size().await, 1); // Only first transaction

        Ok(())
    }
}
