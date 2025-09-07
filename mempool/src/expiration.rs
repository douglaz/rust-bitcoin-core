use bitcoin::{Amount, Transaction, Txid};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::info;

/// Mempool expiration policy
#[derive(Debug, Clone)]
pub struct ExpirationPolicy {
    /// Maximum time a transaction can stay in mempool (seconds)
    pub max_mempool_age: u64,

    /// Minimum fee rate to keep transaction (sat/vB)
    pub min_fee_rate: u64,

    /// Maximum number of transactions in mempool
    pub max_mempool_size: usize,

    /// Maximum memory usage in bytes
    pub max_mempool_memory: usize,

    /// Expiration scan interval
    pub scan_interval: Duration,

    /// Enable RBF (Replace-By-Fee) eviction
    pub enable_rbf_eviction: bool,
}

impl Default for ExpirationPolicy {
    fn default() -> Self {
        Self {
            max_mempool_age: 336 * 3600,            // 2 weeks (336 hours)
            min_fee_rate: 1,                        // 1 sat/vB minimum
            max_mempool_size: 300_000,              // 300k transactions
            max_mempool_memory: 300_000_000,        // 300 MB
            scan_interval: Duration::from_secs(60), // Check every minute
            enable_rbf_eviction: true,
        }
    }
}

/// Transaction expiration entry
#[derive(Debug, Clone)]
pub struct ExpirationEntry {
    pub txid: Txid,
    pub entry_time: u64,
    pub fee_rate: u64,
    pub size: usize,
    pub descendant_count: u32,
    pub ancestor_count: u32,
}

/// Manages mempool transaction expiration
pub struct MempoolExpiration {
    /// Expiration policy
    policy: ExpirationPolicy,

    /// Tracked transactions by age
    by_age: VecDeque<ExpirationEntry>,

    /// Transactions indexed by txid
    entries: HashMap<Txid, ExpirationEntry>,

    /// Current mempool statistics
    stats: MempoolStats,
}

#[derive(Debug, Clone, Default)]
pub struct MempoolStats {
    pub total_size: usize,
    pub total_memory: usize,
    pub total_transactions: usize,
    pub expired_count: u64,
    pub evicted_count: u64,
}

impl MempoolExpiration {
    /// Create new expiration manager
    pub fn new(policy: ExpirationPolicy) -> Self {
        Self {
            policy,
            by_age: VecDeque::new(),
            entries: HashMap::new(),
            stats: MempoolStats::default(),
        }
    }

    /// Add transaction to expiration tracking
    pub fn add_transaction(
        &mut self,
        txid: Txid,
        tx: &Transaction,
        fee: Amount,
        entry_time: Option<u64>,
    ) {
        let size = bitcoin::consensus::encode::serialize(tx).len();
        let vsize = tx.vsize();
        let fee_rate = if vsize > 0 {
            fee.to_sat() / vsize as u64
        } else {
            0
        };

        let time = entry_time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        let entry = ExpirationEntry {
            txid,
            entry_time: time,
            fee_rate,
            size,
            descendant_count: 0,
            ancestor_count: 0,
        };

        // Add to tracking
        self.entries.insert(txid, entry.clone());
        self.by_age.push_back(entry);

        // Update stats
        self.stats.total_transactions += 1;
        self.stats.total_size += size;
        self.stats.total_memory += size;
    }

    /// Remove transaction from tracking
    pub fn remove_transaction(&mut self, txid: &Txid) -> Option<ExpirationEntry> {
        if let Some(entry) = self.entries.remove(txid) {
            // Remove from age queue
            self.by_age.retain(|e| e.txid != *txid);

            // Update stats
            self.stats.total_transactions = self.stats.total_transactions.saturating_sub(1);
            self.stats.total_size = self.stats.total_size.saturating_sub(entry.size);
            self.stats.total_memory = self.stats.total_memory.saturating_sub(entry.size);

            Some(entry)
        } else {
            None
        }
    }

    /// Check and expire old transactions
    pub fn expire_old_transactions(&mut self, current_time: u64) -> Vec<Txid> {
        let mut expired = Vec::new();

        // Check age-based expiration
        while let Some(entry) = self.by_age.front() {
            let age = current_time.saturating_sub(entry.entry_time);

            if age > self.policy.max_mempool_age {
                if let Some(entry) = self.by_age.pop_front() {
                    info!(
                        "Expiring transaction {} (age: {} hours)",
                        entry.txid,
                        age / 3600
                    );

                    self.entries.remove(&entry.txid);
                    expired.push(entry.txid);

                    // Update stats
                    self.stats.total_transactions = self.stats.total_transactions.saturating_sub(1);
                    self.stats.total_size = self.stats.total_size.saturating_sub(entry.size);
                    self.stats.total_memory = self.stats.total_memory.saturating_sub(entry.size);
                    self.stats.expired_count += 1;
                }
            } else {
                // Queue is ordered by age, so we can stop here
                break;
            }
        }

        expired
    }

    /// Evict transactions to meet size limits
    pub fn evict_for_size_limit(&mut self) -> Vec<Txid> {
        let mut evicted = Vec::new();

        // Check transaction count limit
        if self.stats.total_transactions > self.policy.max_mempool_size {
            let to_evict = self.stats.total_transactions - self.policy.max_mempool_size;
            evicted.extend(self.evict_lowest_fee_rate(to_evict));
        }

        // Check memory limit
        if self.stats.total_memory > self.policy.max_mempool_memory {
            let target_memory = self.policy.max_mempool_memory * 95 / 100; // Target 95% of limit
            evicted.extend(self.evict_until_memory_target(target_memory));
        }

        evicted
    }

    /// Evict transactions with lowest fee rate
    fn evict_lowest_fee_rate(&mut self, count: usize) -> Vec<Txid> {
        let mut evicted = Vec::new();

        // Sort by fee rate (lowest first)
        let mut sorted_entries: Vec<_> = self.entries.values().cloned().collect();
        sorted_entries.sort_by_key(|e| e.fee_rate);

        for entry in sorted_entries.iter().take(count) {
            if entry.fee_rate < self.policy.min_fee_rate {
                info!(
                    "Evicting low-fee transaction {} (fee rate: {} sat/vB)",
                    entry.txid, entry.fee_rate
                );

                self.remove_transaction(&entry.txid);
                evicted.push(entry.txid);
                self.stats.evicted_count += 1;
            }
        }

        evicted
    }

    /// Evict transactions until memory target is met
    fn evict_until_memory_target(&mut self, target_memory: usize) -> Vec<Txid> {
        let mut evicted = Vec::new();

        // Sort by fee rate (lowest first)
        let mut sorted_entries: Vec<_> = self.entries.values().cloned().collect();
        sorted_entries.sort_by_key(|e| e.fee_rate);

        for entry in sorted_entries {
            if self.stats.total_memory <= target_memory {
                break;
            }

            info!(
                "Evicting transaction {} for memory limit (size: {} bytes)",
                entry.txid, entry.size
            );

            self.remove_transaction(&entry.txid);
            evicted.push(entry.txid);
            self.stats.evicted_count += 1;
        }

        evicted
    }

    /// Check if transaction should be replaced (RBF)
    pub fn should_replace(&self, new_tx: &Transaction, new_fee: Amount) -> Option<Vec<Txid>> {
        if !self.policy.enable_rbf_eviction {
            return None;
        }

        let new_vsize = new_tx.vsize();
        let new_fee_rate = if new_vsize > 0 {
            new_fee.to_sat() / new_vsize as u64
        } else {
            return None;
        };

        // Find transactions that spend the same inputs
        let mut conflicts = Vec::new();
        let mut total_replaced_fee = 0u64;

        for input in &new_tx.input {
            // Check if any existing transaction spends this input
            for entry in self.entries.values() {
                // This would need actual UTXO tracking to work properly
                // For now, just demonstrate the structure
                if entry.fee_rate < new_fee_rate {
                    conflicts.push(entry.txid);
                    total_replaced_fee += entry.fee_rate * entry.size as u64;
                }
            }
        }

        // BIP125 rules: new fee must be higher than sum of replaced fees + relay fee
        let min_replacement_fee =
            total_replaced_fee + (self.policy.min_fee_rate * new_vsize as u64);

        if new_fee.to_sat() >= min_replacement_fee && !conflicts.is_empty() {
            Some(conflicts)
        } else {
            None
        }
    }

    /// Run periodic maintenance
    pub fn run_maintenance(&mut self) -> MaintenanceResult {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Expire old transactions
        let expired = self.expire_old_transactions(current_time);

        // Evict for size limits
        let evicted = self.evict_for_size_limit();

        // Log statistics
        if !expired.is_empty() || !evicted.is_empty() {
            info!(
                "Mempool maintenance: {} expired, {} evicted, {} remaining",
                expired.len(),
                evicted.len(),
                self.stats.total_transactions
            );
        }

        MaintenanceResult {
            expired_txids: expired,
            evicted_txids: evicted,
            stats: self.stats.clone(),
        }
    }

    /// Get current statistics
    pub fn get_stats(&self) -> &MempoolStats {
        &self.stats
    }

    /// Check if a transaction is being tracked
    pub fn has_transaction(&self, txid: &Txid) -> bool {
        self.entries.contains_key(txid)
    }

    /// Update descendant/ancestor counts
    pub fn update_package_info(&mut self, txid: &Txid, descendants: u32, ancestors: u32) {
        if let Some(entry) = self.entries.get_mut(txid) {
            entry.descendant_count = descendants;
            entry.ancestor_count = ancestors;
        }
    }
}

/// Result of maintenance operation
#[derive(Debug)]
pub struct MaintenanceResult {
    pub expired_txids: Vec<Txid>,
    pub evicted_txids: Vec<Txid>,
    pub stats: MempoolStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::hashes::Hash;

    #[test]
    fn test_expiration_policy_default() {
        let policy = ExpirationPolicy::default();
        assert_eq!(policy.max_mempool_age, 336 * 3600);
        assert_eq!(policy.min_fee_rate, 1);
        assert_eq!(policy.max_mempool_size, 300_000);
    }

    #[test]
    fn test_add_remove_transaction() {
        let mut expiration = MempoolExpiration::new(ExpirationPolicy::default());

        let txid = Txid::from_byte_array([1u8; 32]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        expiration.add_transaction(txid, &tx, Amount::from_sat(1000), None);
        assert_eq!(expiration.stats.total_transactions, 1);

        expiration.remove_transaction(&txid);
        assert_eq!(expiration.stats.total_transactions, 0);
    }

    #[test]
    fn test_expire_old_transactions() {
        let mut policy = ExpirationPolicy::default();
        policy.max_mempool_age = 3600; // 1 hour for testing

        let mut expiration = MempoolExpiration::new(policy);

        let txid = Txid::from_byte_array([1u8; 32]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Add transaction with old timestamp
        let old_time = 1000;
        expiration.add_transaction(txid, &tx, Amount::from_sat(1000), Some(old_time));

        // Expire after 2 hours
        let current_time = old_time + 7200;
        let expired = expiration.expire_old_transactions(current_time);

        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], txid);
        assert_eq!(expiration.stats.expired_count, 1);
    }
}
