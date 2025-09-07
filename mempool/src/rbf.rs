use anyhow::{bail, Result};
use bitcoin::consensus::encode::serialize;
use bitcoin::{OutPoint, Transaction, TxOut, Txid};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, trace};

use std::future::Future;
use std::pin::Pin;

/// UTXO provider for fee calculation
pub trait UtxoProvider: Send + Sync {
    /// Get UTXO for an outpoint
    fn get_utxo(
        &self,
        outpoint: &OutPoint,
    ) -> Pin<Box<dyn Future<Output = Result<Option<TxOut>>> + Send + '_>>;
}

/// RBF (Replace-By-Fee) policy for mempool
/// Implements BIP125 opt-in full replace-by-fee
pub struct RBFPolicy {
    /// Minimum fee rate increase for replacement (in sat/vB)
    min_relay_fee_rate: u64,

    /// Minimum absolute fee increase
    min_replacement_fee_increment: u64,

    /// Maximum number of transactions that can be replaced
    max_replacement_candidates: usize,

    /// Maximum size of all replaced transactions
    max_replacement_size: usize,

    /// Allow full RBF (replace even non-signaling transactions)
    full_rbf_enabled: bool,

    /// UTXO provider for fee calculation
    utxo_provider: Arc<dyn UtxoProvider>,
}

impl RBFPolicy {
    pub fn new(utxo_provider: Arc<dyn UtxoProvider>) -> Self {
        Self {
            min_relay_fee_rate: 1,               // 1 sat/vB minimum
            min_replacement_fee_increment: 1000, // 1000 sats minimum increase
            max_replacement_candidates: 100,     // Max 100 transactions can be replaced
            max_replacement_size: 101_000,       // 101 KB max size of replaced txs
            full_rbf_enabled: false,             // BIP125 opt-in only by default
            utxo_provider,
        }
    }

    /// Enable full RBF (replace any transaction)
    pub fn enable_full_rbf(&mut self) {
        self.full_rbf_enabled = true;
    }

    /// Check if a transaction signals RBF (BIP125)
    pub fn signals_rbf(tx: &Transaction) -> bool {
        // A transaction signals RBF if any of its inputs have a sequence number < 0xfffffffe
        tx.input.iter().any(|input| input.sequence.0 < 0xfffffffe)
    }

    /// Check if a transaction can be replaced according to policy
    pub async fn can_replace(
        &self,
        replacement_tx: &Transaction,
        conflicting_txs: &[Transaction],
        mempool_descendants: &HashMap<Txid, Vec<Txid>>,
    ) -> Result<ReplacementCheck> {
        let replacement_txid = replacement_tx.compute_txid();
        debug!(
            "Checking RBF replacement for transaction {}",
            replacement_txid
        );

        // BIP125 Rule #1: Original transactions must signal replaceability
        // unless full RBF is enabled
        if !self.full_rbf_enabled {
            for tx in conflicting_txs {
                if !Self::signals_rbf(tx) {
                    bail!(
                        "BIP125 Rule #1: Transaction {} does not signal RBF and full RBF is not enabled",
                        tx.compute_txid()
                    );
                }
            }
        }

        // BIP125 Rule #2: The replacement must not add any new unconfirmed inputs
        let replacement_inputs: HashSet<_> = replacement_tx
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect();

        let mut original_inputs = HashSet::new();
        for tx in conflicting_txs {
            for input in &tx.input {
                original_inputs.insert(input.previous_output);
            }
        }

        // Check for new unconfirmed inputs
        for input in &replacement_inputs {
            if !original_inputs.contains(input) {
                // This is a new input - verify it's confirmed
                let utxo = self.utxo_provider.get_utxo(input).await?;
                if utxo.is_none() {
                    // If not in UTXO set, it might be unconfirmed
                    bail!(
                        "BIP125 Rule #2: Replacement adds new unconfirmed input {:?}",
                        input
                    );
                }
            }
        }

        // Calculate fees and sizes
        let replacement_fee = self.calculate_fee(replacement_tx).await?;
        let replacement_size = serialize(replacement_tx).len();
        let replacement_vsize = self.calculate_vsize(replacement_tx);
        let replacement_fee_rate = (replacement_fee as f64 / replacement_vsize as f64) as u64;

        let mut total_replaced_fee = 0u64;
        let mut total_replaced_size = 0usize;
        let mut all_conflicts = Vec::new();

        // Collect all transactions that would be evicted (direct conflicts + descendants)
        for tx in conflicting_txs {
            let txid = tx.compute_txid();
            all_conflicts.push(txid);

            let fee = self.calculate_fee(tx).await?;
            let size = serialize(tx).len();
            total_replaced_fee += fee;
            total_replaced_size += size;

            // Add descendants if any
            if let Some(descendants) = mempool_descendants.get(&txid) {
                for desc_txid in descendants {
                    all_conflicts.push(*desc_txid);
                    // Would need to fetch descendant tx to calculate fee/size
                    // For now, estimate
                    total_replaced_fee += 1000; // Placeholder
                    total_replaced_size += 250; // Placeholder
                }
            }
        }

        // BIP125 Rule #5: Number of replaced transactions must not exceed limit
        if all_conflicts.len() > self.max_replacement_candidates {
            bail!(
                "BIP125 Rule #5: Replacement would evict {} transactions, exceeding limit of {}",
                all_conflicts.len(),
                self.max_replacement_candidates
            );
        }

        // Additional check: Total size of replaced transactions must not exceed limit
        if total_replaced_size > self.max_replacement_size {
            bail!(
                "Total size of replaced transactions ({} bytes) exceeds limit of {} bytes",
                total_replaced_size,
                self.max_replacement_size
            );
        }

        // BIP125 Rule #3: Replacement must pay more absolute fee
        let required_fee = total_replaced_fee + self.min_replacement_fee_increment;
        if replacement_fee < required_fee {
            bail!(
                "BIP125 Rule #3: Replacement fee {} is less than required fee {} (original {} + increment {})",
                replacement_fee,
                required_fee,
                total_replaced_fee,
                self.min_replacement_fee_increment
            );
        }

        // BIP125 Rule #4: Replacement must pay higher fee rate than all replaced transactions
        let total_replaced_vsize = self.calculate_total_vsize(conflicting_txs);
        let replaced_fee_rate = if total_replaced_vsize > 0 {
            (total_replaced_fee as f64 / total_replaced_vsize as f64) as u64
        } else {
            0
        };

        if replacement_fee_rate <= replaced_fee_rate {
            bail!(
                "BIP125 Rule #4: Replacement fee rate {} sat/vB must be higher than replaced rate {} sat/vB",
                replacement_fee_rate,
                replaced_fee_rate
            );
        }

        // Additional check: Minimum relay fee rate
        if replacement_fee_rate < self.min_relay_fee_rate {
            bail!(
                "Replacement fee rate {} sat/vB is below minimum relay rate {}",
                replacement_fee_rate,
                self.min_relay_fee_rate
            );
        }

        info!(
            "RBF replacement approved: {} replaces {} transactions, fee {} -> {}",
            replacement_txid,
            all_conflicts.len(),
            total_replaced_fee,
            replacement_fee
        );

        Ok(ReplacementCheck {
            can_replace: true,
            replacement_fee,
            replacement_fee_rate,
            replaced_transactions: all_conflicts,
            total_replaced_fee,
            fee_delta: replacement_fee as i64 - total_replaced_fee as i64,
        })
    }

    /// Calculate virtual size (vsize) of a transaction
    fn calculate_vsize(&self, tx: &Transaction) -> usize {
        // vsize = (weight + 3) / 4
        let weight = tx.weight().to_wu() as usize;
        (weight + 3) / 4
    }

    /// Calculate total vsize of multiple transactions
    fn calculate_total_vsize(&self, txs: &[Transaction]) -> usize {
        txs.iter().map(|tx| self.calculate_vsize(tx)).sum()
    }

    /// Calculate transaction fee by looking up actual UTXO values
    async fn calculate_fee(&self, tx: &Transaction) -> Result<u64> {
        let mut input_sum = 0u64;

        // Look up the value of each input from the UTXO set
        for input in &tx.input {
            if input.previous_output.is_null() {
                // Coinbase input has no previous output
                continue;
            }

            match self.utxo_provider.get_utxo(&input.previous_output).await? {
                Some(utxo) => {
                    input_sum = input_sum.saturating_add(utxo.value.to_sat());
                }
                None => {
                    bail!("Input UTXO not found: {:?}", input.previous_output);
                }
            }
        }

        // Calculate sum of outputs
        let output_sum: u64 = tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .fold(0u64, |acc, val| acc.saturating_add(val));

        // Fee = inputs - outputs
        if input_sum < output_sum {
            bail!(
                "Transaction outputs exceed inputs: {} < {}",
                input_sum,
                output_sum
            );
        }

        Ok(input_sum.saturating_sub(output_sum))
    }

    /// Simple validation method for tests
    pub fn validate_replacement(
        &self,
        candidate: &ReplacementCandidate,
        conflict_fees: &HashMap<Txid, bitcoin::Amount>,
    ) -> Result<()> {
        // BIP125 Rule 5: Check that we're not evicting too many transactions
        // The total number of transactions being evicted (including descendants)
        // cannot exceed 100
        if candidate.conflicts.len() > 100 {
            bail!(
                "Too many transactions would be evicted: {} > 100 (BIP125 Rule 5)",
                candidate.conflicts.len()
            );
        }

        // Calculate total fee being replaced
        let total_replaced_fee: u64 = conflict_fees.values().map(|amt| amt.to_sat()).sum();

        // Check minimum fee increment
        let replacement_fee = candidate.fee.to_sat();
        let required_fee = total_replaced_fee + self.min_replacement_fee_increment;

        if replacement_fee < required_fee {
            bail!(
                "Insufficient fee: {} < {} (original {} + increment {})",
                replacement_fee,
                required_fee,
                total_replaced_fee,
                self.min_replacement_fee_increment
            );
        }

        Ok(())
    }
}

/// Candidate transaction for replacement
#[derive(Debug, Clone)]
pub struct ReplacementCandidate {
    /// The replacement transaction
    pub transaction: Transaction,
    /// Fee of the replacement transaction
    pub fee: bitcoin::Amount,
    /// Size of the transaction in bytes
    pub size: usize,
    /// Weight of the transaction
    pub weight: usize,
    /// Ancestor transactions
    pub ancestors: HashSet<Txid>,
    /// Conflicting transactions that would be replaced
    pub conflicts: Vec<Txid>,
}

/// Result of RBF replacement check
#[derive(Debug, Clone)]
pub struct ReplacementCheck {
    /// Whether the replacement is allowed
    pub can_replace: bool,

    /// Fee of the replacement transaction
    pub replacement_fee: u64,

    /// Fee rate of the replacement transaction (sat/vB)
    pub replacement_fee_rate: u64,

    /// Transactions that would be replaced
    pub replaced_transactions: Vec<Txid>,

    /// Total fee of replaced transactions
    pub total_replaced_fee: u64,

    /// Fee delta (positive means replacement pays more)
    pub fee_delta: i64,
}

/// RBF conflict tracker
pub struct RBFConflictTracker {
    /// Map of outpoints to transactions spending them
    spends_by_outpoint: HashMap<OutPoint, HashSet<Txid>>,

    /// Map of transactions to their conflicts
    conflicts: HashMap<Txid, HashSet<Txid>>,
}

impl Default for RBFConflictTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RBFConflictTracker {
    pub fn new() -> Self {
        Self {
            spends_by_outpoint: HashMap::new(),
            conflicts: HashMap::new(),
        }
    }

    /// Add a transaction to the tracker
    pub fn add_transaction(&mut self, tx: &Transaction) {
        let txid = tx.compute_txid();

        for input in &tx.input {
            self.spends_by_outpoint
                .entry(input.previous_output)
                .or_default()
                .insert(txid);
        }
    }

    /// Remove a transaction from the tracker
    pub fn remove_transaction(&mut self, tx: &Transaction) {
        let txid = tx.compute_txid();

        for input in &tx.input {
            if let Some(spenders) = self.spends_by_outpoint.get_mut(&input.previous_output) {
                spenders.remove(&txid);
                if spenders.is_empty() {
                    self.spends_by_outpoint.remove(&input.previous_output);
                }
            }
        }

        self.conflicts.remove(&txid);
    }

    /// Find conflicting transactions for a given transaction
    pub fn find_conflicts(&self, tx: &Transaction) -> Vec<Txid> {
        let mut conflicts = HashSet::new();

        for input in &tx.input {
            if let Some(spenders) = self.spends_by_outpoint.get(&input.previous_output) {
                for &spender_txid in spenders {
                    if spender_txid != tx.compute_txid() {
                        conflicts.insert(spender_txid);
                    }
                }
            }
        }

        conflicts.into_iter().collect()
    }

    /// Check if two transactions conflict
    pub fn conflicts_with(&self, tx1: &Transaction, tx2: &Transaction) -> bool {
        // Two transactions conflict if they spend the same output
        for input1 in &tx1.input {
            for input2 in &tx2.input {
                if input1.previous_output == input2.previous_output {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, TxIn, TxOut};

    fn create_test_transaction(sequence: u32) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence(sequence),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn test_rbf_signaling() {
        // Transaction with sequence < 0xfffffffe signals RBF
        let rbf_tx = create_test_transaction(0xfffffffd);
        assert!(RBFPolicy::signals_rbf(&rbf_tx));

        // Transaction with sequence = 0xfffffffe does not signal RBF
        let non_rbf_tx = create_test_transaction(0xfffffffe);
        assert!(!RBFPolicy::signals_rbf(&non_rbf_tx));

        // Transaction with max sequence does not signal RBF
        let final_tx = create_test_transaction(0xffffffff);
        assert!(!RBFPolicy::signals_rbf(&final_tx));
    }

    #[test]
    fn test_conflict_tracker() {
        let mut tracker = RBFConflictTracker::new();

        // Create two different transactions that spend the same output
        let tx1 = create_test_transaction(0xfffffffd);
        let mut tx2 = create_test_transaction(0xfffffffd);

        // Make tx2 different by changing the output value
        tx2.output[0].value = Amount::from_sat(40000);

        tracker.add_transaction(&tx1);
        tracker.add_transaction(&tx2);

        // Both transactions spend the same output, so they conflict
        assert!(tracker.conflicts_with(&tx1, &tx2));

        // Find conflicts
        let conflicts = tracker.find_conflicts(&tx1);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0], tx2.compute_txid());
    }
}
