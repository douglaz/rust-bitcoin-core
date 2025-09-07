use anyhow::Result;
use bitcoin::{Amount, Transaction};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info};

/// Transaction entry for mining selection
#[derive(Debug, Clone)]
pub struct MiningCandidate {
    pub tx: Transaction,
    pub fee: Amount,
    pub fee_rate: u64, // satoshis per vbyte
    pub weight: usize,
    pub size: usize,
    pub ancestors: HashSet<bitcoin::Txid>,
    pub package_fee: Amount,
    pub package_weight: usize,
}

impl MiningCandidate {
    /// Calculate effective fee rate including ancestors
    pub fn effective_fee_rate(&self) -> u64 {
        if self.package_weight == 0 {
            return 0;
        }
        let package_vsize = self.package_weight.div_ceil(4);
        self.package_fee.to_sat() / package_vsize as u64
    }
}

/// Ordering for priority queue - higher fee rate first
impl Ord for MiningCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.effective_fee_rate().cmp(&other.effective_fee_rate())
    }
}

impl PartialOrd for MiningCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for MiningCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.effective_fee_rate() == other.effective_fee_rate()
    }
}

impl Eq for MiningCandidate {}

/// Transaction selection algorithm for block template creation
pub struct TransactionSelector {
    /// Maximum block weight (4M weight units)
    max_weight: usize,
    /// Reserved weight for coinbase transaction
    coinbase_reserved: usize,
    /// Minimum fee rate for inclusion
    min_fee_rate: u64,
    /// Maximum number of transactions to consider
    max_tx_count: usize,
}

impl Default for TransactionSelector {
    fn default() -> Self {
        Self {
            max_weight: 4_000_000,
            coinbase_reserved: 4000, // Reserve 1000 vbytes for coinbase
            min_fee_rate: 1,
            max_tx_count: 10000,
        }
    }
}

impl TransactionSelector {
    /// Create a new transaction selector with custom parameters
    pub fn new(max_weight: usize, min_fee_rate: u64) -> Self {
        Self {
            max_weight,
            coinbase_reserved: 4000,
            min_fee_rate,
            max_tx_count: 10000,
        }
    }

    /// Select transactions for mining using package-aware greedy algorithm
    pub fn select_transactions(
        &self,
        candidates: Vec<MiningCandidate>,
    ) -> Result<Vec<MiningCandidate>> {
        info!(
            "Selecting transactions from {} candidates",
            candidates.len()
        );

        // Filter by minimum fee rate
        let mut eligible: Vec<_> = candidates
            .into_iter()
            .filter(|c| c.fee_rate >= self.min_fee_rate)
            .collect();

        // Sort by effective fee rate (including ancestors)
        eligible.sort_by(|a, b| b.effective_fee_rate().cmp(&a.effective_fee_rate()));

        let mut selected = Vec::new();
        let mut selected_txids = HashSet::new();
        let mut total_weight = self.coinbase_reserved;
        let mut total_fees = Amount::ZERO;

        for candidate in eligible {
            // Skip if already selected (as ancestor of another tx)
            let txid = candidate.tx.compute_txid();
            if selected_txids.contains(&txid) {
                continue;
            }

            // Check if adding this package would exceed weight limit
            let package_weight = candidate.package_weight;
            if total_weight + package_weight > self.max_weight {
                debug!("Skipping tx {}: would exceed weight limit", txid);
                continue;
            }

            // Check if we've reached max transaction count
            if selected.len() >= self.max_tx_count {
                debug!("Reached maximum transaction count");
                break;
            }

            // Include any ancestors not already selected
            let _package_txs: Vec<bitcoin::Txid> = vec![];
            for ancestor_id in &candidate.ancestors {
                if !selected_txids.contains(ancestor_id) {
                    // Would need to find ancestor tx in candidates
                    // For now, just track the IDs
                    selected_txids.insert(*ancestor_id);
                }
            }

            // Add this transaction
            selected_txids.insert(txid);
            total_weight += candidate.weight;
            total_fees += candidate.fee;
            selected.push(candidate);
        }

        info!(
            "Selected {} transactions, total weight: {}, total fees: {} sats",
            selected.len(),
            total_weight,
            total_fees.to_sat()
        );

        Ok(selected)
    }

    /// Advanced selection using ancestor-descendant scoring
    pub fn select_with_packages(
        &self,
        candidates: Vec<MiningCandidate>,
        dependencies: &HashMap<bitcoin::Txid, HashSet<bitcoin::Txid>>,
    ) -> Result<Vec<MiningCandidate>> {
        // Build dependency graph
        let mut packages = self.build_packages(&candidates, dependencies)?;

        // Score packages by effective fee rate
        packages.sort_by(|a, b| {
            let a_rate = self.calculate_package_fee_rate(a);
            let b_rate = self.calculate_package_fee_rate(b);
            b_rate.cmp(&a_rate)
        });

        let mut selected = Vec::new();
        let mut selected_txids = HashSet::new();
        let mut total_weight = self.coinbase_reserved;

        for package in packages {
            let package_weight: usize = package.iter().map(|c| c.weight).sum();

            // Check weight limit
            if total_weight + package_weight > self.max_weight {
                continue;
            }

            // Add all transactions in package
            for candidate in package {
                let txid = candidate.tx.compute_txid();
                if !selected_txids.contains(&txid) {
                    selected_txids.insert(txid);
                    selected.push(candidate.clone());
                    total_weight += candidate.weight;
                }
            }
        }

        Ok(selected)
    }

    /// Build transaction packages based on dependencies
    fn build_packages(
        &self,
        candidates: &[MiningCandidate],
        dependencies: &HashMap<bitcoin::Txid, HashSet<bitcoin::Txid>>,
    ) -> Result<Vec<Vec<MiningCandidate>>> {
        let mut packages = Vec::new();
        let mut processed = HashSet::new();

        for candidate in candidates {
            let txid = candidate.tx.compute_txid();

            if processed.contains(&txid) {
                continue;
            }

            // Build package starting from this transaction
            let mut package = vec![candidate.clone()];
            processed.insert(txid);

            // Add ancestors
            if let Some(deps) = dependencies.get(&txid) {
                for dep_id in deps {
                    if !processed.contains(dep_id) {
                        // Find the ancestor candidate
                        if let Some(ancestor) =
                            candidates.iter().find(|c| c.tx.compute_txid() == *dep_id)
                        {
                            package.push(ancestor.clone());
                            processed.insert(*dep_id);
                        }
                    }
                }
            }

            packages.push(package);
        }

        Ok(packages)
    }

    /// Calculate effective fee rate for a package
    fn calculate_package_fee_rate(&self, package: &[MiningCandidate]) -> u64 {
        let total_fee: u64 = package.iter().map(|c| c.fee.to_sat()).sum();

        let total_weight: usize = package.iter().map(|c| c.weight).sum();

        if total_weight == 0 {
            return 0;
        }

        let total_vsize = total_weight.div_ceil(4);
        total_fee / total_vsize as u64
    }
}

/// Knapsack-based optimal transaction selection
pub struct KnapsackSelector {
    max_weight: usize,
    min_fee_rate: u64,
}

impl KnapsackSelector {
    pub fn new(max_weight: usize, min_fee_rate: u64) -> Self {
        Self {
            max_weight,
            min_fee_rate,
        }
    }

    /// Select optimal set of transactions using dynamic programming
    /// Note: This is computationally expensive for large mempools
    pub fn select_optimal(
        &self,
        candidates: Vec<MiningCandidate>,
        max_items: usize,
    ) -> Result<Vec<MiningCandidate>> {
        let n = candidates.len().min(max_items);
        if n == 0 {
            return Ok(Vec::new());
        }

        // Filter and sort by fee rate
        let mut items: Vec<_> = candidates
            .into_iter()
            .filter(|c| c.fee_rate >= self.min_fee_rate)
            .take(n)
            .collect();

        items.sort_by(|a, b| b.fee_rate.cmp(&a.fee_rate));

        // Simple greedy approach for now (full DP would be too expensive)
        let mut selected = Vec::new();
        let mut total_weight = 0;

        for item in items {
            if total_weight + item.weight <= self.max_weight {
                total_weight += item.weight;
                selected.push(item);
            }
        }

        Ok(selected)
    }
}

/// Block template builder
pub struct BlockTemplateBuilder {
    selector: TransactionSelector,
}

impl Default for BlockTemplateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockTemplateBuilder {
    pub fn new() -> Self {
        Self {
            selector: TransactionSelector::default(),
        }
    }

    pub fn with_selector(selector: TransactionSelector) -> Self {
        Self { selector }
    }

    /// Build optimal block template from mempool
    pub fn build_template(&self, candidates: Vec<MiningCandidate>) -> Result<Vec<Transaction>> {
        // Select transactions
        let selected = self.selector.select_transactions(candidates)?;

        // Convert to transaction list (coinbase will be added by caller)
        let transactions: Vec<Transaction> = selected.into_iter().map(|c| c.tx).collect();

        Ok(transactions)
    }

    /// Calculate total fees for selected transactions
    pub fn calculate_fees(transactions: &[MiningCandidate]) -> Amount {
        transactions.iter().map(|tx| tx.fee).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Transaction;

    #[test]
    fn test_transaction_selection() {
        let selector = TransactionSelector::default();

        // Create mock candidates
        let candidates = vec![
            create_mock_candidate(1000, 10), // 10 sat/vB
            create_mock_candidate(2000, 5),  // 5 sat/vB
            create_mock_candidate(500, 20),  // 20 sat/vB
        ];

        let selected = selector.select_transactions(candidates).unwrap();

        // Should select in order of fee rate
        assert!(!selected.is_empty());
        assert!(selected[0].fee_rate >= selected.last().unwrap().fee_rate);
    }

    fn create_mock_candidate(weight: usize, fee_rate: u64) -> MiningCandidate {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let vsize = weight.div_ceil(4);
        let fee = Amount::from_sat(fee_rate * vsize as u64);

        MiningCandidate {
            tx,
            fee,
            fee_rate,
            weight,
            size: vsize,
            ancestors: HashSet::new(),
            package_fee: fee,
            package_weight: weight,
        }
    }
}
