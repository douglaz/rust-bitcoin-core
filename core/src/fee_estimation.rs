use bitcoin::{Amount, Block, Transaction};
use parking_lot::RwLock;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Fee rate in satoshis per virtual byte
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeeRate(pub u64);

impl FeeRate {
    /// Create from satoshis per vbyte
    pub fn from_sat_per_vb(sat_per_vb: u64) -> Self {
        Self(sat_per_vb)
    }

    /// Get satoshis per vbyte
    pub fn as_sat_per_vb(&self) -> u64 {
        self.0
    }

    /// Calculate fee for transaction size
    pub fn calculate_fee(&self, vsize: usize) -> Amount {
        Amount::from_sat(self.0 * vsize as u64)
    }

    /// Create from total fee and vsize
    pub fn from_fee_and_vsize(fee: Amount, vsize: usize) -> Self {
        if vsize == 0 {
            Self(0)
        } else {
            Self(fee.to_sat() / vsize as u64)
        }
    }
}

/// Fee estimation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimationMode {
    /// Conservative - overestimate fees
    Conservative,
    /// Economical - more accurate, may underestimate
    Economical,
}

/// Fee statistics for a confirmation target
#[derive(Debug, Clone)]
struct FeeStats {
    /// Number of transactions confirmed
    confirmed_txs: u64,
    /// Total fees paid by confirmed transactions
    total_fees: u64,
    /// Fee rates of confirmed transactions
    fee_rates: Vec<FeeRate>,
}

impl FeeStats {
    fn new() -> Self {
        Self {
            confirmed_txs: 0,
            total_fees: 0,
            fee_rates: Vec::new(),
        }
    }

    /// Add a confirmed transaction
    fn add_confirmed_tx(&mut self, fee_rate: FeeRate) {
        self.confirmed_txs += 1;
        self.total_fees += fee_rate.0;
        self.fee_rates.push(fee_rate);
    }

    /// Get percentile fee rate
    fn get_percentile_fee_rate(&self, percentile: f64) -> FeeRate {
        if self.fee_rates.is_empty() {
            return FeeRate(1); // Minimum fee rate
        }

        let mut sorted = self.fee_rates.clone();
        sorted.sort();

        let index = ((percentile / 100.0) * sorted.len() as f64) as usize;
        let index = index.min(sorted.len() - 1);

        sorted[index]
    }
}

/// Transaction entry for fee estimation
#[derive(Debug, Clone)]
struct TxEntry {
    txid: bitcoin::Txid,
    fee_rate: FeeRate,
    height: u32,
    size: usize,
}

/// Fee estimator
pub struct FeeEstimator {
    /// Historical fee statistics by confirmation target (in blocks)
    stats_by_target: Arc<RwLock<BTreeMap<u32, FeeStats>>>,

    /// Recent blocks for analysis
    recent_blocks: Arc<RwLock<VecDeque<BlockStats>>>,

    /// Mempool transactions being tracked
    mempool_txs: Arc<RwLock<BTreeMap<bitcoin::Txid, TxEntry>>>,

    /// Maximum number of blocks to track
    max_blocks: usize,

    /// Default fee rate if no data available
    default_fee_rate: FeeRate,

    /// Minimum relay fee rate
    min_relay_fee_rate: FeeRate,
}

/// Statistics for a single block
#[derive(Debug, Clone)]
struct BlockStats {
    height: u32,
    /// Fee rates of transactions in the block
    fee_rates: Vec<FeeRate>,
    /// Median fee rate
    median_fee_rate: FeeRate,
    /// Number of transactions
    tx_count: usize,
}

impl FeeEstimator {
    /// Create a new fee estimator
    pub fn new() -> Self {
        let mut stats = BTreeMap::new();

        // Initialize common confirmation targets
        for target in &[1, 2, 3, 6, 12, 24, 48, 144, 504, 1008] {
            stats.insert(*target, FeeStats::new());
        }

        Self {
            stats_by_target: Arc::new(RwLock::new(stats)),
            recent_blocks: Arc::new(RwLock::new(VecDeque::with_capacity(2016))),
            mempool_txs: Arc::new(RwLock::new(BTreeMap::new())),
            max_blocks: 2016, // About 2 weeks
            default_fee_rate: FeeRate::from_sat_per_vb(10),
            min_relay_fee_rate: FeeRate::from_sat_per_vb(1),
        }
    }

    /// Estimate fee for confirmation within target blocks
    pub fn estimate_fee(&self, confirmation_target: u32, mode: EstimationMode) -> FeeRate {
        debug!(
            "Estimating fee for {} blocks, mode: {:?}",
            confirmation_target, mode
        );

        // Check if we have enough data
        let recent_blocks = self.recent_blocks.read();
        if recent_blocks.len() < 10 {
            warn!("Not enough blocks for fee estimation, using default");
            return self.default_fee_rate;
        }

        // Find the closest target we have data for
        let stats = self.stats_by_target.read();
        let target = stats
            .keys()
            .filter(|&&t| t >= confirmation_target)
            .min()
            .copied()
            .unwrap_or(confirmation_target);

        // Get statistics for this target
        if let Some(target_stats) = stats.get(&target) {
            let percentile = match mode {
                EstimationMode::Conservative => 75.0, // 75th percentile
                EstimationMode::Economical => 50.0,   // 50th percentile (median)
            };

            let fee_rate = target_stats.get_percentile_fee_rate(percentile);

            // Ensure minimum fee rate
            let fee_rate = FeeRate(fee_rate.0.max(self.min_relay_fee_rate.0));

            debug!("Estimated fee rate: {} sat/vB", fee_rate.0);
            return fee_rate;
        }

        // Fall back to recent block analysis
        self.estimate_from_recent_blocks(confirmation_target, mode)
    }

    /// Estimate from recent blocks
    fn estimate_from_recent_blocks(
        &self,
        confirmation_target: u32,
        mode: EstimationMode,
    ) -> FeeRate {
        let recent_blocks = self.recent_blocks.read();

        if recent_blocks.is_empty() {
            return self.default_fee_rate;
        }

        // Collect fee rates from recent blocks
        let mut all_fee_rates = Vec::new();
        let blocks_to_analyze = confirmation_target.min(recent_blocks.len() as u32) as usize;

        for block in recent_blocks.iter().take(blocks_to_analyze) {
            all_fee_rates.extend_from_slice(&block.fee_rates);
        }

        if all_fee_rates.is_empty() {
            return self.default_fee_rate;
        }

        // Sort and get percentile
        all_fee_rates.sort();

        let percentile = match mode {
            EstimationMode::Conservative => 0.75,
            EstimationMode::Economical => 0.5,
        };

        let index = (percentile * all_fee_rates.len() as f64) as usize;
        let index = index.min(all_fee_rates.len() - 1);

        FeeRate(all_fee_rates[index].0.max(self.min_relay_fee_rate.0))
    }

    /// Process a new block for fee estimation
    pub fn process_block(&self, block: &Block, height: u32) {
        info!("Processing block {} for fee estimation", height);

        let mut fee_rates = Vec::new();
        let mut mempool_txs = self.mempool_txs.write();

        // Process each transaction (skip coinbase)
        for tx in block.txdata.iter().skip(1) {
            let txid = tx.compute_txid();

            // Check if we were tracking this transaction
            if let Some(entry) = mempool_txs.remove(&txid) {
                fee_rates.push(entry.fee_rate);

                // Update statistics for confirmation targets
                let blocks_to_confirm = height.saturating_sub(entry.height);
                self.update_confirmation_stats(blocks_to_confirm, entry.fee_rate);
            }
        }

        // Calculate median fee rate for the block
        let median_fee_rate = if !fee_rates.is_empty() {
            fee_rates.sort();
            fee_rates[fee_rates.len() / 2]
        } else {
            self.default_fee_rate
        };

        // Add block statistics
        let block_stats = BlockStats {
            height,
            fee_rates,
            median_fee_rate,
            tx_count: block.txdata.len() - 1, // Exclude coinbase
        };

        let mut recent_blocks = self.recent_blocks.write();
        recent_blocks.push_front(block_stats);

        // Limit the number of blocks we keep
        while recent_blocks.len() > self.max_blocks {
            recent_blocks.pop_back();
        }
    }

    /// Update confirmation statistics
    fn update_confirmation_stats(&self, blocks_to_confirm: u32, fee_rate: FeeRate) {
        let mut stats = self.stats_by_target.write();

        // Update all targets that this confirmation time satisfies
        for (&target, target_stats) in stats.iter_mut() {
            if blocks_to_confirm <= target {
                target_stats.add_confirmed_tx(fee_rate);
            }
        }
    }

    /// Add a transaction to the mempool for tracking
    pub fn add_mempool_tx(&self, tx: &Transaction, height: u32, fee: Amount) {
        let txid = tx.compute_txid();
        let vsize = tx.vsize();
        let fee_rate = FeeRate::from_fee_and_vsize(fee, vsize);

        debug!(
            "Tracking mempool tx {} with fee rate {} sat/vB",
            txid, fee_rate.0
        );

        let entry = TxEntry {
            txid,
            fee_rate,
            height,
            size: vsize,
        };

        self.mempool_txs.write().insert(txid, entry);
    }

    /// Remove a transaction from mempool tracking
    pub fn remove_mempool_tx(&self, txid: &bitcoin::Txid) {
        self.mempool_txs.write().remove(txid);
    }

    /// Get current mempool statistics
    pub fn get_mempool_stats(&self) -> MempoolStats {
        let mempool_txs = self.mempool_txs.read();

        let mut fee_rates: Vec<_> = mempool_txs.values().map(|e| e.fee_rate).collect();

        fee_rates.sort();

        let median_fee = if !fee_rates.is_empty() {
            fee_rates[fee_rates.len() / 2]
        } else {
            FeeRate(0)
        };

        let total_size: usize = mempool_txs.values().map(|e| e.size).sum();

        MempoolStats {
            tx_count: mempool_txs.len(),
            total_size,
            median_fee_rate: median_fee,
            min_fee_rate: fee_rates.first().copied().unwrap_or(FeeRate(0)),
            max_fee_rate: fee_rates.last().copied().unwrap_or(FeeRate(0)),
        }
    }

    /// Get fee histogram
    pub fn get_fee_histogram(&self) -> Vec<(FeeRate, usize)> {
        let mempool_txs = self.mempool_txs.read();

        // Group transactions by fee rate ranges
        let mut histogram = BTreeMap::new();

        for entry in mempool_txs.values() {
            // Round to nearest 10 sat/vB for grouping
            let bucket = (entry.fee_rate.0 / 10) * 10;
            *histogram.entry(FeeRate(bucket)).or_insert(0) += 1;
        }

        histogram.into_iter().collect()
    }

    /// Smart fee estimation with multiple targets
    pub fn estimate_smart_fee(&self, confirmation_target: u32) -> SmartFeeEstimate {
        let conservative = self.estimate_fee(confirmation_target, EstimationMode::Conservative);
        let economical = self.estimate_fee(confirmation_target, EstimationMode::Economical);

        // Also provide estimates for faster confirmation
        let priority = if confirmation_target > 1 {
            self.estimate_fee(1, EstimationMode::Conservative)
        } else {
            conservative
        };

        SmartFeeEstimate {
            confirmation_target,
            conservative_fee: conservative,
            economical_fee: economical,
            priority_fee: priority,
        }
    }
}

/// Mempool statistics
#[derive(Debug, Clone)]
pub struct MempoolStats {
    pub tx_count: usize,
    pub total_size: usize,
    pub median_fee_rate: FeeRate,
    pub min_fee_rate: FeeRate,
    pub max_fee_rate: FeeRate,
}

/// Smart fee estimation result
#[derive(Debug, Clone)]
pub struct SmartFeeEstimate {
    pub confirmation_target: u32,
    pub conservative_fee: FeeRate,
    pub economical_fee: FeeRate,
    pub priority_fee: FeeRate,
}

impl SmartFeeEstimate {
    /// Get recommended fee for a given priority level
    pub fn get_recommended_fee(&self, priority: FeePriority) -> FeeRate {
        match priority {
            FeePriority::Low => self.economical_fee,
            FeePriority::Medium => self.conservative_fee,
            FeePriority::High => self.priority_fee,
        }
    }
}

/// Fee priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeePriority {
    Low,    // Economical, may take longer
    Medium, // Conservative, reliable confirmation
    High,   // Priority, fast confirmation
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_rate_calculation() {
        let fee_rate = FeeRate::from_sat_per_vb(10);
        let fee = fee_rate.calculate_fee(250); // 250 vbytes
        assert_eq!(fee, Amount::from_sat(2500));

        let fee_rate = FeeRate::from_fee_and_vsize(Amount::from_sat(5000), 500);
        assert_eq!(fee_rate.as_sat_per_vb(), 10);
    }

    #[test]
    fn test_fee_estimation_with_no_data() {
        let estimator = FeeEstimator::new();
        let fee = estimator.estimate_fee(6, EstimationMode::Economical);
        assert_eq!(fee.0, 10); // Should return default
    }

    #[test]
    fn test_mempool_tracking() {
        let estimator = FeeEstimator::new();

        // Create a dummy transaction
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        estimator.add_mempool_tx(&tx, 100, Amount::from_sat(1000));

        let stats = estimator.get_mempool_stats();
        assert_eq!(stats.tx_count, 1);

        estimator.remove_mempool_tx(&tx.compute_txid());

        let stats = estimator.get_mempool_stats();
        assert_eq!(stats.tx_count, 0);
    }

    #[test]
    fn test_smart_fee_estimation() {
        let estimator = FeeEstimator::new();
        let smart_fee = estimator.estimate_smart_fee(6);

        assert_eq!(smart_fee.confirmation_target, 6);
        assert!(smart_fee.priority_fee.0 >= smart_fee.conservative_fee.0);
        assert!(smart_fee.conservative_fee.0 >= smart_fee.economical_fee.0);
    }
}
