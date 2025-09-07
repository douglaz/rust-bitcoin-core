use anyhow::{bail, Result};
use bitcoin::{Amount, Transaction};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, trace};

/// Fee rate in satoshis per virtual byte
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeeRate(pub u64);

impl FeeRate {
    /// Create a new fee rate
    pub fn from_sat_per_vb(sat_per_vb: u64) -> Self {
        FeeRate(sat_per_vb)
    }

    /// Get fee rate in sat/vB
    pub fn as_sat_per_vb(&self) -> u64 {
        self.0
    }

    /// Calculate fee for a transaction of given size
    pub fn fee_for_vsize(&self, vsize: usize) -> Amount {
        Amount::from_sat(self.0 * vsize as u64)
    }
}

/// Tracks confirmed transactions for fee estimation
#[derive(Debug, Clone)]
struct ConfirmedEntry {
    fee_rate: FeeRate,
    block_height: u32,
    bucket_index: usize,
}

/// Fee estimation bucket
#[derive(Debug, Clone)]
struct FeeBucket {
    total_confirmed: u64,
    fee_rates: Vec<FeeRate>,
}

impl FeeBucket {
    fn new() -> Self {
        Self {
            total_confirmed: 0,
            fee_rates: Vec::new(),
        }
    }

    fn add_transaction(&mut self, fee_rate: FeeRate) {
        self.fee_rates.push(fee_rate);
        self.total_confirmed += 1;

        // Keep only recent transactions (last 1000)
        if self.fee_rates.len() > 1000 {
            self.fee_rates.remove(0);
        }
    }

    fn median_fee_rate(&self) -> Option<FeeRate> {
        self.percentile_fee_rate(50.0)
    }

    /// Calculate fee rate at a given percentile (0-100)
    fn percentile_fee_rate(&self, percentile: f64) -> Option<FeeRate> {
        if self.fee_rates.is_empty() {
            return None;
        }

        let mut sorted = self.fee_rates.clone();
        sorted.sort();

        // Calculate the index for the requested percentile
        let percentile = percentile.clamp(0.0, 100.0);
        let index = ((percentile / 100.0) * (sorted.len() - 1) as f64).round() as usize;

        Some(sorted[index])
    }
}

/// Smart fee estimator using historical data
pub struct FeeEstimator {
    /// Fee buckets indexed by confirmation target (blocks)
    buckets: Arc<RwLock<BTreeMap<u32, FeeBucket>>>,

    /// Recent blocks for short-term estimation
    recent_blocks: Arc<RwLock<VecDeque<BlockStats>>>,

    /// Configuration
    config: FeeEstimatorConfig,

    /// Minimum relay fee
    min_relay_fee: FeeRate,
}

/// Statistics for a single block
#[derive(Debug, Clone)]
struct BlockStats {
    height: u32,
    total_fees: Amount,
    total_vsize: usize,
    tx_count: usize,
    median_fee_rate: FeeRate,
}

/// Fee estimator configuration
#[derive(Debug, Clone)]
pub struct FeeEstimatorConfig {
    pub max_blocks_to_track: usize,
    pub default_buckets: Vec<u32>,
    pub decay_factor: f64,
    pub min_bucket_samples: usize,
    pub default_percentile: f64, // Default percentile for estimates
}

impl Default for FeeEstimatorConfig {
    fn default() -> Self {
        Self {
            max_blocks_to_track: 100,
            default_buckets: vec![1, 2, 3, 6, 15, 25, 144, 1008], // Various confirmation targets
            decay_factor: 0.998,                                  // Slight decay for old data
            min_bucket_samples: 20,
            default_percentile: 50.0, // Use median by default
        }
    }
}

impl FeeEstimator {
    /// Create a new fee estimator
    pub fn new(config: FeeEstimatorConfig) -> Self {
        let mut buckets = BTreeMap::new();

        // Initialize buckets for each confirmation target
        for target in &config.default_buckets {
            buckets.insert(*target, FeeBucket::new());
        }

        Self {
            buckets: Arc::new(RwLock::new(buckets)),
            recent_blocks: Arc::new(RwLock::new(VecDeque::new())),
            config,
            min_relay_fee: FeeRate::from_sat_per_vb(1), // 1 sat/vB minimum
        }
    }

    /// Record a transaction being included in a block
    pub async fn record_transaction(
        &self,
        tx: &Transaction,
        fee: Amount,
        _block_height: u32,
        confirmation_blocks: u32,
    ) -> Result<()> {
        // Calculate transaction virtual size
        let vsize = self.calculate_vsize(tx);
        if vsize == 0 {
            bail!("Invalid transaction size");
        }

        // Calculate fee rate
        let fee_rate = FeeRate::from_sat_per_vb(fee.to_sat() / vsize as u64);

        trace!(
            "Recording tx with fee rate {} sat/vB confirmed in {} blocks",
            fee_rate.as_sat_per_vb(),
            confirmation_blocks
        );

        // Add to appropriate bucket
        let mut buckets = self.buckets.write().await;

        // Find the right bucket for this confirmation time
        for (target, bucket) in buckets.iter_mut() {
            if confirmation_blocks <= *target {
                bucket.add_transaction(fee_rate);
                break;
            }
        }

        Ok(())
    }

    /// Record a new block
    pub async fn record_block(
        &self,
        block_height: u32,
        transactions: Vec<(Transaction, Amount)>,
    ) -> Result<()> {
        let mut total_fees = Amount::ZERO;
        let mut total_vsize = 0;
        let mut fee_rates = Vec::new();

        for (tx, fee) in &transactions {
            let vsize = self.calculate_vsize(tx);
            if vsize > 0 {
                total_vsize += vsize;
                total_fees = total_fees.checked_add(*fee).unwrap_or(Amount::MAX);

                let fee_rate = FeeRate::from_sat_per_vb(fee.to_sat() / vsize as u64);
                fee_rates.push(fee_rate);
            }
        }

        // Calculate median fee rate
        fee_rates.sort();
        let median_fee_rate = if !fee_rates.is_empty() {
            fee_rates[fee_rates.len() / 2]
        } else {
            self.min_relay_fee
        };

        let block_stats = BlockStats {
            height: block_height,
            total_fees,
            total_vsize,
            tx_count: transactions.len(),
            median_fee_rate,
        };

        let mut recent = self.recent_blocks.write().await;
        recent.push_back(block_stats);

        // Keep only recent blocks
        while recent.len() > self.config.max_blocks_to_track {
            recent.pop_front();
        }

        info!(
            "Recorded block {} with {} transactions, median fee rate: {} sat/vB",
            block_height,
            transactions.len(),
            median_fee_rate.as_sat_per_vb()
        );

        Ok(())
    }

    /// Estimate fee for a given confirmation target
    pub async fn estimate_fee(&self, confirmation_target: u32) -> Result<FeeRate> {
        self.estimate_fee_percentile(confirmation_target, self.config.default_percentile)
            .await
    }

    /// Estimate fee for a given confirmation target at a specific percentile
    pub async fn estimate_fee_percentile(
        &self,
        confirmation_target: u32,
        percentile: f64,
    ) -> Result<FeeRate> {
        debug!(
            "Estimating fee for {} block confirmation target at {}th percentile",
            confirmation_target, percentile
        );

        // First check if we have enough data for this target
        let buckets = self.buckets.read().await;

        // Find the closest bucket
        let mut best_bucket = None;
        for (target, bucket) in buckets.iter() {
            if *target >= confirmation_target {
                best_bucket = Some(bucket);
                break;
            }
        }

        if let Some(bucket) = best_bucket {
            if bucket.total_confirmed >= self.config.min_bucket_samples as u64 {
                if let Some(fee_at_percentile) = bucket.percentile_fee_rate(percentile) {
                    let fee_rate = fee_at_percentile.max(self.min_relay_fee);
                    debug!(
                        "Estimated fee rate: {} sat/vB ({}th percentile)",
                        fee_rate.as_sat_per_vb(),
                        percentile
                    );
                    return Ok(fee_rate);
                }
            }
        }

        // Fall back to recent blocks analysis
        let fee_rate = self
            .estimate_from_recent_blocks_percentile(confirmation_target, percentile)
            .await?;
        Ok(fee_rate)
    }

    /// Estimate fee based on recent blocks
    async fn estimate_from_recent_blocks(&self, confirmation_target: u32) -> Result<FeeRate> {
        self.estimate_from_recent_blocks_percentile(confirmation_target, 75.0)
            .await
    }

    /// Estimate fee based on recent blocks at a specific percentile
    async fn estimate_from_recent_blocks_percentile(
        &self,
        confirmation_target: u32,
        percentile: f64,
    ) -> Result<FeeRate> {
        let recent = self.recent_blocks.read().await;

        if recent.is_empty() {
            debug!("No recent block data, using minimum fee");
            return Ok(self.min_relay_fee);
        }

        // Use recent blocks to estimate
        let blocks_to_consider = confirmation_target.min(recent.len() as u32);
        let mut fee_rates = Vec::new();

        for i in 0..blocks_to_consider as usize {
            if let Some(block) = recent.get(recent.len() - 1 - i) {
                fee_rates.push(block.median_fee_rate);
            }
        }

        if fee_rates.is_empty() {
            return Ok(self.min_relay_fee);
        }

        // Calculate fee at requested percentile
        fee_rates.sort();
        let percentile = percentile.clamp(0.0, 100.0);
        let index = ((percentile / 100.0) * (fee_rates.len() - 1) as f64).round() as usize;
        let estimated = fee_rates[index].max(self.min_relay_fee);

        debug!(
            "Estimated fee from recent blocks: {} sat/vB ({}th percentile)",
            estimated.as_sat_per_vb(),
            percentile
        );
        Ok(estimated)
    }

    /// Get fee estimates at multiple percentiles for analysis
    pub async fn get_fee_distribution(
        &self,
        confirmation_target: u32,
        percentiles: &[f64],
    ) -> Result<Vec<(f64, FeeRate)>> {
        let mut results = Vec::new();

        for &percentile in percentiles {
            match self
                .estimate_fee_percentile(confirmation_target, percentile)
                .await
            {
                Ok(fee_rate) => results.push((percentile, fee_rate)),
                Err(e) => {
                    debug!("Failed to estimate at {}th percentile: {}", percentile, e);
                }
            }
        }

        Ok(results)
    }

    /// Estimate smart fee with mode selection
    pub async fn estimate_smart_fee(
        &self,
        confirmation_target: u32,
        mode: EstimateMode,
    ) -> Result<SmartFeeEstimate> {
        // Use different percentiles based on mode
        let percentile = match mode {
            EstimateMode::Economical => 25.0, // 25th percentile for economical
            EstimateMode::Conservative => 75.0, // 75th percentile for conservative
            EstimateMode::Normal => 50.0,     // 50th percentile (median) for normal
        };

        let fee_rate = self
            .estimate_fee_percentile(confirmation_target, percentile)
            .await?;

        // Ensure we don't go below minimum
        let final_rate = fee_rate.max(self.min_relay_fee);

        Ok(SmartFeeEstimate {
            fee_rate: final_rate,
            blocks: confirmation_target,
            errors: Vec::new(),
        })
    }

    /// Calculate virtual size of a transaction
    fn calculate_vsize(&self, tx: &Transaction) -> usize {
        // Proper vsize calculation considering witness data
        // vsize = (weight + 3) / 4
        // weight = (base_size * 3) + total_size

        // Get serialized sizes
        let total_size = bitcoin::consensus::encode::serialize(tx).len();

        // Calculate base size (without witness data)
        let base_size = self.calculate_base_size(tx);

        // Weight = (base_size * 3) + total_size
        let weight = if self.has_witness(tx) {
            // SegWit transaction: base gets 3x weight, witness gets 1x
            base_size * 3 + total_size
        } else {
            // Non-SegWit: weight = size * 4
            total_size * 4
        };

        // Convert weight to vsize
        weight.div_ceil(4)
    }

    /// Calculate base size without witness data
    fn calculate_base_size(&self, tx: &Transaction) -> usize {
        // Version (4) + locktime (4)
        let mut size = 4 + 4;

        // Input/output counts (compact size)
        size += self.compact_size_len(tx.input.len());
        size += self.compact_size_len(tx.output.len());

        // Inputs (without witness)
        for input in &tx.input {
            size += 36; // Previous output (32 + 4)
            size += self.compact_size_len(input.script_sig.len());
            size += input.script_sig.len();
            size += 4; // Sequence
        }

        // Outputs
        for output in &tx.output {
            size += 8; // Amount
            size += self.compact_size_len(output.script_pubkey.len());
            size += output.script_pubkey.len();
        }

        size
    }

    /// Check if transaction has witness data
    fn has_witness(&self, tx: &Transaction) -> bool {
        tx.input.iter().any(|input| !input.witness.is_empty())
    }

    /// Calculate compact size encoding length
    fn compact_size_len(&self, n: usize) -> usize {
        if n < 0xfd {
            1
        } else if n <= 0xffff {
            3
        } else if n <= 0xffffffff {
            5
        } else {
            9
        }
    }

    /// Clear all fee estimation data
    pub async fn clear(&self) {
        let mut buckets = self.buckets.write().await;
        for bucket in buckets.values_mut() {
            bucket.fee_rates.clear();
            bucket.total_confirmed = 0;
        }

        let mut recent = self.recent_blocks.write().await;
        recent.clear();

        info!("Cleared all fee estimation data");
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> FeeEstimatorStats {
        let buckets = self.buckets.read().await;
        let recent = self.recent_blocks.read().await;

        let mut bucket_samples = BTreeMap::new();
        for (target, bucket) in buckets.iter() {
            bucket_samples.insert(*target, bucket.total_confirmed);
        }

        FeeEstimatorStats {
            tracked_blocks: recent.len(),
            bucket_samples,
            last_block_median: recent.back().map(|b| b.median_fee_rate),
        }
    }
}

/// Fee estimation mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EstimateMode {
    /// Lower fee, may take longer
    Economical,
    /// Normal fee estimation
    Normal,
    /// Higher fee for faster confirmation
    Conservative,
}

impl EstimateMode {
    pub fn from_string(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "ECONOMICAL" => Ok(EstimateMode::Economical),
            "CONSERVATIVE" => Ok(EstimateMode::Conservative),
            "NORMAL" => Ok(EstimateMode::Normal),
            _ => bail!("Invalid estimate mode: {}", s),
        }
    }
}

/// Smart fee estimate result
#[derive(Debug, Clone)]
pub struct SmartFeeEstimate {
    pub fee_rate: FeeRate,
    pub blocks: u32,
    pub errors: Vec<String>,
}

/// Fee estimator statistics
#[derive(Debug, Clone)]
pub struct FeeEstimatorStats {
    pub tracked_blocks: usize,
    pub bucket_samples: BTreeMap<u32, u64>,
    pub last_block_median: Option<FeeRate>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_rate() {
        let rate = FeeRate::from_sat_per_vb(10);
        assert_eq!(rate.as_sat_per_vb(), 10);

        let fee = rate.fee_for_vsize(250);
        assert_eq!(fee, Amount::from_sat(2500));
    }

    #[test]
    fn test_fee_bucket() {
        let mut bucket = FeeBucket::new();

        bucket.add_transaction(FeeRate::from_sat_per_vb(5));
        bucket.add_transaction(FeeRate::from_sat_per_vb(10));
        bucket.add_transaction(FeeRate::from_sat_per_vb(15));

        assert_eq!(bucket.total_confirmed, 3);
        assert_eq!(bucket.median_fee_rate(), Some(FeeRate::from_sat_per_vb(10)));
    }

    #[test]
    fn test_percentile_calculation() {
        let mut bucket = FeeBucket::new();

        // Add 10 transactions with different fee rates
        for i in 1..=10 {
            bucket.add_transaction(FeeRate::from_sat_per_vb(i * 10));
        }

        // Test various percentiles
        // With 10 items (10, 20, 30, 40, 50, 60, 70, 80, 90, 100):
        assert_eq!(
            bucket.percentile_fee_rate(0.0),
            Some(FeeRate::from_sat_per_vb(10))
        ); // Min
        assert_eq!(
            bucket.percentile_fee_rate(25.0),
            Some(FeeRate::from_sat_per_vb(30))
        ); // 25th percentile
        assert_eq!(
            bucket.percentile_fee_rate(50.0),
            Some(FeeRate::from_sat_per_vb(60))
        ); // Median (rounds up)
        assert_eq!(
            bucket.percentile_fee_rate(75.0),
            Some(FeeRate::from_sat_per_vb(80))
        ); // 75th percentile
        assert_eq!(
            bucket.percentile_fee_rate(100.0),
            Some(FeeRate::from_sat_per_vb(100))
        ); // Max
    }

    #[tokio::test]
    async fn test_fee_estimator() {
        let estimator = FeeEstimator::new(FeeEstimatorConfig::default());

        // Test with no data - should return minimum
        let fee = estimator.estimate_fee(6).await.unwrap();
        assert_eq!(fee, FeeRate::from_sat_per_vb(1));

        // Add some mock data
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        estimator
            .record_transaction(&tx, Amount::from_sat(1000), 100, 6)
            .await
            .unwrap();

        // Should still use minimum with insufficient data
        let fee = estimator.estimate_fee(6).await.unwrap();
        assert_eq!(fee, FeeRate::from_sat_per_vb(1));
    }

    #[test]
    fn test_estimate_mode() {
        assert_eq!(
            EstimateMode::from_string("ECONOMICAL").unwrap(),
            EstimateMode::Economical
        );
        assert_eq!(
            EstimateMode::from_string("conservative").unwrap(),
            EstimateMode::Conservative
        );
        assert_eq!(
            EstimateMode::from_string("Normal").unwrap(),
            EstimateMode::Normal
        );
        assert!(EstimateMode::from_string("invalid").is_err());
    }
}
