use anyhow::Result;
use bitcoin::Transaction;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, trace};

/// Advanced fee estimation using mempool analysis
pub struct FeeEstimator {
    /// Historical block data
    block_history: Arc<RwLock<VecDeque<BlockStats>>>,

    /// Current mempool snapshot
    mempool_snapshot: Arc<RwLock<MempoolSnapshot>>,

    /// Fee buckets for estimation
    fee_buckets: Arc<RwLock<FeeBuckets>>,

    /// Configuration
    config: FeeEstimatorConfig,

    /// Statistics
    stats: Arc<RwLock<EstimatorStats>>,
}

/// Configuration for fee estimator
#[derive(Debug, Clone)]
pub struct FeeEstimatorConfig {
    /// Number of blocks to analyze for fee estimation
    pub history_blocks: usize,

    /// Minimum number of data points required
    pub min_data_points: usize,

    /// Maximum time to wait for confirmation
    pub max_confirmation_time: Duration,

    /// Fee rate buckets (in sat/vB)
    pub bucket_boundaries: Vec<u64>,

    /// Update interval
    pub update_interval: Duration,

    /// Decay factor for old data
    pub decay_factor: f64,
}

impl Default for FeeEstimatorConfig {
    fn default() -> Self {
        Self {
            history_blocks: 100,
            min_data_points: 10,
            max_confirmation_time: Duration::from_secs(6 * 3600), // 6 hours
            bucket_boundaries: vec![
                1, 2, 3, 4, 5, 6, 8, 10, 12, 15, 20, 25, 30, 40, 50, 60, 80, 100, 125, 150, 200,
                250, 300, 400, 500, 600, 800, 1000, 1500, 2000,
            ],
            update_interval: Duration::from_secs(60),
            decay_factor: 0.998,
        }
    }
}

/// Block statistics for fee analysis
#[derive(Debug, Clone)]
struct BlockStats {
    pub height: u32,
    pub timestamp: u64,
    pub num_txs: usize,
    pub total_fees: u64,
    pub total_size: usize,
    pub fee_rates: Vec<u64>, // Individual tx fee rates
    pub percentiles: FeePercentiles,
}

/// Fee percentiles for a block
#[derive(Debug, Clone)]
struct FeePercentiles {
    pub p10: u64,
    pub p25: u64,
    pub p50: u64,
    pub p75: u64,
    pub p90: u64,
    pub p95: u64,
    pub p99: u64,
}

/// Mempool snapshot for analysis
#[derive(Debug, Clone)]
struct MempoolSnapshot {
    pub timestamp: Instant,
    pub num_txs: usize,
    pub total_fees: u64,
    pub total_size: usize,
    pub fee_distribution: BTreeMap<u64, usize>, // fee_rate -> count
}

/// Fee buckets for tracking confirmation probability
#[derive(Debug)]
struct FeeBuckets {
    /// Map from fee rate to confirmation statistics
    buckets: BTreeMap<u64, BucketStats>,
}

/// Statistics for a fee bucket
#[derive(Debug, Clone)]
struct BucketStats {
    pub fee_rate: u64,
    pub transactions_seen: u64,
    pub transactions_confirmed: u64,
    pub total_confirmation_time: Duration,
    pub confirmation_blocks: Vec<u32>,
}

/// Estimator statistics
#[derive(Debug, Default, Clone)]
pub struct EstimatorStats {
    pub blocks_analyzed: u64,
    pub transactions_analyzed: u64,
    pub estimates_provided: u64,
    pub estimate_accuracy: f64,
    pub last_update: Option<Instant>,
}

/// Fee estimate result
#[derive(Debug, Clone)]
pub struct FeeEstimate {
    /// Estimated fee rate in sat/vB
    pub fee_rate: u64,

    /// Confidence level (0.0 to 1.0)
    pub confidence: f64,

    /// Expected confirmation time
    pub expected_time: Duration,

    /// Number of blocks for confirmation
    pub blocks: u32,

    /// Estimation mode used
    pub mode: EstimationMode,
}

/// Fee estimation mode
#[derive(Debug, Clone, PartialEq)]
pub enum EstimationMode {
    /// Conservative (high confidence)
    Conservative,
    /// Normal (balanced)
    Normal,
    /// Economical (lower fees, longer wait)
    Economical,
    /// Priority (fast confirmation)
    Priority,
    /// Custom target blocks
    Custom(u32),
}

impl FeeEstimator {
    /// Create new fee estimator
    pub fn new(config: FeeEstimatorConfig) -> Self {
        let mut buckets = BTreeMap::new();
        for &rate in &config.bucket_boundaries {
            buckets.insert(
                rate,
                BucketStats {
                    fee_rate: rate,
                    transactions_seen: 0,
                    transactions_confirmed: 0,
                    total_confirmation_time: Duration::from_secs(0),
                    confirmation_blocks: Vec::new(),
                },
            );
        }

        Self {
            block_history: Arc::new(RwLock::new(VecDeque::with_capacity(config.history_blocks))),
            mempool_snapshot: Arc::new(RwLock::new(MempoolSnapshot {
                timestamp: Instant::now(),
                num_txs: 0,
                total_fees: 0,
                total_size: 0,
                fee_distribution: BTreeMap::new(),
            })),
            fee_buckets: Arc::new(RwLock::new(FeeBuckets { buckets })),
            config,
            stats: Arc::new(RwLock::new(EstimatorStats::default())),
        }
    }

    /// Update with new block
    pub async fn process_block(
        &self,
        height: u32,
        timestamp: u64,
        transactions: &[Transaction],
        fees: &[u64],
    ) -> Result<()> {
        debug!(
            "Processing block {} with {} transactions",
            height,
            transactions.len()
        );

        // Calculate fee rates
        let mut fee_rates = Vec::new();
        for (tx, &fee) in transactions.iter().zip(fees.iter()) {
            let size = bitcoin::consensus::encode::serialize(tx).len();
            let vsize = tx.weight().to_vbytes_ceil() as usize;
            let fee_rate = if vsize > 0 { fee / vsize as u64 } else { 0 };
            fee_rates.push(fee_rate);
        }

        // Sort for percentile calculation
        fee_rates.sort_unstable();

        // Calculate percentiles
        let percentiles = if !fee_rates.is_empty() {
            FeePercentiles {
                p10: Self::percentile(&fee_rates, 10),
                p25: Self::percentile(&fee_rates, 25),
                p50: Self::percentile(&fee_rates, 50),
                p75: Self::percentile(&fee_rates, 75),
                p90: Self::percentile(&fee_rates, 90),
                p95: Self::percentile(&fee_rates, 95),
                p99: Self::percentile(&fee_rates, 99),
            }
        } else {
            FeePercentiles {
                p10: 0,
                p25: 0,
                p50: 0,
                p75: 0,
                p90: 0,
                p95: 0,
                p99: 0,
            }
        };

        // Create block stats
        let block_stats = BlockStats {
            height,
            timestamp,
            num_txs: transactions.len(),
            total_fees: fees.iter().sum(),
            total_size: transactions
                .iter()
                .map(|tx| bitcoin::consensus::encode::serialize(tx).len())
                .sum(),
            fee_rates: fee_rates.clone(),
            percentiles,
        };

        // Update block history
        {
            let mut history = self.block_history.write().await;
            history.push_back(block_stats.clone());
            while history.len() > self.config.history_blocks {
                history.pop_front();
            }
        }

        // Update fee buckets
        self.update_fee_buckets(&fee_rates, height).await;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.blocks_analyzed += 1;
            stats.transactions_analyzed += transactions.len() as u64;
            stats.last_update = Some(Instant::now());
        }

        Ok(())
    }

    /// Update mempool snapshot
    pub async fn update_mempool_snapshot(
        &self,
        transactions: &[(Transaction, u64)], // (tx, fee)
    ) -> Result<()> {
        let mut fee_distribution = BTreeMap::new();
        let mut total_fees = 0u64;
        let mut total_size = 0usize;

        for (tx, fee) in transactions {
            let vsize = tx.weight().to_vbytes_ceil() as usize;
            let fee_rate = if vsize > 0 { fee / vsize as u64 } else { 0 };

            *fee_distribution.entry(fee_rate).or_insert(0) += 1;
            total_fees += fee;
            total_size += vsize;
        }

        let snapshot = MempoolSnapshot {
            timestamp: Instant::now(),
            num_txs: transactions.len(),
            total_fees,
            total_size,
            fee_distribution,
        };

        *self.mempool_snapshot.write().await = snapshot;

        Ok(())
    }

    /// Estimate fee for confirmation target
    pub async fn estimate_fee(&self, mode: EstimationMode) -> Result<FeeEstimate> {
        let target_blocks = match &mode {
            EstimationMode::Priority => 1,
            EstimationMode::Normal => 3,
            EstimationMode::Conservative => 6,
            EstimationMode::Economical => 12,
            EstimationMode::Custom(blocks) => *blocks,
        };

        // Get historical data
        let history = self.block_history.read().await;
        if history.len() < self.config.min_data_points {
            // Not enough data, use defaults
            return Ok(self.default_estimate(mode));
        }

        // Analyze recent blocks
        let mut required_fee_rates = Vec::new();

        for block in history.iter().rev().take(target_blocks as usize) {
            // Get the minimum fee rate that got into this block
            if !block.fee_rates.is_empty() {
                // Use 5th percentile as minimum to account for priority transactions
                let min_rate = Self::percentile(&block.fee_rates, 5);
                required_fee_rates.push(min_rate);
            }
        }

        if required_fee_rates.is_empty() {
            return Ok(self.default_estimate(mode));
        }

        // Calculate estimate based on mode
        let fee_rate = match mode {
            EstimationMode::Conservative => {
                // Use 75th percentile of required rates
                Self::percentile(&mut required_fee_rates, 75)
            }
            EstimationMode::Priority => {
                // Use 90th percentile for high priority
                Self::percentile(&mut required_fee_rates, 90)
            }
            EstimationMode::Normal => {
                // Use median
                Self::percentile(&mut required_fee_rates, 50)
            }
            EstimationMode::Economical => {
                // Use 25th percentile
                Self::percentile(&mut required_fee_rates, 25)
            }
            EstimationMode::Custom(_) => {
                // Use median for custom
                Self::percentile(&mut required_fee_rates, 50)
            }
        };

        // Consider current mempool state
        let adjusted_fee_rate = self.adjust_for_mempool(fee_rate).await;

        // Calculate confidence based on data quality
        let confidence = self.calculate_confidence(&history, target_blocks).await;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.estimates_provided += 1;
        }

        Ok(FeeEstimate {
            fee_rate: adjusted_fee_rate,
            confidence,
            expected_time: Duration::from_secs(target_blocks as u64 * 600),
            blocks: target_blocks,
            mode,
        })
    }

    /// Get smart fee estimate with fallback
    pub async fn smart_fee_estimate(&self, conf_target: u32) -> Result<SmartFeeEstimate> {
        let mode = if conf_target <= 2 {
            EstimationMode::Priority
        } else if conf_target <= 6 {
            EstimationMode::Normal
        } else if conf_target <= 12 {
            EstimationMode::Conservative
        } else {
            EstimationMode::Economical
        };

        let estimate = self.estimate_fee(mode).await?;

        // Get mempool info for context
        let mempool = self.mempool_snapshot.read().await;

        Ok(SmartFeeEstimate {
            fee_rate: estimate.fee_rate,
            confidence: estimate.confidence,
            blocks: estimate.blocks,
            mempool_size: mempool.num_txs,
            mempool_bytes: mempool.total_size,
            errors: Vec::new(),
        })
    }

    /// Update fee buckets with confirmation data
    async fn update_fee_buckets(&self, fee_rates: &[u64], height: u32) {
        let mut buckets = self.fee_buckets.write().await;

        for &rate in fee_rates {
            // Find appropriate bucket
            let bucket_rate = self
                .config
                .bucket_boundaries
                .iter()
                .find(|&&b| b >= rate)
                .copied()
                .unwrap_or(*self.config.bucket_boundaries.last().unwrap());

            if let Some(bucket) = buckets.buckets.get_mut(&bucket_rate) {
                bucket.transactions_confirmed += 1;
                bucket.confirmation_blocks.push(height);

                // Clean old data
                if bucket.confirmation_blocks.len() > 1000 {
                    bucket.confirmation_blocks.remove(0);
                }
            }
        }
    }

    /// Adjust fee rate based on current mempool state
    async fn adjust_for_mempool(&self, base_rate: u64) -> u64 {
        let mempool = self.mempool_snapshot.read().await;

        // If mempool is congested, increase fee
        if mempool.num_txs > 10000 {
            let congestion_factor = 1.0 + (mempool.num_txs as f64 / 10000.0).min(2.0);
            (base_rate as f64 * congestion_factor) as u64
        } else {
            base_rate
        }
    }

    /// Calculate confidence level
    async fn calculate_confidence(
        &self,
        history: &VecDeque<BlockStats>,
        target_blocks: u32,
    ) -> f64 {
        // Base confidence on amount of data
        let data_points = history.len().min(target_blocks as usize * 10);
        let data_confidence = (data_points as f64 / (target_blocks as f64 * 10.0)).min(1.0);

        // Consider variance in recent blocks
        let recent_blocks: Vec<_> = history.iter().rev().take(target_blocks as usize).collect();

        let variance_confidence = if recent_blocks.len() >= 2 {
            let fee_rates: Vec<f64> = recent_blocks
                .iter()
                .map(|b| b.percentiles.p50 as f64)
                .collect();

            let mean = fee_rates.iter().sum::<f64>() / fee_rates.len() as f64;
            let variance =
                fee_rates.iter().map(|&r| (r - mean).powi(2)).sum::<f64>() / fee_rates.len() as f64;

            // Lower confidence for high variance
            1.0 / (1.0 + variance / mean.max(1.0))
        } else {
            0.5
        };

        // Combine factors
        data_confidence * 0.7 + variance_confidence * 0.3
    }

    /// Calculate percentile
    fn percentile(sorted_values: &[u64], percentile: usize) -> u64 {
        if sorted_values.is_empty() {
            return 0;
        }

        let index = (sorted_values.len() - 1) * percentile / 100;
        sorted_values[index]
    }

    /// Get default estimate when not enough data
    fn default_estimate(&self, mode: EstimationMode) -> FeeEstimate {
        let (fee_rate, blocks) = match mode {
            EstimationMode::Priority => (50, 1),
            EstimationMode::Normal => (20, 3),
            EstimationMode::Conservative => (10, 6),
            EstimationMode::Economical => (5, 12),
            EstimationMode::Custom(b) => (15, b),
        };

        FeeEstimate {
            fee_rate,
            confidence: 0.3,
            expected_time: Duration::from_secs(blocks as u64 * 600),
            blocks,
            mode,
        }
    }

    /// Get fee histogram
    pub async fn get_fee_histogram(&self) -> Vec<(u64, usize)> {
        let mempool = self.mempool_snapshot.read().await;
        mempool
            .fee_distribution
            .iter()
            .map(|(&rate, &count)| (rate, count))
            .collect()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> EstimatorStats {
        let stats = self.stats.read().await;
        (*stats).clone()
    }

    /// Run periodic analysis
    pub async fn run_analysis_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.config.update_interval);

        loop {
            interval.tick().await;

            // Apply decay to old bucket data
            if let Ok(mut buckets) = self.fee_buckets.try_write() {
                for bucket in buckets.buckets.values_mut() {
                    bucket.transactions_seen =
                        (bucket.transactions_seen as f64 * self.config.decay_factor) as u64;
                    bucket.transactions_confirmed =
                        (bucket.transactions_confirmed as f64 * self.config.decay_factor) as u64;
                }
            }

            trace!("Fee estimator analysis complete");
        }
    }
}

/// Smart fee estimate result
#[derive(Debug, Clone)]
pub struct SmartFeeEstimate {
    pub fee_rate: u64,
    pub confidence: f64,
    pub blocks: u32,
    pub mempool_size: usize,
    pub mempool_bytes: usize,
    pub errors: Vec<String>,
}

/// Fee priority levels
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FeePriority {
    Minimum, // 1 sat/vB
    Low,     // Economy
    Medium,  // Normal
    High,    // Priority
    Maximum, // Urgent
}

impl FeePriority {
    /// Convert to estimation mode
    pub fn to_mode(self) -> EstimationMode {
        match self {
            FeePriority::Minimum => EstimationMode::Custom(144),
            FeePriority::Low => EstimationMode::Economical,
            FeePriority::Medium => EstimationMode::Normal,
            FeePriority::High => EstimationMode::Conservative,
            FeePriority::Maximum => EstimationMode::Priority,
        }
    }

    /// Get target blocks
    pub fn target_blocks(self) -> u32 {
        match self {
            FeePriority::Minimum => 144,
            FeePriority::Low => 12,
            FeePriority::Medium => 6,
            FeePriority::High => 3,
            FeePriority::Maximum => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fee_estimation() {
        let config = FeeEstimatorConfig::default();
        let estimator = FeeEstimator::new(config);

        // Add some mock block data
        let mock_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let txs = vec![mock_tx.clone(); 100];
        let fees = vec![1000u64; 100];

        estimator
            .process_block(1, 1234567890, &txs, &fees)
            .await
            .unwrap();

        // Get estimate
        let estimate = estimator
            .estimate_fee(EstimationMode::Normal)
            .await
            .unwrap();
        assert!(estimate.fee_rate > 0);
        assert!(estimate.confidence >= 0.0 && estimate.confidence <= 1.0);
    }

    #[test]
    fn test_percentile_calculation() {
        let values = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(FeeEstimator::percentile(&values, 50), 5);
        assert_eq!(FeeEstimator::percentile(&values, 90), 9);
        assert_eq!(FeeEstimator::percentile(&values, 10), 1);
    }
}
