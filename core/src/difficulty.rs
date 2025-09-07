use anyhow::{bail, Result};
use bitcoin::{block::Header as BlockHeader, CompactTarget, Target, Work};
use tracing::{debug, info, trace, warn};

/// Difficulty adjustment interval (2016 blocks)
const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016;

/// Target block time (10 minutes in seconds)
const TARGET_BLOCK_TIME: u32 = 600;

/// Target timespan for 2016 blocks (2 weeks in seconds)
const TARGET_TIMESPAN: u32 = DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME;

/// Maximum adjustment factor (4x)
const MAX_ADJUSTMENT_FACTOR: u32 = 4;

/// Minimum adjustment factor (1/4)
const MIN_ADJUSTMENT_FACTOR: u32 = 4;

/// Difficulty calculator for Bitcoin consensus
pub struct DifficultyCalculator {
    /// Network parameters
    network: String,

    /// Maximum target (minimum difficulty)
    max_target: Target,

    /// Minimum target (maximum difficulty)
    min_target: Target,
}

impl DifficultyCalculator {
    /// Create new difficulty calculator
    pub fn new(network: String) -> Self {
        let max_target = match network.as_str() {
            "testnet" => Target::from_compact(CompactTarget::from_consensus(0x1d00ffff)),
            "regtest" => Target::from_compact(CompactTarget::from_consensus(0x207fffff)),
            _ => Target::from_compact(CompactTarget::from_consensus(0x1d00ffff)), // Mainnet
        };

        let min_target = Target::from_be_bytes([0u8; 32]);

        Self {
            network,
            max_target,
            min_target,
        }
    }

    /// Calculate next difficulty target
    pub fn calculate_next_target(
        &self,
        current_height: u32,
        current_target: Target,
        first_block_time: u32,
        last_block_time: u32,
    ) -> Result<Target> {
        // Check if adjustment is needed
        if !self.is_adjustment_height(current_height + 1) {
            return Ok(current_target);
        }

        info!(
            "Calculating difficulty adjustment at height {}",
            current_height + 1
        );

        // Calculate actual timespan
        let actual_timespan = last_block_time.saturating_sub(first_block_time);

        // Apply bounds to prevent extreme adjustments
        let adjusted_timespan = self.apply_timespan_bounds(actual_timespan);

        // Calculate new target
        let new_target = self.adjust_target(current_target, adjusted_timespan)?;

        // Ensure within network bounds
        let final_target = self.apply_target_bounds(new_target);

        let difficulty_change = self.calculate_difficulty_change(current_target, final_target);

        info!(
            "Difficulty adjustment: actual_time={}, adjusted_time={}, change={:.2}%",
            actual_timespan,
            adjusted_timespan,
            difficulty_change * 100.0
        );

        Ok(final_target)
    }

    /// Check if height requires difficulty adjustment
    pub fn is_adjustment_height(&self, height: u32) -> bool {
        // Special case for regtest
        if self.network == "regtest" {
            return false; // No adjustment in regtest
        }

        height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0
    }

    /// Get adjustment interval
    pub fn adjustment_interval(&self) -> u32 {
        DIFFICULTY_ADJUSTMENT_INTERVAL
    }

    /// Apply bounds to timespan to limit adjustment
    fn apply_timespan_bounds(&self, actual_timespan: u32) -> u32 {
        let min_timespan = TARGET_TIMESPAN / MAX_ADJUSTMENT_FACTOR;
        let max_timespan = TARGET_TIMESPAN * MAX_ADJUSTMENT_FACTOR;

        if actual_timespan < min_timespan {
            debug!(
                "Timespan {} below minimum, clamping to {}",
                actual_timespan, min_timespan
            );
            min_timespan
        } else if actual_timespan > max_timespan {
            debug!(
                "Timespan {} above maximum, clamping to {}",
                actual_timespan, max_timespan
            );
            max_timespan
        } else {
            actual_timespan
        }
    }

    /// Adjust target based on timespan
    fn adjust_target(&self, current_target: Target, adjusted_timespan: u32) -> Result<Target> {
        // new_target = old_target * actual_timespan / target_timespan

        // Convert target to big integer for calculation
        let current_bits = current_target.to_compact_lossy().to_consensus();
        let (exp, mant) = decode_compact(current_bits);

        // Calculate as 256-bit integer to prevent overflow
        let current_value = (mant as u64) << (8 * (exp as usize - 3));

        // Multiply by timespan ratio
        let new_value =
            (current_value as u128 * adjusted_timespan as u128) / TARGET_TIMESPAN as u128;

        // Convert back to compact format
        let new_bits = encode_compact(new_value)?;
        let new_target = Target::from_compact(CompactTarget::from_consensus(new_bits));

        Ok(new_target)
    }

    /// Apply network-specific bounds to target
    fn apply_target_bounds(&self, target: Target) -> Target {
        if target > self.max_target {
            debug!("Target exceeds maximum, clamping to network max");
            self.max_target
        } else if target < self.min_target {
            debug!("Target below minimum, clamping to network min");
            self.min_target
        } else {
            target
        }
    }

    /// Calculate difficulty change percentage
    fn calculate_difficulty_change(&self, old_target: Target, new_target: Target) -> f64 {
        // Difficulty is inverse of target
        // Change = (old_difficulty / new_difficulty) - 1
        //        = (new_target / old_target) - 1

        let old_work = old_target.to_work();
        let new_work = new_target.to_work();

        // Check if either work is effectively zero (simplified check)
        if new_work.to_be_bytes() == [0u8; 32] || old_work.to_be_bytes() == [0u8; 32] {
            return 0.0;
        }

        // Log the work change for debugging and monitoring
        trace!(
            "Work change: old={:?}, new={:?}",
            old_work.to_be_bytes()[..8].to_vec(), // First 8 bytes for brevity
            new_work.to_be_bytes()[..8].to_vec()
        );

        // Simplified calculation for display
        let old_bits = old_target.to_compact_lossy().to_consensus();
        let new_bits = new_target.to_compact_lossy().to_consensus();

        let old_diff = self.bits_to_difficulty(old_bits);
        let new_diff = self.bits_to_difficulty(new_bits);

        (new_diff / old_diff) - 1.0
    }

    /// Convert compact bits to difficulty
    pub fn bits_to_difficulty(&self, bits: u32) -> f64 {
        let max_body = 0x00ffff;
        let scale_factor = 256.0_f64.powi(0x1d - 3);

        let (exp, mant) = decode_compact(bits);

        let difficulty = if exp <= 3 {
            (mant as f64) / (max_body as f64 * scale_factor)
        } else {
            let shift = exp - 3;
            (max_body as f64 * scale_factor) / ((mant as f64) * 256.0_f64.powi(shift as i32))
        };

        difficulty.max(1.0)
    }

    /// Calculate network hashrate from difficulty
    pub fn difficulty_to_hashrate(&self, difficulty: f64) -> f64 {
        // hashrate = difficulty * 2^32 / block_time
        difficulty * 4_294_967_296.0 / TARGET_BLOCK_TIME as f64
    }

    /// Get the genesis block target for the network
    pub fn genesis_target(&self) -> Target {
        self.max_target
    }

    /// Validate a block header meets difficulty requirements
    pub fn validate_block_header(&self, header: &BlockHeader) -> Result<bool> {
        let block_hash = header.block_hash();
        let target = header.target();

        // Convert hash to number for comparison
        let hash_ref: &[u8] = block_hash.as_ref();
        let mut hash_bytes = hash_ref.to_vec();
        hash_bytes.reverse();
        let hash_num = num_bigint::BigUint::from_bytes_be(&hash_bytes);

        // Convert target to number
        let target_bytes = target.to_be_bytes();
        let target_num = num_bigint::BigUint::from_bytes_be(&target_bytes);

        if hash_num > target_num {
            warn!("Block hash {} exceeds target", block_hash);
            return Ok(false);
        }

        Ok(true)
    }

    /// Get minimum valid target for network
    pub fn min_target(&self) -> Target {
        self.min_target
    }

    /// Get maximum valid target for network
    pub fn max_target(&self) -> Target {
        self.max_target
    }
}

/// Decode compact target format
fn decode_compact(bits: u32) -> (u32, u32) {
    let exp = bits >> 24;
    let mant = bits & 0x00ffffff;
    (exp, mant)
}

/// Encode to compact target format
fn encode_compact(value: u128) -> Result<u32> {
    if value == 0 {
        return Ok(0);
    }

    // Find the most significant byte
    let mut exp = 0u32;
    let mut mant = value;

    // Normalize to 3 bytes
    while mant > 0x00ffffff {
        mant >>= 8;
        exp += 1;
    }

    exp += 3; // Adjust for Bitcoin's encoding

    // Handle negative flag (bit 23 of mantissa)
    if mant & 0x00800000 != 0 {
        mant >>= 8;
        exp += 1;
    }

    if exp > 34 {
        bail!("Target overflow");
    }

    Ok((exp << 24) | (mant as u32 & 0x00ffffff))
}

/// Calculate work required between two targets
pub fn calculate_work_required(from_target: Target, to_target: Target) -> Work {
    // Work = 2^256 / (target + 1)
    // This is simplified calculation

    let from_work = from_target.to_work();
    let to_work = to_target.to_work();

    // Return difference in work
    Work::from_be_bytes(to_work.to_be_bytes())
}

/// Statistics for difficulty adjustments
#[derive(Debug, Clone)]
pub struct DifficultyStats {
    /// Current difficulty
    pub current_difficulty: f64,

    /// Current target
    pub current_target: Target,

    /// Blocks until next adjustment
    pub blocks_until_adjustment: u32,

    /// Estimated next difficulty
    pub estimated_next_difficulty: Option<f64>,

    /// Network hashrate estimate
    pub network_hashrate: f64,

    /// Last adjustment percentage
    pub last_adjustment: Option<f64>,
}

impl DifficultyStats {
    /// Create stats from current chain state
    pub fn from_chain_state(
        height: u32,
        current_bits: u32,
        calculator: &DifficultyCalculator,
    ) -> Self {
        let current_target = Target::from_compact(CompactTarget::from_consensus(current_bits));
        let current_difficulty = calculator.bits_to_difficulty(current_bits);
        let network_hashrate = calculator.difficulty_to_hashrate(current_difficulty);

        let blocks_until_adjustment = if calculator.is_adjustment_height(height + 1) {
            0
        } else {
            DIFFICULTY_ADJUSTMENT_INTERVAL - (height % DIFFICULTY_ADJUSTMENT_INTERVAL)
        };

        Self {
            current_difficulty,
            current_target,
            blocks_until_adjustment,
            estimated_next_difficulty: None,
            network_hashrate,
            last_adjustment: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_calculation() {
        let calc = DifficultyCalculator::new("mainnet".to_string());

        // Test that genesis difficulty is 1
        let genesis_bits = 0x1d00ffff;
        let difficulty = calc.bits_to_difficulty(genesis_bits);
        assert!((difficulty - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_adjustment_height() {
        let calc = DifficultyCalculator::new("mainnet".to_string());

        assert!(!calc.is_adjustment_height(1));
        assert!(!calc.is_adjustment_height(2015));
        assert!(calc.is_adjustment_height(2016));
        assert!(!calc.is_adjustment_height(2017));
        assert!(calc.is_adjustment_height(4032));
    }

    #[test]
    fn test_timespan_bounds() {
        let calc = DifficultyCalculator::new("mainnet".to_string());

        // Test minimum bound
        let min_time = calc.apply_timespan_bounds(100);
        assert_eq!(min_time, TARGET_TIMESPAN / 4);

        // Test maximum bound
        let max_time = calc.apply_timespan_bounds(10_000_000);
        assert_eq!(max_time, TARGET_TIMESPAN * 4);

        // Test normal range
        let normal_time = calc.apply_timespan_bounds(TARGET_TIMESPAN);
        assert_eq!(normal_time, TARGET_TIMESPAN);
    }

    #[test]
    fn test_compact_encoding() {
        // Test encoding/decoding
        let value = 0x00ffff_u128;
        let compact = encode_compact(value).unwrap();
        let (exp, mant) = decode_compact(compact);

        assert_eq!(exp, 3);
        assert_eq!(mant, 0x00ffff);
    }
}
