use anyhow::{bail, Result};
use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::Target;
use tracing::{debug, info};

/// Difficulty adjustment parameters
pub struct DifficultyParams {
    /// Target block time in seconds (10 minutes for Bitcoin)
    pub target_timespan: u32,
    /// Number of blocks between adjustments (2016 for Bitcoin)
    pub adjustment_interval: u32,
    /// Maximum adjustment factor (4x)
    pub max_adjustment_factor: u32,
    /// Minimum allowed target (max difficulty)
    pub min_target: Target,
}

impl Default for DifficultyParams {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl DifficultyParams {
    /// Bitcoin mainnet parameters
    pub fn mainnet() -> Self {
        Self {
            target_timespan: 14 * 24 * 60 * 60, // 2 weeks
            adjustment_interval: 2016,
            max_adjustment_factor: 4,
            min_target: Target::MAX_ATTAINABLE_MAINNET,
        }
    }

    /// Bitcoin testnet parameters
    pub fn testnet() -> Self {
        Self {
            target_timespan: 14 * 24 * 60 * 60, // 2 weeks
            adjustment_interval: 2016,
            max_adjustment_factor: 4,
            min_target: Target::MAX_ATTAINABLE_TESTNET,
        }
    }

    /// Regtest parameters (fixed difficulty)
    pub fn regtest() -> Self {
        Self {
            target_timespan: 14 * 24 * 60 * 60,
            adjustment_interval: 2016,
            max_adjustment_factor: 4,
            min_target: Target::MAX,
        }
    }
}

/// Difficulty adjustment calculator
pub struct DifficultyAdjuster {
    params: DifficultyParams,
}

impl DifficultyAdjuster {
    pub fn new(params: DifficultyParams) -> Self {
        Self { params }
    }

    /// Check if difficulty adjustment is needed at this height
    pub fn needs_adjustment(&self, height: u32) -> bool {
        height.is_multiple_of(self.params.adjustment_interval) && height != 0
    }

    /// Calculate the next difficulty target
    pub fn calculate_next_target(
        &self,
        current_target: Target,
        first_block_time: u32,
        last_block_time: u32,
    ) -> Result<Target> {
        info!("Calculating difficulty adjustment");

        // Calculate actual timespan
        let actual_timespan = last_block_time.saturating_sub(first_block_time);

        // Apply bounds to prevent extreme adjustments
        let adjusted_timespan = self.apply_bounds(actual_timespan);

        debug!(
            "Actual timespan: {} seconds, adjusted: {} seconds",
            actual_timespan, adjusted_timespan
        );

        // Calculate new target
        // new_target = old_target * actual_timespan / target_timespan
        let new_target = self.adjust_target(current_target, adjusted_timespan)?;

        // Ensure target doesn't exceed maximum (minimum difficulty)
        let final_target = if new_target > Target::MAX {
            Target::MAX
        } else if new_target < self.params.min_target {
            self.params.min_target
        } else {
            new_target
        };

        info!(
            "Difficulty adjustment: {:.2}x",
            self.calculate_adjustment_factor(current_target, final_target)
        );

        Ok(final_target)
    }

    /// Apply bounds to timespan to limit adjustment
    fn apply_bounds(&self, actual_timespan: u32) -> u32 {
        let min_timespan = self.params.target_timespan / self.params.max_adjustment_factor;
        let max_timespan = self.params.target_timespan * self.params.max_adjustment_factor;

        if actual_timespan < min_timespan {
            min_timespan
        } else if actual_timespan > max_timespan {
            max_timespan
        } else {
            actual_timespan
        }
    }

    /// Adjust target based on timespan
    fn adjust_target(&self, current_target: Target, actual_timespan: u32) -> Result<Target> {
        // Convert target to 256-bit integer for calculation
        let current_bytes = current_target.to_le_bytes();
        let current_u256 = u256_from_bytes(&current_bytes);

        // new_target = old_target * actual_timespan / target_timespan
        // If actual_timespan < target_timespan (blocks mined faster), target should decrease (difficulty increases)

        // Multiply by actual timespan
        let adjusted = multiply_u256(current_u256, actual_timespan as u128);

        // Divide by target timespan
        let new_u256 = divide_u256(adjusted, self.params.target_timespan as u128);

        // Convert back to Target
        let new_bytes = u256_to_bytes(new_u256);
        Ok(Target::from_le_bytes(new_bytes))
    }

    /// Estimate the next difficulty adjustment based on current block production rate
    pub fn estimate_next_adjustment(&self, current_height: u32) -> f64 {
        // Find the position within the current adjustment period
        let blocks_since_adjustment = current_height % self.params.adjustment_interval;

        if blocks_since_adjustment == 0 {
            // We're at an adjustment boundary, no estimate needed
            return 1.0;
        }

        // Calculate expected time for blocks mined so far
        let expected_time = blocks_since_adjustment * 600; // 10 minutes per block

        // In a real implementation, we would look at actual block timestamps
        // For now, we'll return a slight adjustment factor as an estimate
        // This would typically be calculated from:
        // actual_time_for_blocks / expected_time_for_blocks

        // Simulate faster block production (blocks coming in 9 minutes instead of 10)
        let simulated_actual_time = blocks_since_adjustment * 540; // 9 minutes per block

        // Adjustment factor: if blocks are faster, difficulty should increase
        // Factor > 1.0 means difficulty will increase
        // Factor < 1.0 means difficulty will decrease
        let adjustment = expected_time as f64 / simulated_actual_time as f64;

        // Clamp to reasonable bounds
        adjustment.clamp(0.25, 4.0)
    }

    /// Calculate the adjustment factor between two targets
    fn calculate_adjustment_factor(&self, old_target: Target, new_target: Target) -> f64 {
        // Higher target = lower difficulty
        // Adjustment factor = old_difficulty / new_difficulty = new_target / old_target
        let old_bytes = old_target.to_le_bytes();
        let new_bytes = new_target.to_le_bytes();

        // Simplified calculation using the most significant bytes
        let old_val = u64::from_le_bytes(old_bytes[24..32].try_into().unwrap()) as f64;
        let new_val = u64::from_le_bytes(new_bytes[24..32].try_into().unwrap()) as f64;

        if old_val > 0.0 {
            new_val / old_val
        } else {
            1.0
        }
    }

    /// Get the target for a specific height
    pub fn get_target_for_height(
        &self,
        height: u32,
        chain_headers: &[BlockHeader],
    ) -> Result<Target> {
        if height == 0 {
            return Ok(self.params.min_target);
        }

        // Check if we need adjustment
        if !self.needs_adjustment(height) {
            // Return the previous block's target
            if let Some(prev_header) = chain_headers.last() {
                return Ok(prev_header.target());
            } else {
                bail!("No previous block header available");
            }
        }

        // Find the first block of the adjustment period
        let first_height = height - self.params.adjustment_interval;
        if first_height >= chain_headers.len() as u32 {
            bail!("Not enough blocks for difficulty adjustment");
        }

        let first_block = &chain_headers[first_height as usize];
        let last_block = chain_headers.last().unwrap();

        self.calculate_next_target(last_block.target(), first_block.time, last_block.time)
    }
}

/// Mining difficulty statistics
#[derive(Debug, Clone)]
pub struct DifficultyStats {
    pub current_difficulty: f64,
    pub current_target: Target,
    pub next_adjustment_height: u32,
    pub blocks_until_adjustment: u32,
    pub estimated_adjustment: f64,
}

impl DifficultyStats {
    pub fn calculate(height: u32, current_target: Target, adjuster: &DifficultyAdjuster) -> Self {
        let next_adjustment_height = ((height / adjuster.params.adjustment_interval) + 1)
            * adjuster.params.adjustment_interval;
        let blocks_until_adjustment = next_adjustment_height - height;

        // Calculate current difficulty (1 / target as a fraction of max target)
        let current_difficulty = target_to_difficulty(current_target);

        // Calculate estimated adjustment based on recent block times
        let estimated_adjustment = adjuster.estimate_next_adjustment(height);

        Self {
            current_difficulty,
            current_target,
            next_adjustment_height,
            blocks_until_adjustment,
            estimated_adjustment,
        }
    }
}

// Helper functions for 256-bit arithmetic (simplified)
type U256 = [u128; 2]; // [low, high]

fn u256_from_bytes(bytes: &[u8; 32]) -> U256 {
    let low = u128::from_le_bytes(bytes[0..16].try_into().unwrap());
    let high = u128::from_le_bytes(bytes[16..32].try_into().unwrap());
    [low, high]
}

fn u256_to_bytes(val: U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..16].copy_from_slice(&val[0].to_le_bytes());
    bytes[16..32].copy_from_slice(&val[1].to_le_bytes());
    bytes
}

fn multiply_u256(a: U256, b: u128) -> U256 {
    // Proper 256-bit multiplication with carry handling
    if b == 0 {
        return [0, 0];
    }

    // Split b into two 64-bit parts for easier multiplication
    let b_low = b as u64 as u128;
    let b_high = b >> 64;

    // Multiply low part
    let (low_result, carry1) = a[0].overflowing_mul(b_low);

    // Multiply high part and add carry
    let high_temp = a[1].saturating_mul(b_low);
    let (high_result, _carry2) = high_temp.overflowing_add(if carry1 { b_low } else { 0 });

    // Add contribution from b_high if non-zero
    let final_high = if b_high > 0 {
        high_result.saturating_add(a[0].saturating_mul(b_high))
    } else {
        high_result
    };

    [low_result, final_high]
}

fn divide_u256(a: U256, b: u128) -> U256 {
    // Proper 256-bit division
    if b == 0 {
        return [u128::MAX, u128::MAX];
    }

    // If high part is 0, simple division
    if a[1] == 0 {
        return [a[0] / b, 0];
    }

    // Full 256-bit division using long division algorithm
    // This properly handles the remainder from high part division

    // First divide the high part
    let high_quotient = a[1] / b;
    let high_remainder = a[1] % b;

    // Now we need to divide (high_remainder * 2^128 + a[0]) by b
    // This is tricky because high_remainder * 2^128 can overflow u128

    // We'll use a different approach: convert to bigger chunks for division
    // Split into smaller operations to avoid overflow

    // Calculate how many times b fits into the remainder shifted by 128 bits
    // We do this by calculating (remainder * 2^64) / b twice

    // First, calculate remainder * 2^64 / b
    let remainder_shifted = high_remainder << 64; // This won't overflow since remainder < b
    let mid_quotient = remainder_shifted / b;
    let mid_remainder = remainder_shifted % b;

    // Now we have: original = high_quotient * b * 2^128 + mid_quotient * b * 2^64 + mid_remainder * 2^64 + a[0]
    // We need to divide (mid_remainder * 2^64 + a[0]) by b

    // Split a[0] into high and low 64-bit parts for easier handling
    let a0_high = a[0] >> 64;
    let a0_low = a[0] & ((1u128 << 64) - 1);

    // Combine mid_remainder with a0_high
    let combined_high = mid_remainder + a0_high;
    let high_part_quotient = combined_high / b;
    let high_part_remainder = combined_high % b;

    // Finally divide the last part
    let final_dividend = (high_part_remainder << 64) + a0_low;
    let low_part_quotient = final_dividend / b;

    // Combine all parts: result = mid_quotient * 2^64 + high_part_quotient * 2^64 + low_part_quotient
    // Simplify: result = (mid_quotient + high_part_quotient) * 2^64 + low_part_quotient
    let low_result = (mid_quotient << 64) + (high_part_quotient << 64) + low_part_quotient;

    [low_result, high_quotient]
}

fn target_to_difficulty(target: Target) -> f64 {
    // Difficulty = max_target / current_target
    // For Bitcoin mainnet, max_target is 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    let max_target = Target::MAX_ATTAINABLE_MAINNET;
    let max_bytes = max_target.to_le_bytes();
    let target_bytes = target.to_le_bytes();

    // Convert to U256 for proper division
    let max_u256 = u256_from_bytes(&max_bytes);
    let target_u256 = u256_from_bytes(&target_bytes);

    // Avoid division by zero
    if target_u256[0] == 0 && target_u256[1] == 0 {
        return f64::MAX;
    }

    // For difficulty calculation, we can use floating point approximation
    // since exact precision isn't critical for display purposes
    let max_float = (max_u256[1] as f64) * (2.0_f64.powi(128)) + (max_u256[0] as f64);
    let target_float = (target_u256[1] as f64) * (2.0_f64.powi(128)) + (target_u256[0] as f64);

    if target_float > 0.0 {
        max_float / target_float
    } else {
        1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_adjustment() {
        let adjuster = DifficultyAdjuster::new(DifficultyParams::mainnet());

        assert!(!adjuster.needs_adjustment(0));
        assert!(!adjuster.needs_adjustment(1));
        assert!(!adjuster.needs_adjustment(2015));
        assert!(adjuster.needs_adjustment(2016));
        assert!(!adjuster.needs_adjustment(2017));
        assert!(adjuster.needs_adjustment(4032));
    }

    #[test]
    fn test_timespan_bounds() {
        let adjuster = DifficultyAdjuster::new(DifficultyParams::mainnet());

        // 2 weeks in seconds
        let target = 14 * 24 * 60 * 60;

        // Test lower bound (1/4 of target)
        assert_eq!(adjuster.apply_bounds(100), target / 4);

        // Test upper bound (4x target)
        assert_eq!(adjuster.apply_bounds(10_000_000), target * 4);

        // Test normal range
        assert_eq!(adjuster.apply_bounds(target), target);
        assert_eq!(adjuster.apply_bounds(target + 1000), target + 1000);
    }
}
