use bitcoin::Target;
use num_bigint::{BigUint, ToBigUint};
use num_traits::{One, Zero};
use std::cmp::Ordering;

/// Represents cumulative chain work as a 256-bit integer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainWork {
    value: BigUint,
}

impl ChainWork {
    /// Create a new ChainWork with zero value
    pub fn zero() -> Self {
        Self {
            value: BigUint::zero(),
        }
    }

    /// Create ChainWork from a u128 (for backwards compatibility)
    pub fn from_u128(value: u128) -> Self {
        Self {
            value: value.to_biguint().unwrap(),
        }
    }

    /// Calculate work from a block's target using proper 256-bit arithmetic
    /// Work = 2^256 / (target + 1)
    pub fn from_target(target: Target) -> Self {
        // Convert target to BigUint
        let target_bytes = target.to_le_bytes();
        let mut full_bytes = [0u8; 32];
        full_bytes[..target_bytes.len()].copy_from_slice(&target_bytes);

        // Convert to big-endian for BigUint
        full_bytes.reverse();
        let target_value = BigUint::from_bytes_be(&full_bytes);

        // Calculate 2^256
        let two_256: BigUint = BigUint::one() << 256;

        // Work = 2^256 / (target + 1)
        let work = if target_value == BigUint::zero() {
            // Maximum work for zero target (shouldn't happen in practice)
            two_256.clone()
        } else {
            two_256 / (target_value + BigUint::one())
        };

        Self { value: work }
    }

    /// Add two ChainWork values
    pub fn add(&self, other: &ChainWork) -> ChainWork {
        Self {
            value: &self.value + &other.value,
        }
    }

    /// Subtract two ChainWork values (saturating)
    pub fn saturating_sub(&self, other: &ChainWork) -> ChainWork {
        if self.value > other.value {
            Self {
                value: &self.value - &other.value,
            }
        } else {
            Self::zero()
        }
    }

    /// Compare two ChainWork values
    pub fn cmp(&self, other: &ChainWork) -> Ordering {
        self.value.cmp(&other.value)
    }

    /// Check if this work is greater than another
    pub fn is_greater_than(&self, other: &ChainWork) -> bool {
        self.value > other.value
    }

    /// Convert to u128 (may overflow for very large values)
    pub fn to_u128(&self) -> u128 {
        // Try to convert, return MAX if too large
        if self.value.bits() > 128 {
            u128::MAX
        } else {
            // Convert to bytes and then to u128
            let bytes = self.value.to_bytes_le();
            let mut u128_bytes = [0u8; 16];
            let len = bytes.len().min(16);
            u128_bytes[..len].copy_from_slice(&bytes[..len]);
            u128::from_le_bytes(u128_bytes)
        }
    }

    /// Get a human-readable string representation
    pub fn to_hex_string(&self) -> String {
        format!("{:064x}", self.value)
    }

    /// Convert to bytes (32 bytes, big-endian)
    pub fn to_bytes(&self) -> [u8; 32] {
        let bytes = self.value.to_bytes_be();
        let mut result = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        result[start..].copy_from_slice(&bytes);
        result
    }

    /// Create from bytes (32 bytes, big-endian)
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self {
            value: BigUint::from_bytes_be(&bytes),
        }
    }

    /// Check if this work is zero
    pub fn is_zero(&self) -> bool {
        self.value.is_zero()
    }

    /// Calculate the work for a chain of blocks
    pub fn calculate_chain_work(targets: &[Target]) -> Self {
        let mut total = Self::zero();
        for target in targets {
            total = total.add(&Self::from_target(*target));
        }
        total
    }

    /// Get the approximate log2 of the work (useful for comparison)
    pub fn log2(&self) -> f64 {
        if self.value.is_zero() {
            0.0
        } else {
            self.value.bits() as f64
        }
    }
}

impl Default for ChainWork {
    fn default() -> Self {
        Self::zero()
    }
}

impl std::fmt::Display for ChainWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChainWork({})", self.to_hex_string())
    }
}

impl From<u128> for ChainWork {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl PartialOrd for ChainWork {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ChainWork {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::CompactTarget;

    #[test]
    fn test_chain_work_from_target() {
        // Test with a typical mainnet target
        let compact = CompactTarget::from_consensus(0x1b0404cb);
        let target = Target::from(compact);

        let work = ChainWork::from_target(target);

        // Work should be non-zero
        assert!(!work.value.is_zero());

        // Check that work calculation is deterministic
        let work2 = ChainWork::from_target(target);
        assert_eq!(work, work2);
    }

    #[test]
    fn test_chain_work_addition() {
        let work1 = ChainWork::from_u128(1000);
        let work2 = ChainWork::from_u128(2000);

        let total = work1.add(&work2);
        assert_eq!(total.to_u128(), 3000);
    }

    #[test]
    fn test_chain_work_comparison() {
        let work1 = ChainWork::from_u128(1000);
        let work2 = ChainWork::from_u128(2000);

        assert!(work2.is_greater_than(&work1));
        assert!(!work1.is_greater_than(&work2));
        assert_eq!(work1.cmp(&work1), Ordering::Equal);
    }

    #[test]
    fn test_chain_work_subtraction() {
        let work1 = ChainWork::from_u128(3000);
        let work2 = ChainWork::from_u128(1000);

        let diff = work1.saturating_sub(&work2);
        assert_eq!(diff.to_u128(), 2000);

        // Test saturating behavior
        let diff2 = work2.saturating_sub(&work1);
        assert_eq!(diff2, ChainWork::zero());
    }

    #[test]
    fn test_difficulty_one_target() {
        // Maximum target (difficulty 1)
        let max_target = Target::MAX;
        let work = ChainWork::from_target(max_target);

        // Work for difficulty 1 should be very small
        assert!(work.value.bits() < 100);
    }

    #[test]
    fn test_high_difficulty_target() {
        // A high difficulty target (small target value)
        let compact = CompactTarget::from_consensus(0x170b3ce0);
        let target = Target::from(compact);

        let work = ChainWork::from_target(target);

        // Higher difficulty should result in more work
        let easy_work = ChainWork::from_target(Target::MAX);
        assert!(work.is_greater_than(&easy_work));
    }
}
