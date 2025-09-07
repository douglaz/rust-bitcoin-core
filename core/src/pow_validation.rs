use anyhow::{bail, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::Params;
use bitcoin::{Block, BlockHash, Network, Target, Work};
use num_bigint::BigUint;
use std::collections::HashMap;
use tracing::{debug, info, trace, warn};

/// Proof of Work validator
pub struct PowValidator {
    /// Network parameters
    network: Network,
    /// Cached work calculations
    work_cache: HashMap<BlockHash, Work>,
    /// Maximum target (minimum difficulty)
    max_target: Target,
}

impl PowValidator {
    /// Create new PoW validator
    pub fn new(network: Network) -> Self {
        let max_target = match network {
            Network::Bitcoin => Target::MAX_ATTAINABLE_MAINNET,
            Network::Testnet => Target::MAX_ATTAINABLE_TESTNET,
            Network::Regtest => Target::MAX_ATTAINABLE_REGTEST,
            Network::Signet => Target::MAX_ATTAINABLE_SIGNET,
            _ => Target::MAX_ATTAINABLE_TESTNET,
        };

        info!(
            "Creating PowValidator for network={:?}, max_target={:?}",
            network, max_target
        );

        Self {
            network,
            work_cache: HashMap::new(),
            max_target,
        }
    }

    /// Validate block header proof of work
    pub fn validate_header_pow(&self, header: &BlockHeader) -> Result<()> {
        // For regtest, skip PoW validation entirely
        if self.network == Network::Regtest {
            info!(
                "Skipping PoW validation for regtest network (network={:?})",
                self.network
            );
            return Ok(());
        }

        let target = header.target();
        let hash = header.block_hash();

        debug!("Validating PoW for block {}", hash);

        // Check target is not too easy (above max)
        if target > self.max_target {
            bail!(
                "Block target {:?} exceeds maximum {:?}",
                target,
                self.max_target
            );
        }

        // Convert hash to target for comparison
        use bitcoin::hashes::Hash;
        let hash_bytes = hash.to_byte_array();
        let hash_as_target = Target::from_le_bytes(hash_bytes);

        // Check if hash meets target difficulty
        if hash_as_target > target {
            bail!(
                "Block hash {} does not meet target difficulty {:?}",
                hash,
                target
            );
        }

        debug!("Block {} has valid proof of work", hash);
        Ok(())
    }

    /// Validate full block proof of work
    pub fn validate_block_pow(&self, block: &Block) -> Result<()> {
        self.validate_header_pow(&block.header)
    }

    /// Calculate work for a block header
    pub fn calculate_work(&mut self, header: &BlockHeader) -> Work {
        let hash = header.block_hash();

        // Check cache first
        if let Some(&work) = self.work_cache.get(&hash) {
            return work;
        }

        // Calculate work
        let work = header.work();

        // Cache for future use
        self.work_cache.insert(hash, work);

        work
    }

    /// Calculate cumulative work for a chain of headers
    pub fn calculate_chain_work(&mut self, headers: &[BlockHeader]) -> Work {
        headers
            .iter()
            .map(|h| self.calculate_work(h))
            .fold(Work::from_be_bytes([0u8; 32]), |acc, w| acc + w)
    }

    /// Validate difficulty adjustment
    pub fn validate_difficulty_adjustment(
        &self,
        new_header: &BlockHeader,
        previous_header: &BlockHeader,
        height: u32,
    ) -> Result<()> {
        // Check if this is a difficulty adjustment block
        if !self.is_difficulty_adjustment_block(height) {
            // Not an adjustment block, difficulty should remain the same
            if new_header.bits != previous_header.bits {
                bail!(
                    "Unexpected difficulty change at height {}: {:?} -> {:?}",
                    height,
                    previous_header.bits,
                    new_header.bits
                );
            }
            return Ok(());
        }

        // For adjustment blocks, validate the new difficulty
        // This would require looking at the past 2016 blocks
        // For now, we'll accept any valid difficulty at adjustment heights
        info!(
            "Difficulty adjustment at height {}: {:?} -> {:?}",
            height, previous_header.bits, new_header.bits
        );

        Ok(())
    }

    /// Check if height is a difficulty adjustment block
    fn is_difficulty_adjustment_block(&self, height: u32) -> bool {
        match self.network {
            Network::Bitcoin | Network::Testnet | Network::Signet => {
                // Difficulty adjusts every 2016 blocks
                height % 2016 == 0
            }
            Network::Regtest => {
                // No difficulty adjustment in regtest
                false
            }
            _ => false,
        }
    }

    /// Validate timestamp
    pub fn validate_timestamp(
        &self,
        header: &BlockHeader,
        previous_header: &BlockHeader,
        median_time_past: u32,
    ) -> Result<()> {
        // Check timestamp is greater than median time past
        if header.time <= median_time_past {
            bail!(
                "Block timestamp {} not greater than median time past {}",
                header.time,
                median_time_past
            );
        }

        // Check timestamp is not too far in the future
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as u32;

        // Allow 2 hours in the future
        if header.time > now + 7200 {
            bail!(
                "Block timestamp {} too far in future (current time: {})",
                header.time,
                now
            );
        }

        // For Bitcoin mainnet, check that timestamp is greater than previous
        if self.network == Network::Bitcoin && header.time <= previous_header.time {
            warn!(
                "Block timestamp {} not greater than previous {}",
                header.time, previous_header.time
            );
        }

        Ok(())
    }

    /// Calculate median time past from previous headers
    pub fn calculate_median_time_past(&self, headers: &[BlockHeader]) -> u32 {
        if headers.is_empty() {
            return 0;
        }

        // Get last 11 blocks (or fewer if not available)
        let count = headers.len().min(11);
        let mut timestamps: Vec<u32> = headers[headers.len() - count..]
            .iter()
            .map(|h| h.time)
            .collect();

        // Sort timestamps
        timestamps.sort_unstable();

        // Return median
        timestamps[timestamps.len() / 2]
    }

    /// Validate version bits
    pub fn validate_version(&self, header: &BlockHeader, height: u32) -> Result<()> {
        // BIP 9 version bits
        if height >= 419328 && self.network == Network::Bitcoin {
            let version = header.version.to_consensus();

            // Top 3 bits should be 001 for version 4+ blocks
            if version < 0x20000000 {
                warn!(
                    "Block at height {} has outdated version: {:08x}",
                    height, version
                );
            }
        }

        Ok(())
    }

    /// Check if a hash meets a target difficulty
    pub fn check_pow(hash: &BlockHash, target: Target) -> bool {
        use bitcoin::hashes::Hash;
        let hash_bytes = hash.to_byte_array();
        let hash_as_target = Target::from_le_bytes(hash_bytes);
        hash_as_target <= target
    }

    /// Get minimum difficulty for network
    pub fn min_difficulty(&self) -> Target {
        self.max_target
    }

    /// Validate retargeting
    pub fn validate_retarget(
        &self,
        first_block_time: u32,
        last_block_time: u32,
        old_target: Target,
        new_target: Target,
    ) -> Result<()> {
        // Calculate actual timespan
        let actual_timespan = last_block_time.saturating_sub(first_block_time);

        // Target timespan is 2 weeks
        const TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60; // 2 weeks in seconds
        const MAX_ADJUST: u32 = TARGET_TIMESPAN * 4;
        const MIN_ADJUST: u32 = TARGET_TIMESPAN / 4;

        // Limit adjustment factor
        let adjusted_timespan = actual_timespan.clamp(MIN_ADJUST, MAX_ADJUST);

        // Calculate new target (in simplified form)
        // new_target = old_target * adjusted_timespan / target_timespan

        debug!(
            "Retarget validation: actual_timespan={}, adjusted_timespan={}, old_target={:?}, new_target={:?}",
            actual_timespan, adjusted_timespan, old_target, new_target
        );

        // For now, accept the retarget if it's within reasonable bounds
        if new_target > self.max_target {
            bail!("New target exceeds maximum allowed difficulty");
        }

        Ok(())
    }
}


/// Calculate the next required work target
pub fn calculate_next_work_required(
    last_block_header: &BlockHeader,
    first_block_header: &BlockHeader,
    params: &Params,
) -> Target {
    // This is a simplified version
    // In production, would use full Bitcoin consensus rules

    let last_block_time = last_block_header.time;
    let first_block_time = first_block_header.time;

    // Calculate actual timespan
    let actual_timespan = last_block_time.saturating_sub(first_block_time);

    // Target timespan is 2 weeks
    const TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60;
    const MAX_ADJUST: u32 = TARGET_TIMESPAN * 4;
    const MIN_ADJUST: u32 = TARGET_TIMESPAN / 4;

    // Limit adjustment
    let adjusted_timespan = actual_timespan.clamp(MIN_ADJUST, MAX_ADJUST);

    // Get old target
    let old_target = last_block_header.target();

    // Calculate new target
    // This is simplified - proper implementation would use big integer arithmetic
    let old_compact = last_block_header.bits;

    // Log difficulty adjustment calculation
    info!(
        "Difficulty adjustment: actual_timespan={}, adjusted_timespan={}, old_bits={:#x}",
        actual_timespan, adjusted_timespan, old_compact
    );

    // Calculate new target: new_target = old_target * adjusted_timespan / TARGET_TIMESPAN
    // Using BigUint for precise 256-bit arithmetic
    
    // Convert old target to BigUint (256-bit big-endian)
    let old_target_bytes = old_target.to_be_bytes();
    let old_target_bigint = BigUint::from_bytes_be(&old_target_bytes);
    
    // Perform the calculation: (old_target * adjusted_timespan) / TARGET_TIMESPAN
    let adjusted_timespan_bigint = BigUint::from(adjusted_timespan);
    let target_timespan_bigint = BigUint::from(TARGET_TIMESPAN);
    
    let new_target_bigint = (&old_target_bigint * &adjusted_timespan_bigint) / &target_timespan_bigint;
    
    // Ensure the result fits in 256 bits
    let max_target = BigUint::from(1u32) << 256;
    let new_target_clamped = if new_target_bigint >= max_target {
        max_target - BigUint::from(1u32)
    } else {
        new_target_bigint
    };
    
    // Convert back to 32-byte array for Target
    let new_target_bytes_vec = new_target_clamped.to_bytes_be();
    let mut new_target_bytes = [0u8; 32];
    
    // Pad with zeros if necessary (for smaller targets)
    let offset = 32_usize.saturating_sub(new_target_bytes_vec.len());
    new_target_bytes[offset..].copy_from_slice(&new_target_bytes_vec);
    
    // Create the new Target
    let new_target = Target::from_be_bytes(new_target_bytes);
    
    // Log the adjustment
    if adjusted_timespan != TARGET_TIMESPAN {
        let adjustment_ratio = (adjusted_timespan as f64) / (TARGET_TIMESPAN as f64);
        info!(
            "Difficulty adjustment by factor {:.4} ({}/{})",
            adjustment_ratio,
            adjusted_timespan,
            TARGET_TIMESPAN
        );
        
        debug!(
            "Old target: {:064x}, New target: {:064x}",
            old_target_bigint,
            new_target_clamped
        );
    }
    
    new_target
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    #[test]
    fn test_work_calculation_and_adjustment() {
        // Test that adjusted_timespan and old_compact are properly used
        let first_header = BlockHeader {
            version: bitcoin::blockdata::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1000000,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        };
        
        let last_header = BlockHeader {
            version: bitcoin::blockdata::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1000000 + (14 * 24 * 60 * 60) + 3600, // 2 weeks + 1 hour
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        };
        
        let params = Params::new(Network::Bitcoin);
        
        // This should calculate adjusted timespan and use it
        let new_target = calculate_next_work_required(&last_header, &first_header, &params);
        
        // The target should be adjusted based on the timespan ratio
        // Since we took 2 weeks + 1 hour instead of exactly 2 weeks,
        // the target should be slightly easier (higher value)
        let old_target = last_header.target();
        
        // Verify that the target was actually adjusted
        assert_ne!(new_target, old_target, "Target should be adjusted based on timespan");
        
        // Since we took more time than expected (2 weeks + 1 hour), 
        // the new target should be easier (higher value)
        assert!(new_target > old_target, 
                "Target should be easier (higher) when blocks took longer than expected");
    }

    #[test]
    fn test_pow_validation() {
        let validator = PowValidator::new(Network::Bitcoin); // Use Bitcoin network for stricter validation

        // Create a header with invalid PoW
        let header = BlockHeader {
            version: bitcoin::blockdata::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff), // Standard difficulty
            nonce: 0,
        };

        // This should fail because nonce=0 doesn't produce valid PoW for this difficulty
        let result = validator.validate_header_pow(&header);
        assert!(
            result.is_err(),
            "Expected PoW validation to fail for invalid header"
        );

        // Test with regtest where difficulty is minimal
        let regtest_validator = PowValidator::new(Network::Regtest);
        let regtest_header = BlockHeader {
            version: bitcoin::blockdata::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff), // Regtest difficulty
            nonce: 2, // Small nonce should work with regtest difficulty
        };

        // For regtest, validation may pass or fail depending on the actual hash
        // We just verify it doesn't panic
        let _ = regtest_validator.validate_header_pow(&regtest_header);
    }

    #[test]
    fn test_difficulty_adjustment_detection() {
        let validator = PowValidator::new(Network::Bitcoin);

        assert!(validator.is_difficulty_adjustment_block(0));
        assert!(validator.is_difficulty_adjustment_block(2016));
        assert!(validator.is_difficulty_adjustment_block(4032));
        assert!(!validator.is_difficulty_adjustment_block(1));
        assert!(!validator.is_difficulty_adjustment_block(2015));
        assert!(!validator.is_difficulty_adjustment_block(2017));
    }

    #[test]
    fn test_median_time_calculation() {
        let validator = PowValidator::new(Network::Bitcoin);

        let headers: Vec<BlockHeader> = (0..11)
            .map(|i| BlockHeader {
                version: bitcoin::blockdata::block::Version::from_consensus(1),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1000 + i * 100,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            })
            .collect();

        let median = validator.calculate_median_time_past(&headers);
        assert_eq!(median, 1500); // Middle value of 1000-2000
    }

    #[test]
    fn test_work_calculation() {
        let mut validator = PowValidator::new(Network::Bitcoin);

        let header = BlockHeader {
            version: bitcoin::blockdata::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x1b0404cb),
            nonce: 0,
        };

        let work1 = validator.calculate_work(&header);
        let work2 = validator.calculate_work(&header); // Should come from cache

        assert_eq!(work1, work2);
        assert_eq!(validator.work_cache.len(), 1);
    }
}
