//! BIP113: Median time-past as endpoint for lock-time calculations
//!
//! This module implements BIP113 which uses the median time of the last 11 blocks
//! (median-time-past or MTP) for lock-time calculations instead of the block's timestamp.
//! This prevents miners from gaming lock-time by setting timestamps in the future.

use anyhow::{bail, Result};
use bitcoin::blockdata::block::Header as BlockHeader;
use tracing::{debug, trace};

/// Number of blocks to use for median time calculation
pub const MEDIAN_TIME_SPAN: usize = 11;

/// Calculate median time-past (MTP) from block headers
///
/// Returns the median timestamp of the last 11 blocks (or fewer if not enough blocks).
/// This is used for lock-time comparisons as per BIP113.
pub fn calculate_median_time_past(headers: &[BlockHeader]) -> u32 {
    if headers.is_empty() {
        return 0;
    }

    // Collect timestamps
    let mut timestamps: Vec<u32> = headers
        .iter()
        .rev() // Start from most recent
        .take(MEDIAN_TIME_SPAN)
        .map(|h| h.time)
        .collect();

    // Sort timestamps
    timestamps.sort_unstable();

    // Return median
    let len = timestamps.len();
    if len == 0 {
        0
    } else if len % 2 == 0 {
        // Even number: average of two middle values
        (timestamps[len / 2 - 1] + timestamps[len / 2]) / 2
    } else {
        // Odd number: middle value
        timestamps[len / 2]
    }
}

/// Check if BIP113 is active at a given block height
///
/// BIP113 activated at block 419328 on mainnet
pub fn is_bip113_active(height: u32, network: bitcoin::Network) -> bool {
    match network {
        bitcoin::Network::Bitcoin => height >= 419328,
        bitcoin::Network::Testnet => height >= 770112,
        bitcoin::Network::Signet => true, // Always active on signet
        bitcoin::Network::Regtest => height >= 1, // Active from block 1 on regtest
        _ => false,
    }
}

/// Validate transaction lock-time using BIP113 rules
///
/// Compares the transaction's lock-time against the median-time-past
/// instead of the block's timestamp when BIP113 is active.
pub fn validate_locktime_bip113(
    tx_locktime: u32,
    block_time: u32,
    median_time_past: u32,
    bip113_active: bool,
) -> Result<bool> {
    // If lock-time is 0, it's always valid
    if tx_locktime == 0 {
        return Ok(true);
    }

    // Determine the comparison time
    let comparison_time = if bip113_active {
        debug!(
            "BIP113 active: using median-time-past {} instead of block time {}",
            median_time_past, block_time
        );
        median_time_past
    } else {
        trace!("BIP113 not active: using block time {}", block_time);
        block_time
    };

    // Check lock-time type (block height vs timestamp)
    let locktime_is_time = tx_locktime >= 500_000_000;

    if locktime_is_time {
        // Time-based lock-time (seconds since Unix epoch)
        Ok(comparison_time >= tx_locktime)
    } else {
        // Height-based lock-time - this function shouldn't be called for height locks
        bail!("Height-based lock-time should be validated against block height, not time")
    }
}

/// Get the time to use for lock-time comparisons
///
/// Returns median-time-past if BIP113 is active, otherwise block time
pub fn get_locktime_comparison_time(
    block_time: u32,
    median_time_past: u32,
    bip113_active: bool,
) -> u32 {
    if bip113_active {
        median_time_past
    } else {
        block_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::block::Version;
    use bitcoin::hashes::Hash;

    fn create_header(time: u32) -> BlockHeader {
        BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        }
    }

    #[test]
    fn test_median_time_calculation() -> Result<()> {
        // Test with odd number of blocks
        let headers = vec![
            create_header(1000),
            create_header(1100),
            create_header(1050),
            create_header(1200),
            create_header(1150),
        ];

        let mtp = calculate_median_time_past(&headers);
        // Sorted: [1000, 1050, 1100, 1150, 1200], median = 1100
        assert_eq!(mtp, 1100);

        // Test with even number of blocks
        let headers = vec![
            create_header(1000),
            create_header(1100),
            create_header(1050),
            create_header(1200),
        ];

        let mtp = calculate_median_time_past(&headers);
        // Sorted: [1000, 1050, 1100, 1200], median = (1050 + 1100) / 2 = 1075
        assert_eq!(mtp, 1075);

        Ok(())
    }

    #[test]
    fn test_full_median_span() -> Result<()> {
        // Test with exactly 15 blocks
        let headers: Vec<BlockHeader> = (0..15).map(|i| create_header(1000 + i * 100)).collect();

        let mtp = calculate_median_time_past(&headers);
        // Headers have times: 1000, 1100, 1200, ..., 2400 (15 blocks)
        // Last 11 blocks in reverse: 2400, 2300, 2200, 2100, 2000, 1900, 1800, 1700, 1600, 1500, 1400
        // Sorted: [1400, 1500, 1600, 1700, 1800, 1900, 2000, 2100, 2200, 2300, 2400]
        // Median = 1900 (6th element, index 5 of 11 elements)
        assert_eq!(mtp, 1900);

        Ok(())
    }

    #[test]
    fn test_bip113_activation() -> Result<()> {
        use bitcoin::Network;

        // Mainnet
        assert!(!is_bip113_active(419327, Network::Bitcoin));
        assert!(is_bip113_active(419328, Network::Bitcoin));
        assert!(is_bip113_active(500000, Network::Bitcoin));

        // Testnet
        assert!(!is_bip113_active(770111, Network::Testnet));
        assert!(is_bip113_active(770112, Network::Testnet));

        // Signet (always active)
        assert!(is_bip113_active(0, Network::Signet));
        assert!(is_bip113_active(1, Network::Signet));

        // Regtest (active from block 1)
        assert!(!is_bip113_active(0, Network::Regtest));
        assert!(is_bip113_active(1, Network::Regtest));

        Ok(())
    }

    #[test]
    fn test_locktime_validation() -> Result<()> {
        // Test time-based lock-time with BIP113 active
        let tx_locktime = 1500000000; // Time-based (> 500M)
        let block_time = 1500000100;
        let mtp = 1500000050;

        // With BIP113: use MTP (1500000050) >= tx_locktime (1500000000) = true
        assert!(validate_locktime_bip113(
            tx_locktime,
            block_time,
            mtp,
            true
        )?);

        // Without BIP113: use block_time (1500000100) >= tx_locktime (1500000000) = true
        assert!(validate_locktime_bip113(
            tx_locktime,
            block_time,
            mtp,
            false
        )?);

        // Test failure case
        let tx_locktime = 1500000100; // Higher than MTP
        let mtp = 1500000050;

        // With BIP113: MTP (1500000050) >= tx_locktime (1500000100) = false
        assert!(!validate_locktime_bip113(
            tx_locktime,
            block_time,
            mtp,
            true
        )?);

        Ok(())
    }

    #[test]
    fn test_locktime_zero() -> Result<()> {
        // Lock-time of 0 is always valid
        assert!(validate_locktime_bip113(0, 1000, 500, true)?);
        assert!(validate_locktime_bip113(0, 1000, 500, false)?);

        Ok(())
    }

    #[test]
    fn test_height_based_locktime_error() -> Result<()> {
        // Height-based lock-time should cause an error
        let tx_locktime = 100000; // < 500M, so height-based
        let result = validate_locktime_bip113(tx_locktime, 200000, 150000, true);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Height-based"));

        Ok(())
    }
}
