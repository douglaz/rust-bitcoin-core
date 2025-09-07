//! BIP68: Relative lock-time using consensus-enforced sequence numbers
//!
//! This module implements BIP68 which introduces relative lock-time through
//! the use of sequence numbers. It allows transactions to be locked until
//! a certain number of blocks or time has passed since the input was confirmed.

use anyhow::{bail, Result};
use bitcoin::{Sequence, Transaction};
use tracing::{debug, trace};

/// BIP68 constants
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;
pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 512; // 512 seconds

/// Represents a relative lock-time from BIP68
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelativeLockTime {
    /// Lock-time disabled (sequence >= 0x80000000)
    Disabled,
    /// Relative height-based lock (number of blocks)
    Blocks(u16),
    /// Relative time-based lock (multiple of 512 seconds)
    Time(u16),
}

impl RelativeLockTime {
    /// Parse a sequence number according to BIP68
    pub fn from_sequence(sequence: Sequence) -> Self {
        let n = sequence.0;

        // If the disable flag is set, relative lock-time is disabled
        if n & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return RelativeLockTime::Disabled;
        }

        // Extract the lock-time value
        let lock_value = (n & SEQUENCE_LOCKTIME_MASK) as u16;

        // Check if it's time-based or block-based
        if n & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
            // Time-based lock (in 512-second granularity)
            RelativeLockTime::Time(lock_value)
        } else {
            // Block-based lock
            RelativeLockTime::Blocks(lock_value)
        }
    }

    /// Check if this lock-time is satisfied given the input's confirmation height/time
    pub fn is_satisfied(
        &self,
        input_height: u32,
        input_time: u32,
        current_height: u32,
        current_time: u32,
    ) -> bool {
        match self {
            RelativeLockTime::Disabled => true,
            RelativeLockTime::Blocks(blocks) => {
                let blocks_passed = current_height.saturating_sub(input_height);
                blocks_passed >= *blocks as u32
            }
            RelativeLockTime::Time(time_units) => {
                let seconds_required = (*time_units as u32) * SEQUENCE_LOCKTIME_GRANULARITY;
                let seconds_passed = current_time.saturating_sub(input_time);
                seconds_passed >= seconds_required
            }
        }
    }
}

/// Check if a transaction's sequence locks are satisfied
pub fn check_sequence_locks(
    tx: &Transaction,
    prevout_heights: &[u32],
    prevout_times: &[u32],
    block_height: u32,
    block_time: u32,
) -> Result<bool> {
    // BIP68 only applies if transaction version >= 2
    if tx.version.0 < 2 {
        trace!("Transaction version < 2, BIP68 does not apply");
        return Ok(true);
    }

    // Check each input's sequence lock
    for (i, input) in tx.input.iter().enumerate() {
        let lock_time = RelativeLockTime::from_sequence(input.sequence);

        match lock_time {
            RelativeLockTime::Disabled => {
                // No relative lock-time for this input
                continue;
            }
            RelativeLockTime::Blocks(blocks) => {
                let input_height = prevout_heights[i];
                let blocks_passed = block_height.saturating_sub(input_height);

                if blocks_passed < blocks as u32 {
                    debug!(
                        "BIP68 blocks lock not satisfied: input {} requires {} blocks, only {} passed",
                        i, blocks, blocks_passed
                    );
                    return Ok(false);
                }
            }
            RelativeLockTime::Time(time_units) => {
                let input_time = prevout_times[i];
                let seconds_required = (time_units as u32) * SEQUENCE_LOCKTIME_GRANULARITY;
                let seconds_passed = block_time.saturating_sub(input_time);

                if seconds_passed < seconds_required {
                    debug!(
                        "BIP68 time lock not satisfied: input {} requires {} seconds, only {} passed",
                        i, seconds_required, seconds_passed
                    );
                    return Ok(false);
                }
            }
        }
    }

    Ok(true)
}

/// Validate that sequence numbers are being used correctly for BIP68
pub fn validate_sequence_numbers(tx: &Transaction) -> Result<()> {
    // BIP68 only applies to version 2+ transactions
    if tx.version.0 < 2 {
        return Ok(());
    }

    // Check for any invalid combinations
    for (i, input) in tx.input.iter().enumerate() {
        let sequence = input.sequence.0;

        // If disable flag is not set, this is a relative lock-time
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG == 0 {
            // The value must be within valid range
            let lock_value = sequence & SEQUENCE_LOCKTIME_MASK;
            if lock_value > 0xffff {
                bail!(
                    "Invalid BIP68 sequence value in input {}: {:#x}",
                    i,
                    lock_value
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::script::ScriptBuf;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, Transaction, TxIn, Witness};

    #[test]
    fn test_relative_lock_time_parsing() -> Result<()> {
        // Test disabled lock-time
        let seq_disabled = Sequence(0xfffffffe);
        assert_eq!(
            RelativeLockTime::from_sequence(seq_disabled),
            RelativeLockTime::Disabled
        );

        // Test block-based lock (10 blocks)
        let seq_blocks = Sequence(10);
        assert_eq!(
            RelativeLockTime::from_sequence(seq_blocks),
            RelativeLockTime::Blocks(10)
        );

        // Test time-based lock (5 * 512 seconds)
        let seq_time = Sequence(SEQUENCE_LOCKTIME_TYPE_FLAG | 5);
        assert_eq!(
            RelativeLockTime::from_sequence(seq_time),
            RelativeLockTime::Time(5)
        );

        Ok(())
    }

    #[test]
    fn test_lock_time_satisfaction() -> Result<()> {
        // Test block-based lock
        let lock = RelativeLockTime::Blocks(10);
        assert!(!lock.is_satisfied(100, 1000, 105, 1500)); // Only 5 blocks passed
        assert!(lock.is_satisfied(100, 1000, 110, 2000)); // 10 blocks passed
        assert!(lock.is_satisfied(100, 1000, 120, 3000)); // 20 blocks passed

        // Test time-based lock (5 units = 2560 seconds)
        let lock = RelativeLockTime::Time(5);
        assert!(!lock.is_satisfied(100, 1000, 200, 2000)); // Only 1000 seconds passed
        assert!(lock.is_satisfied(100, 1000, 200, 3560)); // 2560 seconds passed
        assert!(lock.is_satisfied(100, 1000, 200, 5000)); // 4000 seconds passed

        // Test disabled lock
        let lock = RelativeLockTime::Disabled;
        assert!(lock.is_satisfied(0, 0, 0, 0)); // Always satisfied

        Ok(())
    }

    #[test]
    fn test_check_sequence_locks() -> Result<()> {
        // Create a version 2 transaction with relative locks
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![
                TxIn {
                    previous_output: OutPoint::default(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(10), // 10 blocks relative lock
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint::default(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(SEQUENCE_LOCKTIME_TYPE_FLAG | 5), // 5 * 512 seconds
                    witness: Witness::new(),
                },
            ],
            output: vec![],
        };

        let prevout_heights = vec![100, 100];
        let prevout_times = vec![1000, 1000];

        // Test: locks not satisfied
        assert!(!check_sequence_locks(
            &tx,
            &prevout_heights,
            &prevout_times,
            105,
            2000
        )?);

        // Test: block lock satisfied but time lock not
        assert!(!check_sequence_locks(
            &tx,
            &prevout_heights,
            &prevout_times,
            110,
            2000
        )?);

        // Test: both locks satisfied
        assert!(check_sequence_locks(
            &tx,
            &prevout_heights,
            &prevout_times,
            110,
            3560
        )?);

        Ok(())
    }

    #[test]
    fn test_version_1_transaction() -> Result<()> {
        // Version 1 transactions should ignore BIP68
        let tx = Transaction {
            version: Version(1),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(10), // Would be a relative lock in v2
                witness: Witness::new(),
            }],
            output: vec![],
        };

        let prevout_heights = vec![100];
        let prevout_times = vec![1000];

        // Should always pass for version 1
        assert!(check_sequence_locks(
            &tx,
            &prevout_heights,
            &prevout_times,
            101,
            1100
        )?);

        Ok(())
    }
}
