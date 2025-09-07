//! BIP112: CHECKSEQUENCEVERIFY opcode
//! 
//! This module implements BIP112 which adds the CHECKSEQUENCEVERIFY opcode.
//! CSV allows a transaction output to be made unspendable until a relative
//! time (BIP68) has passed since the output was mined.

use anyhow::Result;
use bitcoin::{Transaction, Sequence};
use tracing::{debug, trace};

use crate::bip68::{RelativeLockTime, SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG, SEQUENCE_LOCKTIME_MASK};

/// Verify CHECKSEQUENCEVERIFY for a transaction input
/// 
/// This implements the consensus rules for CSV as defined in BIP112.
/// Returns true if the CSV check passes, false otherwise.
pub fn verify_checksequenceverify(
    tx: &Transaction,
    input_index: usize,
    sequence_value: i64,
    tx_version: i32,
) -> Result<bool> {
    // CSV is a NOP for tx version < 2
    if tx_version < 2 {
        trace!("CSV: Transaction version < 2, treating as NOP");
        return Ok(true);
    }
    
    // Negative values fail immediately
    if sequence_value < 0 {
        debug!("CSV failed: negative sequence value {}", sequence_value);
        return Ok(false);
    }
    
    let csv_sequence = sequence_value as u32;
    
    // If the disable flag is set, CSV is satisfied (acts as NOP)
    if csv_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        trace!("CSV: Disable flag set, treating as NOP");
        return Ok(true);
    }
    
    // Get the input's sequence number
    let input = tx.input.get(input_index)
        .ok_or_else(|| anyhow::anyhow!("Invalid input index {} for CSV", input_index))?;
    let tx_sequence = input.sequence.0;
    
    // To pass CSV, the transaction's sequence number must not disable relative lock-time
    if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        debug!("CSV failed: transaction sequence has disable flag set");
        return Ok(false);
    }
    
    // The type flag (time vs blocks) must match between CSV value and tx sequence
    let csv_time_flag = csv_sequence & SEQUENCE_LOCKTIME_TYPE_FLAG;
    let tx_time_flag = tx_sequence & SEQUENCE_LOCKTIME_TYPE_FLAG;
    
    if csv_time_flag != tx_time_flag {
        debug!(
            "CSV failed: type mismatch - CSV uses {}, tx uses {}",
            if csv_time_flag != 0 { "time" } else { "blocks" },
            if tx_time_flag != 0 { "time" } else { "blocks" }
        );
        return Ok(false);
    }
    
    // The transaction sequence number must be greater than or equal to the CSV value
    // We only compare the masked values (lower 16 bits)
    let csv_masked = csv_sequence & SEQUENCE_LOCKTIME_MASK;
    let tx_masked = tx_sequence & SEQUENCE_LOCKTIME_MASK;
    
    if tx_masked < csv_masked {
        debug!(
            "CSV failed: tx sequence {} < CSV requirement {}",
            tx_masked, csv_masked
        );
        return Ok(false);
    }
    
    debug!("CSV passed: tx sequence {} >= CSV requirement {}", tx_masked, csv_masked);
    Ok(true)
}

/// Check if a sequence value would make CSV pass trivially
pub fn is_csv_trivially_satisfied(sequence_value: i64) -> bool {
    // Negative values or values with disable flag set make CSV a NOP
    sequence_value < 0 || (sequence_value as u32 & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0
}

/// Extract the relative lock-time from a CSV value
pub fn csv_to_relative_lock_time(csv_value: i64) -> Option<RelativeLockTime> {
    if csv_value < 0 {
        return None;
    }
    
    let sequence = Sequence(csv_value as u32);
    Some(RelativeLockTime::from_sequence(sequence))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Transaction, TxIn, OutPoint, Witness};
    use bitcoin::blockdata::script::ScriptBuf;
    use bitcoin::transaction::Version;
    
    #[test]
    fn test_csv_version_1_tx() -> Result<()> {
        // Version 1 transactions should always pass (CSV is NOP)
        let tx = Transaction {
            version: Version(1),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0), // Even with 0 sequence
                witness: Witness::new(),
            }],
            output: vec![],
        };
        
        // Any CSV value should pass for version 1
        assert!(verify_checksequenceverify(&tx, 0, 100, 1)?);
        assert!(verify_checksequenceverify(&tx, 0, -1, 1)?);
        assert!(verify_checksequenceverify(&tx, 0, 0xffffffff as i64, 1)?);
        
        Ok(())
    }
    
    #[test]
    fn test_csv_negative_value() -> Result<()> {
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(10),
                witness: Witness::new(),
            }],
            output: vec![],
        };
        
        // Negative CSV values should fail
        assert!(!verify_checksequenceverify(&tx, 0, -1, 2)?);
        assert!(!verify_checksequenceverify(&tx, 0, -100, 2)?);
        
        Ok(())
    }
    
    #[test]
    fn test_csv_disable_flag() -> Result<()> {
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xfffffffe), // Disable flag set
                witness: Witness::new(),
            }],
            output: vec![],
        };
        
        // CSV with disable flag should always pass
        let csv_with_disable = (SEQUENCE_LOCKTIME_DISABLE_FLAG | 100) as i64;
        assert!(verify_checksequenceverify(&tx, 0, csv_with_disable, 2)?);
        
        Ok(())
    }
    
    #[test]
    fn test_csv_type_mismatch() -> Result<()> {
        // Transaction using block-based lock
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(10), // Block-based (no time flag)
                witness: Witness::new(),
            }],
            output: vec![],
        };
        
        // CSV requiring time-based lock should fail
        let csv_time = (SEQUENCE_LOCKTIME_TYPE_FLAG | 5) as i64;
        assert!(!verify_checksequenceverify(&tx, 0, csv_time, 2)?);
        
        // CSV requiring block-based lock should pass if value is satisfied
        let csv_blocks = 5_i64;
        assert!(verify_checksequenceverify(&tx, 0, csv_blocks, 2)?);
        
        Ok(())
    }
    
    #[test]
    fn test_csv_value_comparison() -> Result<()> {
        // Transaction with sequence = 100
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(100),
                witness: Witness::new(),
            }],
            output: vec![],
        };
        
        // CSV <= 100 should pass
        assert!(verify_checksequenceverify(&tx, 0, 50, 2)?);
        assert!(verify_checksequenceverify(&tx, 0, 100, 2)?);
        
        // CSV > 100 should fail
        assert!(!verify_checksequenceverify(&tx, 0, 101, 2)?);
        assert!(!verify_checksequenceverify(&tx, 0, 200, 2)?);
        
        Ok(())
    }
    
    #[test]
    fn test_csv_time_based() -> Result<()> {
        // Transaction using time-based lock (10 * 512 seconds)
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(SEQUENCE_LOCKTIME_TYPE_FLAG | 10),
                witness: Witness::new(),
            }],
            output: vec![],
        };
        
        // Time-based CSV <= 10 should pass
        let csv_time_5 = (SEQUENCE_LOCKTIME_TYPE_FLAG | 5) as i64;
        let csv_time_10 = (SEQUENCE_LOCKTIME_TYPE_FLAG | 10) as i64;
        assert!(verify_checksequenceverify(&tx, 0, csv_time_5, 2)?);
        assert!(verify_checksequenceverify(&tx, 0, csv_time_10, 2)?);
        
        // Time-based CSV > 10 should fail
        let csv_time_11 = (SEQUENCE_LOCKTIME_TYPE_FLAG | 11) as i64;
        assert!(!verify_checksequenceverify(&tx, 0, csv_time_11, 2)?);
        
        Ok(())
    }
    
    #[test]
    fn test_is_csv_trivially_satisfied() {
        // Negative values are trivially satisfied
        assert!(is_csv_trivially_satisfied(-1));
        assert!(is_csv_trivially_satisfied(-100));
        
        // Values with disable flag are trivially satisfied
        assert!(is_csv_trivially_satisfied(SEQUENCE_LOCKTIME_DISABLE_FLAG as i64));
        assert!(is_csv_trivially_satisfied((SEQUENCE_LOCKTIME_DISABLE_FLAG | 100) as i64));
        
        // Normal values are not trivially satisfied
        assert!(!is_csv_trivially_satisfied(0));
        assert!(!is_csv_trivially_satisfied(100));
        assert!(!is_csv_trivially_satisfied(SEQUENCE_LOCKTIME_TYPE_FLAG as i64));
    }
}