use anyhow::Result;
use bitcoin::{
    absolute::LockTime, consensus::serialize, hashes::Hash, transaction::Version, Amount, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use mempool::rbf::{RBFConflictTracker, RBFPolicy};
use std::collections::{HashMap, HashSet};

/// Create a transaction with specified inputs and outputs
fn create_transaction(
    inputs: Vec<(Txid, u32, u32)>, // (txid, vout, sequence)
    outputs: Vec<Amount>,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .into_iter()
            .map(|(txid, vout, sequence)| TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(sequence),
                witness: Witness::new(),
            })
            .collect(),
        output: outputs
            .into_iter()
            .map(|value| TxOut {
                value,
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros()),
            })
            .collect(),
    }
}

/// Helper to create a simple RBF-signaling transaction
fn create_rbf_transaction(fee: Amount) -> Transaction {
    let output_value = Amount::from_sat(100_000) - fee;
    create_transaction(
        vec![(Txid::all_zeros(), 0, 0xfffffffd)], // RBF sequence
        vec![output_value],
    )
}

/// Helper to create a non-RBF transaction
fn create_final_transaction(fee: Amount) -> Transaction {
    let output_value = Amount::from_sat(100_000) - fee;
    create_transaction(
        vec![(Txid::all_zeros(), 0, 0xffffffff)], // Final sequence
        vec![output_value],
    )
}

#[test]
fn test_bip125_rule1_explicit_signaling() -> Result<()> {
    // BIP125 Rule 1: The replacement transaction must explicitly signal replaceability
    
    let rbf_tx = create_rbf_transaction(Amount::from_sat(1000));
    let final_tx = create_final_transaction(Amount::from_sat(1000));
    
    // Check RBF signaling using the static method
    assert!(RBFPolicy::signals_rbf(&rbf_tx), "RBF tx should signal");
    assert!(!RBFPolicy::signals_rbf(&final_tx), "Final tx should not signal");
    
    Ok(())
}

#[test]
fn test_rbf_conflict_tracking() -> Result<()> {
    // Test basic conflict tracking
    
    let mut tracker = RBFConflictTracker::new();
    
    // Add original transaction
    let original_tx = create_rbf_transaction(Amount::from_sat(1000));
    let original_txid = original_tx.compute_txid();
    tracker.add_transaction(&original_tx);
    
    // Create replacement spending same input
    let replacement_tx = create_transaction(
        vec![(Txid::all_zeros(), 0, 0xfffffffd)],
        vec![Amount::from_sat(98_000)], // Higher fee
    );
    
    // Find conflicts
    let conflicts = tracker.find_conflicts(&replacement_tx);
    assert_eq!(conflicts.len(), 1);
    assert!(conflicts.contains(&original_txid));
    
    Ok(())
}

#[test]
fn test_multiple_conflict_detection() -> Result<()> {
    // Test detecting multiple conflicting transactions
    
    let mut tracker = RBFConflictTracker::new();
    
    // Add multiple transactions spending different outputs of same parent
    let input_txid = Txid::from_slice(&[1; 32])?;
    
    for i in 0..3 {
        let tx = create_transaction(
            vec![(input_txid, i, 0xfffffffd)],
            vec![Amount::from_sat(99_000 - i as u64 * 1000)],
        );
        tracker.add_transaction(&tx);
    }
    
    // Create replacement that spends first output
    let replacement = create_transaction(
        vec![(input_txid, 0, 0xfffffffd)],
        vec![Amount::from_sat(95_000)],
    );
    
    // Should only conflict with the transaction spending output 0
    let conflicts = tracker.find_conflicts(&replacement);
    assert_eq!(conflicts.len(), 1);
    
    Ok(())
}

#[test]
fn test_rbf_signaling_detection() -> Result<()> {
    // Test various sequence values for RBF signaling
    
    // RBF signaling sequences (< 0xfffffffe)
    let rbf_sequences = vec![
        0x00000000,
        0x00000001,
        0x80000000,
        0xfffffffd,
    ];
    
    for seq in rbf_sequences {
        let tx = create_transaction(
            vec![(Txid::all_zeros(), 0, seq)],
            vec![Amount::from_sat(99_000)],
        );
        assert!(RBFPolicy::signals_rbf(&tx), "Sequence {} should signal RBF", seq);
    }
    
    // Non-RBF sequences (>= 0xfffffffe)
    let non_rbf_sequences = vec![
        0xfffffffe,
        0xffffffff,
    ];
    
    for seq in non_rbf_sequences {
        let tx = create_transaction(
            vec![(Txid::all_zeros(), 0, seq)],
            vec![Amount::from_sat(99_000)],
        );
        assert!(!RBFPolicy::signals_rbf(&tx), "Sequence {} should not signal RBF", seq);
    }
    
    Ok(())
}

#[test]
fn test_transaction_chain_conflicts() -> Result<()> {
    // Test conflict detection in transaction chains
    
    let mut tracker = RBFConflictTracker::new();
    
    // Create chain: tx1 -> tx2 -> tx3
    let tx1 = create_transaction(
        vec![(Txid::all_zeros(), 0, 0xfffffffd)],
        vec![Amount::from_sat(99_000)],
    );
    let tx1_id = tx1.compute_txid();
    
    let tx2 = create_transaction(
        vec![(tx1_id, 0, 0xfffffffd)],
        vec![Amount::from_sat(98_000)],
    );
    let tx2_id = tx2.compute_txid();
    
    let tx3 = create_transaction(
        vec![(tx2_id, 0, 0xfffffffd)],
        vec![Amount::from_sat(97_000)],
    );
    
    // Add all to tracker
    tracker.add_transaction(&tx1);
    tracker.add_transaction(&tx2);
    tracker.add_transaction(&tx3);
    
    // Replacement for tx1 should conflict with tx1
    let replacement = create_transaction(
        vec![(Txid::all_zeros(), 0, 0xfffffffd)],
        vec![Amount::from_sat(95_000)],
    );
    
    let conflicts = tracker.find_conflicts(&replacement);
    assert!(conflicts.contains(&tx1_id));
    
    // Replacement for tx2 should conflict with tx2
    let replacement2 = create_transaction(
        vec![(tx1_id, 0, 0xfffffffd)],
        vec![Amount::from_sat(94_000)],
    );
    
    let conflicts2 = tracker.find_conflicts(&replacement2);
    assert!(conflicts2.contains(&tx2_id));
    
    Ok(())
}

#[test]
fn test_double_spend_detection() -> Result<()> {
    // Test detection of double-spend attempts
    
    let mut tracker = RBFConflictTracker::new();
    
    // Add transaction spending specific UTXO
    let input_txid = Txid::from_slice(&[5; 32])?;
    let tx1 = create_transaction(
        vec![(input_txid, 0, 0xfffffffd)],
        vec![Amount::from_sat(99_000)],
    );
    let tx1_id = tx1.compute_txid();
    tracker.add_transaction(&tx1);
    
    // Try to add another transaction spending same UTXO
    let tx2 = create_transaction(
        vec![(input_txid, 0, 0xfffffffd)],
        vec![Amount::from_sat(98_000)],
    );
    
    // Should detect the conflict
    let conflicts = tracker.find_conflicts(&tx2);
    assert_eq!(conflicts.len(), 1);
    assert!(conflicts.contains(&tx1_id));
    
    Ok(())
}

#[test]
fn test_multiple_input_transaction() -> Result<()> {
    // Test RBF with transactions having multiple inputs
    
    let mut tracker = RBFConflictTracker::new();
    
    // Create transaction with multiple inputs
    let input1 = Txid::from_slice(&[1; 32])?;
    let input2 = Txid::from_slice(&[2; 32])?;
    
    let tx1 = create_transaction(
        vec![
            (input1, 0, 0xfffffffd),
            (input2, 0, 0xfffffffd),
        ],
        vec![Amount::from_sat(190_000)],
    );
    let tx1_id = tx1.compute_txid();
    tracker.add_transaction(&tx1);
    
    // Replacement spending only one of the inputs should conflict
    let replacement = create_transaction(
        vec![(input1, 0, 0xfffffffd)],
        vec![Amount::from_sat(95_000)],
    );
    
    let conflicts = tracker.find_conflicts(&replacement);
    assert_eq!(conflicts.len(), 1);
    assert!(conflicts.contains(&tx1_id));
    
    Ok(())
}

#[test]
fn test_rbf_tracker_removal() -> Result<()> {
    // Test removing transactions from conflict tracker
    
    let mut tracker = RBFConflictTracker::new();
    
    // Add transaction
    let tx = create_rbf_transaction(Amount::from_sat(1000));
    let txid = tx.compute_txid();
    tracker.add_transaction(&tx);
    
    // Create a different tx spending same input to test conflict
    let conflict_tx = create_rbf_transaction(Amount::from_sat(2000));
    
    // Verify it's tracked by finding conflicts
    let conflicts = tracker.find_conflicts(&conflict_tx);
    assert_eq!(conflicts.len(), 1);
    assert!(conflicts.contains(&txid));
    
    // Remove transaction
    tracker.remove_transaction(&tx);
    
    // Verify it's no longer tracked
    let conflicts_after = tracker.find_conflicts(&conflict_tx);
    assert_eq!(conflicts_after.len(), 0);
    
    Ok(())
}

#[test]
fn test_partial_conflict_detection() -> Result<()> {
    // Test detecting partial conflicts (some inputs conflict, others don't)
    
    let mut tracker = RBFConflictTracker::new();
    
    // Add two transactions spending different UTXOs
    let input1 = Txid::from_slice(&[1; 32])?;
    let input2 = Txid::from_slice(&[2; 32])?;
    
    let tx1 = create_transaction(
        vec![(input1, 0, 0xfffffffd)],
        vec![Amount::from_sat(99_000)],
    );
    let tx1_id = tx1.compute_txid();
    
    let tx2 = create_transaction(
        vec![(input2, 0, 0xfffffffd)],
        vec![Amount::from_sat(98_000)],
    );
    let tx2_id = tx2.compute_txid();
    
    tracker.add_transaction(&tx1);
    tracker.add_transaction(&tx2);
    
    // Create replacement spending both inputs
    let replacement = create_transaction(
        vec![
            (input1, 0, 0xfffffffd),
            (input2, 0, 0xfffffffd),
        ],
        vec![Amount::from_sat(190_000)],
    );
    
    // Should conflict with both transactions
    let conflicts = tracker.find_conflicts(&replacement);
    assert_eq!(conflicts.len(), 2);
    assert!(conflicts.contains(&tx1_id));
    assert!(conflicts.contains(&tx2_id));
    
    Ok(())
}

#[test]
fn test_rbf_signaling_with_mixed_inputs() -> Result<()> {
    // Test RBF signaling with mixed sequence numbers
    
    // Transaction with one RBF input and one final input
    let mixed_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xfffffffd), // RBF
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffffffff), // Final
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros()),
        }],
    };
    
    // Should signal RBF (at least one input signals)
    assert!(RBFPolicy::signals_rbf(&mixed_tx));
    
    // Transaction with all final inputs
    let final_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffffffff), // Final
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xfffffffe), // Also final
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros()),
        }],
    };
    
    // Should not signal RBF (all inputs are final)
    assert!(!RBFPolicy::signals_rbf(&final_tx));
    
    Ok(())
}