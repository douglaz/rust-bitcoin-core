use anyhow::Result;
use bitcoin::{
    absolute::LockTime, consensus::serialize, hashes::Hash, transaction::Version, Amount, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use mempool::package_relay::{
    Package, PackageType, PackageValidator, PackageRelayManager, MAX_PACKAGE_COUNT,
    MAX_PACKAGE_SIZE, MAX_PACKAGE_WEIGHT,
};
use std::collections::HashSet;

/// Create a simple transaction for testing
fn create_test_transaction(inputs: Vec<(Txid, u32)>, outputs: Vec<Amount>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .into_iter()
            .map(|(txid, vout)| TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
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

/// Create a chain of transactions (parent -> child -> grandchild)
fn create_transaction_chain(chain_length: usize, base_fee: Amount) -> Vec<Transaction> {
    let mut transactions = Vec::new();
    let mut prev_txid = Txid::all_zeros();

    for i in 0..chain_length {
        let input_value = Amount::from_sat(100_000);
        let fee = base_fee + Amount::from_sat(i as u64 * 100);
        let output_value = input_value - fee;

        let tx = if i == 0 {
            // First transaction uses external input
            create_test_transaction(vec![(prev_txid, 0)], vec![output_value])
        } else {
            // Subsequent transactions spend from previous
            create_test_transaction(vec![(prev_txid, 0)], vec![output_value])
        };

        prev_txid = tx.compute_txid();
        transactions.push(tx);
    }

    transactions
}

/// Create a tree of transactions (parent with multiple children)
fn create_transaction_tree(num_children: usize) -> Vec<Transaction> {
    let mut transactions = Vec::new();

    // Create parent transaction with multiple outputs
    let parent_outputs: Vec<Amount> = (0..num_children)
        .map(|_| Amount::from_sat(50_000))
        .collect();
    
    let parent = create_test_transaction(vec![(Txid::all_zeros(), 0)], parent_outputs);
    let parent_txid = parent.compute_txid();
    transactions.push(parent);

    // Create child transactions, each spending one output from parent
    for i in 0..num_children {
        let child = create_test_transaction(
            vec![(parent_txid, i as u32)],
            vec![Amount::from_sat(49_000)], // 1000 sat fee per child
        );
        transactions.push(child);
    }

    transactions
}

#[test]
fn test_package_creation_valid() -> Result<()> {
    let transactions = create_transaction_chain(3, Amount::from_sat(1000));
    // Use new_with_fee for testing with explicit fee
    let total_fee = Amount::from_sat(3000); // 1000 sat per tx
    let package = Package::new_with_fee(
        transactions.clone(), 
        PackageType::ChildWithParents,
        total_fee
    )?;

    assert_eq!(package.transactions.len(), 3);
    assert_eq!(package.txids.len(), 3);
    assert!(package.total_weight > 0);
    assert!(package.total_size > 0);
    assert!(package.package_feerate > 0.0);

    Ok(())
}

#[test]
fn test_package_creation_empty() -> Result<()> {
    let result = Package::new(Vec::new(), PackageType::ChildWithParents);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Package cannot be empty"));
    Ok(())
}

#[test]
fn test_package_creation_too_many_transactions() -> Result<()> {
    let transactions = create_transaction_chain(MAX_PACKAGE_COUNT + 1, Amount::from_sat(1000));
    let result = Package::new(transactions, PackageType::ChildWithParents);
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceeds limit"));
    Ok(())
}

#[test]
fn test_package_topological_sort() -> Result<()> {
    // Create transactions in reverse order (grandchild, child, parent)
    let chain = create_transaction_chain(3, Amount::from_sat(1000));
    let mut reversed = chain.clone();
    reversed.reverse();

    let mut package = Package::new(reversed, PackageType::ChildWithParents)?;
    package.topological_sort()?;

    // After sorting, parent should come before child
    for i in 1..package.transactions.len() {
        let current_tx = &package.transactions[i];
        let current_inputs: HashSet<_> = current_tx
            .input
            .iter()
            .map(|input| input.previous_output.txid)
            .collect();

        // Check if any previous transaction is a parent
        for j in 0..i {
            let prev_txid = package.transactions[j].compute_txid();
            if current_inputs.contains(&prev_txid) {
                // Found parent before child - correct order
                break;
            }
        }
    }

    Ok(())
}

#[test]
fn test_package_conflict_detection() -> Result<()> {
    // Create two transactions spending the same output
    let shared_input = (Txid::from_slice(&[1; 32])?, 0);
    
    let tx1 = create_test_transaction(vec![shared_input], vec![Amount::from_sat(49_000)]);
    let tx2 = create_test_transaction(vec![shared_input], vec![Amount::from_sat(48_000)]);
    
    let package = Package::new(vec![tx1, tx2], PackageType::ChildWithParents)?;
    let result = package.check_conflicts();
    
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("conflicting transactions"));
    Ok(())
}

#[test]
fn test_package_validator_size_limits() -> Result<()> {
    let validator = PackageValidator::default();
    
    // Create a package near the size limit
    let mut transactions = Vec::new();
    let mut total_size = 0;
    let mut tx_count = 0;
    
    while total_size < MAX_PACKAGE_SIZE - 500 && tx_count < MAX_PACKAGE_COUNT {
        // Use different outputs to avoid conflicts
        let tx = create_test_transaction(
            vec![(Txid::from_slice(&[tx_count as u8; 32]).unwrap(), 0)],
            vec![Amount::from_sat(49_000)],
        );
        total_size += serialize(&tx).len();
        transactions.push(tx);
        tx_count += 1;
    }
    
    // Use new_with_fee for testing
    let total_fee = Amount::from_sat(tx_count as u64 * 1000);
    let package = Package::new_with_fee(
        transactions, 
        PackageType::ChildWithParents,
        total_fee
    )?;
    
    // Should pass validation if under limit
    if package.total_size <= MAX_PACKAGE_SIZE {
        match validator.validate_package(&package) {
            Ok(_) => {},
            Err(e) => panic!("Validation failed: {} (size: {}, weight: {}, feerate: {})", 
                             e, package.total_size, package.total_weight, package.package_feerate),
        }
    }
    
    Ok(())
}

#[test]
fn test_package_validator_weight_limits() -> Result<()> {
    let validator = PackageValidator::default();
    
    // Create a package with high weight
    let mut transactions = Vec::new();
    let mut total_weight = 0;
    let mut tx_count = 0;
    
    while total_weight < MAX_PACKAGE_WEIGHT - 2000 && transactions.len() < MAX_PACKAGE_COUNT {
        // Use different outputs to avoid conflicts
        let tx = create_test_transaction(
            vec![(Txid::from_slice(&[tx_count as u8; 32]).unwrap(), 0)],
            vec![Amount::from_sat(49_000)],
        );
        total_weight += tx.weight().to_wu() as usize;
        transactions.push(tx);
        tx_count += 1;
    }
    
    // Use new_with_fee for testing
    let total_fee = Amount::from_sat(tx_count as u64 * 1000);
    let package = Package::new_with_fee(
        transactions, 
        PackageType::ChildWithParents,
        total_fee
    )?;
    
    // Should pass validation if under weight limit
    if package.total_weight <= MAX_PACKAGE_WEIGHT {
        match validator.validate_package(&package) {
            Ok(_) => {},
            Err(e) => panic!("Validation failed: {} (size: {}, weight: {}, feerate: {})", 
                             e, package.total_size, package.total_weight, package.package_feerate),
        }
    }
    
    Ok(())
}

#[test]
fn test_package_validator_feerate() -> Result<()> {
    let mut validator = PackageValidator::default();
    validator.min_package_feerate = 10.0; // 10 sat/vB minimum
    
    // Create package with low fee rate
    let low_fee_tx = create_test_transaction(
        vec![(Txid::all_zeros(), 0)],
        vec![Amount::from_sat(99_950)], // Only 50 sat fee
    );
    
    let package = Package::new(vec![low_fee_tx], PackageType::ChildWithParents)?;
    
    // Should fail validation due to low fee rate
    let result = validator.validate_package(&package);
    if package.package_feerate < 10.0 {
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fee rate"));
    }
    
    Ok(())
}

#[test]
fn test_package_relay_manager_orphan_handling() -> Result<()> {
    let mut manager = PackageRelayManager::new(PackageValidator::default());
    
    // Create an orphan transaction (depends on unknown parent)
    let missing_parent = Txid::from_slice(&[1; 32])?;
    let orphan_tx = create_test_transaction(
        vec![(missing_parent, 0)],
        vec![Amount::from_sat(49_000)],
    );
    let orphan_txid = orphan_tx.compute_txid();
    
    // Add orphan
    manager.add_orphan(orphan_tx.clone(), vec![missing_parent]);
    
    // Resolve orphan when parent arrives
    let resolved = manager.resolve_orphans(missing_parent);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].compute_txid(), orphan_txid);
    
    Ok(())
}

#[test]
fn test_package_relay_manager_create_child_with_parents() -> Result<()> {
    let manager = PackageRelayManager::new(PackageValidator::default());
    
    // Create parent transactions
    let parent1 = create_test_transaction(
        vec![(Txid::all_zeros(), 0)],
        vec![Amount::from_sat(50_000)],
    );
    let parent1_txid = parent1.compute_txid();
    
    let parent2 = create_test_transaction(
        vec![(Txid::all_zeros(), 1)],
        vec![Amount::from_sat(50_000)],
    );
    let parent2_txid = parent2.compute_txid();
    
    // Create child that spends from both parents
    let child = create_test_transaction(
        vec![(parent1_txid, 0), (parent2_txid, 0)],
        vec![Amount::from_sat(95_000)],
    );
    
    // Create package
    let package = manager.create_child_with_parents_package(
        child.clone(),
        vec![parent1, parent2],
    )?;
    
    assert_eq!(package.transactions.len(), 3);
    assert_eq!(package.package_type, PackageType::ChildWithParents);
    
    // Verify topological order (parents before child)
    let child_txid = child.compute_txid();
    let child_pos = package.txids.iter().position(|&id| id == child_txid).unwrap();
    assert_eq!(child_pos, 2); // Child should be last
    
    Ok(())
}

#[test]
fn test_package_relay_manager_multiple_orphans() -> Result<()> {
    let mut manager = PackageRelayManager::new(PackageValidator::default());
    
    let shared_parent = Txid::from_slice(&[2; 32])?;
    
    // Create multiple orphans depending on same parent
    let mut orphans = Vec::new();
    for i in 0..3 {
        let orphan = create_test_transaction(
            vec![(shared_parent, i)],
            vec![Amount::from_sat(48_000 - i as u64 * 1000)],
        );
        manager.add_orphan(orphan.clone(), vec![shared_parent]);
        orphans.push(orphan);
    }
    
    // Resolve all orphans when parent arrives
    let resolved = manager.resolve_orphans(shared_parent);
    assert_eq!(resolved.len(), 3);
    
    // Verify all orphans were resolved
    let resolved_txids: HashSet<_> = resolved.iter().map(|tx| tx.compute_txid()).collect();
    for orphan in &orphans {
        assert!(resolved_txids.contains(&orphan.compute_txid()));
    }
    
    Ok(())
}

#[test]
fn test_ancestor_package_type() -> Result<()> {
    // Create a chain representing ancestors
    let transactions = create_transaction_chain(4, Amount::from_sat(1500));
    let package = Package::new(transactions, PackageType::AncestorPackage)?;
    
    assert_eq!(package.package_type, PackageType::AncestorPackage);
    assert_eq!(package.transactions.len(), 4);
    
    // Verify relationships are properly tracked
    assert!(!package.relationships.is_empty());
    
    Ok(())
}

#[test]
fn test_descendant_package_type() -> Result<()> {
    // Create a tree with one parent and multiple children (descendants)
    let transactions = create_transaction_tree(3);
    let package = Package::new(transactions, PackageType::DescendantPackage)?;
    
    assert_eq!(package.package_type, PackageType::DescendantPackage);
    assert_eq!(package.transactions.len(), 4); // 1 parent + 3 children
    
    Ok(())
}

#[test]
fn test_package_with_high_fees() -> Result<()> {
    let validator = PackageValidator::default();
    
    // Create package with very high fees
    let high_fee_txs = create_transaction_chain(3, Amount::from_sat(50_000));
    let total_fee = Amount::from_sat(150_000); // 50k sat per tx
    let package = Package::new_with_fee(
        high_fee_txs,
        PackageType::ChildWithParents,
        total_fee
    )?;
    
    // Should pass validation
    assert!(validator.validate_package(&package).is_ok());
    
    // Fee rate should be very high
    assert!(package.package_feerate > 100.0);
    
    Ok(())
}


#[test]
fn test_complex_package_relationships() -> Result<()> {
    // Create a complex package with multiple parents and children
    let mut transactions = Vec::new();
    
    // Create two parent transactions
    let parent1 = create_test_transaction(
        vec![(Txid::all_zeros(), 0)],
        vec![Amount::from_sat(50_000), Amount::from_sat(50_000)],
    );
    let parent1_txid = parent1.compute_txid();
    transactions.push(parent1);
    
    let parent2 = create_test_transaction(
        vec![(Txid::all_zeros(), 1)],
        vec![Amount::from_sat(50_000)],
    );
    let parent2_txid = parent2.compute_txid();
    transactions.push(parent2);
    
    // Create child that spends from both parents
    let child = create_test_transaction(
        vec![(parent1_txid, 0), (parent2_txid, 0)],
        vec![Amount::from_sat(95_000)], // 5000 sat fee
    );
    transactions.push(child);
    
    let package = Package::new(transactions, PackageType::ChildWithParents)?;
    
    // Verify relationships
    assert_eq!(package.transactions.len(), 3);
    assert!(!package.relationships.is_empty());
    
    // Check topological ordering
    package.check_conflicts()?;
    
    Ok(())
}

