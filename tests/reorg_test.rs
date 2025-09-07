use anyhow::Result;
use bitcoin::{Block, BlockHash, Transaction, TxOut, Amount, Network};
use bitcoin_core_lib::chain::ChainManager;
use bitcoin_core_lib::reorg::ReorgManager;
use storage::StorageManager;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;

/// Test basic chain reorganization
#[tokio::test]
async fn test_basic_reorg() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let storage = Arc::new(StorageManager::new(temp_dir.path()).await?);
    let chain = Arc::new(RwLock::new(
        ChainManager::new(storage.clone(), Network::Regtest).await?
    ));
    
    // Build initial chain: A -> B -> C
    let block_a = create_test_block(BlockHash::all_zeros(), 1, 1);
    let block_b = create_test_block(block_a.block_hash(), 2, 2);
    let block_c = create_test_block(block_b.block_hash(), 3, 3);
    
    // Add blocks to chain
    {
        let mut chain_guard = chain.write().await;
        chain_guard.process_block(block_a.clone(), 1).await?;
        chain_guard.process_block(block_b.clone(), 2).await?;
        chain_guard.process_block(block_c.clone(), 3).await?;
    }
    
    // Verify initial chain
    {
        let chain_guard = chain.read().await;
        assert_eq!(chain_guard.get_best_height(), 3);
        assert_eq!(chain_guard.get_best_hash(), block_c.block_hash());
    }
    
    // Create competing chain: A -> B' -> C' -> D' (longer)
    let block_b_prime = create_test_block(block_a.block_hash(), 2, 20); // Different nonce
    let block_c_prime = create_test_block(block_b_prime.block_hash(), 3, 30);
    let block_d_prime = create_test_block(block_c_prime.block_hash(), 4, 40);
    
    // Process competing chain - should trigger reorg
    {
        let mut chain_guard = chain.write().await;
        chain_guard.process_block(block_b_prime.clone(), 2).await?;
        chain_guard.process_block(block_c_prime.clone(), 3).await?;
        chain_guard.process_block(block_d_prime.clone(), 4).await?;
    }
    
    // Verify reorg happened
    {
        let chain_guard = chain.read().await;
        assert_eq!(chain_guard.get_best_height(), 4);
        assert_eq!(chain_guard.get_best_hash(), block_d_prime.block_hash());
    }
    
    Ok(())
}

/// Test deep reorganization
#[tokio::test]
async fn test_deep_reorg() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let storage = Arc::new(StorageManager::new(temp_dir.path()).await?);
    let chain = Arc::new(RwLock::new(
        ChainManager::new(storage.clone(), Network::Regtest).await?
    ));
    
    // Build initial long chain (100 blocks)
    let mut current_hash = BlockHash::all_zeros();
    let mut original_chain = vec![];
    
    for i in 1..=100 {
        let block = create_test_block(current_hash, i, i);
        current_hash = block.block_hash();
        original_chain.push(block);
    }
    
    // Add all blocks to chain
    {
        let mut chain_guard = chain.write().await;
        for (i, block) in original_chain.iter().enumerate() {
            chain_guard.process_block(block.clone(), (i + 1) as u32).await?;
        }
    }
    
    // Create competing chain from block 50 (51 block reorg)
    current_hash = original_chain[49].block_hash(); // Fork at block 50
    let mut competing_chain = vec![];
    
    for i in 51..=102 {
        let block = create_test_block(current_hash, i, i * 10); // Different nonce
        current_hash = block.block_hash();
        competing_chain.push(block);
    }
    
    // Process competing chain - should trigger deep reorg
    {
        let mut chain_guard = chain.write().await;
        for (i, block) in competing_chain.iter().enumerate() {
            chain_guard.process_block(block.clone(), (51 + i) as u32).await?;
        }
    }
    
    // Verify deep reorg happened
    {
        let chain_guard = chain.read().await;
        assert_eq!(chain_guard.get_best_height(), 102);
        assert_eq!(chain_guard.get_best_hash(), competing_chain.last().unwrap().block_hash());
    }
    
    println!("Successfully performed 51-block reorg");
    
    Ok(())
}

/// Test reorg with transaction conflicts
#[tokio::test]
async fn test_reorg_with_tx_conflicts() -> Result<()> {
    use bitcoin::TxIn;
    use bitcoin::blockdata::script::ScriptBuf;
    use bitcoin::OutPoint;
    
    let temp_dir = TempDir::new()?;
    let storage = Arc::new(StorageManager::new(temp_dir.path()).await?);
    let chain = Arc::new(RwLock::new(
        ChainManager::new(storage.clone(), Network::Regtest).await?
    ));
    
    // Create initial chain with specific transaction
    let block_a = create_test_block(BlockHash::all_zeros(), 1, 1);
    
    // Create transaction that spends from block A's coinbase
    let tx_spend = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: block_a.txdata[0].compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_99999000), // Minus fee
            script_pubkey: ScriptBuf::new(),
        }],
    };
    
    // Create block B with the spending transaction
    let mut block_b = create_test_block(block_a.block_hash(), 2, 2);
    block_b.txdata.push(tx_spend.clone());
    
    // Add blocks to chain
    {
        let mut chain_guard = chain.write().await;
        chain_guard.process_block(block_a.clone(), 1).await?;
        chain_guard.process_block(block_b.clone(), 2).await?;
    }
    
    // Create competing block B' with different transaction
    let tx_spend_alt = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: block_a.txdata[0].compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::from(vec![0x01]), // Different script
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_99998000), // Different amount
            script_pubkey: ScriptBuf::new(),
        }],
    };
    
    let mut block_b_prime = create_test_block(block_a.block_hash(), 2, 20);
    block_b_prime.txdata.push(tx_spend_alt);
    
    let block_c_prime = create_test_block(block_b_prime.block_hash(), 3, 30);
    
    // Process competing chain - should handle transaction conflicts
    {
        let mut chain_guard = chain.write().await;
        chain_guard.process_block(block_b_prime.clone(), 2).await?;
        chain_guard.process_block(block_c_prime.clone(), 3).await?;
    }
    
    // Verify reorg handled transaction conflicts
    {
        let chain_guard = chain.read().await;
        assert_eq!(chain_guard.get_best_height(), 3);
        assert_eq!(chain_guard.get_best_hash(), block_c_prime.block_hash());
    }
    
    Ok(())
}

/// Test reorg limits and protection
#[tokio::test]
async fn test_reorg_limits() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let storage = Arc::new(StorageManager::new(temp_dir.path()).await?);
    
    // Create reorg manager with limits
    let reorg_manager = ReorgManager::new(storage.clone(), 10); // Max 10 block reorg
    
    // Build initial chain
    let mut current_hash = BlockHash::all_zeros();
    let mut blocks = vec![];
    
    for i in 1..=20 {
        let block = create_test_block(current_hash, i, i);
        current_hash = block.block_hash();
        blocks.push(block);
    }
    
    // Try to reorg more than limit (should be rejected)
    let fork_point = blocks[5].block_hash(); // Fork at block 6
    let mut competing_chain = vec![];
    current_hash = fork_point;
    
    for i in 7..=22 {
        let block = create_test_block(current_hash, i, i * 100);
        current_hash = block.block_hash();
        competing_chain.push(block);
    }
    
    // This should fail due to reorg depth limit
    let result = reorg_manager.process_competing_chain(competing_chain).await;
    assert!(result.is_err(), "Deep reorg should be rejected");
    
    Ok(())
}

/// Test concurrent reorgs (race conditions)
#[tokio::test]
async fn test_concurrent_reorgs() -> Result<()> {
    use tokio::task;
    
    let temp_dir = TempDir::new()?;
    let storage = Arc::new(StorageManager::new(temp_dir.path()).await?);
    let chain = Arc::new(RwLock::new(
        ChainManager::new(storage.clone(), Network::Regtest).await?
    ));
    
    // Build initial chain
    let block_a = create_test_block(BlockHash::all_zeros(), 1, 1);
    {
        let mut chain_guard = chain.write().await;
        chain_guard.process_block(block_a.clone(), 1).await?;
    }
    
    // Create two competing chains
    let chain1 = chain.clone();
    let chain2 = chain.clone();
    
    // Chain 1: A -> B1 -> C1
    let handle1 = task::spawn(async move {
        let block_b1 = create_test_block(block_a.block_hash(), 2, 100);
        let block_c1 = create_test_block(block_b1.block_hash(), 3, 101);
        
        let mut chain_guard = chain1.write().await;
        chain_guard.process_block(block_b1, 2).await.unwrap();
        chain_guard.process_block(block_c1, 3).await.unwrap();
    });
    
    // Chain 2: A -> B2 -> C2 -> D2
    let handle2 = task::spawn(async move {
        let block_b2 = create_test_block(block_a.block_hash(), 2, 200);
        let block_c2 = create_test_block(block_b2.block_hash(), 3, 201);
        let block_d2 = create_test_block(block_c2.block_hash(), 4, 202);
        
        let mut chain_guard = chain2.write().await;
        chain_guard.process_block(block_b2, 2).await.unwrap();
        chain_guard.process_block(block_c2, 3).await.unwrap();
        chain_guard.process_block(block_d2, 4).await.unwrap();
    });
    
    // Wait for both to complete
    handle1.await?;
    handle2.await?;
    
    // Verify one chain won (should be the longer one)
    {
        let chain_guard = chain.read().await;
        assert_eq!(chain_guard.get_best_height(), 4, "Longer chain should win");
    }
    
    Ok(())
}

// Helper function to create test blocks with custom nonce
fn create_test_block(prev_hash: BlockHash, height: u32, nonce: u32) -> Block {
    use bitcoin::blockdata::block::Header;
    use bitcoin::blockdata::transaction::{TxIn, TxOut, OutPoint, Version};
    use bitcoin::blockdata::script::ScriptBuf;
    use bitcoin::absolute::LockTime;
    use bitcoin::CompactTarget;
    
    let coinbase = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from(vec![height as u8]),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_00000000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    
    Block {
        header: Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: prev_hash,
            merkle_root: coinbase.compute_txid().to_raw_hash().into(),
            time: 1234567890 + height,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce,
        },
        txdata: vec![coinbase],
    }
}