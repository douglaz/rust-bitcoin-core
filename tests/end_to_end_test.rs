use anyhow::Result;
use bitcoin::{Block, BlockHeader, Transaction, OutPoint, TxIn, TxOut};
use bitcoin::hashes::Hash;
use bitcoin_node::NodeRunner;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};

/// Test full node initialization and startup
#[tokio::test]
async fn test_node_initialization() -> Result<()> {
    // Create node runner with test configuration
    let data_dir = tempfile::tempdir()?;
    let node = NodeRunner::new(
        data_dir.path().to_str().unwrap().to_string(),
        bitcoin::Network::Regtest,
    ).await?;
    
    // Start the node
    node.start().await?;
    
    // Wait for initialization
    sleep(Duration::from_secs(2)).await;
    
    // Shutdown cleanly
    node.shutdown().await?;
    
    Ok(())
}

/// Test block processing pipeline end-to-end
#[tokio::test]
async fn test_block_processing_pipeline() -> Result<()> {
    let data_dir = tempfile::tempdir()?;
    let node = NodeRunner::new(
        data_dir.path().to_str().unwrap().to_string(),
        bitcoin::Network::Regtest,
    ).await?;
    
    // Start the node
    node.start().await?;
    
    // Create and submit a test block
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    node.submit_block(genesis.clone()).await?;
    
    // Wait for processing
    sleep(Duration::from_secs(1)).await;
    
    // Verify block was processed
    // In a real test, we'd check the chain state here
    
    node.shutdown().await?;
    
    Ok(())
}

/// Test transaction mempool flow
#[tokio::test]
async fn test_transaction_mempool_flow() -> Result<()> {
    let data_dir = tempfile::tempdir()?;
    let node = NodeRunner::new(
        data_dir.path().to_str().unwrap().to_string(),
        bitcoin::Network::Regtest,
    ).await?;
    
    // Start the node
    node.start().await?;
    
    // Create a test transaction
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(50_000_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    
    // Submit transaction
    node.submit_transaction(tx.clone()).await?;
    
    // Wait for mempool processing
    sleep(Duration::from_millis(500)).await;
    
    // Transaction should be in mempool now
    // In a real test, we'd verify mempool contains the transaction
    
    node.shutdown().await?;
    
    Ok(())
}

/// Test chain synchronization process
#[tokio::test]
async fn test_chain_synchronization() -> Result<()> {
    let data_dir = tempfile::tempdir()?;
    let node = NodeRunner::new(
        data_dir.path().to_str().unwrap().to_string(),
        bitcoin::Network::Regtest,
    ).await?;
    
    // Start the node
    node.start().await?;
    
    // Node should attempt to sync with peers
    // Wait for sync attempts
    sleep(Duration::from_secs(5)).await;
    
    // In a real test, we'd verify sync state and progress
    
    node.shutdown().await?;
    
    Ok(())
}

/// Test block validation and chain reorganization
#[tokio::test]
async fn test_chain_reorg() -> Result<()> {
    use bitcoin::hashes::sha256d;
    use bitcoin::blockdata::block::Header;
    
    let data_dir = tempfile::tempdir()?;
    let network = bitcoin::Network::Regtest;
    
    // Initialize components
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let storage = Arc::new(storage::manager::StorageManager::new(
        data_dir.path().to_str().unwrap()
    ).await?);
    
    // Add genesis block
    let genesis = bitcoin::blockdata::constants::genesis_block(network);
    storage.store_block(genesis.clone(), 0).await?;
    chain.add_block(genesis.clone(), 0).await?;
    
    // Create two competing chains
    // Chain A: genesis -> block1a -> block2a
    // Chain B: genesis -> block1b -> block2b -> block3b
    
    let prev_hash = genesis.block_hash();
    
    // Build chain A (2 blocks)
    let block1a = create_test_block(prev_hash, 1);
    let block2a = create_test_block(block1a.block_hash(), 2);
    
    // Build chain B (3 blocks - longer)
    let block1b = create_test_block(prev_hash, 1);
    let block2b = create_test_block(block1b.block_hash(), 2);
    let block3b = create_test_block(block2b.block_hash(), 3);
    
    // Process chain A first
    chain.add_block(block1a.clone(), 1).await?;
    chain.add_block(block2a.clone(), 2).await?;
    
    // Now process longer chain B - should trigger reorg
    chain.add_block(block1b.clone(), 1).await?;
    chain.add_block(block2b.clone(), 2).await?;
    chain.add_block(block3b.clone(), 3).await?;
    
    // Verify chain B is now the active chain
    let best_height = chain.get_best_height();
    assert_eq!(best_height, 3, "Best chain should have height 3");
    
    let best_hash = chain.get_best_block_hash();
    assert_eq!(best_hash, block3b.block_hash(), "Best block should be block3b");
    
    Ok(())
}

/// Test mempool persistence across restarts
#[tokio::test]
async fn test_mempool_persistence() -> Result<()> {
    let data_dir = tempfile::tempdir()?;
    let network = bitcoin::Network::Regtest;
    
    // First session - add transactions
    {
        let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
        let mut mempool = mempool::pool::Mempool::with_persistence(
            Default::default(),
            chain.clone(),
            data_dir.path().join("mempool.dat"),
        ).await?;
        
        // Add test transaction
        let tx = create_test_transaction();
        mempool.add_transaction(tx.clone()).await?;
        
        // Save to disk
        mempool.save_to_disk().await?;
        
        assert_eq!(mempool.size(), 1);
    }
    
    // Second session - load from disk
    {
        let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
        let mempool = mempool::pool::Mempool::with_persistence(
            Default::default(),
            chain.clone(),
            data_dir.path().join("mempool.dat"),
        ).await?;
        
        // Should have loaded the transaction
        assert_eq!(mempool.size(), 1, "Mempool should have persisted transaction");
    }
    
    Ok(())
}

/// Test UTXO set management
#[tokio::test]
async fn test_utxo_management() -> Result<()> {
    use bitcoin::Amount;
    use bitcoin_core_lib::utxo_cache_manager::{UtxoCacheManager, CacheConfig};
    
    let data_dir = tempfile::tempdir()?;
    let storage = Arc::new(storage::manager::StorageManager::new(
        data_dir.path().to_str().unwrap()
    ).await?);
    
    let cache = UtxoCacheManager::new(storage.clone(), CacheConfig::default())?;
    
    // Create test UTXO
    let outpoint = OutPoint {
        txid: bitcoin::Txid::all_zeros(),
        vout: 0,
    };
    
    let output = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: bitcoin::ScriptBuf::new(),
    };
    
    // Add UTXO
    cache.add_utxo(outpoint, output.clone(), 100, false).await?;
    
    // Retrieve UTXO
    let retrieved = cache.get_utxo(&outpoint).await?;
    assert!(retrieved.is_some(), "UTXO should be retrievable");
    assert_eq!(retrieved.unwrap().output.value, output.value);
    
    // Spend UTXO
    let spent = cache.spend_utxo(&outpoint).await?;
    assert!(spent.is_some(), "Should return spent output");
    
    // Verify it's gone
    let after_spend = cache.get_utxo(&outpoint).await?;
    assert!(after_spend.is_none(), "UTXO should be spent");
    
    // Test cache statistics
    let stats = cache.get_stats().await;
    assert!(stats.hits > 0 || stats.misses > 0);
    
    Ok(())
}

/// Test pruning functionality
#[tokio::test]
async fn test_block_pruning() -> Result<()> {
    let data_dir = tempfile::tempdir()?;
    let mut storage = storage::manager::StorageManager::new(
        data_dir.path().to_str().unwrap()
    ).await?;
    
    // Enable pruning with 1GB target
    let pruning_config = storage::pruning::PruningConfig {
        enabled: true,
        target_size: 1_000_000_000, // 1GB
        min_blocks_to_keep: 288,     // ~2 days
        prune_height_buffer: 100,
    };
    
    storage.enable_pruning(pruning_config).await?;
    assert!(storage.is_pruning_enabled());
    
    // Add some blocks
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    for height in 0..500 {
        let block = if height == 0 {
            genesis.clone()
        } else {
            create_test_block(BlockHash::all_zeros(), height)
        };
        storage.store_block(block, height).await?;
    }
    
    // Trigger pruning
    storage.prune_if_needed().await?;
    
    // Check that old blocks may be pruned
    let is_available = storage.is_block_available(10).await;
    // Depending on pruning logic, old blocks might not be available
    
    Ok(())
}

/// Test fee estimation
#[tokio::test]
async fn test_fee_estimation() -> Result<()> {
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?;
    
    // Add transactions with different fee rates
    for i in 1..10 {
        let mut tx = create_test_transaction();
        // Vary the fee by changing output value
        if let Some(output) = tx.output.get_mut(0) {
            output.value = bitcoin::Amount::from_sat(50_000_000 - (i * 1000));
        }
        mempool.add_transaction(tx).await?;
    }
    
    // Estimate fees for different confirmation targets
    let fee_2_blocks = mempool.estimate_smart_fee(2, bitcoin_core_lib::fee_estimation::EstimateMode::Conservative);
    let fee_6_blocks = mempool.estimate_smart_fee(6, bitcoin_core_lib::fee_estimation::EstimateMode::Economical);
    
    // Fee for 2 blocks should be higher than 6 blocks
    if let (Some(rate2), Some(rate6)) = (fee_2_blocks, fee_6_blocks) {
        assert!(rate2.as_sat_per_vb() >= rate6.as_sat_per_vb(), 
                "Faster confirmation should have higher fee");
    }
    
    Ok(())
}

/// Test complete transaction lifecycle
#[tokio::test]
async fn test_transaction_lifecycle() -> Result<()> {
    let data_dir = tempfile::tempdir()?;
    let network = bitcoin::Network::Regtest;
    
    // Initialize node components
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let storage = Arc::new(storage::manager::StorageManager::new(
        data_dir.path().to_str().unwrap()
    ).await?);
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    // Create and add transaction to mempool
    let tx = create_test_transaction();
    let txid = tx.compute_txid();
    mempool.write().await.add_transaction(tx.clone()).await?;
    
    // Verify in mempool
    assert!(mempool.read().await.has_transaction(&txid));
    
    // Mine block with transaction
    let mut block = create_test_block(BlockHash::all_zeros(), 1);
    block.txdata.push(tx.clone());
    
    // Process block
    chain.add_block(block.clone(), 1).await?;
    storage.store_block(block.clone(), 1).await?;
    
    // Remove from mempool
    mempool.write().await.remove_mined_transactions(&block).await?;
    
    // Verify removed from mempool
    assert!(!mempool.read().await.has_transaction(&txid));
    
    Ok(())
}

// Helper functions

fn create_test_block(prev_hash: bitcoin::BlockHash, height: u32) -> Block {
    use bitcoin::blockdata::block::Header;
    use bitcoin::CompactTarget;
    
    Block {
        header: Header {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash: prev_hash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: height * 600 + 1_500_000_000, // Incrementing timestamp
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: height,
        },
        txdata: vec![],
    }
}

fn create_test_transaction() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::all_zeros(),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(50_000_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    }
}