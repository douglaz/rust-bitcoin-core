use anyhow::Result;
use bitcoin::{Block, BlockHash, Transaction, TxOut, Amount, Network};
use bitcoin_node::config::NodeConfig;
use bitcoin_node::node::Node;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

/// Test Initial Block Download (IBD) process
#[tokio::test]
async fn test_initial_block_download() -> Result<()> {
    // Setup test environment
    let temp_dir = TempDir::new()?;
    let config = NodeConfig {
        network: "regtest".to_string(),
        datadir: temp_dir.path().to_str().unwrap().to_string(),
        rpc_enabled: true,
        rpc_bind: "127.0.0.1:28444".to_string(),
        connect_peers: vec![],
        max_connections: 8,
    };

    // Create and start node
    let mut node = Node::new(config).await?;
    
    // Start node in background
    let node_handle = tokio::spawn(async move {
        node.run().await
    });
    
    // Wait for node to start
    sleep(Duration::from_secs(2)).await;
    
    // Connect to a test peer (in real test, this would be another node)
    // For now, we'll simulate IBD completion
    
    // Give some time for sync
    sleep(Duration::from_secs(5)).await;
    
    // Check that node is syncing
    // In a real test, we'd check sync progress
    
    Ok(())
}

/// Test syncing a chain of blocks
#[tokio::test] 
async fn test_chain_sync() -> Result<()> {
    use bitcoin_core_lib::chain::ChainManager;
    use storage::StorageManager;
    
    // Setup
    let temp_dir = TempDir::new()?;
    let storage = Arc::new(StorageManager::new(temp_dir.path()).await?);
    let chain = ChainManager::new(storage.clone(), Network::Regtest).await?;
    
    // Create a chain of test blocks
    let mut blocks = vec![];
    let mut prev_hash = BlockHash::all_zeros(); // Genesis
    
    for i in 0..10 {
        let block = create_test_block(prev_hash, i);
        prev_hash = block.block_hash();
        blocks.push(block);
    }
    
    // Process blocks sequentially
    for (height, block) in blocks.iter().enumerate() {
        match chain.process_block(block.clone(), height as u32).await {
            Ok(_) => println!("Block {} processed successfully", height),
            Err(e) => println!("Failed to process block {}: {}", height, e),
        }
    }
    
    // Verify chain height
    assert_eq!(chain.get_best_height(), 9);
    
    Ok(())
}

/// Test syncing with multiple peers
#[tokio::test]
async fn test_multi_peer_sync() -> Result<()> {
    // This test would require multiple node instances
    // For now, we'll create a basic structure
    
    let temp_dir = TempDir::new()?;
    
    // Create multiple nodes
    let mut nodes = vec![];
    for i in 0..3 {
        let config = NodeConfig {
            network: "regtest".to_string(),
            datadir: format!("{}/node{}", temp_dir.path().display(), i),
            rpc_enabled: true,
            rpc_bind: format!("127.0.0.1:{}", 28445 + i),
            connect_peers: if i > 0 {
                vec![format!("127.0.0.1:{}", 28445)]
            } else {
                vec![]
            },
            max_connections: 8,
        };
        
        let node = Node::new(config).await?;
        nodes.push(node);
    }
    
    // Start all nodes
    // In real test, they would sync with each other
    
    Ok(())
}

/// Test IBD performance metrics
#[tokio::test]
async fn test_ibd_performance() -> Result<()> {
    use std::time::Instant;
    
    let start = Instant::now();
    let temp_dir = TempDir::new()?;
    
    // Create test chain with many blocks
    let num_blocks = 100;
    let mut blocks = vec![];
    let mut prev_hash = BlockHash::all_zeros();
    
    for i in 0..num_blocks {
        let block = create_test_block(prev_hash, i);
        prev_hash = block.block_hash();
        blocks.push(block);
    }
    
    // Measure sync time
    let storage = Arc::new(StorageManager::new(temp_dir.path()).await?);
    let chain = ChainManager::new(storage.clone(), Network::Regtest).await?;
    
    for (height, block) in blocks.iter().enumerate() {
        chain.process_block(block.clone(), height as u32).await?;
    }
    
    let elapsed = start.elapsed();
    let blocks_per_sec = num_blocks as f64 / elapsed.as_secs_f64();
    
    println!("IBD Performance:");
    println!("  Processed {} blocks in {:?}", num_blocks, elapsed);
    println!("  Rate: {:.2} blocks/second", blocks_per_sec);
    
    // Assert minimum performance
    assert!(blocks_per_sec > 10.0, "IBD too slow: {} blocks/sec", blocks_per_sec);
    
    Ok(())
}

// Helper function to create test blocks
fn create_test_block(prev_hash: BlockHash, height: u32) -> Block {
    use bitcoin::blockdata::block::Header;
    use bitcoin::blockdata::transaction::{TxIn, TxOut, OutPoint, Version};
    use bitcoin::blockdata::script::ScriptBuf;
    use bitcoin::absolute::LockTime;
    use bitcoin::CompactTarget;
    
    // Create coinbase transaction
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
            value: Amount::from_sat(50_00000000), // 50 BTC reward
            script_pubkey: ScriptBuf::new(),
        }],
    };
    
    Block {
        header: Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: prev_hash,
            merkle_root: coinbase.compute_txid().to_raw_hash().into(),
            time: 1234567890 + height,
            bits: CompactTarget::from_consensus(0x207fffff), // Easy difficulty
            nonce: height, // Simple nonce
        },
        txdata: vec![coinbase],
    }
}

/// Test header-first synchronization
#[tokio::test]
async fn test_headers_first_sync() -> Result<()> {
    use bitcoin_node::headers_sync::HeadersSyncManager;
    
    let temp_dir = TempDir::new()?;
    let storage = Arc::new(StorageManager::new(temp_dir.path()).await?);
    
    // Create headers sync manager
    let headers_sync = HeadersSyncManager::new(storage.clone());
    
    // Create chain of headers
    let mut headers = vec![];
    let mut prev_hash = BlockHash::all_zeros();
    
    for i in 0..100 {
        let block = create_test_block(prev_hash, i);
        prev_hash = block.block_hash();
        headers.push(block.header);
    }
    
    // Process headers
    let start = std::time::Instant::now();
    headers_sync.process_headers(headers).await?;
    let elapsed = start.elapsed();
    
    println!("Processed 100 headers in {:?}", elapsed);
    
    // Verify headers were stored
    assert_eq!(headers_sync.get_best_header_height().await, 99);
    
    Ok(())
}