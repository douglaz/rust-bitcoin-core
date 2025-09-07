use anyhow::Result;
use bitcoin::{Block, Transaction, OutPoint, TxIn, TxOut};
use bitcoin::hashes::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::sleep;
use futures::future::join_all;

/// Stress test mempool with many concurrent transactions
#[tokio::test]
async fn stress_test_mempool_concurrent_adds() -> Result<()> {
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    let num_transactions = 1000;
    let num_workers = 10;
    let semaphore = Arc::new(Semaphore::new(num_workers));
    let success_count = Arc::new(AtomicU64::new(0));
    let fail_count = Arc::new(AtomicU64::new(0));
    
    let start = Instant::now();
    
    let mut tasks = vec![];
    
    for i in 0..num_transactions {
        let mempool_clone = mempool.clone();
        let semaphore_clone = semaphore.clone();
        let success_count_clone = success_count.clone();
        let fail_count_clone = fail_count.clone();
        
        let task = tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            
            // Create unique transaction
            let tx = create_unique_transaction(i);
            
            // Try to add to mempool
            let mut mempool = mempool_clone.write().await;
            match mempool.add_transaction(tx).await {
                Ok(_) => {
                    success_count_clone.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    fail_count_clone.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        tasks.push(task);
    }
    
    // Wait for all tasks
    join_all(tasks).await;
    
    let elapsed = start.elapsed();
    let successful = success_count.load(Ordering::Relaxed);
    let failed = fail_count.load(Ordering::Relaxed);
    
    println!("Mempool stress test results:");
    println!("  Transactions: {}", num_transactions);
    println!("  Successful: {}", successful);
    println!("  Failed: {}", failed);
    println!("  Time: {:?}", elapsed);
    println!("  TPS: {:.2}", successful as f64 / elapsed.as_secs_f64());
    
    // Verify mempool size
    let final_size = mempool.read().await.size();
    assert!(final_size > 0, "Mempool should contain transactions");
    
    Ok(())
}

/// Stress test block validation with large blocks
#[tokio::test]
async fn stress_test_large_block_validation() -> Result<()> {
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let validator = bitcoin_core_lib::validation::BlockValidator::new(network);
    
    // Create a large block with many transactions
    let num_txs = 2000;
    let mut block = create_test_block(bitcoin::BlockHash::all_zeros(), 1);
    
    // Add coinbase
    block.txdata.push(create_coinbase_transaction(1));
    
    // Add many transactions
    for i in 1..num_txs {
        block.txdata.push(create_unique_transaction(i as u64));
    }
    
    let start = Instant::now();
    
    // Validate block structure
    let is_valid = validator.validate_block_structure(&block).await.is_ok();
    
    let elapsed = start.elapsed();
    
    println!("Large block validation stress test:");
    println!("  Block size: {} transactions", num_txs);
    println!("  Valid: {}", is_valid);
    println!("  Validation time: {:?}", elapsed);
    
    assert!(is_valid, "Block should be structurally valid");
    
    Ok(())
}

/// Stress test UTXO cache with many operations
#[tokio::test]
async fn stress_test_utxo_cache() -> Result<()> {
    use bitcoin_core_lib::utxo_cache_manager::{UtxoCacheManager, CacheConfig};
    
    let temp_dir = tempfile::tempdir()?;
    let storage = Arc::new(storage::manager::StorageManager::new(
        temp_dir.path().to_str().unwrap()
    ).await?);
    
    let cache = Arc::new(UtxoCacheManager::new(
        storage.clone(),
        CacheConfig {
            max_entries: 10_000,
            max_size_bytes: 100 * 1024 * 1024, // 100MB
            flush_interval: Duration::from_secs(60),
            write_through: false,
        }
    )?);
    
    let num_operations = 5000;
    let num_workers = 20;
    let semaphore = Arc::new(Semaphore::new(num_workers));
    
    let start = Instant::now();
    let mut tasks = vec![];
    
    // Add UTXOs
    for i in 0..num_operations {
        let cache_clone = cache.clone();
        let semaphore_clone = semaphore.clone();
        
        let task = tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            
            let outpoint = OutPoint {
                txid: bitcoin::Txid::from_byte_array([i as u8; 32]),
                vout: 0,
            };
            
            let output = TxOut {
                value: bitcoin::Amount::from_sat(100_000 + i),
                script_pubkey: bitcoin::ScriptBuf::new(),
            };
            
            let _ = cache_clone.add_utxo(outpoint, output, 100, false).await;
        });
        
        tasks.push(task);
    }
    
    join_all(tasks).await;
    
    // Now read them back
    let mut read_tasks = vec![];
    
    for i in 0..num_operations {
        let cache_clone = cache.clone();
        let semaphore_clone = semaphore.clone();
        
        let task = tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            
            let outpoint = OutPoint {
                txid: bitcoin::Txid::from_byte_array([i as u8; 32]),
                vout: 0,
            };
            
            let _ = cache_clone.get_utxo(&outpoint).await;
        });
        
        read_tasks.push(task);
    }
    
    join_all(read_tasks).await;
    
    let elapsed = start.elapsed();
    let stats = cache.get_stats().await;
    
    println!("UTXO cache stress test results:");
    println!("  Operations: {}", num_operations * 2);
    println!("  Time: {:?}", elapsed);
    println!("  Cache entries: {}", stats.entries);
    println!("  Cache hits: {}", stats.hits);
    println!("  Cache misses: {}", stats.misses);
    println!("  Hit rate: {:.2}%", 
             stats.hits as f64 / (stats.hits + stats.misses) as f64 * 100.0);
    
    Ok(())
}

/// Stress test network with many concurrent connections
#[tokio::test]
async fn stress_test_network_connections() -> Result<()> {
    use network::NetworkManager;
    
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    let network_manager = Arc::new(tokio::sync::Mutex::new(
        NetworkManager::new(network, chain, Some(mempool))
    ));
    
    // Start network
    network_manager.lock().await.start().await?;
    
    let num_connections = 50;
    let mut tasks = vec![];
    
    let start = Instant::now();
    
    // Try to connect to many peers concurrently
    for i in 0..num_connections {
        let network_clone = network_manager.clone();
        
        let task = tokio::spawn(async move {
            // Generate test addresses
            let addr = format!("127.0.0.1:{}", 18444 + i);
            if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
                let _ = network_clone.lock().await.connect_to_peer(socket_addr).await;
            }
        });
        
        tasks.push(task);
    }
    
    // Wait for all connection attempts
    join_all(tasks).await;
    
    let elapsed = start.elapsed();
    let peer_count = network_manager.lock().await.peer_count().await;
    
    println!("Network connection stress test:");
    println!("  Connection attempts: {}", num_connections);
    println!("  Connected peers: {}", peer_count);
    println!("  Time: {:?}", elapsed);
    
    // Shutdown
    network_manager.lock().await.shutdown().await?;
    
    Ok(())
}

/// Stress test chain reorganization handling
#[tokio::test]
async fn stress_test_chain_reorg() -> Result<()> {
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    
    // Add genesis
    let genesis = bitcoin::blockdata::constants::genesis_block(network);
    chain.add_block(genesis.clone(), 0).await?;
    
    let num_reorgs = 10;
    let chain_length = 100;
    
    let start = Instant::now();
    
    for reorg_num in 0..num_reorgs {
        // Build main chain
        let mut prev_hash = genesis.block_hash();
        let mut main_chain = vec![];
        
        for height in 1..=chain_length {
            let block = create_test_block(prev_hash, height);
            prev_hash = block.block_hash();
            main_chain.push(block);
        }
        
        // Add main chain
        for (i, block) in main_chain.iter().enumerate() {
            chain.add_block(block.clone(), (i + 1) as u32).await?;
        }
        
        // Build competing chain (longer by 1)
        prev_hash = genesis.block_hash();
        let mut competing_chain = vec![];
        
        for height in 1..=(chain_length + 1) {
            let mut block = create_test_block(prev_hash, height);
            // Make it different
            block.header.nonce = height * 1000 + reorg_num;
            prev_hash = block.block_hash();
            competing_chain.push(block);
        }
        
        // Add competing chain (triggers reorg)
        for (i, block) in competing_chain.iter().enumerate() {
            chain.add_block(block.clone(), (i + 1) as u32).await?;
        }
    }
    
    let elapsed = start.elapsed();
    let final_height = chain.get_best_height();
    
    println!("Chain reorganization stress test:");
    println!("  Number of reorgs: {}", num_reorgs);
    println!("  Chain length: {}", chain_length);
    println!("  Final height: {}", final_height);
    println!("  Time: {:?}", elapsed);
    println!("  Reorgs/sec: {:.2}", num_reorgs as f64 / elapsed.as_secs_f64());
    
    Ok(())
}

/// Stress test DoS protection with attack simulation
#[tokio::test]
async fn stress_test_dos_protection() -> Result<()> {
    use network::dos_protection::{DosProtectionManager, DosProtectionConfig};
    
    let config = DosProtectionConfig {
        max_connections_per_ip: 5,
        connection_rate_limit: 10, // per minute
        max_messages_per_second: 100,
        ban_threshold: -100,
        disconnect_threshold: -50,
        ban_duration: Duration::from_secs(3600),
        ..Default::default()
    };
    
    let dos_manager = Arc::new(DosProtectionManager::new(config));
    
    // Simulate connection flood
    let attacker_ip = "192.168.1.100".parse::<std::net::IpAddr>()?;
    let mut connection_blocked = false;
    
    let start = Instant::now();
    
    for _ in 0..100 {
        match dos_manager.check_connection_allowed(&attacker_ip).await {
            Ok(_) => {}
            Err(_) => {
                connection_blocked = true;
                break;
            }
        }
    }
    
    assert!(connection_blocked, "DoS protection should block connection flood");
    
    // Simulate message flood
    let attacker_addr = "192.168.1.100:8333".parse::<std::net::SocketAddr>()?;
    let mut message_blocked = false;
    
    for _ in 0..1000 {
        match dos_manager.check_message_allowed(&attacker_addr, "inv").await {
            Ok(_) => {}
            Err(_) => {
                message_blocked = true;
                break;
            }
        }
    }
    
    assert!(message_blocked, "DoS protection should block message flood");
    
    // Simulate misbehavior leading to ban
    for _ in 0..5 {
        dos_manager.update_peer_score(&attacker_addr, -25, "Misbehavior").await?;
    }
    
    assert!(dos_manager.is_peer_banned(&attacker_addr).await, 
            "Peer should be banned after reaching ban threshold");
    
    let elapsed = start.elapsed();
    
    println!("DoS protection stress test:");
    println!("  Connection flood blocked: {}", connection_blocked);
    println!("  Message flood blocked: {}", message_blocked);
    println!("  Peer banned: {}", dos_manager.is_peer_banned(&attacker_addr).await);
    println!("  Test time: {:?}", elapsed);
    
    Ok(())
}

/// Stress test concurrent block downloads
#[tokio::test]
async fn stress_test_concurrent_block_downloads() -> Result<()> {
    use network::block_download::{BlockDownloadManager, BlockDownloadConfig};
    
    let config = BlockDownloadConfig {
        max_blocks_in_flight: 16,
        block_download_timeout: Duration::from_secs(30),
        max_peers: 8,
        preferred_peers: 3,
    };
    
    let download_manager = Arc::new(BlockDownloadManager::new(config));
    
    let num_blocks = 100;
    let num_workers = 8;
    let semaphore = Arc::new(Semaphore::new(num_workers));
    
    let start = Instant::now();
    let mut tasks = vec![];
    
    for i in 0..num_blocks {
        let download_clone = download_manager.clone();
        let semaphore_clone = semaphore.clone();
        
        let task = tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            
            let block_hash = bitcoin::BlockHash::from_byte_array([i as u8; 32]);
            let peer_addr = format!("127.0.0.1:{}", 18444 + (i % 8))
                .parse::<std::net::SocketAddr>()
                .unwrap();
            
            // Queue block for download
            download_clone.queue_download(block_hash, peer_addr).await;
            
            // Simulate download completion
            sleep(Duration::from_millis(10)).await;
            
            let test_block = create_test_block(bitcoin::BlockHash::all_zeros(), i);
            download_clone.block_received(block_hash, test_block).await;
        });
        
        tasks.push(task);
    }
    
    join_all(tasks).await;
    
    let elapsed = start.elapsed();
    let stats = download_manager.get_stats().await;
    
    println!("Concurrent block download stress test:");
    println!("  Blocks requested: {}", num_blocks);
    println!("  Time: {:?}", elapsed);
    println!("  Blocks/sec: {:.2}", num_blocks as f64 / elapsed.as_secs_f64());
    println!("  Stats: {:?}", stats);
    
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
            time: height * 600 + 1_500_000_000,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: height,
        },
        txdata: vec![],
    }
}

fn create_unique_transaction(index: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([(index % 256) as u8; 32]),
                vout: (index % 10) as u32,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(50_000_000 - (index * 1000)),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    }
}

fn create_coinbase_transaction(height: u32) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::from_bytes(height.to_le_bytes().to_vec()),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(50_000_000_000), // 50 BTC
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    }
}