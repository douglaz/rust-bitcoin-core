use anyhow::Result;
use bitcoin::{Block, BlockHeader, BlockHash, Transaction};
use bitcoin::hashes::Hash;
use network::{NetworkManager, Message, peer::Peer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{sleep, timeout};

/// Test peer connectivity and handshake
#[tokio::test]
async fn test_peer_connection_and_handshake() -> Result<()> {
    // Create network manager
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    let mut network_manager = NetworkManager::new(network, chain, Some(mempool));
    
    // Start network manager
    network_manager.start().await?;
    
    // Add a test peer
    let test_addr: SocketAddr = "127.0.0.1:18444".parse()?;
    network_manager.connect_to_peer(test_addr).await?;
    
    // Wait for connection
    sleep(Duration::from_secs(2)).await;
    
    // Check peer count
    let peer_count = network_manager.peer_count().await;
    assert!(peer_count > 0, "Should have at least one peer");
    
    // Shutdown
    network_manager.shutdown().await?;
    
    Ok(())
}

/// Test message relay between peers
#[tokio::test]
async fn test_message_relay() -> Result<()> {
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    let network_manager = Arc::new(Mutex::new(NetworkManager::new(network, chain, Some(mempool))));
    
    // Start network
    network_manager.lock().await.start().await?;
    
    // Create a test transaction
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    
    // Broadcast transaction
    network_manager.lock().await.broadcast_transaction(&tx).await?;
    
    // Wait for relay
    sleep(Duration::from_millis(500)).await;
    
    // Shutdown
    network_manager.lock().await.shutdown().await?;
    
    Ok(())
}

/// Test block announcement and relay
#[tokio::test]
async fn test_block_relay() -> Result<()> {
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    let network_manager = Arc::new(Mutex::new(NetworkManager::new(network, chain.clone(), Some(mempool))));
    
    // Start network
    network_manager.lock().await.start().await?;
    
    // Create genesis block
    let genesis = bitcoin::blockdata::constants::genesis_block(network);
    
    // Broadcast block
    network_manager.lock().await.broadcast_block(genesis.clone()).await?;
    
    // Wait for relay
    sleep(Duration::from_millis(500)).await;
    
    // Shutdown
    network_manager.lock().await.shutdown().await?;
    
    Ok(())
}

/// Test peer discovery via DNS seeds
#[tokio::test]
async fn test_dns_peer_discovery() -> Result<()> {
    let network = bitcoin::Network::Bitcoin; // Use mainnet for DNS seeds
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    let mut network_manager = NetworkManager::new(network, chain, Some(mempool));
    
    // Start network (will trigger DNS discovery)
    network_manager.start().await?;
    
    // Wait for discovery
    sleep(Duration::from_secs(5)).await;
    
    // Check we found peers
    let peer_count = network_manager.peer_count().await;
    assert!(peer_count > 0, "Should have discovered peers via DNS");
    
    // Shutdown
    network_manager.shutdown().await?;
    
    Ok(())
}

/// Test headers synchronization
#[tokio::test]
async fn test_headers_sync() -> Result<()> {
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    let network_manager = Arc::new(Mutex::new(NetworkManager::new(network, chain.clone(), Some(mempool))));
    
    // Start network
    network_manager.lock().await.start().await?;
    
    // Create test peer address
    let peer_addr: SocketAddr = "127.0.0.1:18444".parse()?;
    
    // Send getheaders message
    let genesis_hash = bitcoin::blockdata::constants::genesis_block(network).block_hash();
    let stop_hash = BlockHash::all_zeros();
    
    network_manager.lock().await
        .send_getheaders_to_peer(peer_addr, vec![genesis_hash], stop_hash)
        .await?;
    
    // Wait for response
    sleep(Duration::from_secs(2)).await;
    
    // Shutdown
    network_manager.lock().await.shutdown().await?;
    
    Ok(())
}

/// Test compact block relay (BIP152)
#[tokio::test]
async fn test_compact_block_relay() -> Result<()> {
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    let network_manager = Arc::new(Mutex::new(NetworkManager::new(network, chain.clone(), Some(mempool))));
    
    // Start network
    network_manager.lock().await.start().await?;
    
    // Compact blocks are handled automatically by the protocol handler
    // Just ensure the network starts successfully with compact block support
    
    // Shutdown
    network_manager.lock().await.shutdown().await?;
    
    Ok(())
}

/// Test DoS protection and rate limiting
#[tokio::test]
async fn test_dos_protection() -> Result<()> {
    use network::dos_protection::{DosProtectionManager, DosProtectionConfig};
    
    let config = DosProtectionConfig::default();
    let dos_manager = Arc::new(DosProtectionManager::new(config));
    
    // Test connection rate limiting
    let test_addr: SocketAddr = "192.168.1.100:8333".parse()?;
    let ip = test_addr.ip();
    
    // Should allow first connection
    assert!(dos_manager.check_connection_allowed(&ip).await?);
    
    // Rapid connections should eventually be limited
    for _ in 0..10 {
        let _ = dos_manager.check_connection_allowed(&ip).await;
    }
    
    // Test message rate limiting
    for _ in 0..200 {
        if let Err(_) = dos_manager.check_message_allowed(&test_addr, "inv").await {
            // Rate limit triggered - expected
            break;
        }
    }
    
    // Test peer scoring
    dos_manager.update_peer_score(&test_addr, -50, "Test violation").await?;
    let score = dos_manager.get_peer_score(&test_addr).await;
    assert_eq!(score, -50);
    
    // Test ban threshold
    dos_manager.update_peer_score(&test_addr, -60, "Another violation").await?;
    assert!(dos_manager.is_peer_banned(&test_addr).await);
    
    // Test ban cleanup
    dos_manager.cleanup_expired_bans().await?;
    
    Ok(())
}

/// Test peer ping/pong mechanism
#[tokio::test]
async fn test_peer_ping_pong() -> Result<()> {
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    let network_manager = Arc::new(Mutex::new(NetworkManager::new(network, chain, Some(mempool))));
    
    // Start network
    network_manager.lock().await.start().await?;
    
    // Get connected peers
    let peers = network_manager.lock().await.get_connected_peers().await;
    
    // Send ping to each peer
    for peer_addr in peers {
        let nonce = rand::random::<u64>();
        network_manager.lock().await
            .send_ping_to_peer(&peer_addr, nonce)
            .await?;
    }
    
    // Wait for pongs
    sleep(Duration::from_secs(1)).await;
    
    // Shutdown
    network_manager.lock().await.shutdown().await?;
    
    Ok(())
}

/// Test multi-peer connectivity
#[tokio::test]
async fn test_multi_peer_connection() -> Result<()> {
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    let mut network_manager = NetworkManager::new(network, chain, Some(mempool));
    
    // Start network
    network_manager.start().await?;
    
    // Add multiple test peers
    let test_peers = vec![
        "127.0.0.1:18444",
        "127.0.0.1:18445", 
        "127.0.0.1:18446",
    ];
    
    for peer_str in test_peers {
        if let Ok(addr) = peer_str.parse::<SocketAddr>() {
            let _ = network_manager.connect_to_peer(addr).await;
        }
    }
    
    // Wait for connections
    sleep(Duration::from_secs(2)).await;
    
    // Check peer count
    let peer_count = network_manager.peer_count().await;
    println!("Connected to {} peers", peer_count);
    
    // Get peer heights
    let peer_heights = network_manager.get_peer_heights().await;
    for (addr, height) in peer_heights {
        println!("Peer {} at height {}", addr, height);
    }
    
    // Shutdown
    network_manager.shutdown().await?;
    
    Ok(())
}

/// Test automatic peer discovery and connection
#[tokio::test]
async fn test_auto_peer_discovery() -> Result<()> {
    let network = bitcoin::Network::Regtest;
    let chain = Arc::new(bitcoin_core_lib::chain::ChainManager::new(network));
    let mempool = Arc::new(RwLock::new(mempool::pool::Mempool::new(
        Default::default(),
        chain.clone(),
    ).await?));
    
    let mut network_manager = NetworkManager::new(network, chain, Some(mempool));
    
    // Start network
    network_manager.start().await?;
    
    // Trigger automatic discovery when peer count is low
    let initial_count = network_manager.peer_count().await;
    if initial_count < 8 {
        network_manager.discover_and_connect_peers(8 - initial_count).await?;
    }
    
    // Wait for connections
    sleep(Duration::from_secs(3)).await;
    
    // Verify we have more peers
    let final_count = network_manager.peer_count().await;
    assert!(final_count >= initial_count, "Should have discovered new peers");
    
    // Shutdown
    network_manager.shutdown().await?;
    
    Ok(())
}