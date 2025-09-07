use anyhow::Result;
use jsonrpsee::client_transport::ws::WsTransportClientBuilder;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::params::ArrayParams;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use rpc::SimpleRpcServer;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;

#[tokio::test]
async fn test_simple_rpc_server() -> Result<()> {
    // Use explicit extern crate to disambiguate within the test
    extern crate bitcoin_core_lib as bitcoin_core;
    // Setup test components
    let storage = Arc::new(::storage::manager::StorageManager::new("/tmp/test_rpc").await?);
    let chain = Arc::new(RwLock::new(
        bitcoin_core::chain::ChainManager::new(storage.clone(), "regtest".to_string()).await?,
    ));
    let utxo_manager = Arc::new(bitcoin_core::utxo_manager::UtxoManager::new());
    let mempool = Arc::new(RwLock::new(
        ::mempool::pool::Mempool::new(chain.clone(), utxo_manager).await?,
    ));
    let chain_unwrapped = Arc::new(
        bitcoin_core::chain::ChainManager::new(storage.clone(), "regtest".to_string()).await?,
    );
    let network = Arc::new(Mutex::new(::network::manager::NetworkManager::new(
        bitcoin::Network::Regtest,
        chain_unwrapped,
        0,
    )));

    // Start server in background
    let addr: SocketAddr = "127.0.0.1:18332".parse()?;
    let server = SimpleRpcServer::new(addr, chain, mempool, network);

    let server_handle = tokio::spawn(async move {
        match server.run().await {
            Ok(handle) => {
                // Keep the server running
                handle.stopped().await;
            }
            Err(e) => {
                eprintln!("Server failed to start: {}", e);
            }
        }
    });

    // Wait for server to start with retries
    let mut connected = false;
    for _ in 0..10 {
        sleep(Duration::from_millis(200)).await;
        if let Ok(client) = HttpClientBuilder::default().build(format!("http://{}", addr)) {
            // Try a simple request to check if server is up
            if client.request::<u32, _>("getblockcount", rpc_params![]).await.is_ok() {
                connected = true;
                break;
            }
        }
    }
    
    if !connected {
        server_handle.abort();
        panic!("Failed to connect to RPC server after 2 seconds");
    }

    // Create HTTP client
    let client = HttpClientBuilder::default().build(format!("http://{}", addr))?;

    // Test getblockcount
    let count: u32 = client.request("getblockcount", rpc_params![]).await?;
    assert_eq!(count, 0);

    // Test getbestblockhash
    let hash: String = client.request("getbestblockhash", rpc_params![]).await?;
    assert_eq!(hash.len(), 64);

    // Test getconnectioncount
    let connections: u32 = client.request("getconnectioncount", rpc_params![]).await?;
    assert_eq!(connections, 0);

    // Test getmempoolinfo
    let mempool_info: Value = client.request("getmempoolinfo", rpc_params![]).await?;
    assert!(mempool_info["loaded"].as_bool().unwrap());
    assert_eq!(mempool_info["size"].as_u64().unwrap(), 0);

    // Test getnetworkinfo
    let network_info: Value = client.request("getnetworkinfo", rpc_params![]).await?;
    assert_eq!(network_info["version"].as_u64().unwrap(), 250000);
    assert!(network_info["networkactive"].as_bool().unwrap());

    // Test getblockchaininfo
    let blockchain_info: Value = client.request("getblockchaininfo", rpc_params![]).await?;
    assert_eq!(blockchain_info["chain"].as_str().unwrap(), "regtest");
    assert_eq!(blockchain_info["blocks"].as_u64().unwrap(), 0);

    // Cleanup
    server_handle.abort();

    Ok(())
}

// Macro for RPC params
macro_rules! rpc_params {
    () => {
        jsonrpsee::core::params::ArrayParams::new()
    };
    ($($param:expr),+) => {
        {
            let mut params = jsonrpsee::core::params::ArrayParams::new();
            $(
                params.insert($param)?;
            )+
            params
        }
    };
}
