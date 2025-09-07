use anyhow::Result;
use bitcoin::{Address, Network};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use serde_json::Value;
use std::process::{Command, Child};
use std::str::FromStr;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use tempfile::TempDir;

/// Test harness for Bitcoin node
struct NodeTestHarness {
    process: Option<Child>,
    datadir: TempDir,
    rpc_client: HttpClient,
}

impl NodeTestHarness {
    /// Start a new regtest node
    async fn start_regtest() -> Result<Self> {
        // Create temporary data directory
        let datadir = TempDir::new()?;
        
        // Start bitcoin-node process
        let mut process = Command::new("target/debug/bitcoin-node")
            .arg("--network")
            .arg("regtest")
            .arg("--datadir")
            .arg(datadir.path())
            .arg("--rpc-bind")
            .arg("127.0.0.1:18443")
            .spawn()?;
        
        // Wait for node to start
        sleep(Duration::from_secs(2)).await;
        
        // Create RPC client
        let rpc_client = HttpClientBuilder::default()
            .build("http://127.0.0.1:18443")?;
        
        // Wait for RPC to be ready
        let mut attempts = 0;
        loop {
            match rpc_client.request::<u32, _>("getblockcount", rpc_params![]).await {
                Ok(_) => break,
                Err(_) if attempts < 10 => {
                    attempts += 1;
                    sleep(Duration::from_millis(500)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
        
        Ok(Self {
            process: Some(process),
            datadir,
            rpc_client,
        })
    }
    
    /// Get RPC client
    fn rpc(&self) -> &HttpClient {
        &self.rpc_client
    }
}

impl Drop for NodeTestHarness {
    fn drop(&mut self) {
        // Stop the node process
        if let Some(mut process) = self.process.take() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}

#[tokio::test]
#[ignore] // Requires built binary
async fn test_node_startup() -> Result<()> {
    // Start node
    let node = NodeTestHarness::start_regtest().await?;
    
    // Test getblockcount
    let count: u32 = node.rpc().request("getblockcount", rpc_params![]).await?;
    assert_eq!(count, 0, "Fresh regtest should have 0 blocks");
    
    // Test getbestblockhash
    let hash: String = node.rpc().request("getbestblockhash", rpc_params![]).await?;
    assert_eq!(hash.len(), 64, "Block hash should be 64 hex characters");
    
    // Test getblockchaininfo
    let info: Value = node.rpc().request("getblockchaininfo", rpc_params![]).await?;
    assert_eq!(info["chain"], "regtest");
    assert_eq!(info["blocks"], 0);
    
    Ok(())
}

#[tokio::test]
#[ignore] // Requires built binary
async fn test_mining_blocks() -> Result<()> {
    // Start node
    let node = NodeTestHarness::start_regtest().await?;
    
    // Create a test address
    let address = "bcrt1q6rhpng9evdsfnn833ytcdwa0eg6mzm335n2le";
    
    // Mine 10 blocks
    let block_hashes: Vec<String> = node.rpc()
        .request("generatetoaddress", rpc_params![10, address])
        .await?;
    
    assert_eq!(block_hashes.len(), 10, "Should mine 10 blocks");
    
    // Verify block count
    let count: u32 = node.rpc().request("getblockcount", rpc_params![]).await?;
    assert_eq!(count, 10, "Should have 10 blocks after mining");
    
    // Get and verify first mined block
    let block: Value = node.rpc()
        .request("getblock", rpc_params![&block_hashes[0]])
        .await?;
    
    assert_eq!(block["height"], 1);
    assert_eq!(block["confirmations"], 10);
    
    Ok(())
}

#[tokio::test]
#[ignore] // Requires built binary
async fn test_mempool_operations() -> Result<()> {
    // Start node
    let node = NodeTestHarness::start_regtest().await?;
    
    // Check empty mempool
    let mempool: Vec<String> = node.rpc()
        .request("getrawmempool", rpc_params![])
        .await?;
    assert_eq!(mempool.len(), 0, "Mempool should be empty");
    
    // Get mempool info
    let info: Value = node.rpc()
        .request("getmempoolinfo", rpc_params![])
        .await?;
    
    assert_eq!(info["size"], 0);
    assert_eq!(info["bytes"], 0);
    assert!(info["loaded"].as_bool().unwrap());
    
    Ok(())
}

#[tokio::test]
#[ignore] // Requires built binary
async fn test_network_info() -> Result<()> {
    // Start node
    let node = NodeTestHarness::start_regtest().await?;
    
    // Get network info
    let info: Value = node.rpc()
        .request("getnetworkinfo", rpc_params![])
        .await?;
    
    assert_eq!(info["version"], 250000);
    assert!(info["networkactive"].as_bool().unwrap());
    assert_eq!(info["connections"], 0); // No peers in isolated regtest
    
    // Get peer info
    let peers: Vec<Value> = node.rpc()
        .request("getpeerinfo", rpc_params![])
        .await?;
    assert_eq!(peers.len(), 0, "Should have no peers in regtest");
    
    // Get connection count
    let connections: u32 = node.rpc()
        .request("getconnectioncount", rpc_params![])
        .await?;
    assert_eq!(connections, 0);
    
    Ok(())
}

#[tokio::test]
#[ignore] // Requires built binary
async fn test_chain_progress() -> Result<()> {
    // Start node
    let node = NodeTestHarness::start_regtest().await?;
    
    let address = "bcrt1q6rhpng9evdsfnn833ytcdwa0eg6mzm335n2le";
    
    // Mine blocks one by one and verify chain progress
    for i in 1..=5 {
        // Mine one block
        let hashes: Vec<String> = node.rpc()
            .request("generatetoaddress", rpc_params![1, address])
            .await?;
        assert_eq!(hashes.len(), 1);
        
        // Verify block count
        let count: u32 = node.rpc().request("getblockcount", rpc_params![]).await?;
        assert_eq!(count, i, "Should have {} blocks", i);
        
        // Verify best block hash changed
        let best_hash: String = node.rpc()
            .request("getbestblockhash", rpc_params![])
            .await?;
        assert_eq!(best_hash, hashes[0]);
    }
    
    Ok(())
}

#[tokio::test]
#[ignore] // Requires built binary
async fn test_block_details() -> Result<()> {
    // Start node
    let node = NodeTestHarness::start_regtest().await?;
    
    let address = "bcrt1q6rhpng9evdsfnn833ytcdwa0eg6mzm335n2le";
    
    // Mine a block
    let hashes: Vec<String> = node.rpc()
        .request("generatetoaddress", rpc_params![1, address])
        .await?;
    
    let block_hash = &hashes[0];
    
    // Get block details
    let block: Value = node.rpc()
        .request("getblock", rpc_params![block_hash])
        .await?;
    
    // Verify block fields
    assert_eq!(block["hash"], *block_hash);
    assert_eq!(block["height"], 1);
    assert_eq!(block["version"], 4);
    assert!(block["time"].as_u64().unwrap() > 0);
    assert!(block["nTx"].as_u64().unwrap() >= 1); // At least coinbase
    
    // Verify it has a coinbase transaction
    assert!(block["tx"].as_array().unwrap().len() >= 1);
    
    Ok(())
}

#[tokio::test]
#[ignore] // Requires wallet crate
async fn test_wallet_persistence() -> Result<()> {
    use rust_bitcoin_core_wallet::wallet::Wallet;
    use rust_bitcoin_core_wallet::address::AddressType;
    use tempfile::TempDir;
    use bitcoin::{TxOut};
    
    // Create temporary directory for wallet
    let temp_dir = TempDir::new()?;
    let wallet_path = temp_dir.path().join("test_wallet");
    std::fs::create_dir_all(&wallet_path)?;
    
    // Test mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "testpass";
    
    // Create and setup wallet
    {
        let mut wallet = Wallet::create(
            "test_wallet".to_string(),
            mnemonic,
            passphrase,
            Network::Regtest,
            &wallet_path,
        ).await?;
        
        // Generate some addresses
        let addr1 = wallet.get_new_address(AddressType::P2wpkh)?;
        let _addr2 = wallet.get_new_address(AddressType::P2wpkh)?;
        
        println!("Generated address: {}", addr1);
        
        // Simulate receiving a transaction
        let mut block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(4),
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![],
        };
        
        // Create a fake transaction that sends to our address
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: bitcoin::Amount::from_sat(50_000_000), // 0.5 BTC
                    script_pubkey: addr1.script_pubkey(),
                },
            ],
        };
        
        block.txdata.push(tx);
        
        // Process the block
        wallet.process_block(&block, 1)?;
        
        // Check balance
        let balance = wallet.get_balance()?;
        assert_eq!(balance.to_sat(), 50_000_000, "Balance should be 0.5 BTC");
        
        // Save state explicitly
        wallet.save_wallet_state()?;
        
        println!("Wallet state saved with balance: {} BTC", balance.to_btc());
    }
    
    // Load wallet from disk
    {
        let mut wallet = Wallet::load(&wallet_path).await?;
        
        // Wallet should be locked
        assert!(wallet.is_locked(), "Wallet should be locked after loading");
        
        // Check that balance is restored even when locked
        let balance = wallet.get_balance()?;
        println!("Restored balance: {} BTC", balance.to_btc());
        assert_eq!(balance.to_sat(), 50_000_000, "Balance should be restored to 0.5 BTC");
        
        // Unlock wallet
        wallet.unlock(mnemonic, passphrase)?;
        assert!(!wallet.is_locked(), "Wallet should be unlocked");
        
        // Verify addresses are restored
        let addresses = wallet.list_addresses()?;
        assert!(addresses.len() >= 2, "Should have at least 2 addresses");
        
        println!("✓ Wallet persistence test passed! Restored {} addresses", addresses.len());
    }
    
    Ok(())
}

// Unit tests that don't require the full node
#[cfg(test)]
mod unit_tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Block, BlockHash, Transaction};
    
    #[test]
    fn test_block_hash_format() {
        // Test that block hashes are properly formatted
        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(4),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![],
        };
        
        let hash = block.block_hash();
        let hash_str = hash.to_string();
        
        assert_eq!(hash_str.len(), 64);
        assert!(hash_str.chars().all(|c| c.is_ascii_hexdigit()));
    }
    
    #[test]
    fn test_regtest_address_parsing() {
        // Test that regtest addresses can be parsed
        let address_str = "bcrt1q6rhpng9evdsfnn833ytcdwa0eg6mzm335n2le";
        let address = Address::from_str(address_str);
        
        assert!(address.is_ok());
        let addr = address.unwrap().assume_checked();
        
        // Verify it's a valid bech32 address
        assert!(address_str.starts_with("bcrt1"));
    }
}