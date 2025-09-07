use anyhow::Result;
use bitcoin::consensus::encode::deserialize;
use bitcoin::Block;
use serde_json::{json, Value};
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

/// Helper to make RPC calls to a running node
async fn rpc_call(port: u16, method: &str, params: Value) -> Result<Value> {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://127.0.0.1:{}", port))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }))
        .send()
        .await?;

    let result: Value = response.json().await?;

    if let Some(error) = result.get("error") {
        anyhow::bail!("RPC error: {}", error);
    }

    Ok(result["result"].clone())
}

#[tokio::test]
async fn test_genesis_block() -> Result<()> {
    // Test that we can deserialize and validate the genesis block
    // This is the regtest genesis block
    let genesis_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    let genesis_bytes = hex::decode(genesis_hex)?;
    let genesis_block: Block = deserialize(&genesis_bytes)?;

    assert_eq!(genesis_block.header.version.to_consensus(), 1);
    assert_eq!(genesis_block.txdata.len(), 1); // Only coinbase
    assert!(genesis_block.txdata[0].is_coinbase());

    Ok(())
}

// RPC integration tests - require a running node
#[cfg(feature = "integration-test")]
mod rpc_tests {
    use super::*;

    const TEST_RPC_PORT: u16 = 29500;

    #[tokio::test]
    async fn test_rpc_getblockcount() -> Result<()> {
        let result = rpc_call(TEST_RPC_PORT, "getblockcount", json!([])).await?;
        assert!(result.is_number());
        Ok(())
    }

    #[tokio::test]
    async fn test_rpc_getblockchaininfo() -> Result<()> {
        let result = rpc_call(TEST_RPC_PORT, "getblockchaininfo", json!([])).await?;
        assert!(result.is_object());
        assert_eq!(result["chain"], "regtest");
        Ok(())
    }

    #[tokio::test]
    async fn test_rpc_getmempoolinfo() -> Result<()> {
        let result = rpc_call(TEST_RPC_PORT, "getmempoolinfo", json!([])).await?;
        assert!(result.is_object());
        assert!(result["size"].is_number());
        Ok(())
    }

    #[tokio::test]
    async fn test_rpc_getnetworkinfo() -> Result<()> {
        let result = rpc_call(TEST_RPC_PORT, "getnetworkinfo", json!([])).await?;
        assert!(result.is_object());
        assert_eq!(result["protocolversion"], 70016);
        Ok(())
    }
}

// Skip this test due to core crate name conflict with std::core
// The test would need to be in a separate crate or within bitcoin-node/src
// #[tokio::test]
// async fn test_block_validation() -> Result<()> {
//     Ok(())
// }

// Test basic network types without full integration
// Commented out as these types don't exist yet
// #[tokio::test]
// async fn test_relay_config() -> Result<()> {
//     use network::{BlockRelayConfig, TxRelayConfig};
//
//     // Test that default configs work
//     let tx_config = TxRelayConfig::default();
//     assert_eq!(tx_config.max_orphan_txs, 100);
//     assert_eq!(tx_config.max_inv_per_message, 1000);
//
//     let block_config = BlockRelayConfig::default();
//     assert_eq!(block_config.max_blocks_in_flight, 16);
//     assert_eq!(block_config.max_orphan_blocks, 100);
//
//     Ok(())
// }

// Test header validation
// Commented out as HeaderValidator doesn't exist yet
// #[tokio::test]
// async fn test_header_validation() -> Result<()> {
//     use network::HeaderValidator;
//
//     // Create header validator
//     let validator = HeaderValidator::new(bitcoin::Network::Regtest);
//
//     // This is a basic test that the validator can be created
//     // Full validation tests would require actual block headers
//     assert!(true);
//
//     Ok(())
// }
