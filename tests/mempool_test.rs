use anyhow::Result;
use bitcoin::{Transaction, TxOut, OutPoint, Amount};
use rust_bitcoin_core_mempool::pool::Mempool;
use rust_bitcoin_core_chain::chain::ChainManager;
use rust_bitcoin_core_storage::manager::UtxoManager;
use std::sync::Arc;
use tokio::sync::RwLock;
use tempfile::TempDir;

#[tokio::test]
async fn test_mempool_basic_operations() -> Result<()> {
    // Create temporary directory
    let temp_dir = TempDir::new()?;
    
    // Initialize chain manager
    let chain_manager = ChainManager::new(
        bitcoin::Network::Regtest,
        temp_dir.path(),
    ).await?;
    let chain = Arc::new(RwLock::new(chain_manager));
    
    // Initialize UTXO manager
    let utxo_manager = UtxoManager::new(temp_dir.path()).await?;
    let utxo = Arc::new(utxo_manager);
    
    // Create mempool
    let mut mempool = Mempool::new(chain.clone(), utxo.clone()).await?;
    
    // Check initial state
    assert_eq!(mempool.get_transaction_ids().len(), 0);
    let (size, bytes, _) = mempool.get_mempool_info();
    assert_eq!(size, 0);
    
    // Create a simple transaction
    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],  // Would need valid inputs in real scenario
        output: vec![
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }
        ],
    };
    
    // Try to add transaction (will fail due to no inputs, but tests the flow)
    match mempool.add_transaction(tx.clone()).await {
        Ok(_) => println!("Transaction added successfully"),
        Err(e) => println!("Expected error adding tx with no inputs: {}", e),
    }
    
    // Verify mempool is still functional after error
    assert_eq!(mempool.get_transaction_ids().len(), 0);
    
    println!("✓ Mempool basic operations test passed!");
    Ok(())
}

#[tokio::test]
async fn test_mempool_transaction_listing() -> Result<()> {
    // Create temporary directory
    let temp_dir = TempDir::new()?;
    
    // Initialize components
    let chain_manager = ChainManager::new(
        bitcoin::Network::Regtest,
        temp_dir.path(),
    ).await?;
    let chain = Arc::new(RwLock::new(chain_manager));
    
    let utxo_manager = UtxoManager::new(temp_dir.path()).await?;
    let utxo = Arc::new(utxo_manager);
    
    let mempool = Mempool::new(chain.clone(), utxo.clone()).await?;
    
    // Get transaction IDs (should be empty)
    let txids = mempool.get_transaction_ids();
    assert_eq!(txids.len(), 0, "Mempool should start empty");
    
    // Get mempool info
    let (size, bytes, fee_rate) = mempool.get_mempool_info();
    assert_eq!(size, 0, "Mempool size should be 0");
    assert_eq!(bytes, 0, "Mempool bytes should be 0");
    
    println!("✓ Mempool transaction listing test passed!");
    Ok(())
}