use anyhow::Result;
use bitcoin::{Network, Amount, Transaction, TxOut};
use rust_bitcoin_core_wallet::{
    Wallet, 
    AddressType, 
    WalletAutoSave, 
    FAST_AUTOSAVE_INTERVAL
};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_wallet_complete_workflow() -> Result<()> {
    // Create temporary directory for wallet
    let temp_dir = TempDir::new()?;
    let wallet_path = temp_dir.path().join("test_wallet");
    std::fs::create_dir_all(&wallet_path)?;
    
    // Test mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "testpass";
    
    // Create wallet
    let mut wallet = Wallet::create(
        "integration_test".to_string(),
        mnemonic,
        passphrase,
        Network::Regtest,
        &wallet_path,
    ).await?;
    
    // Generate addresses
    let addr1 = wallet.get_new_address(AddressType::P2wpkh)?;
    let addr2 = wallet.get_new_address(AddressType::P2wpkh)?;
    let addr3 = wallet.get_new_address(AddressType::P2wpkh)?;
    
    println!("Generated addresses:");
    println!("  Address 1: {}", addr1);
    println!("  Address 2: {}", addr2);
    println!("  Address 3: {}", addr3);
    
    // Simulate receiving transactions
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
    
    // Transaction 1: 0.5 BTC to addr1
    let tx1 = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: addr1.script_pubkey(),
            },
        ],
    };
    block.txdata.push(tx1);
    
    // Transaction 2: 0.3 BTC to addr2
    let tx2 = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(30_000_000),
                script_pubkey: addr2.script_pubkey(),
            },
        ],
    };
    block.txdata.push(tx2);
    
    // Process block
    wallet.process_block(&block, 1)?;
    
    // Check balance
    let balance = wallet.get_balance()?;
    assert_eq!(balance.to_sat(), 80_000_000, "Balance should be 0.8 BTC");
    
    let balance_details = wallet.get_balance_details();
    println!("Wallet balance:");
    println!("  Confirmed: {} BTC", balance_details.confirmed.to_btc());
    println!("  Pending: {} BTC", balance_details.pending.to_btc());
    println!("  Unconfirmed: {} BTC", balance_details.unconfirmed.to_btc());
    println!("  Total: {} BTC", balance_details.total.to_btc());
    
    // List unspent
    let utxos = wallet.list_unspent();
    assert_eq!(utxos.len(), 2, "Should have 2 UTXOs");
    println!("UTXOs: {}", utxos.len());
    
    // Save wallet state
    wallet.save_wallet_state()?;
    
    println!("✓ Wallet complete workflow test passed!");
    Ok(())
}

#[tokio::test]
async fn test_wallet_autosave() -> Result<()> {
    // Create temporary directory
    let temp_dir = TempDir::new()?;
    let wallet_path = temp_dir.path().join("autosave_wallet");
    std::fs::create_dir_all(&wallet_path)?;
    
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "testpass";
    
    // Create wallet wrapped in Arc<RwLock>
    let wallet = Wallet::create(
        "autosave_test".to_string(),
        mnemonic,
        passphrase,
        Network::Regtest,
        &wallet_path,
    ).await?;
    
    let wallet_arc = Arc::new(RwLock::new(wallet));
    
    // Start autosave with fast interval (10 seconds)
    let _autosave_handle = wallet_arc.clone().start_autosave(FAST_AUTOSAVE_INTERVAL);
    
    // Add some activity
    {
        let mut wallet = wallet_arc.write().await;
        let addr = wallet.get_new_address(AddressType::P2wpkh)?;
        
        // Add a transaction
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
        
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000_000),
                    script_pubkey: addr.script_pubkey(),
                },
            ],
        };
        block.txdata.push(tx);
        
        wallet.process_block(&block, 1)?;
    }
    
    // Wait for autosave to trigger
    println!("Waiting for autosave to trigger (12 seconds)...");
    sleep(Duration::from_secs(12)).await;
    
    // Load wallet from disk to verify autosave worked
    let loaded_wallet = Wallet::load(&wallet_path).await?;
    let balance = loaded_wallet.get_balance()?;
    assert_eq!(balance.to_sat(), 100_000_000, "Balance should be persisted by autosave");
    
    println!("✓ Wallet autosave test passed!");
    Ok(())
}

#[tokio::test]
async fn test_wallet_lock_unlock() -> Result<()> {
    // Create temporary directory
    let temp_dir = TempDir::new()?;
    let wallet_path = temp_dir.path().join("lock_test_wallet");
    std::fs::create_dir_all(&wallet_path)?;
    
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "testpass";
    
    // Create and setup wallet
    {
        let mut wallet = Wallet::create(
            "lock_test".to_string(),
            mnemonic,
            passphrase,
            Network::Regtest,
            &wallet_path,
        ).await?;
        
        // Generate addresses
        let _addr1 = wallet.get_new_address(AddressType::P2wpkh)?;
        let _addr2 = wallet.get_new_address(AddressType::P2wpkh)?;
        
        // Lock the wallet
        wallet.lock();
        assert!(wallet.is_locked(), "Wallet should be locked");
        
        // Try to generate address while locked (should fail)
        match wallet.get_new_address(AddressType::P2wpkh) {
            Err(_) => println!("✓ Correctly failed to generate address while locked"),
            Ok(_) => panic!("Should not be able to generate address while locked"),
        }
        
        // Unlock wallet
        wallet.unlock(mnemonic, passphrase)?;
        assert!(!wallet.is_locked(), "Wallet should be unlocked");
        
        // Should work now
        let _addr3 = wallet.get_new_address(AddressType::P2wpkh)?;
        
        wallet.save_wallet_state()?;
    }
    
    // Load wallet (should be locked)
    {
        let mut wallet = Wallet::load(&wallet_path).await?;
        assert!(wallet.is_locked(), "Loaded wallet should be locked");
        
        // Unlock and verify addresses are restored
        wallet.unlock(mnemonic, passphrase)?;
        let addresses = wallet.list_addresses()?;
        assert!(addresses.len() >= 3, "Should have at least 3 addresses");
        
        println!("✓ Successfully restored {} addresses after unlock", addresses.len());
    }
    
    println!("✓ Wallet lock/unlock test passed!");
    Ok(())
}