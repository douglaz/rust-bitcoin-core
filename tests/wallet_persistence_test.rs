use anyhow::Result;
use bitcoin::{Address, Network, Transaction, TxOut, OutPoint};
use rust_bitcoin_core_wallet::wallet::Wallet;
use rust_bitcoin_core_wallet::address::AddressType;
use tempfile::TempDir;
use std::str::FromStr;

#[tokio::test]
async fn test_wallet_persistence() -> Result<()> {
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
        let addr2 = wallet.get_new_address(AddressType::P2wpkh)?;
        
        println!("Generated addresses: {}, {}", addr1, addr2);
        
        // Simulate receiving a transaction (process a fake block)
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
        let mut tx = Transaction {
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
        
        println!("Successfully restored wallet with {} addresses", addresses.len());
    }
    
    println!("✓ Wallet persistence test passed!");
    Ok(())
}

#[tokio::test]
async fn test_wallet_utxo_persistence() -> Result<()> {
    // Create temporary directory for wallet
    let temp_dir = TempDir::new()?;
    let wallet_path = temp_dir.path().join("test_wallet_utxo");
    std::fs::create_dir_all(&wallet_path)?;
    
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "testpass";
    
    // Create wallet and add multiple UTXOs
    {
        let mut wallet = Wallet::create(
            "test_wallet_utxo".to_string(),
            mnemonic,
            passphrase,
            Network::Regtest,
            &wallet_path,
        ).await?;
        
        let addr1 = wallet.get_new_address(AddressType::P2wpkh)?;
        
        // Create multiple transactions
        for i in 0..3 {
            let mut block = bitcoin::Block {
                header: bitcoin::block::Header {
                    version: bitcoin::block::Version::from_consensus(4),
                    prev_blockhash: bitcoin::BlockHash::all_zeros(),
                    merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                    time: 1234567890 + i,
                    bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                    nonce: i,
                },
                txdata: vec![],
            };
            
            let tx = Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![
                    TxOut {
                        value: bitcoin::Amount::from_sat(10_000_000 * (i + 1) as u64),
                        script_pubkey: addr1.script_pubkey(),
                    },
                ],
            };
            
            block.txdata.push(tx);
            wallet.process_block(&block, i + 1)?;
        }
        
        let balance = wallet.get_balance()?;
        // Total: 10M + 20M + 30M = 60M sats = 0.6 BTC
        assert_eq!(balance.to_sat(), 60_000_000, "Balance should be 0.6 BTC");
        
        let utxos = wallet.list_unspent();
        assert_eq!(utxos.len(), 3, "Should have 3 UTXOs");
        
        println!("Created wallet with {} UTXOs, balance: {} BTC", utxos.len(), balance.to_btc());
    }
    
    // Load and verify
    {
        let wallet = Wallet::load(&wallet_path).await?;
        
        let balance = wallet.get_balance()?;
        assert_eq!(balance.to_sat(), 60_000_000, "Balance should be restored to 0.6 BTC");
        
        let utxos = wallet.list_unspent();
        assert_eq!(utxos.len(), 3, "Should have 3 UTXOs restored");
        
        println!("✓ Successfully restored {} UTXOs with balance: {} BTC", utxos.len(), balance.to_btc());
    }
    
    Ok(())
}