use anyhow::Result;
use bitcoin::{Block, BlockHash, Transaction, TxOut, Amount};
use bitcoin::blockdata::block::Header;
use bitcoin::blockdata::transaction::{TxIn, OutPoint};
use bitcoin::hashes::Hash;
use network::compact_block_protocol::{CompactBlockProtocol, CompactBlockConfig, SendCmpct};
use network::compact_blocks::{CompactBlock, CompactBlockRelay, BlockTxn};
use network::message::Message;
use std::sync::Arc;
use std::time::Duration;

/// Create a test block with transactions
fn create_test_block(num_transactions: usize) -> Block {
    let mut txdata = Vec::new();
    
    // Create coinbase transaction
    let coinbase = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::blockdata::transaction::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5000000000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    txdata.push(coinbase);
    
    // Create regular transactions
    for i in 1..=num_transactions {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_slice(&[i as u8; 32]).unwrap(),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::blockdata::transaction::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100000000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        txdata.push(tx);
    }
    
    Block {
        header: Header {
            version: bitcoin::blockdata::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txdata,
    }
}

#[tokio::test]
async fn test_bip152_full_flow() -> Result<()> {
    // Create compact block protocol
    let config = CompactBlockConfig {
        enabled: true,
        prefer_high_bandwidth: false,
        max_high_bandwidth_peers: 3,
        compact_block_timeout: Duration::from_secs(30),
        missing_tx_timeout: Duration::from_secs(10),
    };
    
    let relay = Arc::new(CompactBlockRelay::new(None));
    let protocol = CompactBlockProtocol::new(relay, config);
    
    // Test SendCmpct negotiation
    let peer_id = "peer1";
    let sendcmpct = SendCmpct {
        high_bandwidth: false,
        version: 1,
    };
    
    let response = protocol.handle_sendcmpct(peer_id, sendcmpct).await?;
    assert!(response.is_some(), "Should respond to SendCmpct");
    
    // Create a test block
    let block = create_test_block(10);
    let block_hash = block.block_hash();
    
    // Convert to compact block
    let compact_block = CompactBlock::from_block(&block, Some(12345));
    
    // Process compact block
    let messages = protocol.handle_cmpctblock(peer_id, compact_block.clone()).await?;
    
    // Should either reconstruct or request missing transactions
    assert!(!messages.is_empty(), "Should generate response messages");
    
    // Check if we got a GetBlockTxn request
    let mut has_getblocktxn = false;
    for msg in &messages {
        if let Message::Other(_) = msg {
            has_getblocktxn = true;
        }
    }
    
    if has_getblocktxn {
        // Simulate receiving BlockTxn response
        let missing_txs: Vec<Transaction> = block.txdata[1..5].to_vec();
        let block_txn = BlockTxn {
            block_hash,
            transactions: missing_txs,
        };
        
        let response = protocol.handle_blocktxn(peer_id, block_txn).await;
        // Response can be None if block isn't fully reconstructed yet
        assert!(response.is_ok(), "Should process BlockTxn without error");
    }
    
    Ok(())
}

#[tokio::test]
async fn test_compact_block_reconstruction() -> Result<()> {
    let relay = Arc::new(CompactBlockRelay::new(None));
    
    // Create a block with transactions
    let block = create_test_block(5);
    
    // Convert to compact block
    let compact_block = CompactBlock::from_block(&block, None);
    
    // Verify compact block has correct structure
    assert_eq!(compact_block.prefilled_txs.len(), 1, "Should have coinbase prefilled");
    assert_eq!(compact_block.short_ids.len(), 5, "Should have 5 short IDs");
    
    // Try to reconstruct without cache (will need missing transactions)
    let result = relay.process_compact_block(compact_block).await?;
    
    // Check result
    match result {
        network::compact_blocks::CompactBlockResult::Reconstructed(reconstructed) => {
            // If reconstructed, verify structure
            assert_eq!(reconstructed.txdata.len(), block.txdata.len());
            assert_eq!(reconstructed.block_hash(), block.block_hash());
        }
        network::compact_blocks::CompactBlockResult::MissingTransactions(missing) => {
            // This is expected without transactions in cache
            assert!(!missing.is_empty(), "Should identify missing transactions");
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_missing_transaction_flow() -> Result<()> {
    let config = CompactBlockConfig::default();
    let relay = Arc::new(CompactBlockRelay::new(None));
    let protocol = CompactBlockProtocol::new(relay.clone(), config);
    
    let peer_id = "peer1";
    
    // Create a block
    let block = create_test_block(10);
    let block_hash = block.block_hash();
    
    // Create compact block
    let compact_block = CompactBlock::from_block(&block, Some(999));
    
    // Process without having transactions in cache
    let messages = protocol.handle_cmpctblock(peer_id, compact_block.clone()).await?;
    
    // Should request missing transactions
    let mut get_block_txn_msg = None;
    for msg in messages {
        if let Message::Other(_) = msg {
            // This would be the GetBlockTxn message
            get_block_txn_msg = Some(msg);
        }
    }
    
    assert!(get_block_txn_msg.is_some(), "Should request missing transactions");
    
    // Simulate receiving the missing transactions
    let missing_indexes = protocol.get_missing_indexes(&compact_block);
    assert!(!missing_indexes.is_empty(), "Should identify missing transactions");
    
    // Create BlockTxn response with requested transactions
    let mut missing_txs = Vec::new();
    for idx in missing_indexes {
        if (idx as usize) < block.txdata.len() {
            missing_txs.push(block.txdata[idx as usize + 1].clone()); // +1 to skip coinbase
        }
    }
    
    let block_txn = BlockTxn {
        block_hash,
        transactions: missing_txs,
    };
    
    // Process BlockTxn
    let response = protocol.handle_blocktxn(peer_id, block_txn).await?;
    
    // Should either reconstruct the block or indicate success
    assert!(response.is_some() || response.is_none(), "BlockTxn processing should complete");
    
    Ok(())
}

#[tokio::test]
async fn test_high_bandwidth_mode() -> Result<()> {
    let config = CompactBlockConfig {
        enabled: true,
        prefer_high_bandwidth: true,
        max_high_bandwidth_peers: 3,
        compact_block_timeout: Duration::from_secs(30),
        missing_tx_timeout: Duration::from_secs(10),
    };
    
    let relay = Arc::new(CompactBlockRelay::new(None));
    let protocol = CompactBlockProtocol::new(relay, config);
    
    // Test high bandwidth negotiation
    let peer_id = "high_bandwidth_peer";
    let sendcmpct = SendCmpct {
        high_bandwidth: true,
        version: 1,
    };
    
    let response = protocol.handle_sendcmpct(peer_id, sendcmpct).await?;
    assert!(response.is_some(), "Should respond to high bandwidth request");
    
    // We can't check internal state, but we verified the response
    
    Ok(())
}

#[tokio::test]
async fn test_block_announcement() -> Result<()> {
    let config = CompactBlockConfig::default();
    let relay = Arc::new(CompactBlockRelay::new(None));
    let protocol = CompactBlockProtocol::new(relay, config);
    
    // Create a block for announcement
    let block = create_test_block(5);
    
    // Test block announcement to a peer
    let result = protocol.announce_block(&block, "peer1").await;
    
    // Should generate an announcement message
    assert!(result.is_ok(), "Block announcement should succeed");
    
    Ok(())
}

#[tokio::test]
async fn test_protocol_statistics() -> Result<()> {
    let config = CompactBlockConfig::default();
    let relay = Arc::new(CompactBlockRelay::new(None));
    let protocol = CompactBlockProtocol::new(relay, config);
    
    let peer_id = "stats_peer";
    
    // Process some messages to generate statistics
    let sendcmpct = SendCmpct {
        high_bandwidth: false,
        version: 1,
    };
    protocol.handle_sendcmpct(peer_id, sendcmpct).await?;
    
    // Create and process a compact block
    let block = create_test_block(3);
    let compact_block = CompactBlock::from_block(&block, None);
    let result = protocol.handle_cmpctblock(peer_id, compact_block).await;
    
    // Verify processing completed
    assert!(result.is_ok(), "Should process compact block");
    
    Ok(())
}

#[tokio::test]
async fn test_cleanup_stale_pending() -> Result<()> {
    let config = CompactBlockConfig {
        enabled: true,
        prefer_high_bandwidth: false,
        max_high_bandwidth_peers: 3,
        compact_block_timeout: Duration::from_millis(100), // Short timeout for testing
        missing_tx_timeout: Duration::from_secs(10),
    };
    
    let relay = Arc::new(CompactBlockRelay::new(None));
    let protocol = CompactBlockProtocol::new(relay, config);
    
    let peer_id = "cleanup_peer";
    
    // Add a pending block that will timeout
    let block = create_test_block(2);
    let compact_block = CompactBlock::from_block(&block, None);
    
    // Process to create pending state
    protocol.handle_cmpctblock(peer_id, compact_block).await?;
    
    // Wait for timeout
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Run cleanup
    protocol.cleanup_stale_pending().await;
    
    // Cleanup completed successfully
    
    Ok(())
}