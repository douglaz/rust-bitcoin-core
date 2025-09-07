use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header as BlockHeader, Version as BlockVersion};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::Sequence;
use bitcoin::{Block, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use std::sync::Arc;
use tokio::sync::RwLock;

// Import from the bitcoin-core-lib crate (our crate), not the built-in core
use bitcoin_core_lib::consensus::{ConsensusParams, ValidationResult};
use bitcoin_core_lib::script::ScriptFlags;
use bitcoin_core_lib::tx_validator::TxValidationPipeline;
use bitcoin_core_lib::validation::BlockValidator;
use storage::utxo::UtxoSet;

/// Create a test block with specified transactions
fn create_test_block(txs: Vec<Transaction>) -> Block {
    // Calculate the correct merkle root from transactions
    let merkle_root =
        bitcoin::merkle_tree::calculate_root(txs.iter().map(|tx| tx.compute_txid().to_raw_hash()))
            .map(|root| bitcoin::TxMerkleNode::from_raw_hash(root))
            .unwrap_or_else(|| bitcoin::TxMerkleNode::from_byte_array([0u8; 32]));

    Block {
        header: BlockHeader {
            version: BlockVersion::from_consensus(4),
            prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
            merkle_root,
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        },
        txdata: txs,
    }
}

/// Create a coinbase transaction
fn create_coinbase(height: u32, value: u64) -> Transaction {
    let mut coinbase_script = Vec::new();

    // Encode height in script (BIP34) - use minimal encoding
    if height == 0 {
        coinbase_script.push(0x00); // OP_0/OP_FALSE
    } else if height <= 0x7f {
        // Single byte
        coinbase_script.push(0x01); // Push 1 byte
        coinbase_script.push(height as u8);
    } else if height <= 0x7fff {
        // Two bytes
        coinbase_script.push(0x02); // Push 2 bytes
        coinbase_script.extend_from_slice(&height.to_le_bytes()[..2]);
    } else if height <= 0x7fffff {
        // Three bytes
        coinbase_script.push(0x03); // Push 3 bytes
        coinbase_script.extend_from_slice(&height.to_le_bytes()[..3]);
    } else {
        // Four bytes
        coinbase_script.push(0x04); // Push 4 bytes
        coinbase_script.extend_from_slice(&height.to_le_bytes());
    }

    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(coinbase_script),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

/// Create a regular transaction
fn create_transaction(inputs: Vec<OutPoint>, output_value: u64) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .into_iter()
            .map(|outpoint| TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(output_value),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

#[tokio::test]
async fn test_valid_block_validation() -> Result<()> {
    // Setup
    let consensus_params = ConsensusParams::for_network("regtest")?;
    let db = Arc::new(sled::Config::new().temporary(true).open()?);
    let utxo_set = Arc::new(RwLock::new(UtxoSet::new(db.clone())));
    let tx_validator = Arc::new(TxValidationPipeline::new(
        ScriptFlags::P2SH | ScriptFlags::WITNESS,
    ));
    let validator = BlockValidator::new(consensus_params, tx_validator, utxo_set);

    // Create a valid block with just a coinbase
    let coinbase = create_coinbase(1, 50_00000000);
    let block = create_test_block(vec![coinbase]);

    // Validate
    let result = validator.validate_block(&block, 1, None).await?;

    assert!(matches!(result, ValidationResult::Valid));
    Ok(())
}

#[tokio::test]
async fn test_invalid_coinbase_value() -> Result<()> {
    // Setup
    let consensus_params = ConsensusParams::for_network("regtest")?;
    let db = Arc::new(sled::Config::new().temporary(true).open()?);
    let utxo_set = Arc::new(RwLock::new(UtxoSet::new(db.clone())));
    let tx_validator = Arc::new(TxValidationPipeline::new(ScriptFlags::empty()));
    let validator = BlockValidator::new(consensus_params, tx_validator, utxo_set);

    // Create block with excessive coinbase value
    let coinbase = create_coinbase(1, 100_00000000); // Too much!
    let block = create_test_block(vec![coinbase]);

    // Validate
    let result = validator.validate_block(&block, 1, None).await?;

    match result {
        ValidationResult::Invalid(reason) => {
            assert!(reason.contains("Coinbase value"));
        }
        _ => panic!("Expected invalid result"),
    }

    Ok(())
}

#[tokio::test]
async fn test_no_coinbase_transaction() -> Result<()> {
    // Setup
    let consensus_params = ConsensusParams::for_network("regtest")?;
    let db = Arc::new(sled::Config::new().temporary(true).open()?);
    let utxo_set = Arc::new(RwLock::new(UtxoSet::new(db.clone())));
    let tx_validator = Arc::new(TxValidationPipeline::new(ScriptFlags::empty()));
    let validator = BlockValidator::new(consensus_params, tx_validator, utxo_set);

    // Create block without coinbase (invalid)
    let regular_tx = create_transaction(vec![OutPoint::null()], 1000);
    let block = create_test_block(vec![regular_tx]);

    // Validate
    let result = validator.validate_block(&block, 1, None).await?;

    match result {
        ValidationResult::Invalid(reason) => {
            assert!(reason.contains("coinbase"));
        }
        _ => panic!("Expected invalid result"),
    }

    Ok(())
}

#[tokio::test]
async fn test_duplicate_coinbase() -> Result<()> {
    // Setup
    let consensus_params = ConsensusParams::for_network("regtest")?;
    let db = Arc::new(sled::Config::new().temporary(true).open()?);
    let utxo_set = Arc::new(RwLock::new(UtxoSet::new(db.clone())));
    let tx_validator = Arc::new(TxValidationPipeline::new(ScriptFlags::empty()));
    let validator = BlockValidator::new(consensus_params, tx_validator, utxo_set);

    // Create block with two coinbase transactions (invalid)
    let coinbase1 = create_coinbase(1, 25_00000000);
    let coinbase2 = create_coinbase(1, 25_00000000);
    let block = create_test_block(vec![coinbase1, coinbase2]);

    // Validate
    let result = validator.validate_block(&block, 1, None).await?;

    match result {
        ValidationResult::Invalid(reason) => {
            assert!(reason.contains("coinbase"));
        }
        _ => panic!("Expected invalid result"),
    }

    Ok(())
}

#[tokio::test]
async fn test_block_weight_limit() -> Result<()> {
    // Setup
    let consensus_params = ConsensusParams::for_network("regtest")?;
    let db = Arc::new(sled::Config::new().temporary(true).open()?);
    let utxo_set = Arc::new(RwLock::new(UtxoSet::new(db.clone())));
    let tx_validator = Arc::new(TxValidationPipeline::new(ScriptFlags::empty()));
    let validator = BlockValidator::new(consensus_params, tx_validator, utxo_set);

    // Create block with many large transactions
    let mut txs = vec![create_coinbase(1, 50_00000000)];

    // Add transactions until we exceed weight limit
    // Each transaction with large script will contribute to weight
    for _i in 0..10000 {
        let mut tx = create_transaction(vec![OutPoint::null()], 1000);
        // Add a large script to increase weight
        tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0u8; 500]);
        txs.push(tx);
    }

    let block = create_test_block(txs);

    // Validate - should fail due to weight limit
    let result = validator.validate_block(&block, 1, None).await?;

    match result {
        ValidationResult::Invalid(reason) => {
            assert!(reason.contains("weight") || reason.contains("Weight"));
        }
        _ => panic!("Expected invalid result due to weight limit"),
    }

    Ok(())
}

#[tokio::test]
async fn test_merkle_root_validation() -> Result<()> {
    // Setup
    let consensus_params = ConsensusParams::for_network("regtest")?;
    let db = Arc::new(sled::Config::new().temporary(true).open()?);
    let utxo_set = Arc::new(RwLock::new(UtxoSet::new(db.clone())));
    let tx_validator = Arc::new(TxValidationPipeline::new(ScriptFlags::empty()));
    let validator = BlockValidator::new(consensus_params, tx_validator, utxo_set);

    // Create block with incorrect merkle root
    let coinbase = create_coinbase(1, 50_00000000);
    let mut block = create_test_block(vec![coinbase]);

    // Set wrong merkle root
    block.header.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0u8; 32]);

    // Validate
    let result = validator.validate_block(&block, 1, None).await?;

    match result {
        ValidationResult::Invalid(reason) => {
            assert!(reason.contains("merkle"));
        }
        _ => panic!("Expected invalid result"),
    }

    Ok(())
}

#[tokio::test]
async fn test_block_reward_halving() -> Result<()> {
    // Setup
    let consensus_params = ConsensusParams::for_network("regtest")?;
    let db = Arc::new(sled::Config::new().temporary(true).open()?);
    let utxo_set = Arc::new(RwLock::new(UtxoSet::new(db.clone())));
    let tx_validator = Arc::new(TxValidationPipeline::new(ScriptFlags::empty()));
    let validator = BlockValidator::new(consensus_params, tx_validator, utxo_set);

    // Test at first halving (block 150 for regtest)
    let coinbase = create_coinbase(150, 25_00000000); // Should be 25 BTC after halving
    let block = create_test_block(vec![coinbase]);

    // Validate
    let result = validator.validate_block(&block, 150, None).await?;

    assert!(matches!(result, ValidationResult::Valid));

    // Test with wrong reward amount
    let coinbase_wrong = create_coinbase(150, 50_00000000); // Wrong! Should be halved
    let block_wrong = create_test_block(vec![coinbase_wrong]);

    let result_wrong = validator.validate_block(&block_wrong, 150, None).await?;

    match result_wrong {
        ValidationResult::Invalid(reason) => {
            assert!(reason.contains("Coinbase value"));
        }
        _ => panic!("Expected invalid result for wrong block reward"),
    }

    Ok(())
}

#[test]
fn test_consensus_params() -> Result<()> {
    // Test mainnet parameters
    let mainnet = ConsensusParams::for_network("mainnet")?;
    assert_eq!(mainnet.max_block_weight, 4_000_000);
    assert_eq!(mainnet.coinbase_maturity, 100);
    assert_eq!(mainnet.subsidy_halving_interval, 210_000);

    // Test testnet parameters
    let testnet = ConsensusParams::for_network("testnet")?;
    assert_eq!(testnet.max_block_weight, 4_000_000);
    assert_eq!(testnet.coinbase_maturity, 100);

    // Test regtest parameters
    let regtest = ConsensusParams::for_network("regtest")?;
    assert_eq!(regtest.subsidy_halving_interval, 150); // Different for regtest

    Ok(())
}
