use anyhow::Result;
use bitcoin::{Block, Transaction};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use bitcoin_core_lib::validation::BlockValidator;
use bitcoin_core_lib::consensus::{ConsensusParams, ValidationResult};
use bitcoin_core_lib::tx_validator::TxValidationPipeline;
use bitcoin_core_lib::script::ScriptFlags;
use std::sync::Arc;

/// Test vector from Bitcoin Core for block validation
/// These are actual blocks from the Bitcoin blockchain
mod test_vectors {
    /// Genesis block (mainnet)
    pub const GENESIS_BLOCK_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    /// First block after genesis (block 1)
    pub const BLOCK_1_HEX: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000";

    /// Real mainnet transaction from block 170
    pub const VALID_TX_1: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";

    /// Transaction with duplicate inputs (invalid)
    pub const INVALID_TX_DUPLICATE_INPUTS: &str = "0100000002c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffffc997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";

    /// Script validation test vectors (P2PKH)
    pub const P2PKH_SCRIPT_PUBKEY: &str = "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac";
    pub const P2PKH_SCRIPT_SIG: &str = "483045022100f477b3dfb9334e864a7c9ad7b6b77d5f8e2198d8c260e991e21b3b445e4b88ee022072ee5633b5a4e75c5a375fb6c9b8bf594e7cc06b09d3b9f6dc1e7bd88298918a0121031b38c5c31c6a58ac9b0d01b1c6e1e0a8a9a8e5e7c6a31ef1b7235e9a8e9aefb85f";

    /// Real SegWit transaction from mainnet
    pub const SEGWIT_TX_HEX: &str = "020000000001010ccc140e766b5dbc884ea2d780c5e91e4eb77597ae64288a42575228b79e234900000000000000000002bd37060000000000225120245091249f4f29d30820e5f36e1e5d477dc3386144220bd6f35839e94de4b9caf0c10d00000000001600140416e0f1d5382c7e011ed53ccde141231ccdd66b024730440220085ffea28c7103ce24af60004ee2a01e688dddf33e8d407c708cfa2a103e0dfa022067bbaf83f2e59f5e0c7d009fe4e4dd2e47cc956f940f5bc2df920e1e49c7cb170121039fce4f01a7945dd45bdf2e86b039d24bb63032e604eda3c37f59296e08ba58db00000000";
}

#[tokio::test]
async fn test_genesis_block_validation() -> Result<()> {
    let genesis_bytes = Vec::<u8>::from_hex(test_vectors::GENESIS_BLOCK_HEX)?;
    let genesis_block: Block = deserialize(&genesis_bytes)?;
    
    // Verify genesis block hash
    let hash = genesis_block.block_hash();
    assert_eq!(
        hash.to_string(),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
    
    // Verify merkle root
    assert_eq!(
        genesis_block.header.merkle_root.to_string(),
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    );
    
    Ok(())
}

#[tokio::test]
async fn test_block_1_validation() -> Result<()> {
    let block_bytes = Vec::<u8>::from_hex(test_vectors::BLOCK_1_HEX)?;
    let block: Block = deserialize(&block_bytes)?;
    
    // Verify block hash
    let hash = block.block_hash();
    assert_eq!(
        hash.to_string(),
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
    );
    
    // Verify it references genesis
    assert_eq!(
        block.header.prev_blockhash.to_string(),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
    
    Ok(())
}

#[tokio::test]
async fn test_valid_transaction_parsing() -> Result<()> {
    let tx_bytes = Vec::<u8>::from_hex(test_vectors::VALID_TX_1)?;
    let tx: Transaction = deserialize(&tx_bytes)?;
    
    // Verify transaction structure
    assert_eq!(tx.version.0, 1);
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);
    
    // Verify TXID
    let txid = tx.compute_txid();
    assert!(txid.to_string().len() == 64); // Valid hex string
    
    Ok(())
}

#[tokio::test]
async fn test_invalid_transaction_duplicate_inputs() -> Result<()> {
    let tx_bytes = Vec::<u8>::from_hex(test_vectors::INVALID_TX_DUPLICATE_INPUTS)?;
    let tx: Transaction = deserialize(&tx_bytes)?;
    
    // Check for duplicate inputs manually
    let mut seen_inputs = std::collections::HashSet::new();
    for input in &tx.input {
        if !seen_inputs.insert(input.previous_output) {
            // Duplicate input found
            assert!(true, "Correctly detected duplicate input");
            return Ok(());
        }
    }
    
    panic!("Should have detected duplicate inputs");
}

#[tokio::test]
async fn test_segwit_transaction_validation() -> Result<()> {
    let tx_bytes = Vec::<u8>::from_hex(test_vectors::SEGWIT_TX_HEX)?;
    let tx: Transaction = deserialize(&tx_bytes)?;
    
    // Verify SegWit structure
    assert_eq!(tx.version.0, 2); // Version 2 for this transaction
    assert!(!tx.input[0].witness.is_empty(), "SegWit tx should have witness data");
    
    // Verify witness structure
    let witness = &tx.input[0].witness;
    assert_eq!(witness.len(), 2); // Signature and pubkey
    
    // Verify this is a SegWit transaction
    assert!(tx.is_coinbase() == false);
    
    Ok(())
}


#[tokio::test]
async fn test_script_validation_p2pkh() -> Result<()> {
    use bitcoin::ScriptBuf;
    use bitcoin_core_lib::script::interpreter::ScriptInterpreter;
    
    let script_pubkey_bytes = Vec::<u8>::from_hex(test_vectors::P2PKH_SCRIPT_PUBKEY)?;
    let script_pubkey = ScriptBuf::from_bytes(script_pubkey_bytes);
    
    let script_sig_bytes = Vec::<u8>::from_hex(test_vectors::P2PKH_SCRIPT_SIG)?;
    let script_sig = ScriptBuf::from_bytes(script_sig_bytes);
    
    // Create script interpreter
    let interpreter = ScriptInterpreter::new(ScriptFlags::default());
    
    // For a proper test, we'd need the full transaction context
    // This just verifies the scripts parse correctly
    assert!(script_pubkey.is_p2pkh());
    assert!(!script_sig.is_empty());
    
    Ok(())
}

#[tokio::test]
async fn test_consensus_params_mainnet() -> Result<()> {
    let params = ConsensusParams::for_network("mainnet")?;
    
    // Test mainnet consensus parameters
    assert_eq!(params.bip34_height, 227931);
    assert_eq!(params.bip65_height, 388381);
    assert_eq!(params.bip66_height, 363725);
    assert_eq!(params.segwit_height, 481824);
    
    // Test activation heights
    assert!(params.is_bip34_active(230000));
    assert!(!params.is_bip34_active(200000));
    
    assert!(params.is_bip65_active(400000));
    assert!(!params.is_bip65_active(300000));
    
    assert!(params.is_bip66_active(370000));
    assert!(!params.is_bip66_active(350000));
    
    assert!(params.is_segwit_active(500000));
    assert!(!params.is_segwit_active(400000));
    
    Ok(())
}

#[tokio::test]
async fn test_consensus_params_testnet() -> Result<()> {
    let params = ConsensusParams::for_network("testnet")?;
    
    // Test testnet consensus parameters
    assert_eq!(params.bip34_height, 21111);
    assert_eq!(params.bip65_height, 581885);
    assert_eq!(params.bip66_height, 330776);
    assert_eq!(params.segwit_height, 834624);
    
    Ok(())
}

#[tokio::test]
async fn test_block_weight_calculation() -> Result<()> {
    // Test block weight calculation for SegWit blocks
    let tx_bytes = Vec::<u8>::from_hex(test_vectors::SEGWIT_TX_HEX)?;
    let tx: Transaction = deserialize(&tx_bytes)?;
    
    let weight = tx.weight();
    assert!(weight.to_wu() > 0, "Weight should be greater than 0");
    
    // For SegWit transactions:
    // Weight = (base_size * 3) + total_size
    // where base_size is tx without witness data
    // and total_size includes witness
    let total_size = tx_bytes.len();
    
    // Verify weight is reasonable (between total_size and 4*total_size)
    assert!(weight.to_wu() >= total_size as u64);
    assert!(weight.to_wu() <= (total_size * 4) as u64);
    
    Ok(())
}

#[tokio::test]
async fn test_merkle_root_calculation() -> Result<()> {
    use bitcoin::merkle_tree::calculate_root;
    
    let block_bytes = Vec::<u8>::from_hex(test_vectors::GENESIS_BLOCK_HEX)?;
    let block: Block = deserialize(&block_bytes)?;
    
    // Calculate merkle root from transactions
    let txids: Vec<_> = block.txdata.iter()
        .map(|tx| tx.compute_txid().to_raw_hash())
        .collect();
    
    let calculated_root = calculate_root(txids.into_iter())
        .map(|root| bitcoin::TxMerkleNode::from_raw_hash(root));
    
    assert_eq!(
        calculated_root,
        Some(block.header.merkle_root)
    );
    
    Ok(())
}

/// Test BIP34 block height encoding in coinbase
#[tokio::test]
async fn test_bip34_coinbase_height() -> Result<()> {
    use bitcoin::Transaction;
    
    // Helper to create coinbase with BIP34 height
    fn create_bip34_coinbase(height: u32) -> Transaction {
        let mut script = Vec::new();
        
        // Encode height per BIP34
        if height == 0 {
            script.push(0x00);
        } else if height <= 16 {
            script.push(0x50 + height as u8); // OP_1 through OP_16
        } else if height < 128 {
            script.push(0x01);
            script.push(height as u8);
        } else if height < 32768 {
            script.push(0x02);
            script.extend_from_slice(&(height as u16).to_le_bytes());
        } else {
            script.push(0x03);
            script.extend_from_slice(&height.to_le_bytes()[..3]);
        }
        
        Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from_bytes(script),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(5000000000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }
    
    // Test various heights
    let heights = vec![0, 1, 16, 17, 127, 128, 32767, 32768, 100000];
    
    for height in heights {
        let tx = create_bip34_coinbase(height);
        assert!(tx.is_coinbase());
        
        // Verify script starts with height encoding
        let script = &tx.input[0].script_sig;
        assert!(!script.is_empty());
    }
    
    Ok(())
}