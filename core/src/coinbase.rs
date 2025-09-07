use anyhow::{bail, Result};
use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::blockdata::opcodes::OP_FALSE;
use bitcoin::blockdata::script::Instruction;
use bitcoin::{Block, OutPoint, ScriptBuf, Transaction, TxOut};
use tracing::trace;

/// Coinbase maturity constant (100 blocks)
pub const COINBASE_MATURITY: u32 = 100;

/// Check if a coinbase output is mature enough to be spent
pub fn is_coinbase_mature(coinbase_height: u32, current_height: u32) -> bool {
    current_height >= coinbase_height + COINBASE_MATURITY
}

/// Extract height from coinbase script (BIP34)
pub fn extract_height_from_coinbase(coinbase: &Transaction) -> Result<Option<u32>> {
    if !coinbase.is_coinbase() {
        bail!("Transaction is not a coinbase");
    }

    if coinbase.input.is_empty() {
        bail!("Coinbase has no inputs");
    }

    let script = &coinbase.input[0].script_sig;
    let mut instructions = script.instructions();

    // First instruction should be a push of the height
    if let Some(Ok(instruction)) = instructions.next() {
        match instruction {
            Instruction::Op(op) if op == OP_FALSE => {
                // Height 0 encoded as OP_FALSE (OP_0)
                trace!("Extracted height 0 from coinbase (OP_FALSE)");
                return Ok(Some(0));
            }
            Instruction::PushBytes(push) => {
                let bytes = push.as_bytes();

                if bytes.is_empty() {
                    // Empty bytes also means 0
                    return Ok(Some(0));
                }

                // Decode script number (signed little-endian with minimal encoding)
                let mut height: i64 = 0;
                for (i, &byte) in bytes.iter().enumerate() {
                    if i == bytes.len() - 1 {
                        // Last byte - check for sign
                        if byte & 0x80 != 0 {
                            // Negative number (shouldn't happen for block heights)
                            return Ok(None);
                        }
                    }
                    height |= (byte as i64) << (8 * i);
                }

                if height < 0 || height > u32::MAX as i64 {
                    return Ok(None);
                }

                trace!("Extracted height {} from coinbase", height);
                return Ok(Some(height as u32));
            }
            _ => {
                // First instruction is not a push
                return Ok(None);
            }
        }
    }

    Ok(None)
}

/// Validate coinbase transaction
pub fn validate_coinbase(
    block: &Block,
    height: u32,
    block_reward: u64,
    total_fees: u64,
) -> Result<()> {
    if block.txdata.is_empty() {
        bail!("Block has no transactions");
    }

    let coinbase = &block.txdata[0];

    // Must be coinbase
    if !coinbase.is_coinbase() {
        bail!("First transaction is not coinbase");
    }

    // Check that no other transaction is coinbase
    for (i, tx) in block.txdata[1..].iter().enumerate() {
        if tx.is_coinbase() {
            bail!("Transaction {} is also coinbase", i + 1);
        }
    }

    // Check height in coinbase (BIP34)
    if height >= 227836 {
        // BIP34 activation height on mainnet
        match extract_height_from_coinbase(coinbase)? {
            Some(coinbase_height) => {
                if coinbase_height != height {
                    bail!(
                        "Coinbase height {} doesn't match block height {}",
                        coinbase_height,
                        height
                    );
                }
            }
            None => {
                bail!("BIP34 requires height in coinbase after block 227836");
            }
        }
    }

    // Calculate maximum allowed coinbase value
    let max_allowed = block_reward + total_fees;
    let coinbase_value: u64 = coinbase.output.iter().map(|o| o.value.to_sat()).sum();

    if coinbase_value > max_allowed {
        bail!(
            "Coinbase value {} exceeds maximum {} (reward {} + fees {})",
            coinbase_value,
            max_allowed,
            block_reward,
            total_fees
        );
    }

    // Check coinbase script size (must be between 2 and 100 bytes)
    let script_sig_len = coinbase.input[0].script_sig.len();
    if !(2..=100).contains(&script_sig_len) {
        bail!(
            "Coinbase script sig length {} not in valid range [2, 100]",
            script_sig_len
        );
    }

    Ok(())
}

/// Check if spending a coinbase output is allowed
pub fn check_coinbase_spend(
    outpoint: &OutPoint,
    output_height: u32,
    current_height: u32,
    is_coinbase_tx: bool,
) -> Result<()> {
    if is_coinbase_tx && !is_coinbase_mature(output_height, current_height) {
        bail!(
            "Coinbase output from height {} not mature at height {} (requires {} confirmations)",
            output_height,
            current_height,
            COINBASE_MATURITY
        );
    }
    Ok(())
}

/// Calculate block subsidy based on height
pub fn calculate_block_subsidy(height: u32) -> u64 {
    calculate_block_subsidy_with_params(height, 210_000)
}

/// Calculate block subsidy with custom halving interval (for testing)
pub fn calculate_block_subsidy_with_params(height: u32, halving_interval: u32) -> u64 {
    // Bitcoin halving schedule
    let halvings = height / halving_interval;

    if halvings >= 64 {
        return 0; // No more block rewards after 64 halvings
    }

    // Start at 50 BTC, halve every halving_interval blocks
    50_00000000u64 >> halvings
}

/// Create coinbase transaction for mining
pub fn create_coinbase_transaction(
    height: u32,
    coinbase_script: ScriptBuf,
    value: u64,
    witness_commitment: Option<[u8; 32]>,
) -> Transaction {
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Create coinbase input with height
    let mut script_sig = ScriptBuf::new();

    // Push height as required by BIP34
    // BIP34 requires encoding as a script number (minimally encoded)
    use bitcoin::script::PushBytesBuf;

    // Encode height as script number (minimally encoded)
    let height_bytes = if height == 0 {
        // Special case: 0 is encoded as empty array
        vec![]
    } else if height <= 16 {
        // Special case: small numbers 1-16 use OP_1 through OP_16
        // But for BIP34, we always use push bytes
        vec![height as u8]
    } else {
        // Encode as minimal little-endian bytes
        let mut bytes = Vec::new();
        let mut n = height;

        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }

        // If the high bit is set, add a sign byte (script numbers are signed)
        if !bytes.is_empty() && (bytes[bytes.len() - 1] & 0x80) != 0 {
            bytes.push(0);
        }

        bytes
    };

    // Push the height bytes as data
    if !height_bytes.is_empty() {
        let push_bytes = PushBytesBuf::try_from(height_bytes).unwrap();
        script_sig.push_slice(push_bytes);
    } else {
        // Height 0: push empty array
        script_sig.push_opcode(OP_FALSE); // OP_0 is the same as OP_FALSE
    }

    // Add extra nonce space (can be used for additional entropy)
    let nonce_bytes = PushBytesBuf::try_from(b"CyberKrill".to_vec()).unwrap();
    script_sig.push_slice(nonce_bytes);

    tx.input.push(bitcoin::TxIn {
        previous_output: OutPoint::null(),
        script_sig,
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::new(),
    });

    // Create coinbase output
    tx.output.push(TxOut {
        value: bitcoin::Amount::from_sat(value),
        script_pubkey: coinbase_script,
    });

    // Add witness commitment if provided (for SegWit blocks)
    if let Some(commitment) = witness_commitment {
        let mut commitment_script = ScriptBuf::new();
        commitment_script.push_opcode(OP_RETURN);
        let header_bytes = PushBytesBuf::try_from(vec![0x24, 0xaa, 0x21, 0xa9, 0xed]).unwrap();
        commitment_script.push_slice(header_bytes); // Witness commitment header
        let commitment_bytes = PushBytesBuf::try_from(commitment.to_vec()).unwrap();
        commitment_script.push_slice(commitment_bytes);

        tx.output.push(TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: commitment_script,
        });
    }

    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coinbase_maturity() {
        assert!(!is_coinbase_mature(100, 199));
        assert!(is_coinbase_mature(100, 200));
        assert!(is_coinbase_mature(100, 201));
    }

    #[test]
    fn test_block_subsidy() {
        // Genesis era: 50 BTC
        assert_eq!(calculate_block_subsidy(0), 50_00000000);
        assert_eq!(calculate_block_subsidy(209_999), 50_00000000);

        // First halving: 25 BTC
        assert_eq!(calculate_block_subsidy(210_000), 25_00000000);
        assert_eq!(calculate_block_subsidy(419_999), 25_00000000);

        // Second halving: 12.5 BTC
        assert_eq!(calculate_block_subsidy(420_000), 12_50000000);

        // Third halving: 6.25 BTC
        assert_eq!(calculate_block_subsidy(630_000), 6_25000000);

        // Fourth halving: 3.125 BTC
        assert_eq!(calculate_block_subsidy(840_000), 3_12500000);
    }

    #[test]
    fn test_create_coinbase() {
        let script = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]); // Example script
        let tx = create_coinbase_transaction(12345, script.clone(), 50_00000000, None);

        assert!(tx.is_coinbase());
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 50_00000000);
    }

    #[test]
    fn test_extract_height() {
        // Create a coinbase with height
        let script = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]);
        let tx = create_coinbase_transaction(12345, script, 50_00000000, None);

        let height = extract_height_from_coinbase(&tx).unwrap();
        assert_eq!(height, Some(12345));
    }
}
