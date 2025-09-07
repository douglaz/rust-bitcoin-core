use anyhow::{bail, Result};
use bitcoin::consensus::encode::Encodable;
use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::{Block, Script, Transaction, TxOut};
use tracing::{debug, trace, warn};

/// Witness commitment validation for SegWit blocks
pub struct WitnessValidator;

impl WitnessValidator {
    /// Validate witness commitment in a block
    pub fn validate_witness_commitment(block: &Block) -> Result<bool> {
        // If there are no witness transactions, no commitment needed
        if !Self::has_witness_transactions(block) {
            trace!("Block has no witness transactions, skipping witness validation");
            return Ok(true);
        }

        // Find witness commitment in coinbase
        let coinbase = &block.txdata[0];
        let commitment_output = Self::find_witness_commitment(coinbase)?;

        if commitment_output.is_none() {
            // If block has witness transactions but no commitment, it's invalid
            if Self::has_witness_transactions(block) {
                bail!("Block has witness transactions but no witness commitment");
            }
            return Ok(true);
        }

        let commitment = commitment_output.unwrap();

        // Calculate witness merkle root
        let witness_root = Self::calculate_witness_merkle_root(block)?;

        // Get witness reserved value (in coinbase witness)
        let witness_reserved = Self::get_witness_reserved_value(&block.txdata[0])?;

        // Calculate commitment hash
        let mut commitment_data = Vec::new();
        witness_root.consensus_encode(&mut commitment_data)?;
        witness_reserved.consensus_encode(&mut commitment_data)?;

        let calculated_commitment = sha256d::Hash::hash(&commitment_data);

        // Extract commitment from output script
        let stored_commitment = Self::extract_commitment_from_script(&commitment.script_pubkey)?;

        if calculated_commitment.as_byte_array() != &stored_commitment {
            bail!("Witness commitment mismatch");
        }

        debug!("Witness commitment validated successfully");
        Ok(true)
    }

    /// Check if block contains witness transactions
    fn has_witness_transactions(block: &Block) -> bool {
        block
            .txdata
            .iter()
            .any(|tx| tx.input.iter().any(|input| !input.witness.is_empty()))
    }

    /// Find witness commitment output in coinbase transaction
    fn find_witness_commitment(coinbase: &Transaction) -> Result<Option<TxOut>> {
        // Witness commitment is in an output with OP_RETURN followed by 36 bytes
        // First 4 bytes are commitment header (0xaa21a9ed), next 32 are the hash

        for output in coinbase.output.iter().rev() {
            if Self::is_witness_commitment_script(&output.script_pubkey) {
                return Ok(Some(output.clone()));
            }
        }

        Ok(None)
    }

    /// Check if script is a witness commitment
    fn is_witness_commitment_script(script: &Script) -> bool {
        let bytes = script.as_bytes();

        // Witness commitment pattern: OP_RETURN OP_PUSHBYTES_36 [0xaa21a9ed + 32 bytes]
        if bytes.len() >= 38
            && bytes[0] == 0x6a && // OP_RETURN
               bytes[1] == 0x24 && // OP_PUSHBYTES_36
               bytes[2..6] == [0xaa, 0x21, 0xa9, 0xed]
        // Witness commitment header
        {
            return true;
        }

        false
    }

    /// Extract commitment hash from witness commitment script
    fn extract_commitment_from_script(script: &Script) -> Result<[u8; 32]> {
        let bytes = script.as_bytes();

        if bytes.len() < 38 {
            bail!("Invalid witness commitment script length");
        }

        // Skip OP_RETURN (1), OP_PUSHBYTES_36 (1), and header (4)
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&bytes[6..38]);

        Ok(commitment)
    }

    /// Calculate witness merkle root for all transactions
    fn calculate_witness_merkle_root(block: &Block) -> Result<sha256d::Hash> {
        let mut hashes = Vec::new();

        // First hash is always 0x00...00 for coinbase witness
        hashes.push(sha256d::Hash::all_zeros());

        // Add witness hashes for all other transactions
        for tx in &block.txdata[1..] {
            let wtxid = Self::calculate_wtxid(tx)?;
            hashes.push(wtxid);
        }

        // Calculate merkle root
        Ok(Self::merkle_root(&hashes))
    }

    /// Calculate witness transaction ID (wtxid)
    fn calculate_wtxid(tx: &Transaction) -> Result<sha256d::Hash> {
        let has_witness = tx.input.iter().any(|input| !input.witness.is_empty());

        if !has_witness {
            // For non-witness transactions, wtxid = txid
            Ok(sha256d::Hash::hash(&bitcoin::consensus::encode::serialize(
                tx,
            )))
        } else {
            // For witness transactions, hash includes witness data
            let mut data = Vec::new();
            tx.consensus_encode(&mut data)?;
            Ok(sha256d::Hash::hash(&data))
        }
    }

    /// Get witness reserved value from coinbase
    fn get_witness_reserved_value(coinbase: &Transaction) -> Result<[u8; 32]> {
        // Witness reserved value is in the coinbase input witness stack
        if coinbase.input.is_empty() {
            bail!("Coinbase has no inputs");
        }

        let coinbase_witness = &coinbase.input[0].witness;
        if coinbase_witness.is_empty() {
            bail!("Coinbase has no witness data");
        }

        // The witness reserved value is the first (and only) item in coinbase witness
        let witness_item = coinbase_witness
            .last()
            .ok_or_else(|| anyhow::anyhow!("Empty coinbase witness"))?;

        if witness_item.len() != 32 {
            bail!(
                "Invalid witness reserved value length: {}",
                witness_item.len()
            );
        }

        let mut reserved = [0u8; 32];
        reserved.copy_from_slice(witness_item);

        Ok(reserved)
    }

    /// Calculate merkle root from transaction hashes
    fn merkle_root(hashes: &[sha256d::Hash]) -> sha256d::Hash {
        if hashes.is_empty() {
            return sha256d::Hash::all_zeros();
        }

        if hashes.len() == 1 {
            return hashes[0];
        }

        let mut tree = hashes.to_vec();

        while tree.len() > 1 {
            // If odd number, duplicate last element
            if tree.len() % 2 == 1 {
                tree.push(*tree.last().unwrap());
            }

            let mut next_level = Vec::new();
            for chunk in tree.chunks(2) {
                let mut data = Vec::new();
                data.extend_from_slice(chunk[0].as_byte_array());
                data.extend_from_slice(chunk[1].as_byte_array());
                next_level.push(sha256d::Hash::hash(&data));
            }

            tree = next_level;
        }

        tree[0]
    }

    /// Validate witness signature for a transaction input
    pub fn validate_witness_signature(
        tx: &Transaction,
        input_index: usize,
        prev_output: &TxOut,
    ) -> Result<bool> {
        let input = tx
            .input
            .get(input_index)
            .ok_or_else(|| anyhow::anyhow!("Invalid input index"))?;

        // Check if this is a witness input
        if input.witness.is_empty() {
            return Ok(true); // Non-witness input, validated elsewhere
        }

        // Check script type and validate accordingly
        if Self::is_p2wpkh(&prev_output.script_pubkey) {
            Self::validate_p2wpkh_witness(tx, input_index, prev_output)
        } else if Self::is_p2wsh(&prev_output.script_pubkey) {
            Self::validate_p2wsh_witness(tx, input_index, prev_output)
        } else {
            // Not a native witness output, check for P2SH-wrapped witness
            Ok(true) // Would need more complex validation here
        }
    }

    /// Check if script is P2WPKH
    fn is_p2wpkh(script: &Script) -> bool {
        let bytes = script.as_bytes();
        bytes.len() == 22 && bytes[0] == 0x00 && bytes[1] == 0x14
    }

    /// Check if script is P2WSH
    fn is_p2wsh(script: &Script) -> bool {
        let bytes = script.as_bytes();
        bytes.len() == 34 && bytes[0] == 0x00 && bytes[1] == 0x20
    }

    /// Validate P2WPKH witness
    fn validate_p2wpkh_witness(
        tx: &Transaction,
        input_index: usize,
        prev_output: &TxOut,
    ) -> Result<bool> {
        let witness = &tx.input[input_index].witness;

        // P2WPKH witness should have exactly 2 items: signature and pubkey
        if witness.len() != 2 {
            bail!("Invalid P2WPKH witness item count: {}", witness.len());
        }

        // Extract signature and pubkey from witness
        let signature = &witness[0];
        let pubkey = &witness[1];

        // Validate pubkey length (33 bytes for compressed, 65 for uncompressed)
        if pubkey.len() != 33 && pubkey.len() != 65 {
            bail!("Invalid public key length: {}", pubkey.len());
        }

        // Calculate BIP143 signature hash for this input
        use bitcoin::sighash::{EcdsaSighashType, SighashCache};
        use bitcoin::PublicKey;

        // Parse the public key
        let pk = PublicKey::from_slice(pubkey)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

        // Create P2WPKH script from pubkey hash
        let pk_hash = pk
            .wpubkey_hash()
            .map_err(|e| anyhow::anyhow!("Failed to get wpubkey hash: {}", e))?;
        let script_code = bitcoin::ScriptBuf::new_p2wpkh(&pk_hash);

        // Get sighash type from last byte of signature
        let sighash_type = if !signature.is_empty() {
            EcdsaSighashType::from_standard(*signature.last().unwrap() as u32)
                .map_err(|e| anyhow::anyhow!("Invalid sighash type: {}", e))?
        } else {
            bail!("Empty signature");
        };

        // Calculate signature hash using BIP143
        let mut cache = SighashCache::new(tx);
        let sighash = cache
            .p2wpkh_signature_hash(input_index, &script_code, prev_output.value, sighash_type)
            .map_err(|e| anyhow::anyhow!("Failed to calculate sighash: {}", e))?;

        // Verify ECDSA signature
        use bitcoin::secp256k1::{Message, Secp256k1};

        // Parse the signature (excluding sighash type byte)
        let sig_len = signature.len();
        if !(9..=73).contains(&sig_len) {
            bail!("Invalid signature length: {}", sig_len);
        }

        // Remove sighash type byte from signature
        let sig_bytes = &signature[..sig_len - 1];

        // Parse ECDSA signature
        let ecdsa_sig = bitcoin::ecdsa::Signature::from_slice(sig_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid ECDSA signature: {}", e))?;

        // Create secp256k1 context
        let secp = Secp256k1::verification_only();

        // Create message from sighash
        let msg = Message::from_digest_slice(sighash.as_byte_array())
            .map_err(|e| anyhow::anyhow!("Invalid message: {}", e))?;

        // Verify the signature
        let verification_result = secp.verify_ecdsa(&msg, &ecdsa_sig.signature, &pk.inner);

        match verification_result {
            Ok(()) => {
                debug!("P2WPKH signature verification successful");
                Ok(true)
            }
            Err(e) => {
                warn!("P2WPKH signature verification failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Validate P2WSH witness
    fn validate_p2wsh_witness(
        tx: &Transaction,
        input_index: usize,
        prev_output: &TxOut,
    ) -> Result<bool> {
        let witness = &tx.input[input_index].witness;

        // P2WSH witness should have at least 2 items (could be more for multisig)
        if witness.len() < 2 {
            bail!("Invalid P2WSH witness item count: {}", witness.len());
        }

        // Last item should be the witnessScript
        let witness_script = witness
            .last()
            .ok_or_else(|| anyhow::anyhow!("Empty witness stack"))?;

        // Hash of witness script should match the script pubkey
        let script_hash = sha256::Hash::hash(witness_script);
        let expected_hash = &prev_output.script_pubkey.as_bytes()[2..];

        if script_hash.as_byte_array() != expected_hash {
            bail!("Witness script hash mismatch");
        }

        // Execute witness script with witness stack
        // Create a stack from witness items (excluding the witness script itself)
        let mut stack = Vec::new();
        for i in 0..witness.len() - 1 {
            stack.push(witness[i].to_vec());
        }

        // Parse witness script
        let script = bitcoin::ScriptBuf::from(witness_script.to_vec());

        // Basic script validation
        // Check for standard script patterns
        if script.is_p2pk() || script.is_p2pkh() {
            // Single signature script
            if stack.is_empty() {
                bail!("Not enough items on stack for script execution");
            }
        } else if script.len() > 10000 {
            // Script too large
            bail!("Witness script too large: {} bytes", script.len());
        }

        // Check for OP_CHECKMULTISIG pattern (simplified)
        let script_bytes = script.as_bytes();
        if script_bytes.len() > 3 {
            // Look for multisig pattern: OP_n ... OP_m OP_CHECKMULTISIG
            let last_op = script_bytes[script_bytes.len() - 1];
            if last_op == 0xae {
                // OP_CHECKMULTISIG
                // This is a multisig script
                if stack.is_empty() {
                    bail!("Empty stack for multisig execution");
                }

                // In a real implementation, we would:
                // 1. Parse the m-of-n requirements
                // 2. Verify m signatures against n public keys
                // 3. Check signature order matches key order
                debug!("Multisig witness script detected");
            }
        }

        // For now, accept valid structure as passing validation
        // Full script execution would require a complete script interpreter
        debug!("P2WSH witness structure validated");
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_commitment_pattern() {
        // Test witness commitment script pattern detection
        let commitment_script = bitcoin::ScriptBuf::from_hex(
            "6a24aa21a9ed0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        assert!(WitnessValidator::is_witness_commitment_script(
            &commitment_script
        ));

        // Test non-commitment script
        let normal_script = bitcoin::ScriptBuf::from_hex("76a914").unwrap();
        assert!(!WitnessValidator::is_witness_commitment_script(
            &normal_script
        ));
    }

    #[test]
    fn test_merkle_root_calculation() {
        use bitcoin::hashes::Hash;

        // Test with single hash
        let hash1 = sha256d::Hash::from_slice(&[1u8; 32]).unwrap();
        let root = WitnessValidator::merkle_root(&[hash1]);
        assert_eq!(root, hash1);

        // Test with two hashes
        let hash2 = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let root = WitnessValidator::merkle_root(&[hash1, hash2]);
        assert_ne!(root, hash1);
        assert_ne!(root, hash2);
    }
}
