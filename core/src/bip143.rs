use anyhow::{bail, Context, Result};
use bitcoin::consensus::encode::Encodable;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use std::io::Write;
use tracing::{debug, trace};

/// BIP143 signature hash implementation for SegWit transactions
/// This is used for witness version 0 scripts (P2WPKH and P2WSH)
pub struct Bip143SighashComputer<'a> {
    tx: &'a Transaction,
    prevouts: &'a [TxOut],
    sighash_cache: Option<SighashCache<&'a Transaction>>,
}

impl<'a> Bip143SighashComputer<'a> {
    /// Create a new BIP143 sighash computer
    pub fn new(tx: &'a Transaction, prevouts: &'a [TxOut]) -> Self {
        Self {
            tx,
            prevouts,
            sighash_cache: None,
        }
    }

    /// Compute BIP143 signature hash for a specific input
    pub fn compute_sighash(
        &mut self,
        input_index: usize,
        script_code: &ScriptBuf,
        value: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<[u8; 32]> {
        debug!(
            "Computing BIP143 sighash for input {} with type {:?}",
            input_index, sighash_type
        );

        // Validate input index
        if input_index >= self.tx.input.len() {
            bail!("Input index {} out of bounds", input_index);
        }

        // Use rust-bitcoin's built-in BIP143 implementation via SighashCache
        if self.sighash_cache.is_none() {
            self.sighash_cache = Some(SighashCache::new(self.tx));
        }

        let cache = self.sighash_cache.as_mut().unwrap();

        // Compute witness sighash using the new API
        // In bitcoin 0.32, we use p2wpkh_signature_hash or p2wsh_signature_hash
        // For general script_code, we use p2wsh_signature_hash
        let sighash = cache
            .p2wsh_signature_hash(input_index, script_code, value, sighash_type)
            .context("Failed to compute P2WSH signature hash")?;

        Ok(sighash.to_byte_array())
    }

    /// Compute signature hash using manual BIP143 algorithm (for understanding/debugging)
    pub fn compute_sighash_manual(
        &self,
        input_index: usize,
        script_code: &ScriptBuf,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<[u8; 32]> {
        trace!("Computing manual BIP143 sighash");

        let mut preimage = Vec::new();

        // 1. nVersion (4 bytes)
        self.tx.version.consensus_encode(&mut preimage)?;

        // 2. hashPrevouts (32 bytes)
        let hash_prevouts = if (sighash_type.to_u32() & 0x80) == 0 {
            self.compute_prevouts_hash()?
        } else {
            [0u8; 32]
        };
        preimage.write_all(&hash_prevouts)?;

        // 3. hashSequence (32 bytes)
        let hash_sequence = if (sighash_type.to_u32() & 0x80) == 0
            && sighash_type != EcdsaSighashType::Single
            && sighash_type != EcdsaSighashType::None
        {
            self.compute_sequence_hash()?
        } else {
            [0u8; 32]
        };
        preimage.write_all(&hash_sequence)?;

        // 4. outpoint (32 bytes + 4 bytes)
        self.tx.input[input_index]
            .previous_output
            .consensus_encode(&mut preimage)?;

        // 5. scriptCode (serialized with length prefix)
        script_code.consensus_encode(&mut preimage)?;

        // 6. value (8 bytes)
        value.consensus_encode(&mut preimage)?;

        // 7. nSequence (4 bytes)
        self.tx.input[input_index]
            .sequence
            .consensus_encode(&mut preimage)?;

        // 8. hashOutputs (32 bytes)
        let hash_outputs = match sighash_type {
            EcdsaSighashType::All => self.compute_outputs_hash()?,
            EcdsaSighashType::Single if input_index < self.tx.output.len() => {
                self.compute_single_output_hash(input_index)?
            }
            _ => [0u8; 32],
        };
        preimage.write_all(&hash_outputs)?;

        // 9. nLockTime (4 bytes)
        self.tx.lock_time.consensus_encode(&mut preimage)?;

        // 10. sighash type (4 bytes)
        (sighash_type.to_u32()).consensus_encode(&mut preimage)?;

        // Double SHA256
        let hash = sha256d::Hash::hash(&preimage);
        Ok(hash.to_byte_array())
    }

    /// Compute hash of all prevouts
    fn compute_prevouts_hash(&self) -> Result<[u8; 32]> {
        let mut data = Vec::new();
        for input in &self.tx.input {
            input.previous_output.consensus_encode(&mut data)?;
        }
        Ok(sha256d::Hash::hash(&data).to_byte_array())
    }

    /// Compute hash of all sequences
    fn compute_sequence_hash(&self) -> Result<[u8; 32]> {
        let mut data = Vec::new();
        for input in &self.tx.input {
            input.sequence.consensus_encode(&mut data)?;
        }
        Ok(sha256d::Hash::hash(&data).to_byte_array())
    }

    /// Compute hash of all outputs
    fn compute_outputs_hash(&self) -> Result<[u8; 32]> {
        let mut data = Vec::new();
        for output in &self.tx.output {
            output.consensus_encode(&mut data)?;
        }
        Ok(sha256d::Hash::hash(&data).to_byte_array())
    }

    /// Compute hash of single output
    fn compute_single_output_hash(&self, index: usize) -> Result<[u8; 32]> {
        let mut data = Vec::new();
        self.tx.output[index].consensus_encode(&mut data)?;
        Ok(sha256d::Hash::hash(&data).to_byte_array())
    }
}

/// Verify a BIP143 witness signature
pub fn verify_witness_signature(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &ScriptBuf,
    value: Amount,
    witness: &bitcoin::Witness,
) -> Result<bool> {
    debug!("Verifying witness signature for input {}", input_index);

    // Check witness structure
    if witness.is_empty() {
        bail!("Empty witness");
    }

    // Determine witness program type
    if script_pubkey.is_p2wpkh() {
        verify_p2wpkh_witness(tx, input_index, script_pubkey, value, witness)
    } else if script_pubkey.is_p2wsh() {
        verify_p2wsh_witness(tx, input_index, script_pubkey, value, witness)
    } else {
        bail!("Not a witness script")
    }
}

/// Verify P2WPKH witness
fn verify_p2wpkh_witness(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &ScriptBuf,
    value: Amount,
    witness: &bitcoin::Witness,
) -> Result<bool> {
    // P2WPKH witness must have exactly 2 elements: signature and pubkey
    if witness.len() != 2 {
        bail!("P2WPKH witness must have exactly 2 elements");
    }

    let signature = witness.nth(0).context("Missing signature")?;
    let pubkey = witness.nth(1).context("Missing pubkey")?;

    // Extract pubkey hash from script
    let script_bytes = script_pubkey.as_bytes();
    if script_bytes.len() != 22 || script_bytes[0] != 0x00 || script_bytes[1] != 0x14 {
        bail!("Invalid P2WPKH script");
    }

    let pubkey_hash = &script_bytes[2..22];

    // Verify pubkey hash matches
    let computed_hash = bitcoin::hashes::hash160::Hash::hash(pubkey);
    if computed_hash.as_byte_array() != pubkey_hash {
        return Ok(false);
    }

    // Create script code for P2WPKH (OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG)
    let script_code = ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_slice(pubkey_hash)?);

    // Verify signature
    verify_ecdsa_signature(tx, input_index, &script_code, value, signature, pubkey)
}

/// Verify P2WSH witness
fn verify_p2wsh_witness(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &ScriptBuf,
    value: Amount,
    witness: &bitcoin::Witness,
) -> Result<bool> {
    // P2WSH witness must have at least 1 element (the witness script)
    if witness.is_empty() {
        bail!("P2WSH witness is empty");
    }

    // Last element is the witness script
    let witness_script_bytes = witness.last().context("Missing witness script")?;
    let witness_script = ScriptBuf::from(witness_script_bytes.to_vec());

    // Extract script hash from script_pubkey
    let script_bytes = script_pubkey.as_bytes();
    if script_bytes.len() != 34 || script_bytes[0] != 0x00 || script_bytes[1] != 0x20 {
        bail!("Invalid P2WSH script");
    }

    let script_hash = &script_bytes[2..34];

    // Verify script hash matches
    let computed_hash = bitcoin::hashes::sha256::Hash::hash(witness_script.as_bytes());
    if computed_hash.as_byte_array() != script_hash {
        return Ok(false);
    }

    // Create signature hash for witness script execution
    let mut cache = bitcoin::sighash::SighashCache::new(tx);
    let sighash = cache.p2wsh_signature_hash(
        input_index,
        &witness_script,
        value,
        bitcoin::sighash::EcdsaSighashType::All,
    )?;

    // Validate that we're using the correct input
    if input_index >= tx.input.len() {
        bail!(
            "Invalid input index {} for transaction with {} inputs",
            input_index,
            tx.input.len()
        );
    }

    trace!(
        "P2WSH validation for tx input {} with value {} sats, sighash: {}",
        input_index,
        value.to_sat(),
        sighash
    );

    // Prepare witness stack (all items except the last one which is the script)
    let mut witness_stack = Vec::with_capacity(witness.len().saturating_sub(1));
    for i in 0..witness.len() - 1 {
        witness_stack.push(witness[i].to_vec());
    }

    // Execute the witness script with the witness stack
    let mut interpreter = crate::script_interpreter::ScriptInterpreter::new(
        crate::script_interpreter::ScriptFlags::default(),
    );

    let result = interpreter.execute_witness_script(
        &witness_stack,
        &witness_script.as_script(),
        tx,
        input_index,
        value,
        sighash.as_byte_array(),
    )?;

    if !result {
        trace!("P2WSH witness script execution failed");
        return Ok(false);
    }

    trace!("P2WSH witness script execution succeeded");
    Ok(true)
}

/// Verify ECDSA signature using BIP143
fn verify_ecdsa_signature(
    tx: &Transaction,
    input_index: usize,
    script_code: &ScriptBuf,
    value: Amount,
    signature_bytes: &[u8],
    pubkey_bytes: &[u8],
) -> Result<bool> {
    use secp256k1::{Message, PublicKey, Secp256k1};

    // Parse signature and sighash type
    if signature_bytes.is_empty() {
        return Ok(false);
    }

    let sighash_type =
        EcdsaSighashType::from_standard(signature_bytes[signature_bytes.len() - 1] as u32)
            .unwrap_or(EcdsaSighashType::All);

    let sig_bytes = &signature_bytes[..signature_bytes.len() - 1];

    // Parse signature
    let signature = match secp256k1::ecdsa::Signature::from_der(sig_bytes) {
        Ok(sig) => sig,
        Err(_) => return Ok(false),
    };

    // Parse public key
    let pubkey = match PublicKey::from_slice(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return Ok(false),
    };

    // Compute sighash using BIP143
    let mut cache = SighashCache::new(tx);
    // Use the appropriate method based on script type
    let sighash = cache
        .p2wsh_signature_hash(input_index, script_code, value, sighash_type)
        .context("Failed to compute P2WSH signature hash")?;

    // Create message from sighash
    let message = Message::from_digest_slice(sighash.as_byte_array())
        .map_err(|e| anyhow::anyhow!("Invalid message: {}", e))?;

    // Verify signature
    let secp = Secp256k1::new();
    Ok(secp.verify_ecdsa(&message, &signature, &pubkey).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, ScriptBuf, TxOut, WPubkeyHash};

    #[test]
    fn test_bip143_sighash_computation() {
        // Create a test transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()),
            }],
        };

        let prevouts = vec![TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()),
        }];

        let mut computer = Bip143SighashComputer::new(&tx, &prevouts);
        let script_code = ScriptBuf::new();
        let value = Amount::from_sat(100000);

        // Should compute without error
        let result = computer.compute_sighash(0, &script_code, value, EcdsaSighashType::All);
        assert!(result.is_ok());
    }

    #[test]
    fn test_witness_detection() {
        // P2WPKH script
        let p2wpkh = ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros());
        assert!(p2wpkh.is_p2wpkh());
        assert!(!p2wpkh.is_p2wsh());

        // P2WSH script
        let p2wsh = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::all_zeros());
        assert!(!p2wsh.is_p2wpkh());
        assert!(p2wsh.is_p2wsh());
    }

    #[test]
    fn test_p2wsh_witness_verification() -> Result<()> {
        use bitcoin::blockdata::opcodes::all::OP_EQUAL;
        use bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1;
        use bitcoin::hashes::Hash;
        use bitcoin::TxIn;

        // Create a test transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // Test 1: Simple OP_TRUE script (OP_TRUE = 0x51 = OP_PUSHNUM_1)
        {
            let witness_script = ScriptBuf::from_bytes(vec![0x51]); // OP_TRUE/OP_1
            let script_hash = bitcoin::hashes::sha256::Hash::hash(witness_script.as_bytes());

            let script_pubkey = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array(
                script_hash.to_byte_array(),
            ));

            // Witness only contains the script (no other stack items needed for OP_TRUE)
            let witness = bitcoin::Witness::from_slice(&[witness_script.as_bytes()]);

            let result =
                verify_p2wsh_witness(&tx, 0, &script_pubkey, Amount::from_sat(1000), &witness)?;

            assert!(result, "P2WSH with OP_TRUE script should succeed");
        }

        // Test 2: Script requiring a value on stack (OP_1 OP_EQUAL)
        {
            let witness_script =
                ScriptBuf::from_bytes(vec![OP_PUSHNUM_1.to_u8(), OP_EQUAL.to_u8()]);
            let script_hash = bitcoin::hashes::sha256::Hash::hash(witness_script.as_bytes());

            let script_pubkey = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array(
                script_hash.to_byte_array(),
            ));

            // Witness contains: value "1", then the script
            let witness_data = vec![
                vec![1u8], // Push value 1 onto stack
                witness_script.as_bytes().to_vec(),
            ];
            let witness = bitcoin::Witness::from_slice(&witness_data);

            let result =
                verify_p2wsh_witness(&tx, 0, &script_pubkey, Amount::from_sat(1000), &witness)?;

            assert!(
                result,
                "P2WSH with OP_1 OP_EQUAL should succeed with correct value"
            );
        }

        // Test 3: Invalid script hash
        {
            let witness_script = ScriptBuf::from_bytes(vec![0x51]); // OP_TRUE
            let wrong_script = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::all_zeros());
            let witness = bitcoin::Witness::from_slice(&[witness_script.as_bytes()]);

            let result =
                verify_p2wsh_witness(&tx, 0, &wrong_script, Amount::from_sat(1000), &witness)?;

            assert!(!result, "P2WSH should fail with wrong script hash");
        }

        // Test 4: Empty witness should fail
        {
            let script_pubkey = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::all_zeros());
            let witness = bitcoin::Witness::new();

            let result =
                verify_p2wsh_witness(&tx, 0, &script_pubkey, Amount::from_sat(1000), &witness);

            assert!(result.is_err(), "P2WSH should fail with empty witness");
        }

        Ok(())
    }
}
