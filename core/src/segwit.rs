use anyhow::{bail, Context, Result};
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache};
use bitcoin::witness::Witness;
use bitcoin::{Amount, Block, Network, ScriptBuf, Transaction, TxOut};
use tracing::debug;

/// BIP141 SegWit constants
pub const WITNESS_V0_KEYHASH_SIZE: usize = 20;
pub const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;
pub const WITNESS_V1_TAPROOT_SIZE: usize = 32;
pub const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
pub const WITNESS_SCALE_FACTOR: u64 = 4;

/// SegWit activation parameters
pub struct SegWitParams {
    pub activation_height: u32,
    pub activation_time: u32,
    pub version_bits_start_time: u32,
    pub version_bits_timeout: u32,
}

impl SegWitParams {
    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Bitcoin => Self {
                activation_height: 481_824,  // SegWit activated at this height on mainnet
                activation_time: 1503539857, // August 24, 2017
                version_bits_start_time: 1479168000,
                version_bits_timeout: 1510704000,
            },
            Network::Testnet => Self {
                activation_height: 834_624,
                activation_time: 1493596800,
                version_bits_start_time: 1462060800,
                version_bits_timeout: 1493596800,
            },
            _ => Self {
                activation_height: 0, // Always active on regtest/signet
                activation_time: 0,
                version_bits_start_time: 0,
                version_bits_timeout: 0,
            },
        }
    }

    pub fn is_active(&self, height: u32) -> bool {
        height >= self.activation_height
    }
}

/// BIP141 SegWit validator
pub struct SegWitValidator {
    params: SegWitParams,
    network: Network,
}

impl SegWitValidator {
    pub fn new(network: Network) -> Self {
        Self {
            params: SegWitParams::for_network(network),
            network,
        }
    }

    /// Validate a SegWit transaction
    pub fn validate_transaction(
        &self,
        tx: &Transaction,
        prevouts: &[TxOut],
        flags: ValidationFlags,
    ) -> Result<()> {
        // Check if this is a SegWit transaction
        if !self.is_witness_transaction(tx) {
            return Ok(()); // Non-witness transaction, skip SegWit validation
        }

        // BIP141: Check transaction weight
        let weight = tx.weight().to_wu();
        if weight > MAX_STANDARD_TX_WEIGHT {
            bail!(
                "Transaction weight {} exceeds maximum {}",
                weight,
                MAX_STANDARD_TX_WEIGHT
            );
        }

        // Validate each input's witness
        for (index, input) in tx.input.iter().enumerate() {
            if index >= prevouts.len() {
                bail!("Missing prevout for input {}", index);
            }

            let prevout = &prevouts[index];

            // Check if this input requires witness validation
            if self.is_witness_program(&prevout.script_pubkey) {
                self.validate_witness_program(
                    tx,
                    index,
                    &input.witness,
                    &prevout.script_pubkey,
                    prevout.value,
                    prevouts,
                    flags,
                )?;
            }
        }

        Ok(())
    }

    /// Check if transaction has witness data
    pub fn is_witness_transaction(&self, tx: &Transaction) -> bool {
        tx.input.iter().any(|input| !input.witness.is_empty())
    }

    /// Check if script is a witness program
    pub fn is_witness_program(&self, script: &ScriptBuf) -> bool {
        let bytes = script.as_bytes();

        // Witness program is OP_0..OP_16 followed by 2-40 bytes of push data
        if bytes.len() < 4 || bytes.len() > 42 {
            return false;
        }

        // First byte must be OP_0 or OP_1..OP_16
        let version = bytes[0];
        if version != OP_PUSHBYTES_0.to_u8()
            && (version < OP_PUSHNUM_1.to_u8() || version > OP_PUSHNUM_16.to_u8())
        {
            return false;
        }

        // Second byte is push length
        let push_len = bytes[1] as usize;

        // Total length must match
        bytes.len() == push_len + 2
    }

    /// Extract witness version and program
    pub fn extract_witness_program(&self, script: &ScriptBuf) -> Option<(u8, Vec<u8>)> {
        if !self.is_witness_program(script) {
            return None;
        }

        let bytes = script.as_bytes();
        let version = if bytes[0] == OP_PUSHBYTES_0.to_u8() {
            0
        } else {
            bytes[0] - OP_PUSHNUM_1.to_u8() + 1
        };

        let program = bytes[2..].to_vec();
        Some((version, program))
    }

    /// Validate witness program
    fn validate_witness_program(
        &self,
        tx: &Transaction,
        input_index: usize,
        witness: &Witness,
        script_pubkey: &ScriptBuf,
        amount: Amount,
        prevouts: &[TxOut],
        flags: ValidationFlags,
    ) -> Result<()> {
        let (version, program) = self
            .extract_witness_program(script_pubkey)
            .context("Failed to extract witness program")?;

        match version {
            0 => self.validate_witness_v0(
                tx,
                input_index,
                witness,
                &program,
                amount,
                prevouts,
                flags,
            ),
            1 if flags.taproot => self.validate_witness_v1_taproot(
                tx,
                input_index,
                witness,
                &program,
                amount,
                prevouts,
            ),
            _ => {
                // Future witness versions - anyone can spend for now
                if flags.discourage_upgradable_witness && witness.is_empty() {
                    bail!("Non-standard witness version {}", version);
                }
                Ok(())
            }
        }
    }

    /// Validate version 0 witness program (P2WPKH or P2WSH)
    fn validate_witness_v0(
        &self,
        tx: &Transaction,
        input_index: usize,
        witness: &Witness,
        program: &[u8],
        amount: Amount,
        prevouts: &[TxOut],
        flags: ValidationFlags,
    ) -> Result<()> {
        match program.len() {
            WITNESS_V0_KEYHASH_SIZE => {
                // P2WPKH
                self.validate_p2wpkh(tx, input_index, witness, program, amount, prevouts)
            }
            WITNESS_V0_SCRIPTHASH_SIZE => {
                // P2WSH
                self.validate_p2wsh(tx, input_index, witness, program, amount, prevouts, flags)
            }
            _ => bail!("Invalid witness v0 program length: {}", program.len()),
        }
    }

    /// Validate P2WPKH (Pay to Witness Public Key Hash)
    fn validate_p2wpkh(
        &self,
        tx: &Transaction,
        input_index: usize,
        witness: &Witness,
        keyhash: &[u8],
        amount: Amount,
        prevouts: &[TxOut],
    ) -> Result<()> {
        // P2WPKH witness stack must have exactly 2 items: signature and pubkey
        if witness.len() != 2 {
            bail!(
                "P2WPKH witness must have exactly 2 items, got {}",
                witness.len()
            );
        }

        let signature = witness
            .nth(0)
            .context("Missing signature in P2WPKH witness")?;
        let pubkey = witness.nth(1).context("Missing pubkey in P2WPKH witness")?;

        // Verify pubkey matches the keyhash
        let pubkey_hash = bitcoin::hashes::hash160::Hash::hash(pubkey);
        if pubkey_hash.as_byte_array() != keyhash {
            bail!("P2WPKH pubkey doesn't match keyhash");
        }

        // Verify signature
        let mut sighash_cache = SighashCache::new(tx.clone());
        let prevouts = Prevouts::All(prevouts);

        let sighash_type = if !signature.is_empty() {
            EcdsaSighashType::from_consensus(signature[signature.len() - 1] as u32)
        } else {
            EcdsaSighashType::All
        };

        let sighash = sighash_cache.p2wpkh_signature_hash(
            input_index,
            &create_p2pkh_script(keyhash),
            amount,
            sighash_type,
        )?;

        // Verify ECDSA signature
        self.verify_ecdsa_signature(signature, pubkey, sighash.as_byte_array())?;

        Ok(())
    }

    /// Validate P2WSH (Pay to Witness Script Hash)
    fn validate_p2wsh(
        &self,
        tx: &Transaction,
        input_index: usize,
        witness: &Witness,
        scripthash: &[u8],
        amount: Amount,
        prevouts: &[TxOut],
        flags: ValidationFlags,
    ) -> Result<()> {
        // P2WSH witness stack must have at least 1 item (the witness script)
        if witness.is_empty() {
            bail!("P2WSH witness stack is empty");
        }

        // Last item is the witness script
        let witness_script = witness.last().context("Missing witness script in P2WSH")?;

        // Verify script matches the hash
        let script_hash = sha256::Hash::hash(witness_script);
        if script_hash.as_byte_array() != scripthash {
            bail!("P2WSH witness script doesn't match scripthash");
        }

        // Execute the witness script with the remaining stack items
        let witness_stack: Vec<Vec<u8>> = witness
            .iter()
            .take(witness.len() - 1)
            .map(|item| item.to_vec())
            .collect();

        // Create script from witness script bytes
        let script = ScriptBuf::from(witness_script.to_vec());

        // Verify the script execution
        self.verify_witness_script(
            tx,
            input_index,
            &witness_stack,
            &script,
            amount,
            prevouts,
            flags,
        )?;

        Ok(())
    }

    /// Validate witness v1 (Taproot)
    fn validate_witness_v1_taproot(
        &self,
        tx: &Transaction,
        input_index: usize,
        witness: &Witness,
        program: &[u8],
        amount: Amount,
        prevouts: &[TxOut],
    ) -> Result<()> {
        if program.len() != WITNESS_V1_TAPROOT_SIZE {
            bail!("Invalid Taproot program length: {}", program.len());
        }

        if witness.is_empty() {
            bail!("Empty witness for Taproot input");
        }

        // Use the TaprootValidator for proper BIP341/342 validation
        use crate::taproot::{TaprootValidationFlags, TaprootValidator};

        let flags = TaprootValidationFlags::default();
        let mut validator = TaprootValidator::new(flags);

        // Get the previous output for this input
        let prevout = if input_index < prevouts.len() {
            &prevouts[input_index]
        } else {
            bail!("Invalid input index {} for prevouts", input_index);
        };

        // Validate the Taproot spend
        validator
            .validate_taproot_spend(tx, input_index, prevout, witness)
            .context("Taproot validation failed")?;

        debug!("Taproot validation successful for input {}", input_index);

        Ok(())
    }

    /// Verify witness script execution
    fn verify_witness_script(
        &self,
        tx: &Transaction,
        input_index: usize,
        stack: &[Vec<u8>],
        script: &ScriptBuf,
        amount: Amount,
        prevouts: &[TxOut],
        _flags: ValidationFlags,
    ) -> Result<()> {
        // This would integrate with the script interpreter
        // For now, we'll do basic validation

        if script.is_p2pkh() || script.is_p2pk() {
            // These shouldn't be in witness scripts
            bail!("Legacy script types not allowed in witness scripts");
        }

        // Full witness script execution implementation
        use crate::script::ScriptFlags;
        use crate::script::{ScriptInterpreter, TransactionSignatureChecker};

        let checker =
            TransactionSignatureChecker::new(tx, input_index, amount.to_sat(), prevouts.to_vec());

        // Create script interpreter with witness flags
        let mut script_flags = ScriptFlags::WITNESS;

        // Add standard validation flags
        script_flags |= ScriptFlags::CHECKLOCKTIMEVERIFY;
        script_flags |= ScriptFlags::CHECKSEQUENCEVERIFY;
        script_flags |= ScriptFlags::NULLDUMMY;

        if _flags.discourage_upgradable_witness {
            script_flags |= ScriptFlags::DISCOURAGE_UPGRADEABLE_WITNESS_PROGRAM;
        }

        let mut interpreter = ScriptInterpreter::new(script_flags);

        // Push initial stack items from witness
        for item in stack {
            interpreter.push_stack(item.clone())?;
        }

        // Execute the witness script
        interpreter.execute(script, &checker)?;

        // Check final stack - must have exactly one true value
        if interpreter.stack_size() != 1 {
            bail!("Witness script must leave exactly one item on stack");
        }

        let top = interpreter.pop_stack()?;
        if !Self::cast_to_bool(&top) {
            bail!("Witness script evaluated to false");
        }

        debug!("Witness script execution completed successfully");

        Ok(())
    }

    /// Cast a stack item to bool (following Bitcoin's rules)
    fn cast_to_bool(item: &[u8]) -> bool {
        // Empty array is false
        if item.is_empty() {
            return false;
        }

        // Array of all zeros (any length) is false
        for &byte in item {
            if byte != 0 {
                // Check for negative zero (0x80)
                if item.len() == 1 && byte == 0x80 {
                    return false;
                }
                return true;
            }
        }

        false
    }

    /// Verify ECDSA signature
    fn verify_ecdsa_signature(
        &self,
        signature: &[u8],
        pubkey: &[u8],
        sighash: &[u8],
    ) -> Result<()> {
        use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

        let secp = Secp256k1::verification_only();

        // Parse signature (remove sighash type byte)
        let sig_bytes = &signature[..signature.len() - 1];
        let sig = Signature::from_der(sig_bytes).context("Invalid DER signature")?;

        // Parse public key
        let pk = PublicKey::from_slice(pubkey).context("Invalid public key")?;

        // Create message from sighash
        let msg = Message::from_digest_slice(sighash).context("Invalid message hash")?;

        // Verify
        secp.verify_ecdsa(&msg, &sig, &pk)
            .context("ECDSA signature verification failed")?;

        Ok(())
    }

    /// Validate witness commitment in block
    pub fn validate_witness_commitment(&self, block: &Block) -> Result<()> {
        // Skip if no witness transactions
        if !block
            .txdata
            .iter()
            .any(|tx| self.is_witness_transaction(tx))
        {
            return Ok(());
        }

        // Find witness commitment in coinbase
        let coinbase = &block.txdata[0];
        let commitment = self.find_witness_commitment(coinbase)?;

        // Calculate witness merkle root
        let witness_root = self.calculate_witness_merkle_root(block)?;

        // Get witness nonce from coinbase
        let witness_nonce = if !coinbase.input[0].witness.is_empty() {
            coinbase.input[0].witness[0].to_vec()
        } else {
            vec![0; 32]
        };

        // Calculate expected commitment
        let mut data = Vec::new();
        data.extend_from_slice(&witness_root);
        data.extend_from_slice(&witness_nonce);
        let expected = bitcoin::hashes::sha256d::Hash::hash(&data);

        // Compare commitments
        if expected.as_byte_array() != &commitment {
            bail!("Witness commitment mismatch");
        }

        Ok(())
    }

    /// Find witness commitment in coinbase outputs
    fn find_witness_commitment(&self, coinbase: &Transaction) -> Result<[u8; 32]> {
        const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

        for output in coinbase.output.iter().rev() {
            let script = output.script_pubkey.as_bytes();
            if script.len() >= 38 && script[0..6] == WITNESS_COMMITMENT_PREFIX {
                let mut commitment = [0u8; 32];
                commitment.copy_from_slice(&script[6..38]);
                return Ok(commitment);
            }
        }

        bail!("No witness commitment found in coinbase");
    }

    /// Calculate witness merkle root
    fn calculate_witness_merkle_root(&self, block: &Block) -> Result<[u8; 32]> {
        use bitcoin::merkle_tree;

        let mut hashes = Vec::new();

        // First is always zero (coinbase wtxid)
        hashes.push(bitcoin::hashes::sha256d::Hash::all_zeros());

        // Add wtxids for all other transactions
        for tx in &block.txdata[1..] {
            let wtxid = tx.compute_wtxid();
            hashes.push(bitcoin::hashes::sha256d::Hash::from_byte_array(
                *wtxid.as_byte_array(),
            ));
        }

        let root = merkle_tree::calculate_root(hashes.into_iter())
            .context("Failed to calculate witness merkle root")?;

        Ok(root.to_byte_array())
    }
}

/// Create P2PKH script from keyhash
fn create_p2pkh_script(keyhash: &[u8]) -> ScriptBuf {
    use bitcoin::script::PushBytesBuf;
    let push_bytes = PushBytesBuf::try_from(keyhash.to_vec()).unwrap();
    bitcoin::blockdata::script::Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(push_bytes)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Validation flags
#[derive(Debug, Clone, Copy)]
pub struct ValidationFlags {
    pub taproot: bool,
    pub discourage_upgradable_witness: bool,
}

impl Default for ValidationFlags {
    fn default() -> Self {
        Self {
            taproot: false,
            discourage_upgradable_witness: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segwit_params() -> Result<()> {
        let params = SegWitParams::for_network(Network::Bitcoin);
        assert_eq!(params.activation_height, 481_824);
        assert!(params.is_active(500_000));
        assert!(!params.is_active(400_000));
        Ok(())
    }

    #[test]
    fn test_witness_program_detection() -> Result<()> {
        let validator = SegWitValidator::new(Network::Bitcoin);

        // P2WPKH
        let mut p2wpkh_bytes = vec![0x00, 0x14];
        p2wpkh_bytes.extend_from_slice(&[0; 20]);
        let p2wpkh = ScriptBuf::from_bytes(p2wpkh_bytes);
        assert!(validator.is_witness_program(&p2wpkh));

        // P2WSH
        let mut p2wsh_bytes = vec![0x00, 0x20];
        p2wsh_bytes.extend_from_slice(&[0; 32]);
        let p2wsh = ScriptBuf::from_bytes(p2wsh_bytes);
        assert!(validator.is_witness_program(&p2wsh));

        // Not a witness program
        let p2pkh = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]);
        assert!(!validator.is_witness_program(&p2pkh));

        Ok(())
    }
}
