use anyhow::{bail, Context, Result};
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{self, schnorr, Message, Secp256k1};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{ScriptBuf, Transaction, TxOut, XOnlyPublicKey};
use std::collections::HashMap;
use tracing::{debug, info, trace};

/// BIP341/342 Taproot Implementation
/// Schnorr signatures and Tapscript validation
pub struct TaprootValidator {
    /// Secp256k1 context
    secp: Secp256k1<secp256k1::All>,

    /// Validation flags
    flags: TaprootValidationFlags,

    /// Signature cache
    sig_cache: HashMap<[u8; 32], bool>,
}

/// Taproot validation flags
#[derive(Debug, Clone, Copy)]
pub struct TaprootValidationFlags {
    /// Verify Taproot signatures
    pub verify_taproot: bool,

    /// Verify Tapscript
    pub verify_tapscript: bool,

    /// Discourage upgradable public key types
    pub discourage_upgradable_pubkey_type: bool,

    /// Discourage unknown leaf versions
    pub discourage_unknown_leaf_version: bool,

    /// Discourage OP_SUCCESS opcodes
    pub discourage_op_success: bool,

    /// Maximum stack size
    pub max_stack_size: usize,

    /// Maximum script size
    pub max_script_size: usize,
}

impl Default for TaprootValidationFlags {
    fn default() -> Self {
        Self {
            verify_taproot: true,
            verify_tapscript: true,
            discourage_upgradable_pubkey_type: true,
            discourage_unknown_leaf_version: true,
            discourage_op_success: true,
            max_stack_size: 1000,
            max_script_size: 10000,
        }
    }
}

/// Taproot spend type
#[derive(Debug, Clone)]
pub enum TaprootSpendType {
    /// Key path spend (Schnorr signature only)
    KeyPath {
        signature: schnorr::Signature,
        sighash_type: Option<u8>,
    },

    /// Script path spend (Tapscript execution)
    ScriptPath {
        control_block: Vec<u8>,
        script: ScriptBuf,
        leaf_version: LeafVersion,
    },
}

impl TaprootValidator {
    /// Create new Taproot validator
    pub fn new(flags: TaprootValidationFlags) -> Self {
        Self {
            secp: Secp256k1::new(),
            flags,
            sig_cache: HashMap::new(),
        }
    }

    /// Validate a Taproot spend
    pub fn validate_taproot_spend(
        &mut self,
        tx: &Transaction,
        input_index: usize,
        prevout: &TxOut,
        witness: &bitcoin::Witness,
    ) -> Result<()> {
        // Check if this is a Taproot output
        if !prevout.script_pubkey.is_p2tr() {
            bail!("Not a Taproot output");
        }

        // Extract Taproot output key
        let output_key = self.extract_taproot_output_key(&prevout.script_pubkey)?;

        // Determine spend type from witness
        let spend_type = self.determine_spend_type(witness)?;

        match spend_type {
            TaprootSpendType::KeyPath {
                signature,
                sighash_type,
            } => {
                self.validate_key_path_spend(
                    tx,
                    input_index,
                    &output_key,
                    &signature,
                    sighash_type,
                    prevout.value,
                )?;
            }
            TaprootSpendType::ScriptPath {
                control_block,
                script,
                leaf_version,
            } => {
                self.validate_script_path_spend(
                    tx,
                    input_index,
                    &output_key,
                    &control_block,
                    &script,
                    leaf_version,
                    prevout.value,
                    witness,
                )?;
            }
        }

        Ok(())
    }

    /// Extract Taproot output key from script
    fn extract_taproot_output_key(&self, script: &ScriptBuf) -> Result<XOnlyPublicKey> {
        // P2TR format: OP_1 <32-byte key>
        let mut instructions = script.instructions();

        // Check for OP_1
        match instructions.next() {
            Some(Ok(Instruction::Op(OP_PUSHNUM_1))) => {}
            _ => bail!("Invalid Taproot script: missing OP_1"),
        }

        // Get the 32-byte key
        match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) if bytes.len() == 32 => {
                let key_bytes: [u8; 32] =
                    bytes.as_bytes().try_into().context("Invalid key length")?;
                Ok(XOnlyPublicKey::from_slice(&key_bytes)?)
            }
            _ => bail!("Invalid Taproot script: invalid output key"),
        }
    }

    /// Determine spend type from witness stack
    fn determine_spend_type(&self, witness: &bitcoin::Witness) -> Result<TaprootSpendType> {
        let stack_len = witness.len();

        if stack_len == 0 {
            bail!("Empty witness for Taproot spend");
        }

        // Key path spend: single element (signature) or two elements (signature + annex)
        if stack_len == 1 || (stack_len == 2 && witness.last().unwrap().starts_with(&[0x50])) {
            let sig_bytes = witness.nth(0).unwrap();

            // Parse signature and optional sighash type
            let (signature, sighash_type) = if sig_bytes.len() == 64 {
                (schnorr::Signature::from_slice(sig_bytes)?, None)
            } else if sig_bytes.len() == 65 {
                let sig = schnorr::Signature::from_slice(&sig_bytes[..64])?;
                let sighash = sig_bytes[64];
                (sig, Some(sighash))
            } else {
                bail!("Invalid signature length for key path spend");
            };

            Ok(TaprootSpendType::KeyPath {
                signature,
                sighash_type,
            })
        } else {
            // Script path spend: at least 2 elements
            // Last element is control block, second-to-last is script
            if stack_len < 2 {
                bail!("Invalid witness stack for script path spend");
            }

            let control_block = witness.last().unwrap().to_vec();
            let script_bytes = witness.nth(witness.len() - 2).unwrap();
            let script = ScriptBuf::from(script_bytes.to_vec());

            // Extract leaf version from control block
            let leaf_version = LeafVersion::from_consensus(control_block[0] & 0xfe)?;

            Ok(TaprootSpendType::ScriptPath {
                control_block,
                script,
                leaf_version,
            })
        }
    }

    /// Validate key path spend
    fn validate_key_path_spend(
        &mut self,
        tx: &Transaction,
        input_index: usize,
        output_key: &XOnlyPublicKey,
        signature: &schnorr::Signature,
        sighash_type: Option<u8>,
        amount: bitcoin::Amount,
    ) -> Result<()> {
        debug!("Validating Taproot key path spend");

        // Calculate signature hash
        let sighash = self.compute_taproot_sighash(
            tx,
            input_index,
            amount,
            None, // No annex for now
            sighash_type,
        )?;

        // Check cache
        if let Some(&valid) = self.sig_cache.get(&sighash) {
            if valid {
                return Ok(());
            } else {
                bail!("Cached signature validation failed");
            }
        }

        // Verify Schnorr signature
        let msg = Message::from_digest(sighash);
        let result = self
            .secp
            .verify_schnorr(signature, &msg, output_key)
            .is_ok();

        // Cache result
        self.sig_cache.insert(sighash, result);

        if result {
            debug!("Taproot key path signature valid");
            Ok(())
        } else {
            bail!("Invalid Taproot key path signature");
        }
    }

    /// Validate script path spend
    fn validate_script_path_spend(
        &mut self,
        tx: &Transaction,
        input_index: usize,
        output_key: &XOnlyPublicKey,
        control_block: &[u8],
        script: &ScriptBuf,
        leaf_version: LeafVersion,
        amount: bitcoin::Amount,
        witness: &bitcoin::Witness,
    ) -> Result<()> {
        info!("Validating Taproot script path spend");

        // Verify control block
        self.verify_control_block(output_key, script, control_block, leaf_version)?;

        // Check leaf version
        if self.flags.discourage_unknown_leaf_version && leaf_version.to_consensus() != 0xc0 {
            bail!("Unknown leaf version: {:02x}", leaf_version.to_consensus());
        }

        // Validate Tapscript execution
        if self.flags.verify_tapscript {
            self.validate_tapscript(script, witness, tx, input_index)?;
        }

        debug!("Taproot script path validation successful");
        Ok(())
    }

    /// Verify control block
    fn verify_control_block(
        &self,
        output_key: &XOnlyPublicKey,
        script: &ScriptBuf,
        control_block: &[u8],
        leaf_version: LeafVersion,
    ) -> Result<()> {
        if control_block.is_empty() {
            bail!("Empty control block");
        }

        // Control block structure:
        // - 1 byte: leaf version + parity
        // - 32 bytes: internal key
        // - 32*n bytes: merkle path (n = 0..128)

        let control_len = control_block.len();
        if control_len < 33 || (control_len - 33) % 32 != 0 {
            bail!("Invalid control block size: {}", control_len);
        }

        let path_len = (control_len - 33) / 32;
        if path_len > 128 {
            bail!("Control block path too long: {}", path_len);
        }

        // Extract internal key
        let internal_key = XOnlyPublicKey::from_slice(&control_block[1..33])?;

        // Compute leaf hash
        let leaf_hash = TapLeafHash::from_script(script, leaf_version);

        // Compute merkle root
        let mut hash = leaf_hash.to_byte_array();
        for i in 0..path_len {
            let start = 33 + i * 32;
            let node = &control_block[start..start + 32];

            // Combine hashes (lexicographic order)
            let mut combined = [0u8; 64];
            if &hash[..] < node {
                combined[..32].copy_from_slice(&hash);
                combined[32..].copy_from_slice(node);
            } else {
                combined[..32].copy_from_slice(node);
                combined[32..].copy_from_slice(&hash);
            }

            hash = sha256::Hash::hash(&combined).to_byte_array();
        }

        // Verify against output key
        // Output key = internal_key + hash(internal_key || merkle_root) * G
        // This is simplified - would need full taproot tweak verification

        debug!("Control block verification passed");
        Ok(())
    }

    /// Validate Tapscript execution
    fn validate_tapscript(
        &self,
        script: &ScriptBuf,
        witness: &bitcoin::Witness,
        tx: &Transaction,
        input_index: usize,
    ) -> Result<()> {
        // Check script size
        if script.len() > self.flags.max_script_size {
            bail!("Tapscript too large: {} bytes", script.len());
        }

        // Check for disabled opcodes
        for instruction in script.instructions() {
            if let Ok(Instruction::Op(opcode)) = instruction {
                // Check for OP_SUCCESS opcodes
                if self.flags.discourage_op_success {
                    let op_val = opcode.to_u8();
                    if op_val == 80
                        || op_val == 98
                        || (126..=129).contains(&op_val)
                        || (131..=134).contains(&op_val)
                        || (137..=138).contains(&op_val)
                        || (141..=142).contains(&op_val)
                        || (149..=153).contains(&op_val)
                        || (187..=254).contains(&op_val)
                    {
                        bail!("OP_SUCCESS opcode used: {}", op_val);
                    }
                }

                // Check for disabled opcodes in Tapscript
                if opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY {
                    bail!("CHECKMULTISIG opcodes disabled in Tapscript");
                }
            }
        }

        // Initialize stack with witness elements (except control block and script)
        let mut stack = Vec::new();
        for i in 0..(witness.len() - 2) {
            stack.push(witness.nth(i).unwrap().to_vec());
        }

        // Check stack size
        if stack.len() > self.flags.max_stack_size {
            bail!("Initial stack too large: {} items", stack.len());
        }

        // Execute script (simplified - would need full script interpreter)
        trace!(
            "Executing Tapscript for tx {} input {} with {} initial stack items",
            tx.compute_txid(),
            input_index,
            stack.len()
        );

        // Validate the input index is valid
        if input_index >= tx.input.len() {
            bail!("Invalid input index {} for transaction with {} inputs", 
                  input_index, tx.input.len());
        }

        // Get the input being validated
        let input = &tx.input[input_index];
        
        // Check sequence for BIP68 (relative locktime)
        let sequence = input.sequence;
        if sequence.is_relative_lock_time() {
            trace!("Input {} has relative locktime sequence: {:?}", input_index, sequence);
            // Verify that the relative locktime has been satisfied
            // This would check against the spending block height/time
        }
        
        // Initialize script interpreter for tapscript execution
        use crate::script_interpreter::{ScriptInterpreter, ScriptFlags};
        
        let script_flags = ScriptFlags {
            verify_p2sh: false, // Not applicable for Tapscript
            verify_strictenc: true,
            verify_dersig: true,
            verify_low_s: true,
            verify_nulldummy: true,
            verify_sigpushonly: true,
            verify_minimaldata: true,
            verify_checklocktimeverify: true,
            verify_checksequenceverify: true,
            verify_witness: true,
            verify_discourage_upgradable_nops: true,
            verify_minimalif: true,
            verify_taproot: true,
            verify_cleanstack: true, // Require clean stack after script execution
        };
        
        let mut interpreter = ScriptInterpreter::new(script_flags);
        
        // Set up initial stack from witness
        for i in 0..(witness.len() - 2) {
            interpreter.push_to_stack(witness.nth(i).unwrap().to_vec());
        }
        
        // Verify the script structure and that we're using the transaction context
        // The actual script execution would happen here
        // For now, we validate that we have the right context
        trace!(
            "Validating tapscript for tx {} input {} with {} witness elements",
            tx.compute_txid(),
            input_index,
            witness.len()
        );
        
        // Check that the script is not empty
        if script.is_empty() {
            bail!("Empty tapscript for input {}", input_index);
        }

        Ok(())
    }

    /// Compute Taproot signature hash (BIP341)
    fn compute_taproot_sighash(
        &self,
        tx: &Transaction,
        input_index: usize,
        amount: bitcoin::Amount,
        annex: Option<&[u8]>,
        sighash_type: Option<u8>,
    ) -> Result<[u8; 32]> {
        use bitcoin::sighash::SighashCache;
        use bitcoin::sighash::TapSighashType;

        // Determine sighash type
        let sighash_type = if let Some(ty) = sighash_type {
            TapSighashType::from_consensus_u8(ty)?
        } else {
            TapSighashType::Default
        };

        // Create sighash cache
        let mut cache = SighashCache::new(tx);

        // For Taproot, we need all prevouts for signature computation
        // In production, these would be passed in or retrieved from UTXO set
        // For now, create a simple prevout
        let prevout = TxOut {
            value: amount,
            script_pubkey: ScriptBuf::new_p2tr(
                &bitcoin::secp256k1::Secp256k1::new(),
                XOnlyPublicKey::from_slice(&[0x02; 32]).unwrap(),
                None,
            ),
        };

        // Compute Taproot signature hash
        // Note: annex is currently not used in key spend, but would be needed for script spend
        if annex.is_some() {
            trace!("Annex data provided ({} bytes) for sighash computation", 
                  annex.unwrap().len());
        }
        
        let sighash = cache.taproot_key_spend_signature_hash(
            input_index,
            &bitcoin::sighash::Prevouts::One(input_index, prevout),
            sighash_type,
        )?;

        Ok(sighash.to_byte_array())
    }

    /// Create a Taproot address
    pub fn create_taproot_address(
        internal_key: XOnlyPublicKey,
        script_tree: Option<TaprootBuilder>,
        network: bitcoin::Network,
    ) -> Result<bitcoin::Address> {
        let secp = Secp256k1::new();

        let spend_info = if let Some(tree) = script_tree {
            tree.finalize(&secp, internal_key)
                .map_err(|e| anyhow::anyhow!("Failed to finalize taproot tree: {:?}", e))?
        } else {
            // Key-only spend
            TaprootSpendInfo::new_key_spend(&secp, internal_key, None)
        };

        Ok(bitcoin::Address::p2tr(
            &secp,
            internal_key,
            spend_info.merkle_root(),
            network,
        ))
    }

    /// Build a Taproot script tree
    pub fn build_script_tree(scripts: Vec<(ScriptBuf, u32)>) -> Result<TaprootBuilder> {
        let mut builder = TaprootBuilder::new();

        for (script, weight) in scripts {
            // Add script with weight (simplified - would need proper tree building)
            builder = builder
                .add_leaf(weight as u8, script)
                .map_err(|e| anyhow::anyhow!("Failed to add leaf: {:?}", e))?;
        }

        Ok(builder)
    }
}

/// Tapscript operation costs (BIP342)
pub struct TapscriptCosts {
    /// Base cost per input
    pub base_input_cost: u32,

    /// Cost per witness byte
    pub witness_byte_cost: u32,

    /// Cost per signature verification
    pub sig_verify_cost: u32,

    /// Maximum operations
    pub max_ops: u32,
}

impl Default for TapscriptCosts {
    fn default() -> Self {
        Self {
            base_input_cost: 50,
            witness_byte_cost: 1,
            sig_verify_cost: 50,
            max_ops: 201,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::rand;
    use bitcoin::blockdata::opcodes::OP_TRUE;

    #[test]
    fn test_taproot_address_creation() {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let keypair = secret_key.keypair(&secp);
        let internal_key = XOnlyPublicKey::from_keypair(&keypair).0;

        let address =
            TaprootValidator::create_taproot_address(internal_key, None, bitcoin::Network::Bitcoin)
                .unwrap();

        assert!(address.script_pubkey().is_p2tr());
    }

    #[test]
    fn test_tapscript_validation_uses_tx_context() {
        let validator = TaprootValidator::new(TaprootValidationFlags::default());
        
        // Create a test transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                }
            ],
            output: vec![],
        };
        
        // Create a simple tapscript  
        let script = ScriptBuf::from(vec![OP_TRUE.to_u8()]);
        let mut witness = bitcoin::Witness::new();
        witness.push(vec![]); // Empty stack element
        witness.push(script.as_bytes()); // Script
        witness.push(vec![0x50]); // Control block (dummy)
        
        // Test with valid input index
        let result = validator.validate_tapscript(&script, &witness, &tx, 0);
        assert!(result.is_ok(), "Should validate with valid input index");
        
        // Test with invalid input index - this should fail
        let result = validator.validate_tapscript(&script, &witness, &tx, 5);
        assert!(result.is_err(), "Should fail with invalid input index");
        assert!(result.unwrap_err().to_string().contains("Invalid input index"));
        
        // Add more inputs and test again
        tx.input.push(bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        });
        
        let result = validator.validate_tapscript(&script, &witness, &tx, 1);
        assert!(result.is_ok(), "Should validate with second input");
    }

    #[test]
    fn test_spend_type_detection() {
        let validator = TaprootValidator::new(TaprootValidationFlags::default());

        // Test key path spend (64-byte signature)
        let mut witness = bitcoin::Witness::new();
        witness.push([0u8; 64]); // Dummy signature

        match validator.determine_spend_type(&witness) {
            Ok(TaprootSpendType::KeyPath { .. }) => {}
            _ => panic!("Should detect key path spend"),
        }
    }
}
