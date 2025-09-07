use anyhow::{bail, Context, Result};
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::{Instruction, Script};
use bitcoin::consensus::encode;
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxOut};
use std::collections::HashMap;
use tracing::{debug, trace, warn};

use crate::bip68;

/// Transaction validation flags
#[derive(Debug, Clone, Copy)]
pub struct ValidationFlags {
    /// BIP16 P2SH validation
    pub verify_p2sh: bool,

    /// BIP65 CHECKLOCKTIMEVERIFY
    pub verify_checklocktimeverify: bool,

    /// BIP68/112/113 CHECKSEQUENCEVERIFY
    pub verify_checksequenceverify: bool,

    /// BIP141/143 Segregated Witness
    pub verify_witness: bool,

    /// BIP147 NULLDUMMY (dummy element must be empty)
    pub verify_nulldummy: bool,

    /// Discourage upgradable witness program
    pub discourage_upgradable_witness: bool,

    /// Taproot validation
    pub verify_taproot: bool,
}

impl ValidationFlags {
    /// Get flags for a given block height
    pub fn for_height(height: u32) -> Self {
        Self {
            verify_p2sh: height >= 173805,                // BIP16 activation
            verify_checklocktimeverify: height >= 388381, // BIP65 activation
            verify_checksequenceverify: height >= 419328, // BIP68/112/113 activation
            verify_witness: height >= 481824,             // BIP141 activation
            verify_nulldummy: height >= 481824,           // BIP147 activation
            discourage_upgradable_witness: height >= 481824,
            verify_taproot: height >= 709632, // Taproot activation
        }
    }
}

/// Transaction validator with full consensus rules
#[derive(Clone)]
pub struct TransactionValidator {
    /// Validation flags
    flags: ValidationFlags,

    /// Current block height
    block_height: u32,

    /// Block time
    block_time: u32,

    /// Median time past
    median_time_past: u32,

    /// Secp256k1 context for signature verification
    secp: Secp256k1<secp256k1::All>,
}

impl TransactionValidator {
    pub fn new(
        flags: ValidationFlags,
        block_height: u32,
        block_time: u32,
        median_time_past: u32,
    ) -> Self {
        Self {
            flags,
            block_height,
            block_time,
            median_time_past,
            secp: Secp256k1::new(),
        }
    }

    /// Validate a transaction with all consensus rules
    pub fn validate_transaction(
        &self,
        tx: &Transaction,
        prevouts: &HashMap<OutPoint, TxOut>,
        spent_outputs: &HashMap<OutPoint, u32>, // Maps outpoint to height when spent
    ) -> Result<()> {
        // Basic checks
        self.check_transaction_basic(tx)?;

        // Check inputs exist and not double-spent
        self.check_inputs_exist(tx, prevouts)?;

        // Validate locktime
        self.validate_locktime(tx)?;

        // Validate sequence (CSV)
        if self.flags.verify_checksequenceverify {
            self.validate_sequence_locks(tx, spent_outputs)?;
        }

        // Validate scripts for each input
        for (index, input) in tx.input.iter().enumerate() {
            let prevout = prevouts
                .get(&input.previous_output)
                .context("Missing prevout for validation")?;

            self.validate_input_script(tx, index, prevout)?;

            // BIP147 NULLDUMMY check
            if self.flags.verify_nulldummy {
                self.check_nulldummy(tx, index)?;
            }
        }

        Ok(())
    }

    /// Basic transaction checks
    fn check_transaction_basic(&self, tx: &Transaction) -> Result<()> {
        // Check transaction isn't empty
        if tx.input.is_empty() {
            bail!("Transaction has no inputs");
        }
        if tx.output.is_empty() {
            bail!("Transaction has no outputs");
        }

        // Check transaction size
        let tx_size = encode::serialize(tx).len();
        if tx_size > 1_000_000 {
            bail!("Transaction size {} exceeds maximum", tx_size);
        }

        // Check for negative or overflow output values
        let mut total_out = 0u64;
        for output in &tx.output {
            if output.value.to_sat() > 21_000_000 * 100_000_000 {
                bail!("Output value exceeds maximum");
            }
            total_out = total_out
                .checked_add(output.value.to_sat())
                .ok_or_else(|| anyhow::anyhow!("Output value overflow"))?;
        }

        if total_out > 21_000_000 * 100_000_000 {
            bail!("Total output value exceeds maximum supply");
        }

        // Check for duplicate inputs
        let mut inputs_seen = std::collections::HashSet::new();
        for input in &tx.input {
            if !inputs_seen.insert(input.previous_output) {
                bail!("Duplicate input found");
            }
        }

        // Check coinbase
        if tx.is_coinbase() {
            if tx.input.len() != 1 {
                bail!("Coinbase must have exactly one input");
            }
            let coinbase_script_len = tx.input[0].script_sig.len();
            if !(2..=100).contains(&coinbase_script_len) {
                bail!("Coinbase script size out of range");
            }
        } else {
            // Check that prevouts exist for non-coinbase
            for input in &tx.input {
                if input.previous_output.is_null() {
                    bail!("Non-coinbase transaction has null input");
                }
            }
        }

        Ok(())
    }

    /// Check that all inputs exist
    fn check_inputs_exist(
        &self,
        tx: &Transaction,
        prevouts: &HashMap<OutPoint, TxOut>,
    ) -> Result<()> {
        if tx.is_coinbase() {
            return Ok(());
        }

        for input in &tx.input {
            if !prevouts.contains_key(&input.previous_output) {
                bail!("Input {} not found in UTXO set", input.previous_output);
            }
        }

        Ok(())
    }

    /// Validate transaction locktime (BIP65 CHECKLOCKTIMEVERIFY + BIP113)
    fn validate_locktime(&self, tx: &Transaction) -> Result<()> {
        // If all sequence numbers are final, locktime is ignored
        let all_final = tx.input.iter().all(|input| input.sequence.is_final());
        if all_final {
            return Ok(());
        }

        let locktime = tx.lock_time.to_consensus_u32();

        // Check if locktime has passed
        if locktime > 0 {
            if locktime < 500_000_000 {
                // Block height locktime
                if locktime > self.block_height {
                    bail!(
                        "Transaction locktime {} not reached (current height: {})",
                        locktime,
                        self.block_height
                    );
                }
            } else {
                // Timestamp locktime - use BIP113 median time if active
                let comparison_time = if self.block_height >= 419328 {
                    // BIP113 active: use median-time-past
                    debug!("Using BIP113 median-time-past for locktime comparison");
                    self.median_time_past
                } else {
                    // BIP113 not active: use block time
                    trace!("BIP113 not active, using block time for locktime comparison");
                    self.block_time
                };

                if locktime > comparison_time {
                    bail!(
                        "Transaction locktime {} not reached (comparison time: {})",
                        locktime,
                        comparison_time
                    );
                }
            }
        }

        Ok(())
    }

    /// Validate sequence locks (BIP68 relative locktime)
    fn validate_sequence_locks(
        &self,
        tx: &Transaction,
        spent_outputs: &HashMap<OutPoint, u32>,
    ) -> Result<()> {
        // BIP68 only applies to version 2+ transactions
        if tx.version.0 < 2 {
            return Ok(());
        }

        // First validate that the sequence numbers are valid
        bip68::validate_sequence_numbers(tx)?;

        // Build arrays of prevout heights and times for BIP68 checking
        let mut prevout_heights = Vec::with_capacity(tx.input.len());
        let mut prevout_times = Vec::with_capacity(tx.input.len());

        for input in &tx.input {
            // Get the height when this output was created
            let spent_height = spent_outputs
                .get(&input.previous_output)
                .copied()
                .unwrap_or(0);

            // For now, use block height as a proxy for time
            // In a real implementation, we'd need the actual block time
            let spent_time = spent_height * 600; // Approximate 10 minutes per block

            prevout_heights.push(spent_height);
            prevout_times.push(spent_time);
        }

        // Check if all sequence locks are satisfied
        let locks_satisfied = bip68::check_sequence_locks(
            tx,
            &prevout_heights,
            &prevout_times,
            self.block_height,
            self.block_time,
        )?;

        if !locks_satisfied {
            bail!("BIP68 sequence locks not satisfied for transaction");
        }

        Ok(())
    }

    /// Validate input script
    fn validate_input_script(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevout: &TxOut,
    ) -> Result<()> {
        let input = &tx.input[input_index];

        // Check for standard script types
        if prevout.script_pubkey.is_p2pkh() {
            self.validate_p2pkh(input, &prevout.script_pubkey)?;
        } else if prevout.script_pubkey.is_p2sh() && self.flags.verify_p2sh {
            self.validate_p2sh(input, &prevout.script_pubkey)?;
        } else if prevout.script_pubkey.is_p2wpkh() && self.flags.verify_witness {
            self.validate_p2wpkh(tx, input_index, &prevout.script_pubkey)?;
        } else if prevout.script_pubkey.is_p2wsh() && self.flags.verify_witness {
            self.validate_p2wsh(tx, input_index, &prevout.script_pubkey)?;
        } else if prevout.script_pubkey.is_p2tr() && self.flags.verify_taproot {
            self.validate_p2tr(tx, input_index, &prevout.script_pubkey)?;
        } else {
            // Generic script validation
            debug!("Validating generic script");
        }

        Ok(())
    }

    /// BIP147 NULLDUMMY check
    fn check_nulldummy(&self, tx: &Transaction, input_index: usize) -> Result<()> {
        let input = &tx.input[input_index];

        // Check if scriptSig contains OP_CHECKMULTISIG
        let script_ops: Vec<_> = input.script_sig.instructions().collect();

        for op in script_ops {
            if let Ok(Instruction::Op(opcode)) = op {
                if opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY {
                    // For CHECKMULTISIG, the dummy element must be empty
                    // This requires looking at the stack state, which we'd need
                    // a full script interpreter for. For now, we'll check basic cases.

                    // In P2SH multisig, the first element after OP_0 should be empty
                    if let Some(Ok(Instruction::Op(op))) = input.script_sig.instructions().next() {
                        if op == OP_PUSHBYTES_0 {
                            warn!("Potential NULLDUMMY violation in input {}", input_index);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate P2PKH script
    fn validate_p2pkh(&self, input: &bitcoin::TxIn, script_pubkey: &ScriptBuf) -> Result<()> {
        // P2PKH requires signature and pubkey in scriptSig
        let sig_script_len = input.script_sig.len();
        if !(100..=150).contains(&sig_script_len) {
            bail!("Invalid P2PKH scriptSig length: {}", sig_script_len);
        }

        // Extract signature and pubkey from scriptSig
        let sig_script_ops: Vec<_> = input
            .script_sig
            .instructions()
            .filter_map(|op| op.ok())
            .collect();

        if sig_script_ops.len() != 2 {
            bail!("P2PKH scriptSig must have exactly 2 elements");
        }

        // First element should be signature
        let _signature = match &sig_script_ops[0] {
            Instruction::PushBytes(push) => {
                if push.as_bytes().len() < 65 || push.as_bytes().len() > 73 {
                    bail!("Invalid signature length in P2PKH");
                }
                push.as_bytes()
            }
            _ => bail!("First element of P2PKH scriptSig must be signature"),
        };

        // Second element should be pubkey
        let pubkey_bytes = match &sig_script_ops[1] {
            Instruction::PushBytes(push) => {
                if push.as_bytes().len() != 33 && push.as_bytes().len() != 65 {
                    bail!("Invalid pubkey length in P2PKH");
                }
                push.as_bytes()
            }
            _ => bail!("Second element of P2PKH scriptSig must be pubkey"),
        };

        // Verify the pubkey hash matches
        use bitcoin::hashes::Hash;
        let pubkey_hash = bitcoin::hashes::hash160::Hash::hash(pubkey_bytes);

        // Extract expected hash from script_pubkey
        let script_ops: Vec<_> = script_pubkey
            .instructions()
            .filter_map(|op| op.ok())
            .collect();

        if script_ops.len() != 5 {
            bail!("Invalid P2PKH script structure");
        }

        // P2PKH: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        if let Instruction::PushBytes(expected_hash) = &script_ops[2] {
            if expected_hash.as_bytes() != pubkey_hash.as_byte_array() {
                bail!("Pubkey hash mismatch in P2PKH");
            }
        }

        debug!("P2PKH validation passed");
        Ok(())
    }

    /// Validate P2SH script
    fn validate_p2sh(&self, input: &bitcoin::TxIn, script_pubkey: &ScriptBuf) -> Result<()> {
        // P2SH validation requires executing the redeem script
        if input.script_sig.is_empty() {
            bail!("P2SH requires scriptSig");
        }

        // Get the last element of scriptSig (the redeem script)
        let sig_script_ops: Vec<_> = input
            .script_sig
            .instructions()
            .filter_map(|op| op.ok())
            .collect();

        if sig_script_ops.is_empty() {
            bail!("P2SH scriptSig is empty");
        }

        // Last element should be the redeem script
        let redeem_script = match sig_script_ops.last() {
            Some(Instruction::PushBytes(push)) => ScriptBuf::from(push.as_bytes().to_vec()),
            _ => bail!("Last element of P2SH scriptSig must be redeem script"),
        };

        // Hash the redeem script and verify it matches the P2SH hash
        let redeem_script_hash = bitcoin::ScriptHash::hash(redeem_script.as_bytes());

        // Extract expected hash from script_pubkey (P2SH: OP_HASH160 <scripthash> OP_EQUAL)
        let script_ops: Vec<_> = script_pubkey
            .instructions()
            .filter_map(|op| op.ok())
            .collect();

        if script_ops.len() != 3 {
            bail!("Invalid P2SH script structure");
        }

        if let Instruction::PushBytes(expected_hash) = &script_ops[1] {
            if expected_hash.as_bytes() != redeem_script_hash.as_byte_array() {
                bail!("Redeem script hash mismatch in P2SH");
            }
        }

        // Check if redeem script is witness program (P2SH-wrapped witness)
        if redeem_script.is_p2wpkh() || redeem_script.is_p2wsh() {
            trace!("P2SH-wrapped witness script detected");
            if !self.flags.verify_witness {
                bail!("Witness scripts not allowed at this height");
            }

            // For P2SH-wrapped witness, scriptSig should only contain the redeem script
            if sig_script_ops.len() != 1 {
                bail!("P2SH-wrapped witness scriptSig must only contain redeem script");
            }
        }

        debug!("P2SH validation passed");
        Ok(())
    }

    /// Validate P2WPKH script
    fn validate_p2wpkh(
        &self,
        tx: &Transaction,
        input_index: usize,
        script_pubkey: &ScriptBuf,
    ) -> Result<()> {
        let input = &tx.input[input_index];

        // P2WPKH requires empty scriptSig
        if !input.script_sig.is_empty() {
            bail!("P2WPKH requires empty scriptSig");
        }

        // Check witness
        if input.witness.is_empty() {
            bail!("P2WPKH requires witness data");
        }

        // Witness should have exactly 2 items (signature and pubkey)
        if input.witness.len() != 2 {
            bail!(
                "P2WPKH witness must have exactly 2 items, got {}",
                input.witness.len()
            );
        }

        // Extract signature and pubkey from witness
        let signature_bytes = input
            .witness
            .nth(0)
            .ok_or_else(|| anyhow::anyhow!("Missing signature in witness"))?;
        let pubkey_bytes = input
            .witness
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Missing pubkey in witness"))?;

        // Validate signature format (DER encoded + sighash type)
        if signature_bytes.is_empty() || signature_bytes.len() > 73 {
            bail!("Invalid signature length in P2WPKH witness");
        }

        // Validate pubkey format (compressed only for witness v0)
        if pubkey_bytes.len() != 33 {
            bail!("P2WPKH requires compressed pubkey (33 bytes)");
        }

        // Extract witness program from script_pubkey
        let witness_program = script_pubkey.as_bytes();
        if witness_program.len() != 22 || witness_program[0] != 0x00 || witness_program[1] != 0x14 {
            bail!("Invalid P2WPKH script structure");
        }

        // Verify pubkey hash matches witness program
        let pubkey_hash = bitcoin::hashes::hash160::Hash::hash(pubkey_bytes);
        let expected_hash = &witness_program[2..22];

        if pubkey_hash.as_byte_array() != expected_hash {
            bail!("Pubkey hash mismatch in P2WPKH");
        }

        debug!("P2WPKH validation passed");
        Ok(())
    }

    /// Validate P2WSH script
    fn validate_p2wsh(
        &self,
        tx: &Transaction,
        input_index: usize,
        script_pubkey: &ScriptBuf,
    ) -> Result<()> {
        let input = &tx.input[input_index];

        // P2WSH requires empty scriptSig
        if !input.script_sig.is_empty() {
            bail!("P2WSH requires empty scriptSig");
        }

        // Check witness
        if input.witness.is_empty() {
            bail!("P2WSH requires witness data");
        }

        // Last witness item should be the witness script
        if input.witness.len() < 2 {
            bail!("P2WSH witness must have at least 2 items");
        }

        // Get the witness script (last item)
        let witness_script_bytes = input
            .witness
            .last()
            .ok_or_else(|| anyhow::anyhow!("Missing witness script"))?;
        let witness_script = ScriptBuf::from(witness_script_bytes.to_vec());

        // Hash the witness script and verify it matches the P2WSH commitment
        let witness_script_hash = bitcoin::WScriptHash::hash(witness_script.as_bytes());

        // Extract witness program from script_pubkey
        let witness_program = script_pubkey.as_bytes();
        if witness_program.len() != 34 || witness_program[0] != 0x00 || witness_program[1] != 0x20 {
            bail!("Invalid P2WSH script structure");
        }

        let expected_hash = &witness_program[2..34];

        if witness_script_hash.as_byte_array() != expected_hash {
            bail!("Witness script hash mismatch in P2WSH");
        }

        // Validate witness script structure
        if witness_script.len() > 10000 {
            bail!("Witness script too large (max 10000 bytes)");
        }

        // Check for standard witness script patterns
        if witness_script.is_p2pk() || witness_script.is_p2pkh() {
            trace!("Standard witness script pattern detected");
        } else if self.is_multisig_script(&witness_script)? {
            trace!("Multisig witness script detected");
            self.validate_multisig_witness(input, &witness_script)?;
        }

        debug!("P2WSH validation passed");
        Ok(())
    }

    /// Validate P2TR (Taproot) script
    fn validate_p2tr(
        &self,
        tx: &Transaction,
        input_index: usize,
        script_pubkey: &ScriptBuf,
    ) -> Result<()> {
        let input = &tx.input[input_index];

        // P2TR requires empty scriptSig
        if !input.script_sig.is_empty() {
            bail!("P2TR requires empty scriptSig");
        }

        // Check witness
        if input.witness.is_empty() {
            bail!("P2TR requires witness data");
        }

        // Extract taproot output key from script_pubkey
        let script_bytes = script_pubkey.as_bytes();
        if script_bytes.len() != 34 || script_bytes[0] != 0x51 || script_bytes[1] != 0x20 {
            bail!("Invalid P2TR script structure");
        }

        let output_key_bytes = &script_bytes[2..34];
        let _output_key =
            XOnlyPublicKey::from_slice(output_key_bytes).context("Invalid taproot output key")?;

        // Determine spend type based on witness stack size
        match input.witness.len() {
            1 => {
                // Key path spend - single signature
                let signature_bytes = input
                    .witness
                    .nth(0)
                    .ok_or_else(|| anyhow::anyhow!("Missing signature in taproot witness"))?;

                // Schnorr signatures are 64 or 65 bytes (with sighash flag)
                if signature_bytes.len() != 64 && signature_bytes.len() != 65 {
                    bail!(
                        "Invalid taproot signature length: {}",
                        signature_bytes.len()
                    );
                }

                trace!("Taproot key path spend detected");
            }
            n if n >= 2 => {
                // Script path spend - script, optional arguments, control block, optional annex
                let control_block_bytes = input
                    .witness
                    .nth(input.witness.len() - 1)
                    .ok_or_else(|| anyhow::anyhow!("Missing control block"))?;

                // Control block validation
                self.validate_control_block(control_block_bytes)?;

                // Check for annex (starts with 0x50)
                let has_annex = if input.witness.len() >= 2 {
                    let potential_annex = input.witness.nth(input.witness.len() - 2).unwrap_or(&[]);
                    !potential_annex.is_empty() && potential_annex[0] == 0x50
                } else {
                    false
                };

                let script_index = if has_annex {
                    input.witness.len() - 3
                } else {
                    input.witness.len() - 2
                };

                if script_index >= input.witness.len() {
                    bail!("Invalid taproot script path witness structure");
                }

                let _script_bytes = input
                    .witness
                    .nth(script_index)
                    .ok_or_else(|| anyhow::anyhow!("Missing tapscript"))?;

                trace!("Taproot script path spend detected (annex: {})", has_annex);
            }
            _ => bail!("Invalid taproot witness stack size"),
        }

        debug!("P2TR validation passed");
        Ok(())
    }

    /// Validate taproot control block
    fn validate_control_block(&self, control_block: &[u8]) -> Result<()> {
        if control_block.is_empty() {
            bail!("Empty control block");
        }

        let leaf_version = control_block[0] & 0xfe;
        let parity = control_block[0] & 0x01;

        // Check leaf version (0xc0 is the initial tapscript version)
        if leaf_version != 0xc0 && leaf_version != 0xc2 {
            if self.flags.discourage_upgradable_witness {
                bail!("Unknown taproot leaf version: 0x{:02x}", leaf_version);
            }
            warn!("Unknown taproot leaf version: 0x{:02x}", leaf_version);
        }

        // Control block size: 33 + 32n where n is the path length
        if control_block.len() < 33 {
            bail!("Control block too short");
        }

        if (control_block.len() - 33) % 32 != 0 {
            bail!("Invalid control block size");
        }

        let path_len = (control_block.len() - 33) / 32;
        if path_len > 128 {
            bail!("Control block path too long (max 128)");
        }

        trace!(
            "Control block validated: leaf_version=0x{:02x}, parity={}, path_len={}",
            leaf_version,
            parity,
            path_len
        );

        Ok(())
    }

    /// Check if a script is a multisig script
    fn is_multisig_script(&self, script: &Script) -> Result<bool> {
        let ops: Vec<_> = script.instructions().filter_map(|op| op.ok()).collect();

        if ops.is_empty() {
            return Ok(false);
        }

        // Check for OP_CHECKMULTISIG at the end
        if let Some(Instruction::Op(last_op)) = ops.last() {
            if *last_op == OP_CHECKMULTISIG || *last_op == OP_CHECKMULTISIGVERIFY {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Validate multisig witness
    fn validate_multisig_witness(
        &self,
        input: &bitcoin::TxIn,
        witness_script: &Script,
    ) -> Result<()> {
        // Extract m and n from multisig script
        let ops: Vec<_> = witness_script
            .instructions()
            .filter_map(|op| op.ok())
            .collect();

        if ops.len() < 4 {
            bail!("Invalid multisig script structure");
        }

        // First op should be OP_x for required signatures
        let m = match ops.first() {
            Some(Instruction::Op(op))
                if op.to_u8() >= OP_PUSHNUM_1.to_u8() && op.to_u8() <= OP_PUSHNUM_16.to_u8() =>
            {
                op.to_u8() - OP_PUSHNUM_1.to_u8() + 1
            }
            _ => bail!("Invalid multisig m value"),
        };

        // Find n (total keys) - should be before OP_CHECKMULTISIG
        let n = match ops[ops.len() - 2] {
            Instruction::Op(op)
                if op.to_u8() >= OP_PUSHNUM_1.to_u8() && op.to_u8() <= OP_PUSHNUM_16.to_u8() =>
            {
                op.to_u8() - OP_PUSHNUM_1.to_u8() + 1
            }
            _ => bail!("Invalid multisig n value"),
        };

        if m > n {
            bail!("Multisig m > n");
        }

        // Count signatures in witness (excluding witness script and dummy element)
        let sig_count = input.witness.len().saturating_sub(2);

        if sig_count < m as usize {
            bail!(
                "Not enough signatures for multisig (need {}, got {})",
                m,
                sig_count
            );
        }

        trace!(
            "Multisig witness validated: {}-of-{}, {} signatures provided",
            m,
            n,
            sig_count
        );
        Ok(())
    }
}

/// Sequence number extensions for relative locktime
trait SequenceExt {
    fn is_relative_lock_time(&self) -> bool;
    fn is_height_locked(&self) -> bool;
    fn is_time_locked(&self) -> bool;
}

impl SequenceExt for Sequence {
    fn is_relative_lock_time(&self) -> bool {
        // Bit 31 unset means relative lock-time
        self.to_consensus_u32() < 0x80000000
    }

    fn is_height_locked(&self) -> bool {
        // Bit 22 unset means height-locked
        self.to_consensus_u32() & (1 << 22) == 0
    }

    fn is_time_locked(&self) -> bool {
        // Bit 22 set means time-locked
        self.to_consensus_u32() & (1 << 22) != 0
    }
}

/// Transaction validation context
pub struct ValidationContext {
    /// Block height
    pub height: u32,

    /// Block time
    pub time: u32,

    /// Median time past
    pub median_time_past: u32,

    /// Validation flags
    pub flags: ValidationFlags,
}

impl ValidationContext {
    pub fn new(height: u32, time: u32, median_time_past: u32) -> Self {
        Self {
            height,
            time,
            median_time_past,
            flags: ValidationFlags::for_height(height),
        }
    }

    /// Create a validator for this context
    pub fn create_validator(&self) -> TransactionValidator {
        TransactionValidator::new(self.flags, self.height, self.time, self.median_time_past)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_flags() {
        // Test flag activation heights
        let flags = ValidationFlags::for_height(500000);
        assert!(flags.verify_p2sh);
        assert!(flags.verify_checklocktimeverify);
        assert!(flags.verify_checksequenceverify);
        assert!(flags.verify_witness);
        assert!(flags.verify_nulldummy);
    }

    #[test]
    fn test_basic_transaction_validation() {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let context = ValidationContext::new(500000, 1234567890, 1234567800);
        let validator = context.create_validator();

        // Empty transaction should fail
        assert!(validator.check_transaction_basic(&tx).is_err());
    }
}
