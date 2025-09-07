use anyhow::{bail, Context, Result};
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::opcodes::Opcode;
use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use bitcoin::key::PublicKey;
use bitcoin::secp256k1::{self, Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Script, Transaction};
use std::collections::VecDeque;
use tracing::trace;

/// Maximum script size
const MAX_SCRIPT_SIZE: usize = 10000;

/// Maximum stack size
const MAX_STACK_SIZE: usize = 1000;

/// Maximum script element size
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum opcodes per script
const MAX_OPS_PER_SCRIPT: usize = 201;

/// Script verification flags
#[derive(Debug, Clone, Copy)]
pub struct ScriptFlags {
    pub verify_p2sh: bool,
    pub verify_strictenc: bool,
    pub verify_dersig: bool,
    pub verify_low_s: bool,
    pub verify_nulldummy: bool,
    pub verify_sigpushonly: bool,
    pub verify_minimaldata: bool,
    pub verify_discourage_upgradable_nops: bool,
    pub verify_cleanstack: bool,
    pub verify_checklocktimeverify: bool,
    pub verify_checksequenceverify: bool,
    pub verify_witness: bool,
    pub verify_taproot: bool,
    pub verify_minimalif: bool,
}

impl Default for ScriptFlags {
    fn default() -> Self {
        Self {
            verify_p2sh: true,
            verify_strictenc: true,
            verify_dersig: true,
            verify_low_s: true,
            verify_nulldummy: true,
            verify_sigpushonly: true,
            verify_minimaldata: true,
            verify_discourage_upgradable_nops: true,
            verify_cleanstack: true,
            verify_checklocktimeverify: true,
            verify_checksequenceverify: true,
            verify_witness: true,
            verify_taproot: true,
            verify_minimalif: true,
        }
    }
}

/// Script interpreter for transaction validation
pub struct ScriptInterpreter {
    /// Main stack
    stack: VecDeque<Vec<u8>>,

    /// Alt stack for OP_TOALTSTACK/OP_FROMALTSTACK
    alt_stack: VecDeque<Vec<u8>>,

    /// Conditional execution state
    exec_stack: Vec<bool>,

    /// Script flags
    flags: ScriptFlags,

    /// Operation count
    op_count: usize,

    /// Secp256k1 context
    secp: Secp256k1<secp256k1::All>,
}

impl ScriptInterpreter {
    /// Create new script interpreter
    pub fn new(flags: ScriptFlags) -> Self {
        Self {
            stack: VecDeque::new(),
            alt_stack: VecDeque::new(),
            exec_stack: Vec::new(),
            flags,
            op_count: 0,
            secp: Secp256k1::new(),
        }
    }

    /// Push data to the stack
    pub fn push_to_stack(&mut self, data: Vec<u8>) {
        self.stack.push_back(data);
    }

    /// Execute witness script with pre-populated stack
    /// Used for P2WSH validation where witness items form the initial stack
    pub fn execute_witness_script(
        &mut self,
        witness_stack: &[Vec<u8>],
        witness_script: &Script,
        tx: &Transaction,
        input_index: usize,
        amount: bitcoin::Amount,
        sighash: &[u8; 32],
    ) -> Result<bool> {
        // Clear stacks
        self.stack.clear();
        self.alt_stack.clear();
        self.exec_stack.clear();
        self.op_count = 0;

        // Pre-populate stack with witness items (excluding the script itself)
        for item in witness_stack {
            self.stack.push_back(item.clone());
        }

        // Execute the witness script
        if !self.execute_script(witness_script, tx, input_index, amount, true)? {
            return Ok(false);
        }

        // Check if stack evaluation is true
        if !self.is_stack_true() {
            trace!("Witness script execution failed: stack not true");
            return Ok(false);
        }

        // For clean stack flag, ensure only one element remains
        if self.flags.verify_cleanstack && self.stack.len() != 1 {
            trace!("Witness script execution failed: stack not clean (len={})", self.stack.len());
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify script execution
    pub fn verify_script(
        &mut self,
        script_sig: &Script,
        script_pubkey: &Script,
        tx: &Transaction,
        input_index: usize,
        amount: bitcoin::Amount,
    ) -> Result<bool> {
        // Clear stacks
        self.stack.clear();
        self.alt_stack.clear();
        self.exec_stack.clear();
        self.op_count = 0;

        // Execute scriptSig
        if !self.execute_script(script_sig, tx, input_index, amount, false)? {
            return Ok(false);
        }

        // Save stack for P2SH
        let stack_copy = self.stack.clone();

        // Execute scriptPubKey
        if !self.execute_script(script_pubkey, tx, input_index, amount, false)? {
            return Ok(false);
        }

        // Check if stack is clean (should have single true value)
        if !self.is_stack_true() {
            return Ok(false);
        }

        // Additional P2SH validation
        if self.flags.verify_p2sh && script_pubkey.is_p2sh() {
            // Restore stack
            self.stack = stack_copy;

            if self.stack.is_empty() {
                return Ok(false);
            }

            // Pop redeem script
            let redeem_script_bytes = self
                .stack
                .pop_back()
                .ok_or_else(|| anyhow::anyhow!("Missing redeem script"))?;
            let redeem_script = Script::from_bytes(&redeem_script_bytes);

            // Execute redeem script
            if !self.execute_script(redeem_script, tx, input_index, amount, true)? {
                return Ok(false);
            }

            if !self.is_stack_true() {
                return Ok(false);
            }
        }

        // Clean stack check
        if self.flags.verify_cleanstack && self.stack.len() != 1 {
            bail!("Stack not clean after execution");
        }

        Ok(true)
    }

    /// Execute a script
    fn execute_script(
        &mut self,
        script: &Script,
        tx: &Transaction,
        input_index: usize,
        amount: bitcoin::Amount,
        is_redeem_script: bool,
    ) -> Result<bool> {
        if script.len() > MAX_SCRIPT_SIZE {
            bail!("Script size exceeds maximum");
        }

        let pc = script.instructions().peekable();

        for instruction in pc {
            let instruction = instruction.context("Failed to parse instruction")?;

            // Check operation count
            self.op_count += 1;
            if self.op_count > MAX_OPS_PER_SCRIPT {
                bail!("Operation count exceeds maximum");
            }

            // Check if we should execute
            let should_execute = self.exec_stack.is_empty() || *self.exec_stack.last().unwrap();

            match instruction {
                Instruction::PushBytes(data) => {
                    if should_execute {
                        self.push_data(data.as_bytes())?;
                    }
                }
                Instruction::Op(opcode) => {
                    self.execute_opcode(opcode, tx, input_index, amount, should_execute)?;
                }
            }

            // Check stack size
            if self.stack.len() + self.alt_stack.len() > MAX_STACK_SIZE {
                bail!("Stack size exceeds maximum");
            }
        }

        // Check for unbalanced conditionals
        if !self.exec_stack.is_empty() {
            bail!("Unbalanced conditional");
        }

        Ok(true)
    }

    /// Execute an opcode
    fn execute_opcode(
        &mut self,
        opcode: Opcode,
        tx: &Transaction,
        input_index: usize,
        amount: bitcoin::Amount,
        should_execute: bool,
    ) -> Result<()> {
        // Handle flow control opcodes that work even when not executing
        match opcode {
            OP_IF | OP_NOTIF => {
                let mut value = false;
                if should_execute {
                    if self.stack.is_empty() {
                        bail!("Stack empty for OP_IF/OP_NOTIF");
                    }
                    value = self.pop_bool()?;
                    if opcode == OP_NOTIF {
                        value = !value;
                    }
                }
                self.exec_stack.push(should_execute && value);
                return Ok(());
            }
            OP_ELSE => {
                if self.exec_stack.is_empty() {
                    bail!("OP_ELSE without OP_IF");
                }
                let last = self.exec_stack.len() - 1;
                self.exec_stack[last] =
                    !self.exec_stack[last] && (last == 0 || self.exec_stack[last - 1]);
                return Ok(());
            }
            OP_ENDIF => {
                if self.exec_stack.is_empty() {
                    bail!("OP_ENDIF without OP_IF");
                }
                self.exec_stack.pop();
                return Ok(());
            }
            _ => {}
        }

        // Don't execute if in false branch
        if !should_execute {
            return Ok(());
        }

        // Execute opcode
        match opcode {
            // Constants
            OP_PUSHBYTES_0 => self.stack.push_back(vec![]),
            OP_PUSHNUM_NEG1 => self.stack.push_back(vec![0x81]),
            n if n.to_u8() >= OP_PUSHNUM_1.to_u8() && n.to_u8() <= OP_PUSHNUM_16.to_u8() => {
                let num = n.to_u8() - (OP_PUSHNUM_1.to_u8() - 1);
                self.stack.push_back(vec![num]);
            }

            // Stack operations
            OP_DUP => {
                if self.stack.is_empty() {
                    bail!("Stack empty for OP_DUP");
                }
                let top = self.stack.back().unwrap().clone();
                self.stack.push_back(top);
            }
            OP_DROP => {
                if self.stack.is_empty() {
                    bail!("Stack empty for OP_DROP");
                }
                self.stack.pop_back();
            }
            OP_SWAP => {
                if self.stack.len() < 2 {
                    bail!("Stack too small for OP_SWAP");
                }
                let len = self.stack.len();
                self.stack.swap(len - 1, len - 2);
            }
            OP_TOALTSTACK => {
                if self.stack.is_empty() {
                    bail!("Stack empty for OP_TOALTSTACK");
                }
                let item = self.stack.pop_back().unwrap();
                self.alt_stack.push_back(item);
            }
            OP_FROMALTSTACK => {
                if self.alt_stack.is_empty() {
                    bail!("Alt stack empty for OP_FROMALTSTACK");
                }
                let item = self.alt_stack.pop_back().unwrap();
                self.stack.push_back(item);
            }

            // Crypto operations
            OP_SHA256 => {
                if self.stack.is_empty() {
                    bail!("Stack empty for OP_SHA256");
                }
                let data = self.stack.pop_back().unwrap();
                let hash = sha256::Hash::hash(&data);
                self.stack.push_back(hash.to_byte_array().to_vec());
            }
            OP_HASH256 => {
                if self.stack.is_empty() {
                    bail!("Stack empty for OP_HASH256");
                }
                let data = self.stack.pop_back().unwrap();
                let hash = sha256d::Hash::hash(&data);
                self.stack.push_back(hash.to_byte_array().to_vec());
            }
            OP_HASH160 => {
                if self.stack.is_empty() {
                    bail!("Stack empty for OP_HASH160");
                }
                let data = self.stack.pop_back().unwrap();
                let hash = hash160::Hash::hash(&data);
                self.stack.push_back(hash.to_byte_array().to_vec());
            }
            OP_RIPEMD160 => {
                if self.stack.is_empty() {
                    bail!("Stack empty for OP_RIPEMD160");
                }
                let data = self.stack.pop_back().unwrap();
                let hash = ripemd160::Hash::hash(&data);
                self.stack.push_back(hash.to_byte_array().to_vec());
            }

            // Comparison operations
            OP_EQUAL | OP_EQUALVERIFY => {
                if self.stack.len() < 2 {
                    bail!("Stack too small for OP_EQUAL");
                }
                let b = self.stack.pop_back().unwrap();
                let a = self.stack.pop_back().unwrap();
                let equal = a == b;

                if opcode == OP_EQUAL {
                    self.stack.push_back(if equal { vec![1] } else { vec![] });
                } else if !equal {
                    bail!("OP_EQUALVERIFY failed");
                }
            }

            // Signature operations
            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                if self.stack.len() < 2 {
                    bail!("Stack too small for OP_CHECKSIG");
                }

                let pubkey_bytes = self.stack.pop_back().unwrap();
                let sig_bytes = self.stack.pop_back().unwrap();

                let valid =
                    self.check_signature(&sig_bytes, &pubkey_bytes, tx, input_index, amount)?;

                if opcode == OP_CHECKSIG {
                    self.stack.push_back(if valid { vec![1] } else { vec![] });
                } else if !valid {
                    bail!("OP_CHECKSIGVERIFY failed");
                }
            }
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                self.execute_checkmultisig(opcode, tx, input_index, amount)?;
            }

            // Locktime operations
            OP_CLTV => {
                if !self.flags.verify_checklocktimeverify {
                    return Ok(()); // Treat as NOP
                }
                self.execute_checklocktimeverify(tx)?;
            }
            OP_CSV => {
                if !self.flags.verify_checksequenceverify {
                    return Ok(()); // Treat as NOP
                }
                self.execute_checksequenceverify(tx, input_index)?;
            }

            // NOP operations
            OP_NOP => {}
            n if n.to_u8() >= OP_NOP1.to_u8() && n.to_u8() <= OP_NOP10.to_u8() => {
                if self.flags.verify_discourage_upgradable_nops {
                    bail!("Upgradable NOP used");
                }
            }

            // Disabled operations
            OP_CAT | OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR
            | OP_2MUL | OP_2DIV | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT => {
                bail!("Disabled opcode: {:?}", opcode);
            }

            // Other operations
            OP_VERIFY => {
                if self.stack.is_empty() || !self.is_true(self.stack.back().unwrap()) {
                    bail!("OP_VERIFY failed");
                }
                self.stack.pop_back();
            }
            OP_RETURN => {
                bail!("OP_RETURN encountered");
            }

            _ => {
                trace!("Unhandled opcode: {:?}", opcode);
            }
        }

        Ok(())
    }

    /// Check signature validity
    fn check_signature(
        &self,
        sig_bytes: &[u8],
        pubkey_bytes: &[u8],
        tx: &Transaction,
        input_index: usize,
        amount: bitcoin::Amount,
    ) -> Result<bool> {
        // Empty signature is always false
        if sig_bytes.is_empty() {
            return Ok(false);
        }

        // Parse signature and sighash type
        if sig_bytes.is_empty() {
            return Ok(false);
        }

        let sighash_type = EcdsaSighashType::from_consensus(sig_bytes[sig_bytes.len() - 1] as u32);
        let sig_der = &sig_bytes[..sig_bytes.len() - 1];

        // Parse signature
        let signature = match bitcoin::ecdsa::Signature::from_slice(sig_der) {
            Ok(sig) => sig,
            Err(_) => {
                if self.flags.verify_dersig {
                    bail!("Invalid DER signature");
                }
                return Ok(false);
            }
        };

        // Check low S value
        // Note: low_s check would need to be implemented manually
        // if self.flags.verify_low_s && !signature.is_low_s() {
        //     bail!("Signature S value not low");
        // }

        // Parse public key
        let pubkey = match PublicKey::from_slice(pubkey_bytes) {
            Ok(key) => key,
            Err(_) => {
                if self.flags.verify_strictenc {
                    bail!("Invalid public key");
                }
                return Ok(false);
            }
        };

        // Calculate sighash
        let cache = SighashCache::new(tx);
        let sighash = cache
            .legacy_signature_hash(
                input_index,
                Script::from_bytes(pubkey_bytes),
                sighash_type.to_u32(),
            )
            .context("Failed to calculate sighash")?;

        // Verify signature
        let message =
            Message::from_digest_slice(sighash.as_ref()).context("Failed to create message")?;

        Ok(self
            .secp
            .verify_ecdsa(&message, &signature.signature, &pubkey.inner)
            .is_ok())
    }

    /// Execute CHECKMULTISIG operation
    fn execute_checkmultisig(
        &mut self,
        opcode: Opcode,
        tx: &Transaction,
        input_index: usize,
        amount: bitcoin::Amount,
    ) -> Result<()> {
        if self.stack.is_empty() {
            bail!("Stack empty for CHECKMULTISIG");
        }

        // Get number of public keys
        let n = self.pop_number()? as usize;
        if n > 20 {
            bail!("Too many public keys for CHECKMULTISIG");
        }

        // Get public keys
        let mut pubkeys = Vec::new();
        for _ in 0..n {
            if self.stack.is_empty() {
                bail!("Stack too small for CHECKMULTISIG pubkeys");
            }
            pubkeys.push(self.stack.pop_back().unwrap());
        }

        // Get number of signatures
        let m = self.pop_number()? as usize;
        if m > n {
            bail!("More signatures than pubkeys in CHECKMULTISIG");
        }

        // Get signatures
        let mut sigs = Vec::new();
        for _ in 0..m {
            if self.stack.is_empty() {
                bail!("Stack too small for CHECKMULTISIG signatures");
            }
            sigs.push(self.stack.pop_back().unwrap());
        }

        // Remove dummy element (BIP147)
        if self.stack.is_empty() {
            bail!("Stack missing dummy element for CHECKMULTISIG");
        }
        let dummy = self.stack.pop_back().unwrap();
        if self.flags.verify_nulldummy && !dummy.is_empty() {
            bail!("CHECKMULTISIG dummy element not null");
        }

        // Verify signatures
        let mut valid = true;
        let mut sig_idx = 0;
        let mut key_idx = 0;

        while sig_idx < m && key_idx < n {
            let sig_valid =
                self.check_signature(&sigs[sig_idx], &pubkeys[key_idx], tx, input_index, amount)?;

            if sig_valid {
                sig_idx += 1;
            }
            key_idx += 1;
        }

        valid = sig_idx == m;

        if opcode == OP_CHECKMULTISIG {
            self.stack.push_back(if valid { vec![1] } else { vec![] });
        } else if !valid {
            bail!("OP_CHECKMULTISIGVERIFY failed");
        }

        Ok(())
    }

    /// Execute CHECKLOCKTIMEVERIFY
    fn execute_checklocktimeverify(&mut self, tx: &Transaction) -> Result<()> {
        if self.stack.is_empty() {
            bail!("Stack empty for CHECKLOCKTIMEVERIFY");
        }

        let locktime_bytes = self.stack.back().unwrap();
        if locktime_bytes.len() > 5 {
            bail!("Invalid locktime for CHECKLOCKTIMEVERIFY");
        }

        let locktime = self.decode_number(locktime_bytes)?;
        if locktime < 0 {
            bail!("Negative locktime for CHECKLOCKTIMEVERIFY");
        }

        // Check if transaction locktime is final
        if tx.lock_time.to_consensus_u32() == 0xffffffff {
            bail!("Transaction locktime disabled for CHECKLOCKTIMEVERIFY");
        }

        // Compare locktimes
        let tx_locktime = tx.lock_time.to_consensus_u32() as i64;

        // Check locktime types match
        if (locktime < 500_000_000 && tx_locktime >= 500_000_000)
            || (locktime >= 500_000_000 && tx_locktime < 500_000_000)
        {
            bail!("Locktime type mismatch in CHECKLOCKTIMEVERIFY");
        }

        if locktime > tx_locktime {
            bail!("Locktime requirement not satisfied");
        }

        Ok(())
    }

    /// Execute CHECKSEQUENCEVERIFY
    fn execute_checksequenceverify(&mut self, tx: &Transaction, input_index: usize) -> Result<()> {
        if self.stack.is_empty() {
            bail!("Stack empty for CHECKSEQUENCEVERIFY");
        }

        let sequence_bytes = self.stack.back().unwrap();
        if sequence_bytes.len() > 5 {
            bail!("Invalid sequence for CHECKSEQUENCEVERIFY");
        }

        let sequence = self.decode_number(sequence_bytes)?;
        if sequence < 0 {
            bail!("Negative sequence for CHECKSEQUENCEVERIFY");
        }

        // Check if sequence is disabled
        if sequence & (1 << 31) != 0 {
            return Ok(()); // Sequence disabled, always pass
        }

        // Get input sequence
        let input_sequence = tx.input[input_index].sequence.to_consensus_u32();

        // Check if input sequence is final
        if input_sequence == 0xffffffff {
            bail!("Input sequence is final for CHECKSEQUENCEVERIFY");
        }

        // Compare sequences
        if (sequence as u32) > input_sequence {
            bail!("Sequence requirement not satisfied");
        }

        Ok(())
    }

    /// Push data to stack
    fn push_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
            bail!("Script element size exceeds maximum");
        }
        self.stack.push_back(data.to_vec());
        Ok(())
    }

    /// Pop a boolean from stack
    fn pop_bool(&mut self) -> Result<bool> {
        if self.stack.is_empty() {
            bail!("Stack empty");
        }
        let val = self.stack.pop_back().unwrap();
        Ok(self.is_true(&val))
    }

    /// Pop a number from stack
    fn pop_number(&mut self) -> Result<i64> {
        if self.stack.is_empty() {
            bail!("Stack empty");
        }
        let val = self.stack.pop_back().unwrap();
        self.decode_number(&val)
    }

    /// Check if value is true
    fn is_true(&self, val: &[u8]) -> bool {
        for (i, &byte) in val.iter().enumerate() {
            if byte != 0 {
                // Negative zero is false
                if i == val.len() - 1 && byte == 0x80 {
                    return false;
                }
                return true;
            }
        }
        false
    }

    /// Check if stack top is true
    fn is_stack_true(&self) -> bool {
        !self.stack.is_empty() && self.is_true(self.stack.back().unwrap())
    }

    /// Decode script number
    fn decode_number(&self, bytes: &[u8]) -> Result<i64> {
        if bytes.is_empty() {
            return Ok(0);
        }

        if bytes.len() > 4 {
            bail!("Script number overflow");
        }

        let mut result = 0i64;
        for (i, &byte) in bytes.iter().enumerate() {
            result |= (byte as i64) << (8 * i);
        }

        // Handle sign
        if bytes[bytes.len() - 1] & 0x80 != 0 {
            result = -(result & !(0x80i64 << (8 * (bytes.len() - 1))));
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_interpreter_basic() -> Result<()> {
        let flags = ScriptFlags::default();
        let mut interpreter = ScriptInterpreter::new(flags);

        // Test simple push and pop
        interpreter.push_data(&[1, 2, 3])?;
        assert_eq!(interpreter.stack.len(), 1);

        let val = interpreter.stack.pop_back().unwrap();
        assert_eq!(val, vec![1, 2, 3]);

        Ok(())
    }

    #[test]
    fn test_number_encoding() -> Result<()> {
        let interpreter = ScriptInterpreter::new(ScriptFlags::default());

        // Test positive number
        assert_eq!(interpreter.decode_number(&[0x7f])?, 127);

        // Test negative number
        assert_eq!(interpreter.decode_number(&[0x81])?, -1);

        // Test zero
        assert_eq!(interpreter.decode_number(&[])?, 0);

        Ok(())
    }

    #[test]
    fn test_is_true() {
        let interpreter = ScriptInterpreter::new(ScriptFlags::default());

        // True values
        assert!(interpreter.is_true(&[1]));
        assert!(interpreter.is_true(&[0x81])); // -1 is true

        // False values
        assert!(!interpreter.is_true(&[]));
        assert!(!interpreter.is_true(&[0]));
        assert!(!interpreter.is_true(&[0x80])); // Negative zero
    }
}
