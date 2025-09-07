use crate::script::{
    stack::StackItem, Opcode, ScriptError, ScriptFlags, ScriptResult, SignatureChecker, Stack,
};
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use bitcoin::Script;

const MAX_OPS: usize = 201;
const MAX_SCRIPT_SIZE: usize = 10000;
const MAX_NUM_SIZE: usize = 4;

/// Script interpreter for executing Bitcoin scripts
pub struct ScriptInterpreter {
    pub stack: Stack,
    pub alt_stack: Stack,
    flags: ScriptFlags,
    op_count: usize,
    cond_stack: Vec<bool>,
}

impl ScriptInterpreter {
    pub fn new(flags: ScriptFlags) -> Self {
        Self {
            stack: Stack::new(),
            alt_stack: Stack::new(),
            flags,
            op_count: 0,
            cond_stack: Vec::new(),
        }
    }

    pub fn execute(&mut self, script: &Script, checker: &dyn SignatureChecker) -> ScriptResult<()> {
        if script.len() > MAX_SCRIPT_SIZE {
            return Err(ScriptError::ScriptSize);
        }

        let mut pc = 0;
        let script_bytes = script.as_bytes();

        for instruction in script.instructions() {
            let inst = instruction.map_err(|e| {
                // Map instruction parsing errors to appropriate script errors
                use bitcoin::script::Error as InstructionError;
                match e {
                    InstructionError::EarlyEndOfScript => {
                        // This usually means a push opcode claimed to push more bytes than available
                        ScriptError::PushSize
                    }
                    InstructionError::NumericOverflow => ScriptError::NumberOverflow,
                    _ => ScriptError::BadOpcode,
                }
            })?;

            // Check if we're in a false conditional branch
            let exec = self.cond_stack.is_empty() || self.cond_stack.iter().all(|&x| x);

            match inst {
                Instruction::Op(op) => {
                    let opcode = Opcode::from(op);

                    // Handle conditional opcodes regardless of exec state
                    if opcode.is_conditional() {
                        self.handle_conditional(opcode)?;
                        continue;
                    }

                    if !exec {
                        continue;
                    }

                    // Check for disabled opcodes
                    if opcode.is_disabled() {
                        return Err(ScriptError::DisabledOpcode);
                    }

                    // Count operations
                    if opcode.is_counted() {
                        self.op_count += 1;
                        if self.op_count > MAX_OPS {
                            return Err(ScriptError::OpCount);
                        }
                    }

                    // Execute opcode
                    self.execute_opcode(opcode, script_bytes, &mut pc, checker)?;
                }

                Instruction::PushBytes(data) => {
                    if exec {
                        // Check for push size limit
                        let push_data = data.as_bytes();
                        if push_data.len() > 520 {
                            return Err(ScriptError::PushSize);
                        }
                        self.stack.push(push_data.to_vec())?;
                    }
                    pc += data.len();
                }
            }

            pc += 1;
        }

        // Check for unbalanced conditionals
        if !self.cond_stack.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }

        Ok(())
    }

    fn handle_conditional(&mut self, opcode: Opcode) -> ScriptResult<()> {
        match opcode.0 {
            x if x == OP_IF.to_u8() || x == OP_NOTIF.to_u8() => {
                let mut exec = true;

                if self.cond_stack.is_empty() || self.cond_stack.iter().all(|&x| x) {
                    // We're executing, check stack for condition
                    if self.stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }

                    let val = self.stack.pop()?;
                    exec = val.to_bool();

                    if x == OP_NOTIF.to_u8() {
                        exec = !exec;
                    }
                }

                self.cond_stack.push(exec);
            }

            x if x == OP_ELSE.to_u8() => {
                if self.cond_stack.is_empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                let len = self.cond_stack.len();
                self.cond_stack[len - 1] = !self.cond_stack[len - 1];
            }

            x if x == OP_ENDIF.to_u8() => {
                if self.cond_stack.is_empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                self.cond_stack.pop();
            }

            _ => return Err(ScriptError::BadOpcode),
        }

        Ok(())
    }

    fn execute_opcode(
        &mut self,
        opcode: Opcode,
        script_bytes: &[u8],
        pc: &mut usize,
        checker: &dyn SignatureChecker,
    ) -> ScriptResult<()> {
        match opcode.0 {
            // Push values
            x if x <= OP_PUSHDATA4.to_u8() => {
                // These are handled by Instruction::PushBytes
                Ok(())
            }

            x if x == OP_PUSHNUM_NEG1.to_u8() => {
                self.stack.push_int(-1)?;
                Ok(())
            }

            x if x >= OP_PUSHNUM_1.to_u8() && x <= OP_PUSHNUM_16.to_u8() => {
                let n = (x - OP_PUSHNUM_1.to_u8() + 1) as i64;
                self.stack.push_int(n)?;
                Ok(())
            }

            // Control flow
            x if x == OP_NOP.to_u8() => Ok(()),

            x if x == OP_VER.to_u8() => {
                // Disabled opcode
                Err(ScriptError::DisabledOpcode)
            }

            // Stack operations
            x if x == OP_TOALTSTACK.to_u8() => {
                let val = self.stack.pop()?;
                self.alt_stack.push(val)?;
                Ok(())
            }

            x if x == OP_FROMALTSTACK.to_u8() => {
                let val = self.alt_stack.pop()?;
                self.stack.push(val)?;
                Ok(())
            }

            x if x == OP_DROP.to_u8() => {
                self.stack.pop()?;
                Ok(())
            }

            x if x == OP_2DROP.to_u8() => {
                self.stack.pop()?;
                self.stack.pop()?;
                Ok(())
            }

            x if x == OP_DUP.to_u8() => {
                self.stack.dup(-1)?;
                Ok(())
            }

            x if x == OP_2DUP.to_u8() => {
                self.stack.dup(-2)?;
                self.stack.dup(-2)?;
                Ok(())
            }

            x if x == OP_3DUP.to_u8() => {
                self.stack.dup(-3)?;
                self.stack.dup(-3)?;
                self.stack.dup(-3)?;
                Ok(())
            }

            x if x == OP_SWAP.to_u8() => {
                self.stack.swap(0, 1)?;
                Ok(())
            }

            x if x == OP_2SWAP.to_u8() => {
                self.stack.swap(0, 2)?;
                self.stack.swap(1, 3)?;
                Ok(())
            }

            x if x == OP_ROT.to_u8() => {
                self.stack.swap(2, 1)?;
                self.stack.swap(1, 0)?;
                Ok(())
            }

            x if x == OP_2ROT.to_u8() => {
                self.stack.swap(5, 3)?;
                self.stack.swap(4, 2)?;
                self.stack.swap(3, 1)?;
                self.stack.swap(2, 0)?;
                Ok(())
            }

            x if x == OP_NIP.to_u8() => {
                self.stack.remove(-2)?;
                Ok(())
            }

            x if x == OP_OVER.to_u8() => {
                self.stack.dup(-2)?;
                Ok(())
            }

            x if x == OP_2OVER.to_u8() => {
                self.stack.dup(-4)?;
                self.stack.dup(-4)?;
                Ok(())
            }

            x if x == OP_PICK.to_u8() => {
                let n = self.stack.pop()?.to_i64()?;
                if n < 0 || n >= self.stack.len() as i64 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                self.stack.dup(-(n + 1) as isize)?;
                Ok(())
            }

            x if x == OP_ROLL.to_u8() => {
                let n = self.stack.pop()?.to_i64()?;
                if n < 0 || n >= self.stack.len() as i64 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let val = self.stack.remove(-(n + 1) as isize)?;
                self.stack.push(val)?;
                Ok(())
            }

            x if x == OP_TUCK.to_u8() => {
                self.stack.swap(0, 1)?;
                self.stack.dup(-1)?;
                Ok(())
            }

            // Splice operations (all disabled)
            x if x == OP_CAT.to_u8()
                || x == OP_SUBSTR.to_u8()
                || x == OP_LEFT.to_u8()
                || x == OP_RIGHT.to_u8() =>
            {
                Err(ScriptError::DisabledOpcode)
            }

            x if x == OP_SIZE.to_u8() => {
                let size = self.stack.top()?.len() as i64;
                self.stack.push_int(size)?;
                Ok(())
            }

            // Bitwise logic (all disabled except EQUAL)
            x if x == OP_INVERT.to_u8()
                || x == OP_AND.to_u8()
                || x == OP_OR.to_u8()
                || x == OP_XOR.to_u8() =>
            {
                Err(ScriptError::DisabledOpcode)
            }

            x if x == OP_EQUAL.to_u8() => {
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                self.stack.push_bool(a == b)?;
                Ok(())
            }

            x if x == OP_EQUALVERIFY.to_u8() => {
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                if a != b {
                    return Err(ScriptError::EqualVerify);
                }
                Ok(())
            }

            // Arithmetic operations
            x if x == OP_1ADD.to_u8() => {
                let n = self.stack.pop()?.to_i64()?;
                self.stack.push_int(n + 1)?;
                Ok(())
            }

            x if x == OP_1SUB.to_u8() => {
                let n = self.stack.pop()?.to_i64()?;
                self.stack.push_int(n - 1)?;
                Ok(())
            }

            x if x == OP_2MUL.to_u8() || x == OP_2DIV.to_u8() => Err(ScriptError::DisabledOpcode),

            x if x == OP_NEGATE.to_u8() => {
                let n = self.stack.pop()?.to_i64()?;
                self.stack.push_int(-n)?;
                Ok(())
            }

            x if x == OP_ABS.to_u8() => {
                let n = self.stack.pop()?.to_i64()?;
                self.stack.push_int(n.abs())?;
                Ok(())
            }

            x if x == OP_NOT.to_u8() => {
                let n = self.stack.pop()?.to_i64()?;
                self.stack.push_bool(n == 0)?;
                Ok(())
            }

            x if x == OP_0NOTEQUAL.to_u8() => {
                let n = self.stack.pop()?.to_i64()?;
                self.stack.push_bool(n != 0)?;
                Ok(())
            }

            x if x == OP_ADD.to_u8() => {
                let b = self.stack.pop()?.to_i64()?;
                let a = self.stack.pop()?.to_i64()?;
                self.stack.push_int(a + b)?;
                Ok(())
            }

            x if x == OP_SUB.to_u8() => {
                let b = self.stack.pop()?.to_i64()?;
                let a = self.stack.pop()?.to_i64()?;
                self.stack.push_int(a - b)?;
                Ok(())
            }

            x if x == OP_MUL.to_u8()
                || x == OP_DIV.to_u8()
                || x == OP_MOD.to_u8()
                || x == OP_LSHIFT.to_u8()
                || x == OP_RSHIFT.to_u8() =>
            {
                Err(ScriptError::DisabledOpcode)
            }

            x if x == OP_BOOLAND.to_u8() => {
                let b = self.stack.pop()?.to_bool();
                let a = self.stack.pop()?.to_bool();
                self.stack.push_bool(a && b)?;
                Ok(())
            }

            x if x == OP_BOOLOR.to_u8() => {
                let b = self.stack.pop()?.to_bool();
                let a = self.stack.pop()?.to_bool();
                self.stack.push_bool(a || b)?;
                Ok(())
            }

            x if x == OP_NUMEQUAL.to_u8() => {
                let b = self.stack.pop()?.to_i64()?;
                let a = self.stack.pop()?.to_i64()?;
                self.stack.push_bool(a == b)?;
                Ok(())
            }

            x if x == OP_NUMEQUALVERIFY.to_u8() => {
                let b = self.stack.pop()?.to_i64()?;
                let a = self.stack.pop()?.to_i64()?;
                if a != b {
                    return Err(ScriptError::NumEqualVerify);
                }
                Ok(())
            }

            x if x == OP_NUMNOTEQUAL.to_u8() => {
                let b = self.stack.pop()?.to_i64()?;
                let a = self.stack.pop()?.to_i64()?;
                self.stack.push_bool(a != b)?;
                Ok(())
            }

            x if x == OP_LESSTHAN.to_u8() => {
                let b = self.stack.pop()?.to_i64()?;
                let a = self.stack.pop()?.to_i64()?;
                self.stack.push_bool(a < b)?;
                Ok(())
            }

            x if x == OP_GREATERTHAN.to_u8() => {
                let b = self.stack.pop()?.to_i64()?;
                let a = self.stack.pop()?.to_i64()?;
                self.stack.push_bool(a > b)?;
                Ok(())
            }

            x if x == OP_LESSTHANOREQUAL.to_u8() => {
                let b = self.stack.pop()?.to_i64()?;
                let a = self.stack.pop()?.to_i64()?;
                self.stack.push_bool(a <= b)?;
                Ok(())
            }

            x if x == OP_GREATERTHANOREQUAL.to_u8() => {
                let b = self.stack.pop()?.to_i64()?;
                let a = self.stack.pop()?.to_i64()?;
                self.stack.push_bool(a >= b)?;
                Ok(())
            }

            x if x == OP_MIN.to_u8() => {
                let b = self.stack.pop()?.to_i64()?;
                let a = self.stack.pop()?.to_i64()?;
                self.stack.push_int(a.min(b))?;
                Ok(())
            }

            x if x == OP_MAX.to_u8() => {
                let b = self.stack.pop()?.to_i64()?;
                let a = self.stack.pop()?.to_i64()?;
                self.stack.push_int(a.max(b))?;
                Ok(())
            }

            x if x == OP_WITHIN.to_u8() => {
                let max = self.stack.pop()?.to_i64()?;
                let min = self.stack.pop()?.to_i64()?;
                let x = self.stack.pop()?.to_i64()?;
                self.stack.push_bool(min <= x && x < max)?;
                Ok(())
            }

            // Crypto operations
            x if x == OP_RIPEMD160.to_u8() => {
                let data = self.stack.pop()?;
                let hash = ripemd160::Hash::hash(&data);
                self.stack.push(hash.to_byte_array().to_vec())?;
                Ok(())
            }

            x if x == OP_SHA1.to_u8() => {
                // SHA1 is deprecated but still supported
                let data = self.stack.pop()?;
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(&data);
                let hash = hasher.finalize();
                self.stack.push(hash.to_vec())?;
                Ok(())
            }

            x if x == OP_SHA256.to_u8() => {
                let data = self.stack.pop()?;
                let hash = sha256::Hash::hash(&data);
                self.stack.push(hash.to_byte_array().to_vec())?;
                Ok(())
            }

            x if x == OP_HASH160.to_u8() => {
                let data = self.stack.pop()?;
                let hash = hash160::Hash::hash(&data);
                self.stack.push(hash.to_byte_array().to_vec())?;
                Ok(())
            }

            x if x == OP_HASH256.to_u8() => {
                let data = self.stack.pop()?;
                let hash = sha256d::Hash::hash(&data);
                self.stack.push(hash.to_byte_array().to_vec())?;
                Ok(())
            }

            // Signature verification
            x if x == OP_CHECKSIG.to_u8() => {
                let pubkey = self.stack.pop()?;
                let sig = self.stack.pop()?;

                let result = checker.check_sig(&sig, &pubkey, script_bytes, self.flags)?;
                self.stack.push_bool(result)?;
                Ok(())
            }

            x if x == OP_CHECKSIGVERIFY.to_u8() => {
                let pubkey = self.stack.pop()?;
                let sig = self.stack.pop()?;

                let result = checker.check_sig(&sig, &pubkey, script_bytes, self.flags)?;
                if !result {
                    return Err(ScriptError::CheckSigVerifyFailed);
                }
                Ok(())
            }

            x if x == OP_CHECKMULTISIG.to_u8() || x == OP_CHECKMULTISIGVERIFY.to_u8() => {
                // Get pubkey count
                let pubkey_count = self.stack.pop()?.to_i64()?;
                if !(0..=20).contains(&pubkey_count) {
                    return Err(ScriptError::PubKeyCount);
                }

                self.op_count += pubkey_count as usize;
                if self.op_count > MAX_OPS {
                    return Err(ScriptError::OpCount);
                }

                // Get pubkeys
                let mut pubkeys = Vec::new();
                for _ in 0..pubkey_count {
                    pubkeys.push(self.stack.pop()?);
                }

                // Get signature count
                let sig_count = self.stack.pop()?.to_i64()?;
                if sig_count < 0 || sig_count > pubkey_count {
                    return Err(ScriptError::SigCount);
                }

                // Get signatures
                let mut sigs = Vec::new();
                for _ in 0..sig_count {
                    sigs.push(self.stack.pop()?);
                }

                // Remove dummy value (due to bug in original implementation)
                let dummy = self.stack.pop()?;
                if self.flags.contains(ScriptFlags::NULLDUMMY) && !dummy.is_empty() {
                    return Err(ScriptError::NullDummy);
                }

                // Verify signatures
                let mut success = true;
                let mut sig_idx = 0;
                let mut key_idx = 0;

                while sig_idx < sigs.len() && success {
                    let sig = &sigs[sig_idx];

                    while key_idx < pubkeys.len() {
                        let pubkey = &pubkeys[key_idx];
                        key_idx += 1;

                        if checker.check_sig(sig, pubkey, script_bytes, self.flags)? {
                            sig_idx += 1;
                            break;
                        }
                    }

                    if sig_idx < sigs.len() && key_idx >= pubkeys.len() {
                        success = false;
                    }
                }

                if x == OP_CHECKMULTISIGVERIFY.to_u8() {
                    if !success {
                        return Err(ScriptError::CheckMultiSigVerifyFailed);
                    }
                } else {
                    self.stack.push_bool(success)?;
                }

                Ok(())
            }

            // Locktime operations
            x if x == OP_CLTV.to_u8() => {
                if !self.flags.contains(ScriptFlags::CHECKLOCKTIMEVERIFY) {
                    if self
                        .flags
                        .contains(ScriptFlags::DISCOURAGE_UPGRADEABLE_NOPS)
                    {
                        return Err(ScriptError::DiscourageUpgradeableNops);
                    }
                    return Ok(());
                }

                if self.stack.is_empty() {
                    return Err(ScriptError::InvalidStackOperation);
                }

                let locktime = self.stack.top()?.to_i64()?;
                if !checker.check_locktime(locktime)? {
                    return Err(ScriptError::UnsatisfiedLocktime);
                }

                Ok(())
            }

            x if x == OP_CSV.to_u8() => {
                if !self.flags.contains(ScriptFlags::CHECKSEQUENCEVERIFY) {
                    if self
                        .flags
                        .contains(ScriptFlags::DISCOURAGE_UPGRADEABLE_NOPS)
                    {
                        return Err(ScriptError::DiscourageUpgradeableNops);
                    }
                    return Ok(());
                }

                if self.stack.is_empty() {
                    return Err(ScriptError::InvalidStackOperation);
                }

                let sequence = self.stack.top()?.to_i64()?;
                if !checker.check_sequence(sequence)? {
                    return Err(ScriptError::UnsatisfiedLocktime);
                }

                Ok(())
            }

            // NOP operations
            x if x >= OP_NOP1.to_u8() && x <= OP_NOP10.to_u8() => {
                if self
                    .flags
                    .contains(ScriptFlags::DISCOURAGE_UPGRADEABLE_NOPS)
                {
                    return Err(ScriptError::DiscourageUpgradeableNops);
                }
                Ok(())
            }

            // Other operations
            x if x == OP_CODESEPARATOR.to_u8() => {
                // Updates script code position for signature verification
                *pc += 1;
                Ok(())
            }

            x if x == OP_DEPTH.to_u8() => {
                let depth = self.stack.len() as i64;
                self.stack.push_int(depth)?;
                Ok(())
            }

            x if x == OP_IFDUP.to_u8() => {
                if !self.stack.is_empty() && self.stack.top()?.to_bool() {
                    self.stack.dup(-1)?;
                }
                Ok(())
            }

            x if x == OP_VERIFY.to_u8() => {
                if self.stack.is_empty() || !self.stack.pop()?.to_bool() {
                    return Err(ScriptError::EvalFalse);
                }
                Ok(())
            }

            x if x == OP_RETURN.to_u8() => Err(ScriptError::OpReturn),

            _ => Err(ScriptError::BadOpcode),
        }
    }

    /// Push an item onto the stack
    pub fn push_stack(&mut self, item: Vec<u8>) -> ScriptResult<()> {
        self.stack.push(item)?;
        Ok(())
    }

    /// Pop an item from the stack
    pub fn pop_stack(&mut self) -> ScriptResult<Vec<u8>> {
        self.stack.pop()
    }

    /// Get the size of the stack
    pub fn stack_size(&self) -> usize {
        self.stack.len()
    }
}
