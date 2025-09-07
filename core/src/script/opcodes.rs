use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::opcodes::Opcode as BitcoinOpcode;
use bitcoin::Script;

/// Re-export Bitcoin opcodes
pub use bitcoin::blockdata::opcodes::all;

/// Opcode type for script execution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opcode(pub u8);

impl Opcode {
    /// Check if opcode is disabled
    pub fn is_disabled(&self) -> bool {
        matches!(self.0,
            x if x == OP_CAT.to_u8() ||
                 x == OP_SUBSTR.to_u8() ||
                 x == OP_LEFT.to_u8() ||
                 x == OP_RIGHT.to_u8() ||
                 x == OP_INVERT.to_u8() ||
                 x == OP_AND.to_u8() ||
                 x == OP_OR.to_u8() ||
                 x == OP_XOR.to_u8() ||
                 x == OP_2MUL.to_u8() ||
                 x == OP_2DIV.to_u8() ||
                 x == OP_MUL.to_u8() ||
                 x == OP_DIV.to_u8() ||
                 x == OP_MOD.to_u8() ||
                 x == OP_LSHIFT.to_u8() ||
                 x == OP_RSHIFT.to_u8()
        )
    }

    /// Check if opcode is a push operation
    pub fn is_push(&self) -> bool {
        self.0 <= OP_PUSHNUM_16.to_u8() || self.0 == OP_PUSHNUM_NEG1.to_u8()
    }

    /// Check if opcode is counted toward operation limit
    pub fn is_counted(&self) -> bool {
        self.0 > OP_PUSHNUM_16.to_u8()
    }

    /// Check if this is a conditional opcode
    pub fn is_conditional(&self) -> bool {
        matches!(self.0,
            x if x == OP_IF.to_u8() ||
                 x == OP_NOTIF.to_u8() ||
                 x == OP_ELSE.to_u8() ||
                 x == OP_ENDIF.to_u8()
        )
    }

    /// Check if this is an upgradeable NOP
    pub fn is_upgradeable_nop(&self) -> bool {
        self.0 >= OP_NOP1.to_u8() && self.0 <= OP_NOP10.to_u8()
    }

    /// Get push length for this opcode
    pub fn get_push_len(&self) -> Option<usize> {
        match self.0 {
            0x00..=0x4b => Some(self.0 as usize),
            0x4c => Some(1), // OP_PUSHDATA1
            0x4d => Some(2), // OP_PUSHDATA2
            0x4e => Some(4), // OP_PUSHDATA4
            _ => None,
        }
    }
}

impl From<u8> for Opcode {
    fn from(byte: u8) -> Self {
        Opcode(byte)
    }
}

impl From<BitcoinOpcode> for Opcode {
    fn from(op: BitcoinOpcode) -> Self {
        Opcode(op.to_u8())
    }
}

/// Check if a script contains only push operations
pub fn is_push_only(script: &Script) -> bool {
    for instruction in script.instructions() {
        match instruction {
            Ok(bitcoin::blockdata::script::Instruction::Op(op)) => {
                if op.to_u8() > OP_PUSHNUM_16.to_u8() {
                    return false;
                }
            }
            Ok(bitcoin::blockdata::script::Instruction::PushBytes(_)) => {
                // Push operations are allowed
            }
            Err(_) => return false,
        }
    }
    true
}

/// Count the number of signature operations in a script
pub fn count_sigops(script: &Script, accurate: bool) -> usize {
    let mut count = 0;
    let mut last_op: Option<BitcoinOpcode> = None;

    for instruction in script.instructions() {
        if let Ok(bitcoin::blockdata::script::Instruction::Op(op)) = instruction {
            match op {
                OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                    count += 1;
                }
                OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                    if accurate {
                        // If accurate, use the actual pubkey count
                        if let Some(last) = last_op {
                            if last.to_u8() >= OP_PUSHNUM_1.to_u8()
                                && last.to_u8() <= OP_PUSHNUM_16.to_u8()
                            {
                                count += (last.to_u8() - OP_PUSHNUM_1.to_u8() + 1) as usize;
                            } else if last == OP_PUSHNUM_NEG1 {
                                // -1 is treated as 0
                                // count += 0;
                            } else {
                                count += 20; // Default to maximum
                            }
                        } else {
                            count += 20; // Default to maximum
                        }
                    } else {
                        count += 20; // Always use maximum for non-accurate count
                    }
                }
                _ => {}
            }
            last_op = Some(op);
        } else {
            last_op = None;
        }
    }

    count
}

/// Count witness signature operations
pub fn count_witness_sigops(
    witness_version: u8,
    witness_program: &[u8],
    witness: &[Vec<u8>],
) -> usize {
    if witness_version == 0 {
        if witness_program.len() == 20 {
            // P2WPKH
            1
        } else if witness_program.len() == 32 {
            // P2WSH - need to count ops in witness script
            if let Some(script_bytes) = witness.last() {
                let script = Script::from_bytes(script_bytes);
                count_sigops(script, true)
            } else {
                0
            }
        } else {
            0
        }
    } else {
        // Future witness versions
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_properties() {
        let op = Opcode::from(OP_CHECKSIG);
        assert!(!op.is_push());
        assert!(op.is_counted());
        assert!(!op.is_conditional());

        let push_op = Opcode::from(0x05);
        assert!(push_op.is_push());
        assert!(!push_op.is_counted());
        assert_eq!(push_op.get_push_len(), Some(5));

        let disabled_op = Opcode::from(OP_CAT);
        assert!(disabled_op.is_disabled());

        let nop = Opcode::from(OP_NOP1);
        assert!(nop.is_upgradeable_nop());
    }

    #[test]
    fn test_count_sigops() {
        use bitcoin::blockdata::script::Builder;

        // Single CHECKSIG
        let script = Builder::new().push_opcode(OP_CHECKSIG).into_script();
        assert_eq!(count_sigops(&script, false), 1);

        // CHECKMULTISIG with 2-of-3
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_2)
            .push_opcode(OP_PUSHNUM_3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(count_sigops(&script, true), 3);
        assert_eq!(count_sigops(&script, false), 20);
    }
}
