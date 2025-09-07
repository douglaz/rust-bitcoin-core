pub mod error;
pub mod flags;
pub mod interpreter;
pub mod opcodes;
pub mod signature;
pub mod stack;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_bip112;

#[cfg(test)]
mod test_vectors;

pub use error::{ScriptError, ScriptResult};
pub use flags::ScriptFlags;
pub use interpreter::ScriptInterpreter;
pub use opcodes::{is_push_only, Opcode};
pub use signature::{SignatureChecker, TransactionSignatureChecker};
pub use stack::{Stack, StackItem};

use bitcoin::{Script, Transaction};
use tracing::debug;

/// Count signature operations in a script
pub fn count_sigops(script: &Script, accurate: bool) -> usize {
    use bitcoin::blockdata::opcodes::all::*;

    let mut sigops = 0;
    let mut pc = 0;
    let script_bytes = script.as_bytes();

    while pc < script_bytes.len() {
        let opcode = script_bytes[pc];
        pc += 1;

        // Handle push operations
        if opcode <= OP_PUSHDATA4.to_u8() {
            let push_len = if opcode < OP_PUSHDATA1.to_u8() {
                opcode as usize
            } else if opcode == OP_PUSHDATA1.to_u8() && pc < script_bytes.len() {
                let len = script_bytes[pc] as usize;
                pc += 1;
                len
            } else if opcode == OP_PUSHDATA2.to_u8() && pc + 1 < script_bytes.len() {
                let len = u16::from_le_bytes([script_bytes[pc], script_bytes[pc + 1]]) as usize;
                pc += 2;
                len
            } else if opcode == OP_PUSHDATA4.to_u8() && pc + 3 < script_bytes.len() {
                let len = u32::from_le_bytes([
                    script_bytes[pc],
                    script_bytes[pc + 1],
                    script_bytes[pc + 2],
                    script_bytes[pc + 3],
                ]) as usize;
                pc += 4;
                len
            } else {
                break;
            };

            // Skip the pushed data
            pc = pc.saturating_add(push_len);
            if pc > script_bytes.len() {
                break;
            }
        } else if opcode == OP_CHECKSIG.to_u8() || opcode == OP_CHECKSIGVERIFY.to_u8() {
            sigops += 1;
        } else if opcode == OP_CHECKMULTISIG.to_u8() || opcode == OP_CHECKMULTISIGVERIFY.to_u8() {
            if accurate && pc >= 2 {
                // Look back for the number of pubkeys if accurate counting
                let prev_op = script_bytes[pc - 2];
                if prev_op >= OP_PUSHNUM_1.to_u8() && prev_op <= OP_PUSHNUM_16.to_u8() {
                    sigops += (prev_op - OP_PUSHNUM_1.to_u8() + 1) as usize;
                } else {
                    sigops += 20; // Default maximum
                }
            } else {
                sigops += 20; // Conservative maximum
            }
        }
    }

    sigops
}

/// Count signature operations in a transaction
pub fn count_transaction_sigops(
    tx: &Transaction,
    utxo_scripts: &[bitcoin::ScriptBuf],
    flags: ScriptFlags,
) -> usize {
    let mut total_sigops = 0;

    for (index, input) in tx.input.iter().enumerate() {
        // Count sigops in input script
        total_sigops += count_sigops(&input.script_sig, false);

        // For P2SH, count sigops in the redeemed script
        if flags.contains(ScriptFlags::P2SH) && index < utxo_scripts.len() {
            let prev_script = &utxo_scripts[index];
            if prev_script.is_p2sh() {
                // Extract the serialized script from the last push in script_sig
                if let Some(redeem_script) = extract_p2sh_redeem_script(&input.script_sig) {
                    total_sigops += count_sigops(&redeem_script, true);
                }
            }
        }
    }

    // Count witness sigops for SegWit transactions
    if flags.contains(ScriptFlags::WITNESS) {
        for (index, input) in tx.input.iter().enumerate() {
            if !input.witness.is_empty() && index < utxo_scripts.len() {
                let prev_script = &utxo_scripts[index];

                // Check for witness programs
                if prev_script.is_p2wpkh() {
                    total_sigops += 1; // P2WPKH always has 1 sigop
                } else if prev_script.is_p2wsh() {
                    // P2WSH: count sigops in witness script (last item)
                    if let Some(witness_script_bytes) = input.witness.last() {
                        let witness_script =
                            bitcoin::ScriptBuf::from(witness_script_bytes.to_vec());
                        total_sigops += count_sigops(&witness_script, true);
                    }
                } else if prev_script.is_p2sh() && !input.witness.is_empty() {
                    // P2SH-wrapped witness
                    if let Some(redeem_script) = extract_p2sh_redeem_script(&input.script_sig) {
                        if redeem_script.is_p2wpkh() {
                            total_sigops += 1;
                        } else if redeem_script.is_p2wsh() {
                            if let Some(witness_script_bytes) = input.witness.last() {
                                let witness_script =
                                    bitcoin::ScriptBuf::from(witness_script_bytes.to_vec());
                                total_sigops += count_sigops(&witness_script, true);
                            }
                        }
                    }
                }
            }
        }
    }

    total_sigops
}

/// Extract P2SH redeem script from script_sig
fn extract_p2sh_redeem_script(script_sig: &bitcoin::Script) -> Option<bitcoin::ScriptBuf> {
    let bytes = script_sig.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    // Find the last push operation
    let mut last_push_start = None;
    let mut last_push_len = 0;
    let mut pc = 0;

    while pc < bytes.len() {
        let opcode = bytes[pc];
        pc += 1;

        if opcode <= bitcoin::blockdata::opcodes::all::OP_PUSHDATA4.to_u8() {
            let (push_start, push_len) = if opcode
                < bitcoin::blockdata::opcodes::all::OP_PUSHDATA1.to_u8()
            {
                (pc, opcode as usize)
            } else if opcode == bitcoin::blockdata::opcodes::all::OP_PUSHDATA1.to_u8()
                && pc < bytes.len()
            {
                let len = bytes[pc] as usize;
                pc += 1;
                (pc, len)
            } else if opcode == bitcoin::blockdata::opcodes::all::OP_PUSHDATA2.to_u8()
                && pc + 1 < bytes.len()
            {
                let len = u16::from_le_bytes([bytes[pc], bytes[pc + 1]]) as usize;
                pc += 2;
                (pc, len)
            } else if opcode == bitcoin::blockdata::opcodes::all::OP_PUSHDATA4.to_u8()
                && pc + 3 < bytes.len()
            {
                let len =
                    u32::from_le_bytes([bytes[pc], bytes[pc + 1], bytes[pc + 2], bytes[pc + 3]])
                        as usize;
                pc += 4;
                (pc, len)
            } else {
                break;
            };

            if pc + push_len <= bytes.len() {
                last_push_start = Some(push_start);
                last_push_len = push_len;
                pc += push_len;
            } else {
                break;
            }
        }
    }

    // Extract the last pushed data as the redeem script
    if let Some(start) = last_push_start {
        if start + last_push_len <= bytes.len() {
            let script_bytes = &bytes[start..start + last_push_len];
            return Some(bitcoin::ScriptBuf::from(script_bytes.to_vec()));
        }
    }

    None
}

/// Verify a script execution
pub fn verify_script(
    script_sig: &Script,
    script_pubkey: &Script,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> ScriptResult<()> {
    let mut interpreter = ScriptInterpreter::new(flags);

    // Execute scriptSig
    interpreter.execute(script_sig, checker)?;

    // Copy stack to altstack for P2SH
    let stack_copy = interpreter.stack.clone();

    // Execute scriptPubKey
    interpreter.execute(script_pubkey, checker)?;

    // Check if the execution was successful
    if interpreter.stack.is_empty() || !interpreter.stack.top()?.to_bool() {
        return Err(ScriptError::EvalFalse);
    }

    // Additional P2SH validation if needed
    if flags.contains(ScriptFlags::P2SH) && script_pubkey.is_p2sh() {
        if !script_sig.is_push_only() {
            return Err(ScriptError::SigPushOnly);
        }

        // The stack cannot be empty at this point
        if stack_copy.is_empty() {
            return Err(ScriptError::EvalFalse);
        }

        // Deserialize the P2SH script - clone the top item first
        let top_item = stack_copy.top()?.clone();
        let redeem_script = Script::from_bytes(&top_item);
        interpreter.stack = stack_copy;
        interpreter.stack.pop()?;

        // Execute the redeem script
        interpreter.execute(redeem_script, checker)?;

        if interpreter.stack.is_empty() || !interpreter.stack.top()?.to_bool() {
            return Err(ScriptError::EvalFalse);
        }
    }

    // Check for clean stack if required
    if flags.contains(ScriptFlags::CLEANSTACK) && interpreter.stack.len() != 1 {
        return Err(ScriptError::CleanStack);
    }

    Ok(())
}

/// Verify witness program execution
pub fn verify_witness_program(
    witness: &[Vec<u8>],
    witness_version: u8,
    witness_program: &[u8],
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> ScriptResult<()> {
    if witness_version == 0 {
        if witness_program.len() == 20 {
            // P2WPKH
            if witness.len() != 2 {
                return Err(ScriptError::WitnessProgramMismatch);
            }

            // Build P2PKH script - witness_program is exactly 20 bytes for P2WPKH
            let mut script_bytes = Vec::new();
            script_bytes.push(bitcoin::blockdata::opcodes::all::OP_DUP.to_u8());
            script_bytes.push(bitcoin::blockdata::opcodes::all::OP_HASH160.to_u8());
            script_bytes.push(20u8); // Push 20 bytes
            script_bytes.extend_from_slice(witness_program);
            script_bytes.push(bitcoin::blockdata::opcodes::all::OP_EQUALVERIFY.to_u8());
            script_bytes.push(bitcoin::blockdata::opcodes::all::OP_CHECKSIG.to_u8());
            let script = Script::from_bytes(&script_bytes);

            let mut interpreter = ScriptInterpreter::new(flags);
            interpreter.stack.push_vec(witness[0].clone())?;
            interpreter.stack.push_vec(witness[1].clone())?;
            interpreter.execute(script, checker)?;

            if interpreter.stack.is_empty() || !interpreter.stack.top()?.to_bool() {
                return Err(ScriptError::EvalFalse);
            }
        } else if witness_program.len() == 32 {
            // P2WSH
            if witness.is_empty() {
                return Err(ScriptError::WitnessProgramEmpty);
            }

            let script_bytes = &witness[witness.len() - 1];
            let script = Script::from_bytes(script_bytes);

            // Verify script hash matches
            use bitcoin::hashes::{sha256, Hash};
            let script_hash = sha256::Hash::hash(script.as_bytes());
            if script_hash.as_byte_array() != witness_program {
                return Err(ScriptError::WitnessProgramMismatch);
            }

            let mut interpreter = ScriptInterpreter::new(flags);
            for item in &witness[..witness.len() - 1] {
                interpreter.stack.push_vec(item.clone())?;
            }
            interpreter.execute(script, checker)?;

            if interpreter.stack.is_empty() || !interpreter.stack.top()?.to_bool() {
                return Err(ScriptError::EvalFalse);
            }
        } else {
            return Err(ScriptError::WitnessProgramWrongLength);
        }
    } else if witness_version == 1 && witness_program.len() == 32 {
        // Taproot (P2TR) validation
        if !flags.contains(ScriptFlags::TAPROOT) {
            return Err(ScriptError::DiscourageUpgradeableWitnessProgram);
        }

        // Verify the witness program is a valid X-only public key
        let _output_key = bitcoin::XOnlyPublicKey::from_slice(witness_program)
            .map_err(|_| ScriptError::InvalidTaprootKey)?;

        // Basic taproot validation - check witness stack structure
        if witness.is_empty() {
            return Err(ScriptError::WitnessProgramEmpty);
        }

        let stack_len = witness.len();

        // Key path spend: 1 or 2 elements (signature + optional annex)
        // Script path spend: at least 2 elements (script inputs + script + control block + optional annex)
        if stack_len == 1 {
            // Key path spend with just signature
            let sig_bytes = witness.last().unwrap();
            if sig_bytes.len() != 64 && sig_bytes.len() != 65 {
                return Err(ScriptError::TaprootValidation);
            }
        } else if stack_len >= 2 {
            // Could be key path with annex or script path spend
            let last = witness.last().unwrap();

            // Check if last element might be an annex (starts with 0x50)
            if last.starts_with(&[0x50]) && stack_len == 2 {
                // Key path with annex
                let sig_bytes = &witness[0];
                if sig_bytes.len() != 64 && sig_bytes.len() != 65 {
                    return Err(ScriptError::TaprootValidation);
                }
            } else {
                // Script path spend - control block should be at least 33 bytes
                let control_block = &witness[stack_len - 1];
                if control_block.len() < 33 {
                    return Err(ScriptError::TaprootValidation);
                }

                // First byte of control block contains leaf version and parity bit
                let first_byte = control_block[0];
                let _leaf_version = first_byte & 0xFE;

                // Rest should be internal key (32 bytes) and optional merkle path
                let remaining = control_block.len() - 1;
                if remaining < 32 || (remaining - 32) % 32 != 0 {
                    return Err(ScriptError::TaprootValidation);
                }
            }
        }

        // TODO: Full taproot validation would require access to transaction context
        // For now, we accept structurally valid taproot witnesses
        debug!("Taproot witness validation passed (basic checks)");

        return Ok(());
    } else {
        // Unknown witness version
        if flags.contains(ScriptFlags::DISCOURAGE_UPGRADEABLE_WITNESS_PROGRAM) {
            return Err(ScriptError::DiscourageUpgradeableWitnessProgram);
        }
    }

    Ok(())
}
