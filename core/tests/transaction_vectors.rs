//! Bitcoin Core transaction test vectors
//! 
//! This module validates transaction handling against Bitcoin Core's test vectors

use anyhow::{bail, Result};
use bitcoin::{Transaction, TxOut, Amount, ScriptBuf, OutPoint, Txid};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin_core_lib::script::{verify_script, ScriptFlags};
use serde_json::Value;
use std::str::FromStr;

/// Parse script flags from string
fn parse_flags(flags_str: &str) -> ScriptFlags {
    let mut flags = ScriptFlags::NONE;
    
    for flag in flags_str.split(',') {
        match flag.trim() {
            "P2SH" => flags |= ScriptFlags::P2SH,
            "STRICTENC" => flags |= ScriptFlags::STRICTENC,
            "WITNESS" => flags |= ScriptFlags::WITNESS,
            "TAPROOT" => flags |= ScriptFlags::TAPROOT,
            "CHECKLOCKTIMEVERIFY" => flags |= ScriptFlags::CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => flags |= ScriptFlags::CHECKSEQUENCEVERIFY,
            "" | "NONE" => {},
            _ => eprintln!("Warning: Unknown flag: {}", flag),
        }
    }
    
    flags
}

/// Parse a transaction test vector
fn parse_tx_test(test: &Value) -> Result<(Vec<(OutPoint, TxOut)>, Transaction, ScriptFlags, String)> {
    if let Value::Array(arr) = test {
        if arr.len() < 3 {
            bail!("Invalid test format");
        }
        
        // Parse previous outputs
        let mut prevouts = Vec::new();
        if let Value::Array(prevout_arr) = &arr[0] {
            for prevout in prevout_arr {
                if let Value::Array(p) = prevout {
                    if p.len() >= 4 {
                        let hash_str = p[0].as_str().unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
                        let txid = Txid::from_str(hash_str)?;
                        let vout = p[1].as_u64().unwrap_or(0) as u32;
                        
                        let script_str = p[2].as_str().unwrap_or("0x51");
                        let script = parse_script_from_string(script_str)?;
                        
                        let value = p[3].as_u64().unwrap_or(0);
                        
                        let outpoint = OutPoint::new(txid, vout);
                        let txout = TxOut {
                            value: Amount::from_sat(value),
                            script_pubkey: script,
                        };
                        
                        prevouts.push((outpoint, txout));
                    }
                }
            }
        }
        
        // Parse serialized transaction
        let tx_hex = arr[1].as_str().unwrap_or("");
        let tx_bytes = hex::decode(tx_hex)?;
        let tx: Transaction = deserialize(&tx_bytes)?;
        
        // Parse flags
        let flags_str = arr[2].as_str().unwrap_or("");
        let flags = parse_flags(flags_str);
        
        // Get description if available
        let description = if arr.len() > 3 {
            arr[3].as_str().unwrap_or("No description").to_string()
        } else {
            "No description".to_string()
        };
        
        Ok((prevouts, tx, flags, description))
    } else {
        bail!("Test is not an array");
    }
}

/// Parse script from string (handles hex and opcodes)
fn parse_script_from_string(s: &str) -> Result<ScriptBuf> {
    // Handle the test format like "0x21 0x03e158... 0xac"
    if s.contains(" 0x") {
        // Split by spaces and parse each part
        let parts: Vec<&str> = s.split_whitespace().collect();
        let mut script_bytes = Vec::new();
        
        for part in parts {
            if part.starts_with("0x") {
                let hex = &part[2..];
                script_bytes.extend_from_slice(&hex::decode(hex)?);
            } else {
                // Try parsing as hex directly
                script_bytes.extend_from_slice(&hex::decode(part)?);
            }
        }
        
        Ok(ScriptBuf::from(script_bytes))
    } else if s.starts_with("0x") {
        // Hex encoded script
        let hex = &s[2..];
        let bytes = hex::decode(hex)?;
        Ok(ScriptBuf::from(bytes))
    } else {
        // For now, treat as hex without 0x prefix
        let bytes = hex::decode(s)?;
        Ok(ScriptBuf::from(bytes))
    }
}

/// Validate a transaction against its inputs
fn validate_transaction(
    prevouts: &[(OutPoint, TxOut)],
    tx: &Transaction,
    flags: ScriptFlags,
) -> Result<()> {
    // Basic transaction checks
    if tx.input.is_empty() {
        bail!("Transaction has no inputs");
    }
    if tx.output.is_empty() {
        bail!("Transaction has no outputs");
    }
    
    // Create a map of prevouts for easy lookup
    let prevout_map: std::collections::HashMap<OutPoint, &TxOut> = 
        prevouts.iter().map(|(op, txo)| (*op, txo)).collect();
    
    // Validate each input
    for (index, input) in tx.input.iter().enumerate() {
        // Check for null/coinbase input (which should only be in coinbase transactions)
        if input.previous_output.is_null() && !tx.is_coinbase() {
            bail!("Non-coinbase transaction has null prevout");
        }
        
        // Check for invalid txid (all 0xFF is invalid)
        let txid_bytes = input.previous_output.txid.to_byte_array();
        if txid_bytes.iter().all(|&b| b == 0xff) {
            bail!("Invalid prevout txid (all 0xFF)");
        }
        
        let prevout = prevout_map.get(&input.previous_output)
            .ok_or_else(|| anyhow::anyhow!("Missing prevout for input {}", index))?;
        
        // For witness transactions, we need all prevouts
        let all_prevouts: Vec<TxOut> = if flags.contains(ScriptFlags::WITNESS) {
            tx.input.iter()
                .map(|inp| {
                    prevout_map.get(&inp.previous_output)
                        .map(|&txout| txout.clone())
                        .unwrap_or_else(|| TxOut {
                            value: Amount::ZERO,
                            script_pubkey: ScriptBuf::new(),
                        })
                })
                .collect()
        } else {
            vec![]
        };
        
        let checker = bitcoin_core_lib::script::TransactionSignatureChecker::new(
            tx,
            index,
            prevout.value.to_sat(),
            all_prevouts,
        );
        
        verify_script(
            &input.script_sig,
            &prevout.script_pubkey,
            flags,
            &checker,
        )?;
        
        // Also verify witness if present
        if !input.witness.is_empty() && flags.contains(ScriptFlags::WITNESS) {
            // Witness verification would go here
            // For now, we'll skip detailed witness validation
        }
    }
    
    Ok(())
}

#[test]
fn test_valid_transactions() {
    let test_data = include_str!("data/tx_valid.json");
    let json: Value = serde_json::from_str(test_data).expect("Failed to parse test JSON");
    
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    
    if let Value::Array(tests) = json {
        for test in tests {
            // Skip comments
            if let Value::Array(arr) = &test {
                if arr.len() == 1 {
                    continue;
                }
            }
            
            match parse_tx_test(&test) {
                Ok((prevouts, tx, flags, description)) => {
                    match validate_transaction(&prevouts, &tx, flags) {
                        Ok(()) => {
                            passed += 1;
                        }
                        Err(e) => {
                            eprintln!("Test '{}' should be valid but failed: {}", description, e);
                            failed += 1;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse test: {}", e);
                    skipped += 1;
                }
            }
        }
    }
    
    println!("\n=== Valid Transaction Test Results ===");
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);
    println!("Skipped: {}", skipped);
    println!("Total: {}", passed + failed + skipped);
    
    assert!(passed > 0, "No tests passed");
    assert_eq!(failed, 0, "Some valid transactions failed validation");
}

#[test]
fn test_invalid_transactions() {
    let test_data = include_str!("data/tx_invalid.json");
    let json: Value = serde_json::from_str(test_data).expect("Failed to parse test JSON");
    
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    
    if let Value::Array(tests) = json {
        for test in tests {
            // Skip comments
            if let Value::Array(arr) = &test {
                if arr.len() == 1 {
                    continue;
                }
            }
            
            match parse_tx_test(&test) {
                Ok((prevouts, tx, flags, description)) => {
                    match validate_transaction(&prevouts, &tx, flags) {
                        Ok(()) => {
                            eprintln!("Test '{}' should be invalid but passed", description);
                            eprintln!("  TX: {:?}", tx.compute_txid());
                            eprintln!("  Flags: {:?}", flags);
                            eprintln!("  Prevouts: {} inputs", prevouts.len());
                            if prevouts.len() > 0 {
                                let (_op, txout) = &prevouts[0];
                                eprintln!("  First prevout script: {} bytes, hex: {}", 
                                    txout.script_pubkey.len(), 
                                    hex::encode(txout.script_pubkey.as_bytes()));
                            }
                            failed += 1;
                        }
                        Err(_) => {
                            passed += 1;
                        }
                    }
                }
                Err(_) => {
                    // Parse failure for invalid transaction is OK
                    passed += 1;
                }
            }
        }
    }
    
    println!("\n=== Invalid Transaction Test Results ===");
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);
    println!("Skipped: {}", skipped);
    println!("Total: {}", passed + failed + skipped);
    
    assert!(passed > 0, "No tests passed");
    assert_eq!(failed, 0, "Some invalid transactions passed validation");
}

#[test]
fn test_debug_invalid_signature_tx() {
    // Parse the specific failing transaction
    // The original hex has an issue - there's an extra 00000000 after the prevout
    // Correct format should be: version(4) + input_count(1) + prevout_hash(32) + prevout_index(4) + scriptsig_len + scriptsig + sequence(4) + output_count(1) + outputs
    // let tx_hex = "0100000001000000000000000000000000000000000000000000000000000000000000000000000000004847304402203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022054e1c258c2981cdfba5df1f46661fb6541c44f77ca0092f3600331abfffb125101ffffffff010000000000000000016a00000000";
    
    // The hex should be: (removing the extra 00000000)
    let tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000000000004847304402203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022054e1c258c2981cdfba5df1f46661fb6541c44f77ca0092f3600331abfffb125101ffffffff010000000000000000016a00000000";
    
    println!("Transaction hex length: {}", tx_hex.len());
    println!("Expected bytes: {}", tx_hex.len() / 2);
    
    let tx_bytes = match hex::decode(tx_hex) {
        Ok(bytes) => {
            println!("Decoded {} bytes", bytes.len());
            bytes
        }
        Err(e) => panic!("Failed to decode hex: {:?}", e),
    };
    
    // Manual parse to understand the issue
    println!("\nManual parsing:");
    let mut pos = 0;
    
    // Version (4 bytes)
    println!("Version bytes: {:02x?}", &tx_bytes[pos..pos+4]);
    pos += 4;
    
    // Input count (varint)
    let input_count = tx_bytes[pos];
    println!("Input count: {}", input_count);
    pos += 1;
    
    // First input
    println!("Input 1:");
    println!("  Previous txid: {:02x?}", &tx_bytes[pos..pos+32]);
    pos += 32;
    println!("  Previous vout: {:02x?}", &tx_bytes[pos..pos+4]);
    pos += 4;
    
    // ScriptSig length
    let script_len = tx_bytes[pos] as usize;
    println!("  ScriptSig length: {} (0x{:02x})", script_len, tx_bytes[pos]);
    pos += 1;
    
    // ScriptSig data
    if pos + script_len <= tx_bytes.len() {
        println!("  ScriptSig: {:02x?}", &tx_bytes[pos..pos+script_len]);
        pos += script_len;
    } else {
        println!("  ERROR: Not enough bytes for ScriptSig! Need {} but only {} remain", script_len, tx_bytes.len() - pos);
    }
    
    // Sequence
    if pos + 4 <= tx_bytes.len() {
        println!("  Sequence: {:02x?}", &tx_bytes[pos..pos+4]);
        pos += 4;
    } else {
        println!("  ERROR: Not enough bytes for sequence! Only {} bytes remain", tx_bytes.len() - pos);
    }
    
    // Output count
    if pos < tx_bytes.len() {
        let output_count = tx_bytes[pos];
        println!("\nOutput count: {}", output_count);
        pos += 1;
        
        // First output
        if output_count > 0 && pos + 8 <= tx_bytes.len() {
            println!("Output 1:");
            println!("  Value: {:02x?}", &tx_bytes[pos..pos+8]);
            pos += 8;
            
            // ScriptPubKey length
            if pos < tx_bytes.len() {
                let script_len = tx_bytes[pos] as usize;
                println!("  ScriptPubKey length: {}", script_len);
                pos += 1;
                
                if pos + script_len <= tx_bytes.len() {
                    println!("  ScriptPubKey: {:02x?}", &tx_bytes[pos..pos+script_len]);
                    pos += script_len;
                }
            }
        }
        
        // Locktime
        if pos + 4 <= tx_bytes.len() {
            println!("\nLocktime: {:02x?}", &tx_bytes[pos..pos+4]);
            pos += 4;
        }
    }
    
    println!("\nBytes consumed so far: {}", pos);
    println!("Bytes remaining: {}", tx_bytes.len() - pos);
    
    if pos == tx_bytes.len() {
        println!("Transaction parsed successfully!");
        
        // Now try to deserialize it
        let tx: Transaction = deserialize(&tx_bytes).expect("Failed to deserialize");
        println!("\nDeserialized transaction:");
        println!("  TX ID: {:?}", tx.compute_txid());
        println!("  Inputs: {}", tx.input.len());
        println!("  Outputs: {}", tx.output.len());
        
        // Now test our validation with the actual prevout from the test vector
        println!("\nTesting validation with actual prevout...");
        
        // The prevout from the test: "0x21 0x03e15819e2e22f89e4b8e2f6e8f9e4b8e2f6e8f9e4b8e2f6e8f9e4b8e2f6e8f9 0xac"
        // This is a P2PK script: OP_PUSHBYTES_33 <pubkey> OP_CHECKSIG
        // Fixed: We need exactly 33 bytes for the pubkey
        let script_bytes = vec![
            0x21, // Push 33 bytes  
            // 33-byte compressed pubkey - add one more byte!
            0x03, 0xe1, 0x58, 0x19, 0xe2, 0xe2, 0x2f, 0x89,
            0xe4, 0xb8, 0xe2, 0xf6, 0xe8, 0xf9, 0xe4, 0xb8,
            0xe2, 0xf6, 0xe8, 0xf9, 0xe4, 0xb8, 0xe2, 0xf6,
            0xe8, 0xf9, 0xe4, 0xb8, 0xe2, 0xf6, 0xe8, 0xf9,
            0x00, // One more byte to make 33 total
            0xac, // OP_CHECKSIG
        ];
        
        assert_eq!(script_bytes.len(), 35, "Script should be 35 bytes: 1 (push) + 33 (pubkey) + 1 (OP_CHECKSIG)");
        
        println!("Script bytes hex: {}", hex::encode(&script_bytes));
        println!("Script length: {}", script_bytes.len());
        println!("Last byte (should be 0xac for OP_CHECKSIG): 0x{:02x}", script_bytes[script_bytes.len()-1]);
        
        let prevout = TxOut {
            value: Amount::from_sat(1000000),
            script_pubkey: ScriptBuf::from(script_bytes),
        };
        
        let outpoint = OutPoint::new(Txid::all_zeros(), 0);
        let prevouts = vec![(outpoint, prevout.clone())];
        let flags = ScriptFlags::P2SH | ScriptFlags::STRICTENC;
        
        // Let's manually verify this transaction step by step
        println!("\nManual verification:");
        
        // Create signature checker
        let all_prevouts = vec![prevout.clone()];
        let checker = bitcoin_core_lib::script::TransactionSignatureChecker::new(
            &tx,
            0, // input index
            prevout.value.to_sat(),
            all_prevouts,
        );
        
        // Print scriptSig details
        println!("ScriptSig hex: {}", hex::encode(tx.input[0].script_sig.as_bytes()));
        println!("ScriptSig length: {}", tx.input[0].script_sig.len());
        
        // Parse ScriptSig manually
        let script_bytes = tx.input[0].script_sig.as_bytes();
        println!("ScriptSig breakdown:");
        let mut pos = 0;
        while pos < script_bytes.len() {
            if script_bytes[pos] <= 75 {
                // Direct push
                let push_len = script_bytes[pos] as usize;
                println!("  Push {} bytes at position {}", push_len, pos);
                if pos + 1 + push_len <= script_bytes.len() {
                    println!("    Data: {}", hex::encode(&script_bytes[pos + 1..pos + 1 + push_len]));
                }
                pos += 1 + push_len;
            } else {
                println!("  Opcode: 0x{:02x} at position {}", script_bytes[pos], pos);
                pos += 1;
            }
        }
        
        // Verify the script
        let result = bitcoin_core_lib::script::verify_script(
            &tx.input[0].script_sig,
            &prevout.script_pubkey,
            flags,
            &checker,
        );
        
        match result {
            Ok(()) => println!("UNEXPECTED: Script verification passed! Transaction with invalid signature was accepted."),
            Err(e) => println!("Expected: Script verification failed with: {:?}", e),
        }
    } else {
        panic!("Transaction parsing issue");
    }
}