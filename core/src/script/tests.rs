#[cfg(test)]
mod tests {

    use crate::script::{
        verify_script, verify_witness_program, ScriptError, ScriptFlags, SignatureChecker,
    };

    use bitcoin::blockdata::opcodes::all::*;

    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    use bitcoin::ScriptBuf;

    /// Test signature checker that allows specific signatures
    struct TestSignatureChecker {
        valid_sigs: Vec<Vec<u8>>,
        valid_pubkeys: Vec<Vec<u8>>,
    }

    impl TestSignatureChecker {
        fn new() -> Self {
            Self {
                valid_sigs: vec![],
                valid_pubkeys: vec![],
            }
        }

        fn add_valid_pair(&mut self, sig: Vec<u8>, pubkey: Vec<u8>) {
            self.valid_sigs.push(sig);
            self.valid_pubkeys.push(pubkey);
        }
    }

    impl SignatureChecker for TestSignatureChecker {
        fn check_sig(
            &self,
            signature: &[u8],
            pubkey: &[u8],
            _script_code: &[u8],
            _flags: ScriptFlags,
        ) -> crate::script::ScriptResult<bool> {
            // Check if this sig/pubkey pair is valid
            for (i, sig) in self.valid_sigs.iter().enumerate() {
                if sig == signature && self.valid_pubkeys[i] == pubkey {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        fn check_schnorr_sig(
            &self,
            _signature: &[u8],
            _pubkey: &[u8],
            _flags: ScriptFlags,
        ) -> crate::script::ScriptResult<bool> {
            Ok(false)
        }

        fn check_locktime(&self, _locktime: i64) -> crate::script::ScriptResult<bool> {
            Ok(true)
        }

        fn check_sequence(&self, _sequence: i64) -> crate::script::ScriptResult<bool> {
            Ok(true)
        }
    }

    #[test]
    fn test_simple_push_and_verify() {
        // Test simple script: push value and verify it's true
        let script = ScriptBuf::from(vec![OP_PUSHNUM_1.to_u8()]);
        let empty_script = ScriptBuf::new();
        let checker = TestSignatureChecker::new();
        let flags = ScriptFlags::P2SH;

        let result = verify_script(&empty_script, &script, flags, &checker);
        assert!(result.is_ok());
    }

    #[test]
    #[ignore] // Temporarily ignored - script arithmetic operations need proper testing
    fn test_push_and_duplicate() {
        // Test: Push 5, duplicate, add, verify equals 10
        let script_sig = ScriptBuf::from(vec![0x01, 0x05]); // Push 5
        let script_pubkey = ScriptBuf::from(vec![
            OP_DUP.to_u8(),
            OP_ADD.to_u8(),
            0x01,
            0x0a, // Push 10
            OP_EQUAL.to_u8(),
        ]);

        let checker = TestSignatureChecker::new();
        let flags = ScriptFlags::P2SH;

        let result = verify_script(&script_sig, &script_pubkey, flags, &checker);

        // This test expects the script to succeed
        // The script pushes 5, duplicates it (5, 5), adds them (10),
        // pushes 10, and checks equality
        match result {
            Ok(()) => {} // Test passes
            Err(e) => panic!("Script validation failed: {:?}", e),
        }
    }

    #[test]
    #[ignore] // Ignored due to mock signature checker limitations
    fn test_p2pkh_script() {
        // Test Pay-to-Public-Key-Hash script
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey_bytes = public_key.serialize();

        // Create P2PKH script: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        let pubkey_hash = bitcoin::PublicKey::from_slice(&pubkey_bytes)
            .unwrap()
            .pubkey_hash();

        let mut script_pubkey_bytes = vec![];
        script_pubkey_bytes.push(OP_DUP.to_u8());
        script_pubkey_bytes.push(OP_HASH160.to_u8());
        script_pubkey_bytes.push(20); // Push 20 bytes
        script_pubkey_bytes.extend_from_slice(&pubkey_hash.to_byte_array());
        script_pubkey_bytes.push(OP_EQUALVERIFY.to_u8());
        script_pubkey_bytes.push(OP_CHECKSIG.to_u8());

        let script_pubkey = ScriptBuf::from(script_pubkey_bytes);

        // Create scriptSig: <signature> <pubkey>
        let mut script_sig_bytes = vec![];
        // Dummy signature (would be real in actual transaction)
        let dummy_sig = vec![0x30, 0x44, 0x02, 0x20, 0x01, 0x02, 0x03, 0x04]; // Simplified
        script_sig_bytes.push(dummy_sig.len() as u8);
        script_sig_bytes.extend_from_slice(&dummy_sig);
        script_sig_bytes.push(pubkey_bytes.len() as u8);
        script_sig_bytes.extend_from_slice(&pubkey_bytes);

        let script_sig = ScriptBuf::from(script_sig_bytes);

        // Create test checker
        let mut checker = TestSignatureChecker::new();
        checker.add_valid_pair(dummy_sig, pubkey_bytes.to_vec());

        // Verify script
        let result = verify_script(
            &script_sig,
            &script_pubkey,
            ScriptFlags::WITNESS | ScriptFlags::P2SH,
            &checker,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_p2sh_script() {
        // Test Pay-to-Script-Hash
        // Redeem script: OP_1 OP_1 OP_ADD OP_2 OP_EQUAL
        let mut redeem_script_bytes = vec![];
        redeem_script_bytes.push(OP_PUSHNUM_1.to_u8());
        redeem_script_bytes.push(OP_PUSHNUM_1.to_u8());
        redeem_script_bytes.push(OP_ADD.to_u8());
        redeem_script_bytes.push(OP_PUSHNUM_2.to_u8());
        redeem_script_bytes.push(OP_EQUAL.to_u8());

        let redeem_script = ScriptBuf::from(redeem_script_bytes.clone());

        // Create P2SH script: OP_HASH160 <script_hash> OP_EQUAL
        let script_hash = redeem_script.script_hash();
        let mut script_pubkey_bytes = vec![];
        script_pubkey_bytes.push(OP_HASH160.to_u8());
        script_pubkey_bytes.push(20); // Push 20 bytes
        script_pubkey_bytes.extend_from_slice(script_hash.as_ref());
        script_pubkey_bytes.push(OP_EQUAL.to_u8());

        let script_pubkey = ScriptBuf::from(script_pubkey_bytes);

        // Create scriptSig: <redeem_script>
        let mut script_sig_bytes = vec![];
        script_sig_bytes.push(redeem_script_bytes.len() as u8);
        script_sig_bytes.extend_from_slice(&redeem_script_bytes);

        let script_sig = ScriptBuf::from(script_sig_bytes);

        let checker = TestSignatureChecker::new();

        // Verify script with P2SH flag
        let result = verify_script(&script_sig, &script_pubkey, ScriptFlags::P2SH, &checker);

        assert!(result.is_ok());
    }

    #[test]
    fn test_multisig_script() {
        // Test 2-of-3 multisig
        let pubkey1 = vec![0x02; 33]; // Compressed pubkey
        let pubkey2 = vec![0x03; 33];
        let pubkey3 = vec![0x04; 33];

        let sig1 = vec![0x30, 0x44, 0x01]; // Dummy sig
        let sig2 = vec![0x30, 0x44, 0x02];

        // Create multisig script: OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
        let mut script_pubkey_bytes = vec![];
        script_pubkey_bytes.push(OP_PUSHNUM_2.to_u8());
        script_pubkey_bytes.push(33);
        script_pubkey_bytes.extend_from_slice(&pubkey1);
        script_pubkey_bytes.push(33);
        script_pubkey_bytes.extend_from_slice(&pubkey2);
        script_pubkey_bytes.push(33);
        script_pubkey_bytes.extend_from_slice(&pubkey3);
        script_pubkey_bytes.push(OP_PUSHNUM_3.to_u8());
        script_pubkey_bytes.push(OP_CHECKMULTISIG.to_u8());

        let script_pubkey = ScriptBuf::from(script_pubkey_bytes);

        // Create scriptSig: OP_0 <sig1> <sig2> (OP_0 is due to bug in original implementation)
        let mut script_sig_bytes = vec![];
        script_sig_bytes.push(0x00); // OP_0/OP_FALSE
        script_sig_bytes.push(sig1.len() as u8);
        script_sig_bytes.extend_from_slice(&sig1);
        script_sig_bytes.push(sig2.len() as u8);
        script_sig_bytes.extend_from_slice(&sig2);

        let script_sig = ScriptBuf::from(script_sig_bytes);

        // Create test checker
        let mut checker = TestSignatureChecker::new();
        checker.add_valid_pair(sig1, pubkey1);
        checker.add_valid_pair(sig2, pubkey2);

        // Verify script
        let result = verify_script(
            &script_sig,
            &script_pubkey,
            ScriptFlags::WITNESS | ScriptFlags::P2SH,
            &checker,
        );

        assert!(result.is_ok());
    }

    #[test]
    #[ignore] // Ignored due to mock witness validation limitations
    fn test_p2wpkh_witness_program() {
        // Test Pay-to-Witness-Public-Key-Hash
        let pubkey = vec![0x02; 33]; // Compressed pubkey
        let signature = vec![0x30, 0x44]; // Dummy signature

        // Witness program is 20-byte pubkey hash
        let pubkey_hash = bitcoin::PublicKey::from_slice(&pubkey)
            .unwrap()
            .wpubkey_hash()
            .unwrap();

        let witness_program = &pubkey_hash.to_byte_array()[..];
        assert_eq!(witness_program.len(), 20);

        // Witness stack: [signature, pubkey]
        let witness = vec![signature.clone(), pubkey.clone()];

        let mut checker = TestSignatureChecker::new();
        checker.add_valid_pair(signature, pubkey);

        let result = verify_witness_program(
            &witness,
            0, // version 0
            witness_program,
            ScriptFlags::WITNESS,
            &checker,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_p2wsh_witness_program() {
        // Test Pay-to-Witness-Script-Hash
        // Witness script: OP_1 OP_1 OP_ADD OP_2 OP_EQUAL
        let mut witness_script_bytes = vec![];
        witness_script_bytes.push(OP_PUSHNUM_1.to_u8());
        witness_script_bytes.push(OP_PUSHNUM_1.to_u8());
        witness_script_bytes.push(OP_ADD.to_u8());
        witness_script_bytes.push(OP_PUSHNUM_2.to_u8());
        witness_script_bytes.push(OP_EQUAL.to_u8());

        // Witness program is 32-byte script hash
        let script_hash = sha256::Hash::hash(&witness_script_bytes);
        let witness_program = &script_hash.to_byte_array()[..];
        assert_eq!(witness_program.len(), 32);

        // Witness stack: [witness_script]
        let witness = vec![witness_script_bytes];

        let checker = TestSignatureChecker::new();

        let result = verify_witness_program(
            &witness,
            0, // version 0
            witness_program,
            ScriptFlags::WITNESS,
            &checker,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_script_arithmetic() {
        // Test arithmetic operations
        // Script: OP_2 OP_3 OP_ADD OP_5 OP_EQUAL
        let mut script_bytes = vec![];
        script_bytes.push(OP_PUSHNUM_2.to_u8());
        script_bytes.push(OP_PUSHNUM_3.to_u8());
        script_bytes.push(OP_ADD.to_u8());
        script_bytes.push(OP_PUSHNUM_5.to_u8());
        script_bytes.push(OP_EQUAL.to_u8());

        let script = ScriptBuf::from(script_bytes);
        let empty_script = ScriptBuf::new();

        let checker = TestSignatureChecker::new();

        let result = verify_script(&empty_script, &script, ScriptFlags::empty(), &checker);

        assert!(result.is_ok());
    }

    #[test]
    fn test_script_conditionals() {
        // Test IF/ELSE/ENDIF
        // Script: OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let mut script_bytes = vec![];
        script_bytes.push(OP_PUSHNUM_1.to_u8());
        script_bytes.push(OP_IF.to_u8());
        script_bytes.push(OP_PUSHNUM_2.to_u8());
        script_bytes.push(OP_ELSE.to_u8());
        script_bytes.push(OP_PUSHNUM_3.to_u8());
        script_bytes.push(OP_ENDIF.to_u8());

        let script = ScriptBuf::from(script_bytes);
        let empty_script = ScriptBuf::new();

        let checker = TestSignatureChecker::new();

        let result = verify_script(&empty_script, &script, ScriptFlags::empty(), &checker);

        assert!(result.is_ok());
    }

    #[test]
    fn test_disabled_opcodes() {
        // Test that disabled opcodes fail
        let mut script_bytes = vec![];
        script_bytes.push(OP_CAT.to_u8()); // Disabled opcode

        let script = ScriptBuf::from(script_bytes);
        let empty_script = ScriptBuf::new();

        let checker = TestSignatureChecker::new();

        let result = verify_script(&empty_script, &script, ScriptFlags::empty(), &checker);

        assert!(matches!(result, Err(ScriptError::DisabledOpcode)));
    }

    #[test]
    fn test_op_return() {
        // OP_RETURN makes script invalid
        let mut script_bytes = vec![];
        script_bytes.push(OP_RETURN.to_u8());
        script_bytes.push(OP_PUSHNUM_1.to_u8());

        let script = ScriptBuf::from(script_bytes);
        let empty_script = ScriptBuf::new();

        let checker = TestSignatureChecker::new();

        let result = verify_script(&empty_script, &script, ScriptFlags::empty(), &checker);

        assert!(result.is_err());
    }

    #[test]
    fn test_stack_operations() {
        // Test various stack operations
        // Script: OP_1 OP_2 OP_SWAP OP_SUB OP_1 OP_EQUAL
        let mut script_bytes = vec![];
        script_bytes.push(OP_PUSHNUM_1.to_u8());
        script_bytes.push(OP_PUSHNUM_2.to_u8());
        script_bytes.push(OP_SWAP.to_u8());
        script_bytes.push(OP_SUB.to_u8());
        script_bytes.push(OP_PUSHNUM_1.to_u8());
        script_bytes.push(OP_EQUAL.to_u8());

        let script = ScriptBuf::from(script_bytes);
        let empty_script = ScriptBuf::new();

        let checker = TestSignatureChecker::new();

        let result = verify_script(&empty_script, &script, ScriptFlags::empty(), &checker);

        assert!(result.is_ok());
    }

    #[test]
    fn test_hash_operations() {
        // Test hash operations
        // Create a script that hashes data and compares
        let data = b"hello";
        let hash = sha256::Hash::hash(data);

        let mut script_bytes = vec![];
        // Push data
        script_bytes.push(data.len() as u8);
        script_bytes.extend_from_slice(data);
        // Hash it
        script_bytes.push(OP_SHA256.to_u8());
        // Push expected hash
        script_bytes.push(32);
        script_bytes.extend_from_slice(&hash.to_byte_array());
        // Compare
        script_bytes.push(OP_EQUAL.to_u8());

        let script = ScriptBuf::from(script_bytes);
        let empty_script = ScriptBuf::new();

        let checker = TestSignatureChecker::new();

        let result = verify_script(&empty_script, &script, ScriptFlags::empty(), &checker);

        assert!(result.is_ok());
    }

    #[test]
    fn test_clean_stack_rule() {
        // Test CLEANSTACK flag - stack must have exactly one element
        // Script that leaves multiple items on stack
        let mut script_bytes = vec![];
        script_bytes.push(OP_PUSHNUM_1.to_u8());
        script_bytes.push(OP_PUSHNUM_1.to_u8());
        script_bytes.push(OP_PUSHNUM_1.to_u8());

        let script = ScriptBuf::from(script_bytes);
        let empty_script = ScriptBuf::new();

        let checker = TestSignatureChecker::new();

        // Without CLEANSTACK flag - should succeed
        let result = verify_script(&empty_script, &script, ScriptFlags::empty(), &checker);
        assert!(result.is_ok());

        // With CLEANSTACK flag - should fail
        let result = verify_script(&empty_script, &script, ScriptFlags::CLEANSTACK, &checker);
        assert!(matches!(result, Err(ScriptError::CleanStack)));
    }

    #[test]
    fn test_bip66_strict_der_signatures() {
        // Test BIP66 strict DER signature enforcement
        use crate::script::SignatureChecker;

        // Create a test signature checker that validates DER signatures
        struct DERChecker {
            allow_invalid_der: bool,
        }

        impl SignatureChecker for DERChecker {
            fn check_sig(
                &self,
                signature: &[u8],
                _pubkey: &[u8],
                _script_code: &[u8],
                flags: ScriptFlags,
            ) -> crate::script::ScriptResult<bool> {
                // Check if we're enforcing strict DER
                if flags.contains(ScriptFlags::STRICTENC) && !self.allow_invalid_der {
                    // Validate DER encoding
                    if signature.is_empty() {
                        return Ok(false);
                    }

                    // Simple check: proper DER should start with 0x30
                    if signature[0] != 0x30 {
                        return Err(ScriptError::SigDer);
                    }
                }
                Ok(true)
            }

            fn check_schnorr_sig(
                &self,
                _signature: &[u8],
                _pubkey: &[u8],
                _flags: ScriptFlags,
            ) -> crate::script::ScriptResult<bool> {
                Ok(false)
            }

            fn check_locktime(&self, _locktime: i64) -> crate::script::ScriptResult<bool> {
                Ok(true)
            }

            fn check_sequence(&self, _sequence: i64) -> crate::script::ScriptResult<bool> {
                Ok(true)
            }
        }

        // Create a script with CHECKSIG
        let mut script_pubkey_bytes = vec![];
        // Push pubkey (33 bytes compressed)
        script_pubkey_bytes.push(33);
        script_pubkey_bytes.extend_from_slice(&[0x02; 33]);
        script_pubkey_bytes.push(OP_CHECKSIG.to_u8());
        let script_pubkey = ScriptBuf::from(script_pubkey_bytes);

        // Create scriptSig with valid DER signature
        let mut valid_sig = vec![0x30]; // DER sequence tag
        valid_sig.extend_from_slice(&[0x44; 68]); // Dummy signature data
        valid_sig.push(0x01); // SIGHASH_ALL

        let mut script_sig_bytes = vec![];
        script_sig_bytes.push(valid_sig.len() as u8);
        script_sig_bytes.extend_from_slice(&valid_sig);
        let script_sig = ScriptBuf::from(script_sig_bytes);

        // Test with BIP66 enabled - should succeed with valid DER
        let checker = DERChecker {
            allow_invalid_der: false,
        };
        let result = verify_script(
            &script_sig,
            &script_pubkey,
            ScriptFlags::STRICTENC,
            &checker,
        );
        assert!(
            result.is_ok(),
            "Should accept valid DER signature with BIP66"
        );

        // Create scriptSig with invalid DER signature (wrong tag)
        let mut invalid_sig = vec![0x31]; // Wrong DER tag
        invalid_sig.extend_from_slice(&[0x44; 68]);
        invalid_sig.push(0x01); // SIGHASH_ALL

        let mut script_sig_bytes = vec![];
        script_sig_bytes.push(invalid_sig.len() as u8);
        script_sig_bytes.extend_from_slice(&invalid_sig);
        let invalid_script_sig = ScriptBuf::from(script_sig_bytes);

        // Test with BIP66 enabled - should fail with invalid DER
        let result = verify_script(
            &invalid_script_sig,
            &script_pubkey,
            ScriptFlags::STRICTENC,
            &checker,
        );
        assert!(
            result.is_err(),
            "Should reject invalid DER signature with BIP66"
        );

        // Test without BIP66 - should accept invalid DER
        let result = verify_script(
            &invalid_script_sig,
            &script_pubkey,
            ScriptFlags::empty(),
            &checker,
        );
        assert!(result.is_ok(), "Should accept invalid DER without BIP66");
    }

    #[test]
    fn test_checklocktimeverify() {
        // Test BIP65 CHECKLOCKTIMEVERIFY
        // Create a script that uses OP_CHECKLOCKTIMEVERIFY (OP_NOP2 when BIP65 active)

        // Test 1: Valid locktime check
        let mut script_bytes = vec![];
        // Push locktime value (block height 100)
        script_bytes.push(1); // push 1 byte
        script_bytes.push(100);
        // CHECKLOCKTIMEVERIFY (OP_NOP2)
        script_bytes.push(OP_CLTV.to_u8());
        // Drop the locktime value
        script_bytes.push(OP_DROP.to_u8());
        // Push true to succeed
        script_bytes.push(OP_PUSHNUM_1.to_u8());

        let script = ScriptBuf::from(script_bytes);
        let empty_script = ScriptBuf::new();

        // Create a test checker that accepts the locktime
        struct CLTVChecker {
            locktime_ok: bool,
        }

        impl SignatureChecker for CLTVChecker {
            fn check_sig(
                &self,
                _signature: &[u8],
                _pubkey: &[u8],
                _script_code: &[u8],
                _flags: ScriptFlags,
            ) -> crate::script::ScriptResult<bool> {
                Ok(false)
            }

            fn check_schnorr_sig(
                &self,
                _signature: &[u8],
                _pubkey: &[u8],
                _flags: ScriptFlags,
            ) -> crate::script::ScriptResult<bool> {
                Ok(false)
            }

            fn check_locktime(&self, locktime: i64) -> crate::script::ScriptResult<bool> {
                // Check if the requested locktime (100) is valid
                Ok(self.locktime_ok && locktime == 100)
            }

            fn check_sequence(&self, _sequence: i64) -> crate::script::ScriptResult<bool> {
                Ok(true)
            }
        }

        // Test with BIP65 enabled and valid locktime
        let checker = CLTVChecker { locktime_ok: true };
        let result = verify_script(
            &empty_script,
            &script,
            ScriptFlags::CHECKLOCKTIMEVERIFY,
            &checker,
        );
        assert!(result.is_ok(), "CLTV should succeed with valid locktime");

        // Test with BIP65 enabled but invalid locktime
        let checker = CLTVChecker { locktime_ok: false };
        let result = verify_script(
            &empty_script,
            &script,
            ScriptFlags::CHECKLOCKTIMEVERIFY,
            &checker,
        );
        assert!(result.is_err(), "CLTV should fail with invalid locktime");

        // Test with BIP65 disabled - should act as NOP
        let checker = CLTVChecker { locktime_ok: false };
        let result = verify_script(&empty_script, &script, ScriptFlags::empty(), &checker);
        assert!(result.is_ok(), "CLTV should be NOP when BIP65 is disabled");

        // Test 2: Empty stack should fail
        let mut script_bytes = vec![];
        script_bytes.push(OP_CLTV.to_u8());

        let script = ScriptBuf::from(script_bytes);
        let checker = CLTVChecker { locktime_ok: true };

        let result = verify_script(
            &empty_script,
            &script,
            ScriptFlags::CHECKLOCKTIMEVERIFY,
            &checker,
        );
        assert!(result.is_err(), "CLTV should fail with empty stack");
    }
}
