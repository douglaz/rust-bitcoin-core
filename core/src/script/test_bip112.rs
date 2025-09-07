//! Tests for BIP112 (CHECKSEQUENCEVERIFY) integration

#[cfg(test)]
mod tests {
    use crate::bip68::SEQUENCE_LOCKTIME_TYPE_FLAG;
    use crate::script::signature::SignatureChecker;
    use crate::script::{error::ScriptError, ScriptFlags, ScriptInterpreter};
    use bitcoin::blockdata::opcodes::all::OP_CSV;
    use bitcoin::blockdata::opcodes::all::{OP_DROP, OP_PUSHNUM_1};
    use bitcoin::blockdata::script::{Builder as ScriptBuilder, ScriptBuf};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    struct TestCSVChecker {
        tx: Transaction,
        input_index: usize,
    }

    impl SignatureChecker for TestCSVChecker {
        fn check_sig(
            &self,
            _signature: &[u8],
            _pubkey: &[u8],
            _script_code: &[u8],
            _flags: ScriptFlags,
        ) -> crate::script::ScriptResult<bool> {
            Ok(true)
        }

        fn check_schnorr_sig(
            &self,
            _signature: &[u8],
            _pubkey: &[u8],
            _flags: ScriptFlags,
        ) -> crate::script::ScriptResult<bool> {
            Ok(true)
        }

        fn check_locktime(&self, _locktime: i64) -> crate::script::ScriptResult<bool> {
            Ok(true)
        }

        fn check_sequence(&self, sequence: i64) -> crate::script::ScriptResult<bool> {
            // Use BIP112 implementation
            let result = crate::bip112::verify_checksequenceverify(
                &self.tx,
                self.input_index,
                sequence,
                self.tx.version.0,
            )
            .map_err(|_| ScriptError::InvalidStackOperation)?;

            Ok(result)
        }
    }

    #[test]
    fn test_csv_script_success() -> anyhow::Result<()> {
        // Create a v2 transaction with sequence = 100
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(100),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let checker = TestCSVChecker {
            tx: tx.clone(),
            input_index: 0,
        };

        // Create script: <50> OP_CHECKSEQUENCEVERIFY
        // Should pass since tx sequence (100) >= required (50)
        let script = ScriptBuilder::new()
            .push_int(50)
            .push_opcode(OP_CSV)
            .into_script();

        let mut interpreter = ScriptInterpreter::new(ScriptFlags::CHECKSEQUENCEVERIFY);
        let result = interpreter.execute(&script, &checker);

        // Should succeed
        assert!(result.is_ok());

        Ok(())
    }

    #[test]
    fn test_csv_script_failure() -> anyhow::Result<()> {
        // Create a v2 transaction with sequence = 50
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(50),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let checker = TestCSVChecker {
            tx: tx.clone(),
            input_index: 0,
        };

        // Create script: <100> OP_CHECKSEQUENCEVERIFY
        // Should fail since tx sequence (50) < required (100)
        let script = ScriptBuilder::new()
            .push_int(100)
            .push_opcode(OP_CSV)
            .into_script();

        let mut interpreter = ScriptInterpreter::new(ScriptFlags::CHECKSEQUENCEVERIFY);
        let result = interpreter.execute(&script, &checker);

        // Should fail with locktime error
        assert!(matches!(result, Err(ScriptError::UnsatisfiedLocktime)));

        Ok(())
    }

    #[test]
    fn test_csv_time_based() -> anyhow::Result<()> {
        // Create a v2 transaction with time-based sequence (10 * 512 seconds)
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(SEQUENCE_LOCKTIME_TYPE_FLAG | 10),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let checker = TestCSVChecker {
            tx: tx.clone(),
            input_index: 0,
        };

        // Create script requiring 5 time units (should pass)
        let csv_value = (SEQUENCE_LOCKTIME_TYPE_FLAG | 5) as i64;
        let script = ScriptBuilder::new()
            .push_int(csv_value)
            .push_opcode(OP_CSV)
            .into_script();

        let mut interpreter = ScriptInterpreter::new(ScriptFlags::CHECKSEQUENCEVERIFY);
        let result = interpreter.execute(&script, &checker);

        // Should succeed
        assert!(result.is_ok());

        // Now test with higher requirement (should fail)
        let csv_value = (SEQUENCE_LOCKTIME_TYPE_FLAG | 15) as i64;
        let script = ScriptBuilder::new()
            .push_int(csv_value)
            .push_opcode(OP_CSV)
            .into_script();

        let result = interpreter.execute(&script, &checker);

        // Should fail
        assert!(matches!(result, Err(ScriptError::UnsatisfiedLocktime)));

        Ok(())
    }

    #[test]
    fn test_csv_version_1_nop() -> anyhow::Result<()> {
        // Create a v1 transaction (CSV should be NOP)
        let tx = Transaction {
            version: Version(1),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0), // Even with 0 sequence
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let checker = TestCSVChecker {
            tx: tx.clone(),
            input_index: 0,
        };

        // Create script: <100> OP_CHECKSEQUENCEVERIFY OP_DROP OP_1
        // Should succeed because CSV is NOP for v1 tx
        let script = ScriptBuilder::new()
            .push_int(100)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP) // Drop the 100 from stack
            .push_opcode(OP_PUSHNUM_1) // Push 1 for success
            .into_script();

        let mut interpreter = ScriptInterpreter::new(ScriptFlags::CHECKSEQUENCEVERIFY);
        let result = interpreter.execute(&script, &checker);

        // Should succeed
        assert!(result.is_ok());

        Ok(())
    }
}
