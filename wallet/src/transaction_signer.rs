use anyhow::{bail, Result};
use bitcoin::hashes::Hash;
use bitcoin::psbt::{Input as PsbtInput, Psbt};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache};
use bitcoin::{
    Amount, Network, OutPoint, PrivateKey, PublicKey, Script, ScriptBuf, Transaction, TxIn, TxOut,
    Witness,
};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Transaction signer for wallet
pub struct TransactionSigner {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    network: Network,
}

impl TransactionSigner {
    /// Create new transaction signer
    pub fn new(network: Network) -> Self {
        Self {
            secp: Secp256k1::new(),
            network,
        }
    }

    /// Sign a transaction with provided private keys
    pub fn sign_transaction(
        &self,
        tx: &mut Transaction,
        prevouts: &[TxOut],
        private_keys: &HashMap<OutPoint, PrivateKey>,
    ) -> Result<()> {
        // Validate inputs match prevouts
        if tx.input.len() != prevouts.len() {
            bail!("Transaction inputs count doesn't match prevouts");
        }

        // Create sighash cache for efficiency
        let mut cache = SighashCache::new(tx.clone());

        // Sign each input
        for (input_index, tx_in) in tx.input.iter_mut().enumerate() {
            let prevout = &prevouts[input_index];

            // Get private key for this input
            let private_key = private_keys
                .get(&tx_in.previous_output)
                .ok_or_else(|| anyhow::anyhow!("No private key for input {}", input_index))?;

            // Determine script type and sign accordingly
            if prevout.script_pubkey.is_p2pkh() {
                self.sign_p2pkh_input(&mut cache, input_index, prevout, private_key, tx_in)?;
            } else if prevout.script_pubkey.is_p2wpkh() {
                self.sign_p2wpkh_input(&mut cache, input_index, prevout, private_key, tx_in)?;
            } else if prevout.script_pubkey.is_p2sh() {
                // Could be P2SH-P2WPKH
                self.sign_p2sh_input(&mut cache, input_index, prevout, private_key, tx_in)?;
            } else {
                bail!("Unsupported script type for input {}", input_index);
            }
        }

        // Update transaction with signed version
        *tx = cache.into_transaction();

        Ok(())
    }

    /// Sign P2PKH input
    fn sign_p2pkh_input(
        &self,
        cache: &mut SighashCache<Transaction>,
        input_index: usize,
        prevout: &TxOut,
        private_key: &PrivateKey,
        tx_in: &mut TxIn,
    ) -> Result<()> {
        debug!("Signing P2PKH input {}", input_index);

        // Calculate sighash
        let sighash = cache.legacy_signature_hash(
            input_index,
            &prevout.script_pubkey,
            EcdsaSighashType::All as u32,
        )?;

        // Sign the hash
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = self.secp.sign_ecdsa(&message, &private_key.inner);

        // Create scriptSig
        let mut sig_bytes = signature.serialize_der().to_vec();
        sig_bytes.push(EcdsaSighashType::All as u8);

        let pubkey = PublicKey::from_private_key(&self.secp, private_key);

        // Build scriptSig: <sig> <pubkey>
        let script_sig = bitcoin::blockdata::script::Builder::new()
            .push_slice(&bitcoin::script::PushBytesBuf::try_from(sig_bytes.clone()).unwrap()[..])
            .push_key(&pubkey)
            .into_script();

        tx_in.script_sig = script_sig;

        Ok(())
    }

    /// Sign P2WPKH input (native SegWit)
    fn sign_p2wpkh_input(
        &self,
        cache: &mut SighashCache<Transaction>,
        input_index: usize,
        prevout: &TxOut,
        private_key: &PrivateKey,
        tx_in: &mut TxIn,
    ) -> Result<()> {
        debug!("Signing P2WPKH input {}", input_index);

        // Create prevouts for segwit signing
        let prevouts = Prevouts::All(&[prevout.clone()]);

        // Calculate sighash for witness
        let sighash = cache.p2wpkh_signature_hash(
            input_index,
            &prevout.script_pubkey,
            prevout.value,
            EcdsaSighashType::All,
        )?;

        // Sign the hash
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = self.secp.sign_ecdsa(&message, &private_key.inner);

        // Create witness
        let mut sig_bytes = signature.serialize_der().to_vec();
        sig_bytes.push(EcdsaSighashType::All as u8);

        let pubkey = PublicKey::from_private_key(&self.secp, private_key);

        // Set witness data
        tx_in.witness = Witness::from_slice(&[sig_bytes, pubkey.to_bytes()]);

        Ok(())
    }

    /// Sign P2SH input (might be P2SH-P2WPKH)
    fn sign_p2sh_input(
        &self,
        cache: &mut SighashCache<Transaction>,
        input_index: usize,
        prevout: &TxOut,
        private_key: &PrivateKey,
        tx_in: &mut TxIn,
    ) -> Result<()> {
        debug!("Signing P2SH input {}", input_index);

        // For P2SH-P2WPKH (wrapped SegWit)
        let pubkey = PublicKey::from_private_key(&self.secp, private_key);
        let pubkey_hash = pubkey.pubkey_hash();

        // Create the witness program (P2WPKH)
        let witness_program = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());

        // Calculate witness sighash
        let sighash = cache.p2wpkh_signature_hash(
            input_index,
            &witness_program,
            prevout.value,
            EcdsaSighashType::All,
        )?;

        // Sign the hash
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = self.secp.sign_ecdsa(&message, &private_key.inner);

        // Create witness
        let mut sig_bytes = signature.serialize_der().to_vec();
        sig_bytes.push(EcdsaSighashType::All as u8);

        // Set witness data
        tx_in.witness = Witness::from_slice(&[sig_bytes, pubkey.to_bytes()]);

        // Set scriptSig to push the witness program
        tx_in.script_sig = bitcoin::blockdata::script::Builder::new()
            .push_slice(
                &bitcoin::script::PushBytesBuf::try_from(witness_program.to_bytes()).unwrap()[..],
            )
            .into_script();

        Ok(())
    }

    /// Create and sign a simple transaction
    pub fn create_signed_transaction(
        &self,
        inputs: Vec<(OutPoint, TxOut, PrivateKey)>,
        outputs: Vec<TxOut>,
        fee: Amount,
    ) -> Result<Transaction> {
        // Calculate total input value
        let total_in: Amount = inputs.iter().map(|(_, prevout, _)| prevout.value).sum();

        // Calculate total output value
        let total_out: Amount = outputs.iter().map(|out| out.value).sum();

        // Verify fee
        if total_in < total_out + fee {
            bail!(
                "Insufficient inputs: {} < {} + {} fee",
                total_in,
                total_out,
                fee
            );
        }

        // Create transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs
                .iter()
                .map(|(outpoint, _, _)| TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs,
        };

        // Prepare prevouts and keys for signing
        let prevouts: Vec<TxOut> = inputs
            .iter()
            .map(|(_, prevout, _)| prevout.clone())
            .collect();

        let mut private_keys = HashMap::new();
        for (outpoint, _, key) in &inputs {
            private_keys.insert(*outpoint, *key);
        }

        // Sign the transaction
        self.sign_transaction(&mut tx, &prevouts, &private_keys)?;

        info!("Created and signed transaction: {}", tx.compute_txid());

        Ok(tx)
    }

    /// Sign a PSBT (Partially Signed Bitcoin Transaction)
    pub fn sign_psbt(&self, psbt: &mut Psbt, private_keys: &[PrivateKey]) -> Result<()> {
        let tx = &psbt.unsigned_tx;

        for (input_index, psbt_input) in psbt.inputs.iter_mut().enumerate() {
            // Get the UTXO being spent
            let utxo = if let Some(witness_utxo) = &psbt_input.witness_utxo {
                witness_utxo.clone()
            } else if let Some(non_witness_utxo) = &psbt_input.non_witness_utxo {
                let vout = tx.input[input_index].previous_output.vout;
                non_witness_utxo.output[vout as usize].clone()
            } else {
                warn!("No UTXO info for input {}", input_index);
                continue;
            };

            // Try each private key
            for private_key in private_keys {
                let pubkey = PublicKey::from_private_key(&self.secp, private_key);

                // Check if this key can sign this input
                if !self.can_sign_input(&utxo.script_pubkey, &pubkey) {
                    continue;
                }

                // Sign based on script type
                if utxo.script_pubkey.is_p2wpkh() || utxo.script_pubkey.is_p2wsh() {
                    self.sign_psbt_witness_input(psbt_input, tx, input_index, &utxo, private_key)?;
                } else {
                    self.sign_psbt_legacy_input(psbt_input, tx, input_index, &utxo, private_key)?;
                }
            }
        }

        Ok(())
    }

    /// Check if a public key can sign for a script
    fn can_sign_input(&self, script: &Script, pubkey: &PublicKey) -> bool {
        // Check P2PKH
        if script.is_p2pkh() {
            let pubkey_hash = pubkey.pubkey_hash();
            return script == &ScriptBuf::new_p2pkh(&pubkey_hash);
        }

        // Check P2WPKH
        if script.is_p2wpkh() {
            let pubkey_hash = pubkey.wpubkey_hash().unwrap();
            return script == &ScriptBuf::new_p2wpkh(&pubkey_hash);
        }

        // Add more script types as needed
        false
    }

    /// Sign witness input in PSBT
    fn sign_psbt_witness_input(
        &self,
        psbt_input: &mut PsbtInput,
        tx: &Transaction,
        input_index: usize,
        utxo: &TxOut,
        private_key: &PrivateKey,
    ) -> Result<()> {
        // Create sighash cache
        let mut cache = SighashCache::new(tx.clone());

        // Calculate sighash
        let sighash = cache.p2wpkh_signature_hash(
            input_index,
            &utxo.script_pubkey,
            utxo.value,
            EcdsaSighashType::All,
        )?;

        // Sign
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = self.secp.sign_ecdsa(&message, &private_key.inner);

        // Add to PSBT
        let pubkey = PublicKey::from_private_key(&self.secp, private_key);
        let ecdsa_sig = bitcoin::ecdsa::Signature {
            signature,
            sighash_type: EcdsaSighashType::All,
        };
        psbt_input.partial_sigs.insert(pubkey, ecdsa_sig);

        Ok(())
    }

    /// Sign legacy input in PSBT
    fn sign_psbt_legacy_input(
        &self,
        psbt_input: &mut PsbtInput,
        tx: &Transaction,
        input_index: usize,
        utxo: &TxOut,
        private_key: &PrivateKey,
    ) -> Result<()> {
        // Create sighash cache
        let cache = SighashCache::new(tx.clone());

        // Calculate sighash
        let sighash = cache.legacy_signature_hash(
            input_index,
            &utxo.script_pubkey,
            EcdsaSighashType::All as u32,
        )?;

        // Sign
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = self.secp.sign_ecdsa(&message, &private_key.inner);

        // Add to PSBT
        let pubkey = PublicKey::from_private_key(&self.secp, private_key);
        let ecdsa_sig = bitcoin::ecdsa::Signature {
            signature,
            sighash_type: EcdsaSighashType::All,
        };
        psbt_input.partial_sigs.insert(pubkey, ecdsa_sig);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::Keypair;
    use bitcoin::Txid;

    #[test]
    fn test_transaction_signer_creation() {
        let _signer = TransactionSigner::new(Network::Bitcoin);
        assert!(true); // Basic creation test
    }

    #[test]
    fn test_create_transaction() {
        let signer = TransactionSigner::new(Network::Testnet);
        let secp = Secp256k1::new();

        // Create test keypair
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());
        let private_key = PrivateKey::new(keypair.secret_key(), Network::Testnet);

        // Create test inputs
        let outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };

        let pubkey = PublicKey::from_private_key(&secp, &private_key);
        let prevout = TxOut {
            value: Amount::from_sat(10000),
            script_pubkey: ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap()),
        };

        let inputs = vec![(outpoint, prevout, private_key)];

        // Create output
        let output = TxOut {
            value: Amount::from_sat(9000),
            script_pubkey: ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap()),
        };

        let outputs = vec![output];
        let fee = Amount::from_sat(1000);

        // Create and sign transaction
        let tx = signer.create_signed_transaction(inputs, outputs, fee);
        assert!(tx.is_ok());
    }
}
