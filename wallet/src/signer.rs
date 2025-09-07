use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::{
    ecdsa::Signature as EcdsaSignature,
    secp256k1::{self, Message, Secp256k1},
    sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType},
    Network, PrivateKey, PublicKey, ScriptBuf, Transaction, TxOut, Witness,
};
use tracing::{debug, info};

use crate::balance::Utxo;
use crate::error::{WalletError, WalletResult};
use crate::keychain::KeyChain;

/// Script type for signing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptType {
    /// Pay to Public Key Hash (legacy)
    P2PKH,
    /// Pay to Witness Public Key Hash (native segwit v0)
    P2WPKH,
    /// Pay to Script Hash wrapping P2WPKH (nested segwit)
    P2SH_P2WPKH,
    /// Pay to Witness Script Hash (native segwit v0 for multisig)
    P2WSH,
    /// Pay to Taproot (segwit v1)
    P2TR,
}

impl ScriptType {
    /// Detect script type from a script pubkey
    pub fn from_script(script: &ScriptBuf) -> Option<Self> {
        if script.is_p2pkh() {
            Some(ScriptType::P2PKH)
        } else if script.is_p2wpkh() {
            Some(ScriptType::P2WPKH)
        } else if script.is_p2sh() {
            // We'd need to know the redeem script to determine if it's P2SH-P2WPKH
            // For now, assume P2SH wraps P2WPKH for single-sig
            Some(ScriptType::P2SH_P2WPKH)
        } else if script.is_p2wsh() {
            Some(ScriptType::P2WSH)
        } else if script.is_p2tr() {
            Some(ScriptType::P2TR)
        } else {
            None
        }
    }
}

/// Transaction signer
pub struct TransactionSigner {
    secp: Secp256k1<secp256k1::All>,
    network: Network,
}

impl TransactionSigner {
    /// Create a new transaction signer
    pub fn new(network: Network) -> Self {
        Self {
            secp: Secp256k1::new(),
            network,
        }
    }

    /// Sign a transaction with the provided inputs and keys
    pub fn sign_transaction(
        &self,
        tx: &mut Transaction,
        inputs: &[Utxo],
        keychain: &KeyChain,
        derivation_paths: &[bitcoin::bip32::DerivationPath],
    ) -> WalletResult<()> {
        info!("Signing transaction with {} inputs", tx.input.len());

        if tx.input.len() != inputs.len() {
            return Err(WalletError::SigningFailed(
                "Input count mismatch".to_string(),
            ));
        }

        if tx.input.len() != derivation_paths.len() {
            return Err(WalletError::SigningFailed(
                "Derivation path count mismatch".to_string(),
            ));
        }

        for (input_idx, (utxo, path)) in inputs.iter().zip(derivation_paths.iter()).enumerate() {
            // Derive private key for this input
            let xpriv = keychain.derive_private_key(path)?;
            let private_key = PrivateKey::new(xpriv.private_key, self.network);
            let public_key = private_key.public_key(&self.secp);

            // Detect script type
            let script_type =
                ScriptType::from_script(&utxo.output.script_pubkey).ok_or_else(|| {
                    WalletError::SigningFailed(format!(
                        "Unknown script type for input {}",
                        input_idx
                    ))
                })?;

            debug!(
                "Signing input {} with script type {:?}",
                input_idx, script_type
            );

            // Sign based on script type
            match script_type {
                ScriptType::P2PKH => {
                    self.sign_p2pkh_input(tx, input_idx, utxo, &private_key)?;
                }
                ScriptType::P2WPKH => {
                    self.sign_p2wpkh_input(tx, input_idx, utxo, &private_key)?;
                }
                ScriptType::P2SH_P2WPKH => {
                    self.sign_p2sh_p2wpkh_input(tx, input_idx, utxo, &private_key, &public_key)?;
                }
                ScriptType::P2WSH => {
                    // For now, we don't support P2WSH (would need witness script)
                    return Err(WalletError::SigningFailed(
                        "P2WSH signing not yet implemented".to_string(),
                    ));
                }
                ScriptType::P2TR => {
                    self.sign_p2tr_input(tx, input_idx, inputs, &private_key)?;
                }
            }
        }

        info!("Transaction signing completed");
        Ok(())
    }

    /// Sign a P2PKH input
    fn sign_p2pkh_input(
        &self,
        tx: &mut Transaction,
        input_idx: usize,
        utxo: &Utxo,
        private_key: &PrivateKey,
    ) -> WalletResult<()> {
        let sighash_cache = SighashCache::new(tx.clone());
        let sighash_type = EcdsaSighashType::All;

        // For P2PKH, we need to use legacy sighash algorithm
        let sighash = sighash_cache
            .legacy_signature_hash(input_idx, &utxo.output.script_pubkey, sighash_type.to_u32())
            .map_err(|e| {
                WalletError::SigningFailed(format!("Failed to compute P2PKH sighash: {}", e))
            })?;

        // Sign the sighash
        let message = Message::from_digest(*sighash.as_byte_array());
        let signature = self.secp.sign_ecdsa(&message, &private_key.inner);

        // Create script sig
        let mut sig_bytes = signature.serialize_der().to_vec();
        sig_bytes.push(sighash_type as u8);

        let public_key = private_key.public_key(&self.secp);

        // Build scriptSig: <signature> <pubkey>
        let mut script_sig = Vec::new();
        // Push signature
        script_sig.push(sig_bytes.len() as u8);
        script_sig.extend_from_slice(&sig_bytes);
        // Push pubkey
        let pubkey_bytes = public_key.to_bytes();
        script_sig.push(pubkey_bytes.len() as u8);
        script_sig.extend_from_slice(&pubkey_bytes);

        tx.input[input_idx].script_sig = ScriptBuf::from(script_sig);

        Ok(())
    }

    /// Sign a P2WPKH input
    fn sign_p2wpkh_input(
        &self,
        tx: &mut Transaction,
        input_idx: usize,
        utxo: &Utxo,
        private_key: &PrivateKey,
    ) -> WalletResult<()> {
        let mut sighash_cache = SighashCache::new(tx.clone());
        let sighash_type = EcdsaSighashType::All;

        let sighash = sighash_cache
            .p2wpkh_signature_hash(
                input_idx,
                &utxo.output.script_pubkey,
                utxo.output.value,
                sighash_type,
            )
            .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

        // Sign the sighash
        let message = Message::from_digest(*sighash.as_byte_array());
        let signature = self.secp.sign_ecdsa(&message, &private_key.inner);

        // Create witness
        let mut witness = Witness::new();
        witness.push_ecdsa_signature(&EcdsaSignature {
            signature,
            sighash_type,
        });
        witness.push(private_key.public_key(&self.secp).to_bytes());

        tx.input[input_idx].witness = witness;

        Ok(())
    }

    /// Sign a P2SH-P2WPKH (nested segwit) input
    fn sign_p2sh_p2wpkh_input(
        &self,
        tx: &mut Transaction,
        input_idx: usize,
        utxo: &Utxo,
        private_key: &PrivateKey,
        public_key: &PublicKey,
    ) -> WalletResult<()> {
        // First, create the witness program (P2WPKH)
        let wpkh = public_key.wpubkey_hash().map_err(|_| {
            WalletError::SigningFailed("Failed to create witness pubkey hash".to_string())
        })?;

        // Create the redeem script (OP_0 <20-byte-key-hash>)
        let redeem_script = ScriptBuf::new_p2wpkh(&wpkh);

        // Sign with P2WPKH logic
        let mut sighash_cache = SighashCache::new(tx.clone());
        let sighash_type = EcdsaSighashType::All;

        // Use the witness script (P2PKH-like) for sighash
        let witness_script = ScriptBuf::new_p2pkh(&public_key.pubkey_hash());

        let sighash = sighash_cache
            .p2wpkh_signature_hash(input_idx, &witness_script, utxo.output.value, sighash_type)
            .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

        // Sign the sighash
        let message = Message::from_digest(*sighash.as_byte_array());
        let signature = self.secp.sign_ecdsa(&message, &private_key.inner);

        // Set the scriptSig to the redeem script
        let redeem_bytes = redeem_script.as_bytes();
        let mut script_sig = Vec::new();
        script_sig.push(redeem_bytes.len() as u8);
        script_sig.extend_from_slice(redeem_bytes);
        tx.input[input_idx].script_sig = ScriptBuf::from(script_sig);

        // Create witness
        let mut witness = Witness::new();
        witness.push_ecdsa_signature(&EcdsaSignature {
            signature,
            sighash_type,
        });
        witness.push(public_key.to_bytes());

        tx.input[input_idx].witness = witness;

        Ok(())
    }

    /// Sign a P2TR (Taproot) input
    fn sign_p2tr_input(
        &self,
        tx: &mut Transaction,
        input_idx: usize,
        all_utxos: &[Utxo],
        private_key: &PrivateKey,
    ) -> WalletResult<()> {
        // Collect all prevouts for taproot signing
        let prevouts: Vec<TxOut> = all_utxos.iter().map(|u| u.output.clone()).collect();

        let prevouts = Prevouts::All(&prevouts);

        let mut sighash_cache = SighashCache::new(tx.clone());
        let sighash_type = TapSighashType::Default;

        // Compute taproot key-spend signature hash
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(input_idx, &prevouts, sighash_type)
            .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

        // Get the internal key pair
        let keypair = secp256k1::Keypair::from_secret_key(&self.secp, &private_key.inner);

        // Tweak the key for taproot
        let tweaked_keypair = keypair.tap_tweak(&self.secp, None);

        // Sign with the tweaked key
        let message = Message::from_digest(*sighash.as_byte_array());
        let signature = self
            .secp
            .sign_schnorr(&message, &tweaked_keypair.to_inner());

        // Create witness with just the signature (key-spend path)
        let mut witness = Witness::new();
        witness.push(signature.serialize());

        tx.input[input_idx].witness = witness;

        Ok(())
    }

    /// Create a signature for a specific input (used for PSBT)
    pub fn create_signature(
        &self,
        tx: &Transaction,
        input_idx: usize,
        utxo: &TxOut,
        private_key: &PrivateKey,
        sighash_type: EcdsaSighashType,
    ) -> WalletResult<Vec<u8>> {
        let mut sighash_cache = SighashCache::new(tx.clone());

        // Detect if this is segwit
        if utxo.script_pubkey.is_p2wpkh() || utxo.script_pubkey.is_p2wsh() {
            // Segwit signing
            let sighash = sighash_cache
                .p2wpkh_signature_hash(input_idx, &utxo.script_pubkey, utxo.value, sighash_type)
                .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

            let message = Message::from_digest(*sighash.as_byte_array());
            let signature = self.secp.sign_ecdsa(&message, &private_key.inner);

            let mut sig_bytes = signature.serialize_der().to_vec();
            sig_bytes.push(sighash_type as u8);

            Ok(sig_bytes)
        } else {
            // Legacy signing
            let sighash = sighash_cache
                .legacy_signature_hash(input_idx, &utxo.script_pubkey, sighash_type.to_u32())
                .map_err(|e| {
                    WalletError::SigningFailed(format!("Failed to compute legacy sighash: {}", e))
                })?;

            let message = Message::from_digest(*sighash.as_byte_array());
            let signature = self.secp.sign_ecdsa(&message, &private_key.inner);

            let mut sig_bytes = signature.serialize_der().to_vec();
            sig_bytes.push(sighash_type as u8);

            Ok(sig_bytes)
        }
    }
}

/// Helper to determine derivation paths for UTXOs
pub struct DerivationPathFinder {
    keychain: KeyChain,
    network: Network,
}

impl DerivationPathFinder {
    pub fn new(keychain: KeyChain, network: Network) -> Self {
        Self { keychain, network }
    }

    /// Find the derivation path for a UTXO
    pub fn find_path_for_utxo(&self, utxo: &Utxo) -> WalletResult<bitcoin::bip32::DerivationPath> {
        // Try common derivation paths
        let paths_to_try = vec![
            // BIP84 (native segwit)
            KeyChain::bip84_path(0, 0, 0)?,
            KeyChain::bip84_path(0, 0, 1)?,
            KeyChain::bip84_path(0, 0, 2)?,
            KeyChain::bip84_path(0, 1, 0)?, // Change
            // BIP49 (nested segwit)
            KeyChain::bip49_path(0, 0, 0)?,
            KeyChain::bip49_path(0, 0, 1)?,
            // BIP44 (legacy)
            KeyChain::bip44_path(0, 0, 0)?,
            KeyChain::bip44_path(0, 0, 1)?,
        ];

        let secp = Secp256k1::new();

        for path in paths_to_try {
            let xpriv = self.keychain.derive_private_key(&path)?;
            let private_key = PrivateKey::new(xpriv.private_key, self.network);
            let public_key = private_key.public_key(&secp);

            // Check different address types
            // We need to handle both compressed and uncompressed keys

            // P2PKH (legacy) - works with both compressed and uncompressed
            let addr = bitcoin::Address::p2pkh(public_key, self.network);
            if addr.to_string() == utxo.address {
                return Ok(path);
            }

            // For segwit addresses, we need compressed keys
            if let Ok(compressed_key) = bitcoin::key::CompressedPublicKey::try_from(public_key) {
                // P2WPKH (native segwit)
                let addr = bitcoin::Address::p2wpkh(&compressed_key, self.network);
                if addr.to_string() == utxo.address {
                    return Ok(path);
                }

                // P2SH-P2WPKH (nested segwit)
                let addr = bitcoin::Address::p2shwpkh(&compressed_key, self.network);
                if addr.to_string() == utxo.address {
                    return Ok(path);
                }
            }

            // P2TR (taproot)
            let xonly = public_key.inner.x_only_public_key().0;
            let addr = bitcoin::Address::p2tr(&secp, xonly, None, self.network);
            if addr.to_string() == utxo.address {
                return Ok(path);
            }
        }

        Err(WalletError::KeyDerivationFailed(format!(
            "Could not find derivation path for address {}",
            utxo.address
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    #[test]
    fn test_script_type_detection() {
        // P2WPKH
        let addr = bitcoin::Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            .unwrap()
            .assume_checked();
        assert_eq!(
            ScriptType::from_script(&addr.script_pubkey()),
            Some(ScriptType::P2WPKH)
        );

        // P2PKH
        let addr = bitcoin::Address::from_str("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
            .unwrap()
            .assume_checked();
        assert_eq!(
            ScriptType::from_script(&addr.script_pubkey()),
            Some(ScriptType::P2PKH)
        );

        // P2SH
        let addr = bitcoin::Address::from_str("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
            .unwrap()
            .assume_checked();
        assert_eq!(
            ScriptType::from_script(&addr.script_pubkey()),
            Some(ScriptType::P2SH_P2WPKH)
        );
    }
}
