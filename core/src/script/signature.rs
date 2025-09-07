use crate::bip112;
use crate::script::error::{ScriptError, ScriptResult};
use crate::script::flags::ScriptFlags;
use bitcoin::ecdsa::Signature as EcdsaSignature;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, Message, PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{EcdsaSighashType, Transaction, TxOut};

/// Trait for checking signatures during script execution
pub trait SignatureChecker {
    /// Check an ECDSA signature
    fn check_sig(
        &self,
        signature: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        flags: ScriptFlags,
    ) -> ScriptResult<bool>;

    /// Check a Schnorr signature (for Taproot)
    fn check_schnorr_sig(
        &self,
        signature: &[u8],
        pubkey: &[u8],
        flags: ScriptFlags,
    ) -> ScriptResult<bool>;

    /// Check locktime
    fn check_locktime(&self, locktime: i64) -> ScriptResult<bool>;

    /// Check sequence
    fn check_sequence(&self, sequence: i64) -> ScriptResult<bool>;
}

/// Base signature checker that always returns false
pub struct BaseSignatureChecker;

impl SignatureChecker for BaseSignatureChecker {
    fn check_sig(
        &self,
        _signature: &[u8],
        _pubkey: &[u8],
        _script_code: &[u8],
        _flags: ScriptFlags,
    ) -> ScriptResult<bool> {
        Ok(false)
    }

    fn check_schnorr_sig(
        &self,
        _signature: &[u8],
        _pubkey: &[u8],
        _flags: ScriptFlags,
    ) -> ScriptResult<bool> {
        Ok(false)
    }

    fn check_locktime(&self, _locktime: i64) -> ScriptResult<bool> {
        Ok(false)
    }

    fn check_sequence(&self, _sequence: i64) -> ScriptResult<bool> {
        Ok(false)
    }
}

/// Transaction signature checker for validating signatures against a transaction
pub struct TransactionSignatureChecker<'a> {
    tx: &'a Transaction,
    input_index: usize,
    amount: u64,
    prevouts: Vec<TxOut>,
    secp: Secp256k1<secp256k1::All>,
}

impl<'a> TransactionSignatureChecker<'a> {
    pub fn new(tx: &'a Transaction, input_index: usize, amount: u64, prevouts: Vec<TxOut>) -> Self {
        Self {
            tx,
            input_index,
            amount,
            prevouts,
            secp: Secp256k1::new(),
        }
    }

    fn parse_ecdsa_signature(
        &self,
        sig_bytes: &[u8],
        flags: ScriptFlags,
    ) -> ScriptResult<(EcdsaSignature, EcdsaSighashType)> {
        if sig_bytes.is_empty() {
            return Err(ScriptError::SigDer);
        }

        // Extract sighash type from last byte
        let sighash_byte = sig_bytes[sig_bytes.len() - 1];
        let sighash_type = EcdsaSighashType::from_standard(sighash_byte as u32)
            .map_err(|_| ScriptError::SigHashType)?;

        // Parse signature without sighash byte
        let sig_der = &sig_bytes[..sig_bytes.len() - 1];

        // Strict encoding check
        if flags.require_strict_encoding() {
            // Validate DER encoding
            if !is_valid_der(sig_der) {
                return Err(ScriptError::SigDer);
            }
        }

        let sig =
            secp256k1::ecdsa::Signature::from_der(sig_der).map_err(|_| ScriptError::SigDer)?;

        // Check for low S value if required
        if flags.contains(ScriptFlags::LOW_S) {
            // Check if S value is canonical (low S)
            let sig_bytes = sig.serialize_compact();
            if !is_low_s_bytes(&sig_bytes[32..64]) {
                return Err(ScriptError::SigHighS);
            }
        }

        Ok((
            EcdsaSignature {
                signature: sig,
                sighash_type,
            },
            sighash_type,
        ))
    }

    fn compute_sighash(
        &self,
        script_code: &[u8],
        sighash_type: EcdsaSighashType,
    ) -> ScriptResult<Message> {
        let script = bitcoin::Script::from_bytes(script_code);
        let mut cache = SighashCache::new(self.tx);

        // For legacy transactions (non-witness), we should use legacy_signature_hash
        // not p2wpkh_signature_hash which is for witness transactions
        let sighash = if self.tx.is_coinbase() {
            // Coinbase transactions don't have previous outputs
            [0u8; 32]
        } else {
            // Use legacy sighash for non-witness transactions
            cache
                .legacy_signature_hash(self.input_index, script, sighash_type.to_u32())
                .map_err(|_| ScriptError::Unknown)?
                .to_byte_array()
        };

        Ok(Message::from_digest_slice(&sighash).unwrap())
    }
}

impl<'a> SignatureChecker for TransactionSignatureChecker<'a> {
    fn check_sig(
        &self,
        signature: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        flags: ScriptFlags,
    ) -> ScriptResult<bool> {
        // Empty signature always fails
        if signature.is_empty() {
            return Ok(false);
        }

        // Parse public key
        let pk = if flags.contains(ScriptFlags::WITNESS_PUBKEYTYPE) {
            // In witness, require compressed public keys
            if pubkey.len() != 33 {
                return Err(ScriptError::WitnessPubkeyType);
            }
            PublicKey::from_slice(pubkey).map_err(|_| ScriptError::PubKeyType)?
        } else {
            // Accept both compressed and uncompressed
            match PublicKey::from_slice(pubkey) {
                Ok(pk) => pk,
                Err(_) => {
                    // If we can't parse the public key and STRICTENC is set, it's an error
                    if flags.contains(ScriptFlags::STRICTENC) {
                        return Err(ScriptError::PubKeyType);
                    }
                    // Otherwise, it's just a signature validation failure
                    return Ok(false);
                }
            }
        };

        // Parse signature and sighash type - this may fail with STRICTENC
        let (sig, sighash_type) = match self.parse_ecdsa_signature(signature, flags) {
            Ok(result) => result,
            Err(e) => {
                // If STRICTENC is set and we get a parsing error, propagate it
                if flags.contains(ScriptFlags::STRICTENC) {
                    return Err(e);
                }
                // Otherwise, treat as signature validation failure
                return Ok(false);
            }
        };

        // Compute sighash
        let message = self.compute_sighash(script_code, sighash_type)?;

        // Verify signature
        let result = self
            .secp
            .verify_ecdsa(&message, &sig.signature, &pk)
            .is_ok();

        Ok(result)
    }

    fn check_schnorr_sig(
        &self,
        signature: &[u8],
        pubkey: &[u8],
        flags: ScriptFlags,
    ) -> ScriptResult<bool> {
        if !flags.contains(ScriptFlags::TAPROOT) {
            return Ok(false);
        }

        // Parse Schnorr signature (64 bytes + optional sighash byte)
        let (sig_bytes, sighash_type) = if signature.len() == 64 {
            (signature, TapSighashType::Default)
        } else if signature.len() == 65 {
            let sighash_byte = signature[64];
            let sighash_type = TapSighashType::from_consensus_u8(sighash_byte)
                .map_err(|_| ScriptError::SigHashType)?;
            (&signature[..64], sighash_type)
        } else {
            return Err(ScriptError::TaprootValidation);
        };

        // Parse public key (32 bytes x-only)
        if pubkey.len() != 32 {
            return Err(ScriptError::TaprootValidation);
        }

        let xonly_pk =
            XOnlyPublicKey::from_slice(pubkey).map_err(|_| ScriptError::TaprootValidation)?;

        let sig = secp256k1::schnorr::Signature::from_slice(sig_bytes)
            .map_err(|_| ScriptError::TaprootValidation)?;

        // Create sighash cache for taproot
        let prevouts = Prevouts::All(&self.prevouts);
        let mut cache = SighashCache::new(self.tx);

        // Compute taproot sighash
        let sighash = cache
            .taproot_key_spend_signature_hash(self.input_index, &prevouts, sighash_type)
            .map_err(|_| ScriptError::Unknown)?;

        let message = Message::from_digest(sighash.to_byte_array());

        // Verify Schnorr signature
        let result = self.secp.verify_schnorr(&sig, &message, &xonly_pk).is_ok();

        Ok(result)
    }

    fn check_locktime(&self, locktime: i64) -> ScriptResult<bool> {
        if locktime < 0 {
            return Err(ScriptError::NegativeLocktime);
        }

        let locktime = locktime as u32;
        let tx_locktime = self.tx.lock_time.to_consensus_u32();

        // Locktime is ignored if all inputs have final sequence
        let input = &self.tx.input[self.input_index];
        if input.sequence.0 == 0xffffffff {
            return Ok(false);
        }

        // Check that locktime types match (block height vs timestamp)
        if (locktime < 500_000_000 && tx_locktime >= 500_000_000)
            || (locktime >= 500_000_000 && tx_locktime < 500_000_000)
        {
            return Ok(false);
        }

        Ok(tx_locktime >= locktime)
    }

    fn check_sequence(&self, sequence: i64) -> ScriptResult<bool> {
        // Use BIP112 implementation for CHECKSEQUENCEVERIFY
        let result = bip112::verify_checksequenceverify(
            self.tx,
            self.input_index,
            sequence,
            self.tx.version.0,
        )
        .map_err(|_| ScriptError::InvalidStackOperation)?;

        Ok(result)
    }
}

/// Check if signature S value bytes are low
fn is_low_s_bytes(s_bytes: &[u8]) -> bool {
    // Check if S value is at most half the curve order
    // This prevents signature malleability

    // Half of the curve order
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];

    if s_bytes.len() != 32 {
        return false;
    }

    for i in 0..32 {
        if s_bytes[i] < HALF_ORDER[i] {
            return true;
        }
        if s_bytes[i] > HALF_ORDER[i] {
            return false;
        }
    }
    true
}

/// Validate DER encoding
fn is_valid_der(sig: &[u8]) -> bool {
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }

    // Check header byte
    if sig[0] != 0x30 {
        return false;
    }

    // Check length
    if sig[1] as usize != sig.len() - 2 {
        return false;
    }

    // Check R value
    if sig[2] != 0x02 {
        return false;
    }

    let r_len = sig[3] as usize;
    if r_len == 0 || r_len > 33 {
        return false;
    }

    // Check for negative R
    if sig[4] & 0x80 != 0 {
        return false;
    }

    // Check for excessive padding
    if r_len > 1 && sig[4] == 0 && sig[5] & 0x80 == 0 {
        return false;
    }

    // Check S value
    let s_pos = 4 + r_len;
    if s_pos + 2 >= sig.len() {
        return false;
    }

    if sig[s_pos] != 0x02 {
        return false;
    }

    let s_len = sig[s_pos + 1] as usize;
    if s_len == 0 || s_len > 33 {
        return false;
    }

    // Check for negative S
    if sig[s_pos + 2] & 0x80 != 0 {
        return false;
    }

    // Check for excessive padding
    if s_len > 1 && sig[s_pos + 2] == 0 && sig[s_pos + 3] & 0x80 == 0 {
        return false;
    }

    // Check total length
    if s_pos + 2 + s_len != sig.len() {
        return false;
    }

    true
}
