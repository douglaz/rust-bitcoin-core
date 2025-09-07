use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::Network;
use secp256k1::Secp256k1;
use std::str::FromStr;
use tracing::{debug, info};

use crate::error::{WalletError, WalletResult};

/// HD wallet keychain manager
#[derive(Clone)]
pub struct KeyChain {
    master_key: Xpriv,
    network: Network,
    secp: Secp256k1<secp256k1::All>,
}

impl KeyChain {
    /// Create a new keychain from a mnemonic phrase
    pub fn from_mnemonic(
        mnemonic_str: &str,
        passphrase: &str,
        network: Network,
    ) -> WalletResult<Self> {
        info!("Creating keychain from mnemonic");

        let mnemonic =
            Mnemonic::from_str(mnemonic_str).map_err(|_| WalletError::InvalidMnemonic)?;

        let seed = mnemonic.to_seed(passphrase);
        let secp = Secp256k1::new();

        let master_key = Xpriv::new_master(network, &seed)
            .map_err(|e| WalletError::KeyDerivationFailed(e.to_string()))?;

        Ok(Self {
            master_key,
            network,
            secp,
        })
    }
    
    /// Get the seed from a mnemonic (for encryption purposes)
    pub fn seed_from_mnemonic(mnemonic_str: &str, passphrase: &str) -> WalletResult<Vec<u8>> {
        let mnemonic =
            Mnemonic::from_str(mnemonic_str).map_err(|_| WalletError::InvalidMnemonic)?;
        Ok(mnemonic.to_seed(passphrase).to_vec())
    }

    /// Generate a new random mnemonic (12 words)
    pub fn generate_mnemonic() -> WalletResult<String> {
        // Generate 128 bits of entropy for 12-word mnemonic
        let entropy = rand::random::<[u8; 16]>();
        let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| {
            WalletError::Other(anyhow::anyhow!("Failed to generate mnemonic: {}", e))
        })?;
        Ok(mnemonic.to_string())
    }

    /// Create a BIP84 path for native segwit
    pub fn bip84_path(account: u32, change: u32, index: u32) -> WalletResult<DerivationPath> {
        let path_str = format!("m/84'/0'/{}'/{}/{}", account, change, index);
        DerivationPath::from_str(&path_str)
            .map_err(|e| WalletError::InvalidDerivationPath(e.to_string()))
    }

    /// Create a BIP49 path for nested segwit
    pub fn bip49_path(account: u32, change: u32, index: u32) -> WalletResult<DerivationPath> {
        let path_str = format!("m/49'/0'/{}'/{}/{}", account, change, index);
        DerivationPath::from_str(&path_str)
            .map_err(|e| WalletError::InvalidDerivationPath(e.to_string()))
    }

    /// Create a BIP44 path for legacy addresses
    pub fn bip44_path(account: u32, change: u32, index: u32) -> WalletResult<DerivationPath> {
        let path_str = format!("m/44'/0'/{}'/{}/{}", account, change, index);
        DerivationPath::from_str(&path_str)
            .map_err(|e| WalletError::InvalidDerivationPath(e.to_string()))
    }

    /// Derive a private key at the given path
    pub fn derive_private_key(&self, path: &DerivationPath) -> WalletResult<Xpriv> {
        debug!("Deriving private key at path: {}", path);

        self.master_key
            .derive_priv(&self.secp, path)
            .map_err(|e| WalletError::KeyDerivationFailed(e.to_string()))
    }

    /// Derive a public key at the given path
    pub fn derive_public_key(&self, path: &DerivationPath) -> WalletResult<Xpub> {
        let private_key = self.derive_private_key(path)?;
        Ok(Xpub::from_priv(&self.secp, &private_key))
    }

    /// Get the master public key
    pub fn master_public_key(&self) -> Xpub {
        Xpub::from_priv(&self.secp, &self.master_key)
    }

    /// Get the master fingerprint
    pub fn master_fingerprint(&self) -> Fingerprint {
        self.master_key.fingerprint(&self.secp)
    }

    /// Get the network
    pub fn network(&self) -> Network {
        self.network
    }
}
