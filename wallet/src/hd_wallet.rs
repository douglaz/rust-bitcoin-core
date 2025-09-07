use anyhow::{bail, Result};
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, PublicKey};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::{debug, info, trace};

/// HD Wallet implementation following BIP32/BIP39/BIP44/BIP49/BIP84
pub struct HDWallet {
    /// Master extended private key
    master_key: ExtendedPrivKey,

    /// Master extended public key
    master_pubkey: ExtendedPubKey,

    /// Network
    network: Network,

    /// Mnemonic phrase (optional, for backup)
    mnemonic: Option<Mnemonic>,

    /// Derived keys cache
    key_cache: HashMap<DerivationPath, ExtendedPrivKey>,

    /// Address cache
    address_cache: HashMap<DerivationPath, Address>,

    /// Secp256k1 context
    secp: Secp256k1<secp256k1::All>,
}

impl HDWallet {
    /// Create a new HD wallet from mnemonic
    pub fn from_mnemonic(
        mnemonic_str: &str,
        passphrase: Option<&str>,
        network: Network,
    ) -> Result<Self> {
        let mnemonic = Mnemonic::parse_normalized(mnemonic_str)
            .map_err(|e| anyhow::anyhow!("Invalid mnemonic phrase: {:?}", e))?;

        let seed_bytes = mnemonic.to_seed(passphrase.unwrap_or(""));

        if seed_bytes.len() < 32 {
            bail!("Seed too short");
        }

        let secp = Secp256k1::new();
        let master_key = ExtendedPrivKey::new_master(network, &seed_bytes)?;
        let master_pubkey = ExtendedPubKey::from_priv(&secp, &master_key);

        info!(
            "Created HD wallet with fingerprint: {}",
            master_key.fingerprint(&secp)
        );

        Ok(Self {
            master_key,
            master_pubkey,
            network,
            mnemonic: Some(mnemonic),
            key_cache: HashMap::new(),
            address_cache: HashMap::new(),
            secp,
        })
    }

    /// Create from seed bytes
    pub fn from_seed(seed: &[u8], network: Network) -> Result<Self> {
        if seed.len() < 32 {
            bail!("Seed must be at least 32 bytes");
        }

        let secp = Secp256k1::new();
        let master_key = ExtendedPrivKey::new_master(network, seed)?;
        let master_pubkey = ExtendedPubKey::from_priv(&secp, &master_key);

        Ok(Self {
            master_key,
            master_pubkey,
            network,
            mnemonic: None,
            key_cache: HashMap::new(),
            address_cache: HashMap::new(),
            secp,
        })
    }

    /// Generate a new mnemonic wallet
    pub fn generate(word_count: usize, passphrase: Option<&str>, network: Network) -> Result<Self> {
        // Calculate entropy size from word count
        let entropy_bits = match word_count {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            _ => bail!("Invalid word count. Must be 12, 15, 18, 21, or 24"),
        };

        // Generate entropy and create mnemonic
        let entropy = (0..entropy_bits / 8)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| anyhow::anyhow!("Failed to create mnemonic: {:?}", e))?;
        let mnemonic_str = mnemonic.to_string();

        Self::from_mnemonic(&mnemonic_str, passphrase, network)
    }

    /// Derive a key at a specific path
    pub fn derive_key(&mut self, path: &DerivationPath) -> Result<ExtendedPrivKey> {
        // Check cache
        if let Some(key) = self.key_cache.get(path) {
            return Ok(*key);
        }

        // Derive key
        let derived = self.master_key.derive_priv(&self.secp, path)?;

        // Cache it
        self.key_cache.insert(path.clone(), derived);

        trace!("Derived key at path: {}", path);
        Ok(derived)
    }

    /// Derive public key at path
    pub fn derive_pubkey(&mut self, path: &DerivationPath) -> Result<ExtendedPubKey> {
        let priv_key = self.derive_key(path)?;
        Ok(ExtendedPubKey::from_priv(&self.secp, &priv_key))
    }

    /// Get address for a derivation path
    pub fn get_address(
        &mut self,
        path: &DerivationPath,
        address_type: AddressType,
    ) -> Result<Address> {
        // Check cache
        if let Some(address) = self.address_cache.get(path) {
            return Ok(address.clone());
        }

        let key = self.derive_key(path)?;
        let pubkey = PublicKey::from_private_key(&self.secp, &key.to_priv());

        let address = match address_type {
            AddressType::P2PKH => {
                let compressed = bitcoin::key::CompressedPublicKey::try_from(pubkey)
                    .map_err(|e| anyhow::anyhow!("Failed to compress public key: {:?}", e))?;
                Address::p2pkh(compressed, self.network)
            }
            AddressType::P2SH_P2WPKH => {
                // P2SH-wrapped P2WPKH (BIP49)
                let compressed = bitcoin::key::CompressedPublicKey::try_from(pubkey)
                    .map_err(|e| anyhow::anyhow!("Failed to compress public key: {:?}", e))?;
                Address::p2shwpkh(&compressed, self.network)
            }
            AddressType::P2WPKH => {
                // Native SegWit (BIP84)
                let compressed = bitcoin::key::CompressedPublicKey::try_from(pubkey)
                    .map_err(|e| anyhow::anyhow!("Failed to compress public key: {:?}", e))?;
                Address::p2wpkh(&compressed, self.network)
            }
            AddressType::P2TR => {
                // Taproot (BIP86)
                let (xonly, _parity) = pubkey.inner.x_only_public_key();
                Address::p2tr(&self.secp, xonly, None, self.network)
            }
        };

        // Cache it
        self.address_cache.insert(path.clone(), address.clone());

        Ok(address)
    }

    /// Get BIP44 address (legacy P2PKH)
    /// m/44'/coin'/account'/change/index
    pub fn get_bip44_address(&mut self, account: u32, change: bool, index: u32) -> Result<Address> {
        let coin_type = get_coin_type(self.network);
        let path = DerivationPath::from_str(&format!(
            "m/44'/{}'/{}'/{}/{}",
            coin_type,
            account,
            if change { 1 } else { 0 },
            index
        ))?;

        self.get_address(&path, AddressType::P2PKH)
    }

    /// Get BIP49 address (P2SH-wrapped SegWit)
    /// m/49'/coin'/account'/change/index
    pub fn get_bip49_address(&mut self, account: u32, change: bool, index: u32) -> Result<Address> {
        let coin_type = get_coin_type(self.network);
        let path = DerivationPath::from_str(&format!(
            "m/49'/{}'/{}'/{}/{}",
            coin_type,
            account,
            if change { 1 } else { 0 },
            index
        ))?;

        self.get_address(&path, AddressType::P2SH_P2WPKH)
    }

    /// Get BIP84 address (native SegWit)
    /// m/84'/coin'/account'/change/index
    pub fn get_bip84_address(&mut self, account: u32, change: bool, index: u32) -> Result<Address> {
        let coin_type = get_coin_type(self.network);
        let path = DerivationPath::from_str(&format!(
            "m/84'/{}'/{}'/{}/{}",
            coin_type,
            account,
            if change { 1 } else { 0 },
            index
        ))?;

        self.get_address(&path, AddressType::P2WPKH)
    }

    /// Get BIP86 address (Taproot)
    /// m/86'/coin'/account'/change/index
    pub fn get_bip86_address(&mut self, account: u32, change: bool, index: u32) -> Result<Address> {
        let coin_type = get_coin_type(self.network);
        let path = DerivationPath::from_str(&format!(
            "m/86'/{}'/{}'/{}/{}",
            coin_type,
            account,
            if change { 1 } else { 0 },
            index
        ))?;

        self.get_address(&path, AddressType::P2TR)
    }

    /// Get account extended public key (for watch-only wallets)
    pub fn get_account_xpub(&mut self, purpose: u32, account: u32) -> Result<ExtendedPubKey> {
        let coin_type = get_coin_type(self.network);
        let path =
            DerivationPath::from_str(&format!("m/{}'/{}'/{}'", purpose, coin_type, account))?;

        self.derive_pubkey(&path)
    }

    /// Sign a message with a key at path
    pub fn sign_message(&mut self, path: &DerivationPath, message: &[u8]) -> Result<Vec<u8>> {
        let key = self.derive_key(path)?;
        let secret_key = key.to_priv().inner;

        // Create message hash
        use bitcoin::hashes::{Hash, HashEngine};
        let mut engine = bitcoin::hashes::sha256d::Hash::engine();
        engine.input(message);
        let hash = bitcoin::hashes::sha256d::Hash::from_engine(engine);
        let msg = secp256k1::Message::from_digest(*hash.as_ref());

        // Sign
        let sig = self.secp.sign_ecdsa(&msg, &secret_key);

        Ok(sig.serialize_der().to_vec())
    }

    /// Get the master fingerprint
    pub fn fingerprint(&self) -> Fingerprint {
        self.master_key.fingerprint(&self.secp)
    }

    /// Get the mnemonic phrase (if available)
    pub fn mnemonic(&self) -> Option<String> {
        self.mnemonic.as_ref().map(|m| m.to_string())
    }

    /// Export extended private key at path (DANGEROUS!)
    pub fn export_xpriv(&mut self, path: &DerivationPath) -> Result<String> {
        let key = self.derive_key(path)?;
        Ok(key.to_string())
    }

    /// Export extended public key at path
    pub fn export_xpub(&mut self, path: &DerivationPath) -> Result<String> {
        let pubkey = self.derive_pubkey(path)?;
        Ok(pubkey.to_string())
    }
}

/// Address types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Legacy P2PKH
    P2PKH,
    /// P2SH-wrapped P2WPKH (BIP49)
    P2SH_P2WPKH,
    /// Native SegWit P2WPKH (BIP84)
    P2WPKH,
    /// Taproot P2TR (BIP86)
    P2TR,
}

/// Get coin type for BIP44 based on network
fn get_coin_type(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet | Network::Signet | Network::Regtest => 1,
        _ => 0,
    }
}

/// Account discovery for HD wallets
pub struct AccountDiscovery {
    wallet: HDWallet,
    gap_limit: usize,
}

impl AccountDiscovery {
    pub fn new(wallet: HDWallet, gap_limit: usize) -> Self {
        Self { wallet, gap_limit }
    }

    /// Discover active accounts
    pub async fn discover_accounts(&mut self) -> Result<Vec<AccountInfo>> {
        let mut accounts = Vec::new();
        let mut account_index = 0;

        loop {
            let account_info = self.scan_account(account_index).await?;

            if account_info.used {
                accounts.push(account_info);
                account_index += 1;
            } else {
                // No activity on this account, stop scanning
                break;
            }

            // Safety limit
            if account_index > 100 {
                debug!("Reached maximum account scan limit");
                break;
            }
        }

        info!("Discovered {} active accounts", accounts.len());
        Ok(accounts)
    }

    /// Scan a single account for activity
    async fn scan_account(&mut self, account: u32) -> Result<AccountInfo> {
        let used = false;
        let balance = 0u64;
        let mut addresses = Vec::new();

        // Scan external chain (receiving addresses)
        for index in 0..self.gap_limit {
            let address = self
                .wallet
                .get_bip84_address(account, false, index as u32)?;
            addresses.push(address.clone());

            // In production, would check blockchain for address usage
            // For now, just mark as unused
        }

        // Scan internal chain (change addresses)
        for index in 0..self.gap_limit {
            let address = self.wallet.get_bip84_address(account, true, index as u32)?;
            addresses.push(address.clone());
        }

        Ok(AccountInfo {
            account,
            used,
            balance,
            addresses,
        })
    }
}

/// Account information
#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub account: u32,
    pub used: bool,
    pub balance: u64,
    pub addresses: Vec<Address>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hd_wallet_creation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = HDWallet::from_mnemonic(mnemonic, None, Network::Bitcoin).unwrap();

        assert!(wallet.mnemonic().is_some());
    }

    #[test]
    fn test_address_derivation() {
        let mut wallet = HDWallet::from_seed(&[0u8; 64], Network::Bitcoin).unwrap();

        // Test BIP44 address
        let addr44 = wallet.get_bip44_address(0, false, 0).unwrap();
        assert!(addr44.to_string().starts_with('1')); // Legacy address

        // Test BIP84 address
        let addr84 = wallet.get_bip84_address(0, false, 0).unwrap();
        assert!(addr84.to_string().starts_with("bc1q")); // Native SegWit
    }

    #[test]
    fn test_key_derivation_paths() {
        let mut wallet = HDWallet::from_seed(&[1u8; 64], Network::Bitcoin).unwrap();

        // Standard BIP44 path
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let key = wallet.derive_key(&path).unwrap();

        // Should be cached
        let key2 = wallet.derive_key(&path).unwrap();
        assert_eq!(key.to_string(), key2.to_string());
    }
}
