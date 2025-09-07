use anyhow::{bail, Context, Result};
use argon2::{password_hash::SaltString, Argon2, Params, Version};
use bitcoin::secp256k1::SecretKey;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Encrypted wallet storage version
const WALLET_VERSION: u32 = 1;

/// Argon2 parameters for key derivation
const ARGON2_MEM_COST: u32 = 65536; // 64 MB
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Encrypted wallet data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    /// Wallet version for compatibility
    pub version: u32,

    /// Salt for password derivation
    pub salt: Vec<u8>,

    /// Encrypted master seed
    pub encrypted_seed: Vec<u8>,

    /// Nonce for seed encryption
    pub seed_nonce: Vec<u8>,

    /// Encrypted private keys (address -> encrypted key)
    pub encrypted_keys: HashMap<String, EncryptedKey>,

    /// Wallet metadata (unencrypted)
    pub metadata: WalletMetadata,

    /// Authentication tag for integrity
    pub auth_tag: Vec<u8>,
}

/// Encrypted key data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    /// Encrypted private key bytes
    pub ciphertext: Vec<u8>,

    /// Nonce for this key
    pub nonce: Vec<u8>,

    /// Key derivation path
    pub path: String,

    /// Associated Bitcoin address
    pub address: String,
}

/// Wallet metadata (stored unencrypted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMetadata {
    /// Wallet creation timestamp
    pub created_at: u64,

    /// Last modification timestamp
    pub modified_at: u64,

    /// Wallet name/label
    pub name: String,

    /// Network type (mainnet, testnet, etc.)
    pub network: String,

    /// Number of keys in wallet
    pub key_count: usize,

    /// HD wallet fingerprint
    pub fingerprint: Option<[u8; 4]>,
}

/// Secure passphrase wrapper that zeros memory on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct Passphrase(Vec<u8>);

impl Passphrase {
    /// Create from string
    pub fn from_string(s: String) -> Self {
        Self(s.into_bytes())
    }

    /// Create from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Wallet encryption manager
pub struct WalletEncryption {
    /// Derived encryption key (if unlocked)
    encryption_key: Option<Key>,

    /// Wallet file path
    wallet_path: PathBuf,

    /// Encrypted wallet data
    encrypted_data: Option<EncryptedWallet>,

    /// Decrypted keys cache (address -> SecretKey)
    decrypted_keys: HashMap<String, SecretKey>,

    /// Lock state
    is_locked: bool,
}

impl WalletEncryption {
    /// Create new encrypted wallet with mnemonic-derived seed
    pub async fn create_with_seed(
        wallet_path: PathBuf,
        passphrase: Passphrase,
        seed: &[u8],
        metadata: WalletMetadata,
    ) -> Result<Self> {
        info!(
            "Creating new encrypted wallet with provided seed at {:?}",
            wallet_path
        );

        // Generate salt for key derivation
        let salt = SaltString::generate(&mut OsRng);

        // Derive encryption key from passphrase
        let key = Self::derive_key(&passphrase, salt.as_ref())?;

        // Encrypt the provided seed
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted_seed = cipher
            .encrypt(&nonce, seed)
            .map_err(|e| anyhow::anyhow!("Failed to encrypt master seed: {:?}", e))?;

        // Create encrypted wallet structure
        let encrypted_wallet = EncryptedWallet {
            version: WALLET_VERSION,
            salt: salt.to_string().into_bytes(),
            encrypted_seed,
            seed_nonce: nonce.to_vec(),
            encrypted_keys: HashMap::new(),
            metadata,
            auth_tag: vec![],
        };

        // Save to disk
        Self::save_to_disk(&wallet_path, &encrypted_wallet).await?;

        Ok(Self {
            encryption_key: Some(key),
            wallet_path,
            encrypted_data: Some(encrypted_wallet),
            decrypted_keys: HashMap::new(),
            is_locked: false,
        })
    }

    /// Create new encrypted wallet with generated seed
    pub async fn create_new(
        wallet_path: PathBuf,
        passphrase: Passphrase,
        metadata: WalletMetadata,
    ) -> Result<Self> {
        info!("Creating new encrypted wallet at {:?}", wallet_path);

        // Generate salt for key derivation
        let salt = SaltString::generate(&mut OsRng);

        // Derive encryption key from passphrase
        let key = Self::derive_key(&passphrase, salt.as_ref())?;

        // Generate master seed
        let mut seed = vec![0u8; 64];
        OsRng.fill_bytes(&mut seed);

        // Encrypt master seed
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted_seed = cipher
            .encrypt(&nonce, seed.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to encrypt master seed: {:?}", e))?;

        // Clear seed from memory
        seed.zeroize();

        // Create encrypted wallet structure
        let encrypted_wallet = EncryptedWallet {
            version: WALLET_VERSION,
            salt: salt.to_string().into_bytes(),
            encrypted_seed,
            seed_nonce: nonce.to_vec(),
            encrypted_keys: HashMap::new(),
            metadata,
            auth_tag: vec![],
        };

        // Save to disk
        Self::save_to_disk(&wallet_path, &encrypted_wallet).await?;

        Ok(Self {
            encryption_key: Some(key),
            wallet_path,
            encrypted_data: Some(encrypted_wallet),
            decrypted_keys: HashMap::new(),
            is_locked: false,
        })
    }

    /// Load existing encrypted wallet
    pub async fn load_from_disk(wallet_path: PathBuf) -> Result<Self> {
        info!("Loading encrypted wallet from {:?}", wallet_path);

        let encrypted_wallet = Self::read_from_disk(&wallet_path).await?;

        // Verify version
        if encrypted_wallet.version != WALLET_VERSION {
            bail!("Unsupported wallet version: {}", encrypted_wallet.version);
        }

        Ok(Self {
            encryption_key: None,
            wallet_path,
            encrypted_data: Some(encrypted_wallet),
            decrypted_keys: HashMap::new(),
            is_locked: true,
        })
    }

    /// Unlock wallet with passphrase
    pub fn unlock(&mut self, passphrase: Passphrase) -> Result<()> {
        if !self.is_locked {
            return Ok(());
        }

        let encrypted_wallet = self
            .encrypted_data
            .as_ref()
            .context("No encrypted wallet loaded")?;

        // Derive key from passphrase
        let salt_str = std::str::from_utf8(&encrypted_wallet.salt).context("Invalid salt")?;
        let key = Self::derive_key(&passphrase, salt_str)?;

        // Verify passphrase by decrypting seed
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(&encrypted_wallet.seed_nonce);

        match cipher.decrypt(nonce, encrypted_wallet.encrypted_seed.as_ref()) {
            Ok(_seed) => {
                self.encryption_key = Some(key);
                self.is_locked = false;
                info!("Wallet unlocked successfully");
                Ok(())
            }
            Err(_) => {
                bail!("Invalid passphrase");
            }
        }
    }

    /// Lock wallet
    pub fn lock(&mut self) {
        self.encryption_key = None;
        self.decrypted_keys.clear();
        self.is_locked = true;
        info!("Wallet locked");
    }

    /// Change wallet passphrase
    pub async fn change_passphrase(
        &mut self,
        old_passphrase: Passphrase,
        new_passphrase: Passphrase,
    ) -> Result<()> {
        // Unlock with old passphrase
        if self.is_locked {
            self.unlock(old_passphrase.clone())?;
        }

        let mut encrypted_wallet = self
            .encrypted_data
            .as_ref()
            .context("No encrypted wallet loaded")?
            .clone();

        // Decrypt seed with old key
        let old_key = self
            .encryption_key
            .as_ref()
            .context("Wallet not unlocked")?;
        let cipher = ChaCha20Poly1305::new(old_key);
        let nonce = Nonce::from_slice(&encrypted_wallet.seed_nonce);
        let seed = cipher
            .decrypt(nonce, encrypted_wallet.encrypted_seed.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to decrypt seed: {:?}", e))?;

        // Generate new salt and derive new key
        let new_salt = SaltString::generate(&mut OsRng);
        let new_key = Self::derive_key(&new_passphrase, new_salt.as_ref())?;

        // Re-encrypt seed with new key
        let new_cipher = ChaCha20Poly1305::new(&new_key);
        let new_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let new_encrypted_seed = new_cipher
            .encrypt(&new_nonce, seed.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to re-encrypt seed: {:?}", e))?;

        // Re-encrypt all keys
        let mut new_encrypted_keys = HashMap::new();
        for (address, enc_key) in &encrypted_wallet.encrypted_keys {
            // Decrypt with old key
            let key_nonce = Nonce::from_slice(&enc_key.nonce);
            let decrypted = cipher
                .decrypt(key_nonce, enc_key.ciphertext.as_ref())
                .map_err(|e| anyhow::anyhow!("Failed to decrypt key: {:?}", e))?;

            // Re-encrypt with new key
            let new_key_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let new_ciphertext = new_cipher
                .encrypt(&new_key_nonce, decrypted.as_ref())
                .map_err(|e| anyhow::anyhow!("Failed to re-encrypt key: {:?}", e))?;

            new_encrypted_keys.insert(
                address.clone(),
                EncryptedKey {
                    ciphertext: new_ciphertext,
                    nonce: new_key_nonce.to_vec(),
                    path: enc_key.path.clone(),
                    address: enc_key.address.clone(),
                },
            );
        }

        // Update encrypted wallet
        encrypted_wallet.salt = new_salt.to_string().into_bytes();
        encrypted_wallet.encrypted_seed = new_encrypted_seed;
        encrypted_wallet.seed_nonce = new_nonce.to_vec();
        encrypted_wallet.encrypted_keys = new_encrypted_keys;

        // Save to disk
        Self::save_to_disk(&self.wallet_path, &encrypted_wallet).await?;

        // Update state
        self.encrypted_data = Some(encrypted_wallet);
        self.encryption_key = Some(new_key);

        info!("Wallet passphrase changed successfully");
        Ok(())
    }

    /// Add a new private key to the wallet
    pub async fn add_key(
        &mut self,
        secret_key: SecretKey,
        path: String,
        address: String,
    ) -> Result<()> {
        if self.is_locked {
            bail!("Wallet is locked");
        }

        let key = self
            .encryption_key
            .as_ref()
            .context("No encryption key available")?;

        // Encrypt the private key
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, secret_key.secret_bytes().as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to encrypt private key: {:?}", e))?;

        let encrypted_key = EncryptedKey {
            ciphertext,
            nonce: nonce.to_vec(),
            path,
            address: address.clone(),
        };

        // Update encrypted wallet
        if let Some(ref mut wallet) = self.encrypted_data {
            wallet.encrypted_keys.insert(address.clone(), encrypted_key);
            wallet.metadata.key_count = wallet.encrypted_keys.len();
            wallet.metadata.modified_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Save to disk
            Self::save_to_disk(&self.wallet_path, wallet).await?;
        }

        // Cache decrypted key
        self.decrypted_keys.insert(address, secret_key);

        Ok(())
    }

    /// Get a decrypted private key
    pub fn get_key(&mut self, address: &str) -> Result<SecretKey> {
        if self.is_locked {
            bail!("Wallet is locked");
        }

        // Check cache first
        if let Some(key) = self.decrypted_keys.get(address) {
            return Ok(*key);
        }

        // Decrypt from storage
        let encrypted_wallet = self
            .encrypted_data
            .as_ref()
            .context("No encrypted wallet loaded")?;

        let encrypted_key = encrypted_wallet
            .encrypted_keys
            .get(address)
            .context("Key not found for address")?;

        let key = self
            .encryption_key
            .as_ref()
            .context("No encryption key available")?;

        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&encrypted_key.nonce);
        let decrypted = cipher
            .decrypt(nonce, encrypted_key.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to decrypt private key: {:?}", e))?;

        let secret_key = SecretKey::from_slice(&decrypted).context("Invalid private key")?;

        // Cache for future use
        self.decrypted_keys.insert(address.to_string(), secret_key);

        Ok(secret_key)
    }

    /// List all addresses in the wallet
    pub fn list_addresses(&self) -> Vec<String> {
        self.encrypted_data
            .as_ref()
            .map(|w| w.encrypted_keys.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Check if wallet is locked
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    /// Derive encryption key from passphrase using Argon2
    fn derive_key(passphrase: &Passphrase, salt: &str) -> Result<Key> {
        let params = Params::new(
            ARGON2_MEM_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(32),
        )
        .map_err(|e| anyhow::anyhow!("Failed to create Argon2 params: {:?}", e))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let mut key_bytes = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt.as_bytes(), &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to derive key: {:?}", e))?;

        Ok(Key::from(key_bytes))
    }

    /// Save encrypted wallet to disk
    async fn save_to_disk(path: &Path, wallet: &EncryptedWallet) -> Result<()> {
        let json = serde_json::to_string_pretty(wallet)?;
        fs::write(path, json).await?;
        debug!("Saved encrypted wallet to {:?}", path);
        Ok(())
    }

    /// Read encrypted wallet from disk
    async fn read_from_disk(path: &Path) -> Result<EncryptedWallet> {
        let json = fs::read_to_string(path).await?;
        let wallet: EncryptedWallet = serde_json::from_str(&json)?;
        debug!("Loaded encrypted wallet from {:?}", path);
        Ok(wallet)
    }

    /// Create backup of encrypted wallet
    pub async fn create_backup(&self, backup_path: PathBuf) -> Result<()> {
        let wallet = self
            .encrypted_data
            .as_ref()
            .context("No encrypted wallet loaded")?;

        Self::save_to_disk(&backup_path, wallet).await?;
        info!("Created wallet backup at {:?}", backup_path);
        Ok(())
    }

    /// Restore from backup
    pub async fn restore_from_backup(backup_path: PathBuf, wallet_path: PathBuf) -> Result<Self> {
        let wallet = Self::read_from_disk(&backup_path).await?;

        // Save to new location
        Self::save_to_disk(&wallet_path, &wallet).await?;

        info!("Restored wallet from backup");
        Ok(Self {
            encryption_key: None,
            wallet_path,
            encrypted_data: Some(wallet),
            decrypted_keys: HashMap::new(),
            is_locked: true,
        })
    }
}

impl Drop for WalletEncryption {
    fn drop(&mut self) {
        // Clear sensitive data from memory
        self.decrypted_keys.clear();
        self.encryption_key = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_wallet_encryption() -> Result<()> {
        let dir = tempdir()?;
        let wallet_path = dir.path().join("wallet.enc");

        let metadata = WalletMetadata {
            created_at: 0,
            modified_at: 0,
            name: "Test Wallet".to_string(),
            network: "testnet".to_string(),
            key_count: 0,
            fingerprint: None,
        };

        // Create new encrypted wallet
        let passphrase = Passphrase::from_string("test_password".to_string());
        let mut wallet =
            WalletEncryption::create_new(wallet_path.clone(), passphrase.clone(), metadata).await?;

        // Add a key
        let secret_key = SecretKey::from_slice(&[1u8; 32])?;
        wallet
            .add_key(
                secret_key,
                "m/84'/0'/0'/0/0".to_string(),
                "bc1qtest".to_string(),
            )
            .await?;

        // Lock and unlock
        wallet.lock();
        assert!(wallet.is_locked());

        wallet.unlock(passphrase)?;
        assert!(!wallet.is_locked());

        // Retrieve key
        let retrieved = wallet.get_key("bc1qtest")?;
        assert_eq!(retrieved.secret_bytes(), secret_key.secret_bytes());

        Ok(())
    }

    #[tokio::test]
    async fn test_change_passphrase() -> Result<()> {
        let dir = tempdir()?;
        let wallet_path = dir.path().join("wallet.enc");

        let metadata = WalletMetadata {
            created_at: 0,
            modified_at: 0,
            name: "Test Wallet".to_string(),
            network: "testnet".to_string(),
            key_count: 0,
            fingerprint: None,
        };

        let old_pass = Passphrase::from_string("old_password".to_string());
        let new_pass = Passphrase::from_string("new_password".to_string());

        // Create wallet
        let mut wallet =
            WalletEncryption::create_new(wallet_path.clone(), old_pass.clone(), metadata).await?;

        // Change passphrase
        wallet.change_passphrase(old_pass, new_pass.clone()).await?;

        // Lock and try to unlock with new passphrase
        wallet.lock();
        wallet.unlock(new_pass)?;
        assert!(!wallet.is_locked());

        Ok(())
    }
}
