use serde::{Deserialize, Serialize};
use sled::Db;
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

use crate::error::WalletResult;

/// Wallet metadata stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMetadata {
    pub name: String,
    pub network: String,
    pub created_at: u64,
    pub encrypted: bool,
    pub derivation_path_type: String, // "bip84", "bip49", "bip44"
    pub gap_limit: u32,
}

/// Address metadata for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAddress {
    pub address: String,
    pub derivation_path: String,
    pub address_type: String,
    pub index: u32,
    pub change: bool,
    pub used: bool,
}

/// Transaction metadata for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTransaction {
    pub txid: String,
    pub raw_tx: Vec<u8>,
    pub height: Option<u32>,
    pub timestamp: u64,
    pub fee: u64,
    pub memo: Option<String>,
}

/// Wallet storage manager
pub struct WalletStorage {
    db: Db,
}

impl WalletStorage {
    /// Open or create wallet storage
    pub fn open(path: &Path) -> WalletResult<Self> {
        info!("Opening wallet storage at: {:?}", path);

        let db = sled::open(path)?;

        Ok(Self { db })
    }

    /// Store wallet metadata
    pub fn store_metadata(&self, metadata: &WalletMetadata) -> WalletResult<()> {
        debug!("Storing wallet metadata");

        let key = b"metadata";
        let value = bincode::serialize(metadata)?;

        self.db.insert(key, value)?;
        self.db.flush()?;

        Ok(())
    }

    /// Load wallet metadata
    pub fn load_metadata(&self) -> WalletResult<Option<WalletMetadata>> {
        debug!("Loading wallet metadata");

        let key = b"metadata";

        if let Some(value) = self.db.get(key)? {
            let metadata = bincode::deserialize(&value)?;
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    /// Store encrypted seed (mnemonic)
    pub fn store_encrypted_seed(&self, encrypted_seed: &[u8]) -> WalletResult<()> {
        debug!("Storing encrypted seed");

        let key = b"encrypted_seed";
        self.db.insert(key, encrypted_seed)?;
        self.db.flush()?;

        Ok(())
    }

    /// Load encrypted seed
    pub fn load_encrypted_seed(&self) -> WalletResult<Option<Vec<u8>>> {
        debug!("Loading encrypted seed");

        let key = b"encrypted_seed";

        if let Some(value) = self.db.get(key)? {
            Ok(Some(value.to_vec()))
        } else {
            Ok(None)
        }
    }

    /// Store an address
    pub fn store_address(&self, address: &StoredAddress) -> WalletResult<()> {
        debug!("Storing address: {}", address.address);

        let tree = self.db.open_tree("addresses")?;
        let key = address.address.as_bytes();
        let value = bincode::serialize(address)?;

        tree.insert(key, value)?;

        Ok(())
    }

    /// Load all addresses
    pub fn load_addresses(&self) -> WalletResult<Vec<StoredAddress>> {
        debug!("Loading all addresses");

        let tree = self.db.open_tree("addresses")?;
        let mut addresses = Vec::new();

        for item in tree.iter() {
            let (_, value) = item?;
            let address: StoredAddress = bincode::deserialize(&value)?;
            addresses.push(address);
        }

        Ok(addresses)
    }

    /// Mark address as used
    pub fn mark_address_used(&self, address: &str) -> WalletResult<()> {
        debug!("Marking address as used: {}", address);

        let tree = self.db.open_tree("addresses")?;
        let key = address.as_bytes();

        if let Some(value) = tree.get(key)? {
            let mut stored: StoredAddress = bincode::deserialize(&value)?;
            stored.used = true;

            let new_value = bincode::serialize(&stored)?;
            tree.insert(key, new_value)?;
        }

        Ok(())
    }

    /// Store a transaction
    pub fn store_transaction(&self, tx: &StoredTransaction) -> WalletResult<()> {
        debug!("Storing transaction: {}", tx.txid);

        let tree = self.db.open_tree("transactions")?;
        let key = tx.txid.as_bytes();
        let value = bincode::serialize(tx)?;

        tree.insert(key, value)?;

        Ok(())
    }

    /// Load all transactions
    pub fn load_transactions(&self) -> WalletResult<Vec<StoredTransaction>> {
        debug!("Loading all transactions");

        let tree = self.db.open_tree("transactions")?;
        let mut transactions = Vec::new();

        for item in tree.iter() {
            let (_, value) = item?;
            let tx: StoredTransaction = bincode::deserialize(&value)?;
            transactions.push(tx);
        }

        Ok(transactions)
    }

    /// Store UTXO set
    pub fn store_utxos(&self, utxos: &[u8]) -> WalletResult<()> {
        debug!("Storing UTXO set");

        let key = b"utxos";
        self.db.insert(key, utxos)?;
        self.db.flush()?;

        Ok(())
    }

    /// Load UTXO set
    pub fn load_utxos(&self) -> WalletResult<Option<Vec<u8>>> {
        debug!("Loading UTXO set");

        let key = b"utxos";

        if let Some(value) = self.db.get(key)? {
            Ok(Some(value.to_vec()))
        } else {
            Ok(None)
        }
    }

    /// Store spent outputs
    pub fn store_spent(&self, spent: &[u8]) -> WalletResult<()> {
        debug!("Storing spent outputs");

        let key = b"spent";
        self.db.insert(key, spent)?;
        self.db.flush()?;

        Ok(())
    }

    /// Load spent outputs
    pub fn load_spent(&self) -> WalletResult<Option<Vec<u8>>> {
        debug!("Loading spent outputs");

        let key = b"spent";

        if let Some(value) = self.db.get(key)? {
            Ok(Some(value.to_vec()))
        } else {
            Ok(None)
        }
    }

    /// Clear all data
    pub fn clear(&self) -> WalletResult<()> {
        info!("Clearing wallet storage");

        self.db.clear()?;
        self.db.flush()?;

        Ok(())
    }

    /// Flush to disk
    pub fn flush(&self) -> WalletResult<()> {
        self.db.flush()?;
        Ok(())
    }

    /// Create a backup of the wallet data
    pub fn create_backup(&self, backup_path: &Path) -> WalletResult<()> {
        info!("Creating wallet backup at: {:?}", backup_path);

        // Create backup data structure
        let backup = WalletBackup {
            version: 1,
            metadata: self.load_metadata()?,
            encrypted_seed: self.load_encrypted_seed()?,
            addresses: self.load_addresses()?,
            transactions: self.load_transactions()?,
            utxos: self.load_utxos()?,
            spent: self.load_spent()?,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Serialize backup to JSON
        let backup_json = serde_json::to_string_pretty(&backup)?;

        // Create parent directories if they don't exist
        if let Some(parent) = backup_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write backup to file
        fs::write(backup_path, backup_json)?;

        info!("Wallet backup created successfully");
        Ok(())
    }

    /// Restore wallet from a backup
    pub fn restore_backup(&self, backup_path: &Path) -> WalletResult<()> {
        info!("Restoring wallet from backup: {:?}", backup_path);

        // Read backup file
        let backup_json = fs::read_to_string(backup_path)?;

        // Deserialize backup
        let backup: WalletBackup = serde_json::from_str(&backup_json)?;

        // Validate backup version
        if backup.version != 1 {
            return Err(crate::error::WalletError::Other(anyhow::anyhow!(
                "Unsupported backup version: {}",
                backup.version
            )));
        }

        // Clear existing data
        self.clear()?;

        // Restore metadata
        if let Some(metadata) = backup.metadata {
            self.store_metadata(&metadata)?;
        }

        // Restore encrypted seed
        if let Some(seed) = backup.encrypted_seed {
            self.store_encrypted_seed(&seed)?;
        }

        // Restore addresses
        for address in backup.addresses {
            self.store_address(&address)?;
        }

        // Restore transactions
        for tx in backup.transactions {
            self.store_transaction(&tx)?;
        }

        // Restore UTXOs
        if let Some(utxos) = backup.utxos {
            self.store_utxos(&utxos)?;
        }

        // Restore spent outputs
        if let Some(spent) = backup.spent {
            self.store_spent(&spent)?;
        }

        // Flush to disk
        self.flush()?;

        info!("Wallet restored successfully from backup");
        Ok(())
    }

    /// Export wallet data to JSON (excluding sensitive data)
    pub fn export_public_data(&self, export_path: &Path) -> WalletResult<()> {
        info!("Exporting public wallet data to: {:?}", export_path);

        let export = WalletExport {
            metadata: self.load_metadata()?,
            addresses: self.load_addresses()?,
            transactions: self.load_transactions()?,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let export_json = serde_json::to_string_pretty(&export)?;

        // Create parent directories if they don't exist
        if let Some(parent) = export_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(export_path, export_json)?;

        info!("Public wallet data exported successfully");
        Ok(())
    }

    /// Verify backup integrity
    pub fn verify_backup(backup_path: &Path) -> WalletResult<BackupInfo> {
        debug!("Verifying wallet backup at: {:?}", backup_path);

        // Check if file exists
        if !backup_path.exists() {
            return Err(crate::error::WalletError::Other(anyhow::anyhow!(
                "Backup file does not exist"
            )));
        }

        // Read and parse backup
        let backup_json = fs::read_to_string(backup_path)?;
        let backup: WalletBackup = serde_json::from_str(&backup_json)?;

        // Check version
        if backup.version != 1 {
            warn!("Backup has unsupported version: {}", backup.version);
        }

        // Gather backup info
        let info = BackupInfo {
            version: backup.version,
            has_metadata: backup.metadata.is_some(),
            has_seed: backup.encrypted_seed.is_some(),
            address_count: backup.addresses.len(),
            transaction_count: backup.transactions.len(),
            has_utxos: backup.utxos.is_some(),
            has_spent: backup.spent.is_some(),
            timestamp: backup.timestamp,
            file_size: fs::metadata(backup_path)?.len(),
        };

        Ok(info)
    }
}

/// Complete wallet backup structure
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletBackup {
    pub version: u32,
    pub metadata: Option<WalletMetadata>,
    pub encrypted_seed: Option<Vec<u8>>,
    pub addresses: Vec<StoredAddress>,
    pub transactions: Vec<StoredTransaction>,
    pub utxos: Option<Vec<u8>>,
    pub spent: Option<Vec<u8>>,
    pub timestamp: u64,
}

/// Public wallet export (without sensitive data)
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletExport {
    pub metadata: Option<WalletMetadata>,
    pub addresses: Vec<StoredAddress>,
    pub transactions: Vec<StoredTransaction>,
    pub timestamp: u64,
}

/// Backup verification info
#[derive(Debug)]
pub struct BackupInfo {
    pub version: u32,
    pub has_metadata: bool,
    pub has_seed: bool,
    pub address_count: usize,
    pub transaction_count: usize,
    pub has_utxos: bool,
    pub has_spent: bool,
    pub timestamp: u64,
    pub file_size: u64,
}
