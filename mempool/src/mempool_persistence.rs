use anyhow::{Context, Result};
use bitcoin::{Transaction, Txid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// Use the acceptance module's entry for persistence
use crate::mempool_acceptance::MempoolEntry;

/// Persistent mempool for saving unconfirmed transactions
#[derive(Debug, Serialize, Deserialize)]
pub struct PersistentMempool {
    /// Version for compatibility
    version: u32,

    /// Saved transactions
    transactions: Vec<SerializedMempoolEntry>,

    /// Timestamp of save
    saved_at: u64,

    /// Network
    network: String,
}

/// Serializable mempool entry
#[derive(Debug, Serialize, Deserialize)]
struct SerializedMempoolEntry {
    /// Transaction hex
    tx_hex: String,

    /// Fee in satoshis
    fee: u64,

    /// Weight units
    weight: usize,

    /// Entry time
    entry_time: u64,

    /// Entry height
    entry_height: u32,

    /// Fee rate (sats/vB)
    fee_rate: f64,
}

impl SerializedMempoolEntry {
    fn from_entry(tx: &Transaction, entry: &MempoolEntry) -> Self {
        use bitcoin::consensus::serialize;

        Self {
            tx_hex: hex::encode(serialize(tx)),
            fee: entry.fee,
            weight: entry.weight,
            entry_time: entry.time,
            entry_height: entry.height,
            fee_rate: entry.fee_rate,
        }
    }

    fn to_transaction(&self) -> Result<Transaction> {
        use bitcoin::consensus::deserialize;

        let bytes = hex::decode(&self.tx_hex).context("Failed to decode transaction hex")?;

        deserialize(&bytes).context("Failed to deserialize transaction")
    }

    fn to_entry(&self, tx: Transaction) -> MempoolEntry {
        MempoolEntry {
            tx: tx.clone(),
            txid: tx.compute_txid(),
            wtxid: tx.compute_txid(), // MempoolEntry expects Txid type for wtxid
            fee: self.fee,
            vsize: self.weight / 4,
            weight: self.weight,
            fee_rate: self.fee_rate,
            time: self.entry_time,
            height: self.entry_height,
            ancestors: Default::default(),
            descendants: Default::default(),
            rbf: false,
        }
    }
}

/// Mempool persistence manager
pub struct MempoolPersistence {
    /// Data directory
    data_dir: String,

    /// File path
    mempool_path: String,

    /// Backup path
    backup_path: String,

    /// Write lock
    write_lock: Arc<RwLock<()>>,

    /// Maximum transactions to save
    max_saved_txs: usize,
}

impl MempoolPersistence {
    /// Create new persistence manager
    pub fn new(data_dir: &str) -> Self {
        let mempool_path = format!("{}/mempool.json", data_dir);
        let backup_path = format!("{}/mempool.backup.json", data_dir);

        Self {
            data_dir: data_dir.to_string(),
            mempool_path,
            backup_path,
            write_lock: Arc::new(RwLock::new(())),
            max_saved_txs: 5000, // Save up to 5000 transactions
        }
    }

    /// Save mempool to disk
    pub async fn save_mempool(
        &self,
        transactions: &HashMap<Txid, (Transaction, MempoolEntry)>,
        network: &str,
    ) -> Result<()> {
        let _lock = self.write_lock.write().await;

        info!("Saving mempool with {} transactions", transactions.len());

        // Sort by fee rate and take top N transactions
        let mut sorted_txs: Vec<_> = transactions
            .iter()
            .map(|(txid, (tx, entry))| (*txid, tx, entry))
            .collect();

        sorted_txs.sort_by(|a, b| b.2.fee_rate.partial_cmp(&a.2.fee_rate).unwrap());

        sorted_txs.truncate(self.max_saved_txs);

        // Convert to serializable format
        let serialized: Vec<SerializedMempoolEntry> = sorted_txs
            .into_iter()
            .map(|(_, tx, entry)| SerializedMempoolEntry::from_entry(tx, entry))
            .collect();

        // Create persistent mempool
        let persistent = PersistentMempool {
            version: 1,
            transactions: serialized,
            saved_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            network: network.to_string(),
        };

        // Serialize to JSON
        let json =
            serde_json::to_string_pretty(&persistent).context("Failed to serialize mempool")?;

        // Write to temp file
        let temp_path = format!("{}.tmp", self.mempool_path);
        fs::write(&temp_path, json)
            .await
            .context("Failed to write mempool")?;

        // Backup existing file
        if Path::new(&self.mempool_path).exists() {
            fs::rename(&self.mempool_path, &self.backup_path)
                .await
                .context("Failed to backup mempool")?;
        }

        // Move temp to final
        fs::rename(&temp_path, &self.mempool_path)
            .await
            .context("Failed to move mempool file")?;

        info!("Mempool saved successfully");
        Ok(())
    }

    /// Load mempool from disk
    pub async fn load_mempool(
        &self,
        expected_network: &str,
        max_age_secs: u64,
    ) -> Result<Vec<(Transaction, MempoolEntry)>> {
        if !Path::new(&self.mempool_path).exists() {
            info!("No saved mempool found");
            return Ok(Vec::new());
        }

        info!("Loading mempool from {}", self.mempool_path);

        // Read file
        let json = fs::read_to_string(&self.mempool_path)
            .await
            .context("Failed to read mempool file")?;

        // Deserialize
        let persistent: PersistentMempool =
            serde_json::from_str(&json).context("Failed to deserialize mempool")?;

        // Check version
        if persistent.version != 1 {
            warn!("Unsupported mempool version: {}", persistent.version);
            return Ok(Vec::new());
        }

        // Check network
        if persistent.network != expected_network {
            warn!(
                "Mempool is for wrong network: expected {}, got {}",
                expected_network, persistent.network
            );
            return Ok(Vec::new());
        }

        // Check age
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now - persistent.saved_at > max_age_secs {
            warn!("Mempool is too old: {} seconds", now - persistent.saved_at);
            return Ok(Vec::new());
        }

        // Convert to transactions
        let mut loaded = Vec::new();
        let mut failed = 0;

        for serialized in persistent.transactions {
            match serialized.to_transaction() {
                Ok(tx) => {
                    let entry = serialized.to_entry(tx.clone());
                    loaded.push((tx, entry));
                }
                Err(e) => {
                    warn!("Failed to load transaction: {}", e);
                    failed += 1;
                }
            }
        }

        info!(
            "Loaded {} transactions from mempool ({} failed)",
            loaded.len(),
            failed
        );

        Ok(loaded)
    }

    /// Delete saved mempool
    pub async fn clear(&self) -> Result<()> {
        if Path::new(&self.mempool_path).exists() {
            fs::remove_file(&self.mempool_path)
                .await
                .context("Failed to delete mempool file")?;
        }

        if Path::new(&self.backup_path).exists() {
            fs::remove_file(&self.backup_path)
                .await
                .context("Failed to delete backup file")?;
        }

        info!("Mempool persistence cleared");
        Ok(())
    }
}

/// Auto-save manager for periodic mempool persistence
pub struct MempoolAutoSave {
    persistence: Arc<MempoolPersistence>,
    interval_secs: u64,
    shutdown: Arc<RwLock<bool>>,
}

impl MempoolAutoSave {
    /// Create new auto-save manager
    pub fn new(persistence: Arc<MempoolPersistence>, interval_secs: u64) -> Self {
        Self {
            persistence,
            interval_secs,
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Start auto-save loop
    pub async fn start<F, Fut>(self, get_mempool: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = (HashMap<Txid, (Transaction, MempoolEntry)>, String)>
            + Send,
    {
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(self.interval_secs));

            loop {
                interval.tick().await;

                if *shutdown.read().await {
                    break;
                }

                // Get current mempool
                let (transactions, network) = get_mempool().await;

                // Skip if empty
                if transactions.is_empty() {
                    continue;
                }

                // Save
                if let Err(e) = self.persistence.save_mempool(&transactions, &network).await {
                    error!("Mempool auto-save failed: {}", e);
                } else {
                    debug!(
                        "Mempool auto-saved with {} transactions",
                        transactions.len()
                    );
                }
            }

            info!("Mempool auto-save stopped");
        });
    }

    /// Stop auto-save
    pub async fn stop(&self) {
        *self.shutdown.write().await = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_save_and_load() {
        let temp_dir = tempfile::tempdir().unwrap();
        let persistence = MempoolPersistence::new(temp_dir.path().to_str().unwrap());

        // Create test transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Use the mempool_acceptance entry for testing
        let entry = crate::mempool_acceptance::MempoolEntry {
            tx: tx.clone(),
            txid: tx.compute_txid(),
            wtxid: tx.compute_txid(),
            fee: 1000,
            vsize: 100,
            weight: 400,
            fee_rate: 2.5,
            time: 12345,
            height: 100,
            ancestors: Default::default(),
            descendants: Default::default(),
            rbf: false,
        };

        let mut transactions = HashMap::new();
        transactions.insert(tx.compute_txid(), (tx.clone(), entry.clone()));

        // Save
        persistence
            .save_mempool(&transactions, "test")
            .await
            .unwrap();

        // Load
        let loaded = persistence.load_mempool("test", 3600).await.unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0.compute_txid(), tx.compute_txid());
        assert_eq!(loaded[0].1.fee, entry.fee);
    }
}
