use anyhow::{Context, Result};
use bitcoin::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

/// Mempool persistence for saving/loading mempool state across restarts
#[derive(Debug, Serialize, Deserialize)]
pub struct MempoolSnapshot {
    /// Version for forward compatibility
    pub version: u32,
    /// Timestamp when snapshot was taken
    pub timestamp: u64,
    /// All transactions in mempool
    pub transactions: Vec<SerializedTransaction>,
    /// Fee rates for transactions
    pub fee_rates: HashMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SerializedTransaction {
    /// Transaction ID as hex string
    pub txid: String,
    /// Serialized transaction data in hex
    pub hex: String,
    /// Time when transaction was added
    pub added_time: u64,
    /// Fee rate in satoshis per vbyte
    pub fee_rate: u64,
}

pub struct MempoolPersistence {
    mempool_path: std::path::PathBuf,
}

impl MempoolPersistence {
    pub fn new(data_dir: &Path) -> Self {
        let mempool_path = data_dir.join("mempool.dat");
        Self { mempool_path }
    }

    /// Save mempool snapshot to disk
    pub async fn save_snapshot(
        &self,
        transactions: &HashMap<bitcoin::Txid, Transaction>,
        fee_rates: &HashMap<bitcoin::Txid, u64>,
    ) -> Result<()> {
        info!(
            "Saving mempool snapshot with {} transactions",
            transactions.len()
        );

        let mut serialized_txs = Vec::new();
        let mut fee_rate_strings = HashMap::new();

        for (txid, tx) in transactions {
            let tx_hex = bitcoin::consensus::encode::serialize_hex(tx);
            let fee_rate = fee_rates.get(txid).copied().unwrap_or(1);

            serialized_txs.push(SerializedTransaction {
                txid: txid.to_string(),
                hex: tx_hex,
                added_time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                fee_rate,
            });

            fee_rate_strings.insert(txid.to_string(), fee_rate);
        }

        let snapshot = MempoolSnapshot {
            version: 1,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            transactions: serialized_txs,
            fee_rates: fee_rate_strings,
        };

        // Serialize to JSON
        let json = serde_json::to_vec(&snapshot).context("Failed to serialize mempool snapshot")?;

        // Write to temporary file first, then rename (atomic operation)
        let temp_path = self.mempool_path.with_extension("tmp");

        let mut file = fs::File::create(&temp_path)
            .await
            .context("Failed to create temporary mempool file")?;

        file.write_all(&json)
            .await
            .context("Failed to write mempool data")?;

        file.sync_all()
            .await
            .context("Failed to sync mempool file")?;

        // Atomically rename temp file to final location
        fs::rename(&temp_path, &self.mempool_path)
            .await
            .context("Failed to rename mempool file")?;

        info!("Mempool snapshot saved successfully");
        Ok(())
    }

    /// Load mempool snapshot from disk
    pub async fn load_snapshot(&self) -> Result<MempoolSnapshot> {
        if !self.mempool_path.exists() {
            debug!("No mempool snapshot found at {:?}", self.mempool_path);
            return Ok(MempoolSnapshot {
                version: 1,
                timestamp: 0,
                transactions: Vec::new(),
                fee_rates: HashMap::new(),
            });
        }

        info!("Loading mempool snapshot from {:?}", self.mempool_path);

        let mut file = fs::File::open(&self.mempool_path)
            .await
            .context("Failed to open mempool file")?;

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .await
            .context("Failed to read mempool file")?;

        let snapshot: MempoolSnapshot =
            serde_json::from_slice(&contents).context("Failed to deserialize mempool snapshot")?;

        // Check version compatibility
        if snapshot.version > 1 {
            warn!(
                "Mempool snapshot version {} is newer than supported version 1",
                snapshot.version
            );
        }

        info!(
            "Loaded mempool snapshot with {} transactions",
            snapshot.transactions.len()
        );
        Ok(snapshot)
    }

    /// Delete mempool snapshot
    pub async fn delete_snapshot(&self) -> Result<()> {
        if self.mempool_path.exists() {
            fs::remove_file(&self.mempool_path)
                .await
                .context("Failed to delete mempool snapshot")?;
            debug!("Deleted mempool snapshot");
        }
        Ok(())
    }

    /// Restore transactions from snapshot
    pub fn restore_transactions(
        &self,
        snapshot: &MempoolSnapshot,
    ) -> Result<Vec<(bitcoin::Txid, Transaction, u64)>> {
        let mut restored = Vec::new();

        // Check age of snapshot - skip if too old (> 2 weeks)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        const TWO_WEEKS_SECS: u64 = 14 * 24 * 60 * 60;

        if snapshot.timestamp > 0 && now > snapshot.timestamp + TWO_WEEKS_SECS {
            warn!("Mempool snapshot is older than 2 weeks, discarding");
            return Ok(Vec::new());
        }

        for serialized_tx in &snapshot.transactions {
            // Skip transactions older than 2 weeks
            if now > serialized_tx.added_time + TWO_WEEKS_SECS {
                debug!("Skipping old transaction {}", serialized_tx.txid);
                continue;
            }

            // Deserialize transaction
            match bitcoin::consensus::encode::deserialize_hex::<Transaction>(&serialized_tx.hex) {
                Ok(tx) => {
                    let txid = tx.compute_txid();

                    // Verify txid matches
                    if txid.to_string() != serialized_tx.txid {
                        warn!(
                            "Transaction ID mismatch: {} vs {}",
                            txid, serialized_tx.txid
                        );
                        continue;
                    }

                    restored.push((txid, tx, serialized_tx.fee_rate));
                }
                Err(e) => {
                    warn!(
                        "Failed to deserialize transaction {}: {}",
                        serialized_tx.txid, e
                    );
                }
            }
        }

        info!("Restored {} transactions from snapshot", restored.len());
        Ok(restored)
    }

    /// Prune old transactions from snapshot before saving
    pub fn prune_old_transactions(snapshot: &mut MempoolSnapshot) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        const TWO_WEEKS_SECS: u64 = 14 * 24 * 60 * 60;

        let before_count = snapshot.transactions.len();

        snapshot
            .transactions
            .retain(|tx| now <= tx.added_time + TWO_WEEKS_SECS);

        let removed = before_count - snapshot.transactions.len();
        if removed > 0 {
            debug!("Pruned {} old transactions from mempool", removed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mempool_persistence() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let persistence = MempoolPersistence::new(temp_dir.path());

        // Create test transaction
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let txid = tx.compute_txid();
        let mut transactions = HashMap::new();
        transactions.insert(txid, tx);

        let mut fee_rates = HashMap::new();
        fee_rates.insert(txid, 10);

        // Save snapshot
        persistence.save_snapshot(&transactions, &fee_rates).await?;

        // Load snapshot
        let snapshot = persistence.load_snapshot().await?;
        assert_eq!(snapshot.transactions.len(), 1);

        // Restore transactions
        let restored = persistence.restore_transactions(&snapshot)?;
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].0, txid);
        assert_eq!(restored[0].2, 10);

        Ok(())
    }

    #[test]
    fn test_prune_old_transactions() {
        let mut snapshot = MempoolSnapshot {
            version: 1,
            timestamp: 0,
            transactions: vec![
                SerializedTransaction {
                    txid: "test1".to_string(),
                    hex: "".to_string(),
                    added_time: 0, // Very old
                    fee_rate: 1,
                },
                SerializedTransaction {
                    txid: "test2".to_string(),
                    hex: "".to_string(),
                    added_time: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(), // Current
                    fee_rate: 1,
                },
            ],
            fee_rates: HashMap::new(),
        };

        MempoolPersistence::prune_old_transactions(&mut snapshot);
        assert_eq!(snapshot.transactions.len(), 1);
        assert_eq!(snapshot.transactions[0].txid, "test2");
    }
}
