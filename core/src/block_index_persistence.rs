use anyhow::{Context, Result};
use bitcoin::{block::Header as BlockHeader, BlockHash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::chain::{BlockIndexEntry, BlockStatus};
use crate::work::ChainWork;

/// Persistent block index for fast startup
#[derive(Debug, Serialize, Deserialize)]
pub struct PersistentBlockIndex {
    /// Version for compatibility checking
    version: u32,

    /// Network this index is for
    network: String,

    /// Best block hash
    best_hash: BlockHash,

    /// Best block height
    best_height: u32,

    /// Block index entries
    entries: Vec<SerializedBlockEntry>,

    /// Active chain hashes (in order)
    active_chain: Vec<BlockHash>,

    /// Timestamp of last update
    last_updated: u64,
}

/// Serializable block index entry
#[derive(Debug, Serialize, Deserialize)]
struct SerializedBlockEntry {
    hash: BlockHash,
    height: u32,
    header: BlockHeader,
    total_work: String, // Hex encoded
    status: String,
}

impl From<&BlockIndexEntry> for SerializedBlockEntry {
    fn from(entry: &BlockIndexEntry) -> Self {
        Self {
            hash: entry.hash,
            height: entry.height,
            header: entry.header,
            total_work: entry.total_work.to_hex_string(),
            status: match entry.status {
                BlockStatus::Valid => "valid",
                BlockStatus::Invalid => "invalid",
                BlockStatus::InActiveChain => "active",
                BlockStatus::Orphan => "orphan",
            }
            .to_string(),
        }
    }
}

impl SerializedBlockEntry {
    fn to_block_index_entry(&self) -> Result<BlockIndexEntry> {
        let status = match self.status.as_str() {
            "valid" => BlockStatus::Valid,
            "invalid" => BlockStatus::Invalid,
            "active" => BlockStatus::InActiveChain,
            "orphan" => BlockStatus::Orphan,
            _ => BlockStatus::Valid,
        };

        Ok(BlockIndexEntry {
            hash: self.hash,
            height: self.height,
            header: self.header,
            total_work: ChainWork::from_be_bytes(
                hex::decode(&self.total_work)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid work bytes"))?,
            ),
            status,
        })
    }
}

/// Block index persistence manager
pub struct BlockIndexPersistence {
    /// Data directory
    data_dir: String,

    /// Index file path
    index_path: String,

    /// Backup file path
    backup_path: String,

    /// Write lock to prevent concurrent writes
    write_lock: Arc<RwLock<()>>,
}

impl BlockIndexPersistence {
    /// Create new persistence manager
    pub fn new(data_dir: &str) -> Self {
        let index_path = format!("{}/block_index.json", data_dir);
        let backup_path = format!("{}/block_index.backup.json", data_dir);

        Self {
            data_dir: data_dir.to_string(),
            index_path,
            backup_path,
            write_lock: Arc::new(RwLock::new(())),
        }
    }

    /// Save block index to disk
    pub async fn save_index(
        &self,
        best_hash: BlockHash,
        best_height: u32,
        entries: &HashMap<BlockHash, BlockIndexEntry>,
        active_chain: &[BlockHash],
        network: &str,
    ) -> Result<()> {
        let _lock = self.write_lock.write().await;

        info!("Saving block index with {} entries", entries.len());

        // Convert entries to serializable format
        let serialized_entries: Vec<SerializedBlockEntry> =
            entries.values().map(SerializedBlockEntry::from).collect();

        // Create persistent index
        let index = PersistentBlockIndex {
            version: 1,
            network: network.to_string(),
            best_hash,
            best_height,
            entries: serialized_entries,
            active_chain: active_chain.to_vec(),
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Serialize to JSON
        let json =
            serde_json::to_string_pretty(&index).context("Failed to serialize block index")?;

        // Write to temporary file first
        let temp_path = format!("{}.tmp", self.index_path);
        fs::write(&temp_path, json)
            .await
            .context("Failed to write block index")?;

        // Backup existing index if it exists
        if Path::new(&self.index_path).exists() {
            fs::rename(&self.index_path, &self.backup_path)
                .await
                .context("Failed to backup existing index")?;
        }

        // Move temp file to final location
        fs::rename(&temp_path, &self.index_path)
            .await
            .context("Failed to move index file")?;

        info!("Block index saved successfully");
        Ok(())
    }

    /// Load block index from disk
    pub async fn load_index(
        &self,
        expected_network: &str,
    ) -> Result<
        Option<(
            BlockHash,
            u32,
            HashMap<BlockHash, BlockIndexEntry>,
            Vec<BlockHash>,
        )>,
    > {
        // Check if index file exists
        if !Path::new(&self.index_path).exists() {
            info!("No existing block index found");
            return Ok(None);
        }

        info!("Loading block index from {}", self.index_path);

        // Read index file
        let json = fs::read_to_string(&self.index_path)
            .await
            .context("Failed to read block index")?;

        // Deserialize
        let index: PersistentBlockIndex =
            serde_json::from_str(&json).context("Failed to deserialize block index")?;

        // Check version
        if index.version != 1 {
            warn!("Unsupported block index version: {}", index.version);
            return Ok(None);
        }

        // Check network
        if index.network != expected_network {
            warn!(
                "Block index is for wrong network: expected {}, got {}",
                expected_network, index.network
            );
            return Ok(None);
        }

        // Convert entries back
        let mut entries = HashMap::new();
        for serialized in index.entries {
            match serialized.to_block_index_entry() {
                Ok(entry) => {
                    entries.insert(entry.hash, entry);
                }
                Err(e) => {
                    warn!("Failed to deserialize block entry: {}", e);
                }
            }
        }

        info!(
            "Loaded block index: {} entries, height {}, updated {}s ago",
            entries.len(),
            index.best_height,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - index.last_updated
        );

        Ok(Some((
            index.best_hash,
            index.best_height,
            entries,
            index.active_chain,
        )))
    }

    /// Create checkpoint snapshot
    pub async fn create_checkpoint(&self) -> Result<()> {
        let checkpoint_path = format!(
            "{}/checkpoint_{}.json",
            self.data_dir,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        if Path::new(&self.index_path).exists() {
            fs::copy(&self.index_path, &checkpoint_path)
                .await
                .context("Failed to create checkpoint")?;

            info!("Created checkpoint at {}", checkpoint_path);
        }

        Ok(())
    }

    /// Restore from backup
    pub async fn restore_from_backup(&self) -> Result<bool> {
        if !Path::new(&self.backup_path).exists() {
            return Ok(false);
        }

        warn!("Restoring block index from backup");

        fs::copy(&self.backup_path, &self.index_path)
            .await
            .context("Failed to restore from backup")?;

        info!("Block index restored from backup");
        Ok(true)
    }

    /// Validate index integrity
    pub async fn validate_index(&self) -> Result<bool> {
        if !Path::new(&self.index_path).exists() {
            return Ok(false);
        }

        // Try to load and parse
        let json = fs::read_to_string(&self.index_path).await?;
        let index: PersistentBlockIndex = match serde_json::from_str(&json) {
            Ok(idx) => idx,
            Err(e) => {
                error!("Block index validation failed: {}", e);
                return Ok(false);
            }
        };

        // Basic validation
        if index.entries.is_empty() && index.best_height > 0 {
            error!("Block index has no entries but non-zero height");
            return Ok(false);
        }

        if index.active_chain.len() as u32 != index.best_height + 1 {
            error!(
                "Active chain length {} doesn't match height {}",
                index.active_chain.len(),
                index.best_height + 1
            );
            return Ok(false);
        }

        debug!("Block index validation passed");
        Ok(true)
    }
}

/// Auto-save manager for periodic index persistence
pub struct AutoSaveManager {
    persistence: Arc<BlockIndexPersistence>,
    interval_secs: u64,
    shutdown: Arc<RwLock<bool>>,
}

impl AutoSaveManager {
    /// Create new auto-save manager
    pub fn new(persistence: Arc<BlockIndexPersistence>, interval_secs: u64) -> Self {
        Self {
            persistence,
            interval_secs,
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Start auto-save loop
    pub async fn start<F, Fut>(self, get_state: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<
                Output = (
                    BlockHash,
                    u32,
                    HashMap<BlockHash, BlockIndexEntry>,
                    Vec<BlockHash>,
                    String,
                ),
            > + Send,
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

                // Get current state
                let (best_hash, best_height, entries, active_chain, network) = get_state().await;

                // Save index
                if let Err(e) = self
                    .persistence
                    .save_index(best_hash, best_height, &entries, &active_chain, &network)
                    .await
                {
                    error!("Auto-save failed: {}", e);
                }
            }

            info!("Auto-save manager stopped");
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
    use bitcoin::hashes::Hash;

    #[tokio::test]
    async fn test_save_and_load() {
        let temp_dir = tempfile::tempdir().unwrap();
        let persistence = BlockIndexPersistence::new(temp_dir.path().to_str().unwrap());

        // Create test data
        let mut entries = HashMap::new();
        let hash = BlockHash::from_byte_array([0u8; 32]);
        let entry = BlockIndexEntry {
            hash,
            height: 0,
            header: BlockHeader {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            total_work: ChainWork::zero(),
            status: BlockStatus::InActiveChain,
        };
        entries.insert(hash, entry);

        let active_chain = vec![hash];

        // Save
        persistence
            .save_index(hash, 0, &entries, &active_chain, "test")
            .await
            .unwrap();

        // Load
        let loaded = persistence.load_index("test").await.unwrap();
        assert!(loaded.is_some());

        let (loaded_hash, loaded_height, loaded_entries, loaded_chain) = loaded.unwrap();
        assert_eq!(loaded_hash, hash);
        assert_eq!(loaded_height, 0);
        assert_eq!(loaded_entries.len(), 1);
        assert_eq!(loaded_chain.len(), 1);
    }
}
