use anyhow::{Context, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::{Block, BlockHash, OutPoint, TxOut};
use serde::{Deserialize, Serialize};
use sled::{Batch, Db, Tree};
use std::path::Path;
use std::sync::Arc;
use tracing::info;

/// Database trees
const TREE_UTXO: &str = "utxo";
const TREE_BLOCKS: &str = "blocks";
const TREE_HEADERS: &str = "headers";
const TREE_HEIGHT_INDEX: &str = "height_index";
const TREE_TX_INDEX: &str = "tx_index";
const TREE_UNDO: &str = "undo";
const TREE_STATE: &str = "state";

/// UTXO entry in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub outpoint: OutPoint,
    pub output: TxOut,
    pub height: u32,
    pub is_coinbase: bool,
}

/// Block index entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockIndexEntry {
    pub hash: BlockHash,
    pub height: u32,
    pub header: BlockHeader,
    pub total_work: [u8; 32],
}

/// Undo data for reverting blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoData {
    pub spent_outputs: Vec<UtxoEntry>,
    pub created_outputs: Vec<OutPoint>,
}

/// Chain state metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    pub tip_hash: BlockHash,
    pub tip_height: u32,
    pub total_work: [u8; 32],
    pub utxo_count: u64,
}

/// Bitcoin Core database using sled
pub struct CoreDatabase {
    db: Arc<Db>,
    utxo_tree: Tree,
    blocks_tree: Tree,
    headers_tree: Tree,
    height_index: Tree,
    tx_index: Tree,
    undo_tree: Tree,
    state_tree: Tree,
}

impl CoreDatabase {
    /// Open or create database
    pub fn open(path: &Path) -> Result<Self> {
        info!("Opening sled database at {:?}", path);

        let db = sled::open(path).context("Failed to open sled database")?;
        let db = Arc::new(db);

        // Open trees
        let utxo_tree = db.open_tree(TREE_UTXO)?;
        let blocks_tree = db.open_tree(TREE_BLOCKS)?;
        let headers_tree = db.open_tree(TREE_HEADERS)?;
        let height_index = db.open_tree(TREE_HEIGHT_INDEX)?;
        let tx_index = db.open_tree(TREE_TX_INDEX)?;
        let undo_tree = db.open_tree(TREE_UNDO)?;
        let state_tree = db.open_tree(TREE_STATE)?;

        Ok(Self {
            db,
            utxo_tree,
            blocks_tree,
            headers_tree,
            height_index,
            tx_index,
            undo_tree,
            state_tree,
        })
    }

    /// Get UTXO by outpoint
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>> {
        let key = self.utxo_key(outpoint);

        match self.utxo_tree.get(key)? {
            Some(data) => {
                let entry =
                    bincode::deserialize(&data).context("Failed to deserialize UTXO entry")?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Store UTXO
    pub fn put_utxo(&self, entry: &UtxoEntry) -> Result<()> {
        let key = self.utxo_key(&entry.outpoint);
        let value = bincode::serialize(entry).context("Failed to serialize UTXO entry")?;

        self.utxo_tree.insert(key, value)?;
        Ok(())
    }

    /// Remove UTXO
    pub fn delete_utxo(&self, outpoint: &OutPoint) -> Result<()> {
        let key = self.utxo_key(outpoint);
        self.utxo_tree.remove(key)?;
        Ok(())
    }

    /// Batch update UTXOs (atomic operation)
    pub fn update_utxos(&self, to_add: Vec<UtxoEntry>, to_remove: Vec<OutPoint>) -> Result<()> {
        let mut batch = Batch::default();

        // Add new UTXOs
        for entry in to_add {
            let key = self.utxo_key(&entry.outpoint);
            let value = bincode::serialize(&entry).context("Failed to serialize UTXO")?;
            batch.insert(key, value);
        }

        // Remove spent UTXOs
        for outpoint in to_remove {
            let key = self.utxo_key(&outpoint);
            batch.remove(key);
        }

        self.utxo_tree.apply_batch(batch)?;
        self.utxo_tree.flush()?;

        Ok(())
    }

    /// Get block header by hash
    pub fn get_block_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>> {
        let key: &[u8] = hash.as_ref();

        match self.headers_tree.get(key)? {
            Some(data) => {
                let header =
                    bincode::deserialize(&data).context("Failed to deserialize block header")?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    /// Store block header
    pub fn put_block_header(&self, hash: &BlockHash, header: &BlockHeader) -> Result<()> {
        let key: &[u8] = hash.as_ref();
        let value = bincode::serialize(header).context("Failed to serialize block header")?;

        self.headers_tree.insert(key, value)?;
        Ok(())
    }

    /// Get block hash at height
    pub fn get_block_hash_at_height(&self, height: u32) -> Result<Option<BlockHash>> {
        let key = height.to_be_bytes();

        match self.height_index.get(key)? {
            Some(data) => {
                let hash = BlockHash::from_raw_hash(
                    bitcoin::hashes::Hash::from_slice(&data)
                        .context("Invalid block hash in database")?,
                );
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Store block height mapping
    pub fn put_block_height(&self, height: u32, hash: &BlockHash) -> Result<()> {
        let key = height.to_be_bytes();
        let value: &[u8] = hash.as_ref();

        self.height_index.insert(key, value)?;
        Ok(())
    }

    /// Store complete block
    pub fn put_block(&self, hash: &BlockHash, block: &Block, height: u32) -> Result<()> {
        // Store header
        self.put_block_header(hash, &block.header)?;

        // Store height mapping
        self.put_block_height(height, hash)?;

        // Store block data
        let key: &[u8] = hash.as_ref();
        let value = bitcoin::consensus::encode::serialize(block);
        self.blocks_tree.insert(key, value)?;

        // Flush to ensure durability
        self.db.flush()?;

        Ok(())
    }

    /// Get block data
    pub fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        let key: &[u8] = hash.as_ref();

        match self.blocks_tree.get(key)? {
            Some(data) => {
                let block = bitcoin::consensus::encode::deserialize(&data)
                    .context("Failed to deserialize block")?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Store undo data for a block
    pub fn put_undo_data(&self, hash: &BlockHash, undo_data: &UndoData) -> Result<()> {
        let key: &[u8] = hash.as_ref();
        let value = bincode::serialize(undo_data)?;

        self.undo_tree.insert(key, value)?;
        Ok(())
    }

    /// Get undo data for a block
    pub fn get_undo_data(&self, hash: &BlockHash) -> Result<Option<UndoData>> {
        let key: &[u8] = hash.as_ref();

        match self.undo_tree.get(key)? {
            Some(data) => {
                let undo = bincode::deserialize(&data)?;
                Ok(Some(undo))
            }
            None => Ok(None),
        }
    }

    /// Save chain state
    pub fn save_chain_state(&self, state: &ChainState) -> Result<()> {
        let key: &[u8] = b"chain_state";
        let value = bincode::serialize(state)?;

        self.state_tree.insert(key, value)?;
        self.state_tree.flush()?;

        info!(
            "Saved chain state: tip={} height={}",
            state.tip_hash, state.tip_height
        );
        Ok(())
    }

    /// Load chain state
    pub fn load_chain_state(&self) -> Result<Option<ChainState>> {
        let key: &[u8] = b"chain_state";

        match self.state_tree.get(key)? {
            Some(data) => {
                let state = bincode::deserialize(&data)?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Iterate all UTXOs
    pub fn iter_utxos(&self) -> impl Iterator<Item = Result<UtxoEntry>> + '_ {
        self.utxo_tree.iter().map(|item| {
            let (_, value) = item?;
            bincode::deserialize(&value).context("Failed to deserialize UTXO")
        })
    }

    /// Count total UTXOs
    pub fn count_utxos(&self) -> Result<u64> {
        Ok(self.utxo_tree.len() as u64)
    }

    /// Prune old blocks
    pub fn prune_blocks(&self, keep_from_height: u32) -> Result<u64> {
        let mut pruned = 0u64;
        let mut batch = Batch::default();

        for item in self.height_index.iter() {
            let (key, hash_bytes) = item?;
            let height = u32::from_be_bytes(key.as_ref().try_into()?);

            if height < keep_from_height {
                // Delete block data but keep headers
                batch.remove(hash_bytes.clone());
                pruned += 1;
            }
        }

        self.blocks_tree.apply_batch(batch)?;

        info!("Pruned {} blocks below height {}", pruned, keep_from_height);
        Ok(pruned)
    }

    /// Compact database
    pub fn compact(&self) -> Result<()> {
        info!("Compacting database...");

        // Sled doesn't expose manual compaction, but we can flush
        self.db.flush()?;

        info!("Database flush complete");
        Ok(())
    }

    /// Get database statistics
    pub fn get_stats(&self) -> Result<DatabaseStats> {
        let utxo_count = self.count_utxos()?;
        let chain_state = self.load_chain_state()?;

        Ok(DatabaseStats {
            utxo_count,
            tip_height: chain_state.as_ref().map(|s| s.tip_height).unwrap_or(0),
            db_size: self.db.size_on_disk()?,
        })
    }

    // Key generation helpers

    fn utxo_key(&self, outpoint: &OutPoint) -> Vec<u8> {
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(outpoint.txid.as_ref());
        key.extend_from_slice(&outpoint.vout.to_le_bytes());
        key
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub utxo_count: u64,
    pub tip_height: u32,
    pub db_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{TxOut, Txid};

    use tempfile::TempDir;

    #[test]
    fn test_database_operations() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let db = CoreDatabase::open(temp_dir.path())?;

        // Test UTXO operations
        let outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };

        let utxo = UtxoEntry {
            outpoint,
            output: TxOut {
                value: bitcoin::Amount::from_sat(50000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            },
            height: 100,
            is_coinbase: true,
        };

        // Store and retrieve UTXO
        db.put_utxo(&utxo)?;
        let retrieved = db.get_utxo(&outpoint)?;
        assert!(retrieved.is_some());

        // Delete UTXO
        db.delete_utxo(&outpoint)?;
        let deleted = db.get_utxo(&outpoint)?;
        assert!(deleted.is_none());

        Ok(())
    }

    #[test]
    fn test_chain_state() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let db = CoreDatabase::open(temp_dir.path())?;

        let state = ChainState {
            tip_hash: BlockHash::from_byte_array([0u8; 32]),
            tip_height: 1000,
            total_work: [0; 32],
            utxo_count: 50000,
        };

        db.save_chain_state(&state)?;
        let loaded = db.load_chain_state()?;

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.tip_height, 1000);
        assert_eq!(loaded.utxo_count, 50000);

        Ok(())
    }
}
