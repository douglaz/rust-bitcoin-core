use anyhow::{Context, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::{Block, BlockHash, OutPoint, Transaction, TxOut, Txid};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};

use crate::block_store::{BlockMetadata, BlockStore};
use crate::chain_state::ChainState;
use crate::database::{Database, DatabaseConfig};
use crate::pruning::{PruningConfig, PruningManager};
use crate::undo_store::{BlockUndoData, UndoStore};
use crate::utxo::UtxoSet;
pub use crate::utxo::UtxoStats;
use crate::utxo_store::UtxoStore;

pub struct StorageManager {
    db: Arc<Database>,
    block_store: BlockStore,
    utxo_set: UtxoSet,
    #[allow(dead_code)]
    utxo_store: Arc<UtxoStore>,
    chain_state: ChainState,
    undo_store: UndoStore,
    pruning_manager: Option<Arc<PruningManager>>,
}

impl StorageManager {
    pub async fn new(data_dir: &str) -> Result<Self> {
        info!("Initializing storage at: {}", data_dir);

        // Create data directory if it doesn't exist
        std::fs::create_dir_all(data_dir)?;

        // Configure and open RocksDB database
        let config = DatabaseConfig {
            path: Path::new(data_dir).join("db").to_str().unwrap().to_string(),
            ..Default::default()
        };
        let db = Arc::new(Database::new(config)?);

        // Create temporary sled DB for legacy components (will migrate later)
        let sled_path = Path::new(data_dir).join("sled_temp");
        let sled_db = Arc::new(sled::open(&sled_path)?);

        // Initialize components
        let block_store = BlockStore::new(sled_db.clone());
        let utxo_set = UtxoSet::new(sled_db.clone());
        let chain_state = ChainState::new(sled_db.clone());
        let undo_store = UndoStore::new(sled_db.clone());

        // Create UTXO store with sled tree
        let utxo_tree = db
            .get_db()
            .open_tree("utxo")
            .context("Failed to open UTXO tree")?;
        let utxo_store = Arc::new(UtxoStore::new(Arc::new(utxo_tree)));

        Ok(Self {
            db,
            block_store,
            utxo_set,
            utxo_store,
            chain_state,
            undo_store,
            pruning_manager: None,
        })
    }

    pub async fn store_block(&self, block: Block, height: u32) -> Result<()> {
        let hash = block.block_hash();

        // Store block in RocksDB
        self.db.put_block(&hash, &block)?;
        self.db.put_header(&hash, &block.header, height)?;

        // Store transactions
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            self.db.put_transaction(&txid, tx)?;
        }

        // Update legacy stores (will migrate later)
        self.block_store
            .store(&block, height)
            .await
            .context("Failed to store block in legacy store")?;

        // Update chain tip if this is a new best block
        self.chain_state
            .update_tip(&block.header, height)
            .await
            .context("Failed to update chain tip")?;

        // Update chain tip in database
        self.db.set_best_block_hash(&hash)?;

        debug!("Stored block {} at height {}", hash, height);
        Ok(())
    }

    /// Store block with undo data for potential reorg
    pub async fn store_block_with_undo(
        &self,
        block: Block,
        height: u32,
        undo_data: BlockUndoData,
    ) -> Result<()> {
        let hash = block.block_hash();

        // Store the block
        self.store_block(block, height).await?;

        // Store the undo data
        self.undo_store
            .store(&hash, &undo_data)
            .await
            .context("Failed to store undo data")?;

        debug!("Stored block {} with undo data", hash);
        Ok(())
    }

    pub async fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        // Try RocksDB first
        if let Some(block) = self.db.get_block(hash)? {
            return Ok(Some(block));
        }

        // Fall back to legacy store
        self.block_store.get(hash).await
    }

    /// Get just a block header
    pub async fn get_block_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>> {
        // Try RocksDB first
        if let Some((header, _)) = self.db.get_header(hash)? {
            return Ok(Some(header));
        }

        // Fall back to legacy store
        self.block_store.get_header(hash).await
    }

    /// Get block metadata
    pub async fn get_block_metadata(&self, hash: &BlockHash) -> Result<Option<BlockMetadata>> {
        self.block_store.get_metadata(hash).await
    }

    /// Get block by height
    pub async fn get_block_by_height(&self, height: u32) -> Result<Option<Block>> {
        self.block_store.get_by_height(height).await
    }

    /// Get block hash at height
    pub async fn get_hash_at_height(&self, height: u32) -> Result<Option<BlockHash>> {
        self.block_store.get_hash_at_height(height).await
    }

    pub async fn get_chain_tip(&self) -> Result<Option<(BlockHeader, u32)>> {
        self.chain_state.get_tip().await
    }

    pub async fn update_chain_tip(&self, header: &BlockHeader, height: u32) -> Result<()> {
        self.chain_state.update_tip(header, height).await
    }

    pub async fn get_all_headers(&self) -> Result<Vec<(BlockHash, BlockHeader, u32)>> {
        self.chain_state.get_all_headers().await
    }

    /// Find a transaction by its ID (uses transaction index)
    pub async fn find_transaction(&self, txid: &Txid) -> Result<Option<(Transaction, BlockHash)>> {
        self.block_store.get_transaction(txid).await
    }

    /// Get a specific UTXO
    pub async fn get_utxo(&self, outpoint: &bitcoin::OutPoint) -> Result<Option<bitcoin::TxOut>> {
        self.utxo_set.get_async(outpoint).await
    }

    /// Get UTXO set statistics
    pub async fn get_utxo_stats(&self) -> Result<UtxoStats> {
        self.utxo_set.get_stats().await
    }

    pub async fn close(&self) -> Result<()> {
        info!("Closing storage");
        self.flush().await?;
        Ok(())
    }

    /// Get storage statistics
    pub async fn get_storage_stats(&self) -> Result<StorageStats> {
        let block_stats = self.block_store.get_stats().await?;
        let utxo_stats = self.utxo_set.get_stats().await?;

        Ok(StorageStats {
            block_count: block_stats.block_count,
            max_height: block_stats.max_height,
            tx_count: block_stats.tx_count,
            utxo_count: utxo_stats.count as usize,
            total_size: block_stats.total_size,
        })
    }

    // Get a UTXO implementation helper
    #[allow(dead_code)]
    async fn get_utxo_internal(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        // Try new UTXO store first
        if let Some(entry) = self.utxo_store.get_utxo(outpoint)? {
            return Ok(Some(entry.output));
        }

        // Fall back to legacy UTXO set
        self.utxo_set.get(outpoint)
    }

    /// Prune old blocks to save disk space
    pub async fn prune_blocks_before(&self, height: u32) -> Result<usize> {
        info!("Pruning blocks below height {}", height);
        self.block_store.prune_before(height).await
    }

    /// Delete a block from storage
    pub async fn delete_block(&self, hash: &BlockHash) -> Result<()> {
        // Delete block and its undo data
        self.block_store.delete(hash).await?;
        self.undo_store.delete(hash).await?;
        Ok(())
    }

    /// Get undo data for a block
    pub async fn get_undo_data(&self, hash: &BlockHash) -> Result<Option<BlockUndoData>> {
        self.undo_store.get(hash).await
    }

    /// Prune old undo data
    pub async fn prune_undo_data_before(&self, height: u32) -> Result<usize> {
        info!("Pruning undo data below height {}", height);
        self.undo_store.prune_before(height).await
    }

    /// Flush all data to disk
    pub async fn flush(&self) -> Result<()> {
        debug!("Flushing storage to disk");

        // Flush database
        self.db.flush()?;

        // Flush UTXO store
        self.utxo_store.flush()?;

        // Flush UTXO set (if it has a flush method)
        if let Err(e) = self.utxo_set.flush() {
            debug!("UTXO set flush not available or failed: {}", e);
        }

        // Note: block_store uses async tokio fs which auto-flushes

        info!("Storage flushed successfully");
        Ok(())
    }

    /// Get database handle (for direct access)
    pub fn get_db(&self) -> Arc<Database> {
        Arc::clone(&self.db)
    }

    /// Get total storage size in bytes
    pub async fn get_size(&self) -> Result<u64> {
        self.db.get_size().await
    }

    /// Enable pruning with configuration
    pub async fn enable_pruning(&mut self, config: PruningConfig) -> Result<()> {
        if self.pruning_manager.is_none() {
            // Use the data directory from where we store blocks
            let data_dir = Path::new("./data");
            let target_size = config.target_size;
            let pruning_manager = PruningManager::new(data_dir, config)?;
            pruning_manager.initialize().await?;
            self.pruning_manager = Some(Arc::new(pruning_manager));
            info!(
                "Pruning enabled with target size: {} GB",
                target_size / 1_000_000_000
            );
        }
        Ok(())
    }

    /// Check if pruning is enabled
    pub fn is_pruning_enabled(&self) -> bool {
        self.pruning_manager.is_some()
    }

    /// Get pruning manager
    pub fn pruning_manager(&self) -> Option<Arc<PruningManager>> {
        self.pruning_manager.clone()
    }

    /// Prune old blocks if needed
    pub async fn prune_if_needed(&self) -> Result<()> {
        if let Some(ref pruning_manager) = self.pruning_manager {
            if pruning_manager.should_prune().await {
                let result = pruning_manager.prune().await?;
                info!(
                    "Pruned {} blocks, freed {} MB",
                    result.blocks_pruned,
                    result.bytes_freed / 1_000_000
                );

                // After pruning, trigger a database compaction
                // Note: Sled automatically handles compaction
                self.db.flush()?;
            }
        }
        Ok(())
    }

    /// Check if a block is available (not pruned)
    pub async fn is_block_available(&self, height: u32) -> bool {
        if let Some(ref pruning_manager) = self.pruning_manager {
            pruning_manager.is_block_available(height).await
        } else {
            true // All blocks available if not pruning
        }
    }
}

/// Overall storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub block_count: usize,
    pub max_height: u32,
    pub tx_count: usize,
    pub utxo_count: usize,
    pub total_size: u64,
}
