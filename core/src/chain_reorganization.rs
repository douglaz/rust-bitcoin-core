use anyhow::{bail, Result};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, TxOut, Txid};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::utxo_manager::UtxoManager;
use storage::manager::StorageManager;

/// Maximum reorganization depth allowed (100 blocks)
const MAX_REORG_DEPTH: u32 = 100;

/// Maximum reorganization depth for automatic acceptance (6 blocks)
const MAX_AUTO_REORG_DEPTH: u32 = 6;

/// UTXO undo data for a single transaction
#[derive(Debug, Clone)]
pub struct TxUndoData {
    /// Transaction ID
    pub txid: Txid,

    /// Outputs spent by this transaction (for restoration on disconnect)
    pub spent_outputs: Vec<(OutPoint, TxOut)>,

    /// Outputs created by this transaction (for removal on disconnect)
    pub created_outputs: Vec<OutPoint>,
}

/// UTXO undo data for a complete block
#[derive(Debug, Clone)]
pub struct BlockUndoData {
    /// Block hash
    pub block_hash: BlockHash,

    /// Block height
    pub height: u32,

    /// Transaction undo data (in reverse order for disconnection)
    pub tx_undo_data: Vec<TxUndoData>,

    /// Previous chain tip before this block
    pub prev_tip: BlockHash,

    /// Timestamp when connected
    pub connected_at: u64,
}

/// Result of a chain reorganization
#[derive(Debug, Clone)]
pub struct ReorgResult {
    /// Blocks disconnected from the old chain
    pub disconnected_blocks: Vec<(BlockHash, u32)>,

    /// Blocks connected to the new chain
    pub connected_blocks: Vec<(BlockHash, u32)>,

    /// New chain tip
    pub new_tip: BlockHash,

    /// New chain height
    pub new_height: u32,

    /// Old chain tip
    pub old_tip: BlockHash,

    /// Old chain height
    pub old_height: u32,

    /// Fork point
    pub fork_point: BlockHash,

    /// Fork height
    pub fork_height: u32,

    /// Total work difference
    pub work_difference: i64,

    /// Total number of transactions affected by the reorg
    pub txs_affected: u64,

    /// Total number of UTXOs restored during disconnection
    pub utxos_restored: u64,

    /// Total number of UTXOs removed during reconnection
    pub utxos_removed: u64,
}

/// Statistics about reorganizations
#[derive(Debug, Default, Clone)]
pub struct ReorgStats {
    /// Total number of reorganizations
    pub total_reorgs: u64,

    /// Deepest reorganization depth
    pub max_depth: u32,

    /// Average reorganization depth
    pub avg_depth: f64,

    /// Number of blocks disconnected
    pub blocks_disconnected: u64,

    /// Number of blocks connected
    pub blocks_connected: u64,

    /// Number of transactions affected
    pub txs_affected: u64,

    /// Number of UTXOs restored
    pub utxos_restored: u64,

    /// Number of UTXOs removed
    pub utxos_removed: u64,
}

/// Enhanced chain reorganization manager
pub struct ChainReorganizer {
    /// Storage manager
    storage: Arc<StorageManager>,

    /// UTXO manager
    utxo_manager: Arc<UtxoManager>,

    /// Undo data for recent blocks
    undo_data: Arc<RwLock<HashMap<BlockHash, BlockUndoData>>>,

    /// Maximum undo data to keep (blocks)
    max_undo_blocks: usize,

    /// Reorganization statistics
    stats: Arc<RwLock<ReorgStats>>,

    /// Active reorganization flag
    reorg_in_progress: Arc<RwLock<bool>>,
}

impl ChainReorganizer {
    /// Create new chain reorganizer
    pub fn new(storage: Arc<StorageManager>, utxo_manager: Arc<UtxoManager>) -> Self {
        Self {
            storage,
            utxo_manager,
            undo_data: Arc::new(RwLock::new(HashMap::new())),
            max_undo_blocks: 1000, // Keep undo data for last 1000 blocks
            stats: Arc::new(RwLock::new(ReorgStats::default())),
            reorg_in_progress: Arc::new(RwLock::new(false)),
        }
    }

    /// Check if a reorganization is in progress
    pub async fn is_reorg_in_progress(&self) -> bool {
        *self.reorg_in_progress.read().await
    }

    /// Perform a chain reorganization
    pub async fn reorganize_chain(
        &self,
        old_tip: BlockHash,
        old_height: u32,
        new_tip: BlockHash,
        new_height: u32,
        new_work: [u8; 32],
        old_work: [u8; 32],
    ) -> Result<ReorgResult> {
        // Acquire reorganization lock
        {
            let mut in_progress = self.reorg_in_progress.write().await;
            if *in_progress {
                bail!("Reorganization already in progress");
            }
            *in_progress = true;
        }

        // Ensure we complete or rollback
        let _guard = ReorgGuard {
            flag: self.reorg_in_progress.clone(),
        };

        info!(
            "Starting chain reorganization: old_tip={} (height={}) -> new_tip={} (height={})",
            old_tip, old_height, new_tip, new_height
        );

        // Find fork point
        let (fork_point, fork_height) = self
            .find_fork_point(old_tip, old_height, new_tip, new_height)
            .await?;

        // Calculate reorganization depth
        let reorg_depth = old_height - fork_height;

        // Check depth limits
        if reorg_depth > MAX_REORG_DEPTH {
            bail!(
                "Reorganization too deep: {} blocks (max: {})",
                reorg_depth,
                MAX_REORG_DEPTH
            );
        }

        if reorg_depth > MAX_AUTO_REORG_DEPTH {
            warn!(
                "Deep reorganization detected: {} blocks. Manual intervention may be required.",
                reorg_depth
            );
        }

        // Build disconnect and connect lists
        let disconnect_blocks = self
            .build_disconnect_list(old_tip, old_height, fork_point, fork_height)
            .await?;

        let connect_blocks = self
            .build_connect_list(new_tip, new_height, fork_point, fork_height)
            .await?;

        // Create UTXO snapshot for rollback
        let utxo_snapshot = self.create_utxo_snapshot().await?;

        // Perform the reorganization
        let result = match self
            .execute_reorg(
                disconnect_blocks.clone(),
                connect_blocks.clone(),
                fork_point,
                fork_height,
                old_tip,
                old_height,
                new_tip,
                new_height,
            )
            .await
        {
            Ok(result) => result,
            Err(e) => {
                error!("Reorganization failed: {}. Rolling back...", e);
                self.rollback_utxo_snapshot(utxo_snapshot).await?;
                return Err(e);
            }
        };

        // Update statistics
        self.update_stats(&result).await;

        info!(
            "Chain reorganization complete: disconnected {} blocks, connected {} blocks",
            result.disconnected_blocks.len(),
            result.connected_blocks.len()
        );

        Ok(result)
    }

    /// Find the fork point between two chains
    async fn find_fork_point(
        &self,
        tip1: BlockHash,
        height1: u32,
        tip2: BlockHash,
        height2: u32,
    ) -> Result<(BlockHash, u32)> {
        let mut hash1 = tip1;
        let mut hash2 = tip2;
        let mut h1 = height1;
        let mut h2 = height2;

        // Bring both chains to the same height
        while h1 > h2 {
            let header = self
                .storage
                .get_block_header(&hash1)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Missing header for {}", hash1))?;
            hash1 = header.prev_blockhash;
            h1 -= 1;
        }

        while h2 > h1 {
            let header = self
                .storage
                .get_block_header(&hash2)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Missing header for {}", hash2))?;
            hash2 = header.prev_blockhash;
            h2 -= 1;
        }

        // Walk back until we find common ancestor
        while hash1 != hash2 {
            if h1 == 0 {
                bail!("No common ancestor found - chains don't connect");
            }

            let header1 = self
                .storage
                .get_block_header(&hash1)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Missing header for {}", hash1))?;
            let header2 = self
                .storage
                .get_block_header(&hash2)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Missing header for {}", hash2))?;

            hash1 = header1.prev_blockhash;
            hash2 = header2.prev_blockhash;
            h1 -= 1;
            h2 -= 1;
        }

        debug!("Found fork point at block {} height {}", hash1, h1);
        Ok((hash1, h1))
    }

    /// Build list of blocks to disconnect
    async fn build_disconnect_list(
        &self,
        from_tip: BlockHash,
        from_height: u32,
        to_fork: BlockHash,
        to_height: u32,
    ) -> Result<Vec<(BlockHash, u32)>> {
        let mut blocks = Vec::new();
        let mut current_hash = from_tip;
        let mut current_height = from_height;

        while current_hash != to_fork {
            blocks.push((current_hash, current_height));

            let header = self
                .storage
                .get_block_header(&current_hash)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Missing header for {}", current_hash))?;

            current_hash = header.prev_blockhash;
            current_height -= 1;

            if blocks.len() > MAX_REORG_DEPTH as usize {
                bail!("Disconnect list too long");
            }
        }

        debug!("Built disconnect list with {} blocks", blocks.len());
        Ok(blocks)
    }

    /// Build list of blocks to connect
    async fn build_connect_list(
        &self,
        from_tip: BlockHash,
        from_height: u32,
        to_fork: BlockHash,
        to_height: u32,
    ) -> Result<Vec<(BlockHash, u32)>> {
        let mut blocks = VecDeque::new();
        let mut current_hash = from_tip;
        let mut current_height = from_height;

        while current_hash != to_fork {
            blocks.push_front((current_hash, current_height));

            let header = self
                .storage
                .get_block_header(&current_hash)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Missing header for {}", current_hash))?;

            current_hash = header.prev_blockhash;
            current_height -= 1;

            if blocks.len() > MAX_REORG_DEPTH as usize {
                bail!("Connect list too long");
            }
        }

        debug!("Built connect list with {} blocks", blocks.len());
        Ok(blocks.into())
    }

    /// Execute the reorganization
    async fn execute_reorg(
        &self,
        disconnect_blocks: Vec<(BlockHash, u32)>,
        connect_blocks: Vec<(BlockHash, u32)>,
        fork_point: BlockHash,
        fork_height: u32,
        old_tip: BlockHash,
        old_height: u32,
        new_tip: BlockHash,
        new_height: u32,
    ) -> Result<ReorgResult> {
        let mut disconnected = Vec::new();
        let mut connected = Vec::new();
        let mut txs_affected = 0u64;
        let mut utxos_restored = 0u64;
        let mut utxos_removed = 0u64;

        // Disconnect blocks from old chain (in reverse order)
        for (block_hash, height) in disconnect_blocks.iter().rev() {
            info!("Disconnecting block {} at height {}", block_hash, height);

            let (txs, restored, removed) = self.disconnect_block(*block_hash, *height).await?;

            disconnected.push((*block_hash, *height));
            txs_affected += txs;
            utxos_restored += restored;
            utxos_removed += removed;
        }

        // Connect blocks to new chain
        for (block_hash, height) in &connect_blocks {
            info!("Connecting block {} at height {}", block_hash, height);

            let (txs, created, spent) = self.connect_block(*block_hash, *height).await?;

            connected.push((*block_hash, *height));
            txs_affected += txs;
            utxos_restored += spent;
            utxos_removed += created;
        }

        // Calculate work difference (simplified)
        let work_difference = (new_height as i64) - (old_height as i64);

        // Log reorganization metrics
        info!(
            "Reorganization complete: {} blocks disconnected, {} connected, {} txs affected, {} UTXOs restored, {} UTXOs removed",
            disconnected.len(),
            connected.len(),
            txs_affected,
            utxos_restored,
            utxos_removed
        );

        Ok(ReorgResult {
            disconnected_blocks: disconnected,
            connected_blocks: connected,
            new_tip,
            new_height,
            old_tip,
            old_height,
            fork_point,
            fork_height,
            work_difference,
            txs_affected,
            utxos_restored,
            utxos_removed,
        })
    }

    /// Disconnect a block from the chain
    async fn disconnect_block(
        &self,
        block_hash: BlockHash,
        height: u32,
    ) -> Result<(u64, u64, u64)> {
        // Load undo data
        let undo_data = self
            .undo_data
            .read()
            .await
            .get(&block_hash)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No undo data for block {}", block_hash))?;

        // Load the block
        let block = self
            .storage
            .get_block(&block_hash)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Block {} not found", block_hash))?;

        let mut utxos_restored = 0u64;
        let mut utxos_removed = 0u64;

        // Process transactions in reverse order
        for tx_undo in undo_data.tx_undo_data.iter().rev() {
            // Restore spent outputs
            for (outpoint, output) in &tx_undo.spent_outputs {
                self.utxo_manager
                    .add_utxo(*outpoint, output.clone(), height, false)
                    .await?;
                utxos_restored += 1;
            }

            // Remove created outputs
            for outpoint in &tx_undo.created_outputs {
                self.utxo_manager.remove_utxo(outpoint).await?;
                utxos_removed += 1;
            }
        }

        // Remove undo data for this block
        self.undo_data.write().await.remove(&block_hash);

        debug!(
            "Disconnected block {} with {} txs, restored {} UTXOs, removed {} UTXOs",
            block_hash,
            block.txdata.len(),
            utxos_restored,
            utxos_removed
        );

        Ok((block.txdata.len() as u64, utxos_restored, utxos_removed))
    }

    /// Connect a block to the chain
    async fn connect_block(&self, block_hash: BlockHash, height: u32) -> Result<(u64, u64, u64)> {
        // Load the block
        let block = self
            .storage
            .get_block(&block_hash)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Block {} not found", block_hash))?;

        let mut block_undo = BlockUndoData {
            block_hash,
            height,
            tx_undo_data: Vec::new(),
            prev_tip: BlockHash::from_byte_array([0u8; 32]), // Will be updated
            connected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let mut utxos_created = 0u64;
        let mut utxos_spent = 0u64;

        // Process all transactions
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            let mut tx_undo = TxUndoData {
                txid,
                spent_outputs: Vec::new(),
                created_outputs: Vec::new(),
            };

            // Process inputs (spend UTXOs)
            if !tx.is_coinbase() {
                for input in &tx.input {
                    // Get and save the spent output for undo
                    if let Some(entry) = self.utxo_manager.get_utxo(&input.previous_output).await {
                        tx_undo
                            .spent_outputs
                            .push((input.previous_output, entry.output));

                        // Remove from UTXO set
                        self.utxo_manager
                            .remove_utxo(&input.previous_output)
                            .await?;
                        utxos_spent += 1;
                    } else {
                        bail!("Missing UTXO for input: {:?}", input.previous_output);
                    }
                }
            }

            // Process outputs (create UTXOs)
            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };

                tx_undo.created_outputs.push(outpoint);

                // Add to UTXO set
                let is_coinbase = tx.is_coinbase();
                self.utxo_manager
                    .add_utxo(outpoint, output.clone(), height, is_coinbase)
                    .await?;
                utxos_created += 1;
            }

            block_undo.tx_undo_data.push(tx_undo);
        }

        // Store undo data
        self.store_undo_data(block_undo).await?;

        debug!(
            "Connected block {} with {} txs, created {} UTXOs, spent {} UTXOs",
            block_hash,
            block.txdata.len(),
            utxos_created,
            utxos_spent
        );

        Ok((block.txdata.len() as u64, utxos_created, utxos_spent))
    }

    /// Store undo data for a block
    async fn store_undo_data(&self, undo_data: BlockUndoData) -> Result<()> {
        let mut undo_map = self.undo_data.write().await;

        // Enforce size limit
        if undo_map.len() >= self.max_undo_blocks {
            // Remove oldest undo data
            let oldest = undo_map
                .values()
                .min_by_key(|d| d.connected_at)
                .map(|d| d.block_hash);

            if let Some(hash) = oldest {
                undo_map.remove(&hash);
                debug!("Evicted old undo data for block {}", hash);
            }
        }

        undo_map.insert(undo_data.block_hash, undo_data);
        Ok(())
    }

    /// Create a UTXO snapshot for rollback
    async fn create_utxo_snapshot(&self) -> Result<HashMap<OutPoint, TxOut>> {
        // In production, this would snapshot the current UTXO set
        // For now, return empty snapshot
        Ok(HashMap::new())
    }

    /// Rollback to a UTXO snapshot
    async fn rollback_utxo_snapshot(&self, _snapshot: HashMap<OutPoint, TxOut>) -> Result<()> {
        // In production, this would restore the UTXO set from snapshot
        warn!("UTXO rollback not fully implemented");
        Ok(())
    }

    /// Update reorganization statistics
    async fn update_stats(&self, result: &ReorgResult) {
        let mut stats = self.stats.write().await;

        stats.total_reorgs += 1;

        let depth = result.disconnected_blocks.len() as u32;
        if depth > stats.max_depth {
            stats.max_depth = depth;
        }

        // Update average depth
        let total_depth = stats.avg_depth * (stats.total_reorgs - 1) as f64 + depth as f64;
        stats.avg_depth = total_depth / stats.total_reorgs as f64;

        stats.blocks_disconnected += result.disconnected_blocks.len() as u64;
        stats.blocks_connected += result.connected_blocks.len() as u64;
    }

    /// Get reorganization statistics
    pub async fn get_stats(&self) -> ReorgStats {
        self.stats.read().await.clone()
    }

    /// Check if we should perform a reorganization
    pub fn should_reorg(old_work: &[u8; 32], new_work: &[u8; 32]) -> bool {
        // Compare work arrays (big-endian)
        for i in 0..32 {
            if new_work[i] > old_work[i] {
                return true;
            } else if new_work[i] < old_work[i] {
                return false;
            }
        }
        false
    }
}

/// Guard to ensure reorg flag is reset
struct ReorgGuard {
    flag: Arc<RwLock<bool>>,
}

impl Drop for ReorgGuard {
    fn drop(&mut self) {
        // Reset flag when guard is dropped
        let flag = self.flag.clone();
        tokio::spawn(async move {
            *flag.write().await = false;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_reorg() {
        let mut old_work = [0u8; 32];
        let mut new_work = [0u8; 32];

        // Equal work - no reorg
        assert!(!ChainReorganizer::should_reorg(&old_work, &new_work));

        // New work greater - should reorg
        new_work[31] = 1;
        assert!(ChainReorganizer::should_reorg(&old_work, &new_work));

        // Old work greater - no reorg
        old_work[31] = 2;
        assert!(!ChainReorganizer::should_reorg(&old_work, &new_work));
    }
}
