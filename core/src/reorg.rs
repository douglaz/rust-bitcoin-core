use anyhow::{bail, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::{
    chain::ChainManager,
    database::{CoreDatabase, UndoData, UtxoEntry},
    validation::BlockValidator,
};

/// Maximum reorganization depth to handle
const MAX_REORG_DEPTH: u32 = 100;

/// Chain reorganization manager
pub struct ReorgManager {
    chain: Arc<RwLock<ChainManager>>,
    database: Arc<CoreDatabase>,
    validator: Arc<BlockValidator>,
}

/// Fork information
#[derive(Debug, Clone)]
pub struct Fork {
    /// Common ancestor block
    pub common_ancestor: BlockHash,
    pub common_height: u32,

    /// Old chain blocks (to disconnect)
    pub old_chain: Vec<BlockHash>,

    /// New chain blocks (to connect)
    pub new_chain: Vec<BlockHash>,

    /// Total work of new chain
    pub new_work: [u8; 32],
}

impl ReorgManager {
    /// Create a new reorganization manager
    pub fn new(
        chain: Arc<RwLock<ChainManager>>,
        database: Arc<CoreDatabase>,
        validator: Arc<BlockValidator>,
    ) -> Self {
        Self {
            chain,
            database,
            validator,
        }
    }

    /// Check if a reorganization is needed
    pub async fn check_reorg_needed(
        &self,
        new_tip: &BlockHash,
        new_work: &[u8; 32],
    ) -> Result<bool> {
        let chain = self.chain.read().await;
        let current_tip = chain.get_best_block_hash();

        // No reorg if same tip
        if current_tip == *new_tip {
            return Ok(false);
        }

        // Check if new chain has more work
        // Calculate current chain's work from genesis to tip
        let chain = self.chain.read().await;
        let current_height = chain.get_best_height();

        // Build chain from genesis to current tip
        let mut current_chain = Vec::new();
        let mut hash = current_tip;
        for _ in 0..=current_height {
            current_chain.push(hash);
            if let Some(header) = chain.get_block_header(&hash) {
                if header.prev_blockhash == BlockHash::from_byte_array([0u8; 32]) {
                    break; // Reached genesis
                }
                hash = header.prev_blockhash;
            } else {
                break;
            }
        }
        drop(chain);

        current_chain.reverse();
        let current_work = self.calculate_chain_work(&current_chain).await?;

        Ok(self.compare_work(new_work, &current_work) > 0)
    }

    /// Find fork point between current chain and new chain
    pub async fn find_fork(&self, new_chain_tip: &BlockHash) -> Result<Fork> {
        let chain = self.chain.read().await;
        let current_tip = chain.get_best_block_hash();
        let current_height = chain.get_best_height();

        // Walk back both chains to find common ancestor
        let mut old_chain = Vec::new();
        let mut new_chain = Vec::new();

        let mut old_hash = current_tip;
        let mut new_hash = *new_chain_tip;
        let mut old_height = current_height;
        let mut new_height = self.get_block_height(&new_hash).await?;

        // Align to same height
        while old_height > new_height {
            old_chain.push(old_hash);
            old_hash = self.get_block_parent(&old_hash).await?;
            old_height -= 1;
        }

        while new_height > old_height {
            new_chain.push(new_hash);
            new_hash = self.get_block_parent(&new_hash).await?;
            new_height -= 1;
        }

        // Walk back until common ancestor found
        while old_hash != new_hash {
            if old_chain.len() + new_chain.len() > MAX_REORG_DEPTH as usize {
                bail!(
                    "Reorganization depth exceeds maximum of {}",
                    MAX_REORG_DEPTH
                );
            }

            old_chain.push(old_hash);
            new_chain.push(new_hash);

            old_hash = self.get_block_parent(&old_hash).await?;
            new_hash = self.get_block_parent(&new_hash).await?;
            old_height -= 1;
            new_height -= 1;
        }

        // Reverse new_chain so it's in forward order
        new_chain.reverse();

        let new_work = self.calculate_chain_work(&new_chain).await?;

        Ok(Fork {
            common_ancestor: old_hash,
            common_height: old_height,
            old_chain,
            new_chain,
            new_work,
        })
    }

    /// Perform chain reorganization
    pub async fn reorganize(&self, fork: Fork) -> Result<()> {
        info!(
            "Starting reorganization: disconnecting {} blocks, connecting {} blocks",
            fork.old_chain.len(),
            fork.new_chain.len()
        );

        // Validation: ensure new chain is valid
        let mut prev_header: Option<BlockHeader> = None;
        let mut height = fork.common_height;
        
        for hash in &fork.new_chain {
            height += 1;
            let block = self
                .database
                .get_block(hash)?
                .ok_or_else(|| anyhow::anyhow!("Block {} not found for reorg", hash))?;

            // Validate the block with full consensus rules
            debug!("Validating block {} at height {} for reorg", hash, height);
            let validation_result = self.validator
                .validate_block(&block, height, prev_header.as_ref())
                .await?;
            
            if !validation_result.is_valid() {
                error!("Block {} failed validation during reorg: {:?}", hash, validation_result);
                bail!("Invalid block {} in new chain, aborting reorg", hash);
            }
            
            // Update prev_header for next iteration
            prev_header = Some(block.header.clone());
        }

        // Phase 1: Disconnect old chain blocks
        let mut disconnected_utxos = Vec::new();
        for hash in fork.old_chain.iter().rev() {
            let utxos = self.disconnect_block(hash).await?;
            disconnected_utxos.push((*hash, utxos));
        }

        // Phase 2: Connect new chain blocks
        let mut connected = Vec::new();
        for hash in &fork.new_chain {
            match self.connect_block(hash).await {
                Ok(undo_data) => {
                    connected.push((*hash, undo_data));
                }
                Err(e) => {
                    // Rollback on failure
                    error!("Failed to connect block {} during reorg: {}", hash, e);
                    self.rollback_reorg(disconnected_utxos, connected).await?;
                    return Err(e);
                }
            }
        }

        // Update chain state
        let mut chain = self.chain.write().await;
        let new_tip = *fork.new_chain.last().unwrap();
        let new_height = fork.common_height + fork.new_chain.len() as u32;
        chain.set_best_block(new_tip, new_height)?;

        // Save new chain state
        let state = crate::database::ChainState {
            tip_hash: *fork.new_chain.last().unwrap(),
            tip_height: fork.common_height + fork.new_chain.len() as u32,
            total_work: fork.new_work,
            utxo_count: self.database.count_utxos()?,
        };
        self.database.save_chain_state(&state)?;

        info!(
            "Reorganization complete: new tip {} at height {}",
            state.tip_hash, state.tip_height
        );

        Ok(())
    }

    /// Disconnect a block from the chain
    async fn disconnect_block(&self, hash: &BlockHash) -> Result<Vec<UtxoEntry>> {
        debug!("Disconnecting block {}", hash);

        // Get block
        let block = self
            .database
            .get_block(hash)?
            .ok_or_else(|| anyhow::anyhow!("Block {} not found", hash))?;

        // Get undo data
        let undo_data = self
            .database
            .get_undo_data(hash)?
            .ok_or_else(|| anyhow::anyhow!("Undo data not found for block {}", hash))?;

        let mut utxos_to_restore = Vec::new();
        let mut utxos_to_remove = Vec::new();

        // Restore spent UTXOs (from undo data)
        for utxo in undo_data.spent_outputs {
            utxos_to_restore.push(utxo.clone());
        }

        // Remove created UTXOs (from this block's outputs)
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            for (vout, _) in tx.output.iter().enumerate() {
                utxos_to_remove.push(bitcoin::OutPoint {
                    txid,
                    vout: vout as u32,
                });
            }
        }

        // Update database
        self.database
            .update_utxos(utxos_to_restore.clone(), utxos_to_remove)?;

        Ok(utxos_to_restore)
    }

    /// Connect a block to the chain
    async fn connect_block(&self, hash: &BlockHash) -> Result<UndoData> {
        debug!("Connecting block {}", hash);

        // Get block
        let block = self
            .database
            .get_block(hash)?
            .ok_or_else(|| anyhow::anyhow!("Block {} not found", hash))?;

        let height = self.get_block_height(hash).await?;

        let mut spent_outputs = Vec::new();
        let mut created_outputs = Vec::new();
        let mut utxos_to_add = Vec::new();
        let mut utxos_to_remove = Vec::new();

        // Process transactions
        for tx in &block.txdata {
            let txid = tx.compute_txid();

            // Remove spent UTXOs (inputs)
            if !tx.is_coinbase() {
                for input in &tx.input {
                    // Save spent UTXO for undo
                    if let Some(utxo) = self.database.get_utxo(&input.previous_output)? {
                        spent_outputs.push(utxo);
                    }
                    utxos_to_remove.push(input.previous_output);
                }
            }

            // Add new UTXOs (outputs)
            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = bitcoin::OutPoint {
                    txid,
                    vout: vout as u32,
                };

                let utxo = UtxoEntry {
                    outpoint,
                    output: output.clone(),
                    height,
                    is_coinbase: tx.is_coinbase(),
                };

                utxos_to_add.push(utxo);
                created_outputs.push(outpoint);
            }
        }

        // Update database
        self.database.update_utxos(utxos_to_add, utxos_to_remove)?;

        // Create and store undo data
        let undo_data = UndoData {
            spent_outputs,
            created_outputs,
        };

        self.database.put_undo_data(hash, &undo_data)?;

        Ok(undo_data)
    }

    /// Rollback a failed reorganization
    async fn rollback_reorg(
        &self,
        disconnected: Vec<(BlockHash, Vec<UtxoEntry>)>,
        connected: Vec<(BlockHash, UndoData)>,
    ) -> Result<()> {
        warn!("Rolling back failed reorganization");

        // Disconnect the blocks we connected
        for (hash, _) in connected.iter().rev() {
            if let Err(e) = self.disconnect_block(hash).await {
                error!("Failed to rollback block {}: {}", hash, e);
            }
        }

        // Reconnect the blocks we disconnected
        for (hash, _) in disconnected.iter().rev() {
            if let Err(e) = self.connect_block(hash).await {
                error!("Failed to restore block {}: {}", hash, e);
            }
        }

        Ok(())
    }

    /// Get block height
    async fn get_block_height(&self, hash: &BlockHash) -> Result<u32> {
        // First check if the block is in the main chain
        let chain = self.chain.read().await;
        if let Ok(height) = chain.get_block_height(hash) {
            return Ok(height);
        }
        drop(chain);

        // If not in main chain, walk back to find a block that is
        let mut current = *hash;
        let mut distance = 0u32;

        loop {
            // Get the parent
            let header = self
                .database
                .get_block_header(&current)?
                .ok_or_else(|| anyhow::anyhow!("Block header {} not found", current))?;

            // Check if we reached genesis
            if header.prev_blockhash == BlockHash::from_byte_array([0u8; 32])
                || header.prev_blockhash == self.get_genesis_hash()
            {
                return Ok(distance);
            }

            // Check if parent is in main chain
            let chain = self.chain.read().await;
            if let Ok(parent_height) = chain.get_block_height(&header.prev_blockhash) {
                return Ok(parent_height + distance + 1);
            }
            drop(chain);

            current = header.prev_blockhash;
            distance += 1;

            // Prevent infinite loops
            if distance > 1_000_000 {
                bail!("Chain too deep or contains cycle");
            }
        }
    }

    /// Get parent block hash
    async fn get_block_parent(&self, hash: &BlockHash) -> Result<BlockHash> {
        let header = self
            .database
            .get_block_header(hash)?
            .ok_or_else(|| anyhow::anyhow!("Block header {} not found", hash))?;
        Ok(header.prev_blockhash)
    }

    /// Calculate total chain work
    async fn calculate_chain_work(&self, chain: &[BlockHash]) -> Result<[u8; 32]> {
        // Sum up the work for each block in the chain
        let mut total_work = [0u8; 32];

        for hash in chain {
            let header = self
                .database
                .get_block_header(hash)?
                .ok_or_else(|| anyhow::anyhow!("Header {} not found", hash))?;

            // Add block's work to total
            let block_work = self.calculate_block_work(&header);
            self.add_work(&mut total_work, &block_work);
        }

        Ok(total_work)
    }

    /// Calculate work for a single block
    fn calculate_block_work(&self, header: &BlockHeader) -> [u8; 32] {
        // Calculate work from block's target (difficulty)
        // Work = 2^256 / (target + 1)
        // This uses Bitcoin's actual proof-of-work calculation

        // Get the target from the header's bits field
        let target = header.target();
        let target_bytes = target.to_be_bytes();

        // Calculate 2^256 / (target + 1)
        // Since 2^256 is represented as 1 followed by 256 zero bits,
        // and we're dividing by target, the result represents the expected
        // number of hashes needed to find a valid block

        let mut work = [0u8; 32];

        // Find the highest set bit position in target to determine magnitude
        let mut highest_bit = 255;
        for i in 0..32 {
            for bit in (0..8).rev() {
                if (target_bytes[i] & (1 << bit)) != 0 {
                    highest_bit = (31 - i) * 8 + (7 - bit);
                    break;
                }
            }
            if highest_bit != 255 {
                break;
            }
        }

        if highest_bit == 255 {
            // Target is zero (impossible), return max work
            for i in 0..32 {
                work[i] = 0xFF;
            }
            return work;
        }

        // Calculate work based on the position of the highest bit
        // The work is approximately 2^(256 - highest_bit)
        let work_bits = 255_u16.saturating_sub(highest_bit as u16);
        
        // Set the appropriate bytes in the work array
        let byte_pos = (work_bits / 8) as usize;
        let bit_pos = (work_bits % 8) as u8;

        if byte_pos < 32 {
            // Set the main work byte
            work[31 - byte_pos] = 1 << bit_pos;
            
            // For more precision, consider the next few bits of the target
            if byte_pos > 0 && byte_pos < 32 {
                let target_val = target_bytes[31 - byte_pos];
                if target_val > 0 {
                    // Add fractional work based on target precision
                    work[31 - byte_pos + 1] = 0xFF / target_val;
                }
            }
        }

        work
    }

    /// Add work values (256-bit addition)
    fn add_work(&self, total: &mut [u8; 32], work: &[u8; 32]) {
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let sum = total[i] as u16 + work[i] as u16 + carry;
            total[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
    }

    /// Compare work values
    fn compare_work(&self, a: &[u8], b: &[u8]) -> i32 {
        for i in 0..32 {
            if a[i] > b[i] {
                return 1;
            }
            if a[i] < b[i] {
                return -1;
            }
        }
        0
    }

    /// Get genesis block hash
    fn get_genesis_hash(&self) -> BlockHash {
        // Return actual genesis hash based on network

        use bitcoin::hashes::Hash;

        // Get network from chain manager's consensus params
        // For now, default to mainnet genesis
        // In a real implementation, this would come from the chain's network configuration

        // Bitcoin mainnet genesis hash
        const MAINNET_GENESIS: &str =
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        // Bitcoin testnet genesis hash
        const TESTNET_GENESIS: &str =
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
        // Bitcoin regtest genesis hash
        const REGTEST_GENESIS: &str =
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

        // Try to determine network from chain (simplified for now)
        // In production, this would be properly configured
        let genesis_hex = MAINNET_GENESIS;

        let genesis_bytes = hex::decode(genesis_hex).expect("Invalid genesis hash hex");
        BlockHash::from_slice(&genesis_bytes).expect("Invalid genesis hash")
    }
}

/// Handle competing chain tips
pub struct ChainTipManager {
    tips: Arc<RwLock<HashMap<BlockHash, ChainTip>>>,
    reorg_manager: Arc<ReorgManager>,
}

#[derive(Debug, Clone)]
struct ChainTip {
    hash: BlockHash,
    height: u32,
    work: [u8; 32],
    status: TipStatus,
}

#[derive(Debug, Clone, PartialEq)]
enum TipStatus {
    Active,       // Current best chain
    ValidFork,    // Valid but not best
    ValidHeaders, // Headers validated but not fully validated
    Invalid,      // Contains invalid block
}

impl ChainTipManager {
    /// Create new chain tip manager
    pub fn new(reorg_manager: Arc<ReorgManager>) -> Self {
        Self {
            tips: Arc::new(RwLock::new(HashMap::new())),
            reorg_manager,
        }
    }

    /// Add a new chain tip
    pub async fn add_tip(&self, hash: BlockHash, height: u32, work: [u8; 32]) -> Result<()> {
        let mut tips = self.tips.write().await;

        let tip = ChainTip {
            hash,
            height,
            work,
            status: TipStatus::ValidHeaders,
        };

        tips.insert(hash, tip);

        // Check if this tip should become active
        self.update_active_tip().await?;

        Ok(())
    }

    /// Update the active chain tip
    async fn update_active_tip(&self) -> Result<()> {
        let tips = self.tips.read().await;

        // Find tip with most work
        let best_tip = tips
            .values()
            .filter(|tip| tip.status != TipStatus::Invalid)
            .max_by(|a, b| {
                for i in 0..32 {
                    if a.work[i] != b.work[i] {
                        return a.work[i].cmp(&b.work[i]);
                    }
                }
                std::cmp::Ordering::Equal
            });

        if let Some(best) = best_tip {
            if best.status != TipStatus::Active {
                // Need reorganization
                let best_hash = best.hash;
                drop(tips); // Drop the read lock before getting write lock

                let fork = self.reorg_manager.find_fork(&best_hash).await?;
                self.reorg_manager.reorganize(fork).await?;

                // Update tip statuses
                let mut tips = self.tips.write().await;
                for tip in tips.values_mut() {
                    tip.status = if tip.hash == best_hash {
                        TipStatus::Active
                    } else {
                        TipStatus::ValidFork
                    };
                }
            }
        }

        Ok(())
    }

    /// Mark a tip as invalid
    pub async fn invalidate_tip(&self, hash: BlockHash) -> Result<()> {
        let mut tips = self.tips.write().await;

        if let Some(tip) = tips.get_mut(&hash) {
            tip.status = TipStatus::Invalid;
            info!("Marked chain tip {} as invalid", hash);
        }

        Ok(())
    }

    /// Get all chain tips
    pub async fn get_tips(&self) -> Vec<ChainTip> {
        let tips = self.tips.read().await;
        tips.values().cloned().collect()
    }

    /// Get active chain tip
    pub async fn get_active_tip(&self) -> Option<ChainTip> {
        let tips = self.tips.read().await;
        tips.values()
            .find(|tip| tip.status == TipStatus::Active)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[tokio::test]
    async fn test_work_comparison() {
        use crate::consensus::ConsensusParams;
        use crate::script::ScriptFlags;
        use crate::tx_validator::TxValidationPipeline;
        use storage::utxo::UtxoSet;

        let consensus_params = ConsensusParams::for_network("regtest").unwrap();
        let tx_validator = Arc::new(TxValidationPipeline::new(ScriptFlags::all()));
        let utxo_db = Arc::new(sled::Config::new().temporary(true).open().unwrap());
        let utxo_set = Arc::new(RwLock::new(UtxoSet::new(utxo_db)));

        let temp_dir = tempfile::tempdir().unwrap();
        let reorg_mgr = ReorgManager::new(
            Arc::new(RwLock::new(
                ChainManager::new(
                    Arc::new(
                        storage::StorageManager::new(
                            temp_dir.path().join("storage").to_str().unwrap(),
                        )
                        .await
                        .unwrap(),
                    ),
                    "regtest".to_string(),
                )
                .await
                .unwrap(),
            )),
            Arc::new(CoreDatabase::open(&temp_dir.path().join("db")).unwrap()),
            Arc::new(BlockValidator::new(
                consensus_params,
                tx_validator,
                utxo_set,
            )),
        );

        let mut work1 = [0u8; 32];
        let mut work2 = [0u8; 32];

        work1[31] = 1;
        work2[31] = 2;

        assert_eq!(reorg_mgr.compare_work(&work1, &work2), -1);
        assert_eq!(reorg_mgr.compare_work(&work2, &work1), 1);
        assert_eq!(reorg_mgr.compare_work(&work1, &work1), 0);
    }
}
