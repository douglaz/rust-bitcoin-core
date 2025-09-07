use anyhow::{Result, Context, bail};
use bitcoin::{Block, BlockHash, Transaction, OutPoint, TxOut};
use bitcoin::block::Header as BlockHeader;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tracing::{info, warn, error, debug, trace};

use crate::database_sled::{CoreDatabase, UndoData};

/// Maximum reorganization depth allowed
const MAX_REORG_DEPTH: u32 = 100;

/// Chain reorganization result
#[derive(Debug)]
pub struct ReorgResult {
    pub disconnected_blocks: Vec<BlockHash>,
    pub connected_blocks: Vec<BlockHash>,
    pub new_tip: BlockHash,
    pub new_height: u32,
    pub old_tip: BlockHash,
    pub old_height: u32,
}

/// Complete chain reorganization implementation
pub struct ChainReorganizer {
    database: Arc<CoreDatabase>,
}

impl ChainReorganizer {
    pub fn new(database: Arc<CoreDatabase>) -> Self {
        Self { database }
    }
    
    /// Perform a chain reorganization
    pub async fn reorganize(
        &self,
        old_tip: BlockHash,
        new_tip: BlockHash,
        fork_point: BlockHash,
        fork_height: u32,
    ) -> Result<ReorgResult> {
        info!("Starting chain reorganization from {} to {}", old_tip, new_tip);
        
        // Build list of blocks to disconnect
        let disconnect_blocks = self.build_disconnect_list(old_tip, fork_point).await?;
        
        // Build list of blocks to connect
        let connect_blocks = self.build_connect_list(new_tip, fork_point).await?;
        
        // Validate reorg depth
        if disconnect_blocks.len() > MAX_REORG_DEPTH as usize {
            bail!("Reorganization too deep: {} blocks", disconnect_blocks.len());
        }
        
        // Begin atomic database transaction
        let mut batch = self.database.begin_batch()?;
        
        // Disconnect old chain blocks
        let mut disconnected = Vec::new();
        let mut utxo_updates = HashMap::new();
        
        for block_hash in disconnect_blocks.iter().rev() {
            debug!("Disconnecting block {}", block_hash);
            self.disconnect_block(*block_hash, &mut utxo_updates, &mut batch).await?;
            disconnected.push(*block_hash);
        }
        
        // Connect new chain blocks
        let mut connected = Vec::new();
        let mut new_height = fork_height;
        
        for block_hash in &connect_blocks {
            debug!("Connecting block {}", block_hash);
            new_height += 1;
            self.connect_block(*block_hash, new_height, &mut utxo_updates, &mut batch).await?;
            connected.push(*block_hash);
        }
        
        // Update chain tip in database
        self.database.set_chain_tip(&mut batch, new_tip, new_height)?;
        
        // Apply UTXO set changes
        self.apply_utxo_updates(utxo_updates, &mut batch)?;
        
        // Commit all changes atomically
        self.database.commit_batch(batch)?;
        
        // Get old height for result
        let old_height = self.database.get_block_height(&old_tip)?
            .ok_or_else(|| anyhow::anyhow!("Old tip not found"))?;
        
        let result = ReorgResult {
            disconnected_blocks: disconnected,
            connected_blocks: connected,
            new_tip,
            new_height,
            old_tip,
            old_height,
        };
        
        info!("Chain reorganization complete: disconnected {} blocks, connected {} blocks",
              result.disconnected_blocks.len(), result.connected_blocks.len());
        
        Ok(result)
    }
    
    /// Build list of blocks to disconnect from old chain
    async fn build_disconnect_list(
        &self,
        from: BlockHash,
        to: BlockHash,
    ) -> Result<Vec<BlockHash>> {
        let mut blocks = Vec::new();
        let mut current = from;
        
        while current != to {
            blocks.push(current);
            
            // Get parent block
            let block_index = self.database.get_block_index(&current)?
                .ok_or_else(|| anyhow::anyhow!("Block {} not in index", current))?;
            
            current = block_index.header.prev_blockhash;
            
            if blocks.len() > MAX_REORG_DEPTH as usize {
                bail!("Fork too deep while building disconnect list");
            }
        }
        
        Ok(blocks)
    }
    
    /// Build list of blocks to connect from new chain
    async fn build_connect_list(
        &self,
        from: BlockHash,
        to: BlockHash,
    ) -> Result<Vec<BlockHash>> {
        let mut blocks = VecDeque::new();
        let mut current = from;
        
        while current != to {
            blocks.push_front(current);
            
            // Get parent block
            let block_index = self.database.get_block_index(&current)?
                .ok_or_else(|| anyhow::anyhow!("Block {} not in index", current))?;
            
            current = block_index.header.prev_blockhash;
            
            if blocks.len() > MAX_REORG_DEPTH as usize {
                bail!("Fork too deep while building connect list");
            }
        }
        
        Ok(blocks.into())
    }
    
    /// Disconnect a block from the chain
    async fn disconnect_block(
        &self,
        block_hash: BlockHash,
        utxo_updates: &mut HashMap<OutPoint, Option<TxOut>>,
        batch: &mut sled::Batch,
    ) -> Result<()> {
        // Load block from database
        let block = self.database.get_block(&block_hash)?
            .ok_or_else(|| anyhow::anyhow!("Block {} not found", block_hash))?;
        
        // Load undo data for this block
        let undo_data = self.database.get_undo_data(&block_hash)?
            .ok_or_else(|| anyhow::anyhow!("Undo data not found for block {}", block_hash))?;
        
        // Reverse all transactions in reverse order
        for tx in block.txdata.iter().rev() {
            let txid = tx.compute_txid();
            
            // Remove outputs created by this transaction
            for (vout, _output) in tx.output.iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                utxo_updates.insert(outpoint, None); // Mark for deletion
            }
            
            // Restore inputs spent by this transaction (except coinbase)
            if !tx.is_coinbase() {
                for input in &tx.input {
                    // Find the spent output in undo data
                    if let Some(spent_output) = undo_data.get_spent_output(&input.previous_output) {
                        utxo_updates.insert(input.previous_output, Some(spent_output.clone()));
                    }
                }
            }
        }
        
        // Mark block as disconnected in index
        self.database.mark_block_disconnected(batch, &block_hash)?;
        
        trace!("Disconnected block {} with {} transactions", block_hash, block.txdata.len());
        Ok(())
    }
    
    /// Connect a block to the chain
    async fn connect_block(
        &self,
        block_hash: BlockHash,
        height: u32,
        utxo_updates: &mut HashMap<OutPoint, Option<TxOut>>,
        batch: &mut sled::Batch,
    ) -> Result<()> {
        // Load block from database
        let block = self.database.get_block(&block_hash)?
            .ok_or_else(|| anyhow::anyhow!("Block {} not found", block_hash))?;
        
        // Create undo data for future disconnection
        let mut undo_data = UndoData::new();
        
        // Process all transactions
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            
            // Spend inputs (except coinbase)
            if !tx.is_coinbase() {
                for input in &tx.input {
                    // Save spent output for undo
                    if let Some(spent_output) = utxo_updates.get(&input.previous_output) {
                        if let Some(output) = spent_output {
                            undo_data.add_spent_output(input.previous_output, output.clone());
                        }
                    } else {
                        // Load from database if not in updates
                        if let Some(output) = self.database.get_utxo(&input.previous_output)? {
                            undo_data.add_spent_output(input.previous_output, output);
                        }
                    }
                    
                    // Mark as spent
                    utxo_updates.insert(input.previous_output, None);
                }
            }
            
            // Create outputs
            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                utxo_updates.insert(outpoint, Some(output.clone()));
            }
        }
        
        // Save undo data
        self.database.save_undo_data(batch, &block_hash, &undo_data)?;
        
        // Mark block as connected in index
        self.database.mark_block_connected(batch, &block_hash, height)?;
        
        trace!("Connected block {} at height {} with {} transactions", 
               block_hash, height, block.txdata.len());
        Ok(())
    }
    
    /// Apply UTXO set updates to database
    fn apply_utxo_updates(
        &self,
        updates: HashMap<OutPoint, Option<TxOut>>,
        batch: &mut sled::Batch,
    ) -> Result<()> {
        for (outpoint, maybe_output) in updates {
            if let Some(output) = maybe_output {
                // Add or restore UTXO
                self.database.add_utxo(batch, &outpoint, &output)?;
                trace!("Added UTXO: {}", outpoint);
            } else {
                // Remove UTXO
                self.database.remove_utxo(batch, &outpoint)?;
                trace!("Removed UTXO: {}", outpoint);
            }
        }
        
        debug!("Applied {} UTXO updates", updates.len());
        Ok(())
    }
}

/// Fork finder for identifying chain splits
pub struct ForkFinder {
    database: Arc<CoreDatabase>,
}

impl ForkFinder {
    pub fn new(database: Arc<CoreDatabase>) -> Self {
        Self { database }
    }
    
    /// Find the common ancestor (fork point) between two chain tips
    pub async fn find_fork_point(
        &self,
        tip1: BlockHash,
        tip2: BlockHash,
    ) -> Result<(BlockHash, u32)> {
        // Get heights of both tips
        let height1 = self.database.get_block_height(&tip1)?
            .ok_or_else(|| anyhow::anyhow!("Block {} not found", tip1))?;
        let height2 = self.database.get_block_height(&tip2)?
            .ok_or_else(|| anyhow::anyhow!("Block {} not found", tip2))?;
        
        let mut hash1 = tip1;
        let mut hash2 = tip2;
        let mut h1 = height1;
        let mut h2 = height2;
        
        // Bring both to same height
        while h1 > h2 {
            let index = self.database.get_block_index(&hash1)?
                .ok_or_else(|| anyhow::anyhow!("Block index not found"))?;
            hash1 = index.header.prev_blockhash;
            h1 -= 1;
        }
        
        while h2 > h1 {
            let index = self.database.get_block_index(&hash2)?
                .ok_or_else(|| anyhow::anyhow!("Block index not found"))?;
            hash2 = index.header.prev_blockhash;
            h2 -= 1;
        }
        
        // Walk back until we find common ancestor
        while hash1 != hash2 {
            if h1 == 0 {
                bail!("No common ancestor found - chains don't connect");
            }
            
            let index1 = self.database.get_block_index(&hash1)?
                .ok_or_else(|| anyhow::anyhow!("Block index not found"))?;
            let index2 = self.database.get_block_index(&hash2)?
                .ok_or_else(|| anyhow::anyhow!("Block index not found"))?;
            
            hash1 = index1.header.prev_blockhash;
            hash2 = index2.header.prev_blockhash;
            h1 -= 1;
            h2 -= 1;
        }
        
        info!("Found fork point at block {} height {}", hash1, h1);
        Ok((hash1, h1))
    }
    
    /// Calculate total chain work up to a given block
    pub async fn calculate_chain_work(&self, tip: BlockHash) -> Result<[u8; 32]> {
        let mut total_work = [0u8; 32];
        let mut current = tip;
        
        loop {
            let index = self.database.get_block_index(&current)?
                .ok_or_else(|| anyhow::anyhow!("Block {} not in index", current))?;
            
            // Add this block's work to total
            total_work = self.add_work(&total_work, &index.block_work)?;
            
            if index.height == 0 {
                break; // Reached genesis
            }
            
            current = index.header.prev_blockhash;
        }
        
        Ok(total_work)
    }
    
    /// Add two work values (256-bit integers)
    fn add_work(&self, a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
        let mut result = [0u8; 32];
        let mut carry = 0u16;
        
        for i in (0..32).rev() {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            result[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        
        if carry != 0 {
            bail!("Work overflow");
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_work_addition() {
        let finder = ForkFinder::new(Arc::new(CoreDatabase::memory().unwrap()));
        
        let work1 = [0u8; 32];
        let work2 = [0u8; 32];
        let result = finder.add_work(&work1, &work2).unwrap();
        assert_eq!(result, [0u8; 32]);
        
        let mut work3 = [0u8; 32];
        work3[31] = 1;
        let mut work4 = [0u8; 32];
        work4[31] = 2;
        let result = finder.add_work(&work3, &work4).unwrap();
        assert_eq!(result[31], 3);
    }
}