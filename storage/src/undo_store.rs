use anyhow::{Context, Result};
use bitcoin::{Block, BlockHash, OutPoint, TxOut};
use serde::{Deserialize, Serialize};
use sled::{Db, Tree};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Undo data for reverting a single block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockUndoData {
    pub block_hash: BlockHash,
    pub height: u32,
    pub spent_outputs: Vec<SpentOutput>,
    pub created_outputs: Vec<OutPoint>,
}

/// A spent output that needs to be restored during reorg
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpentOutput {
    pub outpoint: OutPoint,
    pub output: TxOut,
    pub height: u32,
    pub is_coinbase: bool,
}

/// Manages undo data for block reversals during reorganization
pub struct UndoStore {
    undo_tree: Tree,
}

impl UndoStore {
    pub fn new(db: Arc<Db>) -> Self {
        let undo_tree = db.open_tree("undo_data").expect("Failed to open undo tree");
        Self { undo_tree }
    }

    /// Generate undo data for a block
    pub fn generate_undo_data(
        block: &Block,
        height: u32,
        utxo_set: &HashMap<OutPoint, TxOut>,
    ) -> BlockUndoData {
        let mut spent_outputs = Vec::new();
        let mut created_outputs = Vec::new();

        // Process all transactions
        for tx in block.txdata.iter() {
            // Skip coinbase inputs (they don't spend anything)
            if !tx.is_coinbase() {
                // Record spent outputs
                for input in &tx.input {
                    if let Some(output) = utxo_set.get(&input.previous_output) {
                        spent_outputs.push(SpentOutput {
                            outpoint: input.previous_output,
                            output: output.clone(),
                            height: 0,          // Would need to track this properly
                            is_coinbase: false, // Would need to track this properly
                        });
                    }
                }
            }

            // Record created outputs
            let txid = tx.compute_txid();
            for (vout, _) in tx.output.iter().enumerate() {
                created_outputs.push(OutPoint {
                    txid,
                    vout: vout as u32,
                });
            }
        }

        BlockUndoData {
            block_hash: block.block_hash(),
            height,
            spent_outputs,
            created_outputs,
        }
    }

    /// Store undo data for a block
    pub async fn store(&self, block_hash: &BlockHash, undo_data: &BlockUndoData) -> Result<()> {
        debug!("Storing undo data for block {}", block_hash);

        let key: &[u8] = block_hash.as_ref();
        let value = bincode::serialize(undo_data).context("Failed to serialize undo data")?;

        self.undo_tree
            .insert(key, value)
            .context("Failed to store undo data")?;

        Ok(())
    }

    /// Get undo data for a block
    pub async fn get(&self, block_hash: &BlockHash) -> Result<Option<BlockUndoData>> {
        let key: &[u8] = block_hash.as_ref();

        match self.undo_tree.get(key)? {
            Some(data) => {
                let undo_data =
                    bincode::deserialize(&data).context("Failed to deserialize undo data")?;
                Ok(Some(undo_data))
            }
            None => Ok(None),
        }
    }

    /// Delete undo data for a block
    pub async fn delete(&self, block_hash: &BlockHash) -> Result<()> {
        let key: &[u8] = block_hash.as_ref();
        self.undo_tree.remove(key)?;
        debug!("Deleted undo data for block {}", block_hash);
        Ok(())
    }

    /// Apply undo data to revert a block
    pub fn apply_undo_data(
        undo_data: &BlockUndoData,
        utxo_set: &mut HashMap<OutPoint, TxOut>,
    ) -> Result<()> {
        info!(
            "Applying undo data for block {} at height {}",
            undo_data.block_hash, undo_data.height
        );

        // Remove created outputs
        for outpoint in &undo_data.created_outputs {
            utxo_set.remove(outpoint);
        }

        // Restore spent outputs
        for spent in &undo_data.spent_outputs {
            utxo_set.insert(spent.outpoint, spent.output.clone());
        }

        debug!(
            "Reverted {} created outputs and restored {} spent outputs",
            undo_data.created_outputs.len(),
            undo_data.spent_outputs.len()
        );

        Ok(())
    }

    /// Get statistics about stored undo data
    pub async fn get_stats(&self) -> Result<UndoStoreStats> {
        let entry_count = self.undo_tree.len();
        // Estimate size (sled doesn't expose exact disk size)
        let size_on_disk = (entry_count * 1024) as u64; // Estimate 1KB per entry

        Ok(UndoStoreStats {
            entry_count,
            size_on_disk,
        })
    }

    /// Prune old undo data
    pub async fn prune_before(&self, height: u32) -> Result<usize> {
        let mut pruned = 0;
        let mut to_delete = Vec::new();

        // Find entries to delete
        for (key, value) in self.undo_tree.iter().flatten() {
            if let Ok(undo_data) = bincode::deserialize::<BlockUndoData>(&value) {
                if undo_data.height < height {
                    to_delete.push(key);
                }
            }
        }

        // Delete old entries
        for key in to_delete {
            self.undo_tree.remove(key)?;
            pruned += 1;
        }

        info!("Pruned {} undo entries below height {}", pruned, height);
        Ok(pruned)
    }
}

/// Statistics about the undo store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoStoreStats {
    pub entry_count: usize,
    pub size_on_disk: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_undo_data_generation() {
        // Create a simple block for testing
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Bitcoin);
        let utxo_set = HashMap::new();

        let undo_data = UndoStore::generate_undo_data(&genesis, 0, &utxo_set);

        assert_eq!(undo_data.height, 0);
        assert_eq!(undo_data.block_hash, genesis.block_hash());
        assert!(!undo_data.created_outputs.is_empty());
        assert!(undo_data.spent_outputs.is_empty()); // Genesis doesn't spend anything
    }
}
