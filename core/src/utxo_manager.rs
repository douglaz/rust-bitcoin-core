use anyhow::{bail, Context, Result};
use bitcoin::{Amount, BlockHash, OutPoint, Transaction, TxOut};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Undo data for a block - contains all information needed to rollback
#[derive(Debug, Clone)]
pub struct BlockUndoData {
    pub spent_utxos: Vec<(OutPoint, UtxoEntry)>,
    pub created_outpoints: Vec<OutPoint>,
    pub block_hash: BlockHash,
    pub height: u32,
}

/// UTXO entry representing an unspent transaction output
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub output: TxOut,
    pub height: u32,
    pub is_coinbase: bool,
    pub block_hash: BlockHash,
}

/// UTXO manager for tracking unspent transaction outputs
pub struct UtxoManager {
    utxos: Arc<RwLock<HashMap<OutPoint, UtxoEntry>>>,
    spent_in_mempool: Arc<RwLock<HashMap<OutPoint, bool>>>,
}

impl UtxoManager {
    /// Create a new UTXO manager
    pub fn new() -> Self {
        Self {
            utxos: Arc::new(RwLock::new(HashMap::new())),
            spent_in_mempool: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add UTXOs from a confirmed block and return undo data
    pub async fn add_block_utxos(
        &self,
        block: &bitcoin::Block,
        height: u32,
    ) -> Result<BlockUndoData> {
        let block_hash = block.block_hash();
        let mut utxos = self.utxos.write().await;
        let mut spent_utxos = Vec::new();
        let mut created_outpoints = Vec::new();

        // Add new UTXOs from this block
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            let is_coinbase = tx_index == 0;
            let txid = tx.compute_txid();

            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };

                let entry = UtxoEntry {
                    output: output.clone(),
                    height,
                    is_coinbase,
                    block_hash,
                };

                utxos.insert(outpoint, entry);
                created_outpoints.push(outpoint);
                debug!("Added UTXO: {}:{}", txid, vout);
            }
        }

        // Remove spent UTXOs and save them for undo
        for tx in &block.txdata[1..] {
            // Skip coinbase
            for input in &tx.input {
                if let Some(spent_entry) = utxos.remove(&input.previous_output) {
                    spent_utxos.push((input.previous_output, spent_entry));
                    debug!("Spent UTXO: {}", input.previous_output);
                } else {
                    warn!("Spending non-existent UTXO: {}", input.previous_output);
                }
            }
        }

        info!(
            "Processed block {} at height {}, UTXO set size: {}",
            block_hash,
            height,
            utxos.len()
        );

        Ok(BlockUndoData {
            spent_utxos,
            created_outpoints,
            block_hash,
            height,
        })
    }

    /// Apply undo data to rollback a block
    pub async fn apply_block_undo(&self, undo_data: &BlockUndoData) -> Result<()> {
        let mut utxos = self.utxos.write().await;

        // Remove UTXOs created by this block
        for outpoint in &undo_data.created_outpoints {
            if utxos.remove(outpoint).is_some() {
                debug!("Removed created UTXO: {}", outpoint);
            } else {
                warn!("Could not find UTXO to remove: {}", outpoint);
            }
        }

        // Restore UTXOs spent by this block
        for (outpoint, entry) in &undo_data.spent_utxos {
            utxos.insert(*outpoint, entry.clone());
            debug!("Restored spent UTXO: {}", outpoint);
        }

        info!(
            "Applied undo for block {} at height {}, UTXO set size: {}",
            undo_data.block_hash,
            undo_data.height,
            utxos.len()
        );

        Ok(())
    }

    /// Remove UTXOs from a block (for reorg) - legacy method
    pub async fn remove_block_utxos(&self, block: &bitcoin::Block, height: u32) -> Result<()> {
        let block_hash = block.block_hash();
        let mut utxos = self.utxos.write().await;

        // Remove UTXOs created by this block
        for tx in &block.txdata {
            let txid = tx.compute_txid();

            for vout in 0..tx.output.len() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };

                utxos.remove(&outpoint);
                debug!("Removed UTXO: {}:{}", txid, vout);
            }
        }

        // Note: Without undo data, we cannot restore spent UTXOs
        warn!("UTXO restoration requires undo data - use apply_block_undo instead");

        info!(
            "Removed block {} at height {}, UTXO set size: {}",
            block_hash,
            height,
            utxos.len()
        );

        Ok(())
    }

    /// Get a UTXO by outpoint
    pub async fn get_utxo(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        self.utxos.read().await.get(outpoint).cloned()
    }

    /// Check if a UTXO exists
    pub async fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        self.utxos.read().await.contains_key(outpoint)
    }

    /// Get multiple UTXOs
    pub async fn get_utxos(&self, outpoints: &[OutPoint]) -> HashMap<OutPoint, UtxoEntry> {
        let utxos = self.utxos.read().await;
        let mut result = HashMap::new();

        for outpoint in outpoints {
            if let Some(entry) = utxos.get(outpoint) {
                result.insert(*outpoint, entry.clone());
            }
        }

        result
    }

    /// Mark UTXOs as spent in mempool
    pub async fn mark_spent_in_mempool(&self, tx: &Transaction) -> Result<()> {
        let mut spent = self.spent_in_mempool.write().await;

        for input in &tx.input {
            if !self.has_utxo(&input.previous_output).await {
                bail!(
                    "Transaction spends non-existent UTXO: {}",
                    input.previous_output
                );
            }

            if spent.contains_key(&input.previous_output) {
                bail!("Transaction double-spends UTXO: {}", input.previous_output);
            }

            spent.insert(input.previous_output, true);
        }

        Ok(())
    }

    /// Remove mempool spending markers for a transaction
    pub async fn unmark_spent_in_mempool(&self, tx: &Transaction) {
        let mut spent = self.spent_in_mempool.write().await;

        for input in &tx.input {
            spent.remove(&input.previous_output);
        }
    }

    /// Clear all mempool spending markers
    pub async fn clear_mempool_spent(&self) {
        self.spent_in_mempool.write().await.clear();
    }

    /// Check if a UTXO is available (not spent in mempool)
    pub async fn is_utxo_available(&self, outpoint: &OutPoint) -> bool {
        if !self.has_utxo(outpoint).await {
            return false;
        }

        !self.spent_in_mempool.read().await.contains_key(outpoint)
    }

    /// Validate transaction inputs against UTXO set with current height
    pub async fn validate_transaction_inputs_at_height(
        &self,
        tx: &Transaction,
        current_height: u32,
    ) -> Result<Amount> {
        let mut total_input = Amount::ZERO;
        const COINBASE_MATURITY: u32 = 100;

        for input in &tx.input {
            let utxo = self
                .get_utxo(&input.previous_output)
                .await
                .with_context(|| format!("UTXO not found: {}", input.previous_output))?;

            // Check coinbase maturity (100 blocks)
            if utxo.is_coinbase {
                let age = current_height.saturating_sub(utxo.height);
                if age < COINBASE_MATURITY {
                    bail!(
                        "Coinbase UTXO at height {} cannot be spent until height {} (current: {})",
                        utxo.height,
                        utxo.height + COINBASE_MATURITY,
                        current_height
                    );
                }
                debug!(
                    "Coinbase UTXO at height {} is mature (age: {} blocks)",
                    utxo.height, age
                );
            }

            total_input = total_input
                .checked_add(utxo.output.value)
                .context("Input value overflow")?;
        }

        Ok(total_input)
    }

    /// Validate transaction inputs against UTXO set (legacy, assumes maturity)
    pub async fn validate_transaction_inputs(&self, tx: &Transaction) -> Result<Amount> {
        let mut total_input = Amount::ZERO;

        for input in &tx.input {
            let utxo = self
                .get_utxo(&input.previous_output)
                .await
                .with_context(|| format!("UTXO not found: {}", input.previous_output))?;

            // Check coinbase maturity (100 blocks)
            if utxo.is_coinbase {
                // Would need current height to check properly
                debug!(
                    "Warning: Coinbase UTXO at height {} - maturity not checked",
                    utxo.height
                );
            }

            total_input = total_input
                .checked_add(utxo.output.value)
                .context("Input value overflow")?;
        }

        Ok(total_input)
    }

    /// Get UTXO set statistics
    pub async fn get_stats(&self) -> UtxoStats {
        let utxos = self.utxos.read().await;
        let spent_in_mempool = self.spent_in_mempool.read().await;

        let mut total_amount = Amount::ZERO;
        let mut total_count = 0;

        for entry in utxos.values() {
            total_amount = total_amount
                .checked_add(entry.output.value)
                .unwrap_or(Amount::MAX);
            total_count += 1;
        }

        UtxoStats {
            total_count,
            total_amount,
            spent_in_mempool_count: spent_in_mempool.len(),
        }
    }

    /// Find UTXOs for a specific script pubkey
    pub async fn find_utxos_for_script(
        &self,
        script_pubkey: &bitcoin::ScriptBuf,
    ) -> Vec<(OutPoint, UtxoEntry)> {
        let utxos = self.utxos.read().await;
        let mut result = Vec::new();

        for (outpoint, entry) in utxos.iter() {
            if &entry.output.script_pubkey == script_pubkey {
                result.push((*outpoint, entry.clone()));
            }
        }

        result
    }

    /// Prune old UTXOs (for pruned nodes)
    pub async fn prune_before_height(&self, height: u32) -> usize {
        let mut utxos = self.utxos.write().await;
        let initial_size = utxos.len();

        utxos.retain(|_, entry| entry.height >= height);

        let pruned = initial_size - utxos.len();
        if pruned > 0 {
            info!("Pruned {} UTXOs before height {}", pruned, height);
        }

        pruned
    }

    /// Add a single UTXO
    pub async fn add_utxo(
        &self,
        outpoint: OutPoint,
        output: TxOut,
        height: u32,
        is_coinbase: bool,
    ) -> Result<()> {
        let mut utxos = self.utxos.write().await;
        let entry = UtxoEntry {
            output,
            height,
            is_coinbase,
            block_hash: BlockHash::from_raw_hash(
                bitcoin::hashes::Hash::from_slice(&[0; 32]).unwrap(),
            ), // Will be set properly when needed
        };
        utxos.insert(outpoint, entry);
        Ok(())
    }

    /// Remove a single UTXO
    pub async fn remove_utxo(&self, outpoint: &OutPoint) -> Result<()> {
        let mut utxos = self.utxos.write().await;
        utxos.remove(outpoint);
        Ok(())
    }

    /// Spend a UTXO
    pub async fn spend_utxo(&self, outpoint: &OutPoint) -> Result<()> {
        let mut utxos = self.utxos.write().await;
        if utxos.remove(outpoint).is_none() {
            bail!("Attempting to spend non-existent UTXO: {}", outpoint);
        }
        Ok(())
    }

    /// Flush UTXO data to persistent storage
    pub async fn flush(&self) -> Result<()> {
        // Note: This implementation keeps everything in memory.
        // In a production system, this would persist to disk.
        let utxos = self.utxos.read().await;
        let count = utxos.len();

        debug!("UTXO manager flush: {} UTXOs in memory", count);

        // In a real implementation, we would:
        // 1. Serialize the UTXO set
        // 2. Write to disk in batches
        // 3. Sync to ensure durability

        Ok(())
    }

    /// Save UTXO checkpoint
    pub async fn save_checkpoint(&self, height: u32, hash: &BlockHash) -> Result<()> {
        let utxos = self.utxos.read().await;
        info!(
            "Saving UTXO checkpoint at height {} ({}) with {} UTXOs",
            height,
            hash,
            utxos.len()
        );

        // In a real implementation, this would:
        // 1. Create a snapshot of the current UTXO set
        // 2. Save it with the height and hash metadata
        // 3. Allow for recovery from this point

        Ok(())
    }

    /// Load UTXO checkpoint
    pub async fn load_checkpoint(&self, height: u32, hash: &BlockHash) -> Result<()> {
        info!("Loading UTXO checkpoint from height {} ({})", height, hash);

        // In a real implementation, this would:
        // 1. Load the saved UTXO snapshot
        // 2. Verify the hash matches
        // 3. Replace the current UTXO set

        Ok(())
    }
}

/// UTXO set statistics
#[derive(Debug, Clone)]
pub struct UtxoStats {
    pub total_count: usize,
    pub total_amount: Amount,
    pub spent_in_mempool_count: usize,
}

impl Default for UtxoManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Block, Sequence, Transaction, TxIn, TxOut, Witness};

    #[tokio::test]
    async fn test_utxo_management() -> Result<()> {
        let manager = UtxoManager::new();

        // Create a simple block with coinbase
        let coinbase = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5000000000), // 50 BTC
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(1),
                prev_blockhash: BlockHash::from_raw_hash(
                    bitcoin::hashes::Hash::from_slice(&[0; 32]).unwrap(),
                ),
                merkle_root: bitcoin::hashes::Hash::from_byte_array([0u8; 32]),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![coinbase],
        };

        // Add block UTXOs
        manager.add_block_utxos(&block, 0).await?;

        // Check UTXO exists
        let outpoint = OutPoint {
            txid: block.txdata[0].compute_txid(),
            vout: 0,
        };

        assert!(manager.has_utxo(&outpoint).await);

        // Get UTXO
        let utxo = manager.get_utxo(&outpoint).await.unwrap();
        assert_eq!(utxo.output.value, Amount::from_sat(5000000000));
        assert!(utxo.is_coinbase);

        // Check stats
        let stats = manager.get_stats().await;
        assert_eq!(stats.total_count, 1);
        assert_eq!(stats.total_amount, Amount::from_sat(5000000000));

        Ok(())
    }

    #[tokio::test]
    async fn test_mempool_spending() -> Result<()> {
        let manager = UtxoManager::new();

        // Add a UTXO manually for testing
        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };

        let entry = UtxoEntry {
            output: TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            },
            height: 100,
            is_coinbase: false,
            block_hash: BlockHash::from_raw_hash(
                bitcoin::hashes::Hash::from_slice(&[0; 32]).unwrap(),
            ),
        };

        manager.utxos.write().await.insert(outpoint, entry);

        // Create transaction spending this UTXO
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        // Mark as spent in mempool
        manager.mark_spent_in_mempool(&tx).await?;

        // Check it's no longer available
        assert!(!manager.is_utxo_available(&outpoint).await);

        // But still exists in UTXO set
        assert!(manager.has_utxo(&outpoint).await);

        Ok(())
    }
}
