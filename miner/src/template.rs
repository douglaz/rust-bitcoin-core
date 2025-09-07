use anyhow::Result;
use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, BlockHash, Transaction, TxMerkleNode, Txid, Weight};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{debug, info};

use crate::sigop_counter::SigopCounter;

/// Transaction package for mining selection
#[derive(Debug, Clone)]
pub struct MiningTransaction {
    pub tx: Transaction,
    pub fee: Amount,
    pub weight: Weight,
    pub fee_rate: f64, // sats per weight unit
    pub ancestors: Vec<Txid>,
    pub descendants: Vec<Txid>,
}

impl MiningTransaction {
    pub fn new(tx: Transaction, fee: Amount) -> Self {
        let weight = tx.weight();
        let fee_rate = fee.to_sat() as f64 / weight.to_wu() as f64;

        Self {
            tx,
            fee,
            weight,
            fee_rate,
            ancestors: Vec::new(),
            descendants: Vec::new(),
        }
    }

    /// Calculate package fee rate including ancestors
    pub fn package_fee_rate(&self, packages: &BTreeMap<Txid, MiningTransaction>) -> f64 {
        let mut total_fee = self.fee;
        let mut total_weight = self.weight;

        for ancestor_id in &self.ancestors {
            if let Some(ancestor) = packages.get(ancestor_id) {
                total_fee += ancestor.fee;
                total_weight += ancestor.weight;
            }
        }

        total_fee.to_sat() as f64 / total_weight.to_wu() as f64
    }
}

/// Enhanced block template with full transaction selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedBlockTemplate {
    pub version: i32,
    pub previous_block_hash: BlockHash,
    pub coinbase_value: Amount,
    pub target: bitcoin::Target,
    pub bits: bitcoin::CompactTarget,
    pub min_time: u32,
    pub cur_time: u32,
    pub height: u32,
    pub transactions: Vec<Transaction>,
    pub fees: Amount,
    pub weight: Weight,
    pub sigop_count: u32,
}

/// Transaction selector for block template generation
pub struct TransactionSelector {
    max_weight: Weight,
    max_sigops: u32,
    min_fee_rate: f64,
    sigop_counter: Option<Arc<SigopCounter>>,
}

impl Default for TransactionSelector {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionSelector {
    pub fn new() -> Self {
        Self {
            max_weight: Weight::from_wu(4_000_000), // 4MB weight limit
            max_sigops: 80_000,                     // Max sigops per block
            min_fee_rate: 1.0,                      // 1 sat/vB minimum
            sigop_counter: None,
        }
    }

    /// Set the sigop counter for accurate sigop counting
    pub fn with_sigop_counter(mut self, counter: Arc<SigopCounter>) -> Self {
        self.sigop_counter = Some(counter);
        self
    }

    /// Select transactions for inclusion in a block
    pub async fn select_transactions(
        &self,
        mempool_txs: Vec<MiningTransaction>,
    ) -> Result<(Vec<Transaction>, Amount)> {
        info!(
            "Selecting transactions from {} candidates",
            mempool_txs.len()
        );

        // Build package map
        let mut packages: BTreeMap<Txid, MiningTransaction> = BTreeMap::new();
        for tx in mempool_txs {
            packages.insert(tx.tx.compute_txid(), tx);
        }

        // Sort by package fee rate (descending)
        let mut sorted_txs: Vec<_> = packages.values().cloned().collect();
        sorted_txs.sort_by(|a, b| {
            let a_rate = a.package_fee_rate(&packages);
            let b_rate = b.package_fee_rate(&packages);
            b_rate.partial_cmp(&a_rate).unwrap()
        });

        // Select transactions greedily
        let mut selected = Vec::with_capacity(sorted_txs.len());
        let mut total_weight = Weight::from_wu(0);
        let mut total_fees = Amount::ZERO;
        let mut total_sigops = 0u32;
        let mut included_txids = std::collections::HashSet::new();

        // Reserve space for coinbase transaction (roughly 250 bytes)
        total_weight += Weight::from_wu(1000);

        for mining_tx in sorted_txs {
            // Skip if fee rate too low
            if mining_tx.fee_rate < self.min_fee_rate {
                continue;
            }

            // Skip if already included
            if included_txids.contains(&mining_tx.tx.compute_txid()) {
                continue;
            }

            // Check if ancestors are included
            let mut can_include = true;
            for ancestor_id in &mining_tx.ancestors {
                if !included_txids.contains(ancestor_id) {
                    can_include = false;
                    break;
                }
            }

            if !can_include {
                continue;
            }

            // Check weight limit
            if total_weight + mining_tx.weight > self.max_weight {
                debug!("Skipping tx due to weight limit");
                continue;
            }

            // Check sigop limit
            let tx_sigops = if let Some(ref counter) = self.sigop_counter {
                // Use accurate sigop counting
                match counter.count_transaction_sigops(&mining_tx.tx).await {
                    Ok(count) => count,
                    Err(e) => {
                        debug!(
                            "Error counting sigops for tx {}: {}",
                            mining_tx.tx.compute_txid(),
                            e
                        );
                        // Fallback to conservative estimate
                        mining_tx.tx.input.len() as u32 * 2
                    }
                }
            } else {
                // Simplified counting - conservative estimate
                mining_tx.tx.input.len() as u32 * 2
            };
            if total_sigops + tx_sigops > self.max_sigops {
                debug!(
                    "Skipping tx due to sigop limit: {} + {} > {}",
                    total_sigops, tx_sigops, self.max_sigops
                );
                continue;
            }

            // Include transaction
            selected.push(mining_tx.tx.clone());
            total_weight += mining_tx.weight;
            total_fees += mining_tx.fee;
            total_sigops += tx_sigops;
            included_txids.insert(mining_tx.tx.compute_txid());

            debug!(
                "Selected tx {} with fee rate {:.2} sat/vB",
                mining_tx.tx.compute_txid(),
                mining_tx.fee_rate * 4.0 // Convert to sat/vB
            );
        }

        info!(
            "Selected {} transactions, total fees: {} sats, weight: {} WU",
            selected.len(),
            total_fees.to_sat(),
            total_weight.to_wu()
        );

        Ok((selected, total_fees))
    }
}

/// Block template builder
pub struct TemplateBuilder {
    selector: TransactionSelector,
}

impl Default for TemplateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateBuilder {
    pub fn new() -> Self {
        Self {
            selector: TransactionSelector::new(),
        }
    }

    /// Build an enhanced block template
    pub async fn build_template(
        &self,
        chain_tip: BlockHash,
        height: u32,
        target: bitcoin::Target,
        mempool_txs: Vec<MiningTransaction>,
    ) -> Result<EnhancedBlockTemplate> {
        debug!("Building block template for height {}", height);

        // Select transactions
        let (transactions, fees) = self.selector.select_transactions(mempool_txs).await?;

        // Calculate total weight
        let mut total_weight = Weight::from_wu(1000); // Coinbase weight estimate
        for tx in &transactions {
            total_weight += tx.weight();
        }

        // Calculate coinbase value (block reward + fees)
        let block_reward = calculate_block_reward(height);
        let coinbase_value = block_reward + fees;

        // Get current time
        let cur_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let sigop_count = transactions.len() as u32; // Calculate before move

        Ok(EnhancedBlockTemplate {
            version: 0x20000000, // Version 2 blocks
            previous_block_hash: chain_tip,
            coinbase_value,
            target,
            bits: bitcoin::CompactTarget::from_consensus(target.to_compact_lossy().to_consensus()),
            min_time: cur_time - 600, // 10 minutes earlier
            cur_time,
            height,
            transactions,
            fees,
            weight: total_weight,
            sigop_count, // Use pre-calculated value
        })
    }

    /// Create the actual block from a template
    pub fn create_block(
        &self,
        template: &EnhancedBlockTemplate,
        coinbase_tx: Transaction,
    ) -> Result<Block> {
        // Build transaction list
        let mut txdata = vec![coinbase_tx];
        txdata.extend(template.transactions.clone());

        // Calculate merkle root
        let tx_hashes: Vec<_> = txdata.iter().map(|tx| tx.compute_txid().into()).collect();
        let merkle_root = bitcoin::merkle_tree::calculate_root(tx_hashes.into_iter())
            .unwrap_or(TxMerkleNode::from_byte_array([0u8; 32]));

        // Create block header
        let header = BlockHeader {
            version: bitcoin::blockdata::block::Version::from_consensus(template.version),
            prev_blockhash: template.previous_block_hash,
            merkle_root,
            time: template.cur_time,
            bits: template.bits,
            nonce: 0,
        };

        Ok(Block { header, txdata })
    }
}

/// Calculate block reward for a given height
pub fn calculate_block_reward(height: u32) -> Amount {
    // Bitcoin block reward calculation
    let halvings = height / 210_000;
    if halvings >= 64 {
        return Amount::ZERO;
    }
    Amount::from_sat(50_0000_0000u64 >> halvings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_reward_calculation() {
        assert_eq!(calculate_block_reward(0), Amount::from_sat(50_0000_0000));
        assert_eq!(
            calculate_block_reward(210_000),
            Amount::from_sat(25_0000_0000)
        );
        assert_eq!(
            calculate_block_reward(420_000),
            Amount::from_sat(12_5000_0000)
        );
        assert_eq!(
            calculate_block_reward(630_000),
            Amount::from_sat(6_2500_0000)
        );
    }

    #[tokio::test]
    async fn test_transaction_selection() {
        let selector = TransactionSelector::new();

        // Create test transactions with different fee rates
        let mut mempool_txs = Vec::new();

        // High fee transaction - make sure inputs/outputs are not empty for realistic txid
        let tx1 = bitcoin::Transaction {
            version: bitcoin::transaction::Version::non_standard(2),
            lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(0),
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(40000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let mut mining_tx1 = MiningTransaction::new(tx1, Amount::from_sat(10000));
        mining_tx1.weight = Weight::from_wu(1000);
        mining_tx1.fee_rate = 10.0;
        mempool_txs.push(mining_tx1);

        // Low fee transaction - different input to make unique txid
        let tx2 = bitcoin::Transaction {
            version: bitcoin::transaction::Version::non_standard(2),
            lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(0),
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 1,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(9000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let mut mining_tx2 = MiningTransaction::new(tx2, Amount::from_sat(1000));
        mining_tx2.weight = Weight::from_wu(1000);
        mining_tx2.fee_rate = 1.0;
        mempool_txs.push(mining_tx2);

        let (selected, total_fees) = selector.select_transactions(mempool_txs).await.unwrap();

        // Should select both transactions (high fee first)
        assert_eq!(
            selected.len(),
            2,
            "Expected 2 transactions, got {}",
            selected.len()
        );
        assert_eq!(total_fees, Amount::from_sat(11000));
    }
}
