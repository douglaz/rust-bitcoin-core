use anyhow::{bail, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::blockdata::constants::WITNESS_SCALE_FACTOR;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, OutPoint, Script, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use bitcoin::{BlockHash, CompactTarget, Network, Target};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

use crate::fee_calculator::MiningFeeCalculator;

/// Block template for mining
#[derive(Debug, Clone)]
pub struct BlockTemplate {
    /// Block version
    pub version: i32,
    /// Previous block hash
    pub previous_block_hash: BlockHash,
    /// Merkle root (will be calculated)
    pub merkle_root: bitcoin::hash_types::TxMerkleNode,
    /// Block timestamp
    pub time: u32,
    /// Target bits
    pub bits: CompactTarget,
    /// Included transactions
    pub transactions: Vec<Transaction>,
    /// Coinbase value (block reward + fees)
    pub coinbase_value: Amount,
    /// Block height
    pub height: u32,
    /// Block weight
    pub weight: u64,
    /// Witness commitment (for SegWit)
    pub witness_commitment: Option<[u8; 32]>,
}

/// Block template configuration
#[derive(Debug, Clone)]
pub struct BlockTemplateConfig {
    pub max_block_weight: u64,
    pub max_block_size: usize,
    pub coinbase_reserve: usize,
    pub min_fee_rate: u64, // satoshis per virtual byte
}

impl Default for BlockTemplateConfig {
    fn default() -> Self {
        Self {
            max_block_weight: 4_000_000, // 4M weight units (SegWit)
            max_block_size: 1_000_000,   // 1MB base size
            coinbase_reserve: 1000,      // Reserve for coinbase
            min_fee_rate: 1,             // 1 sat/vB minimum
        }
    }
}

/// Block template builder
pub struct BlockTemplateBuilder {
    #[allow(dead_code)]
    network: Network,
    config: BlockTemplateConfig,
    fee_calculator: Option<Arc<MiningFeeCalculator>>,
}

impl BlockTemplateBuilder {
    /// Create new block template builder
    pub fn new(network: Network, config: BlockTemplateConfig) -> Self {
        Self {
            network,
            config,
            fee_calculator: None,
        }
    }

    /// Set the fee calculator for accurate fee computation
    pub fn with_fee_calculator(mut self, calculator: Arc<MiningFeeCalculator>) -> Self {
        self.fee_calculator = Some(calculator);
        self
    }

    /// Build block template
    pub async fn build_template(
        &self,
        prev_hash: BlockHash,
        height: u32,
        transactions: Vec<Transaction>,
        target: Target,
        coinbase_script: &Script,
    ) -> Result<BlockTemplate> {
        debug!("Building block template at height {}", height);

        // Calculate timestamp
        let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        // Select transactions that fit in block
        let selected = self.select_transactions(transactions, height).await?;

        // Calculate total fees
        let total_fees = self.calculate_total_fees(&selected).await?;

        // Calculate block reward
        let block_reward = self.calculate_block_reward(height);
        let coinbase_value = block_reward + total_fees;

        // Create coinbase transaction
        let coinbase_tx =
            self.create_coinbase_transaction(height, coinbase_value, coinbase_script, &selected)?;

        // Build final transaction list
        let mut final_txs = vec![coinbase_tx];
        final_txs.extend(selected);

        // Calculate merkle root
        let merkle_root = self.calculate_merkle_root(&final_txs)?;

        // Calculate witness commitment if needed
        let witness_commitment = if self.has_witness_transactions(&final_txs) {
            Some(self.calculate_witness_commitment(&final_txs)?)
        } else {
            None
        };

        // Calculate block weight
        let weight = self.calculate_block_weight(&final_txs)?;

        let template = BlockTemplate {
            version: 0x20000000, // Version 2 with BIP9 signaling
            previous_block_hash: prev_hash,
            merkle_root,
            time,
            bits: target.to_compact_lossy(),
            transactions: final_txs,
            coinbase_value,
            height,
            weight,
            witness_commitment,
        };

        info!(
            "Created block template: height={}, txs={}, weight={}, fees={}",
            height,
            template.transactions.len(),
            weight,
            total_fees
        );

        Ok(template)
    }

    /// Select transactions for inclusion in block
    async fn select_transactions(
        &self,
        transactions: Vec<Transaction>,
        _height: u32,
    ) -> Result<Vec<Transaction>> {
        // Calculate fee rates for all transactions
        let mut tx_with_rates = Vec::new();
        for tx in transactions {
            let fee_rate = self.calculate_fee_rate(&tx).await.unwrap_or(0);
            tx_with_rates.push((tx, fee_rate));
        }

        // Sort by fee rate (descending)
        tx_with_rates.sort_by(|a, b| b.1.cmp(&a.1));

        let mut selected = Vec::new();
        let mut total_weight = self.config.coinbase_reserve as u64 * WITNESS_SCALE_FACTOR as u64;
        let mut total_size = self.config.coinbase_reserve;

        for (tx, fee_rate) in tx_with_rates {
            let tx_weight = self.calculate_tx_weight(&tx)?;
            let tx_size = self.calculate_tx_size(&tx)?;

            // Check if transaction fits
            if total_weight + tx_weight > self.config.max_block_weight {
                continue;
            }
            if total_size + tx_size > self.config.max_block_size {
                continue;
            }

            // Check minimum fee rate
            if fee_rate < self.config.min_fee_rate {
                continue;
            }

            selected.push(tx);
            total_weight += tx_weight;
            total_size += tx_size;
        }

        Ok(selected)
    }

    /// Calculate total fees from selected transactions
    async fn calculate_total_fees(&self, transactions: &[Transaction]) -> Result<Amount> {
        if let Some(ref calculator) = self.fee_calculator {
            // Use actual UTXO lookups for accurate fee calculation
            let fees = calculator.calculate_fees_batch(transactions).await?;
            Ok(fees.into_iter().sum())
        } else {
            // Fallback to estimation if no calculator available
            let fee_per_tx = Amount::from_sat(1000); // 1000 sats per tx estimate
            Ok(fee_per_tx * transactions.len() as u64)
        }
    }

    /// Calculate block reward for given height
    fn calculate_block_reward(&self, height: u32) -> Amount {
        // Bitcoin halving schedule
        let halvings = height / 210_000;
        let subsidy = if halvings >= 64 {
            0
        } else {
            50_0000_0000u64 >> halvings // 50 BTC initial, halves every 210,000 blocks
        };

        Amount::from_sat(subsidy)
    }

    /// Create coinbase transaction
    fn create_coinbase_transaction(
        &self,
        height: u32,
        value: Amount,
        coinbase_script: &Script,
        _witness_txs: &[Transaction],
    ) -> Result<Transaction> {
        // Create coinbase input
        let mut coinbase_input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: Witness::new(),
        };

        // Add height to coinbase (BIP34)
        let height_bytes = height.to_le_bytes();
        let mut script_sig = vec![height_bytes.len() as u8];
        script_sig.extend_from_slice(&height_bytes[..3]); // Use 3 bytes for height
        coinbase_input.script_sig = ScriptBuf::from(script_sig);

        // Create coinbase output
        let coinbase_output = TxOut {
            value,
            script_pubkey: coinbase_script.to_owned(),
        };

        // Add witness commitment output if needed
        let mut outputs = vec![coinbase_output];
        if let Some(commitment) = self.calculate_witness_commitment_output(&[])? {
            outputs.push(commitment);
        }

        let coinbase = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![coinbase_input],
            output: outputs,
        };

        Ok(coinbase)
    }

    /// Calculate merkle root of transactions
    fn calculate_merkle_root(
        &self,
        transactions: &[Transaction],
    ) -> Result<bitcoin::hash_types::TxMerkleNode> {
        if transactions.is_empty() {
            bail!("Cannot calculate merkle root of empty transaction list");
        }

        let hashes: Vec<_> = transactions
            .iter()
            .map(|tx| tx.compute_txid().to_raw_hash())
            .collect();

        bitcoin::merkle_tree::calculate_root(hashes.into_iter())
            .map(bitcoin::hash_types::TxMerkleNode::from_raw_hash)
            .ok_or_else(|| anyhow::anyhow!("Failed to calculate merkle root"))
    }

    /// Check if any transactions have witness data
    fn has_witness_transactions(&self, transactions: &[Transaction]) -> bool {
        transactions
            .iter()
            .any(|tx| tx.input.iter().any(|input| !input.witness.is_empty()))
    }

    /// Calculate witness commitment
    fn calculate_witness_commitment(&self, transactions: &[Transaction]) -> Result<[u8; 32]> {
        let wtxids: Vec<_> = transactions
            .iter()
            .map(|tx| tx.compute_wtxid().to_byte_array())
            .collect();

        // Calculate witness merkle root
        let witness_root = bitcoin::merkle_tree::calculate_root(
            wtxids
                .iter()
                .map(|w| bitcoin::hashes::sha256d::Hash::from_byte_array(*w)),
        )
        .ok_or_else(|| anyhow::anyhow!("Failed to calculate witness root"))?;

        Ok(witness_root.to_byte_array())
    }

    /// Create witness commitment output
    fn calculate_witness_commitment_output(
        &self,
        _transactions: &[Transaction],
    ) -> Result<Option<TxOut>> {
        // For SegWit blocks, add witness commitment
        // This is a simplified version
        Ok(None)
    }

    /// Calculate transaction weight
    fn calculate_tx_weight(&self, tx: &Transaction) -> Result<u64> {
        let base_size = tx.base_size() as u64;
        let total_size = tx.total_size() as u64;
        let _witness_size = total_size - base_size;

        Ok(base_size * 3 + total_size)
    }

    /// Calculate transaction size
    fn calculate_tx_size(&self, tx: &Transaction) -> Result<usize> {
        let mut size = Vec::new();
        tx.consensus_encode(&mut size)?;
        Ok(size.len())
    }

    /// Calculate fee rate for transaction
    async fn calculate_fee_rate(&self, tx: &Transaction) -> Result<u64> {
        if let Some(ref calculator) = self.fee_calculator {
            // Use actual UTXO lookups for accurate fee rate
            let fee_rate = calculator.calculate_fee_rate(tx).await?;
            Ok(fee_rate as u64)
        } else {
            // Fallback to estimation if no calculator available
            let weight = self.calculate_tx_weight(tx)?;
            let fee = Amount::from_sat(1000); // Estimated fee
            Ok((fee.to_sat() * 4) / weight) // sat per weight unit * 4 = sat per vbyte
        }
    }

    /// Calculate total block weight
    fn calculate_block_weight(&self, transactions: &[Transaction]) -> Result<u64> {
        let mut total_weight = 0u64;

        for tx in transactions {
            total_weight += self.calculate_tx_weight(tx)?;
        }

        Ok(total_weight)
    }
}

/// Create block from template
pub fn create_block_from_template(template: &BlockTemplate, nonce: u32) -> Block {
    let header = BlockHeader {
        version: bitcoin::block::Version::from_consensus(template.version),
        prev_blockhash: template.previous_block_hash,
        merkle_root: template.merkle_root,
        time: template.time,
        bits: template.bits,
        nonce,
    };

    Block {
        header,
        txdata: template.transactions.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    #[test]
    fn test_block_reward_calculation() {
        let builder = BlockTemplateBuilder::new(Network::Bitcoin, BlockTemplateConfig::default());

        // Initial reward
        assert_eq!(
            builder.calculate_block_reward(0),
            Amount::from_btc(50.0).unwrap()
        );

        // First halving
        assert_eq!(
            builder.calculate_block_reward(210_000),
            Amount::from_btc(25.0).unwrap()
        );

        // Second halving
        assert_eq!(
            builder.calculate_block_reward(420_000),
            Amount::from_btc(12.5).unwrap()
        );

        // Third halving
        assert_eq!(
            builder.calculate_block_reward(630_000),
            Amount::from_btc(6.25).unwrap()
        );
    }

    #[test]
    fn test_coinbase_transaction_creation() {
        let builder = BlockTemplateBuilder::new(Network::Bitcoin, BlockTemplateConfig::default());

        let script = ScriptBuf::new();
        let coinbase = builder
            .create_coinbase_transaction(100_000, Amount::from_btc(50.0).unwrap(), &script, &[])
            .unwrap();

        assert_eq!(coinbase.input.len(), 1);
        assert!(coinbase.is_coinbase());
        assert_eq!(coinbase.output[0].value, Amount::from_btc(50.0).unwrap());
    }
}
