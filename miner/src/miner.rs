use anyhow::Result;
use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Block, BlockHash, Target, Transaction};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tracing::{debug, info};

use crate::difficulty::{DifficultyAdjuster, DifficultyParams};
use crate::pow::ProofOfWorkMiner;
use crate::template::{EnhancedBlockTemplate, MiningTransaction, TemplateBuilder};
use crate::tx_selection::{MiningCandidate, TransactionSelector};

/// Transaction selector callback
pub type TxSelectorCallback = Box<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<Vec<MiningTransaction>>> + Send>> + Send + Sync,
>;

/// Block template for mining
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTemplate {
    pub version: i32,
    pub previous_block_hash: BlockHash,
    pub coinbase_value: u64,
    pub target: String,
    pub min_time: u32,
    pub cur_time: u32,
    pub height: u32,
    pub transactions: Vec<Transaction>,
}

/// Enhanced miner for generating blocks
pub struct Miner {
    coinbase_address: Option<Address>,
    pow_miner: ProofOfWorkMiner,
    template_builder: TemplateBuilder,
    difficulty_adjuster: DifficultyAdjuster,
    #[allow(dead_code)]
    num_threads: usize,
    tx_selector: Option<TxSelectorCallback>,
}

impl Default for Miner {
    fn default() -> Self {
        Self::new()
    }
}

impl Miner {
    pub fn new() -> Self {
        let num_threads = num_cpus::get();
        Self {
            coinbase_address: None,
            pow_miner: ProofOfWorkMiner::new(num_threads),
            template_builder: TemplateBuilder::new(),
            difficulty_adjuster: DifficultyAdjuster::new(DifficultyParams::mainnet()),
            num_threads,
            tx_selector: None,
        }
    }

    /// Create a miner with custom parameters
    pub fn with_params(num_threads: usize, params: DifficultyParams) -> Self {
        Self {
            coinbase_address: None,
            pow_miner: ProofOfWorkMiner::new(num_threads),
            template_builder: TemplateBuilder::new(),
            difficulty_adjuster: DifficultyAdjuster::new(params),
            num_threads,
            tx_selector: None,
        }
    }

    /// Set the transaction selector callback
    pub fn set_tx_selector(&mut self, selector: TxSelectorCallback) {
        self.tx_selector = Some(selector);
    }

    /// Get transactions from mempool using callback
    pub async fn get_mempool_transactions(&self) -> Result<Vec<MiningTransaction>> {
        if let Some(ref selector) = self.tx_selector {
            selector().await
        } else {
            Ok(Vec::new())
        }
    }

    pub fn set_coinbase_address(&mut self, address: Address) {
        self.coinbase_address = Some(address);
    }

    /// Check if mining is enabled (has coinbase address set)
    pub fn is_mining_enabled(&self) -> bool {
        self.coinbase_address.is_some()
    }

    /// Create an enhanced block template with proper transaction selection
    pub async fn create_enhanced_block_template(
        &self,
        chain_tip: BlockHash,
        height: u32,
        target: Target,
        coinbase_address: &Address,
    ) -> Result<EnhancedBlockTemplate> {
        debug!("Creating enhanced block template for height {}", height);

        // Get transactions from mempool
        let mempool_txs = self.get_mempool_transactions().await?;

        // Calculate total fees
        let total_fees: u64 = mempool_txs.iter().map(|tx| tx.fee.to_sat()).sum();

        // Calculate block reward (subsidy + fees)
        let subsidy = self.calculate_block_reward(height);
        let coinbase_value = subsidy + total_fees;

        // Create coinbase transaction
        let coinbase_tx =
            self.create_coinbase_transaction_with_value(coinbase_address, height, coinbase_value)?;

        // Build transaction list (coinbase + mempool transactions)
        let mut transactions = vec![coinbase_tx];
        transactions.extend(mempool_txs.iter().map(|mt| mt.tx.clone()));

        // Calculate merkle root
        let tx_hashes: Vec<_> = transactions
            .iter()
            .map(|tx| tx.compute_txid().into())
            .collect();
        let _merkle_root = bitcoin::merkle_tree::calculate_root(tx_hashes.into_iter())
            .unwrap_or(bitcoin::TxMerkleNode::from_byte_array([0u8; 32]));

        // Calculate total weight
        let total_weight: u64 = transactions.iter().map(|tx| tx.weight().to_wu()).sum();

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        Ok(EnhancedBlockTemplate {
            version: 0x20000000, // Version as i32
            previous_block_hash: chain_tip,
            transactions,
            coinbase_value: bitcoin::Amount::from_sat(coinbase_value),
            weight: bitcoin::Weight::from_wu(total_weight),
            fees: bitcoin::Amount::from_sat(total_fees),
            height,
            target,
            bits: bitcoin::CompactTarget::from_consensus(target.to_compact_lossy().to_consensus()),
            min_time: current_time,
            cur_time: current_time,
            sigop_count: 0, // Would calculate actual sigops
        })
    }

    /// Create a block template for mining (simple version)
    pub async fn create_block_template(
        &self,
        chain_tip: BlockHash,
        height: u32,
        transactions: Vec<Transaction>,
    ) -> Result<BlockTemplate> {
        debug!("Creating block template for height {}", height);

        let coinbase_value = self.calculate_block_reward(height);

        Ok(BlockTemplate {
            version: 0x20000000, // Version 2 blocks
            previous_block_hash: chain_tip,
            coinbase_value,
            target: "00000000ffff0000000000000000000000000000000000000000000000000000".to_string(),
            min_time: 0,
            cur_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            height,
            transactions,
        })
    }

    /// Create an optimized block template using advanced transaction selection
    pub async fn create_optimized_template(
        &self,
        chain_tip: BlockHash,
        height: u32,
        candidates: Vec<MiningCandidate>,
        target: Target,
    ) -> Result<EnhancedBlockTemplate> {
        info!(
            "Creating optimized block template with {} candidates",
            candidates.len()
        );

        // Use transaction selector to pick best transactions
        let selector = TransactionSelector::new(
            4_000_000 - 4000, // Max weight minus coinbase reserved
            1,                // Min fee rate of 1 sat/vB
        );

        let selected_candidates = selector.select_transactions(candidates)?;

        // Convert to transactions
        let transactions: Vec<Transaction> =
            selected_candidates.iter().map(|c| c.tx.clone()).collect();

        // Calculate total fees and weight
        let total_fees: u64 = selected_candidates.iter().map(|c| c.fee.to_sat()).sum();

        let total_weight: u64 = selected_candidates.iter().map(|c| c.weight as u64).sum();

        let coinbase_value = self.calculate_block_reward(height) + total_fees;

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        Ok(EnhancedBlockTemplate {
            version: 0x20000000,
            previous_block_hash: chain_tip,
            transactions,
            coinbase_value: bitcoin::Amount::from_sat(coinbase_value),
            weight: bitcoin::Weight::from_wu(total_weight + 4000), // Add coinbase weight
            fees: bitcoin::Amount::from_sat(total_fees),
            height,
            target,
            bits: bitcoin::CompactTarget::from_consensus(target.to_compact_lossy().to_consensus()),
            min_time: current_time,
            cur_time: current_time,
            sigop_count: 0, // Would calculate actual sigops
        })
    }

    /// Generate a block to a specific address (for testing/regtest)
    pub async fn generate_to_address(
        &self,
        address: &Address,
        chain_tip: BlockHash,
        height: u32,
    ) -> Result<Block> {
        info!("Generating block {} to address {}", height, address);

        // Create coinbase transaction
        let coinbase_tx = self.create_coinbase_transaction(address, height)?;

        // Create block header
        let header = BlockHeader {
            version: bitcoin::blockdata::block::Version::from_consensus(0x20000000),
            prev_blockhash: chain_tip,
            merkle_root: bitcoin::merkle_tree::calculate_root(std::iter::once(
                coinbase_tx.compute_txid().into(),
            ))
            .unwrap_or(bitcoin::TxMerkleNode::from_byte_array([0u8; 32])),
            time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff), // Regtest difficulty
            nonce: 0,
        };

        // Simple mining (find nonce)
        let mut mutable_header = header;
        let target = bitcoin::Target::from_compact(mutable_header.bits);

        loop {
            let hash = mutable_header.block_hash();
            if bitcoin::Target::from_le_bytes(hash.to_byte_array()) <= target {
                break;
            }
            mutable_header.nonce = mutable_header.nonce.wrapping_add(1);
        }

        Ok(Block {
            header: mutable_header,
            txdata: vec![coinbase_tx],
        })
    }

    fn calculate_block_reward(&self, height: u32) -> u64 {
        // Bitcoin block reward calculation
        let halvings = height / 210_000;
        if halvings >= 64 {
            return 0;
        }
        50_0000_0000u64 >> halvings
    }

    fn create_coinbase_transaction(&self, address: &Address, height: u32) -> Result<Transaction> {
        let value = self.calculate_block_reward(height);
        self.create_coinbase_transaction_with_value(address, height, value)
    }

    fn create_coinbase_transaction_with_value(
        &self,
        address: &Address,
        height: u32,
        value: u64,
    ) -> Result<Transaction> {
        use bitcoin::{OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        // Create coinbase input with height in scriptSig (BIP34)
        let coinbase_input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::builder()
                .push_int(height as i64)
                .push_opcode(bitcoin::opcodes::OP_FALSE) // OP_0
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        // Create output to the specified address
        let output = TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey: address.script_pubkey(),
        };

        Ok(Transaction {
            version: bitcoin::transaction::Version::non_standard(1),
            lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(0),
            input: vec![coinbase_input],
            output: vec![output],
        })
    }

    /// Create an enhanced block template with transaction selection
    pub async fn create_enhanced_template(
        &self,
        chain_tip: BlockHash,
        height: u32,
        target: Target,
        mempool_txs: Vec<MiningTransaction>,
    ) -> Result<EnhancedBlockTemplate> {
        debug!("Creating enhanced block template for height {}", height);

        self.template_builder
            .build_template(chain_tip, height, target, mempool_txs)
            .await
    }

    /// Mine a block with proof of work
    pub async fn mine_block(
        &self,
        template: &EnhancedBlockTemplate,
        address: &Address,
        timeout: Option<Duration>,
    ) -> Result<Block> {
        info!(
            "Mining block {} with {} transactions",
            template.height,
            template.transactions.len()
        );

        // Create coinbase transaction with fees
        let coinbase_tx = self.create_coinbase_with_fees(address, template)?;

        // Create block from template
        let block = self.template_builder.create_block(template, coinbase_tx)?;

        // Mine with proof of work
        let (mined_header, stats) =
            self.pow_miner
                .mine_block_header(block.header, template.target, timeout)?;

        info!(
            "Block mined! Nonce: {}, Hash rate: {:.2} MH/s",
            mined_header.nonce,
            stats.hash_rate / 1_000_000.0
        );

        Ok(Block {
            header: mined_header,
            txdata: block.txdata,
        })
    }

    /// Create coinbase transaction with fees
    fn create_coinbase_with_fees(
        &self,
        address: &Address,
        template: &EnhancedBlockTemplate,
    ) -> Result<Transaction> {
        use bitcoin::{OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        // Create coinbase input with height in script
        let coinbase_input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::builder()
                .push_int(template.height as i64)
                .push_slice(b"Mined by rust-bitcoin-core")
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        // Create output with block reward + fees
        let output = TxOut {
            value: template.coinbase_value,
            script_pubkey: address.script_pubkey(),
        };

        Ok(Transaction {
            version: bitcoin::transaction::Version::non_standard(1),
            lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(0),
            input: vec![coinbase_input],
            output: vec![output],
        })
    }

    /// Get mining statistics
    pub fn get_mining_info(&self, height: u32, target: Target, mempool_size: usize) -> serde_json::Value {
        use crate::difficulty::DifficultyStats;

        let stats = DifficultyStats::calculate(height, target, &self.difficulty_adjuster);

        serde_json::json!({
            "blocks": height,
            "difficulty": stats.current_difficulty,
            "networkhashps": stats.current_difficulty * 7158278.827, // Approximate
            "pooledtx": mempool_size,
            "chain": "main",
            "warnings": "",
        })
    }
}
