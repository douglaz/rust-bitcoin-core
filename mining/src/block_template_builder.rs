use anyhow::{bail, Context, Result};
use bitcoin::{
    Block, BlockHash, BlockHeader, Transaction, TxOut, OutPoint,
    Amount, Script, ScriptBuf, Witness, TxIn, Sequence,
    absolute::LockTime, CompactTarget, Target, Work,
};
use bitcoin::blockdata::transaction::Version as TxVersion;
use bitcoin::block::Version as BlockVersion;
use bitcoin::hashes::{Hash, sha256d};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use bitcoin_core_lib::chain::ChainManager;
use mempool::{MempoolAcceptance, MempoolEntry};

/// Block template for mining
#[derive(Debug, Clone)]
pub struct BlockTemplate {
    /// Block header (without nonce)
    pub header: BlockHeader,
    
    /// Transactions to include
    pub transactions: Vec<Transaction>,
    
    /// Coinbase value (subsidy + fees)
    pub coinbase_value: u64,
    
    /// Block height
    pub height: u32,
    
    /// Previous block hash
    pub prev_hash: BlockHash,
    
    /// Target difficulty
    pub target: Target,
    
    /// Minimum time
    pub min_time: u32,
    
    /// Maximum time
    pub max_time: u32,
    
    /// Current time
    pub cur_time: u32,
    
    /// Block weight
    pub weight: usize,
    
    /// Block size
    pub size: usize,
    
    /// Total fees
    pub fees: u64,
    
    /// Witness commitment (if any)
    pub witness_commitment: Option<[u8; 32]>,
}

/// Block template builder
pub struct BlockTemplateBuilder {
    /// Chain manager
    chain: Arc<RwLock<ChainManager>>,
    
    /// Mempool
    mempool: Arc<MempoolAcceptance>,
    
    /// Mining address for coinbase
    mining_address: ScriptBuf,
    
    /// Extra nonce for coinbase
    extra_nonce: Arc<RwLock<u32>>,
    
    /// Maximum block weight
    max_block_weight: usize,
    
    /// Minimum block time
    min_block_time: u32,
}

impl BlockTemplateBuilder {
    /// Create new block template builder
    pub fn new(
        chain: Arc<RwLock<ChainManager>>,
        mempool: Arc<MempoolAcceptance>,
        mining_address: ScriptBuf,
    ) -> Self {
        Self {
            chain,
            mempool,
            mining_address,
            extra_nonce: Arc::new(RwLock::new(0)),
            max_block_weight: 4_000_000, // 4M weight units
            min_block_time: 0,
        }
    }
    
    /// Build a new block template
    pub async fn build_template(&self) -> Result<BlockTemplate> {
        info!("Building new block template");
        
        // Get chain state
        let chain = self.chain.read().await;
        let best_height = chain.get_best_height();
        let best_hash = chain.get_best_block_hash();
        let next_height = best_height + 1;
        
        // Get difficulty target
        let target = self.calculate_target(&chain, next_height).await?;
        
        // Get median time past
        let median_time = chain.get_median_time_past(best_height);
        drop(chain);
        
        // Calculate times
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        
        let min_time = median_time + 1;
        let max_time = now + 2 * 60 * 60; // 2 hours in future
        let cur_time = now.max(min_time);
        
        // Select transactions from mempool
        let (transactions, total_fees, total_weight) = 
            self.select_transactions(next_height).await?;
        
        // Calculate block subsidy
        let subsidy = self.calculate_subsidy(next_height);
        let coinbase_value = subsidy + total_fees;
        
        // Create coinbase transaction
        let coinbase_tx = self.create_coinbase_transaction(
            next_height,
            coinbase_value,
            &transactions,
        ).await?;
        
        // Build complete transaction list
        let mut block_txs = vec![coinbase_tx];
        block_txs.extend(transactions.clone());
        
        // Calculate block size
        let block_size = block_txs.iter()
            .map(|tx| bitcoin::consensus::serialize(tx).len())
            .sum::<usize>() + 80; // Plus header
        
        // Create block header
        let header = BlockHeader {
            version: BlockVersion::TWO,
            prev_blockhash: best_hash,
            merkle_root: self.calculate_merkle_root(&block_txs),
            time: cur_time,
            bits: CompactTarget::from_consensus(target.to_compact_lossy().to_consensus()),
            nonce: 0, // Will be filled by miner
        };
        
        // Calculate witness commitment if needed
        let witness_commitment = if block_txs.iter().any(|tx| !tx.input[0].witness.is_empty()) {
            Some(self.calculate_witness_commitment(&block_txs))
        } else {
            None
        };
        
        let template = BlockTemplate {
            header,
            transactions: block_txs,
            coinbase_value,
            height: next_height,
            prev_hash: best_hash,
            target,
            min_time,
            max_time,
            cur_time,
            weight: total_weight,
            size: block_size,
            fees: total_fees,
            witness_commitment,
        };
        
        info!(
            "Built block template: height={}, txs={}, fees={}, weight={}", 
            next_height, template.transactions.len(), total_fees, total_weight
        );
        
        Ok(template)
    }
    
    /// Select transactions from mempool
    async fn select_transactions(
        &self,
        block_height: u32,
    ) -> Result<(Vec<Transaction>, u64, usize)> {
        let mut selected = Vec::new();
        let mut total_fees = 0u64;
        let mut total_weight = 272; // Coinbase weight
        
        // Get all mempool transactions sorted by fee rate
        let all_txs = self.mempool.get_all_transactions().await;
        let mut candidates: Vec<(Transaction, u64, usize)> = Vec::new();
        
        for tx in all_txs {
            let txid = tx.compute_txid();
            if let Some(entry) = self.mempool.get_transaction(&txid).await {
                candidates.push((tx, entry.fee, entry.weight));
            }
        }
        
        // Sort by fee rate (descending)
        candidates.sort_by(|a, b| {
            let rate_a = a.1 as f64 / a.2 as f64;
            let rate_b = b.1 as f64 / b.2 as f64;
            rate_b.partial_cmp(&rate_a).unwrap()
        });
        
        // Select transactions that fit in block
        for (tx, fee, weight) in candidates {
            if total_weight + weight > self.max_block_weight {
                continue; // Skip if doesn't fit
            }
            
            selected.push(tx);
            total_fees += fee;
            total_weight += weight;
            
            // Stop if block is nearly full
            if total_weight > self.max_block_weight * 95 / 100 {
                break;
            }
        }
        
        debug!(
            "Selected {} transactions with {} total fees", 
            selected.len(), total_fees
        );
        
        Ok((selected, total_fees, total_weight))
    }
    
    /// Create coinbase transaction
    async fn create_coinbase_transaction(
        &self,
        height: u32,
        value: u64,
        transactions: &[Transaction],
    ) -> Result<Transaction> {
        // Create coinbase input
        let mut coinbase_script = vec![];
        
        // Add block height (BIP34)
        if height >= 227931 {
            let height_bytes = height.to_le_bytes();
            let len = if height < 128 {
                1
            } else if height < 32768 {
                2
            } else if height < 8388608 {
                3
            } else {
                4
            };
            coinbase_script.push(len);
            coinbase_script.extend_from_slice(&height_bytes[..len as usize]);
        }
        
        // Add extra nonce
        let mut extra_nonce = self.extra_nonce.write().await;
        *extra_nonce += 1;
        coinbase_script.extend_from_slice(&extra_nonce.to_le_bytes());
        
        // Add mining software identifier
        coinbase_script.extend_from_slice(b"/rust-bitcoin-node/");
        
        let coinbase_input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from(coinbase_script),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        
        // Create outputs
        let mut outputs = vec![
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: self.mining_address.clone(),
            }
        ];
        
        // Add witness commitment output if needed
        if transactions.iter().any(|tx| {
            tx.input.iter().any(|input| !input.witness.is_empty())
        }) {
            let commitment = self.calculate_witness_commitment(transactions);
            let commitment_script = Self::create_witness_commitment_script(commitment);
            outputs.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: commitment_script,
            });
        }
        
        Ok(Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![coinbase_input],
            output: outputs,
        })
    }
    
    /// Calculate block subsidy
    fn calculate_subsidy(&self, height: u32) -> u64 {
        let halvings = height / 210_000;
        if halvings >= 64 {
            return 0;
        }
        
        let subsidy = 50 * 100_000_000; // 50 BTC in satoshis
        subsidy >> halvings
    }
    
    /// Calculate merkle root
    fn calculate_merkle_root(&self, transactions: &[Transaction]) -> bitcoin::hashes::sha256d::Hash {
        if transactions.is_empty() {
            return sha256d::Hash::all_zeros();
        }
        
        let mut hashes: Vec<_> = transactions
            .iter()
            .map(|tx| tx.compute_txid().to_raw_hash())
            .collect();
        
        if hashes.len() == 1 {
            return hashes[0];
        }
        
        // Build merkle tree
        while hashes.len() > 1 {
            if hashes.len() % 2 != 0 {
                hashes.push(*hashes.last().unwrap());
            }
            
            let mut new_hashes = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut data = Vec::new();
                data.extend_from_slice(chunk[0].as_ref());
                data.extend_from_slice(chunk[1].as_ref());
                new_hashes.push(sha256d::Hash::hash(&data));
            }
            
            hashes = new_hashes;
        }
        
        hashes[0]
    }
    
    /// Calculate witness commitment
    fn calculate_witness_commitment(&self, transactions: &[Transaction]) -> [u8; 32] {
        // Calculate witness root
        let mut hashes: Vec<_> = transactions
            .iter()
            .map(|tx| tx.compute_wtxid().to_raw_hash())
            .collect();
        
        // First transaction witness is zero
        hashes[0] = sha256d::Hash::all_zeros();
        
        // Build merkle tree
        while hashes.len() > 1 {
            if hashes.len() % 2 != 0 {
                hashes.push(*hashes.last().unwrap());
            }
            
            let mut new_hashes = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut data = Vec::new();
                data.extend_from_slice(chunk[0].as_ref());
                data.extend_from_slice(chunk[1].as_ref());
                new_hashes.push(sha256d::Hash::hash(&data));
            }
            
            hashes = new_hashes;
        }
        
        // Commitment is hash of witness root and witness nonce
        let mut commitment_data = Vec::new();
        commitment_data.extend_from_slice(hashes[0].as_ref());
        commitment_data.extend_from_slice(&[0u8; 32]); // Witness nonce
        
        sha256d::Hash::hash(&commitment_data).to_byte_array()
    }
    
    /// Create witness commitment script
    fn create_witness_commitment_script(commitment: [u8; 32]) -> ScriptBuf {
        let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        script.extend_from_slice(&commitment);
        ScriptBuf::from(script)
    }
    
    /// Calculate target for next block
    async fn calculate_target(&self, chain: &ChainManager, height: u32) -> Result<Target> {
        // For now, return current difficulty
        // Real implementation would calculate based on difficulty adjustment rules
        let difficulty = chain.get_current_difficulty();
        
        // Convert difficulty to target
        let max_target = Target::MAX;
        let target_f = max_target.to_work_be() / difficulty;
        
        // This is simplified - real implementation needs proper conversion
        Ok(Target::from_be_bytes([0xff; 32]))
    }
    
    /// Submit a mined block
    pub async fn submit_block(&self, block: Block) -> Result<()> {
        info!("Submitting mined block: {}", block.block_hash());
        
        // Validate block
        let mut chain = self.chain.write().await;
        chain.process_block(block.clone()).await?;
        
        info!("Successfully added mined block to chain");
        Ok(())
    }
    
    /// Get current mining info
    pub async fn get_mining_info(&self) -> Result<MiningInfo> {
        let chain = self.chain.read().await;
        let height = chain.get_best_height();
        let difficulty = chain.get_current_difficulty();
        let hash_rate = self.estimate_network_hashrate(difficulty);
        
        Ok(MiningInfo {
            blocks: height,
            current_block_weight: 0,
            current_block_tx: 0,
            difficulty,
            network_hashps: hash_rate,
            pooled_tx: self.mempool.get_stats().await.count,
            chain: "main".to_string(),
        })
    }
    
    /// Estimate network hashrate from difficulty
    fn estimate_network_hashrate(&self, difficulty: f64) -> f64 {
        // hashrate = difficulty * 2^32 / 600 seconds
        difficulty * 4_294_967_296.0 / 600.0
    }
}

/// Mining information
#[derive(Debug, Clone)]
pub struct MiningInfo {
    pub blocks: u32,
    pub current_block_weight: usize,
    pub current_block_tx: usize,
    pub difficulty: f64,
    pub network_hashps: f64,
    pub pooled_tx: usize,
    pub chain: String,
}