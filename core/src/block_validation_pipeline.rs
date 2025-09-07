use anyhow::{bail, Context, Result};
use bitcoin::{Block, BlockHash, OutPoint, TxOut};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, info};

use crate::consensus_rules::ConsensusRules;
use crate::parallel_validation::ParallelValidator;
use crate::transaction_validation::ValidationFlags;

/// Maximum parallel validation workers
const MAX_VALIDATION_WORKERS: usize = 16;

/// Maximum transactions to validate in parallel
const MAX_PARALLEL_TX_VALIDATION: usize = 100;

/// Block validation stages
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValidationStage {
    /// Initial block header validation
    HeaderValidation,

    /// Transaction structure validation
    StructureValidation,

    /// Transaction script validation
    ScriptValidation,

    /// UTXO updates
    UtxoUpdate,

    /// Final consensus checks
    ConsensusValidation,

    /// Complete
    Complete,
}

/// Block validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub block_hash: BlockHash,
    pub height: u32,
    pub valid: bool,
    pub error: Option<String>,
    pub validation_time: Duration,
    pub tx_validated: usize,
    pub tx_failed: usize,
    pub stage_timings: HashMap<ValidationStage, Duration>,
}

/// Block validation pipeline for parallel validation
pub struct BlockValidationPipeline {
    /// Consensus rules
    consensus_rules: Arc<ConsensusRules>,

    /// Validation semaphore for concurrency control
    validation_semaphore: Arc<Semaphore>,

    /// UTXO provider
    utxo_provider: Arc<RwLock<Box<dyn UtxoProvider + Send + Sync>>>,

    /// Validation flags
    validation_flags: ValidationFlags,

    /// Statistics
    stats: Arc<RwLock<ValidationStats>>,

    /// Worker count
    worker_count: usize,

    /// Parallel validator for script validation
    parallel_validator: Arc<ParallelValidator>,
}

/// UTXO provider trait
#[async_trait::async_trait]
pub trait UtxoProvider {
    /// Get UTXO for an outpoint
    async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>>;

    /// Get multiple UTXOs
    async fn get_utxos(&self, outpoints: &[OutPoint]) -> Result<HashMap<OutPoint, TxOut>>;

    /// Check if UTXO exists
    async fn has_utxo(&self, outpoint: &OutPoint) -> Result<bool>;

    /// Apply UTXO updates from block
    async fn apply_block(&self, block: &Block, height: u32) -> Result<()>;

    /// Revert UTXO updates from block
    async fn revert_block(&self, block: &Block, height: u32) -> Result<()>;
}

/// Validation statistics
#[derive(Debug, Default, Clone)]
pub struct ValidationStats {
    pub blocks_validated: u64,
    pub blocks_failed: u64,
    pub total_transactions: u64,
    pub failed_transactions: u64,
    pub total_validation_time: Duration,
    pub average_block_time: Duration,
    pub average_tx_time: Duration,
}

impl BlockValidationPipeline {
    /// Create new block validation pipeline
    pub fn new(
        consensus_rules: Arc<ConsensusRules>,
        utxo_provider: Box<dyn UtxoProvider + Send + Sync>,
        worker_count: usize,
    ) -> Self {
        let worker_count = worker_count.min(MAX_VALIDATION_WORKERS);
        Self {
            consensus_rules,
            validation_semaphore: Arc::new(Semaphore::new(worker_count)),
            utxo_provider: Arc::new(RwLock::new(utxo_provider)),
            validation_flags: ValidationFlags::for_height(800000), // Current height
            stats: Arc::new(RwLock::new(ValidationStats::default())),
            worker_count,
            parallel_validator: Arc::new(ParallelValidator::new(worker_count)),
        }
    }

    /// Validate a block
    pub async fn validate_block(
        &self,
        block: &Block,
        height: u32,
        prev_block_hash: BlockHash,
    ) -> Result<ValidationResult> {
        let start = Instant::now();
        let mut stage_timings = HashMap::new();

        info!(
            "Starting validation for block {} at height {}",
            block.block_hash(),
            height
        );

        // Stage 1: Header validation
        let stage_start = Instant::now();
        self.validate_header(block, height, prev_block_hash).await?;
        stage_timings.insert(ValidationStage::HeaderValidation, stage_start.elapsed());

        // Stage 2: Structure validation
        let stage_start = Instant::now();
        self.validate_structure(block, height).await?;
        stage_timings.insert(ValidationStage::StructureValidation, stage_start.elapsed());

        // Stage 3: Script validation (parallel)
        let stage_start = Instant::now();
        let (tx_validated, tx_failed) = self.validate_scripts(block, height).await?;
        stage_timings.insert(ValidationStage::ScriptValidation, stage_start.elapsed());

        // Stage 4: UTXO updates
        let stage_start = Instant::now();
        self.update_utxos(block, height).await?;
        stage_timings.insert(ValidationStage::UtxoUpdate, stage_start.elapsed());

        // Stage 5: Consensus validation
        let stage_start = Instant::now();
        self.validate_consensus(block, height).await?;
        stage_timings.insert(ValidationStage::ConsensusValidation, stage_start.elapsed());

        let validation_time = start.elapsed();

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.blocks_validated += 1;
        stats.total_transactions += block.txdata.len() as u64;
        stats.total_validation_time += validation_time;
        stats.average_block_time = stats.total_validation_time / stats.blocks_validated as u32;

        info!(
            "Block {} validated successfully in {:?}",
            block.block_hash(),
            validation_time
        );

        Ok(ValidationResult {
            block_hash: block.block_hash(),
            height,
            valid: true,
            error: None,
            validation_time,
            tx_validated,
            tx_failed,
            stage_timings,
        })
    }

    /// Validate block header
    async fn validate_header(
        &self,
        block: &Block,
        height: u32,
        prev_block_hash: BlockHash,
    ) -> Result<()> {
        debug!("Validating block header");

        // Check previous block hash
        if block.header.prev_blockhash != prev_block_hash {
            bail!("Invalid previous block hash");
        }

        // Check proof of work
        let target = block.header.target();
        let block_hash = block.header.block_hash();
        // Convert block hash to U256 for comparison with target
        let hash_ref: &[u8; 32] = block_hash.as_ref();
        let hash_bytes: [u8; 32] = *hash_ref;
        let hash_val = bitcoin::pow::Target::from_le_bytes(hash_bytes);
        if hash_val > target {
            bail!("Block does not meet proof of work requirement");
        }

        // Check timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let block_time = block.header.time as u64;

        // Block timestamp must not be more than 2 hours in the future
        if block_time > now + 7200 {
            bail!("Block timestamp too far in the future");
        }

        // Check version
        if height >= 750000 && block.header.version.to_consensus() < 0x20000000 {
            bail!("Block version too old");
        }

        Ok(())
    }

    /// Validate block structure
    async fn validate_structure(&self, block: &Block, height: u32) -> Result<()> {
        debug!("Validating block structure");

        // Check block size
        let block_size = bitcoin::consensus::encode::serialize(block).len();
        if block_size > 4_000_000 {
            bail!("Block size exceeds maximum");
        }

        // Check transaction count
        if block.txdata.is_empty() {
            bail!("Block has no transactions");
        }

        if block.txdata.len() > 1_000_000 {
            bail!("Block has too many transactions");
        }

        // First transaction must be coinbase
        if !block.txdata[0].is_coinbase() {
            bail!("First transaction is not coinbase");
        }

        // No other transaction should be coinbase
        for tx in &block.txdata[1..] {
            if tx.is_coinbase() {
                bail!("Non-first transaction is coinbase");
            }
        }

        // Check merkle root
        let calculated_root = block
            .compute_merkle_root()
            .context("Failed to compute merkle root")?;

        if calculated_root != block.header.merkle_root {
            bail!("Merkle root mismatch");
        }

        // Check witness commitment (for SegWit blocks)
        if height >= 481824 {
            self.validate_witness_commitment(block)?;
        }

        Ok(())
    }

    /// Validate witness commitment
    fn validate_witness_commitment(&self, block: &Block) -> Result<()> {
        // Check if block has witness data
        let has_witness = block
            .txdata
            .iter()
            .any(|tx| !tx.input.iter().all(|input| input.witness.is_empty()));

        if !has_witness {
            return Ok(()); // No witness data, no commitment needed
        }

        // Find witness commitment in coinbase
        let coinbase = &block.txdata[0];
        let mut found_commitment = false;

        for output in &coinbase.output {
            if output.script_pubkey.len() >= 38 {
                let script_bytes = output.script_pubkey.as_bytes();
                // Check for witness commitment pattern
                if script_bytes[0] == 0x6a && // OP_RETURN
                   script_bytes[1] == 0x24 && // Push 36 bytes
                   &script_bytes[2..6] == b"\xaa\x21\xa9\xed"
                {
                    found_commitment = true;

                    // Verify commitment
                    let commitment = &script_bytes[6..38];
                    let calculated = block
                        .witness_root()
                        .context("Failed to calculate witness root")?;

                    let calc_ref: &[u8] = calculated.as_ref();
                    if commitment != calc_ref {
                        bail!("Witness commitment mismatch");
                    }
                    break;
                }
            }
        }

        if !found_commitment {
            bail!("Block with witness data missing witness commitment");
        }

        Ok(())
    }

    /// Validate transaction scripts in parallel
    async fn validate_scripts(&self, block: &Block, height: u32) -> Result<(usize, usize)> {
        debug!("Validating transaction scripts using ParallelValidator");

        // Collect all required UTXOs
        let mut required_utxos = Vec::new();
        for tx in &block.txdata[1..] {
            // Skip coinbase
            for input in &tx.input {
                required_utxos.push(input.previous_output);
            }
        }

        // Fetch UTXOs from provider
        let utxo_provider = self.utxo_provider.read().await;
        let utxos = utxo_provider.get_utxos(&required_utxos).await?;
        drop(utxo_provider);

        // Use ParallelValidator for optimized parallel validation
        let result = self
            .parallel_validator
            .validate_block(block.clone(), height, utxos.clone())
            .await?;

        if !result.valid {
            if let Some(error) = result.error {
                bail!("Block validation failed: {}", error);
            } else {
                bail!("Block validation failed");
            }
        }

        debug!(
            "ParallelValidator completed: {} scripts validated ({} cached) in {}ms",
            result.scripts_validated, result.scripts_cached, result.validation_time_ms
        );

        Ok((result.scripts_validated as usize, 0))
    }

    /// Update UTXO set
    async fn update_utxos(&self, block: &Block, height: u32) -> Result<()> {
        debug!("Updating UTXO set");

        let utxo_provider = self.utxo_provider.write().await;
        utxo_provider.apply_block(block, height).await?;

        Ok(())
    }

    /// Validate consensus rules
    async fn validate_consensus(&self, block: &Block, height: u32) -> Result<()> {
        debug!("Validating consensus rules");

        // Check block reward
        let reward = self.calculate_block_reward(height);
        let coinbase = &block.txdata[0];
        let total_out: u64 = coinbase.output.iter().map(|o| o.value.to_sat()).sum();

        // Calculate fees from other transactions
        let mut total_fees = 0u64;
        let utxo_provider = self.utxo_provider.read().await;

        for tx in &block.txdata[1..] {
            let mut input_value = 0u64;
            for input in &tx.input {
                if let Some(utxo) = utxo_provider.get_utxo(&input.previous_output).await? {
                    input_value += utxo.value.to_sat();
                }
            }

            let output_value: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();

            if input_value < output_value {
                bail!("Transaction spends more than inputs");
            }

            total_fees += input_value - output_value;
        }

        // Coinbase output cannot exceed reward + fees
        if total_out > reward + total_fees {
            bail!("Coinbase output exceeds allowed amount");
        }

        // Check sigop count
        let total_sigops = self
            .count_block_sigops(block, utxo_provider.as_ref())
            .await?;
        if total_sigops > 80000 {
            bail!("Block exceeds maximum sigop count");
        }

        // Additional consensus rules based on height
        if height >= 750000 {
            // Taproot activation
            self.validate_taproot_rules(block)?;
        }

        Ok(())
    }

    /// Calculate block reward for height
    fn calculate_block_reward(&self, height: u32) -> u64 {
        let halvings = height / 210000;
        if halvings >= 64 {
            return 0;
        }
        50_0000_0000 >> halvings
    }

    /// Count sigops in block
    async fn count_block_sigops(
        &self,
        block: &Block,
        utxo_provider: &dyn UtxoProvider,
    ) -> Result<usize> {
        let mut total_sigops = 0;

        for tx in &block.txdata {
            // Count legacy sigops
            for output in &tx.output {
                total_sigops += count_script_sigops(&output.script_pubkey);
            }

            // Count P2SH sigops
            if !tx.is_coinbase() {
                for input in &tx.input {
                    if let Some(utxo) = utxo_provider.get_utxo(&input.previous_output).await? {
                        if utxo.script_pubkey.is_p2sh() {
                            // Would need to parse scriptSig to count accurately
                            total_sigops += 15; // Conservative estimate
                        }
                    }
                }
            }
        }

        Ok(total_sigops)
    }

    /// Validate Taproot-specific rules
    fn validate_taproot_rules(&self, block: &Block) -> Result<()> {
        // Taproot-specific validation
        for tx in &block.txdata {
            for (idx, input) in tx.input.iter().enumerate() {
                if !input.witness.is_empty() {
                    // Check for annex
                    if let Some(last) = input.witness.last() {
                        if !last.is_empty() && last[0] == 0x50 {
                            // Annex present, validate size
                            if last.len() > 256 {
                                bail!(
                                    "Taproot annex too large in tx {} input {}",
                                    tx.compute_txid(),
                                    idx
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get validation statistics
    pub async fn get_stats(&self) -> ValidationStats {
        self.stats.read().await.clone()
    }

    /// Get parallel validator statistics
    pub async fn get_parallel_stats(&self) -> crate::parallel_validation::ValidationStats {
        self.parallel_validator.get_stats().await
    }
}

/// Count sigops in a script
fn count_script_sigops(script: &bitcoin::ScriptBuf) -> usize {
    use bitcoin::blockdata::opcodes::{all::*, Opcode};

    let mut sigops = 0;
    let mut last_opcode: Option<Opcode> = None;

    for instruction in script.instructions() {
        if let Ok(bitcoin::blockdata::script::Instruction::Op(opcode)) = instruction {
            match opcode {
                OP_CHECKSIG | OP_CHECKSIGVERIFY => sigops += 1,
                OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                    // Count based on previous opcode
                    if let Some(prev) = last_opcode {
                        if prev.to_u8() >= OP_PUSHNUM_1.to_u8()
                            && prev.to_u8() <= OP_PUSHNUM_16.to_u8()
                        {
                            let n = (prev.to_u8() - OP_PUSHNUM_1.to_u8() + 1) as usize;
                            sigops += n;
                        } else {
                            sigops += 20; // Conservative default
                        }
                    } else {
                        sigops += 20;
                    }
                }
                _ => {}
            }
            last_opcode = Some(opcode);
        }
    }

    sigops
}

/// In-memory UTXO provider for testing
pub struct InMemoryUtxoProvider {
    utxos: Arc<RwLock<HashMap<OutPoint, TxOut>>>,
}

impl Default for InMemoryUtxoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryUtxoProvider {
    pub fn new() -> Self {
        Self {
            utxos: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl UtxoProvider for InMemoryUtxoProvider {
    async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        Ok(self.utxos.read().await.get(outpoint).cloned())
    }

    async fn get_utxos(&self, outpoints: &[OutPoint]) -> Result<HashMap<OutPoint, TxOut>> {
        let utxos = self.utxos.read().await;
        let mut result = HashMap::new();

        for outpoint in outpoints {
            if let Some(utxo) = utxos.get(outpoint) {
                result.insert(*outpoint, utxo.clone());
            }
        }

        Ok(result)
    }

    async fn has_utxo(&self, outpoint: &OutPoint) -> Result<bool> {
        Ok(self.utxos.read().await.contains_key(outpoint))
    }

    async fn apply_block(&self, block: &Block, _height: u32) -> Result<()> {
        let mut utxos = self.utxos.write().await;

        // Remove spent UTXOs
        for tx in &block.txdata {
            if !tx.is_coinbase() {
                for input in &tx.input {
                    utxos.remove(&input.previous_output);
                }
            }
        }

        // Add new UTXOs
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                utxos.insert(outpoint, output.clone());
            }
        }

        Ok(())
    }

    async fn revert_block(&self, block: &Block, _height: u32) -> Result<()> {
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
            }
        }

        // Note: We would need to restore spent UTXOs here in a real implementation

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[tokio::test]
    async fn test_validation_pipeline_creation() {
        let consensus_rules = Arc::new(ConsensusRules::new(Network::Bitcoin));
        let utxo_provider = Box::new(InMemoryUtxoProvider::new());

        let pipeline = BlockValidationPipeline::new(consensus_rules, utxo_provider, 4);

        let stats = pipeline.get_stats().await;
        assert_eq!(stats.blocks_validated, 0);
    }

    #[test]
    fn test_block_reward_calculation() {
        let consensus_rules = Arc::new(ConsensusRules::new(Network::Bitcoin));
        let utxo_provider = Box::new(InMemoryUtxoProvider::new());

        let pipeline = BlockValidationPipeline::new(consensus_rules, utxo_provider, 4);

        // Test halvings
        assert_eq!(pipeline.calculate_block_reward(0), 50_0000_0000);
        assert_eq!(pipeline.calculate_block_reward(210000), 25_0000_0000);
        assert_eq!(pipeline.calculate_block_reward(420000), 12_5000_0000);
        assert_eq!(pipeline.calculate_block_reward(630000), 6_2500_0000);
    }
}
