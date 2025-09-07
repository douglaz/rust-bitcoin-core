use anyhow::{bail, Result};
use bitcoin::{Block, BlockHash, OutPoint, Transaction, TxOut};
use bitcoin_hashes::Hash;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

/// Parallel block validation for improved performance
pub struct ParallelValidator {
    /// Number of worker threads
    num_workers: usize,

    /// Semaphore for limiting concurrent validations
    validation_semaphore: Arc<Semaphore>,

    /// Script validation thread pool
    script_pool: rayon::ThreadPool,

    /// Signature cache for validation
    sig_cache: Arc<RwLock<SignatureCache>>,

    /// Script cache for common scripts
    script_cache: Arc<RwLock<ScriptCache>>,

    /// Validation queue
    validation_queue: Arc<RwLock<ValidationQueue>>,
}

/// Signature cache to avoid repeated validations
pub struct SignatureCache {
    cache: lru::LruCache<[u8; 32], bool>,
    hits: u64,
    misses: u64,
}

impl SignatureCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: lru::LruCache::new(std::num::NonZeroUsize::new(capacity).unwrap()),
            hits: 0,
            misses: 0,
        }
    }

    pub fn get(&mut self, sig_hash: &[u8; 32]) -> Option<bool> {
        if let Some(&valid) = self.cache.get(sig_hash) {
            self.hits += 1;
            Some(valid)
        } else {
            self.misses += 1;
            None
        }
    }

    pub fn insert(&mut self, sig_hash: [u8; 32], valid: bool) {
        self.cache.put(sig_hash, valid);
    }
}

/// Script execution cache
pub struct ScriptCache {
    cache: HashMap<[u8; 32], bool>,
    max_size: usize,
}

impl ScriptCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_size,
        }
    }

    pub fn get(&self, script_hash: &[u8; 32]) -> Option<bool> {
        self.cache.get(script_hash).copied()
    }

    pub fn insert(&mut self, script_hash: [u8; 32], valid: bool) {
        if self.cache.len() >= self.max_size {
            // Simple eviction - remove random entry
            if let Some(key) = self.cache.keys().next().cloned() {
                self.cache.remove(&key);
            }
        }
        self.cache.insert(script_hash, valid);
    }
}

/// Validation task for queue
#[derive(Debug)]
struct ValidationTask {
    block: Block,
    height: u32,
    prevouts: HashMap<OutPoint, TxOut>,
    result_sender: mpsc::Sender<ValidationResult>,
}

/// Validation result
#[derive(Debug)]
pub struct ValidationResult {
    pub block_hash: BlockHash,
    pub height: u32,
    pub valid: bool,
    pub error: Option<String>,
    pub validation_time_ms: u64,
    pub scripts_validated: u32,
    pub scripts_cached: u32,
}

/// Validation queue for pending blocks
struct ValidationQueue {
    tasks: Vec<ValidationTask>,
    in_progress: HashSet<BlockHash>,
}

impl ParallelValidator {
    /// Create new parallel validator
    pub fn new(num_workers: usize) -> Self {
        let script_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_workers)
            .thread_name(|i| format!("script-validator-{}", i))
            .build()
            .expect("Failed to create thread pool");

        Self {
            num_workers,
            validation_semaphore: Arc::new(Semaphore::new(num_workers)),
            script_pool,
            sig_cache: Arc::new(RwLock::new(SignatureCache::new(500_000))), // Optimized: 500k signatures
            script_cache: Arc::new(RwLock::new(ScriptCache::new(200_000))), // Optimized: 200k scripts
            validation_queue: Arc::new(RwLock::new(ValidationQueue {
                tasks: Vec::new(),
                in_progress: HashSet::new(),
            })),
        }
    }

    /// Validate block with parallel script execution
    pub async fn validate_block(
        &self,
        block: Block,
        height: u32,
        prevouts: HashMap<OutPoint, TxOut>,
    ) -> Result<ValidationResult> {
        let start = std::time::Instant::now();
        let block_hash = block.block_hash();

        info!(
            "Starting parallel validation of block {} at height {}",
            block_hash, height
        );

        // Acquire validation permit
        let _permit = self.validation_semaphore.acquire().await?;

        // Mark block as in progress
        {
            let mut queue = self.validation_queue.write().await;
            if !queue.in_progress.insert(block_hash) {
                bail!("Block {} already being validated", block_hash);
            }
        }

        // Validate block structure first (single-threaded)
        self.validate_block_structure(&block)?;

        // Validate transactions in parallel
        let (scripts_validated, scripts_cached) = self
            .validate_transactions_parallel(&block, &prevouts)
            .await?;

        // Remove from in progress
        {
            let mut queue = self.validation_queue.write().await;
            queue.in_progress.remove(&block_hash);
        }

        let validation_time_ms = start.elapsed().as_millis() as u64;

        info!(
            "Block {} validated in {}ms ({} scripts validated, {} cached)",
            block_hash, validation_time_ms, scripts_validated, scripts_cached
        );

        Ok(ValidationResult {
            block_hash,
            height,
            valid: true,
            error: None,
            validation_time_ms,
            scripts_validated,
            scripts_cached,
        })
    }

    /// Validate block structure (non-parallel checks)
    fn validate_block_structure(&self, block: &Block) -> Result<()> {
        // Check block size
        let block_size = bitcoin::consensus::encode::serialize(block).len();
        if block_size > 4_000_000 {
            bail!("Block size {} exceeds maximum", block_size);
        }

        // Check transaction count
        if block.txdata.is_empty() {
            bail!("Block has no transactions");
        }

        // Check first transaction is coinbase
        if !block.txdata[0].is_coinbase() {
            bail!("First transaction is not coinbase");
        }

        // Check no other coinbase transactions
        for tx in &block.txdata[1..] {
            if tx.is_coinbase() {
                bail!("Multiple coinbase transactions");
            }
        }

        Ok(())
    }

    /// Validate all transactions in parallel
    async fn validate_transactions_parallel(
        &self,
        block: &Block,
        prevouts: &HashMap<OutPoint, TxOut>,
    ) -> Result<(u32, u32)> {
        let mut total_scripts = 0u32;
        let mut cached_scripts = 0u32;

        // Skip coinbase (first transaction)
        let transactions: Vec<_> = block.txdata[1..].to_vec();

        // Create validation tasks for each transaction
        let validation_tasks: Vec<_> = transactions
            .into_par_iter()
            .enumerate()
            .map(|(tx_idx, tx)| {
                let actual_idx = tx_idx + 1; // Account for skipped coinbase
                self.validate_transaction_scripts(tx, actual_idx, prevouts)
            })
            .collect();

        // Collect results
        for result in validation_tasks {
            let (validated, cached) = result?;
            total_scripts += validated;
            cached_scripts += cached;
        }

        Ok((total_scripts, cached_scripts))
    }

    /// Validate scripts for a single transaction
    fn validate_transaction_scripts(
        &self,
        tx: Transaction,
        tx_index: usize,
        prevouts: &HashMap<OutPoint, TxOut>,
    ) -> Result<(u32, u32)> {
        let mut scripts_validated = 0u32;
        let scripts_cached = 0u32;

        // Validate each input in parallel
        let input_results: Vec<Result<bool>> = tx
            .input
            .par_iter()
            .enumerate()
            .map(|(input_idx, input)| {
                // Get the prevout
                let prevout = prevouts
                    .get(&input.previous_output)
                    .ok_or_else(|| anyhow::anyhow!("Missing prevout for input {}", input_idx))?;

                // Calculate script hash for caching
                let script_hash = self.calculate_script_hash(
                    &input.script_sig,
                    &prevout.script_pubkey,
                    &tx,
                    input_idx,
                );

                // Check script cache
                let cached_result = {
                    let script_cache = self.script_cache.blocking_read();
                    script_cache.get(&script_hash)
                };

                if let Some(valid) = cached_result {
                    return Ok(valid);
                }

                // Validate script (this would call the actual script interpreter)
                let valid = self.validate_script_execution(
                    &input.script_sig,
                    &prevout.script_pubkey,
                    &tx,
                    input_idx,
                    prevout.value,
                )?;

                // Update cache
                {
                    let mut script_cache = self.script_cache.blocking_write();
                    script_cache.insert(script_hash, valid);
                }

                Ok(valid)
            })
            .collect();

        // Check all inputs validated successfully
        for (i, result) in input_results.iter().enumerate() {
            match result {
                Ok(true) => scripts_validated += 1,
                Ok(false) => bail!(
                    "Script validation failed for transaction {} input {}",
                    tx_index,
                    i
                ),
                Err(e) => bail!("Script validation error: {}", e),
            }
        }

        Ok((scripts_validated, scripts_cached))
    }

    /// Calculate hash of script execution for caching
    fn calculate_script_hash(
        &self,
        script_sig: &bitcoin::ScriptBuf,
        script_pubkey: &bitcoin::ScriptBuf,
        tx: &Transaction,
        input_index: usize,
    ) -> [u8; 32] {
        use bitcoin::hashes::{sha256, Hash};

        let mut data = Vec::new();
        data.extend_from_slice(script_sig.as_bytes());
        data.extend_from_slice(script_pubkey.as_bytes());
        data.extend_from_slice(&tx.compute_txid()[..]);
        data.extend_from_slice(&(input_index as u32).to_le_bytes());

        sha256::Hash::hash(&data).to_byte_array()
    }

    /// Validate script execution using actual script interpreter
    fn validate_script_execution(
        &self,
        script_sig: &bitcoin::ScriptBuf,
        script_pubkey: &bitcoin::ScriptBuf,
        tx: &Transaction,
        input_index: usize,
        amount: bitcoin::Amount,
    ) -> Result<bool> {
        use crate::script::{verify_script, ScriptFlags, TransactionSignatureChecker};

        debug!(
            "Validating script for input {} (amount: {})",
            input_index, amount
        );

        // For now, create empty prevouts vector (would need full context in production)
        let prevouts = vec![];

        // Create signature checker for this input
        let checker = TransactionSignatureChecker::new(tx, input_index, amount.to_sat(), prevouts);

        // Standard script verification flags
        let flags = ScriptFlags::P2SH
            | ScriptFlags::STRICTENC
            | ScriptFlags::CHECKLOCKTIMEVERIFY
            | ScriptFlags::CHECKSEQUENCEVERIFY
            | ScriptFlags::WITNESS
            | ScriptFlags::NULLDUMMY
            | ScriptFlags::MINIMALDATA
            | ScriptFlags::DISCOURAGE_UPGRADEABLE_WITNESS_PROGRAM
            | ScriptFlags::WITNESS_PUBKEYTYPE;

        // Scripts are already the correct type - just need references
        let sig_script = script_sig.as_script();
        let pub_script = script_pubkey.as_script();

        // Verify the script execution
        match verify_script(sig_script, pub_script, flags, &checker) {
            Ok(()) => {
                debug!("Script validation passed for input {}", input_index);
                Ok(true)
            }
            Err(e) => {
                warn!("Script validation error for input {}: {}", input_index, e);
                Ok(false)
            }
        }
    }

    /// Batch validate multiple blocks
    pub async fn validate_blocks_batch(
        &self,
        blocks: Vec<(Block, u32, HashMap<OutPoint, TxOut>)>,
    ) -> Vec<ValidationResult> {
        let mut handles = Vec::new();

        for (block, height, prevouts) in blocks {
            let validator = self.clone();
            let handle: JoinHandle<Result<ValidationResult>> =
                tokio::spawn(
                    async move { validator.validate_block(block, height, prevouts).await },
                );
            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => {
                    error!("Block validation failed: {}", e);
                    results.push(ValidationResult {
                        block_hash: BlockHash::all_zeros(),
                        height: 0,
                        valid: false,
                        error: Some(e.to_string()),
                        validation_time_ms: 0,
                        scripts_validated: 0,
                        scripts_cached: 0,
                    });
                }
                Err(e) => {
                    error!("Task join error: {}", e);
                }
            }
        }

        results
    }

    /// Get validation statistics
    pub async fn get_stats(&self) -> ValidationStats {
        let sig_cache = self.sig_cache.read().await;
        let queue = self.validation_queue.read().await;

        ValidationStats {
            sig_cache_hits: sig_cache.hits,
            sig_cache_misses: sig_cache.misses,
            pending_validations: queue.tasks.len(),
            in_progress_validations: queue.in_progress.len(),
            worker_threads: self.num_workers,
        }
    }
}

// Make ParallelValidator cloneable
impl Clone for ParallelValidator {
    fn clone(&self) -> Self {
        Self {
            num_workers: self.num_workers,
            validation_semaphore: self.validation_semaphore.clone(),
            script_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(self.num_workers)
                .build()
                .expect("Failed to create thread pool"),
            sig_cache: self.sig_cache.clone(),
            script_cache: self.script_cache.clone(),
            validation_queue: self.validation_queue.clone(),
        }
    }
}

/// Validation statistics
#[derive(Debug, Clone)]
pub struct ValidationStats {
    pub sig_cache_hits: u64,
    pub sig_cache_misses: u64,
    pub pending_validations: usize,
    pub in_progress_validations: usize,
    pub worker_threads: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[tokio::test]
    async fn test_parallel_validation() -> Result<()> {
        let validator = ParallelValidator::new(4);

        // Create a test block
        let block = bitcoin::blockdata::constants::genesis_block(Network::Bitcoin);
        let prevouts = HashMap::new();

        let result = validator.validate_block(block, 0, prevouts).await?;

        assert!(result.valid);
        assert_eq!(result.height, 0);

        Ok(())
    }
}
