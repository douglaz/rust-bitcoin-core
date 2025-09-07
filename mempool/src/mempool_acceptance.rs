use anyhow::{bail, Result};
use bitcoin::{OutPoint, Transaction, TxOut, Txid};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::fee_estimation::{EstimationMode, FeeEstimate, FeeEstimator, FeeEstimatorConfig};
use bitcoin_core_lib::{TransactionValidator, UtxoTracker, ValidationFlags};

/// Mempool acceptance configuration
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum mempool size in bytes
    pub max_size_bytes: usize,

    /// Maximum mempool count
    pub max_count: usize,

    /// Minimum fee rate (sats/vbyte)
    pub min_fee_rate: f64,

    /// Maximum replacement fee rate multiplier
    pub replacement_fee_multiplier: f64,

    /// Maximum ancestors for a transaction
    pub max_ancestors: usize,

    /// Maximum descendants for a transaction
    pub max_descendants: usize,

    /// Expiry time in hours
    pub expiry_hours: u32,

    /// Enable full RBF
    pub full_rbf: bool,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 300_000_000, // 300MB
            max_count: 100_000,
            min_fee_rate: 1.0,               // 1 sat/vbyte
            replacement_fee_multiplier: 1.1, // 10% higher for RBF
            max_ancestors: 25,
            max_descendants: 25,
            expiry_hours: 336, // 2 weeks
            full_rbf: true,
        }
    }
}

/// Mempool entry with transaction and metadata
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// The transaction
    pub tx: Transaction,

    /// Transaction ID
    pub txid: Txid,

    /// Witness transaction ID
    pub wtxid: Txid,

    /// Fee in satoshis
    pub fee: u64,

    /// Virtual size
    pub vsize: usize,

    /// Weight
    pub weight: usize,

    /// Fee rate (sats/vbyte)
    pub fee_rate: f64,

    /// Time added to mempool
    pub time: u64,

    /// Height when added
    pub height: u32,

    /// Ancestors in mempool
    pub ancestors: HashSet<Txid>,

    /// Descendants in mempool
    pub descendants: HashSet<Txid>,

    /// RBF signaling
    pub rbf: bool,
}

/// Mempool with transaction acceptance logic
pub struct MempoolAcceptance {
    /// Configuration
    config: MempoolConfig,

    /// Transaction entries
    entries: Arc<RwLock<HashMap<Txid, MempoolEntry>>>,

    /// UTXO tracker
    utxo_tracker: Arc<UtxoTracker>,

    /// Transaction validator
    tx_validator: Arc<TransactionValidator>,

    /// Fee estimator
    fee_estimator: Arc<FeeEstimator>,

    /// Current mempool size in bytes
    size_bytes: Arc<RwLock<usize>>,

    /// Spent outputs in mempool
    spent_outputs: Arc<RwLock<HashMap<OutPoint, Txid>>>,

    /// Statistics
    stats: Arc<RwLock<MempoolStats>>,
    
    /// RBF policy (optional)
    rbf_policy: Option<Arc<crate::rbf::RBFPolicy>>,
}

/// Mempool statistics
#[derive(Debug, Default, Clone)]
pub struct MempoolStats {
    /// Number of transactions
    pub count: usize,

    /// Total size in bytes
    pub total_size: usize,

    /// Total fees
    pub total_fees: u64,

    /// Average fee rate
    pub avg_fee_rate: f64,

    /// Minimum fee rate
    pub min_fee_rate: f64,

    /// Maximum fee rate  
    pub max_fee_rate: f64,

    /// Transactions accepted
    pub tx_accepted: u64,

    /// Transactions rejected
    pub tx_rejected: u64,

    /// Transactions replaced (RBF)
    pub tx_replaced: u64,

    /// Transactions evicted
    pub tx_evicted: u64,
}

/// Transaction acceptance result
#[derive(Debug)]
pub enum AcceptanceResult {
    /// Transaction accepted
    Accepted { txid: Txid, fee: u64, vsize: usize },

    /// Transaction rejected
    Rejected { txid: Txid, reason: String },

    /// Transaction replaced existing one (RBF)
    Replaced {
        new_txid: Txid,
        replaced_txids: Vec<Txid>,
        fee_delta: i64,
    },
}

impl MempoolAcceptance {
    /// Create new mempool with acceptance logic
    pub fn new(config: MempoolConfig, utxo_tracker: Arc<UtxoTracker>, chain_height: u32) -> Self {
        let flags = ValidationFlags::for_height(chain_height);
        let fee_estimator = Arc::new(FeeEstimator::new(FeeEstimatorConfig::default()));

        Self {
            config,
            entries: Arc::new(RwLock::new(HashMap::new())),
            utxo_tracker,
            tx_validator: Arc::new(TransactionValidator::new(
                flags,
                chain_height,
                0, // Will be updated
                0, // Will be updated
            )),
            fee_estimator,
            size_bytes: Arc::new(RwLock::new(0)),
            spent_outputs: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(MempoolStats::default())),
            rbf_policy: None,
        }
    }

    /// Accept a transaction into the mempool
    pub async fn accept_transaction(&self, tx: Transaction) -> Result<AcceptanceResult> {
        let txid = tx.compute_txid();

        debug!("Evaluating transaction {} for mempool acceptance", txid);

        // Basic checks
        self.check_basic(&tx)?;

        // Check if already in mempool
        if self.entries.read().await.contains_key(&txid) {
            return Ok(AcceptanceResult::Rejected {
                txid,
                reason: "Transaction already in mempool".to_string(),
            });
        }

        // Check size limits
        let tx_size = bitcoin::consensus::serialize(&tx).len();
        if tx_size > 100_000 {
            return Ok(AcceptanceResult::Rejected {
                txid,
                reason: format!("Transaction too large: {} bytes", tx_size),
            });
        }

        // Calculate virtual size and weight
        let weight = Self::calculate_weight(&tx);
        let vsize = weight.div_ceil(4);

        // Validate inputs exist and calculate fee
        let (fee, prevouts) = self.validate_inputs_and_fee(&tx).await?;

        // Check minimum fee rate
        let fee_rate = fee as f64 / vsize as f64;
        if fee_rate < self.config.min_fee_rate {
            return Ok(AcceptanceResult::Rejected {
                txid,
                reason: format!(
                    "Fee rate {:.2} below minimum {:.2}",
                    fee_rate, self.config.min_fee_rate
                ),
            });
        }

        // Check for conflicts (double spends)
        let conflicts = self.find_conflicts(&tx).await;

        // Handle RBF if conflicts exist
        if !conflicts.is_empty() {
            return self.handle_rbf(tx, conflicts, fee, vsize).await;
        }

        // Validate scripts
        self.validate_scripts(&tx, &prevouts).await?;

        // Check ancestors/descendants limits
        self.check_package_limits(&tx).await?;

        // Check mempool size limits and evict if needed
        self.evict_if_needed(vsize).await?;

        // Add to mempool
        self.add_to_mempool(tx, fee, vsize, weight).await?;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.tx_accepted += 1;
        }

        info!(
            "Accepted transaction {} with fee {} sats ({:.2} sat/vB)",
            txid, fee, fee_rate
        );

        Ok(AcceptanceResult::Accepted { txid, fee, vsize })
    }

    /// Basic transaction checks
    fn check_basic(&self, tx: &Transaction) -> Result<()> {
        // Check transaction isn't coinbase
        if tx.is_coinbase() {
            bail!("Coinbase transactions not allowed in mempool");
        }

        // Check has inputs and outputs
        if tx.input.is_empty() {
            bail!("Transaction has no inputs");
        }
        if tx.output.is_empty() {
            bail!("Transaction has no outputs");
        }

        // Check for duplicate inputs
        let mut seen_inputs = HashSet::new();
        for input in &tx.input {
            if !seen_inputs.insert(input.previous_output) {
                bail!("Transaction has duplicate inputs");
            }
        }

        // Check output values
        let mut total_out = 0u64;
        for output in &tx.output {
            let value = output.value.to_sat();
            if value > 21_000_000 * 100_000_000 {
                bail!("Output value too large");
            }
            total_out = total_out
                .checked_add(value)
                .ok_or_else(|| anyhow::anyhow!("Output value overflow"))?;
        }

        Ok(())
    }

    /// Validate inputs exist and calculate fee
    async fn validate_inputs_and_fee(
        &self,
        tx: &Transaction,
    ) -> Result<(u64, HashMap<OutPoint, TxOut>)> {
        let mut prevouts = HashMap::new();
        let mut total_input = 0u64;

        for input in &tx.input {
            // Check if input is in mempool
            let entries = self.entries.read().await;
            let output = if let Some(parent_txid) =
                self.spent_outputs.read().await.get(&input.previous_output)
            {
                // Input spends mempool transaction
                let parent = entries
                    .get(parent_txid)
                    .ok_or_else(|| anyhow::anyhow!("Parent transaction not found"))?;

                parent
                    .tx
                    .output
                    .get(input.previous_output.vout as usize)
                    .ok_or_else(|| anyhow::anyhow!("Invalid output index"))?
                    .clone()
            } else {
                // Input spends UTXO
                self.utxo_tracker
                    .get_utxo(&input.previous_output)
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!("Input UTXO not found: {:?}", input.previous_output)
                    })?
                    .output
            };

            total_input += output.value.to_sat();
            prevouts.insert(input.previous_output, output);
        }

        // Calculate total output
        let total_output: u64 = tx.output.iter().map(|out| out.value.to_sat()).sum();

        // Calculate fee
        let fee = total_input
            .checked_sub(total_output)
            .ok_or_else(|| anyhow::anyhow!("Transaction fee would be negative"))?;

        Ok((fee, prevouts))
    }

    /// Find conflicting transactions (double spends)
    async fn find_conflicts(&self, tx: &Transaction) -> Vec<Txid> {
        let mut conflicts = Vec::new();
        let spent = self.spent_outputs.read().await;

        for input in &tx.input {
            if let Some(conflicting_txid) = spent.get(&input.previous_output) {
                if !conflicts.contains(conflicting_txid) {
                    conflicts.push(*conflicting_txid);
                }
            }
        }

        conflicts
    }

    /// Handle Replace-By-Fee (BIP125 compliant)
    async fn handle_rbf(
        &self,
        tx: Transaction,
        conflicts: Vec<Txid>,
        new_fee: u64,
        new_vsize: usize,
    ) -> Result<AcceptanceResult> {
        let txid = tx.compute_txid();

        info!(
            "Processing RBF replacement: {} replacing {} transaction(s)",
            txid,
            conflicts.len()
        );

        // BIP125 Rule #1: Original transactions must signal replaceability
        if !self.config.full_rbf {
            let entries = self.entries.read().await;
            for conflict_txid in &conflicts {
                if let Some(entry) = entries.get(conflict_txid) {
                    if !entry.rbf {
                        debug!(
                            "RBF rejected: {} doesn't signal replaceability",
                            conflict_txid
                        );
                        return Ok(AcceptanceResult::Rejected {
                            txid,
                            reason: format!(
                                "BIP125 Rule #1: Transaction {} is not replaceable",
                                conflict_txid
                            ),
                        });
                    }
                }
            }
        }

        // BIP125 Rule #2: No new unconfirmed inputs
        let mut original_spent = HashSet::new();
        let mut all_descendants = HashSet::new();
        {
            let entries = self.entries.read().await;
            for conflict_txid in &conflicts {
                if let Some(entry) = entries.get(conflict_txid) {
                    for input in &entry.tx.input {
                        original_spent.insert(input.previous_output);
                    }
                    // Collect all descendants that will be evicted
                    all_descendants.extend(&entry.descendants);
                }
            }

            // Add descendants' inputs to allowed set
            for desc_txid in &all_descendants {
                if let Some(desc_entry) = entries.get(desc_txid) {
                    for input in &desc_entry.tx.input {
                        original_spent.insert(input.previous_output);
                    }
                }
            }
        }

        // Check replacement doesn't add new unconfirmed inputs
        let spent_outputs = self.spent_outputs.read().await;
        for input in &tx.input {
            if !original_spent.contains(&input.previous_output) {
                // This is a new input - check if it's unconfirmed
                if spent_outputs.contains_key(&input.previous_output) {
                    debug!(
                        "RBF rejected: adds new unconfirmed input {:?}",
                        input.previous_output
                    );
                    return Ok(AcceptanceResult::Rejected {
                        txid,
                        reason: "BIP125 Rule #2: Replacement adds new unconfirmed inputs"
                            .to_string(),
                    });
                }
            }
        }
        drop(spent_outputs);

        // BIP125 Rule #5: Number of replacements limit
        // (limiting total number of transactions that will be evicted)
        let total_evictions = conflicts.len() + all_descendants.len();
        const MAX_REPLACEMENT_CANDIDATES: usize = 100;
        if total_evictions > MAX_REPLACEMENT_CANDIDATES {
            debug!(
                "RBF rejected: too many transactions would be evicted ({})",
                total_evictions
            );
            return Ok(AcceptanceResult::Rejected {
                txid,
                reason: format!(
                    "BIP125 Rule #5: Too many transactions to replace ({})",
                    total_evictions
                ),
            });
        }

        // Calculate total fee and size of transactions being replaced (including descendants)
        let mut old_fee = 0u64;
        let mut old_vsize = 0usize;
        {
            let entries = self.entries.read().await;

            // Add fees from direct conflicts
            for conflict_txid in &conflicts {
                if let Some(entry) = entries.get(conflict_txid) {
                    old_fee += entry.fee;
                    old_vsize += entry.vsize;
                }
            }

            // Add fees from descendants
            for desc_txid in &all_descendants {
                if let Some(entry) = entries.get(desc_txid) {
                    old_fee += entry.fee;
                    old_vsize += entry.vsize;
                }
            }
        }

        // BIP125 Rule #3: Replacement must pay for its own bandwidth
        let min_relay_fee = (new_vsize as f64 * self.config.min_fee_rate) as u64;
        let fee_for_bandwidth = old_fee + min_relay_fee;

        if new_fee < fee_for_bandwidth {
            debug!(
                "RBF rejected: insufficient fee for bandwidth. Need {} got {}",
                fee_for_bandwidth, new_fee
            );
            return Ok(AcceptanceResult::Rejected {
                txid,
                reason: format!(
                    "BIP125 Rule #3: Insufficient fee. Need {} sats, got {} sats",
                    fee_for_bandwidth, new_fee
                ),
            });
        }

        // BIP125 Rule #4: Replacement must pay higher feerate than replaced transactions
        let old_feerate = if old_vsize > 0 {
            old_fee as f64 / old_vsize as f64
        } else {
            0.0
        };
        let new_feerate = new_fee as f64 / new_vsize as f64;

        if new_feerate <= old_feerate {
            debug!(
                "RBF rejected: new feerate {} <= old feerate {}",
                new_feerate, old_feerate
            );
            return Ok(AcceptanceResult::Rejected {
                txid,
                reason: format!(
                    "BIP125 Rule #4: New feerate ({:.2} sat/vB) must exceed old ({:.2} sat/vB)",
                    new_feerate, old_feerate
                ),
            });
        }

        info!(
            "RBF accepted: {} replaces {} tx(s), fee increase: {} sats, feerate: {:.2} -> {:.2}",
            txid,
            conflicts.len(),
            new_fee - old_fee,
            old_feerate,
            new_feerate
        );

        // Remove conflicting transactions and their descendants
        for conflict_txid in &conflicts {
            self.remove_transaction(conflict_txid).await?;
        }

        // Remove descendants
        for desc_txid in &all_descendants {
            self.remove_transaction(desc_txid).await?;
        }

        // Add new transaction
        let weight = Self::calculate_weight(&tx);
        self.add_to_mempool(tx, new_fee, new_vsize, weight).await?;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.tx_replaced += conflicts.len() as u64;
        }

        info!(
            "Replaced {} transactions with {} (fee delta: {})",
            conflicts.len(),
            txid,
            new_fee as i64 - old_fee as i64
        );

        Ok(AcceptanceResult::Replaced {
            new_txid: txid,
            replaced_txids: conflicts,
            fee_delta: new_fee as i64 - old_fee as i64,
        })
    }

    /// Validate transaction scripts
    async fn validate_scripts(
        &self,
        tx: &Transaction,
        prevouts: &HashMap<OutPoint, TxOut>,
    ) -> Result<()> {
        // In real implementation, would call script interpreter
        // self.tx_validator.validate_transaction(tx, prevouts)?;
        Ok(())
    }

    /// Check package limits (ancestors/descendants)
    async fn check_package_limits(&self, tx: &Transaction) -> Result<()> {
        let entries = self.entries.read().await;
        let mut ancestors = HashSet::new();
        let mut to_check = Vec::new();

        // Find direct ancestors
        for input in &tx.input {
            if let Some(parent_txid) = self.spent_outputs.read().await.get(&input.previous_output) {
                ancestors.insert(*parent_txid);
                to_check.push(*parent_txid);
            }
        }

        // Find all ancestors recursively
        while let Some(txid) = to_check.pop() {
            if let Some(entry) = entries.get(&txid) {
                for ancestor in &entry.ancestors {
                    if ancestors.insert(*ancestor) {
                        to_check.push(*ancestor);
                    }
                }
            }
        }

        if ancestors.len() > self.config.max_ancestors {
            bail!("Transaction has too many ancestors: {}", ancestors.len());
        }

        Ok(())
    }

    /// Evict transactions if mempool is full
    async fn evict_if_needed(&self, new_size: usize) -> Result<()> {
        let current_size = *self.size_bytes.read().await;

        if current_size + new_size > self.config.max_size_bytes {
            // Sort by fee rate and evict lowest fee rate transactions
            let entries = self.entries.read().await;
            let mut sorted: Vec<_> = entries
                .values()
                .map(|e| (e.txid, e.fee_rate, e.vsize))
                .collect();
            sorted.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
            drop(entries);

            let mut evicted_size = 0;
            let mut evicted_count = 0;

            for (txid, _, vsize) in sorted {
                if current_size - evicted_size + new_size <= self.config.max_size_bytes {
                    break;
                }

                self.remove_transaction(&txid).await?;
                evicted_size += vsize;
                evicted_count += 1;
            }

            if evicted_count > 0 {
                let mut stats = self.stats.write().await;
                stats.tx_evicted += evicted_count;

                info!("Evicted {} transactions to make room", evicted_count);
            }
        }

        Ok(())
    }

    /// Add transaction to mempool
    async fn add_to_mempool(
        &self,
        tx: Transaction,
        fee: u64,
        vsize: usize,
        weight: usize,
    ) -> Result<()> {
        let txid = tx.compute_txid();
        let wtxid = tx.compute_txid(); // MempoolEntry expects Txid type for wtxid field
        let fee_rate = fee as f64 / vsize as f64;

        // Check for RBF signaling
        let rbf = tx.input.iter().any(|input| input.sequence.0 < 0xfffffffe);

        // Create entry
        let entry = MempoolEntry {
            tx: tx.clone(),
            txid,
            wtxid,
            fee,
            vsize,
            weight,
            fee_rate,
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            height: self.utxo_tracker.get_chain_height().await,
            ancestors: HashSet::new(), // Will be updated
            descendants: HashSet::new(),
            rbf,
        };

        // Update spent outputs
        {
            let mut spent = self.spent_outputs.write().await;
            for input in &tx.input {
                spent.insert(input.previous_output, txid);
            }
        }

        // Add to entries
        self.entries.write().await.insert(txid, entry);

        // Update size
        *self.size_bytes.write().await += vsize;

        // Update stats
        self.update_stats().await;

        Ok(())
    }

    /// Remove transaction from mempool
    async fn remove_transaction(&self, txid: &Txid) -> Result<()> {
        if let Some(entry) = self.entries.write().await.remove(txid) {
            // Remove from spent outputs
            let mut spent = self.spent_outputs.write().await;
            for input in &entry.tx.input {
                spent.remove(&input.previous_output);
            }

            // Update size
            *self.size_bytes.write().await -= entry.vsize;

            // Update stats
            self.update_stats().await;
        }

        Ok(())
    }

    /// Calculate transaction weight
    fn calculate_weight(tx: &Transaction) -> usize {
        let base_size = bitcoin::consensus::serialize(tx).len();
        // Weight = base_size * 3 + total_size
        // For now, simplified calculation
        base_size * 4
    }

    /// Update statistics
    async fn update_stats(&self) {
        let entries = self.entries.read().await;
        let mut stats = self.stats.write().await;

        stats.count = entries.len();
        stats.total_size = *self.size_bytes.read().await;

        if !entries.is_empty() {
            stats.total_fees = entries.values().map(|e| e.fee).sum();
            stats.avg_fee_rate =
                stats.total_fees as f64 / entries.values().map(|e| e.vsize).sum::<usize>() as f64;

            stats.min_fee_rate = entries
                .values()
                .map(|e| e.fee_rate)
                .min_by(|a, b| a.partial_cmp(b).unwrap())
                .unwrap_or(0.0);

            stats.max_fee_rate = entries
                .values()
                .map(|e| e.fee_rate)
                .max_by(|a, b| a.partial_cmp(b).unwrap())
                .unwrap_or(0.0);
        }
    }

    /// Get mempool statistics
    pub async fn get_stats(&self) -> MempoolStats {
        self.stats.read().await.clone()
    }

    /// Get all transactions
    pub async fn get_all_transactions(&self) -> Vec<Transaction> {
        self.entries
            .read()
            .await
            .values()
            .map(|e| e.tx.clone())
            .collect()
    }

    /// Update fee estimator with current mempool state
    pub async fn update_fee_estimator(&self) -> Result<()> {
        let entries = self.entries.read().await;

        // Prepare transaction data for fee estimator
        let tx_data: Vec<(Transaction, u64)> = entries
            .values()
            .map(|entry| (entry.tx.clone(), entry.fee))
            .collect();

        // Update mempool snapshot in fee estimator
        self.fee_estimator.update_mempool_snapshot(&tx_data).await?;

        Ok(())
    }

    /// Process a new block for fee estimation
    pub async fn process_block_for_fees(
        &self,
        height: u32,
        timestamp: u64,
        block_txs: &[Transaction],
    ) -> Result<()> {
        // Calculate fees for transactions in the block
        let mut fees = Vec::new();

        for tx in block_txs {
            let txid = tx.compute_txid();

            // Check if we had this transaction in mempool
            if let Some(entry) = self.entries.read().await.get(&txid) {
                fees.push(entry.fee);
            } else {
                // Estimate fee based on inputs/outputs
                // For coinbase, fee is 0
                if tx.is_coinbase() {
                    fees.push(0);
                } else {
                    // This would need UTXO lookups to calculate actual fee
                    // For now, use a placeholder
                    fees.push(1000); // 1000 sats placeholder
                }
            }
        }

        // Update fee estimator with block data
        self.fee_estimator
            .process_block(height, timestamp, block_txs, &fees)
            .await?;

        // Remove confirmed transactions from mempool
        for tx in block_txs {
            let txid = tx.compute_txid();
            self.remove_transaction(&txid).await?;
        }

        Ok(())
    }

    /// Get fee estimate for confirmation target
    pub async fn estimate_fee(&self, conf_target: u32) -> Result<FeeEstimate> {
        // Update estimator with current mempool state
        self.update_fee_estimator().await?;

        // Determine estimation mode based on target
        let mode = if conf_target <= 2 {
            EstimationMode::Priority
        } else if conf_target <= 6 {
            EstimationMode::Normal
        } else if conf_target <= 12 {
            EstimationMode::Conservative
        } else {
            EstimationMode::Economical
        };

        self.fee_estimator.estimate_fee(mode).await
    }

    /// Get smart fee estimate
    pub async fn estimate_smart_fee(
        &self,
        conf_target: u32,
    ) -> Result<crate::fee_estimation::SmartFeeEstimate> {
        // Update estimator with current mempool state
        self.update_fee_estimator().await?;

        self.fee_estimator.smart_fee_estimate(conf_target).await
    }

    /// Start fee estimator background task
    pub fn start_fee_estimator(&self) -> Arc<FeeEstimator> {
        let estimator = self.fee_estimator.clone();

        // Start the analysis loop
        let estimator_clone = estimator.clone();
        tokio::spawn(async move {
            estimator_clone.run_analysis_loop().await;
        });

        estimator
    }

    /// Get transaction by ID
    pub async fn get_transaction(&self, txid: &Txid) -> Option<MempoolEntry> {
        self.entries.read().await.get(txid).cloned()
    }
}
