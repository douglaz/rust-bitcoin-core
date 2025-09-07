use anyhow::{bail, Context, Result};
use bitcoin::{Amount, OutPoint, Transaction};
use dashmap::DashMap;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::persistence::MempoolPersistence;
use crate::validation::{
    validate_mempool_acceptance, EnhancedMempoolEntry, MempoolPolicy, PackageInfo,
    ValidationContext,
};
use bitcoin_core_lib::chain::ChainManager;
use bitcoin_core_lib::fee::FeeCalculator;
use bitcoin_core_lib::fee_estimation::{FeeEstimator, FeeRate as EstimatorFeeRate};
use bitcoin_core_lib::script::ScriptFlags;
use bitcoin_core_lib::utxo_manager::UtxoManager;
use futures::FutureExt;

pub struct Mempool {
    transactions: DashMap<bitcoin::Txid, Transaction>,
    // Enhanced entries with full metadata
    entries: DashMap<bitcoin::Txid, EnhancedMempoolEntry>,
    chain: Arc<RwLock<ChainManager>>,
    fee_calculator: FeeCalculator,
    // Fee estimator for dynamic fee calculation
    fee_estimator: Arc<FeeEstimator>,
    // Track spent outputs to detect double-spends
    spent_outputs: DashMap<OutPoint, bitcoin::Txid>,
    // Mempool acceptance policy
    policy: MempoolPolicy,
    // UTXO manager for validation
    utxo_manager: Arc<UtxoManager>,
    // Track fee rates for persistence
    fee_rates: DashMap<bitcoin::Txid, u64>,
    // Persistence handler
    persistence: Option<MempoolPersistence>,
    // Current block height for tracking
    current_height: Arc<RwLock<u32>>,
    // Track orphan transactions waiting for parents
    orphans: DashMap<bitcoin::Txid, Transaction>,
    // Map from missing parent to orphans waiting for it
    orphan_deps: DashMap<bitcoin::Txid, HashSet<bitcoin::Txid>>,
    // Package relay manager
    package_relay_manager: Arc<RwLock<crate::package_relay::PackageRelayManager>>,
}

impl Mempool {
    pub async fn new(
        chain: Arc<RwLock<ChainManager>>,
        utxo_manager: Arc<UtxoManager>,
    ) -> Result<Self> {
        Ok(Self {
            transactions: DashMap::new(),
            entries: DashMap::new(),
            chain,
            fee_calculator: FeeCalculator::default(),
            fee_estimator: Arc::new(FeeEstimator::new()),
            spent_outputs: DashMap::new(),
            policy: MempoolPolicy::default(),
            utxo_manager,
            fee_rates: DashMap::new(),
            persistence: None,
            current_height: Arc::new(RwLock::new(0)),
            orphans: DashMap::new(),
            orphan_deps: DashMap::new(),
            package_relay_manager: Arc::new(RwLock::new(
                crate::package_relay::PackageRelayManager::new(
                    crate::package_relay::PackageValidator::default(),
                ),
            )),
        })
    }

    /// Create mempool with persistence support
    pub async fn with_persistence(
        chain: Arc<RwLock<ChainManager>>,
        utxo_manager: Arc<UtxoManager>,
        data_dir: &Path,
    ) -> Result<Self> {
        let mut mempool = Self::new(chain, utxo_manager).await?;
        let persistence = MempoolPersistence::new(data_dir);

        // Try to load saved mempool
        if let Ok(snapshot) = persistence.load_snapshot().await {
            info!("Loading mempool from saved snapshot");
            if let Ok(restored) = persistence.restore_transactions(&snapshot) {
                let height = *mempool.current_height.read().await;
                for (txid, tx, fee_rate) in restored {
                    // Re-validate transaction before adding
                    // For now, just add it back
                    mempool.transactions.insert(txid, tx.clone());
                    mempool.fee_rates.insert(txid, fee_rate);

                    // Add to fee estimator
                    let fee = Amount::from_sat(fee_rate * tx.vsize() as u64);
                    mempool.fee_estimator.add_mempool_tx(&tx, height, fee);
                }
                info!(
                    "Restored {} transactions from mempool snapshot",
                    mempool.transactions.len()
                );
            }
        }

        mempool.persistence = Some(persistence);
        Ok(mempool)
    }

    /// Save mempool to disk
    pub async fn save_to_disk(&self) -> Result<()> {
        if let Some(ref persistence) = self.persistence {
            let mut transactions = HashMap::new();
            let mut fee_rates = HashMap::new();

            for entry in self.transactions.iter() {
                transactions.insert(*entry.key(), entry.value().clone());
                if let Some(rate) = self.fee_rates.get(entry.key()) {
                    fee_rates.insert(*entry.key(), *rate);
                }
            }

            persistence.save_snapshot(&transactions, &fee_rates).await?;
            debug!("Mempool saved to disk");
        }
        Ok(())
    }

    pub fn size(&self) -> usize {
        self.transactions.len()
    }

    /// Check if a transaction exists in the mempool
    pub fn has_transaction(&self, txid: &bitcoin::Txid) -> bool {
        self.transactions.contains_key(txid)
    }

    pub async fn flush(&mut self) -> Result<()> {
        // Save to disk before clearing
        self.save_to_disk().await?;
        self.transactions.clear();
        self.spent_outputs.clear();
        self.fee_rates.clear();
        Ok(())
    }

    // Methods for RPC access

    /// Get mempool info for RPC
    pub fn get_mempool_info(&self) -> (usize, u64, f64) {
        let size = self.transactions.len();
        let bytes = self.calculate_total_size();
        let min_fee = self.policy.min_relay_fee_rate as f64 / 100_000_000.0; // Convert sat/vB to BTC
        (size, bytes, min_fee)
    }

    /// Get all transaction IDs in mempool
    pub fn get_transaction_ids(&self) -> Vec<bitcoin::Txid> {
        self.transactions.iter().map(|entry| *entry.key()).collect()
    }

    /// Calculate total size of all transactions
    fn calculate_total_size(&self) -> u64 {
        // Simplified: estimate 250 bytes per transaction
        (self.transactions.len() as u64) * 250
    }

    /// Get a specific transaction from mempool
    pub fn get_transaction(&self, txid: &bitcoin::Txid) -> Option<Transaction> {
        self.transactions.get(txid).map(|entry| entry.clone())
    }

    /// Add a transaction to the mempool with full validation
    pub async fn add_transaction(&mut self, tx: Transaction) -> Result<()> {
        let txid = tx.compute_txid();

        // 1. Check if transaction already exists
        if self.transactions.contains_key(&txid) || self.entries.contains_key(&txid) {
            bail!("Transaction already in mempool");
        }

        // 2. Use chain manager for full validation
        let chain_guard = self.chain.read().await;
        chain_guard
            .validate_transaction_for_mempool(&tx)
            .await
            .context("Transaction failed chain validation")?;
        drop(chain_guard);

        // 3. Check for orphan transaction (missing dependencies)
        // Only check if parent transactions are in mempool if they're not confirmed
        let mut missing_deps = Vec::new();
        for input in &tx.input {
            let parent_txid = input.previous_output.txid;

            // Skip coinbase transaction (null outpoint)
            if input.previous_output.is_null() {
                continue;
            }

            // Check if parent is in mempool
            if !self.entries.contains_key(&parent_txid) {
                // Check if the UTXO exists in the UTXO manager (confirmed)
                let utxo_result = self.utxo_manager.get_utxo(&input.previous_output).await;

                if utxo_result.is_none() {
                    // Parent is neither confirmed nor in mempool - it's missing
                    debug!(
                        "UTXO not found for input {:?}, marking as orphan",
                        input.previous_output
                    );
                    missing_deps.push(parent_txid);
                } else {
                    debug!(
                        "UTXO found for input {:?}, not an orphan",
                        input.previous_output
                    );
                }
            } else {
                debug!("Parent transaction {} is in mempool", parent_txid);
            }
        }

        if !missing_deps.is_empty() {
            // Store as orphan to process later
            info!(
                "Transaction {} is orphan, waiting for {} parents",
                txid,
                missing_deps.len()
            );
            self.orphans.insert(txid, tx.clone());

            // Track which parents this orphan is waiting for
            for parent_txid in missing_deps {
                self.orphan_deps
                    .entry(parent_txid)
                    .or_default()
                    .insert(txid);
            }

            return Ok(());
        }

        // 4. Verify all inputs exist in UTXO set
        let total_input_value = self.utxo_manager.validate_transaction_inputs(&tx).await?;

        // 4. Calculate transaction properties
        let tx_size = bitcoin::consensus::encode::serialize(&tx).len();
        let tx_weight = tx.weight().to_wu() as usize;
        let tx_vsize = tx_weight.div_ceil(4);

        let total_output_value: Amount = tx.output.iter().map(|out| out.value).sum();

        let fee = total_input_value
            .checked_sub(total_output_value)
            .context("Transaction outputs exceed inputs")?;

        let fee_rate = fee.to_sat() / tx_vsize as u64;

        // 5. Create validation context
        let spent_outputs_map: HashMap<OutPoint, bitcoin::Txid> = self
            .spent_outputs
            .iter()
            .map(|e| (*e.key(), *e.value()))
            .collect();

        let entries_map: HashMap<bitcoin::Txid, EnhancedMempoolEntry> = self
            .entries
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect();

        let validation_ctx = ValidationContext {
            policy: &self.policy,
            mempool_txs: &entries_map,
            spent_outputs: &spent_outputs_map,
        };

        // 6. Apply mempool policy validation
        validate_mempool_acceptance(&tx, fee, &validation_ctx)?;

        // 7. Verify scripts
        let script_flags = ScriptFlags::P2SH | ScriptFlags::WITNESS | ScriptFlags::STRICTENC;
        for (index, input) in tx.input.iter().enumerate() {
            let utxo = self
                .utxo_manager
                .get_utxo(&input.previous_output)
                .await
                .context("UTXO not found for script verification")?;

            // Collect all prevouts for signature verification
            let mut prevouts = Vec::new();
            for inp in &tx.input {
                let utxo_out = self
                    .utxo_manager
                    .get_utxo(&inp.previous_output)
                    .await
                    .context("UTXO not found for prevouts")?;
                prevouts.push(utxo_out.output.clone());
            }

            let checker = bitcoin_core_lib::script::TransactionSignatureChecker::new(
                &tx,
                index,
                utxo.output.value.to_sat(),
                prevouts,
            );

            bitcoin_core_lib::script::verify_script(
                &input.script_sig,
                &utxo.output.script_pubkey,
                script_flags,
                &checker,
            )
            .context(format!("Script verification failed for input {}", index))?;
        }

        // 8. Calculate package information
        let package_info = crate::validation::calculate_package_info(&tx, &entries_map);

        // 9. Determine if spends coinbase
        let mut spends_coinbase = false;
        for input in &tx.input {
            // Check if input is coinbase (would need UTXO metadata)
            // For now, assume not coinbase
            spends_coinbase = false;
        }

        // 10. Calculate actual sigops
        let mut utxo_scripts = Vec::new();
        for input in &tx.input {
            let utxo = self
                .utxo_manager
                .get_utxo(&input.previous_output)
                .await
                .context("UTXO not found for sigops calculation")?;
            utxo_scripts.push(utxo.output.script_pubkey.clone());
        }

        let sigops =
            bitcoin_core_lib::script::count_transaction_sigops(&tx, &utxo_scripts, script_flags);

        // 11. Create enhanced entry
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let height = *self.current_height.read().await;

        let entry = EnhancedMempoolEntry {
            tx: tx.clone(),
            fee,
            fee_rate,
            weight: tx_weight,
            size: tx_size,
            time: current_time,
            height,
            spends_coinbase,
            sigops: sigops as u32,
            package_info,
        };

        // 11. Add to mempool
        self.transactions.insert(txid, tx.clone());
        self.entries.insert(txid, entry);
        self.fee_rates.insert(txid, fee_rate);

        // 12. Mark outputs as spent
        for input in &tx.input {
            self.spent_outputs.insert(input.previous_output, txid);
        }

        // 13. Mark UTXOs as spent in UTXO manager
        self.utxo_manager.mark_spent_in_mempool(&tx).await?;

        // 14. Update ancestor/descendant relationships
        self.update_ancestors_for_new_tx(txid).await?;

        // 15. Add to fee estimator
        self.fee_estimator.add_mempool_tx(&tx, height, fee);

        info!(
            "Added transaction {} to mempool (fee: {} sats, rate: {} sat/vB)",
            txid,
            fee.to_sat(),
            fee_rate
        );

        // 16. Check if any orphans can now be processed
        self.process_orphans_for_parent(txid).await?;

        Ok(())
    }

    /// Basic transaction validation
    fn validate_transaction_basic(&self, tx: &Transaction) -> Result<()> {
        // Check transaction isn't too large
        let tx_size = bitcoin::consensus::encode::serialize(tx).len();
        if tx_size > 100_000 {
            bail!("Transaction too large: {} bytes", tx_size);
        }

        // Must have at least one input and one output
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
        for output in &tx.output {
            if output.value > Amount::from_btc(21_000_000.0).unwrap() {
                bail!("Output value too large");
            }
        }

        Ok(())
    }

    /// Process orphans that were waiting for a parent transaction
    async fn process_orphans_for_parent(&mut self, parent_txid: bitcoin::Txid) -> Result<()> {
        // Collect orphans to process (avoid recursion)
        let mut orphans_to_process = Vec::new();

        if let Some((_, orphan_set)) = self.orphan_deps.remove(&parent_txid) {
            for orphan_txid in orphan_set {
                if let Some((_, orphan_tx)) = self.orphans.remove(&orphan_txid) {
                    orphans_to_process.push((orphan_txid, orphan_tx));
                }
            }
        }

        // Process orphans non-recursively
        for (orphan_txid, orphan_tx) in orphans_to_process {
            info!(
                "Processing orphan {} after parent {} arrived",
                orphan_txid, parent_txid
            );

            // Try to add the orphan to mempool using a separate method
            if let Err(e) = self.add_orphan_transaction(orphan_tx).await {
                warn!("Failed to add orphan {}: {}", orphan_txid, e);
            }
        }

        Ok(())
    }

    /// Add an orphan transaction (non-recursive version for orphan processing)
    async fn add_orphan_transaction(&mut self, tx: Transaction) -> Result<()> {
        // This is a copy of add_transaction logic but without the recursive call
        // Just do the basic validation and add to mempool
        let txid = tx.compute_txid();

        if self.transactions.contains_key(&txid) || self.entries.contains_key(&txid) {
            return Ok(()); // Already in mempool, skip
        }

        // Simplified validation for orphans - they were already partially validated
        let total_input_value = self.utxo_manager.validate_transaction_inputs(&tx).await?;

        let tx_size = bitcoin::consensus::encode::serialize(&tx).len();
        let tx_weight = tx.weight().to_wu() as usize;
        let tx_vsize = tx_weight.div_ceil(4);

        let total_output_value: Amount = tx.output.iter().map(|out| out.value).sum();

        let fee = total_input_value
            .checked_sub(total_output_value)
            .context("Transaction outputs exceed inputs")?;

        let fee_rate = fee.to_sat() / tx_vsize as u64;

        // Create enhanced entry
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let height = *self.current_height.read().await;

        let entry = EnhancedMempoolEntry {
            tx: tx.clone(),
            fee,
            fee_rate,
            weight: tx_weight,
            size: tx_size,
            time: current_time,
            height,
            spends_coinbase: false,
            sigops: 0,
            package_info: PackageInfo::new(),
        };

        // Add to mempool
        self.transactions.insert(txid, tx.clone());
        self.entries.insert(txid, entry);
        self.fee_rates.insert(txid, fee_rate);

        // Mark outputs as spent
        for input in &tx.input {
            self.spent_outputs.insert(input.previous_output, txid);
        }

        // Mark UTXOs as spent
        self.utxo_manager.mark_spent_in_mempool(&tx).await?;

        // Add to fee estimator
        self.fee_estimator.add_mempool_tx(&tx, height, fee);

        info!("Added orphan transaction {} to mempool", txid);
        Ok(())
    }

    /// Remove a transaction from the mempool
    pub async fn remove_transaction(
        &mut self,
        txid: &bitcoin::Txid,
    ) -> Result<Option<Transaction>> {
        if let Some((_, tx)) = self.transactions.remove(txid) {
            // Get the entry before removing for ancestor/descendant updates
            let entry_clone = self.entries.get(txid).map(|e| e.clone());

            // Remove from entries
            self.entries.remove(txid);

            // Update ancestor/descendant relationships
            if let Some(entry) = entry_clone {
                self.update_ancestors_for_removed_tx(*txid, &entry).await?;
            }

            // Remove spent outputs tracking
            for input in &tx.input {
                self.spent_outputs.remove(&input.previous_output);
            }

            // Unmark UTXOs as spent in mempool
            self.utxo_manager.unmark_spent_in_mempool(&tx).await;

            // Remove from fee estimator
            self.fee_estimator.remove_mempool_tx(txid);

            // Remove fee rate tracking
            self.fee_rates.remove(txid);

            // Remove any orphans that depended on this transaction
            self.orphan_deps.remove(txid);

            Ok(Some(tx))
        } else {
            Ok(None)
        }
    }

    /// Test if a transaction would be accepted (without adding it)
    pub async fn test_accept(&self, tx: &Transaction) -> Result<bool> {
        let txid = tx.compute_txid();

        // Check if already in mempool
        if self.transactions.contains_key(&txid) {
            return Ok(false);
        }

        // Validate transaction
        let chain_guard = self.chain.read().await;
        if let Err(_) = chain_guard.validate_transaction_for_mempool(&tx).await {
            return Ok(false);
        }
        drop(chain_guard);

        // Check all inputs exist
        for input in &tx.input {
            if input.previous_output.is_null() {
                continue;
            }

            // Check if input is available (not in mempool or UTXO set)
            if !self.entries.contains_key(&input.previous_output.txid) {
                if self
                    .utxo_manager
                    .get_utxo(&input.previous_output)
                    .await
                    .is_none()
                {
                    return Ok(false);
                }
            }
        }

        // Calculate fee and validate policy
        let total_input_value = match self.utxo_manager.validate_transaction_inputs(&tx).await {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };

        let total_output_value: Amount = tx.output.iter().map(|out| out.value).sum();
        let fee = match total_input_value.checked_sub(total_output_value) {
            Some(f) => f,
            None => return Ok(false),
        };

        // Create validation context
        let spent_outputs_map: HashMap<OutPoint, bitcoin::Txid> = self
            .spent_outputs
            .iter()
            .map(|e| (*e.key(), *e.value()))
            .collect();

        let entries_map: HashMap<bitcoin::Txid, EnhancedMempoolEntry> = self
            .entries
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect();

        let validation_ctx = ValidationContext {
            policy: &self.policy,
            mempool_txs: &entries_map,
            spent_outputs: &spent_outputs_map,
        };

        // Validate against policy
        if let Err(_) = validate_mempool_acceptance(&tx, fee, &validation_ctx) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get detailed entry information for a transaction
    pub fn get_entry(&self, txid: &bitcoin::Txid) -> Option<MempoolEntry> {
        if let Some(entry) = self.entries.get(txid) {
            Some(MempoolEntry {
                size: entry.size as u32,
                fee: entry.fee.to_sat(),
                time: entry.time,
                height: entry.height,
                descendantcount: entry.package_info.descendants.len() as u32,
                descendantsize: entry.package_info.descendant_size as u32,
                ancestorcount: entry.package_info.ancestors.len() as u32,
                ancestorsize: entry.package_info.ancestor_size as u32,
            })
        } else {
            None
        }
    }

    /// Get verbose entry information for RPC
    pub fn get_verbose_entry(&self, txid: &bitcoin::Txid) -> Option<serde_json::Value> {
        if let Some(entry) = self.entries.get(txid) {
            let depends: Vec<String> = entry
                .package_info
                .ancestors
                .iter()
                .map(|dep| dep.to_string())
                .collect();

            let spentby: Vec<String> = entry
                .package_info
                .descendants
                .iter()
                .map(|dep| dep.to_string())
                .collect();

            Some(json!({
                "vsize": entry.tx.vsize(),
                "weight": entry.weight,
                "time": entry.time,
                "height": entry.height,
                "descendantcount": entry.package_info.descendants.len(),
                "descendantsize": entry.package_info.descendant_size,
                "descendantfees": entry.package_info.descendant_fees,
                "ancestorcount": entry.package_info.ancestors.len(),
                "ancestorsize": entry.package_info.ancestor_size,
                "ancestorfees": entry.package_info.ancestor_fees,
                "wtxid": entry.tx.compute_wtxid().to_string(),
                "fees": {
                    "base": entry.fee.to_sat(),
                    "modified": entry.fee.to_sat(), // Could track modified fees separately
                    "ancestor": entry.fee.to_sat() + entry.package_info.ancestor_fees,
                    "descendant": entry.fee.to_sat() + entry.package_info.descendant_fees
                },
                "depends": depends,
                "spentby": spentby,
                "bip125-replaceable": true, // Simplified - all transactions are RBF-enabled
                "unbroadcast": false // Simplified - assume all are broadcast
            }))
        } else {
            None
        }
    }

    /// Get enhanced mining candidates for advanced block template creation
    pub async fn get_mining_candidates(&self) -> Vec<miner::tx_selection::MiningCandidate> {
        use miner::tx_selection::MiningCandidate;

        let mut candidates = Vec::new();

        for entry in self.entries.iter() {
            let txid = *entry.key();
            let enhanced_entry = entry.value();

            // Build ancestors set
            let ancestors = enhanced_entry.package_info.ancestors.clone();

            let candidate = MiningCandidate {
                tx: enhanced_entry.tx.clone(),
                fee: enhanced_entry.fee,
                fee_rate: enhanced_entry.fee_rate,
                weight: enhanced_entry.weight,
                size: enhanced_entry.size,
                ancestors,
                package_fee: enhanced_entry.fee
                    + Amount::from_sat(enhanced_entry.package_info.ancestor_fees),
                package_weight: enhanced_entry.weight + enhanced_entry.package_info.ancestor_size,
            };

            candidates.push(candidate);
        }

        candidates
    }

    /// Get transactions for mining with proper fee-based selection
    pub async fn get_mining_transactions(&self, max_weight: u64) -> Result<Vec<MiningTransaction>> {
        let mut mining_txs = Vec::new();
        let mut total_weight = 0u64;
        let mut included_txids = HashSet::new();

        // Collect all transactions with their fee rates
        let mut tx_candidates: Vec<_> = self
            .transactions
            .iter()
            .map(|entry| {
                let tx = entry.value();
                let txid = *entry.key();
                let size = bitcoin::consensus::encode::serialize(tx).len() as u64;
                let weight = tx.weight().to_wu();

                // Calculate actual fee from inputs minus outputs
                // For now use estimation
                let fee = self.fee_calculator.estimate_fee(tx);
                let fee_rate = if weight > 0 {
                    (fee.to_sat() as f64 * 4.0) / (weight as f64)
                } else {
                    0.0
                };

                (txid, tx.clone(), fee, weight, fee_rate)
            })
            .collect();

        // Sort by fee rate (highest first)
        tx_candidates.sort_by(|a, b| b.4.partial_cmp(&a.4).unwrap_or(std::cmp::Ordering::Equal));

        // Select transactions using greedy algorithm
        for (txid, tx, fee, weight, fee_rate) in tx_candidates {
            // Skip if we'd exceed block weight limit
            if total_weight + weight > max_weight {
                continue;
            }

            // Check if all inputs are available (parent transactions included)
            let mut can_include = true;
            for input in &tx.input {
                // Check if input is from another mempool transaction
                if let Some(parent_txid) = self
                    .transactions
                    .iter()
                    .find(|e| e.value().compute_txid() == input.previous_output.txid)
                    .map(|e| *e.key())
                {
                    // Parent must be included first
                    if !included_txids.contains(&parent_txid) {
                        can_include = false;
                        break;
                    }
                }
            }

            if !can_include {
                continue;
            }

            // Add transaction to block
            mining_txs.push(MiningTransaction {
                tx,
                fee,
                weight,
                fee_rate,
            });

            included_txids.insert(txid);
            total_weight += weight;

            // Stop if we've filled the block
            if total_weight >= max_weight * 95 / 100 {
                break;
            }
        }

        debug!(
            "Selected {} transactions for mining, total weight: {}",
            mining_txs.len(),
            total_weight
        );

        Ok(mining_txs)
    }

    /// Clear mempool after a block is mined
    pub async fn remove_mined_transactions(&mut self, block: &bitcoin::Block) -> Result<()> {
        let mut removed_count = 0;

        for tx in &block.txdata {
            let txid = tx.compute_txid();
            if self.remove_transaction(&txid).await?.is_some() {
                removed_count += 1;
            }
        }

        info!(
            "Removed {} transactions from mempool after block",
            removed_count
        );
        Ok(())
    }

    /// Update the current block height
    pub async fn update_height(&self, height: u32) {
        *self.current_height.write().await = height;
    }

    /// Process a new block for fee estimation
    pub fn process_block_for_fee_estimation(&self, block: &bitcoin::Block, height: u32) {
        self.fee_estimator.process_block(block, height);
    }

    /// Estimate fee for confirmation within target blocks
    pub fn estimate_smart_fee(
        &self,
        confirmation_target: u32,
    ) -> bitcoin_core_lib::fee_estimation::SmartFeeEstimate {
        self.fee_estimator.estimate_smart_fee(confirmation_target)
    }

    /// Get mempool statistics
    pub fn get_mempool_stats(&self) -> bitcoin_core_lib::fee_estimation::MempoolStats {
        self.fee_estimator.get_mempool_stats()
    }

    /// Get fee histogram
    pub fn get_fee_histogram(&self) -> Vec<(EstimatorFeeRate, usize)> {
        self.fee_estimator.get_fee_histogram()
    }

    /// Get fee estimator reference
    pub fn fee_estimator(&self) -> &FeeEstimator {
        &self.fee_estimator
    }

    /// Remove expired transactions (transactions that have been in mempool too long)
    pub async fn remove_expired_transactions(&mut self, max_age_seconds: u64) -> Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut removed_count = 0;
        let mut txids_to_remove = Vec::new();

        // Find expired transactions using entries which have metadata
        for entry_ref in self.entries.iter() {
            let (txid, entry) = entry_ref.pair();
            if now - entry.time > max_age_seconds {
                txids_to_remove.push(*txid);
            }
        }

        // Remove expired transactions
        for txid in txids_to_remove {
            if self.remove_transaction(&txid).await.is_ok() {
                removed_count += 1;
                debug!("Removed expired transaction: {}", txid);
            }
        }

        if removed_count > 0 {
            info!(
                "Removed {} expired transactions from mempool",
                removed_count
            );
        }

        Ok(removed_count)
    }

    /// Evict transactions by fee rate to maintain size limit
    pub async fn evict_by_feerate(&mut self, target_size: usize) -> Result<usize> {
        if self.transactions.len() <= target_size {
            return Ok(0);
        }

        // Collect transactions with their fee rates from entries
        let mut tx_by_feerate: Vec<(bitcoin::Txid, f64)> = self
            .entries
            .iter()
            .map(|entry_ref| {
                let (txid, entry) = entry_ref.pair();
                // Use the pre-calculated fee_rate field
                let fee_rate = entry.fee_rate as f64;
                (*txid, fee_rate)
            })
            .collect();

        // Sort by fee rate (ascending, so lowest fee rates first)
        tx_by_feerate.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        // Calculate how many to remove
        let to_remove = self.transactions.len() - target_size;
        let mut removed_count = 0;

        // Remove lowest fee rate transactions
        for (txid, fee_rate) in tx_by_feerate.iter().take(to_remove) {
            if self.remove_transaction(txid).await.is_ok() {
                removed_count += 1;
                debug!(
                    "Evicted transaction {} with fee rate {:.2} sat/vB",
                    txid, fee_rate
                );
            }
        }

        if removed_count > 0 {
            info!(
                "Evicted {} low-fee transactions from mempool",
                removed_count
            );
        }

        Ok(removed_count)
    }

    /// Update ancestor relationships when a new transaction is added
    async fn update_ancestors_for_new_tx(&self, txid: bitcoin::Txid) -> Result<()> {
        // Get the entry we just added
        let entry = self
            .entries
            .get(&txid)
            .ok_or_else(|| anyhow::anyhow!("Transaction not found in mempool"))?;

        let tx = &entry.tx;
        let package_info = &entry.package_info;

        // For each ancestor, add this tx as a descendant
        for ancestor_txid in &package_info.ancestors {
            if let Some(mut ancestor_entry) = self.entries.get_mut(ancestor_txid) {
                // Add this tx to ancestor's descendants
                ancestor_entry.package_info.descendants.insert(txid);
                ancestor_entry.package_info.descendant_size += entry.size;
                ancestor_entry.package_info.descendant_fees += entry.fee.to_sat();

                // Also add all of this tx's descendants to the ancestor
                for desc_txid in &package_info.descendants {
                    if !ancestor_entry.package_info.descendants.contains(desc_txid) {
                        if let Some(desc_entry) = self.entries.get(desc_txid) {
                            ancestor_entry.package_info.descendants.insert(*desc_txid);
                            ancestor_entry.package_info.descendant_size += desc_entry.size;
                            ancestor_entry.package_info.descendant_fees += desc_entry.fee.to_sat();
                        }
                    }
                }
            }
        }

        // For each descendant, add this tx as an ancestor
        for descendant_txid in &package_info.descendants {
            if let Some(mut descendant_entry) = self.entries.get_mut(descendant_txid) {
                // Add this tx to descendant's ancestors
                descendant_entry.package_info.ancestors.insert(txid);
                descendant_entry.package_info.ancestor_size += entry.size;
                descendant_entry.package_info.ancestor_fees += entry.fee.to_sat();

                // Also add all of this tx's ancestors to the descendant
                for anc_txid in &package_info.ancestors {
                    if !descendant_entry.package_info.ancestors.contains(anc_txid) {
                        if let Some(anc_entry) = self.entries.get(anc_txid) {
                            descendant_entry.package_info.ancestors.insert(*anc_txid);
                            descendant_entry.package_info.ancestor_size += anc_entry.size;
                            descendant_entry.package_info.ancestor_fees += anc_entry.fee.to_sat();
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Update relationships when removing a transaction
    async fn update_ancestors_for_removed_tx(
        &self,
        txid: bitcoin::Txid,
        entry: &EnhancedMempoolEntry,
    ) -> Result<()> {
        // Remove this tx from all ancestors' descendant lists
        for ancestor_txid in &entry.package_info.ancestors {
            if let Some(mut ancestor_entry) = self.entries.get_mut(ancestor_txid) {
                ancestor_entry.package_info.descendants.remove(&txid);
                ancestor_entry.package_info.descendant_size = ancestor_entry
                    .package_info
                    .descendant_size
                    .saturating_sub(entry.size);
                ancestor_entry.package_info.descendant_fees = ancestor_entry
                    .package_info
                    .descendant_fees
                    .saturating_sub(entry.fee.to_sat());
            }
        }

        // Remove this tx from all descendants' ancestor lists
        for descendant_txid in &entry.package_info.descendants {
            if let Some(mut descendant_entry) = self.entries.get_mut(descendant_txid) {
                descendant_entry.package_info.ancestors.remove(&txid);
                descendant_entry.package_info.ancestor_size = descendant_entry
                    .package_info
                    .ancestor_size
                    .saturating_sub(entry.size);
                descendant_entry.package_info.ancestor_fees = descendant_entry
                    .package_info
                    .ancestor_fees
                    .saturating_sub(entry.fee.to_sat());
            }
        }

        Ok(())
    }

    /// Accept a package of transactions atomically
    pub async fn accept_package(
        &mut self,
        package: crate::package_relay::Package,
    ) -> Result<crate::package_relay::PackageAcceptanceResult> {
        use crate::package_relay::{PackageAcceptanceResult, PackageValidator};

        info!(
            "Processing package with {} transactions, total fee: {}, total size: {} bytes",
            package.transactions.len(),
            package.total_fee,
            package.total_size
        );

        // Validate package structure
        let validator = PackageValidator::default();
        validator.validate_package(&package)?;

        // Check for conflicts with existing mempool transactions
        let mut conflicts = Vec::new();
        for tx in &package.transactions {
            for input in &tx.input {
                if let Some(conflict_txid) = self.spent_outputs.get(&input.previous_output) {
                    let conflict_txid = *conflict_txid.value();
                    if let Some(entry) = self.entries.get(&conflict_txid) {
                        conflicts.push(entry.tx.clone());
                    }
                }
            }
        }

        // If there are conflicts, check package RBF
        if !conflicts.is_empty() {
            info!(
                "Package conflicts with {} existing transactions",
                conflicts.len()
            );

            // For now, reject packages with conflicts
            // Full implementation would check package RBF rules
            let reasons: Vec<(bitcoin::Txid, String)> = package
                .transactions
                .iter()
                .map(|tx| {
                    (
                        tx.compute_txid(),
                        "Package conflicts with mempool".to_string(),
                    )
                })
                .collect();

            return Ok(PackageAcceptanceResult::AllRejected { reasons });
        }

        // Try to accept each transaction in topological order
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();

        for tx in &package.transactions {
            let txid = tx.compute_txid();

            // Check if already in mempool
            if self.transactions.contains_key(&txid) {
                debug!("Transaction {} already in mempool", txid);
                accepted.push(txid);
                continue;
            }

            // Try to add to mempool
            match self.add_transaction(tx.clone()).await {
                Ok(()) => {
                    info!("Accepted package transaction {}", txid);
                    accepted.push(txid);

                    // Check for orphans that can now be resolved
                    let mut orphans_to_process = Vec::new();
                    if let Some((_, orphan_set)) = self.orphan_deps.remove(&txid) {
                        for orphan_txid in orphan_set {
                            if let Some((_, orphan_tx)) = self.orphans.remove(&orphan_txid) {
                                orphans_to_process.push(orphan_tx.clone());
                            }
                        }
                    }

                    // Process resolved orphans
                    for orphan_tx in orphans_to_process {
                        let _ = self.add_transaction(orphan_tx).await;
                    }
                }
                Err(e) => {
                    warn!("Rejected package transaction {}: {}", txid, e);
                    rejected.push((txid, e.to_string()));
                }
            }
        }

        // Return appropriate result
        if rejected.is_empty() {
            Ok(PackageAcceptanceResult::AllAccepted {
                txids: accepted,
                total_fee: package.total_fee,
                total_size: package.total_size,
            })
        } else if accepted.is_empty() {
            Ok(PackageAcceptanceResult::AllRejected { reasons: rejected })
        } else {
            Ok(PackageAcceptanceResult::PartiallyAccepted { accepted, rejected })
        }
    }

    /// Create a package from a child transaction and its unconfirmed parents
    pub async fn create_child_with_parents_package(
        &self,
        child_txid: bitcoin::Txid,
    ) -> Result<Option<crate::package_relay::Package>> {
        // Get the child transaction
        let child_tx = if let Some(tx) = self.transactions.get(&child_txid) {
            tx.value().clone()
        } else {
            return Ok(None);
        };

        // Find unconfirmed parent transactions
        let mut parents = Vec::new();
        for input in &child_tx.input {
            let parent_txid = input.previous_output.txid;

            // Check if parent is in mempool
            if let Some(parent_tx) = self.transactions.get(&parent_txid) {
                parents.push(parent_tx.value().clone());
            }
        }

        if parents.is_empty() {
            // No unconfirmed parents, not a package
            return Ok(None);
        }

        // Create package
        let package_manager = self.package_relay_manager.read().await;
        let package = package_manager.create_child_with_parents_package(child_tx, parents)?;

        Ok(Some(package))
    }
}

/// Mempool entry information for RPC
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub size: u32,
    pub fee: u64,
    pub time: u64,
    pub height: u32,
    pub descendantcount: u32,
    pub descendantsize: u32,
    pub ancestorcount: u32,
    pub ancestorsize: u32,
}

/// Transaction for mining selection
#[derive(Debug, Clone)]
pub struct MiningTransaction {
    pub tx: Transaction,
    pub fee: Amount,
    pub weight: u64,
    pub fee_rate: f64, // satoshis per vbyte
}
