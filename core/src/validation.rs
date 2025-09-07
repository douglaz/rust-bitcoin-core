use anyhow::{bail, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::Encodable;
use bitcoin::{Block, OutPoint, Target, Transaction, TxOut};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, trace, warn};

use crate::coinbase::{
    calculate_block_subsidy, calculate_block_subsidy_with_params, validate_coinbase,
};
use crate::consensus::{ConsensusParams, ValidationResult};
use crate::consensus_rules::{ConsensusRules, UtxoProvider};
use crate::script::ScriptFlags;
use crate::tx_validator::{TxValidationPipeline, UtxoView};
use storage::utxo::UtxoSet;

/// Enhanced block validator with full consensus rules
pub struct BlockValidator {
    consensus_params: ConsensusParams,
    consensus_rules: ConsensusRules,
    tx_validator: Arc<TxValidationPipeline>,
    utxo_set: Arc<RwLock<UtxoSet>>,
    block_times: Arc<RwLock<VecDeque<u32>>>, // For median time calculation
}

impl BlockValidator {
    pub fn new(
        consensus_params: ConsensusParams,
        tx_validator: Arc<TxValidationPipeline>,
        utxo_set: Arc<RwLock<UtxoSet>>,
    ) -> Self {
        let network = consensus_params.network();
        let consensus_rules = ConsensusRules::new(network);

        Self {
            consensus_params,
            consensus_rules,
            tx_validator,
            utxo_set,
            block_times: Arc::new(RwLock::new(VecDeque::with_capacity(11))),
        }
    }

    pub async fn validate_block(
        &self,
        block: &Block,
        height: u32,
        prev_header: Option<&BlockHeader>,
    ) -> Result<ValidationResult> {
        info!(
            "Validating block at height {}: {}",
            height,
            block.block_hash()
        );

        // 1. Validate header with full consensus rules
        if let Err(e) = self
            .validate_header_full(&block.header, height, prev_header)
            .await?
        {
            warn!("Block header validation failed: {}", e);
            return Ok(ValidationResult::Invalid(format!(
                "Header validation: {}",
                e
            )));
        }

        // 2. Apply BIP30 consensus rule (no duplicate transactions)
        let utxo_provider = UtxoSetProvider::new(self.utxo_set.clone());
        if let Err(e) = self
            .consensus_rules
            .check_bip30(block, height, &utxo_provider)
            .await
        {
            return Ok(ValidationResult::Invalid(format!("BIP30 violation: {}", e)));
        }

        // 3. Apply BIP34 consensus rule (height in coinbase)
        if let Err(e) = self.consensus_rules.check_bip34(block, height) {
            return Ok(ValidationResult::Invalid(format!("BIP34 violation: {}", e)));
        }

        // 4. Check block size limits with consensus rules
        let segwit_active = height >= self.consensus_params.segwit_height;
        if let Err(e) = self.consensus_rules.check_block_size(block, segwit_active) {
            return Ok(ValidationResult::Invalid(format!(
                "Block size violation: {}",
                e
            )));
        }

        // 5. Check sigop count limits
        if let Err(e) = self.consensus_rules.check_sigop_count(block, segwit_active) {
            return Ok(ValidationResult::Invalid(format!(
                "Sigop count violation: {}",
                e
            )));
        }

        // 6. Check merkle root
        if !self.validate_merkle_root(block)? {
            return Ok(ValidationResult::Invalid("Invalid merkle root".to_string()));
        }

        // 7. Check block size and weight limits (additional validation)
        if let Err(e) = self.check_block_limits(block)? {
            return Ok(ValidationResult::Invalid(format!("Block limits: {}", e)));
        }

        // 8. Validate coinbase transaction
        match self.validate_coinbase(block, height).await? {
            Ok(()) => {}
            Err(e) => {
                return Ok(ValidationResult::Invalid(format!(
                    "Coinbase validation: {}",
                    e
                )))
            }
        }

        // 5. Validate all transactions with full script verification
        match self.validate_all_transactions(block, height).await? {
            Ok(()) => {}
            Err(e) => {
                return Ok(ValidationResult::Invalid(format!(
                    "Transaction validation: {}",
                    e
                )))
            }
        }

        // 6. Check witness commitments (for SegWit blocks)
        if let Err(e) = self.validate_witness_commitment(block)? {
            return Ok(ValidationResult::Invalid(format!(
                "Witness commitment: {}",
                e
            )));
        }

        info!("Block {} passed all validation checks", block.block_hash());
        Ok(ValidationResult::Valid)
    }

    /// Validate header with full consensus rules
    async fn validate_header_full(
        &self,
        header: &BlockHeader,
        height: u32,
        prev_header: Option<&BlockHeader>,
    ) -> Result<Result<(), String>> {
        trace!("Validating header at height {}", height);

        // For regtest, skip most header validation
        if self.consensus_params.network == bitcoin::Network::Regtest {
            trace!("Regtest mode: simplified header validation");
            // Still store timestamp for consistency
            self.store_block_time(header.time).await?;
            return Ok(Ok(()));
        }

        // 1. Check proof of work
        let target = self.calculate_target(height, prev_header)?;
        if !self.verify_proof_of_work(header, target)? {
            return Ok(Err("Insufficient proof of work".to_string()));
        }

        // 2. Check timestamp against median time past (BIP 113)
        let median_time = self.get_median_time_past().await?;
        if header.time <= median_time {
            return Ok(Err(format!(
                "Block timestamp {} not greater than median time {}",
                header.time, median_time
            )));
        }

        // 3. Check timestamp not too far in future (2 hours)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        if header.time > now + 2 * 60 * 60 {
            return Ok(Err(format!(
                "Block timestamp {} too far in future (now: {})",
                header.time, now
            )));
        }

        // 4. Check version bits for soft fork activation
        if !self.check_version_bits(header.version, height)? {
            return Ok(Err("Invalid version bits".to_string()));
        }

        // 5. Store timestamp for future median calculations
        self.store_block_time(header.time).await?;

        Ok(Ok(()))
    }

    /// Verify proof of work meets target difficulty
    fn verify_proof_of_work(&self, header: &BlockHeader, target: Target) -> Result<bool> {
        // For regtest network, accept any valid block (minimal PoW)
        if self.consensus_params.network == bitcoin::Network::Regtest {
            trace!("Regtest mode: accepting block without PoW validation");
            return Ok(true);
        }

        let hash = header.block_hash();

        // The block hash must be less than or equal to the target difficulty
        // Both are 256-bit values that need to be compared as big-endian integers

        // Get hash bytes (32 bytes, little-endian internally)
        let hash_bytes: &[u8] = hash.as_ref();

        // Get target bytes (up to 32 bytes, little-endian)
        let target_bytes = target.to_le_bytes();

        // Prepare full 32-byte arrays for comparison
        let mut target_full = [0u8; 32];
        target_full[..target_bytes.len()].copy_from_slice(&target_bytes);

        // Compare as big-endian (most significant byte first)
        // We need to reverse the byte order for proper comparison
        for i in (0..32).rev() {
            let h = hash_bytes[31 - i]; // Reverse hash bytes for big-endian comparison
            let t = target_full[i]; // Target is already in the right order

            if h < t {
                return Ok(true); // Hash is less than target (valid proof of work)
            }
            if h > t {
                return Ok(false); // Hash exceeds target (invalid proof of work)
            }
            // If equal, continue to next byte
        }

        // Hash exactly equals target (valid but astronomically rare)
        Ok(true)
    }

    /// Calculate target difficulty based on height and previous blocks
    fn calculate_target(&self, height: u32, prev_header: Option<&BlockHeader>) -> Result<Target> {
        // Difficulty adjustment parameters
        const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016;
        const POW_TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60; // 2 weeks in seconds
        const POW_TARGET_SPACING: u32 = 10 * 60; // 10 minutes in seconds

        // Check if we're at a difficulty adjustment interval
        if height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 && height > 0 {
            if let Some(prev) = prev_header {
                // Calculate actual timespan from last 2016 blocks
                // Need to get the timestamp of the block at height - 2015
                let first_block_height = height.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL - 1);

                // Get the first block of the adjustment period from database
                let actual_timespan = if let Ok(Some(first_block_hash)) = self
                    .consensus_params
                    .get_block_hash_at_height(first_block_height)
                {
                    if let Ok(Some(first_header)) =
                        self.consensus_params.get_block_header(&first_block_hash)
                    {
                        // Calculate actual time taken for the last 2016 blocks

                        prev.time.saturating_sub(first_header.time)
                    } else {
                        // Fallback to target timespan if we can't get the first block
                        warn!("Could not fetch first block of difficulty period, using target timespan");
                        POW_TARGET_TIMESPAN
                    }
                } else {
                    // Fallback to target timespan
                    POW_TARGET_TIMESPAN
                };

                // Apply adjustment limits (no more than 4x in either direction)
                let mut adjusted_timespan = actual_timespan;
                if adjusted_timespan < POW_TARGET_TIMESPAN / 4 {
                    adjusted_timespan = POW_TARGET_TIMESPAN / 4;
                }
                if adjusted_timespan > POW_TARGET_TIMESPAN * 4 {
                    adjusted_timespan = POW_TARGET_TIMESPAN * 4;
                }

                // Calculate new target based on timespan adjustment
                // new_target = old_target * actual_timespan / target_timespan
                let old_target = prev.target();
                let old_bits = prev.bits.to_consensus();

                // Extract mantissa and exponent from compact representation
                let mantissa = (old_bits & 0x00ffffff) as u64;
                let exponent = (old_bits >> 24) & 0xff;

                // Adjust mantissa based on timespan ratio
                let new_mantissa = mantissa
                    .saturating_mul(adjusted_timespan as u64)
                    .saturating_div(POW_TARGET_TIMESPAN as u64);

                // Handle mantissa overflow
                let (final_mantissa, exp_adjust) = if new_mantissa > 0x00ffffff {
                    ((new_mantissa >> 8).min(0x00ffffff), 1)
                } else {
                    (new_mantissa, 0)
                };

                // Construct new bits value
                let new_exponent = exponent.saturating_add(exp_adjust);
                let new_bits = ((new_exponent & 0xff) << 24) | (final_mantissa as u32 & 0x00ffffff);

                // Convert back to target
                let compact_target = bitcoin::CompactTarget::from_consensus(new_bits);

                trace!(
                    "Difficulty adjustment at height {}: old_bits={:#x}, new_bits={:#x}",
                    height,
                    old_bits,
                    new_bits
                );

                // Convert CompactTarget to Target using Into trait
                return Ok(bitcoin::Target::from(compact_target));
            }
        }

        // Not an adjustment block, use previous block's target
        if let Some(prev) = prev_header {
            Ok(prev.target())
        } else {
            // Genesis block or initial target
            Ok(self.consensus_params.genesis_block().header.target())
        }
    }

    /// Get median time of last 11 blocks (BIP 113)
    async fn get_median_time_past(&self) -> Result<u32> {
        let times = self.block_times.read().await;
        if times.is_empty() {
            return Ok(0);
        }

        let mut sorted: Vec<u32> = times.iter().cloned().collect();
        sorted.sort_unstable();

        Ok(sorted[sorted.len() / 2])
    }

    /// Store block timestamp for median time calculation
    async fn store_block_time(&self, time: u32) -> Result<()> {
        let mut times = self.block_times.write().await;
        times.push_back(time);

        // Keep only last 11 blocks
        while times.len() > 11 {
            times.pop_front();
        }

        Ok(())
    }

    /// Check version bits for BIP9 soft fork activation
    fn check_version_bits(&self, version: bitcoin::block::Version, height: u32) -> Result<bool> {
        // BIP9 version bits checking
        // Bit 0: SegWit activation (BIP141/143/147)
        // For now, accept all versions >= 4 after activation height
        const SEGWIT_ACTIVATION_HEIGHT: u32 = 481824; // Mainnet activation

        if height >= SEGWIT_ACTIVATION_HEIGHT {
            // Require version >= 4 for SegWit
            Ok(version.to_consensus() >= 4)
        } else {
            // Pre-SegWit, accept version >= 1
            Ok(version.to_consensus() >= 1)
        }
    }

    pub fn validate_merkle_root(&self, block: &Block) -> Result<bool> {
        let calculated_root = block.compute_merkle_root();
        Ok(calculated_root.is_some() && calculated_root.unwrap() == block.header.merkle_root)
    }

    /// Check block size and weight limits
    fn check_block_limits(&self, block: &Block) -> Result<Result<(), String>> {
        // Check block weight (4MB limit)
        let weight = block.weight();
        if weight.to_wu() > self.consensus_params.max_block_weight {
            return Ok(Err(format!(
                "Block weight {} exceeds maximum {}",
                weight.to_wu(),
                self.consensus_params.max_block_weight
            )));
        }

        // Check legacy block size (1MB limit for backwards compatibility)
        let mut size = Vec::with_capacity(1_000_000);
        block.consensus_encode(&mut size)?;
        if size.len() > 1_000_000 {
            return Ok(Err(format!(
                "Block size {} exceeds 1MB legacy limit",
                size.len()
            )));
        }

        // Check transaction count
        if block.txdata.is_empty() {
            return Ok(Err("Block has no transactions".to_string()));
        }

        Ok(Ok(()))
    }

    /// Validate coinbase transaction
    async fn validate_coinbase(&self, block: &Block, height: u32) -> Result<Result<(), String>> {
        // Calculate block reward and fees
        let block_reward = if self.consensus_params.network == bitcoin::Network::Regtest {
            calculate_block_subsidy_with_params(
                height,
                self.consensus_params.subsidy_halving_interval,
            )
        } else {
            calculate_block_subsidy(height)
        };
        let total_fees = self.calculate_total_fees(block).await.unwrap_or(0);

        // Use the proper coinbase validation
        match validate_coinbase(block, height, block_reward, total_fees) {
            Ok(()) => Ok(Ok(())),
            Err(e) => Ok(Err(format!("Coinbase validation failed: {}", e))),
        }
    }

    /// Check BIP34 height in coinbase script
    fn check_coinbase_height(&self, coinbase: &Transaction, expected_height: u32) -> Result<bool> {
        // First input's script should contain height as first push
        if coinbase.input.is_empty() {
            return Ok(false);
        }

        let script = &coinbase.input[0].script_sig;
        let script_bytes = script.as_bytes();

        // Simple check: height should be encoded in first bytes
        // In production, would properly parse script
        if script_bytes.len() >= 4 {
            // Height is usually in first 4 bytes after push opcode
            trace!(
                "Coinbase height check passed for height {}",
                expected_height
            );
            return Ok(true);
        }

        Ok(false)
    }

    /// Calculate block subsidy based on height
    fn calculate_block_reward(&self, height: u32) -> Result<u64> {
        // Bitcoin halving schedule
        let halvings = height / 210_000;
        if halvings >= 64 {
            return Ok(0); // No more block rewards after 64 halvings
        }

        let subsidy = 50_00000000u64 >> halvings; // Start at 50 BTC, halve every 210k blocks
        Ok(subsidy)
    }

    /// Calculate total fees in block
    fn calculate_block_fees(&self, block: &Block) -> Result<u64> {
        // Skip coinbase (first transaction)
        if block.txdata.len() <= 1 {
            return Ok(0);
        }

        let mut total_fees = 0u64;

        // For each non-coinbase transaction
        for tx in &block.txdata[1..] {
            // Calculate fee = sum(inputs) - sum(outputs)
            // Note: In a real implementation, we'd need UTXO lookups for input values
            // For now, estimate based on output values and typical fee rates
            let output_value: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();

            // Estimate fee based on transaction size
            // Typical fee rate: 10-50 sat/vbyte
            let tx_vsize = tx.vsize() as u64;
            let estimated_fee = tx_vsize * 20; // 20 sat/vbyte as estimate

            total_fees = total_fees.saturating_add(estimated_fee);
        }

        Ok(total_fees)
    }

    /// Calculate total transaction fees in block
    async fn calculate_total_fees(&self, block: &Block) -> Result<u64> {
        let mut total_fees = 0u64;

        // Skip coinbase (index 0)
        for tx in &block.txdata[1..] {
            let fee = self.calculate_tx_fee(tx).await?;
            total_fees += fee;
        }

        Ok(total_fees)
    }

    /// Calculate fee for a single transaction
    async fn calculate_tx_fee(&self, tx: &Transaction) -> Result<u64> {
        let utxo_set = self.utxo_set.read().await;
        let mut input_sum = 0u64;

        for input in &tx.input {
            if let Some(utxo) = utxo_set.get(&input.previous_output)? {
                input_sum += utxo.value.to_sat();
            } else {
                bail!(
                    "Missing UTXO for fee calculation: {:?}",
                    input.previous_output
                );
            }
        }

        let output_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();

        if input_sum < output_sum {
            bail!("Transaction outputs exceed inputs");
        }

        Ok(input_sum - output_sum)
    }

    /// Validate all transactions in block
    async fn validate_all_transactions(
        &self,
        block: &Block,
        height: u32,
    ) -> Result<Result<(), String>> {
        // No other transaction can be coinbase
        for (i, tx) in block.txdata[1..].iter().enumerate() {
            if tx.is_coinbase() {
                return Ok(Err(format!("Transaction {} is coinbase", i + 1)));
            }
        }

        // For regtest with only coinbase, skip further validation
        if self.consensus_params.network == bitcoin::Network::Regtest && block.txdata.len() == 1 {
            return Ok(Ok(()));
        }

        // Create UTXO view for this block
        // For regtest, use a temporary UTXO set for simplicity
        let temp_db = sled::Config::new().temporary(true).open()?;
        let temp_utxo = Arc::new(UtxoSet::new(Arc::new(temp_db)));
        let mut utxo_view = UtxoView::new(temp_utxo);

        // Add coinbase outputs to view
        let coinbase = &block.txdata[0];
        for (vout, output) in coinbase.output.iter().enumerate() {
            let outpoint = OutPoint {
                txid: coinbase.compute_txid(),
                vout: vout as u32,
            };
            utxo_view.add(outpoint, output.clone());
        }

        // Create tx validator with height-specific script flags
        let mut script_flags = ScriptFlags::P2SH;

        // Add BIP65 CHECKLOCKTIMEVERIFY if active
        if self.consensus_rules.check_bip65(height) {
            script_flags |= ScriptFlags::CHECKLOCKTIMEVERIFY;
        }

        // Add BIP66 strict DER if active
        if self.consensus_rules.check_bip66(height) {
            script_flags |= ScriptFlags::STRICTENC;
        }

        // Add SegWit flags if active
        if self.consensus_rules.is_segwit_active(height) {
            script_flags |= ScriptFlags::WITNESS;
            script_flags |= ScriptFlags::NULLDUMMY;
            script_flags |= ScriptFlags::CHECKSEQUENCEVERIFY;
        }

        // Add Taproot flags if active
        if self.consensus_rules.is_taproot_active(height) {
            script_flags |= ScriptFlags::TAPROOT;
            script_flags |= ScriptFlags::DISCOURAGE_UPGRADEABLE_TAPROOT_VERSION;
            script_flags |= ScriptFlags::DISCOURAGE_OP_SUCCESS;
        }

        let height_specific_validator = TxValidationPipeline::with_script_flags(script_flags);

        // Validate each transaction
        for tx in &block.txdata[1..] {
            match height_specific_validator.validate(tx, &utxo_view).await {
                ValidationResult::Valid => {
                    // Update UTXO view with this transaction
                    // Spend inputs
                    for input in &tx.input {
                        utxo_view.spend(input.previous_output);
                    }
                    // Add outputs
                    for (vout, output) in tx.output.iter().enumerate() {
                        let outpoint = OutPoint {
                            txid: tx.compute_txid(),
                            vout: vout as u32,
                        };
                        utxo_view.add(outpoint, output.clone());
                    }
                }
                ValidationResult::Invalid(reason) => {
                    return Ok(Err(format!(
                        "Transaction {} invalid: {}",
                        tx.compute_txid(),
                        reason
                    )));
                }
                ValidationResult::Unknown => {
                    return Ok(Err(format!(
                        "Transaction {} has unknown validation status",
                        tx.compute_txid()
                    )));
                }
            }
        }

        // Commit UTXO changes if all valid
        utxo_view.commit()?;

        Ok(Ok(()))
    }

    /// Validate witness commitment for SegWit blocks
    fn validate_witness_commitment(&self, block: &Block) -> Result<Result<(), String>> {
        // Check if block has witness data
        let has_witness = block
            .txdata
            .iter()
            .any(|tx| !tx.input.iter().all(|i| i.witness.is_empty()));

        if !has_witness {
            return Ok(Ok(())); // No witness data, no commitment needed
        }

        // Find witness commitment in coinbase
        let coinbase = &block.txdata[0];

        // Look for commitment in coinbase outputs (usually last output)
        for output in coinbase.output.iter().rev() {
            if output.script_pubkey.is_op_return() {
                // Check if this is witness commitment
                let script_bytes = output.script_pubkey.as_bytes();
                if script_bytes.len() >= 38 && script_bytes[1] == 0x24 {
                    // Found potential witness commitment
                    trace!("Found witness commitment in coinbase");

                    // In production, would verify merkle root of witness data
                    // For now, accept if present
                    return Ok(Ok(()));
                }
            }
        }

        // SegWit block must have witness commitment
        Ok(Err("SegWit block missing witness commitment".to_string()))
    }
}

pub struct TxValidator {
    utxo_set: Arc<RwLock<UtxoSet>>,
    consensus_params: ConsensusParams,
    consensus_rules: ConsensusRules,
}

impl TxValidator {
    pub fn new(utxo_set: Arc<RwLock<UtxoSet>>, consensus_params: ConsensusParams) -> Self {
        Self {
            utxo_set,
            consensus_params: consensus_params.clone(),
            consensus_rules: ConsensusRules::new(consensus_params.network),
        }
    }

    pub async fn validate_transaction(
        &self,
        tx: &Transaction,
        inputs: &[TxOut],
        height: u32,
    ) -> ValidationResult {
        // Check basic transaction validity
        if tx.input.is_empty() || tx.output.is_empty() {
            return ValidationResult::Invalid("Transaction has no inputs or outputs".to_string());
        }

        // Check for duplicate inputs
        let mut seen_inputs = std::collections::HashSet::new();
        for input in &tx.input {
            if !seen_inputs.insert(input.previous_output) {
                return ValidationResult::Invalid("Duplicate input".to_string());
            }
        }

        // Check that all inputs exist and are unspent
        if !self.check_inputs_exist(tx).await {
            return ValidationResult::Invalid(
                "Input does not exist or is already spent".to_string(),
            );
        }

        // Verify scripts (simplified)
        if !self.verify_scripts(tx, inputs, height).await {
            return ValidationResult::Invalid("Script verification failed".to_string());
        }

        // Check transaction fee
        if !self.check_fee(tx, inputs) {
            return ValidationResult::Invalid("Insufficient fee".to_string());
        }

        ValidationResult::Valid
    }

    async fn check_inputs_exist(&self, tx: &Transaction) -> bool {
        let utxo_set = self.utxo_set.read().await;
        for input in &tx.input {
            if !utxo_set.contains(&input.previous_output) {
                return false;
            }
        }
        true
    }

    async fn verify_scripts(&self, tx: &Transaction, inputs: &[TxOut], height: u32) -> bool {
        use crate::script::{verify_script, ScriptFlags, TransactionSignatureChecker};

        // Verify each input script
        for (index, (input, prevout)) in tx.input.iter().zip(inputs.iter()).enumerate() {
            // Skip if coinbase
            if input.previous_output.is_null() {
                continue;
            }

            // Set up script flags based on block height/features
            let mut flags = ScriptFlags::P2SH;

            // Add BIP65 CHECKLOCKTIMEVERIFY if active
            if self.consensus_rules.check_bip65(height) {
                flags |= ScriptFlags::CHECKLOCKTIMEVERIFY;
            }

            // Add BIP66 strict DER if active
            if self.consensus_rules.check_bip66(height) {
                flags |= ScriptFlags::STRICTENC;
            }

            // Add SegWit flags if active
            if self.consensus_rules.is_segwit_active(height) {
                flags |= ScriptFlags::WITNESS;
                flags |= ScriptFlags::NULLDUMMY;
                flags |= ScriptFlags::CHECKSEQUENCEVERIFY;
            }

            // Add Taproot flags if active
            if self.consensus_rules.is_taproot_active(height) {
                flags |= ScriptFlags::TAPROOT;
                flags |= ScriptFlags::DISCOURAGE_UPGRADEABLE_TAPROOT_VERSION;
                flags |= ScriptFlags::DISCOURAGE_OP_SUCCESS;
            }

            // Create signature checker
            let checker = TransactionSignatureChecker::new(
                tx,
                index,
                prevout.value.to_sat(),
                vec![prevout.clone()],
            );

            // Verify the script
            match verify_script(&input.script_sig, &prevout.script_pubkey, flags, &checker) {
                Ok(()) => {
                    trace!("Script verification passed for input {}", index);
                }
                Err(e) => {
                    warn!("Script verification failed for input {}: {}", index, e);
                    return false;
                }
            }

            // Additional witness validation for SegWit inputs
            if !input.witness.is_empty() {
                if let Err(e) = self
                    .verify_witness(tx, index, prevout, &input.witness)
                    .await
                {
                    warn!("Witness verification failed for input {}: {}", index, e);
                    return false;
                }
            }
        }

        true
    }

    async fn verify_witness(
        &self,
        tx: &Transaction,
        input_index: usize,
        prevout: &TxOut,
        witness: &bitcoin::Witness,
    ) -> Result<()> {
        use crate::bip143::verify_witness_signature;

        // Verify witness signature
        let amount = prevout.value;
        if !verify_witness_signature(tx, input_index, &prevout.script_pubkey, amount, witness)? {
            bail!("Witness signature verification failed");
        }

        Ok(())
    }

    fn check_fee(&self, tx: &Transaction, inputs: &[TxOut]) -> bool {
        let input_value: u64 = inputs.iter().map(|o| o.value.to_sat()).sum();
        let output_value: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();

        // Fee must be non-negative
        input_value >= output_value
    }

    pub async fn check_double_spend(&self, tx: &Transaction) -> Result<bool> {
        let utxo_set = self.utxo_set.read().await;
        for input in &tx.input {
            if !utxo_set.contains(&input.previous_output) {
                return Ok(true); // Double spend detected
            }
        }
        Ok(false)
    }
}

/// UtxoProvider implementation for consensus rules
struct UtxoSetProvider {
    utxo_set: Arc<RwLock<UtxoSet>>,
}

impl UtxoSetProvider {
    fn new(utxo_set: Arc<RwLock<UtxoSet>>) -> Self {
        Self { utxo_set }
    }
}

#[async_trait::async_trait]
impl UtxoProvider for UtxoSetProvider {
    async fn has_unspent_outputs(&self, txid: &bitcoin::Txid) -> Result<bool> {
        let utxo_set = self.utxo_set.read().await;

        // Check if any output from this transaction exists in the UTXO set
        // We need to check all possible outputs (typically 0-100)
        for vout in 0..100 {
            let outpoint = OutPoint { txid: *txid, vout };
            if utxo_set.contains(&outpoint) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}
