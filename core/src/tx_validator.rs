use anyhow::{bail, Result};
use async_trait::async_trait;
use bitcoin::{OutPoint, Transaction, TxOut};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::runtime::Handle;
use tracing::{debug, trace, warn};

use crate::consensus::ValidationResult;
use crate::script::ScriptFlags;
use crate::utxo_manager::UtxoManager;
use storage::utxo::UtxoSet;

/// UTXO source for validation
pub enum UtxoSource {
    Storage(Arc<UtxoSet>),
    Manager(Arc<UtxoManager>),
}

/// UTXO view for transaction validation
pub struct UtxoView {
    source: UtxoSource,
    cache: HashMap<OutPoint, Option<TxOut>>,
    runtime_handle: Option<Handle>,
}

impl UtxoView {
    pub fn new(base: Arc<UtxoSet>) -> Self {
        Self {
            source: UtxoSource::Storage(base),
            cache: HashMap::new(),
            runtime_handle: None,
        }
    }

    /// Create a UtxoView from a UtxoManager
    pub fn from_manager(manager: Arc<UtxoManager>) -> Self {
        Self {
            source: UtxoSource::Manager(manager),
            cache: HashMap::new(),
            runtime_handle: None, // Not needed anymore since we're async
        }
    }

    pub async fn get(&self, outpoint: &OutPoint) -> Option<TxOut> {
        // Check cache first
        if let Some(entry) = self.cache.get(outpoint) {
            return entry.clone();
        }

        // Fall back to base UTXO source
        match &self.source {
            UtxoSource::Storage(utxo_set) => utxo_set.get(outpoint).ok().flatten(),
            UtxoSource::Manager(manager) => {
                manager.get_utxo(outpoint).await.map(|entry| entry.output)
            }
        }
    }

    pub fn spend(&mut self, outpoint: OutPoint) {
        self.cache.insert(outpoint, None);
    }

    pub fn add(&mut self, outpoint: OutPoint, output: TxOut) {
        self.cache.insert(outpoint, Some(output));
    }

    pub fn is_spent(&self, outpoint: &OutPoint) -> bool {
        if let Some(entry) = self.cache.get(outpoint) {
            return entry.is_none();
        }
        false
    }

    pub fn commit(self) -> Result<()> {
        // Apply changes to the underlying UTXO source
        match self.source {
            UtxoSource::Storage(utxo_set) => {
                for (outpoint, output) in self.cache {
                    match output {
                        Some(txout) => utxo_set.add(outpoint, txout)?,
                        None => {
                            let _ = utxo_set.spend(&outpoint)?;
                        }
                    }
                }
            }
            UtxoSource::Manager(_manager) => {
                // UtxoManager updates are handled differently (during block processing)
                // This is primarily for storage-based UTXO sets
                // For now, we don't apply changes to the manager here
            }
        }
        Ok(())
    }
}

/// Transaction validator trait
#[async_trait]
pub trait TxValidator: Send + Sync {
    async fn validate(&self, tx: &Transaction, utxo_view: &UtxoView) -> Result<()>;
    fn name(&self) -> &str;
}

/// Transaction validation pipeline
pub struct TxValidationPipeline {
    validators: Vec<Arc<dyn TxValidator>>,
    script_flags: ScriptFlags,
}

impl TxValidationPipeline {
    pub fn new(script_flags: ScriptFlags) -> Self {
        let mut validators: Vec<Arc<dyn TxValidator>> = Vec::new();

        // Add validators in order
        validators.push(Arc::new(BasicTxValidator));
        validators.push(Arc::new(InputValidator));
        validators.push(Arc::new(AmountValidator));
        validators.push(Arc::new(ScriptValidator::new(script_flags)));

        Self {
            validators,
            script_flags,
        }
    }

    /// Create a new pipeline with dynamic script flags
    pub fn with_script_flags(script_flags: ScriptFlags) -> Self {
        Self::new(script_flags)
    }

    pub async fn validate(&self, tx: &Transaction, utxo_view: &UtxoView) -> ValidationResult {
        debug!("Validating transaction: {}", tx.compute_txid());

        // Run validators in sequence
        for validator in &self.validators {
            trace!("Running validator: {}", validator.name());

            if let Err(e) = validator.validate(tx, utxo_view).await {
                warn!(
                    "Transaction validation failed in {}: {}",
                    validator.name(),
                    e
                );
                return ValidationResult::Invalid(format!("{}: {}", validator.name(), e));
            }
        }

        debug!("Transaction {} passed all validation", tx.compute_txid());
        ValidationResult::Valid
    }
}

/// Basic transaction structure validator
pub struct BasicTxValidator;

#[async_trait]
impl TxValidator for BasicTxValidator {
    async fn validate(&self, tx: &Transaction, _utxo_view: &UtxoView) -> Result<()> {
        // Check transaction size
        const MAX_TX_WEIGHT: usize = 400_000; // 400k weight units
        let weight = tx.weight().to_wu() as usize;
        if weight > MAX_TX_WEIGHT {
            bail!(
                "Transaction exceeds maximum weight: {} > {}",
                weight,
                MAX_TX_WEIGHT
            );
        }

        // Check for empty inputs/outputs
        if tx.input.is_empty() {
            bail!("Transaction has no inputs");
        }

        if tx.output.is_empty() {
            bail!("Transaction has no outputs");
        }

        // Check for duplicate inputs
        let mut inputs = HashSet::new();
        for input in &tx.input {
            if !inputs.insert(input.previous_output) {
                bail!(
                    "Transaction has duplicate input: {:?}",
                    input.previous_output
                );
            }
        }

        // Check output values
        const MAX_MONEY: u64 = 21_000_000 * 100_000_000; // 21 million BTC in satoshis
        for (index, output) in tx.output.iter().enumerate() {
            if output.value.to_sat() > MAX_MONEY {
                bail!("Output {} value exceeds maximum: {}", index, output.value);
            }
        }

        // Check total output value
        let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if total_out > MAX_MONEY {
            bail!("Total output value exceeds maximum: {}", total_out);
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "BasicTxValidator"
    }
}

/// Input existence and availability validator
pub struct InputValidator;

#[async_trait]
impl TxValidator for InputValidator {
    async fn validate(&self, tx: &Transaction, utxo_view: &UtxoView) -> Result<()> {
        // Skip for coinbase transactions
        if tx.is_coinbase() {
            return Ok(());
        }

        for (index, input) in tx.input.iter().enumerate() {
            // Check if UTXO exists
            let utxo = utxo_view.get(&input.previous_output).await.ok_or_else(|| {
                anyhow::anyhow!(
                    "Input {} references non-existent UTXO: {:?}",
                    index,
                    input.previous_output
                )
            })?;

            // Verify it's not already spent in this view
            if utxo_view.is_spent(&input.previous_output) {
                bail!("Input {} already spent: {:?}", index, input.previous_output);
            }

            trace!(
                "Input {} valid: {:?} = {} sats",
                index,
                input.previous_output,
                utxo.value
            );
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "InputValidator"
    }
}

/// Amount validator - ensures inputs >= outputs
pub struct AmountValidator;

#[async_trait]
impl TxValidator for AmountValidator {
    async fn validate(&self, tx: &Transaction, utxo_view: &UtxoView) -> Result<()> {
        // Skip for coinbase transactions
        if tx.is_coinbase() {
            return Ok(());
        }

        // Calculate total input value
        let mut total_in = 0u64;
        for input in &tx.input {
            let utxo = utxo_view
                .get(&input.previous_output)
                .await
                .ok_or_else(|| anyhow::anyhow!("UTXO not found for amount validation"))?;
            total_in += utxo.value.to_sat();
        }

        // Calculate total output value
        let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();

        // Inputs must be >= outputs (difference is fee)
        if total_in < total_out {
            bail!(
                "Total input value {} < total output value {}",
                total_in,
                total_out
            );
        }

        let fee = total_in - total_out;
        trace!("Transaction fee: {} sats", fee);

        // Check for reasonable fee (prevent accidental fee burns)
        const MAX_FEE: u64 = 100_000_000; // 1 BTC max fee as safety
        if fee > MAX_FEE {
            bail!("Transaction fee {} exceeds maximum {}", fee, MAX_FEE);
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "AmountValidator"
    }
}

/// Script signature validator
pub struct ScriptValidator {
    script_flags: ScriptFlags,
}

impl ScriptValidator {
    pub fn new(script_flags: ScriptFlags) -> Self {
        Self { script_flags }
    }
}

#[async_trait]
impl TxValidator for ScriptValidator {
    async fn validate(&self, tx: &Transaction, utxo_view: &UtxoView) -> Result<()> {
        // Skip for coinbase transactions
        if tx.is_coinbase() {
            return Ok(());
        }

        for (index, input) in tx.input.iter().enumerate() {
            let utxo = utxo_view
                .get(&input.previous_output)
                .await
                .ok_or_else(|| anyhow::anyhow!("UTXO not found for script validation"))?;

            // Create signature checker for this transaction
            let mut prevouts = Vec::new();
            for i in &tx.input {
                if let Some(out) = utxo_view.get(&i.previous_output).await {
                    prevouts.push(out);
                }
            }

            let checker = crate::script::TransactionSignatureChecker::new(
                tx,
                index,
                utxo.value.to_sat(),
                prevouts,
            );

            // Verify script execution
            crate::script::verify_script(
                &input.script_sig,
                &utxo.script_pubkey,
                self.script_flags,
                &checker,
            )?;

            trace!("Script validation passed for input {}", index);
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "ScriptValidator"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn create_test_transaction() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[tokio::test]
    async fn test_basic_validator() {
        let validator = BasicTxValidator;
        let tx = create_test_transaction();
        let utxo_view = UtxoView::new(Arc::new(UtxoSet::new(Arc::new(
            sled::Config::new().temporary(true).open().unwrap(),
        ))));

        let result = validator.validate(&tx, &utxo_view).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_empty_inputs_validation() {
        let validator = BasicTxValidator;
        let mut tx = create_test_transaction();
        tx.input.clear();

        let utxo_view = UtxoView::new(Arc::new(UtxoSet::new(Arc::new(
            sled::Config::new().temporary(true).open().unwrap(),
        ))));

        let result = validator.validate(&tx, &utxo_view).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no inputs"));
    }

    #[tokio::test]
    async fn test_duplicate_inputs() {
        let validator = BasicTxValidator;
        let mut tx = create_test_transaction();

        // Add duplicate input
        let dup_input = tx.input[0].clone();
        tx.input.push(dup_input);

        let utxo_view = UtxoView::new(Arc::new(UtxoSet::new(Arc::new(
            sled::Config::new().temporary(true).open().unwrap(),
        ))));

        let result = validator.validate(&tx, &utxo_view).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate"));
    }

    #[tokio::test]
    async fn test_utxo_view() {
        let base = Arc::new(UtxoSet::new(Arc::new(
            sled::Config::new().temporary(true).open().unwrap(),
        )));
        let mut view = UtxoView::new(base);

        let outpoint = OutPoint::null();
        let output = TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new(),
        };

        // Add to view
        view.add(outpoint, output.clone());
        assert!(view.get(&outpoint).await.is_some());

        // Spend in view
        view.spend(outpoint);
        assert!(view.is_spent(&outpoint));
        assert!(view.get(&outpoint).await.is_none());
    }
}
