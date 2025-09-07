use anyhow::{bail, Result};
use bitcoin::{Amount, OutPoint, Transaction, TxOut};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

/// UTXO provider trait for mining fee calculation
#[async_trait::async_trait]
pub trait MiningUtxoProvider: Send + Sync {
    /// Get a UTXO by outpoint
    async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>>;

    /// Get multiple UTXOs in batch
    async fn get_utxos(&self, outpoints: &[OutPoint]) -> Result<HashMap<OutPoint, TxOut>>;
}

/// Fee calculator for mining that uses actual UTXO lookups
pub struct MiningFeeCalculator {
    utxo_provider: Arc<dyn MiningUtxoProvider>,
    /// Cache of recently looked up UTXOs
    utxo_cache: Arc<RwLock<HashMap<OutPoint, TxOut>>>,
}

impl MiningFeeCalculator {
    /// Create a new fee calculator
    pub fn new(utxo_provider: Arc<dyn MiningUtxoProvider>) -> Self {
        Self {
            utxo_provider,
            utxo_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Calculate the actual fee for a transaction
    pub async fn calculate_tx_fee(&self, tx: &Transaction) -> Result<Amount> {
        if tx.is_coinbase() {
            return Ok(Amount::ZERO);
        }

        // Calculate input sum
        let input_sum = self.calculate_input_sum(tx).await?;

        // Calculate output sum
        let output_sum: Amount = tx.output.iter().map(|out| out.value).sum::<Amount>();

        // Fee = inputs - outputs
        if input_sum < output_sum {
            bail!(
                "Transaction {} has negative fee: inputs {} < outputs {}",
                tx.compute_txid(),
                input_sum,
                output_sum
            );
        }

        let fee = input_sum - output_sum;
        debug!(
            "Transaction {} fee: {} sats (inputs: {}, outputs: {})",
            tx.compute_txid(),
            fee.to_sat(),
            input_sum.to_sat(),
            output_sum.to_sat()
        );

        Ok(fee)
    }

    /// Calculate the sum of all inputs
    async fn calculate_input_sum(&self, tx: &Transaction) -> Result<Amount> {
        let mut sum = Amount::ZERO;

        // Check cache first
        let cache = self.utxo_cache.read().await;
        let mut missing_outpoints = Vec::new();

        for input in &tx.input {
            if let Some(utxo) = cache.get(&input.previous_output) {
                sum += utxo.value;
            } else {
                missing_outpoints.push(input.previous_output);
            }
        }
        drop(cache);

        // Fetch missing UTXOs
        if !missing_outpoints.is_empty() {
            let fetched_utxos = self.utxo_provider.get_utxos(&missing_outpoints).await?;

            // Update cache
            let mut cache = self.utxo_cache.write().await;
            for (outpoint, utxo) in &fetched_utxos {
                sum += utxo.value;
                cache.insert(*outpoint, utxo.clone());
            }

            // Check if any UTXOs are still missing
            for outpoint in &missing_outpoints {
                if !fetched_utxos.contains_key(outpoint) {
                    bail!("UTXO not found for input: {:?}", outpoint);
                }
            }
        }

        Ok(sum)
    }

    /// Calculate fees for multiple transactions
    pub async fn calculate_fees_batch(&self, transactions: &[Transaction]) -> Result<Vec<Amount>> {
        let mut fees = Vec::with_capacity(transactions.len());

        for tx in transactions {
            fees.push(self.calculate_tx_fee(tx).await?);
        }

        Ok(fees)
    }

    /// Calculate fee rate (sats per virtual byte)
    pub async fn calculate_fee_rate(&self, tx: &Transaction) -> Result<f64> {
        let fee = self.calculate_tx_fee(tx).await?;
        let vsize = tx.vsize() as f64;

        if vsize == 0.0 {
            return Ok(0.0);
        }

        Ok(fee.to_sat() as f64 / vsize)
    }

    /// Clear the UTXO cache
    pub async fn clear_cache(&self) {
        let mut cache = self.utxo_cache.write().await;
        cache.clear();
        debug!("Cleared UTXO cache");
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.utxo_cache.read().await;
        CacheStats {
            entries: cache.len(),
            size_bytes: cache.len() * std::mem::size_of::<(OutPoint, TxOut)>(),
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub size_bytes: usize,
}

// Note: UtxoSetProvider would need to be implemented by the node that uses this
// It should connect to the actual UTXO storage backend
// For now, we'll leave this as a placeholder for the actual implementation

/// Mock UTXO provider for testing
pub struct MockUtxoProvider {
    utxos: Arc<RwLock<HashMap<OutPoint, TxOut>>>,
}

impl Default for MockUtxoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockUtxoProvider {
    pub fn new() -> Self {
        Self {
            utxos: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_utxo(&self, outpoint: OutPoint, output: TxOut) {
        let mut utxos = self.utxos.write().await;
        utxos.insert(outpoint, output);
    }
}

#[async_trait::async_trait]
impl MiningUtxoProvider for MockUtxoProvider {
    async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        let utxos = self.utxos.read().await;
        Ok(utxos.get(outpoint).cloned())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{ScriptBuf, TxIn, Witness};

    #[tokio::test]
    async fn test_fee_calculation() {
        let provider = Arc::new(MockUtxoProvider::new());
        let calculator = MiningFeeCalculator::new(provider.clone());

        // Create a test transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Add an input
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };
        tx.input.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: Witness::new(),
        });

        // Add the UTXO for this input (10,000 sats)
        provider
            .add_utxo(
                outpoint,
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::new(),
                },
            )
            .await;

        // Add an output (9,500 sats)
        tx.output.push(TxOut {
            value: Amount::from_sat(9_500),
            script_pubkey: ScriptBuf::new(),
        });

        // Calculate fee (should be 500 sats)
        let fee = calculator.calculate_tx_fee(&tx).await.unwrap();
        assert_eq!(fee.to_sat(), 500);

        // Calculate fee rate
        let fee_rate = calculator.calculate_fee_rate(&tx).await.unwrap();
        assert!(fee_rate > 0.0);
    }

    #[tokio::test]
    async fn test_coinbase_fee() {
        let provider = Arc::new(MockUtxoProvider::new());
        let calculator = MiningFeeCalculator::new(provider);

        // Create a coinbase transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(625_000_000), // 6.25 BTC
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // Coinbase should have zero fee
        let fee = calculator.calculate_tx_fee(&tx).await.unwrap();
        assert_eq!(fee, Amount::ZERO);
    }
}
