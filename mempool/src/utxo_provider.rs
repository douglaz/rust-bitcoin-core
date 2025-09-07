use anyhow::Result;
use bitcoin::{OutPoint, TxOut};
use std::sync::Arc;
use storage::utxo::UtxoSet;
use tokio::sync::RwLock;

/// Implementation of UtxoProvider for RBF policy that connects to the actual UTXO set
pub struct MempoolUtxoProvider {
    utxo_set: Arc<RwLock<UtxoSet>>,
}

impl MempoolUtxoProvider {
    pub fn new(utxo_set: Arc<RwLock<UtxoSet>>) -> Self {
        Self { utxo_set }
    }
}

impl crate::rbf::UtxoProvider for MempoolUtxoProvider {
    fn get_utxo(
        &self,
        outpoint: &OutPoint,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<TxOut>>> + Send + '_>>
    {
        let utxo_set = self.utxo_set.clone();
        let outpoint = *outpoint;
        Box::pin(async move {
            let utxo_set = utxo_set.read().await;
            utxo_set.get(&outpoint)
        })
    }
}

/// In-memory UTXO provider for testing
pub struct InMemoryUtxoProvider {
    utxos: Arc<RwLock<std::collections::HashMap<OutPoint, TxOut>>>,
}

impl Default for InMemoryUtxoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryUtxoProvider {
    pub fn new() -> Self {
        Self {
            utxos: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub async fn add_utxo(&self, outpoint: OutPoint, output: TxOut) {
        let mut utxos = self.utxos.write().await;
        utxos.insert(outpoint, output);
    }

    pub async fn remove_utxo(&self, outpoint: &OutPoint) -> Option<TxOut> {
        let mut utxos = self.utxos.write().await;
        utxos.remove(outpoint)
    }
}

impl crate::rbf::UtxoProvider for InMemoryUtxoProvider {
    fn get_utxo(
        &self,
        outpoint: &OutPoint,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<TxOut>>> + Send + '_>>
    {
        let utxos = self.utxos.clone();
        let outpoint = *outpoint;
        Box::pin(async move {
            let utxos = utxos.read().await;
            Ok(utxos.get(&outpoint).cloned())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbf::UtxoProvider as _;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, ScriptBuf, Txid};

    #[tokio::test]
    async fn test_in_memory_provider() -> Result<()> {
        let provider = InMemoryUtxoProvider::new();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };

        let output = TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: ScriptBuf::new(),
        };

        // Initially should not exist
        assert!(provider.get_utxo(&outpoint).await?.is_none());

        // Add UTXO
        provider.add_utxo(outpoint, output.clone()).await;

        // Should now exist
        let retrieved = provider.get_utxo(&outpoint).await?;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().value, output.value);

        // Remove UTXO
        provider.remove_utxo(&outpoint).await;

        // Should no longer exist
        assert!(provider.get_utxo(&outpoint).await?.is_none());

        Ok(())
    }
}
