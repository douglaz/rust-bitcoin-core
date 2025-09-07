use crate::utxo_cache_levels::UtxoStorage;
use anyhow::Result;
use bitcoin::{OutPoint, TxOut};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use storage::manager::StorageManager;

/// Simple in-memory storage adapter for testing
/// In production, this would integrate with the actual storage backend
pub struct StorageAdapter {
    storage: Arc<StorageManager>,
    // Temporary in-memory storage for put/delete operations
    // until we can properly integrate with the storage manager
    memory_store: Arc<RwLock<HashMap<OutPoint, (TxOut, u32, bool)>>>,
}

impl StorageAdapter {
    pub fn new(storage: Arc<StorageManager>) -> Self {
        Self {
            storage,
            memory_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl UtxoStorage for StorageAdapter {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<(TxOut, u32, bool)>> {
        // Check memory store first
        if let Some(entry) = self.memory_store.read().get(outpoint) {
            return Ok(Some(entry.clone()));
        }

        // Fall back to storage manager
        let storage = self.storage.clone();
        let outpoint = *outpoint;

        let handle = tokio::runtime::Handle::current();
        let result = handle.block_on(async move {
            if let Some(output) = storage.get_utxo(&outpoint).await? {
                // Default values for height and is_coinbase since storage doesn't track them yet
                Ok(Some((output, 0, false)))
            } else {
                Ok(None)
            }
        });

        result
    }

    fn put(
        &self,
        outpoint: &OutPoint,
        output: &TxOut,
        height: u32,
        is_coinbase: bool,
    ) -> Result<()> {
        // Store in memory for now
        self.memory_store
            .write()
            .insert(*outpoint, (output.clone(), height, is_coinbase));
        Ok(())
    }

    fn delete(&self, outpoint: &OutPoint) -> Result<()> {
        // Remove from memory store
        self.memory_store.write().remove(outpoint);
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        // In production, this would write to persistent storage
        // For now, just clear the memory store
        Ok(())
    }
}
