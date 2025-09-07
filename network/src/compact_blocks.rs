use anyhow::{bail, Result};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Block, BlockHash, Transaction, Txid};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// BIP152 Compact Block implementation
/// https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki

/// Compact block version
pub const COMPACT_BLOCK_VERSION: u64 = 2; // Version 2 for SegWit support

/// Short transaction ID (6 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShortTxId(pub [u8; 6]);

impl ShortTxId {
    /// Create short ID from transaction ID and nonce
    pub fn from_txid(txid: &Txid, nonce: u64) -> Self {
        let mut hasher = sha256::Hash::engine();
        hasher.write_all(&txid.to_byte_array()).unwrap();
        hasher.write_all(&nonce.to_le_bytes()).unwrap();
        let hash = sha256::Hash::from_engine(hasher);

        let mut short_id = [0u8; 6];
        short_id.copy_from_slice(&hash.as_byte_array()[0..6]);
        ShortTxId(short_id)
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

/// Prefilled transaction in compact block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefilledTransaction {
    /// Index in the block
    pub index: u16,
    /// The full transaction
    pub tx: Transaction,
}

/// Compact block header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactBlockHeader {
    /// Block header
    pub header: bitcoin::block::Header,
    /// Nonce for short ID calculation
    pub nonce: u64,
}

/// Compact block message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactBlock {
    /// Header with nonce
    pub header: CompactBlockHeader,
    /// Short IDs for transactions
    pub short_ids: Vec<ShortTxId>,
    /// Prefilled transactions (always includes coinbase)
    pub prefilled_txs: Vec<PrefilledTransaction>,
}

impl CompactBlock {
    /// Create compact block from full block
    pub fn from_block(block: &Block, nonce: Option<u64>) -> Self {
        // Generate random nonce if not provided
        let nonce = nonce.unwrap_or_else(|| {
            use rand::Rng;
            rand::thread_rng().gen()
        });

        let header = CompactBlockHeader {
            header: block.header,
            nonce,
        };

        let mut short_ids = Vec::new();
        let mut prefilled_txs = Vec::new();

        // Always prefill coinbase (index 0)
        prefilled_txs.push(PrefilledTransaction {
            index: 0,
            tx: block.txdata[0].clone(),
        });

        // Generate short IDs for other transactions
        for (idx, tx) in block.txdata[1..].iter().enumerate() {
            let txid = tx.compute_txid();
            short_ids.push(ShortTxId::from_txid(&txid, nonce));
        }

        CompactBlock {
            header,
            short_ids,
            prefilled_txs,
        }
    }

    /// Get block hash
    pub fn block_hash(&self) -> BlockHash {
        self.header.header.block_hash()
    }

    /// Calculate expected transaction count
    pub fn tx_count(&self) -> usize {
        self.short_ids.len() + self.prefilled_txs.len()
    }
}

/// Request for missing transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBlockTxn {
    /// Block hash
    pub block_hash: BlockHash,
    /// Indexes of requested transactions
    pub indexes: Vec<u16>,
}

/// Response with requested transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTxn {
    /// Block hash
    pub block_hash: BlockHash,
    /// Requested transactions
    pub transactions: Vec<Transaction>,
}

/// Compact block relay manager
pub struct CompactBlockRelay {
    /// Transaction mempool for reconstruction
    mempool: Option<Arc<RwLock<mempool::pool::Mempool>>>,
    /// Fallback transaction cache if no mempool available
    tx_cache: Arc<RwLock<HashMap<Txid, Transaction>>>,
    /// Recently seen transactions (short ID -> transaction)
    recent_txs: Arc<RwLock<HashMap<ShortTxId, Transaction>>>,
    /// Recently seen transactions by txid for quick lookup
    recent_txs_by_id: Arc<RwLock<HashMap<Txid, Transaction>>>,
    /// Short ID lookup cache (nonce -> (ShortTxId -> Txid))
    short_id_cache: Arc<RwLock<HashMap<u64, HashMap<ShortTxId, Txid>>>>,
    /// Pending compact blocks
    pending_blocks: Arc<RwLock<HashMap<BlockHash, PendingBlock>>>,
    /// Statistics
    stats: Arc<RwLock<CompactBlockStats>>,
}

/// Pending compact block awaiting reconstruction
struct PendingBlock {
    compact_block: CompactBlock,
    available_txs: HashMap<u16, Transaction>,
    missing_indexes: HashSet<u16>,
    requested_at: Option<std::time::Instant>,
}

/// Compact block statistics
#[derive(Debug, Default, Clone)]
pub struct CompactBlockStats {
    pub blocks_received: u64,
    pub blocks_reconstructed: u64,
    pub blocks_failed: u64,
    pub txs_from_mempool: u64,
    pub txs_requested: u64,
    pub avg_reconstruction_time_ms: u64,
}

impl CompactBlockRelay {
    /// Create new compact block relay manager
    pub fn new(mempool: Option<Arc<RwLock<mempool::pool::Mempool>>>) -> Self {
        Self {
            mempool,
            tx_cache: Arc::new(RwLock::new(HashMap::new())),
            recent_txs: Arc::new(RwLock::new(HashMap::new())),
            recent_txs_by_id: Arc::new(RwLock::new(HashMap::new())),
            short_id_cache: Arc::new(RwLock::new(HashMap::new())),
            pending_blocks: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CompactBlockStats::default())),
        }
    }
    
    /// Build short ID lookup cache for a given nonce
    async fn build_short_id_cache(&self, nonce: u64) -> HashMap<ShortTxId, Txid> {
        let mut cache = HashMap::new();
        
        // Add transactions from mempool
        if let Some(mempool) = &self.mempool {
            let mempool_guard = mempool.read().await;
            let tx_ids = mempool_guard.get_transaction_ids();
            
            for txid in tx_ids {
                let short_id = ShortTxId::from_txid(&txid, nonce);
                cache.insert(short_id, txid);
            }
        }
        
        // Add transactions from tx_cache
        let tx_cache = self.tx_cache.read().await;
        for txid in tx_cache.keys() {
            let short_id = ShortTxId::from_txid(txid, nonce);
            cache.insert(short_id, *txid);
        }
        
        // Add transactions from recent_txs_by_id
        let recent_by_id = self.recent_txs_by_id.read().await;
        for txid in recent_by_id.keys() {
            let short_id = ShortTxId::from_txid(txid, nonce);
            cache.insert(short_id, *txid);
        }
        
        cache
    }

    /// Process received compact block
    pub async fn process_compact_block(
        &self,
        compact_block: CompactBlock,
    ) -> Result<CompactBlockResult> {
        let start = std::time::Instant::now();
        let block_hash = compact_block.block_hash();

        info!(
            "Processing compact block {} with {} transactions",
            block_hash,
            compact_block.tx_count()
        );

        self.stats.write().await.blocks_received += 1;

        // Try to reconstruct block
        match self.reconstruct_block(compact_block.clone()).await {
            Ok(block) => {
                let reconstruction_time = start.elapsed().as_millis() as u64;

                let mut stats = self.stats.write().await;
                stats.blocks_reconstructed += 1;
                stats.avg_reconstruction_time_ms = (stats.avg_reconstruction_time_ms
                    * (stats.blocks_reconstructed - 1)
                    + reconstruction_time)
                    / stats.blocks_reconstructed;

                info!(
                    "Successfully reconstructed block {} in {}ms",
                    block_hash, reconstruction_time
                );

                Ok(CompactBlockResult::Reconstructed(block))
            }
            Err(missing_indexes) => {
                // Store pending block
                let pending = PendingBlock {
                    compact_block: compact_block.clone(),
                    available_txs: HashMap::new(),
                    missing_indexes: missing_indexes.clone(),
                    requested_at: Some(std::time::Instant::now()),
                };

                self.pending_blocks
                    .write()
                    .await
                    .insert(block_hash, pending);
                self.stats.write().await.txs_requested += missing_indexes.len() as u64;

                warn!(
                    "Failed to reconstruct block {}, missing {} transactions",
                    block_hash,
                    missing_indexes.len()
                );

                Ok(CompactBlockResult::MissingTransactions(missing_indexes))
            }
        }
    }

    /// Reconstruct full block from compact block
    pub async fn reconstruct_block(
        &self,
        compact_block: CompactBlock,
    ) -> std::result::Result<Block, HashSet<u16>> {
        let mut transactions = vec![None; compact_block.tx_count()];
        let mut missing_indexes = HashSet::new();
        let nonce = compact_block.header.nonce;

        // Place prefilled transactions
        for prefilled in &compact_block.prefilled_txs {
            if prefilled.index as usize >= transactions.len() {
                // Return empty set to indicate a fatal error
                return Err(HashSet::new());
            }
            transactions[prefilled.index as usize] = Some(prefilled.tx.clone());
        }

        // Build or get cached short ID lookup
        let short_id_lookup = {
            let mut cache = self.short_id_cache.write().await;
            
            // Check if we have a cached lookup for this nonce
            if let Some(lookup) = cache.get(&nonce) {
                lookup.clone()
            } else {
                // Build new lookup and cache it
                let lookup = self.build_short_id_cache(nonce).await;
                
                // Keep cache size reasonable (max 10 nonces)
                if cache.len() >= 10 {
                    // Remove oldest entry (first in HashMap)
                    if let Some(key) = cache.keys().next().cloned() {
                        cache.remove(&key);
                    }
                }
                
                cache.insert(nonce, lookup.clone());
                lookup
            }
        };

        // Try to fill from optimized lookup
        let mut tx_index = 0usize;
        for (block_index, slot) in transactions.iter_mut().enumerate() {
            if slot.is_some() {
                continue; // Already prefilled
            }

            if tx_index >= compact_block.short_ids.len() {
                // Return empty set to indicate a fatal error
                return Err(HashSet::new());
            }

            let short_id = &compact_block.short_ids[tx_index];
            tx_index += 1;

            // Check our optimized lookup first (O(1) operation)
            if let Some(txid) = short_id_lookup.get(short_id) {
                // Try to get transaction from various sources
                let mut found_tx = None;
                
                // Check mempool first
                if let Some(mempool) = &self.mempool {
                    let mempool_guard = mempool.read().await;
                    if let Some(tx) = mempool_guard.get_transaction(txid) {
                        found_tx = Some(tx);
                    }
                }
                
                // Check tx_cache if not found in mempool
                if found_tx.is_none() {
                    let tx_cache = self.tx_cache.read().await;
                    if let Some(tx) = tx_cache.get(txid) {
                        found_tx = Some(tx.clone());
                    }
                }
                
                // Check recent_txs_by_id if still not found
                if found_tx.is_none() {
                    let recent_by_id = self.recent_txs_by_id.read().await;
                    if let Some(tx) = recent_by_id.get(txid) {
                        found_tx = Some(tx.clone());
                    }
                }
                
                if let Some(tx) = found_tx {
                    *slot = Some(tx.clone());
                    self.stats.write().await.txs_from_mempool += 1;
                    
                    // Cache for future use
                    self.recent_txs.write().await.insert(*short_id, tx.clone());
                } else {
                    missing_indexes.insert(block_index as u16);
                }
            } else {
                // Short ID not found in our lookup
                missing_indexes.insert(block_index as u16);
            }
        }

        if !missing_indexes.is_empty() {
            return Err(missing_indexes);
        }

        // All transactions found, construct block
        let txdata: Vec<Transaction> = transactions
            .into_iter()
            .map(|opt| opt.expect("All transactions should be filled"))
            .collect();

        Ok(Block {
            header: compact_block.header.header,
            txdata,
        })
    }

    /// Process received transactions for pending block
    pub async fn process_block_txn(&self, block_txn: BlockTxn) -> Result<Option<Block>> {
        let mut pending_blocks = self.pending_blocks.write().await;

        if let Some(mut pending) = pending_blocks.remove(&block_txn.block_hash) {
            // Add received transactions
            let mut tx_iter = block_txn.transactions.iter();
            for &index in &pending.missing_indexes {
                if let Some(tx) = tx_iter.next() {
                    pending.available_txs.insert(index, tx.clone());

                    // Cache transaction
                    let short_id = ShortTxId::from_txid(
                        &tx.compute_txid(),
                        pending.compact_block.header.nonce,
                    );
                    self.recent_txs.write().await.insert(short_id, tx.clone());
                }
            }

            // Try to reconstruct again
            if pending.available_txs.len() == pending.missing_indexes.len() {
                // All missing transactions received
                let mut transactions = vec![None; pending.compact_block.tx_count()];

                // Place prefilled
                for prefilled in &pending.compact_block.prefilled_txs {
                    transactions[prefilled.index as usize] = Some(prefilled.tx.clone());
                }

                // Place newly received
                for (index, tx) in pending.available_txs {
                    transactions[index as usize] = Some(tx);
                }

                // Fill remaining from mempool
                let result = self.reconstruct_block(pending.compact_block.clone()).await;

                match result {
                    Ok(block) => {
                        self.stats.write().await.blocks_reconstructed += 1;
                        return Ok(Some(block));
                    }
                    Err(_) => {
                        self.stats.write().await.blocks_failed += 1;
                        bail!("Failed to reconstruct block after receiving transactions");
                    }
                }
            } else {
                // Still missing some transactions, put back
                pending_blocks.insert(block_txn.block_hash, pending);
            }
        }

        Ok(None)
    }

    /// Create GetBlockTxn request for missing transactions
    pub fn create_get_block_txn(
        &self,
        block_hash: BlockHash,
        missing_indexes: HashSet<u16>,
    ) -> GetBlockTxn {
        let mut indexes: Vec<u16> = missing_indexes.into_iter().collect();
        indexes.sort_unstable();

        GetBlockTxn {
            block_hash,
            indexes,
        }
    }

    /// Add transaction to recent cache
    pub async fn add_recent_tx(&self, tx: Transaction) {
        // This would be called when transactions are received normally
        // to help with future compact block reconstruction
        let txid = tx.compute_txid();

        // Add to tx_cache and recent_txs_by_id
        self.tx_cache.write().await.insert(txid, tx.clone());
        self.recent_txs_by_id.write().await.insert(txid, tx.clone());
        
        // Add with multiple nonces for better matching
        for nonce_offset in 0..4 {
            let nonce = rand::random::<u64>().wrapping_add(nonce_offset);
            let short_id = ShortTxId::from_txid(&txid, nonce);
            self.recent_txs.write().await.insert(short_id, tx.clone());
        }
    }

    /// Clean up old pending blocks
    pub async fn cleanup_pending(&self, timeout: std::time::Duration) {
        let mut pending = self.pending_blocks.write().await;
        let now = std::time::Instant::now();

        pending.retain(|hash, block| {
            if let Some(requested_at) = block.requested_at {
                if now.duration_since(requested_at) > timeout {
                    warn!("Removing timed out pending block {}", hash);
                    return false;
                }
            }
            true
        });
    }

    /// Get statistics
    pub async fn get_stats(&self) -> CompactBlockStats {
        self.stats.read().await.clone()
    }
}

/// Result of compact block processing
#[derive(Debug)]
pub enum CompactBlockResult {
    /// Block successfully reconstructed
    Reconstructed(Block),
    /// Missing transactions, need to request
    MissingTransactions(HashSet<u16>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_short_tx_id() {
        let txid = Txid::from_byte_array([1u8; 32]);
        let nonce = 12345u64;

        let short_id1 = ShortTxId::from_txid(&txid, nonce);
        let short_id2 = ShortTxId::from_txid(&txid, nonce);

        assert_eq!(short_id1, short_id2);

        let short_id3 = ShortTxId::from_txid(&txid, nonce + 1);
        assert_ne!(short_id1, short_id3);
    }

    #[test]
    fn test_compact_block_creation() {
        let block = bitcoin::blockdata::constants::genesis_block(Network::Bitcoin);
        let compact = CompactBlock::from_block(&block, Some(42));

        assert_eq!(compact.header.nonce, 42);
        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.prefilled_txs[0].index, 0);
        assert_eq!(compact.short_ids.len(), 0); // Genesis has only coinbase
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_compact_block_relay() {
        let relay = CompactBlockRelay::new(None);

        let block = bitcoin::blockdata::constants::genesis_block(Network::Bitcoin);
        let compact = CompactBlock::from_block(&block, None);

        let result = relay.process_compact_block(compact).await.unwrap();

        match result {
            CompactBlockResult::Reconstructed(reconstructed) => {
                assert_eq!(reconstructed.block_hash(), block.block_hash());
            }
            _ => panic!("Expected successful reconstruction"),
        }
    }
}
