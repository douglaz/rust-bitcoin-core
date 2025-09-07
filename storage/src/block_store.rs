use anyhow::{Context, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::{Block, BlockHash, Transaction, Txid};
use bitcoin_hashes::Hash;
use serde::{Deserialize, Serialize};
use sled::{Batch, Db, Tree};
use std::sync::Arc;
use tracing::{debug, info};

/// Metadata about a stored block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMetadata {
    pub hash: BlockHash,
    pub height: u32,
    pub size: usize,
    pub weight: u64,
    pub tx_count: usize,
    pub timestamp: u32,
    pub version: i32,
}

/// Block storage with indexing
pub struct BlockStore {
    blocks_tree: Tree,   // Full block data
    headers_tree: Tree,  // Just headers for fast access
    metadata_tree: Tree, // Block metadata
    height_index: Tree,  // Height -> BlockHash index
    tx_index: Tree,      // Txid -> BlockHash index
}

impl BlockStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            blocks_tree: db.open_tree("blocks").expect("Failed to open blocks tree"),
            headers_tree: db
                .open_tree("headers")
                .expect("Failed to open headers tree"),
            metadata_tree: db
                .open_tree("block_metadata")
                .expect("Failed to open metadata tree"),
            height_index: db
                .open_tree("height_index")
                .expect("Failed to open height index tree"),
            tx_index: db
                .open_tree("tx_index")
                .expect("Failed to open tx index tree"),
        }
    }

    /// Store a block with full indexing
    pub async fn store(&self, block: &Block, height: u32) -> Result<()> {
        let hash = block.block_hash();
        info!("Storing block {} at height {}", hash, height);

        // Prepare batch for atomic write
        let mut batch = Batch::default();

        // Store full block data
        let block_key: &[u8] = hash.as_ref();
        let block_data = bitcoin::consensus::encode::serialize(block);
        batch.insert(block_key, block_data.clone());

        // Store header separately for fast access
        let header_data = bitcoin::consensus::encode::serialize(&block.header);
        self.headers_tree.insert(block_key, header_data)?;

        // Create and store metadata
        let metadata = BlockMetadata {
            hash,
            height,
            size: block_data.len(),
            weight: block.weight().to_wu(),
            tx_count: block.txdata.len(),
            timestamp: block.header.time,
            version: block.header.version.to_consensus(),
        };
        let metadata_data = bincode::serialize(&metadata)?;
        self.metadata_tree.insert(block_key, metadata_data)?;

        // Index by height
        let height_key = height.to_be_bytes();
        self.height_index.insert(height_key, block_key)?;

        // Index transactions
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            let tx_key: &[u8] = txid.as_ref();
            self.tx_index.insert(tx_key, block_key)?;
        }

        // Apply batch atomically
        self.blocks_tree.apply_batch(batch)?;

        debug!(
            "Stored block {} with {} transactions",
            hash,
            block.txdata.len()
        );
        Ok(())
    }

    /// Get a block by hash
    pub async fn get(&self, hash: &BlockHash) -> Result<Option<Block>> {
        let key: &[u8] = hash.as_ref();

        match self.blocks_tree.get(key)? {
            Some(data) => {
                let block = bitcoin::consensus::encode::deserialize(&data)
                    .context("Failed to deserialize block")?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Get just a block header
    pub async fn get_header(&self, hash: &BlockHash) -> Result<Option<BlockHeader>> {
        let key: &[u8] = hash.as_ref();

        match self.headers_tree.get(key)? {
            Some(data) => {
                let header = bitcoin::consensus::encode::deserialize(&data)
                    .context("Failed to deserialize header")?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    /// Get block metadata
    pub async fn get_metadata(&self, hash: &BlockHash) -> Result<Option<BlockMetadata>> {
        let key: &[u8] = hash.as_ref();

        match self.metadata_tree.get(key)? {
            Some(data) => {
                let metadata =
                    bincode::deserialize(&data).context("Failed to deserialize metadata")?;
                Ok(Some(metadata))
            }
            None => Ok(None),
        }
    }

    /// Get block by height
    pub async fn get_by_height(&self, height: u32) -> Result<Option<Block>> {
        let height_key = height.to_be_bytes();

        match self.height_index.get(height_key)? {
            Some(hash_bytes) => {
                let hash = BlockHash::from_byte_array(
                    hash_bytes
                        .as_ref()
                        .try_into()
                        .context("Invalid block hash length in height index")?,
                );
                self.get(&hash).await
            }
            None => Ok(None),
        }
    }

    /// Get block hash at height
    pub async fn get_hash_at_height(&self, height: u32) -> Result<Option<BlockHash>> {
        let height_key = height.to_be_bytes();

        match self.height_index.get(height_key)? {
            Some(hash_bytes) => {
                let hash = BlockHash::from_byte_array(
                    hash_bytes
                        .as_ref()
                        .try_into()
                        .context("Invalid block hash length in height index")?,
                );
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Find which block contains a transaction
    pub async fn find_tx_block(&self, txid: &Txid) -> Result<Option<BlockHash>> {
        let tx_key: &[u8] = txid.as_ref();

        match self.tx_index.get(tx_key)? {
            Some(hash_bytes) => {
                let hash = BlockHash::from_byte_array(
                    hash_bytes
                        .as_ref()
                        .try_into()
                        .context("Invalid block hash length in tx index")?,
                );
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Get a specific transaction from storage
    pub async fn get_transaction(&self, txid: &Txid) -> Result<Option<(Transaction, BlockHash)>> {
        // First find which block contains the transaction
        if let Some(block_hash) = self.find_tx_block(txid).await? {
            // Then get the block and find the transaction
            if let Some(block) = self.get(&block_hash).await? {
                for tx in block.txdata {
                    if tx.compute_txid() == *txid {
                        return Ok(Some((tx, block_hash)));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Delete a block and all its indexes
    pub async fn delete(&self, hash: &BlockHash) -> Result<()> {
        let key: &[u8] = hash.as_ref();

        // Get metadata to find height and transactions
        if let Some(metadata) = self.get_metadata(hash).await? {
            // Remove height index
            let height_key = metadata.height.to_be_bytes();
            self.height_index.remove(height_key)?;

            // Remove transaction indexes
            if let Some(block) = self.get(hash).await? {
                for tx in block.txdata {
                    let txid = tx.compute_txid();
                    let tx_key: &[u8] = txid.as_ref();
                    self.tx_index.remove(tx_key)?;
                }
            }
        }

        // Remove block data
        self.blocks_tree.remove(key)?;
        self.headers_tree.remove(key)?;
        self.metadata_tree.remove(key)?;

        debug!("Deleted block {}", hash);
        Ok(())
    }

    /// Get statistics about stored blocks
    pub async fn get_stats(&self) -> Result<BlockStoreStats> {
        let block_count = self.blocks_tree.len();
        // Estimate size based on entry count (sled doesn't expose exact size)
        let avg_block_size = 1_000_000; // 1MB average
        let avg_metadata_size = 100;
        let total_size = (block_count * avg_block_size
            + self.headers_tree.len() * 80
            + self.metadata_tree.len() * avg_metadata_size
            + self.height_index.len() * 36
            + self.tx_index.len() * 64) as u64;

        // Find highest block
        let mut max_height = 0u32;
        for (height_bytes, _) in self.height_index.iter().flatten() {
            let height = u32::from_be_bytes([
                height_bytes[0],
                height_bytes[1],
                height_bytes[2],
                height_bytes[3],
            ]);
            max_height = max_height.max(height);
        }

        Ok(BlockStoreStats {
            block_count,
            total_size,
            max_height,
            tx_count: self.tx_index.len(),
        })
    }

    /// Prune blocks below a certain height (keep only headers)
    pub async fn prune_before(&self, height: u32) -> Result<usize> {
        let mut pruned = 0;

        for h in 0..height {
            if let Some(hash) = self.get_hash_at_height(h).await? {
                let key: &[u8] = hash.as_ref();

                // Keep header and metadata, delete full block
                if self.blocks_tree.remove(key)?.is_some() {
                    pruned += 1;
                    debug!("Pruned block {} at height {}", hash, h);
                }
            }
        }

        info!("Pruned {} blocks below height {}", pruned, height);
        Ok(pruned)
    }
}

/// Statistics about the block store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockStoreStats {
    pub block_count: usize,
    pub total_size: u64,
    pub max_height: u32,
    pub tx_count: usize,
}
