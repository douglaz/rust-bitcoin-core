use anyhow::Result;
use bitcoin::block::Header as BlockHeader;
use bitcoin::{Block, BlockHash};
use bitcoin_hashes::Hash;
use sled::{Db, Tree};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Storage callback for persisting blocks
pub type StorageCallback =
    Box<dyn Fn(Block, u32) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

pub struct ChainState {
    tree: Tree,
    index: Tree,
    storage_callback: Option<StorageCallback>,
    best_height: u32,
    best_hash: BlockHash,
}

impl ChainState {
    pub fn new(db: Arc<Db>) -> Self {
        let tree = db.open_tree("chain").expect("Failed to open chain tree");
        let index = db.open_tree("index").expect("Failed to open index tree");

        // Try to load tip
        let (best_height, best_hash) = if let Ok(Some(data)) = tree.get(b"tip") {
            if let Ok((header, height)) = bincode::deserialize::<(BlockHeader, u32)>(&data) {
                (height, header.block_hash())
            } else {
                (0, BlockHash::from_byte_array([0u8; 32]))
            }
        } else {
            (0, BlockHash::from_byte_array([0u8; 32]))
        };

        Self {
            tree,
            index,
            storage_callback: None,
            best_height,
            best_hash,
        }
    }

    pub async fn get_tip(&self) -> Result<Option<(BlockHeader, u32)>> {
        match self.tree.get(b"tip")? {
            Some(data) => {
                let (header, height): (BlockHeader, u32) = bincode::deserialize(&data)?;
                Ok(Some((header, height)))
            }
            None => Ok(None),
        }
    }

    pub async fn update_tip(&self, header: &BlockHeader, height: u32) -> Result<()> {
        let data = bincode::serialize(&(header, height))?;
        self.tree.insert(b"tip", data)?;

        // Also store in index
        self.store_header(header, height).await?;

        Ok(())
    }

    async fn store_header(&self, header: &BlockHeader, height: u32) -> Result<()> {
        let hash = header.block_hash();
        let key: &[u8] = hash.as_ref();
        let data = bincode::serialize(&(header, height))?;

        self.index.insert(key, data)?;
        Ok(())
    }

    pub async fn get_all_headers(&self) -> Result<Vec<(BlockHash, BlockHeader, u32)>> {
        let mut headers = Vec::new();

        for item in self.index.iter() {
            let (key, value) = item?;

            if key.len() == 32 {
                let hash = BlockHash::from_slice(&key)?;

                let (header, height): (BlockHeader, u32) = bincode::deserialize(&value)?;
                headers.push((hash, header, height));
            }
        }

        Ok(headers)
    }

    /// Set the storage callback
    pub fn set_storage_callback(&mut self, callback: StorageCallback) {
        self.storage_callback = Some(callback);
    }

    /// Add a new block to the chain
    pub async fn add_block(&mut self, block: Block) -> Result<()> {
        let height = self.best_height + 1;
        let hash = block.block_hash();

        // Store the block header
        self.update_tip(&block.header, height).await?;

        // Call storage callback if set
        if let Some(ref callback) = self.storage_callback {
            callback(block.clone(), height).await?;
        }

        // Update best
        self.best_height = height;
        self.best_hash = hash;

        Ok(())
    }

    /// Get the best block height
    pub fn get_best_height(&self) -> Result<u32> {
        Ok(self.best_height)
    }

    /// Get the best block hash
    pub fn get_best_hash(&self) -> Result<BlockHash> {
        Ok(self.best_hash)
    }

    /// Get current height (simpler getter)
    pub fn height(&self) -> u32 {
        self.best_height
    }

    /// Set height directly
    pub fn set_height(&mut self, height: u32) {
        self.best_height = height;
    }
}
