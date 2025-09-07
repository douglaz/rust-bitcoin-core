use anyhow::{bail, Result};
use bitcoin::{block::Header as BlockHeader, Block, BlockHash};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Maximum number of orphan blocks to keep
const MAX_ORPHAN_BLOCKS: usize = 100;

/// Maximum time to keep an orphan block (1 hour)
const ORPHAN_EXPIRY_TIME: Duration = Duration::from_secs(3600);

/// Maximum size of orphan blocks in bytes (10MB)
const MAX_ORPHAN_SIZE_BYTES: usize = 10_000_000;

/// Orphan block with metadata
#[derive(Debug, Clone)]
pub struct OrphanBlock {
    /// The block
    pub block: Block,

    /// Block hash
    pub hash: BlockHash,

    /// Parent block hash
    pub parent_hash: BlockHash,

    /// Time received
    pub received_at: Instant,

    /// Size in bytes
    pub size: usize,

    /// Peer that sent this block
    pub peer: Option<std::net::SocketAddr>,
}

/// Statistics about orphan blocks
#[derive(Debug, Default, Clone)]
pub struct OrphanStats {
    /// Total orphan blocks stored
    pub count: usize,

    /// Total size in bytes
    pub total_size: usize,

    /// Oldest orphan age in seconds
    pub oldest_age: u64,

    /// Number of blocks accepted from orphans
    pub blocks_accepted: u64,

    /// Number of blocks rejected from orphans
    pub blocks_rejected: u64,

    /// Number of blocks evicted (expired or size limit)
    pub blocks_evicted: u64,
}

/// Manages orphan blocks (blocks without known parents)
pub struct OrphanBlockManager {
    /// Orphan blocks by hash
    orphans: Arc<RwLock<HashMap<BlockHash, OrphanBlock>>>,

    /// Map from parent hash to orphan children
    orphans_by_parent: Arc<RwLock<HashMap<BlockHash, HashSet<BlockHash>>>>,

    /// Queue for eviction (oldest first)
    eviction_queue: Arc<RwLock<VecDeque<(Instant, BlockHash)>>>,

    /// Total size of orphan blocks
    total_size: Arc<RwLock<usize>>,

    /// Statistics
    stats: Arc<RwLock<OrphanStats>>,
}

impl Default for OrphanBlockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl OrphanBlockManager {
    /// Create new orphan block manager
    pub fn new() -> Self {
        Self {
            orphans: Arc::new(RwLock::new(HashMap::new())),
            orphans_by_parent: Arc::new(RwLock::new(HashMap::new())),
            eviction_queue: Arc::new(RwLock::new(VecDeque::new())),
            total_size: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(OrphanStats::default())),
        }
    }

    /// Add an orphan block
    pub async fn add_orphan(&self, block: Block, peer: Option<std::net::SocketAddr>) -> Result<()> {
        let hash = block.block_hash();
        let parent_hash = block.header.prev_blockhash;
        let size = bitcoin::consensus::serialize(&block).len();

        // Check if we already have this orphan
        if self.orphans.read().await.contains_key(&hash) {
            debug!("Orphan block {} already exists", hash);
            return Ok(());
        }

        // Evict old orphans if needed
        self.evict_expired().await;

        // Check size limits
        let current_size = *self.total_size.read().await;
        if current_size + size > MAX_ORPHAN_SIZE_BYTES {
            self.evict_until_size(MAX_ORPHAN_SIZE_BYTES - size).await?;
        }

        // Check count limits
        if self.orphans.read().await.len() >= MAX_ORPHAN_BLOCKS {
            self.evict_oldest().await?;
        }

        info!(
            "Adding orphan block {} with parent {} from {:?}",
            hash, parent_hash, peer
        );

        // Create orphan entry
        let orphan = OrphanBlock {
            block,
            hash,
            parent_hash,
            received_at: Instant::now(),
            size,
            peer,
        };

        // Add to storage
        {
            let mut orphans = self.orphans.write().await;
            let mut by_parent = self.orphans_by_parent.write().await;
            let mut queue = self.eviction_queue.write().await;

            orphans.insert(hash, orphan);
            by_parent
                .entry(parent_hash)
                .or_insert_with(HashSet::new)
                .insert(hash);
            queue.push_back((Instant::now(), hash));
        }

        // Update size and stats
        *self.total_size.write().await += size;

        let mut stats = self.stats.write().await;
        stats.count = self.orphans.read().await.len();
        stats.total_size = *self.total_size.read().await;

        Ok(())
    }

    /// Get orphan blocks that depend on a given parent
    pub async fn get_orphans_by_parent(&self, parent_hash: &BlockHash) -> Vec<Block> {
        let by_parent = self.orphans_by_parent.read().await;
        let orphans = self.orphans.read().await;

        if let Some(children) = by_parent.get(parent_hash) {
            children
                .iter()
                .filter_map(|hash| orphans.get(hash))
                .map(|o| o.block.clone())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Remove an orphan block
    pub async fn remove_orphan(&self, hash: &BlockHash) -> Option<Block> {
        let mut orphans = self.orphans.write().await;
        let mut by_parent = self.orphans_by_parent.write().await;

        if let Some(orphan) = orphans.remove(hash) {
            // Remove from parent map
            if let Some(siblings) = by_parent.get_mut(&orphan.parent_hash) {
                siblings.remove(hash);
                if siblings.is_empty() {
                    by_parent.remove(&orphan.parent_hash);
                }
            }

            // Update size
            *self.total_size.write().await -= orphan.size;

            // Update stats
            let mut stats = self.stats.write().await;
            stats.count = orphans.len();
            stats.total_size = *self.total_size.read().await;

            debug!("Removed orphan block {}", hash);
            Some(orphan.block)
        } else {
            None
        }
    }

    /// Process orphans after a new block is accepted
    /// Returns blocks that should be processed next
    pub async fn process_new_parent(&self, parent_hash: &BlockHash) -> Vec<Block> {
        let mut blocks_to_process = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(*parent_hash);

        // BFS to find all descendants
        while let Some(current_hash) = queue.pop_front() {
            let children = self.get_orphans_by_parent(&current_hash).await;

            for child in children {
                let child_hash = child.block_hash();

                // Remove from orphans
                if self.remove_orphan(&child_hash).await.is_some() {
                    blocks_to_process.push(child.clone());
                    queue.push_back(child_hash);

                    info!(
                        "Found orphan child {} of parent {}, queuing for processing",
                        child_hash, current_hash
                    );
                }
            }
        }

        if !blocks_to_process.is_empty() {
            info!(
                "Processing {} orphan blocks after new parent {}",
                blocks_to_process.len(),
                parent_hash
            );

            // Update stats
            let mut stats = self.stats.write().await;
            stats.blocks_accepted += blocks_to_process.len() as u64;
        }

        blocks_to_process
    }

    /// Check if a block is an orphan
    pub async fn is_orphan(&self, hash: &BlockHash) -> bool {
        self.orphans.read().await.contains_key(hash)
    }

    /// Get an orphan block
    pub async fn get_orphan(&self, hash: &BlockHash) -> Option<Block> {
        self.orphans.read().await.get(hash).map(|o| o.block.clone())
    }

    /// Get parent hash of an orphan
    pub async fn get_orphan_parent(&self, hash: &BlockHash) -> Option<BlockHash> {
        self.orphans.read().await.get(hash).map(|o| o.parent_hash)
    }

    /// Evict expired orphans
    async fn evict_expired(&self) {
        let cutoff = Instant::now() - ORPHAN_EXPIRY_TIME;
        let mut to_remove = Vec::new();

        {
            let orphans = self.orphans.read().await;
            for (hash, orphan) in orphans.iter() {
                if orphan.received_at < cutoff {
                    to_remove.push(*hash);
                }
            }
        }

        if !to_remove.is_empty() {
            let count = to_remove.len();
            info!("Evicting {} expired orphan blocks", count);

            for hash in to_remove {
                self.remove_orphan(&hash).await;
            }

            // Update stats
            let mut stats = self.stats.write().await;
            stats.blocks_evicted += count as u64;
        }
    }

    /// Evict oldest orphan
    async fn evict_oldest(&self) -> Result<()> {
        let mut queue = self.eviction_queue.write().await;

        while let Some((_, hash)) = queue.pop_front() {
            if self.orphans.read().await.contains_key(&hash) {
                self.remove_orphan(&hash).await;

                // Update stats
                let mut stats = self.stats.write().await;
                stats.blocks_evicted += 1;

                debug!("Evicted oldest orphan block {}", hash);
                return Ok(());
            }
        }

        bail!("No orphans to evict");
    }

    /// Evict orphans until size is below target
    async fn evict_until_size(&self, target_size: usize) -> Result<()> {
        let mut current_size = *self.total_size.read().await;
        let mut evicted = 0;

        while current_size > target_size {
            // Find largest orphan
            let largest = {
                let orphans = self.orphans.read().await;
                orphans
                    .values()
                    .max_by_key(|o| o.size)
                    .map(|o| (o.hash, o.size))
            };

            if let Some((hash, size)) = largest {
                self.remove_orphan(&hash).await;
                current_size -= size;
                evicted += 1;

                debug!("Evicted large orphan {} ({} bytes)", hash, size);
            } else {
                break;
            }
        }

        if evicted > 0 {
            info!("Evicted {} orphan blocks to reduce size", evicted);

            // Update stats
            let mut stats = self.stats.write().await;
            stats.blocks_evicted += evicted;
        }

        Ok(())
    }

    /// Get statistics
    pub async fn get_stats(&self) -> OrphanStats {
        let mut stats = self.stats.read().await.clone();

        // Calculate oldest age
        if let Some(oldest) = self
            .orphans
            .read()
            .await
            .values()
            .min_by_key(|o| o.received_at)
        {
            stats.oldest_age = oldest.received_at.elapsed().as_secs();
        }

        stats
    }

    /// Clean up orphans (called periodically)
    pub async fn cleanup(&self) {
        debug!("Running orphan block cleanup");

        // Evict expired orphans
        self.evict_expired().await;

        // Clean up eviction queue
        let mut queue = self.eviction_queue.write().await;
        let orphans = self.orphans.read().await;

        queue.retain(|(_, hash)| orphans.contains_key(hash));
    }

    /// Get all orphan headers for debugging
    pub async fn get_orphan_headers(&self) -> Vec<(BlockHash, BlockHeader, std::net::SocketAddr)> {
        self.orphans
            .read()
            .await
            .values()
            .filter_map(|o| o.peer.map(|p| (o.hash, o.block.header, p)))
            .collect()
    }

    /// Request missing parent blocks from peers
    pub async fn get_missing_parents(&self) -> HashSet<BlockHash> {
        let by_parent = self.orphans_by_parent.read().await;
        by_parent.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn create_test_block(prev_hash: BlockHash) -> Block {
        Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: prev_hash,
                merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                    bitcoin::hashes::Hash::from_slice(&[0u8; 32]).unwrap(),
                ),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata: vec![],
        }
    }

    #[tokio::test]
    async fn test_add_orphan() -> Result<()> {
        let manager = OrphanBlockManager::new();
        let block = create_test_block(BlockHash::from_raw_hash(
            bitcoin::hashes::Hash::from_slice(&[0u8; 32]).unwrap(),
        ));

        manager.add_orphan(block.clone(), None).await?;

        assert!(manager.is_orphan(&block.block_hash()).await);
        assert_eq!(manager.get_stats().await.count, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_orphan_chain() -> Result<()> {
        let manager = OrphanBlockManager::new();

        // Create chain of orphans
        let parent_hash = BlockHash::from_byte_array([0u8; 32]);
        let block1 = create_test_block(parent_hash);
        let block2 = create_test_block(block1.block_hash());
        let block3 = create_test_block(block2.block_hash());

        // Add orphans
        manager.add_orphan(block1.clone(), None).await?;
        manager.add_orphan(block2.clone(), None).await?;
        manager.add_orphan(block3.clone(), None).await?;

        // Process parent
        let children = manager.process_new_parent(&parent_hash).await;

        // Should get all descendants
        assert_eq!(children.len(), 3);
        assert_eq!(manager.get_stats().await.count, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_size_limit() -> Result<()> {
        let manager = OrphanBlockManager::new();

        // Add many blocks to exceed size limit
        for i in 0..200 {
            let mut block = create_test_block(BlockHash::from_byte_array([0u8; 32]));
            block.header.nonce = i;
            manager.add_orphan(block, None).await?;
        }

        // Should have evicted some
        let stats = manager.get_stats().await;
        assert!(stats.count <= MAX_ORPHAN_BLOCKS);
        assert!(stats.blocks_evicted > 0);

        Ok(())
    }
}
