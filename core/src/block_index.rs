use anyhow::Result;
use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, trace, warn};

/// Block status flags
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct BlockStatus {
    /// Block data is stored on disk
    pub have_data: bool,
    /// Undo data is stored on disk
    pub have_undo: bool,
    /// Block has been validated
    pub validated: bool,
    /// Block is part of main chain
    pub in_main_chain: bool,
    /// Block failed validation
    pub failed: bool,
    /// Block conflicts with main chain
    pub conflicted: bool,
}

/// Block index entry with all metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockIndexEntry {
    /// Block header
    pub header: BlockHeader,
    /// Block height in main chain (None if not in main chain)
    pub height: Option<u32>,
    /// Block status
    pub status: BlockStatus,
    /// Total chain work up to this block
    pub chain_work: [u8; 32],
    /// Number of transactions in block
    pub n_tx: u32,
    /// File position where block is stored
    pub file_pos: Option<u64>,
    /// File position where undo data is stored
    pub undo_pos: Option<u64>,
    /// Time when block was received
    pub time_received: u64,
}

impl BlockIndexEntry {
    /// Create new block index entry
    pub fn new(header: BlockHeader) -> Self {
        Self {
            header,
            height: None,
            status: BlockStatus::default(),
            chain_work: [0u8; 32],
            n_tx: 0,
            file_pos: None,
            undo_pos: None,
            time_received: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Get block hash
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }
}

/// Block index manager for efficient block lookups and chain navigation
pub struct BlockIndex {
    /// Map from block hash to index entry
    index: Arc<RwLock<HashMap<BlockHash, BlockIndexEntry>>>,
    /// Best chain tip
    best_tip: Arc<RwLock<Option<BlockHash>>>,
    /// Best chain height
    best_height: Arc<RwLock<u32>>,
    /// Headers waiting for validation
    headers_queue: Arc<RwLock<Vec<BlockHash>>>,
    /// Invalid blocks (and their descendants)
    invalid_blocks: Arc<RwLock<HashSet<BlockHash>>>,
}

impl Default for BlockIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockIndex {
    /// Create new block index
    pub fn new() -> Self {
        Self {
            index: Arc::new(RwLock::new(HashMap::new())),
            best_tip: Arc::new(RwLock::new(None)),
            best_height: Arc::new(RwLock::new(0)),
            headers_queue: Arc::new(RwLock::new(Vec::new())),
            invalid_blocks: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Add genesis block
    pub fn add_genesis(&self, genesis: &Block) -> Result<()> {
        let mut index = self.index.write();
        let hash = genesis.block_hash();

        let mut entry = BlockIndexEntry::new(genesis.header);
        entry.height = Some(0);
        entry.status.have_data = true;
        entry.status.validated = true;
        entry.status.in_main_chain = true;
        entry.n_tx = genesis.txdata.len() as u32;
        entry.chain_work = self.calculate_work(&genesis.header)?;

        index.insert(hash, entry);

        let mut best_tip = self.best_tip.write();
        *best_tip = Some(hash);

        let mut best_height = self.best_height.write();
        *best_height = 0;

        info!("Added genesis block to index: {}", hash);
        Ok(())
    }

    /// Add a new block header to the index
    pub fn add_header(&self, header: &BlockHeader) -> Result<()> {
        let hash = header.block_hash();

        // Check if we already have it
        {
            let index = self.index.read();
            if index.contains_key(&hash) {
                trace!("Header {} already in index", hash);
                return Ok(());
            }
        }

        // Verify parent exists
        let parent_entry = {
            let index = self.index.read();
            index.get(&header.prev_blockhash).cloned()
        };

        let parent = parent_entry
            .ok_or_else(|| anyhow::anyhow!("Parent block {} not found", header.prev_blockhash))?;

        // Create new entry
        let mut entry = BlockIndexEntry::new(*header);

        // Calculate chain work
        let block_work = self.calculate_work(header)?;
        entry.chain_work = self.add_work(&parent.chain_work, &block_work)?;

        // Set height if parent is in main chain
        if parent.status.in_main_chain {
            entry.height = parent.height.map(|h| h + 1);
        }

        // Add to index
        {
            let mut index = self.index.write();
            index.insert(hash, entry.clone());
        }

        // Add to validation queue
        {
            let mut queue = self.headers_queue.write();
            queue.push(hash);
        }

        debug!("Added header {} to index", hash);

        // Check if this could be new best chain
        self.maybe_update_tip(hash, &entry.chain_work)?;

        Ok(())
    }

    /// Mark block as having data on disk
    pub fn mark_block_have_data(&self, hash: &BlockHash, file_pos: u64, n_tx: u32) -> Result<()> {
        let mut index = self.index.write();
        let entry = index
            .get_mut(hash)
            .ok_or_else(|| anyhow::anyhow!("Block {} not in index", hash))?;

        entry.status.have_data = true;
        entry.file_pos = Some(file_pos);
        entry.n_tx = n_tx;

        debug!("Marked block {} as having data", hash);
        Ok(())
    }

    /// Mark block as validated
    pub fn mark_block_validated(&self, hash: &BlockHash, height: u32) -> Result<()> {
        let mut index = self.index.write();
        let entry = index
            .get_mut(hash)
            .ok_or_else(|| anyhow::anyhow!("Block {} not in index", hash))?;

        entry.status.validated = true;
        entry.height = Some(height);

        debug!("Marked block {} as validated at height {}", hash, height);
        Ok(())
    }

    /// Mark block as invalid
    pub fn mark_block_invalid(&self, hash: &BlockHash) -> Result<()> {
        let mut index = self.index.write();
        let entry = index
            .get_mut(hash)
            .ok_or_else(|| anyhow::anyhow!("Block {} not in index", hash))?;

        entry.status.failed = true;
        entry.status.in_main_chain = false;

        // Mark all descendants as invalid too
        let mut invalid = self.invalid_blocks.write();
        invalid.insert(*hash);

        warn!("Marked block {} as invalid", hash);

        // Find and mark descendants
        self.mark_descendants_invalid(*hash, &mut index, &mut invalid);

        Ok(())
    }

    /// Mark all descendants of a block as invalid
    fn mark_descendants_invalid(
        &self,
        parent: BlockHash,
        index: &mut HashMap<BlockHash, BlockIndexEntry>,
        invalid: &mut HashSet<BlockHash>,
    ) {
        let descendants: Vec<BlockHash> = index
            .iter()
            .filter(|(_, entry)| entry.header.prev_blockhash == parent)
            .map(|(hash, _)| *hash)
            .collect();

        for hash in descendants {
            if let Some(entry) = index.get_mut(&hash) {
                entry.status.conflicted = true;
                entry.status.in_main_chain = false;
                invalid.insert(hash);

                // Recursively mark descendants
                self.mark_descendants_invalid(hash, index, invalid);
            }
        }
    }

    /// Update main chain
    pub fn set_best_chain(&self, tip: BlockHash, height: u32) -> Result<()> {
        // First, mark old chain as not main
        {
            let mut index = self.index.write();
            if let Some(old_tip) = *self.best_tip.read() {
                self.unmark_chain_main(old_tip, &mut index)?;
            }
        }

        // Then mark new chain as main
        {
            let mut index = self.index.write();
            self.mark_chain_main(tip, &mut index)?;
        }

        // Update best tip
        {
            let mut best = self.best_tip.write();
            *best = Some(tip);
        }

        {
            let mut h = self.best_height.write();
            *h = height;
        }

        info!("Updated best chain to {} at height {}", tip, height);
        Ok(())
    }

    /// Mark chain as main from tip to genesis
    fn mark_chain_main(
        &self,
        tip: BlockHash,
        index: &mut HashMap<BlockHash, BlockIndexEntry>,
    ) -> Result<()> {
        let mut current = tip;
        let mut height = None;

        loop {
            let entry = index
                .get_mut(&current)
                .ok_or_else(|| anyhow::anyhow!("Block {} not in index", current))?;

            entry.status.in_main_chain = true;

            // Set height if not set
            if height.is_none() {
                height = entry.height;
            }

            if entry.header.prev_blockhash == BlockHash::from_byte_array([0u8; 32]) {
                break; // Reached genesis
            }

            current = entry.header.prev_blockhash;
        }

        Ok(())
    }

    /// Unmark chain as main from tip
    fn unmark_chain_main(
        &self,
        tip: BlockHash,
        index: &mut HashMap<BlockHash, BlockIndexEntry>,
    ) -> Result<()> {
        let mut current = tip;

        loop {
            let entry = index
                .get_mut(&current)
                .ok_or_else(|| anyhow::anyhow!("Block {} not in index", current))?;

            entry.status.in_main_chain = false;

            if entry.header.prev_blockhash == BlockHash::from_byte_array([0u8; 32]) {
                break; // Reached genesis
            }

            current = entry.header.prev_blockhash;
        }

        Ok(())
    }

    /// Check if we should update the tip
    fn maybe_update_tip(&self, hash: BlockHash, chain_work: &[u8; 32]) -> Result<()> {
        let best_tip = self.best_tip.read();

        if let Some(current_tip) = *best_tip {
            let index = self.index.read();
            let current = index
                .get(&current_tip)
                .ok_or_else(|| anyhow::anyhow!("Current tip not in index"))?;

            // Compare chain work
            if self.compare_work(chain_work, &current.chain_work) == std::cmp::Ordering::Greater {
                info!("Found new best chain candidate: {}", hash);
                // Note: Actual chain update would happen after validation
            }
        }

        Ok(())
    }

    /// Get block index entry
    pub fn get(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        let index = self.index.read();
        index.get(hash).cloned()
    }

    /// Get block height
    pub fn get_height(&self, hash: &BlockHash) -> Option<u32> {
        let index = self.index.read();
        index.get(hash).and_then(|e| e.height)
    }

    /// Get best chain tip
    pub fn best_tip(&self) -> Option<BlockHash> {
        *self.best_tip.read()
    }

    /// Get best chain height
    pub fn best_height(&self) -> u32 {
        *self.best_height.read()
    }

    /// Get block locator for headers sync
    pub fn get_locator(&self) -> Vec<BlockHash> {
        let mut locator = Vec::new();
        let index = self.index.read();

        if let Some(tip) = *self.best_tip.read() {
            let mut current = tip;
            let mut step = 1;
            let mut i = 0;

            loop {
                locator.push(current);

                // Exponentially fewer blocks as we go back
                if i >= 10 {
                    step *= 2;
                }

                // Walk back 'step' blocks
                for _ in 0..step {
                    if let Some(entry) = index.get(&current) {
                        if entry.header.prev_blockhash == BlockHash::from_byte_array([0u8; 32]) {
                            return locator; // Reached genesis
                        }
                        current = entry.header.prev_blockhash;
                    } else {
                        return locator;
                    }
                }

                i += 1;

                if locator.len() > 100 {
                    break; // Reasonable limit
                }
            }
        }

        locator
    }

    /// Calculate work for a block header
    fn calculate_work(&self, header: &BlockHeader) -> Result<[u8; 32]> {
        // Work = 2^256 / (target + 1)
        let target = header.target();
        // Convert target to work (simplified - would need proper big int math)
        let target_bytes = target.to_be_bytes();
        let mantissa = u64::from_be_bytes([
            target_bytes[24],
            target_bytes[25],
            target_bytes[26],
            target_bytes[27],
            target_bytes[28],
            target_bytes[29],
            target_bytes[30],
            target_bytes[31],
        ]);

        // Simplified calculation for demonstration
        // Real implementation would use proper 256-bit arithmetic
        let mut work = [0u8; 32];
        work[31] = 1; // Minimum work

        Ok(work)
    }

    /// Add two work values
    fn add_work(&self, a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
        let mut result = [0u8; 32];
        let mut carry = 0u16;

        for i in (0..32).rev() {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            result[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }

        Ok(result)
    }

    /// Compare two work values
    fn compare_work(&self, a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
        for i in 0..32 {
            if a[i] != b[i] {
                return a[i].cmp(&b[i]);
            }
        }
        std::cmp::Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_block_index_genesis() {
        let index = BlockIndex::new();
        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin);

        index.add_genesis(&genesis).unwrap();

        assert_eq!(index.best_height(), 0);
        assert_eq!(index.best_tip(), Some(genesis.block_hash()));

        let entry = index.get(&genesis.block_hash()).unwrap();
        assert!(entry.status.in_main_chain);
        assert!(entry.status.validated);
        assert_eq!(entry.height, Some(0));
    }
}
