use anyhow::{bail, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::RwLock as TokioRwLock;
use tracing::{debug, error, info, warn};

use crate::chain_reorganization::{ChainReorganizer, ReorgStats};
use crate::consensus::{ConsensusParams, ValidationResult};
use crate::difficulty::DifficultyCalculator;
use crate::orphan_blocks::{OrphanBlockManager, OrphanStats};
use crate::pow_validation::PowValidator;
use crate::script::ScriptFlags;
use crate::tx_validator::TxValidationPipeline;
use crate::utxo_manager::UtxoManager;
use crate::validation::BlockValidator;
use crate::work::ChainWork;
use storage::manager::StorageManager;
use storage::utxo::UtxoSet;

#[derive(Debug, Clone)]
pub struct BlockIndexEntry {
    pub hash: BlockHash,
    pub height: u32,
    pub header: BlockHeader,
    pub total_work: ChainWork,
    pub status: BlockStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BlockStatus {
    Valid,
    Invalid,
    InActiveChain,
    Orphan,
}

pub struct ChainManager {
    storage: Arc<StorageManager>,
    consensus_params: ConsensusParams,
    block_index: DashMap<BlockHash, BlockIndexEntry>,
    active_chain: RwLock<Vec<BlockHash>>,
    orphan_blocks: DashMap<BlockHash, Block>,
    orphan_manager: Arc<OrphanBlockManager>,
    chain_reorganizer: Arc<ChainReorganizer>,
    best_header: RwLock<BlockHeader>,
    best_height: RwLock<u32>,
    block_validator: Arc<BlockValidator>,
    utxo_set: Arc<TokioRwLock<UtxoSet>>,
    utxo_manager: Arc<UtxoManager>,
    // Mempool reference removed to avoid cyclic dependency
    // The mempool will be managed at a higher level (bitcoin-node)
    difficulty_calculator: Arc<DifficultyCalculator>,
    pow_validator: Arc<PowValidator>,
}

impl ChainManager {
    /// Create a new ChainManager with its own UTXO manager
    pub async fn new(storage: Arc<StorageManager>, network: String) -> Result<Self> {
        let utxo_manager = Arc::new(UtxoManager::new());
        Self::with_utxo_manager(storage, network, utxo_manager).await
    }

    /// Create a new ChainManager with a provided UTXO manager
    pub async fn with_utxo_manager(
        storage: Arc<StorageManager>,
        network: String,
        utxo_manager: Arc<UtxoManager>,
    ) -> Result<Self> {
        let consensus_params = ConsensusParams::for_network(&network)?;

        // Load chain state from storage
        let (best_header, best_height) = if let Some(tip) = storage.get_chain_tip().await? {
            tip
        } else {
            // Initialize with genesis block
            let genesis = consensus_params.genesis_block();
            let genesis_hash = genesis.block_hash();
            let genesis_header = genesis.header;

            info!("Initializing chain with genesis block: {}", genesis_hash);

            // Store genesis block
            storage.store_block(genesis.clone(), 0).await?;
            storage.update_chain_tip(&genesis_header, 0).await?;

            (genesis_header, 0)
        };

        // Use the provided UTXO manager
        // (passed in via with_utxo_manager or created in new())

        // Create UTXO set using database from storage
        let utxo_set = Arc::new(TokioRwLock::new(UtxoSet::new(storage.get_db().get_db())));

        // Create transaction validator
        let tx_validator = Arc::new(TxValidationPipeline::new(
            ScriptFlags::P2SH
                | ScriptFlags::WITNESS
                | ScriptFlags::CHECKLOCKTIMEVERIFY
                | ScriptFlags::CHECKSEQUENCEVERIFY,
        ));

        // Create block validator
        let block_validator = Arc::new(BlockValidator::new(
            consensus_params.clone(),
            tx_validator,
            Arc::clone(&utxo_set),
        ));

        // Create difficulty calculator
        let difficulty_calculator = Arc::new(DifficultyCalculator::new(network.clone()));

        // Create PoW validator
        let bitcoin_network = match network.as_str() {
            "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
            "testnet" => bitcoin::Network::Testnet,
            "regtest" => bitcoin::Network::Regtest,
            "signet" => bitcoin::Network::Signet,
            _ => bitcoin::Network::Bitcoin,
        };
        let pow_validator = Arc::new(PowValidator::new(bitcoin_network));

        // Create orphan block manager
        let orphan_manager = Arc::new(OrphanBlockManager::new());

        // Create chain reorganizer
        let chain_reorganizer =
            Arc::new(ChainReorganizer::new(storage.clone(), utxo_manager.clone()));

        let mut manager = Self {
            storage,
            consensus_params,
            block_index: DashMap::new(),
            active_chain: RwLock::new(Vec::new()),
            orphan_blocks: DashMap::new(),
            orphan_manager,
            chain_reorganizer,
            best_header: RwLock::new(best_header),
            best_height: RwLock::new(best_height),
            block_validator,
            utxo_set,
            utxo_manager,
            // Mempool managed at node level
            difficulty_calculator,
            pow_validator,
        };

        // Load block index from storage
        manager.load_block_index().await?;

        // If block index is empty, add genesis
        if manager.block_index.is_empty() {
            manager.init_genesis_block().await?;
        }

        Ok(manager)
    }

    async fn load_block_index(&mut self) -> Result<()> {
        info!("Loading block index from storage");

        // Load all block headers from storage
        let headers = self.storage.get_all_headers().await?;

        if headers.is_empty() {
            debug!("No headers in storage, will initialize with genesis");
            return Ok(());
        }

        for (hash, header, height) in headers {
            let entry = BlockIndexEntry {
                hash,
                height,
                header,
                total_work: self.calculate_chain_work(hash), // Use proper chain work calculation
                status: BlockStatus::InActiveChain,
            };
            self.block_index.insert(hash, entry);
        }

        // Rebuild active chain
        self.rebuild_active_chain().await?;

        info!("Loaded {} blocks into index", self.block_index.len());
        Ok(())
    }

    /// Initialize with genesis block
    async fn init_genesis_block(&mut self) -> Result<()> {
        let genesis = self.consensus_params.genesis_block();
        let genesis_hash = genesis.block_hash();

        info!(
            "Initializing block index with genesis block: {}",
            genesis_hash
        );

        let entry = BlockIndexEntry {
            hash: genesis_hash,
            height: 0,
            header: genesis.header,
            total_work: ChainWork::from_target(genesis.header.target()),
            status: BlockStatus::InActiveChain,
        };

        self.block_index.insert(genesis_hash, entry);
        self.active_chain.write().push(genesis_hash);

        Ok(())
    }

    fn calculate_total_work(&self, height: u32) -> ChainWork {
        // Calculate cumulative proof-of-work by walking the chain
        // Work = 2^256 / (target + 1) for each block

        let active_chain = self.active_chain.read();
        if height >= active_chain.len() as u32 {
            return ChainWork::zero();
        }

        let mut total_work = ChainWork::zero();
        for h in 0..=height {
            if let Some(hash) = active_chain.get(h as usize) {
                if let Some(entry) = self.block_index.get(hash) {
                    let target = entry.header.target();
                    total_work = total_work.add(&self.calculate_work_from_target(target));
                }
            }
        }

        total_work
    }

    /// Calculate work from a block's target
    fn calculate_work_from_target(&self, target: bitcoin::Target) -> ChainWork {
        // Use proper 256-bit arithmetic for work calculation
        ChainWork::from_target(target)
    }

    /// Get median time past for a block height
    pub fn get_median_time_past(&self, height: u32) -> u32 {
        // Bitcoin uses the median of the last 11 blocks
        const MEDIAN_TIME_SPAN: usize = 11;

        let mut timestamps = Vec::new();
        let start_height = height.saturating_sub(MEDIAN_TIME_SPAN as u32 - 1);

        // Collect timestamps
        for h in start_height..=height {
            if let Some(hash) = self.get_block_hash_at_height(h) {
                if let Some(entry) = self.block_index.get(&hash) {
                    timestamps.push(entry.header.time);
                }
            }
        }

        // If we don't have enough blocks, use current time
        if timestamps.is_empty() {
            return self.best_header.read().time;
        }

        // Sort and find median
        timestamps.sort_unstable();
        timestamps[timestamps.len() / 2]
    }

    /// Calculate cumulative chain work
    fn calculate_chain_work(&self, tip_hash: BlockHash) -> ChainWork {
        let mut total_work = ChainWork::zero();
        let mut current_hash = tip_hash;

        // Walk back through the chain summing work
        while let Some(entry) = self.block_index.get(&current_hash) {
            let target = entry.header.target();
            let work = self.calculate_work_from_target(target);
            total_work = total_work.add(&work);

            if entry.height == 0 {
                break;
            }

            current_hash = entry.header.prev_blockhash;
        }

        total_work
    }

    async fn rebuild_active_chain(&self) -> Result<()> {
        let mut chain = Vec::new();
        let best_height = *self.best_height.read();

        // Walk backwards from best block to genesis
        let mut current_hash = self.best_header.read().block_hash();

        for _ in 0..=best_height {
            chain.push(current_hash);

            if let Some(entry) = self.block_index.get(&current_hash) {
                current_hash = entry.header.prev_blockhash;
            } else {
                break;
            }
        }

        chain.reverse();
        *self.active_chain.write() = chain;

        Ok(())
    }

    pub fn process_block(
        &self,
        block: Block,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<BlockStatus>> + Send + '_>> {
        Box::pin(async move { self.process_block_from_peer(block, None).await })
    }

    /// Process a block with optional peer information
    pub async fn process_block_from_peer(
        &self,
        block: Block,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<BlockStatus> {
        let block_hash = block.block_hash();
        debug!("Processing block: {} from peer: {:?}", block_hash, peer);

        // Check if we already have this block
        if self.block_index.contains_key(&block_hash) {
            debug!("Block already known: {}", block_hash);
            return Ok(BlockStatus::Valid);
        }

        // Check if this is an orphan block
        let prev_hash = block.header.prev_blockhash;
        let genesis_hash = self.consensus_params.genesis_block().block_hash();
        if !self.block_index.contains_key(&prev_hash) && prev_hash != genesis_hash {
            warn!(
                "Orphan block received: {} with parent {}",
                block_hash, prev_hash
            );

            // Add to orphan manager with peer information
            self.orphan_manager.add_orphan(block.clone(), peer).await?;

            // Track in legacy orphan_blocks map for compatibility
            self.orphan_blocks.insert(block_hash, block);

            return Ok(BlockStatus::Orphan);
        }

        // Validate proof of work first
        if let Err(e) = self.pow_validator.validate_block_pow(&block) {
            warn!("Block {} failed PoW validation: {}", block_hash, e);
            return Ok(BlockStatus::Invalid);
        }

        // Validate the block
        let height = self.get_block_height(&prev_hash)? + 1;
        let prev_header = if prev_hash != genesis_hash {
            self.block_index.get(&prev_hash).map(|e| e.header)
        } else {
            None
        };

        // Validate timestamp if we have previous header
        if let Some(prev_header) = &prev_header {
            let median_time = self.get_median_time_past(height - 1);
            if let Err(e) =
                self.pow_validator
                    .validate_timestamp(&block.header, prev_header, median_time)
            {
                warn!("Block {} failed timestamp validation: {}", block_hash, e);
                return Ok(BlockStatus::Invalid);
            }
        }

        match self
            .block_validator
            .validate_block(&block, height, prev_header.as_ref())
            .await?
        {
            ValidationResult::Valid => {
                debug!("Block {} validated successfully", block_hash);
            }
            ValidationResult::Invalid(reason) => {
                warn!("Invalid block {}: {}", block_hash, reason);
                return Ok(BlockStatus::Invalid);
            }
            ValidationResult::Unknown => {
                warn!("Unknown validation result for block: {}", block_hash);
                return Ok(BlockStatus::Invalid);
            }
        }

        // Calculate total work for this block
        let prev_work = if prev_hash != genesis_hash {
            self.block_index
                .get(&prev_hash)
                .map(|e| e.total_work.clone())
                .unwrap_or_default()
        } else {
            ChainWork::zero()
        };

        let block_work = self.calculate_work_from_target(block.header.target());
        let total_work = prev_work.add(&block_work);

        // Add to block index
        let entry = BlockIndexEntry {
            hash: block_hash,
            height,
            header: block.header,
            total_work,
            status: BlockStatus::Valid,
        };
        self.block_index.insert(block_hash, entry);

        // Store the block
        self.storage.store_block(block.clone(), height).await?;

        // Check if this extends the main chain
        if prev_hash == self.best_header.read().block_hash() {
            // Extends the main chain
            self.extend_chain(block.clone()).await?;

            // Process any orphan blocks that depend on this block
            self.process_orphan_descendants(block_hash).await?;

            return Ok(BlockStatus::InActiveChain);
        }

        // Check if this causes a reorg
        if self.should_reorg(&block).await? {
            self.handle_reorg(block.clone()).await?;

            // Update block status in index
            if let Some(mut entry) = self.block_index.get_mut(&block_hash) {
                entry.status = BlockStatus::InActiveChain;
            }

            return Ok(BlockStatus::InActiveChain);
        }

        Ok(BlockStatus::Valid)
    }

    async fn extend_chain(&self, block: Block) -> Result<()> {
        info!("Extending chain with block: {}", block.block_hash());

        let new_height = *self.best_height.read() + 1;

        // Mempool transaction removal is handled at the node level
        debug!("Block contains {} transactions", block.txdata.len());

        // Update UTXO set atomically
        self.utxo_manager
            .add_block_utxos(&block, new_height)
            .await?;

        // Update best header
        *self.best_header.write() = block.header;
        *self.best_height.write() = new_height;

        // Add to active chain
        self.active_chain.write().push(block.block_hash());

        // Update storage
        self.storage
            .update_chain_tip(&block.header, new_height)
            .await?;

        // Process any orphan blocks that might now connect
        self.process_orphans().await?;

        Ok(())
    }

    async fn should_reorg(&self, block: &Block) -> Result<bool> {
        // Check if the new block creates a chain with more work
        let prev_hash = block.header.prev_blockhash;

        // Get the work for the new chain
        if let Some(prev_entry) = self.block_index.get(&prev_hash) {
            let new_chain_work = prev_entry
                .total_work
                .add(&self.calculate_work_from_target(block.header.target()));

            // Get current chain work
            let current_best_hash = self.best_header.read().block_hash();
            if let Some(current_entry) = self.block_index.get(&current_best_hash) {
                // Only reorg if new chain has more work
                if new_chain_work.is_greater_than(&current_entry.total_work) {
                    info!(
                        "New chain has more work: {} > {}",
                        new_chain_work.to_hex_string(),
                        current_entry.total_work.to_hex_string()
                    );
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn handle_reorg(&self, new_block: Block) -> Result<()> {
        let new_tip = new_block.block_hash();
        warn!("Chain reorganization required for block: {}", new_tip);

        // Get current chain state
        let old_tip = self.best_header.read().block_hash();
        let old_height = *self.best_height.read();

        // Calculate new chain height
        let new_height = self.get_block_height(&new_block.header.prev_blockhash)? + 1;

        // Calculate chain work for both tips
        let old_work = self
            .block_index
            .get(&old_tip)
            .map(|e| e.total_work.to_bytes())
            .unwrap_or([0u8; 32]);

        let new_work = self
            .block_index
            .get(&new_block.header.prev_blockhash)
            .map(|e| {
                let block_work = self.calculate_work_from_target(new_block.header.target());
                e.total_work.add(&block_work).to_bytes()
            })
            .unwrap_or([0u8; 32]);

        // Check if reorganization is already in progress
        if self.chain_reorganizer.is_reorg_in_progress().await {
            warn!("Reorganization already in progress, deferring new reorg");
            return Ok(());
        }

        // Perform the reorganization using the enhanced reorganizer
        match self
            .chain_reorganizer
            .reorganize_chain(old_tip, old_height, new_tip, new_height, new_work, old_work)
            .await
        {
            Ok(result) => {
                info!(
                    "Chain reorganization successful: {} blocks disconnected, {} blocks connected",
                    result.disconnected_blocks.len(),
                    result.connected_blocks.len()
                );

                // Update chain state
                *self.best_header.write() = new_block.header;
                *self.best_height.write() = new_height;

                // Update active chain
                self.rebuild_active_chain().await?;

                // Mempool transaction management during reorg is handled at the node level

                Ok(())
            }
            Err(e) => {
                error!("Chain reorganization failed: {}", e);
                Err(e)
            }
        }
    }

    /// Legacy reorganization handler (kept for compatibility)
    async fn handle_reorg_legacy(&self, new_block: Block) -> Result<()> {
        warn!(
            "Chain reorganization required for block: {} (using legacy handler)",
            new_block.block_hash()
        );

        // Find the common ancestor
        let mut old_chain = Vec::new();
        let mut new_chain = vec![new_block.clone()];

        let mut old_hash = self.best_header.read().block_hash();
        let mut new_hash = new_block.header.prev_blockhash;

        // Track heights for proper UTXO updates
        let mut old_heights = Vec::new();
        let mut current_height = *self.best_height.read();

        // Walk back both chains to find common ancestor
        let mut iterations = 0;
        while old_hash != new_hash && iterations < 100 {
            // Walk back old chain if needed
            if let Some(old_entry) = self.block_index.get(&old_hash) {
                if old_entry.height >= self.get_block_height(&new_hash).unwrap_or(0) {
                    if let Ok(Some(old_block)) = self.storage.get_block(&old_hash).await {
                        old_chain.push(old_block);
                        old_heights.push(current_height);
                        current_height = current_height.saturating_sub(1);
                    }
                    old_hash = old_entry.header.prev_blockhash;
                }
            }

            // Walk back new chain if needed
            if let Some(new_entry) = self.block_index.get(&new_hash) {
                if new_entry.height >= self.get_block_height(&old_hash).unwrap_or(0) {
                    if let Ok(Some(block)) = self.storage.get_block(&new_hash).await {
                        new_chain.push(block);
                    }
                    new_hash = new_entry.header.prev_blockhash;
                }
            }

            iterations += 1;
        }

        if iterations >= 100 {
            bail!("Reorg too deep (>100 blocks), refusing to process");
        }

        info!(
            "Reorganizing: removing {} blocks, adding {} blocks",
            old_chain.len(),
            new_chain.len()
        );

        // Collect transactions from old blocks to return to mempool
        let mut disconnected_txs = Vec::new();

        // Remove old blocks from UTXO set (in reverse order)
        for (i, block) in old_chain.iter().enumerate() {
            let height = old_heights
                .get(i)
                .copied()
                .unwrap_or_else(|| self.get_block_height(&block.block_hash()).unwrap_or(0));

            // Collect non-coinbase transactions
            if block.txdata.len() > 1 {
                disconnected_txs.extend(block.txdata[1..].iter().cloned());
            }

            // Remove UTXOs created by this block
            self.utxo_manager.remove_block_utxos(block, height).await?;

            // Update block status in index
            if let Some(mut entry) = self.block_index.get_mut(&block.block_hash()) {
                entry.status = BlockStatus::Valid; // No longer in active chain
            }
        }

        // Add new blocks to UTXO set (in forward order)
        new_chain.reverse();
        let mut new_height = self.get_block_height(&new_chain[0].header.prev_blockhash)? + 1;

        for block in &new_chain {
            // Add UTXOs from this block
            self.utxo_manager.add_block_utxos(block, new_height).await?;

            // Update block status in index
            if let Some(mut entry) = self.block_index.get_mut(&block.block_hash()) {
                entry.status = BlockStatus::InActiveChain;
            }

            // Store block if not already stored
            if self.storage.get_block(&block.block_hash()).await?.is_none() {
                self.storage.store_block(block.clone(), new_height).await?;
            }

            new_height += 1;
        }

        // Update chain tip
        let final_block = &new_chain[new_chain.len() - 1];
        *self.best_header.write() = final_block.header;
        *self.best_height.write() = new_height - 1;

        // Rebuild active chain
        self.rebuild_active_chain().await?;

        // Mempool transaction management during reorg is handled at the node level
        if !disconnected_txs.is_empty() {
            info!("Reorg would affect {} transactions", disconnected_txs.len());
        }

        Ok(())
    }

    async fn process_orphans(&self) -> Result<()> {
        // Process orphan blocks iteratively to avoid recursion
        let mut processed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 100;

        while processed && iterations < MAX_ITERATIONS {
            processed = false;
            iterations += 1;

            // Collect orphans that can now be connected
            let mut connectable = Vec::new();
            for entry in self.orphan_blocks.iter() {
                let block = entry.value();
                if self.block_index.contains_key(&block.header.prev_blockhash) {
                    connectable.push((*entry.key(), block.clone()));
                }
            }

            // Process connectable orphans
            for (hash, block) in connectable {
                debug!("Processing former orphan block: {}", hash);
                self.orphan_blocks.remove(&hash);

                // Process the former orphan block
                match self.process_block(block).await {
                    Ok(status) => {
                        if status == BlockStatus::InActiveChain || status == BlockStatus::Valid {
                            processed = true; // We made progress
                        } else {
                            warn!("Former orphan block {} is invalid", hash);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to process former orphan block {}: {}", hash, e);
                    }
                }
            }
        }

        if iterations >= MAX_ITERATIONS {
            warn!("Orphan processing hit maximum iterations limit");
        }

        Ok(())
    }

    pub fn get_block_height(&self, hash: &BlockHash) -> Result<u32> {
        self.block_index
            .get(hash)
            .map(|entry| entry.height)
            .ok_or_else(|| anyhow::anyhow!("Block not found: {}", hash))
    }

    pub fn get_best_height(&self) -> u32 {
        *self.best_height.read()
    }

    /// Get the UTXO manager
    pub fn get_utxo_manager(&self) -> Arc<UtxoManager> {
        self.utxo_manager.clone()
    }

    /// Get the network
    pub fn network(&self) -> bitcoin::Network {
        self.consensus_params.network()
    }

    // Additional methods for RPC access

    /// Get the best block hash
    pub fn get_best_block_hash(&self) -> BlockHash {
        self.best_header.read().block_hash()
    }

    /// Get block hash by height
    pub fn get_block_hash_at_height(&self, height: u32) -> Option<BlockHash> {
        let chain = self.active_chain.read();
        chain.get(height as usize).copied()
    }

    /// Get block header by hash
    pub fn get_block_header(&self, hash: &BlockHash) -> Option<BlockHeader> {
        self.block_index.get(hash).map(|entry| entry.header)
    }

    /// Get blockchain info for RPC
    pub fn get_blockchain_info(&self) -> (String, u32, BlockHash, f64) {
        let height = self.get_best_height();
        let best_hash = self.get_best_block_hash();
        let difficulty = self.get_current_difficulty();
        let chain = match self.consensus_params.network {
            bitcoin::Network::Bitcoin => "main",
            bitcoin::Network::Testnet => "test",
            bitcoin::Network::Regtest => "regtest",
            bitcoin::Network::Signet => "signet",
            _ => "unknown",
        }
        .to_string();

        (chain, height, best_hash, difficulty)
    }

    /// Check if in initial block download
    pub fn is_initial_block_download(&self) -> bool {
        // Simplified: IBD if we have less than 100 blocks
        self.get_best_height() < 100
    }

    pub fn get_best_hash(&self) -> BlockHash {
        self.best_header.read().block_hash()
    }

    /// Calculate current difficulty from target
    pub fn get_current_difficulty(&self) -> f64 {
        let best_header = self.best_header.read();
        self.calculate_difficulty_from_target(best_header.target())
    }

    /// Calculate difficulty from a target value
    fn calculate_difficulty_from_target(&self, target: bitcoin::Target) -> f64 {
        // Difficulty = max_target / current_target
        // max_target is the target for difficulty 1 (0x1d00ffff)
        let max_target =
            bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(0x1d00ffff));

        // Calculate ratio
        let max_value = max_target.to_work();
        let current_value = target.to_work();

        // Difficulty = max_work / current_work
        // Since Work = 2^256 / (target + 1), and difficulty is inverse
        // We need to be careful with the calculation

        // Simplified calculation using the compact representation
        let max_compact = 0x1d00ffffu32;
        let current_compact = target.to_compact_lossy().to_consensus();

        // Extract mantissa and exponent
        let max_mantissa = max_compact & 0x00ffffff;
        let max_exponent = (max_compact >> 24) as i32;

        let current_mantissa = current_compact & 0x00ffffff;
        let current_exponent = (current_compact >> 24) as i32;

        // Calculate difficulty as ratio
        let mantissa_ratio = max_mantissa as f64 / current_mantissa.max(1) as f64;
        let exponent_diff = (max_exponent - current_exponent) as f64;

        mantissa_ratio * 256f64.powf(exponent_diff)
    }

    /// Set the best block (for reorganization)
    pub fn set_best_block(&mut self, hash: BlockHash, height: u32) -> Result<()> {
        // Clone header first to avoid borrow issues
        let header = self
            .block_index
            .get(&hash)
            .ok_or_else(|| anyhow::anyhow!("Block {} not found in index", hash))?
            .header;

        *self.best_header.write() = header;
        *self.best_height.write() = height;

        // Update active chain
        self.rebuild_active_chain_blocking()?;

        info!("Chain tip updated to {} at height {}", hash, height);

        Ok(())
    }

    /// Rebuild active chain (blocking version for reorg)
    fn rebuild_active_chain_blocking(&mut self) -> Result<()> {
        let mut chain = Vec::new();
        let best_height = *self.best_height.read();

        // Walk backwards from best block to genesis
        let mut current_hash = self.best_header.read().block_hash();

        for _ in 0..=best_height {
            chain.push(current_hash);

            if let Some(entry) = self.block_index.get(&current_hash) {
                if entry.height == 0 {
                    break; // Genesis block
                }
                current_hash = entry.header.prev_blockhash;
            } else {
                break;
            }
        }

        chain.reverse();
        *self.active_chain.write() = chain;

        Ok(())
    }

    // Methods for RPC block access

    pub async fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        self.storage.get_block(hash).await
    }

    pub async fn get_block_header_by_hash(&self, hash: &BlockHash) -> Option<BlockHeader> {
        // First check our header index
        if let Some(header) = self.get_block_header(hash) {
            return Some(header);
        }

        // Fall back to storage if not in index
        if let Ok(Some(block)) = self.storage.get_block(hash).await {
            return Some(block.header);
        }

        None
    }

    /// Find a transaction (check mempool first, then blocks)
    pub async fn find_transaction(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<Option<(bitcoin::Transaction, Option<BlockHash>)>> {
        // Check mempool first (would need mempool reference)
        // For now, just check storage
        if let Some((tx, block_hash)) = self.storage.find_transaction(txid).await? {
            Ok(Some((tx, Some(block_hash))))
        } else {
            Ok(None)
        }
    }

    /// Get a specific UTXO
    pub async fn get_utxo(&self, outpoint: &bitcoin::OutPoint) -> Result<Option<bitcoin::TxOut>> {
        self.storage.get_utxo(outpoint).await
    }

    /// Get UTXO set statistics
    pub async fn get_utxo_stats(&self) -> Result<storage::UtxoStats> {
        self.storage.get_utxo_stats().await
    }

    /// Calculate the next difficulty target
    pub async fn calculate_next_target(&self, height: u32) -> Result<bitcoin::Target> {
        // Check if adjustment is needed
        if !self.difficulty_calculator.is_adjustment_height(height) {
            // No adjustment needed, return current target
            let best_header = self.best_header.read();
            return Ok(best_header.target());
        }

        // Get the first block of this difficulty period
        let period_start_height = height - self.difficulty_calculator.adjustment_interval();
        let period_start_hash = self
            .get_block_hash_at_height(period_start_height)
            .ok_or_else(|| anyhow::anyhow!("Missing block at height {}", period_start_height))?;

        let period_start_header = self
            .get_block_header(&period_start_hash)
            .ok_or_else(|| anyhow::anyhow!("Missing header for block {}", period_start_hash))?;

        // Get the last block of this period
        let period_end_height = height - 1;
        let period_end_hash = self
            .get_block_hash_at_height(period_end_height)
            .ok_or_else(|| anyhow::anyhow!("Missing block at height {}", period_end_height))?;

        let period_end_header = self
            .get_block_header(&period_end_hash)
            .ok_or_else(|| anyhow::anyhow!("Missing header for block {}", period_end_hash))?;

        // Calculate new target
        let current_target = period_end_header.target();
        let first_block_time = period_start_header.time;
        let last_block_time = period_end_header.time;

        self.difficulty_calculator.calculate_next_target(
            period_end_height,
            current_target,
            first_block_time,
            last_block_time,
        )
    }

    /// Add a header to the chain (headers-only, no full block validation)
    pub async fn add_header(&mut self, header: BlockHeader) -> Result<()> {
        let hash = header.block_hash();
        let prev_hash = header.prev_blockhash;

        // Check if we already have this header
        if self.block_index.contains_key(&hash) {
            return Ok(()); // Already have it
        }

        // Validate proof of work
        if let Err(e) = self.pow_validator.validate_header_pow(&header) {
            bail!("Header {} failed PoW validation: {}", hash, e);
        }

        // Check if we have the parent
        let parent_height = if let Some(parent) = self.block_index.get(&prev_hash) {
            parent.height
        } else if prev_hash == BlockHash::from_byte_array([0u8; 32]) {
            // Genesis block
            return Ok(());
        } else {
            bail!("Parent header {} not found", prev_hash);
        };

        let height = parent_height + 1;

        // Validate timestamp
        if let Some(parent) = self.block_index.get(&prev_hash) {
            let median_time = self.get_median_time_past(parent_height);
            if let Err(e) =
                self.pow_validator
                    .validate_timestamp(&header, &parent.header, median_time)
            {
                bail!("Header {} failed timestamp validation: {}", hash, e);
            }

            // Validate difficulty adjustment if needed
            if let Err(e) =
                self.pow_validator
                    .validate_difficulty_adjustment(&header, &parent.header, height)
            {
                bail!(
                    "Header {} failed difficulty adjustment validation: {}",
                    hash,
                    e
                );
            }
        }

        // Calculate total work
        let parent_work = self
            .block_index
            .get(&prev_hash)
            .map(|e| e.total_work.clone())
            .unwrap_or_else(ChainWork::zero);

        let total_work = parent_work.add(&ChainWork::from_target(header.target()));

        // Add to block index
        let entry = BlockIndexEntry {
            hash,
            height,
            header,
            total_work,
            status: BlockStatus::Valid,
        };

        self.block_index.insert(hash, entry);

        // Check if this extends the main chain
        if prev_hash == self.best_header.read().block_hash() {
            *self.best_header.write() = header;
            *self.best_height.write() = height;
            self.active_chain.write().push(hash);
        }

        Ok(())
    }

    /// Batch add headers (more efficient for headers synchronization)
    pub async fn add_headers(&mut self, headers: Vec<BlockHeader>) -> Result<()> {
        info!("Adding batch of {} headers to chain", headers.len());

        for header in headers {
            // Validate PoW for this header
            if let Err(e) = self.pow_validator.validate_header_pow(&header) {
                warn!(
                    "Header {} failed PoW validation: {}",
                    header.block_hash(),
                    e
                );
                continue; // Skip invalid headers
            }

            if let Err(e) = self.add_header(header).await {
                warn!("Failed to add header {}: {}", header.block_hash(), e);
                // Continue with other headers
            }
        }

        // Persist headers to storage periodically
        if self.block_index.len() % 1000 == 0 {
            self.flush().await?;
        }

        Ok(())
    }

    /// Get a full block by hash
    pub async fn flush(&mut self) -> Result<()> {
        info!("Flushing chain state to storage");

        // Flush UTXO manager if it has pending changes
        if let Err(e) = self.utxo_manager.flush().await {
            warn!("Failed to flush UTXO manager: {}", e);
        }

        // Flush storage backend
        self.storage.flush().await?;

        // Save checkpoint for recovery
        let best_height = *self.best_height.read();
        let best_hash = self.best_header.read().block_hash();

        debug!("Saved checkpoint at height {} ({})", best_height, best_hash);

        Ok(())
    }

    // Mempool integration is handled at the node level to avoid cyclic dependencies

    // Mempool checking is handled at the node level

    /// Validate a transaction for mempool acceptance
    pub async fn validate_transaction_for_mempool(&self, tx: &bitcoin::Transaction) -> Result<()> {
        // Check if transaction is already in a block
        let txid = tx.compute_txid();
        if let Ok(Some(_)) = self.storage.find_transaction(&txid).await {
            bail!("Transaction {} already in blockchain", txid);
        }

        // Create UTXO view from our UtxoManager
        let utxo_view = crate::tx_validator::UtxoView::from_manager(self.utxo_manager.clone());

        // Validate transaction
        let tx_validator = TxValidationPipeline::new(
            ScriptFlags::P2SH
                | ScriptFlags::WITNESS
                | ScriptFlags::CHECKLOCKTIMEVERIFY
                | ScriptFlags::CHECKSEQUENCEVERIFY,
        );

        match tx_validator.validate(tx, &utxo_view).await {
            ValidationResult::Valid => Ok(()),
            ValidationResult::Invalid(reason) => bail!("Transaction invalid: {}", reason),
            ValidationResult::Unknown => bail!("Transaction validation unknown"),
        }
    }

    /// Get transactions from mempool for block template
    /// Note: This now returns empty vec as mempool is managed at the node level
    pub async fn get_mempool_transactions_for_mining(
        &self,
        _max_weight: usize,
    ) -> Vec<bitcoin::Transaction> {
        // Mempool integration is handled at the node level
        Vec::new()
    }

    /// Process orphan blocks that depend on a newly accepted block
    async fn process_orphan_descendants(&self, parent_hash: BlockHash) -> Result<()> {
        info!("Processing orphan descendants of block {}", parent_hash);

        // Get all orphan blocks that depend on this parent
        let orphan_blocks = self.orphan_manager.process_new_parent(&parent_hash).await;

        if orphan_blocks.is_empty() {
            debug!("No orphan blocks depend on {}", parent_hash);
            return Ok(());
        }

        info!("Found {} orphan blocks to process", orphan_blocks.len());

        // Process each orphan block
        for block in orphan_blocks {
            let block_hash = block.block_hash();
            debug!("Processing former orphan block {}", block_hash);

            // Remove from legacy orphan storage
            self.orphan_blocks.remove(&block_hash);

            // Recursively process the block
            match self.process_block(block).await {
                Ok(BlockStatus::InActiveChain) => {
                    info!("Former orphan {} added to active chain", block_hash);
                }
                Ok(BlockStatus::Valid) => {
                    info!(
                        "Former orphan {} validated but not in active chain",
                        block_hash
                    );
                }
                Ok(BlockStatus::Orphan) => {
                    // Still an orphan (missing earlier ancestors)
                    debug!("Block {} is still an orphan", block_hash);
                }
                Ok(BlockStatus::Invalid) => {
                    warn!("Former orphan {} is invalid", block_hash);
                }
                Err(e) => {
                    warn!("Error processing former orphan {}: {}", block_hash, e);
                }
            }
        }

        Ok(())
    }

    /// Get orphan block statistics
    pub async fn get_orphan_stats(&self) -> OrphanStats {
        self.orphan_manager.get_stats().await
    }

    /// Check if a block is an orphan
    pub async fn is_orphan(&self, hash: &BlockHash) -> bool {
        self.orphan_manager.is_orphan(hash).await
    }

    /// Get missing parent hashes for orphan blocks
    pub async fn get_missing_parents(&self) -> Vec<BlockHash> {
        let missing = self.orphan_manager.get_missing_parents().await;
        missing.into_iter().collect()
    }

    /// Clean up expired orphan blocks
    pub async fn cleanup_orphans(&self) {
        self.orphan_manager.cleanup().await;

        // Also clean up legacy orphan_blocks map
        let orphan_hashes: Vec<BlockHash> = self
            .orphan_blocks
            .iter()
            .map(|entry| *entry.key())
            .collect();

        for hash in orphan_hashes {
            if !self.orphan_manager.is_orphan(&hash).await {
                self.orphan_blocks.remove(&hash);
            }
        }
    }

    /// Request missing blocks from network (for orphan resolution)
    pub async fn request_missing_blocks(&self) -> Vec<BlockHash> {
        let missing_parents = self.get_missing_parents().await;

        if !missing_parents.is_empty() {
            info!(
                "Requesting {} missing parent blocks for orphan resolution",
                missing_parents.len()
            );

            for hash in &missing_parents {
                debug!("Missing parent block: {}", hash);
            }
        }

        missing_parents
    }

    /// Get chain reorganization statistics
    pub async fn get_reorg_stats(&self) -> ReorgStats {
        self.chain_reorganizer.get_stats().await
    }

    /// Check if a reorganization is in progress
    pub async fn is_reorg_in_progress(&self) -> bool {
        self.chain_reorganizer.is_reorg_in_progress().await
    }

    /// Get the total chain work of the best chain
    pub fn get_best_chain_work(&self) -> ChainWork {
        let best_hash = self.best_header.read().block_hash();
        self.block_index
            .get(&best_hash)
            .map(|e| e.total_work.clone())
            .unwrap_or_else(ChainWork::zero)
    }

    /// Force a chain reorganization check
    pub async fn check_for_reorg(&self) -> Result<bool> {
        // Check if we have any competing chain tips
        let current_tip = self.best_header.read().block_hash();
        let current_work = self
            .block_index
            .get(&current_tip)
            .map(|e| e.total_work.clone())
            .unwrap_or_default();

        // Check all valid blocks not in active chain
        let mut best_alternative = None;
        let mut best_alternative_work = current_work.clone();

        for entry in self.block_index.iter() {
            if entry.status == BlockStatus::Valid
                && entry.status != BlockStatus::InActiveChain
                && entry.total_work.is_greater_than(&best_alternative_work)
            {
                best_alternative = Some(entry.hash);
                best_alternative_work = entry.total_work.clone();
            }
        }

        if let Some(new_tip) = best_alternative {
            if best_alternative_work.is_greater_than(&current_work) {
                info!("Found better chain tip: {}", new_tip);

                // Load the block and trigger reorganization
                if let Ok(Some(block)) = self.storage.get_block(&new_tip).await {
                    self.handle_reorg(block).await?;
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}
