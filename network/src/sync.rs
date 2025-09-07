use anyhow::{bail, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::{Block, BlockHash, Target, Work};
use bitcoin::hashes::Hash;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Synchronization state
#[derive(Debug, Clone, PartialEq)]
pub enum SyncState {
    Idle,
    Headers,
    Blocks,
    Synced,
}

/// Synchronization statistics
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncStats {
    pub headers_downloaded: usize,
    pub blocks_downloaded: usize,
    pub current_height: u32,
    pub target_height: u32,
}

/// Header download batch size
const HEADERS_BATCH_SIZE: usize = 2000;

/// Maximum time difference allowed (2 hours)
const MAX_TIME_DRIFT: u32 = 2 * 60 * 60;

/// Manages blockchain synchronization
pub struct SyncManager {
    state: Arc<RwLock<SyncState>>,
    stats: Arc<RwLock<SyncStats>>,
    chain: Arc<bitcoin_core_lib::chain::ChainManager>,
    /// Headers waiting to be validated
    header_queue: Arc<RwLock<VecDeque<BlockHeader>>>,
    /// Map of block hash to header for quick lookups
    header_index: Arc<RwLock<HashMap<BlockHash, BlockHeader>>>,
    /// Blocks to download queue
    block_download_queue: Arc<RwLock<VecDeque<BlockHash>>>,
}

impl SyncManager {
    /// Create new sync manager
    pub fn new(chain: Arc<bitcoin_core_lib::chain::ChainManager>) -> Self {
        Self {
            state: Arc::new(RwLock::new(SyncState::Idle)),
            stats: Arc::new(RwLock::new(SyncStats::default())),
            chain,
            header_queue: Arc::new(RwLock::new(VecDeque::new())),
            header_index: Arc::new(RwLock::new(HashMap::new())),
            block_download_queue: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Get current state
    pub async fn state(&self) -> SyncState {
        self.state.read().await.clone()
    }

    /// Get statistics
    pub async fn stats(&self) -> SyncStats {
        self.stats.read().await.clone()
    }

    /// Get chain manager reference
    pub fn chain(&self) -> Arc<bitcoin_core_lib::chain::ChainManager> {
        self.chain.clone()
    }

    /// Validate a header against the previous header
    fn validate_header(&self, header: &BlockHeader, prev_header: Option<&BlockHeader>) -> Result<()> {
        // Check timestamp
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        
        if header.time > current_time + MAX_TIME_DRIFT {
            bail!("Header timestamp too far in the future");
        }
        
        // If we have a previous header, validate continuity
        if let Some(prev) = prev_header {
            if header.prev_blockhash != prev.block_hash() {
                bail!("Header does not connect to previous header");
            }
            
            // Check timestamp is after previous block
            if header.time <= prev.time {
                bail!("Header timestamp not greater than previous");
            }
        }
        
        // Validate proof of work
        let target = header.target();
        let hash = header.block_hash();
        let hash_value = Target::from_le_bytes(hash.to_byte_array());
        
        if hash_value > target {
            bail!("Header does not meet proof-of-work requirement");
        }
        
        Ok(())
    }
    
    /// Process headers with full validation
    pub async fn process_headers(&self, headers: Vec<BlockHeader>) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        tracing::info!("Processing {} headers", headers.len());
        
        let mut stats = self.stats.write().await;
        let mut header_index = self.header_index.write().await;
        let mut block_queue = self.block_download_queue.write().await;
        
        let mut prev_header: Option<BlockHeader> = None;
        let mut accepted_headers = Vec::new();
        
        for header in headers {
            // Validate header
            if let Err(e) = self.validate_header(&header, prev_header.as_ref()) {
                tracing::warn!("Header validation failed: {}", e);
                break; // Stop processing on first invalid header
            }
            
            let hash = header.block_hash();
            
            // Check if we already have this header
            if header_index.contains_key(&hash) {
                tracing::debug!("Header {} already known, skipping", hash);
                prev_header = Some(header);
                continue;
            }
            
            // Add to index
            header_index.insert(hash, header.clone());
            accepted_headers.push(hash);
            
            // Add to block download queue
            block_queue.push_back(hash);
            
            prev_header = Some(header);
            stats.headers_downloaded += 1;
        }
        
        if !accepted_headers.is_empty() {
            stats.current_height += accepted_headers.len() as u32;
            
            tracing::info!(
                "Accepted {} new headers, current height: {}",
                accepted_headers.len(),
                stats.current_height
            );
            
            // Schedule block downloads for the new headers
            if block_queue.len() > 0 {
                tracing::info!("Queued {} blocks for download", block_queue.len());
            }
        }

        // Update sync state if we're actively syncing
        if *self.state.read().await == SyncState::Headers {
            if stats.current_height >= stats.target_height {
                *self.state.write().await = SyncState::Blocks;
                tracing::info!("Headers sync complete, switching to blocks sync");
            }
        }

        Ok(())
    }

    /// Process block
    pub async fn process_block(&self, block: Block) -> Result<()> {
        let mut stats = self.stats.write().await;
        stats.blocks_downloaded += 1;

        // Log block processing
        let block_hash = block.block_hash();
        let block_height = stats.current_height;
        
        tracing::info!(
            "Processing block {} at height {}",
            block_hash,
            block_height
        );

        // In a complete implementation, we would:
        // 1. Validate the block (merkle root, transactions, etc.)
        // 2. Process block via chain.process_block(block)
        // 3. Update UTXO set
        // 4. Update chain tip if this extends the best chain
        // 5. Relay block to peers
        
        // For now, just track that we received it
        tracing::debug!(
            "Block {} contains {} transactions",
            block_hash,
            block.txdata.len()
        );

        Ok(())
    }

    /// Generate header locator for requesting headers from peer
    pub async fn get_header_locator(&self) -> Vec<BlockHash> {
        let mut locator = Vec::new();
        let header_index = self.header_index.read().await;
        let stats = self.stats.read().await;
        
        // Start from current height and work backwards exponentially
        let mut step = 1;
        let mut height = stats.current_height;
        
        while height > 0 && locator.len() < 10 {
            // In a real implementation, we'd get the hash at this height
            // For now, we'll use the genesis hash as a placeholder
            let genesis = BlockHash::from_slice(&[0; 32]).unwrap();
            locator.push(genesis);
            
            height = height.saturating_sub(step);
            step *= 2; // Exponential backoff
        }
        
        // Always include genesis
        if locator.is_empty() || height > 0 {
            let genesis = BlockHash::from_slice(&[0; 32]).unwrap();
            locator.push(genesis);
        }
        
        locator
    }
    
    /// Get next blocks to download
    pub async fn get_blocks_to_download(&self, limit: usize) -> Vec<BlockHash> {
        let mut queue = self.block_download_queue.write().await;
        let mut blocks = Vec::new();
        
        for _ in 0..limit {
            if let Some(hash) = queue.pop_front() {
                blocks.push(hash);
            } else {
                break;
            }
        }
        
        blocks
    }
    
    /// Mark block as downloaded
    pub async fn mark_block_downloaded(&self, hash: &BlockHash) -> Result<()> {
        let header_index = self.header_index.read().await;
        
        if !header_index.contains_key(hash) {
            bail!("Unknown block hash: {}", hash);
        }
        
        let mut stats = self.stats.write().await;
        stats.blocks_downloaded += 1;
        
        // Check if we've downloaded all blocks
        if stats.blocks_downloaded >= stats.headers_downloaded {
            *self.state.write().await = SyncState::Synced;
            tracing::info!("Blockchain fully synchronized!");
        }
        
        Ok(())
    }
    
    /// Check if we need more headers
    pub async fn needs_headers(&self) -> bool {
        let stats = self.stats.read().await;
        let state = self.state.read().await;
        
        *state == SyncState::Headers && stats.current_height < stats.target_height
    }
    
    /// Check if we need to download blocks
    pub async fn needs_blocks(&self) -> bool {
        let queue = self.block_download_queue.read().await;
        !queue.is_empty()
    }
    
    /// Update peer information (height and best block)
    pub async fn update_peer_info(
        &self,
        peer_addr: std::net::SocketAddr,
        height: u32,
        best_hash: bitcoin::BlockHash,
    ) {
        let mut stats = self.stats.write().await;

        // Update target height if this peer has more blocks
        if height > stats.target_height {
            stats.target_height = height;
            tracing::info!(
                "Updated target height to {} from peer {}",
                height,
                peer_addr
            );
        }

        // Update state if we're idle and peer has blocks we don't
        if *self.state.read().await == SyncState::Idle && height > stats.current_height {
            *self.state.write().await = SyncState::Headers;
            tracing::info!(
                "Starting synchronization, peer {} is at height {}",
                peer_addr,
                height
            );
        }
    }
}
