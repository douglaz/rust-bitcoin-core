use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, Network};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::headers_sync::HeadersValidator;
use bitcoin_core_lib::chain::ChainManager;
use network::{NetworkManager, SyncHandler};

type PeerId = SocketAddr; // Use socket address as peer ID

/// Synchronization state machine
#[derive(Debug, Clone, PartialEq)]
pub enum SyncState {
    /// Not syncing
    Idle,
    /// Downloading headers
    Headers,
    /// Downloading blocks
    Blocks,
    /// Fully synchronized
    Synced,
}

/// Block download window size
const BLOCK_DOWNLOAD_WINDOW: usize = 1024;
/// Maximum blocks in flight per peer
const MAX_BLOCKS_IN_FLIGHT_PER_PEER: usize = 16;
/// Timeout for block requests
const BLOCK_TIMEOUT: Duration = Duration::from_secs(60);

/// Initial Block Download (IBD) manager
#[derive(Clone)]
pub struct SyncManager {
    chain: Arc<RwLock<ChainManager>>,
    network: Arc<tokio::sync::Mutex<NetworkManager>>,
    state: Arc<RwLock<SyncState>>,
    headers_validator: Arc<HeadersValidator>,

    // Headers sync state
    headers_queue: Arc<RwLock<VecDeque<BlockHeader>>>,
    last_header_time: Arc<RwLock<Instant>>,

    // Block download state
    blocks_in_flight: Arc<RwLock<HashMap<BlockHash, BlockRequest>>>,
    block_queue: Arc<RwLock<VecDeque<Block>>>,
    download_window_start: Arc<RwLock<u32>>,

    // Peer state
    peer_heights: Arc<RwLock<HashMap<PeerId, u32>>>,
    peer_best_hash: Arc<RwLock<HashMap<PeerId, BlockHash>>>,
}

#[derive(Debug, Clone)]
struct BlockRequest {
    peer_id: PeerId,
    hash: BlockHash,
    requested_at: Instant,
    height: u32,
}

impl SyncManager {
    /// Create a new sync manager
    pub fn new(
        chain: Arc<RwLock<ChainManager>>,
        network: Arc<tokio::sync::Mutex<NetworkManager>>,
    ) -> Self {
        Self {
            chain: chain.clone(),
            network,
            state: Arc::new(RwLock::new(SyncState::Idle)),
            headers_validator: Arc::new(HeadersValidator::new(Network::Bitcoin)),
            headers_queue: Arc::new(RwLock::new(VecDeque::new())),
            last_header_time: Arc::new(RwLock::new(Instant::now())),
            blocks_in_flight: Arc::new(RwLock::new(HashMap::new())),
            block_queue: Arc::new(RwLock::new(VecDeque::new())),
            download_window_start: Arc::new(RwLock::new(0)),
            peer_heights: Arc::new(RwLock::new(HashMap::new())),
            peer_best_hash: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start synchronization
    pub async fn start_sync(&self) -> Result<()> {
        info!("Starting blockchain synchronization");

        // Initialize peer heights from connected peers
        self.initialize_peer_heights().await?;

        // Check if we need to sync
        if !self.needs_sync().await? {
            info!("Chain is already synchronized");
            *self.state.write().await = SyncState::Synced;
            return Ok(());
        }

        // Start headers-first sync
        *self.state.write().await = SyncState::Headers;
        self.sync_headers().await?;

        // Then download blocks
        *self.state.write().await = SyncState::Blocks;
        self.sync_blocks().await?;

        // Mark as synced
        *self.state.write().await = SyncState::Synced;
        info!("Synchronization complete");

        Ok(())
    }

    /// Initialize peer heights from connected peers
    async fn initialize_peer_heights(&self) -> Result<()> {
        let peer_heights = self.network.lock().await.get_peer_heights().await;

        if peer_heights.is_empty() {
            warn!("No peer heights available yet, waiting for peers to connect");
            // Wait a bit for peers to connect and send version messages
            tokio::time::sleep(Duration::from_secs(5)).await;

            // Try again
            let peer_heights = self.network.lock().await.get_peer_heights().await;
            if peer_heights.is_empty() {
                return Err(anyhow::anyhow!("No peers available for synchronization"));
            }
        }

        for (peer_addr, height) in peer_heights {
            // Store peer height (converting i32 to u32, using 0 for negative values)
            let height_u32 = if height < 0 { 0 } else { height as u32 };
            self.peer_heights
                .write()
                .await
                .insert(peer_addr, height_u32);

            // Initialize with genesis block hash for now
            // TODO: Get actual best hash from peer
            let genesis_hash = BlockHash::from_byte_array([0u8; 32]);
            self.peer_best_hash
                .write()
                .await
                .insert(peer_addr, genesis_hash);

            info!("Peer {} reports height {}", peer_addr, height_u32);
        }

        info!(
            "Initialized {} peer heights",
            self.peer_heights.read().await.len()
        );
        Ok(())
    }

    /// Check if we need to synchronize
    async fn needs_sync(&self) -> Result<bool> {
        let chain = self.chain.read().await;
        let our_height = chain.get_best_height();

        // Get best height from peers
        let peer_heights = self.peer_heights.read().await;
        let best_peer_height = peer_heights.values().max().copied().unwrap_or(0);

        Ok(best_peer_height > our_height)
    }

    /// Synchronize headers
    async fn sync_headers(&self) -> Result<()> {
        info!("Starting headers synchronization");

        let mut last_height = {
            let chain = self.chain.read().await;
            chain.get_best_height()
        };

        let mut consecutive_failures = 0;
        const MAX_CONSECUTIVE_FAILURES: u32 = 5;

        loop {
            // Get best peer, try different peers on failure
            let peer_id = match self.get_best_peer().await {
                Ok(peer) => peer,
                Err(e) => {
                    warn!("Failed to get best peer: {}", e);
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            // Request headers with error handling
            let locator = match self.build_block_locator().await {
                Ok(loc) => loc,
                Err(e) => {
                    error!("Failed to build block locator: {}", e);
                    return Err(e);
                }
            };

            // Try to send getheaders, but don't fail immediately
            if let Err(e) = self.send_getheaders(peer_id, locator).await {
                warn!("Failed to send getheaders to {}: {}", peer_id, e);
                consecutive_failures += 1;

                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    error!("Too many consecutive failures in headers sync");
                    return Err(anyhow!(
                        "Headers sync failed after {} attempts",
                        MAX_CONSECUTIVE_FAILURES
                    ));
                }

                // Try with a different peer next time
                sleep(Duration::from_secs(1)).await;
                continue;
            }

            // Wait for headers
            let timeout = sleep(Duration::from_secs(30));
            tokio::pin!(timeout);

            tokio::select! {
                _ = &mut timeout => {
                    warn!("Headers request timed out");
                    continue;
                }
                _ = self.wait_for_headers() => {
                    let headers = self.process_headers_queue().await?;
                    if headers.is_empty() {
                        break; // No more headers
                    }

                    info!("Received {} headers", headers.len());

                    // Reset failure counter on successful receipt
                    consecutive_failures = 0;

                    // Validate headers
                    let prev_header = self.headers_validator.get_best_header().await;
                    if let Err(e) = self.headers_validator.validate_headers(&headers, prev_header.as_ref()).await {
                        warn!("Failed to validate headers: {}", e);
                        consecutive_failures += 1;
                        continue;
                    }

                    // Store validated headers in chain manager
                    {
                        let mut chain = self.chain.write().await;
                        if let Err(e) = chain.add_headers(headers.clone()).await {
                            warn!("Failed to store headers: {}", e);
                        }
                    }

                    // Update height
                    last_height = self.headers_validator.get_best_height().await;

                    // Check if we're caught up
                    let peer_heights = self.peer_heights.read().await;
                    let best_height = peer_heights.values().max().copied().unwrap_or(0);

                    if last_height >= best_height {
                        info!("Headers synchronized up to height {}", last_height);
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Synchronize blocks
    async fn sync_blocks(&self) -> Result<()> {
        info!("Starting block download");

        let start_height = {
            let chain = self.chain.read().await;
            chain.get_best_height() + 1
        };

        let target_height = {
            // Use the height from validated headers
            self.headers_validator.get_best_height().await
        };

        if start_height > target_height {
            info!("Already have all blocks up to height {}", target_height);
            return Ok(());
        }

        info!(
            "Downloading blocks from height {} to {}",
            start_height, target_height
        );

        *self.download_window_start.write().await = start_height;

        // Start parallel block download
        let mut current_height = start_height;
        let mut no_progress_count = 0;

        while current_height <= target_height {
            // Fill download window
            self.request_blocks(current_height, target_height).await?;

            // Process downloaded blocks
            let mut made_progress = false;
            while let Some(block) = self.get_next_block().await {
                // Process block
                self.process_block(block, current_height).await?;
                current_height += 1;
                made_progress = true;

                // Update download window
                *self.download_window_start.write().await = current_height;

                // Log progress periodically
                if current_height % 100 == 0 {
                    info!("Block sync progress: {}/{}", current_height, target_height);
                }
            }

            // Check for stalled downloads
            self.check_stalled_downloads().await?;

            // Track if we're making progress
            if !made_progress {
                no_progress_count += 1;
                if no_progress_count > 10 {
                    warn!("No progress in block download, may be stuck");
                    break;
                }
            } else {
                no_progress_count = 0;
            }

            // Small delay to prevent busy loop
            sleep(Duration::from_millis(100)).await;
        }

        info!("Block download complete at height {}", current_height - 1);
        Ok(())
    }

    /// Request blocks in parallel
    async fn request_blocks(&self, start: u32, end: u32) -> Result<()> {
        let mut in_flight = self.blocks_in_flight.write().await;

        // Calculate how many we can request
        let window_end = (start + BLOCK_DOWNLOAD_WINDOW as u32).min(end);
        let available = BLOCK_DOWNLOAD_WINDOW.saturating_sub(in_flight.len());

        if available == 0 {
            return Ok(());
        }

        // Get available peers
        let peers = self.get_available_peers().await?;
        if peers.is_empty() {
            return Ok(());
        }

        let mut height = start;
        let mut peer_index = 0;
        let mut requested = 0;

        while height <= window_end && requested < available {
            // Skip if already in flight
            let hash = self.get_block_hash_at_height(height).await?;
            if in_flight.contains_key(&hash) {
                height += 1;
                continue;
            }

            // Select peer round-robin
            let peer_id = peers[peer_index % peers.len()];

            // Create request
            let request = BlockRequest {
                peer_id,
                hash,
                requested_at: Instant::now(),
                height,
            };

            // Send request
            self.send_getdata_block(peer_id, hash).await?;

            // Track request
            in_flight.insert(hash, request);

            requested += 1;
            height += 1;
            peer_index += 1;
        }

        if requested > 0 {
            debug!("Requested {} blocks", requested);
        }

        Ok(())
    }

    /// Get next block from queue
    async fn get_next_block(&self) -> Option<Block> {
        let mut queue = self.block_queue.write().await;
        queue.pop_front()
    }

    /// Process a downloaded block
    async fn process_block(&self, block: Block, height: u32) -> Result<()> {
        let hash = block.block_hash();
        debug!("Processing block {} at height {}", hash, height);

        // Remove from in-flight
        self.blocks_in_flight.write().await.remove(&hash);

        // Connect block to chain
        let chain = self.chain.write().await;
        match chain.process_block(block.clone()).await {
            Ok(_) => {
                info!("Block {} connected at height {}", hash, height);

                // Update our tracking
                *self.download_window_start.write().await = height + 1;
            }
            Err(e) => {
                warn!(
                    "Failed to connect block {} at height {}: {}",
                    hash, height, e
                );
                // Block might be invalid or we're missing parent
                // In production, would handle different error cases
                return Err(e);
            }
        }

        Ok(())
    }

    /// Check for stalled downloads and retry
    async fn check_stalled_downloads(&self) -> Result<()> {
        let now = Instant::now();
        let mut in_flight = self.blocks_in_flight.write().await;
        let mut stalled = Vec::new();

        for (hash, request) in in_flight.iter() {
            if now.duration_since(request.requested_at) > BLOCK_TIMEOUT {
                warn!("Block request for {} timed out", hash);
                stalled.push(*hash);
            }
        }

        // Remove stalled requests
        for hash in stalled {
            in_flight.remove(&hash);
        }

        Ok(())
    }

    /// Get best peer for sync
    async fn get_best_peer(&self) -> Result<PeerId> {
        let peer_heights = self.peer_heights.read().await;

        peer_heights
            .iter()
            .max_by_key(|(_, height)| *height)
            .map(|(id, _)| *id)
            .ok_or_else(|| anyhow::anyhow!("No peers available"))
    }

    /// Get available peers for download
    async fn get_available_peers(&self) -> Result<Vec<PeerId>> {
        let peer_heights = self.peer_heights.read().await;
        let in_flight = self.blocks_in_flight.read().await;

        let mut peer_loads: HashMap<PeerId, usize> = HashMap::new();
        for request in in_flight.values() {
            *peer_loads.entry(request.peer_id).or_insert(0) += 1;
        }

        let mut available: Vec<PeerId> = peer_heights
            .keys()
            .filter(|id| peer_loads.get(id).copied().unwrap_or(0) < MAX_BLOCKS_IN_FLIGHT_PER_PEER)
            .copied()
            .collect();

        // Sort by load (least loaded first)
        available.sort_by_key(|id| peer_loads.get(id).copied().unwrap_or(0));

        Ok(available)
    }

    /// Build block locator for getheaders
    async fn build_block_locator(&self) -> Result<Vec<BlockHash>> {
        // Build block locator with exponential backoff
        let chain = self.chain.read().await;
        let mut locator = Vec::new();
        let tip_height = chain.get_best_height();
        let mut step = 1;
        let mut height = tip_height;

        // Add recent blocks
        for _ in 0..10 {
            if height == 0 {
                break;
            }
            if let Some(hash) = chain.get_block_hash_at_height(height) {
                locator.push(hash);
            }
            height = height.saturating_sub(1);
        }

        // Add exponentially spaced blocks
        while height > 0 {
            if let Some(hash) = chain.get_block_hash_at_height(height) {
                locator.push(hash);
            }
            height = height.saturating_sub(step);
            step *= 2;
        }

        // Always add genesis
        locator.push(self.get_genesis_hash().await?);

        Ok(locator)
    }

    /// Get genesis block hash for network
    async fn get_genesis_hash(&self) -> Result<BlockHash> {
        // Get genesis hash from height 0
        let chain = self.chain.read().await;
        chain
            .get_block_hash_at_height(0)
            .ok_or_else(|| anyhow::anyhow!("Genesis block not found"))
    }

    /// Get block hash at height
    async fn get_block_hash_at_height(&self, height: u32) -> Result<BlockHash> {
        // First check if we have the header for this height
        let headers = self
            .headers_validator
            .get_headers_after(height.saturating_sub(1))
            .await;
        if !headers.is_empty() && height > 0 {
            // We have the header, return its hash
            let idx = (height - 1) as usize;
            if idx < headers.len() {
                return Ok(headers[idx].block_hash());
            }
        }

        // Otherwise check the chain
        let chain = self.chain.read().await;
        chain
            .get_block_hash_at_height(height)
            .ok_or_else(|| anyhow::anyhow!("Block at height {} not found", height))
    }

    /// Check if a peer is still connected
    async fn is_peer_connected(&self, peer_id: PeerId) -> bool {
        // Check if peer exists in our peer heights map (indicates active connection)
        self.peer_heights.read().await.contains_key(&peer_id)
    }

    /// Send getheaders message with retry logic
    async fn send_getheaders(&self, peer_id: PeerId, locator: Vec<BlockHash>) -> Result<()> {
        // Check if peer is still connected
        if !self.is_peer_connected(peer_id).await {
            bail!("Peer {} is not connected", peer_id);
        }

        // Use the zero hash as stop_hash to get as many headers as possible
        let stop_hash = BlockHash::from_byte_array([0u8; 32]);

        // Try sending with retry logic
        let mut last_error = None;
        for attempt in 0..3 {
            match self
                .network
                .lock()
                .await
                .send_getheaders_to_peer(peer_id, locator.clone(), stop_hash)
                .await
            {
                Ok(_) => {
                    debug!(
                        "Successfully sent getheaders to {} on attempt {}",
                        peer_id,
                        attempt + 1
                    );
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "Failed to send getheaders to {} (attempt {}): {}",
                        peer_id,
                        attempt + 1,
                        e
                    );
                    last_error = Some(e);

                    // Check if peer disconnected
                    if !self.is_peer_connected(peer_id).await {
                        bail!("Peer {} disconnected during getheaders", peer_id);
                    }

                    // Wait before retry
                    if attempt < 2 {
                        sleep(Duration::from_millis(100 * (attempt + 1) as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("Failed to send getheaders after 3 attempts")))
    }

    /// Send getdata for block with retry logic
    async fn send_getdata_block(&self, peer_id: PeerId, hash: BlockHash) -> Result<()> {
        // Check if peer is still connected
        if !self.is_peer_connected(peer_id).await {
            bail!("Peer {} is not connected", peer_id);
        }

        // Try sending with retry logic
        let mut last_error = None;
        for attempt in 0..3 {
            match self
                .network
                .lock()
                .await
                .send_getdata_block_to_peer(peer_id, hash)
                .await
            {
                Ok(_) => {
                    debug!(
                        "Successfully sent getdata for {} to {} on attempt {}",
                        hash,
                        peer_id,
                        attempt + 1
                    );
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "Failed to send getdata to {} (attempt {}): {}",
                        peer_id,
                        attempt + 1,
                        e
                    );
                    last_error = Some(e);

                    // Check if peer disconnected
                    if !self.is_peer_connected(peer_id).await {
                        bail!("Peer {} disconnected during getdata", peer_id);
                    }

                    // Wait before retry
                    if attempt < 2 {
                        sleep(Duration::from_millis(100 * (attempt + 1) as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("Failed to send getdata after 3 attempts")))
    }

    /// Wait for headers to arrive
    async fn wait_for_headers(&self) {
        // Wait for headers with timeout
        let start = Instant::now();
        let timeout = Duration::from_secs(10);

        loop {
            let queue_size = self.headers_queue.read().await.len();
            if queue_size > 0 {
                break;
            }

            if start.elapsed() > timeout {
                warn!("Timeout waiting for headers");
                break;
            }

            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Process headers queue
    async fn process_headers_queue(&self) -> Result<Vec<BlockHeader>> {
        let mut queue = self.headers_queue.write().await;
        let headers: Vec<BlockHeader> = queue.drain(..).collect();
        Ok(headers)
    }

    /// Update peer information
    pub async fn update_peer_height(&self, peer_id: PeerId, height: u32, best_hash: BlockHash) {
        self.peer_heights.write().await.insert(peer_id, height);
        self.peer_best_hash.write().await.insert(peer_id, best_hash);

        // Log the update
        info!("Updated peer {} height to {}", peer_id, height);

        // If we're idle and this peer has more blocks, consider starting sync
        if *self.state.read().await == SyncState::Idle {
            let chain = self.chain.read().await;
            let our_height = chain.get_best_height();

            if height > our_height {
                info!(
                    "Peer {} has {} more blocks than us, may need to sync",
                    peer_id,
                    height - our_height
                );
            }
        }
    }

    /// Process incoming headers from a peer (internal method)
    pub async fn process_headers_internal(&self, headers: Vec<BlockHeader>) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        info!("Processing {} headers", headers.len());

        // Add headers to our queue for processing
        let mut queue = self.headers_queue.write().await;
        queue.extend(headers);

        // Update last header time
        *self.last_header_time.write().await = Instant::now();

        Ok(())
    }

    /// Handle new block announcement or received block
    pub async fn handle_block_announcement(&self, block: Block) -> Result<()> {
        let hash = block.block_hash();
        info!("Received block {} via announcement", hash);

        // Remove from in-flight if it was requested
        let was_requested = {
            let mut in_flight = self.blocks_in_flight.write().await;
            in_flight.remove(&hash).is_some()
        };

        if was_requested {
            // This was a requested block, add to queue for processing
            self.block_queue.write().await.push_back(block);
            debug!("Added requested block {} to queue", hash);
        } else {
            // Unsolicited block - process if we're synced
            if *self.state.read().await == SyncState::Synced {
                // Process new block immediately
                let chain = self.chain.write().await;
                match chain.process_block(block.clone()).await {
                    Ok(_) => info!("Processed new block {}", hash),
                    Err(e) => warn!("Failed to process new block {}: {}", hash, e),
                }
            }
        }

        Ok(())
    }

    /// Get sync state
    pub async fn get_state(&self) -> SyncState {
        self.state.read().await.clone()
    }

    /// Get sync progress
    pub async fn get_progress(&self) -> (u32, u32) {
        let current = *self.download_window_start.read().await;
        let target = self
            .peer_heights
            .read()
            .await
            .values()
            .max()
            .copied()
            .unwrap_or(current);

        (current, target)
    }
}

/// Implement the SyncHandler trait for external integration
#[async_trait]
impl SyncHandler for SyncManager {
    /// Process incoming headers from a peer  
    async fn process_headers(&self, headers: Vec<BlockHeader>) -> Result<()> {
        // Forward to our internal process_headers_internal method
        self.process_headers_internal(headers).await
    }

    /// Update peer information (height and best block)
    async fn update_peer_info(&self, peer_addr: SocketAddr, height: u32, best_hash: BlockHash) {
        // Forward to our existing update_peer_height method
        self.update_peer_height(peer_addr, height, best_hash).await;
    }

    /// Process incoming block from a peer
    async fn process_block(&self, block: Block) -> Result<()> {
        // Forward to our handle_block_announcement method
        self.handle_block_announcement(block).await
    }
}

/// DNS seed addresses for peer discovery
pub fn get_dns_seeds(network: Network) -> Vec<&'static str> {
    match network {
        Network::Bitcoin => vec![
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
            "seed.bitcoinstats.com",
            "seed.btc.petertodd.net",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.bitcoin.sprovoost.nl",
        ],
        Network::Testnet => vec![
            "testnet-seed.bitcoin.jonasschnelli.ch",
            "seed.tbtc.petertodd.net",
            "seed.testnet.bitcoin.sprovoost.nl",
        ],
        Network::Signet => vec!["seed.signet.bitcoin.sprovoost.nl"],
        Network::Regtest => vec![],
        _ => vec![],
    }
}
