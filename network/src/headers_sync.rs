use anyhow::{bail, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::{BlockHash, Network};
use bitcoin_hashes::Hash;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Maximum headers in a single message
const MAX_HEADERS_PER_MSG: usize = 2000;

/// Maximum headers to keep in memory
const MAX_HEADERS_IN_MEMORY: usize = 100_000;

/// Headers sync timeout
const HEADERS_SYNC_TIMEOUT: Duration = Duration::from_secs(30);

/// Headers chain state
#[derive(Debug, Clone)]
pub enum HeadersSyncState {
    Idle,
    Syncing {
        peer: std::net::SocketAddr,
        start_height: u32,
        target_height: u32,
        started_at: Instant,
    },
    Validating,
    Completed,
    Failed(String),
}

/// Headers chain information
#[derive(Debug, Clone)]
pub struct HeadersChain {
    pub tip: BlockHash,
    pub height: u32,
    pub total_work: [u8; 32],
}

/// Headers storage in memory
pub struct HeadersStorage {
    // Map from block hash to header
    headers: HashMap<BlockHash, BlockHeader>,
    // Map from block hash to height
    heights: HashMap<BlockHash, u32>,
    // Map from height to block hash
    hash_by_height: HashMap<u32, BlockHash>,
    // Chain tip
    chain_tip: Option<HeadersChain>,
    // Headers validation queue
    validation_queue: VecDeque<(BlockHeader, u32)>,
}

impl Default for HeadersStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl HeadersStorage {
    /// Create new headers storage
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
            heights: HashMap::new(),
            hash_by_height: HashMap::new(),
            chain_tip: None,
            validation_queue: VecDeque::new(),
        }
    }

    /// Initialize with genesis block
    pub fn init_genesis(&mut self, network: Network) {
        let genesis = genesis_header(network);
        let genesis_hash = genesis.block_hash();

        self.headers.insert(genesis_hash, genesis);
        self.heights.insert(genesis_hash, 0);
        self.hash_by_height.insert(0, genesis_hash);

        self.chain_tip = Some(HeadersChain {
            tip: genesis_hash,
            height: 0,
            total_work: [0u8; 32], // Genesis has minimal work
        });

        info!(
            "Initialized headers chain with genesis block: {}",
            genesis_hash
        );
    }

    /// Add a header to storage
    pub fn add_header(&mut self, header: BlockHeader, height: u32) -> Result<()> {
        let hash = header.block_hash();

        // Check if we already have this header
        if self.headers.contains_key(&hash) {
            return Ok(());
        }

        // Verify it connects to a known header
        if height > 0 && !self.headers.contains_key(&header.prev_blockhash) {
            bail!("Header doesn't connect to known chain");
        }

        // Store header
        self.headers.insert(hash, header);
        self.heights.insert(hash, height);
        self.hash_by_height.insert(height, hash);

        // Add to validation queue
        self.validation_queue.push_back((header, height));

        // Limit memory usage
        if self.headers.len() > MAX_HEADERS_IN_MEMORY {
            self.prune_old_headers();
        }

        debug!("Added header at height {}: {}", height, hash);
        Ok(())
    }

    /// Get header by hash
    pub fn get_header(&self, hash: &BlockHash) -> Option<&BlockHeader> {
        self.headers.get(hash)
    }

    /// Get header by height
    pub fn get_header_by_height(&self, height: u32) -> Option<&BlockHeader> {
        self.hash_by_height
            .get(&height)
            .and_then(|hash| self.headers.get(hash))
    }

    /// Get height of a block
    pub fn get_height(&self, hash: &BlockHash) -> Option<u32> {
        self.heights.get(hash).copied()
    }

    /// Get chain tip
    pub fn get_chain_tip(&self) -> Option<&HeadersChain> {
        self.chain_tip.as_ref()
    }

    /// Update chain tip
    pub fn update_chain_tip(&mut self, tip: BlockHash, height: u32, work: [u8; 32]) {
        self.chain_tip = Some(HeadersChain {
            tip,
            height,
            total_work: work,
        });
        info!("Updated chain tip to height {} ({})", height, tip);
    }

    /// Prune old headers to limit memory usage
    fn prune_old_headers(&mut self) {
        // Keep recent headers and prune old ones
        let tip_height = self.chain_tip.as_ref().map(|c| c.height).unwrap_or(0);
        if tip_height < 10000 {
            return; // Don't prune if chain is short
        }

        let prune_height = tip_height.saturating_sub(50000);
        let to_remove: Vec<BlockHash> = self
            .heights
            .iter()
            .filter(|(_, &h)| h < prune_height)
            .map(|(hash, _)| *hash)
            .collect();

        let remove_count = to_remove.len();
        for hash in to_remove {
            self.headers.remove(&hash);
            if let Some(height) = self.heights.remove(&hash) {
                self.hash_by_height.remove(&height);
            }
        }

        debug!("Pruned {} old headers", remove_count);
    }

    /// Get validation queue
    pub fn get_validation_queue(&mut self) -> VecDeque<(BlockHeader, u32)> {
        std::mem::take(&mut self.validation_queue)
    }
}

/// Headers synchronization manager
pub struct HeadersSyncManager {
    network: Network,
    storage: Arc<RwLock<HeadersStorage>>,
    state: Arc<RwLock<HeadersSyncState>>,
    checkpoints: HashMap<u32, BlockHash>,
}

impl HeadersSyncManager {
    /// Create new headers sync manager
    pub fn new(network: Network) -> Self {
        let mut storage = HeadersStorage::new();
        storage.init_genesis(network);

        Self {
            network,
            storage: Arc::new(RwLock::new(storage)),
            state: Arc::new(RwLock::new(HeadersSyncState::Idle)),
            checkpoints: get_checkpoints(network),
        }
    }

    /// Start headers synchronization
    pub async fn start_sync(&self, peer: std::net::SocketAddr, peer_height: u32) -> Result<()> {
        let current_height = self
            .storage
            .read()
            .await
            .get_chain_tip()
            .map(|c| c.height)
            .unwrap_or(0);

        if peer_height <= current_height {
            debug!("Peer {} has no new headers (height: {})", peer, peer_height);
            return Ok(());
        }

        *self.state.write().await = HeadersSyncState::Syncing {
            peer,
            start_height: current_height,
            target_height: peer_height,
            started_at: Instant::now(),
        };

        info!(
            "Starting headers sync with {} from height {} to {}",
            peer, current_height, peer_height
        );

        Ok(())
    }

    /// Process received headers
    pub async fn process_headers(&self, headers: Vec<BlockHeader>) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        info!("Processing {} headers", headers.len());
        *self.state.write().await = HeadersSyncState::Validating;

        let mut storage = self.storage.write().await;
        let mut current_height = storage.get_chain_tip().map(|c| c.height).unwrap_or(0);

        for header in headers {
            // Basic validation
            self.validate_header(&header, current_height + 1)?;

            // Check checkpoint if available
            if let Some(checkpoint_hash) = self.checkpoints.get(&(current_height + 1)) {
                if header.block_hash() != *checkpoint_hash {
                    bail!(
                        "Header at height {} doesn't match checkpoint",
                        current_height + 1
                    );
                }
                debug!("Header at height {} matches checkpoint", current_height + 1);
            }

            // Add to storage
            storage.add_header(header, current_height + 1)?;
            current_height += 1;
        }

        // Update chain tip
        let last_hash = storage
            .get_header_by_height(current_height)
            .map(|h| h.block_hash());

        if let Some(hash) = last_hash {
            let work = calculate_chain_work(&storage, hash);
            storage.update_chain_tip(hash, current_height, work);
        }

        *self.state.write().await = HeadersSyncState::Completed;
        info!("Headers sync completed at height {}", current_height);

        Ok(())
    }

    /// Validate a header
    fn validate_header(&self, header: &BlockHeader, expected_height: u32) -> Result<()> {
        // Check proof of work
        let target = header.target();
        let hash = header.block_hash();

        let pow_valid = header.validate_pow(target).is_ok();
        if !pow_valid {
            bail!("Invalid proof of work for header {}", hash);
        }

        // Check timestamp (not too far in future)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as u32;

        if header.time > now + 7200 {
            bail!("Header timestamp too far in future");
        }

        // Version check (BIP65 requires version 4+)
        if expected_height > 388_381 && header.version.to_consensus() < 4 {
            bail!("Invalid block version");
        }

        Ok(())
    }

    /// Get sync progress
    pub async fn get_progress(&self) -> (u32, u32) {
        if let HeadersSyncState::Syncing {
            start_height,
            target_height,
            ..
        } = *self.state.read().await
        {
            let current = self
                .storage
                .read()
                .await
                .get_chain_tip()
                .map(|c| c.height)
                .unwrap_or(start_height);
            (current, target_height)
        } else {
            let current = self
                .storage
                .read()
                .await
                .get_chain_tip()
                .map(|c| c.height)
                .unwrap_or(0);
            (current, current)
        }
    }

    /// Check if sync is complete
    pub async fn is_synced(&self) -> bool {
        matches!(*self.state.read().await, HeadersSyncState::Completed)
    }

    /// Get headers for download
    pub async fn get_headers_for_download(&self, count: usize) -> Vec<BlockHash> {
        let storage = self.storage.read().await;
        let tip_height = storage.get_chain_tip().map(|c| c.height).unwrap_or(0);

        let mut headers = Vec::new();
        let start = tip_height.saturating_sub(count as u32);

        for height in start..=tip_height {
            if let Some(header) = storage.get_header_by_height(height) {
                headers.push(header.block_hash());
            }
        }

        headers
    }

    /// Request headers from a specific height
    pub async fn get_locator_hashes(&self) -> Vec<BlockHash> {
        let storage = self.storage.read().await;
        let tip_height = storage.get_chain_tip().map(|c| c.height).unwrap_or(0);

        let mut locator = Vec::new();
        let mut step = 1;
        let mut height = tip_height;

        // Build locator following Bitcoin Core's algorithm
        // Recent blocks: every block for the last 10
        // Then exponentially increasing steps
        while height > 0 {
            if let Some(header) = storage.get_header_by_height(height) {
                locator.push(header.block_hash());
            }

            if locator.len() >= 10 {
                step *= 2;
            }

            height = height.saturating_sub(step);
        }

        // Always include genesis
        if let Some(genesis) = storage.get_header_by_height(0) {
            locator.push(genesis.block_hash());
        }

        locator
    }

    /// Handle timeout for headers sync
    pub async fn check_timeout(&self) -> Result<()> {
        if let HeadersSyncState::Syncing {
            started_at, peer, ..
        } = *self.state.read().await
        {
            if started_at.elapsed() > HEADERS_SYNC_TIMEOUT {
                *self.state.write().await =
                    HeadersSyncState::Failed(format!("Headers sync with {} timed out", peer));
                bail!("Headers sync timeout");
            }
        }
        Ok(())
    }

    /// Mark sync as complete
    pub async fn complete_sync(&self) {
        let storage = self.storage.read().await;
        if let Some(tip) = storage.get_chain_tip() {
            info!("Headers sync completed at height {}", tip.height);
            drop(storage);
            *self.state.write().await = HeadersSyncState::Completed;
        }
    }

    /// Reset sync state on failure
    pub async fn reset_sync(&self, error: String) {
        *self.state.write().await = HeadersSyncState::Failed(error);
    }

    /// Get the best header hash
    pub async fn get_best_header(&self) -> Option<BlockHash> {
        self.storage.read().await.get_chain_tip().map(|c| c.tip)
    }

    /// Validate headers chain continuity
    pub async fn validate_chain_continuity(&self) -> Result<bool> {
        let storage = self.storage.read().await;

        if let Some(tip) = storage.get_chain_tip() {
            let mut current_height = tip.height;
            let mut current_hash = tip.tip;

            // Walk backwards and verify each header points to its parent
            while current_height > 0 {
                if let Some(header) = storage.get_header(&current_hash) {
                    current_hash = header.prev_blockhash;
                    current_height -= 1;

                    // Verify the parent exists at the expected height
                    if let Some(parent) = storage.get_header_by_height(current_height) {
                        if parent.block_hash() != current_hash {
                            bail!("Chain continuity broken at height {}", current_height);
                        }
                    } else {
                        bail!("Missing header at height {}", current_height);
                    }
                } else {
                    bail!("Missing header {}", current_hash);
                }

                // Only check last 1000 blocks for performance
                if tip.height - current_height >= 1000 {
                    break;
                }
            }
        }

        Ok(true)
    }
}

/// Get network-specific checkpoints
fn get_checkpoints(network: Network) -> HashMap<u32, BlockHash> {
    let mut checkpoints = HashMap::new();

    match network {
        Network::Bitcoin => {
            // Add mainnet checkpoints (real Bitcoin mainnet values)
            use std::str::FromStr;

            // Block 11111
            checkpoints.insert(
                11111,
                BlockHash::from_str(
                    "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
                )
                .unwrap(),
            );

            // Block 100000
            checkpoints.insert(
                100000,
                BlockHash::from_str(
                    "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506",
                )
                .unwrap(),
            );

            // Block 200000
            checkpoints.insert(
                200000,
                BlockHash::from_str(
                    "000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf",
                )
                .unwrap(),
            );

            // Block 300000
            checkpoints.insert(
                300000,
                BlockHash::from_str(
                    "000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254",
                )
                .unwrap(),
            );

            // Block 400000
            checkpoints.insert(
                400000,
                BlockHash::from_str(
                    "000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f",
                )
                .unwrap(),
            );

            // Block 500000
            checkpoints.insert(
                500000,
                BlockHash::from_str(
                    "00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04",
                )
                .unwrap(),
            );

            // Block 600000
            checkpoints.insert(
                600000,
                BlockHash::from_str(
                    "00000000000000000019f112ec0a9982926f1258cdcc558dd7c3b7e5dc7fa148",
                )
                .unwrap(),
            );

            // Block 700000
            checkpoints.insert(
                700000,
                BlockHash::from_str(
                    "0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959",
                )
                .unwrap(),
            );
        }
        Network::Testnet => {
            // Add testnet checkpoints
            use std::str::FromStr;

            checkpoints.insert(
                546,
                BlockHash::from_str(
                    "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70",
                )
                .unwrap(),
            );

            checkpoints.insert(
                100000,
                BlockHash::from_str(
                    "00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e",
                )
                .unwrap(),
            );

            checkpoints.insert(
                200000,
                BlockHash::from_str(
                    "0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2",
                )
                .unwrap(),
            );
        }
        _ => {
            // No checkpoints for regtest/signet
        }
    }

    checkpoints
}

/// Get genesis header for network
fn genesis_header(network: Network) -> BlockHeader {
    match network {
        Network::Bitcoin => bitcoin::blockdata::constants::genesis_block(Network::Bitcoin).header,
        Network::Testnet => bitcoin::blockdata::constants::genesis_block(Network::Testnet).header,
        Network::Regtest => bitcoin::blockdata::constants::genesis_block(Network::Regtest).header,
        Network::Signet => bitcoin::blockdata::constants::genesis_block(Network::Signet).header,
        _ => bitcoin::blockdata::constants::genesis_block(Network::Bitcoin).header,
    }
}

/// Calculate total chain work up to a block
fn calculate_chain_work(storage: &HeadersStorage, tip: BlockHash) -> [u8; 32] {
    // Simplified work calculation
    // In reality, this should sum up the work of all blocks in the chain
    let height = storage.get_height(&tip).unwrap_or(0);
    let mut work = [0u8; 32];
    work[0] = (height / 256) as u8;
    work[1] = (height % 256) as u8;
    work
}
