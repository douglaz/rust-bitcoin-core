use anyhow::{bail, Result};
use bitcoin::{Block, BlockHash, Network};
use bitcoin_hashes::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::block_download::BlockDownloadManager;
use crate::headers_sync::HeadersSyncManager;
use crate::peer_manager::PeerManager;

/// IBD (Initial Block Download) phases
#[derive(Debug, Clone, PartialEq)]
pub enum IBDPhase {
    /// Not started
    Idle,
    /// Synchronizing headers
    HeadersSync {
        progress: f64,
        current_height: u32,
        target_height: u32,
    },
    /// Downloading blocks
    BlockDownload {
        progress: f64,
        current_height: u32,
        target_height: u32,
        blocks_per_second: f64,
    },
    /// Validating and importing blocks
    BlockValidation {
        current_height: u32,
        queue_size: usize,
    },
    /// Catching up with recent blocks
    CatchingUp { blocks_behind: u32 },
    /// Fully synchronized
    Synced,
    /// Error occurred
    Failed(String),
}

/// IBD state
#[derive(Debug, Clone)]
pub struct IBDState {
    pub phase: IBDPhase,
    pub started_at: Option<Instant>,
    pub headers_synced: bool,
    pub best_block_height: u32,
    pub best_block_hash: BlockHash,
    pub peer_best_height: u32,
    pub connected_peers: usize,
}

impl Default for IBDState {
    fn default() -> Self {
        Self {
            phase: IBDPhase::Idle,
            started_at: None,
            headers_synced: false,
            best_block_height: 0,
            best_block_hash: BlockHash::from_raw_hash(
                bitcoin_hashes::sha256d::Hash::from_byte_array([0u8; 32]),
            ),
            peer_best_height: 0,
            connected_peers: 0,
        }
    }
}

/// IBD statistics
#[derive(Debug, Clone, Default)]
pub struct IBDStats {
    pub total_headers: usize,
    pub total_blocks_downloaded: usize,
    pub total_blocks_validated: usize,
    pub total_bytes_downloaded: usize,
    pub average_block_size: usize,
    pub download_speed: f64,   // bytes per second
    pub validation_speed: f64, // blocks per second
    pub time_elapsed: Duration,
}

/// Manages Initial Block Download process
pub struct IBDManager {
    network: Network,
    state: Arc<RwLock<IBDState>>,
    stats: Arc<RwLock<IBDStats>>,
    headers_sync: Arc<HeadersSyncManager>,
    block_download: Arc<BlockDownloadManager>,
    peer_manager: Arc<PeerManager>,
    // Block processing channel
    block_processor: mpsc::Sender<(BlockHash, Block)>,
    // Configuration
    batch_size: usize,
    parallel_downloads: usize,
}

impl IBDManager {
    /// Create new IBD manager
    pub fn new(
        network: Network,
        peer_manager: Arc<PeerManager>,
        block_processor: mpsc::Sender<(BlockHash, Block)>,
    ) -> Self {
        let headers_sync = Arc::new(HeadersSyncManager::new(network));
        let block_download = Arc::new(BlockDownloadManager::new(peer_manager.clone()));

        Self {
            network,
            state: Arc::new(RwLock::new(IBDState::default())),
            stats: Arc::new(RwLock::new(IBDStats::default())),
            headers_sync,
            block_download,
            peer_manager,
            block_processor,
            batch_size: 100,
            parallel_downloads: 16,
        }
    }

    /// Start IBD process
    pub async fn start(&self) -> Result<()> {
        let mut state = self.state.write().await;
        if !matches!(state.phase, IBDPhase::Idle) {
            bail!("IBD already in progress");
        }

        state.phase = IBDPhase::HeadersSync {
            progress: 0.0,
            current_height: 0,
            target_height: 0,
        };
        state.started_at = Some(Instant::now());

        info!("Starting Initial Block Download");

        // Start the IBD state machine
        let state_clone = self.state.clone();
        let self_clone = self.clone();
        tokio::spawn(async move {
            if let Err(e) = self_clone.run_state_machine().await {
                warn!("IBD failed: {}", e);
                let mut state = state_clone.write().await;
                state.phase = IBDPhase::Failed(e.to_string());
            }
        });

        Ok(())
    }

    /// Run the IBD state machine
    async fn run_state_machine(&self) -> Result<()> {
        let mut ticker = interval(Duration::from_secs(1));

        loop {
            ticker.tick().await;

            let phase = self.state.read().await.phase.clone();

            match phase {
                IBDPhase::Idle => {
                    // Waiting to start
                }

                IBDPhase::HeadersSync { .. } => {
                    self.handle_headers_sync().await?;
                }

                IBDPhase::BlockDownload { .. } => {
                    self.handle_block_download().await?;
                }

                IBDPhase::BlockValidation { .. } => {
                    self.handle_block_validation().await?;
                }

                IBDPhase::CatchingUp { .. } => {
                    self.handle_catching_up().await?;
                }

                IBDPhase::Synced => {
                    // Fully synced, monitor for new blocks
                    self.monitor_new_blocks().await?;
                }

                IBDPhase::Failed(ref error) => {
                    warn!("IBD failed: {}", error);
                    return Ok(());
                }
            }

            // Update statistics
            self.update_stats().await;
        }
    }

    /// Handle headers synchronization phase
    async fn handle_headers_sync(&self) -> Result<()> {
        // Get best peer
        let peers = self.peer_manager.get_best_peers(1).await;
        if peers.is_empty() {
            debug!("No peers available for headers sync");
            return Ok(());
        }

        let peer = &peers[0];
        let peer_height = peer.best_height;

        // Start headers sync if not already running
        if !self.headers_sync.is_synced().await {
            self.headers_sync.start_sync(peer.addr, peer_height).await?;
        }

        // Get progress
        let (current, target) = self.headers_sync.get_progress().await;
        let progress = if target > 0 {
            (current as f64 / target as f64) * 100.0
        } else {
            0.0
        };

        // Update state
        let mut state = self.state.write().await;
        state.phase = IBDPhase::HeadersSync {
            progress,
            current_height: current,
            target_height: target,
        };

        // Check if headers sync is complete
        if self.headers_sync.is_synced().await {
            state.headers_synced = true;
            state.phase = IBDPhase::BlockDownload {
                progress: 0.0,
                current_height: 0,
                target_height: current,
                blocks_per_second: 0.0,
            };

            info!("Headers sync complete at height {}", current);

            // Queue blocks for download
            self.queue_blocks_for_download(current).await?;
        }

        Ok(())
    }

    /// Handle block download phase
    async fn handle_block_download(&self) -> Result<()> {
        // Get download progress
        let (pending, downloading, completed) = self.block_download.get_progress().await;
        let stats = self.block_download.get_stats().await;

        let mut state = self.state.write().await;

        if let IBDPhase::BlockDownload { target_height, .. } = state.phase {
            let current_height = completed as u32;
            let progress = if target_height > 0 {
                (current_height as f64 / target_height as f64) * 100.0
            } else {
                0.0
            };

            state.phase = IBDPhase::BlockDownload {
                progress,
                current_height,
                target_height,
                blocks_per_second: stats.average_speed,
            };

            // Check if download is complete
            if pending == 0 && downloading == 0 && completed > 0 {
                state.phase = IBDPhase::BlockValidation {
                    current_height,
                    queue_size: completed,
                };
                info!("Block download complete, starting validation");
            }
        }

        Ok(())
    }

    /// Handle block validation phase
    async fn handle_block_validation(&self) -> Result<()> {
        // This is handled by the block processor channel
        // Here we just monitor progress

        let state = self.state.read().await;

        if let IBDPhase::BlockValidation {
            current_height,
            queue_size,
        } = state.phase
        {
            if queue_size == 0 {
                // All blocks validated
                let mut state = self.state.write().await;
                state.phase = IBDPhase::CatchingUp { blocks_behind: 0 };
                info!("Block validation complete at height {}", current_height);
            }
        }

        Ok(())
    }

    /// Handle catching up phase
    async fn handle_catching_up(&self) -> Result<()> {
        // Check if we're caught up with peers
        let peers = self.peer_manager.get_all_peers().await;
        if peers.is_empty() {
            return Ok(());
        }

        let best_peer_height = peers.iter().map(|p| p.best_height).max().unwrap_or(0);
        let our_height = self.state.read().await.best_block_height;

        let blocks_behind = best_peer_height.saturating_sub(our_height);

        let mut state = self.state.write().await;
        state.phase = IBDPhase::CatchingUp { blocks_behind };

        if blocks_behind <= 1 {
            // We're synced!
            state.phase = IBDPhase::Synced;
            info!("Blockchain synchronized at height {}", our_height);
        } else {
            // Queue more blocks for download
            drop(state);
            self.queue_blocks_for_download(blocks_behind).await?;
        }

        Ok(())
    }

    /// Monitor for new blocks when synced
    async fn monitor_new_blocks(&self) -> Result<()> {
        // Check if we've fallen behind
        let peers = self.peer_manager.get_all_peers().await;
        if peers.is_empty() {
            return Ok(());
        }

        let best_peer_height = peers.iter().map(|p| p.best_height).max().unwrap_or(0);
        let our_height = self.state.read().await.best_block_height;

        if best_peer_height > our_height + 1 {
            // We've fallen behind, switch to catching up
            let mut state = self.state.write().await;
            state.phase = IBDPhase::CatchingUp {
                blocks_behind: best_peer_height - our_height,
            };
            info!(
                "Fallen behind, catching up from height {} to {}",
                our_height, best_peer_height
            );
        }

        Ok(())
    }

    /// Queue blocks for download
    async fn queue_blocks_for_download(&self, count: u32) -> Result<()> {
        // Get headers to download
        let headers = self
            .headers_sync
            .get_headers_for_download(count as usize)
            .await;

        if headers.is_empty() {
            return Ok(());
        }

        // Queue blocks in batches
        let mut batch = Vec::new();
        for (i, hash) in headers.iter().enumerate() {
            batch.push((*hash, i as u32));

            if batch.len() >= self.batch_size {
                self.block_download.queue_blocks(batch.clone()).await?;
                batch.clear();
            }
        }

        // Queue remaining blocks
        if !batch.is_empty() {
            self.block_download.queue_blocks(batch).await?;
        }

        // Start download scheduler
        self.block_download.clone().start_scheduler().await;

        info!("Queued {} blocks for download", headers.len());
        Ok(())
    }

    /// Update statistics
    async fn update_stats(&self) {
        let mut stats = self.stats.write().await;

        if let Some(started_at) = self.state.read().await.started_at {
            stats.time_elapsed = started_at.elapsed();
        }

        // Get download stats
        let download_stats = self.block_download.get_stats().await;
        stats.total_blocks_downloaded = download_stats.blocks_downloaded;
        stats.total_bytes_downloaded = download_stats.bytes_downloaded;
        stats.download_speed = download_stats.average_speed;

        if stats.total_blocks_downloaded > 0 {
            stats.average_block_size = stats.total_bytes_downloaded / stats.total_blocks_downloaded;
        }
    }

    /// Get current IBD state
    pub async fn get_state(&self) -> IBDState {
        self.state.read().await.clone()
    }

    /// Get IBD statistics
    pub async fn get_stats(&self) -> IBDStats {
        self.stats.read().await.clone()
    }

    /// Check if IBD is complete
    pub async fn is_synced(&self) -> bool {
        matches!(self.state.read().await.phase, IBDPhase::Synced)
    }

    /// Get sync progress percentage
    pub async fn get_progress(&self) -> f64 {
        match self.state.read().await.phase {
            IBDPhase::HeadersSync { progress, .. } => progress * 0.2, // Headers are 20% of sync
            IBDPhase::BlockDownload { progress, .. } => 20.0 + (progress * 0.6), // Blocks are 60%
            IBDPhase::BlockValidation { .. } => 80.0,                 // Validation is 20%
            IBDPhase::CatchingUp { blocks_behind } => {
                if blocks_behind == 0 {
                    99.0
                } else {
                    95.0
                }
            }
            IBDPhase::Synced => 100.0,
            _ => 0.0,
        }
    }
}

impl Clone for IBDManager {
    fn clone(&self) -> Self {
        Self {
            network: self.network,
            state: self.state.clone(),
            stats: self.stats.clone(),
            headers_sync: self.headers_sync.clone(),
            block_download: self.block_download.clone(),
            peer_manager: self.peer_manager.clone(),
            block_processor: self.block_processor.clone(),
            batch_size: self.batch_size,
            parallel_downloads: self.parallel_downloads,
        }
    }
}
