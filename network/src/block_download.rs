use anyhow::Result;
use bitcoin::{Block, BlockHash};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::message::{InvType, Inventory, Message};
use crate::peer_manager::PeerManager;

/// Maximum blocks to download in parallel
const MAX_PARALLEL_DOWNLOADS: usize = 16;

/// Maximum blocks in flight per peer
const MAX_BLOCKS_PER_PEER: usize = 16;

/// Block download timeout
const BLOCK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum retries for a block
const MAX_DOWNLOAD_RETRIES: usize = 3;

/// Block download status
#[derive(Debug, Clone)]
pub enum DownloadStatus {
    Pending,
    Downloading {
        peer: SocketAddr,
        started_at: Instant,
        attempt: usize,
    },
    Downloaded,
    Failed(String),
}

/// Block download request
#[derive(Debug, Clone)]
pub struct DownloadRequest {
    pub hash: BlockHash,
    pub height: u32,
    pub status: DownloadStatus,
    pub retries: usize,
}

/// Block download statistics
#[derive(Debug, Clone, Default)]
pub struct DownloadStats {
    pub blocks_requested: usize,
    pub blocks_downloaded: usize,
    pub blocks_failed: usize,
    pub bytes_downloaded: usize,
    pub average_speed: f64, // bytes per second
}

/// Manages parallel block downloading
pub struct BlockDownloadManager {
    // Download queue
    download_queue: Arc<RwLock<VecDeque<BlockHash>>>,
    // Active downloads
    active_downloads: Arc<RwLock<HashMap<BlockHash, DownloadRequest>>>,
    // Downloads per peer
    peer_downloads: Arc<RwLock<HashMap<SocketAddr, HashSet<BlockHash>>>>,
    // Downloaded blocks waiting for processing
    completed_blocks: Arc<RwLock<VecDeque<(BlockHash, Block)>>>,
    // Statistics
    stats: Arc<RwLock<DownloadStats>>,
    // Peer manager reference
    peer_manager: Arc<PeerManager>,
    // Channel for received blocks
    block_receiver: Arc<RwLock<Option<mpsc::Receiver<(BlockHash, Block)>>>>,
    block_sender: mpsc::Sender<(BlockHash, Block)>,
}

impl BlockDownloadManager {
    /// Create new block download manager
    pub fn new(peer_manager: Arc<PeerManager>) -> Self {
        let (block_sender, block_receiver) = mpsc::channel(100);

        Self {
            download_queue: Arc::new(RwLock::new(VecDeque::new())),
            active_downloads: Arc::new(RwLock::new(HashMap::new())),
            peer_downloads: Arc::new(RwLock::new(HashMap::new())),
            completed_blocks: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(DownloadStats::default())),
            peer_manager,
            block_receiver: Arc::new(RwLock::new(Some(block_receiver))),
            block_sender,
        }
    }

    /// Queue blocks for download
    pub async fn queue_blocks(&self, blocks: Vec<(BlockHash, u32)>) -> Result<()> {
        let mut queue = self.download_queue.write().await;
        let mut active = self.active_downloads.write().await;

        for (hash, height) in blocks {
            // Skip if already queued or downloading
            if active.contains_key(&hash) || queue.contains(&hash) {
                continue;
            }

            queue.push_back(hash);
            active.insert(
                hash,
                DownloadRequest {
                    hash,
                    height,
                    status: DownloadStatus::Pending,
                    retries: 0,
                },
            );
        }

        info!("Queued {} blocks for download", queue.len());
        Ok(())
    }

    /// Start download scheduler
    pub async fn start_scheduler(self: Arc<Self>) {
        let mut ticker = interval(Duration::from_secs(1));

        tokio::spawn(async move {
            loop {
                ticker.tick().await;

                // Check for timeouts
                self.check_timeouts().await;

                // Schedule new downloads
                if let Err(e) = self.schedule_downloads().await {
                    warn!("Error scheduling downloads: {}", e);
                }

                // Process completed blocks
                self.process_completed_blocks().await;
            }
        });
    }

    /// Schedule block downloads
    async fn schedule_downloads(&self) -> Result<()> {
        let mut queue = self.download_queue.write().await;
        let mut active = self.active_downloads.write().await;
        let mut peer_downloads = self.peer_downloads.write().await;

        // Get best peers for downloading
        let peers = self.peer_manager.get_best_peers(8).await;
        if peers.is_empty() {
            return Ok(());
        }

        // Count active downloads
        let active_count = active
            .values()
            .filter(|r| matches!(r.status, DownloadStatus::Downloading { .. }))
            .count();

        if active_count >= MAX_PARALLEL_DOWNLOADS {
            return Ok(()); // Already at max parallel downloads
        }

        // Schedule downloads
        while !queue.is_empty() && active_count < MAX_PARALLEL_DOWNLOADS {
            let hash = match queue.pop_front() {
                Some(h) => h,
                None => break,
            };

            // Find best peer for this download
            let mut best_peer = None;
            let mut min_downloads = usize::MAX;

            for peer_info in &peers {
                let peer_addr = peer_info.addr;
                let downloads = peer_downloads
                    .get(&peer_addr)
                    .map(|set| set.len())
                    .unwrap_or(0);

                if downloads < MAX_BLOCKS_PER_PEER && downloads < min_downloads {
                    best_peer = Some(peer_addr);
                    min_downloads = downloads;
                }
            }

            if let Some(peer_addr) = best_peer {
                // Send getdata request
                let inv = vec![Inventory {
                    inv_type: InvType::Block,
                    hash,
                }];

                if let Some(peer_info) = self.peer_manager.get_peer(&peer_addr).await {
                    if let Err(e) = peer_info.peer.send_message(Message::GetData(inv)).await {
                        warn!("Failed to request block from {}: {}", peer_addr, e);
                        continue;
                    }

                    // Update tracking
                    if let Some(request) = active.get_mut(&hash) {
                        request.status = DownloadStatus::Downloading {
                            peer: peer_addr,
                            started_at: Instant::now(),
                            attempt: request.retries + 1,
                        };
                    }

                    peer_downloads
                        .entry(peer_addr)
                        .or_insert_with(HashSet::new)
                        .insert(hash);

                    let mut stats = self.stats.write().await;
                    stats.blocks_requested += 1;

                    debug!("Requested block {} from {}", hash, peer_addr);
                }
            } else {
                // No peer available, put back in queue
                queue.push_back(hash);
                break;
            }
        }

        Ok(())
    }

    /// Check for download timeouts
    async fn check_timeouts(&self) {
        let mut active = self.active_downloads.write().await;
        let mut peer_downloads = self.peer_downloads.write().await;
        let mut queue = self.download_queue.write().await;

        let now = Instant::now();
        let mut timed_out = Vec::new();

        for (hash, request) in active.iter() {
            if let DownloadStatus::Downloading {
                peer, started_at, ..
            } = request.status
            {
                if now.duration_since(started_at) > BLOCK_DOWNLOAD_TIMEOUT {
                    timed_out.push((*hash, peer));
                }
            }
        }

        for (hash, peer) in timed_out {
            warn!("Block {} download from {} timed out", hash, peer);

            // Remove from peer downloads
            if let Some(downloads) = peer_downloads.get_mut(&peer) {
                downloads.remove(&hash);
            }

            // Update request status
            if let Some(request) = active.get_mut(&hash) {
                request.retries += 1;

                if request.retries >= MAX_DOWNLOAD_RETRIES {
                    request.status = DownloadStatus::Failed("Max retries exceeded".to_string());
                    let mut stats = self.stats.write().await;
                    stats.blocks_failed += 1;
                } else {
                    request.status = DownloadStatus::Pending;
                    queue.push_back(hash);
                }
            }

            // Penalize peer
            let _ = self
                .peer_manager
                .update_score(&peer, crate::peer_manager::ScoreEvent::Timeout)
                .await;
        }
    }

    /// Handle received block
    pub async fn handle_block(&self, block: Block, from_peer: SocketAddr) -> Result<()> {
        let hash = block.block_hash();

        // Check if we requested this block
        let mut active = self.active_downloads.write().await;
        if !active.contains_key(&hash) {
            debug!("Received unrequested block {}", hash);
            return Ok(());
        }

        // Update tracking
        let mut peer_downloads = self.peer_downloads.write().await;
        if let Some(downloads) = peer_downloads.get_mut(&from_peer) {
            downloads.remove(&hash);
        }

        // Mark as downloaded
        if let Some(request) = active.get_mut(&hash) {
            request.status = DownloadStatus::Downloaded;
        }

        // Update stats
        let mut stats = self.stats.write().await;
        stats.blocks_downloaded += 1;
        stats.bytes_downloaded += bitcoin::consensus::encode::serialize(&block).len();

        // Add to completed queue
        self.completed_blocks
            .write()
            .await
            .push_back((hash, block.clone()));

        // Send through channel
        let _ = self.block_sender.send((hash, block)).await;

        // Reward peer
        let _ = self
            .peer_manager
            .update_score(&from_peer, crate::peer_manager::ScoreEvent::ValidBlock)
            .await;

        info!("Downloaded block {} from {}", hash, from_peer);
        Ok(())
    }

    /// Process completed blocks
    async fn process_completed_blocks(&self) {
        let completed = self.completed_blocks.write().await.len();
        if completed > 0 {
            debug!("Processing {} completed blocks", completed);
            // Blocks are sent through channel for processing
        }
    }

    /// Get download statistics
    pub async fn get_stats(&self) -> DownloadStats {
        self.stats.read().await.clone()
    }

    /// Get download progress
    pub async fn get_progress(&self) -> (usize, usize, usize) {
        let active = self.active_downloads.read().await;
        let pending = active
            .values()
            .filter(|r| matches!(r.status, DownloadStatus::Pending))
            .count();
        let downloading = active
            .values()
            .filter(|r| matches!(r.status, DownloadStatus::Downloading { .. }))
            .count();
        let completed = active
            .values()
            .filter(|r| matches!(r.status, DownloadStatus::Downloaded))
            .count();

        (pending, downloading, completed)
    }

    /// Take block receiver channel
    pub async fn take_receiver(&self) -> Option<mpsc::Receiver<(BlockHash, Block)>> {
        self.block_receiver.write().await.take()
    }
}
