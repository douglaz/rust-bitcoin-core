use anyhow::{bail, Result};
use bitcoin::p2p::ServiceFlags;
use bitcoin::Network;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::peer::Peer;

/// Peer score thresholds
const MIN_PEER_SCORE: i32 = -100;
const INITIAL_PEER_SCORE: i32 = 0;
const MAX_PEER_SCORE: i32 = 100;

/// Connection limits
const DEFAULT_MAX_CONNECTIONS: usize = 125;
const DEFAULT_MAX_OUTBOUND: usize = 8;
const DEFAULT_MAX_INBOUND: usize = 117;

/// Timeouts
const PING_INTERVAL: Duration = Duration::from_secs(120);
const PING_TIMEOUT: Duration = Duration::from_secs(20);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Peer scoring events
#[derive(Debug, Clone)]
pub enum ScoreEvent {
    // Positive events
    ValidBlock,          // +10
    ValidTransaction,    // +1
    FastResponse,        // +2
    SuccessfulHandshake, // +5

    // Negative events
    InvalidBlock,       // -50
    InvalidTransaction, // -10
    Timeout,            // -20
    ProtocolViolation,  // -30
    SlowResponse,       // -5
    Disconnected,       // -10
}

impl ScoreEvent {
    fn score_delta(&self) -> i32 {
        match self {
            ScoreEvent::ValidBlock => 10,
            ScoreEvent::ValidTransaction => 1,
            ScoreEvent::FastResponse => 2,
            ScoreEvent::SuccessfulHandshake => 5,
            ScoreEvent::InvalidBlock => -50,
            ScoreEvent::InvalidTransaction => -10,
            ScoreEvent::Timeout => -20,
            ScoreEvent::ProtocolViolation => -30,
            ScoreEvent::SlowResponse => -5,
            ScoreEvent::Disconnected => -10,
        }
    }
}

/// Peer information with scoring
#[derive(Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub peer: Arc<Peer>,
    pub score: i32,
    pub is_outbound: bool,
    pub connected_at: Instant,
    pub last_ping: Option<Instant>,
    pub last_pong: Option<Instant>,
    pub ping_nonce: Option<u64>,
    pub services: ServiceFlags,
    pub best_height: u32,
    pub misbehavior_count: u32,
}

/// Peer manager configuration
#[derive(Debug, Clone)]
pub struct PeerManagerConfig {
    pub max_connections: usize,
    pub max_outbound: usize,
    pub max_inbound: usize,
    pub enable_auto_reconnect: bool,
    pub enable_peer_scoring: bool,
    pub ban_threshold: i32,
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_outbound: DEFAULT_MAX_OUTBOUND,
            max_inbound: DEFAULT_MAX_INBOUND,
            enable_auto_reconnect: true,
            enable_peer_scoring: true,
            ban_threshold: MIN_PEER_SCORE,
        }
    }
}

/// Manages peer connections and scoring
pub struct PeerManager {
    config: PeerManagerConfig,
    network: Network,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    banned_peers: Arc<RwLock<HashMap<SocketAddr, Instant>>>,
    outbound_count: Arc<RwLock<usize>>,
    inbound_count: Arc<RwLock<usize>>,
}

impl PeerManager {
    /// Create new peer manager
    pub fn new(network: Network, config: PeerManagerConfig) -> Self {
        Self {
            config,
            network,
            peers: Arc::new(RwLock::new(HashMap::new())),
            banned_peers: Arc::new(RwLock::new(HashMap::new())),
            outbound_count: Arc::new(RwLock::new(0)),
            inbound_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Add a new peer
    pub async fn add_peer(
        &self,
        addr: SocketAddr,
        peer: Arc<Peer>,
        is_outbound: bool,
        services: ServiceFlags,
        best_height: u32,
    ) -> Result<()> {
        // Check if peer is banned
        if self.is_banned(&addr).await {
            bail!("Peer {} is banned", addr);
        }

        // Check connection limits
        if is_outbound {
            let count = *self.outbound_count.read().await;
            if count >= self.config.max_outbound {
                bail!("Outbound connection limit reached");
            }
        } else {
            let count = *self.inbound_count.read().await;
            if count >= self.config.max_inbound {
                bail!("Inbound connection limit reached");
            }
        }

        // Check total connection limit
        let total = self.peers.read().await.len();
        if total >= self.config.max_connections {
            bail!("Total connection limit reached");
        }

        // Create peer info
        let peer_info = PeerInfo {
            addr,
            peer,
            score: INITIAL_PEER_SCORE,
            is_outbound,
            connected_at: Instant::now(),
            last_ping: None,
            last_pong: None,
            ping_nonce: None,
            services,
            best_height,
            misbehavior_count: 0,
        };

        // Add peer
        self.peers.write().await.insert(addr, peer_info);

        // Update counters
        if is_outbound {
            *self.outbound_count.write().await += 1;
        } else {
            *self.inbound_count.write().await += 1;
        }

        info!(
            "Added {} peer {} (total: {})",
            if is_outbound { "outbound" } else { "inbound" },
            addr,
            total + 1
        );

        Ok(())
    }

    /// Remove a peer
    pub async fn remove_peer(&self, addr: &SocketAddr) -> Result<()> {
        if let Some(peer_info) = self.peers.write().await.remove(addr) {
            // Update counters
            if peer_info.is_outbound {
                *self.outbound_count.write().await -= 1;
            } else {
                *self.inbound_count.write().await -= 1;
            }

            info!("Removed peer {} (score: {})", addr, peer_info.score);
        }

        Ok(())
    }

    /// Update peer score
    pub async fn update_score(&self, addr: &SocketAddr, event: ScoreEvent) -> Result<()> {
        if !self.config.enable_peer_scoring {
            return Ok(());
        }

        let mut peers = self.peers.write().await;
        if let Some(peer_info) = peers.get_mut(addr) {
            let delta = event.score_delta();
            peer_info.score += delta;

            // Clamp score
            peer_info.score = peer_info.score.clamp(MIN_PEER_SCORE, MAX_PEER_SCORE);

            debug!(
                "Updated peer {} score: {} ({:+}) for {:?}",
                addr, peer_info.score, delta, event
            );

            // Check if peer should be banned
            if peer_info.score <= self.config.ban_threshold {
                drop(peers);
                self.ban_peer(addr, Duration::from_secs(3600)).await?;
            }
        }

        Ok(())
    }

    /// Ban a peer
    pub async fn ban_peer(&self, addr: &SocketAddr, duration: Duration) -> Result<()> {
        self.banned_peers
            .write()
            .await
            .insert(*addr, Instant::now() + duration);
        self.remove_peer(addr).await?;
        warn!("Banned peer {} for {:?}", addr, duration);
        Ok(())
    }

    /// Check if peer is banned
    pub async fn is_banned(&self, addr: &SocketAddr) -> bool {
        let mut banned = self.banned_peers.write().await;
        if let Some(ban_until) = banned.get(addr) {
            if Instant::now() < *ban_until {
                return true;
            } else {
                // Ban expired
                banned.remove(addr);
            }
        }
        false
    }

    /// Get peer info
    pub async fn get_peer(&self, addr: &SocketAddr) -> Option<PeerInfo> {
        self.peers.read().await.get(addr).cloned()
    }

    /// Get all peers
    pub async fn get_all_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Get best peers by score
    pub async fn get_best_peers(&self, count: usize) -> Vec<PeerInfo> {
        let mut peers: Vec<PeerInfo> = self.peers.read().await.values().cloned().collect();
        peers.sort_by_key(|p| -p.score);
        peers.truncate(count);
        peers
    }

    /// Send ping to peer
    pub async fn send_ping(&self, addr: &SocketAddr) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(peer_info) = peers.get_mut(addr) {
            let nonce = rand::random();
            peer_info.ping_nonce = Some(nonce);
            peer_info.last_ping = Some(Instant::now());

            // Send ping message
            peer_info
                .peer
                .send_message(crate::message::Message::Ping(nonce))
                .await?;
            debug!("Sent ping to {} with nonce {}", addr, nonce);
        }
        Ok(())
    }

    /// Handle pong response
    pub async fn handle_pong(&self, addr: &SocketAddr, nonce: u64) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(peer_info) = peers.get_mut(addr) {
            if Some(nonce) == peer_info.ping_nonce {
                peer_info.last_pong = Some(Instant::now());
                peer_info.ping_nonce = None;

                // Calculate ping time
                if let Some(ping_time) = peer_info.last_ping {
                    let latency = peer_info.last_pong.unwrap().duration_since(ping_time);
                    debug!("Peer {} ping time: {:?}", addr, latency);

                    // Update score based on response time
                    drop(peers);
                    if latency < Duration::from_millis(100) {
                        self.update_score(addr, ScoreEvent::FastResponse).await?;
                    } else if latency > Duration::from_secs(5) {
                        self.update_score(addr, ScoreEvent::SlowResponse).await?;
                    }
                }
            } else {
                warn!("Received unexpected pong from {} (nonce mismatch)", addr);
            }
        }
        Ok(())
    }

    /// Start ping/pong monitor
    pub async fn start_ping_monitor(self: Arc<Self>) {
        let mut ticker = interval(PING_INTERVAL);

        tokio::spawn(async move {
            loop {
                ticker.tick().await;

                // Get all connected peers
                let peers = self.get_all_peers().await;

                for peer_info in peers {
                    // Check for ping timeout
                    if let Some(last_ping) = peer_info.last_ping {
                        if peer_info.ping_nonce.is_some() {
                            // Waiting for pong
                            if last_ping.elapsed() > PING_TIMEOUT {
                                warn!("Peer {} ping timeout", peer_info.addr);
                                let _ = self
                                    .update_score(&peer_info.addr, ScoreEvent::Timeout)
                                    .await;
                                let _ = self.remove_peer(&peer_info.addr).await;
                                continue;
                            }
                        }
                    }

                    // Send new ping
                    if peer_info.ping_nonce.is_none() {
                        let _ = self.send_ping(&peer_info.addr).await;
                    }
                }

                // Clean up expired bans
                let now = Instant::now();
                self.banned_peers
                    .write()
                    .await
                    .retain(|_, ban_until| *ban_until > now);
            }
        });
    }

    /// Get connection statistics
    pub async fn get_stats(&self) -> ConnectionStats {
        ConnectionStats {
            total_peers: self.peers.read().await.len(),
            outbound: *self.outbound_count.read().await,
            inbound: *self.inbound_count.read().await,
            banned: self.banned_peers.read().await.len(),
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub total_peers: usize,
    pub outbound: usize,
    pub inbound: usize,
    pub banned: usize,
}
