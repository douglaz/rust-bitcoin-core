use anyhow::{bail, Result};
use bitcoin::Txid;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Maximum number of in-flight requests per peer
const MAX_PEER_TX_IN_FLIGHT: usize = 100;

/// Maximum time to wait for a transaction response
const TX_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of transaction announcements to track
const MAX_TX_ANNOUNCEMENTS: usize = 50000;

/// Time to wait before requesting the same transaction from another peer
const TX_REQUEST_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Transaction announcement from a peer
#[derive(Debug, Clone)]
pub struct TxAnnouncement {
    /// Transaction ID
    pub txid: Txid,
    /// Peer that announced the transaction
    pub peer: SocketAddr,
    /// Time when the announcement was received
    pub received_at: Instant,
    /// Whether we should request this transaction
    pub should_request: bool,
    /// Time when we can request this (for rate limiting)
    pub request_time: Instant,
}

/// In-flight transaction request
#[derive(Debug, Clone)]
pub struct TxRequest {
    /// Transaction ID being requested
    pub txid: Txid,
    /// Peer we requested from
    pub peer: SocketAddr,
    /// Time when request was sent
    pub requested_at: Instant,
    /// Whether this is a retry
    pub is_retry: bool,
}

/// Transaction relay statistics
#[derive(Debug, Clone, Default)]
pub struct TxRelayStats {
    /// Total announcements received
    pub announcements_received: usize,
    /// Total requests sent
    pub requests_sent: usize,
    /// Total transactions received
    pub transactions_received: usize,
    /// Duplicate announcements
    pub duplicate_announcements: usize,
    /// Request timeouts
    pub request_timeouts: usize,
    /// Requests deduplicated
    pub requests_deduplicated: usize,
}

/// Tracks transaction announcements and requests to prevent duplication
pub struct TxRequestTracker {
    /// Announced transactions waiting to be requested
    announced: HashMap<Txid, Vec<TxAnnouncement>>,

    /// In-flight requests (txid -> request info)
    in_flight: HashMap<Txid, TxRequest>,

    /// Per-peer in-flight count
    peer_in_flight: HashMap<SocketAddr, HashSet<Txid>>,

    /// Transactions we've already seen (either received or rejected)
    seen_transactions: HashSet<Txid>,

    /// Queue of transactions to request
    request_queue: VecDeque<(Txid, SocketAddr)>,

    /// Statistics
    stats: TxRelayStats,

    /// Recent rejects to avoid re-requesting
    recent_rejects: HashMap<Txid, Instant>,
}

impl Default for TxRequestTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TxRequestTracker {
    /// Create a new transaction request tracker
    pub fn new() -> Self {
        Self {
            announced: HashMap::new(),
            in_flight: HashMap::new(),
            peer_in_flight: HashMap::new(),
            seen_transactions: HashSet::new(),
            request_queue: VecDeque::new(),
            stats: TxRelayStats::default(),
            recent_rejects: HashMap::new(),
        }
    }

    /// Handle a transaction announcement from a peer
    pub fn on_tx_announcement(&mut self, txid: Txid, peer: SocketAddr) -> Result<bool> {
        self.stats.announcements_received += 1;

        // Check if we've already seen this transaction
        if self.seen_transactions.contains(&txid) {
            self.stats.duplicate_announcements += 1;
            debug!(
                "Ignoring announcement of already-seen transaction {} from {}",
                txid, peer
            );
            return Ok(false);
        }

        // Check if recently rejected
        if let Some(rejected_at) = self.recent_rejects.get(&txid) {
            if rejected_at.elapsed() < Duration::from_secs(600) {
                debug!(
                    "Ignoring announcement of recently rejected transaction {} from {}",
                    txid, peer
                );
                return Ok(false);
            } else {
                self.recent_rejects.remove(&txid);
            }
        }

        // Check if already in-flight
        if self.in_flight.contains_key(&txid) {
            // Add to announced list for potential retry from different peer
            let announcement = TxAnnouncement {
                txid,
                peer,
                received_at: Instant::now(),
                should_request: false, // Don't request while another is in-flight
                request_time: Instant::now() + TX_REQUEST_RETRY_DELAY,
            };

            self.announced.entry(txid).or_default().push(announcement);

            self.stats.duplicate_announcements += 1;
            debug!(
                "Transaction {} already in-flight, queuing announcement from {}",
                txid, peer
            );
            return Ok(false);
        }

        // Add new announcement
        let announcement = TxAnnouncement {
            txid,
            peer,
            received_at: Instant::now(),
            should_request: true,
            request_time: Instant::now(), // Can request immediately
        };

        let is_new = !self.announced.contains_key(&txid);
        self.announced.entry(txid).or_default().push(announcement);

        // Clean up old announcements if we have too many
        if self.announced.len() > MAX_TX_ANNOUNCEMENTS {
            self.cleanup_old_announcements();
        }

        info!("New transaction announcement {} from {}", txid, peer);
        Ok(is_new)
    }

    /// Get next transaction to request
    pub fn get_next_request(&mut self) -> Option<(Txid, SocketAddr)> {
        let now = Instant::now();

        // First, check for any timeouts
        self.check_timeouts();

        // Find a transaction to request
        for (txid, announcements) in &self.announced {
            // Skip if already in-flight
            if self.in_flight.contains_key(txid) {
                continue;
            }

            // Find best peer to request from
            for announcement in announcements {
                if !announcement.should_request {
                    continue;
                }

                if announcement.request_time > now {
                    continue; // Rate limited
                }

                // Check peer's in-flight limit
                let peer_count = self
                    .peer_in_flight
                    .get(&announcement.peer)
                    .map(|set| set.len())
                    .unwrap_or(0);

                if peer_count >= MAX_PEER_TX_IN_FLIGHT {
                    continue;
                }

                return Some((*txid, announcement.peer));
            }
        }

        None
    }

    /// Mark a transaction as requested
    pub fn mark_requested(&mut self, txid: Txid, peer: SocketAddr) -> Result<()> {
        if self.in_flight.contains_key(&txid) {
            bail!("Transaction {} already in-flight", txid);
        }

        let request = TxRequest {
            txid,
            peer,
            requested_at: Instant::now(),
            is_retry: self
                .announced
                .get(&txid)
                .map(|ann| ann.len() > 1)
                .unwrap_or(false),
        };

        self.in_flight.insert(txid, request);
        self.peer_in_flight.entry(peer).or_default().insert(txid);

        self.stats.requests_sent += 1;

        // Mark announcement as requested
        if let Some(announcements) = self.announced.get_mut(&txid) {
            for ann in announcements {
                if ann.peer == peer {
                    ann.should_request = false;
                }
            }
        }

        debug!("Marked transaction {} as requested from {}", txid, peer);
        Ok(())
    }

    /// Handle receiving a transaction
    pub fn on_tx_received(&mut self, txid: Txid, from_peer: SocketAddr) {
        self.stats.transactions_received += 1;

        // Remove from in-flight
        if let Some(request) = self.in_flight.remove(&txid) {
            if let Some(peer_set) = self.peer_in_flight.get_mut(&request.peer) {
                peer_set.remove(&txid);
            }

            let latency = request.requested_at.elapsed();
            debug!(
                "Received transaction {} from {} (latency: {:?})",
                txid, from_peer, latency
            );
        }

        // Mark as seen
        self.seen_transactions.insert(txid);

        // Remove from announced
        self.announced.remove(&txid);
    }

    /// Handle transaction rejection
    pub fn on_tx_rejected(&mut self, txid: Txid, from_peer: SocketAddr) {
        warn!("Transaction {} rejected by {}", txid, from_peer);

        // Remove from in-flight
        if let Some(request) = self.in_flight.remove(&txid) {
            if let Some(peer_set) = self.peer_in_flight.get_mut(&request.peer) {
                peer_set.remove(&txid);
            }
        }

        // Mark as recently rejected
        self.recent_rejects.insert(txid, Instant::now());

        // Remove from announced - we don't want to request again soon
        self.announced.remove(&txid);
    }

    /// Check for request timeouts
    fn check_timeouts(&mut self) {
        let now = Instant::now();
        let mut timed_out = Vec::new();

        for (txid, request) in &self.in_flight {
            if now.duration_since(request.requested_at) > TX_REQUEST_TIMEOUT {
                timed_out.push((*txid, request.peer));
            }
        }

        for (txid, peer) in timed_out {
            warn!("Transaction request {} to {} timed out", txid, peer);
            self.stats.request_timeouts += 1;

            // Remove from in-flight
            self.in_flight.remove(&txid);
            if let Some(peer_set) = self.peer_in_flight.get_mut(&peer) {
                peer_set.remove(&txid);
            }

            // Mark announcements from other peers as requestable
            if let Some(announcements) = self.announced.get_mut(&txid) {
                for ann in announcements {
                    if ann.peer != peer {
                        ann.should_request = true;
                        ann.request_time = now + TX_REQUEST_RETRY_DELAY;
                    }
                }
            }
        }
    }

    /// Clean up old announcements to prevent memory growth
    fn cleanup_old_announcements(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(1200); // 20 minutes

        self.announced.retain(|_, announcements| {
            announcements.retain(|ann| ann.received_at > cutoff);
            !announcements.is_empty()
        });

        // Also clean up old rejects
        self.recent_rejects
            .retain(|_, rejected_at| rejected_at.elapsed() < Duration::from_secs(600));
    }

    /// Get relay statistics
    pub fn get_stats(&self) -> TxRelayStats {
        self.stats.clone()
    }

    /// Check if we should request a transaction
    pub fn should_request_tx(&self, txid: &Txid) -> bool {
        !self.seen_transactions.contains(txid)
            && !self.in_flight.contains_key(txid)
            && !self.recent_rejects.contains_key(txid)
    }

    /// Get number of in-flight requests for a peer
    pub fn get_peer_in_flight_count(&self, peer: &SocketAddr) -> usize {
        self.peer_in_flight
            .get(peer)
            .map(|set| set.len())
            .unwrap_or(0)
    }

    /// Clear all state (for testing or reset)
    pub fn clear(&mut self) {
        self.announced.clear();
        self.in_flight.clear();
        self.peer_in_flight.clear();
        self.seen_transactions.clear();
        self.request_queue.clear();
        self.recent_rejects.clear();
        self.stats = TxRelayStats::default();
    }
}
