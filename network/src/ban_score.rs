use anyhow::Result;
use bitcoin::{Block, BlockHash, Transaction, Txid};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Ban score thresholds
const BAN_SCORE_THRESHOLD: i32 = 100;
const DISCONNECT_SCORE_THRESHOLD: i32 = 50;

/// Misbehavior types with associated scores
#[derive(Debug, Clone)]
pub enum Misbehavior {
    // Protocol violations (severe)
    InvalidMessageChecksum,           // +100 (instant ban)
    InvalidNetworkMagic,              // +100 (instant ban)
    OversizedMessage,                 // +100 (instant ban)
    
    // Block-related misbehavior
    InvalidBlock,                     // +100 (instant ban)
    InvalidBlockHeader,               // +50
    DuplicateBlock,                   // +20
    UnrequestedBlock,                 // +20
    OrphanBlock,                      // +1
    StaleBlock,                       // +10
    BlockFromFuture,                  // +20
    
    // Transaction-related misbehavior
    InvalidTransaction,               // +10
    DuplicateTransaction,             // +5
    OrphanTransaction,                // +1
    TransactionFeeTooLow,             // +0 (no penalty)
    ConflictingTransaction,           // +5
    
    // Header-related misbehavior
    InvalidHeader,                    // +20
    DuplicateHeaders,                 // +20
    TooManyHeaders,                   // +20
    UnconnectedHeaders,               // +10
    HeadersOutOfOrder,                // +20
    
    // Inventory-related misbehavior
    TooManyInventoryItems,            // +20
    UnknownInventoryType,             // +10
    RepeatedInventory,                // +1
    
    // Connection-related misbehavior
    InvalidVersion,                   // +10
    IncompatibleVersion,              // +1
    DuplicateVersion,                 // +10
    UnexpectedMessage,                // +10
    TimeoutViolation,                 // +20
    PingTimeout,                      // +20
    
    // DoS-related misbehavior
    Flooding,                         // +50
    ResourceExhaustion,               // +50
    SlowResponse,                     // +5
    ExcessiveBandwidth,               // +20
    TooManyConnections,               // +10
    
    // Compact block violations (BIP152)
    InvalidCompactBlock,              // +20
    InvalidBlockTxn,                  // +20
    UnrequestedCompactBlock,          // +10
    CompactBlockReconstuctionFailed,  // +5
    
    // SPV/Bloom filter violations (BIP37)
    InvalidBloomFilter,               // +20
    BloomFilterTooLarge,              // +20
    TooManyBloomFilters,              // +20
    
    // Address-related misbehavior
    InvalidAddress,                   // +10
    TooManyAddresses,                 // +10
    SelfAdvertisement,                // +5
    
    // Other protocol violations
    InvalidCheckpoint,                // +50
    InvalidProof,                     // +50
    Custom(String, i32),              // Custom score
}

impl Misbehavior {
    /// Get the ban score for this misbehavior
    pub fn score(&self) -> i32 {
        match self {
            // Instant ban offenses
            Misbehavior::InvalidMessageChecksum => 100,
            Misbehavior::InvalidNetworkMagic => 100,
            Misbehavior::OversizedMessage => 100,
            Misbehavior::InvalidBlock => 100,
            
            // Severe offenses
            Misbehavior::InvalidBlockHeader => 50,
            Misbehavior::Flooding => 50,
            Misbehavior::ResourceExhaustion => 50,
            Misbehavior::InvalidCheckpoint => 50,
            Misbehavior::InvalidProof => 50,
            
            // Moderate offenses
            Misbehavior::DuplicateBlock => 20,
            Misbehavior::UnrequestedBlock => 20,
            Misbehavior::BlockFromFuture => 20,
            Misbehavior::InvalidHeader => 20,
            Misbehavior::DuplicateHeaders => 20,
            Misbehavior::TooManyHeaders => 20,
            Misbehavior::HeadersOutOfOrder => 20,
            Misbehavior::TooManyInventoryItems => 20,
            Misbehavior::TimeoutViolation => 20,
            Misbehavior::PingTimeout => 20,
            Misbehavior::ExcessiveBandwidth => 20,
            Misbehavior::InvalidCompactBlock => 20,
            Misbehavior::InvalidBlockTxn => 20,
            Misbehavior::InvalidBloomFilter => 20,
            Misbehavior::BloomFilterTooLarge => 20,
            Misbehavior::TooManyBloomFilters => 20,
            
            // Minor offenses
            Misbehavior::StaleBlock => 10,
            Misbehavior::UnconnectedHeaders => 10,
            Misbehavior::InvalidTransaction => 10,
            Misbehavior::UnknownInventoryType => 10,
            Misbehavior::InvalidVersion => 10,
            Misbehavior::DuplicateVersion => 10,
            Misbehavior::UnexpectedMessage => 10,
            Misbehavior::TooManyConnections => 10,
            Misbehavior::UnrequestedCompactBlock => 10,
            Misbehavior::InvalidAddress => 10,
            Misbehavior::TooManyAddresses => 10,
            
            // Minimal offenses
            Misbehavior::DuplicateTransaction => 5,
            Misbehavior::ConflictingTransaction => 5,
            Misbehavior::SlowResponse => 5,
            Misbehavior::CompactBlockReconstuctionFailed => 5,
            Misbehavior::SelfAdvertisement => 5,
            
            // Warnings (minimal or no penalty)
            Misbehavior::OrphanBlock => 1,
            Misbehavior::OrphanTransaction => 1,
            Misbehavior::IncompatibleVersion => 1,
            Misbehavior::RepeatedInventory => 1,
            Misbehavior::TransactionFeeTooLow => 0,
            
            // Custom score
            Misbehavior::Custom(_, score) => *score,
        }
    }
    
    /// Check if this misbehavior should trigger instant ban
    pub fn is_instant_ban(&self) -> bool {
        self.score() >= 100
    }
}

/// Ban score tracker for a peer
#[derive(Debug, Clone)]
pub struct PeerBanScore {
    pub addr: SocketAddr,
    pub score: i32,
    pub violations: Vec<(Instant, Misbehavior)>,
    pub last_violation: Option<Instant>,
    pub ban_until: Option<Instant>,
    pub is_whitelisted: bool,
}

impl PeerBanScore {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            score: 0,
            violations: Vec::new(),
            last_violation: None,
            ban_until: None,
            is_whitelisted: false,
        }
    }
    
    /// Add misbehavior and update score
    pub fn add_misbehavior(&mut self, misbehavior: Misbehavior) -> BanDecision {
        // Whitelisted peers are never banned
        if self.is_whitelisted {
            debug!(
                "Peer {} is whitelisted, ignoring misbehavior: {:?}",
                self.addr, misbehavior
            );
            return BanDecision::None;
        }
        
        let score_delta = misbehavior.score();
        self.score += score_delta;
        self.violations.push((Instant::now(), misbehavior.clone()));
        self.last_violation = Some(Instant::now());
        
        warn!(
            "Peer {} misbehavior: {:?} (score: {} -> {})",
            self.addr,
            misbehavior,
            self.score - score_delta,
            self.score
        );
        
        // Check for instant ban
        if misbehavior.is_instant_ban() {
            self.ban_until = Some(Instant::now() + Duration::from_secs(86400)); // 24 hours
            return BanDecision::Ban(Duration::from_secs(86400));
        }
        
        // Check score thresholds
        if self.score >= BAN_SCORE_THRESHOLD {
            self.ban_until = Some(Instant::now() + Duration::from_secs(86400)); // 24 hours
            BanDecision::Ban(Duration::from_secs(86400))
        } else if self.score >= DISCONNECT_SCORE_THRESHOLD {
            BanDecision::Disconnect
        } else {
            BanDecision::None
        }
    }
    
    /// Decay score over time
    pub fn decay_score(&mut self, decay_rate: f64) {
        if let Some(last) = self.last_violation {
            let elapsed = Instant::now().duration_since(last);
            let hours = elapsed.as_secs() / 3600;
            
            if hours > 0 {
                let decay = (self.score as f64 * decay_rate * hours as f64) as i32;
                self.score = (self.score - decay).max(0);
                
                // Remove old violations
                let cutoff = Instant::now() - Duration::from_secs(86400 * 7); // 7 days
                self.violations.retain(|(time, _)| *time > cutoff);
            }
        }
    }
    
    /// Check if peer is currently banned
    pub fn is_banned(&self) -> bool {
        if let Some(ban_until) = self.ban_until {
            ban_until > Instant::now()
        } else {
            false
        }
    }
}

/// Ban decision
#[derive(Debug, Clone)]
pub enum BanDecision {
    None,
    Disconnect,
    Ban(Duration),
}

/// Ban score manager
pub struct BanScoreManager {
    scores: Arc<RwLock<HashMap<SocketAddr, PeerBanScore>>>,
    config: BanScoreConfig,
}

/// Ban score configuration
#[derive(Debug, Clone)]
pub struct BanScoreConfig {
    pub ban_threshold: i32,
    pub disconnect_threshold: i32,
    pub default_ban_duration: Duration,
    pub score_decay_rate: f64, // Per hour
    pub whitelist: Vec<SocketAddr>,
    pub track_violations: bool,
}

impl Default for BanScoreConfig {
    fn default() -> Self {
        Self {
            ban_threshold: BAN_SCORE_THRESHOLD,
            disconnect_threshold: DISCONNECT_SCORE_THRESHOLD,
            default_ban_duration: Duration::from_secs(86400), // 24 hours
            score_decay_rate: 0.01, // 1% per hour
            whitelist: Vec::new(),
            track_violations: true,
        }
    }
}

impl BanScoreManager {
    pub fn new(config: BanScoreConfig) -> Self {
        Self {
            scores: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    
    /// Report misbehavior for a peer
    pub async fn report_misbehavior(
        &self,
        addr: SocketAddr,
        misbehavior: Misbehavior,
    ) -> BanDecision {
        let mut scores = self.scores.write().await;
        let score = scores.entry(addr).or_insert_with(|| {
            let mut score = PeerBanScore::new(addr);
            score.is_whitelisted = self.config.whitelist.contains(&addr);
            score
        });
        
        score.add_misbehavior(misbehavior)
    }
    
    /// Check if a peer is banned
    pub async fn is_banned(&self, addr: &SocketAddr) -> bool {
        let scores = self.scores.read().await;
        scores.get(addr).map_or(false, |s| s.is_banned())
    }
    
    /// Get ban score for a peer
    pub async fn get_score(&self, addr: &SocketAddr) -> i32 {
        let scores = self.scores.read().await;
        scores.get(addr).map_or(0, |s| s.score)
    }
    
    /// Clear ban for a peer
    pub async fn clear_ban(&self, addr: &SocketAddr) {
        let mut scores = self.scores.write().await;
        if let Some(score) = scores.get_mut(addr) {
            score.ban_until = None;
            score.score = 0;
            score.violations.clear();
        }
    }
    
    /// Decay scores for all peers
    pub async fn decay_all_scores(&self) {
        let mut scores = self.scores.write().await;
        for score in scores.values_mut() {
            score.decay_score(self.config.score_decay_rate);
        }
        
        // Remove peers with zero score and no recent violations
        let cutoff = Instant::now() - Duration::from_secs(86400 * 30); // 30 days
        scores.retain(|_, score| {
            score.score > 0 || 
            score.is_banned() ||
            score.last_violation.map_or(false, |t| t > cutoff)
        });
    }
    
    /// Get statistics
    pub async fn get_stats(&self) -> BanScoreStats {
        let scores = self.scores.read().await;
        
        let total_peers = scores.len();
        let banned_peers = scores.values().filter(|s| s.is_banned()).count();
        let high_score_peers = scores.values()
            .filter(|s| s.score >= self.config.disconnect_threshold)
            .count();
        
        BanScoreStats {
            total_peers,
            banned_peers,
            high_score_peers,
        }
    }
    
    /// Start background decay task
    pub fn start_decay_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
            
            loop {
                interval.tick().await;
                self.decay_all_scores().await;
                
                let stats = self.get_stats().await;
                debug!(
                    "Ban score decay complete. Tracking {} peers, {} banned",
                    stats.total_peers, stats.banned_peers
                );
            }
        });
    }
}

/// Ban score statistics
#[derive(Debug, Clone, Default)]
pub struct BanScoreStats {
    pub total_peers: usize,
    pub banned_peers: usize,
    pub high_score_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ban_scoring() {
        let manager = BanScoreManager::new(BanScoreConfig::default());
        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        
        // Minor misbehavior
        let decision = manager.report_misbehavior(
            addr,
            Misbehavior::OrphanTransaction
        ).await;
        assert!(matches!(decision, BanDecision::None));
        assert_eq!(manager.get_score(&addr).await, 1);
        
        // Accumulate to disconnect threshold
        for _ in 0..10 {
            manager.report_misbehavior(addr, Misbehavior::SlowResponse).await;
        }
        
        let decision = manager.report_misbehavior(
            addr,
            Misbehavior::InvalidTransaction
        ).await;
        assert!(matches!(decision, BanDecision::Disconnect));
        
        // Instant ban offense
        let decision = manager.report_misbehavior(
            addr,
            Misbehavior::InvalidBlock
        ).await;
        assert!(matches!(decision, BanDecision::Ban(_)));
        assert!(manager.is_banned(&addr).await);
    }
    
    #[test]
    fn test_misbehavior_scores() {
        assert_eq!(Misbehavior::InvalidBlock.score(), 100);
        assert_eq!(Misbehavior::InvalidBlockHeader.score(), 50);
        assert_eq!(Misbehavior::DuplicateBlock.score(), 20);
        assert_eq!(Misbehavior::InvalidTransaction.score(), 10);
        assert_eq!(Misbehavior::OrphanTransaction.score(), 1);
        assert_eq!(Misbehavior::TransactionFeeTooLow.score(), 0);
        
        assert!(Misbehavior::InvalidBlock.is_instant_ban());
        assert!(!Misbehavior::InvalidTransaction.is_instant_ban());
    }
}