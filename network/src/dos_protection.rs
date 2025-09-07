use anyhow::Result;
use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::message::Message;
use crate::rate_limiter::{BandwidthConfig, BandwidthManager, RateLimiter};

/// DoS protection configuration
#[derive(Debug, Clone)]
pub struct DosProtectionConfig {
    /// Enable DoS protection
    pub enabled: bool,

    /// Message rate limits (messages per second)
    pub max_messages_per_second: usize,
    pub max_blocks_per_minute: usize,
    pub max_headers_per_message: usize,
    pub max_inv_per_message: usize,
    pub max_addr_per_message: usize,

    /// Connection limits
    pub max_connections_per_ip: usize,
    pub connection_rate_limit: Duration,
    pub max_pending_connections: usize,

    /// Misbehavior thresholds
    pub ban_threshold: i32,
    pub ban_duration: Duration,
    pub disconnect_threshold: i32,

    /// Resource limits
    pub max_orphan_transactions: usize,
    pub max_pending_blocks: usize,
    pub max_mempool_size: usize,

    /// Bandwidth limits
    pub bandwidth_config: BandwidthConfig,
}

impl Default for DosProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_messages_per_second: 100,
            max_blocks_per_minute: 20,
            max_headers_per_message: 2000,
            max_inv_per_message: 50000,
            max_addr_per_message: 1000,
            max_connections_per_ip: 5,
            connection_rate_limit: Duration::from_secs(1),
            max_pending_connections: 100,
            ban_threshold: -100,
            ban_duration: Duration::from_secs(86400), // 24 hours
            disconnect_threshold: -50,
            max_orphan_transactions: 100,
            max_pending_blocks: 10,
            max_mempool_size: 300_000_000, // 300 MB
            bandwidth_config: BandwidthConfig::default(),
        }
    }
}

/// Ban entry for a peer
#[derive(Debug, Clone)]
pub struct BanEntry {
    pub addr: SocketAddr,
    pub reason: String,
    pub banned_at: Instant,
    pub ban_until: Instant,
    pub score: i32,
}

/// Serializable ban entry for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableBanEntry {
    addr: String,
    reason: String,
    banned_at_unix: u64,
    ban_duration_secs: u64,
    score: i32,
}

/// DoS protection statistics
#[derive(Debug, Default, Clone)]
pub struct DosProtectionStats {
    pub messages_rejected: u64,
    pub connections_rejected: u64,
    pub peers_banned: u64,
    pub peers_disconnected: u64,
    pub bandwidth_throttled: u64,
    pub orphans_evicted: u64,
}

/// DoS protection manager
pub struct DosProtectionManager {
    /// Configuration
    config: DosProtectionConfig,

    /// Bandwidth manager
    bandwidth_manager: Arc<BandwidthManager>,

    /// Message rate limiters per peer
    message_limiters: Arc<RwLock<HashMap<SocketAddr, Arc<RateLimiter>>>>,

    /// Connection tracking
    connection_times: Arc<RwLock<HashMap<SocketAddr, VecDeque<Instant>>>>,
    connections_per_ip: Arc<RwLock<HashMap<String, usize>>>,

    /// Ban list
    ban_list: Arc<RwLock<HashMap<SocketAddr, BanEntry>>>,

    /// Peer scores
    peer_scores: Arc<RwLock<HashMap<SocketAddr, i32>>>,

    /// Resource tracking
    orphan_count: Arc<RwLock<usize>>,
    pending_blocks: Arc<RwLock<HashSet<BlockHash>>>,
    mempool_size: Arc<RwLock<usize>>,

    /// Statistics
    stats: Arc<RwLock<DosProtectionStats>>,
}

impl DosProtectionManager {
    /// Create new DoS protection manager
    pub fn new(config: DosProtectionConfig) -> Self {
        let bandwidth_manager = Arc::new(BandwidthManager::new(config.bandwidth_config.clone()));

        Self {
            config,
            bandwidth_manager,
            message_limiters: Arc::new(RwLock::new(HashMap::new())),
            connection_times: Arc::new(RwLock::new(HashMap::new())),
            connections_per_ip: Arc::new(RwLock::new(HashMap::new())),
            ban_list: Arc::new(RwLock::new(HashMap::new())),
            peer_scores: Arc::new(RwLock::new(HashMap::new())),
            orphan_count: Arc::new(RwLock::new(0)),
            pending_blocks: Arc::new(RwLock::new(HashSet::new())),
            mempool_size: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(DosProtectionStats::default())),
        }
    }

    /// Check if a peer is banned
    pub async fn is_banned(&self, addr: &SocketAddr) -> bool {
        let ban_list = self.ban_list.read().await;
        if let Some(entry) = ban_list.get(addr) {
            if Instant::now() < entry.ban_until {
                return true;
            }
        }
        false
    }

    /// Check if connection should be allowed
    pub async fn should_allow_connection(&self, addr: &SocketAddr) -> Result<bool> {
        if !self.config.enabled {
            return Ok(true);
        }

        // Check if banned
        if self.is_banned(addr).await {
            self.stats.write().await.connections_rejected += 1;
            return Ok(false);
        }

        // Check connection rate limit
        let mut connection_times = self.connection_times.write().await;
        let times = connection_times.entry(*addr).or_insert_with(VecDeque::new);

        let now = Instant::now();
        let cutoff = now - self.config.connection_rate_limit;

        // Remove old connection times
        while let Some(&front) = times.front() {
            if front < cutoff {
                times.pop_front();
            } else {
                break;
            }
        }

        // Check if exceeding rate limit
        if times.len() >= self.config.max_connections_per_ip {
            warn!("Connection rate limit exceeded for {}", addr);
            self.stats.write().await.connections_rejected += 1;
            return Ok(false);
        }

        times.push_back(now);

        // Note: connections_per_ip tracking would need to be handled by the connection manager
        // when connections are actually established/closed. For now, we only check rate limits
        // based on connection attempts within the time window.

        Ok(true)
    }

    /// Check if message should be processed
    pub async fn should_process_message(
        &self,
        peer_addr: &SocketAddr,
        message: &Message,
    ) -> Result<bool> {
        if !self.config.enabled {
            return Ok(true);
        }

        // Check if banned
        if self.is_banned(peer_addr).await {
            return Ok(false);
        }

        // Get or create rate limiter for peer
        let mut limiters = self.message_limiters.write().await;
        let limiter = limiters
            .entry(*peer_addr)
            .or_insert_with(|| {
                Arc::new(RateLimiter::new(
                    self.config.max_messages_per_second,
                    Some(self.config.max_messages_per_second),  // Burst equals rate for strict limiting
                ))
            })
            .clone();
        drop(limiters);

        // Check message rate limit
        if !limiter.try_acquire(1).await? {
            warn!("Message rate limit exceeded for {}", peer_addr);
            self.stats.write().await.messages_rejected += 1;
            self.adjust_peer_score(peer_addr, -5, "Message rate limit exceeded")
                .await?;
            return Ok(false);
        }

        // Check message-specific limits
        match message {
            Message::Headers(headers) => {
                if headers.len() > self.config.max_headers_per_message {
                    warn!("Too many headers from {}: {}", peer_addr, headers.len());
                    self.adjust_peer_score(peer_addr, -10, "Too many headers")
                        .await?;
                    return Ok(false);
                }
            }
            Message::Inv(inv) => {
                if inv.len() > self.config.max_inv_per_message {
                    warn!("Too many inv items from {}: {}", peer_addr, inv.len());
                    self.adjust_peer_score(peer_addr, -10, "Too many inv items")
                        .await?;
                    return Ok(false);
                }
            }
            Message::Addr(addrs) => {
                if addrs.len() > self.config.max_addr_per_message {
                    warn!("Too many addresses from {}: {}", peer_addr, addrs.len());
                    self.adjust_peer_score(peer_addr, -5, "Too many addresses")
                        .await?;
                    return Ok(false);
                }
            }
            _ => {}
        }

        // Check bandwidth limits
        let message_size = self.estimate_message_size(message);
        if let Err(e) = self
            .bandwidth_manager
            .acquire_download(&peer_addr.to_string(), message_size)
            .await
        {
            debug!("Bandwidth limit exceeded for {}: {}", peer_addr, e);
            self.stats.write().await.bandwidth_throttled += 1;
            return Ok(false);
        }

        Ok(true)
    }

    /// Adjust peer score
    pub async fn adjust_peer_score(
        &self,
        peer_addr: &SocketAddr,
        delta: i32,
        reason: &str,
    ) -> Result<()> {
        let should_ban;
        let should_disconnect;
        let new_score;
        
        {
            let mut scores = self.peer_scores.write().await;
            let score = scores.entry(*peer_addr).or_insert(0);
            *score += delta;
            new_score = *score;

            info!(
                "Adjusted score for {} by {} (reason: {}), new score: {}",
                peer_addr, delta, reason, new_score
            );

            should_ban = new_score <= self.config.ban_threshold;
            should_disconnect = !should_ban && new_score <= self.config.disconnect_threshold;
        } // Release the lock before calling ban_peer

        // Check if should ban
        if should_ban {
            self.ban_peer(peer_addr, reason).await?;
        } else if should_disconnect {
            warn!(
                "Peer {} should be disconnected (score: {})",
                peer_addr, new_score
            );
            self.stats.write().await.peers_disconnected += 1;
        }

        Ok(())
    }

    /// Ban a peer
    pub async fn ban_peer(&self, addr: &SocketAddr, reason: &str) -> Result<()> {
        let ban_entry = BanEntry {
            addr: *addr,
            reason: reason.to_string(),
            banned_at: Instant::now(),
            ban_until: Instant::now() + self.config.ban_duration,
            score: self
                .peer_scores
                .read()
                .await
                .get(addr)
                .copied()
                .unwrap_or(0),
        };

        self.ban_list.write().await.insert(*addr, ban_entry.clone());
        self.stats.write().await.peers_banned += 1;

        error!(
            "Banned peer {} for {} hours (reason: {})",
            addr,
            self.config.ban_duration.as_secs() / 3600,
            reason
        );

        // Save ban list to storage
        self.save_ban_list().await?;

        Ok(())
    }

    /// Unban a peer
    pub async fn unban_peer(&self, addr: &SocketAddr) -> Result<()> {
        if self.ban_list.write().await.remove(addr).is_some() {
            info!("Unbanned peer {}", addr);
            self.save_ban_list().await?;
        }
        Ok(())
    }

    /// Clean expired bans
    pub async fn clean_expired_bans(&self) {
        let now = Instant::now();
        let mut ban_list = self.ban_list.write().await;

        ban_list.retain(|addr, entry| {
            if now >= entry.ban_until {
                info!("Ban expired for {}", addr);
                false
            } else {
                true
            }
        });
    }

    /// Clean expired bans (returns Result for compatibility)
    pub async fn cleanup_expired_bans(&self) -> Result<()> {
        self.clean_expired_bans().await;
        Ok(())
    }

    /// Handle peer disconnection
    pub async fn peer_disconnected(&self, addr: &SocketAddr) {
        // Clean up rate limiter
        self.message_limiters.write().await.remove(addr);

        // Update connections per IP
        let ip = addr.ip().to_string();
        let mut connections_per_ip = self.connections_per_ip.write().await;
        if let Some(count) = connections_per_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                connections_per_ip.remove(&ip);
            }
        }

        // Remove from bandwidth manager
        self.bandwidth_manager.remove_peer(&addr.to_string()).await;
    }

    /// Check resource limits
    pub async fn check_resource_limits(&self) -> Result<()> {
        // Check orphan transaction limit
        let orphan_count = *self.orphan_count.read().await;
        if orphan_count > self.config.max_orphan_transactions {
            warn!("Orphan transaction limit exceeded: {}", orphan_count);
            self.stats.write().await.orphans_evicted +=
                (orphan_count - self.config.max_orphan_transactions) as u64;
        }

        // Check pending blocks limit
        let pending_count = self.pending_blocks.read().await.len();
        if pending_count > self.config.max_pending_blocks {
            warn!("Pending blocks limit exceeded: {}", pending_count);
        }

        // Check mempool size
        let mempool_size = *self.mempool_size.read().await;
        if mempool_size > self.config.max_mempool_size {
            warn!(
                "Mempool size limit exceeded: {} MB",
                mempool_size / 1_000_000
            );
        }

        Ok(())
    }

    /// Update orphan count
    pub async fn update_orphan_count(&self, count: usize) {
        *self.orphan_count.write().await = count;
    }

    /// Update mempool size
    pub async fn update_mempool_size(&self, size: usize) {
        *self.mempool_size.write().await = size;
    }

    /// Add pending block
    pub async fn add_pending_block(&self, hash: BlockHash) {
        self.pending_blocks.write().await.insert(hash);
    }

    /// Remove pending block
    pub async fn remove_pending_block(&self, hash: &BlockHash) {
        self.pending_blocks.write().await.remove(hash);
    }

    /// Get statistics
    pub async fn get_stats(&self) -> DosProtectionStats {
        self.stats.read().await.clone()
    }

    /// Register a new connection
    pub async fn register_connection(&self, addr: &SocketAddr) {
        let ip = addr.ip().to_string();
        let mut connections_per_ip = self.connections_per_ip.write().await;
        let count = connections_per_ip.entry(ip).or_insert(0);
        *count += 1;
    }

    /// Unregister a closed connection
    pub async fn unregister_connection(&self, addr: &SocketAddr) {
        let ip = addr.ip().to_string();
        let mut connections_per_ip = self.connections_per_ip.write().await;
        if let Some(count) = connections_per_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                connections_per_ip.remove(&ip);
            }
        }
    }

    /// Estimate message size
    fn estimate_message_size(&self, message: &Message) -> usize {
        match message {
            Message::Block(_) => 1_000_000, // ~1 MB average
            Message::Tx(_) => 1_000,        // ~1 KB average
            Message::Headers(h) => h.len() * 80,
            Message::Inv(i) => i.len() * 36,
            Message::GetData(g) => g.len() * 36,
            Message::Addr(a) => a.len() * 30,
            _ => 100, // Default small message
        }
    }

    /// Get ban list file path
    fn get_ban_list_path() -> PathBuf {
        PathBuf::from("./data/banlist.json")
    }

    /// Save ban list to storage
    async fn save_ban_list(&self) -> Result<()> {
        // Skip saving in tests to avoid filesystem operations
        #[cfg(test)]
        return Ok(());
        
        #[cfg(not(test))]
        {
            debug!("Saving ban list to storage");
            
            let ban_list = self.ban_list.read().await;
            let now = Instant::now();
            let system_now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        // Convert to serializable format, only keeping active bans
        let serializable_entries: Vec<SerializableBanEntry> = ban_list
            .values()
            .filter(|entry| entry.ban_until > now)
            .map(|entry| {
                let remaining_duration = entry.ban_until.duration_since(now);
                SerializableBanEntry {
                    addr: entry.addr.to_string(),
                    reason: entry.reason.clone(),
                    banned_at_unix: system_now.saturating_sub(
                        entry.ban_until.duration_since(entry.banned_at).as_secs()
                    ),
                    ban_duration_secs: remaining_duration.as_secs(),
                    score: entry.score,
                }
            })
            .collect();
        
        // Create data directory if it doesn't exist
        let ban_list_path = Self::get_ban_list_path();
        if let Some(parent) = ban_list_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        
        // Write to file
        let json = serde_json::to_string_pretty(&serializable_entries)?;
        tokio::fs::write(&ban_list_path, json).await?;
        
        info!("Saved {} ban entries to {:?}", serializable_entries.len(), ban_list_path);
        Ok(())
        }
    }

    /// Load ban list from storage
    pub async fn load_ban_list(&self) -> Result<()> {
        // Skip loading in tests to avoid filesystem operations
        #[cfg(test)]
        return Ok(());
        
        #[cfg(not(test))]
        {
            debug!("Loading ban list from storage");
            
            let ban_list_path = Self::get_ban_list_path();
        
        // Check if file exists
        if !ban_list_path.exists() {
            debug!("Ban list file does not exist, starting with empty ban list");
            return Ok(());
        }
        
        // Read and parse file
        let json = tokio::fs::read_to_string(&ban_list_path).await?;
        let serializable_entries: Vec<SerializableBanEntry> = serde_json::from_str(&json)?;
        
        let now = Instant::now();
        let mut ban_list = self.ban_list.write().await;
        
        // Convert from serializable format
        for entry in serializable_entries {
            // Parse socket address
            let addr: SocketAddr = entry.addr.parse()?;
            
            // Calculate ban times
            let ban_duration = Duration::from_secs(entry.ban_duration_secs);
            let ban_until = now + ban_duration;
            
            // Skip if ban has expired
            if ban_until <= now {
                continue;
            }
            
            // Create ban entry
            let ban_entry = BanEntry {
                addr,
                reason: entry.reason,
                banned_at: now, // Use current time as reference
                ban_until,
                score: entry.score,
            };
            
            ban_list.insert(addr, ban_entry);
        }
        
        info!("Loaded {} ban entries from {:?}", ban_list.len(), ban_list_path);
        Ok(())
        }
    }
}

/// Run DoS protection maintenance loop
pub async fn run_dos_protection_maintenance(manager: Arc<DosProtectionManager>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        interval.tick().await;

        // Clean expired bans
        manager.clean_expired_bans().await;

        // Check resource limits
        if let Err(e) = manager.check_resource_limits().await {
            warn!("Error checking resource limits: {}", e);
        }

        // Log statistics
        let stats = manager.get_stats().await;
        debug!(
            "DoS protection stats: {} messages rejected, {} connections rejected, {} peers banned",
            stats.messages_rejected, stats.connections_rejected, stats.peers_banned
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_connection_rate_limit() {
        let config = DosProtectionConfig {
            max_connections_per_ip: 3,
            connection_rate_limit: Duration::from_millis(100),
            ..Default::default()
        };

        let manager = DosProtectionManager::new(config);
        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();

        // First 3 connections should be allowed
        for _ in 0..3 {
            assert!(manager.should_allow_connection(&addr).await.unwrap());
        }

        // 4th connection should be rejected
        assert!(!manager.should_allow_connection(&addr).await.unwrap());

        // Wait for rate limit to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should allow connection again
        assert!(manager.should_allow_connection(&addr).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_peer_scoring_and_banning() {
        let config = DosProtectionConfig {
            ban_threshold: -20,
            disconnect_threshold: -10,
            ..Default::default()
        };

        let manager = DosProtectionManager::new(config);
        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();

        // Negative score events
        manager
            .adjust_peer_score(&addr, -5, "Test 1")
            .await
            .unwrap();
        assert!(!manager.is_banned(&addr).await);

        manager
            .adjust_peer_score(&addr, -10, "Test 2")
            .await
            .unwrap();
        assert!(!manager.is_banned(&addr).await);

        // Should trigger ban
        manager
            .adjust_peer_score(&addr, -10, "Test 3")
            .await
            .unwrap();
        assert!(manager.is_banned(&addr).await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_message_rate_limiting() {
        let config = DosProtectionConfig {
            max_messages_per_second: 2,
            ..Default::default()
        };

        let manager = DosProtectionManager::new(config);
        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();

        // Should allow first 2 messages
        for _ in 0..2 {
            assert!(manager
                .should_process_message(&addr, &Message::Ping(0))
                .await
                .unwrap());
        }

        // 3rd message should be rate limited
        assert!(!manager
            .should_process_message(&addr, &Message::Ping(0))
            .await
            .unwrap());
    }
}
