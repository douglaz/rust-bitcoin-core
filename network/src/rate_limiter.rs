use anyhow::{bail, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Token bucket rate limiter for bandwidth control
pub struct RateLimiter {
    /// Maximum tokens in bucket
    capacity: usize,
    /// Current tokens available
    tokens: Arc<RwLock<f64>>,
    /// Token refill rate (tokens per second)
    refill_rate: f64,
    /// Last refill time
    last_refill: Arc<RwLock<Instant>>,
    /// Semaphore for concurrent access
    semaphore: Arc<Semaphore>,
    /// Statistics
    stats: Arc<RwLock<RateLimiterStats>>,
}

/// Rate limiter statistics
#[derive(Debug, Default, Clone)]
pub struct RateLimiterStats {
    pub total_bytes_allowed: u64,
    pub total_bytes_throttled: u64,
    pub total_wait_time_ms: u64,
    pub current_rate_bps: f64,
    pub peak_rate_bps: f64,
}

impl RateLimiter {
    /// Create new rate limiter
    ///
    /// # Arguments
    /// * `bytes_per_second` - Maximum bandwidth in bytes per second
    /// * `burst_size` - Maximum burst size in bytes
    pub fn new(bytes_per_second: usize, burst_size: Option<usize>) -> Self {
        let capacity = burst_size.unwrap_or(bytes_per_second * 2);

        Self {
            capacity,
            tokens: Arc::new(RwLock::new(capacity as f64)),
            refill_rate: bytes_per_second as f64,
            last_refill: Arc::new(RwLock::new(Instant::now())),
            semaphore: Arc::new(Semaphore::new(1)),
            stats: Arc::new(RwLock::new(RateLimiterStats::default())),
        }
    }

    /// Request permission to send/receive bytes
    pub async fn acquire(&self, bytes: usize) -> Result<()> {
        if bytes > self.capacity {
            bail!(
                "Request size {} exceeds bucket capacity {}",
                bytes,
                self.capacity
            );
        }

        let _permit = self.semaphore.acquire().await?;

        let start = Instant::now();
        let mut total_wait = Duration::ZERO;

        loop {
            // Refill tokens
            self.refill_tokens().await;

            let mut tokens = self.tokens.write().await;

            if *tokens >= bytes as f64 {
                // Enough tokens available
                *tokens -= bytes as f64;

                // Update stats
                let mut stats = self.stats.write().await;
                stats.total_bytes_allowed += bytes as u64;
                if total_wait > Duration::ZERO {
                    stats.total_bytes_throttled += bytes as u64;
                    stats.total_wait_time_ms += total_wait.as_millis() as u64;
                }

                debug!("Allowed {} bytes, {} tokens remaining", bytes, *tokens);
                return Ok(());
            }

            // Not enough tokens, calculate wait time
            let tokens_needed = bytes as f64 - *tokens;
            let wait_time = Duration::from_secs_f64(tokens_needed / self.refill_rate);

            debug!("Waiting {:?} for {} bytes", wait_time, bytes);

            // Release lock while waiting
            drop(tokens);

            // Wait for tokens to refill
            sleep(wait_time).await;
            total_wait += wait_time;

            // Check for excessive wait
            if total_wait > Duration::from_secs(30) {
                warn!("Excessive wait time for {} bytes: {:?}", bytes, total_wait);
            }
        }
    }

    /// Try to acquire without waiting
    pub async fn try_acquire(&self, bytes: usize) -> Result<bool> {
        if bytes > self.capacity {
            bail!(
                "Request size {} exceeds bucket capacity {}",
                bytes,
                self.capacity
            );
        }

        // Refill tokens
        self.refill_tokens().await;

        let mut tokens = self.tokens.write().await;

        if *tokens >= bytes as f64 {
            *tokens -= bytes as f64;

            // Update stats
            self.stats.write().await.total_bytes_allowed += bytes as u64;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Refill tokens based on elapsed time
    async fn refill_tokens(&self) {
        let mut last_refill = self.last_refill.write().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill);

        if elapsed > Duration::from_millis(10) {
            let mut tokens = self.tokens.write().await;

            // Calculate tokens to add
            let tokens_to_add = self.refill_rate * elapsed.as_secs_f64();
            *tokens = (*tokens + tokens_to_add).min(self.capacity as f64);

            // Update rate statistics
            let mut stats = self.stats.write().await;
            stats.current_rate_bps = if elapsed.as_secs() > 0 {
                stats.total_bytes_allowed as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };

            if stats.current_rate_bps > stats.peak_rate_bps {
                stats.peak_rate_bps = stats.current_rate_bps;
            }

            *last_refill = now;
        }
    }

    /// Get current available tokens
    pub async fn available(&self) -> usize {
        self.refill_tokens().await;
        self.tokens.read().await.floor() as usize
    }

    /// Get statistics
    pub async fn stats(&self) -> RateLimiterStats {
        self.stats.read().await.clone()
    }

    /// Reset rate limiter
    pub async fn reset(&self) {
        *self.tokens.write().await = self.capacity as f64;
        *self.last_refill.write().await = Instant::now();
        *self.stats.write().await = RateLimiterStats::default();
    }
}

/// Per-peer bandwidth limiter
pub struct PeerRateLimiter {
    /// Upload rate limiter
    upload: Arc<RateLimiter>,
    /// Download rate limiter
    download: Arc<RateLimiter>,
    /// Peer identifier
    peer_id: String,
}

impl PeerRateLimiter {
    /// Create new peer rate limiter
    pub fn new(peer_id: String, upload_bps: usize, download_bps: usize) -> Self {
        Self {
            upload: Arc::new(RateLimiter::new(upload_bps, None)),
            download: Arc::new(RateLimiter::new(download_bps, None)),
            peer_id,
        }
    }

    /// Request upload bandwidth
    pub async fn acquire_upload(&self, bytes: usize) -> Result<()> {
        debug!("Peer {} requesting {} bytes upload", self.peer_id, bytes);
        self.upload.acquire(bytes).await
    }

    /// Request download bandwidth
    pub async fn acquire_download(&self, bytes: usize) -> Result<()> {
        debug!("Peer {} requesting {} bytes download", self.peer_id, bytes);
        self.download.acquire(bytes).await
    }

    /// Get statistics
    pub async fn stats(&self) -> (RateLimiterStats, RateLimiterStats) {
        (self.upload.stats().await, self.download.stats().await)
    }
}

/// Global bandwidth manager
pub struct BandwidthManager {
    /// Global upload limiter
    global_upload: Arc<RateLimiter>,
    /// Global download limiter
    global_download: Arc<RateLimiter>,
    /// Per-peer limiters
    peer_limiters: Arc<RwLock<std::collections::HashMap<String, Arc<PeerRateLimiter>>>>,
    /// Configuration
    config: BandwidthConfig,
}

/// Bandwidth configuration
#[derive(Debug, Clone)]
pub struct BandwidthConfig {
    /// Global upload limit (bytes per second)
    pub global_upload_bps: usize,
    /// Global download limit (bytes per second)
    pub global_download_bps: usize,
    /// Per-peer upload limit (bytes per second)
    pub peer_upload_bps: usize,
    /// Per-peer download limit (bytes per second)
    pub peer_download_bps: usize,
    /// Enable adaptive rate limiting
    pub adaptive: bool,
}

impl Default for BandwidthConfig {
    fn default() -> Self {
        Self {
            global_upload_bps: 10_000_000,   // 10 MB/s
            global_download_bps: 50_000_000, // 50 MB/s
            peer_upload_bps: 1_000_000,      // 1 MB/s
            peer_download_bps: 5_000_000,    // 5 MB/s
            adaptive: true,
        }
    }
}

impl BandwidthManager {
    /// Create new bandwidth manager
    pub fn new(config: BandwidthConfig) -> Self {
        Self {
            global_upload: Arc::new(RateLimiter::new(
                config.global_upload_bps,
                Some(config.global_upload_bps * 2),
            )),
            global_download: Arc::new(RateLimiter::new(
                config.global_download_bps,
                Some(config.global_download_bps * 2),
            )),
            peer_limiters: Arc::new(RwLock::new(std::collections::HashMap::new())),
            config,
        }
    }

    /// Get or create peer limiter
    pub async fn get_peer_limiter(&self, peer_id: String) -> Arc<PeerRateLimiter> {
        let mut limiters = self.peer_limiters.write().await;

        limiters
            .entry(peer_id.clone())
            .or_insert_with(|| {
                Arc::new(PeerRateLimiter::new(
                    peer_id,
                    self.config.peer_upload_bps,
                    self.config.peer_download_bps,
                ))
            })
            .clone()
    }

    /// Request upload bandwidth
    pub async fn acquire_upload(&self, peer_id: &str, bytes: usize) -> Result<()> {
        // Check global limit first
        self.global_upload.acquire(bytes).await?;

        // Then check peer limit
        let peer_limiter = self.get_peer_limiter(peer_id.to_string()).await;
        if let Err(e) = peer_limiter.acquire_upload(bytes).await {
            // Return tokens to global limiter on peer limit failure
            // (This is simplified - in production would need proper rollback)
            warn!("Peer {} upload limited: {}", peer_id, e);
            return Err(e);
        }

        Ok(())
    }

    /// Request download bandwidth
    pub async fn acquire_download(&self, peer_id: &str, bytes: usize) -> Result<()> {
        // Check global limit first
        self.global_download.acquire(bytes).await?;

        // Then check peer limit
        let peer_limiter = self.get_peer_limiter(peer_id.to_string()).await;
        if let Err(e) = peer_limiter.acquire_download(bytes).await {
            warn!("Peer {} download limited: {}", peer_id, e);
            return Err(e);
        }

        Ok(())
    }

    /// Remove peer limiter
    pub async fn remove_peer(&self, peer_id: &str) {
        self.peer_limiters.write().await.remove(peer_id);
        info!("Removed rate limiter for peer {}", peer_id);
    }

    /// Get global statistics
    pub async fn global_stats(&self) -> (RateLimiterStats, RateLimiterStats) {
        (
            self.global_upload.stats().await,
            self.global_download.stats().await,
        )
    }

    /// Adjust rates based on network conditions (adaptive mode)
    pub async fn adjust_rates(&self, congestion_level: f64) {
        if !self.config.adaptive {
            return;
        }

        // Simple adaptive algorithm: reduce rates when congested
        let adjustment = 1.0 - congestion_level.min(0.5);

        let new_upload = (self.config.global_upload_bps as f64 * adjustment) as usize;
        let new_download = (self.config.global_download_bps as f64 * adjustment) as usize;

        info!(
            "Adjusting bandwidth limits: upload {}MB/s -> {}MB/s, download {}MB/s -> {}MB/s",
            self.config.global_upload_bps / 1_000_000,
            new_upload / 1_000_000,
            self.config.global_download_bps / 1_000_000,
            new_download / 1_000_000
        );

        // Would need to update rate limiters here
        // This is simplified - in production would recreate or update limiters
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new(1000, Some(2000)); // 1KB/s, 2KB burst

        // Should allow immediate small request
        assert!(limiter.acquire(500).await.is_ok());

        // Should have tokens available
        let available = limiter.available().await;
        assert!((1500..=1600).contains(&available)); // Account for refill
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    // This test waits for rate limiting but is now enabled for comprehensive testing
    async fn test_rate_limiter_throttling() {
        let limiter = RateLimiter::new(100, Some(100)); // 100 bytes/s, 100 byte burst

        // Consume all tokens
        assert!(limiter.acquire(100).await.is_ok());

        // Next request should wait
        let start = Instant::now();
        assert!(limiter.acquire(50).await.is_ok());
        let elapsed = start.elapsed();

        // Should have waited approximately 0.5 seconds
        assert!(elapsed >= Duration::from_millis(400));
        assert!(elapsed <= Duration::from_millis(600));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_bandwidth_manager() {
        let config = BandwidthConfig {
            global_upload_bps: 10000,
            global_download_bps: 20000,
            peer_upload_bps: 5000,
            peer_download_bps: 10000,
            adaptive: false,
        };

        let manager = BandwidthManager::new(config);

        // Test peer bandwidth allocation
        assert!(manager.acquire_upload("peer1", 1000).await.is_ok());
        assert!(manager.acquire_download("peer1", 2000).await.is_ok());

        // Verify peer limiter was created
        let limiters = manager.peer_limiters.read().await;
        assert!(limiters.contains_key("peer1"));
    }
}
