use anyhow::{bail, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Connection retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Initial retry delay
    pub initial_delay: Duration,
    /// Maximum retry delay
    pub max_delay: Duration,
    /// Exponential backoff multiplier
    pub multiplier: f64,
    /// Maximum number of retries
    pub max_retries: u32,
    /// Jitter factor (0.0 to 1.0)
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(300), // 5 minutes
            multiplier: 2.0,
            max_retries: 10,
            jitter_factor: 0.1,
        }
    }
}

/// Connection attempt result
#[derive(Debug, Clone)]
pub enum ConnectionResult {
    Success,
    Failed(String),
    Timeout,
    Refused,
    NetworkUnreachable,
}

/// Retry state for a peer
#[derive(Debug, Clone)]
pub struct RetryState {
    pub peer_addr: SocketAddr,
    pub attempt_count: u32,
    pub last_attempt: Option<Instant>,
    pub next_retry: Option<Instant>,
    pub current_delay: Duration,
    pub consecutive_failures: u32,
    pub total_failures: u32,
    pub last_success: Option<Instant>,
    pub last_error: Option<String>,
}

impl RetryState {
    pub fn new(peer_addr: SocketAddr) -> Self {
        Self {
            peer_addr,
            attempt_count: 0,
            last_attempt: None,
            next_retry: None,
            current_delay: Duration::from_secs(1),
            consecutive_failures: 0,
            total_failures: 0,
            last_success: None,
            last_error: None,
        }
    }

    /// Calculate next retry delay with exponential backoff and jitter
    pub fn calculate_next_delay(&self, config: &RetryConfig) -> Duration {
        let base_delay = if self.consecutive_failures == 0 {
            config.initial_delay
        } else {
            let multiplier = config.multiplier.powi(self.consecutive_failures.min(10) as i32);
            let delay_ms = (config.initial_delay.as_millis() as f64 * multiplier) as u64;
            Duration::from_millis(delay_ms.min(config.max_delay.as_millis() as u64))
        };

        // Add jitter to prevent thundering herd
        let jitter = if config.jitter_factor > 0.0 {
            let jitter_ms = (base_delay.as_millis() as f64 * config.jitter_factor * rand::random::<f64>()) as u64;
            Duration::from_millis(jitter_ms)
        } else {
            Duration::ZERO
        };

        base_delay + jitter
    }

    /// Update state after connection attempt
    pub fn update(&mut self, result: ConnectionResult, config: &RetryConfig) {
        self.attempt_count += 1;
        self.last_attempt = Some(Instant::now());

        match result {
            ConnectionResult::Success => {
                self.consecutive_failures = 0;
                self.last_success = Some(Instant::now());
                self.next_retry = None;
                self.current_delay = config.initial_delay;
                self.last_error = None;
                info!("Connection to {} succeeded", self.peer_addr);
            }
            ConnectionResult::Failed(ref err) => {
                self.consecutive_failures += 1;
                self.total_failures += 1;
                self.last_error = Some(err.clone());
                
                if self.consecutive_failures < config.max_retries {
                    self.current_delay = self.calculate_next_delay(config);
                    self.next_retry = Some(Instant::now() + self.current_delay);
                    
                    warn!(
                        "Connection to {} failed: {}. Retry {} in {:?}",
                        self.peer_addr, err, self.consecutive_failures, self.current_delay
                    );
                } else {
                    self.next_retry = None;
                    warn!(
                        "Connection to {} failed after {} retries. Giving up.",
                        self.peer_addr, config.max_retries
                    );
                }
            }
            ConnectionResult::Timeout |
            ConnectionResult::Refused |
            ConnectionResult::NetworkUnreachable => {
                self.consecutive_failures += 1;
                self.total_failures += 1;
                
                let error_msg = match result {
                    ConnectionResult::Failed(err) => err,
                    ConnectionResult::Timeout => "Connection timeout".to_string(),
                    ConnectionResult::Refused => "Connection refused".to_string(),
                    ConnectionResult::NetworkUnreachable => "Network unreachable".to_string(),
                    _ => unreachable!(),
                };
                
                self.last_error = Some(error_msg.clone());
                
                if self.consecutive_failures < config.max_retries {
                    self.current_delay = self.calculate_next_delay(config);
                    self.next_retry = Some(Instant::now() + self.current_delay);
                    
                    warn!(
                        "Connection to {} failed: {}. Retry {} in {:?}",
                        self.peer_addr, error_msg, self.consecutive_failures, self.current_delay
                    );
                } else {
                    self.next_retry = None;
                    warn!(
                        "Connection to {} failed after {} retries. Giving up.",
                        self.peer_addr, config.max_retries
                    );
                }
            }
        }
    }

    /// Check if retry should be attempted
    pub fn should_retry(&self, config: &RetryConfig) -> bool {
        self.consecutive_failures < config.max_retries &&
        self.next_retry.is_some()
    }

    /// Get time until next retry
    pub fn time_until_retry(&self) -> Option<Duration> {
        self.next_retry.map(|next| {
            let now = Instant::now();
            if next > now {
                next - now
            } else {
                Duration::ZERO
            }
        })
    }
}

/// Connection retry manager
pub struct ConnectionRetryManager {
    config: RetryConfig,
    retry_states: Arc<RwLock<std::collections::HashMap<SocketAddr, RetryState>>>,
}

impl ConnectionRetryManager {
    pub fn new(config: RetryConfig) -> Self {
        Self {
            config,
            retry_states: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Get or create retry state for a peer
    pub async fn get_retry_state(&self, peer_addr: SocketAddr) -> RetryState {
        let mut states = self.retry_states.write().await;
        states.entry(peer_addr)
            .or_insert_with(|| RetryState::new(peer_addr))
            .clone()
    }

    /// Update retry state after connection attempt
    pub async fn update_connection_result(
        &self,
        peer_addr: SocketAddr,
        result: ConnectionResult,
    ) {
        let mut states = self.retry_states.write().await;
        let state = states.entry(peer_addr)
            .or_insert_with(|| RetryState::new(peer_addr));
        state.update(result, &self.config);
    }

    /// Wait for next retry if needed
    pub async fn wait_for_retry(&self, peer_addr: SocketAddr) -> Result<()> {
        let state = self.get_retry_state(peer_addr).await;
        
        if !state.should_retry(&self.config) {
            bail!("Max retries exceeded for {}", peer_addr);
        }

        if let Some(delay) = state.time_until_retry() {
            if delay > Duration::ZERO {
                debug!("Waiting {:?} before retrying connection to {}", delay, peer_addr);
                sleep(delay).await;
            }
        }

        Ok(())
    }

    /// Get peers ready for retry
    pub async fn get_peers_ready_for_retry(&self) -> Vec<SocketAddr> {
        let states = self.retry_states.read().await;
        let now = Instant::now();
        
        states.iter()
            .filter_map(|(addr, state)| {
                if state.should_retry(&self.config) {
                    if let Some(next_retry) = state.next_retry {
                        if next_retry <= now {
                            return Some(*addr);
                        }
                    }
                }
                None
            })
            .collect()
    }

    /// Reset retry state for a peer (e.g., after successful connection)
    pub async fn reset_peer(&self, peer_addr: SocketAddr) {
        let mut states = self.retry_states.write().await;
        states.remove(&peer_addr);
    }

    /// Get statistics
    pub async fn get_stats(&self) -> ConnectionRetryStats {
        let states = self.retry_states.read().await;
        
        let total_peers = states.len();
        let peers_with_failures = states.values()
            .filter(|s| s.total_failures > 0)
            .count();
        let peers_pending_retry = states.values()
            .filter(|s| s.next_retry.is_some())
            .count();
        let total_failures: u32 = states.values()
            .map(|s| s.total_failures)
            .sum();

        ConnectionRetryStats {
            total_peers,
            peers_with_failures,
            peers_pending_retry,
            total_failures,
        }
    }
}

/// Connection retry statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionRetryStats {
    pub total_peers: usize,
    pub peers_with_failures: usize,
    pub peers_pending_retry: usize,
    pub total_failures: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff() {
        let config = RetryConfig::default();
        let mut state = RetryState::new("127.0.0.1:8333".parse().unwrap());

        // First failure: 1 second
        state.consecutive_failures = 1;
        let delay = state.calculate_next_delay(&config);
        assert!(delay >= Duration::from_secs(1) && delay < Duration::from_secs(3));

        // Second failure: ~2 seconds
        state.consecutive_failures = 2;
        let delay = state.calculate_next_delay(&config);
        assert!(delay >= Duration::from_secs(3) && delay < Duration::from_secs(5));

        // Third failure: ~4 seconds
        state.consecutive_failures = 3;
        let delay = state.calculate_next_delay(&config);
        assert!(delay >= Duration::from_secs(7) && delay < Duration::from_secs(9));
    }

    #[tokio::test]
    async fn test_retry_manager() {
        let manager = ConnectionRetryManager::new(RetryConfig::default());
        let peer_addr = "127.0.0.1:8333".parse().unwrap();

        // Initial state
        let state = manager.get_retry_state(peer_addr).await;
        assert_eq!(state.consecutive_failures, 0);

        // Record failure
        manager.update_connection_result(
            peer_addr,
            ConnectionResult::Failed("Test error".to_string())
        ).await;

        let state = manager.get_retry_state(peer_addr).await;
        assert_eq!(state.consecutive_failures, 1);
        assert!(state.next_retry.is_some());

        // Record success
        manager.update_connection_result(peer_addr, ConnectionResult::Success).await;
        let state = manager.get_retry_state(peer_addr).await;
        assert_eq!(state.consecutive_failures, 0);
        assert!(state.next_retry.is_none());
    }
}