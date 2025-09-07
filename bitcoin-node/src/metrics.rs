use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Node metrics collected during operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    // Chain metrics
    pub blocks_processed: u64,
    pub headers_processed: u64,
    pub chain_height: u32,
    pub chain_work: String,

    // Network metrics
    pub peers_connected: usize,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,

    // Mempool metrics
    pub mempool_size: usize,
    pub mempool_bytes: u64,
    pub mempool_min_fee: f64,

    // Performance metrics
    pub block_validation_time_ms: u64,
    pub tx_validation_time_ms: u64,
    pub rpc_requests_total: u64,
    pub rpc_request_duration_ms: u64,

    // System metrics
    pub uptime_seconds: u64,
    pub memory_usage_mb: u64,
    pub database_size_mb: u64,
}

/// Metrics collector for the node
pub struct MetricsCollector {
    // Atomic counters for lock-free updates
    blocks_processed: AtomicU64,
    headers_processed: AtomicU64,
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    rpc_requests_total: AtomicU64,

    // Shared state for complex metrics
    chain_height: Arc<RwLock<u32>>,
    peers_connected: Arc<RwLock<usize>>,
    mempool_stats: Arc<RwLock<MempoolStats>>,

    // Timing metrics
    validation_times: Arc<RwLock<ValidationTimes>>,
    start_time: Instant,
}

#[derive(Debug, Clone, Default)]
struct MempoolStats {
    size: usize,
    bytes: u64,
    min_fee: f64,
}

#[derive(Debug, Clone, Default)]
struct ValidationTimes {
    block_validation_total_ms: u64,
    block_validation_count: u64,
    tx_validation_total_ms: u64,
    tx_validation_count: u64,
    rpc_duration_total_ms: u64,
    rpc_request_count: u64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            blocks_processed: AtomicU64::new(0),
            headers_processed: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            rpc_requests_total: AtomicU64::new(0),
            chain_height: Arc::new(RwLock::new(0)),
            peers_connected: Arc::new(RwLock::new(0)),
            mempool_stats: Arc::new(RwLock::new(MempoolStats::default())),
            validation_times: Arc::new(RwLock::new(ValidationTimes::default())),
            start_time: Instant::now(),
        }
    }

    /// Record a processed block
    pub fn record_block_processed(&self) {
        self.blocks_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record processed headers
    pub fn record_headers_processed(&self, count: u64) {
        self.headers_processed.fetch_add(count, Ordering::Relaxed);
    }

    /// Update chain height
    pub fn update_chain_height(&self, height: u32) {
        *self.chain_height.write() = height;
    }

    /// Update peer count
    pub fn update_peer_count(&self, count: usize) {
        *self.peers_connected.write() = count;
    }

    /// Record network message sent
    pub fn record_message_sent(&self, bytes: u64) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record network message received
    pub fn record_message_received(&self, bytes: u64) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Update mempool statistics
    pub fn update_mempool_stats(&self, size: usize, bytes: u64, min_fee: f64) {
        let mut stats = self.mempool_stats.write();
        stats.size = size;
        stats.bytes = bytes;
        stats.min_fee = min_fee;
    }

    /// Record block validation time
    pub fn record_block_validation(&self, duration_ms: u64) {
        let mut times = self.validation_times.write();
        times.block_validation_total_ms += duration_ms;
        times.block_validation_count += 1;
    }

    /// Record transaction validation time
    pub fn record_tx_validation(&self, duration_ms: u64) {
        let mut times = self.validation_times.write();
        times.tx_validation_total_ms += duration_ms;
        times.tx_validation_count += 1;
    }

    /// Record RPC request
    pub fn record_rpc_request(&self, duration_ms: u64) {
        self.rpc_requests_total.fetch_add(1, Ordering::Relaxed);
        let mut times = self.validation_times.write();
        times.rpc_duration_total_ms += duration_ms;
        times.rpc_request_count += 1;
    }

    /// Get current metrics snapshot
    pub fn get_metrics(&self) -> NodeMetrics {
        let mempool = self.mempool_stats.read();
        let times = self.validation_times.read();

        let avg_block_time = if times.block_validation_count > 0 {
            times.block_validation_total_ms / times.block_validation_count
        } else {
            0
        };

        let avg_tx_time = if times.tx_validation_count > 0 {
            times.tx_validation_total_ms / times.tx_validation_count
        } else {
            0
        };

        let avg_rpc_time = if times.rpc_request_count > 0 {
            times.rpc_duration_total_ms / times.rpc_request_count
        } else {
            0
        };

        NodeMetrics {
            blocks_processed: self.blocks_processed.load(Ordering::Relaxed),
            headers_processed: self.headers_processed.load(Ordering::Relaxed),
            chain_height: *self.chain_height.read(),
            chain_work: "0".to_string(), // TODO: Calculate actual chain work
            peers_connected: *self.peers_connected.read(),
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            mempool_size: mempool.size,
            mempool_bytes: mempool.bytes,
            mempool_min_fee: mempool.min_fee,
            block_validation_time_ms: avg_block_time,
            tx_validation_time_ms: avg_tx_time,
            rpc_requests_total: self.rpc_requests_total.load(Ordering::Relaxed),
            rpc_request_duration_ms: avg_rpc_time,
            uptime_seconds: self.start_time.elapsed().as_secs(),
            memory_usage_mb: Self::get_memory_usage_mb(),
            database_size_mb: 0, // Would need storage reference to get actual size
        }
    }

    /// Get current memory usage in MB
    fn get_memory_usage_mb() -> u64 {
        // Simple approximation using /proc/self/status on Linux
        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("VmRSS:") {
                        if let Some(kb_str) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = kb_str.parse::<u64>() {
                                return kb / 1024; // Convert KB to MB
                            }
                        }
                    }
                }
            }
        }
        0
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics exporter for Prometheus format
pub struct PrometheusExporter;

impl PrometheusExporter {
    /// Export metrics in Prometheus format
    pub fn export(metrics: &NodeMetrics) -> String {
        let mut output = String::new();

        // Chain metrics
        output.push_str(&"# HELP bitcoin_blocks_processed Total number of blocks processed\n".to_string());
        output.push_str(&"# TYPE bitcoin_blocks_processed counter\n".to_string());
        output.push_str(&format!(
            "bitcoin_blocks_processed {}\n",
            metrics.blocks_processed
        ));

        output.push_str(&"# HELP bitcoin_chain_height Current blockchain height\n".to_string());
        output.push_str(&"# TYPE bitcoin_chain_height gauge\n".to_string());
        output.push_str(&format!("bitcoin_chain_height {}\n", metrics.chain_height));

        // Network metrics
        output.push_str(&"# HELP bitcoin_peers_connected Number of connected peers\n".to_string());
        output.push_str(&"# TYPE bitcoin_peers_connected gauge\n".to_string());
        output.push_str(&format!(
            "bitcoin_peers_connected {}\n",
            metrics.peers_connected
        ));

        output.push_str(&"# HELP bitcoin_network_bytes_sent Total bytes sent\n".to_string());
        output.push_str(&"# TYPE bitcoin_network_bytes_sent counter\n".to_string());
        output.push_str(&format!(
            "bitcoin_network_bytes_sent {}\n",
            metrics.bytes_sent
        ));

        output.push_str(&"# HELP bitcoin_network_bytes_received Total bytes received\n".to_string());
        output.push_str(&"# TYPE bitcoin_network_bytes_received counter\n".to_string());
        output.push_str(&format!(
            "bitcoin_network_bytes_received {}\n",
            metrics.bytes_received
        ));

        // Mempool metrics
        output.push_str(&"# HELP bitcoin_mempool_size Number of transactions in mempool\n".to_string());
        output.push_str(&"# TYPE bitcoin_mempool_size gauge\n".to_string());
        output.push_str(&format!("bitcoin_mempool_size {}\n", metrics.mempool_size));

        output.push_str(&"# HELP bitcoin_mempool_bytes Size of mempool in bytes\n".to_string());
        output.push_str(&"# TYPE bitcoin_mempool_bytes gauge\n".to_string());
        output.push_str(&format!(
            "bitcoin_mempool_bytes {}\n",
            metrics.mempool_bytes
        ));

        // Performance metrics
        output.push_str(&"# HELP bitcoin_block_validation_ms Average block validation time in milliseconds\n".to_string());
        output.push_str(&"# TYPE bitcoin_block_validation_ms gauge\n".to_string());
        output.push_str(&format!(
            "bitcoin_block_validation_ms {}\n",
            metrics.block_validation_time_ms
        ));

        output.push_str(&"# HELP bitcoin_rpc_requests_total Total number of RPC requests\n".to_string());
        output.push_str(&"# TYPE bitcoin_rpc_requests_total counter\n".to_string());
        output.push_str(&format!(
            "bitcoin_rpc_requests_total {}\n",
            metrics.rpc_requests_total
        ));

        // System metrics
        output.push_str(&"# HELP bitcoin_uptime_seconds Node uptime in seconds\n".to_string());
        output.push_str(&"# TYPE bitcoin_uptime_seconds counter\n".to_string());
        output.push_str(&format!(
            "bitcoin_uptime_seconds {}\n",
            metrics.uptime_seconds
        ));

        output.push_str(&"# HELP bitcoin_memory_usage_mb Memory usage in MB\n".to_string());
        output.push_str(&"# TYPE bitcoin_memory_usage_mb gauge\n".to_string());
        output.push_str(&format!(
            "bitcoin_memory_usage_mb {}\n",
            metrics.memory_usage_mb
        ));

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector() {
        let collector = MetricsCollector::new();

        // Record some metrics
        collector.record_block_processed();
        collector.record_headers_processed(10);
        collector.update_chain_height(100);
        collector.update_peer_count(8);
        collector.record_message_sent(1024);
        collector.record_message_received(2048);
        collector.update_mempool_stats(50, 100000, 0.00001);
        collector.record_block_validation(100);
        collector.record_tx_validation(5);
        collector.record_rpc_request(2);

        // Get metrics
        let metrics = collector.get_metrics();

        // Verify metrics
        assert_eq!(metrics.blocks_processed, 1);
        assert_eq!(metrics.headers_processed, 10);
        assert_eq!(metrics.chain_height, 100);
        assert_eq!(metrics.peers_connected, 8);
        assert_eq!(metrics.messages_sent, 1);
        assert_eq!(metrics.bytes_sent, 1024);
        assert_eq!(metrics.messages_received, 1);
        assert_eq!(metrics.bytes_received, 2048);
        assert_eq!(metrics.mempool_size, 50);
        assert_eq!(metrics.mempool_bytes, 100000);
        assert_eq!(metrics.block_validation_time_ms, 100);
        assert_eq!(metrics.tx_validation_time_ms, 5);
        assert_eq!(metrics.rpc_requests_total, 1);
        assert!(metrics.uptime_seconds >= 0);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = NodeMetrics {
            blocks_processed: 1000,
            headers_processed: 2000,
            chain_height: 800000,
            chain_work: "0".to_string(),
            peers_connected: 8,
            messages_sent: 50000,
            messages_received: 60000,
            bytes_sent: 1000000,
            bytes_received: 2000000,
            mempool_size: 100,
            mempool_bytes: 500000,
            mempool_min_fee: 0.00001,
            block_validation_time_ms: 50,
            tx_validation_time_ms: 2,
            rpc_requests_total: 10000,
            rpc_request_duration_ms: 5,
            uptime_seconds: 3600,
            memory_usage_mb: 500,
            database_size_mb: 1000,
        };

        let prometheus_output = PrometheusExporter::export(&metrics);

        // Check that output contains expected metrics
        assert!(prometheus_output.contains("bitcoin_blocks_processed 1000"));
        assert!(prometheus_output.contains("bitcoin_chain_height 800000"));
        assert!(prometheus_output.contains("bitcoin_peers_connected 8"));
        assert!(prometheus_output.contains("bitcoin_mempool_size 100"));
        assert!(prometheus_output.contains("bitcoin_uptime_seconds 3600"));
    }
}
