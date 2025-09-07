use anyhow::Result;
use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec,
    IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Registry, Encoder, TextEncoder,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use serde::{Serialize, Deserialize};

/// Performance monitoring and metrics collection
pub struct MetricsCollector {
    /// Prometheus registry
    registry: Registry,
    
    /// Chain metrics
    chain_height: IntGauge,
    chain_work: Gauge,
    chain_headers: IntGauge,
    chain_reorgs: IntCounter,
    
    /// Network metrics
    peers_connected: IntGauge,
    messages_received: IntCounterVec,
    messages_sent: IntCounterVec,
    bytes_received: IntCounter,
    bytes_sent: IntCounter,
    
    /// Mempool metrics
    mempool_size: IntGauge,
    mempool_bytes: IntGauge,
    mempool_fee_rate: Gauge,
    tx_received: IntCounter,
    tx_rejected: IntCounter,
    
    /// Validation metrics
    blocks_validated: IntCounter,
    blocks_failed: IntCounter,
    validation_time: Histogram,
    tx_validated: IntCounter,
    tx_validation_time: Histogram,
    
    /// Storage metrics
    storage_reads: IntCounter,
    storage_writes: IntCounter,
    storage_size: IntGauge,
    utxo_set_size: IntGauge,
    cache_hits: IntCounter,
    cache_misses: IntCounter,
    
    /// Mining metrics
    blocks_mined: IntCounter,
    mining_hashrate: Gauge,
    mining_difficulty: Gauge,
    
    /// Wallet metrics
    wallet_balance: Gauge,
    wallet_utxos: IntGauge,
    wallet_transactions: IntCounter,
    
    /// System metrics
    cpu_usage: Gauge,
    memory_usage: IntGauge,
    disk_usage: IntGauge,
    uptime: IntGauge,
    
    /// Custom metrics
    custom_metrics: Arc<RwLock<HashMap<String, f64>>>,
    
    /// Performance tracking
    performance_tracker: Arc<RwLock<PerformanceTracker>>,
}

/// Performance tracker for detailed metrics
#[derive(Debug, Default)]
struct PerformanceTracker {
    /// Operation timings
    operation_timings: HashMap<String, Vec<Duration>>,
    
    /// Throughput measurements
    throughput_measurements: HashMap<String, Vec<f64>>,
    
    /// Resource usage snapshots
    resource_snapshots: Vec<ResourceSnapshot>,
}

/// Resource usage snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub timestamp: u64,
    pub cpu_percent: f64,
    pub memory_mb: u64,
    pub disk_io_read: u64,
    pub disk_io_write: u64,
    pub network_in: u64,
    pub network_out: u64,
}

/// Metrics snapshot for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub chain: ChainMetrics,
    pub network: NetworkMetrics,
    pub mempool: MempoolMetrics,
    pub validation: ValidationMetrics,
    pub storage: StorageMetrics,
    pub system: SystemMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetrics {
    pub height: i64,
    pub headers: i64,
    pub difficulty: f64,
    pub chainwork: f64,
    pub reorgs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub peers: i64,
    pub messages_in: u64,
    pub messages_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolMetrics {
    pub size: i64,
    pub bytes: i64,
    pub min_fee_rate: f64,
    pub tx_received: u64,
    pub tx_rejected: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationMetrics {
    pub blocks_validated: u64,
    pub blocks_failed: u64,
    pub avg_block_time: f64,
    pub tx_validated: u64,
    pub avg_tx_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetrics {
    pub reads: u64,
    pub writes: u64,
    pub size_gb: f64,
    pub utxo_count: i64,
    pub cache_hit_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_percent: f64,
    pub memory_mb: i64,
    pub disk_gb: f64,
    pub uptime_seconds: i64,
}

impl MetricsCollector {
    /// Create new metrics collector
    pub fn new() -> Result<Self> {
        let registry = Registry::new();
        
        // Chain metrics
        let chain_height = IntGauge::new("chain_height", "Current blockchain height")?;
        let chain_work = Gauge::new("chain_work", "Total chain work")?;
        let chain_headers = IntGauge::new("chain_headers", "Number of headers")?;
        let chain_reorgs = IntCounter::new("chain_reorgs_total", "Total chain reorganizations")?;
        
        registry.register(Box::new(chain_height.clone()))?;
        registry.register(Box::new(chain_work.clone()))?;
        registry.register(Box::new(chain_headers.clone()))?;
        registry.register(Box::new(chain_reorgs.clone()))?;
        
        // Network metrics
        let peers_connected = IntGauge::new("peers_connected", "Number of connected peers")?;
        let messages_received = IntCounterVec::new(
            prometheus::Opts::new("messages_received_total", "Messages received by type"),
            &["type"]
        )?;
        let messages_sent = IntCounterVec::new(
            prometheus::Opts::new("messages_sent_total", "Messages sent by type"),
            &["type"]
        )?;
        let bytes_received = IntCounter::new("bytes_received_total", "Total bytes received")?;
        let bytes_sent = IntCounter::new("bytes_sent_total", "Total bytes sent")?;
        
        registry.register(Box::new(peers_connected.clone()))?;
        registry.register(Box::new(messages_received.clone()))?;
        registry.register(Box::new(messages_sent.clone()))?;
        registry.register(Box::new(bytes_received.clone()))?;
        registry.register(Box::new(bytes_sent.clone()))?;
        
        // Mempool metrics
        let mempool_size = IntGauge::new("mempool_size", "Number of transactions in mempool")?;
        let mempool_bytes = IntGauge::new("mempool_bytes", "Size of mempool in bytes")?;
        let mempool_fee_rate = Gauge::new("mempool_min_fee_rate", "Minimum fee rate in mempool")?;
        let tx_received = IntCounter::new("tx_received_total", "Total transactions received")?;
        let tx_rejected = IntCounter::new("tx_rejected_total", "Total transactions rejected")?;
        
        registry.register(Box::new(mempool_size.clone()))?;
        registry.register(Box::new(mempool_bytes.clone()))?;
        registry.register(Box::new(mempool_fee_rate.clone()))?;
        registry.register(Box::new(tx_received.clone()))?;
        registry.register(Box::new(tx_rejected.clone()))?;
        
        // Validation metrics
        let blocks_validated = IntCounter::new("blocks_validated_total", "Total blocks validated")?;
        let blocks_failed = IntCounter::new("blocks_failed_total", "Total blocks failed validation")?;
        let validation_time = Histogram::new(prometheus::HistogramOpts::new(
            "block_validation_duration_seconds",
            "Block validation time in seconds"
        ))?;
        let tx_validated = IntCounter::new("tx_validated_total", "Total transactions validated")?;
        let tx_validation_time = Histogram::new(prometheus::HistogramOpts::new(
            "tx_validation_duration_seconds",
            "Transaction validation time in seconds"
        ))?;
        
        registry.register(Box::new(blocks_validated.clone()))?;
        registry.register(Box::new(blocks_failed.clone()))?;
        registry.register(Box::new(validation_time.clone()))?;
        registry.register(Box::new(tx_validated.clone()))?;
        registry.register(Box::new(tx_validation_time.clone()))?;
        
        // Storage metrics
        let storage_reads = IntCounter::new("storage_reads_total", "Total storage reads")?;
        let storage_writes = IntCounter::new("storage_writes_total", "Total storage writes")?;
        let storage_size = IntGauge::new("storage_size_bytes", "Storage size in bytes")?;
        let utxo_set_size = IntGauge::new("utxo_set_size", "Number of UTXOs")?;
        let cache_hits = IntCounter::new("cache_hits_total", "Total cache hits")?;
        let cache_misses = IntCounter::new("cache_misses_total", "Total cache misses")?;
        
        registry.register(Box::new(storage_reads.clone()))?;
        registry.register(Box::new(storage_writes.clone()))?;
        registry.register(Box::new(storage_size.clone()))?;
        registry.register(Box::new(utxo_set_size.clone()))?;
        registry.register(Box::new(cache_hits.clone()))?;
        registry.register(Box::new(cache_misses.clone()))?;
        
        // Mining metrics
        let blocks_mined = IntCounter::new("blocks_mined_total", "Total blocks mined")?;
        let mining_hashrate = Gauge::new("mining_hashrate", "Current mining hashrate")?;
        let mining_difficulty = Gauge::new("mining_difficulty", "Current mining difficulty")?;
        
        registry.register(Box::new(blocks_mined.clone()))?;
        registry.register(Box::new(mining_hashrate.clone()))?;
        registry.register(Box::new(mining_difficulty.clone()))?;
        
        // Wallet metrics
        let wallet_balance = Gauge::new("wallet_balance_btc", "Wallet balance in BTC")?;
        let wallet_utxos = IntGauge::new("wallet_utxos", "Number of wallet UTXOs")?;
        let wallet_transactions = IntCounter::new("wallet_transactions_total", "Total wallet transactions")?;
        
        registry.register(Box::new(wallet_balance.clone()))?;
        registry.register(Box::new(wallet_utxos.clone()))?;
        registry.register(Box::new(wallet_transactions.clone()))?;
        
        // System metrics
        let cpu_usage = Gauge::new("system_cpu_usage_percent", "CPU usage percentage")?;
        let memory_usage = IntGauge::new("system_memory_usage_bytes", "Memory usage in bytes")?;
        let disk_usage = IntGauge::new("system_disk_usage_bytes", "Disk usage in bytes")?;
        let uptime = IntGauge::new("system_uptime_seconds", "System uptime in seconds")?;
        
        registry.register(Box::new(cpu_usage.clone()))?;
        registry.register(Box::new(memory_usage.clone()))?;
        registry.register(Box::new(disk_usage.clone()))?;
        registry.register(Box::new(uptime.clone()))?;
        
        Ok(Self {
            registry,
            chain_height,
            chain_work,
            chain_headers,
            chain_reorgs,
            peers_connected,
            messages_received,
            messages_sent,
            bytes_received,
            bytes_sent,
            mempool_size,
            mempool_bytes,
            mempool_fee_rate,
            tx_received,
            tx_rejected,
            blocks_validated,
            blocks_failed,
            validation_time,
            tx_validated,
            tx_validation_time,
            storage_reads,
            storage_writes,
            storage_size,
            utxo_set_size,
            cache_hits,
            cache_misses,
            blocks_mined,
            mining_hashrate,
            mining_difficulty,
            wallet_balance,
            wallet_utxos,
            wallet_transactions,
            cpu_usage,
            memory_usage,
            disk_usage,
            uptime,
            custom_metrics: Arc::new(RwLock::new(HashMap::new())),
            performance_tracker: Arc::new(RwLock::new(PerformanceTracker::default())),
        })
    }
    
    /// Update chain metrics
    pub fn update_chain_metrics(&self, height: i64, headers: i64, difficulty: f64, work: f64) {
        self.chain_height.set(height);
        self.chain_headers.set(headers);
        self.mining_difficulty.set(difficulty);
        self.chain_work.set(work);
    }
    
    /// Increment reorg counter
    pub fn increment_reorgs(&self) {
        self.chain_reorgs.inc();
    }
    
    /// Update network metrics
    pub fn update_network_metrics(&self, peers: i64) {
        self.peers_connected.set(peers);
    }
    
    /// Record message received
    pub fn record_message_received(&self, msg_type: &str) {
        self.messages_received.with_label_values(&[msg_type]).inc();
    }
    
    /// Record message sent
    pub fn record_message_sent(&self, msg_type: &str) {
        self.messages_sent.with_label_values(&[msg_type]).inc();
    }
    
    /// Record bytes transfer
    pub fn record_bytes_transfer(&self, received: u64, sent: u64) {
        self.bytes_received.inc_by(received);
        self.bytes_sent.inc_by(sent);
    }
    
    /// Update mempool metrics
    pub fn update_mempool_metrics(&self, size: i64, bytes: i64, min_fee_rate: f64) {
        self.mempool_size.set(size);
        self.mempool_bytes.set(bytes);
        self.mempool_fee_rate.set(min_fee_rate);
    }
    
    /// Record transaction events
    pub fn record_tx_received(&self) {
        self.tx_received.inc();
    }
    
    pub fn record_tx_rejected(&self) {
        self.tx_rejected.inc();
    }
    
    /// Record block validation
    pub fn record_block_validation(&self, success: bool, duration: Duration) {
        if success {
            self.blocks_validated.inc();
        } else {
            self.blocks_failed.inc();
        }
        self.validation_time.observe(duration.as_secs_f64());
    }
    
    /// Record transaction validation
    pub fn record_tx_validation(&self, duration: Duration) {
        self.tx_validated.inc();
        self.tx_validation_time.observe(duration.as_secs_f64());
    }
    
    /// Update storage metrics
    pub fn update_storage_metrics(&self, reads: u64, writes: u64, size: i64, utxos: i64) {
        self.storage_reads.inc_by(reads);
        self.storage_writes.inc_by(writes);
        self.storage_size.set(size);
        self.utxo_set_size.set(utxos);
    }
    
    /// Record cache performance
    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }
    
    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }
    
    /// Update mining metrics
    pub fn update_mining_metrics(&self, hashrate: f64) {
        self.mining_hashrate.set(hashrate);
    }
    
    pub fn record_block_mined(&self) {
        self.blocks_mined.inc();
    }
    
    /// Update wallet metrics
    pub fn update_wallet_metrics(&self, balance_btc: f64, utxos: i64) {
        self.wallet_balance.set(balance_btc);
        self.wallet_utxos.set(utxos);
    }
    
    pub fn record_wallet_transaction(&self) {
        self.wallet_transactions.inc();
    }
    
    /// Update system metrics
    pub fn update_system_metrics(&self, cpu: f64, memory_mb: i64, disk_gb: f64, uptime_secs: i64) {
        self.cpu_usage.set(cpu);
        self.memory_usage.set(memory_mb * 1024 * 1024);
        self.disk_usage.set((disk_gb * 1024.0 * 1024.0 * 1024.0) as i64);
        self.uptime.set(uptime_secs);
    }
    
    /// Track operation timing
    pub async fn track_operation<F, R>(&self, operation: &str, f: F) -> Result<R>
    where
        F: std::future::Future<Output = Result<R>>,
    {
        let start = Instant::now();
        let result = f.await;
        let duration = start.elapsed();
        
        let mut tracker = self.performance_tracker.write().await;
        tracker.operation_timings
            .entry(operation.to_string())
            .or_insert_with(Vec::new)
            .push(duration);
        
        result
    }
    
    /// Record throughput
    pub async fn record_throughput(&self, metric: &str, value: f64) {
        let mut tracker = self.performance_tracker.write().await;
        tracker.throughput_measurements
            .entry(metric.to_string())
            .or_insert_with(Vec::new)
            .push(value);
    }
    
    /// Take resource snapshot
    pub async fn take_resource_snapshot(&self) -> ResourceSnapshot {
        let snapshot = ResourceSnapshot {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            cpu_percent: self.cpu_usage.get(),
            memory_mb: (self.memory_usage.get() / 1024 / 1024) as u64,
            disk_io_read: 0,  // Would get from system
            disk_io_write: 0,
            network_in: self.bytes_received.get(),
            network_out: self.bytes_sent.get(),
        };
        
        let mut tracker = self.performance_tracker.write().await;
        tracker.resource_snapshots.push(snapshot.clone());
        
        // Keep only last 1000 snapshots
        if tracker.resource_snapshots.len() > 1000 {
            tracker.resource_snapshots.remove(0);
        }
        
        snapshot
    }
    
    /// Get metrics snapshot
    pub fn get_snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            chain: ChainMetrics {
                height: self.chain_height.get(),
                headers: self.chain_headers.get(),
                difficulty: self.mining_difficulty.get(),
                chainwork: self.chain_work.get(),
                reorgs: self.chain_reorgs.get(),
            },
            network: NetworkMetrics {
                peers: self.peers_connected.get(),
                messages_in: 0, // Would sum from vector
                messages_out: 0,
                bytes_in: self.bytes_received.get(),
                bytes_out: self.bytes_sent.get(),
            },
            mempool: MempoolMetrics {
                size: self.mempool_size.get(),
                bytes: self.mempool_bytes.get(),
                min_fee_rate: self.mempool_fee_rate.get(),
                tx_received: self.tx_received.get(),
                tx_rejected: self.tx_rejected.get(),
            },
            validation: ValidationMetrics {
                blocks_validated: self.blocks_validated.get(),
                blocks_failed: self.blocks_failed.get(),
                avg_block_time: 0.0, // Would calculate from histogram
                tx_validated: self.tx_validated.get(),
                avg_tx_time: 0.0,
            },
            storage: StorageMetrics {
                reads: self.storage_reads.get(),
                writes: self.storage_writes.get(),
                size_gb: (self.storage_size.get() as f64) / 1024.0 / 1024.0 / 1024.0,
                utxo_count: self.utxo_set_size.get(),
                cache_hit_rate: {
                    let hits = self.cache_hits.get() as f64;
                    let misses = self.cache_misses.get() as f64;
                    if hits + misses > 0.0 {
                        hits / (hits + misses)
                    } else {
                        0.0
                    }
                },
            },
            system: SystemMetrics {
                cpu_percent: self.cpu_usage.get(),
                memory_mb: self.memory_usage.get() / 1024 / 1024,
                disk_gb: (self.disk_usage.get() as f64) / 1024.0 / 1024.0 / 1024.0,
                uptime_seconds: self.uptime.get(),
            },
        }
    }
    
    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
    
    /// Export metrics as JSON
    pub fn export_json(&self) -> String {
        let snapshot = self.get_snapshot();
        serde_json::to_string_pretty(&snapshot).unwrap()
    }
}

/// Global metrics instance
lazy_static::lazy_static! {
    pub static ref METRICS: MetricsCollector = MetricsCollector::new().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metrics_creation() {
        let metrics = MetricsCollector::new().unwrap();
        
        // Update some metrics
        metrics.update_chain_metrics(700000, 700000, 1000000.0, 1e20);
        metrics.update_network_metrics(8);
        
        // Get snapshot
        let snapshot = metrics.get_snapshot();
        assert_eq!(snapshot.chain.height, 700000);
        assert_eq!(snapshot.network.peers, 8);
    }
    
    #[tokio::test]
    async fn test_operation_tracking() {
        let metrics = MetricsCollector::new().unwrap();
        
        let result = metrics.track_operation("test_op", async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok::<_, anyhow::Error>(42)
        }).await.unwrap();
        
        assert_eq!(result, 42);
    }
}