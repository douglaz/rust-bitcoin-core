//! Prometheus metrics exporter for Bitcoin node
//! 
//! Provides Prometheus-compatible metrics endpoint for monitoring

use anyhow::Result;
use prometheus::{
    register_counter, register_gauge, register_histogram, register_int_counter,
    register_int_gauge, Counter, Encoder, Gauge, Histogram, IntCounter, IntGauge, TextEncoder,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use warp::Filter;

/// Prometheus metrics for the Bitcoin node
pub struct PrometheusMetrics {
    // Chain metrics
    pub chain_height: IntGauge,
    pub chain_headers: IntGauge,
    pub chain_size_bytes: IntGauge,
    pub chain_verification_progress: Gauge,
    
    // Block metrics
    pub blocks_validated_total: IntCounter,
    pub block_validation_duration_seconds: Histogram,
    pub block_size_bytes: Histogram,
    pub block_transactions: Histogram,
    
    // Transaction metrics
    pub transactions_validated_total: IntCounter,
    pub transaction_validation_duration_seconds: Histogram,
    pub transaction_size_bytes: Histogram,
    
    // Network metrics
    pub peers_connected: IntGauge,
    pub peers_inbound: IntGauge,
    pub peers_outbound: IntGauge,
    pub network_bytes_received: IntCounter,
    pub network_bytes_sent: IntCounter,
    pub network_messages_received: IntCounter,
    pub network_messages_sent: IntCounter,
    
    // Mempool metrics
    pub mempool_transactions: IntGauge,
    pub mempool_size_bytes: IntGauge,
    pub mempool_min_fee_rate: Gauge,
    pub mempool_evictions: IntCounter,
    
    // P2P message metrics
    pub p2p_messages_by_type: prometheus::CounterVec,
    pub p2p_message_size_bytes: prometheus::HistogramVec,
    
    // RPC metrics
    pub rpc_requests_total: prometheus::CounterVec,
    pub rpc_request_duration_seconds: prometheus::HistogramVec,
    pub rpc_active_connections: IntGauge,
    
    // Storage metrics
    pub storage_size_bytes: IntGauge,
    pub storage_reads_total: IntCounter,
    pub storage_writes_total: IntCounter,
    pub storage_read_duration_seconds: Histogram,
    pub storage_write_duration_seconds: Histogram,
    
    // UTXO metrics
    pub utxo_set_size: IntGauge,
    pub utxo_cache_size: IntGauge,
    pub utxo_cache_hits: IntCounter,
    pub utxo_cache_misses: IntCounter,
    
    // System metrics
    pub process_cpu_seconds_total: Counter,
    pub process_memory_bytes: IntGauge,
    pub process_open_fds: IntGauge,
    pub process_start_time_seconds: Gauge,
    
    // Mining metrics (if enabled)
    pub mining_hash_rate: Gauge,
    pub mining_blocks_found: IntCounter,
    pub mining_shares_submitted: IntCounter,
    
    // Wallet metrics (if enabled)
    pub wallet_balance_satoshis: IntGauge,
    pub wallet_transactions_total: IntCounter,
    pub wallet_addresses_generated: IntCounter,
}

impl PrometheusMetrics {
    /// Create new metrics instance with all metrics registered
    pub fn new() -> Result<Self> {
        Ok(Self {
            // Chain metrics
            chain_height: register_int_gauge!(
                "bitcoin_chain_height",
                "Current blockchain height"
            )?,
            chain_headers: register_int_gauge!(
                "bitcoin_chain_headers",
                "Number of headers in best chain"
            )?,
            chain_size_bytes: register_int_gauge!(
                "bitcoin_chain_size_bytes",
                "Total size of blockchain on disk"
            )?,
            chain_verification_progress: register_gauge!(
                "bitcoin_chain_verification_progress",
                "Blockchain verification progress (0.0 to 1.0)"
            )?,
            
            // Block metrics
            blocks_validated_total: register_int_counter!(
                "bitcoin_blocks_validated_total",
                "Total number of blocks validated"
            )?,
            block_validation_duration_seconds: register_histogram!(
                "bitcoin_block_validation_duration_seconds",
                "Time spent validating blocks"
            )?,
            block_size_bytes: register_histogram!(
                "bitcoin_block_size_bytes",
                "Distribution of block sizes"
            )?,
            block_transactions: register_histogram!(
                "bitcoin_block_transactions",
                "Number of transactions per block"
            )?,
            
            // Transaction metrics
            transactions_validated_total: register_int_counter!(
                "bitcoin_transactions_validated_total",
                "Total number of transactions validated"
            )?,
            transaction_validation_duration_seconds: register_histogram!(
                "bitcoin_transaction_validation_duration_seconds",
                "Time spent validating transactions"
            )?,
            transaction_size_bytes: register_histogram!(
                "bitcoin_transaction_size_bytes",
                "Distribution of transaction sizes"
            )?,
            
            // Network metrics
            peers_connected: register_int_gauge!(
                "bitcoin_peers_connected",
                "Number of connected peers"
            )?,
            peers_inbound: register_int_gauge!(
                "bitcoin_peers_inbound",
                "Number of inbound peer connections"
            )?,
            peers_outbound: register_int_gauge!(
                "bitcoin_peers_outbound",
                "Number of outbound peer connections"
            )?,
            network_bytes_received: register_int_counter!(
                "bitcoin_network_bytes_received_total",
                "Total bytes received from network"
            )?,
            network_bytes_sent: register_int_counter!(
                "bitcoin_network_bytes_sent_total",
                "Total bytes sent to network"
            )?,
            network_messages_received: register_int_counter!(
                "bitcoin_network_messages_received_total",
                "Total messages received from network"
            )?,
            network_messages_sent: register_int_counter!(
                "bitcoin_network_messages_sent_total",
                "Total messages sent to network"
            )?,
            
            // Mempool metrics
            mempool_transactions: register_int_gauge!(
                "bitcoin_mempool_transactions",
                "Number of transactions in mempool"
            )?,
            mempool_size_bytes: register_int_gauge!(
                "bitcoin_mempool_size_bytes",
                "Total size of mempool in bytes"
            )?,
            mempool_min_fee_rate: register_gauge!(
                "bitcoin_mempool_min_fee_rate",
                "Minimum fee rate in mempool (sat/vB)"
            )?,
            mempool_evictions: register_int_counter!(
                "bitcoin_mempool_evictions_total",
                "Total number of mempool evictions"
            )?,
            
            // P2P message metrics
            p2p_messages_by_type: prometheus::CounterVec::new(
                prometheus::Opts::new(
                    "bitcoin_p2p_messages_total",
                    "P2P messages by type"
                ),
                &["message_type", "direction"]
            )?,
            p2p_message_size_bytes: prometheus::HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "bitcoin_p2p_message_size_bytes",
                    "P2P message sizes by type"
                ),
                &["message_type"]
            )?,
            
            // RPC metrics
            rpc_requests_total: prometheus::CounterVec::new(
                prometheus::Opts::new(
                    "bitcoin_rpc_requests_total",
                    "Total RPC requests by method"
                ),
                &["method", "status"]
            )?,
            rpc_request_duration_seconds: prometheus::HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "bitcoin_rpc_request_duration_seconds",
                    "RPC request duration by method"
                ),
                &["method"]
            )?,
            rpc_active_connections: register_int_gauge!(
                "bitcoin_rpc_active_connections",
                "Number of active RPC connections"
            )?,
            
            // Storage metrics
            storage_size_bytes: register_int_gauge!(
                "bitcoin_storage_size_bytes",
                "Total storage size in bytes"
            )?,
            storage_reads_total: register_int_counter!(
                "bitcoin_storage_reads_total",
                "Total storage read operations"
            )?,
            storage_writes_total: register_int_counter!(
                "bitcoin_storage_writes_total",
                "Total storage write operations"
            )?,
            storage_read_duration_seconds: register_histogram!(
                "bitcoin_storage_read_duration_seconds",
                "Storage read operation duration"
            )?,
            storage_write_duration_seconds: register_histogram!(
                "bitcoin_storage_write_duration_seconds",
                "Storage write operation duration"
            )?,
            
            // UTXO metrics
            utxo_set_size: register_int_gauge!(
                "bitcoin_utxo_set_size",
                "Number of unspent transaction outputs"
            )?,
            utxo_cache_size: register_int_gauge!(
                "bitcoin_utxo_cache_size",
                "Number of UTXOs in cache"
            )?,
            utxo_cache_hits: register_int_counter!(
                "bitcoin_utxo_cache_hits_total",
                "Total UTXO cache hits"
            )?,
            utxo_cache_misses: register_int_counter!(
                "bitcoin_utxo_cache_misses_total",
                "Total UTXO cache misses"
            )?,
            
            // System metrics
            process_cpu_seconds_total: register_counter!(
                "bitcoin_process_cpu_seconds_total",
                "Total CPU time consumed"
            )?,
            process_memory_bytes: register_int_gauge!(
                "bitcoin_process_memory_bytes",
                "Process memory usage in bytes"
            )?,
            process_open_fds: register_int_gauge!(
                "bitcoin_process_open_fds",
                "Number of open file descriptors"
            )?,
            process_start_time_seconds: register_gauge!(
                "bitcoin_process_start_time_seconds",
                "Unix timestamp of process start"
            )?,
            
            // Mining metrics
            mining_hash_rate: register_gauge!(
                "bitcoin_mining_hash_rate",
                "Current mining hash rate"
            )?,
            mining_blocks_found: register_int_counter!(
                "bitcoin_mining_blocks_found_total",
                "Total blocks found by this node"
            )?,
            mining_shares_submitted: register_int_counter!(
                "bitcoin_mining_shares_submitted_total",
                "Total mining shares submitted"
            )?,
            
            // Wallet metrics
            wallet_balance_satoshis: register_int_gauge!(
                "bitcoin_wallet_balance_satoshis",
                "Wallet balance in satoshis"
            )?,
            wallet_transactions_total: register_int_counter!(
                "bitcoin_wallet_transactions_total",
                "Total wallet transactions"
            )?,
            wallet_addresses_generated: register_int_counter!(
                "bitcoin_wallet_addresses_generated_total",
                "Total addresses generated"
            )?,
        })
    }
    
    /// Start Prometheus metrics server
    pub async fn serve(self: Arc<Self>, port: u16) {
        let metrics = self.clone();
        let metrics_route = warp::path("metrics")
            .and(warp::get())
            .map(move || {
                let encoder = TextEncoder::new();
                let metric_families = prometheus::gather();
                let mut buffer = vec![];
                encoder.encode(&metric_families, &mut buffer).unwrap();
                String::from_utf8(buffer).unwrap()
            });
        
        let health_route = warp::path("health")
            .and(warp::get())
            .map(|| "OK");
        
        let routes = metrics_route.or(health_route);
        
        tracing::info!("Starting Prometheus metrics server on port {}", port);
        warp::serve(routes)
            .run(([0, 0, 0, 0], port))
            .await;
    }
    
    /// Update chain metrics
    pub fn update_chain_metrics(
        &self,
        height: i32,
        headers: i32,
        size_bytes: i64,
        progress: f64,
    ) {
        self.chain_height.set(height as i64);
        self.chain_headers.set(headers as i64);
        self.chain_size_bytes.set(size_bytes);
        self.chain_verification_progress.set(progress);
    }
    
    /// Update network metrics
    pub fn update_network_metrics(
        &self,
        peers: i64,
        inbound: i64,
        outbound: i64,
    ) {
        self.peers_connected.set(peers);
        self.peers_inbound.set(inbound);
        self.peers_outbound.set(outbound);
    }
    
    /// Update mempool metrics
    pub fn update_mempool_metrics(
        &self,
        tx_count: i64,
        size_bytes: i64,
        min_fee_rate: f64,
    ) {
        self.mempool_transactions.set(tx_count);
        self.mempool_size_bytes.set(size_bytes);
        self.mempool_min_fee_rate.set(min_fee_rate);
    }
    
    /// Record block validation
    pub fn record_block_validation(&self, duration_secs: f64, size: usize, tx_count: usize) {
        self.blocks_validated_total.inc();
        self.block_validation_duration_seconds.observe(duration_secs);
        self.block_size_bytes.observe(size as f64);
        self.block_transactions.observe(tx_count as f64);
    }
    
    /// Record transaction validation
    pub fn record_transaction_validation(&self, duration_secs: f64, size: usize) {
        self.transactions_validated_total.inc();
        self.transaction_validation_duration_seconds.observe(duration_secs);
        self.transaction_size_bytes.observe(size as f64);
    }
    
    /// Record P2P message
    pub fn record_p2p_message(&self, msg_type: &str, direction: &str, size: usize) {
        self.p2p_messages_by_type
            .with_label_values(&[msg_type, direction])
            .inc();
        self.p2p_message_size_bytes
            .with_label_values(&[msg_type])
            .observe(size as f64);
        
        if direction == "received" {
            self.network_messages_received.inc();
            self.network_bytes_received.inc_by(size as u64);
        } else {
            self.network_messages_sent.inc();
            self.network_bytes_sent.inc_by(size as u64);
        }
    }
    
    /// Record RPC request
    pub fn record_rpc_request(&self, method: &str, duration_secs: f64, success: bool) {
        let status = if success { "success" } else { "error" };
        self.rpc_requests_total
            .with_label_values(&[method, status])
            .inc();
        self.rpc_request_duration_seconds
            .with_label_values(&[method])
            .observe(duration_secs);
    }
    
    /// Update system metrics
    pub fn update_system_metrics(&self) {
        // Get process stats
        if let Ok(me) = procfs::process::Process::myself() {
            if let Ok(stat) = me.stat() {
                let cpu_time = (stat.utime + stat.stime) as f64 / procfs::ticks_per_second() as f64;
                self.process_cpu_seconds_total.inc_by(cpu_time);
            }
            
            if let Ok(status) = me.status() {
                if let Some(vm_rss) = status.vmrss {
                    self.process_memory_bytes.set(vm_rss as i64 * 1024);
                }
            }
            
            if let Ok(fds) = me.fd_count() {
                self.process_open_fds.set(fds as i64);
            }
        }
    }
}

/// Start metrics collection background task
pub async fn start_metrics_collector(
    metrics: Arc<PrometheusMetrics>,
    chain: Arc<RwLock<bitcoin_core_lib::chain::ChainManager>>,
    network: Arc<network::NetworkManager>,
    mempool: Arc<RwLock<mempool::Mempool>>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    
    loop {
        interval.tick().await;
        
        // Update chain metrics
        {
            let chain = chain.read().await;
            metrics.update_chain_metrics(
                chain.get_best_height() as i32,
                chain.get_best_height() as i32,
                0, // TODO: Get actual chain size
                if chain.is_initial_block_download() { 0.5 } else { 1.0 },
            );
        }
        
        // Update network metrics
        {
            let peer_info = network.get_peer_info();
            let inbound = peer_info.iter().filter(|p| p.get("inbound").and_then(|v| v.as_bool()).unwrap_or(false)).count();
            let outbound = peer_info.len() - inbound;
            metrics.update_network_metrics(
                peer_info.len() as i64,
                inbound as i64,
                outbound as i64,
            );
        }
        
        // Update mempool metrics
        {
            let mempool = mempool.read().await;
            let stats = mempool.get_mempool_stats();
            metrics.update_mempool_metrics(
                stats.tx_count as i64,
                stats.total_size as i64,
                stats.min_fee_rate.0 as f64,
            );
        }
        
        // Update system metrics
        metrics.update_system_metrics();
    }
}