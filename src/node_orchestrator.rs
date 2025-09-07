use anyhow::{Context, Result};
use bitcoin::Network;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use bitcoin_core_lib::{
    chain::ChainManager,
    difficulty::DifficultyCalculator,
    utxo_tracker::UtxoTracker,
};
use mempool::mempool_acceptance::MempoolAcceptance;
use mining::BlockTemplateBuilder;
use network::{
    chain_sync::ChainSyncCoordinator,
    ibd_manager::IBDManager,
    network_connection::ConnectionManager,
    p2p_message_handler::P2PMessageHandler,
    peer_discovery::PeerDiscovery,
};
use rpc::rpc_implementation::RpcImplementation;
use storage::{manager::StorageManager, optimized_storage::OptimizedStorage};

/// Configuration for the Bitcoin node
#[derive(Clone)]
pub struct NodeConfig {
    pub network: Network,
    pub data_dir: PathBuf,
    pub rpc_port: u16,
    pub p2p_port: u16,
    pub max_connections: usize,
    pub enable_mining: bool,
    pub mining_address: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            data_dir: PathBuf::from("./bitcoin-data"),
            rpc_port: 8332,
            p2p_port: 8333,
            max_connections: 125,
            enable_mining: false,
            mining_address: None,
        }
    }
}

/// Main node orchestrator that coordinates all components
pub struct NodeOrchestrator {
    config: NodeConfig,
    
    // Core components
    storage: Arc<StorageManager>,
    optimized_storage: Arc<OptimizedStorage>,
    chain: Arc<RwLock<ChainManager>>,
    mempool: Arc<MempoolAcceptance>,
    mempool_shared: Arc<RwLock<mempool::Mempool>>,  // Shared mempool instance
    utxo_tracker: Arc<UtxoTracker>,
    
    // Network components
    connection_manager: Arc<ConnectionManager>,
    peer_discovery: Arc<PeerDiscovery>,
    chain_sync: Arc<ChainSyncCoordinator>,
    ibd_manager: Arc<IBDManager>,
    p2p_handler: Arc<P2PMessageHandler>,
    
    // Mining
    block_template_builder: Option<Arc<BlockTemplateBuilder>>,
    
    // RPC
    rpc_impl: Arc<RpcImplementation>,
    
    // Control
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: Option<mpsc::Receiver<()>>,
}

impl NodeOrchestrator {
    /// Create a new node orchestrator
    pub async fn new(config: NodeConfig) -> Result<Self> {
        info!("Initializing Bitcoin node for network: {:?}", config.network);
        
        // Create data directory if it doesn't exist
        std::fs::create_dir_all(&config.data_dir)
            .context("Failed to create data directory")?;
        
        // Initialize storage
        info!("Initializing storage layer...");
        let storage = Arc::new(
            StorageManager::new(config.data_dir.to_str().unwrap())
                .await
                .context("Failed to initialize storage")?
        );
        
        let optimized_storage = Arc::new(
            OptimizedStorage::new(config.data_dir.join("optimized"))
                .await
                .context("Failed to initialize optimized storage")?
        );
        
        // Initialize chain manager
        info!("Initializing chain manager...");
        let network_str = match config.network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
            Network::Signet => "signet",
        };
        
        let chain = Arc::new(RwLock::new(
            ChainManager::new(storage.clone(), network_str.to_string())
                .await
                .context("Failed to initialize chain manager")?
        ));
        
        // Initialize UTXO tracker
        info!("Initializing UTXO tracker...");
        let utxo_tracker = Arc::new(
            UtxoTracker::new(storage.clone())
                .await
                .context("Failed to initialize UTXO tracker")?
        );
        
        // Initialize mempool
        info!("Initializing mempool...");
        let mempool_config = mempool::MempoolConfig::default();
        let mempool = Arc::new(
            MempoolAcceptance::new(mempool_config, utxo_tracker.clone())
        );
        
        // Create a single shared Mempool instance for RPC and P2P
        let mempool_shared = Arc::new(RwLock::new(
            mempool::Mempool::new(
                chain.clone(),
                Arc::new(core::utxo_manager::UtxoManager::new()),
            ).await?
        ));
        
        // Initialize network components
        info!("Initializing network layer...");
        let connection_manager = Arc::new(
            ConnectionManager::new(config.network, config.max_connections)
        );
        
        let peer_discovery = Arc::new(
            PeerDiscovery::new(network_str.to_string())
        );
        
        let chain_sync = Arc::new(
            ChainSyncCoordinator::new(
                chain.clone(),
                connection_manager.clone(),
            )
        );
        
        let ibd_manager = Arc::new(
            IBDManager::new(
                chain.clone(),
                connection_manager.clone(),
                chain_sync.clone(),
            )
        );
        
        // Initialize P2P message handler with shared mempool
        let p2p_handler = Arc::new(
            P2PMessageHandler::new(
                chain.clone(),
                mempool_shared.clone(),
                connection_manager.clone(),
                config.network,
            )
        );
        
        // Initialize mining if enabled
        let block_template_builder = if config.enable_mining {
            if let Some(mining_addr) = &config.mining_address {
                info!("Initializing mining with address: {}", mining_addr);
                
                // Parse mining address to script
                let script = bitcoin::ScriptBuf::from_hex(mining_addr)
                    .context("Invalid mining address")?;
                
                Some(Arc::new(BlockTemplateBuilder::new(
                    chain.clone(),
                    mempool.clone(),
                    script,
                )))
            } else {
                warn!("Mining enabled but no address provided");
                None
            }
        } else {
            None
        };
        
        // Initialize RPC with shared mempool
        info!("Initializing RPC server...");
        let rpc_impl = Arc::new(RpcImplementation::new(
            chain.clone(),
            mempool_shared.clone(),  // Use the same shared mempool instance
            connection_manager.clone(),
            optimized_storage.clone(),
        ));
        
        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        
        Ok(Self {
            config,
            storage,
            optimized_storage,
            chain,
            mempool,
            mempool_shared,
            utxo_tracker,
            connection_manager,
            peer_discovery,
            chain_sync,
            ibd_manager,
            p2p_handler,
            block_template_builder,
            rpc_impl,
            shutdown_tx,
            shutdown_rx: Some(shutdown_rx),
        })
    }
    
    /// Start the node
    pub async fn start(mut self) -> Result<()> {
        info!("Starting Bitcoin node...");
        
        // Take the shutdown receiver
        let mut shutdown_rx = self.shutdown_rx.take()
            .ok_or_else(|| anyhow::anyhow!("Node already started"))?;
        
        // Start network discovery
        info!("Starting peer discovery...");
        let peers = self.peer_discovery.bootstrap().await?;
        info!("Discovered {} initial peers", peers.len());
        
        // Connect to initial peers
        for peer_addr in peers.iter().take(8) {
            match self.connection_manager.connect_to_peer(*peer_addr).await {
                Ok(_) => info!("Connected to peer: {}", peer_addr),
                Err(e) => warn!("Failed to connect to {}: {}", peer_addr, e),
            }
        }
        
        // Check if IBD is needed and start if necessary
        if self.ibd_manager.is_ibd_needed().await? {
            info!("Initial Block Download required, starting IBD...");
            let ibd = self.ibd_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = ibd.start_ibd().await {
                    error!("IBD failed: {}", e);
                }
            });
        }
        
        // Start RPC server
        info!("Starting RPC server on port {}", self.config.rpc_port);
        let rpc_server = self.start_rpc_server().await?;
        
        // Start chain sync coordinator
        info!("Starting chain synchronization...");
        let chain_sync = self.chain_sync.clone();
        tokio::spawn(async move {
            if let Err(e) = chain_sync.start_sync().await {
                error!("Chain sync failed: {}", e);
            }
        });
        
        // Start mempool management loop
        let mempool = self.mempool.clone();
        let mempool_fee_updater = mempool.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                // Periodic mempool maintenance
                let stats = mempool.get_stats().await;
                debug!("Mempool: {} txs, {} bytes", stats.count, stats.bytes);
                
                // Update fee estimator with current mempool state
                if let Err(e) = mempool.update_fee_estimator().await {
                    warn!("Failed to update fee estimator: {}", e);
                }
            }
        });
        
        // Start fee estimator background task
        info!("Starting fee estimator...");
        let fee_estimator = mempool_fee_updater.start_fee_estimator();
        debug!("Fee estimator started");
        
        // Start peer maintenance task
        let peer_manager = self.p2p_handler.peer_manager();
        let peer_maintenance = network::peer_manager::PeerMaintenance::new(peer_manager.clone());
        info!("Starting peer maintenance task...");
        peer_maintenance.start().await;
        
        // Start compact block cleanup task
        let compact_manager = self.p2p_handler.compact_block_manager();
        info!("Starting compact block maintenance...");
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                // Clean up pending compact blocks older than 5 minutes
                compact_manager.cleanup_pending(Duration::from_secs(300)).await;
            }
        });
        
        // Start orphan block cleanup task
        let chain_for_orphans = self.chain.clone();
        info!("Starting orphan block cleanup task...");
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300)); // Every 5 minutes
            loop {
                interval.tick().await;
                
                // Clean up expired orphan blocks
                let chain = chain_for_orphans.read().await;
                chain.cleanup_orphans().await;
                
                // Get stats for logging
                let stats = chain.get_orphan_stats().await;
                if stats.count > 0 {
                    debug!("Orphan blocks: count={}, size={} bytes, oldest={} seconds", 
                          stats.count, stats.total_size, stats.oldest_age);
                }
                
                // Request missing parent blocks if we have orphans
                if stats.count > 0 {
                    let missing = chain.request_missing_blocks().await;
                    if !missing.is_empty() {
                        debug!("Requesting {} missing parent blocks", missing.len());
                    }
                }
            }
        });
        
        // Start chain reorganization monitoring task
        let chain_for_reorg = self.chain.clone();
        info!("Starting chain reorganization monitor...");
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Every minute
            loop {
                interval.tick().await;
                
                let chain = chain_for_reorg.read().await;
                
                // Check if a reorganization is needed
                if !chain.is_reorg_in_progress().await {
                    match chain.check_for_reorg().await {
                        Ok(true) => {
                            info!("Chain reorganization detected and processed");
                        }
                        Ok(false) => {
                            // No reorganization needed
                        }
                        Err(e) => {
                            warn!("Error checking for chain reorganization: {}", e);
                        }
                    }
                }
                
                // Log reorganization statistics
                let reorg_stats = chain.get_reorg_stats().await;
                if reorg_stats.total_reorgs > 0 {
                    debug!(
                        "Chain reorgs: total={}, max_depth={}, avg_depth={:.1}, blocks_affected={}",
                        reorg_stats.total_reorgs,
                        reorg_stats.max_depth,
                        reorg_stats.avg_depth,
                        reorg_stats.blocks_disconnected + reorg_stats.blocks_connected
                    );
                }
            }
        });
        
        // Start mining if enabled
        if let Some(template_builder) = self.block_template_builder.clone() {
            info!("Starting mining thread...");
            tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    match template_builder.build_template().await {
                        Ok(template) => {
                            info!("Generated mining template with {} transactions", 
                                  template.transactions.len());
                        }
                        Err(e) => {
                            warn!("Failed to generate mining template: {}", e);
                        }
                    }
                }
            });
        }
        
        // Start metrics reporting
        let chain = self.chain.clone();
        let connection_manager = self.connection_manager.clone();
        let peer_manager_metrics = peer_manager.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                
                let chain_guard = chain.read().await;
                let height = chain_guard.get_best_height();
                let best_hash = chain_guard.get_best_block_hash();
                drop(chain_guard);
                
                let peer_count = connection_manager.peer_count().await;
                let peer_stats = peer_manager_metrics.get_stats().await;
                
                info!(
                    "Status: height={}, best_hash={}, peers={} (in:{}/out:{}, score:{})",
                    height, best_hash, peer_count,
                    peer_stats.inbound, peer_stats.outbound, peer_stats.avg_score
                );
            }
        });
        
        // Main event loop
        info!("Bitcoin node started successfully!");
        info!("Node is ready to accept connections on P2P port {}", self.config.p2p_port);
        info!("RPC server listening on port {}", self.config.rpc_port);
        
        // Wait for shutdown signal
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Received shutdown signal");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl-C signal");
            }
        }
        
        // Graceful shutdown
        self.shutdown().await?;
        
        Ok(())
    }
    
    /// Start the RPC server
    async fn start_rpc_server(&self) -> Result<tokio::task::JoinHandle<()>> {
        let rpc_impl = self.rpc_impl.clone();
        let port = self.config.rpc_port;
        
        let handle = tokio::spawn(async move {
            // Create RPC server
            let server = rpc::server::RpcServer::new(rpc_impl);
            
            // Start listening
            let addr = format!("127.0.0.1:{}", port);
            if let Err(e) = server.start(&addr).await {
                error!("RPC server failed: {}", e);
            }
        });
        
        Ok(handle)
    }
    
    /// Shutdown the node gracefully
    async fn shutdown(&self) -> Result<()> {
        info!("Shutting down Bitcoin node...");
        
        // Stop IBD if running
        if self.ibd_manager.is_active().await {
            self.ibd_manager.stop().await;
        }
        
        // Stop chain sync
        self.chain_sync.stop_sync().await;
        
        // Disconnect all peers
        let peers = self.connection_manager.get_connected_peers().await;
        for peer in peers {
            if let Err(e) = self.connection_manager.disconnect_peer(peer).await {
                warn!("Error disconnecting peer {}: {}", peer, e);
            }
        }
        
        // Flush chain state
        let mut chain = self.chain.write().await;
        chain.flush().await?;
        
        // Flush storage
        self.storage.flush().await?;
        
        info!("Bitcoin node shutdown complete");
        Ok(())
    }
    
    /// Get node statistics
    pub async fn get_stats(&self) -> NodeStats {
        let chain = self.chain.read().await;
        let height = chain.get_best_height();
        let best_hash = chain.get_best_block_hash();
        let difficulty = chain.get_current_difficulty();
        drop(chain);
        
        let peer_count = self.connection_manager.peer_count().await;
        let mempool_stats = self.mempool.get_stats().await;
        
        let ibd_active = self.ibd_manager.is_active().await;
        let ibd_stats = if ibd_active {
            Some(self.ibd_manager.get_stats().await)
        } else {
            None
        };
        
        NodeStats {
            chain_height: height,
            best_block_hash: best_hash,
            difficulty,
            peer_count,
            mempool_size: mempool_stats.count,
            mempool_bytes: mempool_stats.bytes,
            ibd_active,
            ibd_progress: ibd_stats.map(|s| s.progress_percent),
        }
    }
}

/// Node statistics
#[derive(Debug, Clone)]
pub struct NodeStats {
    pub chain_height: u32,
    pub best_block_hash: bitcoin::BlockHash,
    pub difficulty: f64,
    pub peer_count: usize,
    pub mempool_size: usize,
    pub mempool_bytes: usize,
    pub ibd_active: bool,
    pub ibd_progress: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_node_config() {
        let config = NodeConfig::default();
        assert_eq!(config.network, Network::Bitcoin);
        assert_eq!(config.rpc_port, 8332);
        assert_eq!(config.p2p_port, 8333);
    }
}