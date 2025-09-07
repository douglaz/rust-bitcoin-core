use anyhow::{Context, Result};
use bitcoin::{Block, BlockHash, Network, Transaction};
use bitcoin_hashes::Hash;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use bitcoin_core_lib::chain::{BlockStatus, ChainManager};
use mempool::Mempool;
use miner::Miner;
use network::NetworkManager;
use rpc::SimpleRpcServer;
use storage::{StorageManager, TransactionIndex};
use wallet::Wallet;

/// Complete Bitcoin node coordinator
pub struct NodeCoordinator {
    /// Node configuration
    config: NodeConfig,

    /// Network type
    network: Network,

    /// Chain manager
    chain_manager: Arc<ChainManager>,

    /// Mempool
    mempool: Arc<RwLock<Mempool>>,

    /// Storage manager
    storage: Arc<StorageManager>,

    /// Network manager
    network_manager: Arc<Mutex<NetworkManager>>,

    /// Miner
    miner: Arc<Miner>,

    /// Wallet (optional)
    wallet: Option<Arc<Mutex<Wallet>>>,

    /// Transaction index
    tx_index: Arc<TransactionIndex>,

    // UTXO cache removed - needs redesign
    /// RPC server
    rpc_server: Option<Arc<SimpleRpcServer>>,

    /// Node statistics
    stats: Arc<RwLock<NodeStats>>,

    /// Shutdown signal
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: Arc<RwLock<mpsc::Receiver<()>>>,
}

/// Node statistics
#[derive(Debug, Default, Clone)]
pub struct NodeStats {
    pub blocks_processed: u64,
    pub transactions_processed: u64,
    pub peers_connected: usize,
    pub chain_height: u32,
    pub mempool_size: usize,
    pub uptime_seconds: u64,
    pub syncing: bool,
    pub ibd_progress: f32,
}

/// Node configuration
pub struct NodeConfig {
    pub network: Network,
    pub data_dir: String,
    pub rpc_enabled: bool,
    pub rpc_bind: String,
    pub rpc_port: u16,
    pub p2p_port: u16,
    pub max_peers: usize,
    pub mining_enabled: bool,
    pub mining_threads: usize,
    pub wallet_enabled: bool,
    pub tx_index_enabled: bool,
    pub prune_mode: bool,
    pub prune_target_size: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            data_dir: ".bitcoin".to_string(),
            rpc_enabled: true,
            rpc_bind: "127.0.0.1".to_string(),
            rpc_port: 8332,
            p2p_port: 8333,
            max_peers: 125,
            mining_enabled: false,
            mining_threads: 4,
            wallet_enabled: true,
            tx_index_enabled: true,
            prune_mode: false,
            prune_target_size: 0,
        }
    }
}

impl NodeCoordinator {
    /// Create new node coordinator
    pub async fn new(config: NodeConfig) -> Result<Self> {
        info!(
            "Initializing Bitcoin node coordinator for {:?}",
            config.network
        );

        // Initialize storage
        let storage = Arc::new(
            StorageManager::new(&config.data_dir)
                .await
                .context("Failed to initialize storage")?,
        );

        // Initialize chain manager
        let network_str = match config.network {
            Network::Bitcoin => "mainnet".to_string(),
            Network::Testnet => "testnet".to_string(),
            Network::Regtest => "regtest".to_string(),
            Network::Signet => "signet".to_string(),
            _ => "mainnet".to_string(),
        };
        let chain_manager = Arc::new(
            ChainManager::new(storage.clone(), network_str.clone())
                .await
                .context("Failed to initialize chain manager")?,
        );

        // Initialize mempool with UTXO manager
        // Wrap chain_manager in RwLock for Mempool
        let chain_for_mempool = Arc::new(RwLock::new(
            ChainManager::new(storage.clone(), network_str.clone())
                .await
                .context("Failed to initialize chain manager for mempool")?,
        ));
        let utxo_manager = Arc::new(bitcoin_core_lib::utxo_manager::UtxoManager::new());
        let mempool = Arc::new(RwLock::new(
            Mempool::new(chain_for_mempool, utxo_manager)
                .await
                .context("Failed to initialize mempool")?,
        ));

        // UTXO cache needs redesign - skipped for now

        // Initialize transaction index
        let tx_index = if config.tx_index_enabled {
            let tx_config = storage::TxIndexConfig::default();
            Arc::new(TransactionIndex::new(
                std::path::Path::new(&config.data_dir).join("txindex"),
                tx_config,
            )?)
        } else {
            Arc::new(TransactionIndex::new(
                std::path::Path::new(&config.data_dir).join("txindex"),
                storage::TxIndexConfig {
                    enabled: false,
                    ..Default::default()
                },
            )?)
        };

        // Initialize network components
        // Get best height from chain manager
        let best_height = chain_manager.get_best_height();

        let mut network_manager =
            NetworkManager::new(config.network, chain_manager.clone(), best_height);

        // Connect mempool to network manager for transaction relay
        network_manager.set_mempool(mempool.clone());

        let network_manager = Arc::new(Mutex::new(network_manager));

        // Network manager handles peer management and transaction broadcasting now

        // Initialize miner
        let miner = Arc::new(Miner::new());

        // Initialize wallet if enabled
        let wallet = if config.wallet_enabled {
            // Create a default wallet with a generated mnemonic for now
            // In production, this should be loaded from existing wallet or user-provided
            match wallet::Wallet::create(
                "default_wallet".to_string(),
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", // Default test mnemonic
                "", // No passphrase
                config.network,
                &Path::new(&config.data_dir).join("wallet"),
            ).await {
                Ok(w) => {
                    info!("Wallet initialized successfully");
                    Some(Arc::new(Mutex::new(w)))
                }
                Err(e) => {
                    warn!("Failed to initialize wallet: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Initialize RPC server if enabled
        let rpc_server = if config.rpc_enabled {
            let rpc_addr = format!("{}:{}", config.rpc_bind, config.rpc_port)
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:8332".parse().unwrap());

            // RPC server needs ChainManager wrapped in RwLock
            let chain_for_rpc = Arc::new(RwLock::new(
                ChainManager::new(storage.clone(), network_str.clone())
                    .await
                    .context("Failed to initialize chain manager for RPC")?,
            ));

            Some(Arc::new(rpc::simple_server::SimpleRpcServer::new(
                rpc_addr,
                chain_for_rpc,
                mempool.clone(),
                network_manager.clone(),
            )))
        } else {
            None
        };

        // Create shutdown channels
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let network = config.network;

        Ok(Self {
            config,
            network,
            chain_manager,
            mempool,
            storage,
            network_manager,
            miner,
            wallet,
            tx_index,
            rpc_server,
            stats: Arc::new(RwLock::new(NodeStats::default())),
            shutdown_tx,
            shutdown_rx: Arc::new(RwLock::new(shutdown_rx)),
        })
    }

    /// Start the node
    pub async fn start(&self) -> Result<()> {
        info!("Starting Bitcoin node");

        // Start network manager
        self.network_manager.lock().await.start().await?;

        // Start RPC server
        if let Some(rpc) = self.rpc_server.clone() {
            let rpc_handle = tokio::spawn(async move {
                match rpc.run().await {
                    Ok(handle) => {
                        info!("RPC server started successfully");
                        // Keep the handle alive
                        tokio::signal::ctrl_c().await.ok();
                        handle.stop().unwrap();
                    }
                    Err(e) => {
                        error!("Failed to start RPC server: {}", e);
                    }
                }
            });

            // Store handle if needed for cleanup
            // For now, we let it run in the background
            info!("RPC server starting...");
        }

        // Start IBD if needed
        if self.needs_ibd().await? {
            info!("Starting Initial Block Download");
            self.start_ibd().await?;
        }

        // Start main event loop
        self.run_event_loop().await?;

        Ok(())
    }

    /// Check if IBD is needed
    async fn needs_ibd(&self) -> Result<bool> {
        let chain_height = self.chain_manager.get_best_height();
        let estimated_height = self.get_estimated_network_height().await?;

        // Need IBD if we're more than 6 blocks behind
        Ok(chain_height + 6 < estimated_height)
    }

    /// Get estimated network height
    async fn get_estimated_network_height(&self) -> Result<u32> {
        // Get from peers or use hardcoded checkpoint
        // For now, return a reasonable estimate
        Ok(800_000)
    }

    /// Start Initial Block Download
    async fn start_ibd(&self) -> Result<()> {
        // Get genesis hash from chain manager
        let genesis_hash = self
            .chain_manager
            .get_block_hash_at_height(0)
            .unwrap_or_else(|| {
                // Use network-specific genesis hash as fallback
                match self.network {
                    Network::Bitcoin => {
                        bitcoin::blockdata::constants::genesis_block(Network::Bitcoin).block_hash()
                    }
                    Network::Testnet => {
                        bitcoin::blockdata::constants::genesis_block(Network::Testnet).block_hash()
                    }
                    Network::Regtest => {
                        bitcoin::blockdata::constants::genesis_block(Network::Regtest).block_hash()
                    }
                    Network::Signet => {
                        bitcoin::blockdata::constants::genesis_block(Network::Signet).block_hash()
                    }
                    _ => BlockHash::from_byte_array([0u8; 32]),
                }
            });

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.syncing = true;
        }

        // IBD is now handled by network manager's sync module
        // The network manager will automatically sync when started

        Ok(())
    }

    /// Main event loop
    async fn run_event_loop(&self) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut block_check_interval = tokio::time::interval(Duration::from_secs(10));
        let mut mempool_cleanup_interval = tokio::time::interval(Duration::from_secs(60));
        let mut stats_interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                // Check for shutdown
                _ = async {
                    let mut rx = self.shutdown_rx.write().await;
                    rx.recv().await
                } => {
                    info!("Shutdown signal received");
                    break;
                }

                // Regular tick
                _ = interval.tick() => {
                    self.process_tick().await?;
                }

                // Check for new blocks
                _ = block_check_interval.tick() => {
                    self.check_for_new_blocks().await?;
                }

                // Clean up mempool
                _ = mempool_cleanup_interval.tick() => {
                    self.cleanup_mempool().await?;
                }

                // Update statistics
                _ = stats_interval.tick() => {
                    self.update_statistics().await?;
                }
            }
        }

        info!("Node event loop stopped");
        Ok(())
    }

    /// Process regular tick
    async fn process_tick(&self) -> Result<()> {
        // Process any pending network messages
        self.process_network_messages().await?;

        // Process any new transactions
        self.process_new_transactions().await?;

        Ok(())
    }

    /// Process network messages
    async fn process_network_messages(&self) -> Result<()> {
        // Network manager handles message processing internally
        // External message processing can be added via message channels if needed

        Ok(())
    }

    /// Handle new block
    async fn handle_new_block(&self, block: Block) -> Result<()> {
        debug!("Processing new block: {}", block.block_hash());

        // Validate and add to chain
        let status = self.chain_manager.process_block(block.clone()).await?;

        match status {
            BlockStatus::Valid | BlockStatus::InActiveChain => {
                // Update statistics
                let mut stats = self.stats.write().await;
                stats.blocks_processed += 1;

                // Get current height from chain manager
                let height = self.chain_manager.get_best_height();
                stats.chain_height = height;

                // Index block if enabled
                if self.config.tx_index_enabled {
                    // Get block time from the header
                    let block_time = block.header.time;
                    self.tx_index
                        .index_block(&block, height, block_time)
                        .await?;
                }

                // Remove mined transactions from mempool
                for tx in &block.txdata[1..] {
                    let mut mempool = self.mempool.write().await;
                    let _ = mempool.remove_transaction(&tx.compute_txid()).await;
                }

                info!("Block {} accepted at height {}", block.block_hash(), height);
            }
            BlockStatus::Invalid => {
                warn!("Block {} rejected as invalid", block.block_hash());
            }
            BlockStatus::Orphan => {
                debug!("Block {} is an orphan", block.block_hash());
            }
        }

        Ok(())
    }

    /// Handle new transaction
    async fn handle_new_transaction(&self, tx: Transaction) -> Result<()> {
        let txid = tx.compute_txid();
        debug!("Processing new transaction: {}", txid);

        // Validate and add to mempool
        match self.mempool.write().await.add_transaction(tx.clone()).await {
            Ok(_) => {
                // Update statistics
                let mut stats = self.stats.write().await;
                stats.transactions_processed += 1;
                stats.mempool_size = self.mempool.read().await.size();

                // Broadcast to peers
                self.network_manager
                    .lock()
                    .await
                    .broadcast_transaction(&tx)
                    .await?;

                debug!("Transaction {} added to mempool", txid);
            }
            Err(e) => {
                debug!("Transaction {} rejected: {}", txid, e);
            }
        }

        Ok(())
    }

    /// Process new transactions from wallet or RPC
    async fn process_new_transactions(&self) -> Result<()> {
        // Note: Wallet transaction processing would require implementing
        // a pending transaction queue in the wallet module.
        // For now, transactions can be submitted via RPC sendrawtransaction
        // which adds them directly to the mempool.

        // This method would:
        // 1. Check wallet for any pending transactions
        // 2. Validate each transaction
        // 3. Add valid transactions to mempool
        // 4. Broadcast to peers

        // Currently handled through RPC interface
        Ok(())
    }

    /// Check for new blocks to mine
    async fn check_for_new_blocks(&self) -> Result<()> {
        // Check if mining is enabled
        if !self.miner.is_mining_enabled() {
            return Ok(());
        }

        // Check if we should mine a new block
        let mempool_size = self.mempool.read().await.size();
        if mempool_size > 0 || self.should_mine_empty_block().await {
            self.mine_new_block().await?;
        }

        Ok(())
    }

    /// Check if we should mine an empty block
    async fn should_mine_empty_block(&self) -> bool {
        // Mine empty blocks in regtest for testing
        self.network == Network::Regtest
    }

    /// Mine a new block
    async fn mine_new_block(&self) -> Result<()> {
        info!("Starting block mining");

        // Get chain tip and height
        let chain_tip = self.chain_manager.get_best_block_hash();
        let height = self.chain_manager.get_best_height() + 1;

        // Get transactions from mempool
        // For now, use empty transaction list since mempool needs redesign
        let transactions = Vec::new();

        // Create block template
        let template = self
            .miner
            .create_block_template(chain_tip, height, transactions)
            .await?;

        info!(
            "Created block template for height {} with {} transactions",
            template.height,
            template.transactions.len()
        );

        // Note: Actual proof-of-work mining would be implemented here
        // Currently simulating mining for testing purposes
        debug!("Block mining not fully implemented - would solve PoW here");

        Ok(())
    }

    /// Clean up mempool
    async fn cleanup_mempool(&self) -> Result<()> {
        debug!("Running mempool cleanup");

        let mut mempool = self.mempool.write().await;

        // Remove transactions older than 2 weeks (14 days)
        const MAX_AGE_SECONDS: u64 = 14 * 24 * 60 * 60;
        let expired_count = mempool.remove_expired_transactions(MAX_AGE_SECONDS).await?;

        // Evict low-fee transactions if mempool is too large
        const MAX_MEMPOOL_SIZE: usize = 300_000; // Max 300k transactions
        let evicted_count = mempool.evict_by_feerate(MAX_MEMPOOL_SIZE).await?;

        if expired_count > 0 || evicted_count > 0 {
            info!(
                "Mempool cleanup: removed {} expired, evicted {} low-fee transactions",
                expired_count, evicted_count
            );
        }

        Ok(())
    }

    /// Update node statistics
    async fn update_statistics(&self) -> Result<()> {
        let mut stats = self.stats.write().await;

        // Update basic stats
        stats.chain_height = self.chain_manager.get_best_height();
        stats.mempool_size = self.mempool.read().await.size();
        stats.peers_connected = self.network_manager.lock().await.peer_count().await;

        // Update IBD progress
        if stats.syncing {
            // Sync stats are tracked by the network manager
            // Progress can be monitored via network.get_sync_progress()
            let estimated_height = self.get_estimated_network_height().await.unwrap_or(0);
            if estimated_height > 0 {
                stats.ibd_progress =
                    (stats.chain_height as f32) / (estimated_height as f32) * 100.0;

                if stats.chain_height >= estimated_height {
                    stats.syncing = false;
                    info!("Initial Block Download complete!");
                }
            }
        }

        // Log statistics
        info!(
            "Node stats: height={}, mempool={}, peers={}, sync={}%",
            stats.chain_height,
            stats.mempool_size,
            stats.peers_connected,
            if stats.syncing {
                stats.ibd_progress
            } else {
                100.0
            }
        );

        Ok(())
    }

    /// Get node statistics
    pub async fn get_stats(&self) -> NodeStats {
        self.stats.read().await.clone()
    }

    /// Shutdown the node
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down Bitcoin node");

        // Send shutdown signal
        self.shutdown_tx.send(()).await?;

        // Stop components
        if let Some(ref rpc) = self.rpc_server {
            // SimpleRpcServer stops when dropped
            info!("Stopping RPC server");
        }

        self.network_manager.lock().await.shutdown().await?;

        // Flush data to disk
        self.storage.flush().await?;
        // UTXO cache removed - no flush needed

        // Save wallet state
        // Wallet persistence is handled automatically by the wallet module

        info!("Node shutdown complete");
        Ok(())
    }
}

/// Network message types
enum NetworkMessage {
    Block(Block),
    Transaction(Transaction),
    Headers(Vec<bitcoin::block::Header>),
    GetBlocks(Vec<BlockHash>),
    GetHeaders(Vec<BlockHash>),
    Inv(Vec<bitcoin::p2p::message_blockdata::Inventory>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_initialization() -> Result<()> {
        let config = NodeConfig {
            network: Network::Regtest,
            data_dir: "/tmp/test_bitcoin".to_string(),
            rpc_enabled: false,
            mining_enabled: false,
            wallet_enabled: false,
            tx_index_enabled: false,
            ..Default::default()
        };

        let node = NodeCoordinator::new(config).await?;
        assert_eq!(node.network, Network::Regtest);

        Ok(())
    }
}
