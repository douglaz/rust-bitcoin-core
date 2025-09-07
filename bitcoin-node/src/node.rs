use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::NodeConfig;
use crate::integration::NodeIntegration;
use crate::sync::SyncManager;
use bitcoin_core_lib::chain::ChainManager;
use bitcoin_core_lib::utxo_manager::UtxoManager;
use mempool::Mempool;
use miner::Miner;
use network::NetworkManager;
use rpc::SimpleRpcServer;
use storage::{ChainState, StorageManager};
use wallet::Wallet;

pub struct Node {
    config: NodeConfig,
    chain: Arc<RwLock<ChainManager>>,
    chain_state: Arc<RwLock<ChainState>>,
    mempool: Arc<RwLock<Mempool>>,
    network: Arc<tokio::sync::Mutex<NetworkManager>>,
    storage: Arc<StorageManager>,
    wallet: Arc<RwLock<Wallet>>,
    miner: Arc<RwLock<Miner>>,
    integration: Arc<NodeIntegration>,
    sync_manager: Arc<SyncManager>,
    rpc: Option<SimpleRpcServer>,
    rpc_handle: Option<()>, // Not used anymore, keeping for compatibility
    rpc_task: Option<tokio::task::JoinHandle<()>>,
    utxo_manager: Arc<UtxoManager>,
}

/// Helper function for periodic mempool snapshots
async fn save_mempool_snapshot(
    datadir: &str,
    network: &str,
    mempool: &Arc<RwLock<Mempool>>,
    chain: &Arc<RwLock<ChainManager>>,
) -> Result<()> {
    use mempool::mempool_persistence::MempoolPersistence;

    let persistence = MempoolPersistence::new(datadir);
    let mempool_guard = mempool.read().await;
    let chain_guard = chain.read().await;

    // Get all transactions from mempool
    let mut transactions = HashMap::new();
    for txid in mempool_guard.get_transaction_ids() {
        if let Some(tx) = mempool_guard.get_transaction(&txid) {
            // Create a simplified entry for persistence
            let entry = mempool::mempool_acceptance::MempoolEntry {
                tx: tx.clone(),
                txid,
                wtxid: tx.compute_txid(), // MempoolEntry expects Txid type for wtxid
                fee: 1000,                // Would get from mempool entry
                vsize: tx.vsize(),
                weight: tx.weight().to_wu() as usize,
                fee_rate: 4.0,
                time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                height: chain_guard.get_best_height(),
                ancestors: HashSet::new(),
                descendants: HashSet::new(),
                rbf: false,
            };
            transactions.insert(txid, (tx, entry));
        }
    }

    if !transactions.is_empty() {
        persistence.save_mempool(&transactions, network).await?;
    }

    Ok(())
}

impl Node {
    pub async fn new(config: NodeConfig) -> Result<Self> {
        info!("Initializing node with network: {}", config.network);

        // Initialize storage
        let storage = Arc::new(StorageManager::new(&config.datadir).await?);

        // Initialize chain state
        let db_path = std::path::Path::new(&config.datadir).join("chain_state");
        let db = sled::open(&db_path)?;
        let chain_state = Arc::new(RwLock::new(ChainState::new(Arc::new(db))));

        // Create a shared UTXO manager that will be used by all components
        let utxo_manager = Arc::new(UtxoManager::new());

        // Initialize chain manager for network (needs Arc<ChainManager>)
        // Uses the shared UTXO manager
        let chain_for_network = ChainManager::with_utxo_manager(
            storage.clone(),
            config.network.clone(),
            utxo_manager.clone(),
        )
        .await?;

        // Create Arc version for NetworkManager
        let chain_unwrapped = Arc::new(chain_for_network);

        // Create chain manager for other components (with RwLock)
        // IMPORTANT: Uses the SAME UTXO manager as chain_for_network
        let chain = Arc::new(RwLock::new(
            ChainManager::with_utxo_manager(
                storage.clone(),
                config.network.clone(),
                utxo_manager.clone(),
            )
            .await?,
        ));

        // Initialize mempool with the chain and the SAME UTXO manager
        // This ensures mempool can verify UTXOs that the chain creates
        let mempool = Arc::new(RwLock::new(
            Mempool::new(chain.clone(), utxo_manager.clone()).await?,
        ));

        // Initialize network manager
        let network_config = match config.network.as_str() {
            "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
            "testnet" => bitcoin::Network::Testnet,
            "regtest" => bitcoin::Network::Regtest,
            "signet" => bitcoin::Network::Signet,
            _ => anyhow::bail!("Unknown network: {}", config.network),
        };
        let network_manager = NetworkManager::new(
            network_config,
            chain_unwrapped.clone(),
            0, // TODO: Get actual best height
        );

        // NetworkManager doesn't have set_mempool - it's handled internally
        let network = Arc::new(tokio::sync::Mutex::new(network_manager));

        // Create sync manager after network manager to avoid circular dependency
        let sync_manager = Arc::new(SyncManager::new(chain.clone(), network.clone()));

        // Set the sync manager as the external handler for the network manager
        network.lock().await.set_sync_handler(sync_manager.clone());

        // Initialize wallet (create or load)
        let wallet_path = std::path::Path::new(&config.datadir).join("wallet");
        let mut wallet = if wallet_path.exists() {
            Wallet::load(&wallet_path).await?
        } else {
            // Create new wallet with default mnemonic for now
            // In production, this should generate a new mnemonic
            let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let network = match config.network.as_str() {
                "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
                "testnet" => bitcoin::Network::Testnet,
                "regtest" => bitcoin::Network::Regtest,
                "signet" => bitcoin::Network::Signet,
                _ => anyhow::bail!("Unknown network: {}", config.network),
            };
            Wallet::create("default".to_string(), mnemonic, "", network, &wallet_path).await?
        };

        // Unlock wallet for regtest (in production, this would require user passphrase)
        if config.network == "regtest" && wallet.is_locked() {
            let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            wallet.unlock(mnemonic, "")?;
            info!("Wallet unlocked for regtest");
        }

        let wallet = Arc::new(RwLock::new(wallet));

        // Initialize miner
        let miner = Arc::new(RwLock::new(Miner::new()));

        // Create integration to wire components together
        let integration = Arc::new(NodeIntegration::new(
            wallet.clone(),
            mempool.clone(),
            miner.clone(),
            network.clone(),
            chain_state.clone(),
            storage.clone(),
        ));

        // Initialize RPC server if enabled
        let rpc = if config.rpc_enabled {
            let mut rpc_server = SimpleRpcServer::new(
                config.rpc_bind.parse()?,
                chain.clone(),
                mempool.clone(),
                network.clone(),
            );

            rpc_server = rpc_server.with_wallet(wallet.clone());
            rpc_server = rpc_server.with_miner(miner.clone());

            Some(rpc_server)
        } else {
            None
        };

        Ok(Self {
            config,
            chain,
            chain_state,
            mempool,
            network,
            storage,
            wallet,
            miner,
            integration,
            sync_manager,
            rpc,
            rpc_handle: None,
            rpc_task: None,
            utxo_manager,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Starting node components");

        // Load mempool from disk if available
        if let Err(e) = self.load_mempool().await {
            warn!("Failed to load mempool from disk: {}", e);
            // Continue anyway, it's not critical
        }

        // Initialize component integration
        self.integration.initialize().await?;

        // Start network manager
        self.network.lock().await.start().await?;

        // Connect to initial peers
        for peer in &self.config.connect_peers {
            debug!("Connecting to peer: {}", peer);
            if let Ok(addr) = peer.parse::<std::net::SocketAddr>() {
                match self.network.lock().await.connect_to_peer(addr).await {
                    Ok(_) => info!("Connected to peer: {}", peer),
                    Err(e) => warn!("Failed to connect to peer {}: {}", peer, e),
                }
            } else {
                warn!("Invalid peer address: {}", peer);
            }
        }

        // If no manual peers specified, DNS discovery is handled by NetworkManager::start()
        if self.config.connect_peers.is_empty() && self.config.network != "regtest" {
            info!("No manual peers specified, using DNS discovery (handled by NetworkManager)");
        }

        // Start synchronization in background (with delay to allow peer connections)
        let sync_handle = {
            let sync = self.sync_manager.clone();
            let network = self.config.network.clone();
            tokio::spawn(async move {
                // Wait for initial peer connections
                warn!("SYNC TASK: Waiting for peer connections before starting sync...");
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

                // Only sync for mainnet/testnet (not regtest)
                if network != "regtest" {
                    warn!(
                        "SYNC TASK: Starting blockchain synchronization for {}",
                        network
                    );
                    if let Err(e) = sync.start_sync().await {
                        error!("SYNC TASK: Sync error: {}", e);
                    } else {
                        warn!("SYNC TASK: Synchronization completed successfully");
                    }
                } else {
                    warn!("SYNC TASK: Skipping sync for regtest network");
                }
            })
        };

        // Start RPC server if enabled
        if let Some(rpc) = self.rpc.take() {
            info!("Spawning RPC server task");
            // Spawn RPC server in background task
            let rpc_task = tokio::spawn(async move {
                info!("RPC task started, calling run()");
                match rpc.run().await {
                    Ok(handle) => {
                        info!("RPC server handle obtained successfully");
                        // The server is now running, just keep the handle alive
                        // Don't wait for ctrl_c here, let the main loop handle shutdown
                        loop {
                            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                        }
                    }
                    Err(e) => {
                        error!("Failed to start RPC server: {}", e);
                    }
                }
            });

            // Store the task handle
            self.rpc_task = Some(rpc_task);

            // Give the server a moment to start
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            info!("RPC server task spawned");
        }

        // Start periodic mempool persistence
        let _persistence_handle = self.start_mempool_persistence();
        info!("Started periodic mempool persistence (every 10 minutes)");

        // Start chain sync
        self.network.lock().await.start().await?;

        // Main event loop
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            // Process any pending work
            self.process_events().await?;
        }
    }

    async fn process_events(&self) -> Result<()> {
        // Process new blocks
        let chain = self.chain.read().await;
        let tip_height = chain.get_best_height();
        debug!("Current chain height: {}", tip_height);

        // Process mempool
        let mempool = self.mempool.read().await;
        let tx_count = mempool.size();
        debug!("Mempool size: {} transactions", tx_count);

        Ok(())
    }

    /// Start periodic mempool persistence
    pub fn start_mempool_persistence(&self) -> tokio::task::JoinHandle<()> {
        let config_datadir = self.config.datadir.clone();
        let config_network = self.config.network.clone();
        let mempool = self.mempool.clone();
        let chain = self.chain.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600)); // Every 10 minutes

            loop {
                interval.tick().await;

                // Perform mempool snapshot
                if let Err(e) =
                    save_mempool_snapshot(&config_datadir, &config_network, &mempool, &chain).await
                {
                    warn!("Failed to save mempool snapshot: {}", e);
                } else {
                    debug!("Mempool snapshot saved successfully");
                }
            }
        })
    }

    /// Discover peers via DNS seeds
    async fn discover_peers_via_dns(&self) -> Result<()> {
        // DNS discovery is now handled by NetworkManager's discovery module
        // The NetworkManager will automatically discover and connect to peers
        info!("Peer discovery handled by NetworkManager");
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down node components");

        // Stop RPC task if running
        if let Some(task) = self.rpc_task.take() {
            info!("Stopping RPC server task");
            task.abort();
        }

        // RPC handle is no longer used (handled by task)

        // Save mempool before shutdown
        if let Err(e) = self.save_mempool().await {
            warn!("Failed to save mempool: {}", e);
        }

        // Stop network manager
        self.network.lock().await.shutdown().await?;

        // Flush chain state
        let mut chain = self.chain.write().await;
        chain.flush().await?;

        // Flush mempool
        let mut mempool = self.mempool.write().await;
        mempool.flush().await?;

        // Close storage
        self.storage.close().await?;

        Ok(())
    }

    /// Save mempool to disk
    async fn save_mempool(&self) -> Result<()> {
        use mempool::mempool_persistence::MempoolPersistence;

        info!("Saving mempool to disk");

        let persistence = MempoolPersistence::new(&self.config.datadir);
        let mempool = self.mempool.read().await;

        // Get all transactions from mempool
        let mut transactions = HashMap::new();
        for txid in mempool.get_transaction_ids() {
            if let Some(tx) = mempool.get_transaction(&txid) {
                // Create a simplified entry for persistence
                let entry = mempool::mempool_acceptance::MempoolEntry {
                    tx: tx.clone(),
                    txid,
                    wtxid: tx.compute_txid(), // MempoolEntry expects Txid type for wtxid
                    fee: 1000,                // Would get from mempool entry
                    vsize: tx.vsize(),
                    weight: tx.weight().to_wu() as usize,
                    fee_rate: 4.0,
                    time: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    height: self.chain.read().await.get_best_height(),
                    ancestors: HashSet::new(),
                    descendants: HashSet::new(),
                    rbf: false,
                };
                transactions.insert(txid, (tx, entry));
            }
        }

        persistence
            .save_mempool(&transactions, &self.config.network)
            .await?;
        info!("Saved {} transactions to mempool.json", transactions.len());

        Ok(())
    }

    /// Load mempool from disk
    async fn load_mempool(&self) -> Result<()> {
        use mempool::mempool_persistence::MempoolPersistence;

        info!("Loading mempool from disk");

        let persistence = MempoolPersistence::new(&self.config.datadir);
        let entries = persistence
            .load_mempool(
                &self.config.network,
                86400, // Max age: 24 hours
            )
            .await?;

        if entries.is_empty() {
            info!("No mempool transactions to load");
            return Ok(());
        }

        let mut mempool = self.mempool.write().await;
        let mut loaded = 0;

        for (tx, _entry) in entries {
            match mempool.add_transaction(tx).await {
                Ok(_) => loaded += 1,
                Err(e) => debug!("Failed to load transaction: {}", e),
            }
        }

        info!("Loaded {} transactions from mempool.json", loaded);
        Ok(())
    }
}
