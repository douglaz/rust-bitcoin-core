use anyhow::{Context, Result};
use bitcoin::{Block, BlockHash, Transaction};
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

use bitcoin_core_lib::{
    chain::ChainManager,
    database::{ChainState as DbChainState, CoreDatabase},
    validation::BlockValidator,
};
use mempool::Mempool;
use network::NetworkManager;
use storage::ChainState;

/// Main node runner that coordinates all components
pub struct NodeRunner {
    // Core components
    chain: Arc<RwLock<ChainManager>>,
    database: Arc<CoreDatabase>,
    mempool: Arc<RwLock<Mempool>>,
    network: Arc<tokio::sync::Mutex<NetworkManager>>,
    validator: Arc<BlockValidator>,

    // State
    chain_state: Arc<RwLock<ChainState>>,
    is_syncing: Arc<RwLock<bool>>,

    // Channels
    block_sender: mpsc::Sender<(Block, BlockHash)>,
    tx_sender: mpsc::Sender<Transaction>,
    shutdown_sender: mpsc::Sender<()>,
}

impl NodeRunner {
    /// Create a new node runner
    pub async fn new(
        datadir: &str,
        network_str: String,
    ) -> Result<(
        Self,
        mpsc::Receiver<(Block, BlockHash)>,
        mpsc::Receiver<Transaction>,
        mpsc::Receiver<()>,
    )> {
        info!("Initializing node runner for network: {}", network_str);

        // Open database
        let db_path = std::path::Path::new(datadir).join("chaindb");
        let database = Arc::new(CoreDatabase::open(&db_path)?);

        // Initialize storage for chain state
        let storage = Arc::new(storage::StorageManager::new(datadir).await?);
        let db_path = std::path::Path::new(datadir).join("chain_state");
        let db = sled::open(&db_path)?;
        let chain_state = Arc::new(RwLock::new(ChainState::new(Arc::new(db))));

        // Initialize chain manager - need both wrapped and unwrapped versions
        let chain_unwrapped =
            Arc::new(ChainManager::new(storage.clone(), network_str.clone()).await?);
        let chain = Arc::new(RwLock::new(
            ChainManager::new(storage.clone(), network_str.clone()).await?,
        ));

        // Initialize UTXO manager and mempool
        let utxo_manager = Arc::new(bitcoin_core_lib::utxo_manager::UtxoManager::new());
        let mempool = Arc::new(RwLock::new(
            Mempool::new(chain.clone(), utxo_manager).await?,
        ));

        // Initialize network manager
        let bind_addr = match network_str.as_str() {
            "mainnet" => "0.0.0.0:8333",
            "testnet" => "0.0.0.0:18333",
            "regtest" => "0.0.0.0:18444",
            _ => "0.0.0.0:8333",
        };

        let bitcoin_network = match network_str.as_str() {
            "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
            "testnet" => bitcoin::Network::Testnet,
            "regtest" => bitcoin::Network::Regtest,
            "signet" => bitcoin::Network::Signet,
            _ => anyhow::bail!("Unknown network: {}", network_str),
        };

        // Get actual best height from chain
        let best_height = chain.read().await.get_best_height();

        let network_mgr =
            NetworkManager::new(bitcoin_network, chain_unwrapped.clone(), best_height);
        // NetworkManager doesn't have set_mempool method
        let network = Arc::new(tokio::sync::Mutex::new(network_mgr));

        // Initialize validator with default parameters
        let consensus_params = bitcoin_core_lib::ConsensusParams::for_network(&network_str)?;
        let script_flags = bitcoin_core_lib::ScriptFlags::all();
        let tx_validator = Arc::new(bitcoin_core_lib::TxValidationPipeline::new(script_flags));
        let utxo_db_path = std::path::Path::new(datadir).join("utxo_db");
        let utxo_db = Arc::new(sled::open(&utxo_db_path)?);
        let utxo_set = Arc::new(RwLock::new(storage::utxo::UtxoSet::new(utxo_db)));
        let validator = Arc::new(BlockValidator::new(
            consensus_params,
            tx_validator,
            utxo_set,
        ));

        // Create channels
        let (block_sender, block_receiver) = mpsc::channel(100);
        let (tx_sender, tx_receiver) = mpsc::channel(1000);
        let (shutdown_sender, shutdown) = mpsc::channel(1);

        Ok((
            Self {
                chain,
                database,
                mempool,
                network,
                validator,
                chain_state,
                is_syncing: Arc::new(RwLock::new(false)),
                block_sender,
                tx_sender,
                shutdown_sender,
            },
            block_receiver,
            tx_receiver,
            shutdown,
        ))
    }

    /// Get block sender channel for external components
    pub fn get_block_sender(&self) -> mpsc::Sender<(Block, BlockHash)> {
        self.block_sender.clone()
    }

    /// Get transaction sender channel
    pub fn get_tx_sender(&self) -> mpsc::Sender<Transaction> {
        self.tx_sender.clone()
    }

    /// Get shutdown sender
    pub fn get_shutdown_sender(&self) -> mpsc::Sender<()> {
        self.shutdown_sender.clone()
    }

    /// Main run loop
    pub async fn run(
        mut self,
        block_receiver: mpsc::Receiver<(Block, BlockHash)>,
        tx_receiver: mpsc::Receiver<Transaction>,
        mut shutdown: mpsc::Receiver<()>,
    ) -> Result<()> {
        info!("Starting node runner main loop");

        // Load chain state from database
        self.load_chain_state().await?;

        // Start network
        self.network.lock().await.start().await?;

        // Start component tasks
        let sync_handle = self.start_sync_task();
        let block_handle = self.start_block_processor(block_receiver);
        let tx_handle = self.start_tx_processor(tx_receiver);
        let peer_handle = self.start_peer_manager();
        let mempool_handle = self.start_mempool_manager();

        // Wait for shutdown signal
        shutdown.recv().await;
        info!("Shutdown signal received, stopping node runner");

        // Cancel all tasks
        sync_handle.abort();
        block_handle.abort();
        tx_handle.abort();
        peer_handle.abort();
        mempool_handle.abort();

        // Save chain state
        self.save_chain_state().await?;

        Ok(())
    }

    /// Load chain state from database
    async fn load_chain_state(&self) -> Result<()> {
        if let Some(db_state) = self.database.load_chain_state()? {
            info!(
                "Loaded chain state: height={}, tip={}",
                db_state.tip_height, db_state.tip_hash
            );

            // Update chain manager with saved state
            let chain = self.chain.write().await;

            // Restore chain to saved state by setting the tip
            // Note: In a full implementation, would verify blocks up to this height
            if db_state.tip_height > 0 {
                info!("Restoring chain to height {}", db_state.tip_height);
                // The chain manager would need a method to restore state
                // For now, we ensure the chain knows its height
            }

            let mut state = self.chain_state.write().await;
            state.set_height(db_state.tip_height);
        } else {
            info!("No saved chain state, starting from genesis");
        }

        Ok(())
    }

    /// Save chain state to database
    async fn save_chain_state(&self) -> Result<()> {
        let chain = self.chain.read().await;
        let state = self.chain_state.read().await;

        // Get the actual chain tip from the chain manager
        let tip_hash = chain.get_best_block_hash();
        let tip_height = chain.get_best_height();

        // Calculate total chain work (simplified - would sum all block difficulties)
        let total_work = [0u8; 32]; // In production, would calculate actual cumulative work

        let db_state = DbChainState {
            tip_hash,
            tip_height,
            total_work,
            utxo_count: self.database.count_utxos()?,
        };

        self.database.save_chain_state(&db_state)?;
        info!("Saved chain state: height={}", db_state.tip_height);

        Ok(())
    }

    /// Start synchronization task
    fn start_sync_task(&self) -> tokio::task::JoinHandle<()> {
        let is_syncing = self.is_syncing.clone();
        let network = self.network.clone();
        let chain = self.chain.clone();
        let chain_state = self.chain_state.clone();

        tokio::spawn(async move {
            info!("Starting blockchain synchronization");

            loop {
                // Check if we're already syncing
                if *is_syncing.read().await {
                    sleep(Duration::from_secs(10)).await;
                    continue;
                }

                // Get our chain height
                let our_height = chain_state.read().await.height();

                // Get peer heights
                let peer_count = network.lock().await.peer_count().await;
                if peer_count == 0 {
                    debug!("No peers connected, waiting...");
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }

                // Get best peer height
                let (best_peer_addr, best_peer_height) = {
                    let net = network.lock().await;
                    // Get peer heights from network manager
                    let peer_heights = net.get_peer_heights().await;
                    peer_heights
                        .into_iter()
                        .max_by_key(|(_, h)| *h)
                        .unwrap_or((std::net::SocketAddr::from(([127, 0, 0, 1], 8333)), 0))
                };

                if best_peer_height > our_height as i32 {
                    info!(
                        "Behind by {} blocks, starting sync",
                        (best_peer_height - our_height as i32).abs()
                    );
                    *is_syncing.write().await = true;

                    // Implement headers-first sync
                    let net = network.lock().await;

                    // Step 1: Request headers from best peer
                    let our_best = chain.read().await.get_best_block_hash();
                    use bitcoin::hashes::Hash;
                    let stop_hash = BlockHash::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]),
                    );
                    if let Err(e) = net
                        .send_getheaders_to_peer(best_peer_addr, vec![our_best], stop_hash)
                        .await
                    {
                        error!("Failed to request headers from {}: {}", best_peer_addr, e);
                    }

                    // Step 2: Headers will be processed via block handler
                    // Step 3: Blocks will be requested automatically after header validation

                    *is_syncing.write().await = false;
                }

                sleep(Duration::from_secs(30)).await;
            }
        })
    }

    /// Start block processor task
    fn start_block_processor(
        &mut self,
        mut receiver: mpsc::Receiver<(Block, BlockHash)>,
    ) -> tokio::task::JoinHandle<()> {
        let chain = self.chain.clone();
        let database = self.database.clone();
        let validator = self.validator.clone();
        let mempool = self.mempool.clone();
        let chain_state = self.chain_state.clone();

        tokio::spawn(async move {
            info!("Starting block processor");

            while let Some((block, hash)) = receiver.recv().await {
                debug!("Processing block: {}", hash);

                // Get current height
                let height = chain_state.read().await.height() + 1;

                // Validate block
                let prev_header = if height > 0 {
                    chain
                        .read()
                        .await
                        .get_block_header(&block.header.prev_blockhash)
                } else {
                    None
                };

                if prev_header.is_some() {
                    // Perform full validation
                    match validator.validate_block(&block, height, None).await {
                        Ok(bitcoin_core_lib::ValidationResult::Valid) => {
                            debug!("Block {} validation passed", hash);
                        }
                        Ok(bitcoin_core_lib::ValidationResult::Invalid(reason)) => {
                            error!("Block {} rejected: {}", hash, reason);
                            continue;
                        }
                        Ok(bitcoin_core_lib::ValidationResult::Unknown) => {
                            warn!("Block {} validation unknown, accepting", hash);
                        }
                        Err(e) => {
                            error!("Block {} validation error: {}", hash, e);
                            continue;
                        }
                    }
                }

                // Store block in database
                if let Err(e) = database.put_block(&hash, &block, height) {
                    error!("Failed to store block {}: {}", hash, e);
                    continue;
                }

                // Update UTXOs
                let mut utxos_to_add = Vec::new();
                let mut utxos_to_remove = Vec::new();

                // Remove spent UTXOs (inputs)
                for tx in &block.txdata {
                    if !tx.is_coinbase() {
                        for input in &tx.input {
                            utxos_to_remove.push(input.previous_output);
                        }
                    }
                }

                // Add new UTXOs (outputs)
                for (tx_index, tx) in block.txdata.iter().enumerate() {
                    let txid = tx.compute_txid();
                    for (vout, output) in tx.output.iter().enumerate() {
                        let entry = bitcoin_core_lib::database::UtxoEntry {
                            outpoint: bitcoin::OutPoint {
                                txid,
                                vout: vout as u32,
                            },
                            output: output.clone(),
                            height,
                            is_coinbase: tx.is_coinbase(),
                        };
                        utxos_to_add.push(entry);
                    }
                }

                // Update database
                if let Err(e) = database.update_utxos(utxos_to_add, utxos_to_remove) {
                    error!("Failed to update UTXOs for block {}: {}", hash, e);
                    continue;
                }

                // Remove transactions from mempool
                let mut mempool = mempool.write().await;
                for tx in &block.txdata {
                    let _ = mempool.remove_transaction(&tx.compute_txid()).await;
                }

                // Update chain state
                let mut state = chain_state.write().await;
                state.set_height(height);

                info!("Processed block {} at height {}", hash, height);
            }
        })
    }

    /// Start transaction processor task
    fn start_tx_processor(
        &mut self,
        mut receiver: mpsc::Receiver<Transaction>,
    ) -> tokio::task::JoinHandle<()> {
        let mempool = self.mempool.clone();
        let network = self.network.clone();

        tokio::spawn(async move {
            info!("Starting transaction processor");

            while let Some(tx) = receiver.recv().await {
                let txid = tx.compute_txid();
                debug!("Processing transaction: {}", txid);

                // Add to mempool
                let mut mempool = mempool.write().await;
                match mempool.add_transaction(tx.clone()).await {
                    Ok(_) => {
                        info!("Added transaction {} to mempool", txid);

                        // Relay to peers
                        if let Err(e) = network.lock().await.broadcast_transaction(&tx).await {
                            warn!("Failed to broadcast transaction {}: {}", txid, e);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to add transaction {} to mempool: {}", txid, e);
                    }
                }
            }
        })
    }

    /// Start peer manager task
    fn start_peer_manager(&self) -> tokio::task::JoinHandle<()> {
        let network = self.network.clone();

        tokio::spawn(async move {
            info!("Starting peer manager");
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let peer_count = network.lock().await.peer_count().await;
                debug!("Connected peers: {}", peer_count);

                // Try to maintain at least 8 connections
                if peer_count < 8 {
                    info!("Low peer count ({}), discovering new peers", peer_count);

                    // Trigger peer discovery via DNS seeds
                    let mut net = network.lock().await;
                    if let Err(e) = net.discover_and_connect_peers(8 - peer_count).await {
                        warn!("Failed to discover new peers: {}", e);
                    }
                }

                // Ping peers to check they're alive
                let net = network.lock().await;
                let peers = net.get_connected_peers().await;
                for peer_addr in peers {
                    // Send ping message to each peer
                    let nonce = rand::thread_rng().gen::<u64>();
                    if let Err(e) = net.send_ping_to_peer(&peer_addr, nonce).await {
                        debug!("Failed to ping peer {}: {}", peer_addr, e);
                    }
                }

                // Ban misbehaving peers (handled by DoS protection manager)
                // The DoS protection manager automatically bans peers that:
                // - Send invalid blocks
                // - Violate protocol rules
                // - Exceed rate limits
                // - Have a ban score below -100
                if let Some(dos_manager) = net.dos_protection_manager() {
                    // Clean up expired bans
                    if let Err(e) = dos_manager.cleanup_expired_bans().await {
                        debug!("Failed to cleanup expired bans: {}", e);
                    }
                }
            }
        })
    }

    /// Start mempool manager task
    fn start_mempool_manager(&self) -> tokio::task::JoinHandle<()> {
        let mempool = self.mempool.clone();
        let database = self.database.clone();

        tokio::spawn(async move {
            info!("Starting mempool manager");

            // Create expiration manager
            let mut expiration = mempool::expiration::MempoolExpiration::new(
                mempool::expiration::ExpirationPolicy::default(),
            );

            let mut interval = interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                let mut mempool = mempool.write().await;
                let count = mempool.size();
                let size = count * 250; // Estimate bytes

                debug!("Mempool: {} transactions, {} bytes", count, size);

                // Sync expiration tracker with mempool entries
                let tx_ids = mempool.get_transaction_ids();
                for txid in tx_ids {
                    if let Some(tx) = mempool.get_transaction(&txid) {
                        if let Some(entry) = mempool.get_entry(&txid) {
                            // Add transaction to expiration tracking
                            let fee = bitcoin::Amount::from_sat(entry.fee);
                            expiration.add_transaction(txid, &tx, fee, Some(entry.time));
                        }
                    }
                }

                // Run maintenance (expire old and evict if needed)
                let result = expiration.run_maintenance();

                // Remove expired transactions from mempool
                for txid in &result.expired_txids {
                    match mempool.remove_transaction(txid).await {
                        Ok(Some(_entry)) => {
                            info!("Expired transaction {} from mempool", txid);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!("Error removing expired transaction {}: {}", txid, e);
                        }
                    }
                }

                // Remove evicted transactions from mempool
                for txid in &result.evicted_txids {
                    match mempool.remove_transaction(txid).await {
                        Ok(Some(_entry)) => {
                            info!("Evicted transaction {} from mempool", txid);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!("Error removing evicted transaction {}: {}", txid, e);
                        }
                    }
                }

                // Log statistics
                if !result.expired_txids.is_empty() || !result.evicted_txids.is_empty() {
                    info!(
                        "Mempool maintenance complete: {} expired, {} evicted, {} remaining",
                        result.expired_txids.len(),
                        result.evicted_txids.len(),
                        mempool.size()
                    );
                }

                // Save mempool to disk every 10 minutes
                static mut SAVE_COUNTER: u32 = 0;
                unsafe {
                    SAVE_COUNTER += 1;
                    if SAVE_COUNTER >= 10 {
                        SAVE_COUNTER = 0;

                        // Get all transactions for persistence
                        let tx_ids = mempool.get_transaction_ids();
                        let mut txs: Vec<Transaction> = Vec::new();
                        for txid in tx_ids {
                            if let Some(tx) = mempool.get_transaction(&txid) {
                                txs.push(tx);
                            }
                        }

                        // Save mempool to disk (using mempool's built-in persistence)
                        if let Err(e) = mempool.save_to_disk().await {
                            warn!("Failed to persist mempool: {}", e);
                        } else {
                            info!("Persisted {} transactions to mempool.dat", txs.len());
                        }
                    }
                }
            }
        })
    }
}

/// Helper to handle channel errors
impl NodeRunner {
    pub async fn submit_block(&self, block: Block) -> Result<()> {
        let hash = block.block_hash();
        self.block_sender
            .send((block, hash))
            .await
            .context("Failed to submit block to processor")?;
        Ok(())
    }

    pub async fn submit_transaction(&self, tx: Transaction) -> Result<()> {
        self.tx_sender
            .send(tx)
            .await
            .context("Failed to submit transaction to processor")?;
        Ok(())
    }
}
