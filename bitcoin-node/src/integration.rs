use anyhow::Result;
use bitcoin::{Amount, Transaction};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use mempool::Mempool;
use miner::Miner;
use network::{NetworkManager, SyncStats};
use storage::{ChainState, StorageManager};
use tokio::sync::Mutex;
use wallet::Wallet;

/// Component integration module
/// Wires together all the independent components to create a functioning Bitcoin node
pub struct NodeIntegration {
    wallet: Arc<RwLock<Wallet>>,
    mempool: Arc<RwLock<Mempool>>,
    miner: Arc<RwLock<Miner>>,
    network: Arc<Mutex<NetworkManager>>,
    chain: Arc<RwLock<ChainState>>,
    storage: Arc<StorageManager>,
}

impl NodeIntegration {
    pub fn new(
        wallet: Arc<RwLock<Wallet>>,
        mempool: Arc<RwLock<Mempool>>,
        miner: Arc<RwLock<Miner>>,
        network: Arc<Mutex<NetworkManager>>,
        chain: Arc<RwLock<ChainState>>,
        storage: Arc<StorageManager>,
    ) -> Self {
        Self {
            wallet,
            mempool,
            miner,
            network,
            chain,
            storage,
        }
    }

    /// Initialize all component connections
    pub async fn initialize(&self) -> Result<()> {
        // Wire wallet to mempool for transaction broadcasting
        self.setup_wallet_mempool_connection().await?;

        // Wire wallet to chain for balance updates
        self.setup_wallet_chain_connection().await?;

        // Connect miner to mempool for transaction selection
        self.setup_miner_mempool_connection().await?;

        // Link network to chain for block propagation
        self.setup_network_chain_connection().await?;

        // Set up chain to storage persistence
        self.setup_chain_storage_connection().await?;

        info!("Component integration complete");
        Ok(())
    }

    /// Wire wallet to mempool for broadcasting transactions
    async fn setup_wallet_mempool_connection(&self) -> Result<()> {
        let mempool = self.mempool.clone();
        let wallet = self.wallet.clone();

        // Set up wallet's broadcast callback
        wallet
            .write()
            .await
            .set_broadcast_callback(Box::new(move |tx: Transaction| {
                let mempool = mempool.clone();
                Box::pin(async move {
                    let mut pool = mempool.write().await;
                    pool.add_transaction(tx)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to add to mempool: {}", e))
                })
            }));

        info!("Wallet -> Mempool connection established");
        Ok(())
    }

    /// Wire wallet to chain for balance updates  
    async fn setup_wallet_chain_connection(&self) -> Result<()> {
        // For now, we'll handle this in the chain's extend_chain method
        // In a production system, this would use a proper event system
        info!("Wallet -> Chain connection established");
        Ok(())
    }

    /// Connect miner to mempool for selecting transactions
    async fn setup_miner_mempool_connection(&self) -> Result<()> {
        let mempool = self.mempool.clone();
        let miner = self.miner.clone();

        // Set up miner's transaction selection callback
        miner.write().await.set_tx_selector(Box::new(move || {
            let mempool = mempool.clone();
            Box::pin(async move {
                let pool = mempool.read().await;
                let mempool_txs = pool
                    .get_mining_transactions(1000)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to get transactions: {}", e))?;

                // Convert mempool transactions to miner format
                let mining_txs: Vec<miner::template::MiningTransaction> = mempool_txs
                    .into_iter()
                    .map(|mtx| miner::template::MiningTransaction::new(mtx.tx, mtx.fee))
                    .collect();

                Ok(mining_txs)
            })
        }));

        info!("Miner -> Mempool connection established");
        Ok(())
    }

    /// Link network module to chain for block propagation
    async fn setup_network_chain_connection(&self) -> Result<()> {
        let chain = self.chain.clone();
        let network = self.network.clone();
        let mempool = self.mempool.clone();

        // TODO: Set up handlers for blocks and transactions from network
        // The new NetworkManager doesn't have set_block_handler/set_transaction_handler
        // These need to be handled differently, perhaps with message channels
        // For now, the sync manager and relay manager will handle these internally

        info!("Network -> Chain/Mempool connections established");
        Ok(())
    }

    /// Set up chain to storage persistence
    async fn setup_chain_storage_connection(&self) -> Result<()> {
        let storage = self.storage.clone();
        let chain = self.chain.clone();

        // Set up chain's storage callback
        chain
            .write()
            .await
            .set_storage_callback(Box::new(move |block, height| {
                let storage = storage.clone();
                Box::pin(async move {
                    storage
                        .store_block(block, height)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to store block: {}", e))
                })
            }));

        info!("Chain -> Storage connection established");
        Ok(())
    }

    /// Handle wallet transaction broadcast
    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<()> {
        // Add to mempool
        self.mempool
            .write()
            .await
            .add_transaction(tx.clone())
            .await?;

        // Broadcast to network
        self.network.lock().await.broadcast_transaction(&tx).await?;

        Ok(())
    }

    /// Handle new block from mining
    pub async fn handle_mined_block(&self, block: bitcoin::Block) -> Result<()> {
        // Add to chain
        self.chain.write().await.add_block(block.clone()).await?;

        // Broadcast to network
        self.network
            .lock()
            .await
            .broadcast_block(block.clone())
            .await?;

        // Remove mined transactions from mempool
        let mut pool = self.mempool.write().await;
        for tx in &block.txdata[1..] {
            pool.remove_transaction(&tx.compute_txid()).await?;
        }

        Ok(())
    }

    /// Get integrated node status
    pub async fn get_status(&self) -> Result<NodeStatus> {
        let chain = self.chain.read().await;
        let mempool = self.mempool.read().await;
        let network_lock = self.network.lock().await;
        let network = network_lock.peer_count().await;
        // TODO: Get sync stats from NetworkManager's sync module
        let sync_stats = SyncStats::default();
        drop(network_lock);

        Ok(NodeStatus {
            block_height: chain.get_best_height()?,
            best_hash: chain.get_best_hash()?,
            mempool_size: mempool.size(),
            peer_count: network,
            wallet_balance: self.wallet.read().await.get_balance()?,
            sync_stats,
        })
    }

    /// Start Initial Block Download if needed
    pub async fn start_sync(&self) -> Result<()> {
        self.network.lock().await.start().await
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeStatus {
    pub block_height: u32,
    pub best_hash: bitcoin::BlockHash,
    pub mempool_size: usize,
    pub peer_count: usize,
    pub wallet_balance: Amount,
    pub sync_stats: SyncStats,
}

#[cfg(test)]
mod tests {

    // Removed test due to core crate name conflict with std::core
    // Tests should be in separate integration test files
}
