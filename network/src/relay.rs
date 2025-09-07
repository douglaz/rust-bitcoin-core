use crate::message::{InvType, Inventory, Message};
use crate::orphan_pool::{OrphanPool, OrphanPoolStats};
use crate::peer::Peer;
use crate::tx_relay::TxRequestTracker;
use anyhow::Result;
use bitcoin::{Block, BlockHash, Transaction, Txid};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// Relay statistics
#[derive(Debug, Clone, Default)]
pub struct RelayStats {
    pub blocks_relayed: usize,
    pub transactions_relayed: usize,
    pub orphans_processed: usize,
    pub duplicate_requests_avoided: usize,
}

/// Manages block and transaction relay
pub struct RelayManager {
    stats: Arc<RwLock<RelayStats>>,
    seen_blocks: Arc<RwLock<HashSet<BlockHash>>>,
    seen_txs: Arc<RwLock<HashSet<Txid>>>,
    peers: Arc<RwLock<HashMap<SocketAddr, Arc<Peer>>>>,
    tx_tracker: Arc<Mutex<TxRequestTracker>>,
    orphan_pool: Arc<Mutex<OrphanPool>>,
}

impl Default for RelayManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayManager {
    /// Create new relay manager
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(RelayStats::default())),
            seen_blocks: Arc::new(RwLock::new(HashSet::new())),
            seen_txs: Arc::new(RwLock::new(HashSet::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            tx_tracker: Arc::new(Mutex::new(TxRequestTracker::new())),
            orphan_pool: Arc::new(Mutex::new(OrphanPool::new())),
        }
    }

    /// Get statistics
    pub async fn stats(&self) -> RelayStats {
        self.stats.read().await.clone()
    }

    /// Check if we've seen a block
    pub async fn has_block(&self, hash: &BlockHash) -> bool {
        self.seen_blocks.read().await.contains(hash)
    }

    /// Check if we've seen a transaction
    pub async fn has_transaction(&self, txid: &Txid) -> bool {
        self.seen_txs.read().await.contains(txid)
    }

    /// Mark block as seen
    pub async fn mark_block_seen(&self, hash: BlockHash) {
        self.seen_blocks.write().await.insert(hash);
    }

    /// Mark transaction as seen
    pub async fn mark_transaction_seen(&self, txid: Txid) {
        self.seen_txs.write().await.insert(txid);
    }

    /// Add a peer for relaying
    pub async fn add_peer(&self, addr: SocketAddr, peer: Arc<Peer>) {
        self.peers.write().await.insert(addr, peer);
        info!("Added peer {} for relay", addr);
    }

    /// Remove a peer from relay
    pub async fn remove_peer(&self, addr: &SocketAddr) {
        self.peers.write().await.remove(addr);
        info!("Removed peer {} from relay", addr);
    }

    /// Relay a block
    pub async fn relay_block(&self, block: &Block) -> Result<()> {
        let hash = block.block_hash();

        if self.has_block(&hash).await {
            debug!("Block {} already seen, not relaying", hash);
            return Ok(());
        }

        self.mark_block_seen(hash).await;

        let mut stats = self.stats.write().await;
        stats.blocks_relayed += 1;
        drop(stats);

        info!("Relaying block {} to peers", hash);

        // Send INV message to all connected peers
        let inv = Message::Inv(vec![Inventory {
            inv_type: InvType::Block,
            hash,
        }]);

        let peers = self.peers.read().await;
        let mut relay_count = 0;

        for (addr, peer) in peers.iter() {
            if let Err(e) = peer.send_message(inv.clone()).await {
                warn!("Failed to relay block to {}: {}", addr, e);
            } else {
                relay_count += 1;
                debug!("Sent block INV to {}", addr);
            }
        }

        info!("Relayed block {} to {} peers", hash, relay_count);

        Ok(())
    }

    /// Relay a transaction
    pub async fn relay_transaction(&self, tx: &Transaction) -> Result<()> {
        let txid = tx.compute_txid();

        if self.has_transaction(&txid).await {
            debug!("Transaction {} already seen, not relaying", txid);
            return Ok(());
        }

        self.mark_transaction_seen(txid).await;

        let mut stats = self.stats.write().await;
        stats.transactions_relayed += 1;
        drop(stats);

        info!("Relaying transaction {} to peers", txid);

        // Send INV message to all connected peers
        let inv = Message::Inv(vec![Inventory {
            inv_type: InvType::Tx,
            hash: BlockHash::from_raw_hash(txid.to_raw_hash()),
        }]);

        let peers = self.peers.read().await;
        let mut relay_count = 0;

        for (addr, peer) in peers.iter() {
            if let Err(e) = peer.send_message(inv.clone()).await {
                warn!("Failed to relay transaction to {}: {}", addr, e);
            } else {
                relay_count += 1;
                debug!("Sent transaction INV to {}", addr);
            }
        }

        info!("Relayed transaction {} to {} peers", txid, relay_count);

        Ok(())
    }

    /// Handle GETDATA request from a peer
    pub async fn handle_getdata(
        &self,
        peer_addr: &SocketAddr,
        inventory: Vec<Inventory>,
        blocks: Arc<RwLock<HashMap<BlockHash, Block>>>,
        txs: Arc<RwLock<HashMap<Txid, Transaction>>>,
    ) -> Result<()> {
        let peers = self.peers.read().await;
        let peer = peers
            .get(peer_addr)
            .ok_or_else(|| anyhow::anyhow!("Peer {} not found", peer_addr))?;

        for inv in inventory {
            match inv.inv_type {
                InvType::Block | InvType::WitnessBlock => {
                    let hash = inv.hash;
                    if let Some(block) = blocks.read().await.get(&hash) {
                        let msg = Message::Block(block.clone());
                        if let Err(e) = peer.send_message(msg).await {
                            warn!("Failed to send block to {}: {}", peer_addr, e);
                        } else {
                            debug!("Sent block {} to {}", hash, peer_addr);
                        }
                    }
                }
                InvType::Tx | InvType::WitnessTx => {
                    let txid = Txid::from_raw_hash(inv.hash.to_raw_hash());
                    if let Some(tx) = txs.read().await.get(&txid) {
                        let msg = Message::Tx(tx.clone());
                        if let Err(e) = peer.send_message(msg).await {
                            warn!("Failed to send transaction to {}: {}", peer_addr, e);
                        } else {
                            debug!("Sent transaction {} to {}", txid, peer_addr);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Handle transaction announcement from a peer
    pub async fn handle_tx_announcement(&self, txid: Txid, peer_addr: SocketAddr) -> Result<bool> {
        let mut tracker = self.tx_tracker.lock().await;
        let should_request = tracker.on_tx_announcement(txid, peer_addr)?;

        if !should_request {
            let mut stats = self.stats.write().await;
            stats.duplicate_requests_avoided += 1;
        }

        Ok(should_request)
    }

    /// Get next transaction to request
    pub async fn get_next_tx_request(&self) -> Option<(Txid, SocketAddr)> {
        let mut tracker = self.tx_tracker.lock().await;
        tracker.get_next_request()
    }

    /// Mark transaction as requested
    pub async fn mark_tx_requested(&self, txid: Txid, peer_addr: SocketAddr) -> Result<()> {
        let mut tracker = self.tx_tracker.lock().await;
        tracker.mark_requested(txid, peer_addr)
    }

    /// Handle received transaction
    pub async fn on_tx_received(&self, tx: &Transaction, from_peer: SocketAddr) -> Result<()> {
        let txid = tx.compute_txid();

        // Update tracker
        let mut tracker = self.tx_tracker.lock().await;
        tracker.on_tx_received(txid, from_peer);
        drop(tracker);

        // Check if any orphans were waiting for this transaction
        let mut orphan_pool = self.orphan_pool.lock().await;
        let orphans_to_process = orphan_pool.remove_orphans_for_parent(&txid);

        if !orphans_to_process.is_empty() {
            info!(
                "Processing {} orphans after parent {} arrived",
                orphans_to_process.len(),
                txid
            );
            let mut stats = self.stats.write().await;
            stats.orphans_processed += orphans_to_process.len();
        }

        Ok(())
    }

    /// Add orphan transaction
    pub async fn add_orphan(
        &self,
        tx: Transaction,
        from_peer: SocketAddr,
        missing_parents: HashSet<Txid>,
    ) -> Result<bool> {
        let mut orphan_pool = self.orphan_pool.lock().await;
        orphan_pool.add_orphan(tx, from_peer, missing_parents)
    }

    /// Process orphans periodically
    pub async fn process_orphans(&self) -> (Vec<Txid>, Vec<Txid>) {
        let mut orphan_pool = self.orphan_pool.lock().await;
        orphan_pool.process_orphans()
    }

    /// Get orphan pool statistics
    pub async fn get_orphan_stats(&self) -> OrphanPoolStats {
        let orphan_pool = self.orphan_pool.lock().await;
        orphan_pool.get_stats()
    }

    /// Clear orphans from disconnected peer
    pub async fn clear_peer_orphans(&self, peer_addr: &SocketAddr) -> usize {
        let mut orphan_pool = self.orphan_pool.lock().await;
        orphan_pool.clear_peer_orphans(peer_addr)
    }

    /// Get transaction relay statistics
    pub async fn get_tx_relay_stats(&self) -> crate::tx_relay::TxRelayStats {
        let tracker = self.tx_tracker.lock().await;
        tracker.get_stats()
    }

    /// Check if we should request a transaction
    pub async fn should_request_tx(&self, txid: &Txid) -> bool {
        let tracker = self.tx_tracker.lock().await;
        tracker.should_request_tx(txid)
    }
}
