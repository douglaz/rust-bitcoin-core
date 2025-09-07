use anyhow::Result;
use bitcoin::p2p::ServiceFlags;
use bitcoin::{Block, BlockHash, Network, Transaction};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::compact_block_protocol::{CompactBlockConfig, CompactBlockProtocol};
use crate::compact_blocks::CompactBlockRelay;
use crate::discovery::PeerDiscovery;
use crate::dos_protection::{DosProtectionConfig, DosProtectionManager};
use crate::message::{InvType, Inventory, Message, SendCompact};
use crate::peer::Peer;
use crate::peer_manager::{PeerManager, PeerManagerConfig, ScoreEvent};
use crate::relay::RelayManager;
use crate::sync::SyncManager;
use crate::sync_trait::SyncHandler;

/// Network manager coordinates all network operations
#[derive(Clone)]
pub struct NetworkManager {
    /// Network
    network: Network,

    /// Connected peers
    peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,

    /// Peer discovery
    discovery: Arc<PeerDiscovery>,

    /// Sync manager - internal stub
    sync_manager: Arc<SyncManager>,

    /// External sync handler (optional)
    external_sync_handler: Option<Arc<dyn SyncHandler>>,

    /// Relay manager
    relay_manager: Arc<RelayManager>,

    /// Our services
    services: ServiceFlags,

    /// Our best height
    best_height: u32,

    /// Maximum peers
    max_peers: usize,

    /// Mempool reference for transaction relay
    mempool: Option<Arc<RwLock<mempool::pool::Mempool>>>,

    /// Compact block protocol handler
    compact_block_protocol: Option<Arc<CompactBlockProtocol>>,

    /// DoS protection manager
    dos_protection: Arc<DosProtectionManager>,
    
    /// Peer manager for scoring and banning
    peer_manager: Arc<PeerManager>,
}

impl NetworkManager {
    /// Create new network manager
    pub fn new(
        network: Network,
        chain: Arc<bitcoin_core_lib::chain::ChainManager>,
        best_height: u32,
    ) -> Self {
        Self {
            network,
            peers: Arc::new(RwLock::new(HashMap::new())),
            discovery: Arc::new(PeerDiscovery::new(network)),
            sync_manager: Arc::new(SyncManager::new(chain)),
            external_sync_handler: None,
            relay_manager: Arc::new(RelayManager::new()),
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            best_height,
            max_peers: 8,
            mempool: None,
            compact_block_protocol: None,
            dos_protection: Arc::new(DosProtectionManager::new(DosProtectionConfig::default())),
            peer_manager: Arc::new(PeerManager::new(network, PeerManagerConfig::default())),
        }
    }

    /// Set external sync handler
    pub fn set_sync_handler(&mut self, handler: Arc<dyn SyncHandler>) {
        self.external_sync_handler = Some(handler);
    }

    /// Start the network manager
    pub async fn start(&self) -> Result<()> {
        info!("Starting network manager for {:?}", self.network);

        // Try DNS discovery first
        match self.discovery.discover_from_dns().await {
            Ok(peers) => {
                info!("Discovered {} peers via DNS", peers.len());
            }
            Err(e) => {
                warn!("DNS discovery failed: {}, using fallback peers", e);
                // Add fallback peers if DNS fails
                self.discovery.add_fallback_peers().await?;
            }
        }

        // If still no peers, add hardcoded seeds
        if self.discovery.get_peers(1).await.is_empty() {
            let seeds = self.discovery.default_seeds();
            self.discovery.add_seeds(seeds).await?;
        }

        // Connect to initial peers
        self.connect_to_peers().await?;

        // Start maintenance loop
        let manager = self.clone();
        tokio::spawn(async move {
            manager.run_maintenance_loop().await;
        });

        Ok(())
    }

    /// Connect to peers
    async fn connect_to_peers(&self) -> Result<()> {
        let current_count = self.peers.read().await.len();
        if current_count >= self.max_peers {
            return Ok(());
        }

        let needed = self.max_peers - current_count;
        let addresses = self.discovery.get_peers(needed).await;

        for addr in addresses {
            if let Err(e) = self.connect_to_peer(addr).await {
                warn!("Failed to connect to {}: {}", addr, e);
                self.discovery.mark_failed(addr).await;
            } else {
                self.discovery.mark_successful(addr).await;
            }
        }

        Ok(())
    }

    /// Connect to a specific peer
    pub async fn connect_to_peer(&self, addr: SocketAddr) -> Result<()> {
        // Check DoS protection
        if !self.dos_protection.should_allow_connection(&addr).await? {
            warn!("Connection to {} rejected by DoS protection", addr);
            return Ok(());
        }

        info!("Connecting to peer {}", addr);

        let (mut peer, send_rx, recv_rx) =
            Peer::new(addr, self.network, self.services, self.best_height);

        peer.connect().await?;

        // Store peer
        self.peers.write().await.insert(addr, peer.clone());
        
        // Add to peer manager for scoring
        self.peer_manager.add_peer(
            addr,
            Arc::new(peer),
            true, // assuming outbound for now
            self.services,
            self.best_height,
        ).await?;

        // Spawn message handling tasks
        let chain = self.sync_manager.chain();
        let peers_ref = self.peers.clone();
        let relay_mgr = self.relay_manager.clone();
        let mempool_ref = self.mempool.clone();

        // Spawn task to handle incoming messages from this peer
        let sync_mgr = self.sync_manager.clone();
        let external_sync = self.external_sync_handler.clone();
        let compact_protocol = self.compact_block_protocol.clone();
        let peer_mgr = self.peer_manager.clone();
        let discovery = self.discovery.clone();
        tokio::spawn(async move {
            Self::handle_peer_messages(
                addr,
                recv_rx,
                chain,
                peers_ref,
                relay_mgr,
                sync_mgr,
                external_sync,
                mempool_ref,
                compact_protocol,
                peer_mgr,
                discovery,
            )
            .await;
        });

        // Spawn task to handle outgoing messages to this peer
        let peers_ref_outgoing = self.peers.clone();
        tokio::spawn(async move {
            Self::handle_outgoing_messages(addr, send_rx, peers_ref_outgoing).await;
        });

        Ok(())
    }

    /// Run maintenance loop for network operations
    async fn run_maintenance_loop(&self) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        
        loop {
            interval.tick().await;
            
            // Maintain peer connections
            let peer_count = self.peers.read().await.len();
            info!("Network maintenance: {} peers connected", peer_count);
            
            // Try to connect to more peers if needed
            if peer_count < self.max_peers {
                if let Err(e) = self.connect_to_peers().await {
                    warn!("Failed to connect to new peers: {}", e);
                }
            }
            
            // Clean up disconnected peers
            let peers_read = self.peers.read().await;
            let mut disconnected = Vec::new();
            for (addr, peer) in peers_read.iter() {
                if !peer.is_connected().await {
                    disconnected.push(*addr);
                }
            }
            drop(peers_read);
            
            let mut peers = self.peers.write().await;
            
            for addr in disconnected {
                info!("Removing disconnected peer: {}", addr);
                peers.remove(&addr);
                self.dos_protection.unregister_connection(&addr).await;
                self.peer_manager.remove_peer(&addr);
            }
            
            // Periodic DNS discovery if we have few peers
            if peer_count < self.max_peers / 2 {
                info!("Running periodic DNS discovery");
                if let Err(e) = self.discovery.discover_from_dns().await {
                    debug!("Periodic DNS discovery failed: {}", e);
                }
            }
        }
    }

    /// Broadcast a block
    pub async fn broadcast_block(&self, block: Block) -> Result<()> {
        self.relay_manager.relay_block(&block).await?;

        // Send to connected peers
        let peers = self.peers.read().await;
        for (addr, peer) in peers.iter() {
            if peer.is_connected().await {
                if let Err(e) = peer.send_message(Message::Block(block.clone())).await {
                    warn!("Failed to send block to {}: {}", addr, e);
                }
            }
        }

        Ok(())
    }

    /// Get connected peer count
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        let mut count = 0;
        for peer in peers.values() {
            if peer.is_connected().await {
                count += 1;
            }
        }
        count
    }

    /// Shutdown the network manager
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down network manager");

        // Disconnect all peers
        let mut peers = self.peers.write().await;
        for (addr, mut peer) in peers.drain() {
            if let Err(e) = peer.disconnect().await {
                warn!("Error disconnecting from {}: {}", addr, e);
            }
        }

        Ok(())
    }

    /// Set mempool reference for transaction relay
    pub fn set_mempool(&mut self, mempool: Arc<RwLock<mempool::pool::Mempool>>) {
        self.mempool = Some(mempool.clone());

        // Initialize compact block protocol with mempool
        let compact_relay = Arc::new(CompactBlockRelay::new(Some(mempool.clone())));
        let compact_config = CompactBlockConfig::default();
        self.compact_block_protocol = Some(Arc::new(CompactBlockProtocol::new(
            compact_relay,
            compact_config,
        )));

        info!("Mempool connected to network manager for transaction relay");
    }

    /// Broadcast transaction to peers
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<()> {
        let txid = tx.compute_txid();
        info!("Broadcasting transaction {} to peers", txid);

        // Relay through relay manager
        self.relay_manager.relay_transaction(tx).await?;

        // Create inventory message
        let inv = vec![Inventory {
            inv_type: InvType::Tx,
            hash: BlockHash::from_raw_hash(txid.to_raw_hash()),
        }];

        // Send inv to all connected peers
        let peers = self.peers.read().await;
        for (addr, peer) in peers.iter() {
            if peer.is_connected().await {
                if let Err(e) = peer.send_message(Message::Inv(inv.clone())).await {
                    warn!("Failed to send inv to {}: {}", addr, e);
                }
            }
        }

        // Also send the actual transaction
        for (addr, peer) in peers.iter() {
            if peer.is_connected().await {
                if let Err(e) = peer.send_message(Message::Tx(tx.clone())).await {
                    warn!("Failed to send transaction to {}: {}", addr, e);
                }
            }
        }

        Ok(())
    }

    /// Get connection count
    pub fn get_connection_count(&self) -> usize {
        // Count connected peers from the peers map
        // Note: This is a blocking operation, but should be fast
        let peers = futures::executor::block_on(self.peers.read());
        let mut count = 0;
        for (_, peer) in peers.iter() {
            if futures::executor::block_on(peer.is_connected()) {
                count += 1;
            }
        }
        count
    }

    /// Get peer info
    pub fn get_peer_info(&self) -> Vec<serde_json::Value> {
        // Get peer information from the peers map
        let peers = futures::executor::block_on(self.peers.read());
        let mut peer_info = Vec::new();

        for (addr, peer) in peers.iter() {
            if futures::executor::block_on(peer.is_connected()) {
                let stats = futures::executor::block_on(peer.stats());
                let version = futures::executor::block_on(peer.version.read());

                let info = serde_json::json!({
                    "addr": addr.to_string(),
                    "services": "0000000000000000",  // Services info not directly accessible
                    "lastsend": stats.last_message.map(|t| t.elapsed().as_secs()).unwrap_or(0),
                    "lastrecv": stats.last_message.map(|t| t.elapsed().as_secs()).unwrap_or(0),
                    "bytessent": stats.bytes_sent,
                    "bytesrecv": stats.bytes_received,
                    "conntime": stats.connected_at.map(|t| t.elapsed().as_secs()).unwrap_or(0),
                    "pingtime": stats.ping_time.map(|d| d.as_millis()).unwrap_or(0),
                    "version": version.as_ref().map(|v| v.version).unwrap_or(0),
                    "subver": version.as_ref().map(|v| v.user_agent.clone()).unwrap_or_default(),
                    "inbound": false,
                    "startingheight": version.as_ref().map(|v| v.start_height).unwrap_or(0),
                    "relaytxes": true,
                });
                peer_info.push(info);
            }
        }

        peer_info
    }

    /// Get traffic statistics
    pub async fn get_traffic_stats(&self) -> (u64, u64) {
        let peers = self.peers.read().await;
        let mut total_sent = 0u64;
        let mut total_received = 0u64;
        
        for peer in peers.values() {
            let stats = peer.stats().await;
            total_sent += stats.bytes_sent;
            total_received += stats.bytes_received;
        }
        
        (total_sent, total_received)
    }

    /// Add a node
    pub async fn add_node(&self, addr: &str, _command: &str) -> Result<()> {
        if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
            self.connect_to_peer(socket_addr).await?;
        }
        Ok(())
    }

    /// Disconnect a node
    pub async fn disconnect_node(&self, addr: &str) -> Result<()> {
        if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
            let mut peers = self.peers.write().await;
            if let Some(mut peer) = peers.remove(&socket_addr) {
                peer.disconnect().await?;
            }
        }
        Ok(())
    }

    /// Get added nodes
    pub fn get_added_nodes(&self) -> Vec<String> {
        // TODO: Implement actual added nodes tracking
        vec![]
    }

    /// Send getheaders message to a specific peer
    pub async fn send_getheaders_to_peer(
        &self,
        peer_addr: SocketAddr,
        locator_hashes: Vec<BlockHash>,
        stop_hash: BlockHash,
    ) -> Result<()> {
        use bitcoin::p2p::message_blockdata::GetHeadersMessage;

        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(&peer_addr) {
            let getheaders = GetHeadersMessage {
                version: 70015,
                locator_hashes,
                stop_hash,
            };

            peer.send_message(Message::GetHeaders(getheaders)).await?;
        } else {
            warn!("Peer {} not found", peer_addr);
        }

        Ok(())
    }

    /// Send getdata message for a block to a specific peer
    pub async fn send_getdata_block_to_peer(
        &self,
        peer_addr: SocketAddr,
        block_hash: BlockHash,
    ) -> Result<()> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(&peer_addr) {
            let inv = vec![Inventory {
                inv_type: InvType::Block,
                hash: block_hash,
            }];

            peer.send_message(Message::GetData(inv)).await?;
        } else {
            warn!("Peer {} not found", peer_addr);
        }

        Ok(())
    }

    /// Send inv message to a specific peer
    pub async fn send_inv_to_peer(
        &self,
        peer_addr: SocketAddr,
        inventories: Vec<Inventory>,
    ) -> Result<()> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(&peer_addr) {
            peer.send_message(Message::Inv(inventories)).await?;
        } else {
            warn!("Peer {} not found", peer_addr);
        }

        Ok(())
    }

    /// Send headers message to a specific peer
    pub async fn send_headers_to_peer(
        &self,
        peer_addr: SocketAddr,
        headers: Vec<bitcoin::block::Header>,
    ) -> Result<()> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(&peer_addr) {
            peer.send_message(Message::Headers(headers)).await?;
        } else {
            warn!("Peer {} not found", peer_addr);
        }

        Ok(())
    }

    /// Get list of connected peer addresses
    pub async fn get_connected_peers(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        let mut connected = Vec::new();
        for (addr, peer) in peers.iter() {
            if peer.is_connected().await {
                connected.push(*addr);
            }
        }
        connected
    }

    /// Get peer heights for synchronization
    pub async fn get_peer_heights(&self) -> Vec<(SocketAddr, i32)> {
        let peers = self.peers.read().await;
        let mut heights = Vec::new();

        for (addr, peer) in peers.iter() {
            if peer.is_connected().await {
                if let Some(version) = peer.version.read().await.as_ref() {
                    heights.push((*addr, version.start_height));
                }
            }
        }

        heights
    }

    /// Discover and connect to new peers
    pub async fn discover_and_connect_peers(&mut self, count: usize) -> Result<()> {
        info!("Discovering and connecting to {} new peers", count);

        // Try DNS discovery first
        let discovered = self.discovery.discover_from_dns().await?;

        // Connect to discovered peers
        let mut connected = 0;
        for addr in discovered.iter().take(count) {
            if self.connect_to_peer(*addr).await.is_ok() {
                connected += 1;
                if connected >= count {
                    break;
                }
            }
        }

        // If we still need more peers, try fallback peers
        if connected < count {
            self.discovery.add_fallback_peers().await?;
            let fallback_peers = self.discovery.get_peers(count - connected).await;
            for addr in fallback_peers {
                if self.connect_to_peer(addr).await.is_ok() {
                    connected += 1;
                    if connected >= count {
                        break;
                    }
                }
            }
        }

        info!("Connected to {} new peers", connected);
        Ok(())
    }

    /// Send ping to a specific peer
    pub async fn send_ping_to_peer(&self, peer_addr: &SocketAddr, nonce: u64) -> Result<()> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(peer_addr) {
            peer.send_message(Message::Ping(nonce)).await?;
            debug!("Sent ping to {} with nonce {}", peer_addr, nonce);
            Ok(())
        } else {
            anyhow::bail!("Peer {} not found", peer_addr)
        }
    }

    /// Get DoS protection manager
    pub fn dos_protection_manager(&self) -> Option<Arc<DosProtectionManager>> {
        Some(self.dos_protection.clone())
    }

    /// Handle messages from a peer
    async fn handle_peer_messages(
        peer_addr: SocketAddr,
        mut recv_rx: mpsc::Receiver<Message>,
        chain: Arc<bitcoin_core_lib::chain::ChainManager>,
        peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
        relay_manager: Arc<RelayManager>,
        sync_manager: Arc<SyncManager>,
        external_sync: Option<Arc<dyn SyncHandler>>,
        mempool: Option<Arc<RwLock<mempool::pool::Mempool>>>,
        compact_protocol: Option<Arc<CompactBlockProtocol>>,
        peer_manager: Arc<PeerManager>,
        discovery: Arc<PeerDiscovery>,
    ) {
        info!("Starting message handler for peer {}", peer_addr);

        while let Some(message) = recv_rx.recv().await {
            // Check DoS protection for message
            if let Some(dos_mgr) = peers
                .read()
                .await
                .iter()
                .find(|(a, _)| **a == peer_addr)
                .map(|(_, p)| p)
            {
                // Get dos protection manager from somewhere
                // For now, we'll skip this check as we need to restructure the message handler
            }

            match message {
                Message::Version(version_msg) => {
                    info!(
                        "Received version from {}: height {}, services {:?}",
                        peer_addr, version_msg.start_height, version_msg.services
                    );

                    // Store peer version info
                    if let Some(peer) = peers.read().await.get(&peer_addr) {
                        *peer.version.write().await = Some(version_msg.clone());

                        // Send verack
                        let _ = peer.send_message(Message::Verack).await;
                    }

                    // Update sync manager with peer height
                    // Convert i32 to u32, using 0 for negative values
                    let height = if version_msg.start_height < 0 {
                        0
                    } else {
                        version_msg.start_height as u32
                    };

                    // For now, use a placeholder hash until we get the actual best block
                    use bitcoin_hashes::Hash;
                    let placeholder_hash = bitcoin::BlockHash::from_raw_hash(
                        bitcoin_hashes::sha256d::Hash::from_byte_array([0u8; 32]),
                    );

                    // Use external sync handler if available, otherwise use internal
                    if let Some(ref handler) = external_sync {
                        handler
                            .update_peer_info(peer_addr, height, placeholder_hash)
                            .await;
                    } else {
                        sync_manager
                            .update_peer_info(peer_addr, height, placeholder_hash)
                            .await;
                    }
                }
                Message::Verack => {
                    info!("Received verack from {}, handshake complete", peer_addr);
                    // Update peer score for successful handshake
                    let _ = peer_manager.update_score(&peer_addr, ScoreEvent::SuccessfulHandshake).await;
                }
                Message::Ping(nonce) => {
                    debug!("Received ping from {}", peer_addr);
                    // Send pong back
                    if let Some(peer) = peers.read().await.get(&peer_addr) {
                        let _ = peer.send_message(Message::Pong(nonce)).await;
                    }
                }
                Message::Headers(headers) => {
                    info!("Received {} headers from {}", headers.len(), peer_addr);
                    // Process headers for synchronization
                    // Use external sync handler if available
                    if let Some(ref handler) = external_sync {
                        if let Err(e) = handler.process_headers(headers.clone()).await {
                            warn!("Failed to process headers from {}: {}", peer_addr, e);
                        }
                    } else if let Err(e) = sync_manager.process_headers(headers).await {
                        warn!("Failed to process headers from {}: {}", peer_addr, e);
                    }
                }
                Message::Block(block) => {
                    info!("Received block {} from {}", block.block_hash(), peer_addr);

                    // First add the block to the sync module's block queue
                    if let Some(ref handler) = external_sync {
                        // The sync module will process it in order
                        handler
                            .handle_block_announcement(block.clone())
                            .await
                            .unwrap_or_else(|e| {
                                warn!("Sync module failed to handle block: {}", e);
                            });
                    }

                    // Also process directly for immediate validation
                    match chain.process_block(block.clone()).await {
                        Ok(status) => {
                            info!(
                                "Block {} processed with status: {:?}",
                                block.block_hash(),
                                status
                            );
                            // Update peer score for valid block
                            let _ = peer_manager.update_score(&peer_addr, ScoreEvent::ValidBlock).await;
                            let _ = relay_manager.relay_block(&block).await;
                        }
                        Err(e) => {
                            warn!("Failed to process block from {}: {}", peer_addr, e);
                            // Update peer score for invalid block
                            let _ = peer_manager.update_score(&peer_addr, ScoreEvent::InvalidBlock).await;
                        }
                    }
                }
                Message::Tx(tx) => {
                    let txid = tx.compute_txid();
                    debug!("Received transaction {} from {}", txid, peer_addr);

                    // Add to mempool if available
                    if let Some(ref mempool) = mempool {
                        match mempool.write().await.add_transaction(tx.clone()).await {
                            Ok(()) => {
                                info!("Added transaction {} to mempool from {}", txid, peer_addr);
                                // Update peer score for valid transaction
                                let _ = peer_manager.update_score(&peer_addr, ScoreEvent::ValidTransaction).await;
                                // Relay to other peers
                                let _ = relay_manager.relay_transaction(&tx).await;
                            }
                            Err(e) => {
                                debug!("Failed to add transaction {} to mempool: {}", txid, e);
                                // Update peer score for invalid transaction
                                let _ = peer_manager.update_score(&peer_addr, ScoreEvent::InvalidTransaction).await;
                            }
                        }
                    } else {
                        // No mempool, just relay
                        let _ = relay_manager.relay_transaction(&tx).await;
                    }
                }
                Message::GetHeaders(msg) => {
                    debug!("Peer {} requesting headers", peer_addr);
                    // Fetch headers from chain and send back
                    let mut headers = Vec::new();
                    let mut current_height = 0u32;

                    // Find the fork point from locator hashes
                    for hash in &msg.locator_hashes {
                        if let Ok(height) = chain.get_block_height(hash) {
                            current_height = height + 1;
                            break;
                        }
                    }

                    // Get up to 2000 headers
                    const MAX_HEADERS: usize = 2000;
                    while headers.len() < MAX_HEADERS {
                        if let Some(hash) = chain.get_block_hash_at_height(current_height) {
                            if let Some(header) = chain.get_block_header(&hash) {
                                headers.push(header);
                                current_height += 1;

                                // Stop if we reach the stop hash
                                if hash == msg.stop_hash {
                                    break;
                                }
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }

                    if !headers.is_empty() {
                        info!("Sending {} headers to {}", headers.len(), peer_addr);
                        if let Some(peer) = peers.read().await.get(&peer_addr) {
                            let _ = peer.send_message(Message::Headers(headers)).await;
                        }
                    }
                }
                Message::GetData(inv) => {
                    debug!("Peer {} requesting {} items", peer_addr, inv.len());
                    // Fetch requested items and send back
                    for item in inv {
                        match item.inv_type {
                            InvType::Block | InvType::WitnessBlock => {
                                // Fetch block from storage
                                if let Ok(Some(block)) = chain.get_block(&item.hash).await {
                                    info!("Sending block {} to {}", item.hash, peer_addr);
                                    if let Some(peer) = peers.read().await.get(&peer_addr) {
                                        let _ = peer.send_message(Message::Block(block)).await;
                                    }
                                } else {
                                    debug!("Block {} not found for {}", item.hash, peer_addr);
                                    // Send notfound message
                                    if let Some(peer) = peers.read().await.get(&peer_addr) {
                                        let _ = peer
                                            .send_message(Message::NotFound(vec![item.clone()]))
                                            .await;
                                    }
                                }
                            }
                            InvType::Tx | InvType::WitnessTx => {
                                // Try to fetch from mempool first
                                let mut found = false;
                                if let Some(ref mempool) = mempool {
                                    let mempool_guard = mempool.read().await;
                                    if let Some(tx) = mempool_guard.get_transaction(
                                        &bitcoin::Txid::from_raw_hash(item.hash.to_raw_hash()),
                                    ) {
                                        info!(
                                            "Sending transaction {} to {} (from mempool)",
                                            item.hash, peer_addr
                                        );
                                        if let Some(peer) = peers.read().await.get(&peer_addr) {
                                            let _ = peer.send_message(Message::Tx(tx)).await;
                                        }
                                        found = true;
                                    }
                                }

                                // If not in mempool, try blockchain
                                if !found {
                                    if let Ok(Some((tx, _))) = chain
                                        .find_transaction(&bitcoin::Txid::from_raw_hash(
                                            item.hash.to_raw_hash(),
                                        ))
                                        .await
                                    {
                                        info!(
                                            "Sending transaction {} to {} (from blockchain)",
                                            item.hash, peer_addr
                                        );
                                        if let Some(peer) = peers.read().await.get(&peer_addr) {
                                            let _ = peer.send_message(Message::Tx(tx)).await;
                                        }
                                    } else {
                                        debug!(
                                            "Transaction {} not found for {}",
                                            item.hash, peer_addr
                                        );
                                        if let Some(peer) = peers.read().await.get(&peer_addr) {
                                            let _ = peer
                                                .send_message(Message::NotFound(vec![item.clone()]))
                                                .await;
                                        }
                                    }
                                }
                            }
                            _ => {
                                debug!("Unknown inventory type requested");
                            }
                        }
                    }
                }
                Message::Inv(inv) => {
                    debug!("Peer {} announcing {} items", peer_addr, inv.len());

                    // Request interesting items
                    let mut items_to_request = Vec::new();

                    for item in &inv {
                        match item.inv_type {
                            InvType::Block | InvType::WitnessBlock => {
                                // Check if we need this block
                                if chain.get_block(&item.hash).await.unwrap_or(None).is_none() {
                                    items_to_request.push(item.clone());
                                }
                            }
                            InvType::CompactBlock => {
                                // Check if we support compact blocks and need this block
                                if compact_protocol.is_some()
                                    && chain.get_block(&item.hash).await.unwrap_or(None).is_none()
                                {
                                    // Request compact block instead of full block
                                    items_to_request.push(item.clone());
                                }
                            }
                            InvType::Tx | InvType::WitnessTx => {
                                // Check if we need this transaction
                                let txid = bitcoin::Txid::from_raw_hash(item.hash.to_raw_hash());
                                let mut need_tx = true;

                                // Check mempool first
                                if let Some(ref mempool) = mempool {
                                    if mempool.read().await.has_transaction(&txid) {
                                        need_tx = false;
                                    }
                                }

                                // Check blockchain if not in mempool
                                if need_tx {
                                    if let Ok(Some(_)) = chain.find_transaction(&txid).await {
                                        need_tx = false;
                                    }
                                }

                                if need_tx {
                                    items_to_request.push(item.clone());
                                }
                            }
                            _ => {}
                        }
                    }

                    // Request the items we need
                    if !items_to_request.is_empty() {
                        info!(
                            "Requesting {} items from {}",
                            items_to_request.len(),
                            peer_addr
                        );
                        if let Some(peer) = peers.read().await.get(&peer_addr) {
                            let _ = peer.send_message(Message::GetData(items_to_request)).await;
                        }
                    }
                }
                Message::Addr(addrs) => {
                    let addr_count = addrs.len();
                    debug!("Received {} addresses from {}", addr_count, peer_addr);
                    // Store addresses for peer discovery
                    for (_timestamp, addr) in addrs {
                        // Convert bitcoin address to SocketAddr
                        if let Ok(socket_addr) = addr.socket_addr() {
                            discovery.add_peer(socket_addr).await;
                        }
                    }
                    info!("Stored {} peer addresses for discovery", addr_count);
                }
                // BIP152 Compact Block messages
                Message::SendCompact(send_compact) => {
                    info!("Peer {} supports compact blocks version {}, high_bandwidth: {}", 
                         peer_addr, send_compact.version, send_compact.high_bandwidth);
                    // Store peer's compact block preferences
                    if let Some(peer) = peers.read().await.get(&peer_addr) {
                        // Could store this in peer state for future use
                    }
                }
                Message::CompactBlock(compact_block) => {
                    info!("Received compact block {} from {}", 
                         compact_block.header.header.block_hash(), peer_addr);
                    
                    if let Some(ref protocol) = compact_protocol {
                        // Process compact block through protocol handler
                        match protocol.handle_cmpctblock(&peer_addr.to_string(), compact_block).await {
                            Ok(messages) => {
                                // Handle response messages
                                for message in messages {
                                    match message {
                                        Message::Block(block) => {
                                            // Successfully reconstructed block
                                            info!("Reconstructed block {} from compact block", block.block_hash());
                                            
                                            // Process the block through chain manager
                                            match chain.process_block(block.clone()).await {
                                                Ok(status) => {
                                                    info!("Processed compact block: {:?}", status);
                                                    // Relay to other peers if accepted
                                                    if matches!(status, bitcoin_core_lib::chain::BlockStatus::InActiveChain) {
                                                        relay_manager.relay_block(&block).await;
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("Failed to process reconstructed block: {}", e);
                                                }
                                            }
                                        }
                                        other => {
                                            // Send other messages (like GetBlockTxn) to peer
                                            let peers_guard = peers.read().await;
                                            if let Some(peer) = peers_guard.get(&peer_addr) {
                                                if let Err(e) = peer.send_message(other).await {
                                                    warn!("Failed to send response to {}: {}", peer_addr, e);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to handle compact block: {}", e);
                            }
                        }
                    } else {
                        debug!("Compact block protocol not enabled");
                    }
                }
                Message::GetBlockTxn(get_block_txn) => {
                    debug!("Peer {} requesting {} transactions for block {}", 
                          peer_addr, get_block_txn.indexes.len(), get_block_txn.block_hash);
                    
                    // Fetch the block and send requested transactions
                    if let Ok(Some(block)) = chain.get_block(&get_block_txn.block_hash).await {
                        let mut transactions = Vec::new();
                        for &index in &get_block_txn.indexes {
                            if let Some(tx) = block.txdata.get(index as usize) {
                                transactions.push(tx.clone());
                            }
                        }
                        
                        if !transactions.is_empty() {
                            let block_txn = crate::compact_blocks::BlockTxn {
                                block_hash: get_block_txn.block_hash,
                                transactions,
                            };
                            
                            if let Some(peer) = peers.read().await.get(&peer_addr) {
                                let _ = peer.send_message(Message::BlockTxn(block_txn)).await;
                            }
                        }
                    }
                }
                Message::BlockTxn(block_txn) => {
                    info!("Received {} transactions for compact block {} from {}", 
                         block_txn.transactions.len(), block_txn.block_hash, peer_addr);
                    
                    if let Some(ref protocol) = compact_protocol {
                        // Add received transactions to compact block
                        match protocol.add_transactions(block_txn.block_hash, block_txn.transactions).await {
                            Ok(Some(block)) => {
                                // Successfully reconstructed block
                                info!("Reconstructed block {} with received transactions", block.block_hash());
                                
                                // Process the block
                                match chain.process_block(block.clone()).await {
                                    Ok(status) => {
                                        info!("Processed reconstructed block: {:?}", status);
                                        // Relay to other peers if accepted
                                        if matches!(status, bitcoin_core_lib::chain::BlockStatus::InActiveChain) {
                                            relay_manager.relay_block(&block).await;
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to process reconstructed block: {}", e);
                                    }
                                }
                            }
                            Ok(None) => {
                                debug!("Still missing transactions for compact block");
                            }
                            Err(e) => {
                                warn!("Failed to add transactions to compact block: {}", e);
                            }
                        }
                    }
                }
                Message::SendCompact(sendcmpct) => {
                    info!(
                        "Received SendCompact from {}: high_bandwidth={}, version={}",
                        peer_addr, sendcmpct.high_bandwidth, sendcmpct.version
                    );
                    
                    // Update compact block protocol state for this peer
                    if let Some(ref protocol) = compact_protocol {
                        // Process the SendCompact message
                        let sendcmpct_msg = crate::compact_block_protocol::SendCmpct {
                            high_bandwidth: sendcmpct.high_bandwidth,
                            version: sendcmpct.version,
                        };
                        if let Err(e) = protocol.handle_sendcmpct(
                            &peer_addr.to_string(),
                            sendcmpct_msg,
                        ).await {
                            warn!("Failed to handle SendCompact from {}: {}", peer_addr, e);
                        } else {
                            // If this is version 1 and we support it, send our own SendCompact
                            if sendcmpct.version == 1 {
                                // Send our SendCompact message to indicate we support compact blocks
                                let our_sendcmpct = SendCompact {
                                    high_bandwidth: false, // Start with low bandwidth mode
                                    version: 1,
                                };
                                
                                // Get the peer to send response
                                let peers_guard = peers.read().await;
                                if let Some(peer) = peers_guard.get(&peer_addr) {
                                    if let Err(e) = peer.send_message(Message::SendCompact(our_sendcmpct)).await {
                                        warn!("Failed to send SendCompact to {}: {}", peer_addr, e);
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {
                    debug!("Received other message from {}", peer_addr);
                }
            }
        }

        info!("Message handler for peer {} ended", peer_addr);
    }

    /// Handle outgoing messages to a peer
    async fn handle_outgoing_messages(
        peer_addr: SocketAddr,
        mut send_rx: mpsc::Receiver<Message>,
        peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
    ) {
        info!("Starting outgoing message handler for peer {}", peer_addr);

        while let Some(message) = send_rx.recv().await {
            // Get the peer to send the message
            let peers_guard = peers.read().await;
            if let Some(peer) = peers_guard.get(&peer_addr) {
                // Send the message to the peer
                if let Err(e) = peer.send_message(message.clone()).await {
                    warn!("Failed to send message to {}: {}", peer_addr, e);
                    // If sending fails, the peer might be disconnected
                    if !peer.is_connected().await {
                        info!(
                            "Peer {} is disconnected, stopping outgoing handler",
                            peer_addr
                        );
                        break;
                    }
                } else {
                    debug!("Sent message to peer {}: {}", peer_addr, message.command());
                }
            } else {
                warn!(
                    "Peer {} not found in peers map, stopping outgoing handler",
                    peer_addr
                );
                break;
            }
        }

        info!("Outgoing message handler for peer {} ended", peer_addr);
    }
}
