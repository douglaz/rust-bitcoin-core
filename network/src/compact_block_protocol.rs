use anyhow::Result;
use bitcoin::{Block, BlockHash, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::compact_blocks::{
    BlockTxn, CompactBlock, CompactBlockRelay, CompactBlockResult, GetBlockTxn,
    COMPACT_BLOCK_VERSION,
};
use crate::message::{InvType, Inventory, Message};

/// BIP152 Compact Block Protocol Implementation
/// Handles sendcmpct, cmpctblock, getblocktxn, blocktxn messages

/// SendCmpct message for negotiating compact block relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendCmpct {
    /// High bandwidth mode (1) or low bandwidth (0)
    pub high_bandwidth: bool,
    /// Protocol version (1 or 2)
    pub version: u64,
}

/// Pending block reconstruction info
#[derive(Debug, Clone)]
pub struct PendingBlock {
    /// The compact block
    pub compact_block: CompactBlock,
    /// Missing transaction indexes
    pub missing_indexes: Vec<u16>,
    /// Received missing transactions
    pub missing_transactions: Vec<Transaction>,
    /// When this pending block was created
    pub created: Instant,
}

/// Compact block protocol state for a peer
#[derive(Debug, Clone)]
pub struct CompactBlockState {
    /// Whether peer supports compact blocks
    pub supports_compact: bool,
    /// Compact block version (1 for pre-SegWit, 2 for SegWit)
    pub version: u64,
    /// High bandwidth mode enabled
    pub high_bandwidth: bool,
    /// Blocks we're waiting for transactions for
    pub pending_blocks: HashMap<BlockHash, PendingBlock>,
    /// Last compact block received time
    pub last_compact_block: Option<Instant>,
}

impl Default for CompactBlockState {
    fn default() -> Self {
        Self {
            supports_compact: false,
            version: 0,
            high_bandwidth: false,
            pending_blocks: HashMap::new(),
            last_compact_block: None,
        }
    }
}

/// Compact block protocol manager
pub struct CompactBlockProtocol {
    /// Compact block relay engine
    relay: Arc<CompactBlockRelay>,
    /// Per-peer compact block states
    peer_states: Arc<RwLock<HashMap<String, CompactBlockState>>>,
    /// High bandwidth relay peers (up to 3)
    high_bandwidth_peers: Arc<RwLock<Vec<String>>>,
    /// Block announcement queue
    announcement_queue: Arc<RwLock<VecDeque<(String, BlockHash)>>>,
    /// Protocol statistics
    stats: Arc<RwLock<ProtocolStats>>,
    /// Configuration
    config: CompactBlockConfig,
}

/// Compact block protocol configuration
#[derive(Debug, Clone)]
pub struct CompactBlockConfig {
    /// Enable compact blocks
    pub enabled: bool,
    /// Prefer high bandwidth mode
    pub prefer_high_bandwidth: bool,
    /// Maximum high bandwidth peers
    pub max_high_bandwidth_peers: usize,
    /// Compact block timeout
    pub compact_block_timeout: Duration,
    /// Request missing transactions timeout
    pub missing_tx_timeout: Duration,
}

impl Default for CompactBlockConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefer_high_bandwidth: true,
            max_high_bandwidth_peers: 3,
            compact_block_timeout: Duration::from_secs(30),
            missing_tx_timeout: Duration::from_secs(10),
        }
    }
}

/// Protocol statistics
#[derive(Debug, Default, Clone)]
pub struct ProtocolStats {
    pub sendcmpct_sent: u64,
    pub sendcmpct_received: u64,
    pub cmpctblock_sent: u64,
    pub cmpctblock_received: u64,
    pub getblocktxn_sent: u64,
    pub getblocktxn_received: u64,
    pub blocktxn_sent: u64,
    pub blocktxn_received: u64,
    pub blocks_reconstructed: u64,
    pub high_bandwidth_peers: usize,
}

impl CompactBlockProtocol {
    /// Create new compact block protocol manager
    pub fn new(relay: Arc<CompactBlockRelay>, config: CompactBlockConfig) -> Self {
        Self {
            relay,
            peer_states: Arc::new(RwLock::new(HashMap::new())),
            high_bandwidth_peers: Arc::new(RwLock::new(Vec::new())),
            announcement_queue: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(ProtocolStats::default())),
            config,
        }
    }

    /// Handle SendCmpct message from peer
    pub async fn handle_sendcmpct(
        &self,
        peer_id: &str,
        sendcmpct: SendCmpct,
    ) -> Result<Option<Message>> {
        info!(
            "Received sendcmpct from {}: version={}, high_bandwidth={}",
            peer_id, sendcmpct.version, sendcmpct.high_bandwidth
        );

        self.stats.write().await.sendcmpct_received += 1;

        // Validate version
        if sendcmpct.version != 1 && sendcmpct.version != 2 {
            warn!(
                "Invalid compact block version {} from {}",
                sendcmpct.version, peer_id
            );
            return Ok(None);
        }

        // Update peer state
        let mut states = self.peer_states.write().await;
        let state = states.entry(peer_id.to_string()).or_default();
        state.supports_compact = true;
        state.version = sendcmpct.version;
        state.high_bandwidth = sendcmpct.high_bandwidth;

        // Handle high bandwidth mode
        if sendcmpct.high_bandwidth {
            let mut high_bandwidth = self.high_bandwidth_peers.write().await;
            if !high_bandwidth.contains(&peer_id.to_string()) {
                if high_bandwidth.len() < self.config.max_high_bandwidth_peers {
                    high_bandwidth.push(peer_id.to_string());
                    info!("Added {} as high bandwidth compact block peer", peer_id);
                    self.stats.write().await.high_bandwidth_peers = high_bandwidth.len();
                } else {
                    info!(
                        "Cannot add {} as high bandwidth peer - limit reached",
                        peer_id
                    );
                }
            }
        }

        // Send our sendcmpct if we haven't already
        if self.config.enabled {
            let our_sendcmpct = SendCmpct {
                high_bandwidth: self.config.prefer_high_bandwidth,
                version: COMPACT_BLOCK_VERSION,
            };
            self.stats.write().await.sendcmpct_sent += 1;
            return Ok(Some(Message::Other(self.encode_sendcmpct(our_sendcmpct))));
        }

        Ok(None)
    }

    /// Handle compact block message from peer
    pub async fn handle_cmpctblock(
        &self,
        peer_id: &str,
        compact_block: CompactBlock,
    ) -> Result<Vec<Message>> {
        let block_hash = compact_block.block_hash();
        info!(
            "Received compact block {} from {} with {} transactions",
            block_hash,
            peer_id,
            compact_block.tx_count()
        );

        self.stats.write().await.cmpctblock_received += 1;

        // Update peer state
        {
            let mut states = self.peer_states.write().await;
            if let Some(state) = states.get_mut(peer_id) {
                state.last_compact_block = Some(Instant::now());
                
                // Check if we need to request missing transactions
                let missing_indexes = self.get_missing_indexes(&compact_block);
                if !missing_indexes.is_empty() {
                    // Store pending block info for reconstruction
                    let pending = PendingBlock {
                        compact_block: compact_block.clone(),
                        missing_indexes: missing_indexes.clone(),
                        missing_transactions: Vec::new(),
                        created: Instant::now(),
                    };
                    state.pending_blocks.insert(block_hash, pending);
                }
            }
        }

        // Process compact block
        let result = self
            .relay
            .process_compact_block(compact_block.clone())
            .await?;

        match result {
            CompactBlockResult::Reconstructed(block) => {
                info!(
                    "Successfully reconstructed block {} from compact block",
                    block_hash
                );
                self.stats.write().await.blocks_reconstructed += 1;

                // Remove from pending
                let mut states = self.peer_states.write().await;
                if let Some(state) = states.get_mut(peer_id) {
                    state.pending_blocks.remove(&block_hash);
                }

                // Return the full block for processing
                Ok(vec![Message::Block(block)])
            }
            CompactBlockResult::MissingTransactions(missing) => {
                let missing_count = missing.len();
                warn!(
                    "Missing {} transactions for block {} from {}",
                    missing_count, block_hash, peer_id
                );

                // Create request for missing transactions
                let get_block_txn = self.relay.create_get_block_txn(block_hash, missing);
                self.stats.write().await.getblocktxn_sent += 1;

                Ok(vec![Message::Other(self.encode_getblocktxn(get_block_txn))])
            }
        }
    }

    /// Handle GetBlockTxn message from peer
    pub async fn handle_getblocktxn(
        &self,
        peer_id: &str,
        get_block_txn: GetBlockTxn,
    ) -> Result<Option<Message>> {
        info!(
            "Received getblocktxn from {} for block {} ({} transactions)",
            peer_id,
            get_block_txn.block_hash,
            get_block_txn.indexes.len()
        );

        self.stats.write().await.getblocktxn_received += 1;

        // Look up the requested transactions from our block storage
        // This requires integration with the storage layer to fetch specific transactions
        // from a block. The implementation would:
        // 1. Fetch the block from storage using get_block_txn.block_hash
        // 2. Extract the requested transactions by index
        // 3. Create and return a BlockTxn message
        
        // For now, return None as block storage integration is pending
        // This would be implemented when the storage layer is fully connected
        warn!(
            "Cannot provide transactions for block {} - pending storage integration",
            get_block_txn.block_hash
        );

        Ok(None)
    }

    /// Handle BlockTxn message from peer
    pub async fn handle_blocktxn(
        &self,
        peer_id: &str,
        block_txn: BlockTxn,
    ) -> Result<Option<Message>> {
        info!(
            "Received blocktxn from {} for block {} ({} transactions)",
            peer_id,
            block_txn.block_hash,
            block_txn.transactions.len()
        );

        self.stats.write().await.blocktxn_received += 1;

        // Process received transactions
        if let Some(block) = self.relay.process_block_txn(block_txn.clone()).await? {
            info!(
                "Successfully reconstructed block {} after receiving transactions",
                block_txn.block_hash
            );
            self.stats.write().await.blocks_reconstructed += 1;

            // Remove from pending
            let mut states = self.peer_states.write().await;
            if let Some(state) = states.get_mut(peer_id) {
                state.pending_blocks.remove(&block_txn.block_hash);
            }

            // Return the reconstructed block
            return Ok(Some(Message::Block(block)));
        }

        Ok(None)
    }

    /// Announce block using compact blocks
    pub async fn announce_block(&self, block: &Block, peer_id: &str) -> Result<Message> {
        let states = self.peer_states.read().await;
        let state = states.get(peer_id);

        // Check if peer supports compact blocks and high bandwidth
        if let Some(state) = state {
            if state.supports_compact && state.high_bandwidth {
                // Create and send compact block directly
                let compact = CompactBlock::from_block(block, None);
                self.stats.write().await.cmpctblock_sent += 1;

                info!(
                    "Announcing block {} to {} using compact block (high bandwidth)",
                    block.block_hash(),
                    peer_id
                );

                return Ok(Message::Other(self.encode_cmpctblock(compact)));
            }
        }

        // Fall back to regular inv announcement
        let inv = vec![Inventory {
            inv_type: InvType::Block,
            hash: block.block_hash(),
        }];

        Ok(Message::Inv(inv))
    }

    /// Send compact block to peer if requested
    pub async fn send_compact_block(
        &self,
        block: &Block,
        peer_id: &str,
    ) -> Result<Option<Message>> {
        let states = self.peer_states.read().await;

        if let Some(state) = states.get(peer_id) {
            if state.supports_compact && !state.high_bandwidth {
                // Low bandwidth mode - send compact block when requested
                let compact = CompactBlock::from_block(block, None);
                self.stats.write().await.cmpctblock_sent += 1;

                info!(
                    "Sending compact block {} to {} (low bandwidth)",
                    block.block_hash(),
                    peer_id
                );

                return Ok(Some(Message::Other(self.encode_cmpctblock(compact))));
            }
        }

        Ok(None)
    }

    /// Check if peer supports compact blocks
    pub async fn peer_supports_compact(&self, peer_id: &str) -> bool {
        let states = self.peer_states.read().await;
        states
            .get(peer_id)
            .map(|s| s.supports_compact)
            .unwrap_or(false)
    }

    /// Get protocol statistics
    pub async fn get_stats(&self) -> ProtocolStats {
        self.stats.read().await.clone()
    }

    /// Clean up disconnected peer
    pub async fn peer_disconnected(&self, peer_id: &str) {
        let mut states = self.peer_states.write().await;
        states.remove(peer_id);

        let mut high_bandwidth = self.high_bandwidth_peers.write().await;
        high_bandwidth.retain(|p| p != peer_id);
        self.stats.write().await.high_bandwidth_peers = high_bandwidth.len();

        info!(
            "Removed compact block state for disconnected peer {}",
            peer_id
        );
    }

    /// Process a compact block and try to reconstruct full block
    pub async fn process_compact_block(&self, compact_block: CompactBlock) -> Result<Option<Block>> {
        // Try to reconstruct the block from the compact block
        match self.relay.reconstruct_block(compact_block.clone()).await {
            Ok(block) => Ok(Some(block)),
            Err(_) => {
                // Need to request missing transactions
                Ok(None)
            }
        }
    }
    
    /// Get indexes of missing transactions for a compact block
    pub fn get_missing_indexes(&self, compact_block: &CompactBlock) -> Vec<u16> {
        // Check which transactions are missing from our mempool
        let mut missing_indexes = Vec::new();
        
        // We need to check each short ID against our mempool
        // For now, we'll return indexes for transactions we don't have
        // In a real implementation, this would check against the actual mempool
        
        for (index, _short_id) in compact_block.short_ids.iter().enumerate() {
            // For testing/development, assume we're missing some transactions
            // This would normally check if we have the transaction matching the short ID
            if index % 3 == 0 {  // Simulate missing every 3rd transaction for testing
                missing_indexes.push(index as u16);
            }
        }
        
        missing_indexes
    }
    
    /// Add received transactions to pending compact block
    pub async fn add_transactions(
        &self,
        block_hash: BlockHash,
        transactions: Vec<Transaction>,
    ) -> Result<Option<Block>> {
        // Try to complete the block reconstruction with received transactions
        let mut states = self.peer_states.write().await;
        
        // Find the peer that has this pending block
        for (_peer_id, state) in states.iter_mut() {
            if let Some(pending) = state.pending_blocks.get_mut(&block_hash) {
                // Add the transactions to the pending block
                pending.missing_transactions.extend(transactions.clone());
                
                // Check if we now have all transactions
                if pending.missing_indexes.is_empty() || 
                   pending.missing_transactions.len() >= pending.missing_indexes.len() {
                    // Try to reconstruct the full block
                    // The coinbase is always the first prefilled transaction
                    let coinbase = pending.compact_block.prefilled_txs
                        .first()
                        .ok_or_else(|| anyhow::anyhow!("No coinbase in compact block"))?
                        .tx.clone();
                    let mut txdata = vec![coinbase];
                    
                    // Add the prefilled transactions and missing transactions in order
                    let mut missing_tx_iter = pending.missing_transactions.iter();
                    let mut prefilled_iter = pending.compact_block.prefilled_txs.iter();
                    let mut next_prefilled = prefilled_iter.next();
                    
                    for i in 0..pending.compact_block.short_ids.len() {
                        // Check if this index has a prefilled transaction
                        if let Some(prefilled) = next_prefilled {
                            if prefilled.index as usize == i + 1 { // +1 because coinbase is at index 0
                                txdata.push(prefilled.tx.clone());
                                next_prefilled = prefilled_iter.next();
                                continue;
                            }
                        }
                        
                        // Otherwise use a missing transaction
                        if let Some(tx) = missing_tx_iter.next() {
                            txdata.push(tx.clone());
                        }
                    }
                    
                    // Create the complete block
                    let block = Block {
                        header: pending.compact_block.header.header.clone(),
                        txdata,
                    };
                    
                    // Remove from pending
                    state.pending_blocks.remove(&block_hash);
                    
                    return Ok(Some(block));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Periodic cleanup of stale pending blocks
    pub async fn cleanup_stale_pending(&self) {
        let mut states = self.peer_states.write().await;
        let now = Instant::now();

        for (peer_id, state) in states.iter_mut() {
            // Check each pending block for timeout
            let mut blocks_to_remove = Vec::new();
            for (block_hash, pending) in state.pending_blocks.iter() {
                if now.duration_since(pending.created) > self.config.compact_block_timeout {
                    blocks_to_remove.push(*block_hash);
                }
            }
            
            if !blocks_to_remove.is_empty() {
                warn!(
                    "Clearing {} stale pending blocks for peer {}",
                    blocks_to_remove.len(),
                    peer_id
                );
                for block_hash in blocks_to_remove {
                    state.pending_blocks.remove(&block_hash);
                    }
            }
        }

        // Also cleanup in the relay manager
        self.relay
            .cleanup_pending(self.config.missing_tx_timeout)
            .await;
    }

    // Helper methods to encode messages (would be properly implemented with bitcoin message encoding)

    fn encode_sendcmpct(&self, sendcmpct: SendCmpct) -> bitcoin::p2p::message::NetworkMessage {
        // Encode SendCmpct message using proper Bitcoin P2P encoding
        let mut payload = Vec::new();
        
        // Encode high_bandwidth as single byte (0 or 1)
        payload.push(if sendcmpct.high_bandwidth { 1u8 } else { 0u8 });
        
        // Encode version as 8 bytes little-endian
        payload.extend_from_slice(&sendcmpct.version.to_le_bytes());
        
        bitcoin::p2p::message::NetworkMessage::Unknown {
            command: bitcoin::p2p::message::CommandString::try_from("sendcmpct").unwrap(),
            payload,
        }
    }

    fn encode_cmpctblock(&self, compact: CompactBlock) -> bitcoin::p2p::message::NetworkMessage {
        // Encode CompactBlock message using proper Bitcoin P2P encoding
        let mut payload = Vec::new();
        
        // Encode block header (80 bytes)
        let header_bytes = bitcoin::consensus::serialize(&compact.header.header);
        payload.extend_from_slice(&header_bytes);
        
        // Encode nonce (8 bytes little-endian)
        payload.extend_from_slice(&compact.header.nonce.to_le_bytes());
        
        // Encode short_ids count as compact size
        self.encode_compact_size(compact.short_ids.len(), &mut payload);
        
        // Encode each short ID (6 bytes each)
        for short_id in &compact.short_ids {
            payload.extend_from_slice(short_id.as_bytes());
        }
        
        // Encode prefilled_txs count as compact size
        self.encode_compact_size(compact.prefilled_txs.len(), &mut payload);
        
        // Encode each prefilled transaction
        for prefilled in &compact.prefilled_txs {
            // Encode index as compact size
            self.encode_compact_size(prefilled.index as usize, &mut payload);
            
            // Encode transaction
            let tx_bytes = bitcoin::consensus::serialize(&prefilled.tx);
            payload.extend_from_slice(&tx_bytes);
        }
        
        bitcoin::p2p::message::NetworkMessage::Unknown {
            command: bitcoin::p2p::message::CommandString::try_from("cmpctblock").unwrap(),
            payload,
        }
    }

    fn encode_getblocktxn(
        &self,
        get_block_txn: GetBlockTxn,
    ) -> bitcoin::p2p::message::NetworkMessage {
        // Encode GetBlockTxn message using proper Bitcoin P2P encoding
        let mut payload = Vec::new();
        
        // Encode block hash (32 bytes)
        let hash_bytes = bitcoin::consensus::serialize(&get_block_txn.block_hash);
        payload.extend_from_slice(&hash_bytes);
        
        // Encode indexes count as compact size
        self.encode_compact_size(get_block_txn.indexes.len(), &mut payload);
        
        // Encode each index as compact size
        for index in &get_block_txn.indexes {
            self.encode_compact_size(*index as usize, &mut payload);
        }
        
        bitcoin::p2p::message::NetworkMessage::Unknown {
            command: bitcoin::p2p::message::CommandString::try_from("getblocktxn").unwrap(),
            payload,
        }
    }
    
    /// Helper to encode compact size (variable length integer)
    fn encode_compact_size(&self, value: usize, buffer: &mut Vec<u8>) {
        if value < 0xFD {
            buffer.push(value as u8);
        } else if value <= 0xFFFF {
            buffer.push(0xFD);
            buffer.extend_from_slice(&(value as u16).to_le_bytes());
        } else if value <= 0xFFFFFFFF {
            buffer.push(0xFE);
            buffer.extend_from_slice(&(value as u32).to_le_bytes());
        } else {
            buffer.push(0xFF);
            buffer.extend_from_slice(&(value as u64).to_le_bytes());
        }
    }
}

/// Run the compact block protocol maintenance loop
pub async fn run_maintenance_loop(protocol: Arc<CompactBlockProtocol>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        interval.tick().await;
        protocol.cleanup_stale_pending().await;

        let stats = protocol.get_stats().await;
        debug!(
            "Compact block protocol stats: {} high bandwidth peers, {} blocks reconstructed",
            stats.high_bandwidth_peers, stats.blocks_reconstructed
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_sendcmpct_handling() {
        let relay = Arc::new(CompactBlockRelay::new(None));
        let protocol = CompactBlockProtocol::new(relay, CompactBlockConfig::default());

        let sendcmpct = SendCmpct {
            high_bandwidth: true,
            version: 2,
        };

        let response = protocol.handle_sendcmpct("peer1", sendcmpct).await.unwrap();
        assert!(response.is_some());

        // Check peer state was updated
        assert!(protocol.peer_supports_compact("peer1").await);

        let stats = protocol.get_stats().await;
        assert_eq!(stats.sendcmpct_received, 1);
        assert_eq!(stats.high_bandwidth_peers, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_compact_block_reconstruction() {
        let relay = Arc::new(CompactBlockRelay::new(None));
        let protocol = CompactBlockProtocol::new(relay, CompactBlockConfig::default());

        // Set up peer state
        let sendcmpct = SendCmpct {
            high_bandwidth: true,
            version: 2,
        };
        protocol.handle_sendcmpct("peer1", sendcmpct).await.unwrap();

        // Create a test compact block
        let block = bitcoin::blockdata::constants::genesis_block(Network::Bitcoin);
        let compact = CompactBlock::from_block(&block, Some(42));

        let messages = protocol.handle_cmpctblock("peer1", compact).await.unwrap();
        assert_eq!(messages.len(), 1);

        // Should reconstruct successfully (genesis block has only coinbase)
        if let Message::Block(reconstructed) = &messages[0] {
            assert_eq!(reconstructed.block_hash(), block.block_hash());
        } else {
            panic!("Expected block message");
        }

        let stats = protocol.get_stats().await;
        assert_eq!(stats.cmpctblock_received, 1);
        assert_eq!(stats.blocks_reconstructed, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_high_bandwidth_peer_limit() {
        let relay = Arc::new(CompactBlockRelay::new(None));
        let mut config = CompactBlockConfig::default();
        config.max_high_bandwidth_peers = 2;
        let protocol = CompactBlockProtocol::new(relay, config);

        // Add first two peers
        for i in 1..=2 {
            let sendcmpct = SendCmpct {
                high_bandwidth: true,
                version: 2,
            };
            protocol
                .handle_sendcmpct(&format!("peer{}", i), sendcmpct)
                .await
                .unwrap();
        }

        let stats = protocol.get_stats().await;
        assert_eq!(stats.high_bandwidth_peers, 2);

        // Try to add third peer - should not be added as high bandwidth
        let sendcmpct = SendCmpct {
            high_bandwidth: true,
            version: 2,
        };
        protocol.handle_sendcmpct("peer3", sendcmpct).await.unwrap();

        let stats = protocol.get_stats().await;
        assert_eq!(stats.high_bandwidth_peers, 2); // Still 2
    }
}
