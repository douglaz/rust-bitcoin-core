use anyhow::Result;
use async_trait::async_trait;
use bitcoin::block::Header as BlockHeader;
use bitcoin::{Block, BlockHash};
use std::net::SocketAddr;

/// Trait for sync managers to handle headers and peer updates
#[async_trait]
pub trait SyncHandler: Send + Sync {
    /// Process incoming headers from a peer
    async fn process_headers(&self, headers: Vec<BlockHeader>) -> Result<()>;

    /// Update peer information (height and best block)
    async fn update_peer_info(&self, peer_addr: SocketAddr, height: u32, best_hash: BlockHash);

    /// Process incoming block from a peer
    async fn process_block(&self, block: Block) -> Result<()>;

    /// Handle block announcement (used for ordered block processing)
    async fn handle_block_announcement(&self, block: Block) -> Result<()> {
        // Default implementation just forwards to process_block
        self.process_block(block).await
    }
}
