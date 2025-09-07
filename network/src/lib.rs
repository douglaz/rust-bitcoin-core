// Simplified network module with essential components only

pub mod addr_manager;
pub mod ban_score;
pub mod block_download;
pub mod bloom_filter;
pub mod compact_block_protocol;
pub mod compact_blocks;
pub mod connection;
pub mod connection_retry;
pub mod discovery;
pub mod dos_protection;
pub mod headers_sync;
pub mod ibd;
pub mod manager;
pub mod message;
pub mod orphan_pool;
pub mod peer;
pub mod peer_manager;
pub mod peer_persistence;
pub mod rate_limiter;
pub mod relay;
pub mod sync;
pub mod sync_trait;
pub mod tx_relay;
pub mod wire_compact_blocks;

#[cfg(test)]
mod tests;

// Re-export main types for external use
pub use addr_manager::{AddrInfo, AddrManager, AddrStats};
pub use ban_score::{
    BanDecision, BanScoreConfig, BanScoreManager, BanScoreStats, Misbehavior, PeerBanScore,
};
pub use block_download::{BlockDownloadManager, DownloadRequest, DownloadStats, DownloadStatus};
pub use bloom_filter::{BloomFilter, BloomFilterStats, BloomFlags, SPVFilterManager};
pub use compact_block_protocol::{
    CompactBlockConfig, CompactBlockProtocol, CompactBlockState,
    ProtocolStats as CompactProtocolStats, SendCmpct,
};
pub use compact_blocks::{
    BlockTxn, CompactBlock, CompactBlockHeader, CompactBlockRelay, CompactBlockResult,
    CompactBlockStats, GetBlockTxn, PrefilledTransaction, ShortTxId,
};
pub use connection::{Connection, ConnectionState};
pub use connection_retry::{
    ConnectionResult, ConnectionRetryManager, ConnectionRetryStats, RetryConfig, RetryState,
};
pub use discovery::{PeerAddress, PeerDiscovery};
pub use dos_protection::{BanEntry, DosProtectionConfig, DosProtectionManager, DosProtectionStats};
pub use headers_sync::{HeadersChain, HeadersStorage, HeadersSyncManager, HeadersSyncState};
pub use ibd::{IBDManager, IBDPhase, IBDState, IBDStats};
pub use manager::NetworkManager;
pub use message::{InvType, Inventory, Message, MessageHeader};
pub use orphan_pool::{OrphanEntry, OrphanPool, OrphanPoolStats};
pub use peer::{Peer, PeerState, PeerStats};
pub use peer_manager::{ConnectionStats, PeerInfo, PeerManager, PeerManagerConfig, ScoreEvent};
pub use peer_persistence::{PeerDatabase, PeerPersistence, PersistentPeer};
pub use rate_limiter::{
    BandwidthConfig, BandwidthManager, PeerRateLimiter, RateLimiter, RateLimiterStats,
};
pub use relay::{RelayManager, RelayStats};
pub use sync::{SyncManager, SyncState, SyncStats};
pub use sync_trait::SyncHandler;
pub use tx_relay::{TxAnnouncement, TxRelayStats, TxRequest, TxRequestTracker};
