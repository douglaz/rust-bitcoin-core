use crate::wire_compact_blocks::*;
use anyhow::{bail, Context, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::{Block, BlockHash, Transaction};
use serde::{Deserialize, Serialize};

/// Our own inventory type since bitcoin 0.32 changed Inventory to an enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvType {
    Error = 0,
    Tx = 1,
    Block = 2,
    FilteredBlock = 3,
    CompactBlock = 4,
    WitnessTx = 0x40000001,
    WitnessBlock = 0x40000002,
}

/// Our own inventory struct
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub inv_type: InvType,
    pub hash: BlockHash,
}

// Re-export SendCompact from compact_block_protocol module
pub use crate::compact_block_protocol::SendCmpct as SendCompact;

/// Simplified message type that wraps bitcoin crate's NetworkMessage
#[derive(Debug, Clone)]
pub enum Message {
    Version(VersionMessage),
    Verack,
    Ping(u64),
    Pong(u64),
    GetHeaders(GetHeadersMessage),
    Headers(Vec<BlockHeader>),
    GetBlocks(GetBlocksMessage),
    Block(Block),
    Tx(Transaction),
    GetAddr,
    Addr(Vec<(u32, bitcoin::p2p::address::Address)>),
    Inv(Vec<Inventory>),
    GetData(Vec<Inventory>),
    NotFound(Vec<Inventory>),
    MemPool,
    FeeFilter(i64),
    SendHeaders,
    // BIP152 Compact Blocks
    SendCompact(SendCompact),
    CompactBlock(crate::compact_blocks::CompactBlock),
    GetBlockTxn(crate::compact_blocks::GetBlockTxn),
    BlockTxn(crate::compact_blocks::BlockTxn),
    Other(NetworkMessage),
}

impl Message {
    /// Convert to bitcoin crate's NetworkMessage
    pub fn to_network_message(&self) -> NetworkMessage {
        match self {
            Message::Version(v) => NetworkMessage::Version(v.clone()),
            Message::Verack => NetworkMessage::Verack,
            Message::Ping(n) => NetworkMessage::Ping(*n),
            Message::Pong(n) => NetworkMessage::Pong(*n),
            Message::GetHeaders(g) => NetworkMessage::GetHeaders(g.clone()),
            Message::Headers(h) => NetworkMessage::Headers(h.clone()),
            Message::GetBlocks(g) => NetworkMessage::GetBlocks(g.clone()),
            Message::Block(b) => NetworkMessage::Block(b.clone()),
            Message::Tx(t) => NetworkMessage::Tx(t.clone()),
            Message::GetAddr => NetworkMessage::GetAddr,
            Message::Addr(a) => NetworkMessage::Addr(a.clone()),
            Message::MemPool => NetworkMessage::MemPool,
            Message::FeeFilter(f) => NetworkMessage::FeeFilter(*f),
            Message::SendHeaders => NetworkMessage::SendHeaders,
            Message::Other(m) => m.clone(),
            // Inv, GetData, NotFound need custom handling since bitcoin 0.32 changed Inventory
            Message::Inv(_) | Message::GetData(_) | Message::NotFound(_) => {
                // For now, return Unknown
                NetworkMessage::Unknown {
                    command: bitcoin::p2p::message::CommandString::try_from("unknown").unwrap(),
                    payload: vec![],
                }
            }
            // BIP152 Compact Blocks - serialize with proper wire protocol
            Message::SendCompact(sc) => {
                let payload = serialize_sendcmpct(sc).unwrap_or_default();
                NetworkMessage::Unknown {
                    command: bitcoin::p2p::message::CommandString::try_from("sendcmpct").unwrap(),
                    payload,
                }
            }
            Message::CompactBlock(cb) => {
                let payload = serialize_compact_block(cb).unwrap_or_default();
                NetworkMessage::Unknown {
                    command: bitcoin::p2p::message::CommandString::try_from("cmpctblock").unwrap(),
                    payload,
                }
            }
            Message::GetBlockTxn(gbt) => {
                let payload = serialize_getblocktxn(gbt).unwrap_or_default();
                NetworkMessage::Unknown {
                    command: bitcoin::p2p::message::CommandString::try_from("getblocktxn").unwrap(),
                    payload,
                }
            }
            Message::BlockTxn(bt) => {
                let payload = serialize_blocktxn(bt).unwrap_or_default();
                NetworkMessage::Unknown {
                    command: bitcoin::p2p::message::CommandString::try_from("blocktxn").unwrap(),
                    payload,
                }
            }
        }
    }

    /// Create from bitcoin crate's NetworkMessage
    pub fn from_network_message(msg: NetworkMessage) -> Self {
        match msg {
            NetworkMessage::Version(v) => Message::Version(v),
            NetworkMessage::Verack => Message::Verack,
            NetworkMessage::Ping(n) => Message::Ping(n),
            NetworkMessage::Pong(n) => Message::Pong(n),
            NetworkMessage::GetHeaders(g) => Message::GetHeaders(g),
            NetworkMessage::Headers(h) => Message::Headers(h),
            NetworkMessage::GetBlocks(g) => Message::GetBlocks(g),
            NetworkMessage::Block(b) => Message::Block(b),
            NetworkMessage::Tx(t) => Message::Tx(t),
            NetworkMessage::GetAddr => Message::GetAddr,
            NetworkMessage::Addr(a) => Message::Addr(a),
            NetworkMessage::MemPool => Message::MemPool,
            NetworkMessage::FeeFilter(f) => Message::FeeFilter(f),
            NetworkMessage::SendHeaders => Message::SendHeaders,
            // Handle Inv, GetData, NotFound specially for bitcoin 0.32
            _ => Message::Other(msg),
        }
    }

    /// Get command string for the message
    pub fn command(&self) -> &'static str {
        match self {
            Message::Version(_) => "version",
            Message::Verack => "verack",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::GetHeaders(_) => "getheaders",
            Message::Headers(_) => "headers",
            Message::GetBlocks(_) => "getblocks",
            Message::Block(_) => "block",
            Message::Tx(_) => "tx",
            Message::GetAddr => "getaddr",
            Message::Addr(_) => "addr",
            Message::Inv(_) => "inv",
            Message::GetData(_) => "getdata",
            Message::NotFound(_) => "notfound",
            Message::MemPool => "mempool",
            Message::FeeFilter(_) => "feefilter",
            Message::SendHeaders => "sendheaders",
            Message::SendCompact(_) => "sendcmpct",
            Message::CompactBlock(_) => "cmpctblock",
            Message::GetBlockTxn(_) => "getblocktxn",
            Message::BlockTxn(_) => "blocktxn",
            Message::Other(_) => "other",
        }
    }
}

/// Message header for P2P protocol
#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub magic: u32,
    pub command: [u8; 12],
    pub length: u32,
    pub checksum: u32,
}

impl MessageHeader {
    pub const SIZE: usize = 24;

    /// Parse header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            bail!("Insufficient data for message header");
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);

        let mut command = [0u8; 12];
        command.copy_from_slice(&data[4..16]);

        let mut length = [0u8; 4];
        length.copy_from_slice(&data[16..20]);

        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&data[20..24]);

        Ok(MessageHeader {
            magic: u32::from_le_bytes(magic),
            command,
            length: u32::from_le_bytes(length),
            checksum: u32::from_le_bytes(checksum),
        })
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.extend_from_slice(&self.magic.to_le_bytes());
        bytes.extend_from_slice(&self.command);
        bytes.extend_from_slice(&self.length.to_le_bytes());
        bytes.extend_from_slice(&self.checksum.to_le_bytes());
        bytes
    }

    /// Get command as string
    pub fn command_string(&self) -> String {
        let end = self.command.iter().position(|&b| b == 0).unwrap_or(12);
        String::from_utf8_lossy(&self.command[..end]).to_string()
    }
}

/// Serialize a message to bytes
pub fn serialize_message(msg: &Message, network_magic: bitcoin::p2p::Magic) -> Result<Vec<u8>> {
    let network_msg = msg.to_network_message();
    let raw_msg = RawNetworkMessage::new(network_magic, network_msg);

    let mut bytes = Vec::new();
    raw_msg
        .consensus_encode(&mut bytes)
        .context("Failed to serialize message")?;

    Ok(bytes)
}

/// Deserialize a message from bytes
pub fn deserialize_message(data: &[u8]) -> Result<(Message, usize)> {
    let mut cursor = std::io::Cursor::new(data);
    let raw_msg = RawNetworkMessage::consensus_decode(&mut cursor)
        .context("Failed to deserialize message")?;

    // Handle compact block messages specially
    let msg = match raw_msg.payload() {
        NetworkMessage::Unknown { command, payload } => match command.as_ref() {
            "sendcmpct" => {
                if let Ok(sc) = deserialize_sendcmpct(payload) {
                    Message::SendCompact(SendCompact {
                        high_bandwidth: sc.high_bandwidth,
                        version: sc.version,
                    })
                } else {
                    Message::from_network_message(raw_msg.payload().clone())
                }
            }
            "cmpctblock" => {
                if let Ok(cb) = deserialize_compact_block(payload) {
                    Message::CompactBlock(cb)
                } else {
                    Message::from_network_message(raw_msg.payload().clone())
                }
            }
            "getblocktxn" => {
                if let Ok(gbt) = deserialize_getblocktxn(payload) {
                    Message::GetBlockTxn(gbt)
                } else {
                    Message::from_network_message(raw_msg.payload().clone())
                }
            }
            "blocktxn" => {
                if let Ok(bt) = deserialize_blocktxn(payload) {
                    Message::BlockTxn(bt)
                } else {
                    Message::from_network_message(raw_msg.payload().clone())
                }
            }
            _ => Message::from_network_message(raw_msg.payload().clone()),
        },
        _ => Message::from_network_message(raw_msg.payload().clone()),
    };

    let bytes_read = cursor.position() as usize;

    Ok((msg, bytes_read))
}
