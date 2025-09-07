use anyhow::{bail, Result};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Transaction, VarInt};
use bitcoin::io::{Read, Write};

use crate::compact_blocks::{
    BlockTxn, CompactBlock, CompactBlockHeader, GetBlockTxn, PrefilledTransaction, ShortTxId,
};
use crate::compact_block_protocol::SendCmpct;

/// Wire protocol serialization for BIP152 Compact Blocks

impl Encodable for SendCmpct {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += (self.high_bandwidth as u8).consensus_encode(w)?;
        len += self.version.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for SendCmpct {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, bitcoin::consensus::encode::Error> {
        let high_bandwidth_byte = u8::consensus_decode(r)?;
        let high_bandwidth = high_bandwidth_byte != 0;
        let version = u64::consensus_decode(r)?;
        
        Ok(SendCmpct {
            high_bandwidth,
            version,
        })
    }
}

impl Encodable for ShortTxId {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        self.as_bytes().consensus_encode(w)
    }
}

impl Decodable for ShortTxId {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, bitcoin::consensus::encode::Error> {
        let mut bytes = [0u8; 6];
        r.read_exact(&mut bytes)?;
        Ok(ShortTxId(bytes))
    }
}

impl Encodable for PrefilledTransaction {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        // Use compact size encoding for index
        len += VarInt(self.index as u64).consensus_encode(w)?;
        len += self.tx.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for PrefilledTransaction {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, bitcoin::consensus::encode::Error> {
        let index = VarInt::consensus_decode(r)?.0 as u16;
        let tx = Transaction::consensus_decode(r)?;
        
        Ok(PrefilledTransaction { index, tx })
    }
}

impl Encodable for CompactBlockHeader {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.header.consensus_encode(w)?;
        len += self.nonce.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for CompactBlockHeader {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, bitcoin::consensus::encode::Error> {
        let header = bitcoin::block::Header::consensus_decode(r)?;
        let nonce = u64::consensus_decode(r)?;
        
        Ok(CompactBlockHeader { header, nonce })
    }
}

impl Encodable for CompactBlock {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.header.consensus_encode(w)?;
        
        // Encode short IDs count and list
        len += VarInt(self.short_ids.len() as u64).consensus_encode(w)?;
        for short_id in &self.short_ids {
            len += short_id.consensus_encode(w)?;
        }
        
        // Encode prefilled transactions count and list
        len += VarInt(self.prefilled_txs.len() as u64).consensus_encode(w)?;
        for prefilled in &self.prefilled_txs {
            len += prefilled.consensus_encode(w)?;
        }
        
        Ok(len)
    }
}

impl Decodable for CompactBlock {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, bitcoin::consensus::encode::Error> {
        let header = CompactBlockHeader::consensus_decode(r)?;
        
        // Decode short IDs
        let short_ids_count = VarInt::consensus_decode(r)?.0 as usize;
        let mut short_ids = Vec::with_capacity(short_ids_count);
        for _ in 0..short_ids_count {
            short_ids.push(ShortTxId::consensus_decode(r)?);
        }
        
        // Decode prefilled transactions
        let prefilled_count = VarInt::consensus_decode(r)?.0 as usize;
        let mut prefilled_txs = Vec::with_capacity(prefilled_count);
        for _ in 0..prefilled_count {
            prefilled_txs.push(PrefilledTransaction::consensus_decode(r)?);
        }
        
        Ok(CompactBlock {
            header,
            short_ids,
            prefilled_txs,
        })
    }
}

impl Encodable for GetBlockTxn {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.block_hash.consensus_encode(w)?;
        
        // Encode indexes using differential encoding
        len += VarInt(self.indexes.len() as u64).consensus_encode(w)?;
        
        let mut last_index = 0u16;
        for &index in &self.indexes {
            let diff = index - last_index;
            len += VarInt(diff as u64).consensus_encode(w)?;
            last_index = index + 1; // Next diff is relative to index + 1
        }
        
        Ok(len)
    }
}

impl Decodable for GetBlockTxn {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, bitcoin::consensus::encode::Error> {
        let block_hash = BlockHash::consensus_decode(r)?;
        
        // Decode indexes using differential encoding
        let count = VarInt::consensus_decode(r)?.0 as usize;
        let mut indexes = Vec::with_capacity(count);
        
        let mut last_index = 0u16;
        for _ in 0..count {
            let diff = VarInt::consensus_decode(r)?.0 as u16;
            last_index += diff;
            indexes.push(last_index);
            last_index += 1; // Next diff is relative to index + 1
        }
        
        Ok(GetBlockTxn {
            block_hash,
            indexes,
        })
    }
}

impl Encodable for BlockTxn {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.block_hash.consensus_encode(w)?;
        
        // Encode transactions
        len += VarInt(self.transactions.len() as u64).consensus_encode(w)?;
        for tx in &self.transactions {
            len += tx.consensus_encode(w)?;
        }
        
        Ok(len)
    }
}

impl Decodable for BlockTxn {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, bitcoin::consensus::encode::Error> {
        let block_hash = BlockHash::consensus_decode(r)?;
        
        // Decode transactions
        let count = VarInt::consensus_decode(r)?.0 as usize;
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            transactions.push(Transaction::consensus_decode(r)?);
        }
        
        Ok(BlockTxn {
            block_hash,
            transactions,
        })
    }
}

/// Serialize compact block message to bytes
pub fn serialize_sendcmpct(msg: &SendCmpct) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    msg.consensus_encode(&mut bytes)
        .map_err(|e| anyhow::anyhow!("Failed to serialize SendCmpct: {}", e))?;
    Ok(bytes)
}

/// Deserialize SendCmpct from bytes
pub fn deserialize_sendcmpct(data: &[u8]) -> Result<SendCmpct> {
    let mut cursor = bitcoin::io::Cursor::new(data);
    SendCmpct::consensus_decode(&mut cursor)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize SendCmpct: {}", e))
}

/// Serialize CompactBlock to bytes
pub fn serialize_compact_block(block: &CompactBlock) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    block.consensus_encode(&mut bytes)
        .map_err(|e| anyhow::anyhow!("Failed to serialize CompactBlock: {}", e))?;
    Ok(bytes)
}

/// Deserialize CompactBlock from bytes
pub fn deserialize_compact_block(data: &[u8]) -> Result<CompactBlock> {
    let mut cursor = bitcoin::io::Cursor::new(data);
    CompactBlock::consensus_decode(&mut cursor)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize CompactBlock: {}", e))
}

/// Serialize GetBlockTxn to bytes
pub fn serialize_getblocktxn(msg: &GetBlockTxn) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    msg.consensus_encode(&mut bytes)
        .map_err(|e| anyhow::anyhow!("Failed to serialize GetBlockTxn: {}", e))?;
    Ok(bytes)
}

/// Deserialize GetBlockTxn from bytes
pub fn deserialize_getblocktxn(data: &[u8]) -> Result<GetBlockTxn> {
    let mut cursor = bitcoin::io::Cursor::new(data);
    GetBlockTxn::consensus_decode(&mut cursor)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize GetBlockTxn: {}", e))
}

/// Serialize BlockTxn to bytes
pub fn serialize_blocktxn(msg: &BlockTxn) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    msg.consensus_encode(&mut bytes)
        .map_err(|e| anyhow::anyhow!("Failed to serialize BlockTxn: {}", e))?;
    Ok(bytes)
}

/// Deserialize BlockTxn from bytes
pub fn deserialize_blocktxn(data: &[u8]) -> Result<BlockTxn> {
    let mut cursor = bitcoin::io::Cursor::new(data);
    BlockTxn::consensus_decode(&mut cursor)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize BlockTxn: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_sendcmpct_serialization() -> Result<()> {
        let msg = SendCmpct {
            high_bandwidth: true,
            version: 2,
        };

        let bytes = serialize_sendcmpct(&msg)?;
        let decoded = deserialize_sendcmpct(&bytes)?;

        assert_eq!(decoded.high_bandwidth, msg.high_bandwidth);
        assert_eq!(decoded.version, msg.version);
        Ok(())
    }

    #[test]
    fn test_compact_block_serialization() -> Result<()> {
        let block = bitcoin::blockdata::constants::genesis_block(Network::Bitcoin);
        let compact = CompactBlock::from_block(&block, Some(42));

        let bytes = serialize_compact_block(&compact)?;
        let decoded = deserialize_compact_block(&bytes)?;

        assert_eq!(decoded.header.nonce, compact.header.nonce);
        assert_eq!(decoded.short_ids.len(), compact.short_ids.len());
        assert_eq!(decoded.prefilled_txs.len(), compact.prefilled_txs.len());
        Ok(())
    }

    #[test]
    fn test_getblocktxn_differential_encoding() -> Result<()> {
        let msg = GetBlockTxn {
            block_hash: BlockHash::all_zeros(),
            indexes: vec![0, 2, 5, 10], // Will be encoded as diffs: 0, 2, 3, 5
        };

        let bytes = serialize_getblocktxn(&msg)?;
        let decoded = deserialize_getblocktxn(&bytes)?;

        assert_eq!(decoded.block_hash, msg.block_hash);
        assert_eq!(decoded.indexes, msg.indexes);
        Ok(())
    }
}