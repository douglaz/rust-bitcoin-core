use anyhow::{bail, Context, Result};
use bitcoin::{
    block::Header as BlockHeader,
    consensus::{Decodable, Encodable},
    hashes::{Hash, HashEngine},
    Block, BlockHash, OutPoint, Script, Transaction, TxOut, Txid,
};
use std::io::Cursor;

/// Bitcoin block with full parsing and validation support
pub struct BitcoinBlock {
    /// The actual block
    pub block: Block,
    /// Cached block hash
    pub hash: BlockHash,
    /// Block height (if known)
    pub height: Option<u32>,
    /// Block size in bytes
    pub size: usize,
    /// Block weight
    pub weight: usize,
    /// Number of transactions
    pub tx_count: usize,
}

impl BitcoinBlock {
    /// Parse block from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        let block = Block::consensus_decode(&mut cursor).context("Failed to decode block")?;

        let hash = block.block_hash();
        let size = data.len();
        let weight = Self::calculate_weight(&block);
        let tx_count = block.txdata.len();

        Ok(Self {
            block,
            hash,
            height: None,
            size,
            weight,
            tx_count,
        })
    }

    /// Serialize block to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.block
            .consensus_encode(&mut buffer)
            .context("Failed to encode block")?;
        Ok(buffer)
    }

    /// Calculate block weight (BIP 141)
    fn calculate_weight(block: &Block) -> usize {
        // Weight = (base size * 3) + total size
        let base_size = Self::calculate_base_size(block);
        let total_size = Self::calculate_total_size(block);
        (base_size * 3) + total_size
    }

    /// Calculate base size (without witness data)
    fn calculate_base_size(block: &Block) -> usize {
        let mut size = 80; // Block header
        size += varint_len(block.txdata.len());

        for tx in &block.txdata {
            size += Self::calculate_tx_base_size(tx);
        }

        size
    }

    /// Calculate total size (with witness data)
    fn calculate_total_size(block: &Block) -> usize {
        let mut buffer = Vec::new();
        block.consensus_encode(&mut buffer).unwrap_or(0);
        buffer.len()
    }

    /// Calculate transaction base size
    fn calculate_tx_base_size(tx: &Transaction) -> usize {
        let mut size = 4; // Version
        size += varint_len(tx.input.len());

        for input in &tx.input {
            size += 32; // Previous output hash
            size += 4; // Previous output index
            size += varint_len(input.script_sig.len());
            size += input.script_sig.len();
            size += 4; // Sequence
        }

        size += varint_len(tx.output.len());
        for output in &tx.output {
            size += 8; // Value
            size += varint_len(output.script_pubkey.len());
            size += output.script_pubkey.len();
        }

        size += 4; // Lock time
        size
    }

    /// Verify merkle root
    pub fn verify_merkle_root(&self) -> bool {
        let calculated = crate::merkle::calculate_merkle_root(&self.block.txdata);
        calculated == self.block.header.merkle_root
    }

    /// Get coinbase transaction
    pub fn coinbase_tx(&self) -> Option<&Transaction> {
        self.block.txdata.first()
    }

    /// Check if this is a valid coinbase transaction
    pub fn has_valid_coinbase(&self) -> bool {
        if let Some(tx) = self.coinbase_tx() {
            // Coinbase must have exactly one input
            if tx.input.len() != 1 {
                return false;
            }

            // Input must reference null outpoint (all zeros txid and 0xffffffff vout)
            let input = &tx.input[0];
            input.previous_output.is_null()
        } else {
            false
        }
    }
}

/// Bitcoin transaction with full parsing support
pub struct BitcoinTransaction {
    /// The actual transaction
    pub tx: Transaction,
    /// Cached txid
    pub txid: Txid,
    /// Cached wtxid (witness txid)
    pub wtxid: bitcoin::Wtxid,
    /// Transaction size
    pub size: usize,
    /// Transaction weight
    pub weight: usize,
    /// Virtual size (vsize)
    pub vsize: usize,
    /// Is segwit transaction
    pub is_segwit: bool,
}

impl BitcoinTransaction {
    /// Parse transaction from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        let tx =
            Transaction::consensus_decode(&mut cursor).context("Failed to decode transaction")?;

        let txid = tx.compute_txid();
        let wtxid = tx.compute_wtxid();
        let size = data.len();
        let is_segwit = tx.input.iter().any(|input| !input.witness.is_empty());

        let weight = Self::calculate_weight(&tx);
        let vsize = weight.div_ceil(4); // Round up

        Ok(Self {
            tx,
            txid,
            wtxid,
            size,
            weight,
            vsize,
            is_segwit,
        })
    }

    /// Serialize transaction to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.tx
            .consensus_encode(&mut buffer)
            .context("Failed to encode transaction")?;
        Ok(buffer)
    }

    /// Calculate transaction weight
    fn calculate_weight(tx: &Transaction) -> usize {
        let base_size = Self::calculate_base_size(tx);
        let total_size = Self::calculate_total_size(tx);
        (base_size * 3) + total_size
    }

    /// Calculate base size (without witness)
    fn calculate_base_size(tx: &Transaction) -> usize {
        let mut size = 4; // Version
        size += varint_len(tx.input.len());

        for input in &tx.input {
            size += 32 + 4; // Outpoint
            size += varint_len(input.script_sig.len());
            size += input.script_sig.len();
            size += 4; // Sequence
        }

        size += varint_len(tx.output.len());
        for output in &tx.output {
            size += 8; // Value
            size += varint_len(output.script_pubkey.len());
            size += output.script_pubkey.len();
        }

        size += 4; // Lock time
        size
    }

    /// Calculate total size (with witness)
    fn calculate_total_size(tx: &Transaction) -> usize {
        let mut buffer = Vec::new();
        tx.consensus_encode(&mut buffer).unwrap_or(0);
        buffer.len()
    }

    /// Check if transaction is coinbase
    pub fn is_coinbase(&self) -> bool {
        self.tx.is_coinbase()
    }

    /// Calculate fee if we have input values
    pub fn calculate_fee(&self, input_values: &[u64]) -> Option<u64> {
        if input_values.len() != self.tx.input.len() {
            return None;
        }

        let total_in: u64 = input_values.iter().sum();
        let total_out: u64 = self.tx.output.iter().map(|out| out.value.to_sat()).sum();

        if total_in >= total_out {
            Some(total_in - total_out)
        } else {
            None
        }
    }

    /// Get fee rate in sats/vbyte if fee is known
    pub fn fee_rate(&self, fee: u64) -> f64 {
        fee as f64 / self.vsize as f64
    }
}

/// Block header with parsing and validation
pub struct BitcoinBlockHeader {
    /// The actual header
    pub header: BlockHeader,
    /// Cached hash
    pub hash: BlockHash,
    /// Difficulty target as compact bits
    pub bits: u32,
    /// Actual difficulty value
    pub difficulty: f64,
}

impl BitcoinBlockHeader {
    /// Parse header from 80 bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != 80 {
            bail!("Block header must be exactly 80 bytes");
        }

        let mut cursor = Cursor::new(data);
        let header =
            BlockHeader::consensus_decode(&mut cursor).context("Failed to decode block header")?;

        let hash = header.block_hash();
        let bits = header.bits.to_consensus();
        let difficulty = Self::calculate_difficulty(bits);

        Ok(Self {
            header,
            hash,
            bits,
            difficulty,
        })
    }

    /// Calculate difficulty from compact bits
    fn calculate_difficulty(bits: u32) -> f64 {
        let max_target = 0x1d00ffff_u32;
        let (max_exp, max_mant) = Self::decode_compact(max_target);
        let (exp, mant) = Self::decode_compact(bits);

        let max_diff = (max_mant as f64) * 256_f64.powi(max_exp as i32 - 3);
        let diff = (mant as f64) * 256_f64.powi(exp as i32 - 3);

        if diff > 0.0 {
            max_diff / diff
        } else {
            0.0
        }
    }

    /// Decode compact bits format
    fn decode_compact(bits: u32) -> (u32, u32) {
        let exp = bits >> 24;
        let mant = bits & 0x00ffffff;
        (exp, mant)
    }

    /// Verify proof of work
    pub fn verify_pow(&self) -> bool {
        let target = self.header.target();
        let hash = self.header.block_hash();

        // Convert hash to big-endian number for comparison
        let mut hash_bytes: Vec<u8> = hash.as_byte_array().to_vec();
        hash_bytes.reverse();

        let hash_num = num_bigint::BigUint::from_bytes_be(&hash_bytes);
        let target_num = num_bigint::BigUint::from_bytes_be(&target.to_be_bytes());

        hash_num <= target_num
    }

    /// Check if header is valid
    pub fn is_valid(&self) -> bool {
        // Check proof of work
        if !self.verify_pow() {
            return false;
        }

        // Check timestamp (not too far in future)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        if self.header.time > now + 2 * 60 * 60 {
            return false; // More than 2 hours in future
        }

        true
    }
}

/// Helper function to calculate variable integer length
fn varint_len(n: usize) -> usize {
    match n {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x10000..=0xFFFFFFFF => 5,
        _ => 9,
    }
}

/// UTXO (Unspent Transaction Output)
#[derive(Debug, Clone)]
pub struct Utxo {
    /// The output
    pub output: TxOut,
    /// The outpoint referencing this UTXO
    pub outpoint: OutPoint,
    /// Block height where this UTXO was created
    pub height: u32,
    /// Is this a coinbase output
    pub is_coinbase: bool,
}

impl Utxo {
    /// Create new UTXO
    pub fn new(output: TxOut, outpoint: OutPoint, height: u32, is_coinbase: bool) -> Self {
        Self {
            output,
            outpoint,
            height,
            is_coinbase,
        }
    }

    /// Check if UTXO is mature (for coinbase)
    pub fn is_mature(&self, current_height: u32) -> bool {
        if !self.is_coinbase {
            return true;
        }

        // Coinbase outputs need 100 confirmations
        current_height >= self.height + 100
    }

    /// Get the value in satoshis
    pub fn value(&self) -> u64 {
        self.output.value.to_sat()
    }

    /// Get the script pubkey
    pub fn script_pubkey(&self) -> &Script {
        &self.output.script_pubkey
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::ScriptBuf;

    #[test]
    fn test_block_parsing() {
        // Genesis block header (80 bytes)
        let genesis_header_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
        let header_bytes = Vec::from_hex(genesis_header_hex).unwrap();

        let header = BitcoinBlockHeader::from_bytes(&header_bytes).unwrap();
        assert_eq!(header.header.version.to_consensus(), 1);
        assert!(header.is_valid());
    }

    #[test]
    fn test_transaction_parsing() {
        // Create a simple transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(50000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let btc_tx = BitcoinTransaction {
            tx: tx.clone(),
            txid: tx.compute_txid(),
            wtxid: tx.compute_wtxid(),
            size: 100,
            weight: 400,
            vsize: 100,
            is_segwit: false,
        };

        assert!(!btc_tx.is_coinbase());
        assert_eq!(btc_tx.tx.output[0].value.to_sat(), 50000);
    }

    #[test]
    fn test_merkle_root_calculation() {
        // Test with single transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let root = crate::merkle::calculate_merkle_root(&[tx.clone()]).to_raw_hash();
        assert_eq!(root, tx.compute_txid().to_raw_hash());
    }
}
