use anyhow::{bail, Result};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{OutPoint, Script, Transaction, Txid};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// BIP37 Bloom filter implementation for SPV clients
/// https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki

/// Maximum bloom filter size in bytes
const MAX_BLOOM_FILTER_SIZE: usize = 36000; // 36KB

/// Maximum number of hash functions
const MAX_HASH_FUNCS: u32 = 50;

/// Bloom filter flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BloomFlags {
    /// Never update the filter
    None = 0,
    /// Update filter when matching pubkey scripts are found
    All = 1,
    /// Update filter only when matching pay-to-pubkey or pay-to-multisig outputs are found
    PubKeyOnly = 2,
}

impl BloomFlags {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(BloomFlags::None),
            1 => Some(BloomFlags::All),
            2 => Some(BloomFlags::PubKeyOnly),
            _ => None,
        }
    }
}

/// Bloom filter for SPV clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomFilter {
    /// Filter data
    data: Vec<u8>,
    /// Number of hash functions to use
    n_hash_funcs: u32,
    /// Random nonce for hash functions
    n_tweak: u32,
    /// Filter update flags
    flags: BloomFlags,
    /// Number of elements added
    elements: u32,
    /// False positive rate
    fp_rate: f64,
}

impl BloomFilter {
    /// Create a new bloom filter
    pub fn new(elements: usize, fp_rate: f64, n_tweak: u32, flags: BloomFlags) -> Result<Self> {
        if fp_rate <= 0.0 || fp_rate >= 1.0 {
            bail!("False positive rate must be between 0 and 1");
        }

        // Calculate optimal filter size
        // n = -m * ln(p) / (ln(2)^2)
        // where n = filter size in bits, m = expected elements, p = false positive rate
        let ln2_squared = 0.4804530139182014; // ln(2)^2
        let filter_bits = (-(elements as f64) * fp_rate.ln() / ln2_squared).ceil() as usize;
        let filter_bytes = (filter_bits + 7) / 8;

        if filter_bytes > MAX_BLOOM_FILTER_SIZE {
            bail!(
                "Bloom filter size {} exceeds maximum {}",
                filter_bytes,
                MAX_BLOOM_FILTER_SIZE
            );
        }

        // Calculate optimal number of hash functions
        // k = (n/m) * ln(2)
        // where k = hash functions, n = filter size, m = expected elements
        let n_hash_funcs = if elements > 0 {
            let k = (filter_bits as f64 / elements as f64 * 0.693147).round() as u32;
            k.min(MAX_HASH_FUNCS).max(1)
        } else {
            1
        };

        Ok(Self {
            data: vec![0u8; filter_bytes],
            n_hash_funcs,
            n_tweak,
            flags,
            elements: 0,
            fp_rate,
        })
    }

    /// Create an empty filter (matches nothing)
    pub fn empty() -> Self {
        Self {
            data: vec![],
            n_hash_funcs: 0,
            n_tweak: 0,
            flags: BloomFlags::None,
            elements: 0,
            fp_rate: 1.0,
        }
    }

    /// Create a full filter (matches everything)
    pub fn full() -> Self {
        Self {
            data: vec![0xFF],
            n_hash_funcs: 1,
            n_tweak: 0,
            flags: BloomFlags::None,
            elements: 0,
            fp_rate: 0.0,
        }
    }

    /// Calculate hash for an element
    fn hash(&self, n_hash_num: u32, data: &[u8]) -> u32 {
        let seed = n_hash_num
            .wrapping_mul(0xFBA4C795)
            .wrapping_add(self.n_tweak);

        // MurmurHash3 algorithm
        let mut h = seed;
        let mut i = 0;

        while i + 4 <= data.len() {
            let k = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            h ^= k.wrapping_mul(0xcc9e2d51);
            h = h.rotate_left(15).wrapping_mul(0x1b873593);
            i += 4;
        }

        // Handle remaining bytes
        if i < data.len() {
            let mut k = 0u32;
            for j in 0..(data.len() - i) {
                k |= (data[i + j] as u32) << (j * 8);
            }
            h ^= k.wrapping_mul(0xcc9e2d51);
        }

        h ^= data.len() as u32;
        h ^= h >> 16;
        h = h.wrapping_mul(0x85ebca6b);
        h ^= h >> 13;
        h = h.wrapping_mul(0xc2b2ae35);
        h ^= h >> 16;

        (h as usize % (self.data.len() * 8)) as u32
    }

    /// Insert data into the filter
    pub fn insert(&mut self, data: &[u8]) {
        if self.data.is_empty() {
            return;
        }

        for i in 0..self.n_hash_funcs {
            let bit_pos = self.hash(i, data);
            let byte_idx = (bit_pos / 8) as usize;
            let bit_idx = (bit_pos % 8) as usize;

            if byte_idx < self.data.len() {
                self.data[byte_idx] |= 1 << bit_idx;
            }
        }

        self.elements += 1;
    }

    /// Check if data might be in the filter
    pub fn contains(&self, data: &[u8]) -> bool {
        if self.data.is_empty() {
            return false;
        }

        if self.data.len() == 1 && self.data[0] == 0xFF {
            return true; // Full filter matches everything
        }

        for i in 0..self.n_hash_funcs {
            let bit_pos = self.hash(i, data);
            let byte_idx = (bit_pos / 8) as usize;
            let bit_idx = (bit_pos % 8) as usize;

            if byte_idx >= self.data.len() {
                return false;
            }

            if (self.data[byte_idx] & (1 << bit_idx)) == 0 {
                return false;
            }
        }

        true
    }

    /// Insert an outpoint
    pub fn insert_outpoint(&mut self, outpoint: &OutPoint) {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&outpoint.txid.to_byte_array());
        data.extend_from_slice(&outpoint.vout.to_le_bytes());
        self.insert(&data);
    }

    /// Check if transaction is relevant to the filter
    pub fn is_relevant_tx(&self, tx: &Transaction) -> bool {
        // Check if any input outpoints match
        for input in &tx.input {
            if !input.previous_output.is_null() {
                let mut data = Vec::with_capacity(36);
                data.extend_from_slice(&input.previous_output.txid.to_byte_array());
                data.extend_from_slice(&input.previous_output.vout.to_le_bytes());

                if self.contains(&data) {
                    return true;
                }
            }
        }

        // Check if any output scripts match
        for output in &tx.output {
            if self.matches_output(&output.script_pubkey) {
                return true;
            }
        }

        // Check if transaction ID matches
        if self.contains(&tx.compute_txid().to_byte_array()) {
            return true;
        }

        false
    }

    /// Check if a script matches the filter
    pub fn matches_output(&self, script: &Script) -> bool {
        // Check the entire script
        if self.contains(script.as_bytes()) {
            return true;
        }

        // For pay-to-pubkey and pay-to-multisig, also check individual pubkeys
        // This is a simplified check - full implementation would parse script opcodes
        let script_bytes = script.as_bytes();

        // Check for data pushes that might be pubkeys (33 or 65 bytes)
        for window in script_bytes.windows(33) {
            if self.contains(window) {
                return true;
            }
        }

        for window in script_bytes.windows(65) {
            if self.contains(window) {
                return true;
            }
        }

        false
    }

    /// Update filter based on matched transaction
    pub fn update(&mut self, tx: &Transaction) -> Vec<OutPoint> {
        let mut added = Vec::new();

        match self.flags {
            BloomFlags::None => {
                // No updates
            }
            BloomFlags::All => {
                // Add all outputs that match
                for (vout, output) in tx.output.iter().enumerate() {
                    if self.matches_output(&output.script_pubkey) {
                        let outpoint = OutPoint {
                            txid: tx.compute_txid(),
                            vout: vout as u32,
                        };
                        self.insert_outpoint(&outpoint);
                        added.push(outpoint);
                    }
                }
            }
            BloomFlags::PubKeyOnly => {
                // Add only pay-to-pubkey and pay-to-multisig outputs
                // This is simplified - full implementation would properly detect script types
                for (vout, output) in tx.output.iter().enumerate() {
                    let script_bytes = output.script_pubkey.as_bytes();

                    // Simple heuristic: P2PK is ~67 bytes, P2MS varies
                    if script_bytes.len() >= 67 && script_bytes.len() <= 200 {
                        if self.matches_output(&output.script_pubkey) {
                            let outpoint = OutPoint {
                                txid: tx.compute_txid(),
                                vout: vout as u32,
                            };
                            self.insert_outpoint(&outpoint);
                            added.push(outpoint);
                        }
                    }
                }
            }
        }

        added
    }

    /// Clear the filter
    pub fn clear(&mut self) {
        self.data.fill(0);
        self.elements = 0;
    }

    /// Get filter statistics
    pub fn stats(&self) -> BloomFilterStats {
        let bits_set = self
            .data
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum();

        let total_bits = self.data.len() * 8;
        let fill_ratio = if total_bits > 0 {
            bits_set as f64 / total_bits as f64
        } else {
            0.0
        };

        BloomFilterStats {
            filter_size: self.data.len(),
            hash_funcs: self.n_hash_funcs,
            elements: self.elements,
            bits_set,
            total_bits,
            fill_ratio,
            fp_rate: self.fp_rate,
        }
    }

    /// Validate filter parameters
    pub fn validate(&self) -> Result<()> {
        if self.data.len() > MAX_BLOOM_FILTER_SIZE {
            bail!("Filter size exceeds maximum");
        }

        if self.n_hash_funcs > MAX_HASH_FUNCS {
            bail!("Too many hash functions");
        }

        Ok(())
    }

    /// Get filter data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get number of hash functions
    pub fn hash_funcs(&self) -> u32 {
        self.n_hash_funcs
    }

    /// Get tweak value
    pub fn tweak(&self) -> u32 {
        self.n_tweak
    }

    /// Get flags
    pub fn flags(&self) -> BloomFlags {
        self.flags
    }
}

/// Bloom filter statistics
#[derive(Debug, Clone)]
pub struct BloomFilterStats {
    pub filter_size: usize,
    pub hash_funcs: u32,
    pub elements: u32,
    pub bits_set: usize,
    pub total_bits: usize,
    pub fill_ratio: f64,
    pub fp_rate: f64,
}

/// SPV client filter manager
pub struct SPVFilterManager {
    filters: std::sync::RwLock<HashMap<std::net::SocketAddr, BloomFilter>>,
    max_filters_per_peer: usize,
}

impl SPVFilterManager {
    pub fn new(max_filters_per_peer: usize) -> Self {
        Self {
            filters: std::sync::RwLock::new(HashMap::new()),
            max_filters_per_peer,
        }
    }

    /// Load filter for a peer
    pub fn load_filter(&self, peer: std::net::SocketAddr, filter: BloomFilter) -> Result<()> {
        filter.validate()?;

        let mut filters = self.filters.write().unwrap();
        filters.insert(peer, filter);
        Ok(())
    }

    /// Clear filter for a peer
    pub fn clear_filter(&self, peer: &std::net::SocketAddr) {
        let mut filters = self.filters.write().unwrap();
        if let Some(filter) = filters.get_mut(peer) {
            filter.clear();
        }
    }

    /// Remove filter for a peer
    pub fn remove_filter(&self, peer: &std::net::SocketAddr) {
        let mut filters = self.filters.write().unwrap();
        filters.remove(peer);
    }

    /// Add element to peer's filter
    pub fn add_to_filter(&self, peer: &std::net::SocketAddr, data: &[u8]) {
        let mut filters = self.filters.write().unwrap();
        if let Some(filter) = filters.get_mut(peer) {
            filter.insert(data);
        }
    }

    /// Check if transaction is relevant for a peer
    pub fn is_relevant_tx(&self, peer: &std::net::SocketAddr, tx: &Transaction) -> bool {
        let filters = self.filters.read().unwrap();
        filters
            .get(peer)
            .map_or(true, |filter| filter.is_relevant_tx(tx))
    }

    /// Get filter for a peer
    pub fn get_filter(&self, peer: &std::net::SocketAddr) -> Option<BloomFilter> {
        let filters = self.filters.read().unwrap();
        filters.get(peer).cloned()
    }
}

use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let mut filter = BloomFilter::new(10, 0.01, 0, BloomFlags::None).unwrap();

        let data1 = b"hello";
        let data2 = b"world";
        let data3 = b"test";

        filter.insert(data1);
        filter.insert(data2);

        assert!(filter.contains(data1));
        assert!(filter.contains(data2));
        assert!(!filter.contains(data3));
    }

    #[test]
    fn test_bloom_filter_outpoint() {
        let mut filter = BloomFilter::new(10, 0.01, 0, BloomFlags::None).unwrap();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };

        filter.insert_outpoint(&outpoint);

        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&outpoint.txid.to_byte_array());
        data.extend_from_slice(&outpoint.vout.to_le_bytes());

        assert!(filter.contains(&data));
    }

    #[test]
    fn test_empty_and_full_filters() {
        let empty = BloomFilter::empty();
        assert!(!empty.contains(b"anything"));

        let full = BloomFilter::full();
        assert!(full.contains(b"anything"));
    }
}
