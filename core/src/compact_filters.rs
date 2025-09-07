use anyhow::{bail, Result};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Block, BlockHash, Script};
use std::collections::{HashMap, HashSet};

/// BIP157/158 Compact Block Filters implementation
pub struct CompactFilterBuilder {
    /// Filter type
    filter_type: FilterType,

    /// Parameters
    params: FilterParams,
}

/// Filter types defined in BIP158
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FilterType {
    /// Basic filter (P = 19, M = 784931)
    Basic,
    /// Extended filter (future use)
    Extended,
}

/// Filter parameters
#[derive(Debug, Clone)]
pub struct FilterParams {
    /// Golomb-Rice parameter P
    pub p: u8,
    /// Modulus M = 2^P * N
    pub m_multiplier: u64,
}

impl Default for FilterParams {
    fn default() -> Self {
        // BIP158 basic filter parameters
        Self {
            p: 19,
            m_multiplier: 784931,
        }
    }
}

/// Compact filter
#[derive(Debug, Clone)]
pub struct CompactFilter {
    /// Filter type
    pub filter_type: FilterType,

    /// Block hash this filter is for
    pub block_hash: BlockHash,

    /// Filter data (Golomb-coded)
    pub filter_data: Vec<u8>,

    /// Number of elements in the filter
    pub n: u32,
}

impl CompactFilter {
    /// Check if filter matches any of the given scripts
    pub fn matches(&self, scripts: &[&Script]) -> Result<bool> {
        if scripts.is_empty() {
            return Ok(false);
        }

        // Decode filter
        let params = match self.filter_type {
            FilterType::Basic => FilterParams::default(),
            FilterType::Extended => bail!("Extended filters not yet supported"),
        };

        let elements = self.decode_filter(&params)?;

        // Hash scripts and check for matches
        for script in scripts {
            let hash = Self::hash_script_element(script, &self.block_hash);
            if elements.contains(&hash) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Decode the Golomb-coded filter
    fn decode_filter(&self, params: &FilterParams) -> Result<HashSet<u64>> {
        let mut reader = GolombDecoder::new(&self.filter_data, params.p);
        let mut elements = HashSet::new();
        let mut last_value = 0u64;

        for _ in 0..self.n {
            let delta = reader.read_value()?;
            last_value += delta;
            elements.insert(last_value);
        }

        Ok(elements)
    }

    /// Hash a script element for the filter
    fn hash_script_element(script: &Script, block_hash: &BlockHash) -> u64 {
        use bitcoin::hashes::Hash;

        let mut data = Vec::new();
        data.extend_from_slice(block_hash.as_ref());
        data.extend_from_slice(script.as_bytes());

        let hash = sha256::Hash::hash(&data);
        let bytes: &[u8] = hash.as_ref();

        // Take first 8 bytes as u64
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }
}

impl CompactFilterBuilder {
    /// Create new filter builder
    pub fn new(filter_type: FilterType) -> Self {
        let params = match filter_type {
            FilterType::Basic => FilterParams::default(),
            FilterType::Extended => FilterParams {
                p: 19,
                m_multiplier: 784931, // Same as basic for now
            },
        };

        Self {
            filter_type,
            params,
        }
    }

    /// Build filter for a block
    pub fn build_filter(&self, block: &Block) -> Result<CompactFilter> {
        let elements = match self.filter_type {
            FilterType::Basic => self.extract_basic_elements(block)?,
            FilterType::Extended => self.extract_extended_elements(block)?,
        };

        if elements.is_empty() {
            // Empty filter
            return Ok(CompactFilter {
                filter_type: self.filter_type,
                block_hash: block.block_hash(),
                filter_data: vec![],
                n: 0,
            });
        }

        // Hash and sort elements
        let block_hash = block.block_hash();
        let mut hashed: Vec<u64> = elements
            .iter()
            .map(|elem| Self::hash_element(elem, &block_hash))
            .collect();
        hashed.sort_unstable();
        hashed.dedup();

        // Encode using Golomb-Rice coding
        let filter_data = self.encode_filter(&hashed)?;

        Ok(CompactFilter {
            filter_type: self.filter_type,
            block_hash,
            filter_data,
            n: hashed.len() as u32,
        })
    }

    /// Extract basic filter elements from block
    fn extract_basic_elements(&self, block: &Block) -> Result<Vec<Vec<u8>>> {
        let mut elements = Vec::new();

        for tx in &block.txdata {
            // Add spent outpoints (except coinbase)
            if !tx.is_coinbase() {
                for input in &tx.input {
                    let mut data = Vec::new();
                    data.extend_from_slice(input.previous_output.txid.as_ref());
                    data.extend_from_slice(&input.previous_output.vout.to_le_bytes());
                    elements.push(data);
                }
            }

            // Add output scripts
            for output in &tx.output {
                elements.push(output.script_pubkey.to_bytes());
            }
        }

        Ok(elements)
    }

    /// Extract extended filter elements from block
    fn extract_extended_elements(&self, block: &Block) -> Result<Vec<Vec<u8>>> {
        let mut elements = Vec::new();

        for tx in &block.txdata {
            // Add witness scripts
            for input in &tx.input {
                for witness_elem in &input.witness.to_vec() {
                    if !witness_elem.is_empty() {
                        elements.push(witness_elem.clone());
                    }
                }
            }

            // Add transaction IDs
            let txid = tx.compute_txid();
            let txid_bytes: &[u8] = txid.as_ref();
            elements.push(txid_bytes.to_vec());
        }

        Ok(elements)
    }

    /// Hash an element for the filter
    fn hash_element(data: &[u8], block_hash: &BlockHash) -> u64 {
        use bitcoin::hashes::Hash;

        let mut hasher_data = Vec::new();
        hasher_data.extend_from_slice(block_hash.as_ref());
        hasher_data.extend_from_slice(data);

        let hash = sha256::Hash::hash(&hasher_data);
        let bytes: &[u8] = hash.as_ref();

        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    /// Encode filter using Golomb-Rice coding
    fn encode_filter(&self, sorted_hashes: &[u64]) -> Result<Vec<u8>> {
        if sorted_hashes.is_empty() {
            return Ok(vec![]);
        }

        let n = sorted_hashes.len() as u64;
        let m = self.params.m_multiplier * n;

        let mut encoder = GolombEncoder::new(self.params.p);
        let mut last_value = 0u64;

        for &hash in sorted_hashes {
            // Map to [0, M)
            let value = hash % m;

            // Encode delta
            let delta = value.saturating_sub(last_value);
            encoder.write_value(delta)?;
            last_value = value;
        }

        Ok(encoder.finish())
    }
}

/// Golomb-Rice encoder
struct GolombEncoder {
    p: u8,
    buffer: Vec<u8>,
    bit_writer: BitWriter,
}

impl GolombEncoder {
    fn new(p: u8) -> Self {
        Self {
            p,
            buffer: Vec::new(),
            bit_writer: BitWriter::new(),
        }
    }

    fn write_value(&mut self, value: u64) -> Result<()> {
        // Split value into quotient and remainder
        let quotient = value >> self.p;
        let remainder = value & ((1 << self.p) - 1);

        // Write quotient in unary
        for _ in 0..quotient {
            self.bit_writer.write_bit(true);
        }
        self.bit_writer.write_bit(false);

        // Write remainder in binary
        for i in (0..self.p).rev() {
            self.bit_writer.write_bit((remainder >> i) & 1 == 1);
        }

        Ok(())
    }

    fn finish(mut self) -> Vec<u8> {
        self.bit_writer.flush_to(&mut self.buffer);
        self.buffer
    }
}

/// Golomb-Rice decoder
struct GolombDecoder<'a> {
    p: u8,
    bit_reader: BitReader<'a>,
}

impl<'a> GolombDecoder<'a> {
    fn new(data: &'a [u8], p: u8) -> Self {
        Self {
            p,
            bit_reader: BitReader::new(data),
        }
    }

    fn read_value(&mut self) -> Result<u64> {
        // Read quotient in unary
        let mut quotient = 0u64;
        while self.bit_reader.read_bit()? {
            quotient += 1;
        }

        // Read remainder in binary
        let mut remainder = 0u64;
        for _ in 0..self.p {
            remainder <<= 1;
            if self.bit_reader.read_bit()? {
                remainder |= 1;
            }
        }

        Ok((quotient << self.p) | remainder)
    }
}

/// Bit writer for encoding
struct BitWriter {
    buffer: Vec<u8>,
    current_byte: u8,
    bit_position: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            current_byte: 0,
            bit_position: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1 << (7 - self.bit_position);
        }
        self.bit_position += 1;

        if self.bit_position == 8 {
            self.buffer.push(self.current_byte);
            self.current_byte = 0;
            self.bit_position = 0;
        }
    }

    fn flush_to(&mut self, output: &mut Vec<u8>) {
        if self.bit_position > 0 {
            self.buffer.push(self.current_byte);
        }
        output.extend_from_slice(&self.buffer);
    }
}

/// Bit reader for decoding
struct BitReader<'a> {
    data: &'a [u8],
    byte_position: usize,
    bit_position: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_position: 0,
            bit_position: 0,
        }
    }

    fn read_bit(&mut self) -> Result<bool> {
        if self.byte_position >= self.data.len() {
            bail!("End of data");
        }

        let bit = (self.data[self.byte_position] >> (7 - self.bit_position)) & 1 == 1;
        self.bit_position += 1;

        if self.bit_position == 8 {
            self.byte_position += 1;
            self.bit_position = 0;
        }

        Ok(bit)
    }
}

/// Filter header chain
pub struct FilterHeaderChain {
    /// Headers by height
    headers: HashMap<u32, FilterHeader>,

    /// Tip height
    tip_height: Option<u32>,
}

/// Filter header
#[derive(Debug, Clone)]
pub struct FilterHeader {
    pub height: u32,
    pub block_hash: BlockHash,
    pub filter_hash: [u8; 32],
    pub prev_header: [u8; 32],
    pub header: [u8; 32],
}

impl Default for FilterHeaderChain {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterHeaderChain {
    /// Create new filter header chain
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
            tip_height: None,
        }
    }

    /// Add a filter header
    pub fn add_header(&mut self, header: FilterHeader) -> Result<()> {
        // Verify header chain
        if header.height > 0 {
            let prev = self
                .headers
                .get(&(header.height - 1))
                .ok_or_else(|| anyhow::anyhow!("Missing previous header"))?;

            if prev.header != header.prev_header {
                bail!("Header chain mismatch");
            }
        }

        self.headers.insert(header.height, header.clone());

        if self.tip_height.map_or(true, |h| header.height > h) {
            self.tip_height = Some(header.height);
        }

        Ok(())
    }

    /// Get filter header at height
    pub fn get_header(&self, height: u32) -> Option<&FilterHeader> {
        self.headers.get(&height)
    }

    /// Calculate filter header from filter
    pub fn calculate_header(filter: &CompactFilter, prev_header: [u8; 32]) -> [u8; 32] {
        use bitcoin::hashes::Hash;

        let mut data = Vec::new();
        data.extend_from_slice(&filter.filter_data);
        data.extend_from_slice(&prev_header);

        let inner_hash = sha256::Hash::hash(&data);
        let hash = sha256::Hash::hash(inner_hash.as_ref());
        let mut header = [0u8; 32];
        header.copy_from_slice(hash.as_ref());
        header
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_golomb_encoding() {
        let mut encoder = GolombEncoder::new(19);
        encoder.write_value(1234567).unwrap();
        encoder.write_value(2345678).unwrap();
        let encoded = encoder.finish();

        let mut decoder = GolombDecoder::new(&encoded, 19);
        assert_eq!(decoder.read_value().unwrap(), 1234567);
        assert_eq!(decoder.read_value().unwrap(), 2345678);
    }

    #[test]
    fn test_filter_building() {
        use bitcoin::Network;

        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin);
        let builder = CompactFilterBuilder::new(FilterType::Basic);

        let filter = builder.build_filter(&genesis).unwrap();
        assert!(filter.n > 0);
        assert!(!filter.filter_data.is_empty());
    }
}
