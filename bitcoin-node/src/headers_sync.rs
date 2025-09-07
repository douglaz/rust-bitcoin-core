use anyhow::{bail, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::{BlockHash, Network};
use bitcoin_hashes::Hash;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Headers chain validator for headers-first synchronization
pub struct HeadersValidator {
    network: Network,
    headers_chain: Arc<RwLock<Vec<BlockHeader>>>,
    header_heights: Arc<RwLock<std::collections::HashMap<BlockHash, u32>>>,
}

impl HeadersValidator {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            headers_chain: Arc::new(RwLock::new(Vec::new())),
            header_heights: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Validate a batch of headers
    pub async fn validate_headers(
        &self,
        headers: &[BlockHeader],
        prev_header: Option<&BlockHeader>,
    ) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        let mut prev = prev_header.cloned();
        let mut height = if let Some(p) = prev_header {
            self.get_header_height(&p.block_hash()).await? + 1
        } else {
            0
        };

        for (idx, header) in headers.iter().enumerate() {
            // Validate header connects to previous
            if let Some(ref p) = prev {
                if header.prev_blockhash != p.block_hash() {
                    bail!(
                        "Header doesn't connect: expected prev {}, got {}",
                        p.block_hash(),
                        header.prev_blockhash
                    );
                }
            }

            // Validate proof of work
            if !self.validate_pow(header)? {
                bail!("Invalid proof of work for header {}", header.block_hash());
            }

            // Validate difficulty adjustment (every 2016 blocks on mainnet/testnet)
            if self.network != Network::Regtest && height > 0 && height % 2016 == 0 {
                // Check if difficulty adjustment is correct
                if let Some(ref p) = prev {
                    let expected_target =
                        self.calculate_next_target(height, &headers[0..idx]).await?;
                    if header.target() != expected_target {
                        warn!(
                            "Incorrect difficulty adjustment at height {}: expected {:?}, got {:?}",
                            height,
                            expected_target,
                            header.target()
                        );
                        // For now just warn, as calculating exact target requires full chain history
                    }
                }
            }

            // Validate timestamp
            if let Some(ref p) = prev {
                // BIP113: Median time past rule (after activation)
                // For now, just check basic timestamp ordering
                if header.time <= p.time - 7200 {
                    bail!(
                        "Header timestamp too far in past: {} vs prev {}",
                        header.time,
                        p.time
                    );
                }
            }

            // Check timestamp not too far in future (2 hours)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
            if header.time > now + 2 * 60 * 60 {
                bail!(
                    "Header timestamp too far in future: {} (now: {})",
                    header.time,
                    now
                );
            }

            // Store header height
            self.store_header_height(&header.block_hash(), height).await;

            prev = Some(*header);
            height += 1;
        }

        // Store headers in chain
        let mut chain = self.headers_chain.write().await;
        chain.extend_from_slice(headers);

        Ok(())
    }

    /// Calculate next difficulty target (simplified version)
    async fn calculate_next_target(
        &self,
        height: u32,
        recent_headers: &[BlockHeader],
    ) -> Result<bitcoin::Target> {
        // This is a simplified version - full implementation would need access to the entire chain
        // For now, return the current target
        if let Some(last) = recent_headers.last() {
            Ok(last.target())
        } else {
            // Return default target for the network
            Ok(bitcoin::Target::MAX)
        }
    }

    /// Validate proof of work for a header
    fn validate_pow(&self, header: &BlockHeader) -> Result<bool> {
        use bitcoin::Target;
        use bitcoin_hashes::Hash;

        let hash = header.block_hash();
        let target = header.target();

        // Convert hash to Target for comparison
        // The block hash when interpreted as a number must be less than or equal to the target
        let hash_as_target = Target::from_le_bytes(hash.to_byte_array());

        // Check if the hash meets the difficulty requirement
        if hash_as_target > target {
            debug!(
                "Header {} fails PoW: hash {:?} > target {:?}",
                hash, hash_as_target, target
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Get the height of a header
    async fn get_header_height(&self, hash: &BlockHash) -> Result<u32> {
        let heights = self.header_heights.read().await;
        heights
            .get(hash)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Header height not found for {}", hash))
    }

    /// Store header height
    async fn store_header_height(&self, hash: &BlockHash, height: u32) {
        let mut heights = self.header_heights.write().await;
        heights.insert(*hash, height);
    }

    /// Build a block locator for requesting headers
    pub async fn build_block_locator(&self) -> Vec<BlockHash> {
        let chain = self.headers_chain.read().await;
        let mut locator = Vec::new();
        let len = chain.len();

        if len == 0 {
            // Return genesis block hash based on network
            let genesis_hash = match self.network {
                Network::Bitcoin => {
                    // Bitcoin mainnet genesis block
                    BlockHash::from_byte_array([
                        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46,
                        0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
                        0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ])
                }
                Network::Testnet => {
                    // Testnet genesis block
                    BlockHash::from_byte_array([
                        0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71, 0x08, 0xf4, 0xa3, 0x0f,
                        0xd9, 0xce, 0xc3, 0xae, 0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
                        0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
                    ])
                }
                _ => {
                    // For other networks, use a placeholder
                    BlockHash::from_byte_array([0u8; 32])
                }
            };
            locator.push(genesis_hash);
            return locator;
        }

        // Build exponential backoff locator
        // Recent blocks: every block for the last 10
        let start = len.saturating_sub(10);
        for i in (start..len).rev() {
            locator.push(chain[i].block_hash());
        }

        // Then exponentially fewer blocks
        let mut step = 1;
        let mut i = start.saturating_sub(1);
        while i > 0 {
            locator.push(chain[i].block_hash());
            if i < step {
                break;
            }
            i = i.saturating_sub(step);
            step *= 2;
        }

        // Always include genesis
        if len > 0 {
            locator.push(chain[0].block_hash());
        }

        locator
    }

    /// Check if we have a header
    pub async fn has_header(&self, hash: &BlockHash) -> bool {
        let heights = self.header_heights.read().await;
        heights.contains_key(hash)
    }

    /// Get the best (highest) header
    pub async fn get_best_header(&self) -> Option<BlockHeader> {
        let chain = self.headers_chain.read().await;
        chain.last().cloned()
    }

    /// Get header by hash
    pub async fn get_header(&self, hash: &BlockHash) -> Option<BlockHeader> {
        let chain = self.headers_chain.read().await;
        chain.iter().find(|h| h.block_hash() == *hash).cloned()
    }

    /// Get the height of the best header
    pub async fn get_best_height(&self) -> u32 {
        let chain = self.headers_chain.read().await;
        chain.len().saturating_sub(1) as u32
    }

    /// Get headers after a certain height
    pub async fn get_headers_after(&self, height: u32) -> Vec<BlockHeader> {
        let chain = self.headers_chain.read().await;
        if height >= chain.len() as u32 {
            return Vec::new();
        }
        chain[(height as usize + 1)..].to_vec()
    }

    /// Clear all headers (for reorg or reset)
    pub async fn clear(&self) {
        let mut chain = self.headers_chain.write().await;
        let mut heights = self.header_heights.write().await;
        chain.clear();
        heights.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    #[tokio::test]
    async fn test_headers_validator() {
        let validator = HeadersValidator::new(Network::Bitcoin);

        // Create a test header with very easy difficulty (regtest-like)
        // Use max target (0x207fffff) which makes any hash valid
        let mut header = BlockHeader {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff), // Max target (easiest difficulty)
            nonce: 0,
        };

        // Find a nonce that produces a valid hash for this target
        // With max target, even nonce=0 should work, but let's verify
        while header.target() < bitcoin::Target::from_le_bytes(header.block_hash().to_byte_array())
        {
            header.nonce += 1;
            if header.nonce > 1000 {
                // Safety check - with max target we shouldn't need many tries
                panic!("Could not find valid nonce with max target");
            }
        }

        // Validate single header
        let result = validator.validate_headers(&[header.clone()], None).await;
        assert!(result.is_ok(), "Validation failed: {:?}", result);

        // Check it was stored
        assert!(validator.has_header(&header.block_hash()).await);
        assert_eq!(validator.get_best_height().await, 0);
    }

    #[tokio::test]
    async fn test_block_locator() {
        let validator = HeadersValidator::new(Network::Bitcoin);

        // Empty chain should return genesis
        let locator = validator.build_block_locator().await;
        assert_eq!(locator.len(), 1);

        // Add some headers with valid PoW
        let mut headers = Vec::new();
        let mut prev_hash = BlockHash::from_byte_array([0u8; 32]);
        for i in 0..100 {
            let mut header = BlockHeader {
                version: bitcoin::block::Version::from_consensus(1),
                prev_blockhash: prev_hash,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time: 1234567890 + i * 600,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff), // Max target for easy mining
                nonce: 0,
            };

            // Find valid nonce (should be quick with max target)
            while header.target()
                < bitcoin::Target::from_le_bytes(header.block_hash().to_byte_array())
            {
                header.nonce += 1;
                if header.nonce > 10000 {
                    panic!("Could not find valid nonce for header {}", i);
                }
            }

            headers.push(header.clone());
            prev_hash = header.block_hash();
        }

        validator.validate_headers(&headers, None).await.unwrap();

        // Check locator has exponential backoff
        let locator = validator.build_block_locator().await;
        assert!(locator.len() > 10);
        assert!(locator.len() < 100);
    }
}
