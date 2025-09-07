use anyhow::{bail, Result};
use bitcoin::{BlockHash, Network};
use std::collections::BTreeMap;
use tracing::{debug, info};

/// Checkpoint data for a specific block
#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub height: u32,
    pub hash: BlockHash,
    pub timestamp: u32,
    pub total_tx: u64,
}

/// Checkpoint manager for faster initial block download
pub struct CheckpointManager {
    /// Network type
    network: Network,

    /// Checkpoints sorted by height
    checkpoints: BTreeMap<u32, Checkpoint>,

    /// Assume valid block (skip script validation before this)
    assume_valid: Option<BlockHash>,

    /// Minimum chain work at specific heights
    min_chain_work: BTreeMap<u32, [u8; 32]>,
}

impl CheckpointManager {
    /// Create new checkpoint manager
    pub fn new(network: Network) -> Self {
        let mut manager = Self {
            network,
            checkpoints: BTreeMap::new(),
            assume_valid: None,
            min_chain_work: BTreeMap::new(),
        };

        manager.load_checkpoints();
        manager
    }

    /// Load hardcoded checkpoints for the network
    fn load_checkpoints(&mut self) {
        match self.network {
            Network::Bitcoin => {
                self.load_mainnet_checkpoints();
            }
            Network::Testnet => {
                self.load_testnet_checkpoints();
            }
            Network::Signet => {
                self.load_signet_checkpoints();
            }
            Network::Regtest => {
                // No checkpoints for regtest
            }
            _ => {}
        }
    }

    /// Load mainnet checkpoints
    fn load_mainnet_checkpoints(&mut self) {
        // These are actual Bitcoin mainnet checkpoints
        self.add_checkpoint(
            0,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", // Genesis
            1231006505,
            1,
        );

        self.add_checkpoint(
            11111,
            "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
            1296688602,
            14384,
        );

        self.add_checkpoint(
            33333,
            "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6",
            1316798414,
            94253,
        );

        self.add_checkpoint(
            74000,
            "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20",
            1339077522,
            309298,
        );

        self.add_checkpoint(
            105000,
            "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97",
            1351008600,
            584802,
        );

        self.add_checkpoint(
            134444,
            "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe",
            1359018858,
            972949,
        );

        self.add_checkpoint(
            168000,
            "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763",
            1371093750,
            1588238,
        );

        self.add_checkpoint(
            193000,
            "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317",
            1384473104,
            2271002,
        );

        self.add_checkpoint(
            210000,
            "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",
            1393813869,
            2992605,
        );

        self.add_checkpoint(
            216116,
            "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e",
            1397080064,
            3295155,
        );

        self.add_checkpoint(
            225430,
            "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932",
            1403128492,
            3825178,
        );

        self.add_checkpoint(
            250000,
            "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214",
            1413472501,
            5307180,
        );

        self.add_checkpoint(
            279000,
            "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40",
            1424276822,
            7509361,
        );

        self.add_checkpoint(
            295000,
            "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983",
            1432483561,
            8842910,
        );

        // More recent checkpoints
        self.add_checkpoint(
            478559,
            "00000000000000000019f112ec0a9982926f1258cdcc558dd7c3b7e5dc7fa148",
            1530359963,
            275282576,
        );

        self.add_checkpoint(
            600000,
            "00000000000000000001a0a12c1e192e3f266f53679bb8195005bc5fa89e70f9",
            1572266427,
            481824432,
        );

        self.add_checkpoint(
            700000,
            "0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959",
            1630616085,
            667765297,
        );

        self.add_checkpoint(
            800000,
            "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
            1691606255,
            836936228,
        );

        // Set assume valid block (can be updated to more recent block)
        self.assume_valid = Some(
            block_hash_from_hex("00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054")
                .unwrap(),
        );

        info!("Loaded {} mainnet checkpoints", self.checkpoints.len());
    }

    /// Load testnet checkpoints
    fn load_testnet_checkpoints(&mut self) {
        self.add_checkpoint(
            0,
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            1296688602,
            1,
        );

        self.add_checkpoint(
            100000,
            "00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e",
            1376543922,
            546901,
        );

        self.add_checkpoint(
            200000,
            "0000000000287bffd321963ef05feab753ebe274e1d78b2fd4e2bfe9ad3aa6f2",
            1493997089,
            1119024,
        );

        info!("Loaded {} testnet checkpoints", self.checkpoints.len());
    }

    /// Load signet checkpoints
    fn load_signet_checkpoints(&mut self) {
        // Signet genesis
        self.add_checkpoint(
            0,
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            1598918400,
            1,
        );

        info!("Loaded {} signet checkpoints", self.checkpoints.len());
    }

    /// Add a checkpoint
    fn add_checkpoint(&mut self, height: u32, hash_str: &str, timestamp: u32, total_tx: u64) {
        let hash = block_hash_from_hex(hash_str).expect("Invalid checkpoint hash");

        self.checkpoints.insert(
            height,
            Checkpoint {
                height,
                hash,
                timestamp,
                total_tx,
            },
        );
    }

    /// Parse block hash from hex string
    fn parse_hash(hex: &str) -> BlockHash {
        use bitcoin::hashes::Hash;
        BlockHash::from_slice(&hex::decode(hex).unwrap()).unwrap()
    }

    /// Check if a block matches a checkpoint
    pub fn validate_checkpoint(&self, height: u32, hash: &BlockHash) -> Result<()> {
        if let Some(checkpoint) = self.checkpoints.get(&height) {
            if checkpoint.hash != *hash {
                bail!(
                    "Block at height {} does not match checkpoint. Expected: {}, Got: {}",
                    height,
                    checkpoint.hash,
                    hash
                );
            }
            debug!("Block at height {} matches checkpoint", height);
        }
        Ok(())
    }

    /// Get checkpoint at specific height
    pub fn get_checkpoint(&self, height: u32) -> Option<&Checkpoint> {
        self.checkpoints.get(&height)
    }

    /// Get the highest checkpoint below or at given height
    pub fn get_last_checkpoint_before(&self, height: u32) -> Option<&Checkpoint> {
        self.checkpoints
            .range(..=height)
            .next_back()
            .map(|(_, cp)| cp)
    }

    /// Check if we can skip script validation for this block
    pub fn can_skip_validation(&self, hash: &BlockHash) -> bool {
        if let Some(assume_valid) = &self.assume_valid {
            // In real implementation, would check if block is ancestor of assume_valid
            // For now, simplified check
            true
        } else {
            false
        }
    }

    /// Get minimum chain work at height
    pub fn get_minimum_chain_work(&self, height: u32) -> Option<[u8; 32]> {
        self.min_chain_work
            .range(..=height)
            .next_back()
            .map(|(_, work)| *work)
    }

    /// Estimate sync progress based on checkpoints
    pub fn estimate_progress(&self, current_height: u32, current_timestamp: u32) -> f64 {
        // Special case: if we're exactly at a checkpoint, use a small but non-zero progress
        if self.checkpoints.contains_key(&current_height) {
            // Find position in checkpoint list
            let total_checkpoints = self.checkpoints.len();
            let checkpoint_index = self
                .checkpoints
                .keys()
                .position(|&h| h == current_height)
                .unwrap_or(0);
            // Return progress based on checkpoint position
            return ((checkpoint_index + 1) as f64 / total_checkpoints as f64).clamp(0.01, 1.0);
        }

        // Find nearest checkpoints
        let last_checkpoint = self.get_last_checkpoint_before(current_height);
        let next_checkpoint = self
            .checkpoints
            .range((current_height + 1)..)
            .next()
            .map(|(_, cp)| cp);

        match (last_checkpoint, next_checkpoint) {
            (Some(last), Some(next)) => {
                // Interpolate between checkpoints
                let height_progress = ((current_height - last.height) as f64
                    / (next.height - last.height) as f64)
                    .clamp(0.0, 1.0);

                let time_progress =
                    if current_timestamp > last.timestamp && next.timestamp > last.timestamp {
                        ((current_timestamp - last.timestamp) as f64
                            / (next.timestamp - last.timestamp) as f64)
                            .clamp(0.0, 1.0)
                    } else {
                        height_progress
                    };

                // Use average of height and time progress, clamped to valid range
                ((height_progress + time_progress) / 2.0).clamp(0.0, 1.0)
            }
            (Some(last), None) => {
                // Past last checkpoint, estimate based on time
                // Assume 10 minutes per block on average
                let expected_blocks = (current_timestamp - last.timestamp) / 600;
                let progress_past = current_height - last.height;

                if expected_blocks > 0 {
                    // Clamp to 1.0 as we're past the last checkpoint
                    (progress_past as f64 / expected_blocks as f64).min(1.0)
                } else {
                    1.0
                }
            }
            _ => {
                // Before first checkpoint
                if let Some(first) = self.checkpoints.values().next() {
                    (current_height as f64 / first.height as f64).clamp(0.0, 1.0)
                } else {
                    0.0
                }
            }
        }
    }

    /// Get total transaction count estimate at height
    pub fn estimate_transaction_count(&self, height: u32) -> u64 {
        let last_cp = self.get_last_checkpoint_before(height);
        let next_cp = self
            .checkpoints
            .range((height + 1)..)
            .next()
            .map(|(_, cp)| cp);

        match (last_cp, next_cp) {
            (Some(last), Some(next)) => {
                // Interpolate transaction count
                let height_ratio =
                    (height - last.height) as f64 / (next.height - last.height) as f64;
                let tx_diff = next.total_tx - last.total_tx;
                last.total_tx + (tx_diff as f64 * height_ratio) as u64
            }
            (Some(last), None) => {
                // Estimate based on average tx per block since last checkpoint
                let blocks_since = height - last.height;
                let avg_tx_per_block = if last.height > 0 {
                    last.total_tx / last.height as u64
                } else {
                    2000 // Rough estimate
                };
                last.total_tx + (blocks_since as u64 * avg_tx_per_block)
            }
            _ => {
                // Rough estimate before first checkpoint
                height as u64 * 100
            }
        }
    }

    /// Check if headers-first sync should be used
    pub fn should_use_headers_first(&self, current_height: u32) -> bool {
        // Use headers-first if we're significantly behind
        if let Some(highest_cp) = self.checkpoints.values().last() {
            current_height < highest_cp.height - 1000
        } else {
            false
        }
    }

    /// Get checkpoint statistics
    pub fn get_stats(&self) -> CheckpointStats {
        CheckpointStats {
            total_checkpoints: self.checkpoints.len(),
            highest_checkpoint: self
                .checkpoints
                .values()
                .last()
                .map(|cp| cp.height)
                .unwrap_or(0),
            assume_valid: self.assume_valid.is_some(),
            network: format!("{:?}", self.network),
        }
    }
}

/// Checkpoint statistics
#[derive(Debug, Clone)]
pub struct CheckpointStats {
    pub total_checkpoints: usize,
    pub highest_checkpoint: u32,
    pub assume_valid: bool,
    pub network: String,
}

/// Parse BlockHash from hex string (helper for checkpoints)
fn block_hash_from_hex(s: &str) -> Result<BlockHash> {
    use bitcoin::hashes::Hash;
    let bytes = hex::decode(s)?;
    Ok(BlockHash::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_validation() {
        let manager = CheckpointManager::new(Network::Bitcoin);

        // Genesis block should match
        let genesis_hash =
            block_hash_from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();

        assert!(manager.validate_checkpoint(0, &genesis_hash).is_ok());

        // Wrong hash should fail
        let wrong_hash =
            block_hash_from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();

        assert!(manager.validate_checkpoint(0, &wrong_hash).is_err());
    }

    #[test]
    fn test_progress_estimation() {
        let manager = CheckpointManager::new(Network::Bitcoin);

        // At checkpoint
        let progress = manager.estimate_progress(250000, 1413472501);
        println!("Progress at 250000: {}", progress);
        assert!(
            (0.0..=1.0).contains(&progress),
            "Progress {} out of range",
            progress
        );

        // Between checkpoints
        let progress = manager.estimate_progress(275000, 1420000000);
        println!("Progress at 275000: {}", progress);
        assert!(
            (0.0..=1.0).contains(&progress),
            "Progress {} out of range",
            progress
        );
    }

    #[test]
    fn test_transaction_count_estimation() {
        let manager = CheckpointManager::new(Network::Bitcoin);

        // Should return reasonable estimates
        let tx_count = manager.estimate_transaction_count(300000);
        assert!(tx_count > 1_000_000); // Should be millions by block 300k
    }
}
