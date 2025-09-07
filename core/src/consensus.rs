use anyhow::Result;
use bitcoin::block::Header as BlockHeader;
use bitcoin::{Block, Network};
use bitcoin_hashes::Hash;

#[derive(Debug, Clone)]
pub struct ConsensusParams {
    pub network: Network,
    pub max_block_weight: u64,
    pub max_block_sigops: u32,
    pub coinbase_maturity: u32,
    pub subsidy_halving_interval: u32,
    pub pow_limit: [u8; 32],
    pub pow_target_spacing: u32,
    pub pow_target_timespan: u32,
    pub segwit_height: u32,
    pub bip34_height: u32,
    pub bip65_height: u32,
    pub bip66_height: u32,
}

impl ConsensusParams {
    pub fn for_network(network_str: &str) -> Result<Self> {
        let network = match network_str {
            "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            _ => anyhow::bail!("Unknown network: {}", network_str),
        };

        Ok(match network {
            Network::Bitcoin => Self {
                network,
                max_block_weight: 4_000_000,
                max_block_sigops: 80_000,
                coinbase_maturity: 100,
                subsidy_halving_interval: 210_000,
                pow_limit: [
                    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                pow_target_spacing: 600,      // 10 minutes
                pow_target_timespan: 1209600, // 2 weeks
                segwit_height: 481824,        // SegWit activation height
                bip34_height: 227931,         // BIP34 activation height
                bip65_height: 388381,         // BIP65 activation height
                bip66_height: 363725,         // BIP66 activation height
            },
            Network::Testnet => Self {
                network,
                max_block_weight: 4_000_000,
                max_block_sigops: 80_000,
                coinbase_maturity: 100,
                subsidy_halving_interval: 210_000,
                pow_limit: [
                    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                pow_target_spacing: 600,
                pow_target_timespan: 1209600,
                segwit_height: 834624, // SegWit activation on testnet
                bip34_height: 21111,   // BIP34 activation on testnet
                bip65_height: 581885,  // BIP65 activation on testnet
                bip66_height: 330776,  // BIP66 activation on testnet
            },
            Network::Regtest => Self {
                network,
                max_block_weight: 4_000_000,
                max_block_sigops: 80_000,
                coinbase_maturity: 100,
                subsidy_halving_interval: 150,
                pow_limit: [
                    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                pow_target_spacing: 600,
                pow_target_timespan: 1209600,
                segwit_height: 0, // Always active on regtest
                bip34_height: 0,  // Always active on regtest
                bip65_height: 0,  // Always active on regtest
                bip66_height: 0,  // Always active on regtest
            },
            Network::Signet => Self {
                network,
                max_block_weight: 4_000_000,
                max_block_sigops: 80_000,
                coinbase_maturity: 100,
                subsidy_halving_interval: 210_000,
                pow_limit: [
                    0x00, 0x00, 0x00, 0x37, 0x7a, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                pow_target_spacing: 600,
                pow_target_timespan: 1209600,
                segwit_height: 0, // Always active on signet
                bip34_height: 0,  // Always active on signet
                bip65_height: 0,  // Always active on signet
                bip66_height: 0,  // Always active on signet
            },
            _ => anyhow::bail!("Unsupported network"),
        })
    }

    pub fn genesis_block(&self) -> Block {
        bitcoin::constants::genesis_block(self.network)
    }

    pub fn get_block_subsidy(&self, height: u32) -> u64 {
        let halvings = height / self.subsidy_halving_interval;
        if halvings >= 64 {
            return 0;
        }
        50_0000_0000 >> halvings
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Check if BIP34 is active at a given height
    pub fn is_bip34_active(&self, height: u32) -> bool {
        height >= self.bip34_height
    }

    /// Check if BIP65 is active at a given height
    pub fn is_bip65_active(&self, height: u32) -> bool {
        height >= self.bip65_height
    }

    /// Check if BIP66 is active at a given height
    pub fn is_bip66_active(&self, height: u32) -> bool {
        height >= self.bip66_height
    }

    /// Check if SegWit is active at a given height  
    pub fn is_segwit_active(&self, height: u32) -> bool {
        height >= self.segwit_height
    }

    pub fn check_proof_of_work(&self, header: &BlockHeader) -> bool {
        let hash = header.block_hash();
        let target = header.target();

        // Check if hash meets target
        let hash_bytes = hash.as_byte_array();
        let target_bytes = target.to_le_bytes();

        // Compare as little-endian integers
        for i in (0..32).rev() {
            if hash_bytes[i] < target_bytes[i % 32] {
                return true;
            }
            if hash_bytes[i] > target_bytes[i % 32] {
                return false;
            }
        }
        true
    }

    // Database accessors for difficulty adjustment
    pub fn get_block_hash_at_height(&self, _height: u32) -> Result<Option<bitcoin::BlockHash>> {
        // This would need to be connected to the actual database
        // For now, return None to use fallback
        Ok(None)
    }

    pub fn get_block_header(&self, _hash: &bitcoin::BlockHash) -> Result<Option<BlockHeader>> {
        // This would need to be connected to the actual database
        // For now, return None to use fallback
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub enum ValidationResult {
    Valid,
    Invalid(String),
    Unknown,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }
}
