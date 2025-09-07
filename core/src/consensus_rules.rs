use anyhow::{bail, Context, Result};
use bitcoin::{Block, BlockHash, Network, Transaction, Txid};
use std::collections::HashSet;
use std::str::FromStr;
use tracing::debug;

/// BIP30: Reject duplicate transactions
/// BIP34: Block height in coinbase
/// BIP66: Strict DER signatures
/// BIP65: OP_CHECKLOCKTIMEVERIFY
/// BIP341/342: Taproot/Tapscript
pub struct ConsensusRules {
    network: Network,
    bip30_exception_blocks: HashSet<BlockHash>,
    bip34_activation_height: u32,
    bip65_activation_height: u32,
    bip66_activation_height: u32,
    taproot_activation_height: u32,
    segwit_activation_height: u32,
}

impl ConsensusRules {
    /// Create consensus rules for a network
    pub fn new(network: Network) -> Self {
        let mut bip30_exceptions = HashSet::new();

        // BIP30 exception blocks (blocks that violated the rule before it was enforced)
        if network == Network::Bitcoin {
            // Block 91842 and 91880 on mainnet
            bip30_exceptions.insert(
                BlockHash::from_str(
                    "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec",
                )
                .unwrap(),
            );
            bip30_exceptions.insert(
                BlockHash::from_str(
                    "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721",
                )
                .unwrap(),
            );
        }

        let (bip34_height, bip65_height, bip66_height, segwit_height, taproot_height) =
            match network {
                Network::Bitcoin => (227931, 388381, 363725, 481824, 709632),
                Network::Testnet => (21111, 581885, 330776, 834624, 2104441),
                Network::Signet => (0, 0, 0, 0, 0),
                Network::Regtest => (0, 0, 0, 0, 0),
                _ => (0, 0, 0, 0, 0),
            };

        Self {
            network,
            bip30_exception_blocks: bip30_exceptions,
            bip34_activation_height: bip34_height,
            bip65_activation_height: bip65_height,
            bip66_activation_height: bip66_height,
            taproot_activation_height: taproot_height,
            segwit_activation_height: segwit_height,
        }
    }

    /// Check BIP30: Ensure no duplicate transaction IDs
    pub async fn check_bip30(
        &self,
        block: &Block,
        height: u32,
        utxo_set: &impl UtxoProvider,
    ) -> Result<()> {
        // Skip if this is one of the exception blocks
        if self.bip30_exception_blocks.contains(&block.block_hash()) {
            return Ok(());
        }

        // BIP30 is always enforced after BIP34
        if height >= self.bip34_activation_height {
            // After BIP34, duplicates are impossible due to height in coinbase
            return Ok(());
        }

        // Check each transaction (except coinbase) doesn't overwrite unspent outputs
        for (i, tx) in block.txdata.iter().enumerate() {
            if i == 0 {
                continue; // Skip coinbase
            }

            let txid = tx.compute_txid();

            // Check if any outputs from a transaction with this ID are unspent
            if utxo_set.has_unspent_outputs(&txid).await? {
                bail!(
                    "BIP30 violation: transaction {} already exists with unspent outputs",
                    txid
                );
            }
        }

        Ok(())
    }

    /// Check BIP34: Block height in coinbase
    pub fn check_bip34(&self, block: &Block, height: u32) -> Result<()> {
        if height < self.bip34_activation_height {
            return Ok(());
        }

        // Get coinbase transaction
        let coinbase = block.txdata.first().context("Block has no transactions")?;

        // Check coinbase input
        if coinbase.input.len() != 1 {
            bail!("BIP34: Coinbase must have exactly one input");
        }

        let coinbase_input = &coinbase.input[0];

        // Parse script to get height
        let script = &coinbase_input.script_sig;
        debug!(
            "BIP34: Checking script for height {}: {:?}",
            height,
            script.as_bytes()
        );
        let height_bytes = Self::extract_height_from_script(script)?;

        // Decode height from script
        let decoded_height = Self::decode_script_number(&height_bytes)?;
        debug!(
            "BIP34: Decoded height {} from bytes {:?}",
            decoded_height, height_bytes
        );

        if decoded_height != height as i64 {
            bail!(
                "BIP34: Block height in coinbase ({}) doesn't match actual height ({})",
                decoded_height,
                height
            );
        }

        debug!("BIP34 validation passed for block at height {}", height);
        Ok(())
    }

    /// Check BIP66: Strict DER signatures
    pub fn check_bip66(&self, height: u32) -> bool {
        height >= self.bip66_activation_height
    }

    /// Check BIP65: CHECKLOCKTIMEVERIFY support
    pub fn check_bip65(&self, height: u32) -> bool {
        height >= self.bip65_activation_height
    }

    /// Check SegWit activation
    pub fn is_segwit_active(&self, height: u32) -> bool {
        height >= self.segwit_activation_height
    }

    /// Check Taproot activation (BIP341/342)
    pub fn is_taproot_active(&self, height: u32) -> bool {
        height >= self.taproot_activation_height
    }

    /// Get Taproot activation height for the network
    pub fn taproot_activation_height(&self) -> u32 {
        self.taproot_activation_height
    }

    /// Get SegWit activation height for the network
    pub fn segwit_activation_height(&self) -> u32 {
        self.segwit_activation_height
    }

    /// Extract height from coinbase script
    fn extract_height_from_script(script: &bitcoin::ScriptBuf) -> Result<Vec<u8>> {
        use bitcoin::blockdata::opcodes;
        use bitcoin::blockdata::script::Instruction;

        let mut instructions = script.instructions();

        // First instruction should be the height
        match instructions.next() {
            Some(Ok(Instruction::PushBytes(data))) => {
                debug!("BIP34: Found PushBytes with data: {:?}", data.as_bytes());
                Ok(data.as_bytes().to_vec())
            }
            Some(Ok(Instruction::Op(op))) if op == opcodes::all::OP_PUSHNUM_1 => {
                // Height 1 is encoded as OP_1
                debug!("BIP34: Found OP_1 for height 1");
                Ok(vec![1])
            }
            Some(Ok(Instruction::Op(op)))
                if op.to_u8() >= opcodes::all::OP_PUSHNUM_1.to_u8()
                    && op.to_u8() <= opcodes::all::OP_PUSHNUM_16.to_u8() =>
            {
                // Heights 1-16 are encoded as OP_1 through OP_16
                let height = op.to_u8() - opcodes::all::OP_PUSHNUM_1.to_u8() + 1;
                debug!("BIP34: Found OP_{} for height {}", height, height);
                Ok(vec![height])
            }
            Some(Ok(Instruction::Op(op))) if op == opcodes::all::OP_PUSHBYTES_0 => {
                // Height 0 could be encoded as OP_0
                debug!("BIP34: Found OP_0 for height 0");
                Ok(vec![])
            }
            Some(Ok(inst)) => {
                debug!(
                    "BIP34: First instruction is {:?}, not valid height encoding",
                    inst
                );
                bail!(
                    "BIP34: Invalid height encoding in coinbase - got {:?}",
                    inst
                )
            }
            Some(Err(e)) => bail!("BIP34: Script parsing error: {}", e),
            None => bail!("BIP34: Empty coinbase script"),
        }
    }

    /// Decode script number (from Bitcoin script format)
    fn decode_script_number(data: &[u8]) -> Result<i64> {
        if data.is_empty() {
            return Ok(0);
        }

        if data.len() > 4 {
            bail!("Script number too large");
        }

        let mut value = 0i64;
        for (i, &byte) in data.iter().enumerate() {
            value |= (byte as i64) << (8 * i);
        }

        // Handle sign
        if data[data.len() - 1] & 0x80 != 0 {
            value = -(value & !(0x80 << (8 * (data.len() - 1))));
        }

        Ok(value)
    }

    /// Check median time past (BIP113)
    pub fn check_median_time_past(
        &self,
        block_time: u32,
        previous_blocks: &[BlockHeader],
    ) -> Result<()> {
        if previous_blocks.len() < 11 {
            // Not enough blocks for median calculation
            return Ok(());
        }

        // Get last 11 block times
        let mut times: Vec<u32> = previous_blocks
            .iter()
            .rev()
            .take(11)
            .map(|h| h.time)
            .collect();

        // Calculate median
        times.sort_unstable();
        let median = times[5]; // Middle of 11 elements

        if block_time <= median {
            bail!(
                "Block timestamp {} not greater than median time past {}",
                block_time,
                median
            );
        }

        Ok(())
    }

    /// Check block size limits
    pub fn check_block_size(&self, block: &Block, segwit_active: bool) -> Result<()> {
        let serialized = bitcoin::consensus::encode::serialize(block);
        let size = serialized.len();

        if segwit_active {
            // Check weight limit (4MB weight)
            let weight = block.weight().to_wu() as usize;
            if weight > 4_000_000 {
                bail!("Block weight {} exceeds maximum 4000000", weight);
            }
        } else {
            // Legacy 1MB limit
            if size > 1_000_000 {
                bail!("Block size {} exceeds maximum 1000000", size);
            }
        }

        Ok(())
    }

    /// Check coinbase maturity (100 blocks)
    pub fn check_coinbase_maturity(
        &self,
        tx: &Transaction,
        spending_height: u32,
        utxo_height: u32,
    ) -> Result<()> {
        // Coinbase outputs must mature for 100 blocks
        const COINBASE_MATURITY: u32 = 100;

        if spending_height < utxo_height + COINBASE_MATURITY {
            bail!(
                "Coinbase output spent at height {} but created at height {} (maturity: {})",
                spending_height,
                utxo_height,
                COINBASE_MATURITY
            );
        }

        Ok(())
    }

    /// Check sigop count limits
    pub fn check_sigop_count(&self, block: &Block, segwit_active: bool) -> Result<()> {
        let max_sigops = if segwit_active {
            80_000 // SegWit increases limit
        } else {
            20_000 // Legacy limit
        };

        let mut total_sigops = 0;

        for tx in &block.txdata {
            // Count legacy sigops
            total_sigops += Self::count_legacy_sigops(tx)?;

            if segwit_active {
                // Count witness sigops
                total_sigops += Self::count_witness_sigops(tx)?;
            }
        }

        if total_sigops > max_sigops {
            bail!(
                "Block sigop count {} exceeds maximum {}",
                total_sigops,
                max_sigops
            );
        }

        Ok(())
    }

    /// Count legacy signature operations
    fn count_legacy_sigops(tx: &Transaction) -> Result<usize> {
        let mut count = 0;

        // Count sigops in outputs
        for output in &tx.output {
            count += Self::count_script_sigops(&output.script_pubkey)?;
        }

        // Count sigops in inputs (for P2SH)
        // This is simplified - full implementation would need to check prevouts

        Ok(count)
    }

    /// Count witness signature operations
    fn count_witness_sigops(tx: &Transaction) -> Result<usize> {
        let mut count = 0;

        for input in &tx.input {
            if !input.witness.is_empty() {
                // Simplified counting - real implementation needs script execution
                count += 1;
            }
        }

        Ok(count)
    }

    /// Count sigops in a script
    fn count_script_sigops(script: &bitcoin::ScriptBuf) -> Result<usize> {
        use bitcoin::blockdata::opcodes::all::*;
        use bitcoin::blockdata::script::Instruction;

        let mut count = 0;

        for instruction in script.instructions() {
            match instruction {
                Ok(Instruction::Op(OP_CHECKSIG | OP_CHECKSIGVERIFY)) => {
                    count += 1;
                }
                Ok(Instruction::Op(OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY)) => {
                    // Worst case: 20 public keys
                    count += 20;
                }
                _ => {}
            }
        }

        Ok(count)
    }
}

/// UTXO provider trait for BIP30 checking
#[async_trait::async_trait]
pub trait UtxoProvider: Send + Sync {
    /// Check if a transaction has unspent outputs
    async fn has_unspent_outputs(&self, txid: &Txid) -> Result<bool>;
}

/// Block header for median time calculation
pub struct BlockHeader {
    pub time: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip34_height_encoding() {
        // Test height encoding/decoding
        let height = 227931u32;
        let encoded = vec![0x5b, 0x7a, 0x03]; // 227931 in little-endian

        let decoded = ConsensusRules::decode_script_number(&encoded).unwrap();
        assert_eq!(decoded, height as i64);
    }

    #[test]
    fn test_median_time_past() {
        let mut headers = Vec::new();

        // Create 11 blocks with incrementing timestamps
        for i in 0..11 {
            headers.push(BlockHeader {
                time: 1000 + i * 10,
            });
        }

        let rules = ConsensusRules::new(Network::Bitcoin);

        // Median of [1000, 1010, 1020, ..., 1100] is 1050
        // So block time must be > 1050
        assert!(rules.check_median_time_past(1051, &headers).is_ok());
        assert!(rules.check_median_time_past(1050, &headers).is_err());
    }
}
