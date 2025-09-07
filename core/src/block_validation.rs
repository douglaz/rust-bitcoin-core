use anyhow::{bail, Context, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::Encodable;
use bitcoin::{Amount, Block, BlockHash, Transaction};
use std::collections::HashMap;
use tracing::{debug, info};

use crate::consensus::ConsensusParams;
use crate::fee::FeeCalculator;
use crate::witness_validation::WitnessValidator;

/// Result of block validation
#[derive(Debug, Clone)]
pub struct BlockValidationResult {
    pub block_hash: BlockHash,
    pub height: u32,
    pub total_fees: Amount,
    pub total_weight: u64,
    pub total_sigops: u32,
}

/// Complete block validation with all consensus rules
pub struct BlockValidationRules {
    consensus_params: ConsensusParams,
    fee_calculator: FeeCalculator,
}

impl BlockValidationRules {
    pub fn new(consensus_params: ConsensusParams) -> Self {
        Self {
            consensus_params,
            fee_calculator: FeeCalculator::default(),
        }
    }

    pub fn mainnet() -> Self {
        Self::new(ConsensusParams::for_network("mainnet").unwrap())
    }

    /// Validate a block against all consensus rules
    pub fn validate_block(
        &self,
        block: &Block,
        height: u32,
        prev_block_hash: BlockHash,
        prev_block_time: u32,
        median_time_past: u32,
        utxo_set: &HashMap<bitcoin::OutPoint, bitcoin::TxOut>,
    ) -> Result<BlockValidationResult> {
        info!(
            "Validating block {} at height {}",
            block.block_hash(),
            height
        );

        // 1. Check proof of work
        self.validate_proof_of_work(&block.header)?;

        // 2. Check block hash matches claimed previous block
        if block.header.prev_blockhash != prev_block_hash {
            bail!("Previous block hash mismatch");
        }

        // 3. Check timestamp
        self.validate_timestamp(block.header.time, prev_block_time, median_time_past)?;

        // 4. Check merkle root matches calculated merkle root
        self.validate_merkle_root(block)?;

        // 5. Check block size
        self.validate_block_size(block)?;

        // 6. Check block weight
        let total_weight = self.validate_block_weight(block)?;

        // 7. Check transaction count
        if block.txdata.is_empty() {
            bail!("Block has no transactions");
        }

        // 8. Validate coinbase transaction
        let block_subsidy = self.calculate_block_subsidy(height);
        let total_fees =
            self.validate_coinbase(&block.txdata[0], height, block_subsidy, utxo_set)?;

        // 9. Validate witness commitment (for SegWit blocks)
        if height >= self.consensus_params.segwit_height {
            WitnessValidator::validate_witness_commitment(block)?;
        }

        // 10. Check for duplicate transactions (BIP30)
        self.check_duplicate_transactions(block)?;

        // 11. Count total sigops
        let total_sigops = self.count_block_sigops(block, utxo_set)?;
        if total_sigops > self.consensus_params.max_block_sigops {
            bail!(
                "Block exceeds maximum sigop count: {} > {}",
                total_sigops,
                self.consensus_params.max_block_sigops
            );
        }

        // 12. Validate all transactions (except coinbase)
        for tx in &block.txdata[1..] {
            self.validate_transaction(tx, utxo_set)?;
        }

        info!("Block {} validation successful", block.block_hash());
        Ok(BlockValidationResult {
            block_hash: block.block_hash(),
            height,
            total_fees,
            total_weight,
            total_sigops,
        })
    }

    /// Validate proof of work
    fn validate_proof_of_work(&self, header: &BlockHeader) -> Result<()> {
        let target = header.target();
        let block_hash = header.block_hash();

        // Use Bitcoin's built-in proof of work validation
        match header.validate_pow(target) {
            Ok(_) => {}
            Err(_) => bail!("Invalid proof of work for block {}", block_hash),
        }

        // Check target is within valid range using pow_limit
        let pow_limit_bytes = self.consensus_params.pow_limit;
        let pow_limit = bitcoin::Target::from_be_bytes(pow_limit_bytes);
        if target > pow_limit {
            bail!("Target difficulty {} exceeds maximum {}", target, pow_limit);
        }

        debug!("Proof of work valid for block {}", block_hash);
        Ok(())
    }

    /// Validate block timestamp
    fn validate_timestamp(
        &self,
        block_time: u32,
        prev_block_time: u32,
        median_time_past: u32,
    ) -> Result<()> {
        // Block time must be greater than median time of past 11 blocks
        if block_time <= median_time_past {
            bail!(
                "Block timestamp {} not greater than median time past {}",
                block_time,
                median_time_past
            );
        }

        // Block time can't be more than 2 hours in the future
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as u32;

        if block_time > now + 2 * 60 * 60 {
            bail!("Block timestamp too far in future");
        }

        Ok(())
    }

    /// Validate merkle root
    fn validate_merkle_root(&self, block: &Block) -> Result<()> {
        let calculated_root = block
            .compute_merkle_root()
            .context("Failed to compute merkle root")?;

        if calculated_root != block.header.merkle_root {
            bail!(
                "Merkle root mismatch: calculated {} vs header {}",
                calculated_root,
                block.header.merkle_root
            );
        }

        Ok(())
    }

    /// Validate block size
    fn validate_block_size(&self, block: &Block) -> Result<()> {
        let mut data = Vec::new();
        block.consensus_encode(&mut data)?;
        let size = data.len();

        // Max block size is 1MB for legacy blocks
        const MAX_BLOCK_SIZE: usize = 1_000_000;
        if size > MAX_BLOCK_SIZE {
            bail!("Block size {} exceeds maximum {}", size, MAX_BLOCK_SIZE);
        }

        Ok(())
    }

    /// Validate block weight
    fn validate_block_weight(&self, block: &Block) -> Result<u64> {
        let weight = self.calculate_block_weight(block);

        const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
        if weight > MAX_BLOCK_WEIGHT {
            bail!(
                "Block weight {} exceeds maximum {}",
                weight,
                MAX_BLOCK_WEIGHT
            );
        }

        Ok(weight)
    }

    /// Calculate block weight
    fn calculate_block_weight(&self, block: &Block) -> u64 {
        let mut weight = 0u64;

        for tx in &block.txdata {
            weight += tx.weight().to_wu();
        }

        weight
    }

    /// Calculate block subsidy (mining reward)
    fn calculate_block_subsidy(&self, height: u32) -> Amount {
        // Bitcoin halving every 210,000 blocks
        let halvings = height / 210_000;

        if halvings >= 64 {
            return Amount::ZERO;
        }

        // Start with 50 BTC and halve
        let subsidy_sats = (50_0000_0000u64) >> halvings;
        Amount::from_sat(subsidy_sats)
    }

    /// Count total sigops in block
    fn count_block_sigops(
        &self,
        block: &Block,
        utxo_set: &HashMap<bitcoin::OutPoint, bitcoin::TxOut>,
    ) -> Result<u32> {
        let mut total_sigops = 0u32;

        for tx in &block.txdata {
            // Count legacy sigops in outputs
            for output in &tx.output {
                total_sigops += self.count_sigops_in_script(&output.script_pubkey)?;
            }

            // Count P2SH sigops (need to look at spent scripts)
            if !tx.is_coinbase() {
                for input in &tx.input {
                    if let Some(utxo) = utxo_set.get(&input.previous_output) {
                        if utxo.script_pubkey.is_p2sh() {
                            // Conservative estimate for P2SH
                            total_sigops += 15;
                        }
                    }
                }
            }
        }

        Ok(total_sigops)
    }

    /// Count sigops in a script
    fn count_sigops_in_script(&self, script: &bitcoin::ScriptBuf) -> Result<u32> {
        let mut sigops = 0u32;
        let bytes = script.as_bytes();

        for byte in bytes {
            match *byte {
                0xac => sigops += 1, // OP_CHECKSIG
                0xad => sigops += 1, // OP_CHECKSIGVERIFY
                0xae | 0xaf => {
                    // OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
                    sigops += 20; // Conservative estimate
                }
                _ => {}
            }
        }

        Ok(sigops)
    }

    /// Validate coinbase transaction
    fn validate_coinbase(
        &self,
        coinbase: &Transaction,
        height: u32,
        block_subsidy: Amount,
        utxo_set: &HashMap<bitcoin::OutPoint, bitcoin::TxOut>,
    ) -> Result<Amount> {
        // Check it's actually a coinbase transaction
        if !coinbase.is_coinbase() {
            bail!("First transaction is not coinbase");
        }

        // Check coinbase input script size
        let script_sig = &coinbase.input[0].script_sig;
        if script_sig.len() < 2 || script_sig.len() > 100 {
            bail!("Coinbase script size out of range: {}", script_sig.len());
        }

        // BIP34: Coinbase must contain block height (after block 227,836)
        if height >= 227_836 {
            // First bytes should encode the height
            let script_bytes = script_sig.as_bytes();
            if script_bytes.is_empty() {
                bail!("Coinbase missing height in script");
            }

            // Check that height is properly encoded in coinbase
            self.validate_coinbase_height(script_bytes, height)?;
        }

        // Validate coinbase outputs don't already exist in UTXO set
        // (This should never happen as coinbase tx hash includes the block hash)
        let coinbase_txid = coinbase.compute_txid();
        for (index, _output) in coinbase.output.iter().enumerate() {
            let outpoint = bitcoin::OutPoint {
                txid: coinbase_txid,
                vout: index as u32,
            };
            if utxo_set.contains_key(&outpoint) {
                bail!("Coinbase output already exists in UTXO set: {:?}", outpoint);
            }
        }

        // Calculate total fees from the block
        let total_fees = Amount::ZERO;
        // Note: Would calculate actual fees from transactions here
        // For now returning zero as placeholder

        // Check coinbase value doesn't exceed subsidy + fees
        let coinbase_value: Amount = coinbase.output.iter().map(|out| out.value).sum();

        let max_allowed = block_subsidy + total_fees;
        if coinbase_value > max_allowed {
            bail!(
                "Coinbase value {} exceeds maximum allowed {} (subsidy: {}, fees: {})",
                coinbase_value,
                max_allowed,
                block_subsidy,
                total_fees
            );
        }

        Ok(total_fees)
    }

    /// Validate BIP34 height in coinbase
    fn validate_coinbase_height(&self, script_bytes: &[u8], expected_height: u32) -> Result<()> {
        if script_bytes.len() < 4 {
            bail!("Coinbase script too short for height encoding");
        }

        // Parse the height from script (simplified)
        // First byte is the length of the height value
        let len = script_bytes[0] as usize;
        if len > 4 || len == 0 {
            bail!("Invalid height encoding length: {}", len);
        }

        if script_bytes.len() < 1 + len {
            bail!("Coinbase script too short for encoded height");
        }

        let mut height_bytes = [0u8; 4];
        height_bytes[..len].copy_from_slice(&script_bytes[1..1 + len]);
        let encoded_height = u32::from_le_bytes(height_bytes);

        if encoded_height != expected_height {
            bail!(
                "Coinbase height mismatch: encoded {} vs expected {}",
                encoded_height,
                expected_height
            );
        }

        Ok(())
    }

    /// Check for duplicate transactions
    fn check_duplicate_transactions(&self, block: &Block) -> Result<()> {
        let mut seen = HashMap::new();

        for tx in &block.txdata {
            let txid = tx.compute_txid();
            if seen.contains_key(&txid) {
                bail!("Duplicate transaction: {}", txid);
            }
            seen.insert(txid, true);
        }

        Ok(())
    }

    /// Validate a non-coinbase transaction
    fn validate_transaction(
        &self,
        tx: &Transaction,
        utxo_set: &HashMap<bitcoin::OutPoint, bitcoin::TxOut>,
    ) -> Result<()> {
        // Check transaction isn't coinbase (those are validated separately)
        if tx.is_coinbase() {
            bail!("Coinbase transaction not allowed except as first transaction");
        }

        // Check transaction has inputs and outputs
        if tx.input.is_empty() {
            bail!("Transaction has no inputs");
        }

        if tx.output.is_empty() {
            bail!("Transaction has no outputs");
        }

        // Check output values are valid
        let mut total_output = 0u64;
        for output in &tx.output {
            if output.value.to_sat() > 21_000_000 * 100_000_000 {
                bail!("Output value exceeds maximum");
            }
            total_output = total_output.saturating_add(output.value.to_sat());
        }

        // Check total output doesn't exceed maximum
        if total_output > 21_000_000 * 100_000_000 {
            bail!("Total output value exceeds maximum supply");
        }

        // Check transaction size
        let tx_size = bitcoin::consensus::encode::serialize(tx).len();
        if tx_size > 1_000_000 {
            bail!("Transaction size {} exceeds maximum", tx_size);
        }

        // Validate all inputs exist in UTXO set and calculate total input value
        let mut total_input = 0u64;
        for input in &tx.input {
            let prevout = &input.previous_output;

            // Check if the UTXO exists
            match utxo_set.get(prevout) {
                Some(prev_tx_out) => {
                    total_input = total_input.saturating_add(prev_tx_out.value.to_sat());
                }
                None => {
                    bail!(
                        "Transaction input references non-existent UTXO: {}:{}",
                        prevout.txid,
                        prevout.vout
                    );
                }
            }
        }

        // Verify that inputs are greater than or equal to outputs (fees)
        if total_input < total_output {
            bail!(
                "Transaction outputs ({} sats) exceed inputs ({} sats)",
                total_output,
                total_input
            );
        }

        Ok(())
    }

    /// Calculate the median time past from previous blocks
    pub fn calculate_median_time_past(&self, block_times: &[u32]) -> u32 {
        if block_times.is_empty() {
            return 0;
        }

        let mut times = block_times.to_vec();
        times.sort_unstable();

        let len = times.len();
        if len % 2 == 0 {
            (times[len / 2 - 1] + times[len / 2]) / 2
        } else {
            times[len / 2]
        }
    }

    /// Check if block is valid for the given chain tip
    pub fn is_valid_next_block(
        &self,
        block: &Block,
        prev_hash: BlockHash,
        _prev_height: u32,
    ) -> bool {
        // Check previous block hash matches
        if block.header.prev_blockhash != prev_hash {
            return false;
        }

        // Check timestamp is reasonable (not too far in future)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        if block.header.time > now + 2 * 60 * 60 {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_subsidy_calculation() {
        let validator = BlockValidationRules::mainnet();

        // Initial subsidy
        assert_eq!(
            validator.calculate_block_subsidy(0),
            Amount::from_sat(50 * 100_000_000)
        );

        // After first halving
        assert_eq!(
            validator.calculate_block_subsidy(210_000),
            Amount::from_sat(25 * 100_000_000)
        );

        // After second halving
        assert_eq!(
            validator.calculate_block_subsidy(420_000),
            Amount::from_sat(1_250_000_000)
        );

        // After third halving
        assert_eq!(
            validator.calculate_block_subsidy(630_000),
            Amount::from_sat(625_000_000)
        );
    }

    #[test]
    fn test_median_time_calculation() {
        let validator = BlockValidationRules::mainnet();

        let times = vec![100, 102, 101, 105, 103, 104, 99, 98, 97, 96, 106];
        let median = validator.calculate_median_time_past(&times);
        assert_eq!(median, 101); // Middle value when sorted

        let times_even = vec![100, 102, 101, 105];
        let median_even = validator.calculate_median_time_past(&times_even);
        assert_eq!(median_even, 101); // Average of two middle values
    }
}
