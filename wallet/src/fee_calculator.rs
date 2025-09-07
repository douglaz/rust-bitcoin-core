use anyhow::{bail, Result};
use bitcoin::blockdata::transaction::OutPoint;
use bitcoin::{Address, Network, ScriptBuf, Transaction, TxOut};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// Fee estimation modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeeEstimationMode {
    /// Conservative - likely to be included quickly
    Conservative,
    /// Economical - balance between cost and speed
    Economical,
    /// Priority - high fee for fast inclusion
    Priority,
    /// Custom - user-specified fee rate
    Custom(u64),
}

/// Fee rate in satoshis per virtual byte
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FeeRate {
    /// Satoshis per virtual byte
    pub sat_per_vbyte: u64,
}

impl FeeRate {
    /// Create from satoshis per vbyte
    pub fn from_sat_per_vbyte(rate: u64) -> Self {
        Self {
            sat_per_vbyte: rate,
        }
    }

    /// Create from BTC per kilobyte
    pub fn from_btc_per_kb(btc: f64) -> Self {
        // Convert BTC/KB to sat/vB
        // 1 BTC = 100,000,000 sats
        // 1 KB = 1000 bytes
        let sat_per_byte = (btc * 100_000_000.0 / 1000.0) as u64;
        Self {
            sat_per_vbyte: sat_per_byte,
        }
    }

    /// Calculate fee for transaction size
    pub fn calculate_fee(&self, vsize: usize) -> u64 {
        self.sat_per_vbyte * vsize as u64
    }
}

/// Input type for size calculation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputType {
    /// Pay to Public Key Hash (legacy)
    P2PKH,
    /// Pay to Script Hash (legacy)
    P2SH,
    /// Pay to Witness Public Key Hash (native segwit)
    P2WPKH,
    /// Pay to Witness Script Hash (native segwit)
    P2WSH,
    /// Pay to Taproot
    P2TR,
    /// Nested P2WPKH in P2SH
    P2SH_P2WPKH,
    /// Nested P2WSH in P2SH
    P2SH_P2WSH,
}

impl InputType {
    /// Get weight units for this input type
    pub fn weight_units(&self) -> usize {
        match self {
            // Legacy inputs (weight = size * 4)
            InputType::P2PKH => 148 * 4, // ~148 bytes
            InputType::P2SH => 298 * 4,  // ~298 bytes (2-of-3 multisig)

            // Native SegWit (witness discounted)
            InputType::P2WPKH => 68 * 4 + 107, // 68 non-witness + ~27 witness
            InputType::P2WSH => 104 * 4 + 255, // 104 non-witness + ~64 witness (2-of-3)

            // Taproot
            InputType::P2TR => 58 * 4 + 65, // 58 non-witness + ~16 witness (key path)

            // Nested SegWit
            InputType::P2SH_P2WPKH => 91 * 4 + 107, // 91 non-witness + ~27 witness
            InputType::P2SH_P2WSH => 127 * 4 + 255, // 127 non-witness + ~64 witness
        }
    }

    /// Detect input type from script
    pub fn from_script(script: &ScriptBuf) -> Self {
        if script.is_p2pkh() {
            InputType::P2PKH
        } else if script.is_p2sh() {
            // Can't distinguish nested segwit without more info
            InputType::P2SH
        } else if script.is_p2wpkh() {
            InputType::P2WPKH
        } else if script.is_p2wsh() {
            InputType::P2WSH
        } else if script.is_p2tr() {
            InputType::P2TR
        } else {
            // Default to P2PKH for unknown
            InputType::P2PKH
        }
    }
}

/// Output type for size calculation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputType {
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR,
    OpReturn(usize), // Size of OP_RETURN data
}

impl OutputType {
    /// Get size in bytes for this output type
    pub fn size_bytes(&self) -> usize {
        match self {
            OutputType::P2PKH => 34,  // 8 (amount) + 1 (script len) + 25 (script)
            OutputType::P2SH => 32,   // 8 + 1 + 23
            OutputType::P2WPKH => 31, // 8 + 1 + 22
            OutputType::P2WSH => 43,  // 8 + 1 + 34
            OutputType::P2TR => 43,   // 8 + 1 + 34
            OutputType::OpReturn(size) => 8 + 1 + 1 + size, // 8 + len + OP_RETURN + data
        }
    }

    /// Detect output type from address
    pub fn from_address(address: &Address) -> Self {
        // Check address type by looking at the script
        let script = address.script_pubkey();
        if script.is_p2pkh() {
            OutputType::P2PKH
        } else if script.is_p2sh() {
            OutputType::P2SH
        } else if script.is_p2wpkh() {
            OutputType::P2WPKH
        } else if script.is_p2wsh() {
            OutputType::P2WSH
        } else if script.is_p2tr() {
            OutputType::P2TR
        } else {
            OutputType::P2PKH // Default
        }
    }
}

/// Fee calculator for Bitcoin transactions
pub struct FeeCalculator {
    /// Current fee rates for different priorities
    fee_rates: HashMap<FeeEstimationMode, FeeRate>,

    /// Network type
    network: Network,

    /// Minimum relay fee (sat/vB)
    min_relay_fee: u64,

    /// Dust threshold (sats)
    dust_threshold: u64,
}

impl FeeCalculator {
    /// Create new fee calculator
    pub fn new(network: Network) -> Self {
        let mut fee_rates = HashMap::new();

        // Default fee rates (these should be updated from network/mempool)
        fee_rates.insert(FeeEstimationMode::Priority, FeeRate::from_sat_per_vbyte(50));
        fee_rates.insert(
            FeeEstimationMode::Conservative,
            FeeRate::from_sat_per_vbyte(20),
        );
        fee_rates.insert(
            FeeEstimationMode::Economical,
            FeeRate::from_sat_per_vbyte(10),
        );

        Self {
            fee_rates,
            network,
            min_relay_fee: 1,    // 1 sat/vB minimum
            dust_threshold: 546, // Standard dust threshold
        }
    }

    /// Update fee rates from network/mempool data
    pub fn update_fee_rates(&mut self, rates: HashMap<FeeEstimationMode, FeeRate>) {
        self.fee_rates = rates;
        info!("Updated fee rates: {:?}", self.fee_rates);
    }

    /// Get current fee rate for mode
    pub fn get_fee_rate(&self, mode: FeeEstimationMode) -> FeeRate {
        match mode {
            FeeEstimationMode::Custom(rate) => FeeRate::from_sat_per_vbyte(rate),
            _ => self
                .fee_rates
                .get(&mode)
                .copied()
                .unwrap_or_else(|| FeeRate::from_sat_per_vbyte(10)),
        }
    }

    /// Calculate transaction size in virtual bytes
    pub fn calculate_vsize(
        &self,
        inputs: &[(OutPoint, InputType)],
        outputs: &[OutputType],
        has_change: bool,
    ) -> usize {
        // Base transaction overhead
        // Version (4) + Input count (1-9) + Output count (1-9) + Locktime (4)
        let mut weight = 10 * 4; // Base weight

        // Add varint for input count
        weight += self.varint_size(inputs.len()) * 4;

        // Add input weights
        for (_, input_type) in inputs {
            weight += input_type.weight_units();
        }

        // Add varint for output count
        let output_count = outputs.len() + if has_change { 1 } else { 0 };
        weight += self.varint_size(output_count) * 4;

        // Add output weights
        for output_type in outputs {
            weight += output_type.size_bytes() * 4;
        }

        // Add change output if needed (assume same type as first input)
        if has_change && !inputs.is_empty() {
            let change_type = match inputs[0].1 {
                InputType::P2PKH => OutputType::P2PKH,
                InputType::P2WPKH | InputType::P2SH_P2WPKH => OutputType::P2WPKH,
                InputType::P2WSH | InputType::P2SH_P2WSH => OutputType::P2WSH,
                InputType::P2TR => OutputType::P2TR,
                _ => OutputType::P2WPKH,
            };
            weight += change_type.size_bytes() * 4;
        }

        // Add witness flag if any segwit inputs
        let has_witness = inputs.iter().any(|(_, t)| {
            matches!(
                t,
                InputType::P2WPKH
                    | InputType::P2WSH
                    | InputType::P2TR
                    | InputType::P2SH_P2WPKH
                    | InputType::P2SH_P2WSH
            )
        });

        if has_witness {
            weight += 2; // Witness flag and marker
        }

        // Convert weight to vbytes (round up)
        weight.div_ceil(4)
    }

    /// Calculate fee for transaction
    pub fn calculate_fee(
        &self,
        inputs: &[(OutPoint, InputType)],
        outputs: &[OutputType],
        has_change: bool,
        mode: FeeEstimationMode,
    ) -> u64 {
        let vsize = self.calculate_vsize(inputs, outputs, has_change);
        let fee_rate = self.get_fee_rate(mode);

        let fee = fee_rate.calculate_fee(vsize);

        // Ensure minimum relay fee
        fee.max(self.min_relay_fee * vsize as u64)
    }

    /// Calculate fee for existing transaction
    pub fn calculate_fee_for_tx(&self, tx: &Transaction, mode: FeeEstimationMode) -> u64 {
        let vsize = tx.vsize();
        let fee_rate = self.get_fee_rate(mode);

        let fee = fee_rate.calculate_fee(vsize);
        fee.max(self.min_relay_fee * vsize as u64)
    }

    /// Check if output amount is dust
    pub fn is_dust(&self, amount: u64, output_type: OutputType) -> bool {
        // Dust calculation based on output type
        let dust_threshold = match output_type {
            OutputType::P2PKH => 546,
            OutputType::P2SH => 540,
            OutputType::P2WPKH => 294,
            OutputType::P2WSH => 330,
            OutputType::P2TR => 330,
            OutputType::OpReturn(_) => 0, // OP_RETURN is never dust
        };

        amount < dust_threshold
    }

    /// Estimate fee for sending amount to address
    pub fn estimate_send_fee(
        &self,
        from_utxos: &[(OutPoint, TxOut)],
        to_address: &Address,
        amount: u64,
        mode: FeeEstimationMode,
    ) -> Result<u64> {
        if from_utxos.is_empty() {
            bail!("No UTXOs provided");
        }

        // Determine input types
        let inputs: Vec<(OutPoint, InputType)> = from_utxos
            .iter()
            .map(|(outpoint, txout)| {
                let input_type = InputType::from_script(&txout.script_pubkey);
                (*outpoint, input_type)
            })
            .collect();

        // Determine output type
        let output_type = OutputType::from_address(to_address);

        // Calculate with change output
        let fee_with_change = self.calculate_fee(&inputs, &[output_type], true, mode);

        // Check if we need change
        let total_input = from_utxos
            .iter()
            .map(|(_, out)| out.value.to_sat())
            .sum::<u64>();
        let total_output = amount + fee_with_change;

        if total_input < total_output {
            bail!("Insufficient funds: {} < {}", total_input, total_output);
        }

        let change_amount = total_input - total_output;

        // If change is dust, don't create change output
        let change_type = match inputs[0].1 {
            InputType::P2PKH => OutputType::P2PKH,
            InputType::P2WPKH | InputType::P2SH_P2WPKH => OutputType::P2WPKH,
            InputType::P2WSH | InputType::P2SH_P2WSH => OutputType::P2WSH,
            InputType::P2TR => OutputType::P2TR,
            _ => OutputType::P2WPKH,
        };

        if self.is_dust(change_amount, change_type) {
            // Recalculate without change
            let fee_without_change = self.calculate_fee(&inputs, &[output_type], false, mode);

            Ok(fee_without_change)
        } else {
            Ok(fee_with_change)
        }
    }

    /// Calculate CPFP (Child Pays For Parent) fee
    pub fn calculate_cpfp_fee(
        &self,
        parent_tx: &Transaction,
        parent_fee: u64,
        target_fee_rate: FeeRate,
    ) -> Result<u64> {
        let parent_vsize = parent_tx.vsize();
        let parent_fee_rate = parent_fee / parent_vsize as u64;

        if parent_fee_rate >= target_fee_rate.sat_per_vbyte {
            bail!("Parent transaction already has sufficient fee rate");
        }

        // Estimate child transaction size (1 input from parent, 1 output)
        let child_vsize = 150; // Approximate for P2WPKH input and output

        // Calculate total fee needed for both transactions
        let total_vsize = parent_vsize + child_vsize;
        let total_fee_needed = target_fee_rate.calculate_fee(total_vsize);

        // Child must pay the difference
        let child_fee = total_fee_needed.saturating_sub(parent_fee);

        debug!(
            "CPFP calculation: parent_vsize={}, parent_fee={}, child_fee={}",
            parent_vsize, parent_fee, child_fee
        );

        Ok(child_fee)
    }

    /// Calculate RBF (Replace By Fee) fee
    pub fn calculate_rbf_fee(
        &self,
        original_tx: &Transaction,
        original_fee: u64,
        target_fee_rate: FeeRate,
    ) -> Result<u64> {
        let vsize = original_tx.vsize();
        let new_fee = target_fee_rate.calculate_fee(vsize);

        // BIP125 requires new fee to be at least original + relay fee increment
        let min_fee = original_fee + (self.min_relay_fee * vsize as u64);

        Ok(new_fee.max(min_fee))
    }

    /// Get varint size
    fn varint_size(&self, n: usize) -> usize {
        match n {
            0..=252 => 1,
            253..=65535 => 3,
            65536..=4294967295 => 5,
            _ => 9,
        }
    }
}

/// Fee estimator that queries network/mempool
pub struct NetworkFeeEstimator {
    calculator: FeeCalculator,
    mempool_stats: MempoolStats,
}

/// Mempool statistics for fee estimation
#[derive(Debug, Clone, Default)]
pub struct MempoolStats {
    pub size: usize,
    pub bytes: usize,
    pub min_fee: u64,
    pub max_fee: u64,
    pub median_fee: u64,
    pub fee_histogram: Vec<(u64, usize)>, // (fee_rate, count)
}

impl NetworkFeeEstimator {
    /// Create new network fee estimator
    pub fn new(network: Network) -> Self {
        Self {
            calculator: FeeCalculator::new(network),
            mempool_stats: MempoolStats::default(),
        }
    }

    /// Update from mempool statistics
    pub fn update_from_mempool(&mut self, stats: MempoolStats) {
        self.mempool_stats = stats;

        // Calculate fee rates based on mempool
        let mut rates = HashMap::new();

        // Priority: Top 10% of fees
        if let Some(&(fee, _)) = self.mempool_stats.fee_histogram.first() {
            rates.insert(
                FeeEstimationMode::Priority,
                FeeRate::from_sat_per_vbyte(fee),
            );
        }

        // Conservative: Median fee
        rates.insert(
            FeeEstimationMode::Conservative,
            FeeRate::from_sat_per_vbyte(self.mempool_stats.median_fee.max(10)),
        );

        // Economical: 25th percentile
        let economical_fee = self.calculate_percentile_fee(25).unwrap_or(5);
        rates.insert(
            FeeEstimationMode::Economical,
            FeeRate::from_sat_per_vbyte(economical_fee),
        );

        self.calculator.update_fee_rates(rates);
    }

    /// Calculate fee at percentile
    fn calculate_percentile_fee(&self, percentile: usize) -> Option<u64> {
        if self.mempool_stats.fee_histogram.is_empty() {
            return None;
        }

        let total: usize = self
            .mempool_stats
            .fee_histogram
            .iter()
            .map(|(_, count)| count)
            .sum();

        let target = (total * percentile) / 100;
        let mut cumulative = 0;

        for &(fee_rate, count) in &self.mempool_stats.fee_histogram {
            cumulative += count;
            if cumulative >= target {
                return Some(fee_rate);
            }
        }

        self.mempool_stats.fee_histogram.last().map(|&(fee, _)| fee)
    }

    /// Estimate confirmation time for fee rate
    pub fn estimate_confirmation_time(&self, fee_rate: FeeRate) -> usize {
        // Simple estimation based on mempool position
        let mut position = 0;
        let mut block_count = 0;

        for &(rate, count) in &self.mempool_stats.fee_histogram {
            if rate >= fee_rate.sat_per_vbyte {
                position += count;
            }
        }

        // Assume ~1MB blocks, ~250 vB average tx
        let txs_per_block = 4000;
        block_count = (position / txs_per_block) + 1;

        block_count.min(100) // Cap at 100 blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    #[test]
    fn test_fee_calculation() {
        let calc = FeeCalculator::new(Network::Bitcoin);

        // Test P2WPKH -> P2WPKH transaction
        let inputs = vec![(
            OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            InputType::P2WPKH,
        )];

        let outputs = vec![OutputType::P2WPKH];

        let fee = calc.calculate_fee(
            &inputs,
            &outputs,
            true, // has change
            FeeEstimationMode::Economical,
        );

        assert!(fee > 0);

        // Verify vsize calculation
        let vsize = calc.calculate_vsize(&inputs, &outputs, true);
        assert!(vsize > 100 && vsize < 200); // Typical P2WPKH tx size
    }

    #[test]
    fn test_dust_detection() {
        let calc = FeeCalculator::new(Network::Bitcoin);

        assert!(calc.is_dust(100, OutputType::P2PKH));
        assert!(calc.is_dust(200, OutputType::P2WPKH));
        assert!(!calc.is_dust(1000, OutputType::P2WPKH));
        assert!(!calc.is_dust(0, OutputType::OpReturn(20)));
    }

    #[test]
    fn test_input_type_weights() {
        assert!(InputType::P2PKH.weight_units() > InputType::P2WPKH.weight_units());
        assert!(InputType::P2TR.weight_units() < InputType::P2WPKH.weight_units());
        assert!(InputType::P2SH.weight_units() > InputType::P2SH_P2WPKH.weight_units());
    }
}
