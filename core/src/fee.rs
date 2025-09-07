use anyhow::{bail, Result};
use bitcoin::{Amount, Transaction, TxOut};

/// Fee calculator for Bitcoin transactions
pub struct FeeCalculator {
    /// Minimum relay fee rate in satoshis per virtual byte
    pub min_relay_fee_rate: u64,
    /// Default fee rate in satoshis per virtual byte
    pub default_fee_rate: u64,
}

impl Default for FeeCalculator {
    fn default() -> Self {
        Self {
            min_relay_fee_rate: 1, // 1 sat/vB minimum
            default_fee_rate: 20,  // 20 sat/vB default
        }
    }
}

impl FeeCalculator {
    /// Create a new fee calculator with custom rates
    pub fn new(min_relay_fee_rate: u64, default_fee_rate: u64) -> Self {
        Self {
            min_relay_fee_rate,
            default_fee_rate,
        }
    }

    /// Calculate the fee for a transaction given its inputs
    pub fn calculate_fee(&self, tx: &Transaction, input_values: &[TxOut]) -> Result<Amount> {
        if tx.input.len() != input_values.len() {
            bail!(
                "Input count mismatch: {} transaction inputs vs {} provided values",
                tx.input.len(),
                input_values.len()
            );
        }

        // Calculate total input value
        let total_input: u64 = input_values
            .iter()
            .map(|output| output.value.to_sat())
            .sum();

        // Calculate total output value
        let total_output: u64 = tx.output.iter().map(|output| output.value.to_sat()).sum();

        // Fee is the difference
        if total_input < total_output {
            bail!(
                "Transaction outputs exceed inputs: {} sats in, {} sats out",
                total_input,
                total_output
            );
        }

        let fee = total_input - total_output;
        Ok(Amount::from_sat(fee))
    }

    /// Calculate the fee for a transaction without input lookup
    /// Returns 0 if inputs are not available (e.g., for coinbase)
    pub fn estimate_fee(&self, tx: &Transaction) -> Amount {
        if tx.is_coinbase() {
            return Amount::ZERO;
        }

        // Estimate based on transaction size
        let tx_weight = self.calculate_weight(tx);
        let tx_vsize = tx_weight.div_ceil(4); // Convert weight to vsize

        let fee = tx_vsize as u64 * self.default_fee_rate;
        Amount::from_sat(fee)
    }

    /// Calculate transaction weight (for fee estimation)
    pub fn calculate_weight(&self, tx: &Transaction) -> usize {
        // Proper weight calculation for BIP141
        // Weight = (base_size * 3) + total_size
        // where total_size includes witness data

        let base_size = self.estimate_base_size(tx);
        let witness_size = self.estimate_witness_size(tx);

        if witness_size > 0 {
            // SegWit transaction: base gets 3x weight, total gets 1x
            // total_size = base_size + witness_size
            base_size * 3 + (base_size + witness_size)
        } else {
            // Non-SegWit: weight = size * 4
            base_size * 4
        }
    }

    /// Estimate base transaction size (without witness)
    fn estimate_base_size(&self, tx: &Transaction) -> usize {
        // Version (4) + locktime (4) + input count + output count
        let mut size = 4 + 4;

        // Add compact size for input/output counts
        size += self.compact_size_len(tx.input.len());
        size += self.compact_size_len(tx.output.len());

        // Each input: prevout (36) + script_sig + sequence (4)
        for input in &tx.input {
            size += 36; // txid (32) + vout (4)
            size += self.compact_size_len(input.script_sig.len());
            size += input.script_sig.len();
            size += 4; // sequence
        }

        // Each output: value (8) + script_pubkey
        for output in &tx.output {
            size += 8; // value
            size += self.compact_size_len(output.script_pubkey.len());
            size += output.script_pubkey.len();
        }

        size
    }

    /// Estimate witness size
    fn estimate_witness_size(&self, tx: &Transaction) -> usize {
        let mut size = 0;

        // Check if any input has witness data
        let has_witness = tx.input.iter().any(|input| !input.witness.is_empty());

        if has_witness {
            // Marker (1) + flag (1)
            size += 2;

            // Each witness
            for input in &tx.input {
                if input.witness.is_empty() {
                    size += 1; // Empty witness stack
                } else {
                    size += self.compact_size_len(input.witness.len());
                    for item in input.witness.iter() {
                        size += self.compact_size_len(item.len());
                        size += item.len();
                    }
                }
            }
        }

        size
    }

    /// Calculate compact size length
    fn compact_size_len(&self, n: usize) -> usize {
        if n < 0xfd {
            1
        } else if n <= 0xffff {
            3
        } else if n <= 0xffffffff {
            5
        } else {
            9
        }
    }

    /// Check if a fee meets the minimum relay requirement
    pub fn meets_minimum_relay(&self, fee: Amount, tx_weight: usize) -> bool {
        let tx_vsize = tx_weight.div_ceil(4);
        let min_fee = tx_vsize as u64 * self.min_relay_fee_rate;
        fee.to_sat() >= min_fee
    }

    /// Calculate fee rate in satoshis per virtual byte
    pub fn calculate_fee_rate(&self, fee: Amount, tx: &Transaction) -> u64 {
        let tx_weight = self.calculate_weight(tx);
        let tx_vsize = tx_weight.div_ceil(4);

        if tx_vsize == 0 {
            return 0;
        }

        fee.to_sat() / tx_vsize as u64
    }

    /// Get minimum fee for a transaction
    pub fn get_minimum_fee(&self, tx: &Transaction) -> Amount {
        let tx_weight = self.calculate_weight(tx);
        let tx_vsize = tx_weight.div_ceil(4);
        let min_fee = tx_vsize as u64 * self.min_relay_fee_rate;
        Amount::from_sat(min_fee)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    #[test]
    fn test_fee_calculation() -> Result<()> {
        let calc = FeeCalculator::default();

        // Create a simple transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // Input with 100000 sats
        let inputs = vec![TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: ScriptBuf::new(),
        }];

        let fee = calc.calculate_fee(&tx, &inputs)?;
        assert_eq!(fee.to_sat(), 50000); // 100000 - 50000 = 50000

        Ok(())
    }

    #[test]
    fn test_fee_estimation() {
        let calc = FeeCalculator::default();

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let fee = calc.estimate_fee(&tx);
        assert!(fee.to_sat() > 0);
    }

    #[test]
    fn test_minimum_relay_fee() {
        let calc = FeeCalculator::new(1, 20);

        let fee = Amount::from_sat(200);
        let tx_weight = 800; // 200 vbytes

        assert!(calc.meets_minimum_relay(fee, tx_weight));

        let low_fee = Amount::from_sat(100);
        assert!(!calc.meets_minimum_relay(low_fee, tx_weight));
    }
}
