use bitcoin::{
    absolute::LockTime, transaction::Version, Address, Amount, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Txid,
};
use std::str::FromStr;
use tracing::info;

use crate::error::{WalletError, WalletResult};

/// Raw transaction builder for creating custom transactions
pub struct RawTransactionBuilder {
    version: Version,
    lock_time: LockTime,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    network: Network,
}

impl RawTransactionBuilder {
    /// Create a new raw transaction builder
    pub fn new(network: Network) -> Self {
        Self {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: Vec::new(),
            outputs: Vec::new(),
            network,
        }
    }

    /// Set transaction version
    pub fn version(mut self, version: i32) -> Self {
        self.version = Version(version);
        self
    }

    /// Set lock time
    pub fn lock_time(mut self, lock_time: u32) -> Self {
        self.lock_time = LockTime::from_consensus(lock_time);
        self
    }

    /// Add an input by outpoint
    pub fn add_input(mut self, txid: &str, vout: u32, sequence: Option<u32>) -> WalletResult<Self> {
        let txid = Txid::from_str(txid)
            .map_err(|e| WalletError::Other(anyhow::anyhow!("Invalid txid: {}", e)))?;

        let outpoint = OutPoint { txid, vout };

        let sequence = sequence
            .map(Sequence::from_consensus)
            .unwrap_or(Sequence::ENABLE_RBF_NO_LOCKTIME);

        self.inputs.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: bitcoin::Witness::new(),
        });

        Ok(self)
    }

    /// Add an input with custom script_sig
    pub fn add_input_with_script(
        mut self,
        txid: &str,
        vout: u32,
        script_sig: ScriptBuf,
        sequence: Option<u32>,
    ) -> WalletResult<Self> {
        let txid = Txid::from_str(txid)
            .map_err(|e| WalletError::Other(anyhow::anyhow!("Invalid txid: {}", e)))?;

        let outpoint = OutPoint { txid, vout };

        let sequence = sequence
            .map(Sequence::from_consensus)
            .unwrap_or(Sequence::ENABLE_RBF_NO_LOCKTIME);

        self.inputs.push(TxIn {
            previous_output: outpoint,
            script_sig,
            sequence,
            witness: bitcoin::Witness::new(),
        });

        Ok(self)
    }

    /// Add an output
    pub fn add_output(mut self, address: &str, amount_sats: u64) -> WalletResult<Self> {
        let address = Address::from_str(address)
            .map_err(|e| WalletError::Other(anyhow::anyhow!("Invalid address: {}", e)))?
            .require_network(self.network)
            .map_err(|e| WalletError::Other(anyhow::anyhow!("Wrong network for address: {}", e)))?;

        self.outputs.push(TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: address.script_pubkey(),
        });

        Ok(self)
    }

    /// Add an output with custom script
    pub fn add_output_with_script(mut self, script_pubkey: ScriptBuf, amount_sats: u64) -> Self {
        self.outputs.push(TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey,
        });

        self
    }

    /// Add a data output (OP_RETURN)
    pub fn add_data_output(mut self, data: &[u8]) -> WalletResult<Self> {
        if data.len() > 80 {
            return Err(WalletError::Other(anyhow::anyhow!(
                "Data output too large: {} bytes (max 80)",
                data.len()
            )));
        }

        // Build OP_RETURN script manually
        let mut script_bytes = Vec::new();
        script_bytes.push(bitcoin::opcodes::all::OP_RETURN.to_u8());
        if !data.is_empty() {
            if data.len() <= 75 {
                script_bytes.push(data.len() as u8);
                script_bytes.extend_from_slice(data);
            } else {
                script_bytes.push(bitcoin::opcodes::all::OP_PUSHDATA1.to_u8());
                script_bytes.push(data.len() as u8);
                script_bytes.extend_from_slice(data);
            }
        }

        let script = ScriptBuf::from(script_bytes);

        self.outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        });

        Ok(self)
    }

    /// Build the transaction
    pub fn build(self) -> WalletResult<Transaction> {
        if self.inputs.is_empty() {
            return Err(WalletError::Other(anyhow::anyhow!(
                "Transaction must have at least one input"
            )));
        }

        if self.outputs.is_empty() {
            return Err(WalletError::Other(anyhow::anyhow!(
                "Transaction must have at least one output"
            )));
        }

        let tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self.inputs,
            output: self.outputs,
        };

        info!(
            "Built raw transaction - {} inputs, {} outputs, size: {} bytes",
            tx.input.len(),
            tx.output.len(),
            bitcoin::consensus::encode::serialize(&tx).len()
        );

        Ok(tx)
    }

    /// Calculate transaction size (without witness data)
    pub fn estimate_size(&self) -> usize {
        // Version: 4 bytes
        // Input count: 1-9 bytes (varint)
        // Output count: 1-9 bytes (varint)
        // Lock time: 4 bytes
        let base_size = 4 + 1 + 1 + 4;

        // Each input: 32 (txid) + 4 (vout) + 1 (script_sig length) + script_sig + 4 (sequence)
        let input_size: usize = self
            .inputs
            .iter()
            .map(|i| 32 + 4 + 1 + i.script_sig.len() + 4)
            .sum();

        // Each output: 8 (value) + 1 (script_pubkey length) + script_pubkey
        let output_size: usize = self
            .outputs
            .iter()
            .map(|o| 8 + 1 + o.script_pubkey.len())
            .sum();

        base_size + input_size + output_size
    }

    /// Calculate virtual size (vsize) for fee estimation
    pub fn estimate_vsize(&self) -> usize {
        // For non-segwit transactions, vsize = size
        // For segwit, we'd need to account for witness data
        self.estimate_size()
    }
}

/// Create a transaction for sending from multiple inputs to multiple outputs
pub fn create_multi_input_transaction(
    inputs: Vec<(String, u32)>,  // (txid, vout)
    outputs: Vec<(String, u64)>, // (address, amount_sats)
    network: Network,
) -> WalletResult<Transaction> {
    let mut builder = RawTransactionBuilder::new(network);

    // Add all inputs
    for (txid, vout) in inputs {
        builder = builder.add_input(&txid, vout, None)?;
    }

    // Add all outputs
    for (address, amount) in outputs {
        builder = builder.add_output(&address, amount)?;
    }

    builder.build()
}

/// Create a transaction that consolidates UTXOs
pub fn create_consolidation_transaction(
    inputs: Vec<(String, u32)>, // (txid, vout)
    destination: &str,
    fee_sats: u64,
    input_total_sats: u64,
    network: Network,
) -> WalletResult<Transaction> {
    if input_total_sats <= fee_sats {
        return Err(WalletError::Other(anyhow::anyhow!(
            "Input total {} sats is not enough to cover fee {} sats",
            input_total_sats,
            fee_sats
        )));
    }

    let mut builder = RawTransactionBuilder::new(network);

    // Add all inputs
    for (txid, vout) in inputs {
        builder = builder.add_input(&txid, vout, None)?;
    }

    // Add single output with amount minus fee
    let output_amount = input_total_sats - fee_sats;
    builder = builder.add_output(destination, output_amount)?;

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_transaction_builder() {
        let network = Network::Bitcoin;
        let builder = RawTransactionBuilder::new(network);

        let tx = builder
            .add_input(
                "0000000000000000000000000000000000000000000000000000000000000001",
                0,
                None,
            )
            .unwrap()
            .add_output("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 100000)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::from_sat(100000));
    }

    #[test]
    fn test_data_output() {
        let network = Network::Bitcoin;
        let builder = RawTransactionBuilder::new(network);

        let data = b"Hello, Bitcoin!";
        let tx = builder
            .add_input(
                "0000000000000000000000000000000000000000000000000000000000000001",
                0,
                None,
            )
            .unwrap()
            .add_data_output(data)
            .unwrap()
            .add_output("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 100000)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value, Amount::ZERO);
        assert!(tx.output[0].script_pubkey.is_op_return());
    }
}
