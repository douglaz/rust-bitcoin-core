use anyhow::Result;
use bitcoin::{Script, Transaction, TxOut};
use std::sync::Arc;
use tracing::debug;

/// Trait for providing spent outputs for sigop counting
#[async_trait::async_trait]
pub trait SpentOutputProvider: Send + Sync {
    /// Get the output being spent by a transaction input
    async fn get_spent_output(&self, txid: &bitcoin::Txid, vout: u32) -> Result<Option<TxOut>>;
}

/// Sigop counter for mining that handles accurate counting
pub struct SigopCounter {
    spent_output_provider: Option<Arc<dyn SpentOutputProvider>>,
}

impl Default for SigopCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl SigopCounter {
    /// Create a new sigop counter
    pub fn new() -> Self {
        Self {
            spent_output_provider: None,
        }
    }

    /// Create a sigop counter with spent output provider for accurate P2SH counting
    pub fn with_provider(provider: Arc<dyn SpentOutputProvider>) -> Self {
        Self {
            spent_output_provider: Some(provider),
        }
    }

    /// Count sigops in a transaction
    pub async fn count_transaction_sigops(&self, tx: &Transaction) -> Result<u32> {
        let mut total_sigops = 0u32;

        // Count sigops in outputs
        for output in &tx.output {
            total_sigops += count_sigops_in_script(&output.script_pubkey, false);
        }

        // For non-coinbase transactions, count sigops in inputs
        if !tx.is_coinbase() {
            // Count legacy sigops in script sigs
            for input in &tx.input {
                total_sigops +=
                    count_sigops_in_script(Script::from_bytes(input.script_sig.as_bytes()), false);
            }

            // Count P2SH sigops if we have a provider
            if let Some(ref provider) = self.spent_output_provider {
                for input in &tx.input {
                    if let Some(spent_output) = provider
                        .get_spent_output(&input.previous_output.txid, input.previous_output.vout)
                        .await?
                    {
                        // Check if this is a P2SH output
                        if spent_output.script_pubkey.is_p2sh() {
                            // For P2SH, we need to count sigops in the redeemScript
                            // which is the last item in the script_sig
                            if let Some(redeem_script) =
                                extract_p2sh_redeem_script(&input.script_sig)
                            {
                                total_sigops += count_sigops_in_script(&redeem_script, true);
                            }
                        }
                    }
                }
            }

            // Count witness sigops for segwit transactions
            for (_i, input) in tx.input.iter().enumerate() {
                if !input.witness.is_empty() {
                    // For witness transactions, count sigops in witness script
                    if let Some(witness_script) = input.witness.last() {
                        let script = Script::from_bytes(witness_script);
                        total_sigops += count_sigops_in_script(script, true);
                    }
                }
            }
        }

        debug!(
            "Transaction {} has {} sigops",
            tx.compute_txid(),
            total_sigops
        );

        Ok(total_sigops)
    }

    /// Count sigops in a block's transactions
    pub async fn count_block_sigops(&self, transactions: &[Transaction]) -> Result<u32> {
        let mut total = 0u32;

        for tx in transactions {
            total += self.count_transaction_sigops(tx).await?;
        }

        Ok(total)
    }
}

/// Count signature operations in a script
fn count_sigops_in_script(script: &Script, accurate: bool) -> u32 {
    // This is a simplified sigop counting implementation
    // A full implementation would need to handle all opcodes properly
    let mut count = 0u32;

    for instruction in script.instructions() {
        if let Ok(bitcoin::blockdata::script::Instruction::Op(op)) = instruction {
            use bitcoin::opcodes::all::*;
            match op {
                OP_CHECKSIG | OP_CHECKSIGVERIFY => count += 1,
                OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                    // Without accurate counting, assume worst case
                    count += if accurate { 3 } else { 20 };
                }
                _ => {}
            }
        }
    }

    count
}

/// Extract P2SH redeem script from scriptSig
fn extract_p2sh_redeem_script(script_sig: &bitcoin::ScriptBuf) -> Option<bitcoin::ScriptBuf> {
    let bytes = script_sig.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    // The redeem script is typically the last push in the scriptSig
    // We need to parse backwards to find it
    let mut pos = bytes.len();

    // Try to extract the last data push
    while pos > 0 {
        pos -= 1;
        let op = bytes[pos];

        // Check for push opcodes
        if op <= 75 {
            // Direct push of op bytes
            if pos + 1 + op as usize <= bytes.len() {
                let script_bytes = &bytes[pos + 1..pos + 1 + op as usize];
                return Some(bitcoin::ScriptBuf::from(script_bytes.to_vec()));
            }
        }
    }

    None
}

// Note: UtxoSpentOutputProvider would need to be implemented by the node
// It should connect to the actual UTXO storage backend
// For now, we'll leave this as a placeholder for the actual implementation

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{TxIn, Witness};

    #[tokio::test]
    async fn test_sigop_counting() {
        let counter = SigopCounter::new();

        // Create a simple transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::all_zeros()),
            }],
        };

        let sigops = counter.count_transaction_sigops(&tx).await.unwrap();
        // P2PKH has 1 sigop
        assert!(sigops > 0);
    }
}
