use bitcoin::psbt::Psbt;
use bitcoin::{
    absolute::LockTime, transaction::Version, Address, Amount, Network, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use tracing::info;

use crate::balance::{BalanceTracker, Utxo};
use crate::error::{WalletError, WalletResult};
use crate::keychain::KeyChain;
use btc_core::fee_estimation::{FeeEstimator, FeePriority};

/// Fee rate in satoshis per vByte
#[derive(Debug, Clone, Copy)]
pub struct FeeRate(pub u64);

impl FeeRate {
    /// Create from sat/vB
    pub fn from_sat_per_vb(sat_per_vb: u64) -> Self {
        Self(sat_per_vb)
    }

    /// Calculate fee for transaction size
    pub fn calculate_fee(&self, tx_size: usize) -> Amount {
        Amount::from_sat(self.0 * tx_size as u64)
    }
}

/// Signed transaction ready for broadcast
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub fee: Amount,
    pub size: usize,
    pub weight: usize,
}

/// Transaction builder
pub struct TransactionBuilder<'a> {
    keychain: &'a KeyChain,
    balance_tracker: &'a BalanceTracker,
    inputs: Vec<Utxo>,
    outputs: Vec<(Address, Amount)>,
    change_address: Option<Address>,
    fee_rate: FeeRate,
    network: Network,
    coin_selection_algorithm: Option<crate::coin_selection::CoinSelectionAlgorithm>,
    fee_estimator: Option<&'a FeeEstimator>,
    fee_priority: FeePriority,
}

impl<'a> TransactionBuilder<'a> {
    /// Create a new transaction builder
    pub fn new(
        keychain: &'a KeyChain,
        balance_tracker: &'a BalanceTracker,
        network: Network,
    ) -> Self {
        Self {
            keychain,
            balance_tracker,
            inputs: Vec::new(),
            outputs: Vec::new(),
            change_address: None,
            fee_rate: FeeRate::from_sat_per_vb(10), // Default 10 sat/vB
            network,
            coin_selection_algorithm: None,
            fee_estimator: None,
            fee_priority: FeePriority::Medium,
        }
    }

    /// Add a recipient
    pub fn add_recipient(mut self, address: Address, amount: Amount) -> Self {
        self.outputs.push((address, amount));
        self
    }

    /// Set change address
    pub fn change_address(mut self, address: Address) -> Self {
        self.change_address = Some(address);
        self
    }

    /// Set fee rate
    pub fn fee_rate(mut self, rate: FeeRate) -> Self {
        self.fee_rate = rate;
        self
    }

    /// Set specific coin selection algorithm
    pub fn with_coin_selection(
        mut self,
        algorithm: crate::coin_selection::CoinSelectionAlgorithm,
    ) -> Self {
        self.coin_selection_algorithm = Some(algorithm);
        self
    }

    /// Set fee estimator for dynamic fee calculation
    pub fn with_fee_estimator(mut self, estimator: &'a FeeEstimator) -> Self {
        self.fee_estimator = Some(estimator);
        self
    }

    /// Set fee priority for dynamic fee calculation
    pub fn fee_priority(mut self, priority: FeePriority) -> Self {
        self.fee_priority = priority;
        self
    }

    /// Build and sign the transaction
    pub fn build_and_sign(mut self) -> WalletResult<SignedTransaction> {
        info!("Building transaction with {} outputs", self.outputs.len());

        // Use dynamic fee estimation if available
        if let Some(estimator) = self.fee_estimator {
            let confirmation_target = match self.fee_priority {
                FeePriority::High => 1,   // Next block
                FeePriority::Medium => 6, // ~1 hour
                FeePriority::Low => 144,  // ~1 day
            };

            let smart_fee = estimator.estimate_smart_fee(confirmation_target);
            let recommended_fee = smart_fee.get_recommended_fee(self.fee_priority);
            self.fee_rate = FeeRate::from_sat_per_vb(recommended_fee.as_sat_per_vb());

            info!(
                "Using dynamic fee rate: {} sat/vB for priority {:?}",
                self.fee_rate.0, self.fee_priority
            );
        }

        // Calculate total output amount
        let total_output: Amount = self.outputs.iter().map(|(_, amount)| *amount).sum();

        // Use advanced coin selection
        let algorithm = self
            .coin_selection_algorithm
            .unwrap_or(crate::coin_selection::CoinSelectionAlgorithm::BranchAndBound);

        // Create coin selector
        let spendable: Vec<Utxo> = self
            .balance_tracker
            .get_spendable_utxos()
            .into_iter()
            .cloned()
            .collect();

        let selector = crate::coin_selection::CoinSelector::new(spendable, self.fee_rate)
            .with_algorithm(algorithm);

        // Select coins
        let selection = selector.select_coins(total_output)?;
        self.inputs = selection.selected_utxos;

        // Use the selection's calculated amounts
        let total_input = selection.total_input;
        let fee = selection.fee;
        let change = selection.change_amount;

        // Build transaction
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };

        // Add inputs
        for utxo in &self.inputs {
            tx.input.push(TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
        }

        // Add outputs
        for (address, amount) in &self.outputs {
            tx.output.push(TxOut {
                value: *amount,
                script_pubkey: address.script_pubkey(),
            });
        }

        // Add change output if needed
        if change > Amount::from_sat(546) {
            // Dust threshold
            let change_addr = self
                .change_address
                .clone()
                .ok_or_else(|| WalletError::Other(anyhow::anyhow!("Change address required")))?;

            tx.output.push(TxOut {
                value: change,
                script_pubkey: change_addr.script_pubkey(),
            });
        }

        // Sign transaction
        self.sign_transaction(&mut tx)?;

        let size = bitcoin::consensus::encode::serialize(&tx).len();
        let weight = tx.weight().to_wu() as usize;

        info!(
            "Transaction built - Size: {} bytes, Weight: {} WU, Fee: {} sats",
            size, weight, fee
        );

        Ok(SignedTransaction {
            transaction: tx,
            fee,
            size,
            weight,
        })
    }

    /// Sign the transaction
    fn sign_transaction(&self, tx: &mut Transaction) -> WalletResult<()> {
        use crate::signer::{DerivationPathFinder, TransactionSigner};

        // Create signer
        let signer = TransactionSigner::new(self.network);

        // Find derivation paths for each UTXO
        let path_finder = DerivationPathFinder::new(self.keychain.clone(), self.network);
        let mut paths = Vec::new();

        for utxo in &self.inputs {
            // Try to find the derivation path for this UTXO
            // For now, use a default path if we can't find it
            let path = path_finder.find_path_for_utxo(utxo).unwrap_or_else(|_| {
                // Default to BIP84 receive address 0
                KeyChain::bip84_path(0, 0, 0).unwrap()
            });
            paths.push(path);
        }

        // Sign the transaction
        signer.sign_transaction(tx, &self.inputs, self.keychain, &paths)?;

        Ok(())
    }

    /// Estimate transaction size
    fn estimate_size(&self) -> usize {
        // Rough estimation:
        // - Version: 4 bytes
        // - Input count: 1-9 bytes
        // - Each input: ~148 bytes (P2WPKH)
        // - Output count: 1-9 bytes
        // - Each output: ~34 bytes
        // - Locktime: 4 bytes

        let base_size = 10; // version + counts + locktime
        let input_size = self.inputs.len() * 148;
        let output_size = (self.outputs.len() + 1) * 34; // +1 for potential change

        base_size + input_size + output_size
    }
}

/// Create a PSBT (Partially Signed Bitcoin Transaction)
pub fn create_psbt(
    inputs: Vec<Utxo>,
    outputs: Vec<(Address, Amount)>,
    _network: Network,
) -> WalletResult<Psbt> {
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    };

    // Add inputs
    for utxo in &inputs {
        tx.input.push(TxIn {
            previous_output: utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }

    // Add outputs
    for (address, amount) in outputs {
        tx.output.push(TxOut {
            value: amount,
            script_pubkey: address.script_pubkey(),
        });
    }

    // Create PSBT
    let mut psbt = Psbt::from_unsigned_tx(tx)
        .map_err(|e| WalletError::Other(anyhow::anyhow!("Failed to create PSBT: {}", e)))?;

    // Add input information
    for (idx, utxo) in inputs.iter().enumerate() {
        psbt.inputs[idx].witness_utxo = Some(utxo.output.clone());
    }

    Ok(psbt)
}
