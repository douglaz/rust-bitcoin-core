use bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

use crate::error::WalletResult;

/// UTXO (Unspent Transaction Output)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub output: TxOut,
    pub height: Option<u32>,
    pub address: String,
    pub confirmations: u32,
}

/// Wallet balance information
#[derive(Debug, Clone, Default)]
pub struct Balance {
    /// Confirmed balance (6+ confirmations)
    pub confirmed: Amount,
    /// Pending balance (1-5 confirmations)
    pub pending: Amount,
    /// Unconfirmed balance (0 confirmations)
    pub unconfirmed: Amount,
    /// Total balance (all)
    pub total: Amount,
}

impl Balance {
    /// Create a new balance
    pub fn new() -> Self {
        Self::default()
    }

    /// Get spendable balance (confirmed only)
    pub fn spendable(&self) -> Amount {
        self.confirmed
    }

    /// Update balance from amounts
    pub fn from_amounts(confirmed: u64, pending: u64, unconfirmed: u64) -> Self {
        let confirmed = Amount::from_sat(confirmed);
        let pending = Amount::from_sat(pending);
        let unconfirmed = Amount::from_sat(unconfirmed);
        let total = confirmed + pending + unconfirmed;

        Self {
            confirmed,
            pending,
            unconfirmed,
            total,
        }
    }
}

/// Balance tracker for wallet
pub struct BalanceTracker {
    utxos: HashMap<OutPoint, Utxo>,
    spent: HashMap<OutPoint, Txid>, // outpoint -> spending txid
    balance_cache: Balance,
    network: bitcoin::Network,
}

impl Default for BalanceTracker {
    fn default() -> Self {
        Self::new(bitcoin::Network::Bitcoin)
    }
}

impl BalanceTracker {
    /// Create a new balance tracker
    pub fn new(network: bitcoin::Network) -> Self {
        Self {
            utxos: HashMap::new(),
            spent: HashMap::new(),
            balance_cache: Balance::new(),
            network,
        }
    }

    /// Add a UTXO
    pub fn add_utxo(&mut self, utxo: Utxo) -> WalletResult<()> {
        debug!("Adding UTXO: {:?}", utxo.outpoint);

        // Check if already spent
        if self.spent.contains_key(&utxo.outpoint) {
            debug!("UTXO already spent: {:?}", utxo.outpoint);
            return Ok(());
        }

        self.utxos.insert(utxo.outpoint, utxo);
        self.recalculate_balance();

        Ok(())
    }

    /// Mark a UTXO as spent
    pub fn spend_utxo(&mut self, outpoint: &OutPoint, spending_tx: Txid) -> WalletResult<()> {
        debug!("Spending UTXO: {:?} in tx {}", outpoint, spending_tx);

        if self.utxos.remove(outpoint).is_some() {
            self.spent.insert(*outpoint, spending_tx);
            self.recalculate_balance();
        }

        Ok(())
    }

    /// Process a transaction (add outputs, spend inputs)
    pub fn process_transaction(
        &mut self,
        tx: &Transaction,
        height: Option<u32>,
        our_addresses: &[String],
        network: bitcoin::Network,
    ) -> WalletResult<()> {
        let txid = tx.compute_txid();
        info!("Processing transaction: {}", txid);

        // Process inputs (spend UTXOs)
        for input in &tx.input {
            self.spend_utxo(&input.previous_output, txid)?;
        }

        // Process outputs (add UTXOs)
        info!(
            "Checking {} outputs for transaction {} with {} wallet addresses",
            tx.output.len(),
            txid,
            our_addresses.len()
        );

        for (vout, output) in tx.output.iter().enumerate() {
            // Check if output is ours
            if let Ok(address) = bitcoin::Address::from_script(&output.script_pubkey, network) {
                let address_str = address.to_string();
                info!(
                    "Output {}: address {} (amount: {} sats)",
                    vout,
                    address_str,
                    output.value.to_sat()
                );
                info!("Wallet addresses: {:?}", our_addresses);

                if our_addresses.contains(&address_str) {
                    info!("MATCH! Address {} belongs to wallet!", address_str);
                    let utxo = Utxo {
                        outpoint: OutPoint {
                            txid,
                            vout: vout as u32,
                        },
                        output: output.clone(),
                        height,
                        address: address_str,
                        confirmations: 0, // Will be updated based on current height
                    };

                    self.add_utxo(utxo)?;
                    info!(
                        "Successfully added UTXO worth {} sats to wallet",
                        output.value.to_sat()
                    );
                }
            }
        }

        Ok(())
    }

    /// Update confirmations based on current blockchain height
    pub fn update_confirmations(&mut self, current_height: u32) {
        for utxo in self.utxos.values_mut() {
            if let Some(height) = utxo.height {
                utxo.confirmations = current_height.saturating_sub(height) + 1;
            } else {
                utxo.confirmations = 0;
            }
        }

        self.recalculate_balance();
    }

    /// Recalculate balance from UTXOs
    fn recalculate_balance(&mut self) {
        let mut confirmed = 0u64;
        let mut pending = 0u64;
        let mut unconfirmed = 0u64;

        for utxo in self.utxos.values() {
            let amount = utxo.output.value.to_sat();

            match utxo.confirmations {
                0 => unconfirmed += amount,
                1..=5 => pending += amount,
                _ => confirmed += amount,
            }
        }

        self.balance_cache = Balance::from_amounts(confirmed, pending, unconfirmed);

        debug!(
            "Balance updated - Confirmed: {}, Pending: {}, Unconfirmed: {}",
            self.balance_cache.confirmed,
            self.balance_cache.pending,
            self.balance_cache.unconfirmed
        );
    }

    /// Get current balance
    pub fn get_balance(&self) -> &Balance {
        &self.balance_cache
    }

    /// Get all UTXOs
    pub fn get_utxos(&self) -> Vec<&Utxo> {
        self.utxos.values().collect()
    }

    /// Get a specific UTXO by outpoint
    pub fn get_utxo(&self, outpoint: &bitcoin::OutPoint) -> Option<&Utxo> {
        self.utxos.get(outpoint)
    }

    /// Get spendable UTXOs (confirmed only)
    pub fn get_spendable_utxos(&self) -> Vec<&Utxo> {
        self.utxos
            .values()
            .filter(|utxo| utxo.confirmations >= 6)
            .collect()
    }

    /// Select UTXOs for spending using advanced coin selection
    pub fn select_utxos(&self, target_amount: Amount) -> WalletResult<Vec<Utxo>> {
        self.select_utxos_with_algorithm(
            target_amount,
            crate::coin_selection::CoinSelectionAlgorithm::BranchAndBound,
        )
    }

    /// Select UTXOs with specific algorithm
    pub fn select_utxos_with_algorithm(
        &self,
        target_amount: Amount,
        algorithm: crate::coin_selection::CoinSelectionAlgorithm,
    ) -> WalletResult<Vec<Utxo>> {
        use crate::coin_selection::CoinSelector;
        use crate::transaction::FeeRate;

        // Get spendable UTXOs
        let spendable: Vec<Utxo> = self.get_spendable_utxos().into_iter().cloned().collect();

        if spendable.is_empty() {
            return Err(crate::error::WalletError::InsufficientFunds {
                required: target_amount.to_sat(),
                available: 0,
            });
        }

        // Create coin selector with default fee rate
        let selector =
            CoinSelector::new(spendable, FeeRate::from_sat_per_vb(10)).with_algorithm(algorithm);

        // Select coins
        let result = selector.select_coins(target_amount)?;

        Ok(result.selected_utxos)
    }

    /// Clear all data
    pub fn clear(&mut self) {
        self.utxos.clear();
        self.spent.clear();
        self.balance_cache = Balance::new();
    }

    /// Serialize UTXOs for persistence
    pub fn serialize_utxos(&self) -> WalletResult<Vec<u8>> {
        let utxos: Vec<Utxo> = self.utxos.values().cloned().collect();
        let serialized = serde_json::to_vec(&utxos).map_err(|e| {
            crate::error::WalletError::Other(anyhow::anyhow!("Failed to serialize UTXOs: {}", e))
        })?;
        Ok(serialized)
    }

    /// Deserialize UTXOs from persistence
    pub fn deserialize_utxos(&mut self, data: &[u8]) -> WalletResult<()> {
        let utxos: Vec<Utxo> = serde_json::from_slice(data).map_err(|e| {
            crate::error::WalletError::Other(anyhow::anyhow!("Failed to deserialize UTXOs: {}", e))
        })?;

        self.utxos.clear();
        for utxo in utxos {
            self.utxos.insert(utxo.outpoint, utxo);
        }

        self.recalculate_balance();
        info!("Restored {} UTXOs from persistence", self.utxos.len());
        Ok(())
    }

    /// Serialize spent outputs for persistence
    pub fn serialize_spent(&self) -> WalletResult<Vec<u8>> {
        let spent: Vec<(OutPoint, Txid)> = self.spent.iter().map(|(k, v)| (*k, *v)).collect();
        let serialized = serde_json::to_vec(&spent).map_err(|e| {
            crate::error::WalletError::Other(anyhow::anyhow!(
                "Failed to serialize spent outputs: {}",
                e
            ))
        })?;
        Ok(serialized)
    }

    /// Deserialize spent outputs from persistence
    pub fn deserialize_spent(&mut self, data: &[u8]) -> WalletResult<()> {
        let spent: Vec<(OutPoint, Txid)> = serde_json::from_slice(data).map_err(|e| {
            crate::error::WalletError::Other(anyhow::anyhow!(
                "Failed to deserialize spent outputs: {}",
                e
            ))
        })?;

        self.spent.clear();
        for (outpoint, txid) in spent {
            self.spent.insert(outpoint, txid);
        }

        info!(
            "Restored {} spent outputs from persistence",
            self.spent.len()
        );
        Ok(())
    }
}
