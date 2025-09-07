use anyhow::Result;
use bitcoin::{Address, Amount, Block, OutPoint, ScriptBuf, Transaction, Txid};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use crate::Wallet;
use btc_core::chain::ChainManager;

/// Scans the blockchain for wallet-related transactions
pub struct BlockchainScanner {
    wallet: Arc<RwLock<Wallet>>,
    watched_addresses: Arc<RwLock<HashSet<Address>>>,
    watched_scripts: Arc<RwLock<HashSet<ScriptBuf>>>,
    transaction_history: Arc<RwLock<TransactionHistory>>,
    scan_progress: Arc<RwLock<ScanProgress>>,
    config: ScannerConfig,
    chain: Arc<RwLock<ChainManager>>,
}

/// Transaction history for the wallet
#[derive(Debug, Clone, Default)]
pub struct TransactionHistory {
    /// All transactions affecting the wallet
    pub transactions: HashMap<Txid, WalletTransaction>,

    /// Unspent outputs
    pub unspent_outputs: HashMap<OutPoint, UnspentOutput>,

    /// Spent outputs
    pub spent_outputs: HashMap<OutPoint, SpentInfo>,
}

/// A transaction that affects the wallet
#[derive(Debug, Clone)]
pub struct WalletTransaction {
    pub txid: Txid,
    pub transaction: Transaction,
    pub block_height: Option<u32>,
    pub block_hash: Option<bitcoin::BlockHash>,
    pub confirmations: u32,
    pub timestamp: Option<u64>,
    pub received: Amount,
    pub sent: Amount,
    pub fee: Option<Amount>,
    pub is_coinbase: bool,
}

/// An unspent output controlled by the wallet
#[derive(Debug, Clone)]
pub struct UnspentOutput {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    pub address: Option<Address>,
    pub confirmations: u32,
    pub is_change: bool,
    pub derivation_path: Option<String>,
}

/// Information about a spent output
#[derive(Debug, Clone)]
pub struct SpentInfo {
    pub spending_txid: Txid,
    pub spent_at_height: u32,
    pub spent_at_time: Option<u64>,
}

/// Scanning progress
#[derive(Debug, Clone, Default)]
pub struct ScanProgress {
    pub current_height: u32,
    pub target_height: u32,
    pub blocks_scanned: u64,
    pub transactions_found: u64,
    pub is_scanning: bool,
}

/// Scanner configuration
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub batch_size: usize,
    pub rescan_from_height: Option<u32>,
    pub look_ahead: u32,
    pub index_addresses: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            rescan_from_height: None,
            look_ahead: 20,
            index_addresses: true,
        }
    }
}

impl BlockchainScanner {
    /// Create a new blockchain scanner
    pub fn new(
        wallet: Arc<RwLock<Wallet>>,
        chain: Arc<RwLock<ChainManager>>,
        config: ScannerConfig,
    ) -> Self {
        Self {
            wallet,
            watched_addresses: Arc::new(RwLock::new(HashSet::new())),
            watched_scripts: Arc::new(RwLock::new(HashSet::new())),
            transaction_history: Arc::new(RwLock::new(TransactionHistory::default())),
            scan_progress: Arc::new(RwLock::new(ScanProgress::default())),
            config,
            chain,
        }
    }

    /// Initialize scanner with wallet addresses
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing blockchain scanner");

        // Get addresses from wallet
        let addresses = self.get_wallet_addresses().await?;

        // Add to watched set
        let mut watched = self.watched_addresses.write().await;
        for addr in addresses {
            watched.insert(addr);
        }

        debug!("Watching {} addresses", watched.len());

        Ok(())
    }

    /// Get all addresses from the wallet
    async fn get_wallet_addresses(&self) -> Result<Vec<Address>> {
        let wallet = self.wallet.read().await;
        let mut addresses = Vec::new();

        // Get receiving addresses
        for i in 0..self.config.look_ahead {
            if let Ok(addr) = wallet.get_address(i) {
                addresses.push(addr);
            }
        }

        // Get change addresses
        for i in 0..self.config.look_ahead {
            if let Ok(addr) = wallet.get_change_address(i) {
                addresses.push(addr);
            }
        }

        Ok(addresses)
    }

    /// Scan a block for wallet transactions
    pub async fn scan_block(&self, block: &Block, height: u32) -> Result<Vec<WalletTransaction>> {
        let mut found_transactions = Vec::new();
        let watched_addresses = self.watched_addresses.read().await;
        let watched_scripts = self.watched_scripts.read().await;

        trace!(
            "Scanning block at height {} for wallet transactions",
            height
        );

        for tx in &block.txdata {
            let mut is_relevant = false;
            let mut received = Amount::ZERO;
            let sent = Amount::ZERO;

            // Check outputs
            for output in &tx.output {
                let script = &output.script_pubkey;

                // Check if output is to a watched address
                if let Ok(addr) = Address::from_script(script, bitcoin::Network::Bitcoin) {
                    if watched_addresses.contains(&addr) {
                        is_relevant = true;
                        received = received.checked_add(output.value).unwrap_or(Amount::MAX);
                    }
                } else if watched_scripts.contains(script) {
                    is_relevant = true;
                    received = received.checked_add(output.value).unwrap_or(Amount::MAX);
                }
            }

            // Check inputs (for spent outputs)
            for input in &tx.input {
                // Check if we're spending a watched output
                if self.is_our_output(&input.previous_output).await {
                    is_relevant = true;
                    // TODO: Look up the value of the spent output
                    // sent = sent + spent_value;
                }
            }

            if is_relevant {
                let wallet_tx = WalletTransaction {
                    txid: tx.compute_txid(),
                    transaction: tx.clone(),
                    block_height: Some(height),
                    block_hash: Some(block.block_hash()),
                    confirmations: 1, // Will be updated later
                    timestamp: Some(block.header.time as u64),
                    received,
                    sent,
                    fee: None, // TODO: Calculate fee
                    is_coinbase: tx.is_coinbase(),
                };

                found_transactions.push(wallet_tx.clone());

                // Update history
                let mut history = self.transaction_history.write().await;
                history.transactions.insert(wallet_tx.txid, wallet_tx);
            }
        }

        // Update scan progress
        let mut progress = self.scan_progress.write().await;
        progress.current_height = height;
        progress.blocks_scanned += 1;
        progress.transactions_found += found_transactions.len() as u64;

        if !found_transactions.is_empty() {
            info!(
                "Found {} wallet transactions in block {}",
                found_transactions.len(),
                height
            );
        }

        Ok(found_transactions)
    }

    /// Check if an output belongs to the wallet
    async fn is_our_output(&self, outpoint: &OutPoint) -> bool {
        let history = self.transaction_history.read().await;
        history.unspent_outputs.contains_key(outpoint)
            || history.spent_outputs.contains_key(outpoint)
    }

    /// Perform a full rescan of the blockchain
    pub async fn rescan(&self, from_height: u32, to_height: u32) -> Result<()> {
        info!(
            "Starting blockchain rescan from height {} to {}",
            from_height, to_height
        );

        // Update scan progress
        {
            let mut progress = self.scan_progress.write().await;
            progress.current_height = from_height;
            progress.target_height = to_height;
            progress.is_scanning = true;
            progress.blocks_scanned = 0;
            progress.transactions_found = 0;
        }

        // Fetch and scan blocks from the chain
        let chain = self.chain.read().await;
        let mut current_height = from_height;

        while current_height <= to_height {
            // Check if we should stop scanning
            {
                let progress = self.scan_progress.read().await;
                if !progress.is_scanning {
                    info!("Rescan interrupted at height {}", current_height);
                    break;
                }
            }

            // Fetch batch of blocks
            let batch_end = (current_height + self.config.batch_size as u32).min(to_height);

            for height in current_height..=batch_end {
                // Get block hash at height
                if let Some(block_hash) = chain.get_block_hash_at_height(height) {
                    // Get block by hash
                    match chain.get_block(&block_hash).await {
                        Ok(Some(block)) => {
                            // Scan the block for wallet transactions
                            if let Err(e) = self.scan_block(&block, height).await {
                                warn!("Error scanning block {}: {}", height, e);
                            }
                        }
                        Ok(None) => {
                            debug!("Block not found at height {}", height);
                        }
                        Err(e) => {
                            warn!("Error fetching block {}: {}", height, e);
                        }
                    }
                }

                current_height = batch_end + 1;

                // Small delay to avoid overloading
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }

            warn!("No chain manager set - cannot fetch blocks");
        }

        // Update final progress
        {
            let mut progress = self.scan_progress.write().await;
            progress.is_scanning = false;
        }

        info!("Blockchain rescan complete");

        Ok(())
    }

    /// Update UTXO set based on a new transaction
    pub async fn update_utxos(&self, tx: &Transaction, height: u32) -> Result<()> {
        let mut history = self.transaction_history.write().await;
        let watched_addresses = self.watched_addresses.read().await;

        let txid = tx.compute_txid();

        // Add new UTXOs from outputs
        for (index, output) in tx.output.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                vout: index as u32,
            };

            // Check if this output belongs to us
            if let Ok(addr) = Address::from_script(&output.script_pubkey, bitcoin::Network::Bitcoin)
            {
                if watched_addresses.contains(&addr) {
                    let unspent = UnspentOutput {
                        outpoint,
                        value: output.value,
                        script_pubkey: output.script_pubkey.clone(),
                        address: Some(addr),
                        confirmations: 0,
                        is_change: false,      // TODO: Determine if change
                        derivation_path: None, // TODO: Get derivation path
                    };

                    history.unspent_outputs.insert(outpoint, unspent);
                    trace!("Added UTXO: {:?}", outpoint);
                }
            }
        }

        // Mark spent UTXOs from inputs
        for input in &tx.input {
            if history
                .unspent_outputs
                .remove(&input.previous_output)
                .is_some()
            {
                let spent_info = SpentInfo {
                    spending_txid: txid,
                    spent_at_height: height,
                    spent_at_time: None,
                };

                history
                    .spent_outputs
                    .insert(input.previous_output, spent_info);
                trace!("Marked UTXO as spent: {:?}", input.previous_output);
            }
        }

        Ok(())
    }

    /// Get wallet balance
    pub async fn get_balance(&self) -> WalletBalance {
        let history = self.transaction_history.read().await;

        let mut confirmed = Amount::ZERO;
        let mut unconfirmed = Amount::ZERO;

        for utxo in history.unspent_outputs.values() {
            if utxo.confirmations >= 6 {
                confirmed = confirmed.checked_add(utxo.value).unwrap_or(Amount::MAX);
            } else {
                unconfirmed = unconfirmed.checked_add(utxo.value).unwrap_or(Amount::MAX);
            }
        }

        WalletBalance {
            confirmed,
            unconfirmed,
            total: confirmed.checked_add(unconfirmed).unwrap_or(Amount::MAX),
        }
    }

    /// Get transaction history
    pub async fn get_transaction_history(&self, limit: Option<usize>) -> Vec<WalletTransaction> {
        let history = self.transaction_history.read().await;

        let mut transactions: Vec<_> = history.transactions.values().cloned().collect();

        // Sort by block height (newest first)
        transactions.sort_by(|a, b| {
            b.block_height
                .cmp(&a.block_height)
                .then_with(|| b.txid.cmp(&a.txid))
        });

        if let Some(limit) = limit {
            transactions.truncate(limit);
        }

        transactions
    }

    /// Get unspent outputs
    pub async fn get_unspent_outputs(&self) -> Vec<UnspentOutput> {
        let history = self.transaction_history.read().await;
        history.unspent_outputs.values().cloned().collect()
    }

    /// Add an address to watch
    pub async fn watch_address(&self, address: Address) -> Result<()> {
        let mut watched = self.watched_addresses.write().await;
        watched.insert(address.clone());
        info!("Now watching address: {}", address);
        Ok(())
    }

    /// Add a script to watch
    pub async fn watch_script(&self, script: ScriptBuf) -> Result<()> {
        let mut watched = self.watched_scripts.write().await;
        watched.insert(script.clone());
        info!("Now watching script");
        Ok(())
    }

    /// Get scan progress
    pub async fn get_progress(&self) -> ScanProgress {
        self.scan_progress.read().await.clone()
    }
}

/// Wallet balance information
#[derive(Debug, Clone, Copy)]
pub struct WalletBalance {
    pub confirmed: Amount,
    pub unconfirmed: Amount,
    pub total: Amount,
}

impl WalletBalance {
    pub fn to_btc(&self) -> (f64, f64, f64) {
        (
            self.confirmed.to_btc(),
            self.unconfirmed.to_btc(),
            self.total.to_btc(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_config_default() {
        let config = ScannerConfig::default();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.look_ahead, 20);
        assert!(config.index_addresses);
    }

    #[test]
    fn test_wallet_balance() {
        let balance = WalletBalance {
            confirmed: Amount::from_sat(100_000_000),
            unconfirmed: Amount::from_sat(50_000_000),
            total: Amount::from_sat(150_000_000),
        };

        let (confirmed_btc, unconfirmed_btc, total_btc) = balance.to_btc();
        assert_eq!(confirmed_btc, 1.0);
        assert_eq!(unconfirmed_btc, 0.5);
        assert_eq!(total_btc, 1.5);
    }
}
