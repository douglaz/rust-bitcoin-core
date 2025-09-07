use bitcoin::{Address, Amount, Network, Transaction};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use tracing::{debug, info, warn};

use crate::address::{AddressManager, AddressType};
use crate::balance::{Balance, BalanceTracker, Utxo};
use crate::encryption::{EncryptedWallet, WalletEncryption};
use crate::error::{WalletError, WalletResult};
use crate::keychain::KeyChain;
use crate::storage::{WalletMetadata, WalletStorage};
use crate::transaction::{FeeRate, SignedTransaction, TransactionBuilder};

/// Transaction broadcast callback
pub type BroadcastCallback = Box<
    dyn Fn(Transaction) -> Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send>>
        + Send
        + Sync,
>;

/// Bitcoin wallet
pub struct Wallet {
    name: String,
    network: Network,
    keychain: Option<KeyChain>,
    address_manager: Option<AddressManager>,
    balance_tracker: BalanceTracker,
    storage: WalletStorage,
    encryptor: WalletEncryption,
    encrypted_wallet: Option<EncryptedWallet>,
    locked: bool,
    broadcast_callback: Option<BroadcastCallback>,
}

impl Wallet {
    /// Create a new wallet
    pub async fn create(
        name: String,
        mnemonic: &str,
        passphrase: &str,
        network: Network,
        storage_path: &Path,
    ) -> WalletResult<Self> {
        info!("Creating new wallet: {}", name);

        // Create keychain
        let keychain = KeyChain::from_mnemonic(mnemonic, passphrase, network)?;

        // Create address manager
        let address_manager = AddressManager::new(keychain.clone());

        // Create balance tracker
        let balance_tracker = BalanceTracker::new(network);

        // Open storage
        let storage = WalletStorage::open(storage_path)?;

        // Store metadata
        let metadata = WalletMetadata {
            name: name.clone(),
            network: network.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            encrypted: true, // Wallet is now encrypted
            derivation_path_type: "bip84".to_string(),
            gap_limit: 20,
        };

        storage.store_metadata(&metadata)?;

        // Get seed from mnemonic for encryption
        let seed = KeyChain::seed_from_mnemonic(mnemonic, passphrase)?;

        // Create wallet encryption with mnemonic-derived seed
        let wallet_file = storage_path.join("wallet.enc");
        let wallet_metadata = crate::encryption::WalletMetadata {
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            modified_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            name: name.clone(),
            network: network.to_string(),
            key_count: 0,
            fingerprint: None,
        };
        let wallet_passphrase = crate::encryption::Passphrase::from_string(passphrase.to_string());
        let encryptor = WalletEncryption::create_with_seed(
            wallet_file,
            wallet_passphrase,
            &seed,
            wallet_metadata,
        )
        .await?;

        Ok(Self {
            name,
            network,
            keychain: Some(keychain),
            address_manager: Some(address_manager),
            balance_tracker,
            storage,
            encryptor,
            encrypted_wallet: None,
            locked: false,
            broadcast_callback: None,
        })
    }

    /// Load an existing wallet
    pub async fn load(storage_path: &Path) -> WalletResult<Self> {
        info!("Loading wallet from: {:?}", storage_path);

        // Open storage
        let storage = WalletStorage::open(storage_path)?;

        // Load metadata
        let metadata = storage
            .load_metadata()?
            .ok_or(WalletError::WalletNotFound)?;

        let network = match metadata.network.as_str() {
            "bitcoin" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            _ => return Err(WalletError::Other(anyhow::anyhow!("Unknown network"))),
        };

        // Create balance tracker and restore persisted state
        let mut balance_tracker = BalanceTracker::new(network);

        // Load UTXOs if available
        if let Some(utxo_data) = storage.load_utxos()? {
            if let Err(e) = balance_tracker.deserialize_utxos(&utxo_data) {
                warn!("Failed to restore UTXOs: {}", e);
            } else {
                info!("Restored UTXOs from storage");
            }
        }

        // Load spent outputs if available
        if let Some(spent_data) = storage.load_spent()? {
            if let Err(e) = balance_tracker.deserialize_spent(&spent_data) {
                warn!("Failed to restore spent outputs: {}", e);
            } else {
                info!("Restored spent outputs from storage");
            }
        }

        // Wallet starts locked - need to unlock with passphrase
        // Load wallet encryption from disk (wallet.enc file in the wallet directory)
        let wallet_file = storage_path.join("wallet.enc");
        let encryptor = WalletEncryption::load_from_disk(wallet_file).await?;

        Ok(Self {
            name: metadata.name.clone(),
            network,
            keychain: None,
            address_manager: None,
            balance_tracker,
            storage,
            encryptor,
            encrypted_wallet: None,
            locked: true,
            broadcast_callback: None,
        })
    }

    /// Unlock the wallet
    pub fn unlock(&mut self, mnemonic: &str, passphrase: &str) -> WalletResult<()> {
        if !self.locked {
            return Ok(());
        }

        info!("Unlocking wallet");

        // Create keychain
        let keychain = KeyChain::from_mnemonic(mnemonic, passphrase, self.network)?;

        // Create address manager
        let mut address_manager = AddressManager::new(keychain.clone());

        // Load addresses from storage and restore them
        let stored_addresses = self.storage.load_addresses()?;
        let num_addresses = stored_addresses.len();
        for addr in stored_addresses {
            // Parse address type from stored string
            let address_type = match addr.address_type.as_str() {
                "P2wpkh" | "NativeSegwit" => AddressType::P2wpkh,
                "P2shwpkh" | "NestedSegwit" => AddressType::P2shwpkh,
                "P2pkh" | "Legacy" => AddressType::P2pkh,
                _ => AddressType::P2wpkh, // Default to native segwit
            };

            // Restore the address
            address_manager.restore_address(
                addr.address.clone(),
                addr.derivation_path,
                address_type,
                addr.index,
                addr.change,
                addr.used,
            )?;
        }

        info!("Restored {} addresses from storage", num_addresses);

        self.keychain = Some(keychain);
        self.address_manager = Some(address_manager);
        self.locked = false;

        Ok(())
    }

    /// Lock the wallet
    pub fn lock(&mut self) {
        info!("Locking wallet");

        self.keychain = None;
        self.address_manager = None;
        self.locked = true;
    }

    /// Check if wallet is locked
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Get an address at a specific index
    pub fn get_address(&self, index: u32) -> WalletResult<Address> {
        if self.locked {
            return Err(WalletError::WalletLocked);
        }

        let address_manager = self
            .address_manager
            .as_ref()
            .ok_or(WalletError::WalletLocked)?;

        // Get address at index for P2WPKH by default
        address_manager.get_receive_address_at_index(AddressType::P2wpkh, index)
    }

    /// Get a change address at a specific index
    pub fn get_change_address(&self, index: u32) -> WalletResult<Address> {
        if self.locked {
            return Err(WalletError::WalletLocked);
        }

        let address_manager = self
            .address_manager
            .as_ref()
            .ok_or(WalletError::WalletLocked)?;

        // Get change address at index for P2WPKH by default
        address_manager.get_change_address_at_index(AddressType::P2wpkh, index)
    }

    /// Get a new receive address
    pub fn get_new_address(&mut self, address_type: AddressType) -> WalletResult<Address> {
        if self.locked {
            return Err(WalletError::WalletLocked);
        }

        let address_manager = self
            .address_manager
            .as_mut()
            .ok_or(WalletError::WalletLocked)?;

        let address = address_manager.new_receive_address(address_type)?;

        // Get the address info to get the actual index and path
        let all_addresses = address_manager.get_all_addresses();
        let address_info = all_addresses
            .iter()
            .find(|info| info.address == address)
            .ok_or_else(|| WalletError::Other(anyhow::anyhow!("Address info not found")))?;

        // Store in database with correct metadata
        let stored = crate::storage::StoredAddress {
            address: address.to_string(),
            derivation_path: address_info.derivation_path.clone(),
            address_type: format!("{:?}", address_type),
            index: address_info.index,
            change: false,
            used: false,
        };

        self.storage.store_address(&stored)?;
        info!(
            "Stored new address {} at index {}",
            address, address_info.index
        );

        Ok(address)
    }

    /// Get balance
    pub fn get_balance(&self) -> Result<Amount, WalletError> {
        Ok(self.balance_tracker.get_balance().confirmed)
    }

    /// Get full balance details
    pub fn get_balance_details(&self) -> &Balance {
        self.balance_tracker.get_balance()
    }

    /// List all addresses
    pub fn list_addresses(&self) -> WalletResult<Vec<Address>> {
        if self.locked {
            return Err(WalletError::WalletLocked);
        }

        let address_manager = self
            .address_manager
            .as_ref()
            .ok_or(WalletError::WalletLocked)?;

        let addresses = address_manager
            .get_all_addresses()
            .iter()
            .map(|info| info.address.clone())
            .collect();

        Ok(addresses)
    }

    /// Process a new transaction
    pub fn process_transaction(
        &mut self,
        tx: &Transaction,
        height: Option<u32>,
    ) -> WalletResult<()> {
        if self.locked {
            return Err(WalletError::WalletLocked);
        }

        let address_manager = self
            .address_manager
            .as_ref()
            .ok_or(WalletError::WalletLocked)?;

        // Get our addresses
        let our_addresses: Vec<String> = address_manager
            .get_all_addresses()
            .iter()
            .map(|info| info.address.to_string())
            .collect();

        // Process transaction
        self.balance_tracker
            .process_transaction(tx, height, &our_addresses, self.network)?;

        // Calculate fee if transaction has inputs (not coinbase)
        let fee = if !tx.input.is_empty() && !tx.is_coinbase() {
            self.calculate_transaction_fee(tx)?
        } else {
            0 // Coinbase transactions have no fee
        };

        // Store transaction
        let stored_tx = crate::storage::StoredTransaction {
            txid: tx.compute_txid().to_string(),
            raw_tx: bitcoin::consensus::encode::serialize(tx),
            height,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            fee,
            memo: None,
        };

        self.storage.store_transaction(&stored_tx)?;

        // Save wallet state after processing transaction
        self.save_wallet_state()?;

        Ok(())
    }

    /// Create and sign a transaction
    pub fn create_transaction(
        &self,
        recipients: Vec<(Address, Amount)>,
        fee_rate: FeeRate,
    ) -> WalletResult<SignedTransaction> {
        if self.locked {
            return Err(WalletError::WalletLocked);
        }

        let keychain = self.keychain.as_ref().ok_or(WalletError::WalletLocked)?;

        let address_manager = self
            .address_manager
            .as_ref()
            .ok_or(WalletError::WalletLocked)?;

        // Create change address
        let xpub = keychain.master_public_key();
        let pubkey = bitcoin::PublicKey::new(xpub.public_key);
        let compressed = bitcoin::key::CompressedPublicKey::try_from(pubkey).map_err(|e| {
            WalletError::Other(anyhow::anyhow!("Failed to compress pubkey: {:?}", e))
        })?;
        let change_address = Address::p2wpkh(&compressed, self.network);

        // Build transaction
        let mut builder = TransactionBuilder::new(keychain, &self.balance_tracker, self.network)
            .fee_rate(fee_rate)
            .change_address(change_address);

        for (address, amount) in recipients {
            builder = builder.add_recipient(address, amount);
        }

        builder.build_and_sign()
    }

    /// Get wallet info
    pub fn get_info(&self) -> WalletInfo {
        WalletInfo {
            name: self.name.clone(),
            network: self.network,
            locked: self.locked,
            balance: self.balance_tracker.get_balance().clone(),
            address_count: self
                .address_manager
                .as_ref()
                .map(|am| am.get_all_addresses().len())
                .unwrap_or(0),
        }
    }

    /// Wrapper for get_new_address (renamed to match RPC)
    pub fn new_address(&mut self, address_type: AddressType) -> WalletResult<Address> {
        self.get_new_address(address_type)
    }

    /// Send bitcoin to an address
    pub async fn send_to_address(
        &mut self,
        address: Address,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> WalletResult<SignedTransaction> {
        let signed_tx = self.create_transaction(vec![(address, amount)], fee_rate)?;

        // Broadcast if callback is set
        if let Some(ref callback) = self.broadcast_callback {
            callback(signed_tx.transaction.clone())
                .await
                .map_err(WalletError::Other)?;
        }

        // Save wallet state after sending transaction
        self.save_wallet_state()?;

        Ok(signed_tx)
    }

    /// Set the broadcast callback
    pub fn set_broadcast_callback(&mut self, callback: BroadcastCallback) {
        self.broadcast_callback = Some(callback);
    }

    /// Broadcast a transaction using the callback
    pub async fn broadcast_transaction(&self, tx: Transaction) -> WalletResult<()> {
        if let Some(ref callback) = self.broadcast_callback {
            callback(tx).await.map_err(WalletError::Other)?;
        } else {
            return Err(WalletError::Other(anyhow::anyhow!(
                "No broadcast callback set"
            )));
        }
        Ok(())
    }

    /// List unspent transaction outputs
    pub fn list_unspent(&self) -> Vec<&Utxo> {
        self.balance_tracker.get_utxos()
    }

    /// Get wallet information for RPC
    pub fn get_wallet_info(&self) -> WalletRpcInfo {
        // Get transaction count from storage
        let tx_count = match self.storage.load_transactions() {
            Ok(txs) => txs.len(),
            Err(_) => 0,
        };

        WalletRpcInfo {
            name: self.name.clone(),
            version: 1,
            balance: self.balance_tracker.get_balance().confirmed,
            unconfirmed_balance: self.balance_tracker.get_balance().unconfirmed,
            tx_count,
        }
    }

    /// Process a new block
    pub fn process_block(&mut self, block: &bitcoin::Block, height: u32) -> WalletResult<()> {
        info!(
            "Processing block {} at height {}",
            block.block_hash(),
            height
        );

        // For block processing, we need to track UTXOs even if wallet is locked
        // This allows us to update balance when blocks are mined
        let our_addresses = if self.locked {
            // If wallet is locked, we can still get addresses we've generated
            // They are stored in the address manager
            vec![]
        } else {
            let address_manager = self
                .address_manager
                .as_ref()
                .ok_or(WalletError::WalletLocked)?;

            address_manager
                .get_all_addresses()
                .iter()
                .map(|info| info.address.to_string())
                .collect()
        };

        // If we have no addresses to track, try to get them from storage
        let our_addresses = if our_addresses.is_empty() {
            // Load addresses from storage
            match self.storage.load_addresses() {
                Ok(stored) => stored.iter().map(|a| a.address.clone()).collect(),
                Err(e) => {
                    warn!("Failed to load addresses from storage: {}", e);
                    vec![]
                }
            }
        } else {
            our_addresses
        };

        info!(
            "Tracking {} addresses for block processing",
            our_addresses.len()
        );

        // Process all transactions in the block
        for tx in &block.txdata {
            // Process transaction directly with balance tracker
            if let Err(e) = self.balance_tracker.process_transaction(
                tx,
                Some(height),
                &our_addresses,
                self.network,
            ) {
                warn!("Failed to process transaction {}: {}", tx.compute_txid(), e);
            }

            // Store transaction if not locked
            if !self.locked {
                // Calculate fee for the transaction
                let fee = if !tx.input.is_empty() && !tx.is_coinbase() {
                    self.calculate_transaction_fee(tx).unwrap_or(0)
                } else {
                    0
                };

                let stored_tx = crate::storage::StoredTransaction {
                    txid: tx.compute_txid().to_string(),
                    raw_tx: bitcoin::consensus::encode::serialize(tx),
                    height: Some(height),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    fee,
                    memo: None,
                };

                if let Err(e) = self.storage.store_transaction(&stored_tx) {
                    warn!("Failed to store transaction: {}", e);
                }
            }
        }

        // Update confirmations for existing UTXOs
        self.balance_tracker.update_confirmations(height);

        // Save UTXO state after processing block
        if let Err(e) = self.save_wallet_state() {
            warn!("Failed to save wallet state: {}", e);
        } else {
            info!("Wallet state saved after block processing");
        }

        info!(
            "Block processing complete. Balance: {} BTC",
            self.balance_tracker.get_balance().total.to_btc()
        );

        Ok(())
    }

    /// Sync wallet with blockchain
    pub async fn sync(&mut self, current_height: u32) -> WalletResult<()> {
        info!("Syncing wallet at height {}", current_height);

        // Update confirmations
        self.balance_tracker.update_confirmations(current_height);

        // Load and process stored transactions
        let stored_txs = self.storage.load_transactions()?;
        info!("Found {} stored transactions to process", stored_txs.len());

        for stored_tx in stored_txs {
            // Deserialize the transaction
            let tx: Transaction = bitcoin::consensus::encode::deserialize(&stored_tx.raw_tx)
                .map_err(|e| {
                    WalletError::Other(anyhow::anyhow!("Failed to deserialize tx: {}", e))
                })?;

            // Get our addresses to check
            let our_addresses: Vec<String> = if self.locked {
                self.storage
                    .load_addresses()?
                    .iter()
                    .map(|a| a.address.clone())
                    .collect()
            } else {
                self.address_manager
                    .as_ref()
                    .ok_or(WalletError::WalletLocked)?
                    .get_all_addresses()
                    .iter()
                    .map(|info| info.address.to_string())
                    .collect()
            };

            // Re-process the transaction to update balance tracker
            if let Err(e) = self.balance_tracker.process_transaction(
                &tx,
                stored_tx.height,
                &our_addresses,
                self.network,
            ) {
                warn!("Failed to re-process transaction {}: {}", stored_tx.txid, e);
            }
        }

        // Save updated state
        self.save_wallet_state()?;

        Ok(())
    }

    /// Sign a raw transaction with wallet keys
    pub fn sign_raw_transaction(&self, tx: &mut Transaction) -> WalletResult<bool> {
        if self.locked {
            return Err(WalletError::WalletLocked);
        }

        let keychain = self.keychain.as_ref().ok_or(WalletError::WalletLocked)?;

        // Get spendable UTXOs to find the inputs
        let utxos = self.balance_tracker.get_spendable_utxos();

        // Find UTXOs for each input
        let mut input_utxos = Vec::new();
        for input in &tx.input {
            let utxo = utxos
                .iter()
                .find(|u| u.outpoint == input.previous_output)
                .ok_or_else(|| {
                    WalletError::Other(anyhow::anyhow!(
                        "UTXO not found for input: {:?}",
                        input.previous_output
                    ))
                })?;
            input_utxos.push((*utxo).clone());
        }

        // Sign the transaction
        use crate::signer::TransactionSigner;
        let signer = TransactionSigner::new(self.network);

        // For simplicity, use default BIP84 paths for now
        let paths: Vec<_> = input_utxos
            .iter()
            .enumerate()
            .map(|(i, _)| KeyChain::bip84_path(0, 0, i as u32).unwrap())
            .collect();

        signer.sign_transaction(tx, &input_utxos, keychain, &paths)?;

        // Check if all inputs are signed (simplified check)
        let complete = tx
            .input
            .iter()
            .all(|input| !input.script_sig.is_empty() || !input.witness.is_empty());

        Ok(complete)
    }

    /// Save wallet state to storage
    pub fn save_wallet_state(&self) -> WalletResult<()> {
        // Save UTXOs
        let utxo_data = self.balance_tracker.serialize_utxos()?;
        self.storage.store_utxos(&utxo_data)?;

        // Save spent outputs
        let spent_data = self.balance_tracker.serialize_spent()?;
        self.storage.store_spent(&spent_data)?;

        debug!("Wallet state saved to storage");
        Ok(())
    }

    /// Calculate transaction fee by looking up input values
    fn calculate_transaction_fee(&self, tx: &Transaction) -> WalletResult<u64> {
        // Calculate total input value
        let mut total_input = Amount::ZERO;
        for input in &tx.input {
            // Try to find the UTXO in our balance tracker
            if let Some(utxo) = self.balance_tracker.get_utxo(&input.previous_output) {
                total_input += utxo.output.value;
            } else {
                // If we don't have the UTXO, we can't calculate the fee
                // This might happen for transactions we're not fully involved in
                debug!("UTXO not found for input: {:?}", input.previous_output);
                return Ok(0);
            }
        }

        // Calculate total output value
        let total_output: Amount = tx.output.iter().map(|out| out.value).sum();

        // Fee is the difference between inputs and outputs
        if total_input >= total_output {
            Ok((total_input - total_output).to_sat())
        } else {
            // This shouldn't happen in valid transactions
            warn!(
                "Transaction outputs exceed inputs: {} > {}",
                total_output, total_input
            );
            Ok(0)
        }
    }

    /// Backup wallet
    pub fn backup(&self, backup_path: &Path) -> WalletResult<()> {
        info!("Backing up wallet to: {:?}", backup_path);

        // TODO: Implement backup

        Ok(())
    }
}

/// Wallet information
#[derive(Debug, Clone)]
pub struct WalletInfo {
    pub name: String,
    pub network: Network,
    pub locked: bool,
    pub balance: Balance,
    pub address_count: usize,
}

/// Wallet RPC information
#[derive(Debug, Clone)]
pub struct WalletRpcInfo {
    pub name: String,
    pub version: u32,
    pub balance: Amount,
    pub unconfirmed_balance: Amount,
    pub tx_count: usize,
}
