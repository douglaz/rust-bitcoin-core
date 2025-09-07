use anyhow::{bail, Result};
use bitcoin::{
    bip32::{ChildNumber, DerivationPath, ExtendedPrivKey},
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    Address, Amount, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Transaction, TxOut,
    Witness,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Maximum gap limit for address discovery
const MAX_GAP_LIMIT: u32 = 100;

/// Default address lookahead
const DEFAULT_LOOKAHEAD: u32 = 20;

/// Wallet manager for handling keys, addresses, and transactions
pub struct WalletManager {
    /// Wallet configuration
    config: WalletConfig,

    /// Master key
    master_key: Arc<RwLock<Option<ExtendedPrivKey>>>,

    /// Derived keys cache
    key_cache: Arc<RwLock<KeyCache>>,

    /// Address index
    address_index: Arc<RwLock<AddressIndex>>,

    /// UTXO set
    utxos: Arc<RwLock<HashMap<OutPoint, WalletUtxo>>>,

    /// Transaction history
    transactions: Arc<RwLock<Vec<WalletTransaction>>>,

    /// Coin selector
    coin_selector: Arc<CoinSelector>,

    /// Secp256k1 context
    secp: Secp256k1<bitcoin::secp256k1::All>,

    /// Wallet state
    state: Arc<RwLock<WalletState>>,
}

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub network: Network,
    pub wallet_name: String,
    pub gap_limit: u32,
    pub lookahead: u32,
    pub min_confirmations: u32,
    pub dust_limit: Amount,
    pub default_fee_rate: u64, // sat/vB
    pub enable_rbf: bool,
    pub derivation_path: String,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            wallet_name: "default".to_string(),
            gap_limit: 20,
            lookahead: DEFAULT_LOOKAHEAD,
            min_confirmations: 1,
            dust_limit: Amount::from_sat(546),
            default_fee_rate: 1,
            enable_rbf: true,
            derivation_path: "m/84'/0'/0'".to_string(), // BIP84 (native segwit)
        }
    }
}

/// Key cache for derived keys
#[derive(Debug, Default)]
struct KeyCache {
    /// External chain keys (receiving addresses)
    external: BTreeMap<u32, DerivedKey>,

    /// Internal chain keys (change addresses)
    internal: BTreeMap<u32, DerivedKey>,
}

/// Derived key information
#[derive(Debug, Clone)]
struct DerivedKey {
    index: u32,
    private_key: PrivateKey,
    public_key: PublicKey,
    address: Address,
    script_pubkey: ScriptBuf,
    used: bool,
}

/// Address index for tracking
#[derive(Debug, Default)]
struct AddressIndex {
    /// Address to derivation path mapping
    address_to_path: HashMap<Address, DerivationInfo>,

    /// Script to address mapping
    script_to_address: HashMap<ScriptBuf, Address>,

    /// Current external index
    external_index: u32,

    /// Current internal index
    internal_index: u32,

    /// Highest used external index
    highest_used_external: Option<u32>,

    /// Highest used internal index
    highest_used_internal: Option<u32>,
}

/// Derivation information
#[derive(Debug, Clone)]
struct DerivationInfo {
    path: DerivationPath,
    chain: Chain,
    index: u32,
}

/// Chain type
#[derive(Debug, Clone, Copy, PartialEq)]
enum Chain {
    External,
    Internal,
}

/// Wallet UTXO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletUtxo {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub height: Option<u32>,
    pub confirmations: u32,
    pub is_coinbase: bool,
    pub spent: bool,
    pub frozen: bool,
}

/// Wallet transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransaction {
    pub tx: Transaction,
    pub height: Option<u32>,
    pub confirmations: u32,
    pub fee: Option<Amount>,
    pub received: Amount,
    pub sent: Amount,
    pub net: i64,
    pub timestamp: u64,
    pub label: Option<String>,
}

/// Wallet state
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WalletState {
    pub balance: Balance,
    pub last_sync_height: u32,
    pub last_sync_time: u64,
    pub transaction_count: usize,
    pub address_count: usize,
}

/// Wallet balance
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Balance {
    pub confirmed: Amount,
    pub unconfirmed: Amount,
    pub immature: Amount,
    pub total: Amount,
}

/// Coin selection result
#[derive(Debug, Clone)]
pub struct CoinSelectionResult {
    pub selected_utxos: Vec<WalletUtxo>,
    pub total_value: Amount,
    pub fee: Amount,
    pub change: Option<Amount>,
}

/// Coin selector for transaction building
pub struct CoinSelector {
    strategy: CoinSelectionStrategy,
}

/// Coin selection strategy
#[derive(Debug, Clone, Copy)]
pub enum CoinSelectionStrategy {
    /// Largest first
    LargestFirst,

    /// Smallest first
    SmallestFirst,

    /// Branch and bound
    BranchAndBound,

    /// Single random draw
    SingleRandomDraw,
}

impl WalletManager {
    /// Create new wallet manager
    pub fn new(config: WalletConfig) -> Self {
        Self {
            config,
            master_key: Arc::new(RwLock::new(None)),
            key_cache: Arc::new(RwLock::new(KeyCache::default())),
            address_index: Arc::new(RwLock::new(AddressIndex::default())),
            utxos: Arc::new(RwLock::new(HashMap::new())),
            transactions: Arc::new(RwLock::new(Vec::new())),
            coin_selector: Arc::new(CoinSelector::new(CoinSelectionStrategy::BranchAndBound)),
            secp: Secp256k1::new(),
            state: Arc::new(RwLock::new(WalletState::default())),
        }
    }

    /// Initialize wallet with seed
    pub async fn init_from_seed(&self, seed: &[u8]) -> Result<()> {
        if seed.len() < 32 {
            bail!("Seed must be at least 32 bytes");
        }

        // Derive master key
        let master = ExtendedPrivKey::new_master(self.config.network, seed)?;

        *self.master_key.write().await = Some(master);

        // Pre-generate addresses
        self.generate_addresses(Chain::External, self.config.lookahead)
            .await?;
        self.generate_addresses(Chain::Internal, self.config.lookahead)
            .await?;

        info!("Wallet initialized with seed");
        Ok(())
    }

    /// Generate new address
    pub async fn get_new_address(&self, label: Option<String>) -> Result<Address> {
        let mut index = self.address_index.write().await;
        let mut cache = self.key_cache.write().await;

        // Get next external index
        let next_index = index.external_index;

        // Check if we need to derive more keys
        if !cache.external.contains_key(&next_index) {
            drop(cache);
            drop(index);
            self.generate_addresses(Chain::External, 1).await?;
            index = self.address_index.write().await;
            cache = self.key_cache.write().await;
        }

        let key = cache
            .external
            .get(&next_index)
            .ok_or_else(|| anyhow::anyhow!("Failed to get derived key"))?;

        let address = key.address.clone();

        // Update index
        index.external_index += 1;

        // Store label if provided
        if let Some(_label) = label {
            // Would store label in persistent storage
        }

        debug!("Generated new address: {}", address);
        Ok(address)
    }

    /// Get change address
    pub async fn get_change_address(&self) -> Result<Address> {
        let mut index = self.address_index.write().await;
        let mut cache = self.key_cache.write().await;

        // Get next internal index
        let next_index = index.internal_index;

        // Check if we need to derive more keys
        if !cache.internal.contains_key(&next_index) {
            drop(cache);
            drop(index);
            self.generate_addresses(Chain::Internal, 1).await?;
            index = self.address_index.write().await;
            cache = self.key_cache.write().await;
        }

        let key = cache
            .internal
            .get(&next_index)
            .ok_or_else(|| anyhow::anyhow!("Failed to get derived key"))?;

        let address = key.address.clone();

        // Update index
        index.internal_index += 1;

        debug!("Generated change address: {}", address);
        Ok(address)
    }

    /// Generate addresses
    async fn generate_addresses(&self, chain: Chain, count: u32) -> Result<()> {
        let master = self.master_key.read().await;
        let master = master
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Wallet not initialized"))?;

        let mut cache = self.key_cache.write().await;
        let mut index = self.address_index.write().await;

        // Parse derivation path
        let base_path = DerivationPath::from_str(&self.config.derivation_path)?;

        // Determine chain index and starting index
        let (chain_index, start_index, target_map) = match chain {
            Chain::External => (0, index.external_index, &mut cache.external),
            Chain::Internal => (1, index.internal_index, &mut cache.internal),
        };

        // Derive keys
        for i in 0..count {
            let idx = start_index + i;

            // Build full derivation path
            let mut path_vec: Vec<ChildNumber> = base_path.into_iter().cloned().collect();
            path_vec.push(ChildNumber::from_normal_idx(chain_index)?);
            path_vec.push(ChildNumber::from_normal_idx(idx)?);
            let path = DerivationPath::from(path_vec);

            // Derive key
            let derived = master.derive_priv(&self.secp, &path)?;
            let private_key = PrivateKey::new(derived.private_key, self.config.network);
            let public_key = PublicKey::from_private_key(&self.secp, &private_key);

            // Generate address (native segwit for BIP84)
            let compressed = bitcoin::key::CompressedPublicKey::try_from(public_key)
                .map_err(|e| anyhow::anyhow!("Failed to compress public key: {:?}", e))?;
            let address = Address::p2wpkh(&compressed, self.config.network);
            let script_pubkey = address.script_pubkey();

            // Create derived key entry
            let derived_key = DerivedKey {
                index: idx,
                private_key,
                public_key,
                address: address.clone(),
                script_pubkey: script_pubkey.clone(),
                used: false,
            };

            // Store in cache
            target_map.insert(idx, derived_key);

            // Update address index
            let deriv_info = DerivationInfo {
                path: path.clone(),
                chain,
                index: idx,
            };

            index.address_to_path.insert(address.clone(), deriv_info);
            index.script_to_address.insert(script_pubkey, address);
        }

        Ok(())
    }

    /// Create transaction
    pub async fn create_transaction(
        &self,
        outputs: Vec<(Address, Amount)>,
        fee_rate: Option<u64>,
        include_utxos: Option<Vec<OutPoint>>,
        exclude_utxos: Option<Vec<OutPoint>>,
    ) -> Result<Transaction> {
        // Calculate total output amount
        let total_output: Amount = outputs.iter().map(|(_, amount)| *amount).sum::<Amount>();

        // Get fee rate
        let fee_rate = fee_rate.unwrap_or(self.config.default_fee_rate);

        // Select coins
        let selection = self
            .select_coins(total_output, fee_rate, include_utxos, exclude_utxos)
            .await?;

        // Build transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };

        // Add inputs
        for utxo in &selection.selected_utxos {
            let input = bitcoin::TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: if self.config.enable_rbf {
                    bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME
                } else {
                    bitcoin::Sequence::MAX
                },
                witness: Witness::default(),
            };
            tx.input.push(input);
        }

        // Add outputs
        for (address, amount) in outputs {
            let output = bitcoin::TxOut {
                value: amount,
                script_pubkey: address.script_pubkey(),
            };
            tx.output.push(output);
        }

        // Add change output if needed
        if let Some(change_amount) = selection.change {
            if change_amount > self.config.dust_limit {
                let change_address = self.get_change_address().await?;
                let change_output = bitcoin::TxOut {
                    value: change_amount,
                    script_pubkey: change_address.script_pubkey(),
                };
                tx.output.push(change_output);
            }
        }

        // Sign transaction
        self.sign_transaction(&mut tx, &selection.selected_utxos)
            .await?;

        info!("Created transaction: {}", tx.compute_txid());
        Ok(tx)
    }

    /// Select coins for transaction
    async fn select_coins(
        &self,
        target: Amount,
        fee_rate: u64,
        include_utxos: Option<Vec<OutPoint>>,
        exclude_utxos: Option<Vec<OutPoint>>,
    ) -> Result<CoinSelectionResult> {
        let utxos = self.utxos.read().await;

        // Filter available UTXOs
        let mut available: Vec<WalletUtxo> = utxos
            .values()
            .filter(|u| {
                !u.spent
                    && !u.frozen
                    && u.confirmations >= self.config.min_confirmations
                    && (!u.is_coinbase || u.confirmations >= 100)
            })
            .filter(|u| {
                if let Some(ref exclude) = exclude_utxos {
                    !exclude.contains(&u.outpoint)
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        // Add specifically included UTXOs
        if let Some(include) = include_utxos {
            for outpoint in include {
                if let Some(utxo) = utxos.get(&outpoint) {
                    if !utxo.spent {
                        available.push(utxo.clone());
                    }
                }
            }
        }

        // Use coin selector
        self.coin_selector.select(available, target, fee_rate)
    }

    /// Sign transaction
    async fn sign_transaction(&self, tx: &mut Transaction, utxos: &[WalletUtxo]) -> Result<()> {
        let cache = self.key_cache.read().await;
        let index = self.address_index.read().await;

        // Create sighash cache outside loop
        let tx_clone = tx.clone();
        let mut sighash_cache = SighashCache::new(tx_clone);

        for (input_index, utxo) in utxos.iter().enumerate() {
            // Find key for this UTXO
            let address = index
                .script_to_address
                .get(&utxo.txout.script_pubkey)
                .ok_or_else(|| anyhow::anyhow!("Address not found for UTXO"))?;

            let deriv_info = index
                .address_to_path
                .get(address)
                .ok_or_else(|| anyhow::anyhow!("Derivation info not found"))?;

            let key = match deriv_info.chain {
                Chain::External => cache.external.get(&deriv_info.index),
                Chain::Internal => cache.internal.get(&deriv_info.index),
            }
            .ok_or_else(|| anyhow::anyhow!("Key not found in cache"))?;

            // Sign based on script type
            if utxo.txout.script_pubkey.is_p2wpkh() {
                // Native segwit signing
                let sighash = sighash_cache.p2wpkh_signature_hash(
                    input_index,
                    &utxo.txout.script_pubkey,
                    utxo.txout.value,
                    EcdsaSighashType::All,
                )?;

                let message = Message::from_digest_slice(&sighash[..])?;
                let sig = self.secp.sign_ecdsa(&message, &key.private_key.inner);

                // Build witness
                let mut witness = Witness::new();
                let mut sig_bytes = sig.serialize_der().to_vec();
                sig_bytes.push(EcdsaSighashType::All as u8);
                witness.push(sig_bytes);
                witness.push(key.public_key.to_bytes());

                tx.input[input_index].witness = witness;
            } else if utxo.txout.script_pubkey.is_p2pkh() {
                // Legacy signing
                let sighash = sighash_cache.legacy_signature_hash(
                    input_index,
                    &utxo.txout.script_pubkey,
                    EcdsaSighashType::All.to_u32(),
                )?;

                let message = Message::from_digest_slice(&sighash[..])?;
                let sig = self.secp.sign_ecdsa(&message, &key.private_key.inner);

                // Build scriptSig
                let mut sig_bytes = sig.serialize_der().to_vec();
                sig_bytes.push(EcdsaSighashType::All as u8);

                tx.input[input_index].script_sig = bitcoin::blockdata::script::Builder::new()
                    .push_slice(
                        &bitcoin::script::PushBytesBuf::try_from(sig_bytes.clone()).unwrap()[..],
                    )
                    .push_key(&key.public_key)
                    .into_script();
            }
        }

        Ok(())
    }

    /// Update UTXO set
    pub async fn update_utxos(&self, new_utxos: Vec<WalletUtxo>) -> Result<()> {
        let mut utxos = self.utxos.write().await;

        for utxo in new_utxos {
            utxos.insert(utxo.outpoint, utxo);
        }

        self.update_balance().await?;
        Ok(())
    }

    /// Mark UTXO as spent
    pub async fn mark_spent(&self, outpoint: &OutPoint) -> Result<()> {
        let mut utxos = self.utxos.write().await;

        if let Some(utxo) = utxos.get_mut(outpoint) {
            utxo.spent = true;
        }

        Ok(())
    }

    /// Update balance
    async fn update_balance(&self) -> Result<()> {
        let utxos = self.utxos.read().await;
        let mut state = self.state.write().await;

        let mut confirmed = Amount::ZERO;
        let mut unconfirmed = Amount::ZERO;
        let mut immature = Amount::ZERO;

        for utxo in utxos.values() {
            if utxo.spent {
                continue;
            }

            if utxo.is_coinbase && utxo.confirmations < 100 {
                immature += utxo.txout.value;
            } else if utxo.confirmations >= self.config.min_confirmations {
                confirmed += utxo.txout.value;
            } else {
                unconfirmed += utxo.txout.value;
            }
        }

        state.balance = Balance {
            confirmed,
            unconfirmed,
            immature,
            total: confirmed + unconfirmed,
        };

        Ok(())
    }

    /// Get balance
    pub async fn get_balance(&self) -> Balance {
        self.state.read().await.balance.clone()
    }

    /// List transactions
    pub async fn list_transactions(&self, count: usize) -> Vec<WalletTransaction> {
        let txs = self.transactions.read().await;
        txs.iter().rev().take(count).cloned().collect()
    }

    /// Get wallet state
    pub async fn get_state(&self) -> WalletState {
        self.state.read().await.clone()
    }
}

impl CoinSelector {
    /// Create new coin selector
    pub fn new(strategy: CoinSelectionStrategy) -> Self {
        Self { strategy }
    }

    /// Select coins using configured strategy
    pub fn select(
        &self,
        available: Vec<WalletUtxo>,
        target: Amount,
        fee_rate: u64,
    ) -> Result<CoinSelectionResult> {
        match self.strategy {
            CoinSelectionStrategy::LargestFirst => {
                self.select_largest_first(available, target, fee_rate)
            }
            CoinSelectionStrategy::BranchAndBound => {
                self.select_branch_and_bound(available, target, fee_rate)
            }
            _ => {
                // Default to largest first
                self.select_largest_first(available, target, fee_rate)
            }
        }
    }

    /// Select coins using largest first strategy
    fn select_largest_first(
        &self,
        mut available: Vec<WalletUtxo>,
        target: Amount,
        fee_rate: u64,
    ) -> Result<CoinSelectionResult> {
        // Sort by value descending
        available.sort_by(|a, b| b.txout.value.cmp(&a.txout.value));

        let mut selected = Vec::new();
        let mut total = Amount::ZERO;

        // Estimate transaction size and fee
        let mut estimated_size = 10; // Base transaction size
        let mut estimated_fee = Amount::ZERO;

        for utxo in available {
            selected.push(utxo.clone());
            total += utxo.txout.value;

            // Update size estimate (148 bytes per P2WPKH input)
            estimated_size += 148;

            // Update fee estimate
            estimated_fee = Amount::from_sat(estimated_size * fee_rate);

            if total >= target + estimated_fee {
                break;
            }
        }

        if total < target + estimated_fee {
            bail!("Insufficient funds");
        }

        let change = if total > target + estimated_fee {
            Some(total - target - estimated_fee)
        } else {
            None
        };

        Ok(CoinSelectionResult {
            selected_utxos: selected,
            total_value: total,
            fee: estimated_fee,
            change,
        })
    }

    /// Select coins using branch and bound algorithm
    fn select_branch_and_bound(
        &self,
        available: Vec<WalletUtxo>,
        target: Amount,
        fee_rate: u64,
    ) -> Result<CoinSelectionResult> {
        // Simplified branch and bound
        // For now, fall back to largest first
        self.select_largest_first(available, target, fee_rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wallet_creation() {
        let config = WalletConfig::default();
        let wallet = WalletManager::new(config);

        let balance = wallet.get_balance().await;
        assert_eq!(balance.total, Amount::ZERO);
    }

    #[tokio::test]
    async fn test_wallet_initialization() -> Result<()> {
        let config = WalletConfig::default();
        let wallet = WalletManager::new(config);

        // Create test seed
        let seed = [0u8; 32];
        wallet.init_from_seed(&seed).await?;

        // Generate address
        let address = wallet.get_new_address(None).await?;
        assert!(!address.to_string().is_empty());

        Ok(())
    }
}
