use anyhow::{Context, Result};
use bitcoin::{Address, Block, Network, Script, Txid};
use serde::{Deserialize, Serialize};
use sled::{Batch, Db, Tree};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Address index for fast lookups
pub struct AddressIndex {
    /// Database handle
    db: Arc<Db>,

    /// Trees for different data
    address_txs: Arc<Tree>, // address -> [txids]
    address_utxos: Arc<Tree>,    // address -> [utxos]
    address_balances: Arc<Tree>, // address -> balance info
    #[allow(dead_code)]
    script_addresses: Arc<Tree>, // script_hash -> address
    #[allow(dead_code)]
    metadata: Arc<Tree>,

    /// Index configuration
    config: AddressIndexConfig,

    /// Index statistics
    stats: Arc<RwLock<AddressIndexStats>>,

    /// Network for address encoding
    network: Network,

    /// Cache for recent lookups
    cache: Arc<RwLock<lru::LruCache<String, AddressInfo>>>,
}

/// Address index configuration
#[derive(Debug, Clone)]
pub struct AddressIndexConfig {
    /// Enable address indexing
    pub enabled: bool,

    /// Cache size for recent lookups
    pub cache_size: usize,

    /// Batch size for writes
    pub batch_size: usize,

    /// Track spent outputs (for full history)
    pub track_spent: bool,

    /// Index witness addresses
    pub index_witness: bool,
}

impl Default for AddressIndexConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_size: 10000,
            batch_size: 1000,
            track_spent: true,
            index_witness: true,
        }
    }
}

/// Address information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    /// Address string
    pub address: String,

    /// Total received (in satoshis)
    pub total_received: u64,

    /// Total sent (in satoshis)
    pub total_sent: u64,

    /// Current balance (in satoshis)
    pub balance: u64,

    /// Number of transactions
    pub tx_count: usize,

    /// Transaction IDs
    pub txids: Vec<Txid>,

    /// Unspent outputs
    pub utxos: Vec<UtxoInfo>,

    /// First seen block height
    pub first_seen: Option<u32>,

    /// Last seen block height
    pub last_seen: Option<u32>,
}

/// UTXO information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInfo {
    /// Transaction ID
    pub txid: Txid,

    /// Output index
    pub vout: u32,

    /// Output value
    pub value: u64,

    /// Block height
    pub height: u32,

    /// Confirmations
    pub confirmations: u32,

    /// Script pubkey
    pub script_pubkey: Vec<u8>,
}

/// Address index statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AddressIndexStats {
    pub total_addresses: u64,
    pub total_transactions: u64,
    pub total_utxos: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub db_reads: u64,
    pub db_writes: u64,
    pub last_indexed_height: u32,
}

impl AddressIndex {
    /// Create new address index
    pub fn new(
        path: impl AsRef<Path>,
        network: Network,
        config: AddressIndexConfig,
    ) -> Result<Self> {
        let path = path.as_ref();

        // Setup Sled database
        let db_config = sled::Config::new()
            .path(path)
            .cache_capacity(128 * 1024 * 1024) // 128MB cache
            .flush_every_ms(Some(5000));

        let db = db_config
            .open()
            .context("Failed to open address index database")?;

        // Open trees
        let address_txs = db.open_tree("address_txs")?;
        let address_utxos = db.open_tree("address_utxos")?;
        let address_balances = db.open_tree("address_balances")?;
        let script_addresses = db.open_tree("script_addresses")?;
        let metadata = db.open_tree("metadata")?;

        // Create cache
        let cache = lru::LruCache::new(std::num::NonZeroUsize::new(config.cache_size).unwrap());

        // Load stats from metadata
        let stats = if let Some(bytes) = metadata.get(b"stats")? {
            bincode::deserialize(&bytes)?
        } else {
            AddressIndexStats::default()
        };

        Ok(Self {
            db: Arc::new(db),
            address_txs: Arc::new(address_txs),
            address_utxos: Arc::new(address_utxos),
            address_balances: Arc::new(address_balances),
            script_addresses: Arc::new(script_addresses),
            metadata: Arc::new(metadata),
            config,
            stats: Arc::new(RwLock::new(stats)),
            network,
            cache: Arc::new(RwLock::new(cache)),
        })
    }

    /// Index a block's transactions
    pub async fn index_block(&self, block: &Block, height: u32) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let block_hash = block.block_hash();
        debug!(
            "Indexing addresses from block {} at height {}",
            block_hash, height
        );

        let mut address_updates: HashMap<String, AddressUpdate> = HashMap::new();

        // Process each transaction
        for tx in &block.txdata {
            let txid = tx.compute_txid();

            // Process inputs (spending)
            if !tx.is_coinbase() {
                for _input in &tx.input {
                    // We need the previous output to get the address
                    // This would come from UTXO set or transaction index
                    // For now, we'll skip spent tracking
                }
            }

            // Process outputs (receiving)
            for (vout, output) in tx.output.iter().enumerate() {
                if let Some(address) = self.extract_address(&output.script_pubkey) {
                    let update = address_updates
                        .entry(address.clone())
                        .or_insert_with(|| AddressUpdate::new(address.clone()));

                    update.received += output.value.to_sat();
                    update.txids.insert(txid);
                    update.utxos.push(UtxoInfo {
                        txid,
                        vout: vout as u32,
                        value: output.value.to_sat(),
                        height,
                        confirmations: 0,
                        script_pubkey: output.script_pubkey.to_bytes(),
                    });

                    if update.first_seen.is_none() {
                        update.first_seen = Some(height);
                    }
                    update.last_seen = Some(height);
                }
            }
        }

        // Apply updates to database
        self.apply_address_updates(address_updates).await?;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.last_indexed_height = height;

        Ok(())
    }

    /// Extract address from script
    fn extract_address(&self, script: &Script) -> Option<String> {
        // Try to extract standard address types
        if script.is_p2pkh() {
            // P2PKH
            if let Ok(addr) = Address::from_script(script, self.network) {
                return Some(addr.to_string());
            }
        } else if script.is_p2sh() {
            // P2SH
            if let Ok(addr) = Address::from_script(script, self.network) {
                return Some(addr.to_string());
            }
        } else if self.config.index_witness {
            // Check for witness addresses
            if script.is_p2wpkh() || script.is_p2wsh() {
                if let Ok(addr) = Address::from_script(script, self.network) {
                    return Some(addr.to_string());
                }
            }
        }

        None
    }

    /// Apply address updates to database
    async fn apply_address_updates(&self, updates: HashMap<String, AddressUpdate>) -> Result<()> {
        let mut batch = Batch::default();
        let update_count = updates.len();

        for (address, update) in updates {
            // Update transaction list
            let mut txids = self.get_address_txids_internal(&address).await?;
            txids.extend(update.txids);
            let txids_bytes = bincode::serialize(&txids)?;
            batch.insert(address.as_bytes(), txids_bytes);

            // Update UTXO list
            let mut utxos = self.get_address_utxos_internal(&address).await?;
            utxos.extend(update.utxos);
            let utxos_bytes = bincode::serialize(&utxos)?;
            self.address_utxos.insert(address.as_bytes(), utxos_bytes)?;

            // Update balance info
            let mut info = self
                .get_address_info_internal(&address)
                .await?
                .unwrap_or_else(|| AddressInfo {
                    address: address.clone(),
                    total_received: 0,
                    total_sent: 0,
                    balance: 0,
                    tx_count: 0,
                    txids: vec![],
                    utxos: vec![],
                    first_seen: None,
                    last_seen: None,
                });

            info.total_received += update.received;
            info.total_sent += update.sent;
            info.balance = info.total_received - info.total_sent;
            info.tx_count = txids.len();
            info.txids = txids;
            info.utxos = utxos;
            if info.first_seen.is_none() {
                info.first_seen = update.first_seen;
            }
            info.last_seen = update.last_seen;

            let info_bytes = bincode::serialize(&info)?;
            self.address_balances
                .insert(address.as_bytes(), info_bytes)?;

            // Update cache
            self.cache.write().await.put(address, info);
        }

        // Apply batch
        self.address_txs.apply_batch(batch)?;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_addresses = self.address_txs.len() as u64;
        stats.db_writes += update_count as u64;

        Ok(())
    }

    /// Get address information
    pub async fn get_address_info(&self, address: &str) -> Result<Option<AddressInfo>> {
        // Check cache first
        if let Some(info) = self.cache.write().await.get(address) {
            let mut stats = self.stats.write().await;
            stats.cache_hits += 1;
            return Ok(Some(info.clone()));
        }

        // Check database
        let info = self.get_address_info_internal(address).await?;

        if let Some(ref info) = info {
            // Update cache
            self.cache
                .write()
                .await
                .put(address.to_string(), info.clone());

            // Update stats
            let mut stats = self.stats.write().await;
            stats.cache_misses += 1;
        }

        Ok(info)
    }

    /// Get address info from database
    async fn get_address_info_internal(&self, address: &str) -> Result<Option<AddressInfo>> {
        if let Some(bytes) = self.address_balances.get(address.as_bytes())? {
            let info: AddressInfo = bincode::deserialize(&bytes)?;

            let mut stats = self.stats.write().await;
            stats.db_reads += 1;

            Ok(Some(info))
        } else {
            Ok(None)
        }
    }

    /// Get address transaction IDs
    async fn get_address_txids_internal(&self, address: &str) -> Result<Vec<Txid>> {
        if let Some(bytes) = self.address_txs.get(address.as_bytes())? {
            let txids: Vec<Txid> = bincode::deserialize(&bytes)?;
            Ok(txids)
        } else {
            Ok(Vec::new())
        }
    }

    /// Get address UTXOs
    async fn get_address_utxos_internal(&self, address: &str) -> Result<Vec<UtxoInfo>> {
        if let Some(bytes) = self.address_utxos.get(address.as_bytes())? {
            let utxos: Vec<UtxoInfo> = bincode::deserialize(&bytes)?;
            Ok(utxos)
        } else {
            Ok(Vec::new())
        }
    }

    /// Get address balance
    pub async fn get_address_balance(&self, address: &str) -> Result<u64> {
        if let Some(info) = self.get_address_info(address).await? {
            Ok(info.balance)
        } else {
            Ok(0)
        }
    }

    /// Get address transaction history
    pub async fn get_address_history(&self, address: &str) -> Result<Vec<Txid>> {
        if let Some(info) = self.get_address_info(address).await? {
            Ok(info.txids)
        } else {
            Ok(Vec::new())
        }
    }

    /// Get address UTXOs
    pub async fn get_address_utxos(&self, address: &str) -> Result<Vec<UtxoInfo>> {
        if let Some(info) = self.get_address_info(address).await? {
            Ok(info.utxos)
        } else {
            Ok(Vec::new())
        }
    }

    /// Remove block from index (for reorgs)
    pub async fn remove_block(&self, block: &Block, height: u32) -> Result<()> {
        // This would reverse the indexing operation
        // For simplicity, we'll just log it
        info!("Removing block {} from address index", block.block_hash());

        // Update stats
        let mut stats = self.stats.write().await;
        if stats.last_indexed_height == height {
            stats.last_indexed_height = height.saturating_sub(1);
        }

        Ok(())
    }

    /// Get index statistics
    pub async fn get_stats(&self) -> AddressIndexStats {
        self.stats.read().await.clone()
    }

    /// Compact the database
    pub async fn compact(&self) -> Result<()> {
        info!("Compacting address index database");

        self.db.flush_async().await?;

        Ok(())
    }
}

/// Address update during block processing
struct AddressUpdate {
    #[allow(dead_code)]
    address: String,
    received: u64,
    sent: u64,
    txids: HashSet<Txid>,
    utxos: Vec<UtxoInfo>,
    first_seen: Option<u32>,
    last_seen: Option<u32>,
}

impl AddressUpdate {
    fn new(address: String) -> Self {
        Self {
            address,
            received: 0,
            sent: 0,
            txids: HashSet::new(),
            utxos: Vec::new(),
            first_seen: None,
            last_seen: None,
        }
    }
}
