//! Configuration management for Bitcoin Core
//!
//! Provides configuration loading from multiple sources:
//! - Configuration files (bitcoin.conf)
//! - Command-line arguments
//! - Environment variables
//! - Default values

use anyhow::{Context, Result};
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Main configuration structure for the Bitcoin node
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Network to operate on (main, test, regtest, signet)
    pub network: Network,

    /// Data directory for blockchain storage
    pub datadir: PathBuf,

    /// P2P network configuration
    pub network_config: NetworkConfig,

    /// RPC server configuration
    pub rpc_config: RpcConfig,

    /// Storage configuration
    pub storage_config: StorageConfig,

    /// Mempool configuration
    pub mempool_config: MempoolConfig,

    /// Mining configuration
    pub mining_config: MiningConfig,

    /// Wallet configuration
    pub wallet_config: WalletConfig,

    /// Performance tuning
    pub performance: PerformanceConfig,

    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// P2P port to listen on
    pub port: u16,

    /// Maximum number of connections
    pub max_connections: usize,

    /// Maximum inbound connections
    pub max_inbound: usize,

    /// Maximum outbound connections  
    pub max_outbound: usize,

    /// Connect timeout
    pub connect_timeout: Duration,

    /// Enable listening for connections
    pub listen: bool,

    /// Bind addresses
    pub bind: Vec<SocketAddr>,

    /// External IP address (for discovery)
    pub external_ip: Option<String>,

    /// DNS seeds to use
    pub dns_seeds: Vec<String>,

    /// Fixed seed nodes
    pub seed_nodes: Vec<SocketAddr>,

    /// User agent string
    pub user_agent: String,

    /// Enable compact blocks (BIP152)
    pub compact_blocks: bool,
}

/// RPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Enable RPC server
    pub enabled: bool,

    /// RPC port
    pub port: u16,

    /// RPC bind addresses
    pub bind: Vec<SocketAddr>,

    /// RPC username
    pub user: Option<String>,

    /// RPC password
    pub password: Option<String>,

    /// RPC authentication cookie file
    pub cookie_file: Option<PathBuf>,

    /// Allowed IP addresses/ranges
    pub allow_ip: Vec<String>,

    /// Maximum concurrent RPC connections
    pub max_connections: usize,

    /// RPC work queue depth
    pub work_queue: usize,

    /// RPC timeout
    pub timeout: Duration,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Enable pruning (0 = disabled, >550 = target size in MB)
    pub prune: u64,

    /// Enable transaction index
    pub txindex: bool,

    /// Enable address index
    pub addressindex: bool,

    /// Enable timestamp index
    pub timestampindex: bool,

    /// Enable spent index
    pub spentindex: bool,

    /// Database cache size in MB
    pub dbcache: usize,

    /// Database backend (sled, rocksdb)
    pub backend: String,

    /// Block files directory
    pub blocks_dir: PathBuf,
}

/// Mempool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolConfig {
    /// Maximum mempool size in MB
    pub max_mempool: usize,

    /// Mempool expiry time in hours
    pub mempool_expiry: u64,

    /// Minimum relay fee in satoshis per kilobyte
    pub min_relay_fee: u64,

    /// Enable replace-by-fee
    pub enable_rbf: bool,

    /// Maximum orphan transactions
    pub max_orphan_tx: usize,

    /// Reject transactions below this fee rate
    pub min_fee_rate: u64,
}

/// Mining configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningConfig {
    /// Enable mining
    pub enabled: bool,

    /// Number of mining threads (0 = auto)
    pub threads: usize,

    /// Mining address
    pub coinbase_address: Option<String>,

    /// Coinbase signature
    pub coinbase_sig: String,

    /// Block size limit
    pub block_max_size: usize,

    /// Block weight limit
    pub block_max_weight: usize,

    /// Minimum block size
    pub block_min_size: usize,
}

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Enable wallet
    pub enabled: bool,

    /// Wallet file path
    pub wallet_file: PathBuf,

    /// Enable wallet broadcasting
    pub broadcast: bool,

    /// Keypool size
    pub keypool_size: usize,

    /// Enable HD wallet
    pub use_hd: bool,

    /// Wallet passphrase (encrypted in config)
    pub passphrase: Option<String>,

    /// Auto-backup wallet
    pub auto_backup: bool,

    /// Backup directory
    pub backup_dir: Option<PathBuf>,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Parallel validation threads (0 = auto)
    pub par: usize,

    /// Signature cache size in MB
    pub sig_cache_size: usize,

    /// Script cache size in MB
    pub script_cache_size: usize,

    /// UTXO cache size in MB
    pub utxo_cache_size: usize,

    /// Maximum buffer size for network messages
    pub max_buffer_size: usize,

    /// Batch write size for database
    pub batch_size: usize,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,

    /// Log to console
    pub console: bool,

    /// Log file path
    pub file: Option<PathBuf>,

    /// Maximum log file size in MB
    pub max_size: usize,

    /// Number of log files to keep
    pub max_files: usize,

    /// Log categories to enable
    pub categories: Vec<String>,

    /// Print timestamps
    pub timestamps: bool,
}

// Default implementations
impl Default for Config {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            datadir: Self::default_data_dir(),
            network_config: NetworkConfig::default(),
            rpc_config: RpcConfig::default(),
            storage_config: StorageConfig::default(),
            mempool_config: MempoolConfig::default(),
            mining_config: MiningConfig::default(),
            wallet_config: WalletConfig::default(),
            performance: PerformanceConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Config {
    /// Get default data directory based on OS
    fn default_data_dir() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));

        #[cfg(target_os = "windows")]
        let datadir = home.join("AppData").join("Roaming").join("Bitcoin");

        #[cfg(target_os = "macos")]
        let datadir = home
            .join("Library")
            .join("Application Support")
            .join("Bitcoin");

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let datadir = home.join(".bitcoin");

        datadir
    }

    /// Load configuration from file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let contents = std::fs::read_to_string(path).context("Failed to read config file")?;

        // Try TOML first
        if let Ok(config) = toml::from_str::<Self>(&contents) {
            return Ok(config);
        }

        // Try bitcoin.conf format
        Self::from_bitcoin_conf(&contents)
    }

    /// Parse bitcoin.conf format
    fn from_bitcoin_conf(contents: &str) -> Result<Self> {
        let mut config = Self::default();

        for line in contents.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse key=value
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                config.apply_setting(key, value)?;
            }
        }

        Ok(config)
    }

    /// Apply a single setting
    pub fn apply_setting(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            // Network settings
            "testnet" if value == "1" => self.network = Network::Testnet,
            "regtest" if value == "1" => self.network = Network::Regtest,
            "signet" if value == "1" => self.network = Network::Signet,
            "port" => self.network_config.port = value.parse()?,
            "maxconnections" => self.network_config.max_connections = value.parse()?,
            "listen" => self.network_config.listen = value == "1",

            // RPC settings
            "rpcport" => self.rpc_config.port = value.parse()?,
            "rpcuser" => self.rpc_config.user = Some(value.to_string()),
            "rpcpassword" => self.rpc_config.password = Some(value.to_string()),
            "rpcallowip" => self.rpc_config.allow_ip.push(value.to_string()),

            // Storage settings
            "datadir" => self.datadir = PathBuf::from(value),
            "prune" => self.storage_config.prune = value.parse()?,
            "txindex" => self.storage_config.txindex = value == "1",
            "dbcache" => self.storage_config.dbcache = value.parse()?,

            // Mempool settings
            "maxmempool" => self.mempool_config.max_mempool = value.parse()?,
            "mempoolexpiry" => self.mempool_config.mempool_expiry = value.parse()?,

            // Mining settings
            "gen" => self.mining_config.enabled = value == "1",
            "genproclimit" => self.mining_config.threads = value.parse()?,

            // Wallet settings
            "wallet" => self.wallet_config.enabled = value == "1",
            "keypool" => self.wallet_config.keypool_size = value.parse()?,

            // Performance settings
            "par" => self.performance.par = value.parse()?,

            // Logging settings
            "debug" => {
                if value == "1" {
                    self.logging.level = "debug".to_string();
                }
            }
            "printtoconsole" => self.logging.console = value == "1",

            _ => {
                // Ignore unknown settings for compatibility
                tracing::warn!("Unknown config option: {} = {}", key, value);
            }
        }

        Ok(())
    }

    /// Merge with command-line arguments
    pub fn merge_args(&mut self, args: &clap::ArgMatches) -> Result<()> {
        if let Some(datadir) = args.get_one::<String>("datadir") {
            self.datadir = PathBuf::from(datadir);
        }

        if args.get_flag("testnet") {
            self.network = Network::Testnet;
        }

        if args.get_flag("regtest") {
            self.network = Network::Regtest;
        }

        if let Some(port) = args.get_one::<u16>("port") {
            self.network_config.port = *port;
        }

        if let Some(rpcport) = args.get_one::<u16>("rpcport") {
            self.rpc_config.port = *rpcport;
        }

        Ok(())
    }

    /// Apply environment variables
    pub fn merge_env(&mut self) -> Result<()> {
        if let Ok(datadir) = std::env::var("BITCOIN_DATADIR") {
            self.datadir = PathBuf::from(datadir);
        }

        if let Ok(network) = std::env::var("BITCOIN_NETWORK") {
            self.network = match network.as_str() {
                "main" | "mainnet" => Network::Bitcoin,
                "test" | "testnet" => Network::Testnet,
                "regtest" => Network::Regtest,
                "signet" => Network::Signet,
                _ => self.network,
            };
        }

        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Check data directory exists or can be created
        if !self.datadir.exists() {
            std::fs::create_dir_all(&self.datadir).context("Failed to create data directory")?;
        }

        // Check port conflicts
        if self.network_config.port == self.rpc_config.port {
            anyhow::bail!("P2P port and RPC port cannot be the same");
        }

        // Check prune settings
        if self.storage_config.prune > 0 && self.storage_config.prune < 550 {
            anyhow::bail!("Prune target must be 0 (disabled) or >= 550 MB");
        }

        // Check cache sizes
        let total_cache = self.storage_config.dbcache
            + self.performance.sig_cache_size
            + self.performance.script_cache_size
            + self.performance.utxo_cache_size;

        if total_cache > 16384 {
            tracing::warn!("Total cache size ({} MB) is very high", total_cache);
        }

        Ok(())
    }

    /// Save configuration to file
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Get network-specific default port
    pub fn default_port(&self) -> u16 {
        match self.network {
            Network::Bitcoin => 8333,
            Network::Testnet => 18333,
            Network::Regtest => 18444,
            Network::Signet => 38333,
            _ => 8333,
        }
    }

    /// Get network-specific RPC port
    pub fn default_rpc_port(&self) -> u16 {
        match self.network {
            Network::Bitcoin => 8332,
            Network::Testnet => 18332,
            Network::Regtest => 18443,
            Network::Signet => 38332,
            _ => 8332,
        }
    }
}

// Default implementations for sub-configurations
impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            port: 8333,
            max_connections: 125,
            max_inbound: 117,
            max_outbound: 8,
            connect_timeout: Duration::from_secs(5),
            listen: true,
            bind: vec![],
            external_ip: None,
            dns_seeds: vec![],
            seed_nodes: vec![],
            user_agent: "/Rust-Bitcoin-Core:1.0.0/".to_string(),
            compact_blocks: true,
        }
    }
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 8332,
            bind: vec!["127.0.0.1:8332".parse().unwrap()],
            user: None,
            password: None,
            cookie_file: None,
            allow_ip: vec!["127.0.0.1".to_string()],
            max_connections: 256,
            work_queue: 16,
            timeout: Duration::from_secs(30),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            prune: 0,
            txindex: false,
            addressindex: false,
            timestampindex: false,
            spentindex: false,
            dbcache: 450,
            backend: "sled".to_string(),
            blocks_dir: PathBuf::from("blocks"),
        }
    }
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_mempool: 300,
            mempool_expiry: 336,
            min_relay_fee: 1000,
            enable_rbf: true,
            max_orphan_tx: 100,
            min_fee_rate: 1,
        }
    }
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threads: 0,
            coinbase_address: None,
            coinbase_sig: String::new(),
            block_max_size: 1_000_000,
            block_max_weight: 4_000_000,
            block_min_size: 0,
        }
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            wallet_file: PathBuf::from("wallet.dat"),
            broadcast: true,
            keypool_size: 1000,
            use_hd: true,
            passphrase: None,
            auto_backup: true,
            backup_dir: None,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            par: 0, // Auto-detect
            sig_cache_size: 32,
            script_cache_size: 32,
            utxo_cache_size: 450,
            max_buffer_size: 32 * 1024 * 1024,
            batch_size: 1000,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            console: false,
            file: Some(PathBuf::from("debug.log")),
            max_size: 100,
            max_files: 3,
            categories: vec![],
            timestamps: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.network, Network::Bitcoin);
        assert_eq!(config.network_config.port, 8333);
        assert_eq!(config.rpc_config.port, 8332);
    }

    #[test]
    fn test_bitcoin_conf_parsing() {
        let conf = r#"
# Bitcoin configuration
testnet=1
port=18333
rpcport=18332
rpcuser=alice
rpcpassword=secret
prune=10000
txindex=1
"#;

        let config = Config::from_bitcoin_conf(conf).unwrap();
        assert_eq!(config.network, Network::Testnet);
        assert_eq!(config.network_config.port, 18333);
        assert_eq!(config.rpc_config.port, 18332);
        assert_eq!(config.rpc_config.user, Some("alice".to_string()));
        assert_eq!(config.storage_config.prune, 10000);
        assert!(config.storage_config.txindex);
    }

    #[test]
    fn test_validation() {
        let mut config = Config::default();

        // Port conflict
        config.rpc_config.port = config.network_config.port;
        assert!(config.validate().is_err());

        // Invalid prune size
        config.rpc_config.port = 8332;
        config.storage_config.prune = 100;
        assert!(config.validate().is_err());
    }
}
