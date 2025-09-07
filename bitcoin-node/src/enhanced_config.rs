use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Bitcoin node command-line interface
#[derive(Parser, Debug)]
#[command(name = "bitcoin-node")]
#[command(about = "A Bitcoin node implementation in Rust", long_about = None)]
pub struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Data directory
    #[arg(short, long, value_name = "DIR", default_value = "~/.bitcoin-rust")]
    pub datadir: PathBuf,

    /// Network to use
    #[arg(short, long, default_value = "mainnet")]
    pub network: String,

    /// Enable debug logging
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Run in daemon mode
    #[arg(short = 'D', long)]
    pub daemon: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the Bitcoin node
    Start {
        /// Reindex the blockchain
        #[arg(long)]
        reindex: bool,

        /// Rescan the blockchain for wallet transactions
        #[arg(long)]
        rescan: bool,
    },

    /// Stop the running node
    Stop,

    /// Get node information
    Info,

    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },

    /// Mining operations
    Mine {
        /// Number of blocks to mine
        #[arg(default_value = "1")]
        blocks: u32,

        /// Mining address
        #[arg(short, long)]
        address: Option<String>,
    },

    /// Network operations
    Network {
        #[command(subcommand)]
        command: NetworkCommands,
    },

    /// Blockchain operations
    Blockchain {
        #[command(subcommand)]
        command: BlockchainCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum WalletCommands {
    /// Create a new wallet
    Create {
        /// Wallet name
        #[arg(short, long)]
        name: String,
    },

    /// Load an existing wallet
    Load {
        /// Wallet name
        #[arg(short, long)]
        name: String,
    },

    /// Get wallet balance
    Balance,

    /// List transactions
    ListTransactions {
        /// Number of transactions to show
        #[arg(default_value = "10")]
        count: usize,
    },

    /// Send Bitcoin
    Send {
        /// Recipient address
        address: String,

        /// Amount in BTC
        amount: f64,

        /// Fee rate in sat/vB
        #[arg(short, long)]
        fee_rate: Option<u64>,
    },

    /// Get new receiving address
    GetAddress,

    /// List unspent outputs
    ListUnspent,
}

#[derive(Subcommand, Debug)]
pub enum NetworkCommands {
    /// Add a peer
    AddPeer {
        /// Peer address (IP:port)
        address: String,
    },

    /// List connected peers
    ListPeers,

    /// Get network info
    Info,

    /// Ban a peer
    Ban {
        /// Peer address or IP
        address: String,

        /// Ban duration in seconds
        #[arg(default_value = "86400")]
        duration: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum BlockchainCommands {
    /// Get blockchain info
    Info,

    /// Get block by hash or height
    GetBlock {
        /// Block hash or height
        block: String,
    },

    /// Get block hash by height
    GetBlockHash {
        /// Block height
        height: u32,
    },

    /// Get transaction
    GetTransaction {
        /// Transaction ID
        txid: String,
    },

    /// Verify the blockchain
    Verify {
        /// Number of blocks to verify
        #[arg(default_value = "1000")]
        blocks: u32,
    },
}

/// Node configuration loaded from file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedNodeConfig {
    // Network settings
    pub network: String,
    pub p2p_bind: String,
    pub p2p_port: u16,
    pub max_connections: usize,
    pub connect_peers: Vec<String>,
    pub dns_seeds: bool,

    // RPC settings
    pub rpc_enabled: bool,
    pub rpc_bind: String,
    pub rpc_port: u16,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    pub rpc_threads: usize,

    // Wallet settings
    pub wallet_enabled: bool,
    pub wallet_dir: String,
    pub keypool_size: usize,
    pub enable_wallet_broadcast: bool,

    // Mining settings
    pub mining_enabled: bool,
    pub mining_address: Option<String>,
    pub mining_threads: usize,
    pub block_min_tx_fee: u64,

    // Mempool settings
    pub mempool_max_size: usize,
    pub mempool_expiry_hours: u32,
    pub min_relay_fee: u64,
    pub max_orphan_tx: usize,

    // Chain settings
    pub assume_valid: Option<String>,
    pub prune: Option<u64>,
    pub dbcache: usize,
    pub block_index_cache: usize,

    // Node behavior
    pub datadir: String,
    pub daemon: bool,
    pub log_level: String,
    pub log_file: Option<String>,
    pub pid_file: Option<String>,

    // Fee estimation
    pub fee_estimates: bool,
    pub fee_estimate_blocks: Vec<u32>,
    pub fee_estimate_mode: String,
}

impl Default for EnhancedNodeConfig {
    fn default() -> Self {
        Self {
            // Network
            network: "mainnet".to_string(),
            p2p_bind: "0.0.0.0:8333".to_string(),
            p2p_port: 8333,
            max_connections: 125,
            connect_peers: Vec::new(),
            dns_seeds: true,

            // RPC
            rpc_enabled: true,
            rpc_bind: "127.0.0.1:8332".to_string(),
            rpc_port: 8332,
            rpc_user: None,
            rpc_password: None,
            rpc_threads: 4,

            // Wallet
            wallet_enabled: true,
            wallet_dir: "wallets".to_string(),
            keypool_size: 1000,
            enable_wallet_broadcast: true,

            // Mining
            mining_enabled: false,
            mining_address: None,
            mining_threads: 1,
            block_min_tx_fee: 1000,

            // Mempool
            mempool_max_size: 300_000_000, // 300MB
            mempool_expiry_hours: 336,     // 2 weeks
            min_relay_fee: 1000,           // 1 sat/vB
            max_orphan_tx: 100,

            // Chain
            assume_valid: None,
            prune: None,
            dbcache: 450,
            block_index_cache: 100,

            // Node
            datadir: "~/.bitcoin-rust".to_string(),
            daemon: false,
            log_level: "info".to_string(),
            log_file: None,
            pid_file: None,

            // Fee estimation
            fee_estimates: true,
            fee_estimate_blocks: vec![1, 2, 3, 6, 15, 25, 144, 1008],
            fee_estimate_mode: "CONSERVATIVE".to_string(),
        }
    }
}

impl EnhancedNodeConfig {
    /// Load configuration from file
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let contents = fs::read_to_string(path).context("Failed to read config file")?;

        // Try JSON first, then TOML
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            serde_json::from_str(&contents).context("Failed to parse JSON config")
        } else {
            toml::from_str(&contents).context("Failed to parse TOML config")
        }
    }

    /// Save configuration to file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let contents = if path.extension().and_then(|s| s.to_str()) == Some("json") {
            serde_json::to_string_pretty(self)?
        } else {
            toml::to_string_pretty(self)?
        };

        fs::write(path, contents).context("Failed to write config file")?;

        Ok(())
    }

    /// Merge with command-line arguments
    pub fn merge_with_cli(&mut self, cli: &Cli) {
        // Override with CLI arguments
        self.network = cli.network.clone();
        self.datadir = cli.datadir.to_string_lossy().to_string();

        if cli.daemon {
            self.daemon = true;
        }

        if cli.verbose {
            self.log_level = "debug".to_string();
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate network
        match self.network.as_str() {
            "mainnet" | "testnet" | "regtest" | "signet" => {}
            _ => anyhow::bail!("Invalid network: {}", self.network),
        }

        // Validate ports
        if self.p2p_port == 0 {
            anyhow::bail!("Invalid P2P port");
        }

        if self.rpc_enabled && self.rpc_port == 0 {
            anyhow::bail!("Invalid RPC port");
        }

        // Validate fee settings
        if self.min_relay_fee == 0 {
            anyhow::bail!("Minimum relay fee must be positive");
        }

        Ok(())
    }

    /// Get the appropriate P2P port for the network
    pub fn get_p2p_port(&self) -> u16 {
        match self.network.as_str() {
            "mainnet" => 8333,
            "testnet" => 18333,
            "regtest" => 18444,
            "signet" => 38333,
            _ => self.p2p_port,
        }
    }

    /// Get the appropriate RPC port for the network
    pub fn get_rpc_port(&self) -> u16 {
        match self.network.as_str() {
            "mainnet" => 8332,
            "testnet" => 18332,
            "regtest" => 18443,
            "signet" => 38332,
            _ => self.rpc_port,
        }
    }
}

/// Parse and validate CLI arguments with config
pub fn parse_config() -> Result<(Cli, EnhancedNodeConfig)> {
    let cli = Cli::parse();

    // Load config file if specified
    let mut config = if let Some(config_path) = &cli.config {
        EnhancedNodeConfig::load_from_file(config_path)?
    } else {
        // Try to load default config
        let default_path = PathBuf::from(&cli.datadir).join("bitcoin.conf");
        if default_path.exists() {
            EnhancedNodeConfig::load_from_file(&default_path).unwrap_or_default()
        } else {
            EnhancedNodeConfig::default()
        }
    };

    // Merge CLI arguments
    config.merge_with_cli(&cli);

    // Validate
    config.validate()?;

    Ok((cli, config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_config_default() {
        let config = EnhancedNodeConfig::default();
        assert_eq!(config.network, "mainnet");
        assert_eq!(config.p2p_port, 8333);
        assert_eq!(config.rpc_port, 8332);
        assert!(config.rpc_enabled);
    }

    #[test]
    fn test_get_network_ports() {
        let mut config = EnhancedNodeConfig::default();

        config.network = "testnet".to_string();
        assert_eq!(config.get_p2p_port(), 18333);
        assert_eq!(config.get_rpc_port(), 18332);

        config.network = "regtest".to_string();
        assert_eq!(config.get_p2p_port(), 18444);
        assert_eq!(config.get_rpc_port(), 18443);
    }

    #[test]
    fn test_config_validation() {
        let mut config = EnhancedNodeConfig::default();
        assert!(config.validate().is_ok());

        config.network = "invalid".to_string();
        assert!(config.validate().is_err());

        config.network = "mainnet".to_string();
        config.min_relay_fee = 0;
        assert!(config.validate().is_err());
    }
}
