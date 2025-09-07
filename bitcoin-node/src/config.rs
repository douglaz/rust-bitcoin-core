use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub network: String,
    pub datadir: String,
    pub rpc_enabled: bool,
    pub rpc_bind: String,
    pub p2p_bind: String,
    pub connect_peers: Vec<String>,
    pub max_connections: usize,
    pub cache_size: usize,
}

impl NodeConfig {
    pub fn from_cli(
        config: Option<String>,
        network: String,
        datadir: String,
        rpc: bool,
        rpc_bind: String,
        p2p_bind: String,
        connect: Vec<String>,
    ) -> Result<Self> {
        // Load from config file if provided
        if let Some(config_path) = config {
            return Self::from_file(&config_path);
        }

        // Otherwise use CLI arguments
        // Adjust RPC bind address based on network if using default
        let actual_rpc_bind = if rpc_bind == "127.0.0.1:8332" {
            match network.as_str() {
                "regtest" => "127.0.0.1:18443".to_string(),
                "testnet" => "127.0.0.1:18332".to_string(),
                "signet" => "127.0.0.1:38332".to_string(),
                _ => rpc_bind,
            }
        } else {
            rpc_bind
        };

        Ok(Self {
            network,
            datadir,
            rpc_enabled: rpc,
            rpc_bind: actual_rpc_bind,
            p2p_bind,
            connect_peers: connect,
            max_connections: 125,
            cache_size: 450, // MB
        })
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: "mainnet".to_string(),
            datadir: "./data".to_string(),
            rpc_enabled: false,
            rpc_bind: "127.0.0.1:8332".to_string(),
            p2p_bind: "0.0.0.0:8333".to_string(),
            connect_peers: vec![],
            max_connections: 125,
            cache_size: 450,
        }
    }
}
