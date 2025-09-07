use anyhow::Result;
use bitcoin_node::{Node, NodeConfig};
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "bitcoin-node")]
#[command(about = "Rust Bitcoin Core Node", long_about = None)]
struct Args {
    /// Network to run on (mainnet, testnet, regtest, signet)
    #[arg(short, long, default_value = "regtest")]
    network: String,
    
    /// Data directory
    #[arg(short, long, default_value = "~/.bitcoin-rust")]
    datadir: PathBuf,
    
    /// Enable RPC server
    #[arg(long, default_value_t = true)]
    rpc: bool,
    
    /// RPC bind address
    #[arg(long, default_value = "127.0.0.1:8332")]
    rpc_bind: String,
    
    /// Connect to specific peers (can be specified multiple times)
    #[arg(long)]
    connect: Vec<String>,
    
    /// Maximum connections
    #[arg(long, default_value_t = 125)]
    max_connections: usize,
    
    /// Enable mining
    #[arg(long)]
    enable_mining: bool,
    
    /// Mining address
    #[arg(long)]
    mining_address: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    // Parse arguments
    let args = Args::parse();
    
    info!("Starting Rust Bitcoin Core Node");
    info!("Network: {}", args.network);
    info!("Data directory: {:?}", args.datadir);
    
    // Expand home directory
    let datadir = if args.datadir.starts_with("~") {
        let home = dirs::home_dir().expect("Could not find home directory");
        home.join(args.datadir.strip_prefix("~/").unwrap())
    } else {
        args.datadir
    };
    
    // Create data directory if it doesn't exist
    std::fs::create_dir_all(&datadir)?;
    
    // Create node configuration
    let config = NodeConfig {
        network: args.network,
        datadir: datadir.to_str().unwrap().to_string(),
        rpc_enabled: args.rpc,
        rpc_bind: args.rpc_bind,
        connect_peers: args.connect,
        max_connections: args.max_connections,
        enable_mining: args.enable_mining,
        mining_address: args.mining_address,
    };
    
    // Create and run node
    let mut node = Node::new(config).await?;
    
    // Setup shutdown handler
    let shutdown = tokio::signal::ctrl_c();
    
    // Run node until shutdown signal
    tokio::select! {
        result = node.run() => {
            if let Err(e) = result {
                error!("Node error: {}", e);
            }
        }
        _ = shutdown => {
            info!("Received shutdown signal");
        }
    }
    
    // Graceful shutdown
    info!("Shutting down node...");
    node.shutdown().await?;
    
    info!("Node shutdown complete");
    Ok(())
}