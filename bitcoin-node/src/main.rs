use anyhow::Result;
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod enhanced_config;
mod headers_sync;
mod integration;
mod node;
mod node_runner;
mod sync;

use config::NodeConfig;
use node::Node;

#[derive(Parser)]
#[command(name = "bitcoin-node")]
#[command(about = "Rust Bitcoin Core Node", long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<String>,

    /// Network to use (mainnet, testnet, regtest)
    #[arg(short, long, default_value = "mainnet")]
    network: String,

    /// Data directory path
    #[arg(long, default_value = "./data")]
    datadir: String,

    /// Enable RPC server
    #[arg(long)]
    rpc: bool,

    /// RPC bind address
    #[arg(long, default_value = "127.0.0.1:8332")]
    rpc_bind: String,

    /// P2P bind address
    #[arg(long, default_value = "0.0.0.0:8333")]
    p2p_bind: String,

    /// Connect to specific peers (can be used multiple times)
    #[arg(long)]
    connect: Vec<String>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.debug)?;

    info!("Starting Rust Bitcoin Core Node");

    // Load configuration
    let config = NodeConfig::from_cli(
        cli.config,
        cli.network,
        cli.datadir,
        cli.rpc,
        cli.rpc_bind,
        cli.p2p_bind,
        cli.connect,
    )?;

    // Create and start the node
    let mut node = Node::new(config).await?;

    // Set up signal handlers
    let shutdown_signal = setup_shutdown_signal();

    // Start the node
    tokio::select! {
        result = node.run() => {
            if let Err(e) = result {
                error!("Node error: {}", e);
                return Err(e);
            }
        }
        _ = shutdown_signal => {
            info!("Shutdown signal received");
        }
    }

    // Graceful shutdown
    info!("Shutting down node...");
    node.shutdown().await?;

    info!("Node stopped");
    Ok(())
}

fn init_logging(debug: bool) -> Result<()> {
    let filter = if debug { "debug" } else { "info" };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    Ok(())
}

async fn setup_shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}
