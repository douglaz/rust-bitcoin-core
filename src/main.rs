use anyhow::{Result, Context};
use bitcoin::Network;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;

mod node_orchestrator;
use node_orchestrator::{NodeConfig, NodeOrchestrator};

/// Bitcoin node command-line interface
#[derive(Parser)]
#[command(name = "bitcoin-node")]
#[command(about = "Full Bitcoin node implementation in Rust")]
#[command(version)]
struct Cli {
    /// Network to connect to
    #[arg(short, long, default_value = "mainnet")]
    network: String,
    
    /// Data directory path
    #[arg(short, long, default_value = "./bitcoin-data")]
    datadir: PathBuf,
    
    /// Enable mining
    #[arg(long)]
    mine: bool,
    
    /// Mining address (required if mining is enabled)
    #[arg(long)]
    mining_address: Option<String>,
    
    /// RPC server port
    #[arg(long, default_value = "8332")]
    rpc_port: u16,
    
    /// P2P port
    #[arg(long, default_value = "8333")]
    p2p_port: u16,
    
    /// Maximum peer connections
    #[arg(long, default_value = "125")]
    max_connections: usize,
    
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
    
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the node (default)
    Start,
    
    /// Show node version and status
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(cli.log_level.parse().unwrap())
        )
        .init();
    
    // Parse network
    let network = match cli.network.as_str() {
        "mainnet" | "main" => Network::Bitcoin,
        "testnet" | "test" => Network::Testnet,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            error!("Invalid network: {}", cli.network);
            std::process::exit(1);
        }
    };
    
    // Handle commands
    match cli.command {
        Some(Commands::Version) => {
            println!("Bitcoin Core Rust Implementation");
            println!("Version: 0.1.0");
            println!("Network: {:?}", network);
            println!("Status: Development");
            Ok(())
        }
        _ => {
            // Create node configuration
            let config = NodeConfig {
                network,
                data_dir: cli.datadir,
                rpc_port: cli.rpc_port,
                p2p_port: cli.p2p_port,
                max_connections: cli.max_connections,
                enable_mining: cli.mine,
                mining_address: cli.mining_address,
            };
            
            // Validate mining configuration
            if config.enable_mining && config.mining_address.is_none() {
                error!("Mining enabled but no mining address provided. Use --mining-address");
                std::process::exit(1);
            }
            
            info!("Starting Bitcoin node...");
            info!("Network: {:?}", config.network);
            info!("Data directory: {:?}", config.data_dir);
            info!("RPC port: {}", config.rpc_port);
            info!("P2P port: {}", config.p2p_port);
            info!("Max connections: {}", config.max_connections);
            info!("Mining: {}", config.enable_mining);
            
            // Create and start node orchestrator
            let orchestrator = NodeOrchestrator::new(config)
                .await
                .context("Failed to initialize node")?;
            
            // Start the node
            orchestrator.start()
                .await
                .context("Node execution failed")?;
            
            info!("Bitcoin node stopped");
            Ok(())
        }
    }
}