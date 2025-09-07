use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bitcoin-cli")]
#[command(about = "Bitcoin Core CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, default_value = "http://127.0.0.1:8332")]
    rpc_url: String,
}

#[derive(Subcommand)]
enum Commands {
    GetBlockchainInfo,
    GetBlock { hash: String },
    GetPeerInfo,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GetBlockchainInfo => {
            println!("Getting blockchain info...");
        }
        Commands::GetBlock { hash } => {
            println!("Getting block: {}", hash);
        }
        Commands::GetPeerInfo => {
            println!("Getting peer info...");
        }
    }

    Ok(())
}
