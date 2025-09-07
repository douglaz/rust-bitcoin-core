//! Rust Bitcoin Core - A Bitcoin node implementation in Rust

pub use bitcoin_node::{Node, NodeConfig};
pub use bitcoin_cli::Cli;
pub use bitcoin_core_lib as core;
pub use network;
pub use storage;
pub use mempool;
pub use miner;
pub use wallet;
pub use rpc;

/// Node orchestrator for managing all components
pub struct NodeOrchestrator {
    node: bitcoin_node::Node,
}

impl NodeOrchestrator {
    /// Create a new node orchestrator
    pub async fn new(config: bitcoin_node::NodeConfig) -> anyhow::Result<Self> {
        let node = bitcoin_node::Node::new(config).await?;
        Ok(Self { node })
    }
    
    /// Run the node
    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.node.run().await
    }
    
    /// Shutdown the node gracefully
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        self.node.shutdown().await
    }
}