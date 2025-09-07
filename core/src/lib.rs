//! # Bitcoin Core Library
//!
//! Core implementation of the Bitcoin protocol in Rust.
//!
//! This library provides the fundamental components for Bitcoin blockchain
//! validation, including transaction and block validation, UTXO management,
//! script execution, and consensus rule enforcement.
//!
//! ## Main Components
//!
//! - **Chain Management**: Blockchain state tracking and management
//! - **Validation**: Complete block and transaction validation
//! - **UTXO Management**: Efficient unspent transaction output tracking
//! - **Script Engine**: Bitcoin script interpreter with SegWit/Taproot support
//! - **Consensus Rules**: Full consensus rule implementation
//! - **Reorganization**: Chain reorganization handling
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use bitcoin_core_lib::chain::ChainManager;
//! use bitcoin_core_lib::validation::BlockValidator;
//!
//! async fn example() -> anyhow::Result<()> {
//!     // Initialize chain manager
//!     let chain = ChainManager::new(Default::default()).await?;
//!     
//!     // Validate and add a block
//!     let validator = BlockValidator::new();
//!     let block = /* ... get block ... */;
//!     if validator.validate_block(&block)? {
//!         chain.add_block(block).await?;
//!     }
//!     Ok(())
//! }
//! ```

pub mod bip112;
pub mod bip113;
pub mod bip143;
pub mod bip68;
pub mod bitcoin_primitives;
pub mod block_validation;
pub mod block_validation_pipeline;
pub mod chain;
pub mod coinbase;
pub mod config;
pub mod consensus;
pub mod consensus_rules;
pub mod database_sled;
pub mod error;
pub mod fee;
pub mod fee_estimator;
pub mod merkle;
pub mod script;
pub mod script_interpreter;
pub mod transaction_validation;
pub mod tx_validator;
pub mod utxo_manager;
pub mod utxo_tracker;
pub mod validation;
pub use database_sled as database;
// Note: database.rs (RocksDB) is deprecated, using database_sled instead
pub mod chain_stats;
pub mod fee_estimation;
pub mod reorg;
pub mod segwit;
pub mod taproot;
pub mod utxo_cache;
pub mod utxo_cache_levels;
pub mod utxo_storage_adapter;
pub mod witness_validation;
// pub mod chain_reorg;  // Disabled: uses old RocksDB methods, functionality in chain_reorganization
pub mod block_index;
pub mod block_index_persistence;
pub mod checkpoints;
pub mod utxo_cache_manager;
// pub mod utxo_compaction;  // Disabled: uses old RocksDB methods
pub mod chain_reorganization;
pub mod compact_filters;
pub mod difficulty;
pub mod orphan_blocks;
pub mod parallel_validation;
pub mod pow_validation;
pub mod work;

#[cfg(test)]
mod taproot_activation_tests;

pub use bitcoin_primitives::{BitcoinBlock, BitcoinBlockHeader, BitcoinTransaction, Utxo};
pub use block_validation_pipeline::{
    BlockValidationPipeline, UtxoProvider, ValidationResult as PipelineValidationResult,
    ValidationStage,
};
pub use chain::ChainManager;
pub use consensus::{ConsensusParams, ValidationResult};
pub use difficulty::{calculate_work_required, DifficultyCalculator, DifficultyStats};
pub use error::CoreError;
pub use fee::FeeCalculator;
pub use fee_estimation::{
    EstimationMode, FeeEstimator, FeePriority, FeeRate, MempoolStats, SmartFeeEstimate,
};
pub use script::{ScriptFlags, ScriptInterpreter};
pub use script_interpreter::{
    ScriptFlags as EnhancedScriptFlags, ScriptInterpreter as EnhancedScriptInterpreter,
};
pub use transaction_validation::{TransactionValidator, ValidationContext, ValidationFlags};
pub use tx_validator::{TxValidationPipeline, TxValidator, UtxoView};
pub use utxo_tracker::{ApplyBlockResult, UtxoStats as TrackerStats, UtxoTracker};
pub use validation::BlockValidator;
