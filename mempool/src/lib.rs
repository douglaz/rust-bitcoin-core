pub mod expiration;
pub mod fee_estimation;
pub mod mempool_acceptance;
pub mod mempool_manager;
pub mod mempool_persistence;
pub mod package_relay;
pub mod persistence;
pub mod pool;
pub mod rbf;
pub mod utxo_provider;
pub mod validation;

// Main mempool implementation
pub use pool::{Mempool, MempoolEntry, MiningTransaction};

// Supporting modules
pub use expiration::{ExpirationPolicy, MaintenanceResult};
pub use fee_estimation::{
    EstimationMode, FeeEstimate, FeeEstimator, FeePriority, SmartFeeEstimate,
};
pub use persistence::{MempoolPersistence, MempoolSnapshot};
pub use package_relay::{
    Package, PackageAcceptanceResult, PackageRelayManager, PackageType, PackageValidator,
};
pub use rbf::{RBFConflictTracker, RBFPolicy, ReplacementCandidate, ReplacementCheck, UtxoProvider};
pub use utxo_provider::{InMemoryUtxoProvider, MempoolUtxoProvider};
pub use validation::{EnhancedMempoolEntry, MempoolPolicy, PackageInfo, ValidationContext};

// Acceptance and manager modules for advanced features
pub use mempool_acceptance::{
    AcceptanceResult, MempoolAcceptance, MempoolConfig as AcceptanceConfig,
};
pub use mempool_manager::{MempoolManager, MempoolManagerConfig};
