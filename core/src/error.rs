use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Chain error: {0}")]
    ChainError(String),

    #[error("Consensus error: {0}")]
    ConsensusError(String),

    #[error("Storage error: {0}")]
    StorageError(#[from] storage::error::StorageError),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}
