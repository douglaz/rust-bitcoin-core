use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Invalid mnemonic phrase")]
    InvalidMnemonic,

    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Address generation failed: {0}")]
    AddressGenerationFailed(String),

    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: u64, available: u64 },

    #[error("Transaction signing failed: {0}")]
    SigningFailed(String),

    #[error("Storage error: {0}")]
    StorageError(#[from] sled::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),

    #[error("Bitcoin error: {0}")]
    BitcoinError(String),

    #[error("Wallet locked")]
    WalletLocked,

    #[error("Wallet not found")]
    WalletNotFound,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

pub type WalletResult<T> = Result<T, WalletError>;
