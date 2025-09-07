use jsonrpsee::types::ErrorObjectOwned;
use std::fmt;

/// RPC error types matching Bitcoin Core error codes
#[derive(Debug)]
pub enum RpcError {
    // Standard JSON-RPC 2.0 errors (-32700 to -32000)
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,

    // General Bitcoin Core errors (-1 to -99)
    Misc(String),
    ForbiddenBySafeMode,
    TypeError(String),
    InvalidAddressOrKey,
    OutOfMemory,
    InvalidParameter(String),
    DatabaseError(String),
    DeserializationError(String),
    VerifyError(String),
    VerifyRejected(String),
    VerifyAlreadyInChain,
    InWarmup,
    MethodDeprecated,

    // P2P client errors (-9 to -19)
    ClientNotConnected,
    ClientInInitialDownload,
    ClientNodeAlreadyAdded,
    ClientNodeNotAdded,
    ClientNodeNotConnected,
    ClientInvalidIpOrSubnet,
    ClientP2PDisabled,

    // Chain errors (-25 to -29)
    RpcVerifyError,
    RpcVerifyRejected,
    RpcVerifyAlreadyInChain,
    RpcInWarmup,
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Standard JSON-RPC 2.0 errors
            RpcError::ParseError => write!(f, "Parse error"),
            RpcError::InvalidRequest => write!(f, "Invalid request"),
            RpcError::MethodNotFound => write!(f, "Method not found"),
            RpcError::InvalidParams => write!(f, "Invalid params"),
            RpcError::InternalError => write!(f, "Internal error"),

            // General Bitcoin Core errors
            RpcError::Misc(s) => write!(f, "Miscellaneous error: {}", s),
            RpcError::ForbiddenBySafeMode => write!(f, "Forbidden by safe mode"),
            RpcError::TypeError(s) => write!(f, "Type error: {}", s),
            RpcError::InvalidAddressOrKey => write!(f, "Invalid address or key"),
            RpcError::OutOfMemory => write!(f, "Out of memory"),
            RpcError::InvalidParameter(s) => write!(f, "Invalid parameter: {}", s),
            RpcError::DatabaseError(s) => write!(f, "Database error: {}", s),
            RpcError::DeserializationError(s) => write!(f, "Deserialization error: {}", s),
            RpcError::VerifyError(s) => write!(f, "Verify error: {}", s),
            RpcError::VerifyRejected(s) => write!(f, "Verify rejected: {}", s),
            RpcError::VerifyAlreadyInChain => write!(f, "Verify already in chain"),
            RpcError::InWarmup => write!(f, "In warmup"),
            RpcError::MethodDeprecated => write!(f, "Method deprecated"),

            // P2P client errors
            RpcError::ClientNotConnected => write!(f, "Client not connected"),
            RpcError::ClientInInitialDownload => write!(f, "Client in initial download"),
            RpcError::ClientNodeAlreadyAdded => write!(f, "Client node already added"),
            RpcError::ClientNodeNotAdded => write!(f, "Client node not added"),
            RpcError::ClientNodeNotConnected => write!(f, "Client node not connected"),
            RpcError::ClientInvalidIpOrSubnet => write!(f, "Client invalid IP or subnet"),
            RpcError::ClientP2PDisabled => write!(f, "Client P2P disabled"),

            // Chain errors
            RpcError::RpcVerifyError => write!(f, "RPC verify error"),
            RpcError::RpcVerifyRejected => write!(f, "RPC verify rejected"),
            RpcError::RpcVerifyAlreadyInChain => write!(f, "RPC verify already in chain"),
            RpcError::RpcInWarmup => write!(f, "RPC in warmup"),
        }
    }
}

impl std::error::Error for RpcError {}

impl RpcError {
    /// Convert to JSON-RPC error code
    pub fn code(&self) -> i32 {
        match self {
            // Standard JSON-RPC 2.0 errors
            RpcError::ParseError => -32700,
            RpcError::InvalidRequest => -32600,
            RpcError::MethodNotFound => -32601,
            RpcError::InvalidParams => -32602,
            RpcError::InternalError => -32603,

            // General Bitcoin Core errors
            RpcError::Misc(_) => -1,
            RpcError::ForbiddenBySafeMode => -2,
            RpcError::TypeError(_) => -3,
            RpcError::InvalidAddressOrKey => -5,
            RpcError::OutOfMemory => -7,
            RpcError::InvalidParameter(_) => -8,
            RpcError::DatabaseError(_) => -20,
            RpcError::DeserializationError(_) => -22,
            RpcError::VerifyError(_) => -25,
            RpcError::VerifyRejected(_) => -26,
            RpcError::VerifyAlreadyInChain => -27,
            RpcError::InWarmup => -28,
            RpcError::MethodDeprecated => -32,

            // P2P client errors
            RpcError::ClientNotConnected => -9,
            RpcError::ClientInInitialDownload => -10,
            RpcError::ClientNodeAlreadyAdded => -23,
            RpcError::ClientNodeNotAdded => -24,
            RpcError::ClientNodeNotConnected => -29,
            RpcError::ClientInvalidIpOrSubnet => -30,
            RpcError::ClientP2PDisabled => -31,

            // Chain errors
            RpcError::RpcVerifyError => -25,
            RpcError::RpcVerifyRejected => -26,
            RpcError::RpcVerifyAlreadyInChain => -27,
            RpcError::RpcInWarmup => -28,
        }
    }

    /// Convert to JSON-RPC ErrorObject
    pub fn to_error_object(&self) -> ErrorObjectOwned {
        ErrorObjectOwned::owned(self.code(), self.to_string(), None::<()>)
    }
}

impl From<RpcError> for ErrorObjectOwned {
    fn from(err: RpcError) -> Self {
        err.to_error_object()
    }
}

impl From<anyhow::Error> for RpcError {
    fn from(_err: anyhow::Error) -> Self {
        RpcError::InternalError
    }
}

/// RPC result type
pub type RpcResult<T> = Result<T, RpcError>;
