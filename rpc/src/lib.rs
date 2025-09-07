// pub mod auth;
pub mod error;
// pub mod methods;  // Complex methods module with signature issues
// pub mod server;  // Old hyper-based server, not compatible with hyper 1.0
pub mod rpc_implementation;
pub mod simple_server;

pub use error::{RpcError, RpcResult};
// pub use server::{RpcConfig, RpcServer};
pub use rpc_implementation::RpcImplementation;
pub use simple_server::SimpleRpcServer;
