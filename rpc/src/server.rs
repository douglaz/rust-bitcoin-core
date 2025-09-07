use anyhow::{Context, Result};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::rpc_implementation::RpcImplementation;

/// JSON-RPC request
#[derive(Debug, serde::Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<Value>,
    id: Option<Value>,
}

/// JSON-RPC response
#[derive(Debug, serde::Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    result: Option<Value>,
    error: Option<JsonRpcError>,
    id: Option<Value>,
}

/// JSON-RPC error
#[derive(Debug, serde::Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    data: Option<Value>,
}

/// RPC Server
pub struct RpcServer {
    implementation: Arc<RpcImplementation>,
}

impl RpcServer {
    /// Create new RPC server
    pub fn new(implementation: Arc<RpcImplementation>) -> Self {
        Self { implementation }
    }
    
    /// Start the RPC server
    pub async fn start(self, addr: &str) -> Result<()> {
        let socket_addr: SocketAddr = addr.parse()
            .context("Invalid RPC server address")?;
        
        let implementation = self.implementation;
        
        // Create service
        let make_svc = make_service_fn(move |_conn| {
            let implementation = implementation.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    handle_request(req, implementation.clone())
                }))
            }
        });
        
        // Create server
        let server = Server::bind(&socket_addr).serve(make_svc);
        
        info!("RPC server listening on {}", socket_addr);
        
        // Run server
        if let Err(e) = server.await {
            error!("RPC server error: {}", e);
        }
        
        Ok(())
    }
}

/// Handle HTTP request
async fn handle_request(
    req: Request<Body>,
    implementation: Arc<RpcImplementation>,
) -> Result<Response<Body>, Infallible> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::POST, "/") => {
            handle_rpc_request(req, implementation).await
        }
        (&Method::GET, "/health") => {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("OK"))
                .unwrap()
        }
        _ => {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap()
        }
    };
    
    Ok(response)
}

/// Handle JSON-RPC request
async fn handle_rpc_request(
    req: Request<Body>,
    implementation: Arc<RpcImplementation>,
) -> Response<Body> {
    // Parse request body
    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return error_response(StatusCode::BAD_REQUEST, "Invalid request body");
        }
    };
    
    // Parse JSON-RPC request
    let rpc_request: JsonRpcRequest = match serde_json::from_slice(&body_bytes) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to parse JSON-RPC request: {}", e);
            return error_response(StatusCode::BAD_REQUEST, "Invalid JSON-RPC request");
        }
    };
    
    debug!("RPC request: method={}, params={:?}", rpc_request.method, rpc_request.params);
    
    // Execute RPC method
    let result = execute_rpc_method(
        &rpc_request.method,
        rpc_request.params,
        implementation,
    ).await;
    
    // Build response
    let response = match result {
        Ok(value) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(value),
            error: None,
            id: rpc_request.id,
        },
        Err(e) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code: -32603,
                message: e.to_string(),
                data: None,
            }),
            id: rpc_request.id,
        },
    };
    
    // Serialize response
    let response_json = match serde_json::to_string(&response) {
        Ok(json) => json,
        Err(e) => {
            error!("Failed to serialize response: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Body::from(response_json))
        .unwrap()
}

/// Execute RPC method
async fn execute_rpc_method(
    method: &str,
    params: Option<Value>,
    implementation: Arc<RpcImplementation>,
) -> Result<Value> {
    match method {
        // Blockchain RPCs
        "getblockchaininfo" => implementation.get_blockchain_info().await,
        "getblockcount" => implementation.get_block_count().await,
        "getbestblockhash" => implementation.get_best_block_hash().await,
        "getblock" => {
            let params = params.ok_or_else(|| anyhow::anyhow!("Missing parameters"))?;
            let hash = params[0].as_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid block hash"))?
                .parse()?;
            let verbosity = params.get(1)
                .and_then(|v| v.as_u64())
                .unwrap_or(1);
            implementation.get_block(hash, verbosity).await
        }
        "getblockhash" => {
            let params = params.ok_or_else(|| anyhow::anyhow!("Missing parameters"))?;
            let height = params[0].as_u64()
                .ok_or_else(|| anyhow::anyhow!("Invalid height"))? as u32;
            implementation.get_block_hash(height).await
        }
        "getdifficulty" => implementation.get_difficulty().await,
        
        // Network RPCs
        "getconnectioncount" => implementation.get_connection_count().await,
        "getpeerinfo" => implementation.get_peer_info().await,
        "getnetworkinfo" => implementation.get_network_info().await,
        
        // Mempool RPCs
        "getmempoolinfo" => implementation.get_mempool_info().await,
        "getrawmempool" => {
            let verbose = params
                .and_then(|p| p[0].as_bool())
                .unwrap_or(false);
            implementation.get_raw_mempool(verbose).await
        }
        
        // Transaction RPCs
        "getrawtransaction" => {
            let params = params.ok_or_else(|| anyhow::anyhow!("Missing parameters"))?;
            let txid = params[0].as_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid txid"))?
                .parse()?;
            let verbose = params.get(1)
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            implementation.get_raw_transaction(txid, verbose).await
        }
        "sendrawtransaction" => {
            let params = params.ok_or_else(|| anyhow::anyhow!("Missing parameters"))?;
            let hex = params[0].as_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid transaction hex"))?;
            implementation.send_raw_transaction(hex).await
        }
        
        // Mining RPCs
        "getmininginfo" => implementation.get_mining_info().await,
        "getblocktemplate" => implementation.get_block_template().await,
        
        // Control RPCs
        "stop" => {
            info!("Received stop command via RPC");
            Ok(json!("Bitcoin node stopping"))
        }
        "uptime" => implementation.get_uptime().await,
        
        _ => {
            warn!("Unknown RPC method: {}", method);
            Err(anyhow::anyhow!("Method not found"))
        }
    }
}

/// Create error response
fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let error = json!({
        "jsonrpc": "2.0",
        "error": {
            "code": -32603,
            "message": message,
        },
        "id": null,
    });
    
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(error.to_string()))
        .unwrap()
}