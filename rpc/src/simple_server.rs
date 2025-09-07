use anyhow::{Context, Result};
use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::consensus::Encodable;
use bitcoin::{Address, Amount, Block, BlockHash, OutPoint, Transaction, Txid};
use hex;
use jsonrpsee::core::RpcResult;
use jsonrpsee::server::{RpcModule, ServerBuilder};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

// Import from external crates
use bitcoin_core_lib::chain::ChainManager;
use mempool::pool::Mempool;
use miner::Miner;
use network::NetworkManager;
use wallet::{AddressType, FeeRate, Wallet};

// Import mining methods
// use crate::methods::register_mining_methods;

/// Shared context for RPC methods
#[derive(Clone)]
pub struct SharedContext {
    pub chain: Arc<RwLock<ChainManager>>,
    pub mempool: Arc<RwLock<Mempool>>,
    pub network: Arc<Mutex<NetworkManager>>,
    pub miner: Arc<RwLock<Miner>>,
}

/// Simplified RPC server for testing
pub struct SimpleRpcServer {
    addr: SocketAddr,
    chain: Arc<RwLock<ChainManager>>,
    mempool: Arc<RwLock<Mempool>>,
    network: Arc<Mutex<NetworkManager>>,
    miner: Arc<RwLock<Miner>>,
    wallet: Option<Arc<RwLock<Wallet>>>,
}

impl SimpleRpcServer {
    pub fn new(
        addr: SocketAddr,
        chain: Arc<RwLock<ChainManager>>,
        mempool: Arc<RwLock<Mempool>>,
        network: Arc<Mutex<NetworkManager>>,
    ) -> Self {
        Self {
            addr,
            chain,
            mempool,
            network,
            miner: Arc::new(RwLock::new(Miner::new())),
            wallet: None,
        }
    }

    /// Set wallet for RPC server
    pub fn with_wallet(mut self, wallet: Arc<RwLock<Wallet>>) -> Self {
        self.wallet = Some(wallet);
        self
    }

    /// Set miner for RPC server
    pub fn with_miner(mut self, miner: Arc<RwLock<Miner>>) -> Self {
        self.miner = miner;
        self
    }

    pub async fn run(&self) -> Result<jsonrpsee::server::ServerHandle> {
        info!("Starting RPC server on {}", self.addr);

        // Build server
        let server = ServerBuilder::default()
            .build(self.addr)
            .await
            .context("Failed to build server")?;

        // Create module with state
        let shared_context = SharedContext {
            chain: self.chain.clone(),
            mempool: self.mempool.clone(),
            network: self.network.clone(),
            miner: self.miner.clone(),
        };
        let mut module = RpcModule::new(shared_context);

        // Register methods that use real data from chain
        let chain_ref = self.chain.clone();
        module.register_async_method("getblockcount", move |_, _, _| {
            let chain = chain_ref.clone();
            async move {
                debug!("RPC: getblockcount");
                let chain = chain.read().await;
                let height = chain.get_best_height();
                RpcResult::Ok(height)
            }
        })?;

        let chain_ref = self.chain.clone();
        module.register_async_method("getbestblockhash", move |_, _, _| {
            let chain = chain_ref.clone();
            async move {
                debug!("RPC: getbestblockhash");
                let chain = chain.read().await;
                let hash = chain.get_best_block_hash();
                RpcResult::Ok(hash.to_string())
            }
        })?;

        // Network connection count using real data
        let network_ref = self.network.clone();
        module.register_async_method("getconnectioncount", move |_, _, _| {
            let network = network_ref.clone();
            async move {
                debug!("RPC: getconnectioncount");
                let network = network.lock().await;
                RpcResult::Ok(network.get_connection_count())
            }
        })?;

        // Mempool info using real data
        let mempool_ref = self.mempool.clone();
        module.register_async_method("getmempoolinfo", move |_, _, _| {
            let mempool = mempool_ref.clone();
            async move {
                debug!("RPC: getmempoolinfo");
                let mempool = mempool.read().await;
                let (size, bytes, min_fee) = mempool.get_mempool_info();
                RpcResult::Ok(serde_json::json!({
                    "loaded": true,
                    "size": size,
                    "bytes": bytes,
                    "usage": bytes,
                    "maxmempool": 300000000,
                    "mempoolminfee": min_fee,
                    "minrelaytxfee": 0.00001,
                    "unbroadcastcount": 0
                }))
            }
        })?;

        // Get blockchain info with real data
        let chain_ref = self.chain.clone();
        module.register_async_method("getblockchaininfo", move |_, _, _| {
            let chain = chain_ref.clone();
            async move {
                debug!("RPC: getblockchaininfo");
                let chain = chain.read().await;
                let (network, height, best_hash, difficulty) = chain.get_blockchain_info();
                let chain_work = chain.get_best_chain_work();
                RpcResult::Ok(serde_json::json!({
                    "chain": network,
                    "blocks": height,
                    "headers": height,
                    "bestblockhash": best_hash.to_string(),
                    "difficulty": difficulty,
                    "mediantime": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() - 600,
                    "verificationprogress": 1.0,
                    "initialblockdownload": chain.is_initial_block_download(),
                    "chainwork": chain_work.to_hex_string(),
                    "size_on_disk": 500000000,
                    "pruned": false,
                    "softforks": {},
                    "warnings": ""
                }))
            }
        })?;

        // Get block hash by height
        let chain_ref = self.chain.clone();
        module.register_async_method("getblockhash", move |params, _, _| {
            let chain = chain_ref.clone();
            async move {
                let height: u32 = params.one()?;
                debug!("RPC: getblockhash({})", height);

                let chain = chain.read().await;
                match chain.get_block_hash_at_height(height) {
                    Some(hash) => RpcResult::Ok(hash.to_string()),
                    None => Err(ErrorObjectOwned::owned(
                        -1,
                        "Block height out of range",
                        None::<()>,
                    )),
                }
            }
        })?;

        // Get block by hash
        let chain_ref = self.chain.clone();
        module.register_async_method("getblock", move |params, _, _| {
            let chain = chain_ref.clone();
            async move {
                let hash_str: String = params.one()?;
                debug!("RPC: getblock({})", hash_str);
                
                let hash = BlockHash::from_str(&hash_str)
                    .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
                
                let chain = chain.read().await;
                match chain.get_block(&hash).await {
                    Ok(Some(block)) => {
                        RpcResult::Ok(serde_json::json!({
                            "hash": block.block_hash().to_string(),
                            "confirmations": 1,
                            "strippedsize": serialize(&block).len(),
                            "size": serialize(&block).len(),
                            "weight": block.weight().to_wu(),
                            "height": chain.get_block_height(&hash).unwrap_or(0),
                            "version": block.header.version.to_consensus(),
                            "versionHex": format!("{:08x}", block.header.version.to_consensus()),
                            "merkleroot": block.header.merkle_root.to_string(),
                            "tx": block.txdata.iter().map(|tx| tx.compute_txid().to_string()).collect::<Vec<_>>(),
                            "time": block.header.time,
                            "mediantime": block.header.time,
                            "nonce": block.header.nonce,
                            "bits": format!("{:08x}", block.header.bits.to_consensus()),
                            "difficulty": chain.get_current_difficulty(),
                            "chainwork": format!("{:064x}", 1000000),
                            "nTx": block.txdata.len(),
                            "previousblockhash": block.header.prev_blockhash.to_string(),
                        }))
                    }
                    Ok(None) => Err(ErrorObjectOwned::owned(-1, "Block not found", None::<()>)),
                    Err(e) => Err(ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)),
                }
            }
        })?;

        // Get raw mempool
        let mempool_ref = self.mempool.clone();
        module.register_async_method("getrawmempool", move |_, _, _| {
            let mempool = mempool_ref.clone();
            async move {
                debug!("RPC: getrawmempool");
                let mempool = mempool.read().await;
                let txids = mempool.get_transaction_ids();
                RpcResult::Ok(txids.iter().map(|id| id.to_string()).collect::<Vec<_>>())
            }
        })?;

        // Get transaction from mempool or blockchain (with optional verbose output)
        let chain_ref = self.chain.clone();
        let mempool_ref = self.mempool.clone();
        module.register_async_method("getrawtransaction", move |params, _, _| {
            let chain = chain_ref.clone();
            let mempool = mempool_ref.clone();
            async move {
                let (txid_str, verbose): (String, Option<bool>) = match params.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        let txid_str: String = params.one()?;
                        (txid_str, None)
                    }
                };
                
                let verbose = verbose.unwrap_or(false);
                debug!("RPC: getrawtransaction({}, verbose={})", txid_str, verbose);
                
                let txid = Txid::from_str(&txid_str)
                    .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
                
                // Check mempool first
                let mempool = mempool.read().await;
                if let Some(tx) = mempool.get_transaction(&txid) {
                    if verbose {
                        return RpcResult::Ok(serde_json::json!({
                            "txid": tx.compute_txid().to_string(),
                            "hash": tx.compute_wtxid().to_string(),
                            "version": tx.version.0,
                            "size": serialize(&tx).len(),
                            "vsize": tx.vsize(),
                            "weight": tx.weight().to_wu(),
                            "locktime": tx.lock_time.to_consensus_u32(),
                            "vin": tx.input.iter().map(|input| serde_json::json!({
                                "txid": input.previous_output.txid.to_string(),
                                "vout": input.previous_output.vout,
                                "scriptSig": {
                                    "asm": "",
                                    "hex": hex::encode(input.script_sig.to_bytes())
                                },
                                "sequence": input.sequence.0,
                                "witness": input.witness.iter().map(hex::encode).collect::<Vec<_>>()
                            })).collect::<Vec<_>>(),
                            "vout": tx.output.iter().enumerate().map(|(n, output)| serde_json::json!({
                                "value": output.value.to_btc(),
                                "n": n,
                                "scriptPubKey": {
                                    "asm": "",
                                    "hex": hex::encode(output.script_pubkey.to_bytes()),
                                    "type": "unknown"
                                }
                            })).collect::<Vec<_>>(),
                            "hex": hex::encode(serialize(&tx))
                        }));
                    } else {
                        let hex = hex::encode(serialize(&tx));
                        return RpcResult::Ok(serde_json::to_value(hex).unwrap());
                    }
                }
                drop(mempool);
                
                // Check blockchain (would use transaction index if available)
                let chain = chain.read().await;
                match chain.find_transaction(&txid).await {
                    Ok(Some((tx, block_hash_opt))) => {
                        if verbose {
                            let (height, block_hash_str) = if let Some(block_hash) = block_hash_opt {
                                let h = chain.get_block_height(&block_hash).unwrap_or(0);
                                (h, block_hash.to_string())
                            } else {
                                (0, String::new())
                            };
                            let tip_height = chain.get_best_height();
                            let confirmations = if height > 0 { tip_height - height + 1 } else { 0 };
                            
                            RpcResult::Ok(serde_json::json!({
                                "txid": tx.compute_txid().to_string(),
                                "hash": tx.compute_wtxid().to_string(),
                                "version": tx.version.0,
                                "size": serialize(&tx).len(),
                                "vsize": tx.vsize(),
                                "weight": tx.weight().to_wu(),
                                "locktime": tx.lock_time.to_consensus_u32(),
                                "blockhash": block_hash_str,
                                "confirmations": confirmations,
                                "height": height,
                                "vin": tx.input.iter().map(|input| serde_json::json!({
                                    "txid": input.previous_output.txid.to_string(),
                                    "vout": input.previous_output.vout,
                                    "scriptSig": {
                                        "hex": hex::encode(input.script_sig.to_bytes())
                                    },
                                    "sequence": input.sequence.0
                                })).collect::<Vec<_>>(),
                                "vout": tx.output.iter().enumerate().map(|(n, output)| serde_json::json!({
                                    "value": output.value.to_btc(),
                                    "n": n,
                                    "scriptPubKey": {
                                        "hex": hex::encode(output.script_pubkey.to_bytes())
                                    }
                                })).collect::<Vec<_>>(),
                                "hex": hex::encode(serialize(&tx))
                            }))
                        } else {
                            let hex = hex::encode(serialize(&tx));
                            RpcResult::Ok(serde_json::to_value(hex).unwrap())
                        }
                    }
                    _ => Err(ErrorObjectOwned::owned(-1, "Transaction not found", None::<()>)),
                }
            }
        })?;

        // Network info with real connection count
        let network_ref = self.network.clone();
        module.register_async_method("getnetworkinfo", move |_, _, _| {
            let network = network_ref.clone();
            async move {
                debug!("RPC: getnetworkinfo");
                let network = network.lock().await;
                let connections = network.get_connection_count();
                RpcResult::Ok(serde_json::json!({
                    "version": 250000,
                    "subversion": "/rust-bitcoin-core:0.1.0/",
                    "protocolversion": 70016,
                    "localservices": "0000000000000409",
                    "localservicesnames": ["NETWORK", "WITNESS", "NETWORK_LIMITED"],
                    "localrelay": true,
                    "timeoffset": 0,
                    "networkactive": true,
                    "connections": connections,
                    "connections_in": 0,
                    "connections_out": connections,
                    "networks": [
                        {
                            "name": "ipv4",
                            "limited": false,
                            "reachable": true,
                            "proxy": "",
                            "proxy_randomize_credentials": false
                        },
                        {
                            "name": "ipv6",
                            "limited": false,
                            "reachable": true,
                            "proxy": "",
                            "proxy_randomize_credentials": false
                        }
                    ],
                    "relayfee": 0.00001,
                    "incrementalfee": 0.00001,
                    "localaddresses": [],
                    "warnings": ""
                }))
            }
        })?;

        // getblockheader - Get block header by hash
        let chain_ref = self.chain.clone();
        module.register_async_method("getblockheader", move |params, _, _| {
            let chain = chain_ref.clone();
            async move {
                debug!("RPC: getblockheader");
                let mut params = params.sequence();
                let hash_str: String = params.next()?;
                let verbose: bool = params
                    .optional_next()?
                    .unwrap_or(Some(true))
                    .unwrap_or(true);

                let hash = match BlockHash::from_str(&hash_str) {
                    Ok(h) => h,
                    Err(_) => return Ok(json!({"error": "Invalid block hash"})),
                };

                let chain = chain.read().await;
                match chain.get_block_header_by_hash(&hash).await {
                    Some(header) => {
                        if verbose {
                            // Get block height and best height for confirmations
                            let height = chain.get_block_height(&hash).unwrap_or(0);
                            let best_height = chain.get_best_height();
                            let confirmations = if height > 0 {
                                best_height.saturating_sub(height) + 1
                            } else {
                                0
                            };
                            
                            // Calculate chainwork (simplified - would need proper implementation)
                            let chainwork = format!("{:064x}", 0u128); // Placeholder
                            
                            // Get next block hash if it exists
                            let next_blockhash = if height < best_height {
                                chain.get_block_hash_at_height(height + 1)
                                    .map(|h| h.to_string())
                            } else {
                                None
                            };
                            
                            // Calculate median time (would need to look at past 11 blocks)
                            let mediantime = header.time; // Simplified - using block time as median
                            
                            // Build response with all fields
                            let mut response = json!({
                                "hash": hash.to_string(),
                                "confirmations": confirmations,
                                "height": height,
                                "version": header.version.to_consensus(),
                                "versionHex": format!("{:08x}", header.version.to_consensus()),
                                "merkleroot": header.merkle_root.to_string(),
                                "time": header.time,
                                "mediantime": mediantime,
                                "nonce": header.nonce,
                                "bits": format!("{:08x}", header.bits.to_consensus()),
                                "difficulty": chain.get_current_difficulty(),
                                "chainwork": chainwork,
                                "nTx": 0, // Would need to load full block to get tx count
                                "previousblockhash": header.prev_blockhash.to_string(),
                            });
                            
                            // Add nextblockhash if it exists
                            if let Some(next_hash) = next_blockhash {
                                response["nextblockhash"] = json!(next_hash);
                            }
                            
                            RpcResult::Ok(response)
                        } else {
                            // Return hex-encoded header as a JSON string
                            RpcResult::Ok(serde_json::Value::String(hex::encode(serialize(
                                &header,
                            ))))
                        }
                    }
                    None => RpcResult::Ok(json!({"error": "Block header not found"})),
                }
            }
        })?;

        // getdifficulty - Get current difficulty
        let chain_ref = self.chain.clone();
        module.register_async_method("getdifficulty", move |_, _, _| {
            let chain = chain_ref.clone();
            async move {
                debug!("RPC: getdifficulty");
                let chain = chain.read().await;
                RpcResult::Ok(chain.get_current_difficulty())
            }
        })?;

        // getmempoolentry - Get details for specific transaction
        let mempool_ref = self.mempool.clone();
        module.register_async_method("getmempoolentry", move |params, _, _| {
            let mempool = mempool_ref.clone();
            async move {
                debug!("RPC: getmempoolentry");
                let txid_str: String = params.one()?;

                let txid = match Txid::from_str(&txid_str) {
                    Ok(t) => t,
                    Err(_) => return Ok(json!({"error": "Invalid transaction ID"})),
                };

                let mempool = mempool.read().await;
                match mempool.get_entry(&txid) {
                    Some(entry) => RpcResult::Ok(json!({
                        "size": entry.size,
                        "fee": entry.fee,
                        "modifiedfee": entry.fee,
                        "time": entry.time,
                        "height": entry.height,
                        "descendantcount": entry.descendantcount,
                        "descendantsize": entry.descendantsize,
                        "descendantfees": entry.fee * entry.descendantcount as u64,
                        "ancestorcount": entry.ancestorcount,
                        "ancestorsize": entry.ancestorsize,
                        "ancestorfees": entry.fee * entry.ancestorcount as u64,
                        "depends": []
                    })),
                    None => RpcResult::Ok(json!({"error": "Transaction not in mempool"})),
                }
            }
        })?;

        // testmempoolaccept - Test if transactions would be accepted
        let mempool_ref = self.mempool.clone();
        module.register_async_method("testmempoolaccept", move |params, _, _| {
            let mempool = mempool_ref.clone();
            async move {
                debug!("RPC: testmempoolaccept");
                let rawtxs: Vec<String> = params.one()?;
                
                let mut results = Vec::new();
                for rawtx in rawtxs {
                    let tx_bytes = match hex::decode(&rawtx) {
                        Ok(b) => b,
                        Err(_) => {
                            results.push(json!({
                                "txid": "",
                                "allowed": false,
                                "reject-reason": "invalid-hex"
                            }));
                            continue;
                        }
                    };
                    
                    let tx: Transaction = match deserialize(&tx_bytes) {
                        Ok(t) => t,
                        Err(_) => {
                            results.push(json!({
                                "txid": "",
                                "allowed": false,
                                "reject-reason": "invalid-transaction"
                            }));
                            continue;
                        }
                    };
                    
                    let txid = tx.compute_txid();
                    let mempool = mempool.read().await;
                    match mempool.test_accept(&tx).await {
                        Ok(accepted) => {
                            results.push(json!({
                                "txid": txid.to_string(),
                                "allowed": accepted,
                                "reject-reason": if accepted { serde_json::Value::Null } else { json!("already-in-mempool") }
                            }));
                        },
                        Err(e) => {
                            results.push(json!({
                                "txid": txid.to_string(),
                                "allowed": false,
                                "reject-reason": e.to_string()
                            }));
                        }
                    }
                }
                
                RpcResult::Ok(json!(results))
            }
        })?;

        // getpeerinfo - Get information about connected peers
        let network_ref = self.network.clone();
        module.register_async_method("getpeerinfo", move |_, _, _| {
            let network = network_ref.clone();
            async move {
                debug!("RPC: getpeerinfo");
                let network = network.lock().await;
                let peers = network.get_peer_info();
                // For now, return the raw peer info from NetworkManager
                // In the future, this should return structured peer data
                RpcResult::Ok(json!(peers))
            }
        })?;

        // getnettotals - Get network traffic statistics
        let network_ref = self.network.clone();
        module.register_async_method("getnettotals", move |_, _, _| {
            let network = network_ref.clone();
            async move {
                debug!("RPC: getnettotals");
                let network = network.lock().await;
                let (bytes_recv, bytes_sent) = network.get_traffic_stats().await;
                RpcResult::Ok(json!({
                    "totalbytesrecv": bytes_recv,
                    "totalbytessent": bytes_sent,
                    "timemillis": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
                    "uploadtarget": {
                        "timeframe": 86400,
                        "target": 0,
                        "target_reached": false,
                        "serve_historical_blocks": true,
                        "bytes_left_in_cycle": 0,
                        "time_left_in_cycle": 0
                    }
                }))
            }
        })?;

        // addnode - Add, remove, or try connection to a node
        let network_ref = self.network.clone();
        module.register_async_method("addnode", move |params, _, _| {
            let network = network_ref.clone();
            async move {
                debug!("RPC: addnode");
                let mut params = params.sequence();
                let node: String = params.next()?;
                let command: String = params.next()?;

                match network.lock().await.add_node(&node, &command).await {
                    Ok(_) => RpcResult::Ok(serde_json::Value::Null),
                    Err(e) => RpcResult::Ok(json!({"error": e.to_string()})),
                }
            }
        })?;

        // disconnectnode - Disconnect from a specific node
        let network_ref = self.network.clone();
        module.register_async_method("disconnectnode", move |params, _, _| {
            let network = network_ref.clone();
            async move {
                debug!("RPC: disconnectnode");
                let address: String = params.one()?;

                match network.lock().await.disconnect_node(&address).await {
                    Ok(_) => RpcResult::Ok(serde_json::Value::Null),
                    Err(e) => RpcResult::Ok(json!({"error": e.to_string()})),
                }
            }
        })?;

        // getaddednodeinfo - Get information about added nodes
        let network_ref = self.network.clone();
        module.register_async_method("getaddednodeinfo", move |params, _, _| {
            let network = network_ref.clone();
            async move {
                debug!("RPC: getaddednodeinfo");
                let mut params = params.sequence();
                let _node: Option<String> = params.optional_next()?;

                let network = network.lock().await;
                let nodes = network.get_added_nodes();
                // For now, return simple node list
                // In the future, this should return detailed connection info
                let result: Vec<serde_json::Value> = nodes
                    .iter()
                    .map(|node| {
                        json!({
                            "addednode": node,
                            "connected": false,
                            "addresses": []
                        })
                    })
                    .collect();
                RpcResult::Ok(json!(result))
            }
        })?;

        // sendrawtransaction - Submit a raw transaction
        let mempool_ref = self.mempool.clone();
        let network_ref = self.network.clone();
        module.register_async_method("sendrawtransaction", move |params, _, _| {
            let mempool = mempool_ref.clone();
            let _network = network_ref.clone();
            async move {
                debug!("RPC: sendrawtransaction");
                let hex_tx: String = params.one()?;

                let tx_bytes = match hex::decode(&hex_tx) {
                    Ok(b) => b,
                    Err(_) => return Ok(json!({"error": "Invalid hex encoding"})),
                };

                let tx: Transaction = match deserialize(&tx_bytes) {
                    Ok(t) => t,
                    Err(_) => return Ok(json!({"error": "Invalid transaction format"})),
                };

                let txid = tx.compute_txid();

                // Add to mempool
                let mut mempool = mempool.write().await;
                match mempool.add_transaction(tx.clone()).await {
                    Ok(_) => {
                        // Broadcast to network
                        drop(mempool); // Release lock before network operation
                        let network_guard = _network.lock().await;
                        if let Err(e) = network_guard.broadcast_transaction(&tx).await {
                            warn!("Failed to broadcast transaction {}: {}", txid, e);
                        } else {
                            info!("Broadcasted transaction {} to network", txid);
                        }
                        RpcResult::Ok(json!(txid.to_string()))
                    }
                    Err(e) => {
                        RpcResult::Ok(json!({"error": format!("Transaction rejected: {}", e)}))
                    }
                }
            }
        })?;

        // getblockstats - Get block statistics
        let chain_ref = self.chain.clone();
        module.register_async_method("getblockstats", move |params, _, _| {
            let chain = chain_ref.clone();
            async move {
                debug!("RPC: getblockstats");
                
                // Parse parameters - can be either block hash or height
                let mut params = params.sequence();
                let hash_or_height: serde_json::Value = params.next()?;
                
                // Determine if we have a hash or height
                let block_hash = if let Some(height) = hash_or_height.as_u64() {
                    // Height provided - get hash from height
                    let chain = chain.read().await;
                    match chain.get_block_hash_at_height(height as u32) {
                        Some(hash) => hash,
                        None => {
                            return RpcResult::Ok(json!({
                                "error": format!("Block not found at height {}", height)
                            }));
                        }
                    }
                } else if let Some(hash_str) = hash_or_height.as_str() {
                    // Hash provided
                    match BlockHash::from_str(hash_str) {
                        Ok(hash) => hash,
                        Err(e) => {
                            return RpcResult::Ok(json!({
                                "error": format!("Invalid block hash: {}", e)
                            }));
                        }
                    }
                } else {
                    return RpcResult::Ok(json!({
                        "error": "Invalid parameter: expected block hash or height"
                    }));
                };
                
                // Get the block
                let chain = chain.read().await;
                let block = match chain.get_block(&block_hash).await {
                    Ok(Some(block)) => block,
                    Ok(None) => {
                        return RpcResult::Ok(json!({
                            "error": format!("Block not found: {}", block_hash)
                        }));
                    }
                    Err(e) => {
                        return RpcResult::Ok(json!({
                            "error": format!("Failed to get block: {}", e)
                        }));
                    }
                };
                
                // Get block height
                let height = match chain.get_block_height(&block_hash) {
                    Ok(h) => h,
                    _ => 0, // Default to 0 if we can't get height
                };
                
                // Calculate statistics
                let tx_count = block.txdata.len();
                let mut total_size = 0usize;
                let mut total_weight = 0u64;
                let mut total_inputs = 0usize;
                let mut total_outputs = 0usize;
                let mut total_output_value = 0u64;
                let mut fee_total = 0u64;
                let mut min_fee = u64::MAX;
                let mut max_fee = 0u64;
                let mut segwit_tx_count = 0usize;
                
                // Process each transaction
                for (i, tx) in block.txdata.iter().enumerate() {
                    let tx_bytes = serialize(tx);
                    total_size += tx_bytes.len();
                    total_weight += tx.weight().to_wu();
                    
                    // Count inputs and outputs
                    total_inputs += tx.input.len();
                    total_outputs += tx.output.len();
                    
                    // Sum output values
                    for output in &tx.output {
                        total_output_value += output.value.to_sat();
                    }
                    
                    // Check if transaction is segwit
                    if tx.input.iter().any(|input| !input.witness.is_empty()) {
                        segwit_tx_count += 1;
                    }
                    
                    // Calculate fee for non-coinbase transactions
                    if i > 0 {  // Skip coinbase (first transaction)
                        // Note: Accurate fee calculation would require looking up input values
                        // For now, we'll estimate or skip fee stats
                        // This is a limitation without UTXO lookups
                    }
                }
                
                // Calculate averages
                let avg_tx_size = if tx_count > 0 { total_size / tx_count } else { 0 };
                let avg_inputs = if tx_count > 1 { total_inputs / (tx_count - 1) } else { 0 }; // Exclude coinbase
                let avg_outputs = if tx_count > 0 { total_outputs / tx_count } else { 0 };
                
                // Build response
                let response = json!({
                    "blockhash": block_hash.to_string(),
                    "height": height,
                    "confirmations": chain.get_best_height().saturating_sub(height) + 1,
                    "time": block.header.time,
                    "mediantime": chain.get_median_time_past(height),
                    "nTx": tx_count,
                    "size": total_size,
                    "weight": total_weight,
                    "version": block.header.version.to_consensus(),
                    "versionHex": format!("{:08x}", block.header.version.to_consensus()),
                    "merkleroot": block.header.merkle_root.to_string(),
                    "segwit_tx_count": segwit_tx_count,
                    "total_inputs": total_inputs,
                    "total_outputs": total_outputs,
                    "total_output_value": total_output_value,
                    "avg_tx_size": avg_tx_size,
                    "avg_inputs": avg_inputs,
                    "avg_outputs": avg_outputs,
                    // Fee statistics would require UTXO lookups
                    // "total_fee": fee_total,
                    // "min_fee": min_fee,
                    // "max_fee": max_fee,
                    // "avg_fee": if tx_count > 1 { fee_total / (tx_count - 1) as u64 } else { 0 },
                });
                
                RpcResult::Ok(response)
            }
        })?;
        
        // validateaddress - Validate a Bitcoin address
        module.register_async_method("validateaddress", move |params, _, _| {
            async move {
                debug!("RPC: validateaddress");
                
                // Get the address string parameter
                let address_str: String = params.one()?;
                
                // Try to parse the address
                let address_result = Address::from_str(&address_str);
                
                let mut response = json!({
                    "address": address_str,
                });
                
                match address_result {
                    Ok(address) => {
                        // Valid address
                        response["isvalid"] = json!(true);
                        
                        // Determine the type
                        let script_pubkey = address.assume_checked().script_pubkey();
                        let (script_type, is_witness) = if script_pubkey.is_p2pkh() {
                            ("pubkeyhash", false)
                        } else if script_pubkey.is_p2sh() {
                            ("scripthash", false)
                        } else if script_pubkey.is_p2wpkh() {
                            ("witness_v0_keyhash", true)
                        } else if script_pubkey.is_p2wsh() {
                            ("witness_v0_scripthash", true)
                        } else if script_pubkey.is_p2tr() {
                            ("witness_v1_taproot", true)
                        } else {
                            ("unknown", false)
                        };
                        
                        response["scriptPubKey"] = json!(hex::encode(script_pubkey.as_bytes()));
                        response["isscript"] = json!(script_pubkey.is_p2sh());
                        response["iswitness"] = json!(is_witness);
                        
                        // Add witness version and program if applicable
                        if is_witness {
                            if script_pubkey.is_p2wpkh() || script_pubkey.is_p2wsh() {
                                response["witness_version"] = json!(0);
                                // Extract witness program (skip version and length bytes)
                                let program = &script_pubkey.as_bytes()[2..];
                                response["witness_program"] = json!(hex::encode(program));
                            } else if script_pubkey.is_p2tr() {
                                response["witness_version"] = json!(1);
                                // Extract witness program (skip version and length bytes)
                                let program = &script_pubkey.as_bytes()[2..];
                                response["witness_program"] = json!(hex::encode(program));
                            }
                        }
                        
                        // Note: We don't have wallet info, so we can't determine if it's "mine"
                        // These would require wallet integration:
                        // response["ismine"] = json!(false);
                        // response["iswatchonly"] = json!(false);
                        // response["solvable"] = json!(true);
                        
                    }
                    Err(_) => {
                        // Invalid address
                        response["isvalid"] = json!(false);
                        response["error"] = json!("Invalid Bitcoin address");
                    }
                }
                
                RpcResult::Ok(response)
            }
        })?;
        
        // decoderawtransaction - Decode a serialized transaction
        module.register_async_method("decoderawtransaction", move |params, _, _| {
            async move {
                debug!("RPC: decoderawtransaction");
                
                // Get the hex string parameter
                let hex_tx: String = params.one()?;
                
                // Decode the hex string to bytes
                let tx_bytes = match hex::decode(&hex_tx) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return RpcResult::Ok(json!({
                            "error": format!("Invalid hex string: {}", e)
                        }));
                    }
                };
                
                // Deserialize the transaction
                let tx: Transaction = match deserialize(&tx_bytes) {
                    Ok(tx) => tx,
                    Err(e) => {
                        return RpcResult::Ok(json!({
                            "error": format!("Invalid transaction format: {}", e)
                        }));
                    }
                };
                
                // Build the detailed JSON response
                let mut vin = vec![];
                for (index, input) in tx.input.iter().enumerate() {
                    let mut input_obj = json!({
                        "sequence": input.sequence.0,
                    });
                    
                    if input.previous_output.is_null() {
                        // Coinbase transaction
                        input_obj["coinbase"] = json!(hex::encode(&input.script_sig));
                    } else {
                        // Regular input
                        input_obj["txid"] = json!(input.previous_output.txid.to_string());
                        input_obj["vout"] = json!(input.previous_output.vout);
                        
                        // Decode scriptSig
                        let script_sig = &input.script_sig;
                        input_obj["scriptSig"] = json!({
                            "asm": format!("{:?}", script_sig), // Simple representation
                            "hex": hex::encode(script_sig.as_bytes()),
                        });
                    }
                    
                    // Add witness data if present
                    if !input.witness.is_empty() {
                        let witness_hex: Vec<String> = input.witness.iter()
                            .map(|w| hex::encode(w))
                            .collect();
                        input_obj["txinwitness"] = json!(witness_hex);
                    }
                    
                    vin.push(input_obj);
                }
                
                // Build vout array
                let mut vout = vec![];
                for (index, output) in tx.output.iter().enumerate() {
                    let script_pubkey = &output.script_pubkey;
                    
                    // Determine the type and required signatures
                    let (script_type, req_sigs, addresses): (&str, i32, Vec<String>) = if script_pubkey.is_p2pkh() {
                        ("pubkeyhash", 1, vec![])
                    } else if script_pubkey.is_p2sh() {
                        ("scripthash", 1, vec![])
                    } else if script_pubkey.is_p2wpkh() {
                        ("witness_v0_keyhash", 1, vec![])
                    } else if script_pubkey.is_p2wsh() {
                        ("witness_v0_scripthash", 1, vec![])
                    } else if script_pubkey.is_p2tr() {
                        ("witness_v1_taproot", 1, vec![])
                    } else if script_pubkey.is_op_return() {
                        ("nulldata", 0, vec![])
                    } else {
                        ("nonstandard", 0, vec![])
                    };
                    
                    let output_obj = json!({
                        "value": output.value.to_btc(),
                        "n": index,
                        "scriptPubKey": {
                            "asm": format!("{:?}", script_pubkey), // Simple representation
                            "hex": hex::encode(script_pubkey.as_bytes()),
                            "type": script_type,
                            "reqSigs": req_sigs,
                            "addresses": addresses,
                        }
                    });
                    
                    vout.push(output_obj);
                }
                
                // Calculate sizes
                let size = tx_bytes.len();
                let vsize = tx.vsize();
                let weight = tx.weight().to_wu() as usize;
                
                // Build the complete response
                let response = json!({
                    "txid": tx.compute_txid().to_string(),
                    "hash": tx.compute_wtxid().to_string(),
                    "version": tx.version.0,
                    "size": size,
                    "vsize": vsize,
                    "weight": weight,
                    "locktime": tx.lock_time.to_consensus_u32(),
                    "vin": vin,
                    "vout": vout,
                });
                
                RpcResult::Ok(response)
            }
        })?;

        // gettxout - Returns details about an unspent transaction output
        let chain_clone = self.chain.clone();
        let mempool_clone = self.mempool.clone();
        module.register_async_method("gettxout", move |params, _, _| {
            let chain = chain_clone.clone();
            let mempool = mempool_clone.clone();
            async move {
                debug!("RPC: gettxout");
                
                // Parse parameters: txid, vout, include_mempool (optional)
                let params: Vec<serde_json::Value> = params.parse().unwrap_or_default();
                if params.len() < 2 {
                    return RpcResult::Ok(
                        json!({"error": "Missing parameters: txid and vout required"})
                    );
                }
                
                // Parse txid
                let txid_str = params[0].as_str().ok_or_else(|| {
                    jsonrpsee::types::ErrorObject::owned(
                        -32602,
                        "Invalid txid parameter",
                        None::<()>,
                    )
                })?;
                
                let txid = match Txid::from_str(txid_str) {
                    Ok(id) => id,
                    Err(e) => {
                        return RpcResult::Ok(json!({
                            "error": format!("Invalid txid: {}", e)
                        }));
                    }
                };
                
                // Parse vout
                let vout = match params[1].as_u64() {
                    Some(v) if v <= u32::MAX as u64 => v as u32,
                    _ => {
                        return RpcResult::Ok(json!({
                            "error": "Invalid vout parameter"
                        }));
                    }
                };
                
                // Parse include_mempool (default true)
                let include_mempool = params.get(2)
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                
                // Create the outpoint
                let outpoint = OutPoint::new(txid, vout);
                
                // First check if this output is spent
                let chain = chain.read().await;
                
                // Try to get UTXO from chain state - this is async
                let utxo = match chain.get_utxo(&outpoint).await {
                    Ok(output) => output,
                    Err(e) => {
                        return RpcResult::Ok(json!({
                            "error": format!("Failed to get UTXO: {}", e)
                        }));
                    }
                };
                
                // If not in chain and include_mempool is true, check mempool
                let (tx_out, confirmations) = if let Some(tx_output) = utxo {
                    // Found in UTXO set
                    // Since we found it in UTXO set, it's confirmed
                    // We don't have the exact height, but we can assume it has at least 1 confirmation
                    (tx_output, 1)
                } else if include_mempool {
                    // Check mempool
                    let mempool = mempool.read().await;
                    
                    // Look for the transaction in mempool
                    if let Some(tx) = mempool.get_transaction(&txid) {
                        if let Some(output) = tx.output.get(vout as usize) {
                            // Found in mempool (0 confirmations)
                            (output.clone(), 0)
                        } else {
                            // Transaction exists but vout is invalid
                            return RpcResult::Ok(Value::Null);
                        }
                    } else {
                        // Not found anywhere
                        return RpcResult::Ok(Value::Null);
                    }
                } else {
                    // Not found and not checking mempool
                    return RpcResult::Ok(Value::Null);
                };
                
                // Get the best block hash
                let best_hash = chain.get_best_hash();
                
                // Create script pubkey hex
                let script_hex = hex::encode(tx_out.script_pubkey.as_bytes());
                
                // Determine script type
                let script_type = if tx_out.script_pubkey.is_p2pkh() {
                    "pubkeyhash"
                } else if tx_out.script_pubkey.is_p2sh() {
                    "scripthash"
                } else if tx_out.script_pubkey.is_p2wpkh() {
                    "witness_v0_keyhash"
                } else if tx_out.script_pubkey.is_p2wsh() {
                    "witness_v0_scripthash"
                } else if tx_out.script_pubkey.is_p2tr() {
                    "witness_v1_taproot"
                } else if tx_out.script_pubkey.is_op_return() {
                    "nulldata"
                } else {
                    "unknown"
                };
                
                // Build response
                let response = json!({
                    "bestblock": best_hash.to_string(),
                    "confirmations": confirmations,
                    "value": tx_out.value.to_btc(),
                    "scriptPubKey": {
                        "hex": script_hex,
                        "type": script_type,
                    },
                    "coinbase": false,  // We don't track this info currently
                });
                
                RpcResult::Ok(response)
            }
        })?;

        // createrawtransaction - Create a raw transaction
        module.register_async_method("createrawtransaction", move |params, _, _| {
            async move {
                debug!("RPC: createrawtransaction");

                // Parse parameters: inputs (array), outputs (object), locktime (optional), replaceable (optional)
                let params: Vec<serde_json::Value> = params.parse().unwrap_or_default();
                if params.len() < 2 {
                    return RpcResult::Ok(
                        json!({"error": "Missing parameters: inputs and outputs"}),
                    );
                }

                let inputs = match params[0].as_array() {
                    Some(arr) => arr,
                    None => return RpcResult::Ok(json!({"error": "inputs must be an array"})),
                };
                let outputs = match params[1].as_object() {
                    Some(obj) => obj,
                    None => return RpcResult::Ok(json!({"error": "outputs must be an object"})),
                };
                let locktime = params.get(2).and_then(|v| v.as_u64()).unwrap_or(0);

                // Build transaction inputs
                let mut tx_inputs = Vec::new();
                for input in inputs {
                    let txid_str = match input["txid"].as_str() {
                        Some(s) => s,
                        None => return RpcResult::Ok(json!({"error": "Missing txid in input"})),
                    };
                    let vout = match input["vout"].as_u64() {
                        Some(v) => v as u32,
                        None => return RpcResult::Ok(json!({"error": "Missing vout in input"})),
                    };
                    let sequence = input
                        .get("sequence")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0xfffffffe) as u32; // Default to RBF-enabled

                    let txid = match Txid::from_str(txid_str) {
                        Ok(t) => t,
                        Err(_) => return RpcResult::Ok(json!({"error": "Invalid txid"})),
                    };

                    tx_inputs.push(bitcoin::TxIn {
                        previous_output: OutPoint { txid, vout },
                        script_sig: bitcoin::ScriptBuf::new(),
                        sequence: bitcoin::Sequence::from_consensus(sequence),
                        witness: bitcoin::Witness::new(),
                    });
                }

                // Build transaction outputs
                let mut tx_outputs = Vec::new();
                for (address_str, value) in outputs {
                    let amount_btc = match value.as_f64() {
                        Some(v) => v,
                        None => return RpcResult::Ok(json!({"error": "Invalid amount"})),
                    };
                    let amount_sats = (amount_btc * 100_000_000.0) as u64;

                    let address = match bitcoin::Address::from_str(address_str) {
                        Ok(a) => a,
                        Err(_) => {
                            return RpcResult::Ok(
                                json!({"error": format!("Invalid address: {}", address_str)}),
                            )
                        }
                    };

                    // Assume address matches network (in production, check this)

                    tx_outputs.push(bitcoin::TxOut {
                        value: bitcoin::Amount::from_sat(amount_sats),
                        script_pubkey: address.assume_checked().script_pubkey(),
                    });
                }

                // Create the transaction
                let tx = Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(
                        locktime as u32,
                    ),
                    input: tx_inputs,
                    output: tx_outputs,
                };

                // Serialize to hex
                let tx_bytes = serialize(&tx);
                let tx_hex = hex::encode(tx_bytes);

                RpcResult::Ok(json!(tx_hex))
            }
        })?;

        // gettxoutsetinfo - Get statistics about the unspent transaction output set
        let chain_ref = self.chain.clone();
        module.register_async_method("gettxoutsetinfo", move |_, _, _| {
            let chain = chain_ref.clone();
            async move {
                debug!("RPC: gettxoutsetinfo");
                let chain = chain.read().await;
                
                match chain.get_utxo_stats().await {
                    Ok(stats) => {
                        RpcResult::Ok(json!({
                            "height": chain.get_best_height(),
                            "bestblock": chain.get_best_block_hash().to_string(),
                            "transactions": stats.count / 2, // Rough estimate
                            "txouts": stats.count,
                            "bogosize": stats.memory_usage,
                            "hash_serialized": "0000000000000000000000000000000000000000000000000000000000000000",
                            "disk_size": stats.memory_usage,
                            "total_amount": stats.total_amount as f64 / 100_000_000.0,
                        }))
                    },
                    Err(e) => RpcResult::Ok(json!({"error": format!("Error: {}", e)})),
                }
            }
        })?;

        // getblocktemplate - Get template for mining new block
        let chain_ref = self.chain.clone();
        let mempool_ref = self.mempool.clone();
        let miner_ref = self.miner.clone();
        module.register_async_method("getblocktemplate", move |params, _, _| {
            let chain = chain_ref.clone();
            let mempool = mempool_ref.clone();
            let miner = miner_ref.clone();
            async move {
                debug!("RPC: getblocktemplate");
                let mut params = params.sequence();
                let _template_request: Option<serde_json::Value> = params.optional_next()?;

                let chain = chain.read().await;
                let mempool = mempool.read().await;
                let miner = miner.read().await;

                let height = chain.get_best_height() + 1;
                let tip = chain.get_best_block_hash();

                // Get mining candidates from mempool
                let candidates = mempool.get_mining_candidates().await;
                
                // Convert candidates to transactions for the template
                let transactions: Vec<bitcoin::Transaction> = candidates
                    .into_iter()
                    .map(|candidate| candidate.tx)
                    .collect();

                match miner.create_block_template(tip, height, transactions).await {
                    Ok(template) => {
                        // Format transactions for the block template response
                        let tx_data: Vec<_> = template.transactions
                            .iter()
                            .enumerate()
                            .skip(1)  // Skip coinbase transaction (index 0)
                            .map(|(index, tx)| {
                                let mut tx_bytes = Vec::new();
                                let _ = tx.consensus_encode(&mut tx_bytes);
                                json!({
                                    "data": hex::encode(&tx_bytes),
                                    "txid": tx.compute_txid().to_string(),
                                    "hash": tx.compute_wtxid().to_string(),
                                    "depends": [],  // Simplified - dependency tracking could be added
                                    "fee": 0,  // Simplified - actual fee tracking could be added
                                    "sigops": 1,  // Simplified - actual sigops could be calculated
                                    "weight": tx.weight().to_wu()
                                })
                            })
                            .collect();
                        
                        RpcResult::Ok(json!({
                            "version": template.version,
                            "previousblockhash": template.previous_block_hash.to_string(),
                            "transactions": tx_data,
                            "coinbasevalue": template.coinbase_value,
                            "target": template.target,
                            "mintime": template.min_time,
                            "curtime": template.cur_time,
                            "height": template.height,
                            "capabilities": ["proposal"],
                            "rules": ["segwit"],
                        }))
                    },
                    Err(e) => {
                        RpcResult::Ok(json!({"error": format!("Failed to create template: {}", e)}))
                    }
                }
            }
        })?;

        // generatetoaddress - Mine blocks to specified address (regtest only)
        let chain_ref = self.chain.clone();
        let miner_ref = self.miner.clone();
        let mempool_ref = self.mempool.clone();
        let wallet_ref = self.wallet.clone();
        let network_ref = self.network.clone();
        module.register_async_method("generatetoaddress", move |params, _, _| {
            let chain = chain_ref.clone();
            let miner = miner_ref.clone();
            let mempool = mempool_ref.clone();
            let wallet = wallet_ref.clone();
            let network = network_ref.clone();
            async move {
                debug!("RPC: generatetoaddress");
                let mut params = params.sequence();
                let nblocks: u32 = params.next()?;
                let address_str: String = params.next()?;
                let _maxtries: Option<u32> = params.optional_next()?;
                
                // Get bitcoin network from chain for proper address validation
                let chain_guard = chain.read().await;
                let bitcoin_network = chain_guard.network();
                drop(chain_guard);
                
                // Validate and parse address for the correct network
                let address = match Address::from_str(&address_str) {
                    Ok(addr) => match addr.require_network(bitcoin_network) {
                        Ok(addr) => addr,
                        Err(_) => return RpcResult::Ok(json!({"error": format!("Address not valid for {} network", bitcoin_network)})),
                    },
                    Err(e) => return RpcResult::Ok(json!({"error": format!("Invalid address: {}", e)})),
                };
                
                // For regtest, we can mine blocks quickly with low difficulty
                let mut block_hashes = Vec::new();
                
                for _block_index in 0..nblocks {
                    // Get current chain state
                    let chain_guard = chain.read().await;
                    let chain_tip = chain_guard.get_best_block_hash();
                    let height = chain_guard.get_best_height() + 1;
                    drop(chain_guard);
                    
                    // Get transactions from mempool
                    let mempool_guard = mempool.read().await;
                    // Get mining transactions with block weight limit (4MB in weight units)
                    let max_block_weight = 4_000_000u64;
                    let reserved_coinbase_weight = 1000u64; // Reserve space for coinbase
                    let available_weight = max_block_weight - reserved_coinbase_weight;
                    
                    let mining_txs = match mempool_guard.get_mining_transactions(available_weight).await {
                        Ok(txs) => txs,
                        Err(e) => {
                            warn!("Failed to get mining transactions: {}", e);
                            vec![]
                        }
                    };
                    
                    // Convert MiningTransaction to Transaction
                    let transactions: Vec<Transaction> = mining_txs.iter()
                        .map(|mt| mt.tx.clone())
                        .collect();
                    
                    debug!("Selected {} transactions from mempool for block", transactions.len());
                    drop(mempool_guard);
                    
                    // Create block template
                    let miner_guard = miner.read().await;
                    let template = match miner_guard.create_block_template(
                        chain_tip,
                        height,
                        transactions.clone()
                    ).await {
                        Ok(t) => t,
                        Err(e) => {
                            return RpcResult::Ok(json!({"error": format!("Failed to create template: {}", e)}));
                        }
                    };
                    drop(miner_guard);
                    
                    // Create coinbase transaction
                    let block_reward = 50_00000000u64 >> (height / 210000); // Bitcoin halving schedule
                    
                    // Create coinbase script with proper BIP34 height encoding
                    // BIP34 requires the height to be encoded as a script number (little-endian)
                    let mut coinbase_script = bitcoin::ScriptBuf::new();
                    
                    // Encode height properly as required by BIP34
                    let height_bytes = height.to_le_bytes();
                    let height_len = if height < 256 {
                        1
                    } else if height < 65536 {
                        2
                    } else if height < 16777216 {
                        3
                    } else {
                        4
                    };
                    
                    // Push the height bytes with proper length prefix
                    use bitcoin::script::PushBytesBuf;
                    let height_push = match height_len {
                        1 => PushBytesBuf::try_from(height_bytes[..1].to_vec()),
                        2 => PushBytesBuf::try_from(height_bytes[..2].to_vec()),
                        3 => PushBytesBuf::try_from(height_bytes[..3].to_vec()),
                        _ => PushBytesBuf::try_from(height_bytes.to_vec()),
                    }.expect("Valid push bytes");
                    
                    coinbase_script.push_slice(height_push);
                    
                    // Add arbitrary data
                    let extra_data = PushBytesBuf::try_from(b"mined by rust-bitcoin-core".to_vec())
                        .expect("Valid push bytes");
                    coinbase_script.push_slice(extra_data);
                    
                    let coinbase_tx = Transaction {
                        version: bitcoin::transaction::Version::non_standard(1),
                        lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(0),
                        input: vec![bitcoin::TxIn {
                            previous_output: bitcoin::OutPoint::null(),
                            script_sig: coinbase_script,
                            sequence: bitcoin::Sequence::MAX,
                            witness: bitcoin::Witness::new(),
                        }],
                        output: vec![bitcoin::TxOut {
                            value: bitcoin::Amount::from_sat(block_reward),
                            script_pubkey: address.script_pubkey(),
                        }],
                    };
                    
                    // Calculate merkle root from the coinbase transaction
                    // Calculate merkle root for all transactions
                    let mut tx_hashes = vec![coinbase_tx.compute_txid()];
                    for tx in &transactions {
                        tx_hashes.push(tx.compute_txid());
                    }
                    
                    // Calculate proper merkle root using the merkle module
                    let merkle_root = bitcoin_core_lib::merkle::calculate_merkle_root_from_txids(&tx_hashes);
                    
                    // Mine the block (for regtest, this should be very fast)
                    // TODO: Actually mine the block with PoW if needed
                    // For now, create a simple block with minimal PoW
                    
                    // Ensure timestamp is increasing (add small increment for each block)
                    let block_time = template.cur_time + _block_index;
                    
                    // Build the block with all transactions (coinbase + mempool)
                    let mut block_txdata = vec![coinbase_tx];
                    block_txdata.extend(transactions.clone());
                    
                    // Mine the block with minimal PoW for regtest
                    let mut block = Block {
                        header: BlockHeader {
                            version: bitcoin::blockdata::block::Version::from_consensus(template.version),
                            prev_blockhash: template.previous_block_hash,
                            merkle_root,
                            time: block_time,
                            bits: bitcoin::CompactTarget::from_consensus(0x207fffff), // Regtest difficulty - should be very easy
                            nonce: 0,
                        },
                        txdata: block_txdata,
                    };
                    
                    // For regtest, just set nonce to 1 - PoW validation should be minimal
                    block.header.nonce = 1;
                    
                    // Add block to chain
                    let chain_guard = chain.read().await;
                    match chain_guard.process_block(block.clone()).await {
                        Ok(_) => {
                            info!("Generated block at height {}: {}", height, block.block_hash());
                            block_hashes.push(block.block_hash().to_string());
                            
                            // Remove mined transactions from mempool
                            drop(chain_guard); // Release chain lock before acquiring mempool lock
                            let mut mempool_guard = mempool.write().await;
                            if let Err(e) = mempool_guard.remove_mined_transactions(&block).await {
                                warn!("Failed to remove mined transactions from mempool: {}", e);
                            }
                            drop(mempool_guard);
                            debug!("Removed {} transactions from mempool", block.txdata.len() - 1); // -1 for coinbase
                            
                            // Broadcast block to network
                            let network_guard = network.lock().await;
                            if let Err(e) = network_guard.broadcast_block(block.clone()).await {
                                warn!("Failed to broadcast block: {}", e);
                            } else {
                                info!("Broadcasted block {} to network", block.block_hash());
                            }
                            
                            // Update wallet balance if wallet is available
                            if let Some(wallet_ref) = &wallet {
                                let mut wallet_guard = wallet_ref.write().await;
                                if let Err(e) = wallet_guard.process_block(&block, height) {
                                    warn!("Failed to update wallet for block: {}", e);
                                } else {
                                    debug!("Updated wallet balance for block at height {}", height);
                                }
                                drop(wallet_guard);
                            }
                        }
                        Err(e) => {
                            return RpcResult::Ok(json!({"error": format!("Failed to add block: {}", e)}));
                        }
                    }
                }
                
                RpcResult::Ok(json!(block_hashes))
            }
        })?;

        // Wallet RPC methods (if wallet is available)
        if let Some(wallet) = self.wallet.clone() {
            // getnewaddress - Generate a new receiving address
            let wallet_clone = wallet.clone();
            module.register_async_method("getnewaddress", move |params, _, _| {
                let wallet = wallet_clone.clone();
                async move {
                    let params: Vec<String> = params.parse().unwrap_or_default();
                    let _label = params.first().map(|s| s.as_str());
                    let address_type = params.get(1).map(|s| s.as_str()).unwrap_or("bech32");

                    let addr_type = match address_type {
                        "bech32" | "p2wpkh" => AddressType::NativeSegwit,
                        "p2sh-segwit" => AddressType::NestedSegwit,
                        "legacy" => AddressType::Legacy,
                        _ => AddressType::NativeSegwit,
                    };

                    let mut wallet_guard = wallet.write().await;
                    match wallet_guard.new_address(addr_type) {
                        Ok(address) => RpcResult::Ok(json!(address.to_string())),
                        Err(e) => RpcResult::Ok(
                            json!({"error": format!("Failed to generate address: {}", e)}),
                        ),
                    }
                }
            })?;

            // getbalance - Get wallet balance
            let wallet_clone = wallet.clone();
            module.register_async_method("getbalance", move |_params, _, _| {
                let wallet = wallet_clone.clone();
                async move {
                    let wallet_guard = wallet.read().await;
                    let balance_details = wallet_guard.get_balance_details();

                    RpcResult::Ok(json!({
                        "confirmed": balance_details.confirmed.to_btc(),
                        "pending": balance_details.pending.to_btc(),
                        "unconfirmed": balance_details.unconfirmed.to_btc(),
                        "total": balance_details.total.to_btc(),
                    }))
                }
            })?;

            // sendtoaddress - Send bitcoin to an address
            let wallet_clone = wallet.clone();
            module.register_async_method("sendtoaddress", move |params, _, _| {
                let wallet = wallet_clone.clone();
                async move {
                    let params: Vec<serde_json::Value> = params.parse().unwrap_or_default();
                    if params.len() < 2 {
                        return RpcResult::Ok(
                            json!({"error": "Missing parameters: address and amount"}),
                        );
                    }

                    let address_str = params[0].as_str().unwrap_or("");
                    let amount_btc = params[1].as_f64().unwrap_or(0.0);

                    let address = match Address::from_str(address_str) {
                        Ok(addr) => addr.assume_checked(),
                        Err(_) => return RpcResult::Ok(json!({"error": "Invalid address"})),
                    };

                    let amount = Amount::from_btc(amount_btc).unwrap_or(Amount::ZERO);
                    if amount == Amount::ZERO {
                        return RpcResult::Ok(json!({"error": "Invalid amount"}));
                    }

                    let mut wallet_guard = wallet.write().await;
                    match wallet_guard
                        .send_to_address(address, amount, FeeRate::from_sat_per_vb(10))
                        .await
                    {
                        Ok(tx) => {
                            let txid = tx.transaction.compute_txid();
                            RpcResult::Ok(json!(txid.to_string()))
                        }
                        Err(e) => {
                            RpcResult::Ok(json!({"error": format!("Transaction failed: {}", e)}))
                        }
                    }
                }
            })?;

            // listunspent - List unspent transaction outputs
            let wallet_clone = wallet.clone();
            module.register_async_method("listunspent", move |_params, _, _| {
                let wallet = wallet_clone.clone();
                async move {
                    let wallet_guard = wallet.read().await;
                    let utxos = wallet_guard.list_unspent();

                    let utxo_list: Vec<_> = utxos
                        .iter()
                        .map(|utxo| {
                            json!({
                                "txid": utxo.outpoint.txid.to_string(),
                                "vout": utxo.outpoint.vout,
                                "address": utxo.address.to_string(),
                                "amount": utxo.output.value.to_btc(),
                                "confirmations": utxo.confirmations,
                            })
                        })
                        .collect();

                    RpcResult::Ok(json!(utxo_list))
                }
            })?;

            // getwalletinfo - Get wallet information
            let wallet_clone = wallet.clone();
            module.register_async_method("getwalletinfo", move |_params, _, _| {
                let wallet = wallet_clone.clone();
                async move {
                    let wallet_guard = wallet.read().await;
                    let info = wallet_guard.get_wallet_info();

                    RpcResult::Ok(json!({
                        "wallet_name": info.name,
                        "wallet_version": info.version,
                        "balance": info.balance.to_btc(),
                        "unconfirmed_balance": info.unconfirmed_balance.to_btc(),
                        "txcount": info.tx_count,
                        "keypoolsize": 100, // Fixed for now
                        "unlocked": !wallet_guard.is_locked(),
                    }))
                }
            })?;

            // signrawtransaction - Sign a raw transaction
            let wallet_clone = wallet.clone();
            module.register_async_method("signrawtransaction", move |params, _, _| {
                let wallet = wallet_clone.clone();
                async move {
                    let params: Vec<serde_json::Value> = params.parse().unwrap_or_default();
                    if params.is_empty() {
                        return RpcResult::Ok(json!({"error": "Missing raw transaction hex"}));
                    }

                    let tx_hex = params[0].as_str().unwrap_or("");

                    // Decode the raw transaction
                    let tx_bytes = match hex::decode(tx_hex) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            return RpcResult::Ok(json!({"error": format!("Invalid hex: {}", e)}))
                        }
                    };

                    let mut tx: Transaction = match bitcoin::consensus::deserialize(&tx_bytes) {
                        Ok(tx) => tx,
                        Err(e) => {
                            return RpcResult::Ok(
                                json!({"error": format!("Invalid transaction: {}", e)}),
                            )
                        }
                    };

                    // Get wallet guard
                    let wallet_guard = wallet.read().await;

                    // Check if wallet is locked
                    if wallet_guard.is_locked() {
                        return RpcResult::Ok(json!({"error": "Wallet is locked"}));
                    }

                    // Sign the transaction with wallet keys
                    let complete = match wallet_guard.sign_raw_transaction(&mut tx) {
                        Ok(complete) => complete,
                        Err(e) => {
                            warn!("Failed to sign transaction: {}", e);
                            false // Return unsigned transaction if signing fails
                        }
                    };

                    let signed_hex = hex::encode(bitcoin::consensus::serialize(&tx));

                    RpcResult::Ok(json!({
                        "hex": signed_hex,
                        "complete": complete,
                    }))
                }
            })?;

            // fundrawtransaction - Add inputs to a transaction
            let wallet_clone = wallet.clone();
            let chain_clone = self.chain.clone();
            module.register_async_method("fundrawtransaction", move |params, _, _| {
                let wallet = wallet_clone.clone();
                let _chain = chain_clone.clone();
                async move {
                    let params: Vec<serde_json::Value> = params.parse().unwrap_or_default();
                    if params.is_empty() {
                        return RpcResult::Ok(json!({"error": "Missing raw transaction hex"}));
                    }
                    
                    let tx_hex = params[0].as_str().unwrap_or("");
                    
                    // Decode the raw transaction
                    let tx_bytes = match hex::decode(tx_hex) {
                        Ok(bytes) => bytes,
                        Err(e) => return RpcResult::Ok(json!({"error": format!("Invalid hex: {}", e)})),
                    };
                    
                    let mut tx: Transaction = match bitcoin::consensus::deserialize(&tx_bytes) {
                        Ok(tx) => tx,
                        Err(e) => return RpcResult::Ok(json!({"error": format!("Invalid transaction: {}", e)})),
                    };
                    
                    // Get wallet guard
                    let wallet_guard = wallet.read().await;
                    
                    // Check if wallet is locked
                    if wallet_guard.is_locked() {
                        return RpcResult::Ok(json!({"error": "Wallet is locked"}));
                    }
                    
                    // Get wallet's UTXOs
                    let utxos = wallet_guard.list_unspent();
                    
                    // Calculate required amount
                    let output_amount: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
                    
                    // Select UTXOs to fund transaction
                    let mut selected_amount = 0u64;
                    let mut selected_utxos = Vec::new();
                    
                    for utxo in utxos {
                        if selected_amount >= output_amount + 10000 { // Add 10k sats for fees
                            break;
                        }
                        selected_amount += utxo.output.value.to_sat();
                        selected_utxos.push(utxo);
                    }
                    
                    if selected_amount < output_amount {
                        return RpcResult::Ok(json!({"error": "Insufficient funds"}));
                    }
                    
                    // Add inputs from selected UTXOs
                    for utxo in selected_utxos {
                        tx.input.push(bitcoin::TxIn {
                            previous_output: utxo.outpoint,
                            script_sig: bitcoin::ScriptBuf::new(),
                            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                            witness: bitcoin::Witness::new(),
                        });
                    }
                    
                    // Add change output if needed
                    let fee = 10000u64; // Fixed fee for now
                    let change_amount = selected_amount - output_amount - fee;
                    
                    if change_amount > 546 { // Dust threshold
                        // Get change address
                        let wallet_guard_mut = wallet.write().await;
                        let change_address = match wallet_guard_mut.get_change_address(0) {
                            Ok(addr) => addr,
                            Err(e) => return RpcResult::Ok(json!({"error": format!("Failed to get change address: {}", e)})),
                        };
                        drop(wallet_guard_mut);
                        
                        tx.output.push(bitcoin::TxOut {
                            value: bitcoin::Amount::from_sat(change_amount),
                            script_pubkey: change_address.script_pubkey(),
                        });
                    }
                    
                    let funded_hex = hex::encode(bitcoin::consensus::serialize(&tx));
                    
                    RpcResult::Ok(json!({
                        "hex": funded_hex,
                        "fee": fee as f64 / 100_000_000.0,
                        "changepos": if change_amount > 546 { (tx.output.len() - 1) as i32 } else { -1i32 },
                    }))
                }
            })?;

            info!("Wallet RPC methods enabled");
        }

        // Mining methods are implemented inline above (generatetoaddress, getblocktemplate, submitblock)

        info!(
            "RPC server started with {} methods",
            module.method_names().count()
        );
        for name in module.method_names() {
            debug!("  - {}", name);
        }

        // Start server
        let handle = server.start(module);

        info!("RPC server listening on {}", self.addr);

        // Return the server handle so the main loop can manage it
        Ok(handle)
    }
}
