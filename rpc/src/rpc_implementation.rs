use anyhow::{bail, Context, Result};
use bitcoin::{BlockHash, Transaction, Txid};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use bitcoin_core_lib::chain::ChainManager;
use mempool::Mempool;
use network::NetworkManager;
use storage::OptimizedStorage;
use wallet::Wallet;

/// Enhanced RPC implementation with real data connections
pub struct RpcImplementation {
    chain: Arc<RwLock<ChainManager>>,
    mempool: Arc<RwLock<Mempool>>,
    network: Arc<NetworkManager>,
    storage: Arc<OptimizedStorage>,
    wallet: Option<Arc<RwLock<Wallet>>>,
    start_time: std::time::Instant,
}

impl RpcImplementation {
    pub fn new(
        chain: Arc<RwLock<ChainManager>>,
        mempool: Arc<RwLock<Mempool>>,
        network: Arc<NetworkManager>,
        storage: Arc<OptimizedStorage>,
    ) -> Self {
        Self {
            chain,
            mempool,
            network,
            storage,
            wallet: None,
            start_time: std::time::Instant::now(),
        }
    }

    pub fn set_wallet(&mut self, wallet: Arc<RwLock<Wallet>>) {
        self.wallet = Some(wallet);
    }

    // ========== Blockchain RPCs ==========

    pub async fn get_blockchain_info(&self) -> Result<Value> {
        let chain = self.chain.read().await;
        let (network, height, best_hash, difficulty) = chain.get_blockchain_info();

        // Get actual chain work
        let chain_work = chain.get_best_chain_work().to_hex_string();

        // Get median time past
        let median_time = chain.get_median_time_past(height);

        // Check if in initial block download
        let ibd = chain.is_initial_block_download();

        // Get storage stats for size on disk
        let size_on_disk = self.storage.get_size().await.unwrap_or(0);

        Ok(json!({
            "chain": network,
            "blocks": height,
            "headers": height,
            "bestblockhash": best_hash.to_string(),
            "difficulty": difficulty,
            "time": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "mediantime": median_time,
            "verificationprogress": if ibd { 0.5 } else { 1.0 },
            "initialblockdownload": ibd,
            "chainwork": chain_work,
            "size_on_disk": size_on_disk,
            "pruned": false,
            "warnings": ""
        }))
    }

    pub async fn get_block_count(&self) -> Result<Value> {
        let chain = self.chain.read().await;
        Ok(json!(chain.get_best_height()))
    }

    pub async fn get_best_block_hash(&self) -> Result<Value> {
        let chain = self.chain.read().await;
        Ok(json!(chain.get_best_block_hash().to_string()))
    }

    pub async fn get_block(&self, hash: BlockHash, verbosity: u64) -> Result<Value> {
        let chain = self.chain.read().await;

        // Get block from storage
        let block = chain
            .get_block(&hash)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Block not found"))?;

        match verbosity {
            0 => {
                // Return raw block hex
                use bitcoin::consensus::Encodable;
                let mut bytes = Vec::new();
                block.consensus_encode(&mut bytes)?;
                Ok(json!(hex::encode(bytes)))
            }
            1 => {
                // Return block with tx hashes
                let height = chain.get_block_height(&hash)?;
                let best_height = chain.get_best_height();
                let confirmations = if height <= best_height {
                    best_height - height + 1
                } else {
                    0
                };

                // Get next block hash if exists
                let next_hash = if height < best_height {
                    chain.get_block_hash_at_height(height + 1)
                } else {
                    None
                };

                Ok(json!({
                    "hash": block.block_hash().to_string(),
                    "confirmations": confirmations,
                    "height": height,
                    "version": block.header.version.to_consensus(),
                    "versionHex": format!("{:08x}", block.header.version.to_consensus()),
                    "merkleroot": block.header.merkle_root.to_string(),
                    "time": block.header.time,
                    "mediantime": chain.get_median_time_past(height),
                    "nonce": block.header.nonce,
                    "bits": format!("{:08x}", block.header.bits.to_consensus()),
                    "difficulty": chain.get_current_difficulty(),
                    "chainwork": format!("{:064x}", block.header.work()),
                    "nTx": block.txdata.len(),
                    "previousblockhash": block.header.prev_blockhash.to_string(),
                    "nextblockhash": next_hash.map(|h| h.to_string()),
                    "tx": block.txdata.iter()
                        .map(|tx| tx.compute_txid().to_string())
                        .collect::<Vec<_>>()
                }))
            }
            _ => {
                // Return block with full tx details
                bail!("Verbosity level {} not implemented", verbosity);
            }
        }
    }

    pub async fn get_block_hash(&self, height: u32) -> Result<Value> {
        let chain = self.chain.read().await;

        let hash = chain
            .get_block_hash_at_height(height)
            .ok_or_else(|| anyhow::anyhow!("Block height out of range"))?;

        Ok(json!(hash.to_string()))
    }

    pub async fn get_difficulty(&self) -> Result<Value> {
        let chain = self.chain.read().await;
        Ok(json!(chain.get_current_difficulty()))
    }

    // ========== Mempool RPCs ==========

    pub async fn get_mempool_info(&self) -> Result<Value> {
        let mempool = self.mempool.read().await;
        let (count, total_size, fee_rate) = mempool.get_mempool_info();

        Ok(json!({
            "loaded": true,
            "size": count,
            "bytes": total_size,
            "usage": total_size * 2,  // Approximate memory usage
            "total_fee": fee_rate,
            "maxmempool": 300_000_000, // 300MB default
            "mempoolminfee": 0.00001,
            "minrelaytxfee": 0.00001,
            "incrementalrelayfee": 0.00001,
            "unbroadcastcount": 0,
            "fullrbf": true
        }))
    }

    pub async fn get_raw_mempool(&self, verbose: bool) -> Result<Value> {
        let mempool = self.mempool.read().await;

        if verbose {
            let mut entries = json!({});

            // Get verbose information for each transaction
            for txid in mempool.get_transaction_ids() {
                if let Some(verbose_entry) = mempool.get_verbose_entry(&txid) {
                    entries[txid.to_string()] = verbose_entry;
                }
            }

            Ok(entries)
        } else {
            let txids: Vec<String> = mempool
                .get_transaction_ids()
                .into_iter()
                .map(|txid| txid.to_string())
                .collect();
            Ok(json!(txids))
        }
    }

    // ========== Network RPCs ==========

    pub async fn get_network_info(&self) -> Result<Value> {
        let peer_count = self.network.peer_count().await;

        Ok(json!({
            "version": 250000,
            "subversion": "/rust-bitcoin:0.1.0/",
            "protocolversion": 70016,
            "localservices": "000000000000040d",
            "localservicesnames": ["NETWORK", "WITNESS", "NETWORK_LIMITED"],
            "localrelay": true,
            "timeoffset": 0,
            "networkactive": true,
            "connections": peer_count,
            "connections_in": 0,
            "connections_out": peer_count,
            "networks": [{
                "name": "ipv4",
                "limited": false,
                "reachable": true,
                "proxy": "",
                "proxy_randomize_credentials": false
            }],
            "relayfee": 0.00001,
            "incrementalfee": 0.00001,
            "localaddresses": [],
            "warnings": ""
        }))
    }

    pub async fn get_peer_info(&self) -> Result<Value> {
        // Get peer information from network manager
        let peer_info = self.network.get_peer_info();

        // If get_peer_info returns empty or we need more details,
        // we can also get connected peers
        let result = if peer_info.is_empty() {
            // Fallback to getting connected peer addresses
            let peers = self.network.get_connected_peers().await;
            peers
                .into_iter()
                .enumerate()
                .map(|(id, addr)| {
                    json!({
                            "id": id,
                            "addr": addr.to_string(),
                            "addrbind": addr.to_string(),
                            "network": if addr.is_ipv4() { "ipv4" } else { "ipv6" },
                            "services": "000000000000040d",
                            "servicesnames": ["NETWORK", "WITNESS", "NETWORK_LIMITED"],
                            "relaytxes": true,
                            "lastsend": 0,
                            "lastrecv": 0,
                        "last_transaction": 0,
                        "last_block": 0,
                        "bytessent": 0,
                        "bytesrecv": 0,
                        "conntime": 0,
                        "timeoffset": 0,
                        "pingtime": 0.001,
                        "minping": 0.001,
                        "version": 70016,
                        "subver": "/Satoshi:25.0.0/",
                        "inbound": false,
                        "bip152_hb_to": false,
                        "bip152_hb_from": false,
                        "startingheight": 0,
                        "presynced_headers": -1,
                        "synced_headers": -1,
                        "synced_blocks": -1,
                        "inflight": [],
                        "addr_relay_enabled": true,
                        "addr_processed": 0,
                        "addr_rate_limited": 0,
                        "permissions": [],
                        "minfeefilter": 0.00001,
                        "bytessent_per_msg": {},
                        "bytesrecv_per_msg": {}
                    })
                })
                .collect()
        } else {
            // Use the detailed peer info from network manager
            peer_info
        };

        Ok(json!(result))
    }

    pub async fn get_connection_count(&self) -> Result<Value> {
        Ok(json!(self.network.peer_count().await))
    }

    // ========== Transaction RPCs ==========

    pub async fn get_raw_transaction(&self, txid: Txid, verbose: bool) -> Result<Value> {
        let chain = self.chain.read().await;

        // Try mempool first
        let mempool = self.mempool.read().await;
        if let Some(tx) = mempool.get_transaction(&txid) {
            if verbose {
                let size = bitcoin::consensus::encode::serialize(&tx).len();
                Ok(json!({
                    "txid": txid.to_string(),
                    "hash": tx.compute_wtxid().to_string(),
                    "version": tx.version.0,
                    "size": size,
                    "vsize": tx.weight().to_vbytes_ceil() as usize,
                    "weight": tx.weight().to_wu(),
                    "locktime": tx.lock_time.to_consensus_u32(),
                    "vin": tx.input.iter().map(|input| {
                        json!({
                            "txid": input.previous_output.txid.to_string(),
                            "vout": input.previous_output.vout,
                            "scriptSig": {
                                "asm": "",
                                "hex": hex::encode(input.script_sig.to_bytes())
                            },
                            "sequence": input.sequence.0,
                            "txinwitness": input.witness.iter()
                                .map(hex::encode)
                                .collect::<Vec<_>>()
                        })
                    }).collect::<Vec<_>>(),
                    "vout": tx.output.iter().enumerate().map(|(n, output)| {
                        json!({
                            "value": output.value.to_btc(),
                            "n": n,
                            "scriptPubKey": {
                                "asm": "",
                                "hex": hex::encode(output.script_pubkey.to_bytes()),
                                "type": "unknown"
                            }
                        })
                    }).collect::<Vec<_>>(),
                    "hex": hex::encode(bitcoin::consensus::serialize(&tx))
                }))
            } else {
                Ok(json!(hex::encode(bitcoin::consensus::serialize(&tx))))
            }
        } else {
            // Try blockchain
            let result = chain
                .find_transaction(&txid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Transaction not found"))?;

            if verbose {
                Ok(json!({
                    "txid": txid.to_string(),
                    "hash": result.0.compute_wtxid().to_string(),
                    "version": result.0.version.0,
                    "locktime": result.0.lock_time.to_consensus_u32(),
                    "blockhash": result.1.map(|h| h.to_string()),
                    "hex": hex::encode(bitcoin::consensus::serialize(&result.0))
                }))
            } else {
                Ok(json!(hex::encode(bitcoin::consensus::serialize(&result.0))))
            }
        }
    }

    pub async fn send_raw_transaction(&self, hex: String) -> Result<Value> {
        let bytes = hex::decode(&hex).context("Invalid hex encoding")?;

        let tx: Transaction =
            bitcoin::consensus::deserialize(&bytes).context("Invalid transaction format")?;

        let txid = tx.compute_txid();

        // Add to mempool
        let mut mempool = self.mempool.write().await;
        mempool.add_transaction(tx.clone()).await?;

        // Broadcast to network
        self.network.broadcast_transaction(&tx).await?;

        Ok(json!(txid.to_string()))
    }

    // ========== Mining RPCs ==========

    pub async fn get_mining_info(&self) -> Result<Value> {
        let chain = self.chain.read().await;
        let difficulty = chain.get_current_difficulty();
        let height = chain.get_best_height();

        Ok(json!({
            "blocks": height,
            "currentblockweight": 0,
            "currentblocktx": 0,
            "difficulty": difficulty,
            "networkhashps": self.estimate_network_hashrate(difficulty),
            "pooledtx": self.mempool.read().await.size(),
            "chain": "main",
            "warnings": ""
        }))
    }

    pub async fn generate_to_address(
        &self,
        nblocks: u32,
        address: String,
        _maxtries: Option<u32>,
    ) -> Result<Value> {
        use bitcoin::Address;

        // Chain parameters are handled by consensus module
        use miner::{BlockTemplateBuilder, BlockTemplateConfig, ProofOfWorkMiner};
        use std::str::FromStr;

        // Check if in regtest mode
        {
            let chain = self.chain.read().await;
            let (network, _, _, _) = chain.get_blockchain_info();
            if network != "regtest" {
                bail!("generatetoaddress is only available in regtest mode");
            }
        }

        // Parse address for regtest network
        let addr = Address::from_str(&address)
            .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?
            .require_network(bitcoin::Network::Regtest)
            .map_err(|_| anyhow::anyhow!("Address not valid for regtest network"))?;

        // Get coinbase script from address
        let coinbase_script = addr.script_pubkey();

        // Get chain parameters for regtest
        // For regtest, use minimal difficulty
        let max_target = bitcoin::Target::MAX;
        let target = max_target;

        // Create block template builder
        let template_builder =
            BlockTemplateBuilder::new(bitcoin::Network::Regtest, BlockTemplateConfig::default());

        // Create miner
        let miner = ProofOfWorkMiner::new(1); // Single thread for regtest

        let mut block_hashes = Vec::new();

        for i in 0..nblocks {
            info!("Generating block {}/{}", i + 1, nblocks);

            // Get current chain state
            let (best_hash, height) = {
                let chain = self.chain.read().await;
                (chain.get_best_block_hash(), chain.get_best_height() + 1)
            };

            // Get mempool transactions
            let mempool_txs = self
                .mempool
                .read()
                .await
                .get_mining_transactions(4_000_000)
                .await
                .unwrap_or_default();
            let transactions: Vec<bitcoin::Transaction> =
                mempool_txs.into_iter().map(|entry| entry.tx).collect();

            // Build block template
            let template = template_builder
                .build_template(best_hash, height, transactions, target, &coinbase_script)
                .await
                .context("Failed to build block template")?;

            // Create block from template
            let mut block = bitcoin::Block {
                header: bitcoin::block::Header {
                    version: bitcoin::block::Version::from_consensus(template.version),
                    prev_blockhash: template.previous_block_hash,
                    merkle_root: template.merkle_root,
                    time: template.time,
                    bits: template.bits,
                    nonce: 0,
                },
                txdata: template.transactions,
            };

            // Mine the block (very easy difficulty for regtest)
            let (mined_header, _stats) = miner
                .mine_block_header(
                    block.header,
                    target,
                    Some(std::time::Duration::from_secs(60)),
                )
                .context("Mining failed")?;

            block.header = mined_header;

            // Submit block to chain
            let chain = self.chain.write().await;
            chain
                .process_block(block.clone())
                .await
                .context("Failed to add block")?;

            let hash = block.block_hash();
            info!("Generated block {} at height {}", hash, height);
            block_hashes.push(hash.to_string());
        }

        Ok(json!(block_hashes))
    }

    // ========== Control RPCs ==========

    pub async fn stop(&self) -> Result<Value> {
        info!("Shutdown requested via RPC");
        Ok(json!("Bitcoin node stopping"))
    }

    pub async fn uptime(&self) -> Result<Value> {
        Ok(json!(self.start_time.elapsed().as_secs()))
    }

    // ========== Helper Methods ==========

    fn estimate_network_hashrate(&self, difficulty: f64) -> f64 {
        // Network hashrate estimation based on difficulty
        // hashrate = difficulty * 2^32 / 600 (10 minutes in seconds)
        difficulty * 4_294_967_296.0 / 600.0
    }
}
