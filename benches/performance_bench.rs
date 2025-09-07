use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use bitcoin::{Block, BlockHash, Transaction, TxOut, Amount, ScriptBuf};
use bitcoin_core_lib::utxo_manager::UtxoManager;
use bitcoin_core_lib::chain::ChainManager;
use mempool::Mempool;
use storage::{StorageManager, TransactionIndex, AddressIndex, AddressIndexConfig};
use std::sync::Arc;
use tokio::runtime::Runtime;

/// Benchmark UTXO operations
fn bench_utxo_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("utxo_operations");
    
    // Benchmark UTXO insertion
    group.bench_function("utxo_insert", |b| {
        let utxo_manager = UtxoManager::new();
        let test_tx = create_test_transaction(1);
        
        b.iter(|| {
            rt.block_on(async {
                let txid = test_tx.compute_txid();
                for (vout, output) in test_tx.output.iter().enumerate() {
                    utxo_manager.add_utxo(
                        black_box(txid),
                        black_box(vout as u32),
                        black_box(output.clone()),
                        black_box(100),
                    ).await;
                }
            });
        });
    });
    
    // Benchmark UTXO lookup
    group.bench_function("utxo_lookup", |b| {
        let utxo_manager = UtxoManager::new();
        let test_tx = create_test_transaction(100);
        let txid = test_tx.compute_txid();
        
        // Pre-populate UTXOs
        rt.block_on(async {
            for (vout, output) in test_tx.output.iter().enumerate() {
                utxo_manager.add_utxo(txid, vout as u32, output.clone(), 100).await;
            }
        });
        
        b.iter(|| {
            rt.block_on(async {
                for vout in 0..100 {
                    let _ = utxo_manager.get_utxo(
                        black_box(&txid),
                        black_box(vout),
                    ).await;
                }
            });
        });
    });
    
    // Benchmark UTXO removal
    group.bench_function("utxo_remove", |b| {
        b.iter_batched(
            || {
                let utxo_manager = UtxoManager::new();
                let test_tx = create_test_transaction(10);
                let txid = test_tx.compute_txid();
                
                // Pre-populate UTXOs
                rt.block_on(async {
                    for (vout, output) in test_tx.output.iter().enumerate() {
                        utxo_manager.add_utxo(txid, vout as u32, output.clone(), 100).await;
                    }
                });
                
                (utxo_manager, txid)
            },
            |(utxo_manager, txid)| {
                rt.block_on(async {
                    for vout in 0..10 {
                        utxo_manager.remove_utxo(
                            black_box(&txid),
                            black_box(vout),
                        ).await;
                    }
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

/// Benchmark block validation
fn bench_block_validation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("block_validation");
    
    for num_txs in [10, 100, 500].iter() {
        group.throughput(Throughput::Elements(*num_txs as u64));
        
        group.bench_with_input(
            BenchmarkId::from_parameter(num_txs),
            num_txs,
            |b, &num_txs| {
                let block = create_test_block(num_txs);
                
                b.iter(|| {
                    rt.block_on(async {
                        // Simulate block validation
                        validate_block_mock(black_box(&block)).await;
                    });
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark mempool operations
fn bench_mempool_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("mempool_operations");
    
    // Setup mempool
    let temp_dir = tempfile::TempDir::new().unwrap();
    let datadir = temp_dir.path().to_str().unwrap();
    
    group.bench_function("mempool_add_transaction", |b| {
        b.iter_batched(
            || {
                rt.block_on(async {
                    let storage = Arc::new(StorageManager::new(datadir).await.unwrap());
                    let utxo_manager = Arc::new(UtxoManager::new());
                    let chain = Arc::new(tokio::sync::RwLock::new(
                        ChainManager::with_utxo_manager(
                            storage.clone(),
                            "regtest".to_string(),
                            utxo_manager.clone(),
                        ).await.unwrap()
                    ));
                    let mempool = Mempool::new(chain, utxo_manager).await.unwrap();
                    (mempool, create_test_transaction(2))
                })
            },
            |(mut mempool, tx)| {
                rt.block_on(async {
                    let _ = mempool.add_transaction(black_box(tx)).await;
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
    
    group.bench_function("mempool_remove_transaction", |b| {
        b.iter_batched(
            || {
                rt.block_on(async {
                    let storage = Arc::new(StorageManager::new(datadir).await.unwrap());
                    let utxo_manager = Arc::new(UtxoManager::new());
                    let chain = Arc::new(tokio::sync::RwLock::new(
                        ChainManager::with_utxo_manager(
                            storage.clone(),
                            "regtest".to_string(),
                            utxo_manager.clone(),
                        ).await.unwrap()
                    ));
                    let mut mempool = Mempool::new(chain, utxo_manager).await.unwrap();
                    
                    // Add some transactions
                    let mut txids = Vec::new();
                    for i in 0..10 {
                        let tx = create_test_transaction(1);
                        let txid = tx.compute_txid();
                        txids.push(txid);
                        let _ = mempool.add_transaction(tx).await;
                    }
                    
                    (mempool, txids)
                })
            },
            |(mut mempool, txids)| {
                rt.block_on(async {
                    for txid in txids {
                        mempool.remove_transaction(&black_box(txid));
                    }
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

/// Benchmark transaction indexing
fn bench_transaction_indexing(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("transaction_indexing");
    
    let temp_dir = tempfile::TempDir::new().unwrap();
    let datadir = temp_dir.path().to_str().unwrap();
    
    group.bench_function("index_transaction", |b| {
        b.iter_batched(
            || {
                rt.block_on(async {
                    let storage = StorageManager::new(datadir).await.unwrap();
                    let tx_index = TransactionIndex::new(storage.get_db()).await.unwrap();
                    let test_tx = create_test_transaction(1);
                    (tx_index, test_tx)
                })
            },
            |(tx_index, test_tx)| {
                rt.block_on(async {
                    let txid = test_tx.compute_txid();
                    tx_index.index_transaction(
                        black_box(&txid),
                        black_box(&BlockHash::all_zeros()),
                        black_box(100),
                        black_box(0),
                        black_box(&test_tx),
                    ).await.unwrap();
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
    
    group.bench_function("lookup_transaction", |b| {
        let storage = rt.block_on(async {
            StorageManager::new(datadir).await.unwrap()
        });
        let tx_index = rt.block_on(async {
            TransactionIndex::new(storage.get_db()).await.unwrap()
        });
        
        // Pre-populate index
        let mut txids = Vec::new();
        rt.block_on(async {
            for i in 0..100 {
                let test_tx = create_test_transaction(1);
                let txid = test_tx.compute_txid();
                txids.push(txid);
                tx_index.index_transaction(
                    &txid,
                    &BlockHash::all_zeros(),
                    i,
                    0,
                    &test_tx,
                ).await.unwrap();
            }
        });
        
        b.iter(|| {
            rt.block_on(async {
                for txid in &txids {
                    let _ = tx_index.get_transaction_location(black_box(txid)).await;
                }
            });
        });
    });
    
    group.finish();
}

/// Benchmark address indexing
fn bench_address_indexing(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("address_indexing");
    
    let temp_dir = tempfile::TempDir::new().unwrap();
    let datadir = temp_dir.path().to_str().unwrap();
    
    group.bench_function("index_address", |b| {
        b.iter_batched(
            || {
                rt.block_on(async {
                    let storage = StorageManager::new(datadir).await.unwrap();
                    let config = AddressIndexConfig::default();
                    let addr_index = AddressIndex::new(
                        storage.get_db(),
                        bitcoin::Network::Regtest,
                        config,
                    ).await.unwrap();
                    (addr_index, format!("bcrt1qtest{}", rand::random::<u32>()))
                })
            },
            |(addr_index, address)| {
                rt.block_on(async {
                    let txid = bitcoin::Txid::all_zeros();
                    addr_index.index_transaction(
                        black_box(&address),
                        black_box(&txid),
                        black_box(100),
                        black_box(true),
                        black_box(Amount::from_sat(50_000_000)),
                    ).await.unwrap();
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
    
    group.bench_function("lookup_address", |b| {
        let storage = rt.block_on(async {
            StorageManager::new(datadir).await.unwrap()
        });
        let config = AddressIndexConfig::default();
        let addr_index = rt.block_on(async {
            AddressIndex::new(
                storage.get_db(),
                bitcoin::Network::Regtest,
                config,
            ).await.unwrap()
        });
        
        // Pre-populate addresses
        let mut addresses = Vec::new();
        rt.block_on(async {
            for i in 0..100 {
                let address = format!("bcrt1qtest{}", i);
                addresses.push(address.clone());
                let txid = bitcoin::Txid::all_zeros();
                addr_index.index_transaction(
                    &address,
                    &txid,
                    i,
                    true,
                    Amount::from_sat(50_000_000),
                ).await.unwrap();
            }
        });
        
        b.iter(|| {
            rt.block_on(async {
                for address in &addresses {
                    let _ = addr_index.get_address_info(black_box(address)).await;
                }
            });
        });
    });
    
    group.finish();
}

/// Benchmark script validation
fn bench_script_validation(c: &mut Criterion) {
    use bitcoin_core_lib::script::interpreter::Interpreter;
    use bitcoin::blockdata::script::Script;
    
    let mut group = c.benchmark_group("script_validation");
    
    // Benchmark P2PKH script validation
    group.bench_function("p2pkh_validation", |b| {
        let script_pubkey = ScriptBuf::new_p2pkh(
            &bitcoin::PublicKey::from_slice(&[0x02; 33]).unwrap().pubkey_hash()
        );
        let script_sig = ScriptBuf::from_hex("483045022100...").unwrap_or_default();
        
        b.iter(|| {
            let mut interpreter = Interpreter::new();
            let _ = interpreter.verify_script(
                black_box(&script_sig),
                black_box(&script_pubkey),
                black_box(&create_test_transaction(1)),
                black_box(0),
            );
        });
    });
    
    // Benchmark P2WPKH script validation
    group.bench_function("p2wpkh_validation", |b| {
        let script_pubkey = ScriptBuf::new_p2wpkh(
            &bitcoin::PublicKey::from_slice(&[0x02; 33]).unwrap().wpubkey_hash().unwrap()
        );
        
        b.iter(|| {
            let mut interpreter = Interpreter::new();
            let _ = interpreter.verify_script(
                black_box(&ScriptBuf::new()),
                black_box(&script_pubkey),
                black_box(&create_test_transaction(1)),
                black_box(0),
            );
        });
    });
    
    group.finish();
}

// Helper functions

fn create_test_transaction(num_outputs: usize) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: (0..num_outputs)
            .map(|i| TxOut {
                value: Amount::from_sat(50_000_000 + i as u64),
                script_pubkey: ScriptBuf::new(),
            })
            .collect(),
    }
}

fn create_test_block(num_txs: usize) -> Block {
    Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        },
        txdata: (0..num_txs)
            .map(|i| create_test_transaction(i % 10 + 1))
            .collect(),
    }
}

async fn validate_block_mock(block: &Block) -> bool {
    // Mock validation logic
    // In reality, this would perform merkle root validation,
    // transaction validation, PoW check, etc.
    !block.txdata.is_empty()
}

criterion_group!(
    benches,
    bench_utxo_operations,
    bench_block_validation,
    bench_mempool_operations,
    bench_transaction_indexing,
    bench_address_indexing,
    bench_script_validation,
);

criterion_main!(benches);