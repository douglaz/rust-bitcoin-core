use bitcoin::blockdata::block::Header;
use bitcoin::blockdata::transaction::{OutPoint, TxIn};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, Transaction, TxOut};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use network::compact_blocks::{CompactBlock, CompactBlockRelay};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Create a test block with a specified number of transactions
fn create_test_block(num_transactions: usize) -> Block {
    let mut txdata = Vec::with_capacity(num_transactions + 1);

    // Create coinbase transaction
    let coinbase = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::blockdata::transaction::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5000000000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    txdata.push(coinbase);

    // Create regular transactions
    for i in 1..=num_transactions {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_slice(&[(i % 256) as u8; 32]).unwrap(),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::blockdata::transaction::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100000000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        txdata.push(tx);
    }

    Block {
        header: Header {
            version: bitcoin::blockdata::block::Version::from_consensus(1),
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txdata,
    }
}

fn bench_compact_block_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("compact_block_creation");

    for size in [10, 100, 1000, 5000].iter() {
        let block = create_test_block(*size);

        group.bench_with_input(BenchmarkId::from_parameter(size), &block, |b, block| {
            b.iter(|| CompactBlock::from_block(black_box(block), Some(12345)));
        });
    }

    group.finish();
}

fn bench_compact_block_reconstruction(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("compact_block_reconstruction");

    for size in [10, 100, 1000].iter() {
        let block = create_test_block(*size);
        let compact_block = CompactBlock::from_block(&block, Some(12345));
        let relay = Arc::new(CompactBlockRelay::new(None));

        // Note: Without cache population, this will always result in missing transactions
        // This benchmarks the worst-case scenario where no transactions are in the mempool

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &(relay.clone(), compact_block.clone()),
            |b, (relay, compact_block)| {
                b.to_async(&rt).iter(|| async {
                    relay
                        .process_compact_block(black_box(compact_block.clone()))
                        .await
                });
            },
        );
    }

    group.finish();
}

fn bench_short_id_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("short_id_calculation");

    // Create sample transactions
    let transactions: Vec<_> = (0..1000)
        .map(|i| Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_slice(&[(i % 256) as u8; 32]).unwrap(),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::blockdata::transaction::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100000000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        })
        .collect();

    let nonce = 12345u64;

    group.bench_function("calculate_1000_short_ids", |b| {
        b.iter(|| {
            for tx in &transactions {
                let txid = tx.compute_txid();
                let _short_id = network::compact_blocks::ShortTxId::from_txid(
                    black_box(&txid),
                    black_box(nonce),
                );
            }
        });
    });

    group.finish();
}

fn bench_bandwidth_savings(c: &mut Criterion) {
    let mut group = c.benchmark_group("bandwidth_savings");

    for size in [100, 500, 1000, 2000].iter() {
        let block = create_test_block(*size);
        let compact_block = CompactBlock::from_block(&block, Some(12345));

        // Calculate sizes
        let full_block_size = bitcoin::consensus::encode::serialize(&block).len();
        let compact_block_size = bitcoin::consensus::encode::serialize(&compact_block).len();
        let savings_percent =
            ((full_block_size - compact_block_size) as f64 / full_block_size as f64) * 100.0;

        println!(
            "Block with {} txs: Full size: {} bytes, Compact size: {} bytes, Savings: {:.1}%",
            size, full_block_size, compact_block_size, savings_percent
        );

        group.bench_with_input(
            BenchmarkId::new("serialize_full", size),
            &block,
            |b, block| {
                b.iter(|| bitcoin::consensus::encode::serialize(black_box(block)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("serialize_compact", size),
            &compact_block,
            |b, compact_block| {
                b.iter(|| bitcoin::consensus::encode::serialize(black_box(compact_block)));
            },
        );
    }

    group.finish();
}

fn bench_missing_transaction_handling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("missing_transaction_handling");

    let block = create_test_block(1000);
    let compact_block = CompactBlock::from_block(&block, Some(12345));
    let relay = Arc::new(CompactBlockRelay::new(None));

    // Benchmark identifying missing transactions without a populated cache
    // This simulates the scenario where most transactions are missing

    group.bench_function("identify_missing_transactions", |b| {
        b.to_async(&rt).iter(|| async {
            relay
                .process_compact_block(black_box(compact_block.clone()))
                .await
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets =
        bench_compact_block_creation,
        bench_compact_block_reconstruction,
        bench_short_id_calculation,
        bench_bandwidth_savings,
        bench_missing_transaction_handling
}

criterion_main!(benches);
