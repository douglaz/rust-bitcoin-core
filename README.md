# rust-bitcoin-core

An experimental Bitcoin Core implementation in Rust for educational and research purposes.

## ⚠️ Important Warning

**This is NOT production-ready software.** This implementation is incomplete and has known security vulnerabilities. Do not use for:
- Real Bitcoin transactions
- Production environments
- Security-sensitive applications
- Mainnet or even testnet with real value

For detailed status, see [ACTUAL_STATUS.md](ACTUAL_STATUS.md)

## Overview

rust-bitcoin-core is a work-in-progress Bitcoin node implementation written in Rust. Currently implemented (with limitations):

- Basic block and transaction validation (incomplete consensus rules)
- Simple mempool management
- JSON-RPC interface (partial Bitcoin Core compatibility)
- Storage layer using Sled
- Modular architecture

**Not yet working:**
- Script validation (always returns true - CRITICAL SECURITY ISSUE)
- Signature verification
- Complete P2P networking
- Many consensus rules

## Architecture

The project is organized as a Cargo workspace with the following crates:

- **`bitcoin-node`** - Main node implementation and orchestration
- **`bitcoin-cli`** - Command-line interface for interacting with the node
- **`bitcoin-core-lib`** - Consensus rules, validation, and chain management (renamed from `core` to avoid namespace conflicts)
- **`network`** - P2P networking and protocol handling
- **`storage`** - Database layer for blocks, UTXO set, and chain state
- **`mempool`** - Transaction pool management
- **`rpc`** - JSON-RPC server implementation
- **`miner`** - Block mining and proof-of-work implementation
- **`wallet`** - Basic wallet functionality

## Building

### Prerequisites

- Rust 1.75.0 or later
- RocksDB development libraries
- OpenSSL development libraries

### Using Nix (Recommended)

The project includes a Nix flake for reproducible builds:

```bash
# Enter development shell
nix develop

# Build the project
cargo build --release

# Run tests
cargo test

# Current test status: 162/165 passing (98.2%)
# Only 3 miner tests failing - see ACTUAL_STATUS.md for details
```

### Manual Build

```bash
# No external database dependencies required!
# Sled is embedded and compiled with the project

# Build the project
cargo build --release

# The binary will be at target/release/bitcoin-node
```

## Running

### Start a node

```bash
# Run on mainnet (default)
./target/release/bitcoin-node

# Run on testnet
./target/release/bitcoin-node --network testnet

# Run on regtest for development (recommended for testing)
./target/release/bitcoin-node --network regtest --rpc --rpc-bind 127.0.0.1:28443 --datadir ./regtest-data

# Enable RPC server (use port 28443 to avoid nginx proxy conflicts)
./target/release/bitcoin-node --rpc --rpc-bind 127.0.0.1:28443

# Connect to specific peers
./target/release/bitcoin-node --connect peer1.example.com:8333 --connect peer2.example.com:8333
```

**Note**: Port 18443 may be proxied by nginx on some systems. Use port 28443 or another available port for RPC to avoid conflicts.

### Using the CLI

```bash
# Get blockchain info
./target/release/bitcoin-cli getblockchaininfo

# Get a specific block
./target/release/bitcoin-cli getblock <block_hash>

# Get connected peers
./target/release/bitcoin-cli getpeerinfo

# Generate blocks (regtest only)
./target/release/bitcoin-cli generatetoaddress 10 <address>
```

### Using RPC directly with curl

```bash
# Get block count
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}' \
  http://127.0.0.1:28443

# Get blockchain info
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' \
  http://127.0.0.1:28443

# Get mempool info
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getmempoolinfo","params":[],"id":1}' \
  http://127.0.0.1:28443
```

### Available RPC Methods

The following RPC methods are currently implemented:

- **Blockchain**
  - `getblockchaininfo` - Get blockchain state information
  - `getblockcount` - Get the current block height
  - `getbestblockhash` - Get the hash of the best block
  - `getblock <hash>` - Get block details by hash
  - `getblockhash <height>` - Get block hash at specific height
  
- **Network**
  - `getnetworkinfo` - Get network state information
  - `getpeerinfo` - Get information about connected peers
  - `getconnectioncount` - Get the number of connections
  
- **Mempool**
  - `getmempoolinfo` - Get mempool state information
  - `getrawmempool` - Get list of transaction IDs in mempool
  - `getrawtransaction <txid>` - Get raw transaction data
  
- **Mining** (regtest only)
  - `generatetoaddress <nblocks> <address>` - Mine blocks to specified address
  
- **Wallet** (if enabled)
  - `getnewaddress` - Generate a new receiving address
  - `getbalance` - Get wallet balance
  - `sendtoaddress <address> <amount>` - Send Bitcoin to an address
  - `listtransactions` - List recent transactions

## Configuration

Configuration can be provided via command-line arguments or a configuration file:

```toml
# bitcoin.conf
network = "mainnet"
datadir = "/path/to/data"
rpc_enabled = true
rpc_bind = "127.0.0.1:8332"
p2p_bind = "0.0.0.0:8333"
max_connections = 125
cache_size = 450
```

Then run with:
```bash
./target/release/bitcoin-node --config bitcoin.conf
```

## Development

### Project Structure

```
rust-bitcoin-core/
├── bitcoin-node/       # Main node binary
├── bitcoin-cli/        # CLI tool  
├── core/              # Consensus and validation (bitcoin-core-lib)
├── network/           # P2P networking
├── miner/             # Mining and proof-of-work
├── wallet/            # Wallet functionality
├── storage/           # Database layer
├── mempool/           # Transaction pool
├── rpc/              # RPC server
├── PLAN.md           # Detailed implementation plan
└── flake.nix         # Nix development environment
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p core

# Run with output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Check for security vulnerabilities
cargo audit
```

## Features

### Implemented
- ✅ Basic project structure and workspace setup
- ✅ Storage layer with Sled (embedded database)
- ✅ Core consensus types and validation framework
- ✅ Chain management and block index
- ✅ UTXO set management with persistence
- ✅ Mempool with fee prioritization
- ✅ Network manager with P2P protocol
- ✅ RPC server with 24+ methods
- ✅ CLI tool for interacting with the node
- ✅ Headers-first synchronization
- ✅ Block and transaction validation
- ✅ Chain reorganization support
- ✅ Mining support with block templates

### In Progress
- 🚧 Parallel block validation
- 🚧 Performance optimization
- 🚧 Integration test suite

### Planned
- ⏳ Full wallet functionality
- ⏳ Fee estimation improvements
- ⏳ Compact block relay (BIP 152)
- ⏳ Address index
- ⏳ ZMQ notifications
- ⏳ Prometheus metrics
- ⏳ Security hardening

## Contributing

Contributions are welcome! Please see the [PLAN.md](PLAN.md) file for the detailed implementation roadmap.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License.

## Acknowledgments

This implementation leverages the excellent [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) ecosystem for Bitcoin primitives and would not be possible without the foundational work done by that team.

## Security

This is an experimental implementation and should not be used in production or with real funds. Always use the official Bitcoin Core for production use.

## Contact

For questions and discussions, please open an issue on GitHub.