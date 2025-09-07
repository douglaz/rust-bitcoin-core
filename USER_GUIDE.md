# Bitcoin Core Rust - User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Running a Full Node](#running-a-full-node)
6. [Using the Wallet](#using-the-wallet)
7. [Mining](#mining)
8. [RPC Interface](#rpc-interface)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

## Introduction

Bitcoin Core Rust is a complete reimplementation of Bitcoin Core in Rust, providing a secure, performant, and memory-safe Bitcoin full node. This guide will help you get started with running your own Bitcoin node.

### System Requirements

**Minimum:**
- CPU: 2 cores
- RAM: 4 GB
- Disk: 600 GB (full node) or 10 GB (pruned)
- Network: Broadband connection (25 GB/month upload, 20 GB/month download)

**Recommended:**
- CPU: 4+ cores
- RAM: 8 GB
- Disk: 1 TB SSD
- Network: Unmetered connection

## Installation

### From Source

#### Prerequisites
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install build dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev

# Install build dependencies (macOS)
brew install pkg-config openssl
```

#### Building
```bash
# Clone the repository
git clone https://github.com/yourusername/rust-bitcoin-core.git
cd rust-bitcoin-core

# Build in release mode (recommended)
cargo build --release

# The binary will be at: target/release/bitcoin-node
```

### Using Pre-built Binaries

Download the latest release for your platform:
- Linux: `bitcoin-node-linux-x64.tar.gz`
- macOS: `bitcoin-node-macos-x64.tar.gz`
- Windows: `bitcoin-node-windows-x64.zip`

Extract and run:
```bash
tar -xzf bitcoin-node-linux-x64.tar.gz
./bitcoin-node
```

## Quick Start

### Running Your First Node

1. **Start the node with default settings:**
```bash
./bitcoin-node
```

2. **Check node status:**
```bash
./bitcoin-cli getblockchaininfo
```

3. **Monitor sync progress:**
```bash
watch -n 10 './bitcoin-cli getblockcount'
```

### Running on Testnet

```bash
./bitcoin-node --testnet
```

### Running with Pruning (Low Disk Usage)

```bash
# Keep only last 10GB of blocks
./bitcoin-node --prune=10000
```

## Configuration

### Configuration File

Create `~/.bitcoin/bitcoin.conf`:

```ini
# Network
# main, test, regtest, or signet
network=main

# Connections
maxconnections=125
port=8333

# RPC Server
rpcport=8332
rpcuser=yourusername
rpcpassword=yourpassword
# WARNING: Only allow trusted IPs
rpcallowip=127.0.0.1
rpcallowip=192.168.1.0/24

# Mempool
maxmempool=300
mempoolexpiry=336

# Storage
# Pruning (0 = disabled, or size in MB)
prune=0
# Transaction index (required for getrawtransaction)
txindex=1
# Address index (for searchrawtransactions)
addressindex=0

# Performance
dbcache=4096
par=0  # 0 = auto-detect CPU cores

# Mining (optional)
gen=0  # 0 = disabled, 1 = enabled
genproclimit=1  # Number of mining threads

# Wallet
wallet=1  # Enable wallet functionality
```

### Command Line Options

All configuration options can be specified on the command line:

```bash
./bitcoin-node \
  --datadir=/custom/path \
  --maxconnections=50 \
  --rpcuser=user \
  --rpcpassword=pass
```

### Environment Variables

Configuration can also use environment variables:
```bash
export BITCOIN_DATADIR=/custom/path
export BITCOIN_NETWORK=testnet
./bitcoin-node
```

## Running a Full Node

### Initial Blockchain Download (IBD)

When you first start your node, it will download and validate the entire blockchain:

1. **Monitor progress:**
```bash
./bitcoin-cli getblockchaininfo | grep -E "blocks|headers|progress"
```

2. **Expected sync times:**
   - Fast connection + SSD: 6-12 hours
   - Average setup: 1-3 days
   - Slow connection or HDD: 3-7 days

### Node Maintenance

#### Backup
```bash
# Stop the node
./bitcoin-cli stop

# Backup wallet (if using)
cp ~/.bitcoin/wallet.dat /backup/location/

# Backup configuration
cp ~/.bitcoin/bitcoin.conf /backup/location/
```

#### Updates
```bash
# Stop node
./bitcoin-cli stop

# Update and rebuild
git pull
cargo build --release

# Restart
./bitcoin-node
```

#### Monitoring
```bash
# Check peer connections
./bitcoin-cli getpeerinfo | grep -c addr

# Check mempool
./bitcoin-cli getmempoolinfo

# Check disk usage
du -sh ~/.bitcoin/
```

## Using the Wallet

### Enable Wallet

Ensure wallet is enabled in config:
```ini
wallet=1
```

### Basic Wallet Operations

#### Create New Address
```bash
./bitcoin-cli getnewaddress "label"
```

#### Check Balance
```bash
./bitcoin-cli getbalance
```

#### Send Bitcoin
```bash
./bitcoin-cli sendtoaddress "address" amount

# With fee rate (sat/vB)
./bitcoin-cli sendtoaddress "address" amount "" "" false true 20
```

#### List Transactions
```bash
./bitcoin-cli listtransactions

# Last 10 transactions
./bitcoin-cli listtransactions "*" 10
```

#### Backup Wallet
```bash
./bitcoin-cli backupwallet "/path/to/backup.dat"
```

### Advanced Wallet Features

#### Create Multisig Address
```bash
./bitcoin-cli createmultisig 2 '["pubkey1", "pubkey2", "pubkey3"]'
```

#### Sign Message
```bash
./bitcoin-cli signmessage "address" "message"
```

#### Coin Control
```bash
# List unspent outputs
./bitcoin-cli listunspent

# Create raw transaction with specific inputs
./bitcoin-cli createrawtransaction '[{"txid":"...", "vout":0}]' '{"address":0.01}'
```

## Mining

### CPU Mining (Testnet/Regtest Only)

**Warning:** CPU mining is not profitable on mainnet.

```bash
# Enable in config
gen=1
genproclimit=4  # Number of threads

# Or via RPC
./bitcoin-cli setgenerate true 4
```

### Mining to Specific Address
```bash
./bitcoin-cli generatetoaddress 1 "your_address"
```

### Check Mining Status
```bash
./bitcoin-cli getmininginfo
```

## RPC Interface

### Using bitcoin-cli

```bash
# General format
./bitcoin-cli [options] <command> [params]

# Get help
./bitcoin-cli help
./bitcoin-cli help getblock
```

### Common RPC Commands

#### Blockchain
```bash
# Get blockchain info
./bitcoin-cli getblockchaininfo

# Get specific block
./bitcoin-cli getblock "blockhash"

# Get block at height
./bitcoin-cli getblockhash 700000
```

#### Network
```bash
# Network info
./bitcoin-cli getnetworkinfo

# Peer info
./bitcoin-cli getpeerinfo

# Add node
./bitcoin-cli addnode "ip:port" "add"
```

#### Mempool
```bash
# Mempool statistics
./bitcoin-cli getmempoolinfo

# Raw mempool
./bitcoin-cli getrawmempool
```

### JSON-RPC via curl

```bash
# Basic request
curl --user user:pass \
  --data-binary '{"jsonrpc":"1.0","method":"getblockcount","params":[]}' \
  -H 'content-type: text/plain;' \
  http://127.0.0.1:8332/

# Pretty print response
curl --user user:pass \
  --data-binary '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
  -H 'content-type: text/plain;' \
  http://127.0.0.1:8332/ | jq '.'
```

## Troubleshooting

### Node Won't Start

1. **Check if already running:**
```bash
ps aux | grep bitcoin-node
```

2. **Check ports:**
```bash
netstat -an | grep -E "8332|8333"
```

3. **Check logs:**
```bash
tail -f ~/.bitcoin/debug.log
```

### Slow Synchronization

1. **Increase cache:**
```ini
dbcache=8192  # Use more RAM for database cache
```

2. **Check peers:**
```bash
./bitcoin-cli getpeerinfo | wc -l  # Should be > 8
```

3. **Add nodes manually:**
```bash
./bitcoin-cli addnode "seed.bitcoin.sipa.be" "add"
```

### High Memory Usage

1. **Reduce mempool:**
```ini
maxmempool=50  # Reduce to 50MB
```

2. **Limit connections:**
```ini
maxconnections=40
```

### Disk Space Issues

1. **Enable pruning:**
```ini
prune=5000  # Keep only 5GB
```

2. **Disable indexes:**
```ini
txindex=0
addressindex=0
```

### Connection Issues

1. **Check firewall:**
```bash
# Allow Bitcoin ports
sudo ufw allow 8333/tcp  # Mainnet
sudo ufw allow 18333/tcp # Testnet
```

2. **Router configuration:**
   - Forward port 8333 to your node
   - Enable UPnP if supported

## FAQ

### Q: How much bandwidth will my node use?
**A:** Typically 5-10 GB upload and 5-10 GB download per month after initial sync.

### Q: Can I run a node on a Raspberry Pi?
**A:** Yes, but use an external SSD and enable pruning. Expect slower performance.

### Q: Is my wallet encrypted?
**A:** Use `./bitcoin-cli encryptwallet "passphrase"` to encrypt your wallet.

### Q: How do I migrate from Bitcoin Core?
**A:** Copy your `blocks/` and `chainstate/` directories to the data directory. Wallet files are compatible.

### Q: Can I run multiple nodes?
**A:** Yes, use different data directories and ports:
```bash
./bitcoin-node --datadir=/path/to/node2 --port=8334 --rpcport=8335
```

### Q: How do I verify the blockchain?
**A:** The node automatically verifies all blocks. To reverify:
```bash
./bitcoin-node --reindex
```

### Q: What's the difference between pruned and full node?
**A:** Full nodes store all historical blocks (~500GB). Pruned nodes delete old blocks, keeping only recent ones and the UTXO set.

## Security Best Practices

1. **Use strong RPC credentials**
2. **Limit RPC access to localhost**
3. **Keep software updated**
4. **Encrypt wallet with strong passphrase**
5. **Regular backups of wallet.dat**
6. **Run node on dedicated user account**
7. **Use firewall to limit connections**
8. **Monitor logs for suspicious activity**

## Getting Help

- **Documentation**: [Full API Documentation](./API_DOCUMENTATION.md)
- **GitHub Issues**: Report bugs and request features
- **Community**: Bitcoin Stack Exchange, /r/Bitcoin

## License

MIT License - See LICENSE file for details.