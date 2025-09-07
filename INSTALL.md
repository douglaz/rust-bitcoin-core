# Installation Guide

## Quick Install

### Using Pre-built Binaries (Recommended)

```bash
# Linux/macOS
curl -L https://github.com/project/releases/latest/download/bitcoin-node-$(uname -s)-$(uname -m).tar.gz | tar xz
sudo mv bitcoin-node /usr/local/bin/
bitcoin-node --version
```

### Using Cargo

```bash
cargo install --git https://github.com/project/rust-bitcoin-core
```

## Building from Source

### Prerequisites

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    curl
```

#### Fedora/RHEL/CentOS
```bash
sudo dnf install -y \
    gcc \
    pkg-config \
    openssl-devel \
    git \
    curl
```

#### macOS
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install pkg-config openssl
```

#### Windows
1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/)
2. Install [Rust](https://rustup.rs/)
3. Install [Git](https://git-scm.com/download/win)

### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Clone and Build

```bash
# Clone repository
git clone https://github.com/project/rust-bitcoin-core.git
cd rust-bitcoin-core

# Build in release mode
cargo build --release

# Install to system
sudo cp target/release/bitcoin-node /usr/local/bin/
sudo cp target/release/bitcoin-cli /usr/local/bin/
```

### Build Options

```bash
# Debug build (slower, with debug symbols)
cargo build

# Release build (optimized)
cargo build --release

# Static binary (for distribution)
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-musl

# Cross-compilation
cargo build --release --target aarch64-unknown-linux-gnu
```

## Docker Installation

### Using Docker Hub

```bash
docker pull bitcoincore/rust-node:latest
docker run -d \
    --name bitcoin-node \
    -p 8333:8333 \
    -p 8332:8332 \
    -v bitcoin-data:/data \
    bitcoincore/rust-node
```

### Building Docker Image

```bash
# Build image
docker build -t bitcoin-node .

# Run container
docker run -d \
    --name bitcoin-node \
    -p 8333:8333 \
    -p 8332:8332 \
    -v $(pwd)/data:/data \
    bitcoin-node
```

### Docker Compose

```yaml
version: '3.8'
services:
  bitcoin-node:
    image: bitcoincore/rust-node:latest
    container_name: bitcoin-node
    ports:
      - "8333:8333"
      - "8332:8332"
    volumes:
      - bitcoin-data:/data
      - ./bitcoin.conf:/data/bitcoin.conf
    restart: unless-stopped
    environment:
      - BITCOIN_NETWORK=main
    
volumes:
  bitcoin-data:
```

## System Service Installation

### systemd (Linux)

Create `/etc/systemd/system/bitcoin-node.service`:

```ini
[Unit]
Description=Bitcoin Core Rust Node
After=network.target

[Service]
Type=simple
User=bitcoin
Group=bitcoin
WorkingDirectory=/var/lib/bitcoin
ExecStart=/usr/local/bin/bitcoin-node --datadir=/var/lib/bitcoin
ExecStop=/usr/local/bin/bitcoin-cli stop
Restart=on-failure
RestartSec=30

# Security
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
PrivateDevices=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
# Create user
sudo useradd -r -s /bin/false bitcoin
sudo mkdir -p /var/lib/bitcoin
sudo chown bitcoin:bitcoin /var/lib/bitcoin

# Enable service
sudo systemctl enable bitcoin-node
sudo systemctl start bitcoin-node
sudo systemctl status bitcoin-node
```

### macOS LaunchAgent

Create `~/Library/LaunchAgents/org.bitcoin.node.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.bitcoin.node</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/bitcoin-node</string>
        <string>--datadir=/Users/USERNAME/.bitcoin</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/bitcoin-node.err</string>
    <key>StandardOutPath</key>
    <string>/tmp/bitcoin-node.out</string>
</dict>
</plist>
```

Load service:
```bash
launchctl load ~/Library/LaunchAgents/org.bitcoin.node.plist
```

## Package Manager Installation

### Homebrew (macOS)

```bash
brew tap bitcoincore/rust
brew install bitcoin-node
```

### APT (Ubuntu/Debian)

```bash
# Add repository
curl -s https://packagecloud.io/install/repositories/bitcoin/rust/script.deb.sh | sudo bash

# Install
sudo apt-get install bitcoin-node
```

### YUM/DNF (Fedora/RHEL)

```bash
# Add repository
curl -s https://packagecloud.io/install/repositories/bitcoin/rust/script.rpm.sh | sudo bash

# Install
sudo dnf install bitcoin-node
```

## Verification

### Verify Installation

```bash
# Check version
bitcoin-node --version

# Check binary location
which bitcoin-node

# Test configuration
bitcoin-node --testnet --printtoconsole
```

### Verify Build

```bash
# Run tests
cargo test

# Check dependencies
cargo tree

# Verify binary
file target/release/bitcoin-node
ldd target/release/bitcoin-node  # Linux
otool -L target/release/bitcoin-node  # macOS
```

## Post-Installation

### Initial Configuration

```bash
# Create data directory
mkdir -p ~/.bitcoin

# Create configuration file
cat > ~/.bitcoin/bitcoin.conf << EOF
# Network
network=main
port=8333

# RPC
rpcport=8332
rpcuser=bitcoinrpc
rpcpassword=$(openssl rand -hex 32)

# Performance
dbcache=4096
maxconnections=125
EOF

# Set permissions
chmod 600 ~/.bitcoin/bitcoin.conf
```

### First Run

```bash
# Start node
bitcoin-node

# In another terminal, check status
bitcoin-cli getblockchaininfo
```

## Troubleshooting Installation

### Rust Version Issues

```bash
# Update Rust
rustup update

# Use specific version
rustup default 1.70.0
```

### Missing Dependencies

```bash
# Find missing libraries (Linux)
ldd bitcoin-node | grep "not found"

# Install missing libraries
sudo apt-get install libssl1.1  # Example for OpenSSL
```

### Permission Issues

```bash
# Fix permissions
sudo chown -R $(whoami):$(whoami) ~/.bitcoin
chmod 755 ~/.bitcoin
chmod 600 ~/.bitcoin/bitcoin.conf
```

### Build Failures

```bash
# Clean build
cargo clean
cargo build --release

# Verbose output
RUST_BACKTRACE=1 cargo build --release --verbose
```

## Uninstallation

### Manual Removal

```bash
# Stop node
bitcoin-cli stop

# Remove binaries
sudo rm /usr/local/bin/bitcoin-node
sudo rm /usr/local/bin/bitcoin-cli

# Remove data (optional - contains blockchain and wallet!)
rm -rf ~/.bitcoin

# Remove systemd service
sudo systemctl disable bitcoin-node
sudo rm /etc/systemd/system/bitcoin-node.service
```

### Package Manager Removal

```bash
# Homebrew
brew uninstall bitcoin-node

# APT
sudo apt-get remove bitcoin-node

# DNF
sudo dnf remove bitcoin-node
```

## Support

For installation issues:
- Check [GitHub Issues](https://github.com/project/issues)
- Read [Troubleshooting Guide](./USER_GUIDE.md#troubleshooting)
- Ask on [Stack Exchange](https://bitcoin.stackexchange.com)