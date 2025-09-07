# rust-bitcoin-core Architecture

## System Overview

rust-bitcoin-core is a modular Bitcoin full node implementation written in Rust, designed with clear separation of concerns and leveraging the rust-bitcoin ecosystem.

```
┌─────────────────────────────────────────────────────────────┐
│                         bitcoin-node                         │
│                    (Main Binary & Orchestrator)              │
└─────────────┬───────────────────────────────────┬───────────┘
              │                                   │
              ▼                                   ▼
┌──────────────────────┐             ┌──────────────────────┐
│      RPC Server      │             │   Network Manager    │
│  (JSON-RPC 2.0 API)  │             │    (P2P Protocol)    │
└──────────┬───────────┘             └──────────┬───────────┘
           │                                     │
           ▼                                     ▼
┌──────────────────────────────────────────────────────────┐
│                      Core Engine                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐│
│  │  Chain   │  │ Validation│  │  Script  │  │  UTXO    ││
│  │ Manager  │  │  Engine   │  │Interpreter│  │   Set    ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘│
└──────────────────────────────────────────────────────────┘
           │                                     │
           ▼                                     ▼
┌──────────────────────┐             ┌──────────────────────┐
│       Mempool        │             │       Storage        │
│  (Transaction Pool)  │             │    (Sled Database)   │
└──────────────────────┘             └──────────────────────┘
           │                                     │
           ▼                                     ▼
┌──────────────────────┐             ┌──────────────────────┐
│        Wallet        │             │        Miner         │
│   (HD Keys & TXs)    │             │  (PoW & Templates)   │
└──────────────────────┘             └──────────────────────┘
```

## Crate Structure

### 1. `bitcoin-node` (Binary)
**Purpose**: Main executable that orchestrates all components
- **Responsibilities**:
  - Command-line argument parsing
  - Component initialization and wiring
  - Service lifecycle management
  - Signal handling and graceful shutdown

### 2. `core` (Library)
**Purpose**: Core blockchain logic and consensus rules
- **Key Components**:
  - `ChainManager`: Blockchain state management
  - `BlockValidator`: Block validation with consensus rules
  - `ScriptInterpreter`: Bitcoin Script execution engine
  - `TransactionValidator`: Transaction validation pipeline
  - `UtxoSet`: UTXO tracking and management

### 3. `network` (Library)
**Purpose**: P2P networking and protocol implementation
- **Key Components**:
  - `NetworkManager`: Peer connection management
  - `MessageHandler`: Bitcoin protocol message processing
  - `PeerManager`: Peer discovery and reputation
  - `SyncManager`: Block and header synchronization

### 4. `storage` (Library)
**Purpose**: Persistent data storage layer
- **Key Components**:
  - `BlockStore`: Block data persistence
  - `ChainState`: Chain tip and metadata
  - `UtxoStore`: UTXO set database
  - `IndexManager`: Transaction and address indexing

### 5. `mempool` (Library)
**Purpose**: Transaction pool management
- **Key Components**:
  - `Mempool`: Unconfirmed transaction storage
  - `FeeEstimator`: Dynamic fee estimation
  - `TxPriorityQueue`: Transaction prioritization
  - `OrphanPool`: Orphan transaction handling

### 6. `rpc` (Library)
**Purpose**: JSON-RPC 2.0 server implementation
- **Key Components**:
  - `SimpleRpcServer`: HTTP JSON-RPC server
  - `BlockchainRpc`: Blockchain query methods
  - `NetworkRpc`: Network status methods
  - `WalletRpc`: Wallet operation methods
  - `MiningRpc`: Mining control methods

### 7. `wallet` (Library)
**Purpose**: HD wallet implementation
- **Key Components**:
  - `KeyChain`: BIP32/39/44 key derivation
  - `AddressManager`: Address generation and tracking
  - `BalanceTracker`: UTXO and balance management
  - `TransactionBuilder`: Transaction creation and signing

### 8. `miner` (Library)
**Purpose**: Mining and block template generation
- **Key Components**:
  - `ProofOfWorkMiner`: Multi-threaded PoW mining
  - `TemplateBuilder`: Block template creation
  - `TransactionSelector`: Fee-based tx selection
  - `DifficultyAdjuster`: Difficulty calculation

## Data Flow

### Block Processing Pipeline
```
Network → MessageHandler → BlockValidator → ChainManager → Storage
                                ↓
                            UtxoSet Update
                                ↓
                            Mempool Update
                                ↓
                            Wallet Notification
```

### Transaction Flow
```
RPC/Network → Mempool → TransactionValidator → UTXO Check
                ↓                                   ↓
            Fee Estimation                    Script Validation
                ↓                                   ↓
            Broadcasting                      Wallet Update
```

### Mining Process
```
Mempool → TransactionSelector → TemplateBuilder → ProofOfWorkMiner
             ↓                        ↓                 ↓
        Fee Sorting            Coinbase Creation    Nonce Search
             ↓                        ↓                 ↓
         Selection              Block Assembly     Block Found
                                                        ↓
                                                  Network Broadcast
```

## Component Interactions

### Critical Integrations
1. **Wallet ↔ Mempool**: Transaction broadcasting
2. **Miner ↔ Mempool**: Transaction selection for blocks
3. **Network ↔ Chain**: Block propagation and validation
4. **RPC ↔ All Components**: External API access
5. **Storage ↔ All Components**: Persistent state

### Event System
- Block notifications: ChainManager → Wallet, Mempool
- Transaction events: Mempool → Wallet, RPC
- Network events: NetworkManager → ChainManager
- Mining events: Miner → RPC, Network

## Concurrency Model

### Thread Pools
- **Network I/O**: Tokio async runtime
- **RPC Server**: Dedicated HTTP server thread
- **Mining**: Configurable worker threads (CPU cores)
- **Validation**: Parallel transaction validation

### Synchronization
- **ChainManager**: Arc<RwLock> for concurrent access
- **Mempool**: Arc<RwLock> for thread-safe updates
- **UTXO Set**: Copy-on-write for validation isolation
- **Wallet**: Mutex for transaction building

## Storage Architecture

### Database Layout
```
/data
├── blocks/          # Block data
├── chainstate/      # UTXO set and chain metadata
├── indexes/         # Transaction and address indexes
├── mempool/         # Persistent mempool
├── wallet/          # Wallet data and keys
└── peers/           # Peer addresses and stats
```

### Key-Value Schemas
- **Blocks**: `block_hash → Block`
- **UTXO**: `outpoint → TxOut`
- **Chain**: `"tip" → BlockHash`
- **Transactions**: `txid → Transaction`
- **Addresses**: `address → [txid]`

## Security Considerations

### Input Validation
- All external data validated before processing
- Size limits on messages and transactions
- Script execution sandboxing
- Resource limits on validation

### DoS Protection
- Connection limits per IP
- Message rate limiting
- CPU/memory usage bounds
- Ban score for misbehaving peers

### Key Management
- BIP39 mnemonic encryption
- Secure key derivation (BIP32)
- Memory zeroing for sensitive data
- Optional hardware wallet support

## Performance Optimizations

### Caching Strategies
- Block header cache (last 2016 blocks)
- UTXO cache (hot set in memory)
- Script validation cache
- Signature cache

### Batch Processing
- Database writes batched per block
- Network message batching
- Parallel transaction validation
- Async I/O throughout

## Extensibility

### Plugin Points
- Custom RPC methods
- Transaction validation rules
- Block validation extensions
- Custom indexes

### Configuration
- TOML configuration file
- Environment variables
- Command-line overrides
- Network-specific settings

## Testing Strategy

### Unit Tests
- Per-module unit tests
- Mock implementations for dependencies
- Property-based testing for consensus

### Integration Tests
- Multi-node network simulation
- Chain reorganization scenarios
- Transaction propagation tests
- Mining simulation

### Performance Tests
- Block validation throughput
- Transaction processing rate
- Network message handling
- Database performance

## Future Enhancements

### Planned Features
1. Lightning Network support
2. Hardware wallet integration
3. SPV mode for light clients
4. Stratum mining protocol
5. REST API alongside JSON-RPC

### Optimization Opportunities
1. UTXO set compression
2. Parallel block download
3. Memory pool clustering
4. Database sharding
5. Zero-copy networking

---

This architecture provides a solid foundation for a production-ready Bitcoin full node while maintaining clean separation of concerns and extensibility for future enhancements.