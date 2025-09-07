#!/usr/bin/env bash

# Test script for Bitcoin node

echo "Building Bitcoin node..."
cargo build --release 2>/dev/null || { echo "Build failed"; exit 1; }

echo "Starting Bitcoin node on regtest..."
./target/release/bitcoin-node \
    --network regtest \
    --rpc \
    --rpc-bind 127.0.0.1:28443 \
    --datadir /tmp/bitcoin-test-$$ &

NODE_PID=$!
echo "Node started with PID: $NODE_PID"

# Wait for node to start
echo "Waiting for node to start..."
sleep 3

# Test RPC calls
echo ""
echo "Testing RPC endpoints..."
echo "========================"

echo "1. Testing getblockcount..."
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}' \
  http://127.0.0.1:28443 | python3 -c "import sys, json; print('   Block count:', json.load(sys.stdin)['result'])"

echo ""
echo "2. Testing getblockchaininfo..."
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}' \
  http://127.0.0.1:28443 | python3 -c "import sys, json; data=json.load(sys.stdin)['result']; print('   Chain:', data['chain']); print('   Blocks:', data['blocks']); print('   Headers:', data['headers'])"

echo ""
echo "3. Testing getnetworkinfo..."
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getnetworkinfo","params":[],"id":1}' \
  http://127.0.0.1:28443 | python3 -c "import sys, json; data=json.load(sys.stdin)['result']; print('   Connections:', data['connections']); print('   Protocol version:', data['protocolversion'])"

echo ""
echo "4. Testing getmempoolinfo..."
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getmempoolinfo","params":[],"id":1}' \
  http://127.0.0.1:28443 | python3 -c "import sys, json; data=json.load(sys.stdin)['result']; print('   Mempool size:', data['size']); print('   Mempool bytes:', data['bytes'])"

echo ""
echo "5. Testing getpeerinfo..."
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"getpeerinfo","params":[],"id":1}' \
  http://127.0.0.1:28443 | python3 -c "import sys, json; peers=json.load(sys.stdin)['result']; print('   Connected peers:', len(peers))"

echo ""
echo "========================"
echo "All tests completed!"
echo ""
echo "Stopping node..."
kill $NODE_PID 2>/dev/null
wait $NODE_PID 2>/dev/null

# Cleanup
rm -rf /tmp/bitcoin-test-$$

echo "Test complete!"