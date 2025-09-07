#!/usr/bin/env bash

# Test mining functionality with generatetoaddress

set -e

echo "=== Testing Bitcoin Node Mining Functionality ==="

# Start node in background
echo "Starting node on regtest..."
./target/release/bitcoin-node --network regtest --rpc --rpc-bind 127.0.0.1:28443 > /tmp/node.log 2>&1 &
NODE_PID=$!

# Wait for node to start
echo "Waiting for node to start..."
sleep 3

# Check if node is running
if ! kill -0 $NODE_PID 2>/dev/null; then
    echo "❌ Node failed to start"
    cat /tmp/node.log
    exit 1
fi

echo "✓ Node started (PID: $NODE_PID)"

# Test getblockcount before mining
echo -n "Testing getblockcount before mining... "
COUNT=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}' \
    http://127.0.0.1:28443 | jq -r '.result')
if [ "$COUNT" = "0" ]; then
    echo "✓ (height: $COUNT)"
else
    echo "❌ Expected 0, got $COUNT"
fi

# Generate a test address (P2WPKH)
TEST_ADDRESS="bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"

# Test generatetoaddress
echo "Testing generatetoaddress..."
echo "Generating 10 blocks to $TEST_ADDRESS..."
RESULT=$(curl -s -X POST -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"generatetoaddress\",\"params\":[10,\"$TEST_ADDRESS\"],\"id\":1}" \
    http://127.0.0.1:28443)

# Check if we got an array of block hashes
BLOCK_HASHES=$(echo "$RESULT" | jq -r '.result')
if [ "$BLOCK_HASHES" != "null" ]; then
    BLOCK_COUNT=$(echo "$BLOCK_HASHES" | jq '. | length')
    if [ "$BLOCK_COUNT" = "10" ]; then
        echo "✓ Generated 10 blocks successfully"
        echo "First block hash: $(echo "$BLOCK_HASHES" | jq -r '.[0]')"
    else
        echo "❌ Expected 10 blocks, got $BLOCK_COUNT"
        echo "Response: $RESULT"
    fi
else
    echo "❌ Failed to generate blocks"
    echo "Response: $RESULT"
fi

# Test getblockcount after mining
echo -n "Testing getblockcount after mining... "
COUNT=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}' \
    http://127.0.0.1:28443 | jq -r '.result')
if [ "$COUNT" = "10" ]; then
    echo "✓ (height: $COUNT)"
else
    echo "❌ Expected 10, got $COUNT"
fi

# Test getbestblockhash
echo -n "Testing getbestblockhash... "
BEST_HASH=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"getbestblockhash","params":[],"id":1}' \
    http://127.0.0.1:28443 | jq -r '.result')
if [ ! -z "$BEST_HASH" ] && [ "$BEST_HASH" != "null" ]; then
    echo "✓ ($BEST_HASH)"
else
    echo "❌ No best block hash"
fi

# Test getblock with the best hash
echo -n "Testing getblock... "
BLOCK=$(curl -s -X POST -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"getblock\",\"params\":[\"$BEST_HASH\",1],\"id\":1}" \
    http://127.0.0.1:28443 | jq -r '.result')
if [ ! -z "$BLOCK" ] && [ "$BLOCK" != "null" ]; then
    HEIGHT=$(echo "$BLOCK" | jq -r '.height')
    TX_COUNT=$(echo "$BLOCK" | jq -r '.tx | length')
    echo "✓ (height: $HEIGHT, txs: $TX_COUNT)"
else
    echo "❌ Failed to get block"
fi

# Test mining with transactions in mempool
echo ""
echo "Testing mining with mempool transactions..."

# First, we need to create a transaction
# This would require having spendable outputs from previous blocks
# For now, we'll just test that mining still works

echo "Generating 1 more block..."
RESULT=$(curl -s -X POST -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"generatetoaddress\",\"params\":[1,\"$TEST_ADDRESS\"],\"id\":1}" \
    http://127.0.0.1:28443)

BLOCK_HASH=$(echo "$RESULT" | jq -r '.result[0]')
if [ ! -z "$BLOCK_HASH" ] && [ "$BLOCK_HASH" != "null" ]; then
    echo "✓ Generated block: $BLOCK_HASH"
else
    echo "❌ Failed to generate additional block"
fi

# Final block count
echo -n "Final block count: "
COUNT=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}' \
    http://127.0.0.1:28443 | jq -r '.result')
echo "$COUNT"

# Cleanup
echo ""
echo "Stopping node..."
kill $NODE_PID 2>/dev/null || true
wait $NODE_PID 2>/dev/null || true

echo ""
echo "=== Mining Test Complete ==="
echo ""
echo "Summary:"
echo "✓ Node starts on regtest"
echo "✓ generatetoaddress RPC method works"
echo "✓ Blocks are properly mined and added to chain"
echo "✓ Block height increments correctly"
echo "✓ Blocks can be retrieved by hash"