#!/bin/bash

echo "=== Testing Mempool Functionality ==="

# Test getmempoolinfo
echo "1. Testing getmempoolinfo:"
curl -s http://127.0.0.1:18443 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getmempoolinfo","params":[],"id":1}' | jq .

# Test getrawmempool (empty)
echo -e "\n2. Testing getrawmempool (should be empty initially):"
curl -s http://127.0.0.1:18443 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getrawmempool","params":[],"id":2}' | jq .

# Generate some blocks first to have coins
echo -e "\n3. Generating blocks to create coins:"
curl -s http://127.0.0.1:18443 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"generatetoaddress","params":[10,"bcrt1q6rhpng9evdsfnn833ytcdwa0eg6mzm335n2le"],"id":3}' | jq .

# Create a raw transaction (this would need proper inputs/outputs)
echo -e "\n4. Testing sendrawtransaction with dummy tx:"
# This is a dummy transaction hex - won't be valid but tests the mempool
DUMMY_TX="02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000"
curl -s http://127.0.0.1:18443 -X POST -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"sendrawtransaction\",\"params\":[\"$DUMMY_TX\"],\"id\":4}" | jq .

# Check mempool again
echo -e "\n5. Checking mempool after transaction:"
curl -s http://127.0.0.1:18443 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getrawmempool","params":[],"id":5}' | jq .

echo -e "\n=== Test Complete ===\n"