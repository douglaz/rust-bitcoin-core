#!/usr/bin/env python3
"""
Test script for rust-bitcoin-core RPC methods
Tests all 26 implemented RPC methods with proper error handling
"""

import json
import requests
from typing import Dict, Any, Optional

class RPCTester:
    def __init__(self, url: str = "http://localhost:8332"):
        self.url = url
        self.id_counter = 0
        self.results = {"passed": 0, "failed": 0, "errors": []}
        
    def call_rpc(self, method: str, params: list = None) -> Dict[str, Any]:
        """Make an RPC call and return the response"""
        self.id_counter += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": self.id_counter
        }
        
        try:
            response = requests.post(self.url, json=payload, timeout=5)
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def test_method(self, method: str, params: list = None, expected_type: type = None):
        """Test a single RPC method"""
        print(f"Testing {method}...", end=" ")
        result = self.call_rpc(method, params)
        
        if "error" in result and not isinstance(result.get("error"), dict):
            # Connection error
            print(f"❌ Connection failed: {result['error']}")
            self.results["failed"] += 1
            self.results["errors"].append(f"{method}: Connection failed")
            return False
        
        if "result" in result:
            if expected_type and not isinstance(result["result"], expected_type):
                print(f"❌ Wrong type: expected {expected_type}, got {type(result['result'])}")
                self.results["failed"] += 1
                self.results["errors"].append(f"{method}: Type mismatch")
                return False
            print(f"✅ Success")
            self.results["passed"] += 1
            return True
        elif "error" in result:
            # RPC error (method returned an error)
            error_msg = result.get("error", {}).get("message", "Unknown error")
            print(f"⚠️  RPC Error: {error_msg}")
            self.results["failed"] += 1
            self.results["errors"].append(f"{method}: {error_msg}")
            return False
        else:
            print(f"❌ Invalid response")
            self.results["failed"] += 1
            self.results["errors"].append(f"{method}: Invalid response format")
            return False
    
    def run_all_tests(self):
        """Run all RPC method tests"""
        print("=" * 60)
        print("Testing rust-bitcoin-core RPC Methods")
        print("=" * 60)
        print()
        
        # Check if server is running
        print("Checking server connection...")
        result = self.call_rpc("getblockcount")
        if "error" in result and not isinstance(result.get("error"), dict):
            print(f"❌ Server not running at {self.url}")
            print("Please start the node with:")
            print("  nix develop -c cargo run --bin bitcoin-node -- --network regtest")
            return
        print("✅ Server is running\n")
        
        # Blockchain Methods (10)
        print("=== Blockchain Methods ===")
        self.test_method("getblockcount", expected_type=int)
        self.test_method("getbestblockhash", expected_type=str)
        self.test_method("getblockchaininfo", expected_type=dict)
        self.test_method("getblockhash", [0], expected_type=str)
        self.test_method("getblock", ["0000000000000000000000000000000000000000000000000000000000000000"])
        self.test_method("getblockheader", ["0000000000000000000000000000000000000000000000000000000000000000"])
        self.test_method("getdifficulty", expected_type=(int, float))
        self.test_method("getrawtransaction", ["0000000000000000000000000000000000000000000000000000000000000000"])
        self.test_method("gettxout", ["0000000000000000000000000000000000000000000000000000000000000000", 0])
        self.test_method("gettxoutsetinfo", expected_type=dict)
        print()
        
        # Network Methods (7)
        print("=== Network Methods ===")
        self.test_method("getconnectioncount", expected_type=int)
        self.test_method("getnetworkinfo", expected_type=dict)
        self.test_method("getpeerinfo", expected_type=list)
        self.test_method("getnettotals", expected_type=dict)
        self.test_method("addnode", ["127.0.0.1:8333", "add"])
        self.test_method("disconnectnode", ["127.0.0.1:8333"])
        self.test_method("getaddednodeinfo", expected_type=list)
        print()
        
        # Mempool Methods (7)
        print("=== Mempool Methods ===")
        self.test_method("getmempoolinfo", expected_type=dict)
        self.test_method("getrawmempool", expected_type=list)
        self.test_method("getrawmempool", [True], expected_type=dict)
        self.test_method("getmempoolentry", ["0000000000000000000000000000000000000000000000000000000000000000"])
        # Test with a simple raw transaction hex
        test_tx = "020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff00000000"
        self.test_method("testmempoolaccept", [[test_tx]], expected_type=list)
        self.test_method("sendrawtransaction", [test_tx])
        print()
        
        # Mining Methods (2)
        print("=== Mining Methods ===")
        self.test_method("getblocktemplate", expected_type=dict)
        self.test_method("generatetoaddress", [1, "bcrt1qtest"])
        print()
        
        # Print summary
        print("=" * 60)
        print("Test Summary")
        print("=" * 60)
        print(f"✅ Passed: {self.results['passed']}")
        print(f"❌ Failed: {self.results['failed']}")
        print(f"Total: {self.results['passed'] + self.results['failed']}/26")
        
        if self.results['errors']:
            print("\nErrors:")
            for error in self.results['errors'][:10]:  # Show first 10 errors
                print(f"  - {error}")
            if len(self.results['errors']) > 10:
                print(f"  ... and {len(self.results['errors']) - 10} more")
        
        print("\nNote: Some methods returning errors is expected for test data")
        print("The important thing is that the server responds to all methods")

if __name__ == "__main__":
    tester = RPCTester()
    tester.run_all_tests()