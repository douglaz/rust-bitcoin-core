use crate::orphan_pool::OrphanPool;
use crate::tx_relay::TxRequestTracker;
use bitcoin::{Amount, OutPoint, Transaction, TxIn, TxOut, Txid};
use bitcoin_hashes::Hash;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn create_test_tx() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    }
}

fn test_peer(id: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, id)), 8333)
}

#[test]
fn test_tx_deduplication() {
    let mut tracker = TxRequestTracker::new();
    let tx = create_test_tx();
    let txid = tx.compute_txid();
    let peer1 = test_peer(1);
    let peer2 = test_peer(2);

    // First announcement should be requestable
    assert!(tracker.on_tx_announcement(txid, peer1).unwrap());

    // Second announcement from different peer should not be immediately requestable
    assert!(!tracker.on_tx_announcement(txid, peer2).unwrap());

    // Get next request should return the first announcement
    let next = tracker.get_next_request();
    assert_eq!(next, Some((txid, peer1)));

    // Mark as requested
    tracker.mark_requested(txid, peer1).unwrap();

    // Now we shouldn't get any more requests for this tx
    assert_eq!(tracker.get_next_request(), None);
}

#[test]
fn test_in_flight_limits() {
    let mut tracker = TxRequestTracker::new();
    let peer = test_peer(1);

    // Add many transactions
    let mut txids = Vec::new();
    for i in 0..150 {
        let mut tx = create_test_tx();
        tx.output[0].value = Amount::from_sat(i as u64);
        let txid = tx.compute_txid();
        txids.push(txid);
        tracker.on_tx_announcement(txid, peer).unwrap();
    }

    // Request up to the limit
    let mut requested = 0;
    while let Some((txid, req_peer)) = tracker.get_next_request() {
        assert_eq!(req_peer, peer);
        tracker.mark_requested(txid, req_peer).unwrap();
        requested += 1;

        // Should stop at MAX_PEER_TX_IN_FLIGHT (100)
        if requested >= 100 {
            break;
        }
    }

    assert_eq!(requested, 100);
    assert_eq!(tracker.get_peer_in_flight_count(&peer), 100);

    // No more requests should be available for this peer
    assert_eq!(tracker.get_next_request(), None);
}

#[test]
fn test_tx_received_clears_in_flight() {
    let mut tracker = TxRequestTracker::new();
    let tx = create_test_tx();
    let txid = tx.compute_txid();
    let peer = test_peer(1);

    // Announce and request
    tracker.on_tx_announcement(txid, peer).unwrap();
    let next = tracker.get_next_request();
    assert_eq!(next, Some((txid, peer)));
    tracker.mark_requested(txid, peer).unwrap();

    // Verify it's in flight
    assert_eq!(tracker.get_peer_in_flight_count(&peer), 1);

    // Receive the transaction
    tracker.on_tx_received(txid, peer);

    // Should no longer be in flight
    assert_eq!(tracker.get_peer_in_flight_count(&peer), 0);

    // Should not request again
    assert!(!tracker.should_request_tx(&txid));
}

#[test]
fn test_tx_rejection_handling() {
    let mut tracker = TxRequestTracker::new();
    let tx = create_test_tx();
    let txid = tx.compute_txid();
    let peer = test_peer(1);

    // Announce and request
    tracker.on_tx_announcement(txid, peer).unwrap();
    tracker.get_next_request();
    tracker.mark_requested(txid, peer).unwrap();

    // Reject the transaction
    tracker.on_tx_rejected(txid, peer);

    // Should not be in flight anymore
    assert_eq!(tracker.get_peer_in_flight_count(&peer), 0);

    // Should not request again soon
    assert!(!tracker.should_request_tx(&txid));

    // Another announcement should be ignored
    assert!(!tracker.on_tx_announcement(txid, test_peer(2)).unwrap());
}

#[test]
fn test_orphan_pool_basic() {
    let mut pool = OrphanPool::new();
    let tx = create_test_tx();
    let txid = tx.compute_txid();
    let peer = test_peer(1);
    let missing_parents = vec![Txid::from_byte_array([0u8; 32])].into_iter().collect();

    // Add orphan
    assert!(pool.add_orphan(tx.clone(), peer, missing_parents).unwrap());
    assert!(pool.has_orphan(&txid));

    // Get stats
    let stats = pool.get_stats();
    assert_eq!(stats.current_orphans, 1);
    assert_eq!(stats.orphans_received, 1);

    // Remove orphan
    let entry = pool.remove_orphan(&txid);
    assert!(entry.is_some());
    assert!(!pool.has_orphan(&txid));
}

#[test]
fn test_orphan_parent_resolution() {
    let mut pool = OrphanPool::new();
    let parent_txid = Txid::from_byte_array([0u8; 32]);
    let peer = test_peer(1);

    // Create multiple orphans waiting for same parent
    let mut orphan_txids = Vec::new();
    for i in 0..3 {
        let mut tx = create_test_tx();
        tx.output[0].value = Amount::from_sat(i * 1000);
        let txid = tx.compute_txid();
        orphan_txids.push(txid);

        let missing_parents = vec![parent_txid].into_iter().collect();
        pool.add_orphan(tx, peer, missing_parents).unwrap();
    }

    // All should be waiting for parent
    let waiting = pool.get_orphans_for_parent(&parent_txid);
    assert_eq!(waiting.len(), 3);

    // Parent arrives - remove orphans
    let resolved = pool.remove_orphans_for_parent(&parent_txid);
    assert_eq!(resolved.len(), 3);

    // Pool should be empty
    assert_eq!(pool.get_stats().current_orphans, 0);
}

#[test]
fn test_orphan_expiration() {
    let mut pool = OrphanPool::new();
    let tx = create_test_tx();
    let peer = test_peer(1);
    let missing_parents = HashSet::new();

    // Add orphan
    pool.add_orphan(tx, peer, missing_parents).unwrap();
    assert_eq!(pool.get_stats().current_orphans, 1);

    // Process orphans immediately - should not expire
    let (expired, _) = pool.process_orphans();
    assert_eq!(expired.len(), 0);
    assert_eq!(pool.get_stats().current_orphans, 1);

    // Note: Can't test actual expiration without mocking time
    // In production, orphans expire after MAX_ORPHAN_AGE (20 minutes)
}

#[test]
fn test_orphan_peer_limits() {
    let mut pool = OrphanPool::new();
    let peer = test_peer(1);

    // Add maximum orphans from one peer (10)
    for i in 0..10 {
        let mut tx = create_test_tx();
        tx.output[0].value = Amount::from_sat(i * 1000);
        let missing_parents = HashSet::new();
        assert!(pool.add_orphan(tx, peer, missing_parents).unwrap());
    }

    // Try to add one more - should fail
    let tx = create_test_tx();
    let missing_parents = HashSet::new();
    assert!(pool.add_orphan(tx, peer, missing_parents).is_err());

    // Different peer should work
    let tx = create_test_tx();
    let missing_parents = HashSet::new();
    assert!(pool.add_orphan(tx, test_peer(2), missing_parents).unwrap());
}

#[test]
fn test_orphan_eviction() {
    let mut pool = OrphanPool::new();

    // Add many orphans to trigger eviction
    let mut added_txids = Vec::new();
    for i in 0..120 {
        let mut tx = create_test_tx();
        tx.output[0].value = Amount::from_sat(i * 1000);
        let txid = tx.compute_txid();
        let peer = test_peer((i % 20) as u8 + 1); // Distribute across peers
        let missing_parents = HashSet::new();

        if pool.add_orphan(tx, peer, missing_parents).is_ok() {
            added_txids.push(txid);
        }
    }

    // Should have evicted some to stay under limit
    let stats = pool.get_stats();
    assert!(stats.current_orphans <= 100); // MAX_ORPHAN_TRANSACTIONS
    assert!(stats.orphans_evicted > 0);
}

#[test]
fn test_clear_peer_orphans() {
    let mut pool = OrphanPool::new();
    let peer1 = test_peer(1);
    let peer2 = test_peer(2);

    // Add orphans from two peers
    for i in 0..5u32 {
        let mut tx = create_test_tx();
        tx.output[0].value = Amount::from_sat(((i + 1) * 1000) as u64); // Ensure unique value
        tx.lock_time = bitcoin::absolute::LockTime::from_height(i).unwrap(); // Make unique
        pool.add_orphan(tx, peer1, HashSet::new()).unwrap();

        let mut tx = create_test_tx();
        tx.output[0].value = Amount::from_sat(((i + 1) * 2000) as u64); // Ensure unique value
        tx.lock_time = bitcoin::absolute::LockTime::from_height(i + 100).unwrap(); // Make unique
        pool.add_orphan(tx, peer2, HashSet::new()).unwrap();
    }

    assert_eq!(pool.get_stats().current_orphans, 10);

    // Clear orphans from peer1
    let cleared = pool.clear_peer_orphans(&peer1);
    assert_eq!(cleared, 5);
    assert_eq!(pool.get_stats().current_orphans, 5);

    // Clear orphans from peer2
    let cleared = pool.clear_peer_orphans(&peer2);
    assert_eq!(cleared, 5);
    assert_eq!(pool.get_stats().current_orphans, 0);
}

#[test]
fn test_deduplication_stats() {
    let mut tracker = TxRequestTracker::new();
    let tx = create_test_tx();
    let txid = tx.compute_txid();

    // Multiple announcements from different peers
    for i in 1..6 {
        let peer = test_peer(i);
        tracker.on_tx_announcement(txid, peer).unwrap();
    }

    let stats = tracker.get_stats();
    assert_eq!(stats.announcements_received, 5);
    // Duplicates aren't counted when transaction is just announced but not in-flight/seen
    assert_eq!(stats.duplicate_announcements, 0);
    assert_eq!(stats.requests_deduplicated, 0); // Haven't requested yet

    // Request the transaction
    if let Some((_, peer)) = tracker.get_next_request() {
        tracker.mark_requested(txid, peer).unwrap();
    }

    let stats = tracker.get_stats();
    assert_eq!(stats.requests_sent, 1);
}
