use anyhow::{bail, Result};
use bitcoin::{Transaction, Txid};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Maximum number of orphan transactions to keep
const MAX_ORPHAN_TRANSACTIONS: usize = 100;

/// Maximum total size of orphan transactions in bytes
const MAX_ORPHAN_SIZE: usize = 5_000_000; // 5MB

/// Maximum time to keep an orphan transaction
const MAX_ORPHAN_AGE: Duration = Duration::from_secs(1200); // 20 minutes

/// Maximum number of orphans from a single peer
const MAX_ORPHANS_PER_PEER: usize = 10;

/// Orphan transaction entry
#[derive(Debug, Clone)]
pub struct OrphanEntry {
    /// The orphan transaction
    pub tx: Transaction,
    /// Peer that sent this orphan
    pub from_peer: std::net::SocketAddr,
    /// Time when the orphan was added
    pub added_at: Instant,
    /// Size of the transaction in bytes
    pub size: usize,
    /// Missing parent transactions
    pub missing_parents: HashSet<Txid>,
    /// Number of times we've requested missing parents
    pub parent_request_count: usize,
}

/// Statistics for orphan pool
#[derive(Debug, Clone, Default)]
pub struct OrphanPoolStats {
    /// Total orphans received
    pub orphans_received: usize,
    /// Orphans that were eventually accepted
    pub orphans_accepted: usize,
    /// Orphans that expired
    pub orphans_expired: usize,
    /// Orphans evicted due to size limit
    pub orphans_evicted: usize,
    /// Current number of orphans
    pub current_orphans: usize,
    /// Current total size
    pub current_size: usize,
}

/// Pool for managing orphan transactions
pub struct OrphanPool {
    /// Orphan transactions by txid
    orphans: HashMap<Txid, OrphanEntry>,

    /// Map from missing parent to orphans waiting for it
    orphans_by_parent: HashMap<Txid, HashSet<Txid>>,

    /// Orphans from each peer
    orphans_by_peer: HashMap<std::net::SocketAddr, HashSet<Txid>>,

    /// Queue for eviction (oldest first)
    eviction_queue: VecDeque<(Txid, Instant)>,

    /// Total size of all orphans
    total_size: usize,

    /// Statistics
    stats: OrphanPoolStats,
}

impl OrphanPool {
    /// Create a new orphan pool
    pub fn new() -> Self {
        Self {
            orphans: HashMap::new(),
            orphans_by_parent: HashMap::new(),
            orphans_by_peer: HashMap::new(),
            eviction_queue: VecDeque::new(),
            total_size: 0,
            stats: OrphanPoolStats::default(),
        }
    }

    /// Add an orphan transaction
    pub fn add_orphan(
        &mut self,
        tx: Transaction,
        from_peer: std::net::SocketAddr,
        missing_parents: HashSet<Txid>,
    ) -> Result<bool> {
        let txid = tx.compute_txid();

        // Check if already have this orphan
        if self.orphans.contains_key(&txid) {
            debug!("Already have orphan transaction {}", txid);
            return Ok(false);
        }

        // Check peer limit
        let peer_count = self
            .orphans_by_peer
            .get(&from_peer)
            .map(|set| set.len())
            .unwrap_or(0);

        if peer_count >= MAX_ORPHANS_PER_PEER {
            warn!(
                "Peer {} has too many orphans ({}), rejecting",
                from_peer, peer_count
            );
            bail!("Too many orphans from peer");
        }

        let tx_size = bitcoin::consensus::encode::serialize(&tx).len();

        // Check if adding this would exceed size limit
        if self.total_size + tx_size > MAX_ORPHAN_SIZE {
            // Evict oldest orphans to make room
            self.evict_to_make_room(tx_size);
        }

        // Check if we still exceed the count limit
        if self.orphans.len() >= MAX_ORPHAN_TRANSACTIONS {
            // Evict oldest orphan
            self.evict_oldest();
        }

        // Create orphan entry
        let entry = OrphanEntry {
            tx: tx.clone(),
            from_peer,
            added_at: Instant::now(),
            size: tx_size,
            missing_parents: missing_parents.clone(),
            parent_request_count: 0,
        };

        // Add to orphan pool
        self.orphans.insert(txid, entry);
        self.total_size += tx_size;

        // Update mappings
        for parent_txid in &missing_parents {
            self.orphans_by_parent
                .entry(*parent_txid)
                .or_default()
                .insert(txid);
        }

        self.orphans_by_peer
            .entry(from_peer)
            .or_default()
            .insert(txid);

        // Add to eviction queue
        self.eviction_queue.push_back((txid, Instant::now()));

        // Update stats
        self.stats.orphans_received += 1;
        self.stats.current_orphans = self.orphans.len();
        self.stats.current_size = self.total_size;

        info!(
            "Added orphan {} from {} (missing {} parents, pool size: {})",
            txid,
            from_peer,
            missing_parents.len(),
            self.orphans.len()
        );

        Ok(true)
    }

    /// Get orphans that were waiting for a specific parent
    pub fn get_orphans_for_parent(&self, parent_txid: &Txid) -> Vec<Transaction> {
        if let Some(orphan_txids) = self.orphans_by_parent.get(parent_txid) {
            orphan_txids
                .iter()
                .filter_map(|txid| self.orphans.get(txid).map(|e| e.tx.clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Remove orphans that were waiting for a parent (after parent arrives)
    pub fn remove_orphans_for_parent(&mut self, parent_txid: &Txid) -> Vec<Transaction> {
        let mut removed_txs = Vec::new();

        if let Some(orphan_txids) = self.orphans_by_parent.remove(parent_txid) {
            for orphan_txid in orphan_txids {
                if let Some(entry) = self.orphans.get_mut(&orphan_txid) {
                    // Remove this parent from missing list
                    entry.missing_parents.remove(parent_txid);

                    // If no more missing parents, this orphan can be processed
                    if entry.missing_parents.is_empty() {
                        if let Some(entry) = self.remove_orphan(&orphan_txid) {
                            removed_txs.push(entry.tx);
                            self.stats.orphans_accepted += 1;
                        }
                    }
                }
            }
        }

        removed_txs
    }

    /// Remove a specific orphan
    pub fn remove_orphan(&mut self, txid: &Txid) -> Option<OrphanEntry> {
        if let Some(entry) = self.orphans.remove(txid) {
            // Update size
            self.total_size = self.total_size.saturating_sub(entry.size);

            // Remove from peer mapping
            if let Some(peer_set) = self.orphans_by_peer.get_mut(&entry.from_peer) {
                peer_set.remove(txid);
                if peer_set.is_empty() {
                    self.orphans_by_peer.remove(&entry.from_peer);
                }
            }

            // Remove from parent mappings
            for parent_txid in &entry.missing_parents {
                if let Some(parent_set) = self.orphans_by_parent.get_mut(parent_txid) {
                    parent_set.remove(txid);
                    if parent_set.is_empty() {
                        self.orphans_by_parent.remove(parent_txid);
                    }
                }
            }

            // Update stats
            self.stats.current_orphans = self.orphans.len();
            self.stats.current_size = self.total_size;

            Some(entry)
        } else {
            None
        }
    }

    /// Expire old orphans
    pub fn expire_old_orphans(&mut self) -> Vec<Txid> {
        let now = Instant::now();
        let mut expired = Vec::new();

        // Check from the front of the queue (oldest first)
        while let Some(&(txid, added_at)) = self.eviction_queue.front() {
            if now.duration_since(added_at) > MAX_ORPHAN_AGE {
                self.eviction_queue.pop_front();
                if self.remove_orphan(&txid).is_some() {
                    expired.push(txid);
                    self.stats.orphans_expired += 1;
                    debug!("Expired orphan {} (age exceeded)", txid);
                }
            } else {
                // Queue is ordered, so we can stop here
                break;
            }
        }

        if !expired.is_empty() {
            info!("Expired {} old orphan transactions", expired.len());
        }

        expired
    }

    /// Evict orphans to make room for new ones
    fn evict_to_make_room(&mut self, needed_size: usize) {
        let target_size = MAX_ORPHAN_SIZE.saturating_sub(needed_size);

        while self.total_size > target_size && !self.eviction_queue.is_empty() {
            if let Some((txid, _)) = self.eviction_queue.pop_front() {
                if self.remove_orphan(&txid).is_some() {
                    self.stats.orphans_evicted += 1;
                    debug!("Evicted orphan {} to make room", txid);
                }
            }
        }
    }

    /// Evict the oldest orphan
    fn evict_oldest(&mut self) {
        if let Some((txid, _)) = self.eviction_queue.pop_front() {
            if self.remove_orphan(&txid).is_some() {
                self.stats.orphans_evicted += 1;
                debug!("Evicted oldest orphan {}", txid);
            }
        }
    }

    /// Get missing parents that we should request
    pub fn get_missing_parents_to_request(&mut self) -> Vec<Txid> {
        let mut parents_to_request = HashSet::new();
        let max_requests = 10; // Limit number of parent requests

        for entry in self.orphans.values_mut() {
            // Only request parents we haven't requested too many times
            if entry.parent_request_count < 3 {
                for parent in &entry.missing_parents {
                    parents_to_request.insert(*parent);
                    if parents_to_request.len() >= max_requests {
                        break;
                    }
                }
                entry.parent_request_count += 1;
            }

            if parents_to_request.len() >= max_requests {
                break;
            }
        }

        parents_to_request.into_iter().collect()
    }

    /// Check if we have an orphan
    pub fn has_orphan(&self, txid: &Txid) -> bool {
        self.orphans.contains_key(txid)
    }

    /// Get orphan statistics
    pub fn get_stats(&self) -> OrphanPoolStats {
        self.stats.clone()
    }

    /// Clear all orphans from a specific peer (e.g., on disconnect)
    pub fn clear_peer_orphans(&mut self, peer: &std::net::SocketAddr) -> usize {
        let mut removed = 0;

        if let Some(orphan_txids) = self.orphans_by_peer.remove(peer) {
            for txid in orphan_txids {
                if self.remove_orphan(&txid).is_some() {
                    removed += 1;
                }
            }
        }

        if removed > 0 {
            info!(
                "Removed {} orphans from disconnected peer {}",
                removed, peer
            );
        }

        removed
    }

    /// Clear all orphans
    pub fn clear(&mut self) {
        self.orphans.clear();
        self.orphans_by_parent.clear();
        self.orphans_by_peer.clear();
        self.eviction_queue.clear();
        self.total_size = 0;
        self.stats.current_orphans = 0;
        self.stats.current_size = 0;
    }

    /// Process orphans periodically (maintenance)
    pub fn process_orphans(&mut self) -> (Vec<Txid>, Vec<Txid>) {
        // Expire old orphans
        let expired = self.expire_old_orphans();

        // Get parents we should request
        let parents_to_request = self.get_missing_parents_to_request();

        (expired, parents_to_request)
    }
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, TxIn, TxOut};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_tx(inputs: Vec<OutPoint>) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs
                .into_iter()
                .map(|outpoint| TxIn {
                    previous_output: outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    fn test_peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333)
    }

    #[test]
    fn test_orphan_pool_basic() {
        let mut pool = OrphanPool::new();

        // Create an orphan transaction
        let tx = create_test_tx(vec![OutPoint::default()]);
        let txid = tx.compute_txid();
        let missing_parents = vec![Txid::from_byte_array([0u8; 32])].into_iter().collect();

        // Add orphan
        assert!(pool
            .add_orphan(tx.clone(), test_peer(), missing_parents)
            .unwrap());
        assert!(pool.has_orphan(&txid));
        assert_eq!(pool.get_stats().current_orphans, 1);

        // Try to add same orphan again
        assert!(!pool.add_orphan(tx, test_peer(), HashSet::new()).unwrap());

        // Remove orphan
        assert!(pool.remove_orphan(&txid).is_some());
        assert!(!pool.has_orphan(&txid));
        assert_eq!(pool.get_stats().current_orphans, 0);
    }

    #[test]
    fn test_orphan_parent_tracking() {
        let mut pool = OrphanPool::new();

        // Create a specific parent txid
        let parent_txid = Txid::from_byte_array([1u8; 32]);

        // Create two different transactions that depend on the parent
        let tx1 = create_test_tx(vec![OutPoint {
            txid: parent_txid,
            vout: 0,
        }]);
        let tx2 = create_test_tx(vec![OutPoint {
            txid: parent_txid,
            vout: 1,
        }]);

        let missing_parents: HashSet<Txid> = vec![parent_txid].into_iter().collect();

        // Add two orphans waiting for same parent
        pool.add_orphan(tx1.clone(), test_peer(), missing_parents.clone())
            .unwrap();
        pool.add_orphan(tx2.clone(), test_peer(), missing_parents)
            .unwrap();

        // Get orphans for parent
        let orphans = pool.get_orphans_for_parent(&parent_txid);
        assert_eq!(orphans.len(), 2);

        // Remove orphans when parent arrives
        let removed = pool.remove_orphans_for_parent(&parent_txid);
        assert_eq!(removed.len(), 2);
        assert_eq!(pool.get_stats().current_orphans, 0);
    }

    #[test]
    fn test_peer_limit() {
        let mut pool = OrphanPool::new();
        let peer = test_peer();

        // Add maximum orphans from one peer
        for i in 0..MAX_ORPHANS_PER_PEER {
            let tx = create_test_tx(vec![OutPoint {
                txid: Txid::from_byte_array([0u8; 32]),
                vout: i as u32,
            }]);
            pool.add_orphan(tx, peer, HashSet::new()).unwrap();
        }

        // Try to add one more - should fail
        let tx = create_test_tx(vec![OutPoint::null()]);
        assert!(pool.add_orphan(tx, peer, HashSet::new()).is_err());

        // Clear peer orphans
        let removed = pool.clear_peer_orphans(&peer);
        assert_eq!(removed, MAX_ORPHANS_PER_PEER);
        assert_eq!(pool.get_stats().current_orphans, 0);
    }
}
