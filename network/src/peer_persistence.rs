use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Persistent peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentPeer {
    pub addr: SocketAddr,
    pub last_seen: u64,
    pub last_success: Option<u64>,
    pub attempts: u32,
    pub score: i32,
    pub services: u64,
    pub version: Option<i32>,
    pub user_agent: Option<String>,
    pub banned_until: Option<u64>,
}

impl PersistentPeer {
    /// Create a new persistent peer entry
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            last_seen: current_timestamp(),
            last_success: None,
            attempts: 0,
            score: 0,
            services: 0,
            version: None,
            user_agent: None,
            banned_until: None,
        }
    }

    /// Update last successful connection
    pub fn mark_success(&mut self) {
        self.last_success = Some(current_timestamp());
        self.last_seen = current_timestamp();
        self.attempts = 0;
    }

    /// Update failed connection attempt
    pub fn mark_failure(&mut self) {
        self.attempts += 1;
        self.last_seen = current_timestamp();
    }

    /// Check if peer is banned
    pub fn is_banned(&self) -> bool {
        if let Some(until) = self.banned_until {
            current_timestamp() < until
        } else {
            false
        }
    }

    /// Ban peer until specified timestamp
    pub fn ban_until(&mut self, timestamp: u64) {
        self.banned_until = Some(timestamp);
    }

    /// Clear ban
    pub fn unban(&mut self) {
        self.banned_until = None;
    }
}

/// Peer database for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDatabase {
    pub version: u32,
    pub peers: HashMap<String, PersistentPeer>,
    pub last_updated: u64,
}

impl Default for PeerDatabase {
    fn default() -> Self {
        Self {
            version: 1,
            peers: HashMap::new(),
            last_updated: current_timestamp(),
        }
    }
}

/// Manages peer persistence to disk
pub struct PeerPersistence {
    path: PathBuf,
    database: PeerDatabase,
}

impl PeerPersistence {
    /// Create new peer persistence manager
    pub fn new(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("peers.json");

        // Load existing database or create new
        let database = if path.exists() {
            match Self::load_from_file(&path) {
                Ok(db) => {
                    info!("Loaded {} peers from persistence", db.peers.len());
                    db
                }
                Err(e) => {
                    warn!("Failed to load peer database: {}, starting fresh", e);
                    PeerDatabase::default()
                }
            }
        } else {
            info!("No peer database found, starting fresh");
            PeerDatabase::default()
        };

        Ok(Self { path, database })
    }

    /// Load database from file
    fn load_from_file(path: &Path) -> Result<PeerDatabase> {
        let data = fs::read_to_string(path)?;
        let database = serde_json::from_str(&data)?;
        Ok(database)
    }

    /// Save database to file
    pub fn save(&mut self) -> Result<()> {
        self.database.last_updated = current_timestamp();
        let data = serde_json::to_string_pretty(&self.database)?;
        fs::write(&self.path, data)?;
        debug!("Saved {} peers to disk", self.database.peers.len());
        Ok(())
    }

    /// Add or update a peer
    pub fn upsert_peer(&mut self, peer: PersistentPeer) -> Result<()> {
        let key = peer.addr.to_string();
        self.database.peers.insert(key, peer);
        Ok(())
    }

    /// Get a peer by address
    pub fn get_peer(&self, addr: &SocketAddr) -> Option<&PersistentPeer> {
        self.database.peers.get(&addr.to_string())
    }

    /// Get mutable peer by address
    pub fn get_peer_mut(&mut self, addr: &SocketAddr) -> Option<&mut PersistentPeer> {
        self.database.peers.get_mut(&addr.to_string())
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, addr: &SocketAddr) -> Option<PersistentPeer> {
        self.database.peers.remove(&addr.to_string())
    }

    /// Get all peers
    pub fn get_all_peers(&self) -> Vec<&PersistentPeer> {
        self.database.peers.values().collect()
    }

    /// Get peers for connection attempts
    pub fn get_connectable_peers(&self, max_count: usize) -> Vec<PersistentPeer> {
        let mut peers: Vec<PersistentPeer> = self
            .database
            .peers
            .values()
            .filter(|p| !p.is_banned())
            .filter(|p| p.attempts < 5) // Skip peers with too many failures
            .cloned()
            .collect();

        // Sort by score and last success
        peers.sort_by_key(|p| (-p.score, p.last_success.unwrap_or(0)));
        peers.truncate(max_count);
        peers
    }

    /// Clean up old peers
    pub fn cleanup_old_peers(&mut self, max_age_days: u64) -> usize {
        let cutoff = current_timestamp() - (max_age_days * 24 * 3600);
        let initial_count = self.database.peers.len();

        self.database.peers.retain(|_, peer| {
            // Keep recently seen peers
            if peer.last_seen > cutoff {
                return true;
            }

            // Keep peers with good scores
            if peer.score > 50 {
                return true;
            }

            // Keep peers we successfully connected to recently
            if let Some(last_success) = peer.last_success {
                if last_success > cutoff {
                    return true;
                }
            }

            false
        });

        let removed = initial_count - self.database.peers.len();
        if removed > 0 {
            info!("Cleaned up {} old peers", removed);
        }
        removed
    }

    /// Import peers from another source
    pub fn import_peers(&mut self, peers: Vec<SocketAddr>) -> usize {
        let mut imported = 0;
        for addr in peers {
            if !self.database.peers.contains_key(&addr.to_string()) {
                self.upsert_peer(PersistentPeer::new(addr)).ok();
                imported += 1;
            }
        }
        if imported > 0 {
            info!("Imported {} new peers", imported);
        }
        imported
    }

    /// Export connectable peers
    pub fn export_peers(&self, max_count: usize) -> Vec<SocketAddr> {
        self.get_connectable_peers(max_count)
            .into_iter()
            .map(|p| p.addr)
            .collect()
    }
}

/// Get current timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tempfile::TempDir;

    #[test]
    fn test_peer_persistence() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let mut persistence = PeerPersistence::new(temp_dir.path())?;

        // Add some peers
        let addr1 = SocketAddr::from_str("127.0.0.1:8333")?;
        let addr2 = SocketAddr::from_str("192.168.1.1:8333")?;

        let mut peer1 = PersistentPeer::new(addr1);
        peer1.score = 50;
        peer1.mark_success();

        let mut peer2 = PersistentPeer::new(addr2);
        peer2.score = -10;
        peer2.mark_failure();

        persistence.upsert_peer(peer1)?;
        persistence.upsert_peer(peer2)?;

        // Save to disk
        persistence.save()?;

        // Load from disk
        let persistence2 = PeerPersistence::new(temp_dir.path())?;
        assert_eq!(persistence2.database.peers.len(), 2);

        // Check peers were loaded correctly
        let loaded_peer1 = persistence2.get_peer(&addr1).unwrap();
        assert_eq!(loaded_peer1.score, 50);
        assert!(loaded_peer1.last_success.is_some());

        let loaded_peer2 = persistence2.get_peer(&addr2).unwrap();
        assert_eq!(loaded_peer2.score, -10);
        assert_eq!(loaded_peer2.attempts, 1);

        Ok(())
    }

    #[test]
    fn test_peer_banning() -> Result<()> {
        let mut peer = PersistentPeer::new(SocketAddr::from_str("127.0.0.1:8333")?);

        // Initially not banned
        assert!(!peer.is_banned());

        // Ban for 1 hour
        let ban_until = current_timestamp() + 3600;
        peer.ban_until(ban_until);
        assert!(peer.is_banned());

        // Unban
        peer.unban();
        assert!(!peer.is_banned());

        Ok(())
    }

    #[test]
    fn test_connectable_peers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let mut persistence = PeerPersistence::new(temp_dir.path())?;

        // Add peers with different scores
        for i in 0..10 {
            let addr = SocketAddr::from_str(&format!("192.168.1.{}:8333", i))?;
            let mut peer = PersistentPeer::new(addr);
            peer.score = i * 10;
            persistence.upsert_peer(peer)?;
        }

        // Get top 5 connectable peers
        let connectable = persistence.get_connectable_peers(5);
        assert_eq!(connectable.len(), 5);

        // Should be sorted by score (highest first)
        assert!(connectable[0].score >= connectable[1].score);

        Ok(())
    }
}
