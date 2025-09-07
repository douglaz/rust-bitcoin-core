use anyhow::{bail, Result};
use bitcoin::p2p::ServiceFlags;
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Maximum addresses in new table
const NEW_BUCKET_COUNT: usize = 1024;
const NEW_BUCKET_SIZE: usize = 64;
const NEW_TABLE_SIZE: usize = NEW_BUCKET_COUNT * NEW_BUCKET_SIZE;

/// Maximum addresses in tried table
const TRIED_BUCKET_COUNT: usize = 256;
const TRIED_BUCKET_SIZE: usize = 64;
const TRIED_TABLE_SIZE: usize = TRIED_BUCKET_COUNT * TRIED_BUCKET_SIZE;

/// Maximum addresses to return in GetAddr
const MAX_GETADDR_RESPONSE: usize = 1000;

/// Address information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddrInfo {
    pub addr: SocketAddr,
    pub source: SocketAddr,
    pub services: u64, // Store as u64 for serialization
    pub timestamp: u64,
    pub last_try: Option<u64>,
    pub last_success: Option<u64>,
    pub attempts: u32,
    pub ref_count: u32,
    pub in_tried: bool,
    pub random_pos: u32,
}

impl AddrInfo {
    pub fn new(addr: SocketAddr, source: SocketAddr, services: ServiceFlags) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            addr,
            source,
            services: services.to_u64(),
            timestamp,
            last_try: None,
            last_success: None,
            attempts: 0,
            ref_count: 0,
            in_tried: false,
            random_pos: rand::random(),
        }
    }

    /// Calculate chance of being returned in GetAddr
    pub fn get_selection_chance(&self, now: u64) -> f64 {
        let mut chance = 1.0;

        // Reduce chance for recently tried addresses
        if let Some(last_try) = self.last_try {
            let hours_ago = (now - last_try) / 3600;
            if hours_ago < 1 {
                chance *= 0.01;
            } else if hours_ago < 24 {
                chance *= 0.1;
            }
        }

        // Increase chance for recently seen addresses
        let age_hours = (now - self.timestamp) / 3600;
        if age_hours < 1 {
            chance *= 2.0;
        } else if age_hours > 24 * 7 {
            chance *= 0.5;
        }

        // Reduce chance for addresses with many failed attempts
        if self.attempts > 0 && self.last_success.is_none() {
            chance *= 0.5_f64.powi(self.attempts.min(8) as i32);
        }

        chance
    }

    /// Check if address is terrible (should be removed)
    pub fn is_terrible(&self, now: u64) -> bool {
        // Never remove if recently tried
        if let Some(last_try) = self.last_try {
            if now - last_try < 60 {
                return false;
            }
        }

        // Remove if too old and never succeeded
        if self.last_success.is_none() {
            let age_days = (now - self.timestamp) / 86400;
            if age_days > 30 {
                return true;
            }

            // Remove if too many failed attempts
            if self.attempts >= 10 {
                return true;
            }
        }

        // Remove if last success was too long ago
        if let Some(last_success) = self.last_success {
            let days_since_success = (now - last_success) / 86400;
            if days_since_success > 90 {
                return true;
            }
        }

        false
    }
}

/// Bucket in address table
#[derive(Debug, Clone, Default)]
struct AddrBucket {
    addrs: Vec<AddrInfo>,
}

impl AddrBucket {
    fn add(&mut self, info: AddrInfo, max_size: usize) -> bool {
        // Check if already exists
        if self.addrs.iter().any(|a| a.addr == info.addr) {
            return false;
        }

        // If bucket is full, randomly evict
        if self.addrs.len() >= max_size {
            let evict_idx = rand::random::<usize>() % self.addrs.len();
            self.addrs.remove(evict_idx);
        }

        self.addrs.push(info);
        true
    }

    fn remove(&mut self, addr: &SocketAddr) -> bool {
        if let Some(pos) = self.addrs.iter().position(|a| &a.addr == addr) {
            self.addrs.remove(pos);
            true
        } else {
            false
        }
    }

    fn find(&self, addr: &SocketAddr) -> Option<&AddrInfo> {
        self.addrs.iter().find(|a| &a.addr == addr)
    }

    fn find_mut(&mut self, addr: &SocketAddr) -> Option<&mut AddrInfo> {
        self.addrs.iter_mut().find(|a| &a.addr == addr)
    }
}

/// Address manager with new/tried tables
pub struct AddrManager {
    /// Network
    network: Network,

    /// New addresses (not yet tried)
    new_table: Vec<AddrBucket>,

    /// Tried addresses (successfully connected)
    tried_table: Vec<AddrBucket>,

    /// Map from address to location in tables
    addr_index: HashMap<SocketAddr, (bool, usize)>, // (in_tried, bucket_id)

    /// Random key for bucket selection
    key: [u8; 32],

    /// Statistics
    stats: AddrStats,
}

/// Address manager statistics
#[derive(Debug, Clone, Default)]
pub struct AddrStats {
    pub new_count: usize,
    pub tried_count: usize,
    pub total_count: usize,
}

impl AddrManager {
    pub fn new(network: Network) -> Self {
        let mut new_table = Vec::with_capacity(NEW_BUCKET_COUNT);
        let mut tried_table = Vec::with_capacity(TRIED_BUCKET_COUNT);

        for _ in 0..NEW_BUCKET_COUNT {
            new_table.push(AddrBucket::default());
        }

        for _ in 0..TRIED_BUCKET_COUNT {
            tried_table.push(AddrBucket::default());
        }

        let mut key = [0u8; 32];
        for byte in &mut key {
            *byte = rand::random();
        }

        Self {
            network,
            new_table,
            tried_table,
            addr_index: HashMap::new(),
            key,
            stats: AddrStats::default(),
        }
    }

    /// Calculate bucket for an address
    fn calculate_bucket(&self, addr: &SocketAddr, in_tried: bool) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        addr.hash(&mut hasher);
        self.key.hash(&mut hasher);
        in_tried.hash(&mut hasher);

        let hash = hasher.finish();

        if in_tried {
            (hash as usize) % TRIED_BUCKET_COUNT
        } else {
            (hash as usize) % NEW_BUCKET_COUNT
        }
    }

    /// Add a new address
    pub fn add(&mut self, addr: SocketAddr, source: SocketAddr, services: ServiceFlags) -> bool {
        // Don't add our own address
        if self.is_local(&addr) {
            return false;
        }

        // Check if already exists
        if self.addr_index.contains_key(&addr) {
            // Update existing entry
            if let Some((in_tried, bucket_id)) = self.addr_index.get(&addr) {
                let bucket = if *in_tried {
                    &mut self.tried_table[*bucket_id]
                } else {
                    &mut self.new_table[*bucket_id]
                };

                if let Some(info) = bucket.find_mut(&addr) {
                    info.timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    info.ref_count += 1;
                }
            }
            return false;
        }

        let info = AddrInfo::new(addr, source, services);
        let bucket_id = self.calculate_bucket(&addr, false);

        if self.new_table[bucket_id].add(info, NEW_BUCKET_SIZE) {
            self.addr_index.insert(addr, (false, bucket_id));
            self.stats.new_count += 1;
            self.stats.total_count += 1;
            debug!("Added new address {} to bucket {}", addr, bucket_id);
            true
        } else {
            false
        }
    }

    /// Mark an address as tried (successfully connected)
    pub fn mark_good(&mut self, addr: SocketAddr) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some((in_tried, bucket_id)) = self.addr_index.get(&addr).cloned() {
            if in_tried {
                // Already in tried, just update
                if let Some(info) = self.tried_table[bucket_id].find_mut(&addr) {
                    info.last_success = Some(now);
                    info.last_try = Some(now);
                    info.attempts = 0;
                }
            } else {
                // Move from new to tried
                if let Some(pos) = self.new_table[bucket_id]
                    .addrs
                    .iter()
                    .position(|a| a.addr == addr)
                {
                    let mut info = self.new_table[bucket_id].addrs.remove(pos);
                    info.last_success = Some(now);
                    info.last_try = Some(now);
                    info.attempts = 0;
                    info.in_tried = true;

                    let tried_bucket_id = self.calculate_bucket(&addr, true);

                    if self.tried_table[tried_bucket_id].add(info, TRIED_BUCKET_SIZE) {
                        self.addr_index.insert(addr, (true, tried_bucket_id));
                        self.stats.new_count -= 1;
                        self.stats.tried_count += 1;
                        info!("Moved {} to tried table", addr);
                    }
                }
            }
        }
    }

    /// Mark an address as attempted
    pub fn mark_attempt(&mut self, addr: SocketAddr) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some((in_tried, bucket_id)) = self.addr_index.get(&addr) {
            let bucket = if *in_tried {
                &mut self.tried_table[*bucket_id]
            } else {
                &mut self.new_table[*bucket_id]
            };

            if let Some(info) = bucket.find_mut(&addr) {
                info.last_try = Some(now);
                info.attempts += 1;
            }
        }
    }

    /// Select random addresses for connection
    pub fn select(&self, count: usize, only_tried: bool) -> Vec<AddrInfo> {
        let mut selected = Vec::new();
        let mut tried_buckets: Vec<usize> = (0..TRIED_BUCKET_COUNT).collect();
        let mut new_buckets: Vec<usize> = (0..NEW_BUCKET_COUNT).collect();

        // Shuffle buckets
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        tried_buckets.shuffle(&mut rng);
        new_buckets.shuffle(&mut rng);

        // Try to get from tried table first
        for bucket_id in tried_buckets {
            if selected.len() >= count {
                break;
            }

            let bucket = &self.tried_table[bucket_id];
            for info in &bucket.addrs {
                if selected.len() >= count {
                    break;
                }
                selected.push(info.clone());
            }
        }

        // If not enough and not only_tried, get from new table
        if !only_tried {
            for bucket_id in new_buckets {
                if selected.len() >= count {
                    break;
                }

                let bucket = &self.new_table[bucket_id];
                for info in &bucket.addrs {
                    if selected.len() >= count {
                        break;
                    }
                    selected.push(info.clone());
                }
            }
        }

        selected
    }

    /// Get addresses for GetAddr response
    pub fn get_addr(&self, max_count: usize) -> Vec<(u32, bitcoin::p2p::address::Address)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut candidates = Vec::new();

        // Collect all addresses with their selection chance
        for bucket in &self.tried_table {
            for info in &bucket.addrs {
                let chance = info.get_selection_chance(now);
                candidates.push((info.clone(), chance));
            }
        }

        for bucket in &self.new_table {
            for info in &bucket.addrs {
                let chance = info.get_selection_chance(now);
                candidates.push((info.clone(), chance));
            }
        }

        // Sort by chance (descending)
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Take top addresses
        candidates
            .into_iter()
            .take(max_count.min(MAX_GETADDR_RESPONSE))
            .map(|(info, _)| {
                let timestamp = info.timestamp as u32;

                // Convert IP address to [u16; 8] format
                let address = match info.addr.ip() {
                    IpAddr::V4(ipv4) => {
                        let octets = ipv4.octets();
                        let mut addr = [0u16; 8];
                        addr[5] = 0xffff;
                        addr[6] = u16::from_be_bytes([octets[0], octets[1]]);
                        addr[7] = u16::from_be_bytes([octets[2], octets[3]]);
                        addr
                    }
                    IpAddr::V6(ipv6) => {
                        let segments = ipv6.segments();
                        segments
                    }
                };

                let addr = bitcoin::p2p::address::Address {
                    services: ServiceFlags::from(info.services),
                    address,
                    port: info.addr.port(),
                };
                (timestamp, addr)
            })
            .collect()
    }

    /// Remove terrible addresses
    pub fn cleanup(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut to_remove = Vec::new();

        // Check new table
        for bucket in &self.new_table {
            for info in &bucket.addrs {
                if info.is_terrible(now) {
                    to_remove.push(info.addr);
                }
            }
        }

        // Check tried table
        for bucket in &self.tried_table {
            for info in &bucket.addrs {
                if info.is_terrible(now) {
                    to_remove.push(info.addr);
                }
            }
        }

        // Remove terrible addresses
        for addr in to_remove {
            self.remove(&addr);
        }
    }

    /// Remove an address
    fn remove(&mut self, addr: &SocketAddr) -> bool {
        if let Some((in_tried, bucket_id)) = self.addr_index.remove(addr) {
            let bucket = if in_tried {
                self.stats.tried_count -= 1;
                &mut self.tried_table[bucket_id]
            } else {
                self.stats.new_count -= 1;
                &mut self.new_table[bucket_id]
            };

            self.stats.total_count -= 1;
            bucket.remove(addr);
            true
        } else {
            false
        }
    }

    /// Check if address is local
    fn is_local(&self, addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
            IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> AddrStats {
        self.stats.clone()
    }

    /// Save to file
    pub async fn save_to_file(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_vec_pretty(self)?;
        tokio::fs::write(path, data).await?;
        Ok(())
    }

    /// Load from file
    pub async fn load_from_file(path: &Path) -> Result<Self> {
        let data = tokio::fs::read(path).await?;
        let manager = serde_json::from_slice(&data)?;
        Ok(manager)
    }
}

impl Serialize for AddrManager {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("AddrManager", 3)?;

        // Collect all addresses
        let mut addrs = Vec::new();
        for bucket in &self.new_table {
            addrs.extend(bucket.addrs.clone());
        }
        for bucket in &self.tried_table {
            addrs.extend(bucket.addrs.clone());
        }

        state.serialize_field("network", &self.network)?;
        state.serialize_field("addrs", &addrs)?;
        state.serialize_field("key", &self.key)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AddrManager {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct AddrManagerData {
            network: Network,
            addrs: Vec<AddrInfo>,
            key: [u8; 32],
        }

        let data = AddrManagerData::deserialize(deserializer)?;
        let mut manager = AddrManager::new(data.network);
        manager.key = data.key;

        // Re-add all addresses
        for info in data.addrs {
            manager.add(info.addr, info.source, ServiceFlags::from(info.services));

            // Restore state
            if info.in_tried {
                manager.mark_good(info.addr);
            }
            if info.attempts > 0 {
                for _ in 0..info.attempts {
                    manager.mark_attempt(info.addr);
                }
            }
        }

        Ok(manager)
    }
}
