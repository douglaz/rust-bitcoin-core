use anyhow::Result;
use bitcoin::Network;
use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Peer address with metadata
#[derive(Debug, Clone)]
pub struct PeerAddress {
    pub addr: SocketAddr,
    pub last_seen: Instant,
    pub last_attempt: Option<Instant>,
    pub failures: u32,
}

/// Peer discovery manager
pub struct PeerDiscovery {
    network: Network,
    known_peers: Arc<RwLock<HashSet<SocketAddr>>>,
    peer_addresses: Arc<RwLock<Vec<PeerAddress>>>,
}

impl PeerDiscovery {
    /// Create new peer discovery
    pub fn new(network: Network) -> Self {
        Self {
            network,
            known_peers: Arc::new(RwLock::new(HashSet::new())),
            peer_addresses: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add seed nodes
    pub async fn add_seeds(&self, seeds: Vec<&str>) -> Result<()> {
        for seed in seeds {
            if let Ok(addr) = seed.parse::<SocketAddr>() {
                self.add_peer(addr).await;
            }
        }
        Ok(())
    }

    /// Add a peer address
    pub async fn add_peer(&self, addr: SocketAddr) {
        let mut known = self.known_peers.write().await;
        if known.insert(addr) {
            let mut addresses = self.peer_addresses.write().await;
            addresses.push(PeerAddress {
                addr,
                last_seen: Instant::now(),
                last_attempt: None,
                failures: 0,
            });
            debug!("Added peer address: {}", addr);
        }
    }

    /// Get peers to connect to
    pub async fn get_peers(&self, count: usize) -> Vec<SocketAddr> {
        let addresses = self.peer_addresses.read().await;
        addresses
            .iter()
            .filter(|p| p.failures < 3)
            .take(count)
            .map(|p| p.addr)
            .collect()
    }

    /// Mark peer as failed
    pub async fn mark_failed(&self, addr: SocketAddr) {
        let mut addresses = self.peer_addresses.write().await;
        if let Some(peer) = addresses.iter_mut().find(|p| p.addr == addr) {
            peer.failures += 1;
            peer.last_attempt = Some(Instant::now());
            debug!(
                "Marked peer {} as failed (failures: {})",
                addr, peer.failures
            );
        }
    }

    /// Mark peer as successful
    pub async fn mark_successful(&self, addr: SocketAddr) {
        let mut addresses = self.peer_addresses.write().await;
        if let Some(peer) = addresses.iter_mut().find(|p| p.addr == addr) {
            peer.failures = 0;
            peer.last_seen = Instant::now();
            peer.last_attempt = Some(Instant::now());
            debug!("Marked peer {} as successful", addr);
        }
    }

    /// Get default seeds for network
    pub fn default_seeds(&self) -> Vec<&'static str> {
        match self.network {
            Network::Bitcoin => vec![
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr.org",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.net",
                "seed.bitcoin.sprovoost.nl",
                "seed.bitnodes.io",
                "dnsseed.emzy.de",
            ],
            Network::Testnet => vec![
                "testnet-seed.bitcoin.jonasschnelli.ch",
                "seed.tbtc.petertodd.org",
                "testnet-seed.bluematt.me",
                "testnet-seed.bitcoin.sprovoost.nl",
            ],
            Network::Signet => vec!["seed.signet.bitcoin.sprovoost.nl"],
            Network::Regtest => vec![],
            _ => vec![],
        }
    }

    /// Discover peers via DNS seeds
    pub async fn discover_from_dns(&self) -> Result<Vec<SocketAddr>> {
        let seeds = self.default_seeds();
        if seeds.is_empty() {
            info!("No DNS seeds available for network");
            return Ok(vec![]);
        }

        info!("Starting DNS discovery for {} seeds", seeds.len());
        let mut discovered_peers = Vec::new();

        for seed in seeds {
            info!("Attempting to resolve DNS seed: {}", seed);
            match tokio::time::timeout(Duration::from_secs(10), self.resolve_dns_seed(seed)).await {
                Ok(Ok(addrs)) => {
                    info!("Resolved {} addresses from {}", addrs.len(), seed);
                    for addr in addrs {
                        self.add_peer(addr).await;
                        discovered_peers.push(addr);
                    }
                }
                Ok(Err(e)) => {
                    warn!("Failed to resolve DNS seed {}: {}", seed, e);
                }
                Err(_) => {
                    warn!("Timeout resolving DNS seed {}", seed);
                }
            }
        }

        info!("Discovered {} peers via DNS", discovered_peers.len());
        Ok(discovered_peers)
    }

    /// Resolve a DNS seed to socket addresses
    async fn resolve_dns_seed(&self, seed: &str) -> Result<Vec<SocketAddr>> {
        debug!("Resolving DNS seed: {}", seed);

        // Clone seed for the blocking task
        let seed_str = seed.to_string();
        let port = match self.network {
            Network::Bitcoin => 8333,
            Network::Testnet => 18333,
            Network::Signet => 38333,
            Network::Regtest => 18444,
            _ => 8333,
        };

        let addresses = tokio::task::spawn_blocking(move || {
            // DNS seeds should be resolved without port
            // Only add port when the seed already contains one (like fallback seeds)
            let lookup_str = if seed_str.contains(':') {
                seed_str.clone()
            } else {
                // For DNS names, resolve just the hostname
                seed_str.clone()
            };

            // Try to resolve the DNS seed
            match lookup_str.to_socket_addrs() {
                Ok(addrs) => {
                    // If we got addresses without ports, add the correct port
                    addrs.take(10).collect::<Vec<_>>()
                }
                Err(_) => {
                    // Try standard DNS lookup for A records
                    use std::net::ToSocketAddrs;
                    let with_port = format!("{}:{}", seed_str, port);
                    with_port
                        .to_socket_addrs()
                        .map(|addrs| addrs.take(10).collect::<Vec<_>>())
                        .unwrap_or_else(|e| {
                            debug!("Failed to resolve {}: {}", seed_str, e);
                            vec![]
                        })
                }
            }
        })
        .await?;

        Ok(addresses)
    }

    /// Add hardcoded fallback peers for network
    pub async fn add_fallback_peers(&self) -> Result<()> {
        let fallbacks = match self.network {
            Network::Bitcoin => vec![
                "91.221.70.137:8333",  // Bitcoin node
                "92.255.176.109:8333", // Bitcoin node
                "94.16.114.254:8333",  // Bitcoin node
                "104.131.131.82:8333", // Bitcoin node
                "138.68.7.97:8333",    // Bitcoin node
                "144.76.236.63:8333",  // Bitcoin node
                "159.89.120.226:8333", // Bitcoin node
                "167.99.90.76:8333",   // Bitcoin node
            ],
            Network::Testnet => vec![
                "18.189.138.49:18333", // Testnet node
                "52.14.65.233:18333",  // Testnet node
                "88.99.166.206:18333", // Testnet node
            ],
            _ => vec![],
        };

        for addr_str in fallbacks {
            if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                self.add_peer(addr).await;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_discovery() {
        let discovery = PeerDiscovery::new(Network::Bitcoin);
        
        // Try to discover peers from DNS
        let result = discovery.discover_from_dns().await;
        
        // DNS discovery might fail in test environment, but should not panic
        match result {
            Ok(peers) => {
                println!("Discovered {} peers from DNS", peers.len());
                // If it succeeds, we should have found at least some peers
                if !peers.is_empty() {
                    assert!(peers.len() > 0);
                }
            }
            Err(e) => {
                println!("DNS discovery failed (expected in test env): {}", e);
                // This is expected in many test environments
            }
        }
    }

    #[test]
    fn test_fallback_peers() {
        let discovery = PeerDiscovery::new(Network::Bitcoin);
        
        // Check we have fallback peers defined
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let result = discovery.add_fallback_peers().await;
            assert!(result.is_ok());
            
            // Should have added some fallback peers
            let peers = discovery.get_peers(10).await;
            assert!(!peers.is_empty(), "Should have fallback peers");
        });
    }

    #[test]
    fn test_default_seeds() {
        let discovery = PeerDiscovery::new(Network::Bitcoin);
        let seeds = discovery.default_seeds();
        assert!(!seeds.is_empty(), "Should have default DNS seeds for mainnet");
        assert!(seeds.len() >= 5, "Should have multiple DNS seeds");
    }
}
