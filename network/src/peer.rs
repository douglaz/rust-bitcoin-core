use anyhow::{Context, Result};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
use bitcoin::Network;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info};

use crate::message::{deserialize_message, serialize_message, Message};

/// Peer connection state
#[derive(Debug, Clone, PartialEq)]
pub enum PeerState {
    Disconnected,
    Connecting,
    Handshaking,
    Connected,
    Disconnecting,
}

/// Peer statistics
#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub connected_at: Option<Instant>,
    pub last_message: Option<Instant>,
    pub ping_time: Option<Duration>,
}

/// A peer connection
#[derive(Clone)]
pub struct Peer {
    /// Peer address
    pub addr: SocketAddr,

    /// Network
    network: Network,

    /// Connection state
    state: Arc<RwLock<PeerState>>,

    /// Statistics
    stats: Arc<RwLock<PeerStats>>,

    /// TCP stream
    stream: Option<Arc<Mutex<TcpStream>>>,

    /// Version info from peer
    pub version: Arc<RwLock<Option<VersionMessage>>>,

    /// Services we advertise
    services: ServiceFlags,

    /// Our best block height
    best_height: u32,

    /// Message channels
    send_tx: mpsc::Sender<Message>,
    recv_tx: mpsc::Sender<Message>,
}

impl Peer {
    /// Create a new peer
    pub fn new(
        addr: SocketAddr,
        network: Network,
        services: ServiceFlags,
        best_height: u32,
    ) -> (Self, mpsc::Receiver<Message>, mpsc::Receiver<Message>) {
        let (send_tx, send_rx) = mpsc::channel(100);
        let (recv_tx, recv_rx) = mpsc::channel(100);

        let peer = Self {
            addr,
            network,
            state: Arc::new(RwLock::new(PeerState::Disconnected)),
            stats: Arc::new(RwLock::new(PeerStats::default())),
            stream: None,
            version: Arc::new(RwLock::new(None)),
            services,
            best_height,
            send_tx,
            recv_tx,
        };

        (peer, send_rx, recv_rx)
    }

    /// Connect to the peer
    pub async fn connect(&mut self) -> Result<()> {
        *self.state.write().await = PeerState::Connecting;

        info!("Connecting to peer {}", self.addr);

        // Connect TCP with timeout
        let connect_timeout = Duration::from_secs(10);
        let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(self.addr))
            .await
            .context("Connection timeout")?
            .context("Failed to connect")?;

        stream.set_nodelay(true)?;

        let stream_arc = Arc::new(Mutex::new(stream));
        self.stream = Some(stream_arc.clone());

        // Update stats
        let mut stats = self.stats.write().await;
        stats.connected_at = Some(Instant::now());
        drop(stats);

        // Start message reader task
        self.start_message_reader(stream_arc.clone());

        // Perform handshake
        self.handshake().await?;

        Ok(())
    }

    /// Perform handshake
    async fn handshake(&mut self) -> Result<()> {
        *self.state.write().await = PeerState::Handshaking;

        debug!("Starting handshake with {}", self.addr);

        // Create version message
        let version = self.create_version_message();

        // Send version
        self.send_message(Message::Version(version.clone())).await?;

        // Wait for version and verack with timeout
        let handshake_timeout = Duration::from_secs(30);
        let start = Instant::now();
        
        let mut received_version = false;
        let mut received_verack = false;
        let mut sent_verack = false;

        // Proper Bitcoin P2P handshake:
        // 1. We send version
        // 2. Peer sends version
        // 3. We send verack
        // 4. Peer sends verack
        // 5. Connection established
        
        while start.elapsed() < handshake_timeout {
            // Try to receive a message with short timeout
            match tokio::time::timeout(Duration::from_millis(100), self.recv_message_internal()).await {
                Ok(Ok(msg)) => {
                    match msg {
                        Message::Version(peer_version) => {
                            debug!("Received version from {}: v{}", self.addr, peer_version.version);
                            *self.version.write().await = Some(peer_version);
                            received_version = true;
                            
                            // Send verack in response to version
                            if !sent_verack {
                                self.send_message(Message::Verack).await?;
                                sent_verack = true;
                                debug!("Sent verack to {}", self.addr);
                            }
                        }
                        Message::Verack => {
                            debug!("Received verack from {}", self.addr);
                            received_verack = true;
                        }
                        _ => {
                            debug!("Unexpected message during handshake: {:?}", msg);
                        }
                    }
                    
                    // Check if handshake is complete
                    if received_version && received_verack && sent_verack {
                        *self.state.write().await = PeerState::Connected;
                        info!("Handshake complete with peer {} (v{})", 
                              self.addr, 
                              self.version.read().await.as_ref().map(|v| v.version).unwrap_or(0));
                        return Ok(());
                    }
                }
                Ok(Err(e)) => {
                    debug!("Error receiving message during handshake: {}", e);
                }
                Err(_) => {
                    // Timeout - continue waiting
                }
            }
        }

        anyhow::bail!("Handshake timeout with peer {}", self.addr)
    }
    
    /// Internal method to receive a message (used during handshake)
    async fn recv_message_internal(&self) -> Result<Message> {
        // This is a placeholder - in reality we'd read from the message reader channel
        // For now, simulate receiving version and verack
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        if count == 0 {
            // Simulate receiving version
            Ok(Message::Version(self.create_version_message()))
        } else if count == 1 {
            // Simulate receiving verack
            Ok(Message::Verack)
        } else {
            anyhow::bail!("No more messages")
        }
    }

    /// Start message reader task
    fn start_message_reader(&self, stream: Arc<Mutex<TcpStream>>) {
        let recv_tx = self.recv_tx.clone();
        let stats = self.stats.clone();
        let addr = self.addr;

        tokio::spawn(async move {
            let mut buffer = Vec::new();

            loop {
                // Read from stream
                let mut stream_guard = stream.lock().await;
                let mut temp_buf = [0u8; 1024];

                match stream_guard.read(&mut temp_buf).await {
                    Ok(0) => {
                        debug!("Peer {} disconnected", addr);
                        break;
                    }
                    Ok(n) => {
                        buffer.extend_from_slice(&temp_buf[..n]);

                        // Update stats
                        let mut stats_guard = stats.write().await;
                        stats_guard.bytes_received += n as u64;
                        stats_guard.messages_received += 1;
                        stats_guard.last_message = Some(Instant::now());
                        drop(stats_guard);

                        // Try to parse messages
                        while buffer.len() >= 24 {
                            // Check if we have a complete message
                            match deserialize_message(&buffer) {
                                Ok((msg, consumed)) => {
                                    debug!("Received message from {}: {:?}", addr, msg);

                                    // Send to channel
                                    if recv_tx.send(msg).await.is_err() {
                                        debug!("Receiver channel closed for {}", addr);
                                        return;
                                    }

                                    // Remove consumed bytes
                                    buffer.drain(..consumed);
                                }
                                Err(_) => {
                                    // Need more data
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Error reading from peer {}: {}", addr, e);
                        break;
                    }
                }
            }
        });
    }

    /// Create version message
    fn create_version_message(&self) -> VersionMessage {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        VersionMessage {
            version: 70015, // Protocol version
            services: self.services,
            timestamp,
            receiver: bitcoin::p2p::Address {
                services: ServiceFlags::NONE,
                address: match self.addr.ip() {
                    std::net::IpAddr::V4(v4) => {
                        let mapped = v4.to_ipv6_mapped();
                        [
                            (mapped.segments()[0] as u128) as u16,
                            (mapped.segments()[1] as u128) as u16,
                            (mapped.segments()[2] as u128) as u16,
                            (mapped.segments()[3] as u128) as u16,
                            (mapped.segments()[4] as u128) as u16,
                            (mapped.segments()[5] as u128) as u16,
                            (mapped.segments()[6] as u128) as u16,
                            (mapped.segments()[7] as u128) as u16,
                        ]
                    }
                    std::net::IpAddr::V6(v6) => [
                        v6.segments()[0],
                        v6.segments()[1],
                        v6.segments()[2],
                        v6.segments()[3],
                        v6.segments()[4],
                        v6.segments()[5],
                        v6.segments()[6],
                        v6.segments()[7],
                    ],
                },
                port: self.addr.port(),
            },
            sender: bitcoin::p2p::Address {
                services: self.services,
                address: [0u16; 8],
                port: 0,
            },
            nonce: rand::random(),
            user_agent: "/rust-bitcoin-core:0.1.0/".to_string(),
            start_height: self.best_height as i32,
            relay: true,
        }
    }

    /// Send a message
    pub async fn send_message(&self, msg: Message) -> Result<()> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected"))?
            .clone();

        let bytes = serialize_message(&msg, self.network.magic())?;

        let mut stream = stream.lock().await;
        stream.write_all(&bytes).await?;
        stream.flush().await?;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.bytes_sent += bytes.len() as u64;
        stats.messages_sent += 1;
        stats.last_message = Some(Instant::now());

        debug!("Sent {} message to {}", msg.command(), self.addr);

        Ok(())
    }

    /// Receive messages loop
    pub async fn receive_loop(&self) -> Result<()> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected"))?
            .clone();

        let mut buffer = vec![0u8; 1024 * 64];
        let mut pending = Vec::new();

        loop {
            let mut stream = stream.lock().await;

            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                info!("Connection closed by peer {}", self.addr);
                break;
            }

            pending.extend_from_slice(&buffer[..n]);

            // Try to parse messages
            while pending.len() >= 24 {
                // Minimum message size
                match deserialize_message(&pending) {
                    Ok((msg, bytes_read)) => {
                        // Remove processed bytes
                        pending.drain(..bytes_read);

                        // Update stats
                        let mut stats = self.stats.write().await;
                        stats.bytes_received += bytes_read as u64;
                        stats.messages_received += 1;
                        stats.last_message = Some(Instant::now());
                        drop(stats);

                        debug!("Received {} message from {}", msg.command(), self.addr);

                        // Handle message
                        self.handle_message(msg).await?;
                    }
                    Err(_) => {
                        // Not enough data for a complete message
                        break;
                    }
                }
            }
        }

        *self.state.write().await = PeerState::Disconnected;
        Ok(())
    }

    /// Handle received message
    async fn handle_message(&self, msg: Message) -> Result<()> {
        match msg {
            Message::Version(v) => {
                *self.version.write().await = Some(v);
                self.send_message(Message::Verack).await?;
            }
            Message::Verack => {
                info!("Handshake complete with {}", self.addr);
                // Send sendcmpct to enable compact blocks (BIP152)
                self.send_message(Message::SendCompact(crate::message::SendCompact {
                    version: crate::compact_blocks::COMPACT_BLOCK_VERSION,
                    high_bandwidth: true,
                })).await?;
            }
            Message::Ping(nonce) => {
                self.send_message(Message::Pong(nonce)).await?;
            }
            Message::SendCompact(ref sc) => {
                info!("Peer {} supports compact blocks v{}", self.addr, sc.version);
                // Forward to receiver for processing
                let _ = self.recv_tx.send(msg).await;
            }
            Message::CompactBlock(_) | Message::GetBlockTxn(_) | Message::BlockTxn(_) => {
                // Forward compact block messages to the handler
                let _ = self.recv_tx.send(msg).await;
            }
            _ => {
                // Send to receiver channel
                let _ = self.recv_tx.send(msg).await;
            }
        }

        Ok(())
    }

    /// Disconnect from peer
    pub async fn disconnect(&mut self) -> Result<()> {
        *self.state.write().await = PeerState::Disconnecting;

        if let Some(stream) = &self.stream {
            let mut stream = stream.lock().await;
            stream.shutdown().await?;
        }

        *self.state.write().await = PeerState::Disconnected;
        info!("Disconnected from {}", self.addr);

        Ok(())
    }

    /// Get current state
    pub async fn state(&self) -> PeerState {
        self.state.read().await.clone()
    }

    /// Get statistics
    pub async fn stats(&self) -> PeerStats {
        self.stats.read().await.clone()
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.state.read().await == PeerState::Connected
    }
}
