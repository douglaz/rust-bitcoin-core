use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, info};

/// Connection state
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

/// TCP connection wrapper
pub struct Connection {
    /// Remote address
    pub addr: SocketAddr,

    /// TCP stream
    stream: Arc<Mutex<TcpStream>>,

    /// Connection state
    state: Arc<Mutex<ConnectionState>>,
}

impl Connection {
    /// Create from existing TCP stream
    pub fn from_stream(stream: TcpStream, addr: SocketAddr) -> Self {
        Self {
            addr,
            stream: Arc::new(Mutex::new(stream)),
            state: Arc::new(Mutex::new(ConnectionState::Connected)),
        }
    }

    /// Connect to address
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        info!("Connecting to {}", addr);

        let stream = TcpStream::connect(addr)
            .await
            .context("Failed to connect")?;

        stream.set_nodelay(true)?;

        Ok(Self {
            addr,
            stream: Arc::new(Mutex::new(stream)),
            state: Arc::new(Mutex::new(ConnectionState::Connected)),
        })
    }

    /// Send bytes
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let mut stream = self.stream.lock().await;
        stream.write_all(data).await?;
        stream.flush().await?;

        debug!("Sent {} bytes to {}", data.len(), self.addr);
        Ok(())
    }

    /// Receive bytes
    pub async fn receive(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut stream = self.stream.lock().await;
        let n = stream.read(buffer).await?;

        if n == 0 {
            info!("Connection closed by {}", self.addr);
        } else {
            debug!("Received {} bytes from {}", n, self.addr);
        }

        Ok(n)
    }

    /// Close connection
    pub async fn close(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        *state = ConnectionState::Disconnecting;

        let mut stream = self.stream.lock().await;
        stream.shutdown().await?;

        *state = ConnectionState::Disconnected;
        info!("Closed connection to {}", self.addr);

        Ok(())
    }

    /// Get current state
    pub async fn state(&self) -> ConnectionState {
        self.state.lock().await.clone()
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.state.lock().await == ConnectionState::Connected
    }
}
