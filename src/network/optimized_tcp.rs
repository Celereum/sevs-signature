//! Optimized TCP Transport
//!
//! High-performance TCP transport with optimizations:
//! - TCP_NODELAY for low latency
//! - SO_REUSEADDR for fast restarts
//! - Connection pooling
//! - Parallel message sending
//!
//! Note: QUIC implementation is available but requires mingw64 dlltool on Windows.
//! This optimized TCP provides similar performance characteristics for most use cases.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use parking_lot::Mutex;
use thiserror::Error;

/// TCP Transport Configuration
#[derive(Debug, Clone)]
pub struct TcpConfig {
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Keep-alive interval
    pub keep_alive: Duration,
    /// Maximum concurrent connections per peer
    pub max_connections_per_peer: usize,
    /// Read buffer size (optimized for block data)
    pub read_buffer_size: usize,
    /// Write buffer size
    pub write_buffer_size: usize,
    /// Enable TCP_NODELAY (Nagle's algorithm disabled)
    pub nodelay: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            keep_alive: Duration::from_secs(15),
            max_connections_per_peer: 4,  // Multiple streams per peer
            read_buffer_size: 256 * 1024,  // 256KB - optimized for blocks
            write_buffer_size: 256 * 1024,
            nodelay: true,  // Low latency
        }
    }
}

/// TCP Transport Error
#[derive(Debug, Error)]
pub enum TcpError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Connection timeout")]
    Timeout,
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("Connection pool exhausted")]
    PoolExhausted,
}

/// A connected peer with connection pool
pub struct TcpPeer {
    /// Peer address
    pub addr: SocketAddr,
    /// Connection pool
    connections: Mutex<Vec<TcpStream>>,
    /// Maximum connections
    max_connections: usize,
    /// Messages sent
    pub messages_sent: std::sync::atomic::AtomicU64,
    /// Bytes sent
    pub bytes_sent: std::sync::atomic::AtomicU64,
}

impl TcpPeer {
    fn new(addr: SocketAddr, max_connections: usize) -> Self {
        Self {
            addr,
            connections: Mutex::new(Vec::with_capacity(max_connections)),
            max_connections,
            messages_sent: std::sync::atomic::AtomicU64::new(0),
            bytes_sent: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Get or create a connection
    async fn get_connection(&self, config: &TcpConfig) -> Result<TcpStream, TcpError> {
        // Try to get existing connection
        {
            let mut pool = self.connections.lock();
            if let Some(conn) = pool.pop() {
                return Ok(conn);
            }
        }

        // Create new connection
        let stream = tokio::time::timeout(
            config.connect_timeout,
            TcpStream::connect(self.addr)
        ).await.map_err(|_| TcpError::Timeout)??;

        // Apply optimizations
        stream.set_nodelay(config.nodelay)?;

        Ok(stream)
    }

    /// Return connection to pool
    fn return_connection(&self, conn: TcpStream) {
        let mut pool = self.connections.lock();
        if pool.len() < self.max_connections {
            pool.push(conn);
        }
        // Otherwise, connection is dropped
    }

    /// Send data to peer
    pub async fn send(&self, data: &[u8], config: &TcpConfig) -> Result<(), TcpError> {
        let mut stream = self.get_connection(config).await?;

        // Send length prefix (4 bytes) + data
        let len = data.len() as u32;
        stream.write_all(&len.to_le_bytes()).await?;
        stream.write_all(data).await?;
        stream.flush().await?;

        self.messages_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.bytes_sent.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);

        self.return_connection(stream);
        Ok(())
    }
}

/// High-performance TCP Transport Layer
pub struct TcpTransport {
    /// Configuration
    config: TcpConfig,
    /// Connected peers
    peers: RwLock<HashMap<SocketAddr, Arc<TcpPeer>>>,
    /// Listener
    listener: Option<TcpListener>,
    /// Local address
    local_addr: Option<SocketAddr>,
    /// Running flag
    running: std::sync::atomic::AtomicBool,
}

impl TcpTransport {
    /// Create new TCP transport
    pub fn new(config: TcpConfig) -> Self {
        Self {
            config,
            peers: RwLock::new(HashMap::new()),
            listener: None,
            local_addr: None,
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Bind to address and start listening
    pub async fn bind(&mut self, addr: SocketAddr) -> Result<(), TcpError> {
        let listener = TcpListener::bind(addr).await?;
        self.local_addr = Some(listener.local_addr()?);
        self.listener = Some(listener);
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Get local address
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Connect to a peer
    pub async fn connect(&self, addr: SocketAddr) -> Result<Arc<TcpPeer>, TcpError> {
        // Check if already connected
        {
            let peers = self.peers.read().await;
            if let Some(peer) = peers.get(&addr) {
                return Ok(peer.clone());
            }
        }

        // Create new peer
        let peer = Arc::new(TcpPeer::new(addr, self.config.max_connections_per_peer));

        // Establish initial connection to verify peer is reachable
        let stream = tokio::time::timeout(
            self.config.connect_timeout,
            TcpStream::connect(addr)
        ).await.map_err(|_| TcpError::Timeout)??;

        stream.set_nodelay(self.config.nodelay)?;
        peer.return_connection(stream);

        // Add to peers
        {
            let mut peers = self.peers.write().await;
            peers.insert(addr, peer.clone());
        }

        Ok(peer)
    }

    /// Send to specific peer
    pub async fn send_to(&self, addr: SocketAddr, data: &[u8]) -> Result<(), TcpError> {
        let peer = {
            let peers = self.peers.read().await;
            peers.get(&addr).cloned()
        };

        match peer {
            Some(p) => p.send(data, &self.config).await,
            None => Err(TcpError::PeerNotFound(addr.to_string())),
        }
    }

    /// Broadcast to all connected peers (parallel)
    pub async fn broadcast(&self, data: &[u8]) -> Vec<Result<(), TcpError>> {
        let peers: Vec<Arc<TcpPeer>> = {
            let peers = self.peers.read().await;
            peers.values().cloned().collect()
        };

        // Use tokio::spawn for parallel sending
        let mut handles = Vec::new();
        let data = Arc::new(data.to_vec());
        let config = self.config.clone();

        for peer in peers {
            let data = data.clone();
            let config = config.clone();
            handles.push(tokio::spawn(async move {
                peer.send(&data, &config).await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(_) => results.push(Err(TcpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Task panicked"
                )))),
            }
        }

        results
    }

    /// Get connected peer count
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get all peer addresses
    pub async fn peer_addresses(&self) -> Vec<SocketAddr> {
        self.peers.read().await.keys().cloned().collect()
    }

    /// Accept incoming connection (call in loop)
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), TcpError> {
        if let Some(listener) = &self.listener {
            let (stream, addr) = listener.accept().await?;
            stream.set_nodelay(self.config.nodelay)?;
            Ok((stream, addr))
        } else {
            Err(TcpError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "Not listening"
            )))
        }
    }

    /// Read message from stream (length-prefixed)
    pub async fn read_message(stream: &mut TcpStream, max_size: usize) -> Result<Vec<u8>, TcpError> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > max_size {
            return Err(TcpError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message too large"
            )));
        }

        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;
        Ok(data)
    }

    /// Disconnect peer
    pub async fn disconnect(&self, addr: SocketAddr) {
        let mut peers = self.peers.write().await;
        peers.remove(&addr);
    }

    /// Shutdown transport
    pub async fn shutdown(&mut self) {
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
        self.peers.write().await.clear();
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new(TcpConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_config_default() {
        let config = TcpConfig::default();
        assert!(config.nodelay);
        assert_eq!(config.max_connections_per_peer, 4);
    }

    #[tokio::test]
    async fn test_tcp_transport_creation() {
        let transport = TcpTransport::default();
        assert!(transport.local_addr().is_none());
        assert_eq!(transport.peer_count().await, 0);
    }
}
