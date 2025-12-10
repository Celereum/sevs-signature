//! Peer management

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

use crate::crypto::Pubkey;

/// Unique peer identifier (based on pubkey)
pub type PeerId = Pubkey;

/// Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer's public key / identity
    pub id: PeerId,
    /// Socket address
    pub addr: SocketAddr,
    /// Gossip port
    pub gossip_port: u16,
    /// RPC port
    pub rpc_port: u16,
    /// Version string
    pub version: String,
    /// Feature set
    pub feature_set: u32,
    /// Shred version (for compatibility)
    pub shred_version: u16,
}

impl PeerInfo {
    pub fn new(id: PeerId, addr: SocketAddr) -> Self {
        Self {
            id,
            addr,
            gossip_port: 8001,
            rpc_port: 8899,
            version: crate::CELEREUM_VERSION.to_string(),
            feature_set: 1,
            shred_version: 1,
        }
    }
}

/// Connected peer
pub struct Peer {
    /// Peer info
    pub info: PeerInfo,
    /// Connection state
    pub state: PeerState,
    /// Last seen time
    pub last_seen: Instant,
    /// Ping latency
    pub latency: Option<Duration>,
    /// Failed connection attempts
    pub failures: u32,
}

/// Peer connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Unknown / not connected
    Unknown,
    /// Connecting
    Connecting,
    /// Connected and healthy
    Connected,
    /// Connection failed
    Failed,
    /// Banned
    Banned,
}

impl Peer {
    pub fn new(info: PeerInfo) -> Self {
        Self {
            info,
            state: PeerState::Unknown,
            last_seen: Instant::now(),
            latency: None,
            failures: 0,
        }
    }

    /// Update last seen time
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Check if peer is stale (not seen recently)
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }

    /// Mark as connected
    pub fn mark_connected(&mut self) {
        self.state = PeerState::Connected;
        self.failures = 0;
        self.touch();
    }

    /// Mark as failed
    pub fn mark_failed(&mut self) {
        self.failures += 1;
        if self.failures >= 5 {
            self.state = PeerState::Banned;
        } else {
            self.state = PeerState::Failed;
        }
    }

    /// Check if should retry connection
    pub fn should_retry(&self) -> bool {
        match self.state {
            PeerState::Banned => false,
            PeerState::Failed => self.failures < 5,
            _ => true,
        }
    }
}

/// Peer connection handler
pub struct PeerConnection {
    peer: PeerInfo,
    stream: TcpStream,
}

impl PeerConnection {
    /// Connect to a peer
    pub async fn connect(addr: SocketAddr) -> Result<Self, std::io::Error> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;

        Ok(Self {
            peer: PeerInfo::new(Pubkey::zero(), addr),
            stream,
        })
    }

    /// Send a message
    pub async fn send(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        // Send length prefix (4 bytes)
        let len = data.len() as u32;
        self.stream.write_all(&len.to_le_bytes()).await?;
        // Send data
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receive a message
    pub async fn recv(&mut self) -> Result<Vec<u8>, std::io::Error> {
        // Read length prefix
        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        // Sanity check
        if len > 10 * 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message too large",
            ));
        }

        // Read data
        let mut data = vec![0u8; len];
        self.stream.read_exact(&mut data).await?;
        Ok(data)
    }

    /// Get peer info
    pub fn peer_info(&self) -> &PeerInfo {
        &self.peer
    }

    /// Set peer info after handshake
    pub fn set_peer_info(&mut self, info: PeerInfo) {
        self.peer = info;
    }

    /// Close connection
    pub async fn close(self) -> Result<(), std::io::Error> {
        drop(self.stream);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_peer_state() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
        let info = PeerInfo::new(Pubkey::zero(), addr);
        let mut peer = Peer::new(info);

        assert_eq!(peer.state, PeerState::Unknown);
        assert!(peer.should_retry());

        peer.mark_connected();
        assert_eq!(peer.state, PeerState::Connected);

        for _ in 0..5 {
            peer.mark_failed();
        }
        assert_eq!(peer.state, PeerState::Banned);
        assert!(!peer.should_retry());
    }
}
