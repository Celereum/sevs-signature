//! Network node - main networking component

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use crate::core::{Block, Transaction};
use crate::crypto::{Keypair, Pubkey};
use crate::storage::Storage;

use super::gossip::{GossipService, GossipConfig};
use super::message::NetworkMessage;
use super::peer::{PeerInfo, PeerId, PeerConnection};

/// Network node configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Listen address for gossip
    pub gossip_addr: SocketAddr,
    /// Bootstrap peers
    pub bootstrap_peers: Vec<SocketAddr>,
    /// Gossip config
    pub gossip_config: GossipConfig,
}

/// Network node
pub struct NetworkNode {
    /// Node identity
    identity: PeerInfo,
    /// Keypair for signing
    keypair: Keypair,
    /// Gossip service
    gossip: Arc<GossipService>,
    /// Storage reference
    storage: Arc<Storage>,
    /// Config
    config: NetworkConfig,
    /// Running flag
    running: Arc<std::sync::atomic::AtomicBool>,
    /// Transaction receiver (from gossip)
    tx_receiver: Option<mpsc::Receiver<Transaction>>,
    /// Block receiver (from gossip)
    block_receiver: Option<mpsc::Receiver<Block>>,
}

impl NetworkNode {
    /// Create a new network node
    pub fn new(
        keypair: Keypair,
        storage: Arc<Storage>,
        config: NetworkConfig,
    ) -> Self {
        let identity = PeerInfo::new(keypair.address(), config.gossip_addr);

        let (gossip, tx_receiver, block_receiver) = GossipService::new(
            identity.clone(),
            storage.clone(),
            config.gossip_config.clone(),
        );

        Self {
            identity,
            keypair,
            gossip: Arc::new(gossip),
            storage,
            config,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            tx_receiver: Some(tx_receiver),
            block_receiver: Some(block_receiver),
        }
    }

    /// Get node identity
    pub fn identity(&self) -> &PeerInfo {
        &self.identity
    }

    /// Get gossip service
    pub fn gossip(&self) -> Arc<GossipService> {
        self.gossip.clone()
    }

    /// Take transaction receiver
    pub fn take_tx_receiver(&mut self) -> Option<mpsc::Receiver<Transaction>> {
        self.tx_receiver.take()
    }

    /// Take block receiver
    pub fn take_block_receiver(&mut self) -> Option<mpsc::Receiver<Block>> {
        self.block_receiver.take()
    }

    /// Start the network node
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        info!("Starting network node at {}", self.config.gossip_addr);

        // Start TCP listener
        let listener = TcpListener::bind(self.config.gossip_addr).await?;
        info!("Gossip listening on {}", self.config.gossip_addr);

        // Connect to bootstrap peers
        for addr in &self.config.bootstrap_peers {
            let gossip = self.gossip.clone();
            let identity = self.identity.clone();
            let addr = *addr;

            tokio::spawn(async move {
                if let Err(e) = Self::connect_to_peer(gossip, identity, addr).await {
                    warn!("Failed to connect to bootstrap peer {}: {}", addr, e);
                }
            });
        }

        // Accept incoming connections
        let gossip = self.gossip.clone();
        let running = self.running.clone();
        let identity = self.identity.clone();

        tokio::spawn(async move {
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("Incoming connection from {}", addr);
                        let gossip = gossip.clone();
                        let identity = identity.clone();

                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(gossip, identity, stream, addr).await {
                                debug!("Connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                    }
                }
            }
        });

        // Start cleanup task
        let gossip = self.gossip.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(30)).await;
                gossip.cleanup_stale_peers().await;
            }
        });

        Ok(())
    }

    /// Stop the network node
    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
        info!("Network node stopped");
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Connect to a peer
    async fn connect_to_peer(
        gossip: Arc<GossipService>,
        identity: PeerInfo,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Connecting to peer at {}", addr);

        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;

        Self::handle_connection(gossip, identity, stream, addr).await
    }

    /// Handle a peer connection
    async fn handle_connection(
        gossip: Arc<GossipService>,
        identity: PeerInfo,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Send hello
        let hello = NetworkMessage::hello(&identity);
        Self::send_message(&mut stream, &hello).await?;

        // Temporary peer ID until we get their hello
        let mut peer_id = Pubkey::zero();

        // Handle messages
        loop {
            match Self::recv_message(&mut stream).await {
                Ok(msg) => {
                    // Update peer ID from hello
                    if msg.msg_type == super::message::MessageType::Hello
                        || msg.msg_type == super::message::MessageType::HelloAck
                    {
                        if let Some(info) = msg.parse_peer_info() {
                            peer_id = info.id;
                        }
                    }

                    // Handle message
                    if let Some(response) = gossip.handle_message(&peer_id, msg).await {
                        Self::send_message(&mut stream, &response).await?;
                    }
                }
                Err(e) => {
                    debug!("Connection closed from {}: {}", addr, e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Send a message on a stream
    async fn send_message(stream: &mut TcpStream, msg: &NetworkMessage) -> Result<(), std::io::Error> {
        let data = msg.serialize();
        let len = data.len() as u32;

        stream.write_all(&len.to_le_bytes()).await?;
        stream.write_all(&data).await?;
        stream.flush().await?;

        Ok(())
    }

    /// Receive a message from a stream
    async fn recv_message(stream: &mut TcpStream) -> Result<NetworkMessage, std::io::Error> {
        // Read length
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
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
        stream.read_exact(&mut data).await?;

        NetworkMessage::deserialize(&data).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message")
        })
    }

    /// Broadcast a transaction
    pub async fn broadcast_transaction(&self, tx: &Transaction) {
        self.gossip.broadcast_transaction(tx).await;
    }

    /// Broadcast a block
    pub async fn broadcast_block(&self, block: &Block) {
        self.gossip.broadcast_block(block).await;
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.gossip.peer_count().await
    }

    /// Get all peers
    pub async fn peers(&self) -> Vec<PeerInfo> {
        self.gossip.all_peers().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_network_node_creation() {
        let keypair = Keypair::generate();
        let storage = Arc::new(Storage::new_memory());
        let config = NetworkConfig {
            gossip_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            bootstrap_peers: vec![],
            gossip_config: GossipConfig::default(),
        };

        let node = NetworkNode::new(keypair, storage, config);
        assert!(!node.is_running());
    }
}
