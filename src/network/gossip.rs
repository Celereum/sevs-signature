//! Gossip protocol for peer discovery and message propagation

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::core::{Block, Transaction};
use crate::crypto::Pubkey;
use crate::storage::Storage;

use super::peer::{Peer, PeerInfo, PeerId, PeerState};
use super::message::{NetworkMessage, MessageType};

/// Gossip configuration
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Maximum number of peers
    pub max_peers: usize,
    /// Peer timeout
    pub peer_timeout: Duration,
    /// Gossip interval
    pub gossip_interval: Duration,
    /// Max message size
    pub max_message_size: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            max_peers: 100,
            peer_timeout: Duration::from_secs(60),
            gossip_interval: Duration::from_millis(200),
            max_message_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Gossip service for peer-to-peer communication
pub struct GossipService {
    /// Our peer info
    pub identity: PeerInfo,
    /// Known peers
    peers: RwLock<HashMap<PeerId, Peer>>,
    /// Recently seen message hashes (dedup)
    seen_messages: RwLock<HashSet<[u8; 32]>>,
    /// Config
    config: GossipConfig,
    /// Storage reference
    storage: Arc<Storage>,
    /// Transaction broadcast channel
    tx_sender: mpsc::Sender<Transaction>,
    /// Block broadcast channel
    block_sender: mpsc::Sender<Block>,
}

impl GossipService {
    /// Create a new gossip service
    pub fn new(
        identity: PeerInfo,
        storage: Arc<Storage>,
        config: GossipConfig,
    ) -> (Self, mpsc::Receiver<Transaction>, mpsc::Receiver<Block>) {
        let (tx_sender, tx_receiver) = mpsc::channel(1000);
        let (block_sender, block_receiver) = mpsc::channel(100);

        let service = Self {
            identity,
            peers: RwLock::new(HashMap::new()),
            seen_messages: RwLock::new(HashSet::new()),
            config,
            storage,
            tx_sender,
            block_sender,
        };

        (service, tx_receiver, block_receiver)
    }

    /// Add a peer
    pub async fn add_peer(&self, info: PeerInfo) {
        let mut peers = self.peers.write().await;
        if peers.len() < self.config.max_peers {
            if !peers.contains_key(&info.id) {
                info!("Adding peer: {} @ {}", info.id, info.addr);
                peers.insert(info.id, Peer::new(info));
            }
        }
    }

    /// Remove a peer
    pub async fn remove_peer(&self, id: &PeerId) {
        let mut peers = self.peers.write().await;
        if peers.remove(id).is_some() {
            info!("Removed peer: {}", id);
        }
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    /// Get connected peers
    pub async fn connected_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values()
            .filter(|p| p.state == PeerState::Connected)
            .map(|p| p.info.clone())
            .collect()
    }

    /// Get all peers info
    pub async fn all_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values().map(|p| p.info.clone()).collect()
    }

    /// Handle incoming message
    pub async fn handle_message(&self, from: &PeerId, msg: NetworkMessage) -> Option<NetworkMessage> {
        // Check for duplicates
        let msg_hash = crate::crypto::Hash::hash(&msg.serialize());
        {
            let mut seen = self.seen_messages.write().await;
            if seen.contains(msg_hash.as_bytes()) {
                return None;
            }
            seen.insert(*msg_hash.as_bytes());

            // Limit seen messages cache
            if seen.len() > 10000 {
                seen.clear();
            }
        }

        match msg.msg_type {
            MessageType::Hello => {
                if let Some(peer_info) = msg.parse_peer_info() {
                    self.add_peer(peer_info).await;
                }
                Some(NetworkMessage::hello_ack(&self.identity))
            }

            MessageType::HelloAck => {
                if let Some(peer_info) = msg.parse_peer_info() {
                    let mut peers = self.peers.write().await;
                    if let Some(peer) = peers.get_mut(from) {
                        peer.info = peer_info;
                        peer.mark_connected();
                    }
                }
                None
            }

            MessageType::Ping => {
                let nonce = msg.parse_nonce().unwrap_or(0);
                Some(NetworkMessage::pong(nonce))
            }

            MessageType::Pong => {
                let mut peers = self.peers.write().await;
                if let Some(peer) = peers.get_mut(from) {
                    peer.touch();
                }
                None
            }

            MessageType::GetPeers => {
                let peers = self.all_peers().await;
                Some(NetworkMessage::peers(&peers))
            }

            MessageType::Peers => {
                if let Some(peer_infos) = msg.parse_peers() {
                    for info in peer_infos {
                        if info.id != self.identity.id {
                            self.add_peer(info).await;
                        }
                    }
                }
                None
            }

            MessageType::Transaction => {
                if let Some(tx) = msg.parse_transaction() {
                    // Verify transaction
                    if tx.verify() {
                        // Add to storage
                        self.storage.add_pending_transaction(tx.clone());
                        // Broadcast to validator
                        let _ = self.tx_sender.try_send(tx);
                    }
                }
                None
            }

            MessageType::Block => {
                if let Some(block) = msg.parse_block() {
                    debug!("Received block for slot {}", block.header.slot);
                    // Broadcast to validator
                    let _ = self.block_sender.try_send(block);
                }
                None
            }

            MessageType::GetBlock => {
                if let Some(slot) = msg.parse_slot() {
                    if let Some(block) = self.storage.get_block(slot) {
                        return Some(NetworkMessage::block(&block));
                    }
                }
                None
            }

            MessageType::GetBlocks => {
                // Parse start slot and count
                if msg.payload.len() >= 16 {
                    let start = u64::from_le_bytes(msg.payload[..8].try_into().unwrap());
                    let count = u64::from_le_bytes(msg.payload[8..16].try_into().unwrap());

                    let mut blocks = Vec::new();
                    for slot in start..start + count.min(100) {
                        if let Some(block) = self.storage.get_block(slot) {
                            blocks.push(block);
                        }
                    }

                    if !blocks.is_empty() {
                        return Some(NetworkMessage::sync_response(&blocks));
                    }
                }
                None
            }

            MessageType::SyncRequest => {
                if let Some(from_slot) = msg.parse_slot() {
                    let current = self.storage.get_current_slot();
                    let mut blocks = Vec::new();

                    for slot in from_slot..=current.min(from_slot + 100) {
                        if let Some(block) = self.storage.get_block(slot) {
                            blocks.push(block);
                        }
                    }

                    if !blocks.is_empty() {
                        return Some(NetworkMessage::sync_response(&blocks));
                    }
                }
                None
            }

            MessageType::SyncResponse => {
                if let Some(blocks) = msg.parse_blocks() {
                    for block in blocks {
                        let _ = self.block_sender.try_send(block);
                    }
                }
                None
            }

            MessageType::Vote => {
                // Handle vote messages
                debug!("Received vote from {}", from);
                None
            }
        }
    }

    /// Broadcast transaction to all peers
    pub async fn broadcast_transaction(&self, tx: &Transaction) {
        let msg = NetworkMessage::transaction(tx);
        self.broadcast_message(&msg).await;
    }

    /// Broadcast block to all peers
    pub async fn broadcast_block(&self, block: &Block) {
        let msg = NetworkMessage::block(block);
        self.broadcast_message(&msg).await;
    }

    /// Broadcast message to all connected peers
    async fn broadcast_message(&self, msg: &NetworkMessage) {
        let peers = self.peers.read().await;
        let connected: Vec<_> = peers.values()
            .filter(|p| p.state == PeerState::Connected)
            .map(|p| p.info.addr)
            .collect();

        debug!("Broadcasting to {} peers", connected.len());
        // In a real implementation, we would send to each peer
        // For now, this is just a placeholder
    }

    /// Clean up stale peers
    pub async fn cleanup_stale_peers(&self) {
        let mut peers = self.peers.write().await;
        let stale: Vec<PeerId> = peers.iter()
            .filter(|(_, p)| p.is_stale(self.config.peer_timeout))
            .map(|(id, _)| *id)
            .collect();

        for id in stale {
            info!("Removing stale peer: {}", id);
            peers.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_gossip_service() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
        let identity = PeerInfo::new(Pubkey::zero(), addr);
        let storage = Arc::new(Storage::new_memory());

        let (service, _, _) = GossipService::new(identity, storage, GossipConfig::default());

        assert_eq!(service.peer_count().await, 0);

        // Add peer
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8002);
        let peer_info = PeerInfo::new(Pubkey::new([1u8; 32]), peer_addr);
        service.add_peer(peer_info).await;

        assert_eq!(service.peer_count().await, 1);
    }
}
