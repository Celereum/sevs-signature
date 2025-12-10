//! Network messages

use serde::{Deserialize, Serialize};

use crate::core::{Block, Transaction, Slot};
use crate::crypto::Hash;
use super::peer::PeerInfo;

/// Network message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake / peer introduction
    Hello = 0,
    /// Handshake response
    HelloAck = 1,
    /// Ping (keepalive)
    Ping = 2,
    /// Pong (keepalive response)
    Pong = 3,
    /// Request peers list
    GetPeers = 4,
    /// Peers list response
    Peers = 5,
    /// New transaction announcement
    Transaction = 6,
    /// New block announcement
    Block = 7,
    /// Request block by slot
    GetBlock = 8,
    /// Request blocks range
    GetBlocks = 9,
    /// Vote message
    Vote = 10,
    /// Request sync from slot
    SyncRequest = 11,
    /// Sync response with blocks
    SyncResponse = 12,
}

/// Network message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    /// Message type
    pub msg_type: MessageType,
    /// Message payload
    pub payload: Vec<u8>,
    /// Timestamp
    pub timestamp: i64,
}

impl NetworkMessage {
    /// Create a new message
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            msg_type,
            payload,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Create Hello message
    pub fn hello(info: &PeerInfo) -> Self {
        let payload = bincode::serialize(info).unwrap_or_default();
        Self::new(MessageType::Hello, payload)
    }

    /// Create HelloAck message
    pub fn hello_ack(info: &PeerInfo) -> Self {
        let payload = bincode::serialize(info).unwrap_or_default();
        Self::new(MessageType::HelloAck, payload)
    }

    /// Create Ping message
    pub fn ping(nonce: u64) -> Self {
        Self::new(MessageType::Ping, nonce.to_le_bytes().to_vec())
    }

    /// Create Pong message
    pub fn pong(nonce: u64) -> Self {
        Self::new(MessageType::Pong, nonce.to_le_bytes().to_vec())
    }

    /// Create GetPeers message
    pub fn get_peers() -> Self {
        Self::new(MessageType::GetPeers, vec![])
    }

    /// Create Peers message
    pub fn peers(peers: &[PeerInfo]) -> Self {
        let payload = bincode::serialize(peers).unwrap_or_default();
        Self::new(MessageType::Peers, payload)
    }

    /// Create Transaction message
    pub fn transaction(tx: &Transaction) -> Self {
        let payload = bincode::serialize(tx).unwrap_or_default();
        Self::new(MessageType::Transaction, payload)
    }

    /// Create Block message
    pub fn block(block: &Block) -> Self {
        let payload = bincode::serialize(block).unwrap_or_default();
        Self::new(MessageType::Block, payload)
    }

    /// Create GetBlock message
    pub fn get_block(slot: Slot) -> Self {
        Self::new(MessageType::GetBlock, slot.to_le_bytes().to_vec())
    }

    /// Create GetBlocks message (range)
    pub fn get_blocks(start_slot: Slot, count: u64) -> Self {
        let mut payload = start_slot.to_le_bytes().to_vec();
        payload.extend_from_slice(&count.to_le_bytes());
        Self::new(MessageType::GetBlocks, payload)
    }

    /// Create SyncRequest message
    pub fn sync_request(from_slot: Slot) -> Self {
        Self::new(MessageType::SyncRequest, from_slot.to_le_bytes().to_vec())
    }

    /// Create SyncResponse message
    pub fn sync_response(blocks: &[Block]) -> Self {
        let payload = bincode::serialize(blocks).unwrap_or_default();
        Self::new(MessageType::SyncResponse, payload)
    }

    /// Serialize message
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize message
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }

    /// Parse payload as PeerInfo
    pub fn parse_peer_info(&self) -> Option<PeerInfo> {
        bincode::deserialize(&self.payload).ok()
    }

    /// Parse payload as peers list
    pub fn parse_peers(&self) -> Option<Vec<PeerInfo>> {
        bincode::deserialize(&self.payload).ok()
    }

    /// Parse payload as transaction
    pub fn parse_transaction(&self) -> Option<Transaction> {
        bincode::deserialize(&self.payload).ok()
    }

    /// Parse payload as block
    pub fn parse_block(&self) -> Option<Block> {
        bincode::deserialize(&self.payload).ok()
    }

    /// Parse payload as blocks
    pub fn parse_blocks(&self) -> Option<Vec<Block>> {
        bincode::deserialize(&self.payload).ok()
    }

    /// Parse payload as slot
    pub fn parse_slot(&self) -> Option<Slot> {
        if self.payload.len() >= 8 {
            Some(u64::from_le_bytes(self.payload[..8].try_into().unwrap()))
        } else {
            None
        }
    }

    /// Parse payload as nonce
    pub fn parse_nonce(&self) -> Option<u64> {
        self.parse_slot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use crate::crypto::Pubkey;

    #[test]
    fn test_message_serialization() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001);
        let info = PeerInfo::new(Pubkey::zero(), addr);
        let msg = NetworkMessage::hello(&info);

        let serialized = msg.serialize();
        let deserialized = NetworkMessage::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.msg_type, MessageType::Hello);
        let parsed_info = deserialized.parse_peer_info().unwrap();
        assert_eq!(parsed_info.addr, addr);
    }

    #[test]
    fn test_ping_pong() {
        let ping = NetworkMessage::ping(12345);
        let pong = NetworkMessage::pong(12345);

        assert_eq!(ping.parse_nonce(), Some(12345));
        assert_eq!(pong.parse_nonce(), Some(12345));
    }
}
