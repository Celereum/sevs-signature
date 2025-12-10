//! P2P Networking for Celereum
//!
//! Handles peer discovery, gossip protocol, and block propagation.
//! Supports multiple transport options for maximum performance.
//!
//! ## Transport Options
//! - **Kernel Bypass**: io_uring (Linux) / IOCP (Windows) for lowest latency
//! - **QUIC**: 0-RTT, multiplexed streams, built-in TLS
//! - **TCP**: Optimized TCP with Nagle disabled, connection pooling
//!
//! ## Optimizations
//! - Bloom Filter message deduplication (99.9% memory reduction)
//! - Rate limiting per peer (DoS protection)
//! - Selective gossip with sqrt(n) propagation
//! - Message batching for efficiency
//! - Zero-copy buffer pools

mod peer;
mod gossip;
mod node;
mod message;
mod optimized_tcp;
mod optimized;
mod kernel_bypass;

// QUIC Transport - Only available on non-Windows platforms
// Windows users should use TCP transport instead
#[cfg(not(target_os = "windows"))]
mod quic_transport;

pub use peer::{Peer, PeerInfo, PeerId};
pub use gossip::{GossipService, GossipConfig};
pub use node::{NetworkNode, NetworkConfig};
pub use message::{NetworkMessage, MessageType};
pub use optimized_tcp::{TcpTransport, TcpConfig, TcpPeer, TcpError};
pub use optimized::{
    MessageBloomFilter, RateLimiter, SelectiveGossip, MessageBatcher,
    BLOOM_FILTER_SIZE, MAX_MESSAGES_PER_SECOND, GOSSIP_FANOUT_FACTOR,
};

// Kernel Bypass Transport
pub use kernel_bypass::{
    KernelBypassTransport, KernelBypassConfig, TransportStats, TransportError,
    BufferPool, IoOp, IoRequest, IoCompletion,
};

#[cfg(not(target_os = "windows"))]
pub use quic_transport::{QuicTransport, QuicConfig, QuicPeer, QuicError};
