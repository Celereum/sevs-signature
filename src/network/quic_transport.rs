//! QUIC Transport Layer
//!
//! Ultra-fast, reliable transport using QUIC protocol.
//! Provides:
//! - 0-RTT connection establishment
//! - Multiplexed streams
//! - Built-in encryption
//! - Connection migration
//! - Congestion control optimized for blockchain

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;

use quinn::{
    Endpoint, ServerConfig, ClientConfig, Connection, SendStream, RecvStream,
    TransportConfig, IdleTimeout, VarInt,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, error, debug};

use crate::crypto::{Keypair, Pubkey};
use super::message::NetworkMessage;

/// QUIC Transport Configuration
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Maximum idle timeout
    pub idle_timeout: Duration,
    /// Keep-alive interval
    pub keep_alive_interval: Duration,
    /// Maximum concurrent streams
    pub max_concurrent_streams: u32,
    /// Initial RTT estimate (for faster initial connections)
    pub initial_rtt: Duration,
    /// Maximum UDP payload size
    pub max_udp_payload_size: u16,
    /// Enable 0-RTT for faster reconnections
    pub enable_0rtt: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(5),
            max_concurrent_streams: 1024,
            initial_rtt: Duration::from_millis(10), // Optimistic for fast networks
            max_udp_payload_size: 1472,
            enable_0rtt: true,
        }
    }
}

/// High-performance QUIC transport configuration
impl QuicConfig {
    /// Create configuration optimized for high throughput
    pub fn high_throughput() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            keep_alive_interval: Duration::from_secs(10),
            max_concurrent_streams: 4096,
            initial_rtt: Duration::from_millis(5),
            max_udp_payload_size: 1472,
            enable_0rtt: true,
        }
    }

    /// Create configuration optimized for low latency
    pub fn low_latency() -> Self {
        Self {
            idle_timeout: Duration::from_secs(15),
            keep_alive_interval: Duration::from_secs(2),
            max_concurrent_streams: 512,
            initial_rtt: Duration::from_millis(1),
            max_udp_payload_size: 1200,
            enable_0rtt: true,
        }
    }
}

/// QUIC Connection to a peer
#[derive(Debug)]
pub struct QuicPeer {
    /// Peer's public key
    pub pubkey: Pubkey,
    /// Remote address
    pub addr: SocketAddr,
    /// Quinn connection
    connection: Connection,
    /// Last activity timestamp
    pub last_activity: std::time::Instant,
}

impl QuicPeer {
    /// Send a message to this peer
    pub async fn send(&self, message: &NetworkMessage) -> Result<(), QuicError> {
        let data = bincode::serialize(message)
            .map_err(|e| QuicError::Serialization(e.to_string()))?;

        let mut send = self.connection.open_uni().await
            .map_err(|e| QuicError::Connection(e.to_string()))?;

        // Write length prefix
        let len = data.len() as u32;
        send.write_all(&len.to_le_bytes()).await
            .map_err(|e| QuicError::Write(e.to_string()))?;

        // Write data
        send.write_all(&data).await
            .map_err(|e| QuicError::Write(e.to_string()))?;

        send.finish()
            .map_err(|e| QuicError::Write(e.to_string()))?;

        Ok(())
    }

    /// Send raw bytes
    pub async fn send_raw(&self, data: &[u8]) -> Result<(), QuicError> {
        let mut send = self.connection.open_uni().await
            .map_err(|e| QuicError::Connection(e.to_string()))?;

        let len = data.len() as u32;
        send.write_all(&len.to_le_bytes()).await
            .map_err(|e| QuicError::Write(e.to_string()))?;

        send.write_all(data).await
            .map_err(|e| QuicError::Write(e.to_string()))?;

        send.finish()
            .map_err(|e| QuicError::Write(e.to_string()))?;

        Ok(())
    }

    /// Check if connection is still alive
    pub fn is_connected(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    /// Get connection RTT estimate
    pub fn rtt(&self) -> Duration {
        self.connection.rtt()
    }
}

/// QUIC Transport for peer-to-peer networking
pub struct QuicTransport {
    /// Local endpoint
    endpoint: Endpoint,
    /// Connected peers
    peers: Arc<RwLock<HashMap<Pubkey, QuicPeer>>>,
    /// Local identity
    keypair: Keypair,
    /// Configuration
    config: QuicConfig,
    /// Message receiver
    message_rx: Option<mpsc::Receiver<(Pubkey, NetworkMessage)>>,
    /// Message sender (for internal use)
    message_tx: mpsc::Sender<(Pubkey, NetworkMessage)>,
}

impl QuicTransport {
    /// Create a new QUIC transport
    pub async fn new(
        bind_addr: SocketAddr,
        keypair: Keypair,
        config: QuicConfig,
    ) -> Result<Self, QuicError> {
        // Generate self-signed certificate
        let (cert, key) = Self::generate_self_signed_cert()?;

        // Create server config
        let server_config = Self::create_server_config(cert.clone(), key, &config)?;

        // Create client config
        let client_config = Self::create_client_config(&config)?;

        // Create endpoint
        let mut endpoint = Endpoint::server(server_config, bind_addr)
            .map_err(|e| QuicError::Bind(e.to_string()))?;

        endpoint.set_default_client_config(client_config);

        let (message_tx, message_rx) = mpsc::channel(10000);

        info!("QUIC transport bound to {}", bind_addr);

        Ok(Self {
            endpoint,
            peers: Arc::new(RwLock::new(HashMap::new())),
            keypair,
            config,
            message_rx: Some(message_rx),
            message_tx,
        })
    }

    /// Generate self-signed certificate for QUIC
    fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), QuicError> {
        let cert = rcgen::generate_simple_self_signed(vec!["celereum".into()])
            .map_err(|e| QuicError::Certificate(e.to_string()))?;

        let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
        let cert = CertificateDer::from(cert.cert);

        Ok((cert, key))
    }

    /// Create server configuration
    fn create_server_config(
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        config: &QuicConfig,
    ) -> Result<ServerConfig, QuicError> {
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| QuicError::Certificate(e.to_string()))?;

        server_crypto.max_early_data_size = if config.enable_0rtt { u32::MAX } else { 0 };

        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(config.idle_timeout)
                .map_err(|e| QuicError::Config(e.to_string()))?
        ));
        transport.keep_alive_interval(Some(config.keep_alive_interval));
        transport.max_concurrent_uni_streams(VarInt::from_u32(config.max_concurrent_streams));
        transport.max_concurrent_bidi_streams(VarInt::from_u32(config.max_concurrent_streams));
        transport.initial_rtt(config.initial_rtt);

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| QuicError::Config(e.to_string()))?
        ));
        server_config.transport_config(Arc::new(transport));

        Ok(server_config)
    }

    /// Create client configuration
    fn create_client_config(config: &QuicConfig) -> Result<ClientConfig, QuicError> {
        let mut roots = rustls::RootCertStore::empty();

        // For development, we accept any certificate
        // In production, this should validate properly
        let client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(config.idle_timeout)
                .map_err(|e| QuicError::Config(e.to_string()))?
        ));
        transport.keep_alive_interval(Some(config.keep_alive_interval));
        transport.initial_rtt(config.initial_rtt);

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .map_err(|e| QuicError::Config(e.to_string()))?
        ));
        client_config.transport_config(Arc::new(transport));

        Ok(client_config)
    }

    /// Connect to a peer
    pub async fn connect(&self, addr: SocketAddr, peer_pubkey: Pubkey) -> Result<(), QuicError> {
        info!("Connecting to peer {} at {}", peer_pubkey, addr);

        let connection = self.endpoint
            .connect(addr, "celereum")
            .map_err(|e| QuicError::Connection(e.to_string()))?
            .await
            .map_err(|e| QuicError::Connection(e.to_string()))?;

        let peer = QuicPeer {
            pubkey: peer_pubkey,
            addr,
            connection,
            last_activity: std::time::Instant::now(),
        };

        self.peers.write().await.insert(peer_pubkey, peer);

        info!("Connected to peer {} (RTT: {:?})", peer_pubkey,
              self.peers.read().await.get(&peer_pubkey).map(|p| p.rtt()));

        Ok(())
    }

    /// Broadcast a message to all peers
    pub async fn broadcast(&self, message: &NetworkMessage) -> Result<usize, QuicError> {
        let peers = self.peers.read().await;
        let mut success_count = 0;

        for peer in peers.values() {
            if peer.is_connected() {
                match peer.send(message).await {
                    Ok(_) => success_count += 1,
                    Err(e) => warn!("Failed to send to {}: {}", peer.pubkey, e),
                }
            }
        }

        Ok(success_count)
    }

    /// Send to a specific peer
    pub async fn send_to(&self, pubkey: &Pubkey, message: &NetworkMessage) -> Result<(), QuicError> {
        let peers = self.peers.read().await;
        let peer = peers.get(pubkey)
            .ok_or(QuicError::PeerNotFound)?;

        peer.send(message).await
    }

    /// Get number of connected peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get all connected peer pubkeys
    pub async fn connected_peers(&self) -> Vec<Pubkey> {
        self.peers.read().await.keys().copied().collect()
    }

    /// Take the message receiver
    pub fn take_message_receiver(&mut self) -> Option<mpsc::Receiver<(Pubkey, NetworkMessage)>> {
        self.message_rx.take()
    }

    /// Start accepting incoming connections
    pub async fn start_accepting(&self) {
        let endpoint = self.endpoint.clone();
        let peers = self.peers.clone();
        let message_tx = self.message_tx.clone();

        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let peers = peers.clone();
                let message_tx = message_tx.clone();

                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            let remote_addr = connection.remote_address();
                            info!("Accepted connection from {}", remote_addr);

                            // For now, use a placeholder pubkey
                            // In production, this would be exchanged via handshake
                            let peer_pubkey = Pubkey::zero();

                            let peer = QuicPeer {
                                pubkey: peer_pubkey,
                                addr: remote_addr,
                                connection: connection.clone(),
                                last_activity: std::time::Instant::now(),
                            };

                            peers.write().await.insert(peer_pubkey, peer);

                            // Handle incoming streams
                            Self::handle_connection(connection, peer_pubkey, message_tx).await;
                        }
                        Err(e) => {
                            warn!("Failed to accept connection: {}", e);
                        }
                    }
                });
            }
        });
    }

    /// Handle incoming data on a connection
    async fn handle_connection(
        connection: Connection,
        peer_pubkey: Pubkey,
        message_tx: mpsc::Sender<(Pubkey, NetworkMessage)>,
    ) {
        loop {
            match connection.accept_uni().await {
                Ok(recv) => {
                    let message_tx = message_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_stream(recv, peer_pubkey, message_tx).await {
                            debug!("Stream error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    debug!("Connection closed: {}", e);
                    break;
                }
            }
        }
    }

    /// Handle a single stream
    async fn handle_stream(
        mut recv: RecvStream,
        peer_pubkey: Pubkey,
        message_tx: mpsc::Sender<(Pubkey, NetworkMessage)>,
    ) -> Result<(), QuicError> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await
            .map_err(|e| QuicError::Read(e.to_string()))?;
        let len = u32::from_le_bytes(len_buf) as usize;

        // Read data
        let mut data = vec![0u8; len];
        recv.read_exact(&mut data).await
            .map_err(|e| QuicError::Read(e.to_string()))?;

        // Deserialize message
        let message: NetworkMessage = bincode::deserialize(&data)
            .map_err(|e| QuicError::Serialization(e.to_string()))?;

        // Send to channel
        message_tx.send((peer_pubkey, message)).await
            .map_err(|e| QuicError::Channel(e.to_string()))?;

        Ok(())
    }

    /// Close the transport
    pub fn close(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"shutdown");
    }
}

/// Skip server certificate verification (for development)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// QUIC transport errors
#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    #[error("Bind error: {0}")]
    Bind(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Write error: {0}")]
    Write(String),

    #[error("Read error: {0}")]
    Read(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Peer not found")]
    PeerNotFound,

    #[error("Channel error: {0}")]
    Channel(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quic_config() {
        let config = QuicConfig::default();
        assert_eq!(config.max_concurrent_streams, 1024);

        let ht = QuicConfig::high_throughput();
        assert_eq!(ht.max_concurrent_streams, 4096);

        let ll = QuicConfig::low_latency();
        assert!(ll.initial_rtt < config.initial_rtt);
    }
}
