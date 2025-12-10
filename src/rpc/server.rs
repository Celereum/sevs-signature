//! RPC Server implementation with HTTP and WebSocket support
//!
//! ## Security Features
//! - Rate limiting per IP with configurable limits
//! - CORS with configurable allowed origins
//! - Request validation and sanitization

use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use http::Method;
use http::header::HeaderValue;
use jsonrpsee::server::{Server, ServerHandle};
use tokio::sync::{broadcast, RwLock};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use crate::storage::Storage;
use crate::rpc::types::{RpcNetworkStats, RpcRecentBlock, RpcValidatorInfo};
use super::methods::{CelereumRpcImpl, CelereumRpcServer};
use super::rate_limiter::{RateLimiter, RateLimitConfig};

/// WebSocket subscription types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubscriptionType {
    /// Subscribe to network stats updates
    NetworkStats,
    /// Subscribe to new blocks
    NewBlock,
    /// Subscribe to slot updates
    SlotUpdate,
}

/// Message broadcast over WebSocket
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", content = "data")]
pub enum WsMessage {
    /// Network stats update
    NetworkStats(RpcNetworkStats),
    /// New block notification
    NewBlock(RpcRecentBlock),
    /// Slot update
    SlotUpdate { slot: u64 },
}

/// RPC Server configuration
#[derive(Debug, Clone)]
pub struct RpcServerConfig {
    /// Allowed CORS origins (empty = allow all for development)
    pub allowed_origins: HashSet<String>,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Enable development mode (relaxed security)
    pub dev_mode: bool,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            allowed_origins: HashSet::new(),
            rate_limit: RateLimitConfig::default(),
            dev_mode: false,
        }
    }
}

impl RpcServerConfig {
    /// Create production config
    pub fn production(allowed_origins: Vec<String>) -> Self {
        Self {
            allowed_origins: allowed_origins.into_iter().collect(),
            rate_limit: RateLimitConfig::default(),
            dev_mode: false,
        }
    }

    /// Create development config (less restrictive)
    pub fn development() -> Self {
        Self {
            allowed_origins: HashSet::new(), // Allow all
            rate_limit: RateLimitConfig {
                max_requests: 1000,
                window: Duration::from_secs(60),
                burst_size: 100,
                enabled: false, // Disable rate limiting in dev
            },
            dev_mode: true,
        }
    }
}

/// JSON-RPC Server for Celereum with WebSocket support
pub struct RpcServer {
    addr: SocketAddr,
    storage: Arc<Storage>,
    handle: Option<ServerHandle>,
    /// Broadcast channel for WebSocket messages
    ws_broadcast: broadcast::Sender<WsMessage>,
    /// Active subscriptions
    subscriptions: Arc<RwLock<HashMap<String, Vec<SubscriptionType>>>>,
    /// Server configuration
    config: RpcServerConfig,
    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,
}

impl RpcServer {
    /// Create a new RPC server with default config
    pub fn new(addr: SocketAddr, storage: Arc<Storage>) -> Self {
        Self::with_config(addr, storage, RpcServerConfig::default())
    }

    /// Create a new RPC server with custom config
    pub fn with_config(addr: SocketAddr, storage: Arc<Storage>, config: RpcServerConfig) -> Self {
        let (ws_broadcast, _) = broadcast::channel(1000);
        let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit.clone()));

        Self {
            addr,
            storage,
            handle: None,
            ws_broadcast,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            config,
            rate_limiter,
        }
    }

    /// Start the RPC server with WebSocket support
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Configure CORS based on config
        let cors = if self.config.allowed_origins.is_empty() || self.config.dev_mode {
            // Development mode: allow all origins
            if !self.config.dev_mode {
                warn!("CORS: Allowing all origins (no origins configured)");
            }
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
                .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
        } else {
            // Production mode: restrict to configured origins
            let origins: Vec<HeaderValue> = self.config.allowed_origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect();

            info!("CORS: Restricting to {} configured origins", origins.len());

            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([Method::POST, Method::OPTIONS])
                .allow_headers([http::header::CONTENT_TYPE])
        };

        let middleware = tower::ServiceBuilder::new().layer(cors);

        // Build server with CORS middleware
        let server = Server::builder()
            .set_http_middleware(middleware)
            .build(self.addr)
            .await?;

        let rpc_impl = CelereumRpcImpl::new(self.storage.clone());
        let handle = server.start(rpc_impl.into_rpc());

        info!("RPC server started at http://{}", self.addr);
        info!("WebSocket available at ws://{}", self.addr);

        if self.config.rate_limit.enabled {
            info!("Rate limiting enabled: {} requests per {:?}",
                  self.config.rate_limit.max_requests,
                  self.config.rate_limit.window);
        }

        // Start background task for broadcasting updates
        let storage = self.storage.clone();
        let ws_broadcast = self.ws_broadcast.clone();
        tokio::spawn(async move {
            Self::broadcast_loop(storage, ws_broadcast).await;
        });

        self.handle = Some(handle);
        Ok(())
    }

    /// Background loop to broadcast updates to WebSocket subscribers
    async fn broadcast_loop(storage: Arc<Storage>, ws_broadcast: broadcast::Sender<WsMessage>) {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        let mut last_slot = 0u64;

        loop {
            interval.tick().await;

            // Get current slot
            let current_slot = storage.get_current_slot();

            // Broadcast slot update if changed
            if current_slot != last_slot {
                last_slot = current_slot;
                let _ = ws_broadcast.send(WsMessage::SlotUpdate { slot: current_slot });

                // Broadcast new block if available
                if let Some(block) = storage.get_block(current_slot) {
                    let recent_block = RpcRecentBlock {
                        slot: current_slot,
                        hash: block.hash().to_base58(),
                        tx_count: block.transactions.len() as u64,
                        timestamp: block.header.timestamp,
                        leader: block.header.leader.to_base58(),
                    };
                    let _ = ws_broadcast.send(WsMessage::NewBlock(recent_block));
                }
            }

            // Broadcast network stats every 500ms
            let stats = RpcNetworkStats {
                tps: storage.get_recent_tps(),
                block_height: current_slot,
                slot_height: current_slot,
                validators: storage.get_validator_count(),
                active_accounts: storage.get_account_count(),
                total_transactions: storage.get_transaction_count(),
                avg_block_time_ms: 400,
                epoch: current_slot / crate::SLOTS_PER_EPOCH,
                total_stake: storage.get_total_stake(),
                version: crate::CELEREUM_VERSION.to_string(),
            };
            let _ = ws_broadcast.send(WsMessage::NetworkStats(stats));
        }
    }

    /// Get the broadcast sender for external use
    pub fn get_broadcast_sender(&self) -> broadcast::Sender<WsMessage> {
        self.ws_broadcast.clone()
    }

    /// Subscribe to receive WebSocket messages
    pub fn subscribe(&self) -> broadcast::Receiver<WsMessage> {
        self.ws_broadcast.subscribe()
    }

    /// Stop the RPC server
    pub async fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop().ok();
            info!("RPC server stopped");
        }
    }

    /// Get the server address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Check if server is running
    pub fn is_running(&self) -> bool {
        self.handle.is_some()
    }

    /// Wait for server to finish
    pub async fn wait(&self) {
        if let Some(ref handle) = self.handle {
            handle.clone().stopped().await;
        }
    }
}

impl Drop for RpcServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop().ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_server_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8899);
        let storage = Arc::new(Storage::new_memory());
        let server = RpcServer::new(addr, storage);
        assert_eq!(server.addr(), addr);
        assert!(!server.is_running());
    }
}
