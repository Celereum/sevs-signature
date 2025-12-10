//! JSON-RPC API for Celereum
//!
//! Compatible with Solana RPC API where possible.
//!
//! ## Security Features
//! - Rate limiting per IP with sliding window
//! - Configurable CORS origins
//! - Request validation

mod server;
mod methods;
pub mod types;
pub mod rate_limiter;

pub use server::{RpcServer, RpcServerConfig};
pub use types::*;
pub use rate_limiter::{RateLimiter, RateLimitConfig, RateLimitResult, RateLimiterStats};
