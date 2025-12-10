//! Rate Limiter for RPC endpoints
//!
//! Implements IP-based rate limiting with sliding window algorithm
//! to prevent spam and DoS attacks.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Window duration
    pub window: Duration,
    /// Burst allowance (extra requests allowed in short bursts)
    pub burst_size: u32,
    /// Whether to enable rate limiting
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,      // 100 requests
            window: Duration::from_secs(60), // per minute
            burst_size: 20,         // allow bursts of 20
            enabled: true,
        }
    }
}

/// Per-IP rate limit state
#[derive(Debug)]
struct IpState {
    /// Request timestamps in current window
    requests: Vec<Instant>,
    /// Last request time
    last_request: Instant,
    /// Number of violations
    violations: u32,
    /// Blocked until (if blocked)
    blocked_until: Option<Instant>,
}

impl IpState {
    fn new() -> Self {
        Self {
            requests: Vec::new(),
            last_request: Instant::now(),
            violations: 0,
            blocked_until: None,
        }
    }
}

/// Rate limiter for RPC endpoints
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Per-IP state
    state: Arc<RwLock<HashMap<IpAddr, IpState>>>,
    /// Endpoint-specific limits (method name -> config)
    endpoint_limits: HashMap<String, RateLimitConfig>,
}

impl RateLimiter {
    /// Create a new rate limiter with default config
    pub fn new(config: RateLimitConfig) -> Self {
        let mut endpoint_limits = HashMap::new();

        // More restrictive limits for expensive endpoints
        endpoint_limits.insert(
            "cel_sendTransaction".to_string(),
            RateLimitConfig {
                max_requests: 30,
                window: Duration::from_secs(60),
                burst_size: 5,
                enabled: true,
            },
        );

        // Very restrictive for airdrop (faucet)
        endpoint_limits.insert(
            "cel_requestAirdrop".to_string(),
            RateLimitConfig {
                max_requests: 3,
                window: Duration::from_secs(3600), // 3 per hour
                burst_size: 1,
                enabled: true,
            },
        );

        // Read-only endpoints can be more permissive
        endpoint_limits.insert(
            "cel_getBalance".to_string(),
            RateLimitConfig {
                max_requests: 300,
                window: Duration::from_secs(60),
                burst_size: 50,
                enabled: true,
            },
        );

        Self {
            config,
            state: Arc::new(RwLock::new(HashMap::new())),
            endpoint_limits,
        }
    }

    /// Check if an IP is allowed to make a request
    pub fn check(&self, ip: IpAddr, method: Option<&str>) -> RateLimitResult {
        if !self.config.enabled {
            return RateLimitResult::Allowed;
        }

        let config = method
            .and_then(|m| self.endpoint_limits.get(m))
            .unwrap_or(&self.config);

        let now = Instant::now();
        let mut state = self.state.write();

        let ip_state = state.entry(ip).or_insert_with(IpState::new);

        // Check if IP is blocked
        if let Some(blocked_until) = ip_state.blocked_until {
            if now < blocked_until {
                let remaining = blocked_until.duration_since(now);
                return RateLimitResult::Blocked {
                    retry_after: remaining,
                    reason: "Too many violations".to_string(),
                };
            }
            // Block expired, clear it
            ip_state.blocked_until = None;
        }

        // Clean old requests outside window
        let window_start = now.checked_sub(config.window).unwrap_or(now);
        ip_state.requests.retain(|&t| t > window_start);

        // Check rate limit
        let request_count = ip_state.requests.len() as u32;

        if request_count >= config.max_requests {
            // Rate limit exceeded
            ip_state.violations += 1;

            // Block IP if too many violations
            if ip_state.violations >= 5 {
                let block_duration = Duration::from_secs(300); // 5 minutes
                ip_state.blocked_until = Some(now + block_duration);

                return RateLimitResult::Blocked {
                    retry_after: block_duration,
                    reason: "Repeated rate limit violations".to_string(),
                };
            }

            // Calculate retry time
            let oldest = ip_state.requests.first().copied().unwrap_or(now);
            let retry_after = config.window.saturating_sub(now.duration_since(oldest));

            return RateLimitResult::Limited {
                retry_after,
                remaining: 0,
            };
        }

        // Check burst limit
        let recent_window = Duration::from_secs(1);
        let recent_start = now.checked_sub(recent_window).unwrap_or(now);
        let recent_count = ip_state.requests.iter()
            .filter(|&&t| t > recent_start)
            .count() as u32;

        if recent_count >= config.burst_size {
            return RateLimitResult::Limited {
                retry_after: Duration::from_millis(100),
                remaining: config.max_requests.saturating_sub(request_count),
            };
        }

        // Allow request
        ip_state.requests.push(now);
        ip_state.last_request = now;

        // Reset violations on successful request
        if ip_state.violations > 0 && request_count < config.max_requests / 2 {
            ip_state.violations = ip_state.violations.saturating_sub(1);
        }

        RateLimitResult::Allowed
    }

    /// Record a request (call after check returns Allowed)
    pub fn record(&self, ip: IpAddr) {
        let mut state = self.state.write();
        if let Some(ip_state) = state.get_mut(&ip) {
            ip_state.last_request = Instant::now();
        }
    }

    /// Get current state for an IP
    pub fn get_state(&self, ip: IpAddr) -> Option<(u32, u32)> {
        let state = self.state.read();
        state.get(&ip).map(|s| {
            (s.requests.len() as u32, s.violations)
        })
    }

    /// Clean up old entries to prevent memory leaks
    pub fn cleanup(&self) {
        let now = Instant::now();
        let cleanup_threshold = Duration::from_secs(3600); // 1 hour

        let mut state = self.state.write();
        state.retain(|_, ip_state| {
            now.duration_since(ip_state.last_request) < cleanup_threshold
        });
    }

    /// Get statistics
    pub fn stats(&self) -> RateLimiterStats {
        let state = self.state.read();
        let total_ips = state.len();
        let blocked_ips = state.values()
            .filter(|s| s.blocked_until.is_some())
            .count();
        let total_violations: u32 = state.values()
            .map(|s| s.violations)
            .sum();

        RateLimiterStats {
            tracked_ips: total_ips,
            blocked_ips,
            total_violations,
        }
    }
}

/// Result of rate limit check
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed,
    /// Request is rate limited
    Limited {
        /// Time until limit resets
        retry_after: Duration,
        /// Remaining requests in window
        remaining: u32,
    },
    /// IP is blocked
    Blocked {
        /// Time until block expires
        retry_after: Duration,
        /// Reason for block
        reason: String,
    },
}

impl RateLimitResult {
    /// Check if request is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed)
    }
}

/// Rate limiter statistics
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    /// Number of IPs being tracked
    pub tracked_ips: usize,
    /// Number of currently blocked IPs
    pub blocked_ips: usize,
    /// Total violations across all IPs
    pub total_violations: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiter_allows_requests() {
        let config = RateLimitConfig {
            max_requests: 10,
            window: Duration::from_secs(60),
            burst_size: 5,
            enabled: true,
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First request should be allowed
        assert!(limiter.check(ip, None).is_allowed());
    }

    #[test]
    fn test_rate_limiter_blocks_after_limit() {
        let config = RateLimitConfig {
            max_requests: 3,
            window: Duration::from_secs(60),
            burst_size: 10,
            enabled: true,
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 requests should be allowed
        for _ in 0..3 {
            assert!(limiter.check(ip, None).is_allowed());
        }

        // 4th request should be rate limited
        assert!(!limiter.check(ip, None).is_allowed());
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let config = RateLimitConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
            burst_size: 1,
            enabled: false, // Disabled
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // All requests should be allowed when disabled
        for _ in 0..10 {
            assert!(limiter.check(ip, None).is_allowed());
        }
    }
}
