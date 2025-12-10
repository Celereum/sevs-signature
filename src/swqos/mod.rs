//! Stake-Weighted Quality of Service (SWQoS)
//!
//! Protects the network from spam by prioritizing connections and transactions
//! based on validator stake. Higher stake = more resources allocated.
//!
//! ## Key Features
//! - Connection quotas based on stake weight
//! - Transaction prioritization by stake
//! - Rate limiting for unstaked peers
//! - Sybil attack resistance
//!
//! ## How It Works
//! 1. Validators with stake get proportional connection quota
//! 2. Transactions forwarded through staked validators get priority
//! 3. Unstaked peers have very limited connection allowance
//! 4. Leader prioritizes packets from high-stake validators

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::RwLock;

use crate::crypto::Pubkey;
use crate::{SWQOS_BASE_CONNECTIONS, SWQOS_MAX_CONNECTIONS, SWQOS_UNSTAKED_LIMIT};

// =============================================================================
// CONFIGURATION
// =============================================================================

/// SWQoS configuration
#[derive(Debug, Clone)]
pub struct SwQosConfig {
    /// Base connections for any staked validator
    pub base_connections: usize,
    /// Maximum connections for highest-stake validators
    pub max_connections: usize,
    /// Connections allowed for unstaked peers
    pub unstaked_limit: usize,
    /// Total stake in the network (for percentage calculation)
    pub total_stake: u64,
    /// Minimum stake to be considered "staked"
    pub min_stake: u64,
    /// Rate limit window (for transaction rate limiting)
    pub rate_limit_window: Duration,
    /// Max transactions per window for unstaked peers
    pub unstaked_tx_limit: usize,
    /// Max packets per second from any single peer
    pub max_packets_per_second: usize,
}

impl Default for SwQosConfig {
    fn default() -> Self {
        Self {
            base_connections: SWQOS_BASE_CONNECTIONS,
            max_connections: SWQOS_MAX_CONNECTIONS,
            unstaked_limit: SWQOS_UNSTAKED_LIMIT,
            total_stake: 1_000_000_000, // 1B default
            min_stake: 1_000_000,       // 0.001 CEL minimum
            rate_limit_window: Duration::from_secs(1),
            unstaked_tx_limit: 10,
            max_packets_per_second: 1000,
        }
    }
}

// =============================================================================
// PEER PRIORITY
// =============================================================================

/// Priority level for a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PeerPriority {
    /// Unstaked peer - lowest priority
    Unstaked = 0,
    /// Low stake (< 0.1% of total)
    LowStake = 1,
    /// Medium stake (0.1% - 1%)
    MediumStake = 2,
    /// High stake (1% - 5%)
    HighStake = 3,
    /// Very high stake (> 5%)
    VeryHighStake = 4,
    /// Current leader - highest priority
    Leader = 5,
}

impl PeerPriority {
    /// Calculate priority from stake percentage
    pub fn from_stake_percentage(percentage: f64, is_leader: bool) -> Self {
        if is_leader {
            PeerPriority::Leader
        } else if percentage >= 5.0 {
            PeerPriority::VeryHighStake
        } else if percentage >= 1.0 {
            PeerPriority::HighStake
        } else if percentage >= 0.1 {
            PeerPriority::MediumStake
        } else if percentage > 0.0 {
            PeerPriority::LowStake
        } else {
            PeerPriority::Unstaked
        }
    }

    /// Get connection multiplier for this priority
    pub fn connection_multiplier(&self) -> f64 {
        match self {
            PeerPriority::Unstaked => 0.1,
            PeerPriority::LowStake => 1.0,
            PeerPriority::MediumStake => 2.0,
            PeerPriority::HighStake => 5.0,
            PeerPriority::VeryHighStake => 10.0,
            PeerPriority::Leader => 20.0,
        }
    }

    /// Get rate limit multiplier
    pub fn rate_limit_multiplier(&self) -> f64 {
        match self {
            PeerPriority::Unstaked => 0.1,
            PeerPriority::LowStake => 1.0,
            PeerPriority::MediumStake => 2.0,
            PeerPriority::HighStake => 4.0,
            PeerPriority::VeryHighStake => 8.0,
            PeerPriority::Leader => 16.0,
        }
    }
}

// =============================================================================
// CONNECTION QUOTA
// =============================================================================

/// Connection quota for a validator
#[derive(Debug, Clone)]
pub struct ConnectionQuota {
    /// Validator pubkey
    pub validator: Pubkey,
    /// Stake amount
    pub stake: u64,
    /// Stake percentage
    pub stake_percentage: f64,
    /// Priority level
    pub priority: PeerPriority,
    /// Maximum allowed connections
    pub max_connections: usize,
    /// Current active connections
    pub active_connections: usize,
    /// Transactions sent this window
    pub tx_count_window: usize,
    /// Window start time
    pub window_start: Instant,
}

impl ConnectionQuota {
    pub fn new(
        validator: Pubkey,
        stake: u64,
        total_stake: u64,
        config: &SwQosConfig,
        is_leader: bool,
    ) -> Self {
        let stake_percentage = if total_stake > 0 {
            (stake as f64 / total_stake as f64) * 100.0
        } else {
            0.0
        };

        let priority = PeerPriority::from_stake_percentage(stake_percentage, is_leader);

        let max_connections = if stake >= config.min_stake {
            let base = config.base_connections as f64;
            let multiplier = priority.connection_multiplier();
            ((base * multiplier) as usize).min(config.max_connections)
        } else {
            config.unstaked_limit
        };

        Self {
            validator,
            stake,
            stake_percentage,
            priority,
            max_connections,
            active_connections: 0,
            tx_count_window: 0,
            window_start: Instant::now(),
        }
    }

    /// Check if a new connection is allowed
    pub fn can_connect(&self) -> bool {
        self.active_connections < self.max_connections
    }

    /// Add a connection
    pub fn add_connection(&mut self) -> bool {
        if self.can_connect() {
            self.active_connections += 1;
            true
        } else {
            false
        }
    }

    /// Remove a connection
    pub fn remove_connection(&mut self) {
        self.active_connections = self.active_connections.saturating_sub(1);
    }

    /// Check if transaction is allowed (rate limiting)
    pub fn can_send_tx(&mut self, config: &SwQosConfig) -> bool {
        // Reset window if expired
        if self.window_start.elapsed() >= config.rate_limit_window {
            self.tx_count_window = 0;
            self.window_start = Instant::now();
        }

        let limit = if self.stake >= config.min_stake {
            (config.unstaked_tx_limit as f64 * self.priority.rate_limit_multiplier()) as usize
        } else {
            config.unstaked_tx_limit
        };

        self.tx_count_window < limit
    }

    /// Record a sent transaction
    pub fn record_tx(&mut self) {
        self.tx_count_window += 1;
    }
}

// =============================================================================
// SWQOS MANAGER
// =============================================================================

/// Stake-weighted QoS manager
pub struct SwQos {
    config: SwQosConfig,
    /// Validator stakes
    stakes: RwLock<HashMap<Pubkey, u64>>,
    /// Connection quotas per validator
    quotas: RwLock<HashMap<Pubkey, ConnectionQuota>>,
    /// Peer address to validator mapping
    peer_validators: RwLock<HashMap<SocketAddr, Pubkey>>,
    /// Current leader
    current_leader: RwLock<Option<Pubkey>>,
    /// Rate limiters per peer address
    rate_limiters: RwLock<HashMap<SocketAddr, RateLimiter>>,
    /// Metrics
    metrics: QosMetrics,
}

/// Simple rate limiter for a peer
struct RateLimiter {
    packets: AtomicU64,
    window_start: RwLock<Instant>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            packets: AtomicU64::new(0),
            window_start: RwLock::new(Instant::now()),
        }
    }

    fn check_and_increment(&self, max_per_second: usize) -> bool {
        let mut window_start = self.window_start.write();
        if window_start.elapsed() >= Duration::from_secs(1) {
            *window_start = Instant::now();
            self.packets.store(1, Ordering::Relaxed);
            true
        } else {
            let current = self.packets.fetch_add(1, Ordering::Relaxed);
            current < max_per_second as u64
        }
    }
}

impl SwQos {
    pub fn new(config: SwQosConfig) -> Self {
        Self {
            config,
            stakes: RwLock::new(HashMap::new()),
            quotas: RwLock::new(HashMap::new()),
            peer_validators: RwLock::new(HashMap::new()),
            current_leader: RwLock::new(None),
            rate_limiters: RwLock::new(HashMap::new()),
            metrics: QosMetrics::new(),
        }
    }

    /// Update validator stakes
    pub fn update_stakes(&self, stakes: HashMap<Pubkey, u64>) {
        let total: u64 = stakes.values().sum();
        let mut config = self.config.clone();
        config.total_stake = total;

        let current_leader = self.current_leader.read().clone();

        let mut quotas = self.quotas.write();
        quotas.clear();

        for (validator, stake) in &stakes {
            let is_leader = current_leader.as_ref() == Some(validator);
            quotas.insert(
                *validator,
                ConnectionQuota::new(*validator, *stake, total, &config, is_leader),
            );
        }

        *self.stakes.write() = stakes;
    }

    /// Set current leader
    pub fn set_leader(&self, leader: Pubkey) {
        *self.current_leader.write() = Some(leader);

        // Update leader's quota
        let mut quotas = self.quotas.write();
        if let Some(quota) = quotas.get_mut(&leader) {
            quota.priority = PeerPriority::Leader;
            quota.max_connections = self.config.max_connections;
        }
    }

    /// Register a peer connection
    pub fn register_peer(&self, addr: SocketAddr, validator: Option<Pubkey>) -> Result<(), SwQosError> {
        // Rate limit check
        {
            let mut limiters = self.rate_limiters.write();
            let limiter = limiters.entry(addr).or_insert_with(RateLimiter::new);
            if !limiter.check_and_increment(self.config.max_packets_per_second) {
                self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                return Err(SwQosError::RateLimited);
            }
        }

        if let Some(validator) = validator {
            let mut quotas = self.quotas.write();

            // Get or create quota
            let quota = quotas.entry(validator).or_insert_with(|| {
                let stake = self.stakes.read().get(&validator).copied().unwrap_or(0);
                let is_leader = self.current_leader.read().as_ref() == Some(&validator);
                ConnectionQuota::new(validator, stake, self.config.total_stake, &self.config, is_leader)
            });

            if quota.add_connection() {
                self.peer_validators.write().insert(addr, validator);
                self.metrics.connections_accepted.fetch_add(1, Ordering::Relaxed);
                Ok(())
            } else {
                self.metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                Err(SwQosError::QuotaExceeded)
            }
        } else {
            // Unstaked peer
            // Check global unstaked limit
            let peer_validators = self.peer_validators.read();
            let unstaked_count = peer_validators.len()
                - peer_validators.values()
                    .filter(|v| self.stakes.read().contains_key(v))
                    .count();

            if unstaked_count < self.config.unstaked_limit * 10 {
                self.metrics.connections_accepted.fetch_add(1, Ordering::Relaxed);
                Ok(())
            } else {
                self.metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                Err(SwQosError::UnstakedLimitReached)
            }
        }
    }

    /// Unregister a peer connection
    pub fn unregister_peer(&self, addr: SocketAddr) {
        if let Some(validator) = self.peer_validators.write().remove(&addr) {
            if let Some(quota) = self.quotas.write().get_mut(&validator) {
                quota.remove_connection();
            }
        }
    }

    /// Check if a transaction can be accepted from a peer
    pub fn can_accept_tx(&self, addr: SocketAddr) -> bool {
        let validator = self.peer_validators.read().get(&addr).copied();

        if let Some(validator) = validator {
            let mut quotas = self.quotas.write();
            if let Some(quota) = quotas.get_mut(&validator) {
                if quota.can_send_tx(&self.config) {
                    quota.record_tx();
                    self.metrics.tx_accepted.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
        }

        // Unstaked peer - apply strict rate limit
        let mut limiters = self.rate_limiters.write();
        let limiter = limiters.entry(addr).or_insert_with(RateLimiter::new);
        let allowed = limiter.check_and_increment(self.config.unstaked_tx_limit);

        if allowed {
            self.metrics.tx_accepted.fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics.tx_rejected.fetch_add(1, Ordering::Relaxed);
        }

        allowed
    }

    /// Get priority for sorting transactions
    pub fn get_tx_priority(&self, from_addr: SocketAddr) -> PeerPriority {
        let validator = self.peer_validators.read().get(&from_addr).copied();

        if let Some(validator) = validator {
            self.quotas.read()
                .get(&validator)
                .map(|q| q.priority)
                .unwrap_or(PeerPriority::Unstaked)
        } else {
            PeerPriority::Unstaked
        }
    }

    /// Get connection quota for a validator
    pub fn get_quota(&self, validator: &Pubkey) -> Option<ConnectionQuota> {
        self.quotas.read().get(validator).cloned()
    }

    /// Get metrics snapshot
    pub fn get_metrics(&self) -> QosMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Cleanup old rate limiters
    pub fn cleanup(&self) {
        let mut limiters = self.rate_limiters.write();
        limiters.retain(|_, limiter| {
            limiter.window_start.read().elapsed() < Duration::from_secs(60)
        });
    }
}

// =============================================================================
// METRICS
// =============================================================================

/// QoS metrics for monitoring
#[derive(Debug)]
pub struct QosMetrics {
    pub connections_accepted: AtomicU64,
    pub connections_rejected: AtomicU64,
    pub tx_accepted: AtomicU64,
    pub tx_rejected: AtomicU64,
    pub rate_limited: AtomicU64,
}

impl QosMetrics {
    pub fn new() -> Self {
        Self {
            connections_accepted: AtomicU64::new(0),
            connections_rejected: AtomicU64::new(0),
            tx_accepted: AtomicU64::new(0),
            tx_rejected: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> QosMetricsSnapshot {
        QosMetricsSnapshot {
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            connections_rejected: self.connections_rejected.load(Ordering::Relaxed),
            tx_accepted: self.tx_accepted.load(Ordering::Relaxed),
            tx_rejected: self.tx_rejected.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
        }
    }
}

impl Default for QosMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of metrics (non-atomic for serialization)
#[derive(Debug, Clone)]
pub struct QosMetricsSnapshot {
    pub connections_accepted: u64,
    pub connections_rejected: u64,
    pub tx_accepted: u64,
    pub tx_rejected: u64,
    pub rate_limited: u64,
}

// =============================================================================
// ERROR TYPES
// =============================================================================

#[derive(Debug, Clone, thiserror::Error)]
pub enum SwQosError {
    #[error("Connection quota exceeded for validator")]
    QuotaExceeded,

    #[error("Unstaked peer limit reached")]
    UnstakedLimitReached,

    #[error("Rate limited - too many requests")]
    RateLimited,

    #[error("Transaction rate limit exceeded")]
    TxRateLimited,

    #[error("Unknown validator")]
    UnknownValidator,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn test_priority_calculation() {
        assert_eq!(
            PeerPriority::from_stake_percentage(0.0, false),
            PeerPriority::Unstaked
        );
        assert_eq!(
            PeerPriority::from_stake_percentage(0.05, false),
            PeerPriority::LowStake
        );
        assert_eq!(
            PeerPriority::from_stake_percentage(0.5, false),
            PeerPriority::MediumStake
        );
        assert_eq!(
            PeerPriority::from_stake_percentage(2.0, false),
            PeerPriority::HighStake
        );
        assert_eq!(
            PeerPriority::from_stake_percentage(10.0, false),
            PeerPriority::VeryHighStake
        );
        assert_eq!(
            PeerPriority::from_stake_percentage(1.0, true),
            PeerPriority::Leader
        );
    }

    #[test]
    fn test_connection_quota() {
        let config = SwQosConfig::default();
        let validator = Keypair::generate().pubkey();

        // High stake validator
        let quota = ConnectionQuota::new(
            validator,
            50_000_000, // 5% stake
            1_000_000_000,
            &config,
            false,
        );

        assert_eq!(quota.priority, PeerPriority::VeryHighStake);
        assert!(quota.max_connections > config.base_connections);
        assert!(quota.can_connect());
    }

    #[test]
    fn test_swqos_registration() {
        let config = SwQosConfig::default();
        let swqos = SwQos::new(config);

        // Set up stakes
        let validator1 = Keypair::generate().pubkey();
        let validator2 = Keypair::generate().pubkey();

        let mut stakes = HashMap::new();
        stakes.insert(validator1, 100_000_000);
        stakes.insert(validator2, 50_000_000);
        swqos.update_stakes(stakes);

        // Register peer
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        assert!(swqos.register_peer(addr, Some(validator1)).is_ok());

        // Check quota
        let quota = swqos.get_quota(&validator1).unwrap();
        assert_eq!(quota.active_connections, 1);
    }

    #[test]
    fn test_rate_limiting() {
        let mut config = SwQosConfig::default();
        config.unstaked_tx_limit = 5;
        config.max_packets_per_second = 10;

        let swqos = SwQos::new(config);
        let addr: SocketAddr = "127.0.0.1:8001".parse().unwrap();

        // Should allow first few
        for _ in 0..5 {
            assert!(swqos.can_accept_tx(addr));
        }

        // Should eventually reject
        let mut rejected = false;
        for _ in 0..100 {
            if !swqos.can_accept_tx(addr) {
                rejected = true;
                break;
            }
        }
        assert!(rejected);
    }

    #[test]
    fn test_tx_priority() {
        let config = SwQosConfig::default();
        let swqos = SwQos::new(config);

        let validator = Keypair::generate().pubkey();
        let mut stakes = HashMap::new();
        stakes.insert(validator, 100_000_000);
        swqos.update_stakes(stakes);

        let addr: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        swqos.register_peer(addr, Some(validator)).unwrap();

        let priority = swqos.get_tx_priority(addr);
        assert!(priority > PeerPriority::Unstaked);
    }
}
