//! FIFO (First-In-First-Out) Fair Ordering
//!
//! Implements timestamp-based ordering with multi-validator verification
//! to prevent transaction reordering attacks.
//!
//! # How it Works
//! 1. Transactions are timestamped upon arrival at each validator
//! 2. Multiple validators attest to the timestamp
//! 3. Consensus timestamp is the median of all attestations
//! 4. Transactions are ordered by consensus timestamp
//!
//! # Security
//! - Prevents front-running by honest timestamp ordering
//! - Median calculation resists up to 1/3 malicious validators
//! - Rate limiting prevents timestamp spam attacks

use crate::core::{Transaction, Slot};
use crate::crypto::{Hash, Keypair, Pubkey, Signature};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;

/// Configuration for FIFO ordering
#[derive(Debug, Clone)]
pub struct FifoConfig {
    /// Minimum attestations required for timestamp verification
    pub min_attestations: usize,
    /// Maximum time skew allowed between validators (ms)
    pub max_time_skew_ms: u64,
    /// Timeout for collecting attestations (ms)
    pub attestation_timeout_ms: u64,
    /// Maximum transactions per time window
    pub max_tx_per_window: usize,
    /// Time window size (ms)
    pub window_size_ms: u64,
    /// Enable strict timestamp verification
    pub strict_verification: bool,
}

impl Default for FifoConfig {
    fn default() -> Self {
        Self {
            min_attestations: 3,
            max_time_skew_ms: 500,
            attestation_timeout_ms: 1000,
            max_tx_per_window: 10_000,
            window_size_ms: 100,
            strict_verification: true,
        }
    }
}

/// A transaction with verified timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedTransaction {
    /// The original transaction
    pub transaction: Transaction,
    /// Transaction hash for deduplication
    pub hash: Hash,
    /// Verified consensus timestamp (microseconds since epoch)
    pub timestamp: u64,
    /// Attestations from validators
    pub attestations: Vec<TimestampAttestation>,
    /// Local arrival time (not consensus verified)
    pub local_arrival: u64,
}

impl TimestampedTransaction {
    /// Create a new timestamped transaction
    pub fn new(transaction: Transaction) -> Self {
        let hash = Hash::hash(&bincode::serialize(&transaction).unwrap_or_default());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            transaction,
            hash,
            timestamp: now,
            attestations: Vec::new(),
            local_arrival: now,
        }
    }

    /// Add an attestation
    pub fn add_attestation(&mut self, attestation: TimestampAttestation) {
        // Don't add duplicate attestations from same validator
        if !self.attestations.iter().any(|a| a.validator == attestation.validator) {
            self.attestations.push(attestation);
        }
    }

    /// Calculate consensus timestamp from attestations
    /// Uses median to resist manipulation
    pub fn calculate_consensus_timestamp(&mut self) -> Option<u64> {
        if self.attestations.is_empty() {
            return None;
        }

        let mut timestamps: Vec<u64> = self.attestations
            .iter()
            .map(|a| a.timestamp)
            .collect();
        timestamps.sort_unstable();

        // Median calculation
        let mid = timestamps.len() / 2;
        let consensus = if timestamps.len() % 2 == 0 {
            (timestamps[mid - 1] + timestamps[mid]) / 2
        } else {
            timestamps[mid]
        };

        self.timestamp = consensus;
        Some(consensus)
    }

    /// Check if transaction has enough attestations
    pub fn has_sufficient_attestations(&self, min_required: usize) -> bool {
        self.attestations.len() >= min_required
    }

    /// Verify all attestations are valid
    pub fn verify_attestations(&self) -> bool {
        for attestation in &self.attestations {
            if !attestation.verify(&self.hash) {
                return false;
            }
        }
        true
    }
}

impl PartialEq for TimestampedTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for TimestampedTransaction {}

impl PartialOrd for TimestampedTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimestampedTransaction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Order by timestamp, then by hash for determinism
        match self.timestamp.cmp(&other.timestamp) {
            std::cmp::Ordering::Equal => self.hash.as_bytes().cmp(other.hash.as_bytes()),
            other => other,
        }
    }
}

/// Timestamp attestation from a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampAttestation {
    /// Validator public key
    pub validator: Pubkey,
    /// Attested timestamp (microseconds)
    pub timestamp: u64,
    /// Signature over (tx_hash || timestamp)
    pub signature: Signature,
}

impl TimestampAttestation {
    /// Create a new attestation
    pub fn new(tx_hash: &Hash, keypair: &Keypair) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let message = Self::create_message(tx_hash, timestamp);
        let sevs_sig = keypair.sign(&message);
        let signature = crate::crypto::TxSignature::new(sevs_sig, keypair.pubkey());

        Self {
            validator: keypair.address(),
            timestamp,
            signature,
        }
    }

    /// Create with specific timestamp
    pub fn with_timestamp(tx_hash: &Hash, timestamp: u64, keypair: &Keypair) -> Self {
        let message = Self::create_message(tx_hash, timestamp);
        let sevs_sig = keypair.sign(&message);
        let signature = crate::crypto::TxSignature::new(sevs_sig, keypair.pubkey());

        Self {
            validator: keypair.address(),
            timestamp,
            signature,
        }
    }

    /// Create the message to sign
    fn create_message(tx_hash: &Hash, timestamp: u64) -> Vec<u8> {
        let mut message = Vec::with_capacity(40);
        message.extend_from_slice(tx_hash.as_bytes());
        message.extend_from_slice(&timestamp.to_le_bytes());
        message
    }

    /// Verify the attestation signature
    pub fn verify(&self, tx_hash: &Hash) -> bool {
        let message = Self::create_message(tx_hash, self.timestamp);
        self.signature.verify(&message)
    }
}

/// Verified timestamp with consensus proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedTimestamp {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Consensus timestamp
    pub timestamp: u64,
    /// Participating validators
    pub validators: Vec<Pubkey>,
    /// Merkle proof of inclusion (optional)
    pub inclusion_proof: Option<Hash>,
}

/// FIFO Orderer - maintains fair ordering of transactions
pub struct FifoOrderer {
    /// Configuration
    config: FifoConfig,
    /// Pending transactions awaiting attestations
    pending: RwLock<HashMap<Hash, TimestampedTransaction>>,
    /// Verified transactions ready for inclusion
    verified: RwLock<BTreeMap<(u64, Hash), TimestampedTransaction>>,
    /// Known validators for attestation
    validators: RwLock<HashSet<Pubkey>>,
    /// Rate limiting: tx count per window
    window_counts: RwLock<HashMap<u64, AtomicU64>>,
    /// Statistics
    stats: FifoStats,
}

/// FIFO orderer statistics
#[derive(Debug, Default)]
pub struct FifoStats {
    pub total_received: AtomicU64,
    pub total_verified: AtomicU64,
    pub total_rejected: AtomicU64,
    pub attestations_received: AtomicU64,
}

impl FifoOrderer {
    /// Create a new FIFO orderer
    pub fn new(config: FifoConfig) -> Self {
        Self {
            config,
            pending: RwLock::new(HashMap::new()),
            verified: RwLock::new(BTreeMap::new()),
            validators: RwLock::new(HashSet::new()),
            window_counts: RwLock::new(HashMap::new()),
            stats: FifoStats::default(),
        }
    }

    /// Register a validator for attestations
    pub fn register_validator(&self, validator: Pubkey) {
        self.validators.write().insert(validator);
    }

    /// Unregister a validator
    pub fn unregister_validator(&self, validator: &Pubkey) {
        self.validators.write().remove(validator);
    }

    /// Submit a new transaction
    pub fn submit_transaction(&self, transaction: Transaction) -> Result<Hash, FifoError> {
        self.stats.total_received.fetch_add(1, AtomicOrdering::Relaxed);

        // Create timestamped transaction
        let ts_tx = TimestampedTransaction::new(transaction);
        let hash = ts_tx.hash;

        // Check rate limiting
        let window = ts_tx.timestamp / (self.config.window_size_ms * 1000);
        {
            let mut windows = self.window_counts.write();
            let counter = windows.entry(window).or_insert_with(|| AtomicU64::new(0));
            let count = counter.fetch_add(1, AtomicOrdering::Relaxed);
            if count as usize >= self.config.max_tx_per_window {
                self.stats.total_rejected.fetch_add(1, AtomicOrdering::Relaxed);
                return Err(FifoError::RateLimitExceeded);
            }
        }

        // Add to pending
        let mut pending = self.pending.write();

        // Check for duplicate
        if pending.contains_key(&hash) {
            return Err(FifoError::DuplicateTransaction);
        }

        pending.insert(hash, ts_tx);
        Ok(hash)
    }

    /// Add an attestation for a transaction
    pub fn add_attestation(&self, tx_hash: Hash, attestation: TimestampAttestation) -> Result<(), FifoError> {
        // Verify validator is known
        if !self.validators.read().contains(&attestation.validator) {
            return Err(FifoError::UnknownValidator);
        }

        // Verify attestation signature
        if !attestation.verify(&tx_hash) {
            return Err(FifoError::InvalidAttestation);
        }

        self.stats.attestations_received.fetch_add(1, AtomicOrdering::Relaxed);

        // Add to pending transaction
        let mut pending = self.pending.write();
        let mut verified = self.verified.write();

        if let Some(tx) = pending.get_mut(&tx_hash) {
            // Check time skew
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64;

            let skew = if attestation.timestamp > now {
                attestation.timestamp - now
            } else {
                now - attestation.timestamp
            };

            if skew > self.config.max_time_skew_ms * 1000 {
                return Err(FifoError::ExcessiveTimeSkew);
            }

            tx.add_attestation(attestation);

            // Check if we have enough attestations
            if tx.has_sufficient_attestations(self.config.min_attestations) {
                // Calculate consensus timestamp
                if let Some(consensus_ts) = tx.calculate_consensus_timestamp() {
                    // Verify all attestations
                    if self.config.strict_verification && !tx.verify_attestations() {
                        self.stats.total_rejected.fetch_add(1, AtomicOrdering::Relaxed);
                        pending.remove(&tx_hash);
                        return Err(FifoError::InvalidAttestation);
                    }

                    // Move to verified
                    let tx = pending.remove(&tx_hash).unwrap();
                    verified.insert((consensus_ts, tx_hash), tx);
                    self.stats.total_verified.fetch_add(1, AtomicOrdering::Relaxed);
                }
            }
        } else if verified.contains_key(&(0, tx_hash)) {
            // Already verified, ignore
            return Ok(());
        } else {
            return Err(FifoError::TransactionNotFound);
        }

        Ok(())
    }

    /// Take ordered transactions for block production
    pub fn take_ordered(&self, max: usize) -> Vec<Transaction> {
        let mut verified = self.verified.write();

        let mut result = Vec::with_capacity(max.min(verified.len()));

        // Take from the front (lowest timestamps first - FIFO)
        while result.len() < max && !verified.is_empty() {
            if let Some((_, ts_tx)) = verified.pop_first() {
                result.push(ts_tx.transaction);
            }
        }

        result
    }

    /// Peek at ordered transactions without removing
    pub fn peek_ordered(&self, max: usize) -> Vec<TimestampedTransaction> {
        let verified = self.verified.read();

        verified.values()
            .take(max)
            .cloned()
            .collect()
    }

    /// Get the number of pending transactions
    pub fn pending_count(&self) -> usize {
        self.pending.read().len()
    }

    /// Get the number of verified transactions
    pub fn verified_count(&self) -> usize {
        self.verified.read().len()
    }

    /// Clean up expired pending transactions
    pub fn cleanup_expired(&self, max_age_ms: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let max_age_us = max_age_ms * 1000;

        let mut pending = self.pending.write();
        pending.retain(|_, tx| {
            now.saturating_sub(tx.local_arrival) < max_age_us
        });

        // Clean old rate limit windows
        let current_window = now / (self.config.window_size_ms * 1000);
        let mut windows = self.window_counts.write();
        windows.retain(|&window, _| window >= current_window.saturating_sub(10));
    }

    /// Get statistics
    pub fn stats(&self) -> FifoStatistics {
        FifoStatistics {
            total_received: self.stats.total_received.load(AtomicOrdering::Relaxed),
            total_verified: self.stats.total_verified.load(AtomicOrdering::Relaxed),
            total_rejected: self.stats.total_rejected.load(AtomicOrdering::Relaxed),
            attestations_received: self.stats.attestations_received.load(AtomicOrdering::Relaxed),
            pending_count: self.pending_count(),
            verified_count: self.verified_count(),
            validator_count: self.validators.read().len(),
        }
    }
}

/// FIFO ordering errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum FifoError {
    #[error("Rate limit exceeded for time window")]
    RateLimitExceeded,

    #[error("Duplicate transaction")]
    DuplicateTransaction,

    #[error("Unknown validator")]
    UnknownValidator,

    #[error("Invalid attestation signature")]
    InvalidAttestation,

    #[error("Excessive time skew")]
    ExcessiveTimeSkew,

    #[error("Transaction not found")]
    TransactionNotFound,

    #[error("Insufficient attestations")]
    InsufficientAttestations,
}

/// FIFO statistics
#[derive(Debug, Clone)]
pub struct FifoStatistics {
    pub total_received: u64,
    pub total_verified: u64,
    pub total_rejected: u64,
    pub attestations_received: u64,
    pub pending_count: usize,
    pub verified_count: usize,
    pub validator_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_transaction() -> Transaction {
        let keypair = Keypair::generate();
        Transaction::new_transfer(
            &keypair,
            Pubkey::new([2u8; 32]),
            100,
            Hash::hash(b"recent_blockhash"),
        )
    }

    #[test]
    fn test_fifo_orderer_basic() {
        let config = FifoConfig {
            min_attestations: 2,
            ..Default::default()
        };
        let orderer = FifoOrderer::new(config);

        // Register validators
        let v1 = Keypair::generate();
        let v2 = Keypair::generate();
        orderer.register_validator(v1.pubkey());
        orderer.register_validator(v2.pubkey());

        // Submit transaction
        let tx = create_test_transaction();
        let hash = orderer.submit_transaction(tx.clone()).unwrap();

        // Add attestations
        let att1 = TimestampAttestation::new(&hash, &v1);
        orderer.add_attestation(hash, att1).unwrap();

        let att2 = TimestampAttestation::new(&hash, &v2);
        orderer.add_attestation(hash, att2).unwrap();

        // Should be verified now
        assert_eq!(orderer.verified_count(), 1);
        assert_eq!(orderer.pending_count(), 0);

        // Take ordered transactions
        let ordered = orderer.take_ordered(10);
        assert_eq!(ordered.len(), 1);
    }

    #[test]
    fn test_timestamp_ordering() {
        let config = FifoConfig {
            min_attestations: 1,
            ..Default::default()
        };
        let orderer = FifoOrderer::new(config);

        let v1 = Keypair::generate();
        orderer.register_validator(v1.pubkey());

        // Submit multiple transactions
        let tx1 = create_test_transaction();
        let tx2 = create_test_transaction();
        let tx3 = create_test_transaction();

        let hash1 = orderer.submit_transaction(tx1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let hash2 = orderer.submit_transaction(tx2).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let hash3 = orderer.submit_transaction(tx3).unwrap();

        // Add attestations with specific timestamps to control order
        let base_time = 1000000u64;

        // tx3 gets earliest timestamp
        let att3 = TimestampAttestation::with_timestamp(&hash3, base_time, &v1);
        orderer.add_attestation(hash3, att3).unwrap();

        // tx1 gets middle timestamp
        let att1 = TimestampAttestation::with_timestamp(&hash1, base_time + 1000, &v1);
        orderer.add_attestation(hash1, att1).unwrap();

        // tx2 gets latest timestamp
        let att2 = TimestampAttestation::with_timestamp(&hash2, base_time + 2000, &v1);
        orderer.add_attestation(hash2, att2).unwrap();

        // Get ordered - should be tx3, tx1, tx2 (by timestamp)
        let ordered = orderer.peek_ordered(10);
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].timestamp, base_time);
        assert_eq!(ordered[1].timestamp, base_time + 1000);
        assert_eq!(ordered[2].timestamp, base_time + 2000);
    }

    #[test]
    fn test_invalid_attestation_rejected() {
        let config = FifoConfig::default();
        let orderer = FifoOrderer::new(config);

        let v1 = Keypair::generate();
        let v2 = Keypair::generate();
        orderer.register_validator(v1.pubkey());

        let tx = create_test_transaction();
        let hash = orderer.submit_transaction(tx).unwrap();

        // Try to add attestation from unregistered validator
        let att = TimestampAttestation::new(&hash, &v2);
        let result = orderer.add_attestation(hash, att);
        assert!(matches!(result, Err(FifoError::UnknownValidator)));
    }

    #[test]
    fn test_duplicate_transaction_rejected() {
        let config = FifoConfig::default();
        let orderer = FifoOrderer::new(config);

        let tx = create_test_transaction();
        orderer.submit_transaction(tx.clone()).unwrap();

        // Try to submit again
        let result = orderer.submit_transaction(tx);
        assert!(matches!(result, Err(FifoError::DuplicateTransaction)));
    }
}
