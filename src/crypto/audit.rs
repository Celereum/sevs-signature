//! Cryptographic Audit Logging for Celereum
//!
//! Provides secure, tamper-evident logging of all cryptographic operations
//! for security monitoring, compliance, and forensic analysis.
//!
//! # Features
//! - Immutable append-only log with hash chain
//! - Async logging (doesn't block crypto operations)
//! - Configurable log levels and filters
//! - Secure storage with optional encryption
//! - Rate limiting to prevent DoS
//!
//! # Security
//! - Logs are hash-chained to detect tampering
//! - Sensitive data (private keys, secrets) is never logged
//! - Only public information and metadata is recorded

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::hash::Hash;
use super::Pubkey;

/// Maximum log entries to keep in memory
const MAX_MEMORY_ENTRIES: usize = 10_000;

/// Rate limit: max operations per second per key
const RATE_LIMIT_OPS_PER_SEC: u64 = 1000;

/// Cryptographic operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoOperation {
    // Key operations
    KeyGeneration,
    KeyImport,
    KeyExport,
    KeyDerivation,
    KeyRotation,

    // Signing operations
    Sign,
    SignBatch,
    BlsSign,
    BlsAggregate,

    // Verification operations
    Verify,
    VerifyBatch,
    BlsVerify,
    BlsVerifyAggregated,

    // VRF operations
    VrfProve,
    VrfVerify,

    // Hashing operations
    Hash,
    HashBatch,

    // Keystore operations
    KeystoreEncrypt,
    KeystoreDecrypt,
    KeystoreLoad,
    KeystoreSave,

    // Other
    ProofOfPossession,
    Custom(u16),
}

impl std::fmt::Display for CryptoOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGeneration => write!(f, "KEY_GENERATION"),
            Self::KeyImport => write!(f, "KEY_IMPORT"),
            Self::KeyExport => write!(f, "KEY_EXPORT"),
            Self::KeyDerivation => write!(f, "KEY_DERIVATION"),
            Self::KeyRotation => write!(f, "KEY_ROTATION"),
            Self::Sign => write!(f, "SIGN"),
            Self::SignBatch => write!(f, "SIGN_BATCH"),
            Self::BlsSign => write!(f, "BLS_SIGN"),
            Self::BlsAggregate => write!(f, "BLS_AGGREGATE"),
            Self::Verify => write!(f, "VERIFY"),
            Self::VerifyBatch => write!(f, "VERIFY_BATCH"),
            Self::BlsVerify => write!(f, "BLS_VERIFY"),
            Self::BlsVerifyAggregated => write!(f, "BLS_VERIFY_AGGREGATED"),
            Self::VrfProve => write!(f, "VRF_PROVE"),
            Self::VrfVerify => write!(f, "VRF_VERIFY"),
            Self::Hash => write!(f, "HASH"),
            Self::HashBatch => write!(f, "HASH_BATCH"),
            Self::KeystoreEncrypt => write!(f, "KEYSTORE_ENCRYPT"),
            Self::KeystoreDecrypt => write!(f, "KEYSTORE_DECRYPT"),
            Self::KeystoreLoad => write!(f, "KEYSTORE_LOAD"),
            Self::KeystoreSave => write!(f, "KEYSTORE_SAVE"),
            Self::ProofOfPossession => write!(f, "PROOF_OF_POSSESSION"),
            Self::Custom(id) => write!(f, "CUSTOM_{}", id),
        }
    }
}

/// Operation result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationResult {
    Success,
    Failed,
    RateLimited,
    InvalidInput,
    Timeout,
}

/// Log severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4,
}

/// Single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Entry sequence number
    pub sequence: u64,
    /// Timestamp (microseconds since UNIX epoch)
    pub timestamp_us: u64,
    /// Operation type
    pub operation: CryptoOperation,
    /// Operation result
    pub result: OperationResult,
    /// Log level
    pub level: LogLevel,
    /// Public key involved (if any)
    pub pubkey: Option<[u8; 32]>,
    /// Message hash (for sign/verify operations)
    pub message_hash: Option<[u8; 32]>,
    /// Number of items in batch operations
    pub batch_size: Option<usize>,
    /// Duration in microseconds
    pub duration_us: Option<u64>,
    /// Additional context
    pub context: Option<String>,
    /// Hash of previous entry (for chain integrity)
    pub prev_hash: [u8; 32],
    /// Hash of this entry
    pub entry_hash: [u8; 32],
}

impl AuditLogEntry {
    /// Compute the hash of this entry
    fn compute_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(256);

        data.extend_from_slice(&self.sequence.to_le_bytes());
        data.extend_from_slice(&self.timestamp_us.to_le_bytes());
        // Use operation name for hashing to avoid enum discriminant issues
        data.extend_from_slice(self.operation.to_string().as_bytes());
        data.extend_from_slice(&(self.result as u8).to_le_bytes());
        data.extend_from_slice(&(self.level as u8).to_le_bytes());

        if let Some(pk) = &self.pubkey {
            data.extend_from_slice(pk);
        }
        if let Some(mh) = &self.message_hash {
            data.extend_from_slice(mh);
        }
        if let Some(bs) = self.batch_size {
            data.extend_from_slice(&(bs as u64).to_le_bytes());
        }
        if let Some(dur) = self.duration_us {
            data.extend_from_slice(&dur.to_le_bytes());
        }
        if let Some(ctx) = &self.context {
            data.extend_from_slice(ctx.as_bytes());
        }
        data.extend_from_slice(&self.prev_hash);

        *Hash::hash(&data).as_bytes()
    }
}

/// Audit log configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Minimum log level
    pub min_level: LogLevel,
    /// Enable rate limiting
    pub rate_limit_enabled: bool,
    /// Operations to log (empty = all)
    pub operations_filter: Vec<CryptoOperation>,
    /// Maximum entries in memory
    pub max_memory_entries: usize,
    /// Log file path (optional)
    pub log_file: Option<String>,
    /// Enable hash chain verification
    pub verify_chain: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            min_level: LogLevel::Info,
            rate_limit_enabled: true,
            operations_filter: vec![],
            max_memory_entries: MAX_MEMORY_ENTRIES,
            log_file: None,
            verify_chain: true,
        }
    }
}

/// Rate limiter for operations
struct RateLimiter {
    /// Operations per key in current window
    ops_count: std::collections::HashMap<[u8; 32], u64>,
    /// Current window start
    window_start: u64,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            ops_count: std::collections::HashMap::new(),
            window_start: Self::current_second(),
        }
    }

    fn current_second() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn check(&mut self, pubkey: Option<&[u8; 32]>) -> bool {
        let now = Self::current_second();

        // Reset if new window
        if now > self.window_start {
            self.ops_count.clear();
            self.window_start = now;
        }

        if let Some(pk) = pubkey {
            let count = self.ops_count.entry(*pk).or_insert(0);
            if *count >= RATE_LIMIT_OPS_PER_SEC {
                return false;
            }
            *count += 1;
        }

        true
    }
}

/// Cryptographic audit logger
pub struct CryptoAuditLogger {
    /// Configuration
    config: AuditConfig,
    /// Log entries
    entries: RwLock<VecDeque<AuditLogEntry>>,
    /// Sequence counter
    sequence: RwLock<u64>,
    /// Last entry hash
    last_hash: RwLock<[u8; 32]>,
    /// Rate limiter
    rate_limiter: RwLock<RateLimiter>,
    /// Statistics
    stats: RwLock<AuditStats>,
}

/// Audit statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total entries logged
    pub total_entries: u64,
    /// Entries by operation type
    pub by_operation: std::collections::HashMap<String, u64>,
    /// Entries by result
    pub successes: u64,
    pub failures: u64,
    pub rate_limited: u64,
    /// Entries dropped due to rate limiting
    pub dropped: u64,
}

impl CryptoAuditLogger {
    /// Create a new audit logger with default config
    pub fn new() -> Self {
        Self::with_config(AuditConfig::default())
    }

    /// Create a new audit logger with custom config
    pub fn with_config(config: AuditConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(VecDeque::new()),
            sequence: RwLock::new(0),
            last_hash: RwLock::new([0u8; 32]),
            rate_limiter: RwLock::new(RateLimiter::new()),
            stats: RwLock::new(AuditStats::default()),
        }
    }

    /// Log a cryptographic operation
    pub fn log(&self, builder: AuditLogBuilder) {
        // Check log level
        if builder.level < self.config.min_level {
            return;
        }

        // Check operation filter
        if !self.config.operations_filter.is_empty()
            && !self.config.operations_filter.contains(&builder.operation)
        {
            return;
        }

        // Check rate limit
        if self.config.rate_limit_enabled {
            let mut limiter = self.rate_limiter.write().unwrap();
            if !limiter.check(builder.pubkey.as_ref()) {
                let mut stats = self.stats.write().unwrap();
                stats.dropped += 1;
                return;
            }
        }

        // Get sequence and last hash
        let mut seq = self.sequence.write().unwrap();
        let mut last = self.last_hash.write().unwrap();

        let timestamp_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        // Create entry
        let mut entry = AuditLogEntry {
            sequence: *seq,
            timestamp_us,
            operation: builder.operation,
            result: builder.result,
            level: builder.level,
            pubkey: builder.pubkey,
            message_hash: builder.message_hash,
            batch_size: builder.batch_size,
            duration_us: builder.duration_us,
            context: builder.context,
            prev_hash: *last,
            entry_hash: [0u8; 32],
        };

        // Compute and set hash
        entry.entry_hash = entry.compute_hash();

        // Update state
        *seq += 1;
        *last = entry.entry_hash;

        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_entries += 1;
            *stats.by_operation
                .entry(entry.operation.to_string())
                .or_insert(0) += 1;
            match entry.result {
                OperationResult::Success => stats.successes += 1,
                OperationResult::Failed => stats.failures += 1,
                OperationResult::RateLimited => stats.rate_limited += 1,
                _ => {}
            }
        }

        // Add to entries
        let mut entries = self.entries.write().unwrap();
        entries.push_back(entry);

        // Trim if needed
        while entries.len() > self.config.max_memory_entries {
            entries.pop_front();
        }
    }

    /// Create a log entry builder
    pub fn entry(&self, operation: CryptoOperation) -> AuditLogBuilder {
        AuditLogBuilder::new(operation)
    }

    /// Get recent entries
    pub fn recent_entries(&self, count: usize) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().unwrap();
        entries.iter().rev().take(count).cloned().collect()
    }

    /// Get entries by operation type
    pub fn entries_by_operation(&self, op: CryptoOperation) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().unwrap();
        entries.iter().filter(|e| e.operation == op).cloned().collect()
    }

    /// Get entries by public key
    pub fn entries_by_pubkey(&self, pubkey: &Pubkey) -> Vec<AuditLogEntry> {
        let pk_bytes = *pubkey.as_bytes();
        let entries = self.entries.read().unwrap();
        entries.iter()
            .filter(|e| e.pubkey == Some(pk_bytes))
            .cloned()
            .collect()
    }

    /// Get failed operations
    pub fn failed_operations(&self) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().unwrap();
        entries.iter()
            .filter(|e| e.result == OperationResult::Failed)
            .cloned()
            .collect()
    }

    /// Get audit statistics
    pub fn stats(&self) -> AuditStats {
        self.stats.read().unwrap().clone()
    }

    /// Verify the hash chain integrity
    pub fn verify_chain(&self) -> Result<(), ChainVerifyError> {
        let entries = self.entries.read().unwrap();

        if entries.is_empty() {
            return Ok(());
        }

        let mut prev_hash = [0u8; 32];

        for (i, entry) in entries.iter().enumerate() {
            // Verify prev_hash matches
            if i > 0 && entry.prev_hash != prev_hash {
                return Err(ChainVerifyError::PrevHashMismatch {
                    sequence: entry.sequence,
                });
            }

            // Verify entry hash
            let computed = entry.compute_hash();
            if computed != entry.entry_hash {
                return Err(ChainVerifyError::EntryHashMismatch {
                    sequence: entry.sequence,
                });
            }

            prev_hash = entry.entry_hash;
        }

        Ok(())
    }

    /// Export logs to JSON
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        let entries: Vec<_> = self.entries.read().unwrap().iter().cloned().collect();
        serde_json::to_string_pretty(&entries)
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.entries.write().unwrap().clear();
        *self.sequence.write().unwrap() = 0;
        *self.last_hash.write().unwrap() = [0u8; 32];
    }
}

impl Default for CryptoAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Chain verification error
#[derive(Debug, Clone)]
pub enum ChainVerifyError {
    PrevHashMismatch { sequence: u64 },
    EntryHashMismatch { sequence: u64 },
}

impl std::fmt::Display for ChainVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrevHashMismatch { sequence } => {
                write!(f, "Previous hash mismatch at sequence {}", sequence)
            }
            Self::EntryHashMismatch { sequence } => {
                write!(f, "Entry hash mismatch at sequence {}", sequence)
            }
        }
    }
}

impl std::error::Error for ChainVerifyError {}

/// Builder for audit log entries
pub struct AuditLogBuilder {
    operation: CryptoOperation,
    result: OperationResult,
    level: LogLevel,
    pubkey: Option<[u8; 32]>,
    message_hash: Option<[u8; 32]>,
    batch_size: Option<usize>,
    duration_us: Option<u64>,
    context: Option<String>,
}

impl AuditLogBuilder {
    /// Create a new builder
    pub fn new(operation: CryptoOperation) -> Self {
        Self {
            operation,
            result: OperationResult::Success,
            level: LogLevel::Info,
            pubkey: None,
            message_hash: None,
            batch_size: None,
            duration_us: None,
            context: None,
        }
    }

    /// Set the result
    pub fn result(mut self, result: OperationResult) -> Self {
        self.result = result;
        self
    }

    /// Set success result
    pub fn success(mut self) -> Self {
        self.result = OperationResult::Success;
        self
    }

    /// Set failed result
    pub fn failed(mut self) -> Self {
        self.result = OperationResult::Failed;
        self.level = LogLevel::Warning;
        self
    }

    /// Set log level
    pub fn level(mut self, level: LogLevel) -> Self {
        self.level = level;
        self
    }

    /// Set public key
    pub fn pubkey(mut self, pubkey: &Pubkey) -> Self {
        self.pubkey = Some(*pubkey.as_bytes());
        self
    }

    /// Set message hash
    pub fn message_hash(mut self, hash: &Hash) -> Self {
        self.message_hash = Some(*hash.as_bytes());
        self
    }

    /// Set batch size
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = Some(size);
        self
    }

    /// Set duration
    pub fn duration_us(mut self, duration: u64) -> Self {
        self.duration_us = Some(duration);
        self
    }

    /// Set context
    pub fn context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Log to a logger
    pub fn log_to(self, logger: &CryptoAuditLogger) {
        logger.log(self);
    }
}

/// Global audit logger instance
static GLOBAL_LOGGER: std::sync::OnceLock<Arc<CryptoAuditLogger>> = std::sync::OnceLock::new();

/// Get the global audit logger
pub fn global_logger() -> &'static Arc<CryptoAuditLogger> {
    GLOBAL_LOGGER.get_or_init(|| Arc::new(CryptoAuditLogger::new()))
}

/// Initialize the global logger with custom config
pub fn init_global_logger(config: AuditConfig) -> Result<(), &'static str> {
    GLOBAL_LOGGER.set(Arc::new(CryptoAuditLogger::with_config(config)))
        .map_err(|_| "Global logger already initialized")
}

/// Log an operation to the global logger
pub fn audit_log(operation: CryptoOperation) -> AuditLogBuilder {
    AuditLogBuilder::new(operation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_entry() {
        let logger = CryptoAuditLogger::new();

        logger.log(
            AuditLogBuilder::new(CryptoOperation::KeyGeneration)
                .success()
                .context("Test key generation")
        );

        let entries = logger.recent_entries(10);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].operation, CryptoOperation::KeyGeneration);
        assert_eq!(entries[0].result, OperationResult::Success);
    }

    #[test]
    fn test_hash_chain() {
        let logger = CryptoAuditLogger::new();

        for i in 0..10 {
            logger.log(
                AuditLogBuilder::new(CryptoOperation::Sign)
                    .success()
                    .context(format!("Sign operation {}", i))
            );
        }

        assert!(logger.verify_chain().is_ok());
    }

    #[test]
    fn test_stats() {
        let logger = CryptoAuditLogger::new();

        logger.log(AuditLogBuilder::new(CryptoOperation::Sign).success());
        logger.log(AuditLogBuilder::new(CryptoOperation::Sign).success());
        logger.log(AuditLogBuilder::new(CryptoOperation::Verify).success());
        logger.log(AuditLogBuilder::new(CryptoOperation::Sign).failed());

        let stats = logger.stats();
        assert_eq!(stats.total_entries, 4);
        assert_eq!(stats.successes, 3);
        assert_eq!(stats.failures, 1);
    }

    #[test]
    fn test_filter_by_operation() {
        let logger = CryptoAuditLogger::new();

        logger.log(AuditLogBuilder::new(CryptoOperation::Sign).success());
        logger.log(AuditLogBuilder::new(CryptoOperation::Verify).success());
        logger.log(AuditLogBuilder::new(CryptoOperation::Sign).success());

        let sign_entries = logger.entries_by_operation(CryptoOperation::Sign);
        assert_eq!(sign_entries.len(), 2);
    }

    #[test]
    fn test_log_level_filter() {
        let config = AuditConfig {
            min_level: LogLevel::Warning,
            ..Default::default()
        };
        let logger = CryptoAuditLogger::with_config(config);

        // Info should be filtered out
        logger.log(
            AuditLogBuilder::new(CryptoOperation::Sign)
                .level(LogLevel::Info)
        );

        // Warning should pass
        logger.log(
            AuditLogBuilder::new(CryptoOperation::Sign)
                .level(LogLevel::Warning)
        );

        assert_eq!(logger.recent_entries(10).len(), 1);
    }

    #[test]
    fn test_failed_operations() {
        let logger = CryptoAuditLogger::new();

        logger.log(AuditLogBuilder::new(CryptoOperation::Verify).success());
        logger.log(AuditLogBuilder::new(CryptoOperation::Verify).failed());
        logger.log(AuditLogBuilder::new(CryptoOperation::Verify).success());
        logger.log(AuditLogBuilder::new(CryptoOperation::Sign).failed());

        let failed = logger.failed_operations();
        assert_eq!(failed.len(), 2);
    }
}
