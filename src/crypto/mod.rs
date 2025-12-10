//! Cryptographic primitives for Celereum
//!
//! # Features
//! - Hardware-accelerated hashing (SHA-NI, AVX2)
//! - SEVS post-quantum signatures (128 bytes, 128-bit security)
//! - BLS12-381 signature aggregation
//! - Encrypted keystore with Argon2id + AES-256-GCM
//! - VRF for leader selection (uses SEVS, quantum-safe)
//! - Cryptographic audit logging
//!
//! # Post-Quantum Security
//! Celereum uses SEVS (Seed-Expanded Verkle Signatures) as the ONLY
//! signature scheme, providing 128-bit post-quantum security
//! with only 128-byte signatures (18.9x smaller than Dilithium).
//!
//! ALL cryptographic operations use SEVS - no Ed25519!
//!
//! # Security
//! All operations use constant-time comparisons where applicable.
//! Private keys are zeroized on drop.

pub mod hash;
pub mod accelerated;
pub mod bls;
pub mod keystore;
pub mod vrf;
pub mod audit;
pub mod sevs;
pub mod sevs_gpu;
pub mod quantum_safe;
pub mod bech32;

// Core types
pub use hash::Hash;

// =============================================================================
// SEVS POST-QUANTUM SIGNATURES (EXCLUSIVE)
// =============================================================================

// SEVS types (direct exports)
pub use sevs::{
    SevsKeypair, SevsPubkey, SevsSignature, SevsSecretKey, SevsError,
    SIGNATURE_SIZE as SEVS_SIGNATURE_SIZE,
    PUBLIC_KEY_SIZE as SEVS_PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE as SEVS_SECRET_KEY_SIZE,
};

// Quantum-safe abstraction layer
pub use quantum_safe::{
    QsPubkey, QsSignature, QsKeypair, QsError, QsSigner,
    Address, TxSignature, MigrationConfig, AddressParseError,
    QS_SIGNATURE_SIZE, QS_PUBKEY_SIZE, ADDRESS_SIZE, TX_SIGNATURE_SIZE,
};

// Standard aliases for compatibility (ALL quantum-safe now)
pub use quantum_safe::Address as Pubkey;
pub use sevs::SevsKeypair as Keypair;
pub use quantum_safe::TxSignature as Signature;

// =============================================================================
// BLS SIGNATURES (for aggregation in consensus)
// =============================================================================

pub use bls::{
    BlsKeypair, BlsPublicKey, BlsSecretKey, BlsSignature,
    AggregatedBlsSignature, ProofOfPossession, RegisteredValidator,
    BlsError, batch_verify, dst,
};

// =============================================================================
// HARDWARE ACCELERATION
// =============================================================================

pub use accelerated::{
    AcceleratedSha256, BatchHasher, FastRandom, HardwareCapabilities,
    fast_hash, fast_hash_batch, poh_hash_chain,
    has_hardware_acceleration, hardware_info, benchmark_hash,
    get_capabilities, HashBenchmark,
};

// =============================================================================
// KEYSTORE & VRF
// =============================================================================

pub use keystore::{
    EncryptedKeystore, MultiKeystore, KeystoreMetadata, KeystoreError,
};

pub use vrf::{
    VrfKeypair, VrfProof, VrfOutput, VrfResult, VrfError,
    VrfLeaderSelector, VrfSortition,
};

// =============================================================================
// AUDIT LOGGING
// =============================================================================

pub use audit::{
    CryptoAuditLogger, AuditLogEntry, AuditLogBuilder, AuditConfig,
    CryptoOperation, OperationResult, LogLevel, AuditStats,
    global_logger, init_global_logger, audit_log,
};

// =============================================================================
// BECH32 ADDRESS ENCODING
// =============================================================================

pub use bech32::{
    encode_cel_address, decode_cel_address, is_valid_cel_address,
    is_cel1_format, is_base58_format, parse_address,
    Bech32Error, CEL_HRP, ADDRESS_BYTES,
};

// =============================================================================
// GPU ACCELERATION (OPTIONAL)
// =============================================================================

// GPU module is available but not re-exported to avoid name conflicts
// Use `crate::crypto::sevs_gpu::get_gpu_context()` directly if needed
