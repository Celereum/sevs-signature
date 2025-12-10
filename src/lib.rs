//! # Celereum Blockchain
//!
//! Swift Beyond Measure - A high-performance blockchain
//! designed for speed, security, and scalability.
//!
//! ## Core Features
//! - Proof of History (PoH) with Tower BFT consensus
//! - Parallel transaction execution (Sealevel-style)
//! - Tile-based architecture for isolation and parallelism
//! - FEC-enabled Turbine for reliable block propagation
//! - Stake-weighted QoS for spam protection
//! - Kernel bypass networking for low latency
//! - 10,000 TPS on consumer hardware
//! - Sub-500ms finality
//!
//! ## Hardware Requirements (Lite Mode)
//! - CPU: 4 cores @ 2.5GHz
//! - RAM: 16GB
//! - SSD: 200GB NVMe
//! - Network: 100Mbps symmetric

pub mod core;
pub mod consensus;
pub mod crypto;
pub mod network;
pub mod runtime;
pub mod storage;
pub mod rpc;
pub mod programs;
pub mod zk;
pub mod ordering;
pub mod validators;
pub mod objects;
pub mod tiles;
pub mod fec;
pub mod swqos;

// Re-exports
pub use core::*;
pub use crypto::Keypair;
pub use crypto::{Hash, Signature};
pub use storage::Storage;
pub use rpc::RpcServer;
pub use network::{NetworkNode, GossipService};
pub use runtime::{Bank, TransactionExecutor};
pub use runtime::{MemoryPool, SpscQueue, BatchProcessor, ShardedCounter, PerformanceMetrics};
pub use consensus::{GpuProofOfHistory, GpuPohConfig, BenchmarkResult};
pub use network::{TcpTransport, TcpConfig};
pub use storage::{StateCompressor, CompressionConfig, CompressionAlgorithm};
pub use zk::{ZkCompressor, ZkRollup, ZkState, Proof, ProofSystem};
pub use programs::{
    SystemProgram, TokenProgram, CEL20_PROGRAM_ID,
    AmmProgram, AMM_PROGRAM_ID, Pool,
    BridgeProgram, BRIDGE_PROGRAM_ID, BridgeConfig, BridgeTransfer,
    StakingProgram, STAKING_PROGRAM_ID, StakingInstruction, StakeState,
};

// RPC Security
pub use rpc::{RateLimiter, RateLimitConfig, RateLimitResult};

// MEV-Resistant Fair Ordering
pub use ordering::{
    FifoOrderer, FifoConfig, TimestampedTransaction, TimestampAttestation,
    BatchAuction, BatchConfig, ClearingPrice,
    CommitRevealOrderer, CommitRevealConfig, EncryptedTransaction,
    FairSequencer, SequencerConfig, OrderingMode,
};

// Single Slot Finality & Alpenglow
pub use consensus::{
    SsfEngine, SsfConfig, SsfVote, FinalityProof,
    Votor, VotorConfig, VotorVote, VotorResult,
    Rotor, RotorConfig, BlockChunk,
};

// Validator Management
pub use validators::{
    RegisteredValidator, ValidatorRegistry, ValidatorStatus,
    ValidatorConsolidation, ConsolidationConfig, EffectiveStake,
    RewardDistributor, RewardConfig, EpochRewards,
    SlashingEngine, SlashingConfig, Offense, SlashEvent,
};

// Object-Centric Model
pub use objects::{
    Object, ObjectId, ObjectRef, ObjectDigest, ObjectType,
    Owner, SharedObject, Ownership, OwnershipError,
    ObjectTransaction, ObjectInput, ObjectOutput, TransactionDigest,
    ObjectExecutor, ExecutionError,
};

// Tile Architecture
pub use tiles::{
    Tile, TileId, TileConfig, TileManager, TileMessage,
    NetTile, SigVerifyTile, BankTile, PohTile, ShredTile,
    TileError, TileStats,
};

// Forward Error Correction
pub use fec::{
    FecEncoder, FecDecoder, FecConfig, Shred, ShredType,
    DataShred, CodingShred, ShredError,
};

// Stake-weighted Quality of Service
pub use swqos::{
    SwQos, SwQosConfig, ConnectionQuota, PeerPriority,
    QosMetrics, SwQosError,
};

// =============================================================================
// NETWORK CONFIGURATION - Lite Mode (10K TPS on Consumer Hardware)
// =============================================================================

/// Celereum version
pub const CELEREUM_VERSION: &str = "0.3.0";

/// Target TPS - 10,000 for Lite mode
pub const TARGET_TPS: u64 = 10_000;

/// Ticks per second - reduced for lower CPU usage
pub const TICKS_PER_SECOND: u64 = 100;

/// Ticks per slot - reduced for testnet
pub const TICKS_PER_SLOT: u64 = 4;

/// Slot time in milliseconds (~320ms per slot)
pub const SLOT_TIME_MS: u64 = (TICKS_PER_SLOT * 1000) / TICKS_PER_SECOND;

/// Slots per epoch (~1 day with 320ms slots)
pub const SLOTS_PER_EPOCH: u64 = 270_000;

/// Celers per CEL (1 CEL = 10^9 celers)
pub const CELERS_PER_CEL: u64 = 1_000_000_000;

/// Max block size - 32MB for faster propagation
pub const MAX_BLOCK_SIZE: usize = 32 * 1024 * 1024;

/// Max transactions per block
pub const MAX_TX_PER_BLOCK: usize = 3_200; // 10K TPS * 0.32s

// =============================================================================
// VALIDATOR LIMITS
// =============================================================================

/// Minimum validators for network operation
pub const MIN_VALIDATORS: usize = 4;

/// Target validators for decentralization
pub const TARGET_VALIDATORS: usize = 100;

/// Maximum validators
pub const MAX_VALIDATORS: usize = 500;

// =============================================================================
// FEC CONFIGURATION
// =============================================================================

/// Data shreds per FEC set
pub const FEC_DATA_SHREDS: usize = 32;

/// Coding (parity) shreds per FEC set
pub const FEC_CODING_SHREDS: usize = 32;

/// Shred size in bytes
pub const SHRED_SIZE: usize = 1228;

// =============================================================================
// SWQOS CONFIGURATION
// =============================================================================

/// Base connections allowed per validator
pub const SWQOS_BASE_CONNECTIONS: usize = 10;

/// Max connections per validator (stake-weighted)
pub const SWQOS_MAX_CONNECTIONS: usize = 100;

/// Unstaked peer connection limit
pub const SWQOS_UNSTAKED_LIMIT: usize = 2;
