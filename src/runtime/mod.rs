//! Runtime / Sealevel - Parallel Transaction Execution
//!
//! Executes transactions in parallel when they don't conflict on account access.
//! Includes Firedancer-style high-performance optimizations.
//!
//! ## Optimizations
//! - Bloom Filter conflict detection (faster than HashSet)
//! - Lock-free batch formation
//! - Adaptive parallelism based on conflict rate
//! - Signature verification pipeline with deduplication

mod executor;
mod bank;
mod program;
mod firedancer;
mod sigverify;
mod optimized;

pub use executor::{TransactionExecutor, ExecutionResult};
pub use bank::Bank;
pub use program::{Program, ProgramId, SystemProgram, SYSTEM_PROGRAM_ID};
pub use firedancer::{
    MemoryPool, PoolStats, SpscQueue, BatchProcessor,
    ShardedCounter, PipelineStage, PerformanceMetrics,
};
pub use sigverify::{
    SigVerifyPipeline, SignatureDedup, CpuFeatures,
    VerifyResult, SigVerifyStats,
};
pub use optimized::{
    OptimizedExecutor, ConflictBloomFilter, AccessPattern,
    ParallelBatch, AdaptiveScheduler, ExecResult, ExecutorStatsSnapshot,
    CONFLICT_BLOOM_SIZE, MAX_BATCH_SIZE,
};
