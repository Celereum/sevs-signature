//! Consensus mechanisms for Celereum blockchain
//!
//! Includes GPU-accelerated PoH and Parallel PoH for maximum throughput.
//!
//! ## PoH Variants
//! - `ProofOfHistory` - Basic single-threaded PoH
//! - `GpuProofOfHistory` - GPU-accelerated PoH with SIMD
//! - `ParallelProofOfHistory` - Multiple parallel PoH lanes for max TPS
//!
//! ## Tower BFT Optimizations
//! - Vote Batching: Aggregates votes in time windows
//! - Gulf Stream: Forwards transactions to upcoming leaders
//! - Turbine: Tree-based block propagation O(log n)
//! - Sliding Window: Bounded memory for vote storage
//!
//! ## BLS Signature Aggregation
//! - Aggregated votes: O(1) signature size regardless of validator count
//! - Proof of Possession: Prevents Rogue Key attacks
//! - Domain separation: Prevents cross-protocol attacks

pub mod poh;
pub mod gpu_poh;
pub mod parallel_poh;
pub mod tower_bft;
pub mod validator;
pub mod optimized;
pub mod bls_voting;
pub mod ssf;
pub mod alpenglow;

pub use poh::ProofOfHistory;
pub use gpu_poh::{GpuProofOfHistory, GpuPohConfig, BenchmarkResult};
pub use parallel_poh::{
    ParallelProofOfHistory, ParallelPohConfig, ParallelPohBenchmark,
    ParallelPohError, MergedEntry, LaneEntry,
    MAX_POH_LANES, MIN_POH_LANES, DEFAULT_POH_LANES, MERGE_INTERVAL_TICKS,
};
pub use tower_bft::TowerBFT;
pub use validator::{Validator, LeaderSchedule, ValidatorInfo as ConsensusValidatorInfo, ValidatorError};
pub use optimized::{
    OptimizedVoteAggregator, VoteBatcher, SlidingWindowVotes,
    GulfStream, Turbine, VoteBatch, TurbineLayer,
    LOCKOUT_TABLE, VOTE_WINDOW_SIZE, VOTE_BATCH_WINDOW_MS,
    TURBINE_FANOUT, GULF_STREAM_DEPTH,
};
pub use bls_voting::{
    BlsVote, AggregatedVotes, BlsVoteAggregator, BlsVoteError,
    BlsValidatorRegistration,
};
pub use ssf::{
    SsfEngine, SsfConfig, SsfVote, FinalityProof, SsfError,
};
pub use alpenglow::{
    Votor, VotorConfig, VotorVote, VotorResult, VotorFinalityProof, VotorStats,
    Rotor, RotorConfig, BlockChunk, RotorStats, VoteProgress,
};
