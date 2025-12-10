//! Storage Layer for Celereum
//!
//! Handles persistent storage of accounts, blocks, and transactions.
//! Includes state compression for reduced storage and faster sync.
//!
//! ## Optimizations
//! - Write Coalescing: Batches writes per slot
//! - Priority Mempool: Bounded with fee-based ordering
//! - Hot Account Cache: LRU cache for frequently accessed accounts

mod accounts;
mod blocks;
mod engine;
mod compression;
mod optimized;

pub use engine::{Storage, ValidatorInfo};
pub use accounts::AccountStore;
pub use blocks::BlockStore;
pub use compression::{
    StateCompressor, CompressionConfig, CompressionAlgorithm,
    CompressedData, CompressionStats, CompressionError,
    BatchCompressor,
};
pub use optimized::{
    OptimizedStorage, BoundedMempool, WriteCoalescer, HotAccountCache,
    PriorityTransaction, MempoolStats, CoalesceStats, CacheStats,
    OptimizedStorageStats,
    MAX_MEMPOOL_SIZE, DEFAULT_MEMPOOL_SIZE, HOT_CACHE_SIZE,
};
