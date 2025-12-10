//! Core types for Celereum blockchain
//!
//! # Post-Quantum Security
//! Celereum uses SEVS (Seed-Expanded Verkle Signatures) for transaction signing,
//! providing 128-bit post-quantum security with compact 128-byte signatures.
//!
//! ## Transaction Signing
//! All transactions use SEVS (quantum-safe) signatures:
//! - 128-byte signatures with 128-bit post-quantum security
//! - Constant-time verification
//! - Deterministic signing (no RNG during sign)
//!
//! ## Replay Protection
//! Transactions are protected from replay attacks via:
//! - Recent blockhash validation (max 150 slots old)
//! - Transaction hash tracking in TxPool
//! - Per-account transaction limits

pub mod account;
pub mod transaction;
pub mod block;
pub mod slot;
pub mod microblock;
pub mod tx_pool;

pub use account::Account;
pub use transaction::{Transaction, TransactionMessage, Instruction, MessageHeader};
pub use block::{Block, BlockHeader, Vote, VotedBlock, VestingSchedule};
pub use slot::Slot;
pub use microblock::{
    MicroBlock, MicroBlockHeader, MicroBlockChain, MicroBlockProducer, MicroBlockError,
    MAX_MICROBLOCKS_PER_SLOT, MIN_MICROBLOCK_INTERVAL_MS, MAX_TRANSACTIONS_PER_MICROBLOCK,
    DEFAULT_MICROBLOCK_INTERVAL_MS,
};
pub use tx_pool::{
    TxPool, TxPoolConfig, TxPoolError, TxPoolStats, SharedTxPool,
    MAX_BLOCKHASH_AGE_SLOTS, MAX_POOL_SIZE, MAX_PER_ACCOUNT,
};
