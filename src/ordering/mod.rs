//! MEV-Resistant Fair Ordering Module for Celereum
//!
//! This module implements multiple strategies to prevent Maximum Extractable Value (MEV)
//! attacks including front-running, sandwich attacks, and transaction reordering.
//!
//! # Strategies Implemented
//! 1. **FIFO Ordering**: First-In-First-Out ordering with verified timestamps
//! 2. **Batch Auction**: Uniform price execution for all transactions in a time window
//! 3. **Commit-Reveal**: Encrypted transaction submission with delayed reveal
//! 4. **Threshold Ordering**: Consensus-based timestamp verification
//!
//! # Security Features
//! - Timestamp verification by multiple validators
//! - Cryptographic commitment schemes
//! - Rate limiting to prevent spam
//! - Equivocation detection for timestamp manipulation

pub mod fifo;
pub mod batch_auction;
pub mod commit_reveal;
pub mod fair_sequencer;

pub use fifo::{
    FifoOrderer, FifoConfig, TimestampedTransaction,
    VerifiedTimestamp, TimestampAttestation,
};
pub use batch_auction::{
    BatchAuction, BatchConfig, AuctionBatch, BatchResult,
    UniformPriceCalculator, ClearingPrice,
};
pub use commit_reveal::{
    CommitRevealOrderer, CommitRevealConfig,
    EncryptedTransaction, TransactionCommitment,
    RevealedTransaction, CommitRevealError,
};
pub use fair_sequencer::{
    FairSequencer, SequencerConfig, OrderingMode,
    OrderingMetrics, FairOrderingError,
};
