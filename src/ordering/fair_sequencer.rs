//! Fair Sequencer - Unified MEV Protection Controller
//!
//! This module provides a unified interface for combining multiple
//! MEV protection strategies: FIFO, Batch Auction, and Commit-Reveal.
//!
//! # Modes of Operation
//! - **FIFO Only**: Simple timestamp-based ordering
//! - **Batch Only**: Uniform price auctions for DEX
//! - **Commit-Reveal Only**: Maximum privacy for sensitive transactions
//! - **Hybrid**: Combines strategies based on transaction type
//!
//! # Usage
//! The fair sequencer acts as the main entry point for transaction submission
//! and provides ordering guarantees based on the configured mode.

use crate::core::{Transaction, Slot};
use crate::crypto::{Hash, Keypair, Pubkey};
use super::fifo::{FifoOrderer, FifoConfig, TimestampAttestation};
use super::batch_auction::{BatchAuction, BatchConfig, OrderType, TradingPair};
use super::commit_reveal::{CommitRevealOrderer, CommitRevealConfig, EncryptedTransaction, RevealKey};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use parking_lot::RwLock;

/// Ordering mode for the fair sequencer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderingMode {
    /// First-in-first-out with timestamp verification
    Fifo,
    /// Batch auctions for uniform price execution
    BatchAuction,
    /// Commit-reveal for maximum privacy
    CommitReveal,
    /// Hybrid mode: routes transactions to appropriate strategy
    Hybrid,
}

impl Default for OrderingMode {
    fn default() -> Self {
        Self::Fifo
    }
}

/// Configuration for the fair sequencer
#[derive(Debug, Clone)]
pub struct SequencerConfig {
    /// Default ordering mode
    pub mode: OrderingMode,
    /// FIFO configuration
    pub fifo: FifoConfig,
    /// Batch auction configuration
    pub batch: BatchConfig,
    /// Commit-reveal configuration
    pub commit_reveal: CommitRevealConfig,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Enable automatic mode switching based on load
    pub adaptive_mode: bool,
    /// Threshold for switching to batch mode (tx/s)
    pub batch_mode_threshold: u64,
}

impl Default for SequencerConfig {
    fn default() -> Self {
        Self {
            mode: OrderingMode::Fifo,
            fifo: FifoConfig::default(),
            batch: BatchConfig::default(),
            commit_reveal: CommitRevealConfig::default(),
            enable_metrics: true,
            adaptive_mode: false,
            batch_mode_threshold: 1000,
        }
    }
}

/// Transaction submission request
#[derive(Debug, Clone)]
pub enum SubmissionRequest {
    /// Standard transaction (FIFO ordered)
    Standard(Transaction),

    /// DEX swap (batch auction)
    Swap {
        transaction: Transaction,
        trading_pair: TradingPair,
        order_type: OrderType,
        amount: u64,
        limit_price: Option<u64>,
    },

    /// Private transaction (commit-reveal)
    Private {
        encrypted: EncryptedTransaction,
    },

    /// Reveal a private transaction
    Reveal {
        reveal_key: RevealKey,
    },
}

/// Result of transaction submission
#[derive(Debug, Clone)]
pub enum SubmissionResult {
    /// Transaction accepted
    Accepted {
        hash: Hash,
        mode: OrderingMode,
    },

    /// Committed (for commit-reveal)
    Committed {
        commitment_hash: Hash,
    },

    /// Revealed (for commit-reveal)
    Revealed {
        hash: Hash,
    },

    /// Failed
    Failed {
        reason: String,
    },
}

/// Fair Sequencer - Main MEV protection controller
pub struct FairSequencer {
    /// Configuration
    config: SequencerConfig,
    /// Current ordering mode
    current_mode: RwLock<OrderingMode>,
    /// FIFO orderer
    fifo: FifoOrderer,
    /// Batch auction manager
    batch: BatchAuction,
    /// Commit-reveal orderer
    commit_reveal: CommitRevealOrderer,
    /// Current slot
    current_slot: AtomicU64,
    /// Metrics
    metrics: OrderingMetrics,
}

/// Ordering metrics
#[derive(Debug, Default)]
pub struct OrderingMetrics {
    /// Total transactions received
    pub total_received: AtomicU64,
    /// Transactions via FIFO
    pub fifo_count: AtomicU64,
    /// Transactions via batch auction
    pub batch_count: AtomicU64,
    /// Transactions via commit-reveal
    pub commit_reveal_count: AtomicU64,
    /// Total rejected
    pub rejected_count: AtomicU64,
    /// Average ordering latency (microseconds)
    pub avg_latency_us: AtomicU64,
}

impl FairSequencer {
    /// Create a new fair sequencer
    pub fn new(config: SequencerConfig) -> Self {
        let mode = config.mode;

        Self {
            fifo: FifoOrderer::new(config.fifo.clone()),
            batch: BatchAuction::new(config.batch.clone()),
            commit_reveal: CommitRevealOrderer::new(config.commit_reveal.clone()),
            current_mode: RwLock::new(mode),
            current_slot: AtomicU64::new(0),
            metrics: OrderingMetrics::default(),
            config,
        }
    }

    /// Set the current slot
    pub fn set_slot(&self, slot: Slot) {
        self.current_slot.store(slot, AtomicOrdering::SeqCst);
        self.commit_reveal.set_slot(slot);
    }

    /// Get current slot
    pub fn current_slot(&self) -> Slot {
        self.current_slot.load(AtomicOrdering::SeqCst)
    }

    /// Register a validator for FIFO attestations
    pub fn register_validator(&self, validator: Pubkey) {
        self.fifo.register_validator(validator);
    }

    /// Submit a transaction
    pub fn submit(&self, request: SubmissionRequest) -> SubmissionResult {
        self.metrics.total_received.fetch_add(1, AtomicOrdering::Relaxed);

        match request {
            SubmissionRequest::Standard(tx) => {
                self.submit_standard(tx)
            }
            SubmissionRequest::Swap { transaction, trading_pair, order_type, amount, limit_price } => {
                self.submit_swap(transaction, trading_pair, order_type, amount, limit_price)
            }
            SubmissionRequest::Private { encrypted } => {
                self.submit_private(encrypted)
            }
            SubmissionRequest::Reveal { reveal_key } => {
                self.reveal_private(reveal_key)
            }
        }
    }

    /// Submit a standard transaction
    fn submit_standard(&self, tx: Transaction) -> SubmissionResult {
        let mode = *self.current_mode.read();

        match mode {
            OrderingMode::Fifo | OrderingMode::Hybrid => {
                match self.fifo.submit_transaction(tx) {
                    Ok(hash) => {
                        self.metrics.fifo_count.fetch_add(1, AtomicOrdering::Relaxed);
                        SubmissionResult::Accepted { hash, mode: OrderingMode::Fifo }
                    }
                    Err(e) => {
                        self.metrics.rejected_count.fetch_add(1, AtomicOrdering::Relaxed);
                        SubmissionResult::Failed { reason: e.to_string() }
                    }
                }
            }
            OrderingMode::BatchAuction => {
                // For non-swap transactions in batch mode, still use FIFO
                match self.fifo.submit_transaction(tx) {
                    Ok(hash) => {
                        self.metrics.fifo_count.fetch_add(1, AtomicOrdering::Relaxed);
                        SubmissionResult::Accepted { hash, mode: OrderingMode::Fifo }
                    }
                    Err(e) => {
                        self.metrics.rejected_count.fetch_add(1, AtomicOrdering::Relaxed);
                        SubmissionResult::Failed { reason: e.to_string() }
                    }
                }
            }
            OrderingMode::CommitReveal => {
                SubmissionResult::Failed {
                    reason: "Commit-reveal mode requires encrypted transactions".to_string()
                }
            }
        }
    }

    /// Submit a swap transaction
    fn submit_swap(
        &self,
        tx: Transaction,
        trading_pair: TradingPair,
        order_type: OrderType,
        amount: u64,
        limit_price: Option<u64>,
    ) -> SubmissionResult {
        let mode = *self.current_mode.read();

        match mode {
            OrderingMode::BatchAuction | OrderingMode::Hybrid => {
                match self.batch.submit_transaction(tx, order_type, amount, Some(trading_pair), limit_price) {
                    Ok(hash) => {
                        self.metrics.batch_count.fetch_add(1, AtomicOrdering::Relaxed);
                        SubmissionResult::Accepted { hash, mode: OrderingMode::BatchAuction }
                    }
                    Err(e) => {
                        // Fallback to FIFO in hybrid mode
                        if mode == OrderingMode::Hybrid {
                            // Create new transaction for FIFO fallback
                            self.metrics.rejected_count.fetch_add(1, AtomicOrdering::Relaxed);
                            SubmissionResult::Failed { reason: e.to_string() }
                        } else {
                            self.metrics.rejected_count.fetch_add(1, AtomicOrdering::Relaxed);
                            SubmissionResult::Failed { reason: e.to_string() }
                        }
                    }
                }
            }
            _ => {
                // In FIFO mode, treat swaps as regular transactions
                self.submit_standard(tx)
            }
        }
    }

    /// Submit a private (encrypted) transaction
    fn submit_private(&self, encrypted: EncryptedTransaction) -> SubmissionResult {
        match self.commit_reveal.commit(encrypted) {
            Ok(hash) => {
                self.metrics.commit_reveal_count.fetch_add(1, AtomicOrdering::Relaxed);
                SubmissionResult::Committed { commitment_hash: hash }
            }
            Err(e) => {
                self.metrics.rejected_count.fetch_add(1, AtomicOrdering::Relaxed);
                SubmissionResult::Failed { reason: e.to_string() }
            }
        }
    }

    /// Reveal a private transaction
    fn reveal_private(&self, reveal_key: RevealKey) -> SubmissionResult {
        match self.commit_reveal.reveal(reveal_key) {
            Ok(revealed) => {
                SubmissionResult::Revealed { hash: revealed.commitment.hash }
            }
            Err(e) => {
                self.metrics.rejected_count.fetch_add(1, AtomicOrdering::Relaxed);
                SubmissionResult::Failed { reason: e.to_string() }
            }
        }
    }

    /// Add a timestamp attestation for FIFO ordering
    pub fn add_attestation(&self, tx_hash: Hash, attestation: TimestampAttestation) -> Result<(), FairOrderingError> {
        self.fifo.add_attestation(tx_hash, attestation)
            .map_err(|e| FairOrderingError::AttestationFailed(e.to_string()))
    }

    /// Start a new batch auction
    pub fn start_batch(&self) -> u64 {
        let slot = self.current_slot();
        self.batch.start_batch(slot)
    }

    /// Finalize current batch
    pub fn finalize_batch(&self) -> Option<super::batch_auction::BatchResult> {
        self.batch.finalize_batch()
    }

    /// Get ordered transactions for block production
    pub fn take_ordered_transactions(&self, max: usize) -> Vec<Transaction> {
        let mode = *self.current_mode.read();
        let mut transactions = Vec::new();

        match mode {
            OrderingMode::Fifo => {
                transactions = self.fifo.take_ordered(max);
            }
            OrderingMode::BatchAuction => {
                transactions = self.batch.get_executable_transactions();
                if transactions.len() < max {
                    let remaining = max - transactions.len();
                    transactions.extend(self.fifo.take_ordered(remaining));
                }
            }
            OrderingMode::CommitReveal => {
                let revealed = self.commit_reveal.take_revealed(max);
                transactions = revealed.into_iter().map(|r| r.transaction).collect();
            }
            OrderingMode::Hybrid => {
                // Take from all sources in priority order
                let revealed = self.commit_reveal.take_revealed(max / 3);
                transactions.extend(revealed.into_iter().map(|r| r.transaction));

                let batch_txs = self.batch.get_executable_transactions();
                let batch_count = (max / 3).min(batch_txs.len());
                transactions.extend(batch_txs.into_iter().take(batch_count));

                let fifo_remaining = max.saturating_sub(transactions.len());
                transactions.extend(self.fifo.take_ordered(fifo_remaining));
            }
        }

        transactions
    }

    /// Switch ordering mode
    pub fn set_mode(&self, mode: OrderingMode) {
        *self.current_mode.write() = mode;
    }

    /// Get current mode
    pub fn mode(&self) -> OrderingMode {
        *self.current_mode.read()
    }

    /// Perform maintenance (cleanup expired items)
    pub fn maintenance(&self) {
        self.fifo.cleanup_expired(60_000); // 60 seconds
        self.commit_reveal.cleanup_expired();
    }

    /// Get comprehensive metrics
    pub fn metrics(&self) -> SequencerMetrics {
        SequencerMetrics {
            total_received: self.metrics.total_received.load(AtomicOrdering::Relaxed),
            fifo_count: self.metrics.fifo_count.load(AtomicOrdering::Relaxed),
            batch_count: self.metrics.batch_count.load(AtomicOrdering::Relaxed),
            commit_reveal_count: self.metrics.commit_reveal_count.load(AtomicOrdering::Relaxed),
            rejected_count: self.metrics.rejected_count.load(AtomicOrdering::Relaxed),
            fifo_stats: self.fifo.stats(),
            batch_stats: self.batch.stats(),
            commit_reveal_stats: self.commit_reveal.stats(),
            current_mode: self.mode(),
        }
    }
}

/// Fair ordering errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum FairOrderingError {
    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    #[error("Invalid mode for operation")]
    InvalidMode,

    #[error("Sequencer error: {0}")]
    SequencerError(String),
}

/// Comprehensive sequencer metrics
#[derive(Debug, Clone)]
pub struct SequencerMetrics {
    pub total_received: u64,
    pub fifo_count: u64,
    pub batch_count: u64,
    pub commit_reveal_count: u64,
    pub rejected_count: u64,
    pub fifo_stats: super::fifo::FifoStatistics,
    pub batch_stats: super::batch_auction::BatchStatistics,
    pub commit_reveal_stats: super::commit_reveal::CommitRevealStatistics,
    pub current_mode: OrderingMode,
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
    fn test_sequencer_fifo_mode() {
        let config = SequencerConfig {
            mode: OrderingMode::Fifo,
            fifo: FifoConfig {
                min_attestations: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let sequencer = FairSequencer::new(config);

        // Register validator
        let validator = Keypair::generate();
        sequencer.register_validator(validator.pubkey());

        // Submit transaction
        let tx = create_test_transaction();
        let result = sequencer.submit(SubmissionRequest::Standard(tx));

        match result {
            SubmissionResult::Accepted { mode, .. } => {
                assert_eq!(mode, OrderingMode::Fifo);
            }
            _ => panic!("Expected Accepted result"),
        }
    }

    #[test]
    fn test_sequencer_batch_mode() {
        let config = SequencerConfig {
            mode: OrderingMode::BatchAuction,
            batch: BatchConfig {
                min_batch_size: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let sequencer = FairSequencer::new(config);
        sequencer.set_slot(1);

        // Start batch
        sequencer.start_batch();

        // Submit swap
        let tx = create_test_transaction();
        let pair = TradingPair {
            base_token: [1u8; 32],
            quote_token: [2u8; 32],
        };

        let result = sequencer.submit(SubmissionRequest::Swap {
            transaction: tx,
            trading_pair: pair,
            order_type: OrderType::Buy,
            amount: 100,
            limit_price: Some(1000),
        });

        match result {
            SubmissionResult::Accepted { mode, .. } => {
                assert_eq!(mode, OrderingMode::BatchAuction);
            }
            _ => panic!("Expected Accepted result"),
        }

        // Finalize batch
        let batch_result = sequencer.finalize_batch();
        assert!(batch_result.is_some());
    }

    #[test]
    fn test_sequencer_hybrid_mode() {
        let config = SequencerConfig {
            mode: OrderingMode::Hybrid,
            fifo: FifoConfig {
                min_attestations: 1,
                ..Default::default()
            },
            batch: BatchConfig {
                min_batch_size: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let sequencer = FairSequencer::new(config);
        sequencer.set_slot(1);

        let validator = Keypair::generate();
        sequencer.register_validator(validator.pubkey());

        // Start batch
        sequencer.start_batch();

        // Submit standard transaction (should use FIFO)
        let tx1 = create_test_transaction();
        let result1 = sequencer.submit(SubmissionRequest::Standard(tx1));
        assert!(matches!(result1, SubmissionResult::Accepted { mode: OrderingMode::Fifo, .. }));

        // Submit swap (should use batch)
        let tx2 = create_test_transaction();
        let pair = TradingPair {
            base_token: [1u8; 32],
            quote_token: [2u8; 32],
        };
        let result2 = sequencer.submit(SubmissionRequest::Swap {
            transaction: tx2,
            trading_pair: pair,
            order_type: OrderType::Sell,
            amount: 50,
            limit_price: Some(900),
        });
        assert!(matches!(result2, SubmissionResult::Accepted { mode: OrderingMode::BatchAuction, .. }));
    }

    #[test]
    fn test_sequencer_metrics() {
        let config = SequencerConfig::default();
        let sequencer = FairSequencer::new(config);

        let validator = Keypair::generate();
        sequencer.register_validator(validator.pubkey());

        // Submit several transactions
        for _ in 0..5 {
            let tx = create_test_transaction();
            sequencer.submit(SubmissionRequest::Standard(tx));
        }

        let metrics = sequencer.metrics();
        assert_eq!(metrics.total_received, 5);
        assert_eq!(metrics.fifo_count, 5);
    }
}
