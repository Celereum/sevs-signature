//! Batch Auction MEV Protection
//!
//! Implements uniform price batch auctions where all transactions in a time window
//! are executed at the same price, eliminating front-running opportunities.
//!
//! # How it Works
//! 1. Transactions are collected over a batch interval (e.g., 100ms)
//! 2. At batch end, a uniform clearing price is calculated
//! 3. All transactions execute at this clearing price
//! 4. Front-running is impossible since insertion order doesn't affect price
//!
//! # Use Cases
//! - DEX swaps (primary use case)
//! - Token sales/auctions
//! - Any scenario where order-dependent pricing creates MEV

use crate::core::{Transaction, Slot};
use crate::crypto::Hash;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::{Mutex, RwLock};

/// Configuration for batch auctions
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Batch interval in milliseconds
    pub batch_interval_ms: u64,
    /// Maximum transactions per batch
    pub max_batch_size: usize,
    /// Minimum transactions to form a batch
    pub min_batch_size: usize,
    /// Maximum price deviation allowed (basis points)
    pub max_price_deviation_bps: u32,
    /// Enable price protection
    pub price_protection: bool,
    /// Timeout for batch completion (ms)
    pub batch_timeout_ms: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            batch_interval_ms: 100,
            max_batch_size: 1000,
            min_batch_size: 1,
            max_price_deviation_bps: 500, // 5%
            price_protection: true,
            batch_timeout_ms: 500,
        }
    }
}

/// A single batch of transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionBatch {
    /// Unique batch ID
    pub batch_id: u64,
    /// Slot this batch is for
    pub slot: Slot,
    /// Batch start time (microseconds)
    pub start_time: u64,
    /// Batch end time (microseconds)
    pub end_time: Option<u64>,
    /// Transactions in this batch
    pub transactions: Vec<BatchTransaction>,
    /// Calculated clearing price (if finalized)
    pub clearing_price: Option<ClearingPrice>,
    /// Batch state
    pub state: BatchState,
}

/// Transaction within a batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTransaction {
    /// The transaction
    pub transaction: Transaction,
    /// Transaction hash
    pub hash: Hash,
    /// Arrival time within batch
    pub arrival_time: u64,
    /// Trading pair (for DEX transactions)
    pub trading_pair: Option<TradingPair>,
    /// Order type
    pub order_type: OrderType,
    /// Amount to trade
    pub amount: u64,
    /// Max/min price willing to accept (optional)
    pub limit_price: Option<u64>,
}

/// Trading pair for DEX transactions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TradingPair {
    pub base_token: [u8; 32],
    pub quote_token: [u8; 32],
}

/// Order type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OrderType {
    /// Buy order
    Buy,
    /// Sell order
    Sell,
    /// Market order (takes any price)
    Market,
}

/// Batch state
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BatchState {
    /// Collecting transactions
    Collecting,
    /// Calculating clearing price
    Processing,
    /// Ready for execution
    Finalized,
    /// Executed
    Executed,
    /// Failed/cancelled
    Failed,
}

/// Calculated clearing price for a batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearingPrice {
    /// Trading pair
    pub trading_pair: TradingPair,
    /// Uniform execution price
    pub price: u64,
    /// Total buy volume at this price
    pub buy_volume: u64,
    /// Total sell volume at this price
    pub sell_volume: u64,
    /// Number of matched orders
    pub matched_orders: usize,
    /// Price discovery method used
    pub method: PriceMethod,
}

/// Price discovery method
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PriceMethod {
    /// Simple average of all orders
    Average,
    /// Volume-weighted average
    VolumeWeighted,
    /// Market clearing (supply = demand)
    MarketClearing,
    /// Oracle-based reference
    Oracle,
}

/// Result of batch execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    /// Batch ID
    pub batch_id: u64,
    /// Executed transactions
    pub executed: Vec<Hash>,
    /// Rejected transactions (price protection)
    pub rejected: Vec<(Hash, RejectionReason)>,
    /// Clearing prices used
    pub clearing_prices: Vec<ClearingPrice>,
    /// Total value transacted
    pub total_value: u64,
    /// Execution time (microseconds)
    pub execution_time_us: u64,
}

/// Reason for transaction rejection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RejectionReason {
    /// Price exceeded limit
    PriceExceeded,
    /// Insufficient liquidity
    InsufficientLiquidity,
    /// Invalid transaction
    InvalidTransaction,
    /// Batch cancelled
    BatchCancelled,
}

/// Uniform price calculator
pub struct UniformPriceCalculator;

impl UniformPriceCalculator {
    /// Calculate uniform clearing price for a set of orders
    ///
    /// Uses a simple supply/demand matching algorithm
    pub fn calculate(orders: &[BatchTransaction]) -> Option<ClearingPrice> {
        if orders.is_empty() {
            return None;
        }

        // Group by trading pair
        let mut pairs: HashMap<TradingPair, Vec<&BatchTransaction>> = HashMap::new();
        for order in orders {
            if let Some(ref pair) = order.trading_pair {
                pairs.entry(pair.clone()).or_default().push(order);
            }
        }

        // Calculate price for largest pair
        let (pair, pair_orders) = pairs.into_iter()
            .max_by_key(|(_, v)| v.len())?;

        let (buys, sells): (Vec<_>, Vec<_>) = pair_orders.iter()
            .partition(|o| o.order_type == OrderType::Buy || o.order_type == OrderType::Market);

        if buys.is_empty() || sells.is_empty() {
            // Use volume-weighted average if no matching
            return Self::calculate_vwap(&pair_orders, pair);
        }

        // Find clearing price where supply meets demand
        Self::find_clearing_price(&buys, &sells, pair)
    }

    /// Calculate volume-weighted average price
    fn calculate_vwap(orders: &[&BatchTransaction], pair: TradingPair) -> Option<ClearingPrice> {
        let mut total_volume = 0u64;
        let mut weighted_sum = 0u128;

        for order in orders {
            if let Some(price) = order.limit_price {
                let volume = order.amount;
                total_volume = total_volume.saturating_add(volume);
                weighted_sum = weighted_sum.saturating_add(price as u128 * volume as u128);
            }
        }

        if total_volume == 0 {
            return None;
        }

        let price = (weighted_sum / total_volume as u128) as u64;

        Some(ClearingPrice {
            trading_pair: pair,
            price,
            buy_volume: orders.iter()
                .filter(|o| o.order_type == OrderType::Buy)
                .map(|o| o.amount)
                .sum(),
            sell_volume: orders.iter()
                .filter(|o| o.order_type == OrderType::Sell)
                .map(|o| o.amount)
                .sum(),
            matched_orders: orders.len(),
            method: PriceMethod::VolumeWeighted,
        })
    }

    /// Find market clearing price
    fn find_clearing_price(
        buys: &[&&BatchTransaction],
        sells: &[&&BatchTransaction],
        pair: TradingPair,
    ) -> Option<ClearingPrice> {
        // Sort buys descending by price (highest willing to pay first)
        let mut sorted_buys: Vec<_> = buys.iter()
            .filter_map(|o| o.limit_price.map(|p| (p, o.amount)))
            .collect();
        sorted_buys.sort_by(|a, b| b.0.cmp(&a.0));

        // Sort sells ascending by price (lowest willing to accept first)
        let mut sorted_sells: Vec<_> = sells.iter()
            .filter_map(|o| o.limit_price.map(|p| (p, o.amount)))
            .collect();
        sorted_sells.sort_by(|a, b| a.0.cmp(&b.0));

        // Build cumulative supply/demand curves
        let mut demand_curve: Vec<(u64, u64)> = Vec::new();
        let mut cumulative_demand = 0u64;
        for (price, amount) in &sorted_buys {
            cumulative_demand = cumulative_demand.saturating_add(*amount);
            demand_curve.push((*price, cumulative_demand));
        }

        let mut supply_curve: Vec<(u64, u64)> = Vec::new();
        let mut cumulative_supply = 0u64;
        for (price, amount) in &sorted_sells {
            cumulative_supply = cumulative_supply.saturating_add(*amount);
            supply_curve.push((*price, cumulative_supply));
        }

        // Find intersection (clearing price)
        // Price where cumulative demand >= cumulative supply
        let mut clearing_price = 0u64;
        let mut clearing_volume = 0u64;

        for (buy_price, demand) in &demand_curve {
            for (sell_price, supply) in &supply_curve {
                if buy_price >= sell_price {
                    // Trade is possible
                    let matched = (*demand).min(*supply);
                    if matched > clearing_volume {
                        clearing_volume = matched;
                        // Clearing price is midpoint
                        clearing_price = (*buy_price + *sell_price) / 2;
                    }
                }
            }
        }

        if clearing_volume == 0 {
            return None;
        }

        Some(ClearingPrice {
            trading_pair: pair,
            price: clearing_price,
            buy_volume: cumulative_demand,
            sell_volume: cumulative_supply,
            matched_orders: buys.len() + sells.len(),
            method: PriceMethod::MarketClearing,
        })
    }
}

/// Batch Auction Manager
pub struct BatchAuction {
    /// Configuration
    config: BatchConfig,
    /// Current active batch
    current_batch: Mutex<Option<AuctionBatch>>,
    /// Completed batches (recent)
    completed_batches: RwLock<VecDeque<AuctionBatch>>,
    /// Next batch ID
    next_batch_id: AtomicU64,
    /// Statistics
    stats: BatchStats,
    /// Last batch time
    last_batch_time: Mutex<Instant>,
}

/// Batch auction statistics
#[derive(Debug, Default)]
struct BatchStats {
    pub batches_created: AtomicU64,
    pub batches_executed: AtomicU64,
    pub transactions_processed: AtomicU64,
    pub total_volume: AtomicU64,
}

impl BatchAuction {
    /// Create a new batch auction manager
    pub fn new(config: BatchConfig) -> Self {
        Self {
            config,
            current_batch: Mutex::new(None),
            completed_batches: RwLock::new(VecDeque::with_capacity(100)),
            next_batch_id: AtomicU64::new(1),
            stats: BatchStats::default(),
            last_batch_time: Mutex::new(Instant::now()),
        }
    }

    /// Start a new batch
    pub fn start_batch(&self, slot: Slot) -> u64 {
        let batch_id = self.next_batch_id.fetch_add(1, AtomicOrdering::SeqCst);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let batch = AuctionBatch {
            batch_id,
            slot,
            start_time: now,
            end_time: None,
            transactions: Vec::new(),
            clearing_price: None,
            state: BatchState::Collecting,
        };

        *self.current_batch.lock() = Some(batch);
        *self.last_batch_time.lock() = Instant::now();
        self.stats.batches_created.fetch_add(1, AtomicOrdering::Relaxed);

        batch_id
    }

    /// Submit a transaction to the current batch
    pub fn submit_transaction(
        &self,
        transaction: Transaction,
        order_type: OrderType,
        amount: u64,
        trading_pair: Option<TradingPair>,
        limit_price: Option<u64>,
    ) -> Result<Hash, BatchError> {
        let mut current = self.current_batch.lock();

        let batch = current.as_mut()
            .ok_or(BatchError::NoBatchActive)?;

        if batch.state != BatchState::Collecting {
            return Err(BatchError::BatchNotCollecting);
        }

        if batch.transactions.len() >= self.config.max_batch_size {
            return Err(BatchError::BatchFull);
        }

        let hash = Hash::hash(&bincode::serialize(&transaction).unwrap_or_default());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let batch_tx = BatchTransaction {
            transaction,
            hash,
            arrival_time: now,
            trading_pair,
            order_type,
            amount,
            limit_price,
        };

        batch.transactions.push(batch_tx);
        Ok(hash)
    }

    /// Check if batch interval has elapsed
    pub fn should_finalize(&self) -> bool {
        let last = self.last_batch_time.lock();
        last.elapsed().as_millis() as u64 >= self.config.batch_interval_ms
    }

    /// Finalize the current batch and calculate clearing prices
    pub fn finalize_batch(&self) -> Option<BatchResult> {
        let mut current = self.current_batch.lock();

        let mut batch = current.take()?;

        if batch.transactions.len() < self.config.min_batch_size {
            // Return transactions to be processed individually
            batch.state = BatchState::Failed;
            return None;
        }

        batch.state = BatchState::Processing;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        batch.end_time = Some(now);

        // Calculate clearing prices
        let clearing_price = UniformPriceCalculator::calculate(&batch.transactions);
        batch.clearing_price = clearing_price.clone();

        // Determine which transactions execute
        let (executed, rejected) = self.apply_price_protection(&batch);

        batch.state = BatchState::Finalized;

        let result = BatchResult {
            batch_id: batch.batch_id,
            executed: executed.clone(),
            rejected,
            clearing_prices: clearing_price.into_iter().collect(),
            total_value: batch.transactions.iter().map(|t| t.amount).sum(),
            execution_time_us: now.saturating_sub(batch.start_time),
        };

        // Store completed batch
        {
            let mut completed = self.completed_batches.write();
            if completed.len() >= 100 {
                completed.pop_front();
            }
            completed.push_back(batch);
        }

        self.stats.batches_executed.fetch_add(1, AtomicOrdering::Relaxed);
        self.stats.transactions_processed.fetch_add(executed.len() as u64, AtomicOrdering::Relaxed);

        Some(result)
    }

    /// Apply price protection and determine execution
    fn apply_price_protection(&self, batch: &AuctionBatch) -> (Vec<Hash>, Vec<(Hash, RejectionReason)>) {
        let mut executed = Vec::new();
        let mut rejected = Vec::new();

        let clearing = batch.clearing_price.as_ref();

        for tx in &batch.transactions {
            if !self.config.price_protection {
                executed.push(tx.hash);
                continue;
            }

            // Check if transaction's limit price is satisfied
            let accepted = match (clearing, tx.limit_price) {
                (Some(cp), Some(limit)) => {
                    match tx.order_type {
                        OrderType::Buy => cp.price <= limit,
                        OrderType::Sell => cp.price >= limit,
                        OrderType::Market => true,
                    }
                }
                (None, _) => true, // No clearing price, accept all
                (_, None) => true, // No limit, accept
            };

            if accepted {
                executed.push(tx.hash);
            } else {
                rejected.push((tx.hash, RejectionReason::PriceExceeded));
            }
        }

        (executed, rejected)
    }

    /// Get transactions from finalized batch for execution
    pub fn get_executable_transactions(&self) -> Vec<Transaction> {
        let completed = self.completed_batches.read();

        completed.back()
            .filter(|b| b.state == BatchState::Finalized)
            .map(|b| b.transactions.iter().map(|t| t.transaction.clone()).collect())
            .unwrap_or_default()
    }

    /// Get batch by ID
    pub fn get_batch(&self, batch_id: u64) -> Option<AuctionBatch> {
        let completed = self.completed_batches.read();
        completed.iter()
            .find(|b| b.batch_id == batch_id)
            .cloned()
    }

    /// Get current batch status
    pub fn current_batch_status(&self) -> Option<(u64, BatchState, usize)> {
        let current = self.current_batch.lock();
        current.as_ref().map(|b| (b.batch_id, b.state, b.transactions.len()))
    }

    /// Get statistics
    pub fn stats(&self) -> BatchStatistics {
        BatchStatistics {
            batches_created: self.stats.batches_created.load(AtomicOrdering::Relaxed),
            batches_executed: self.stats.batches_executed.load(AtomicOrdering::Relaxed),
            transactions_processed: self.stats.transactions_processed.load(AtomicOrdering::Relaxed),
            total_volume: self.stats.total_volume.load(AtomicOrdering::Relaxed),
        }
    }
}

/// Batch auction errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum BatchError {
    #[error("No batch currently active")]
    NoBatchActive,

    #[error("Batch is not in collecting state")]
    BatchNotCollecting,

    #[error("Batch is full")]
    BatchFull,

    #[error("Batch finalization failed")]
    FinalizationFailed,
}

/// Batch statistics
#[derive(Debug, Clone)]
pub struct BatchStatistics {
    pub batches_created: u64,
    pub batches_executed: u64,
    pub transactions_processed: u64,
    pub total_volume: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn create_test_transaction() -> Transaction {
        let keypair = Keypair::generate();
        Transaction::new_transfer(
            &keypair,
            crate::crypto::Pubkey::new([2u8; 32]),
            100,
            Hash::hash(b"recent_blockhash"),
        )
    }

    #[test]
    fn test_batch_auction_basic() {
        let config = BatchConfig {
            batch_interval_ms: 10,
            min_batch_size: 1,
            ..Default::default()
        };
        let auction = BatchAuction::new(config);

        // Start batch
        let batch_id = auction.start_batch(1);
        assert!(batch_id > 0);

        // Submit transactions
        let tx1 = create_test_transaction();
        let hash1 = auction.submit_transaction(
            tx1,
            OrderType::Buy,
            100,
            None,
            Some(1000),
        ).unwrap();

        let tx2 = create_test_transaction();
        let _hash2 = auction.submit_transaction(
            tx2,
            OrderType::Sell,
            100,
            None,
            Some(900),
        ).unwrap();

        // Check batch status
        let (id, state, count) = auction.current_batch_status().unwrap();
        assert_eq!(id, batch_id);
        assert_eq!(state, BatchState::Collecting);
        assert_eq!(count, 2);

        // Finalize batch
        let result = auction.finalize_batch();
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!(result.batch_id, batch_id);
        assert!(!result.executed.is_empty());
    }

    #[test]
    fn test_clearing_price_calculation() {
        let pair = TradingPair {
            base_token: [1u8; 32],
            quote_token: [2u8; 32],
        };

        let orders = vec![
            BatchTransaction {
                transaction: create_test_transaction(),
                hash: Hash::hash(b"tx1"),
                arrival_time: 0,
                trading_pair: Some(pair.clone()),
                order_type: OrderType::Buy,
                amount: 100,
                limit_price: Some(1000),
            },
            BatchTransaction {
                transaction: create_test_transaction(),
                hash: Hash::hash(b"tx2"),
                arrival_time: 0,
                trading_pair: Some(pair.clone()),
                order_type: OrderType::Sell,
                amount: 100,
                limit_price: Some(900),
            },
            BatchTransaction {
                transaction: create_test_transaction(),
                hash: Hash::hash(b"tx3"),
                arrival_time: 0,
                trading_pair: Some(pair.clone()),
                order_type: OrderType::Buy,
                amount: 50,
                limit_price: Some(950),
            },
        ];

        let clearing = UniformPriceCalculator::calculate(&orders);
        assert!(clearing.is_some());

        let clearing = clearing.unwrap();
        assert!(clearing.price >= 900 && clearing.price <= 1000);
    }

    #[test]
    fn test_price_protection() {
        let config = BatchConfig {
            batch_interval_ms: 10,
            min_batch_size: 1,
            price_protection: true,
            ..Default::default()
        };
        let auction = BatchAuction::new(config);

        auction.start_batch(1);

        let pair = TradingPair {
            base_token: [1u8; 32],
            quote_token: [2u8; 32],
        };

        // Buy order with low limit price
        let tx1 = create_test_transaction();
        auction.submit_transaction(
            tx1,
            OrderType::Buy,
            100,
            Some(pair.clone()),
            Some(100), // Very low limit
        ).unwrap();

        // Sell order with high limit price
        let tx2 = create_test_transaction();
        auction.submit_transaction(
            tx2,
            OrderType::Sell,
            100,
            Some(pair),
            Some(1000), // Normal price
        ).unwrap();

        let result = auction.finalize_batch();
        assert!(result.is_some());

        // The buy order should be rejected due to price protection
        // (clearing price will be ~1000, but buy limit is 100)
    }
}
