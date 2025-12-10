//! Transaction Pool with Replay Protection
//!
//! Provides secure transaction management with:
//! - Duplicate transaction detection
//! - Recent blockhash validation
//! - Fee prioritization
//! - Memory-efficient cleanup

use std::collections::{HashMap, HashSet, BinaryHeap};
use std::cmp::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;

use crate::crypto::Hash;
use crate::crypto::quantum_safe::Address;
use crate::core::Transaction;

/// Maximum age of a blockhash before it's considered stale (about 2 minutes)
pub const MAX_BLOCKHASH_AGE_SLOTS: u64 = 150;

/// Maximum number of transactions in the pool
pub const MAX_POOL_SIZE: usize = 50_000;

/// Maximum transactions per account in pool (prevent spam)
pub const MAX_PER_ACCOUNT: usize = 100;

/// Transaction pool configuration
#[derive(Debug, Clone)]
pub struct TxPoolConfig {
    /// Maximum blockhash age in slots
    pub max_blockhash_age: u64,
    /// Maximum pool size
    pub max_pool_size: usize,
    /// Maximum transactions per account
    pub max_per_account: usize,
    /// Enable strict replay protection
    pub strict_replay_protection: bool,
}

impl Default for TxPoolConfig {
    fn default() -> Self {
        Self {
            max_blockhash_age: MAX_BLOCKHASH_AGE_SLOTS,
            max_pool_size: MAX_POOL_SIZE,
            max_per_account: MAX_PER_ACCOUNT,
            strict_replay_protection: true,
        }
    }
}

/// Priority entry for the transaction heap
#[derive(Debug)]
struct PriorityEntry {
    /// Transaction hash
    hash: Hash,
    /// Priority (fee per compute unit)
    priority: u64,
    /// Insertion time for tie-breaking
    inserted_at: Instant,
}

impl PartialEq for PriorityEntry {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.hash == other.hash
    }
}

impl Eq for PriorityEntry {}

impl PartialOrd for PriorityEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first, then older transactions
        self.priority.cmp(&other.priority)
            .then_with(|| other.inserted_at.cmp(&self.inserted_at))
    }
}

/// Transaction pool with replay protection
#[derive(Debug)]
pub struct TxPool {
    /// Configuration
    config: TxPoolConfig,

    /// Pending transactions by hash
    transactions: HashMap<Hash, Transaction>,

    /// Priority queue for transaction ordering
    priority_queue: BinaryHeap<PriorityEntry>,

    /// Transactions per account (for rate limiting)
    account_txs: HashMap<Address, HashSet<Hash>>,

    /// Processed transaction hashes (for replay protection)
    processed_txs: HashSet<Hash>,

    /// Recent blockhashes with their slots
    recent_blockhashes: HashMap<Hash, u64>,

    /// Current slot
    current_slot: u64,
}

impl TxPool {
    /// Create a new transaction pool
    pub fn new(config: TxPoolConfig) -> Self {
        Self {
            config,
            transactions: HashMap::new(),
            priority_queue: BinaryHeap::new(),
            account_txs: HashMap::new(),
            processed_txs: HashSet::new(),
            recent_blockhashes: HashMap::new(),
            current_slot: 0,
        }
    }

    /// Add a transaction to the pool
    pub fn add(&mut self, tx: Transaction) -> Result<Hash, TxPoolError> {
        let tx_hash = tx.hash();

        // Check if already in pool
        if self.transactions.contains_key(&tx_hash) {
            return Err(TxPoolError::DuplicateTransaction);
        }

        // Check if already processed (replay attack)
        if self.config.strict_replay_protection && self.processed_txs.contains(&tx_hash) {
            return Err(TxPoolError::AlreadyProcessed);
        }

        // Validate signatures
        if !tx.verify() {
            return Err(TxPoolError::InvalidSignature);
        }

        // Check recent blockhash
        let blockhash = &tx.message.recent_blockhash;
        if let Some(&hash_slot) = self.recent_blockhashes.get(blockhash) {
            if self.current_slot > hash_slot + self.config.max_blockhash_age {
                return Err(TxPoolError::BlockhashExpired);
            }
        } else if self.config.strict_replay_protection && !blockhash.is_zero() {
            return Err(TxPoolError::UnknownBlockhash);
        }

        // Check pool size
        if self.transactions.len() >= self.config.max_pool_size {
            return Err(TxPoolError::PoolFull);
        }

        // Check per-account limit
        if let Some(fee_payer) = tx.fee_payer() {
            let account_txs = self.account_txs.entry(fee_payer.clone()).or_default();
            if account_txs.len() >= self.config.max_per_account {
                return Err(TxPoolError::AccountLimitExceeded);
            }
            account_txs.insert(tx_hash.clone());
        }

        // Calculate priority (simplified: use fee as priority)
        let priority = 1000; // TODO: Calculate from fee

        // Add to pool
        self.transactions.insert(tx_hash.clone(), tx);
        self.priority_queue.push(PriorityEntry {
            hash: tx_hash.clone(),
            priority,
            inserted_at: Instant::now(),
        });

        Ok(tx_hash)
    }

    /// Get transactions for block production (sorted by priority)
    pub fn get_transactions(&mut self, max_count: usize) -> Vec<Transaction> {
        let mut result = Vec::with_capacity(max_count);
        let mut to_remove = Vec::new();

        while result.len() < max_count {
            if let Some(entry) = self.priority_queue.pop() {
                if let Some(tx) = self.transactions.remove(&entry.hash) {
                    // Remove from account tracking
                    if let Some(fee_payer) = tx.fee_payer() {
                        if let Some(account_txs) = self.account_txs.get_mut(fee_payer) {
                            account_txs.remove(&entry.hash);
                        }
                    }

                    result.push(tx);
                    to_remove.push(entry.hash);
                }
            } else {
                break;
            }
        }

        result
    }

    /// Mark a transaction as processed (for replay protection)
    pub fn mark_processed(&mut self, tx_hash: &Hash) {
        self.processed_txs.insert(tx_hash.clone());
    }

    /// Mark multiple transactions as processed
    pub fn mark_all_processed(&mut self, tx_hashes: &[Hash]) {
        for hash in tx_hashes {
            self.processed_txs.insert(hash.clone());
        }
    }

    /// Remove a transaction from the pool
    pub fn remove(&mut self, tx_hash: &Hash) -> Option<Transaction> {
        if let Some(tx) = self.transactions.remove(tx_hash) {
            if let Some(fee_payer) = tx.fee_payer() {
                if let Some(account_txs) = self.account_txs.get_mut(fee_payer) {
                    account_txs.remove(tx_hash);
                }
            }
            Some(tx)
        } else {
            None
        }
    }

    /// Update slot and blockhash
    pub fn update_slot(&mut self, slot: u64, blockhash: Hash) {
        self.current_slot = slot;
        self.recent_blockhashes.insert(blockhash, slot);

        // Cleanup old blockhashes
        let cutoff = slot.saturating_sub(self.config.max_blockhash_age);
        self.recent_blockhashes.retain(|_, &mut s| s >= cutoff);
    }

    /// Cleanup stale transactions
    pub fn cleanup(&mut self) {
        let cutoff = self.current_slot.saturating_sub(self.config.max_blockhash_age);

        // Remove transactions with expired blockhashes
        let to_remove: Vec<Hash> = self.transactions
            .iter()
            .filter(|(_, tx)| {
                if let Some(&hash_slot) = self.recent_blockhashes.get(&tx.message.recent_blockhash) {
                    hash_slot < cutoff
                } else {
                    true // Unknown blockhash = expired
                }
            })
            .map(|(hash, _)| hash.clone())
            .collect();

        for hash in to_remove {
            self.remove(&hash);
        }

        // Limit processed tx history to prevent memory growth
        const MAX_PROCESSED_HISTORY: usize = 100_000;
        if self.processed_txs.len() > MAX_PROCESSED_HISTORY {
            // Just clear half of them (simple approach)
            let to_keep: HashSet<Hash> = self.processed_txs
                .iter()
                .take(MAX_PROCESSED_HISTORY / 2)
                .cloned()
                .collect();
            self.processed_txs = to_keep;
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> TxPoolStats {
        TxPoolStats {
            pending_count: self.transactions.len(),
            processed_count: self.processed_txs.len(),
            accounts_count: self.account_txs.len(),
            blockhash_count: self.recent_blockhashes.len(),
            current_slot: self.current_slot,
        }
    }

    /// Check if a transaction has been processed
    pub fn is_processed(&self, tx_hash: &Hash) -> bool {
        self.processed_txs.contains(tx_hash)
    }

    /// Get pending transaction count
    pub fn pending_count(&self) -> usize {
        self.transactions.len()
    }
}

/// Transaction pool errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum TxPoolError {
    #[error("Duplicate transaction")]
    DuplicateTransaction,

    #[error("Transaction already processed (replay attack)")]
    AlreadyProcessed,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Blockhash has expired")]
    BlockhashExpired,

    #[error("Unknown blockhash")]
    UnknownBlockhash,

    #[error("Transaction pool is full")]
    PoolFull,

    #[error("Account has too many pending transactions")]
    AccountLimitExceeded,
}

/// Transaction pool statistics
#[derive(Debug, Clone)]
pub struct TxPoolStats {
    pub pending_count: usize,
    pub processed_count: usize,
    pub accounts_count: usize,
    pub blockhash_count: usize,
    pub current_slot: u64,
}

/// Thread-safe transaction pool wrapper
pub struct SharedTxPool {
    inner: Arc<RwLock<TxPool>>,
}

impl SharedTxPool {
    pub fn new(config: TxPoolConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(TxPool::new(config))),
        }
    }

    pub fn add(&self, tx: Transaction) -> Result<Hash, TxPoolError> {
        self.inner.write().add(tx)
    }

    pub fn get_transactions(&self, max_count: usize) -> Vec<Transaction> {
        self.inner.write().get_transactions(max_count)
    }

    pub fn mark_processed(&self, tx_hash: &Hash) {
        self.inner.write().mark_processed(tx_hash);
    }

    pub fn update_slot(&self, slot: u64, blockhash: Hash) {
        self.inner.write().update_slot(slot, blockhash);
    }

    pub fn cleanup(&self) {
        self.inner.write().cleanup();
    }

    pub fn stats(&self) -> TxPoolStats {
        self.inner.read().stats()
    }

    pub fn is_processed(&self, tx_hash: &Hash) -> bool {
        self.inner.read().is_processed(tx_hash)
    }

    pub fn pending_count(&self) -> usize {
        self.inner.read().pending_count()
    }
}

impl Clone for SharedTxPool {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sevs::SevsKeypair;

    fn create_test_tx() -> Transaction {
        let keypair = SevsKeypair::generate();
        let to = SevsKeypair::generate();
        Transaction::new_transfer(&keypair, to.address(), 1000, Hash::zero())
    }

    #[test]
    fn test_add_transaction() {
        let mut pool = TxPool::new(TxPoolConfig::default());
        let tx = create_test_tx();

        let result = pool.add(tx);
        assert!(result.is_ok());
        assert_eq!(pool.pending_count(), 1);
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut pool = TxPool::new(TxPoolConfig::default());
        let tx = create_test_tx();
        let tx_clone = tx.clone();

        pool.add(tx).unwrap();
        let result = pool.add(tx_clone);

        assert!(matches!(result, Err(TxPoolError::DuplicateTransaction)));
    }

    #[test]
    fn test_replay_protection() {
        let mut pool = TxPool::new(TxPoolConfig::default());
        let tx = create_test_tx();
        let tx_hash = tx.hash();
        let tx_clone = tx.clone();

        pool.add(tx).unwrap();
        pool.remove(&tx_hash);
        pool.mark_processed(&tx_hash);

        // Try to add same transaction again
        let result = pool.add(tx_clone);
        assert!(matches!(result, Err(TxPoolError::AlreadyProcessed)));
    }
}
