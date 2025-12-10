//! Optimized Storage Engine for Celereum
//!
//! High-performance storage with:
//! - Write Coalescing: Batch writes per slot to reduce I/O
//! - Bounded Priority Mempool: Priority fee ordering with size limits
//! - Dirty Tracking: Only write modified accounts
//! - LRU Account Cache: Fast access to hot accounts
//!
//! Inspired by Solana's AccountsDB and Firedancer's optimizations.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};
use parking_lot::{RwLock, Mutex};

use crate::core::{Account, Transaction, Slot};
use crate::crypto::Pubkey;
use crate::crypto::Hash;

// ============================================================================
// Constants
// ============================================================================

/// Maximum mempool size (transactions)
pub const MAX_MEMPOOL_SIZE: usize = 50_000;

/// Default mempool size
pub const DEFAULT_MEMPOOL_SIZE: usize = 10_000;

/// Minimum priority fee (celers)
pub const MIN_PRIORITY_FEE: u64 = 0;

/// Maximum accounts in hot cache
pub const HOT_CACHE_SIZE: usize = 100_000;

/// Write coalescing window (ms)
pub const WRITE_COALESCE_MS: u64 = 100;

/// Maximum pending writes per slot
pub const MAX_PENDING_WRITES: usize = 10_000;

/// Account snapshot interval (slots)
pub const SNAPSHOT_INTERVAL: u64 = 1000;

// ============================================================================
// Priority Mempool
// ============================================================================

/// Transaction with priority metadata
#[derive(Clone)]
pub struct PriorityTransaction {
    /// The transaction
    pub transaction: Transaction,
    /// Priority fee (celers per compute unit)
    pub priority_fee: u64,
    /// Estimated compute units
    pub compute_units: u64,
    /// Arrival time
    pub arrival_time: Instant,
    /// Transaction hash for dedup
    pub hash: Hash,
}

impl PriorityTransaction {
    /// Create new priority transaction
    pub fn new(transaction: Transaction, priority_fee: u64, compute_units: u64) -> Self {
        let hash = Hash::hash(&bincode::serialize(&transaction).unwrap_or_default());
        Self {
            transaction,
            priority_fee,
            compute_units,
            arrival_time: Instant::now(),
            hash,
        }
    }

    /// Calculate effective priority score
    /// Higher is better: priority_fee * compute_units
    pub fn priority_score(&self) -> u64 {
        self.priority_fee.saturating_mul(self.compute_units)
    }
}

impl PartialEq for PriorityTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for PriorityTransaction {}

impl PartialOrd for PriorityTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityTransaction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority first, then earlier arrival
        match other.priority_score().cmp(&self.priority_score()) {
            std::cmp::Ordering::Equal => self.arrival_time.cmp(&other.arrival_time),
            other_cmp => other_cmp,
        }
    }
}

/// Bounded priority mempool with efficient operations
pub struct BoundedMempool {
    /// Transactions ordered by priority (BTreeMap for sorted access)
    transactions: RwLock<BTreeMap<(u64, Instant), PriorityTransaction>>,
    /// Hash to key mapping for O(1) lookup
    hash_index: RwLock<HashMap<Hash, (u64, Instant)>>,
    /// Maximum size
    max_size: usize,
    /// Current count
    count: AtomicU64,
    /// Total fees collected
    total_fees: AtomicU64,
    /// Dropped transactions count
    dropped_count: AtomicU64,
}

impl BoundedMempool {
    /// Create new bounded mempool
    pub fn new(max_size: usize) -> Self {
        Self {
            transactions: RwLock::new(BTreeMap::new()),
            hash_index: RwLock::new(HashMap::new()),
            max_size,
            count: AtomicU64::new(0),
            total_fees: AtomicU64::new(0),
            dropped_count: AtomicU64::new(0),
        }
    }

    /// Add transaction to mempool
    /// Returns true if added, false if rejected (duplicate or below threshold)
    pub fn add(&self, tx: PriorityTransaction) -> bool {
        // Check for duplicate
        {
            let index = self.hash_index.read();
            if index.contains_key(&tx.hash) {
                return false;
            }
        }

        let key = (tx.priority_score(), tx.arrival_time);

        // Check if we need to evict
        let current_count = self.count.load(Ordering::Relaxed) as usize;

        if current_count >= self.max_size {
            // Need to evict lowest priority transaction
            let mut txs = self.transactions.write();
            let mut index = self.hash_index.write();

            // Get lowest priority (first in BTreeMap because we use reverse ordering)
            if let Some((lowest_key, lowest_tx)) = txs.iter().next() {
                // Only accept if new tx has higher priority
                if tx.priority_score() <= lowest_tx.priority_score() {
                    self.dropped_count.fetch_add(1, Ordering::Relaxed);
                    return false;
                }

                // Evict lowest
                let lowest_key = *lowest_key;
                let lowest_hash = lowest_tx.hash;
                txs.remove(&lowest_key);
                index.remove(&lowest_hash);
                self.count.fetch_sub(1, Ordering::Relaxed);
                self.dropped_count.fetch_add(1, Ordering::Relaxed);
            }

            // Add new transaction
            let fee = tx.priority_fee;
            index.insert(tx.hash, key);
            txs.insert(key, tx);
            self.count.fetch_add(1, Ordering::Relaxed);
            self.total_fees.fetch_add(fee, Ordering::Relaxed);

            true
        } else {
            // Space available, just add
            let mut txs = self.transactions.write();
            let mut index = self.hash_index.write();

            let fee = tx.priority_fee;
            index.insert(tx.hash, key);
            txs.insert(key, tx);
            self.count.fetch_add(1, Ordering::Relaxed);
            self.total_fees.fetch_add(fee, Ordering::Relaxed);

            true
        }
    }

    /// Take highest priority transactions (up to max)
    pub fn take(&self, max: usize) -> Vec<Transaction> {
        let mut txs = self.transactions.write();
        let mut index = self.hash_index.write();

        let mut result = Vec::with_capacity(max.min(txs.len()));

        // Take from highest priority (last in BTreeMap because higher score = larger key)
        while result.len() < max && !txs.is_empty() {
            if let Some((key, ptx)) = txs.pop_last() {
                index.remove(&ptx.hash);
                self.count.fetch_sub(1, Ordering::Relaxed);
                result.push(ptx.transaction);
            }
        }

        result
    }

    /// Peek at highest priority transactions without removing
    pub fn peek(&self, max: usize) -> Vec<Transaction> {
        let txs = self.transactions.read();
        txs.values()
            .rev()
            .take(max)
            .map(|ptx| ptx.transaction.clone())
            .collect()
    }

    /// Remove transaction by hash
    pub fn remove(&self, hash: &Hash) -> Option<Transaction> {
        let mut index = self.hash_index.write();

        if let Some(key) = index.remove(hash) {
            let mut txs = self.transactions.write();
            if let Some(ptx) = txs.remove(&key) {
                self.count.fetch_sub(1, Ordering::Relaxed);
                return Some(ptx.transaction);
            }
        }
        None
    }

    /// Check if transaction exists
    pub fn contains(&self, hash: &Hash) -> bool {
        self.hash_index.read().contains_key(hash)
    }

    /// Current count
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed) as usize
    }

    /// Is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get stats
    pub fn stats(&self) -> MempoolStats {
        let txs = self.transactions.read();

        let (min_fee, max_fee) = if txs.is_empty() {
            (0, 0)
        } else {
            let fees: Vec<u64> = txs.values().map(|t| t.priority_fee).collect();
            (*fees.iter().min().unwrap_or(&0), *fees.iter().max().unwrap_or(&0))
        };

        MempoolStats {
            count: self.len(),
            max_size: self.max_size,
            total_fees: self.total_fees.load(Ordering::Relaxed),
            dropped_count: self.dropped_count.load(Ordering::Relaxed),
            min_fee,
            max_fee,
        }
    }

    /// Clear expired transactions (older than max_age)
    pub fn clear_expired(&self, max_age: Duration) {
        let now = Instant::now();
        let mut txs = self.transactions.write();
        let mut index = self.hash_index.write();

        let to_remove: Vec<_> = txs.iter()
            .filter(|(_, ptx)| now.duration_since(ptx.arrival_time) > max_age)
            .map(|(k, ptx)| (*k, ptx.hash))
            .collect();

        for (key, hash) in to_remove {
            txs.remove(&key);
            index.remove(&hash);
            self.count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Mempool statistics
#[derive(Debug, Clone)]
pub struct MempoolStats {
    pub count: usize,
    pub max_size: usize,
    pub total_fees: u64,
    pub dropped_count: u64,
    pub min_fee: u64,
    pub max_fee: u64,
}

// ============================================================================
// Write Coalescing
// ============================================================================

/// Dirty account entry
struct DirtyAccount {
    account: Account,
    modified_at: Instant,
    write_count: u32,
}

/// Write coalescing buffer
pub struct WriteCoalescer {
    /// Pending writes per slot
    pending: RwLock<HashMap<Slot, HashMap<Pubkey, DirtyAccount>>>,
    /// Last flush time
    last_flush: Mutex<Instant>,
    /// Coalesce window
    window_ms: u64,
    /// Maximum pending per slot
    max_pending: usize,
    /// Write count
    write_count: AtomicU64,
    /// Coalesced count (writes saved)
    coalesced_count: AtomicU64,
}

impl WriteCoalescer {
    /// Create new write coalescer
    pub fn new(window_ms: u64, max_pending: usize) -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            last_flush: Mutex::new(Instant::now()),
            window_ms,
            max_pending,
            write_count: AtomicU64::new(0),
            coalesced_count: AtomicU64::new(0),
        }
    }

    /// Queue a write (coalesces with pending writes)
    pub fn queue_write(&self, slot: Slot, pubkey: Pubkey, account: Account) {
        let mut pending = self.pending.write();
        let slot_pending = pending.entry(slot).or_insert_with(HashMap::new);

        if let Some(existing) = slot_pending.get_mut(&pubkey) {
            // Coalesce: update existing entry
            existing.account = account;
            existing.modified_at = Instant::now();
            existing.write_count += 1;
            self.coalesced_count.fetch_add(1, Ordering::Relaxed);
        } else {
            // New entry
            if slot_pending.len() < self.max_pending {
                slot_pending.insert(pubkey, DirtyAccount {
                    account,
                    modified_at: Instant::now(),
                    write_count: 1,
                });
                self.write_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Check if flush is needed
    pub fn needs_flush(&self) -> bool {
        let last = self.last_flush.lock();
        last.elapsed().as_millis() as u64 >= self.window_ms
    }

    /// Flush pending writes for a slot
    pub fn flush_slot(&self, slot: Slot) -> Vec<(Pubkey, Account)> {
        let mut pending = self.pending.write();

        if let Some(slot_pending) = pending.remove(&slot) {
            slot_pending.into_iter()
                .map(|(k, v)| (k, v.account))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Flush all slots older than current
    pub fn flush_old_slots(&self, current_slot: Slot) -> HashMap<Slot, Vec<(Pubkey, Account)>> {
        let mut pending = self.pending.write();
        let mut flushed = HashMap::new();

        let old_slots: Vec<Slot> = pending.keys()
            .filter(|&&s| s < current_slot)
            .copied()
            .collect();

        for slot in old_slots {
            if let Some(slot_pending) = pending.remove(&slot) {
                let writes: Vec<_> = slot_pending.into_iter()
                    .map(|(k, v)| (k, v.account))
                    .collect();
                flushed.insert(slot, writes);
            }
        }

        *self.last_flush.lock() = Instant::now();
        flushed
    }

    /// Get pending count for slot
    pub fn pending_count(&self, slot: Slot) -> usize {
        self.pending.read()
            .get(&slot)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Get stats
    pub fn stats(&self) -> CoalesceStats {
        let pending = self.pending.read();
        let total_pending: usize = pending.values().map(|m| m.len()).sum();

        CoalesceStats {
            write_count: self.write_count.load(Ordering::Relaxed),
            coalesced_count: self.coalesced_count.load(Ordering::Relaxed),
            pending_slots: pending.len(),
            total_pending,
        }
    }
}

/// Write coalescing statistics
#[derive(Debug, Clone)]
pub struct CoalesceStats {
    pub write_count: u64,
    pub coalesced_count: u64,
    pub pending_slots: usize,
    pub total_pending: usize,
}

// ============================================================================
// Hot Account Cache (LRU)
// ============================================================================

/// LRU cache entry
struct CacheEntry {
    account: Account,
    last_access: Instant,
    access_count: u32,
}

/// Hot account cache with LRU eviction
pub struct HotAccountCache {
    /// Cached accounts
    cache: RwLock<HashMap<Pubkey, CacheEntry>>,
    /// Access order for LRU
    access_order: Mutex<VecDeque<Pubkey>>,
    /// Maximum size
    max_size: usize,
    /// Hit count
    hits: AtomicU64,
    /// Miss count
    misses: AtomicU64,
}

impl HotAccountCache {
    /// Create new cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(max_size)),
            access_order: Mutex::new(VecDeque::with_capacity(max_size)),
            max_size,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Get account from cache
    pub fn get(&self, pubkey: &Pubkey) -> Option<Account> {
        let mut cache = self.cache.write();

        if let Some(entry) = cache.get_mut(pubkey) {
            entry.last_access = Instant::now();
            entry.access_count += 1;
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.account.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Insert account into cache
    pub fn insert(&self, pubkey: Pubkey, account: Account) {
        let mut cache = self.cache.write();

        // Check if already exists
        if cache.contains_key(&pubkey) {
            // Update existing
            if let Some(entry) = cache.get_mut(&pubkey) {
                entry.account = account;
                entry.last_access = Instant::now();
            }
            return;
        }

        // Evict if necessary
        while cache.len() >= self.max_size {
            // Find LRU entry
            let lru_key = cache.iter()
                .min_by_key(|(_, v)| v.last_access)
                .map(|(k, _)| *k);

            if let Some(key) = lru_key {
                cache.remove(&key);
            } else {
                break;
            }
        }

        // Insert new entry
        cache.insert(pubkey, CacheEntry {
            account,
            last_access: Instant::now(),
            access_count: 1,
        });
    }

    /// Invalidate entry
    pub fn invalidate(&self, pubkey: &Pubkey) {
        self.cache.write().remove(pubkey);
    }

    /// Clear all
    pub fn clear(&self) {
        self.cache.write().clear();
    }

    /// Get stats
    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.read();
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        CacheStats {
            size: cache.len(),
            max_size: self.max_size,
            hits,
            misses,
            hit_rate: if total > 0 { hits as f64 / total as f64 } else { 0.0 },
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub size: usize,
    pub max_size: usize,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
}

// ============================================================================
// Optimized Storage Engine
// ============================================================================

/// Optimized storage engine combining all optimizations
pub struct OptimizedStorage {
    /// Priority mempool
    mempool: Arc<BoundedMempool>,
    /// Write coalescer
    coalescer: Arc<WriteCoalescer>,
    /// Hot account cache
    hot_cache: Arc<HotAccountCache>,
    /// Current slot
    current_slot: AtomicU64,
    /// Snapshot flag
    snapshot_pending: AtomicBool,
}

impl OptimizedStorage {
    /// Create new optimized storage
    pub fn new() -> Self {
        Self {
            mempool: Arc::new(BoundedMempool::new(DEFAULT_MEMPOOL_SIZE)),
            coalescer: Arc::new(WriteCoalescer::new(WRITE_COALESCE_MS, MAX_PENDING_WRITES)),
            hot_cache: Arc::new(HotAccountCache::new(HOT_CACHE_SIZE)),
            current_slot: AtomicU64::new(0),
            snapshot_pending: AtomicBool::new(false),
        }
    }

    /// Create with custom sizes
    pub fn with_config(mempool_size: usize, cache_size: usize, coalesce_window_ms: u64) -> Self {
        Self {
            mempool: Arc::new(BoundedMempool::new(mempool_size)),
            coalescer: Arc::new(WriteCoalescer::new(coalesce_window_ms, MAX_PENDING_WRITES)),
            hot_cache: Arc::new(HotAccountCache::new(cache_size)),
            current_slot: AtomicU64::new(0),
            snapshot_pending: AtomicBool::new(false),
        }
    }

    /// Add transaction with priority
    pub fn add_transaction(&self, tx: Transaction, priority_fee: u64, compute_units: u64) -> bool {
        let ptx = PriorityTransaction::new(tx, priority_fee, compute_units);
        self.mempool.add(ptx)
    }

    /// Add transaction with default priority
    pub fn add_transaction_default(&self, tx: Transaction) -> bool {
        self.add_transaction(tx, MIN_PRIORITY_FEE, 200_000)
    }

    /// Take transactions for block production
    pub fn take_transactions(&self, max: usize) -> Vec<Transaction> {
        self.mempool.take(max)
    }

    /// Peek at pending transactions
    pub fn peek_transactions(&self, max: usize) -> Vec<Transaction> {
        self.mempool.peek(max)
    }

    /// Queue account write
    pub fn queue_account_write(&self, pubkey: Pubkey, account: Account) {
        let slot = self.current_slot.load(Ordering::Relaxed);

        // Update hot cache immediately
        self.hot_cache.insert(pubkey, account.clone());

        // Queue for batched write
        self.coalescer.queue_write(slot, pubkey, account);
    }

    /// Get account (from cache first)
    pub fn get_account(&self, pubkey: &Pubkey) -> Option<Account> {
        self.hot_cache.get(pubkey)
    }

    /// Advance to next slot
    pub fn advance_slot(&self) -> Slot {
        let new_slot = self.current_slot.fetch_add(1, Ordering::SeqCst) + 1;

        // Flush old slot writes
        let _ = self.coalescer.flush_slot(new_slot.saturating_sub(1));

        // Check if snapshot needed
        if new_slot % SNAPSHOT_INTERVAL == 0 {
            self.snapshot_pending.store(true, Ordering::Relaxed);
        }

        new_slot
    }

    /// Current slot
    pub fn current_slot(&self) -> Slot {
        self.current_slot.load(Ordering::Relaxed)
    }

    /// Flush pending writes
    pub fn flush(&self) -> Vec<(Pubkey, Account)> {
        let slot = self.current_slot.load(Ordering::Relaxed);
        self.coalescer.flush_slot(slot)
    }

    /// Get mempool
    pub fn mempool(&self) -> &BoundedMempool {
        &self.mempool
    }

    /// Get stats
    pub fn stats(&self) -> OptimizedStorageStats {
        OptimizedStorageStats {
            mempool: self.mempool.stats(),
            coalesce: self.coalescer.stats(),
            cache: self.hot_cache.stats(),
            current_slot: self.current_slot.load(Ordering::Relaxed),
        }
    }

    /// Clear expired mempool transactions
    pub fn maintenance(&self) {
        // Clear transactions older than 60 seconds
        self.mempool.clear_expired(Duration::from_secs(60));

        // Flush old slots
        let current = self.current_slot.load(Ordering::Relaxed);
        let _ = self.coalescer.flush_old_slots(current);
    }
}

impl Default for OptimizedStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined storage statistics
#[derive(Debug, Clone)]
pub struct OptimizedStorageStats {
    pub mempool: MempoolStats,
    pub coalesce: CoalesceStats,
    pub cache: CacheStats,
    pub current_slot: Slot,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn create_dummy_tx() -> Transaction {
        let keypair = Keypair::generate();
        Transaction::new_transfer(
            &keypair,
            Pubkey::new([2u8; 32]),
            100,
            Hash::hash(b"blockhash"),
        )
    }

    #[test]
    fn test_priority_mempool() {
        let mempool = BoundedMempool::new(5);

        // Add transactions with different priorities
        for i in 0..10 {
            let tx = create_dummy_tx();
            let ptx = PriorityTransaction::new(tx, i as u64 * 1000, 200_000);
            mempool.add(ptx);
        }

        // Should only have 5 highest priority
        assert_eq!(mempool.len(), 5);

        // Take should return highest priority first
        let taken = mempool.take(2);
        assert_eq!(taken.len(), 2);
        assert_eq!(mempool.len(), 3);
    }

    #[test]
    fn test_write_coalescing() {
        let coalescer = WriteCoalescer::new(100, 1000);
        let pubkey = Pubkey::new([1u8; 32]);

        // Multiple writes to same account
        for i in 0..5 {
            let account = Account::new(i * 100, Pubkey::zero());
            coalescer.queue_write(0, pubkey, account);
        }

        // Should have coalesced
        let stats = coalescer.stats();
        assert_eq!(stats.coalesced_count, 4);
        assert_eq!(stats.write_count, 1);

        // Flush should return only last value
        let flushed = coalescer.flush_slot(0);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].1.celers, 400);
    }

    #[test]
    fn test_hot_cache() {
        let cache = HotAccountCache::new(3);

        // Add 3 accounts
        for i in 0..3 {
            let pubkey = Pubkey::new([i as u8; 32]);
            let account = Account::new(i as u64 * 100, Pubkey::zero());
            cache.insert(pubkey, account);
        }

        // All should be cached
        let stats = cache.stats();
        assert_eq!(stats.size, 3);

        // Access first one to make it recently used
        let _ = cache.get(&Pubkey::new([0u8; 32]));

        // Add 4th - should evict LRU (either 1 or 2)
        let pubkey = Pubkey::new([3u8; 32]);
        cache.insert(pubkey, Account::new(300, Pubkey::zero()));

        assert_eq!(cache.stats().size, 3);
    }

    #[test]
    fn test_optimized_storage() {
        let storage = OptimizedStorage::new();

        // Add some transactions
        for i in 0..10 {
            let tx = create_dummy_tx();
            storage.add_transaction(tx, i as u64 * 100, 200_000);
        }

        // Check mempool
        assert_eq!(storage.mempool.len(), 10);

        // Queue some writes
        let pubkey = Pubkey::new([1u8; 32]);
        storage.queue_account_write(pubkey, Account::new(1000, Pubkey::zero()));
        storage.queue_account_write(pubkey, Account::new(2000, Pubkey::zero()));

        // Should be in cache
        let cached = storage.get_account(&pubkey);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().celers, 2000);

        // Advance slot
        storage.advance_slot();
        assert_eq!(storage.current_slot(), 1);
    }
}
