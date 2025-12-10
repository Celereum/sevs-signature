//! Optimized Runtime/Executor for Celereum
//!
//! High-performance parallel execution with:
//! - Bloom Filter based conflict detection (faster than HashSet)
//! - Lock-free batch formation
//! - Pre-computed account access patterns
//! - Adaptive parallelism based on conflict rate
//!
//! Inspired by Solana Sealevel and Firedancer optimizations.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::hash::{Hash as StdHash, Hasher};
use parking_lot::RwLock;
use rayon::prelude::*;

use crate::core::{Account, Transaction, Instruction, Slot};
use crate::crypto::Pubkey;
use crate::crypto::Hash;

// ============================================================================
// Constants
// ============================================================================

/// Bloom filter size for conflict detection (128KB)
pub const CONFLICT_BLOOM_SIZE: usize = 1_048_576; // 1M bits

/// Number of hash functions for conflict bloom
pub const CONFLICT_BLOOM_HASHES: usize = 5;

/// Maximum transactions per batch
pub const MAX_BATCH_SIZE: usize = 1000;

/// Minimum batch size before parallel execution
pub const MIN_PARALLEL_SIZE: usize = 4;

/// Conflict threshold for batch splitting (percentage)
pub const CONFLICT_THRESHOLD: f64 = 0.3;

// ============================================================================
// Bloom Filter for Conflict Detection
// ============================================================================

/// Fast bloom filter for account conflict detection
pub struct ConflictBloomFilter {
    /// Bit array (using u64 for atomic operations)
    bits: Vec<AtomicU64>,
    /// Number of bits
    num_bits: usize,
    /// Number of hash functions
    num_hashes: usize,
}

impl ConflictBloomFilter {
    /// Create new bloom filter
    pub fn new(size_bits: usize, num_hashes: usize) -> Self {
        let num_words = (size_bits + 63) / 64;
        let bits = (0..num_words)
            .map(|_| AtomicU64::new(0))
            .collect();

        Self {
            bits,
            num_bits: size_bits,
            num_hashes,
        }
    }

    /// Insert a pubkey into the filter
    pub fn insert(&self, pubkey: &Pubkey) {
        let hashes = self.compute_hashes(pubkey);

        for h in hashes {
            let idx = h as usize % self.num_bits;
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            self.bits[word_idx].fetch_or(1 << bit_idx, Ordering::Relaxed);
        }
    }

    /// Check if pubkey might be in filter
    pub fn might_contain(&self, pubkey: &Pubkey) -> bool {
        let hashes = self.compute_hashes(pubkey);

        for h in hashes {
            let idx = h as usize % self.num_bits;
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            let word = self.bits[word_idx].load(Ordering::Relaxed);
            if word & (1 << bit_idx) == 0 {
                return false;
            }
        }
        true
    }

    /// Check if any pubkey in set might conflict
    pub fn might_conflict_any(&self, pubkeys: &[Pubkey]) -> bool {
        for pubkey in pubkeys {
            if self.might_contain(pubkey) {
                return true;
            }
        }
        false
    }

    /// Clear the filter
    pub fn clear(&self) {
        for word in &self.bits {
            word.store(0, Ordering::Relaxed);
        }
    }

    /// Compute multiple hash values for a pubkey
    fn compute_hashes(&self, pubkey: &Pubkey) -> Vec<u64> {
        let bytes = pubkey.as_bytes();

        // Use two independent hashes and combine (Kirsch-Mitzenmacher)
        let h1 = self.hash_bytes(bytes, 0);
        let h2 = self.hash_bytes(bytes, h1);

        (0..self.num_hashes as u64)
            .map(|i| h1.wrapping_add(i.wrapping_mul(h2)))
            .collect()
    }

    /// Hash bytes with seed
    fn hash_bytes(&self, bytes: &[u8], seed: u64) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        bytes.hash(&mut hasher);
        hasher.finish()
    }
}

// ============================================================================
// Pre-computed Access Pattern
// ============================================================================

/// Pre-computed account access pattern for a transaction
#[derive(Clone)]
pub struct AccessPattern {
    /// Write accounts
    pub writes: Vec<Pubkey>,
    /// Read accounts
    pub reads: Vec<Pubkey>,
    /// All accounts (for bloom filter)
    pub all_accounts: Vec<Pubkey>,
    /// Compute budget
    pub compute_budget: u64,
}

impl AccessPattern {
    /// Extract access pattern from transaction
    pub fn from_transaction(tx: &Transaction) -> Self {
        let header = &tx.message.header;
        let accounts = &tx.message.account_keys;

        let mut writes = Vec::new();
        let mut reads = Vec::new();

        for (i, account) in accounts.iter().enumerate() {
            let is_writable = if i < header.num_required_signatures as usize {
                i < (header.num_required_signatures - header.num_readonly_signed_accounts) as usize
            } else {
                let unsigned_idx = i - header.num_required_signatures as usize;
                unsigned_idx < (accounts.len() - header.num_required_signatures as usize - header.num_readonly_unsigned_accounts as usize)
            };

            if is_writable {
                writes.push(*account);
            } else {
                reads.push(*account);
            }
        }

        let all_accounts = accounts.clone();

        Self {
            writes,
            reads,
            all_accounts,
            compute_budget: 200_000, // Default
        }
    }

    /// Check if conflicts with another pattern
    pub fn conflicts_with(&self, other: &AccessPattern) -> bool {
        // Write-write conflict
        for w in &self.writes {
            if other.writes.contains(w) {
                return true;
            }
        }

        // Write-read conflict
        for w in &self.writes {
            if other.reads.contains(w) {
                return true;
            }
        }

        // Read-write conflict
        for r in &self.reads {
            if other.writes.contains(r) {
                return true;
            }
        }

        false
    }

    /// Check conflict using bloom filter (faster for large sets)
    pub fn conflicts_with_bloom(&self, bloom: &ConflictBloomFilter) -> bool {
        // Only check writes - they are the conflicts
        for w in &self.writes {
            if bloom.might_contain(w) {
                return true;
            }
        }
        false
    }
}

// ============================================================================
// Lock-free Batch Builder
// ============================================================================

/// Parallel batch for execution
pub struct ParallelBatch {
    /// Transactions with pre-computed patterns
    pub transactions: Vec<(usize, Transaction, AccessPattern)>,
    /// Bloom filter of all write accounts
    write_bloom: ConflictBloomFilter,
    /// Total compute budget
    total_compute: u64,
}

impl ParallelBatch {
    /// Create new batch
    pub fn new() -> Self {
        Self {
            transactions: Vec::with_capacity(MAX_BATCH_SIZE),
            write_bloom: ConflictBloomFilter::new(CONFLICT_BLOOM_SIZE, CONFLICT_BLOOM_HASHES),
            total_compute: 0,
        }
    }

    /// Try to add transaction to batch
    pub fn try_add(&mut self, idx: usize, tx: Transaction, pattern: AccessPattern) -> bool {
        // Check conflicts using bloom filter first (fast path)
        if pattern.conflicts_with_bloom(&self.write_bloom) {
            return false;
        }

        // Double-check with exact conflict detection (slow path for false positives)
        for (_, _, existing_pattern) in &self.transactions {
            if pattern.conflicts_with(existing_pattern) {
                return false;
            }
        }

        // No conflicts - add to batch
        for w in &pattern.writes {
            self.write_bloom.insert(w);
        }
        self.total_compute += pattern.compute_budget;
        self.transactions.push((idx, tx, pattern));

        true
    }

    /// Get transaction count
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

impl Default for ParallelBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Optimized Executor
// ============================================================================

/// Execution result
#[derive(Debug, Clone)]
pub struct ExecResult {
    pub signature: Hash,
    pub success: bool,
    pub error: Option<String>,
    pub compute_units: u64,
    pub fee: u64,
}

impl ExecResult {
    pub fn success(signature: Hash, compute_units: u64, fee: u64) -> Self {
        Self {
            signature,
            success: true,
            error: None,
            compute_units,
            fee,
        }
    }

    pub fn failure(signature: Hash, error: String, fee: u64) -> Self {
        Self {
            signature,
            success: false,
            error: Some(error),
            compute_units: 0,
            fee,
        }
    }
}

/// Optimized parallel executor
pub struct OptimizedExecutor {
    /// Account cache
    accounts: RwLock<HashMap<Pubkey, Account>>,
    /// Base fee per signature
    base_fee: u64,
    /// Compute budget per transaction
    compute_budget: u64,
    /// Statistics
    stats: ExecutorStats,
}

/// Executor statistics
pub struct ExecutorStats {
    pub transactions_executed: AtomicU64,
    pub batches_created: AtomicU64,
    pub conflicts_detected: AtomicU64,
    pub bloom_false_positives: AtomicU64,
    pub total_compute_used: AtomicU64,
    pub parallelism_factor: AtomicU64, // Stored as percentage
}

impl ExecutorStats {
    fn new() -> Self {
        Self {
            transactions_executed: AtomicU64::new(0),
            batches_created: AtomicU64::new(0),
            conflicts_detected: AtomicU64::new(0),
            bloom_false_positives: AtomicU64::new(0),
            total_compute_used: AtomicU64::new(0),
            parallelism_factor: AtomicU64::new(100),
        }
    }
}

impl OptimizedExecutor {
    /// Create new executor
    pub fn new() -> Self {
        Self {
            accounts: RwLock::new(HashMap::new()),
            base_fee: 2500,
            compute_budget: 400_000,
            stats: ExecutorStats::new(),
        }
    }

    /// Load accounts into cache
    pub fn load_accounts(&self, accounts: Vec<(Pubkey, Account)>) {
        let mut cache = self.accounts.write();
        for (key, account) in accounts {
            cache.insert(key, account);
        }
    }

    /// Get account from cache
    pub fn get_account(&self, pubkey: &Pubkey) -> Option<Account> {
        self.accounts.read().get(pubkey).cloned()
    }

    /// Set account in cache
    pub fn set_account(&self, pubkey: &Pubkey, account: Account) {
        self.accounts.write().insert(*pubkey, account);
    }

    /// Execute transactions with optimized parallel batching
    pub fn execute_batch(&self, transactions: Vec<Transaction>) -> Vec<ExecResult> {
        let len = transactions.len();
        if len == 0 {
            return Vec::new();
        }

        // Pre-compute access patterns (parallel)
        let patterns: Vec<(usize, Transaction, AccessPattern)> = transactions
            .into_par_iter()
            .enumerate()
            .map(|(idx, tx)| {
                let pattern = AccessPattern::from_transaction(&tx);
                (idx, tx, pattern)
            })
            .collect();

        // Create batches using bloom filter
        let batches = self.create_batches_bloom(patterns);
        self.stats.batches_created.fetch_add(batches.len() as u64, Ordering::Relaxed);

        // Execute batches
        let results: Arc<RwLock<Vec<Option<ExecResult>>>> = Arc::new(RwLock::new(vec![None; len]));

        for batch in batches {
            if batch.len() >= MIN_PARALLEL_SIZE {
                // Parallel execution within batch
                let batch_results: Vec<(usize, ExecResult)> = batch.transactions
                    .into_par_iter()
                    .map(|(idx, tx, _)| {
                        let result = self.execute_single(&tx);
                        (idx, result)
                    })
                    .collect();

                let mut results_guard = results.write();
                for (idx, result) in batch_results {
                    results_guard[idx] = Some(result);
                }
            } else {
                // Sequential for small batches
                let mut results_guard = results.write();
                for (idx, tx, _) in batch.transactions {
                    let result = self.execute_single(&tx);
                    results_guard[idx] = Some(result);
                }
            }
        }

        // Extract results
        let final_results = results.read();
        final_results.iter().map(|r| {
            r.clone().unwrap_or_else(|| {
                ExecResult::failure(Hash::hash(b"unknown"), "Not executed".to_string(), 0)
            })
        }).collect()
    }

    /// Create batches using bloom filter for fast conflict detection
    fn create_batches_bloom(&self, transactions: Vec<(usize, Transaction, AccessPattern)>) -> Vec<ParallelBatch> {
        let mut batches = Vec::new();
        let mut current_batch = ParallelBatch::new();

        for (idx, tx, pattern) in transactions {
            if !current_batch.try_add(idx, tx.clone(), pattern.clone()) {
                // Conflict detected
                self.stats.conflicts_detected.fetch_add(1, Ordering::Relaxed);

                // Start new batch
                if !current_batch.is_empty() {
                    batches.push(current_batch);
                }
                current_batch = ParallelBatch::new();

                // Add to new batch (should always succeed)
                current_batch.try_add(idx, tx, pattern);
            }
        }

        // Push last batch
        if !current_batch.is_empty() {
            batches.push(current_batch);
        }

        // Update parallelism stats
        if !batches.is_empty() {
            let total_txs: usize = batches.iter().map(|b| b.len()).sum();
            let avg_batch_size = total_txs / batches.len();
            let parallelism = (avg_batch_size * 100) / total_txs.max(1);
            self.stats.parallelism_factor.store(parallelism as u64, Ordering::Relaxed);
        }

        batches
    }

    /// Execute a single transaction
    pub fn execute_single(&self, tx: &Transaction) -> ExecResult {
        let signature = Hash::hash(&bincode::serialize(tx).unwrap_or_default());
        self.stats.transactions_executed.fetch_add(1, Ordering::Relaxed);

        // Verify signatures
        if !tx.verify() {
            return ExecResult::failure(signature, "Invalid signature".to_string(), 0);
        }

        // Calculate fee
        let fee = self.base_fee * tx.signatures.len() as u64;

        // Check fee payer
        if let Some(fee_payer) = tx.message.account_keys.first() {
            let balance = self.get_account(fee_payer)
                .map(|a| a.celers)
                .unwrap_or(0);

            if balance < fee {
                return ExecResult::failure(
                    signature,
                    "Insufficient balance for fee".to_string(),
                    0,
                );
            }

            // Deduct fee
            if let Some(mut account) = self.get_account(fee_payer) {
                account.celers -= fee;
                self.set_account(fee_payer, account);
            }
        }

        // Execute instructions
        let mut compute_used = 0u64;

        for instruction in &tx.message.instructions {
            // Simplified execution
            compute_used += 1000;

            if compute_used > self.compute_budget {
                return ExecResult::failure(
                    signature,
                    "Compute budget exceeded".to_string(),
                    fee,
                );
            }

            // Execute transfer if system program
            if instruction.program_id_index == 0 && instruction.data.len() >= 12 {
                if instruction.data[0] == 2 {
                    let celers = u64::from_le_bytes(
                        instruction.data[4..12].try_into().unwrap_or([0; 8])
                    );

                    if instruction.accounts.len() >= 2 {
                        let from_idx = instruction.accounts[0] as usize;
                        let to_idx = instruction.accounts[1] as usize;

                        if from_idx < tx.message.account_keys.len()
                            && to_idx < tx.message.account_keys.len()
                        {
                            let from = &tx.message.account_keys[from_idx];
                            let to = &tx.message.account_keys[to_idx];

                            // Execute transfer
                            if let Some(mut from_account) = self.get_account(from) {
                                if from_account.celers >= celers {
                                    from_account.celers -= celers;
                                    self.set_account(from, from_account);

                                    let mut to_account = self.get_account(to)
                                        .unwrap_or_else(|| Account::new(0, Pubkey::zero()));
                                    to_account.celers += celers;
                                    self.set_account(to, to_account);
                                }
                            }
                        }
                    }
                }
            }
        }

        self.stats.total_compute_used.fetch_add(compute_used, Ordering::Relaxed);
        ExecResult::success(signature, compute_used, fee)
    }

    /// Get executor statistics
    pub fn get_stats(&self) -> ExecutorStatsSnapshot {
        ExecutorStatsSnapshot {
            transactions_executed: self.stats.transactions_executed.load(Ordering::Relaxed),
            batches_created: self.stats.batches_created.load(Ordering::Relaxed),
            conflicts_detected: self.stats.conflicts_detected.load(Ordering::Relaxed),
            total_compute_used: self.stats.total_compute_used.load(Ordering::Relaxed),
            parallelism_factor: self.stats.parallelism_factor.load(Ordering::Relaxed) as f64 / 100.0,
        }
    }
}

impl Default for OptimizedExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics snapshot
#[derive(Debug, Clone)]
pub struct ExecutorStatsSnapshot {
    pub transactions_executed: u64,
    pub batches_created: u64,
    pub conflicts_detected: u64,
    pub total_compute_used: u64,
    pub parallelism_factor: f64,
}

// ============================================================================
// Adaptive Scheduler
// ============================================================================

/// Adaptive scheduler that adjusts parallelism based on conflict rate
pub struct AdaptiveScheduler {
    /// Recent conflict rates
    conflict_history: RwLock<Vec<f64>>,
    /// Current parallelism level (1.0 = full parallel, 0.0 = sequential)
    parallelism_level: AtomicU64,
    /// History window size
    window_size: usize,
}

impl AdaptiveScheduler {
    /// Create new adaptive scheduler
    pub fn new(window_size: usize) -> Self {
        Self {
            conflict_history: RwLock::new(Vec::with_capacity(window_size)),
            parallelism_level: AtomicU64::new(100), // 100%
            window_size,
        }
    }

    /// Record execution result
    pub fn record_execution(&self, total_txs: usize, conflicts: usize) {
        if total_txs == 0 {
            return;
        }

        let conflict_rate = conflicts as f64 / total_txs as f64;

        let mut history = self.conflict_history.write();
        history.push(conflict_rate);

        if history.len() > self.window_size {
            history.remove(0);
        }

        // Calculate average conflict rate
        let avg_conflict: f64 = history.iter().sum::<f64>() / history.len() as f64;

        // Adjust parallelism level
        let new_level = if avg_conflict > CONFLICT_THRESHOLD {
            // High conflicts - reduce parallelism
            ((1.0 - avg_conflict) * 100.0) as u64
        } else {
            // Low conflicts - increase parallelism
            100
        };

        self.parallelism_level.store(new_level, Ordering::Relaxed);
    }

    /// Get current parallelism level (0.0 - 1.0)
    pub fn parallelism_level(&self) -> f64 {
        self.parallelism_level.load(Ordering::Relaxed) as f64 / 100.0
    }

    /// Should use parallel execution?
    pub fn should_parallelize(&self) -> bool {
        self.parallelism_level.load(Ordering::Relaxed) > 50
    }
}

impl Default for AdaptiveScheduler {
    fn default() -> Self {
        Self::new(100)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_bloom_filter() {
        let bloom = ConflictBloomFilter::new(10000, 5);

        let pubkey1 = Pubkey::new([1u8; 32]);
        let pubkey2 = Pubkey::new([2u8; 32]);
        let pubkey3 = Pubkey::new([3u8; 32]);

        // Insert pubkey1
        bloom.insert(&pubkey1);

        // Check
        assert!(bloom.might_contain(&pubkey1));
        assert!(!bloom.might_contain(&pubkey2)); // Might have false positive

        // Insert more
        bloom.insert(&pubkey2);
        assert!(bloom.might_contain(&pubkey2));

        // pubkey3 not inserted
        // Note: might_contain can have false positives
    }

    #[test]
    fn test_access_pattern() {
        let pattern1 = AccessPattern {
            writes: vec![Pubkey::new([1u8; 32])],
            reads: vec![Pubkey::new([2u8; 32])],
            all_accounts: vec![Pubkey::new([1u8; 32]), Pubkey::new([2u8; 32])],
            compute_budget: 200_000,
        };

        let pattern2 = AccessPattern {
            writes: vec![Pubkey::new([3u8; 32])],
            reads: vec![Pubkey::new([4u8; 32])],
            all_accounts: vec![Pubkey::new([3u8; 32]), Pubkey::new([4u8; 32])],
            compute_budget: 200_000,
        };

        // No conflict
        assert!(!pattern1.conflicts_with(&pattern2));

        let pattern3 = AccessPattern {
            writes: vec![Pubkey::new([1u8; 32])], // Same as pattern1
            reads: vec![],
            all_accounts: vec![Pubkey::new([1u8; 32])],
            compute_budget: 200_000,
        };

        // Write-write conflict
        assert!(pattern1.conflicts_with(&pattern3));
    }

    #[test]
    fn test_parallel_batch() {
        use crate::crypto::Keypair;

        let mut batch = ParallelBatch::new();

        // Create non-conflicting transactions
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();

        let tx1 = Transaction::new_transfer(
            &keypair1,
            Pubkey::new([10u8; 32]),
            100,
            Hash::hash(b"blockhash"),
        );
        let pattern1 = AccessPattern::from_transaction(&tx1);

        let tx2 = Transaction::new_transfer(
            &keypair2,
            Pubkey::new([20u8; 32]),
            100,
            Hash::hash(b"blockhash"),
        );
        let pattern2 = AccessPattern::from_transaction(&tx2);

        // Both should add successfully (no conflicts)
        assert!(batch.try_add(0, tx1, pattern1));
        assert!(batch.try_add(1, tx2, pattern2));
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn test_adaptive_scheduler() {
        let scheduler = AdaptiveScheduler::new(10);

        // Initial: full parallelism
        assert!(scheduler.should_parallelize());

        // Record low conflicts
        for _ in 0..5 {
            scheduler.record_execution(100, 10); // 10% conflict
        }
        assert!(scheduler.should_parallelize());

        // Record high conflicts
        for _ in 0..20 {
            scheduler.record_execution(100, 50); // 50% conflict
        }
        assert!(!scheduler.should_parallelize());
    }
}
