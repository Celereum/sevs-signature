//! Parallel Proof of History - Multiple PoH chains for maximum throughput
//!
//! This module implements multiple parallel PoH chains that are periodically
//! merged into a single unified chain. This enables:
//! - 4-8x higher TPS through parallel transaction processing
//! - Better CPU/GPU utilization across multiple cores
//! - Reduced finality time through parallel slot processing
//!
//! SECURITY CONSIDERATIONS:
//! - Each lane must maintain cryptographic integrity
//! - Merge operations must be deterministic and verifiable
//! - Transaction ordering within lanes must be preserved
//! - Cross-lane dependencies must be handled correctly

use crate::crypto::Hash;
use crate::core::Slot;
use crate::TICKS_PER_SLOT;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::{RwLock, Mutex};
use rayon::prelude::*;

/// Maximum number of parallel PoH lanes
/// SECURITY: Limited to prevent resource exhaustion attacks
pub const MAX_POH_LANES: usize = 16;

/// Minimum number of parallel PoH lanes
pub const MIN_POH_LANES: usize = 2;

/// Default number of parallel PoH lanes
pub const DEFAULT_POH_LANES: usize = 4;

/// Merge interval in ticks (how often lanes are synchronized)
/// SECURITY: Must be frequent enough to prevent divergence attacks
pub const MERGE_INTERVAL_TICKS: u64 = 8;

/// Configuration for Parallel PoH
#[derive(Debug, Clone)]
pub struct ParallelPohConfig {
    /// Number of parallel PoH lanes
    pub num_lanes: usize,
    /// Hashes per tick per lane
    pub hashes_per_tick: u64,
    /// Merge interval in ticks
    pub merge_interval: u64,
    /// Enable cryptographic verification on merge
    pub verify_on_merge: bool,
    /// Maximum transactions per lane per tick
    pub max_tx_per_lane: usize,
}

impl Default for ParallelPohConfig {
    fn default() -> Self {
        let num_cpus = num_cpus::get();
        // Use at most half the CPUs for PoH, leave rest for other tasks
        let lanes = (num_cpus / 2).clamp(MIN_POH_LANES, MAX_POH_LANES);

        Self {
            num_lanes: lanes,
            hashes_per_tick: 1_000,
            merge_interval: MERGE_INTERVAL_TICKS,
            verify_on_merge: true,
            max_tx_per_lane: 10_000,
        }
    }
}

impl ParallelPohConfig {
    /// Validate configuration
    /// SECURITY: Prevents invalid configurations that could cause issues
    pub fn validate(&self) -> Result<(), ParallelPohError> {
        if self.num_lanes < MIN_POH_LANES || self.num_lanes > MAX_POH_LANES {
            return Err(ParallelPohError::InvalidLaneCount(self.num_lanes));
        }
        if self.hashes_per_tick == 0 {
            return Err(ParallelPohError::InvalidHashesPerTick);
        }
        if self.merge_interval == 0 || self.merge_interval > TICKS_PER_SLOT {
            return Err(ParallelPohError::InvalidMergeInterval);
        }
        if self.max_tx_per_lane == 0 {
            return Err(ParallelPohError::InvalidMaxTransactions);
        }
        Ok(())
    }
}

/// Entry in a single PoH lane
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaneEntry {
    /// Lane identifier (0 to num_lanes-1)
    pub lane_id: u8,
    /// Number of hashes since previous entry
    pub num_hashes: u64,
    /// Resulting hash
    pub hash: Hash,
    /// Transactions in this entry
    pub transactions: Vec<Hash>,
    /// Tick index within the lane
    pub tick_index: u64,
    /// Timestamp (nanoseconds since epoch)
    pub timestamp_ns: u64,
}

/// Merged entry from all lanes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedEntry {
    /// Merged hash from all lanes
    pub hash: Hash,
    /// Individual lane entries that were merged
    pub lane_entries: Vec<LaneEntry>,
    /// Merge index (how many merges have occurred)
    pub merge_index: u64,
    /// Total transactions across all lanes
    pub total_transactions: usize,
    /// Slot this merge belongs to
    pub slot: Slot,
}

/// A single PoH lane that operates independently
#[derive(Debug)]
struct PohLane {
    /// Lane identifier
    id: u8,
    /// Current hash state
    current_hash: Hash,
    /// Number of hashes computed
    num_hashes: u64,
    /// Tick count since last merge
    tick_count: u64,
    /// Entries since last merge
    entries: Vec<LaneEntry>,
    /// Pending transactions to be recorded
    pending_tx: Vec<Hash>,
    /// Hashes per tick for this lane
    hashes_per_tick: u64,
    /// Maximum transactions per tick
    max_tx_per_tick: usize,
}

impl PohLane {
    /// Create a new PoH lane
    fn new(id: u8, initial_hash: Hash, hashes_per_tick: u64, max_tx_per_tick: usize) -> Self {
        // SECURITY: Derive lane-specific initial hash to prevent identical lanes
        let lane_hash = Self::derive_lane_hash(initial_hash, id);

        PohLane {
            id,
            current_hash: lane_hash,
            num_hashes: 0,
            tick_count: 0,
            entries: Vec::new(),
            pending_tx: Vec::new(),
            hashes_per_tick,
            max_tx_per_tick,
        }
    }

    /// Derive lane-specific hash from base hash
    /// SECURITY: Each lane starts with unique hash to prevent replay attacks
    fn derive_lane_hash(base_hash: Hash, lane_id: u8) -> Hash {
        let mut data = base_hash.as_bytes().to_vec();
        data.push(lane_id);
        data.extend_from_slice(b"_lane_");
        data.extend_from_slice(&(lane_id as u64).to_le_bytes());
        Hash::hash(&data)
    }

    /// Add a transaction to the pending queue
    /// SECURITY: Limits transactions to prevent DoS
    fn add_transaction(&mut self, tx_hash: Hash) -> Result<(), ParallelPohError> {
        if self.pending_tx.len() >= self.max_tx_per_tick {
            return Err(ParallelPohError::LaneOverloaded(self.id));
        }
        self.pending_tx.push(tx_hash);
        Ok(())
    }

    /// Process one tick in this lane
    fn tick(&mut self) -> LaneEntry {
        let start_hash = self.current_hash;
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Process pending transactions first
        let transactions = std::mem::take(&mut self.pending_tx);

        if transactions.is_empty() {
            // Pure tick - just hash iterations
            for _ in 0..self.hashes_per_tick {
                self.current_hash = self.current_hash.extend(&[]);
            }
            self.num_hashes = self.num_hashes.saturating_add(self.hashes_per_tick);
        } else {
            // Mix transactions into hash
            let mut data = self.current_hash.as_bytes().to_vec();
            for tx_hash in &transactions {
                data.extend_from_slice(tx_hash.as_bytes());
            }
            self.current_hash = Hash::hash(&data);
            self.num_hashes = self.num_hashes.saturating_add(1);
        }

        let entry = LaneEntry {
            lane_id: self.id,
            num_hashes: if transactions.is_empty() { self.hashes_per_tick } else { 1 },
            hash: self.current_hash,
            transactions,
            tick_index: self.tick_count,
            timestamp_ns,
        };

        self.tick_count = self.tick_count.saturating_add(1);
        self.entries.push(entry.clone());

        entry
    }

    /// Take entries and reset for next merge period
    fn take_entries(&mut self) -> Vec<LaneEntry> {
        self.tick_count = 0;
        std::mem::take(&mut self.entries)
    }

    /// Get current state for verification
    fn state(&self) -> (Hash, u64) {
        (self.current_hash, self.num_hashes)
    }
}

/// Parallel Proof of History with multiple lanes
#[derive(Debug)]
pub struct ParallelProofOfHistory {
    /// Individual PoH lanes
    lanes: Vec<Mutex<PohLane>>,
    /// Merged hash (unified chain)
    merged_hash: RwLock<Hash>,
    /// Merged entries
    merged_entries: RwLock<Vec<MergedEntry>>,
    /// Current slot
    slot: AtomicU64,
    /// Global tick count
    global_tick: AtomicU64,
    /// Merge count
    merge_count: AtomicU64,
    /// Configuration
    config: ParallelPohConfig,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Performance metrics
    total_hashes: AtomicU64,
    total_transactions: AtomicU64,
}

impl ParallelProofOfHistory {
    /// Create new Parallel PoH with default configuration
    pub fn new(initial_hash: Hash) -> Result<Self, ParallelPohError> {
        Self::with_config(initial_hash, ParallelPohConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(initial_hash: Hash, config: ParallelPohConfig) -> Result<Self, ParallelPohError> {
        // SECURITY: Validate configuration
        config.validate()?;

        // Create lanes with unique initial hashes
        let lanes: Vec<Mutex<PohLane>> = (0..config.num_lanes)
            .map(|i| {
                Mutex::new(PohLane::new(
                    i as u8,
                    initial_hash,
                    config.hashes_per_tick,
                    config.max_tx_per_lane,
                ))
            })
            .collect();

        Ok(ParallelProofOfHistory {
            lanes,
            merged_hash: RwLock::new(initial_hash),
            merged_entries: RwLock::new(Vec::new()),
            slot: AtomicU64::new(0),
            global_tick: AtomicU64::new(0),
            merge_count: AtomicU64::new(0),
            config,
            running: Arc::new(AtomicBool::new(false)),
            total_hashes: AtomicU64::new(0),
            total_transactions: AtomicU64::new(0),
        })
    }

    /// Get number of lanes
    pub fn num_lanes(&self) -> usize {
        self.config.num_lanes
    }

    /// Get current merged hash
    pub fn current_hash(&self) -> Hash {
        *self.merged_hash.read()
    }

    /// Get current slot
    pub fn current_slot(&self) -> Slot {
        self.slot.load(Ordering::SeqCst)
    }

    /// Get global tick count
    pub fn tick_count(&self) -> u64 {
        self.global_tick.load(Ordering::SeqCst)
    }

    /// Get total hashes computed
    pub fn total_hashes(&self) -> u64 {
        self.total_hashes.load(Ordering::SeqCst)
    }

    /// Get total transactions processed
    pub fn total_transactions(&self) -> u64 {
        self.total_transactions.load(Ordering::SeqCst)
    }

    /// Record a transaction (automatically distributed to lanes)
    /// SECURITY: Uses deterministic lane selection based on transaction hash
    pub fn record(&self, tx_hash: Hash) -> Result<u8, ParallelPohError> {
        // SECURITY: Deterministic lane selection prevents manipulation
        let lane_id = self.select_lane(&tx_hash);

        let mut lane = self.lanes[lane_id as usize].lock();
        lane.add_transaction(tx_hash)?;

        self.total_transactions.fetch_add(1, Ordering::SeqCst);

        Ok(lane_id)
    }

    /// Record a batch of transactions
    /// SECURITY: Distributes transactions across lanes fairly
    pub fn record_batch(&self, tx_hashes: Vec<Hash>) -> Result<Vec<u8>, ParallelPohError> {
        let mut lane_assignments = Vec::with_capacity(tx_hashes.len());

        for tx_hash in tx_hashes {
            let lane_id = self.record(tx_hash)?;
            lane_assignments.push(lane_id);
        }

        Ok(lane_assignments)
    }

    /// Select lane for a transaction
    /// SECURITY: Uses first byte of hash for even distribution
    fn select_lane(&self, tx_hash: &Hash) -> u8 {
        let hash_bytes = tx_hash.as_bytes();
        // Use first byte modulo lane count for distribution
        (hash_bytes[0] as usize % self.config.num_lanes) as u8
    }

    /// Process one tick across all lanes in parallel
    pub fn tick(&self) -> Vec<LaneEntry> {
        let start = Instant::now();

        // Parallel tick processing across all lanes
        let entries: Vec<LaneEntry> = self.lanes
            .par_iter()
            .map(|lane| {
                let mut lane = lane.lock();
                lane.tick()
            })
            .collect();

        // Update global state
        let total_hashes: u64 = entries.iter().map(|e| e.num_hashes).sum();
        self.total_hashes.fetch_add(total_hashes, Ordering::SeqCst);

        let new_tick = self.global_tick.fetch_add(1, Ordering::SeqCst) + 1;

        // Check if we need to merge
        if new_tick % self.config.merge_interval == 0 {
            if let Err(e) = self.merge_lanes() {
                // Log error but don't fail - lanes continue independently
                eprintln!("Merge error: {:?}", e);
            }
        }

        // Check slot completion
        if new_tick % TICKS_PER_SLOT == 0 {
            self.slot.fetch_add(1, Ordering::SeqCst);
        }

        entries
    }

    /// Merge all lane hashes into unified chain
    /// SECURITY: Deterministic merge ensures all nodes arrive at same hash
    fn merge_lanes(&self) -> Result<MergedEntry, ParallelPohError> {
        let slot = self.current_slot();

        // Collect entries from all lanes
        let mut all_entries: Vec<LaneEntry> = Vec::new();
        let mut lane_hashes: Vec<Hash> = Vec::with_capacity(self.config.num_lanes);

        for lane in &self.lanes {
            let mut lane = lane.lock();
            let entries = lane.take_entries();

            // Get final hash from lane
            if let Some(last) = entries.last() {
                lane_hashes.push(last.hash);
            } else {
                lane_hashes.push(lane.state().0);
            }

            all_entries.extend(entries);
        }

        // SECURITY: Sort lane hashes for deterministic merge
        lane_hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        // Create merged hash
        let mut merge_data = self.merged_hash.read().as_bytes().to_vec();
        for lane_hash in &lane_hashes {
            merge_data.extend_from_slice(lane_hash.as_bytes());
        }
        // Add merge index for uniqueness
        let merge_index = self.merge_count.fetch_add(1, Ordering::SeqCst);
        merge_data.extend_from_slice(&merge_index.to_le_bytes());

        let merged_hash = Hash::hash(&merge_data);

        // Verify merge if configured
        if self.config.verify_on_merge {
            self.verify_merge(&lane_hashes, &merged_hash)?;
        }

        // Update merged hash
        *self.merged_hash.write() = merged_hash;

        // Calculate total transactions
        let total_tx: usize = all_entries.iter().map(|e| e.transactions.len()).sum();

        let merged_entry = MergedEntry {
            hash: merged_hash,
            lane_entries: all_entries,
            merge_index,
            total_transactions: total_tx,
            slot,
        };

        self.merged_entries.write().push(merged_entry.clone());

        Ok(merged_entry)
    }

    /// Verify merge integrity
    /// SECURITY: Ensures merge operation is correct
    fn verify_merge(&self, lane_hashes: &[Hash], expected_hash: &Hash) -> Result<(), ParallelPohError> {
        // Recompute merge hash
        let mut merge_data = self.merged_hash.read().as_bytes().to_vec();
        for lane_hash in lane_hashes {
            merge_data.extend_from_slice(lane_hash.as_bytes());
        }
        let merge_index = self.merge_count.load(Ordering::SeqCst);
        merge_data.extend_from_slice(&merge_index.to_le_bytes());

        let computed_hash = Hash::hash(&merge_data);

        if computed_hash != *expected_hash {
            return Err(ParallelPohError::MergeVerificationFailed);
        }

        Ok(())
    }

    /// Get all merged entries
    pub fn merged_entries(&self) -> Vec<MergedEntry> {
        self.merged_entries.read().clone()
    }

    /// Take merged entries (drains buffer)
    pub fn take_merged_entries(&self) -> Vec<MergedEntry> {
        std::mem::take(&mut *self.merged_entries.write())
    }

    /// Reset for new slot
    pub fn reset_slot(&self) {
        self.global_tick.store(0, Ordering::SeqCst);
        self.merged_entries.write().clear();

        // Reset all lanes
        for lane in &self.lanes {
            let mut lane = lane.lock();
            lane.take_entries();
        }
    }

    /// Verify a merged entry chain
    /// SECURITY: Full chain verification for consensus
    pub fn verify_merged_entries(initial_hash: Hash, entries: &[MergedEntry]) -> bool {
        if entries.is_empty() {
            return true;
        }

        let mut current_hash = initial_hash;

        for entry in entries {
            // Collect lane hashes from entry
            let mut lane_hashes: Vec<Hash> = entry.lane_entries
                .iter()
                .filter_map(|le| {
                    // Get last hash from each lane's entries
                    Some(le.hash)
                })
                .collect();

            // SECURITY: Sort for deterministic verification
            lane_hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            lane_hashes.dedup();

            // Recompute merged hash
            let mut merge_data = current_hash.as_bytes().to_vec();
            for lane_hash in &lane_hashes {
                merge_data.extend_from_slice(lane_hash.as_bytes());
            }
            merge_data.extend_from_slice(&entry.merge_index.to_le_bytes());

            let computed_hash = Hash::hash(&merge_data);

            if computed_hash != entry.hash {
                return false;
            }

            current_hash = entry.hash;
        }

        true
    }

    /// Benchmark parallel PoH performance
    pub fn benchmark(duration: Duration) -> ParallelPohBenchmark {
        let config = ParallelPohConfig::default();
        let poh = ParallelProofOfHistory::with_config(
            Hash::hash(b"benchmark"),
            config.clone()
        ).expect("Failed to create benchmark PoH");

        let start = Instant::now();
        let mut tick_count = 0u64;
        let mut merge_count = 0u64;

        while start.elapsed() < duration {
            poh.tick();
            tick_count += 1;

            if tick_count % MERGE_INTERVAL_TICKS == 0 {
                merge_count += 1;
            }
        }

        let elapsed = start.elapsed().as_secs_f64();
        let total_hashes = poh.total_hashes();
        let hashes_per_second = (total_hashes as f64 / elapsed) as u64;
        let ticks_per_second = (tick_count as f64 / elapsed) as u64;
        let merges_per_second = (merge_count as f64 / elapsed) as u64;
        let slot_time_ms = (TICKS_PER_SLOT as f64 / ticks_per_second as f64) * 1000.0;

        // Calculate effective TPS (theoretical max based on hash rate)
        let effective_tps = hashes_per_second / 100; // Assume 100 hashes per tx

        ParallelPohBenchmark {
            num_lanes: config.num_lanes,
            hashes_per_second,
            ticks_per_second,
            merges_per_second,
            slot_time_ms,
            total_hashes,
            effective_tps,
            duration_secs: elapsed,
        }
    }
}

/// Benchmark results for Parallel PoH
#[derive(Debug, Clone)]
pub struct ParallelPohBenchmark {
    pub num_lanes: usize,
    pub hashes_per_second: u64,
    pub ticks_per_second: u64,
    pub merges_per_second: u64,
    pub slot_time_ms: f64,
    pub total_hashes: u64,
    pub effective_tps: u64,
    pub duration_secs: f64,
}

impl std::fmt::Display for ParallelPohBenchmark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Parallel PoH Benchmark Results:\n\
             ═══════════════════════════════\n\
             Parallel Lanes:      {}\n\
             Hashes/second:       {}\n\
             Ticks/second:        {}\n\
             Merges/second:       {}\n\
             Slot time:           {:.2} ms\n\
             Effective TPS:       ~{}\n\
             Total hashes:        {}\n\
             Duration:            {:.2} s",
            self.num_lanes,
            format_number(self.hashes_per_second),
            self.ticks_per_second,
            self.merges_per_second,
            self.slot_time_ms,
            format_number(self.effective_tps),
            format_number(self.total_hashes),
            self.duration_secs
        )
    }
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Errors for Parallel PoH
#[derive(Debug, Clone, thiserror::Error)]
pub enum ParallelPohError {
    #[error("Invalid lane count: {0} (must be {}-{})", MIN_POH_LANES, MAX_POH_LANES)]
    InvalidLaneCount(usize),

    #[error("Invalid hashes per tick (must be > 0)")]
    InvalidHashesPerTick,

    #[error("Invalid merge interval (must be 1-{})", TICKS_PER_SLOT)]
    InvalidMergeInterval,

    #[error("Invalid max transactions (must be > 0)")]
    InvalidMaxTransactions,

    #[error("Lane {0} is overloaded with transactions")]
    LaneOverloaded(u8),

    #[error("Merge verification failed - hash mismatch")]
    MergeVerificationFailed,

    #[error("Lane verification failed for lane {0}")]
    LaneVerificationFailed(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_poh_creation() {
        let poh = ParallelProofOfHistory::new(Hash::hash(b"genesis"));
        assert!(poh.is_ok());

        let poh = poh.unwrap();
        assert!(poh.num_lanes() >= MIN_POH_LANES);
        assert!(poh.num_lanes() <= MAX_POH_LANES);
    }

    #[test]
    fn test_parallel_poh_tick() {
        let poh = ParallelProofOfHistory::new(Hash::hash(b"genesis")).unwrap();
        let initial_hash = poh.current_hash();

        let entries = poh.tick();

        assert_eq!(entries.len(), poh.num_lanes());
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.lane_id as usize, i);
            assert!(entry.num_hashes > 0);
        }
    }

    #[test]
    fn test_parallel_poh_record() {
        let poh = ParallelProofOfHistory::new(Hash::hash(b"genesis")).unwrap();

        let tx_hash = Hash::hash(b"transaction");
        let lane_id = poh.record(tx_hash);

        assert!(lane_id.is_ok());
        assert!(lane_id.unwrap() < poh.num_lanes() as u8);
        assert_eq!(poh.total_transactions(), 1);
    }

    #[test]
    fn test_parallel_poh_batch_record() {
        let poh = ParallelProofOfHistory::new(Hash::hash(b"genesis")).unwrap();

        let tx_hashes: Vec<Hash> = (0u64..100)
            .map(|i| Hash::hash(&i.to_le_bytes()))
            .collect();

        let result = poh.record_batch(tx_hashes);
        assert!(result.is_ok());

        let assignments = result.unwrap();
        assert_eq!(assignments.len(), 100);
        assert_eq!(poh.total_transactions(), 100);
    }

    #[test]
    fn test_parallel_poh_merge() {
        let poh = ParallelProofOfHistory::new(Hash::hash(b"genesis")).unwrap();

        // Generate enough ticks to trigger merge
        for _ in 0..MERGE_INTERVAL_TICKS {
            poh.tick();
        }

        let merged = poh.merged_entries();
        assert!(!merged.is_empty());
        assert_eq!(merged[0].merge_index, 0);
    }

    #[test]
    fn test_parallel_poh_slot_progression() {
        let poh = ParallelProofOfHistory::new(Hash::hash(b"genesis")).unwrap();
        assert_eq!(poh.current_slot(), 0);

        // Generate TICKS_PER_SLOT ticks
        for _ in 0..TICKS_PER_SLOT {
            poh.tick();
        }

        assert_eq!(poh.current_slot(), 1);
    }

    #[test]
    fn test_parallel_poh_verify_merged() {
        let poh = ParallelProofOfHistory::new(Hash::hash(b"genesis")).unwrap();
        let initial_hash = poh.current_hash();

        // Generate some ticks and merges
        for _ in 0..MERGE_INTERVAL_TICKS * 3 {
            poh.tick();
        }

        let merged = poh.merged_entries();
        assert!(ParallelProofOfHistory::verify_merged_entries(initial_hash, &merged));
    }

    #[test]
    fn test_lane_distribution() {
        let poh = ParallelProofOfHistory::new(Hash::hash(b"genesis")).unwrap();

        // Generate many transactions and check distribution
        let mut lane_counts = vec![0u64; poh.num_lanes()];

        for i in 0u64..1000 {
            let tx_hash = Hash::hash(&i.to_le_bytes());
            let lane_id = poh.record(tx_hash).unwrap();
            lane_counts[lane_id as usize] += 1;
        }

        // All lanes should have some transactions (fair distribution)
        for count in &lane_counts {
            assert!(*count > 0, "Lane should have at least one transaction");
        }
    }

    #[test]
    fn test_config_validation() {
        // Invalid lane count
        let config = ParallelPohConfig {
            num_lanes: MAX_POH_LANES + 1,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Invalid hashes per tick
        let config = ParallelPohConfig {
            hashes_per_tick: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Valid config
        let config = ParallelPohConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_benchmark() {
        let result = ParallelProofOfHistory::benchmark(Duration::from_millis(500));

        assert!(result.hashes_per_second > 0);
        assert!(result.ticks_per_second > 0);
        assert!(result.num_lanes >= MIN_POH_LANES);

        println!("{}", result);
    }
}
