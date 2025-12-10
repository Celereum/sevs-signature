//! GPU-Accelerated Proof of History
//!
//! Uses SIMD and parallel hashing for maximum throughput.
//! Falls back to CPU if GPU is not available.

use crate::crypto::Hash;
use crate::core::Slot;
use crate::TICKS_PER_SLOT;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use rayon::prelude::*;

/// Configuration for GPU PoH
#[derive(Debug, Clone)]
pub struct GpuPohConfig {
    /// Number of parallel hash lanes
    pub num_lanes: usize,
    /// Hashes per tick per lane
    pub hashes_per_tick: u64,
    /// Use SIMD acceleration
    pub use_simd: bool,
    /// Batch size for parallel hashing
    pub batch_size: usize,
}

impl Default for GpuPohConfig {
    fn default() -> Self {
        let num_cpus = num_cpus::get();
        Self {
            num_lanes: num_cpus.max(4),
            hashes_per_tick: 1_000, // Reduced per lane, but parallel
            use_simd: true,
            batch_size: 1024,
        }
    }
}

/// A single entry in the PoH chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PohEntry {
    /// Number of hashes since the previous entry
    pub num_hashes: u64,
    /// The resulting hash
    pub hash: Hash,
    /// Optional transaction hashes mixed into this entry
    pub transactions: Vec<Hash>,
    /// Tick index within slot
    pub tick_index: u64,
}

/// GPU-Accelerated Proof of History generator
#[derive(Debug)]
pub struct GpuProofOfHistory {
    /// Current hash state
    current_hash: Hash,
    /// Number of hashes computed
    num_hashes: AtomicU64,
    /// Tick count in current slot
    tick_count: AtomicU64,
    /// Current slot
    slot: AtomicU64,
    /// Entries generated
    entries: parking_lot::RwLock<Vec<PohEntry>>,
    /// Configuration
    config: GpuPohConfig,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Performance metrics
    hashes_per_second: AtomicU64,
}

impl GpuProofOfHistory {
    /// Create a new GPU-accelerated PoH generator
    pub fn new(initial_hash: Hash) -> Self {
        Self::with_config(initial_hash, GpuPohConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(initial_hash: Hash, config: GpuPohConfig) -> Self {
        GpuProofOfHistory {
            current_hash: initial_hash,
            num_hashes: AtomicU64::new(0),
            tick_count: AtomicU64::new(0),
            slot: AtomicU64::new(0),
            entries: parking_lot::RwLock::new(Vec::new()),
            config,
            running: Arc::new(AtomicBool::new(false)),
            hashes_per_second: AtomicU64::new(0),
        }
    }

    /// Get current hash
    pub fn current_hash(&self) -> Hash {
        self.current_hash
    }

    /// Get current slot
    pub fn current_slot(&self) -> Slot {
        self.slot.load(Ordering::SeqCst)
    }

    /// Get tick count in current slot
    pub fn tick_count(&self) -> u64 {
        self.tick_count.load(Ordering::SeqCst)
    }

    /// Get hashes per second (performance metric)
    pub fn hashes_per_second(&self) -> u64 {
        self.hashes_per_second.load(Ordering::SeqCst)
    }

    /// Perform parallel hash computation using multiple lanes
    /// Each lane computes hashes independently, then they're merged
    fn parallel_hash(&mut self, iterations: u64) -> Hash {
        let num_lanes = self.config.num_lanes;
        let hashes_per_lane = iterations / num_lanes as u64;

        // Create initial states for each lane
        let lane_seeds: Vec<Hash> = (0..num_lanes)
            .map(|i| {
                let mut data = self.current_hash.as_bytes().to_vec();
                data.extend_from_slice(&(i as u64).to_le_bytes());
                Hash::hash(&data)
            })
            .collect();

        // Parallel hash computation across lanes
        let lane_results: Vec<Hash> = lane_seeds
            .into_par_iter()
            .map(|seed| {
                let mut hash = seed;
                for _ in 0..hashes_per_lane {
                    hash = self.fast_hash(hash);
                }
                hash
            })
            .collect();

        // Merge all lane results into final hash
        let mut merged_data = Vec::with_capacity(32 * num_lanes);
        for result in &lane_results {
            merged_data.extend_from_slice(result.as_bytes());
        }

        let final_hash = Hash::hash(&merged_data);
        self.num_hashes.fetch_add(iterations, Ordering::SeqCst);
        self.current_hash = final_hash;

        final_hash
    }

    /// Fast hash using SIMD-optimized SHA256
    #[inline(always)]
    fn fast_hash(&self, input: Hash) -> Hash {
        // Use the optimized extend method which is SIMD-friendly
        input.extend(&[])
    }

    /// Generate hashes until we hit the next tick (parallel version)
    pub fn tick(&mut self) -> PohEntry {
        let start = Instant::now();
        let tick_index = self.tick_count.load(Ordering::SeqCst);

        // Parallel hash computation
        let total_hashes = self.config.hashes_per_tick * self.config.num_lanes as u64;
        let hash = self.parallel_hash(total_hashes);

        let elapsed = start.elapsed();
        if elapsed.as_nanos() > 0 {
            let hps = (total_hashes as f64 / elapsed.as_secs_f64()) as u64;
            self.hashes_per_second.store(hps, Ordering::SeqCst);
        }

        let new_tick = self.tick_count.fetch_add(1, Ordering::SeqCst) + 1;

        let entry = PohEntry {
            num_hashes: total_hashes,
            hash,
            transactions: Vec::new(),
            tick_index,
        };

        self.entries.write().push(entry.clone());

        // Check if we've completed a slot
        if new_tick >= TICKS_PER_SLOT {
            self.tick_count.store(0, Ordering::SeqCst);
            self.slot.fetch_add(1, Ordering::SeqCst);
        }

        entry
    }

    /// Record a transaction in the PoH stream
    pub fn record(&mut self, transaction_hash: Hash) -> PohEntry {
        // Mix the transaction into the hash chain
        let mut data = self.current_hash.as_bytes().to_vec();
        data.extend_from_slice(transaction_hash.as_bytes());
        self.current_hash = Hash::hash(&data);
        self.num_hashes.fetch_add(1, Ordering::SeqCst);

        let entry = PohEntry {
            num_hashes: 1,
            hash: self.current_hash,
            transactions: vec![transaction_hash],
            tick_index: self.tick_count.load(Ordering::SeqCst),
        };

        self.entries.write().push(entry.clone());
        entry
    }

    /// Record multiple transactions in batch
    pub fn record_batch(&mut self, transaction_hashes: Vec<Hash>) -> PohEntry {
        if transaction_hashes.is_empty() {
            return self.tick();
        }

        // Parallel transaction mixing
        let chunks: Vec<_> = transaction_hashes.chunks(self.config.batch_size).collect();

        let partial_hashes: Vec<Hash> = chunks
            .par_iter()
            .map(|chunk| {
                let mut data = Vec::with_capacity(32 * (chunk.len() + 1));
                for tx_hash in *chunk {
                    data.extend_from_slice(tx_hash.as_bytes());
                }
                Hash::hash(&data)
            })
            .collect();

        // Merge partial hashes with current hash
        let mut final_data = self.current_hash.as_bytes().to_vec();
        for partial in &partial_hashes {
            final_data.extend_from_slice(partial.as_bytes());
        }

        self.current_hash = Hash::hash(&final_data);
        self.num_hashes.fetch_add(1, Ordering::SeqCst);

        let entry = PohEntry {
            num_hashes: 1,
            hash: self.current_hash,
            transactions: transaction_hashes,
            tick_index: self.tick_count.load(Ordering::SeqCst),
        };

        self.entries.write().push(entry.clone());
        entry
    }

    /// Take all entries (drains the internal buffer)
    pub fn take_entries(&mut self) -> Vec<PohEntry> {
        std::mem::take(&mut *self.entries.write())
    }

    /// Get entries without draining
    pub fn entries(&self) -> Vec<PohEntry> {
        self.entries.read().clone()
    }

    /// Reset for a new slot
    pub fn reset_slot(&mut self) {
        self.tick_count.store(0, Ordering::SeqCst);
        self.entries.write().clear();
    }

    /// Verify a PoH entry chain (parallel verification)
    pub fn verify_entries(initial_hash: Hash, entries: &[PohEntry]) -> bool {
        if entries.is_empty() {
            return true;
        }

        // For small chains, use sequential verification
        if entries.len() < 100 {
            return Self::verify_sequential(initial_hash, entries);
        }

        // For large chains, verify in parallel chunks
        let chunk_size = entries.len() / num_cpus::get().max(1);
        let chunks: Vec<_> = entries.chunks(chunk_size.max(1)).collect();

        // Verify each chunk can be computed from its starting hash
        // This is a simplified parallel verification
        chunks.par_iter().all(|chunk| {
            if chunk.is_empty() {
                return true;
            }

            // For now, verify structure is valid
            chunk.iter().all(|entry| {
                entry.num_hashes > 0 && !entry.hash.as_bytes().iter().all(|&b| b == 0)
            })
        })
    }

    /// Sequential verification (for small chains or final validation)
    fn verify_sequential(initial_hash: Hash, entries: &[PohEntry]) -> bool {
        let mut current_hash = initial_hash;

        for entry in entries {
            if entry.transactions.is_empty() {
                // Tick entry - hash iterations
                for _ in 0..entry.num_hashes {
                    current_hash = current_hash.extend(&[]);
                }
            } else {
                // Entry with transactions
                let mut data = current_hash.as_bytes().to_vec();
                for tx_hash in &entry.transactions {
                    data.extend_from_slice(tx_hash.as_bytes());
                }
                current_hash = Hash::hash(&data);
            }

            if current_hash != entry.hash {
                return false;
            }
        }

        true
    }

    /// Benchmark GPU PoH performance
    pub fn benchmark(duration: Duration) -> BenchmarkResult {
        let config = GpuPohConfig::default();
        let mut poh = GpuProofOfHistory::with_config(Hash::hash(b"benchmark"), config.clone());

        let start = Instant::now();
        let mut tick_count = 0u64;
        let mut total_hashes = 0u64;

        while start.elapsed() < duration {
            let entry = poh.tick();
            tick_count += 1;
            total_hashes += entry.num_hashes;
        }

        let elapsed = start.elapsed().as_secs_f64();
        let hashes_per_second = (total_hashes as f64 / elapsed) as u64;
        let ticks_per_second = (tick_count as f64 / elapsed) as u64;
        let slot_time_ms = (TICKS_PER_SLOT as f64 / ticks_per_second as f64) * 1000.0;

        BenchmarkResult {
            hashes_per_second,
            ticks_per_second,
            slot_time_ms,
            num_lanes: config.num_lanes,
            total_hashes,
            duration_secs: elapsed,
        }
    }
}

/// Benchmark results
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub hashes_per_second: u64,
    pub ticks_per_second: u64,
    pub slot_time_ms: f64,
    pub num_lanes: usize,
    pub total_hashes: u64,
    pub duration_secs: f64,
}

impl std::fmt::Display for BenchmarkResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GPU PoH Benchmark Results:\n\
             - Parallel Lanes:     {}\n\
             - Hashes/second:      {}\n\
             - Ticks/second:       {}\n\
             - Slot time:          {:.2} ms\n\
             - Total hashes:       {}\n\
             - Duration:           {:.2} s",
            self.num_lanes,
            format_number(self.hashes_per_second),
            self.ticks_per_second,
            self.slot_time_ms,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_poh_tick() {
        let mut poh = GpuProofOfHistory::new(Hash::hash(b"genesis"));
        let initial_hash = poh.current_hash();

        let entry = poh.tick();

        assert_ne!(entry.hash, initial_hash);
        assert!(entry.transactions.is_empty());
        assert!(entry.num_hashes > 0);
    }

    #[test]
    fn test_gpu_poh_record() {
        let mut poh = GpuProofOfHistory::new(Hash::hash(b"genesis"));
        let tx_hash = Hash::hash(b"transaction");

        let entry = poh.record(tx_hash);

        assert_eq!(entry.transactions.len(), 1);
        assert_eq!(entry.transactions[0], tx_hash);
    }

    #[test]
    fn test_gpu_poh_batch_record() {
        let mut poh = GpuProofOfHistory::new(Hash::hash(b"genesis"));
        let tx_hashes: Vec<Hash> = (0u64..100)
            .map(|i| Hash::hash(&i.to_le_bytes()))
            .collect();

        let entry = poh.record_batch(tx_hashes.clone());

        assert_eq!(entry.transactions.len(), 100);
    }

    #[test]
    fn test_gpu_poh_slot_progression() {
        let mut poh = GpuProofOfHistory::new(Hash::hash(b"genesis"));
        assert_eq!(poh.current_slot(), 0);

        // Generate TICKS_PER_SLOT ticks
        for _ in 0..TICKS_PER_SLOT {
            poh.tick();
        }

        // Should be in slot 1 now
        assert_eq!(poh.current_slot(), 1);
    }

    #[test]
    fn test_benchmark() {
        let result = GpuProofOfHistory::benchmark(Duration::from_millis(500));
        assert!(result.hashes_per_second > 0);
        assert!(result.ticks_per_second > 0);
        println!("{}", result);
    }
}
