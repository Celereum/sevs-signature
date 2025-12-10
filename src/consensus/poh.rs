//! Proof of History (PoH) - Verifiable Delay Function
//!
//! PoH creates a historical record that proves that an event occurred
//! at a specific moment in time. It's essentially a high-frequency
//! SHA256 hash chain that serves as a cryptographic clock.

use crate::crypto::Hash;
use crate::core::Slot;
use crate::TICKS_PER_SLOT;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A single entry in the PoH chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PohEntry {
    /// Number of hashes since the previous entry
    pub num_hashes: u64,

    /// The resulting hash
    pub hash: Hash,

    /// Optional transaction hashes mixed into this entry
    pub transactions: Vec<Hash>,
}

/// Proof of History generator
#[derive(Debug)]
pub struct ProofOfHistory {
    /// Current hash state
    current_hash: Hash,

    /// Number of hashes computed
    num_hashes: u64,

    /// Tick count in current slot
    tick_count: u64,

    /// Current slot
    slot: Slot,

    /// Entries generated
    entries: Vec<PohEntry>,

    /// Target hashes per tick
    hashes_per_tick: u64,

    /// Running flag
    running: Arc<AtomicBool>,
}

impl ProofOfHistory {
    /// Create a new PoH generator
    pub fn new(initial_hash: Hash) -> Self {
        // Calculate target hashes per tick based on desired tick rate
        // Optimized for ~200ms per slot with 64 ticks
        let hashes_per_tick = 100; // Reduced for testnet - faster block production

        ProofOfHistory {
            current_hash: initial_hash,
            num_hashes: 0,
            tick_count: 0,
            slot: 0,
            entries: Vec::new(),
            hashes_per_tick,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create PoH from a specific slot
    pub fn from_slot(slot: Slot, hash: Hash) -> Self {
        let mut poh = Self::new(hash);
        poh.slot = slot;
        poh
    }

    /// Get current hash
    pub fn current_hash(&self) -> Hash {
        self.current_hash
    }

    /// Get current slot
    pub fn current_slot(&self) -> Slot {
        self.slot
    }

    /// Get tick count in current slot
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Perform a single hash iteration
    #[inline]
    fn hash_once(&mut self) {
        self.current_hash = self.current_hash.extend(&[]);
        self.num_hashes += 1;
    }

    /// Generate hashes until we hit the next tick
    pub fn tick(&mut self) -> PohEntry {
        let start_hash = self.current_hash;
        let start_num_hashes = self.num_hashes;

        // Hash until we reach the target
        for _ in 0..self.hashes_per_tick {
            self.hash_once();
        }

        self.tick_count += 1;

        let entry = PohEntry {
            num_hashes: self.num_hashes - start_num_hashes,
            hash: self.current_hash,
            transactions: Vec::new(),
        };

        self.entries.push(entry.clone());

        // Check if we've completed a slot
        if self.tick_count >= TICKS_PER_SLOT {
            self.tick_count = 0;
            self.slot += 1;
        }

        entry
    }

    /// Record a transaction in the PoH stream
    pub fn record(&mut self, transaction_hash: Hash) -> PohEntry {
        // Mix the transaction into the hash chain
        self.current_hash = Hash::hash_multiple(&[
            self.current_hash.as_bytes(),
            transaction_hash.as_bytes(),
        ]);
        self.num_hashes += 1;

        let entry = PohEntry {
            num_hashes: 1,
            hash: self.current_hash,
            transactions: vec![transaction_hash],
        };

        self.entries.push(entry.clone());
        entry
    }

    /// Record multiple transactions
    pub fn record_batch(&mut self, transaction_hashes: Vec<Hash>) -> PohEntry {
        if transaction_hashes.is_empty() {
            return self.tick();
        }

        // Mix all transactions into the hash
        let mut data = self.current_hash.as_bytes().to_vec();
        for tx_hash in &transaction_hashes {
            data.extend_from_slice(tx_hash.as_bytes());
        }

        self.current_hash = Hash::hash(&data);
        self.num_hashes += 1;

        let entry = PohEntry {
            num_hashes: 1,
            hash: self.current_hash,
            transactions: transaction_hashes,
        };

        self.entries.push(entry.clone());
        entry
    }

    /// Take all entries (drains the internal buffer)
    pub fn take_entries(&mut self) -> Vec<PohEntry> {
        std::mem::take(&mut self.entries)
    }

    /// Get entries without draining
    pub fn entries(&self) -> &[PohEntry] {
        &self.entries
    }

    /// Reset for a new slot
    pub fn reset_slot(&mut self) {
        self.tick_count = 0;
        self.entries.clear();
    }

    /// Verify a PoH entry chain
    pub fn verify_entries(initial_hash: Hash, entries: &[PohEntry]) -> bool {
        let mut current_hash = initial_hash;

        for entry in entries {
            // Verify the hash chain
            if entry.transactions.is_empty() {
                // Tick entry - just hash iterations
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

    /// Benchmark hashes per second
    pub fn benchmark(duration: Duration) -> u64 {
        let mut hash = Hash::hash(b"benchmark");
        let mut count = 0u64;
        let start = Instant::now();

        while start.elapsed() < duration {
            for _ in 0..10000 {
                hash = hash.extend(&[]);
                count += 1;
            }
        }

        let elapsed = start.elapsed().as_secs_f64();
        (count as f64 / elapsed) as u64
    }
}

/// PoH service that runs in a separate thread
pub struct PohService {
    poh: ProofOfHistory,
    running: Arc<AtomicBool>,
}

impl PohService {
    /// Create a new PoH service
    pub fn new(initial_hash: Hash) -> Self {
        PohService {
            poh: ProofOfHistory::new(initial_hash),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the service
    pub fn start(&mut self) {
        self.running.store(true, Ordering::SeqCst);
    }

    /// Stop the service
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get the PoH generator
    pub fn poh(&mut self) -> &mut ProofOfHistory {
        &mut self.poh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poh_tick() {
        let mut poh = ProofOfHistory::new(Hash::hash(b"genesis"));
        let initial_hash = poh.current_hash();

        let entry = poh.tick();

        assert_ne!(entry.hash, initial_hash);
        assert!(entry.transactions.is_empty());
        assert!(entry.num_hashes > 0);
    }

    #[test]
    fn test_poh_record() {
        let mut poh = ProofOfHistory::new(Hash::hash(b"genesis"));
        let tx_hash = Hash::hash(b"transaction");

        let entry = poh.record(tx_hash);

        assert_eq!(entry.transactions.len(), 1);
        assert_eq!(entry.transactions[0], tx_hash);
    }

    #[test]
    fn test_poh_verify() {
        let initial_hash = Hash::hash(b"genesis");
        let mut poh = ProofOfHistory::new(initial_hash);

        // Generate some entries
        poh.tick();
        poh.record(Hash::hash(b"tx1"));
        poh.tick();
        poh.record(Hash::hash(b"tx2"));
        poh.tick();

        let entries = poh.entries().to_vec();

        // Verify the chain
        assert!(ProofOfHistory::verify_entries(initial_hash, &entries));
    }

    #[test]
    fn test_poh_invalid_chain() {
        let initial_hash = Hash::hash(b"genesis");
        let mut poh = ProofOfHistory::new(initial_hash);

        poh.tick();
        let mut entries = poh.entries().to_vec();

        // Tamper with an entry
        entries[0].hash = Hash::hash(b"fake");

        // Should fail verification
        assert!(!ProofOfHistory::verify_entries(initial_hash, &entries));
    }

    #[test]
    fn test_poh_slot_progression() {
        let mut poh = ProofOfHistory::new(Hash::hash(b"genesis"));
        assert_eq!(poh.current_slot(), 0);

        // Generate TICKS_PER_SLOT ticks
        for _ in 0..TICKS_PER_SLOT {
            poh.tick();
        }

        // Should be in slot 1 now
        assert_eq!(poh.current_slot(), 1);
    }
}
