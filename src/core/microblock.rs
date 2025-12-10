//! MicroBlocks - Fast intermediate blocks for ultra-low latency
//!
//! MicroBlocks are small, fast blocks that are produced between main blocks.
//! They provide:
//! - Sub-100ms transaction confirmation (soft confirmation)
//! - Reduced finality time without compromising security
//! - Better throughput during high traffic periods
//! - Streaming transaction processing
//!
//! # Post-Quantum Security
//! All signatures use SEVS (Seed-Expanded Verkle Signatures) for 128-bit
//! post-quantum security.
//!
//! SECURITY CONSIDERATIONS:
//! - MicroBlocks are NOT final until included in a main block
//! - Leader must be verified for each microblock
//! - Microblock chains must be cryptographically linked
//! - DoS protection through rate limiting
//! - Rollback protection through main block anchoring

use crate::crypto::{
    Hash,
    quantum_safe::{Address, TxSignature, QsSigner},
    sevs::SevsKeypair,
};
use crate::core::{Transaction, Slot};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;

/// Maximum microblocks per slot
/// SECURITY: Limits resource usage and prevents spam
pub const MAX_MICROBLOCKS_PER_SLOT: u64 = 128;

/// Minimum interval between microblocks (milliseconds)
/// SECURITY: Prevents rapid-fire microblock attacks
pub const MIN_MICROBLOCK_INTERVAL_MS: u64 = 10;

/// Maximum transactions per microblock
/// SECURITY: Prevents oversized microblocks
pub const MAX_TRANSACTIONS_PER_MICROBLOCK: usize = 500;

/// Default microblock interval (milliseconds)
pub const DEFAULT_MICROBLOCK_INTERVAL_MS: u64 = 50;

/// Microblock header - lightweight block header
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MicroBlockHeader {
    /// Parent slot (main block this belongs to)
    pub slot: Slot,

    /// Microblock index within the slot (0 to MAX_MICROBLOCKS_PER_SLOT-1)
    pub index: u64,

    /// Hash of previous microblock (or main block hash if first)
    pub previous_hash: Hash,

    /// Merkle root of transactions
    pub transactions_root: Hash,

    /// Proof of History hash at this point
    pub poh_hash: Hash,

    /// Leader who produced this microblock (Address)
    pub leader: Address,

    /// Timestamp (nanoseconds since epoch)
    pub timestamp_ns: u64,

    /// Number of transactions in this microblock
    pub transaction_count: u32,
}

impl MicroBlockHeader {
    /// Compute hash of the header
    pub fn hash(&self) -> Hash {
        let data = bincode::serialize(self).unwrap_or_default();
        Hash::hash(&data)
    }

    /// Verify basic header validity
    /// SECURITY: Prevents malformed headers
    pub fn validate(&self) -> Result<(), MicroBlockError> {
        // Check microblock index is within bounds
        if self.index >= MAX_MICROBLOCKS_PER_SLOT {
            return Err(MicroBlockError::InvalidIndex(self.index));
        }

        // Check timestamp is reasonable (not in far future)
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Allow 10 second tolerance for clock skew
        if self.timestamp_ns > now_ns.saturating_add(10_000_000_000) {
            return Err(MicroBlockError::FutureTimestamp);
        }

        // Check transaction count is within bounds
        if self.transaction_count as usize > MAX_TRANSACTIONS_PER_MICROBLOCK {
            return Err(MicroBlockError::TooManyTransactions(self.transaction_count as usize));
        }

        Ok(())
    }
}

/// A MicroBlock containing transactions with SEVS signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroBlock {
    /// Microblock header
    pub header: MicroBlockHeader,

    /// Transactions in this microblock
    pub transactions: Vec<Transaction>,

    /// Leader's SEVS signature on the header (includes pubkey)
    pub signature: TxSignature,
}

impl MicroBlock {
    /// Create a new microblock with SEVS signature
    pub fn new(
        slot: Slot,
        index: u64,
        previous_hash: Hash,
        poh_hash: Hash,
        transactions: Vec<Transaction>,
        keypair: &SevsKeypair,
    ) -> Result<Self, MicroBlockError> {
        // Validate transaction count
        if transactions.len() > MAX_TRANSACTIONS_PER_MICROBLOCK {
            return Err(MicroBlockError::TooManyTransactions(transactions.len()));
        }

        // Validate microblock index
        if index >= MAX_MICROBLOCKS_PER_SLOT {
            return Err(MicroBlockError::InvalidIndex(index));
        }

        // Compute transactions root
        let transactions_root = Self::compute_transactions_root(&transactions);

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let header = MicroBlockHeader {
            slot,
            index,
            previous_hash,
            transactions_root,
            poh_hash,
            leader: keypair.address(),
            timestamp_ns,
            transaction_count: transactions.len() as u32,
        };

        // Sign the header with SEVS
        let header_hash = header.hash();
        let signature = keypair.sign_tx(header_hash.as_bytes());

        Ok(MicroBlock {
            header,
            transactions,
            signature,
        })
    }

    /// Compute merkle root of transactions
    pub fn compute_transactions_root(transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::zero();
        }

        let mut hashes: Vec<Hash> = transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();

        while hashes.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in hashes.chunks(2) {
                let hash = if chunk.len() == 2 {
                    Hash::hash_multiple(&[chunk[0].as_bytes(), chunk[1].as_bytes()])
                } else {
                    Hash::hash_multiple(&[chunk[0].as_bytes(), chunk[0].as_bytes()])
                };
                next_level.push(hash);
            }

            hashes = next_level;
        }

        hashes[0]
    }

    /// Compute hash of this microblock
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Verify microblock SEVS signature
    /// SECURITY: Ensures microblock was created by the claimed leader
    pub fn verify_signature(&self) -> bool {
        let header_hash = self.header.hash();

        // Verify SEVS signature
        if !self.signature.verify(header_hash.as_bytes()) {
            return false;
        }

        // Verify signer matches leader
        if self.signature.address() != &self.header.leader {
            return false;
        }

        true
    }

    /// Verify transactions root matches
    /// SECURITY: Ensures transactions weren't tampered with
    pub fn verify_transactions(&self) -> bool {
        let computed_root = Self::compute_transactions_root(&self.transactions);
        computed_root == self.header.transactions_root
    }

    /// Full verification
    /// SECURITY: Complete integrity check
    pub fn verify(&self) -> Result<(), MicroBlockError> {
        // Validate header
        self.header.validate()?;

        // Verify signature
        if !self.verify_signature() {
            return Err(MicroBlockError::InvalidSignature);
        }

        // Verify transactions root
        if !self.verify_transactions() {
            return Err(MicroBlockError::TransactionsRootMismatch);
        }

        // Verify each transaction
        for (i, tx) in self.transactions.iter().enumerate() {
            if !tx.verify() {
                return Err(MicroBlockError::InvalidTransaction(i));
            }
        }

        Ok(())
    }

    /// Get size in bytes
    pub fn size(&self) -> usize {
        bincode::serialized_size(self).unwrap_or(0) as usize
    }
}

/// Chain of microblocks within a slot
#[derive(Debug)]
pub struct MicroBlockChain {
    /// Parent slot this chain belongs to
    slot: Slot,

    /// Microblocks in order
    microblocks: RwLock<Vec<MicroBlock>>,

    /// Hash of the last microblock (or parent block)
    last_hash: RwLock<Hash>,

    /// Next microblock index
    next_index: AtomicU64,

    /// Last microblock timestamp
    last_timestamp: AtomicU64,

    /// Total transactions in this chain
    total_transactions: AtomicU64,

    /// Is chain finalized (included in main block)
    finalized: AtomicBool,
}

impl MicroBlockChain {
    /// Create new microblock chain for a slot
    pub fn new(slot: Slot, parent_hash: Hash) -> Self {
        MicroBlockChain {
            slot,
            microblocks: RwLock::new(Vec::new()),
            last_hash: RwLock::new(parent_hash),
            next_index: AtomicU64::new(0),
            last_timestamp: AtomicU64::new(0),
            total_transactions: AtomicU64::new(0),
            finalized: AtomicBool::new(false),
        }
    }

    /// Get the slot this chain belongs to
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Get the hash of the last microblock
    pub fn last_hash(&self) -> Hash {
        *self.last_hash.read()
    }

    /// Get the next microblock index
    pub fn next_index(&self) -> u64 {
        self.next_index.load(Ordering::SeqCst)
    }

    /// Check if chain can accept more microblocks
    /// SECURITY: Prevents exceeding limits
    pub fn can_add(&self) -> bool {
        if self.finalized.load(Ordering::SeqCst) {
            return false;
        }

        let index = self.next_index.load(Ordering::SeqCst);
        if index >= MAX_MICROBLOCKS_PER_SLOT {
            return false;
        }

        // Check rate limiting
        let last_ts = self.last_timestamp.load(Ordering::SeqCst);
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let min_interval_ns = MIN_MICROBLOCK_INTERVAL_MS * 1_000_000;
        if now_ns.saturating_sub(last_ts) < min_interval_ns {
            return false;
        }

        true
    }

    /// Add a microblock to the chain
    /// SECURITY: Validates microblock before adding
    pub fn add(&self, microblock: MicroBlock) -> Result<(), MicroBlockError> {
        if self.finalized.load(Ordering::SeqCst) {
            return Err(MicroBlockError::ChainFinalized);
        }

        // Verify the microblock
        microblock.verify()?;

        // Check slot matches
        if microblock.header.slot != self.slot {
            return Err(MicroBlockError::SlotMismatch {
                expected: self.slot,
                got: microblock.header.slot,
            });
        }

        // Check index matches expected
        let expected_index = self.next_index.load(Ordering::SeqCst);
        if microblock.header.index != expected_index {
            return Err(MicroBlockError::IndexMismatch {
                expected: expected_index,
                got: microblock.header.index,
            });
        }

        // Check previous hash matches
        let expected_prev = *self.last_hash.read();
        if microblock.header.previous_hash != expected_prev {
            return Err(MicroBlockError::PreviousHashMismatch);
        }

        // Check we don't exceed limits
        if expected_index >= MAX_MICROBLOCKS_PER_SLOT {
            return Err(MicroBlockError::TooManyMicroBlocks);
        }

        // Update chain state
        let tx_count = microblock.transactions.len() as u64;
        let mb_hash = microblock.hash();

        *self.last_hash.write() = mb_hash;
        self.next_index.fetch_add(1, Ordering::SeqCst);
        self.last_timestamp.store(microblock.header.timestamp_ns, Ordering::SeqCst);
        self.total_transactions.fetch_add(tx_count, Ordering::SeqCst);

        self.microblocks.write().push(microblock);

        Ok(())
    }

    /// Get all microblocks
    pub fn microblocks(&self) -> Vec<MicroBlock> {
        self.microblocks.read().clone()
    }

    /// Get microblock by index
    pub fn get(&self, index: u64) -> Option<MicroBlock> {
        self.microblocks.read().get(index as usize).cloned()
    }

    /// Get total transaction count
    pub fn total_transactions(&self) -> u64 {
        self.total_transactions.load(Ordering::SeqCst)
    }

    /// Get all transactions from all microblocks
    pub fn all_transactions(&self) -> Vec<Transaction> {
        self.microblocks.read()
            .iter()
            .flat_map(|mb| mb.transactions.clone())
            .collect()
    }

    /// Finalize the chain (include in main block)
    /// SECURITY: Once finalized, no more microblocks can be added
    pub fn finalize(&self) -> Hash {
        self.finalized.store(true, Ordering::SeqCst);
        self.last_hash()
    }

    /// Check if chain is finalized
    pub fn is_finalized(&self) -> bool {
        self.finalized.load(Ordering::SeqCst)
    }

    /// Compute chain hash (for inclusion in main block)
    pub fn chain_hash(&self) -> Hash {
        let microblocks = self.microblocks.read();
        if microblocks.is_empty() {
            return Hash::zero();
        }

        // Collect all microblock hashes as byte vectors
        let hash_bytes: Vec<Vec<u8>> = microblocks
            .iter()
            .map(|mb| mb.hash().as_bytes().to_vec())
            .collect();

        // Concatenate all hashes and compute final hash
        let concatenated: Vec<u8> = hash_bytes.into_iter().flatten().collect();
        Hash::hash(&concatenated)
    }

    /// Verify the entire chain
    /// SECURITY: Validates chain integrity
    pub fn verify(&self, parent_hash: Hash, expected_leader: &Address) -> Result<(), MicroBlockError> {
        let microblocks = self.microblocks.read();

        let mut prev_hash = parent_hash;
        for (i, mb) in microblocks.iter().enumerate() {
            // Verify the microblock itself
            mb.verify()?;

            // Verify index
            if mb.header.index != i as u64 {
                return Err(MicroBlockError::IndexMismatch {
                    expected: i as u64,
                    got: mb.header.index,
                });
            }

            // Verify previous hash
            if mb.header.previous_hash != prev_hash {
                return Err(MicroBlockError::PreviousHashMismatch);
            }

            // Verify leader
            if mb.header.leader != *expected_leader {
                return Err(MicroBlockError::InvalidLeader);
            }

            prev_hash = mb.hash();
        }

        Ok(())
    }
}

/// MicroBlock producer - creates microblocks during slot leadership
#[derive(Debug)]
pub struct MicroBlockProducer {
    /// Current slot
    slot: Slot,

    /// Microblock chain for this slot
    chain: Arc<MicroBlockChain>,

    /// Pending transactions to include
    pending_transactions: RwLock<Vec<Transaction>>,

    /// Leader SEVS keypair
    keypair: Arc<SevsKeypair>,

    /// Current PoH hash
    poh_hash: RwLock<Hash>,

    /// Microblock interval
    interval_ms: u64,

    /// Last production time
    last_production: RwLock<Option<Instant>>,

    /// Is active
    active: AtomicBool,
}

impl MicroBlockProducer {
    /// Create new microblock producer with SEVS keypair
    pub fn new(
        slot: Slot,
        parent_hash: Hash,
        poh_hash: Hash,
        keypair: Arc<SevsKeypair>,
    ) -> Self {
        MicroBlockProducer {
            slot,
            chain: Arc::new(MicroBlockChain::new(slot, parent_hash)),
            pending_transactions: RwLock::new(Vec::new()),
            keypair,
            poh_hash: RwLock::new(poh_hash),
            interval_ms: DEFAULT_MICROBLOCK_INTERVAL_MS,
            last_production: RwLock::new(None),
            active: AtomicBool::new(true),
        }
    }

    /// Add transaction to pending queue
    pub fn add_transaction(&self, tx: Transaction) -> Result<(), MicroBlockError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(MicroBlockError::ProducerInactive);
        }

        let mut pending = self.pending_transactions.write();
        if pending.len() >= MAX_TRANSACTIONS_PER_MICROBLOCK {
            return Err(MicroBlockError::TooManyPendingTransactions);
        }

        pending.push(tx);
        Ok(())
    }

    /// Add multiple transactions
    pub fn add_transactions(&self, txs: Vec<Transaction>) -> Result<(), MicroBlockError> {
        for tx in txs {
            self.add_transaction(tx)?;
        }
        Ok(())
    }

    /// Update PoH hash
    pub fn update_poh(&self, poh_hash: Hash) {
        *self.poh_hash.write() = poh_hash;
    }

    /// Check if it's time to produce a microblock
    pub fn should_produce(&self) -> bool {
        if !self.active.load(Ordering::SeqCst) || !self.chain.can_add() {
            return false;
        }

        // Check interval
        let last = self.last_production.read();
        match *last {
            None => true,
            Some(t) => t.elapsed() >= Duration::from_millis(self.interval_ms),
        }
    }

    /// Produce a microblock from pending transactions
    pub fn produce(&self) -> Result<Option<MicroBlock>, MicroBlockError> {
        if !self.should_produce() {
            return Ok(None);
        }

        let transactions: Vec<Transaction> = {
            let mut pending = self.pending_transactions.write();
            let count = pending.len().min(MAX_TRANSACTIONS_PER_MICROBLOCK);
            pending.drain(..count).collect()
        };

        // Don't produce empty microblocks
        if transactions.is_empty() {
            return Ok(None);
        }

        let index = self.chain.next_index();
        let previous_hash = self.chain.last_hash();
        let poh_hash = *self.poh_hash.read();

        let microblock = MicroBlock::new(
            self.slot,
            index,
            previous_hash,
            poh_hash,
            transactions,
            &self.keypair,
        )?;

        // Add to chain
        self.chain.add(microblock.clone())?;

        // Update last production time
        *self.last_production.write() = Some(Instant::now());

        Ok(Some(microblock))
    }

    /// Get the microblock chain
    pub fn chain(&self) -> Arc<MicroBlockChain> {
        Arc::clone(&self.chain)
    }

    /// Finalize and stop producing
    pub fn finalize(&self) -> Hash {
        self.active.store(false, Ordering::SeqCst);
        self.chain.finalize()
    }

    /// Check if producer is active
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Get pending transaction count
    pub fn pending_count(&self) -> usize {
        self.pending_transactions.read().len()
    }
}

/// MicroBlock errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum MicroBlockError {
    #[error("Invalid microblock index: {0} (max {})", MAX_MICROBLOCKS_PER_SLOT - 1)]
    InvalidIndex(u64),

    #[error("Too many transactions: {0} (max {})", MAX_TRANSACTIONS_PER_MICROBLOCK)]
    TooManyTransactions(usize),

    #[error("Timestamp is in the future")]
    FutureTimestamp,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Transactions root mismatch")]
    TransactionsRootMismatch,

    #[error("Invalid transaction at index {0}")]
    InvalidTransaction(usize),

    #[error("Chain is finalized")]
    ChainFinalized,

    #[error("Slot mismatch: expected {expected}, got {got}")]
    SlotMismatch { expected: Slot, got: Slot },

    #[error("Index mismatch: expected {expected}, got {got}")]
    IndexMismatch { expected: u64, got: u64 },

    #[error("Previous hash mismatch")]
    PreviousHashMismatch,

    #[error("Too many microblocks in slot")]
    TooManyMicroBlocks,

    #[error("Invalid leader")]
    InvalidLeader,

    #[error("Producer is inactive")]
    ProducerInactive,

    #[error("Too many pending transactions")]
    TooManyPendingTransactions,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a properly signed test transaction
    fn create_test_transaction(keypair: &SevsKeypair) -> Transaction {
        let to = SevsKeypair::generate();
        Transaction::new_transfer(
            keypair,
            to.address(),
            1000,
            Hash::hash(b"blockhash"),
        )
    }

    #[test]
    fn test_microblock_creation() {
        let keypair = SevsKeypair::generate();
        let txs = vec![create_test_transaction(&keypair)];

        let mb = MicroBlock::new(
            0,
            0,
            Hash::hash(b"parent"),
            Hash::hash(b"poh"),
            txs,
            &keypair,
        );

        assert!(mb.is_ok());
        let mb = mb.unwrap();
        assert_eq!(mb.header.slot, 0);
        assert_eq!(mb.header.index, 0);
        assert_eq!(mb.transactions.len(), 1);
        assert_eq!(mb.header.leader, keypair.address());
    }

    #[test]
    fn test_microblock_verification() {
        let keypair = SevsKeypair::generate();
        let txs = vec![create_test_transaction(&keypair)];

        let mb = MicroBlock::new(
            0,
            0,
            Hash::hash(b"parent"),
            Hash::hash(b"poh"),
            txs,
            &keypair,
        ).unwrap();

        assert!(mb.verify().is_ok());
        assert!(mb.verify_signature());
        assert!(mb.verify_transactions());
    }

    #[test]
    fn test_microblock_chain() {
        let keypair = SevsKeypair::generate();
        let parent_hash = Hash::hash(b"parent");
        let chain = MicroBlockChain::new(0, parent_hash);

        // Add first microblock
        let mb1 = MicroBlock::new(
            0,
            0,
            parent_hash,
            Hash::hash(b"poh1"),
            vec![create_test_transaction(&keypair)],
            &keypair,
        ).unwrap();

        assert!(chain.add(mb1.clone()).is_ok());
        assert_eq!(chain.next_index(), 1);

        // Add second microblock
        let mb2 = MicroBlock::new(
            0,
            1,
            mb1.hash(),
            Hash::hash(b"poh2"),
            vec![create_test_transaction(&keypair)],
            &keypair,
        ).unwrap();

        assert!(chain.add(mb2).is_ok());
        assert_eq!(chain.next_index(), 2);
        assert_eq!(chain.total_transactions(), 2);
    }

    #[test]
    fn test_microblock_producer() {
        let keypair = Arc::new(SevsKeypair::generate());
        let producer = MicroBlockProducer::new(
            0,
            Hash::hash(b"parent"),
            Hash::hash(b"poh"),
            keypair.clone(),
        );

        // Add transaction
        let tx = create_test_transaction(&keypair);
        assert!(producer.add_transaction(tx).is_ok());

        // Produce microblock
        let mb = producer.produce();
        assert!(mb.is_ok());
        let mb = mb.unwrap();
        assert!(mb.is_some());

        let mb = mb.unwrap();
        assert_eq!(mb.transactions.len(), 1);
    }

    #[test]
    fn test_chain_verification() {
        let keypair = SevsKeypair::generate();
        let parent_hash = Hash::hash(b"parent");
        let chain = MicroBlockChain::new(0, parent_hash);

        // Add some microblocks
        let mut prev_hash = parent_hash;
        for i in 0..5 {
            let mb = MicroBlock::new(
                0,
                i,
                prev_hash,
                Hash::hash(&i.to_le_bytes()),
                vec![create_test_transaction(&keypair)],
                &keypair,
            ).unwrap();

            prev_hash = mb.hash();
            chain.add(mb).unwrap();
        }

        // Verify the chain
        assert!(chain.verify(parent_hash, &keypair.address()).is_ok());
    }

    #[test]
    fn test_invalid_index() {
        let keypair = SevsKeypair::generate();
        let txs = vec![create_test_transaction(&keypair)];

        // Try to create microblock with invalid index
        let result = MicroBlock::new(
            0,
            MAX_MICROBLOCKS_PER_SLOT, // Invalid
            Hash::hash(b"parent"),
            Hash::hash(b"poh"),
            txs,
            &keypair,
        );

        assert!(matches!(result, Err(MicroBlockError::InvalidIndex(_))));
    }

    #[test]
    fn test_too_many_transactions() {
        let keypair = SevsKeypair::generate();

        // Create too many transactions
        let txs: Vec<Transaction> = (0..MAX_TRANSACTIONS_PER_MICROBLOCK + 1)
            .map(|_| create_test_transaction(&keypair))
            .collect();

        let result = MicroBlock::new(
            0,
            0,
            Hash::hash(b"parent"),
            Hash::hash(b"poh"),
            txs,
            &keypair,
        );

        assert!(matches!(result, Err(MicroBlockError::TooManyTransactions(_))));
    }

    #[test]
    fn test_chain_finalization() {
        let keypair = SevsKeypair::generate();
        let chain = MicroBlockChain::new(0, Hash::hash(b"parent"));

        // Add microblock
        let mb = MicroBlock::new(
            0,
            0,
            Hash::hash(b"parent"),
            Hash::hash(b"poh"),
            vec![create_test_transaction(&keypair)],
            &keypair,
        ).unwrap();

        chain.add(mb).unwrap();

        // Finalize
        let final_hash = chain.finalize();
        assert!(chain.is_finalized());

        // Try to add after finalization
        let mb2 = MicroBlock::new(
            0,
            1,
            final_hash,
            Hash::hash(b"poh2"),
            vec![create_test_transaction(&keypair)],
            &keypair,
        ).unwrap();

        assert!(matches!(chain.add(mb2), Err(MicroBlockError::ChainFinalized)));
    }
}
