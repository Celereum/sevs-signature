//! Alpenglow/Votor Protocol Infrastructure
//!
//! This module provides the infrastructure for Solana's upcoming Alpenglow consensus,
//! which replaces Tower BFT with a more efficient single-round voting mechanism.
//!
//! # Votor (Vote Orchestrator)
//! - Coordinates validator voting
//! - Single-round finality (vs 3+ rounds in Tower BFT)
//! - Uses BLS signature aggregation
//!
//! # Rotor (Replication Orchestrator)
//! - Coordinates block propagation
//! - Direct broadcast to all nodes (vs tree-based Turbine)
//! - Faster block availability
//!
//! # Note
//! This is infrastructure preparation. Full Alpenglow requires additional
//! protocol changes that depend on upstream Solana releases.

use crate::core::{Block, Slot};
use crate::crypto::{
    Hash,
    Pubkey,
    bls::{BlsPublicKey, BlsSignature, AggregatedBlsSignature, ProofOfPossession, BlsKeypair},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
use parking_lot::{RwLock, Mutex};

// ============================================================================
// Votor (Vote Orchestrator)
// ============================================================================

/// Configuration for Votor
#[derive(Debug, Clone)]
pub struct VotorConfig {
    /// Vote timeout (ms)
    pub vote_timeout_ms: u64,
    /// Supermajority threshold
    pub supermajority_threshold: f64,
    /// Enable pre-vote phase
    pub enable_pre_vote: bool,
    /// Maximum concurrent slots to track
    pub max_concurrent_slots: usize,
    /// Vote aggregation batch size
    pub aggregation_batch_size: usize,
}

impl Default for VotorConfig {
    fn default() -> Self {
        Self {
            vote_timeout_ms: 200,
            supermajority_threshold: 2.0 / 3.0,
            enable_pre_vote: true,
            max_concurrent_slots: 32,
            aggregation_batch_size: 100,
        }
    }
}

/// Votor vote message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotorVote {
    /// Slot being voted on
    pub slot: Slot,
    /// Block hash
    pub block_hash: Hash,
    /// Voter's BLS public key
    pub voter: BlsPublicKey,
    /// BLS signature
    pub signature: BlsSignature,
    /// Vote type
    pub vote_type: VoteType,
    /// Timestamp
    pub timestamp: u64,
}

/// Vote type in Votor protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Pre-vote (first phase, optional)
    PreVote,
    /// Main vote (commits to block)
    Vote,
    /// Finalize vote (confirms finality)
    Finalize,
}

impl VotorVote {
    /// Create a new vote
    pub fn new(
        slot: Slot,
        block_hash: Hash,
        vote_type: VoteType,
        keypair: &BlsKeypair,
    ) -> Self {
        let message = Self::vote_message(slot, &block_hash, vote_type);
        let signature = keypair.sign_vote(&message);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            slot,
            block_hash,
            voter: keypair.public_key().clone(),
            signature,
            vote_type,
            timestamp,
        }
    }

    /// Create vote message
    fn vote_message(slot: Slot, block_hash: &Hash, vote_type: VoteType) -> Vec<u8> {
        let mut msg = Vec::with_capacity(41);
        msg.extend_from_slice(&slot.to_le_bytes());
        msg.extend_from_slice(block_hash.as_bytes());
        msg.push(vote_type as u8);
        msg
    }

    /// Verify the vote
    pub fn verify(&self) -> bool {
        let message = Self::vote_message(self.slot, &self.block_hash, self.vote_type);
        self.voter.verify_vote(&message, &self.signature)
    }
}

/// Aggregated votes for a slot
#[derive(Debug, Clone)]
struct SlotVotes {
    /// Block hash
    block_hash: Hash,
    /// Pre-votes
    pre_votes: Vec<VotorVote>,
    /// Main votes
    votes: Vec<VotorVote>,
    /// Finalize votes
    finalize_votes: Vec<VotorVote>,
    /// Total stake that pre-voted
    pre_vote_stake: u64,
    /// Total stake that voted
    vote_stake: u64,
    /// Total stake that finalized
    finalize_stake: u64,
    /// Voters (to prevent duplicates) - 96-byte BLS public keys
    voters: HashSet<[u8; 96]>,
    /// Start time
    start_time: Instant,
}

impl SlotVotes {
    fn new(block_hash: Hash) -> Self {
        Self {
            block_hash,
            pre_votes: Vec::new(),
            votes: Vec::new(),
            finalize_votes: Vec::new(),
            pre_vote_stake: 0,
            vote_stake: 0,
            finalize_stake: 0,
            voters: HashSet::new(),
            start_time: Instant::now(),
        }
    }
}

/// Vote orchestrator state
pub struct Votor {
    /// Configuration
    config: VotorConfig,
    /// Votes by slot
    slot_votes: RwLock<HashMap<Slot, SlotVotes>>,
    /// Validator stakes (96-byte BLS public keys)
    stakes: RwLock<HashMap<[u8; 96], u64>>,
    /// Total stake
    total_stake: AtomicU64,
    /// Finalized slots
    finalized: RwLock<HashSet<Slot>>,
    /// Latest finalized slot
    latest_finalized: AtomicU64,
    /// Statistics
    stats: VotorStats,
}

/// Votor statistics
#[derive(Debug, Default)]
pub struct VotorStats {
    pub total_votes: AtomicU64,
    pub slots_finalized: AtomicU64,
    pub avg_finality_ms: AtomicU64,
    pub pre_votes_received: AtomicU64,
}

/// Votor result
#[derive(Debug, Clone)]
pub enum VotorResult {
    /// Vote accepted, waiting for more
    Pending,
    /// Pre-vote threshold reached
    PreVoteReached,
    /// Vote threshold reached
    VoteReached,
    /// Slot is finalized
    Finalized { proof: VotorFinalityProof },
    /// Error occurred
    Error(String),
}

/// Finality proof from Votor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotorFinalityProof {
    /// Slot
    pub slot: Slot,
    /// Block hash
    pub block_hash: Hash,
    /// Aggregated signature
    pub signature: Vec<u8>,
    /// Voter public keys
    pub voters: Vec<BlsPublicKey>,
    /// Total stake
    pub total_stake: u64,
    /// Finality time (ms)
    pub finality_time_ms: u64,
}

impl Votor {
    /// Create a new Votor instance
    pub fn new(config: VotorConfig) -> Self {
        Self {
            config,
            slot_votes: RwLock::new(HashMap::new()),
            stakes: RwLock::new(HashMap::new()),
            total_stake: AtomicU64::new(0),
            finalized: RwLock::new(HashSet::new()),
            latest_finalized: AtomicU64::new(0),
            stats: VotorStats::default(),
        }
    }

    /// Register a validator
    pub fn register_validator(&self, pubkey: &BlsPublicKey, stake: u64) {
        let pk_bytes = pubkey.to_bytes();
        let mut stakes = self.stakes.write();

        if !stakes.contains_key(&pk_bytes) {
            stakes.insert(pk_bytes, stake);
            self.total_stake.fetch_add(stake, AtomicOrdering::SeqCst);
        }
    }

    /// Propose a block for voting
    pub fn propose_block(&self, slot: Slot, block_hash: Hash) -> Result<(), String> {
        let mut slot_votes = self.slot_votes.write();

        if slot_votes.len() >= self.config.max_concurrent_slots {
            // Clean up old slots
            let latest = self.latest_finalized.load(AtomicOrdering::SeqCst);
            slot_votes.retain(|&s, _| s > latest);
        }

        if slot_votes.contains_key(&slot) {
            return Err("Slot already proposed".to_string());
        }

        slot_votes.insert(slot, SlotVotes::new(block_hash));
        Ok(())
    }

    /// Submit a vote
    pub fn submit_vote(&self, vote: VotorVote) -> VotorResult {
        self.stats.total_votes.fetch_add(1, AtomicOrdering::Relaxed);

        if vote.vote_type == VoteType::PreVote {
            self.stats.pre_votes_received.fetch_add(1, AtomicOrdering::Relaxed);
        }

        // Verify vote
        if !vote.verify() {
            return VotorResult::Error("Invalid vote signature".to_string());
        }

        let pk_bytes = vote.voter.to_bytes();

        // Get stake
        let stake = self.stakes.read().get(&pk_bytes).copied().unwrap_or(0);
        if stake == 0 {
            return VotorResult::Error("Unknown validator".to_string());
        }

        let total_stake = self.total_stake.load(AtomicOrdering::SeqCst);
        let supermajority = (total_stake as f64 * self.config.supermajority_threshold) as u64;

        let mut slot_votes = self.slot_votes.write();
        let slot_state = match slot_votes.get_mut(&vote.slot) {
            Some(s) => s,
            None => {
                // Auto-create slot state
                slot_votes.insert(vote.slot, SlotVotes::new(vote.block_hash));
                slot_votes.get_mut(&vote.slot).unwrap()
            }
        };

        // Check for conflicting block hash
        if slot_state.block_hash != vote.block_hash {
            return VotorResult::Error("Vote for different block".to_string());
        }

        // Check for duplicate
        if slot_state.voters.contains(&pk_bytes) {
            return VotorResult::Pending;
        }

        // Add vote
        slot_state.voters.insert(pk_bytes);

        match vote.vote_type {
            VoteType::PreVote => {
                slot_state.pre_votes.push(vote);
                slot_state.pre_vote_stake = slot_state.pre_vote_stake.saturating_add(stake);

                if slot_state.pre_vote_stake >= supermajority {
                    return VotorResult::PreVoteReached;
                }
            }
            VoteType::Vote => {
                slot_state.votes.push(vote);
                slot_state.vote_stake = slot_state.vote_stake.saturating_add(stake);

                if slot_state.vote_stake >= supermajority {
                    return VotorResult::VoteReached;
                }
            }
            VoteType::Finalize => {
                slot_state.finalize_votes.push(vote.clone());
                slot_state.finalize_stake = slot_state.finalize_stake.saturating_add(stake);

                if slot_state.finalize_stake >= supermajority {
                    let finality_time_ms = slot_state.start_time.elapsed().as_millis() as u64;

                    // Create finality proof
                    let proof = VotorFinalityProof {
                        slot: vote.slot,
                        block_hash: slot_state.block_hash,
                        signature: vec![], // Would be aggregated signature
                        voters: slot_state.finalize_votes.iter().map(|v| v.voter.clone()).collect(),
                        total_stake: slot_state.finalize_stake,
                        finality_time_ms,
                    };

                    // Mark as finalized
                    drop(slot_votes);
                    self.finalized.write().insert(vote.slot);
                    self.latest_finalized.fetch_max(vote.slot, AtomicOrdering::SeqCst);
                    self.stats.slots_finalized.fetch_add(1, AtomicOrdering::Relaxed);
                    self.stats.avg_finality_ms.store(finality_time_ms, AtomicOrdering::Relaxed);

                    return VotorResult::Finalized { proof };
                }
            }
        }

        VotorResult::Pending
    }

    /// Check if slot is finalized
    pub fn is_finalized(&self, slot: Slot) -> bool {
        self.finalized.read().contains(&slot)
    }

    /// Get latest finalized slot
    pub fn latest_finalized(&self) -> Slot {
        self.latest_finalized.load(AtomicOrdering::SeqCst)
    }

    /// Get vote progress for a slot
    pub fn get_progress(&self, slot: Slot) -> Option<VoteProgress> {
        let slot_votes = self.slot_votes.read();
        let state = slot_votes.get(&slot)?;
        let total = self.total_stake.load(AtomicOrdering::SeqCst);

        Some(VoteProgress {
            slot,
            block_hash: state.block_hash,
            pre_vote_stake: state.pre_vote_stake,
            vote_stake: state.vote_stake,
            finalize_stake: state.finalize_stake,
            total_stake: total,
            pre_vote_percent: (state.pre_vote_stake as f64 / total as f64) * 100.0,
            vote_percent: (state.vote_stake as f64 / total as f64) * 100.0,
            finalize_percent: (state.finalize_stake as f64 / total as f64) * 100.0,
        })
    }

    /// Get statistics
    pub fn stats(&self) -> VotorStatistics {
        VotorStatistics {
            total_votes: self.stats.total_votes.load(AtomicOrdering::Relaxed),
            slots_finalized: self.stats.slots_finalized.load(AtomicOrdering::Relaxed),
            avg_finality_ms: self.stats.avg_finality_ms.load(AtomicOrdering::Relaxed),
            pre_votes_received: self.stats.pre_votes_received.load(AtomicOrdering::Relaxed),
            validators: self.stakes.read().len(),
            total_stake: self.total_stake.load(AtomicOrdering::SeqCst),
        }
    }
}

/// Vote progress for a slot
#[derive(Debug, Clone)]
pub struct VoteProgress {
    pub slot: Slot,
    pub block_hash: Hash,
    pub pre_vote_stake: u64,
    pub vote_stake: u64,
    pub finalize_stake: u64,
    pub total_stake: u64,
    pub pre_vote_percent: f64,
    pub vote_percent: f64,
    pub finalize_percent: f64,
}

/// Votor statistics
#[derive(Debug, Clone)]
pub struct VotorStatistics {
    pub total_votes: u64,
    pub slots_finalized: u64,
    pub avg_finality_ms: u64,
    pub pre_votes_received: u64,
    pub validators: usize,
    pub total_stake: u64,
}

// ============================================================================
// Rotor (Replication Orchestrator)
// ============================================================================

/// Configuration for Rotor
#[derive(Debug, Clone)]
pub struct RotorConfig {
    /// Maximum block size (bytes)
    pub max_block_size: usize,
    /// Chunk size for block distribution
    pub chunk_size: usize,
    /// Replication factor
    pub replication_factor: usize,
    /// Timeout for block propagation (ms)
    pub propagation_timeout_ms: u64,
}

impl Default for RotorConfig {
    fn default() -> Self {
        Self {
            max_block_size: 256 * 1024 * 1024, // 256 MB
            chunk_size: 64 * 1024,              // 64 KB
            replication_factor: 3,
            propagation_timeout_ms: 200,
        }
    }
}

/// Block chunk for distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockChunk {
    /// Slot
    pub slot: Slot,
    /// Block hash
    pub block_hash: Hash,
    /// Chunk index
    pub index: u32,
    /// Total chunks
    pub total_chunks: u32,
    /// Chunk data
    pub data: Vec<u8>,
    /// Merkle proof
    pub proof: Option<Vec<Hash>>,
}

/// Rotor state for block assembly
struct BlockAssembly {
    /// Block hash
    block_hash: Hash,
    /// Received chunks
    chunks: HashMap<u32, BlockChunk>,
    /// Total expected chunks
    total_chunks: u32,
    /// Start time
    start_time: Instant,
}

/// Replication orchestrator
pub struct Rotor {
    /// Configuration
    config: RotorConfig,
    /// Pending block assemblies
    assemblies: RwLock<HashMap<Slot, BlockAssembly>>,
    /// Completed blocks
    completed: RwLock<HashMap<Slot, Vec<u8>>>,
    /// Statistics
    stats: RotorStats,
}

/// Rotor statistics
#[derive(Debug, Default)]
pub struct RotorStats {
    pub chunks_received: AtomicU64,
    pub blocks_assembled: AtomicU64,
    pub bytes_received: AtomicU64,
}

impl Rotor {
    /// Create a new Rotor instance
    pub fn new(config: RotorConfig) -> Self {
        Self {
            config,
            assemblies: RwLock::new(HashMap::new()),
            completed: RwLock::new(HashMap::new()),
            stats: RotorStats::default(),
        }
    }

    /// Split a block into chunks for distribution
    pub fn chunk_block(&self, slot: Slot, block: &[u8]) -> Vec<BlockChunk> {
        let block_hash = Hash::hash(block);
        let total_chunks = (block.len() + self.config.chunk_size - 1) / self.config.chunk_size;

        block.chunks(self.config.chunk_size)
            .enumerate()
            .map(|(i, chunk)| BlockChunk {
                slot,
                block_hash,
                index: i as u32,
                total_chunks: total_chunks as u32,
                data: chunk.to_vec(),
                proof: None, // Would include Merkle proof
            })
            .collect()
    }

    /// Receive a block chunk
    pub fn receive_chunk(&self, chunk: BlockChunk) -> Option<Vec<u8>> {
        self.stats.chunks_received.fetch_add(1, AtomicOrdering::Relaxed);
        self.stats.bytes_received.fetch_add(chunk.data.len() as u64, AtomicOrdering::Relaxed);

        let mut assemblies = self.assemblies.write();
        let assembly = assemblies.entry(chunk.slot).or_insert_with(|| BlockAssembly {
            block_hash: chunk.block_hash,
            chunks: HashMap::new(),
            total_chunks: chunk.total_chunks,
            start_time: Instant::now(),
        });

        // Verify block hash matches
        if assembly.block_hash != chunk.block_hash {
            return None;
        }

        // Store chunk
        assembly.chunks.insert(chunk.index, chunk);

        // Check if complete
        if assembly.chunks.len() as u32 >= assembly.total_chunks {
            // Assemble block
            let mut block_data = Vec::new();
            for i in 0..assembly.total_chunks {
                if let Some(c) = assembly.chunks.get(&i) {
                    block_data.extend_from_slice(&c.data);
                } else {
                    return None; // Missing chunk
                }
            }

            // Verify
            let computed_hash = Hash::hash(&block_data);
            if computed_hash != assembly.block_hash {
                return None; // Hash mismatch
            }

            let slot = assembly.chunks.values().next()?.slot;
            drop(assemblies);

            // Store completed block
            self.completed.write().insert(slot, block_data.clone());
            self.assemblies.write().remove(&slot);
            self.stats.blocks_assembled.fetch_add(1, AtomicOrdering::Relaxed);

            return Some(block_data);
        }

        None
    }

    /// Get a completed block
    pub fn get_block(&self, slot: Slot) -> Option<Vec<u8>> {
        self.completed.read().get(&slot).cloned()
    }

    /// Get assembly progress
    pub fn get_progress(&self, slot: Slot) -> Option<(u32, u32)> {
        let assemblies = self.assemblies.read();
        assemblies.get(&slot).map(|a| (a.chunks.len() as u32, a.total_chunks))
    }

    /// Clean up old assemblies
    pub fn cleanup(&self, max_age_ms: u64) {
        let max_age = Duration::from_millis(max_age_ms);
        let mut assemblies = self.assemblies.write();
        assemblies.retain(|_, a| a.start_time.elapsed() < max_age);
    }

    /// Get statistics
    pub fn stats(&self) -> RotorStatistics {
        RotorStatistics {
            chunks_received: self.stats.chunks_received.load(AtomicOrdering::Relaxed),
            blocks_assembled: self.stats.blocks_assembled.load(AtomicOrdering::Relaxed),
            bytes_received: self.stats.bytes_received.load(AtomicOrdering::Relaxed),
            pending_assemblies: self.assemblies.read().len(),
            completed_blocks: self.completed.read().len(),
        }
    }
}

/// Rotor statistics
#[derive(Debug, Clone)]
pub struct RotorStatistics {
    pub chunks_received: u64,
    pub blocks_assembled: u64,
    pub bytes_received: u64,
    pub pending_assemblies: usize,
    pub completed_blocks: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_votor_with_validators(count: usize, stake: u64) -> (Votor, Vec<BlsKeypair>) {
        let votor = Votor::new(VotorConfig::default());
        let mut keypairs = Vec::new();

        for _ in 0..count {
            let kp = BlsKeypair::generate().unwrap();
            votor.register_validator(kp.public_key(), stake);
            keypairs.push(kp);
        }

        (votor, keypairs)
    }

    #[test]
    fn test_votor_voting() {
        let (votor, keypairs) = setup_votor_with_validators(4, 100);
        let block_hash = Hash::hash(b"test_block");

        votor.propose_block(1, block_hash).unwrap();

        // Vote with 3 validators (75% - supermajority)
        for i in 0..3 {
            let vote = VotorVote::new(1, block_hash, VoteType::Vote, &keypairs[i]);
            let result = votor.submit_vote(vote);

            if i < 2 {
                assert!(matches!(result, VotorResult::Pending));
            } else {
                assert!(matches!(result, VotorResult::VoteReached));
            }
        }
    }

    #[test]
    fn test_votor_finalization() {
        let (votor, keypairs) = setup_votor_with_validators(4, 100);
        let block_hash = Hash::hash(b"test_block");

        votor.propose_block(1, block_hash).unwrap();

        // Finalize votes
        for i in 0..3 {
            let vote = VotorVote::new(1, block_hash, VoteType::Finalize, &keypairs[i]);
            let result = votor.submit_vote(vote);

            if i == 2 {
                assert!(matches!(result, VotorResult::Finalized { .. }));
            }
        }

        assert!(votor.is_finalized(1));
    }

    #[test]
    fn test_rotor_chunking() {
        let rotor = Rotor::new(RotorConfig {
            chunk_size: 10,
            ..Default::default()
        });

        let block_data = b"Hello, this is a test block with some data!";
        let chunks = rotor.chunk_block(1, block_data);

        assert!(chunks.len() > 1);
        assert_eq!(chunks[0].total_chunks, chunks.len() as u32);
    }

    #[test]
    fn test_rotor_assembly() {
        let rotor = Rotor::new(RotorConfig {
            chunk_size: 10,
            ..Default::default()
        });

        let block_data = b"Hello, this is a test block!";
        let chunks = rotor.chunk_block(1, block_data);

        // Receive chunks out of order
        for chunk in chunks.iter().rev() {
            let result = rotor.receive_chunk(chunk.clone());

            if chunk.index == 0 {
                // Last chunk (received first due to reverse)
                assert!(result.is_some());
                assert_eq!(result.unwrap(), block_data.to_vec());
            }
        }
    }
}
