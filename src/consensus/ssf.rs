//! Single Slot Finality (SSF) for Celereum
//!
//! SSF enables immediate finality within a single slot (~400ms) instead of
//! waiting for multiple confirmations. This is achieved through:
//!
//! 1. BLS signature aggregation (O(1) signature size)
//! 2. All validators vote in every slot
//! 3. 2/3 supermajority required for finality
//! 4. No lockout periods - immediate finality
//!
//! # Security Model
//! - Requires 2/3 of total stake to finalize
//! - Equivocation results in immediate slashing
//! - No possibility of reorg after finality
//!
//! # Performance
//! - Target: Finality in < 500ms
//! - Vote aggregation: O(log n) with parallel processing
//! - Signature verification: Single pairing check

use crate::core::{Block, Slot};
use crate::crypto::{
    Hash,
    Pubkey,
    bls::{BlsPublicKey, BlsSignature, AggregatedBlsSignature, ProofOfPossession},
};
use crate::consensus::bls_voting::{BlsVote, AggregatedVotes, BlsVoteAggregator, BlsVoteError};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
use parking_lot::{RwLock, Mutex};

/// Configuration for Single Slot Finality
#[derive(Debug, Clone)]
pub struct SsfConfig {
    /// Supermajority threshold (typically 2/3)
    pub supermajority_threshold: f64,
    /// Maximum time to wait for votes (ms)
    pub vote_timeout_ms: u64,
    /// Minimum validators required
    pub min_validators: usize,
    /// Enable optimistic finality (finalize before full supermajority)
    pub optimistic_finality: bool,
    /// Optimistic threshold (e.g., 0.9 = 90% stake)
    pub optimistic_threshold: f64,
    /// Enable parallel vote aggregation
    pub parallel_aggregation: bool,
    /// Maximum votes to process per batch
    pub batch_size: usize,
}

impl Default for SsfConfig {
    fn default() -> Self {
        Self {
            supermajority_threshold: 2.0 / 3.0,
            vote_timeout_ms: 400,
            min_validators: 4,
            optimistic_finality: true,
            optimistic_threshold: 0.9,
            parallel_aggregation: true,
            batch_size: 1000,
        }
    }
}

/// SSF vote for a slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsfVote {
    /// BLS vote
    pub vote: BlsVote,
    /// Slot being voted on
    pub slot: Slot,
    /// Block hash
    pub block_hash: Hash,
    /// Voter's stake
    pub stake: u64,
    /// Vote timestamp (for ordering)
    pub timestamp: u64,
}

impl SsfVote {
    /// Create a new SSF vote
    pub fn new(
        slot: Slot,
        block_hash: Hash,
        stake: u64,
        keypair: &crate::crypto::bls::BlsKeypair,
    ) -> Self {
        let vote = BlsVote::new(slot, block_hash, stake, keypair);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            vote,
            slot,
            block_hash,
            stake,
            timestamp,
        }
    }

    /// Verify the vote
    pub fn verify(&self) -> bool {
        self.vote.verify()
    }
}

/// Finality status for a slot
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityStatus {
    /// Slot is pending - waiting for votes
    Pending,
    /// Optimistic finality reached (>90% stake)
    Optimistic,
    /// Full finality reached (2/3 stake)
    Finalized,
    /// Slot was skipped or timed out
    Skipped,
    /// Conflicting votes detected
    Conflicted,
}

/// Finality proof for a slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityProof {
    /// Slot that is finalized
    pub slot: Slot,
    /// Finalized block hash
    pub block_hash: Hash,
    /// Aggregated signature from all voters
    pub aggregated_signature: Vec<u8>,
    /// Public keys of voters
    pub voter_pubkeys: Vec<BlsPublicKey>,
    /// Total stake that voted
    pub total_stake: u64,
    /// Finality status
    pub status: FinalityStatus,
    /// Timestamp of finality
    pub finalized_at: u64,
}

impl FinalityProof {
    /// Verify the finality proof
    pub fn verify(&self) -> bool {
        if self.voter_pubkeys.is_empty() {
            return false;
        }

        // Recreate aggregated signature
        if let Ok(agg_sig) = AggregatedBlsSignature::from_bytes(
            &self.aggregated_signature.clone().try_into().unwrap_or([0u8; 48]),
            self.voter_pubkeys.len(),
        ) {
            let message = BlsVote::vote_message(self.slot, &self.block_hash);
            let pk_refs: Vec<&BlsPublicKey> = self.voter_pubkeys.iter().collect();
            agg_sig.verify_votes(&pk_refs, &message)
        } else {
            false
        }
    }
}

/// State for a slot being finalized
#[derive(Debug)]
struct SlotState {
    /// Block hash for this slot
    block_hash: Option<Hash>,
    /// Collected votes
    votes: Vec<BlsVote>,
    /// Stake that has voted
    voted_stake: u64,
    /// Validators that have voted (96-byte BLS public keys)
    voters: HashSet<[u8; 96]>,
    /// Status
    status: FinalityStatus,
    /// Start time
    start_time: Instant,
}

impl SlotState {
    fn new() -> Self {
        Self {
            block_hash: None,
            votes: Vec::new(),
            voted_stake: 0,
            voters: HashSet::new(),
            status: FinalityStatus::Pending,
            start_time: Instant::now(),
        }
    }
}

/// Single Slot Finality Engine
pub struct SsfEngine {
    /// Configuration
    config: SsfConfig,
    /// BLS vote aggregator
    aggregator: RwLock<BlsVoteAggregator>,
    /// State for each slot
    slot_states: RwLock<HashMap<Slot, SlotState>>,
    /// Finality proofs
    finality_proofs: RwLock<HashMap<Slot, FinalityProof>>,
    /// Total network stake
    total_stake: AtomicU64,
    /// Latest finalized slot
    latest_finalized: AtomicU64,
    /// Statistics
    stats: SsfStats,
}

/// SSF statistics
#[derive(Debug, Default)]
pub struct SsfStats {
    pub total_votes: AtomicU64,
    pub finalized_slots: AtomicU64,
    pub optimistic_finalizations: AtomicU64,
    pub skipped_slots: AtomicU64,
    pub avg_finality_time_ms: AtomicU64,
}

impl SsfEngine {
    /// Create a new SSF engine
    pub fn new(config: SsfConfig) -> Self {
        Self {
            config,
            aggregator: RwLock::new(BlsVoteAggregator::new()),
            slot_states: RwLock::new(HashMap::new()),
            finality_proofs: RwLock::new(HashMap::new()),
            total_stake: AtomicU64::new(0),
            latest_finalized: AtomicU64::new(0),
            stats: SsfStats::default(),
        }
    }

    /// Register a validator
    pub fn register_validator(
        &self,
        pubkey: &BlsPublicKey,
        pop: ProofOfPossession,
        stake: u64,
    ) -> Result<(), SsfError> {
        self.aggregator.write()
            .register_validator(pubkey, pop, stake)
            .map_err(|e| SsfError::RegistrationFailed(e.to_string()))?;

        self.total_stake.fetch_add(stake, AtomicOrdering::SeqCst);
        Ok(())
    }

    /// Unregister a validator
    pub fn unregister_validator(&self, pubkey: &BlsPublicKey, stake: u64) {
        self.aggregator.write().unregister_validator(pubkey);
        self.total_stake.fetch_sub(stake, AtomicOrdering::SeqCst);
    }

    /// Propose a block for a slot (called by leader)
    pub fn propose_block(&self, slot: Slot, block_hash: Hash) -> Result<(), SsfError> {
        let mut states = self.slot_states.write();

        if states.contains_key(&slot) {
            return Err(SsfError::SlotAlreadyProposed);
        }

        let mut state = SlotState::new();
        state.block_hash = Some(block_hash);
        states.insert(slot, state);

        Ok(())
    }

    /// Submit a vote for a slot
    pub fn submit_vote(&self, vote: SsfVote) -> Result<FinalityStatus, SsfError> {
        self.stats.total_votes.fetch_add(1, AtomicOrdering::Relaxed);

        // Verify vote
        if !vote.verify() {
            return Err(SsfError::InvalidVote);
        }

        let slot = vote.slot;
        let block_hash = vote.block_hash;
        let pk_bytes = vote.vote.voter.to_bytes();

        // Add to aggregator (for equivocation detection)
        self.aggregator.write()
            .add_vote(vote.vote.clone())
            .map_err(|e| match e {
                BlsVoteError::EquivocationDetected => SsfError::Equivocation,
                _ => SsfError::VoteFailed(e.to_string()),
            })?;

        let total_stake = self.total_stake.load(AtomicOrdering::SeqCst);
        let supermajority_stake = (total_stake as f64 * self.config.supermajority_threshold) as u64;
        let optimistic_stake = (total_stake as f64 * self.config.optimistic_threshold) as u64;

        // Update slot state
        let mut states = self.slot_states.write();
        let state = states.entry(slot).or_insert_with(SlotState::new);

        // Set block hash if not set
        if state.block_hash.is_none() {
            state.block_hash = Some(block_hash);
        } else if state.block_hash != Some(block_hash) {
            // Conflicting block hash
            state.status = FinalityStatus::Conflicted;
            return Err(SsfError::ConflictingBlockHash);
        }

        // Check for duplicate vote
        if state.voters.contains(&pk_bytes) {
            return Ok(state.status);
        }

        // Add vote
        state.voters.insert(pk_bytes);
        state.votes.push(vote.vote);
        state.voted_stake = state.voted_stake.saturating_add(vote.stake);

        // Check for finality
        let new_status = if state.voted_stake >= supermajority_stake {
            FinalityStatus::Finalized
        } else if self.config.optimistic_finality && state.voted_stake >= optimistic_stake {
            FinalityStatus::Optimistic
        } else {
            FinalityStatus::Pending
        };

        if new_status != state.status && new_status != FinalityStatus::Pending {
            state.status = new_status;

            // Create finality proof
            if new_status == FinalityStatus::Finalized || new_status == FinalityStatus::Optimistic {
                drop(states); // Release lock before creating proof
                self.create_finality_proof(slot, block_hash)?;

                if new_status == FinalityStatus::Finalized {
                    self.latest_finalized.fetch_max(slot, AtomicOrdering::SeqCst);
                    self.stats.finalized_slots.fetch_add(1, AtomicOrdering::Relaxed);
                } else {
                    self.stats.optimistic_finalizations.fetch_add(1, AtomicOrdering::Relaxed);
                }
            }
        }

        Ok(new_status)
    }

    /// Create a finality proof for a slot
    fn create_finality_proof(&self, slot: Slot, block_hash: Hash) -> Result<(), SsfError> {
        let states = self.slot_states.read();
        let state = states.get(&slot).ok_or(SsfError::SlotNotFound)?;

        if state.votes.is_empty() {
            return Err(SsfError::NoVotes);
        }

        // Aggregate votes
        let aggregated = AggregatedVotes::aggregate(&state.votes)
            .map_err(|e| SsfError::AggregationFailed(e.to_string()))?;

        let finality_time_ms = state.start_time.elapsed().as_millis() as u64;
        self.stats.avg_finality_time_ms.store(finality_time_ms, AtomicOrdering::Relaxed);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let proof = FinalityProof {
            slot,
            block_hash,
            aggregated_signature: aggregated.aggregated_signature.to_bytes().to_vec(),
            voter_pubkeys: aggregated.voters,
            total_stake: aggregated.total_stake,
            status: state.status,
            finalized_at: now,
        };

        drop(states);
        self.finality_proofs.write().insert(slot, proof);

        Ok(())
    }

    /// Check if a slot is finalized
    pub fn is_finalized(&self, slot: Slot) -> bool {
        self.finality_proofs.read().get(&slot)
            .map(|p| p.status == FinalityStatus::Finalized)
            .unwrap_or(false)
    }

    /// Get finality status for a slot
    pub fn get_status(&self, slot: Slot) -> FinalityStatus {
        self.slot_states.read().get(&slot)
            .map(|s| s.status)
            .unwrap_or(FinalityStatus::Pending)
    }

    /// Get finality proof for a slot
    pub fn get_finality_proof(&self, slot: Slot) -> Option<FinalityProof> {
        self.finality_proofs.read().get(&slot).cloned()
    }

    /// Get latest finalized slot
    pub fn latest_finalized_slot(&self) -> Slot {
        self.latest_finalized.load(AtomicOrdering::SeqCst)
    }

    /// Get current stake voted for a slot
    pub fn stake_for_slot(&self, slot: Slot) -> u64 {
        self.slot_states.read().get(&slot)
            .map(|s| s.voted_stake)
            .unwrap_or(0)
    }

    /// Get percentage of stake that voted for a slot
    pub fn vote_percentage(&self, slot: Slot) -> f64 {
        let total = self.total_stake.load(AtomicOrdering::SeqCst);
        if total == 0 {
            return 0.0;
        }

        let voted = self.stake_for_slot(slot);
        (voted as f64 / total as f64) * 100.0
    }

    /// Check for timed out slots
    pub fn check_timeouts(&self) -> Vec<Slot> {
        let timeout = Duration::from_millis(self.config.vote_timeout_ms);
        let mut timed_out = Vec::new();

        let mut states = self.slot_states.write();
        for (slot, state) in states.iter_mut() {
            if state.status == FinalityStatus::Pending && state.start_time.elapsed() > timeout {
                state.status = FinalityStatus::Skipped;
                timed_out.push(*slot);
                self.stats.skipped_slots.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        timed_out
    }

    /// Clean up old slot states
    pub fn cleanup_old_slots(&self, keep_slots: u64) {
        let latest = self.latest_finalized.load(AtomicOrdering::SeqCst);
        let threshold = latest.saturating_sub(keep_slots);

        self.slot_states.write().retain(|&slot, _| slot > threshold);
        self.finality_proofs.write().retain(|&slot, _| slot > threshold);
        self.aggregator.write().prune(threshold);
    }

    /// Get statistics
    pub fn stats(&self) -> SsfStatistics {
        SsfStatistics {
            total_votes: self.stats.total_votes.load(AtomicOrdering::Relaxed),
            finalized_slots: self.stats.finalized_slots.load(AtomicOrdering::Relaxed),
            optimistic_finalizations: self.stats.optimistic_finalizations.load(AtomicOrdering::Relaxed),
            skipped_slots: self.stats.skipped_slots.load(AtomicOrdering::Relaxed),
            avg_finality_time_ms: self.stats.avg_finality_time_ms.load(AtomicOrdering::Relaxed),
            total_stake: self.total_stake.load(AtomicOrdering::SeqCst),
            latest_finalized: self.latest_finalized.load(AtomicOrdering::SeqCst),
            validator_count: self.aggregator.read().validator_count(),
        }
    }
}

/// SSF errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum SsfError {
    #[error("Registration failed: {0}")]
    RegistrationFailed(String),

    #[error("Slot already proposed")]
    SlotAlreadyProposed,

    #[error("Invalid vote signature")]
    InvalidVote,

    #[error("Equivocation detected - validator voted twice")]
    Equivocation,

    #[error("Vote failed: {0}")]
    VoteFailed(String),

    #[error("Conflicting block hash for slot")]
    ConflictingBlockHash,

    #[error("Slot not found")]
    SlotNotFound,

    #[error("No votes for slot")]
    NoVotes,

    #[error("Aggregation failed: {0}")]
    AggregationFailed(String),

    #[error("Insufficient validators")]
    InsufficientValidators,
}

/// SSF statistics
#[derive(Debug, Clone)]
pub struct SsfStatistics {
    pub total_votes: u64,
    pub finalized_slots: u64,
    pub optimistic_finalizations: u64,
    pub skipped_slots: u64,
    pub avg_finality_time_ms: u64,
    pub total_stake: u64,
    pub latest_finalized: Slot,
    pub validator_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::bls::BlsKeypair;

    fn setup_ssf_engine_with_validators(count: usize, stake_per_validator: u64) -> (SsfEngine, Vec<BlsKeypair>) {
        let config = SsfConfig {
            min_validators: 1,
            ..Default::default()
        };
        let engine = SsfEngine::new(config);
        let mut keypairs = Vec::new();

        for _ in 0..count {
            let kp = BlsKeypair::generate().unwrap();
            engine.register_validator(
                kp.public_key(),
                kp.proof_of_possession().clone(),
                stake_per_validator,
            ).unwrap();
            keypairs.push(kp);
        }

        (engine, keypairs)
    }

    #[test]
    fn test_ssf_finality() {
        let (engine, keypairs) = setup_ssf_engine_with_validators(4, 100);
        let block_hash = Hash::hash(b"test_block");

        // Propose block
        engine.propose_block(1, block_hash).unwrap();

        // First vote (25%)
        let vote1 = SsfVote::new(1, block_hash, 100, &keypairs[0]);
        let status1 = engine.submit_vote(vote1).unwrap();
        assert_eq!(status1, FinalityStatus::Pending);

        // Second vote (50%)
        let vote2 = SsfVote::new(1, block_hash, 100, &keypairs[1]);
        let status2 = engine.submit_vote(vote2).unwrap();
        assert_eq!(status2, FinalityStatus::Pending);

        // Third vote (75% - finalized!)
        let vote3 = SsfVote::new(1, block_hash, 100, &keypairs[2]);
        let status3 = engine.submit_vote(vote3).unwrap();
        assert_eq!(status3, FinalityStatus::Finalized);

        // Check finality
        assert!(engine.is_finalized(1));
        assert_eq!(engine.latest_finalized_slot(), 1);

        // Get finality proof
        let proof = engine.get_finality_proof(1).unwrap();
        assert_eq!(proof.slot, 1);
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.status, FinalityStatus::Finalized);
    }

    #[test]
    fn test_ssf_optimistic_finality() {
        let config = SsfConfig {
            optimistic_finality: true,
            optimistic_threshold: 0.6,  // 60%
            supermajority_threshold: 0.67,
            ..Default::default()
        };
        let engine = SsfEngine::new(config);

        // Register 10 validators with 100 stake each
        let mut keypairs = Vec::new();
        for _ in 0..10 {
            let kp = BlsKeypair::generate().unwrap();
            engine.register_validator(
                kp.public_key(),
                kp.proof_of_possession().clone(),
                100,
            ).unwrap();
            keypairs.push(kp);
        }

        let block_hash = Hash::hash(b"test_block");
        engine.propose_block(1, block_hash).unwrap();

        // 6 votes = 60% (optimistic)
        for i in 0..6 {
            let vote = SsfVote::new(1, block_hash, 100, &keypairs[i]);
            engine.submit_vote(vote).unwrap();
        }

        let status = engine.get_status(1);
        assert_eq!(status, FinalityStatus::Optimistic);

        // Add 7th vote = 70% (finalized)
        let vote = SsfVote::new(1, block_hash, 100, &keypairs[6]);
        let final_status = engine.submit_vote(vote).unwrap();
        assert_eq!(final_status, FinalityStatus::Finalized);
    }

    #[test]
    fn test_ssf_equivocation_detection() {
        let (engine, keypairs) = setup_ssf_engine_with_validators(4, 100);

        let block_hash_a = Hash::hash(b"block_a");
        let block_hash_b = Hash::hash(b"block_b");

        engine.propose_block(1, block_hash_a).unwrap();

        // First vote for block A
        let vote_a = SsfVote::new(1, block_hash_a, 100, &keypairs[0]);
        engine.submit_vote(vote_a).unwrap();

        // Same validator tries to vote for block B - should fail
        let vote_b = SsfVote::new(1, block_hash_b, 100, &keypairs[0]);
        let result = engine.submit_vote(vote_b);
        assert!(matches!(result, Err(SsfError::Equivocation)));
    }

    #[test]
    fn test_ssf_conflicting_block_hash() {
        let (engine, keypairs) = setup_ssf_engine_with_validators(4, 100);

        let block_hash_a = Hash::hash(b"block_a");
        let block_hash_b = Hash::hash(b"block_b");

        engine.propose_block(1, block_hash_a).unwrap();

        // Vote for block A
        let vote_a = SsfVote::new(1, block_hash_a, 100, &keypairs[0]);
        engine.submit_vote(vote_a).unwrap();

        // Different validator votes for block B - conflict
        let vote_b = SsfVote::new(1, block_hash_b, 100, &keypairs[1]);
        let result = engine.submit_vote(vote_b);
        assert!(matches!(result, Err(SsfError::ConflictingBlockHash)));
    }

    #[test]
    fn test_finality_proof_verification() {
        let (engine, keypairs) = setup_ssf_engine_with_validators(4, 100);
        let block_hash = Hash::hash(b"test_block");

        engine.propose_block(1, block_hash).unwrap();

        // Get supermajority
        for i in 0..3 {
            let vote = SsfVote::new(1, block_hash, 100, &keypairs[i]);
            engine.submit_vote(vote).unwrap();
        }

        // Get and verify proof
        let proof = engine.get_finality_proof(1).unwrap();
        assert!(proof.verify());
    }
}
