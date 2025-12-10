//! Tower BFT - Celereum's consensus mechanism
//!
//! Tower BFT is a PBFT-like consensus algorithm optimized for PoH.
//! It uses the PoH clock to reduce messaging overhead and achieve
//! faster finality.

use crate::core::Slot;
use crate::crypto::{Hash, Pubkey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Tower BFT state for a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TowerBFT {
    /// Validator's pubkey
    pub validator: Pubkey,

    /// Vote stack - votes with lockout
    pub votes: Vec<Lockout>,

    /// Root slot (finalized)
    pub root: Option<Slot>,

    /// Last voted slot
    pub last_voted_slot: Option<Slot>,

    /// Total stake in the network
    pub total_stake: u64,
}

/// A vote with lockout period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockout {
    /// Slot voted for
    pub slot: Slot,

    /// Confirmation count (increases lockout exponentially)
    pub confirmation_count: u32,
}

impl Lockout {
    /// Create a new lockout
    pub fn new(slot: Slot) -> Self {
        Lockout {
            slot,
            confirmation_count: 1,
        }
    }

    /// Calculate the lockout duration
    /// Lockout = 2^confirmation_count
    /// SECURITY: Capped at MAX_LOCKOUT_HISTORY to prevent overflow
    pub fn lockout(&self) -> u64 {
        // Cap confirmation_count to prevent overflow (2^63 would overflow)
        let capped_count = self.confirmation_count.min(MAX_LOCKOUT_HISTORY as u32);
        2u64.saturating_pow(capped_count)
    }

    /// Calculate when this lockout expires
    /// SECURITY: Uses saturating_add to prevent overflow
    pub fn expiration_slot(&self) -> Slot {
        self.slot.saturating_add(self.lockout())
    }

    /// Check if this vote is still locked out at the given slot
    pub fn is_locked_out(&self, current_slot: Slot) -> bool {
        current_slot < self.expiration_slot()
    }
}

/// Threshold for supermajority (2/3)
pub const SUPERMAJORITY_THRESHOLD: f64 = 2.0 / 3.0;

/// Maximum lockout (32 confirmations = 2^32 slots)
pub const MAX_LOCKOUT_HISTORY: usize = 32;

impl TowerBFT {
    /// Create a new Tower BFT state
    pub fn new(validator: Pubkey, total_stake: u64) -> Self {
        TowerBFT {
            validator,
            votes: Vec::new(),
            root: None,
            last_voted_slot: None,
            total_stake,
        }
    }

    /// Check if we can vote for a slot
    pub fn can_vote(&self, slot: Slot) -> bool {
        // Can't vote for slots we've already voted for or before
        if let Some(last) = self.last_voted_slot {
            if slot <= last {
                return false;
            }
        }

        // Check lockout - we can only vote if all locked out votes have expired
        // or the new vote is a descendant
        for lockout in &self.votes {
            if lockout.is_locked_out(slot) && slot < lockout.slot {
                return false;
            }
        }

        true
    }

    /// Record a vote
    pub fn vote(&mut self, slot: Slot) -> Result<(), TowerError> {
        if !self.can_vote(slot) {
            return Err(TowerError::LockedOut);
        }

        // Remove expired lockouts
        self.votes.retain(|l| l.is_locked_out(slot));

        // Increment confirmation count for votes that this vote confirms
        for lockout in &mut self.votes {
            if lockout.slot < slot {
                lockout.confirmation_count += 1;
            }
        }

        // Add new vote
        self.votes.push(Lockout::new(slot));

        // Keep only the most recent MAX_LOCKOUT_HISTORY votes
        while self.votes.len() > MAX_LOCKOUT_HISTORY {
            // Pop the oldest vote and potentially set it as root
            let oldest = self.votes.remove(0);
            if oldest.confirmation_count >= MAX_LOCKOUT_HISTORY as u32 {
                self.root = Some(oldest.slot);
            }
        }

        self.last_voted_slot = Some(slot);
        Ok(())
    }

    /// Get the current lockout
    pub fn lockout(&self) -> Option<u64> {
        self.votes.last().map(|l| l.lockout())
    }

    /// Check if a slot is finalized (rooted)
    pub fn is_finalized(&self, slot: Slot) -> bool {
        if let Some(root) = self.root {
            slot <= root
        } else {
            false
        }
    }

    /// Get the root slot
    pub fn root_slot(&self) -> Option<Slot> {
        self.root
    }

    /// Calculate the stake needed for supermajority
    pub fn supermajority_stake(&self) -> u64 {
        (self.total_stake as f64 * SUPERMAJORITY_THRESHOLD) as u64
    }
}

/// Tower BFT errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum TowerError {
    #[error("Validator is locked out and cannot vote")]
    LockedOut,

    #[error("Invalid vote: slot {0} is before last voted slot")]
    InvalidSlot(Slot),

    #[error("Insufficient stake for consensus")]
    InsufficientStake,

    #[error("Invalid vote signature")]
    InvalidVoteSignature,

    #[error("Unknown validator - not in stake map")]
    UnknownValidator,

    #[error("Equivocation detected - validator voted for multiple blocks in same slot")]
    Equivocation,
}

/// Vote aggregator for consensus
#[derive(Debug)]
pub struct VoteAggregator {
    /// Votes by slot: maps slot -> (block_hash -> (voter -> stake))
    /// SECURITY: Track which block each validator voted for to detect equivocation
    votes_by_slot: HashMap<Slot, HashMap<Pubkey, (Hash, u64)>>,

    /// Stakes by validator
    stakes: HashMap<Pubkey, u64>,

    /// Total stake
    total_stake: u64,

    /// Detected equivocators (validators who voted for multiple blocks in same slot)
    equivocators: HashSet<Pubkey>,
}

impl VoteAggregator {
    /// Create a new vote aggregator
    pub fn new(stakes: HashMap<Pubkey, u64>) -> Self {
        let total_stake = stakes.values().sum();

        VoteAggregator {
            votes_by_slot: HashMap::new(),
            stakes,
            total_stake,
            equivocators: HashSet::new(),
        }
    }

    /// Add a vote with signature verification
    /// SECURITY: Requires the actual Vote struct with signature for verification
    pub fn add_vote(&mut self, vote: &crate::core::Vote) -> Result<(), TowerError> {
        // SECURITY FIX #1: Verify vote signature before accepting
        if !vote.verify() {
            return Err(TowerError::InvalidVoteSignature);
        }

        let voter = vote.voter;
        let slot = vote.slot;
        let block_hash = vote.block_hash;

        // Check if voter is a known validator with stake
        let stake = match self.stakes.get(&voter) {
            Some(&s) => s,
            None => return Err(TowerError::UnknownValidator),
        };

        // Check for equivocation (voting for different blocks in same slot)
        let slot_votes = self.votes_by_slot.entry(slot).or_insert_with(HashMap::new);

        if let Some((existing_hash, _)) = slot_votes.get(&voter) {
            if *existing_hash != block_hash {
                // SECURITY: Detected double voting - mark as equivocator
                self.equivocators.insert(voter);
                return Err(TowerError::Equivocation);
            }
            // Already voted for this block, ignore duplicate
            return Ok(());
        }

        // Record the vote
        slot_votes.insert(voter, (block_hash, stake));
        Ok(())
    }

    /// Legacy add_vote for backwards compatibility (DEPRECATED - use add_vote with Vote struct)
    #[deprecated(note = "Use add_vote with Vote struct for signature verification")]
    pub fn add_vote_unchecked(&mut self, voter: Pubkey, slot: Slot, block_hash: Hash) {
        if let Some(&stake) = self.stakes.get(&voter) {
            self.votes_by_slot
                .entry(slot)
                .or_insert_with(HashMap::new)
                .insert(voter, (block_hash, stake));
        }
    }

    /// Check if a validator is an equivocator
    pub fn is_equivocator(&self, validator: &Pubkey) -> bool {
        self.equivocators.contains(validator)
    }

    /// Get all equivocators
    pub fn get_equivocators(&self) -> &HashSet<Pubkey> {
        &self.equivocators
    }

    /// Get the stake that voted for a slot
    pub fn stake_for_slot(&self, slot: Slot) -> u64 {
        self.votes_by_slot
            .get(&slot)
            .map(|votes| votes.values().map(|(_, stake)| stake).sum())
            .unwrap_or(0)
    }

    /// Get the stake that voted for a specific block in a slot
    pub fn stake_for_block(&self, slot: Slot, block_hash: &Hash) -> u64 {
        self.votes_by_slot
            .get(&slot)
            .map(|votes| {
                votes.values()
                    .filter(|(hash, _)| hash == block_hash)
                    .map(|(_, stake)| stake)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Check if a slot has supermajority
    pub fn has_supermajority(&self, slot: Slot) -> bool {
        let stake = self.stake_for_slot(slot);
        let threshold = (self.total_stake as f64 * SUPERMAJORITY_THRESHOLD) as u64;
        stake >= threshold
    }

    /// Get the latest slot with supermajority
    pub fn latest_supermajority_slot(&self) -> Option<Slot> {
        self.votes_by_slot
            .keys()
            .filter(|&&slot| self.has_supermajority(slot))
            .max()
            .copied()
    }

    /// Prune old slots
    pub fn prune(&mut self, before_slot: Slot) {
        self.votes_by_slot.retain(|&slot, _| slot >= before_slot);
    }
}

/// Fork choice rule
#[derive(Debug)]
pub struct ForkChoice {
    /// Block hashes by slot
    blocks: HashMap<Slot, Hash>,

    /// Parent relationships
    parents: HashMap<Slot, Slot>,

    /// Children relationships
    children: HashMap<Slot, HashSet<Slot>>,

    /// Stakes voting for each fork
    fork_stakes: HashMap<Hash, u64>,
}

impl ForkChoice {
    /// Create a new fork choice tracker
    pub fn new() -> Self {
        ForkChoice {
            blocks: HashMap::new(),
            parents: HashMap::new(),
            children: HashMap::new(),
            fork_stakes: HashMap::new(),
        }
    }

    /// Add a block
    pub fn add_block(&mut self, slot: Slot, hash: Hash, parent_slot: Slot) {
        self.blocks.insert(slot, hash);
        self.parents.insert(slot, parent_slot);
        self.children
            .entry(parent_slot)
            .or_insert_with(HashSet::new)
            .insert(slot);
    }

    /// Update stake for a fork
    /// SECURITY: Uses saturating_add to prevent overflow
    pub fn update_stake(&mut self, hash: Hash, stake: u64) {
        let entry = self.fork_stakes.entry(hash).or_insert(0);
        *entry = entry.saturating_add(stake);
    }

    /// Get the best fork (heaviest subtree)
    pub fn best_slot(&self, from_slot: Slot) -> Slot {
        let mut current = from_slot;

        loop {
            if let Some(children) = self.children.get(&current) {
                if children.is_empty() {
                    break;
                }

                // Find child with most stake
                let best_child = children
                    .iter()
                    .max_by_key(|&&child| {
                        self.blocks
                            .get(&child)
                            .and_then(|h| self.fork_stakes.get(h))
                            .unwrap_or(&0)
                    });

                if let Some(&child) = best_child {
                    current = child;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        current
    }

    /// Check if slot is ancestor of another
    pub fn is_ancestor(&self, ancestor: Slot, descendant: Slot) -> bool {
        let mut current = descendant;

        while let Some(&parent) = self.parents.get(&current) {
            if parent == ancestor {
                return true;
            }
            if parent >= current {
                break; // Prevent infinite loop
            }
            current = parent;
        }

        false
    }
}

impl Default for ForkChoice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn test_lockout() {
        let lockout = Lockout::new(100);
        assert_eq!(lockout.lockout(), 2); // 2^1
        assert!(lockout.is_locked_out(100));
        assert!(lockout.is_locked_out(101));
        assert!(!lockout.is_locked_out(102));
    }

    #[test]
    fn test_tower_vote() {
        let validator = Keypair::generate();
        let mut tower = TowerBFT::new(validator.pubkey(), 1000);

        assert!(tower.can_vote(1));
        tower.vote(1).unwrap();

        assert!(!tower.can_vote(1)); // Can't vote again
        assert!(tower.can_vote(2)); // Can vote for next slot
    }

    #[test]
    fn test_tower_lockout_progression() {
        let validator = Keypair::generate();
        let mut tower = TowerBFT::new(validator.pubkey(), 1000);

        // Vote for consecutive slots
        for slot in 1..=10 {
            tower.vote(slot).unwrap();
        }

        // Lockouts should have increased
        assert!(tower.votes.len() > 1);
        assert!(tower.votes.last().unwrap().confirmation_count == 1);
        assert!(tower.votes.first().unwrap().confirmation_count > 1);
    }

    #[test]
    fn test_vote_aggregator() {
        use crate::core::Vote;

        let v1 = Keypair::generate();
        let v2 = Keypair::generate();
        let v3 = Keypair::generate();

        let mut stakes = HashMap::new();
        stakes.insert(v1.pubkey(), 100);
        stakes.insert(v2.pubkey(), 100);
        stakes.insert(v3.pubkey(), 100);

        let mut aggregator = VoteAggregator::new(stakes);
        let block_hash = Hash::hash(b"test_block");

        // Create proper Vote structs with signatures
        let vote1 = Vote::new(v1.pubkey(), 1, block_hash, 100, &v1);
        let vote2 = Vote::new(v2.pubkey(), 1, block_hash, 100, &v2);

        aggregator.add_vote(&vote1).unwrap();
        assert!(!aggregator.has_supermajority(1));

        aggregator.add_vote(&vote2).unwrap();
        assert!(aggregator.has_supermajority(1)); // 200/300 > 2/3
    }

    #[test]
    fn test_vote_aggregator_rejects_invalid_signature() {
        use crate::core::Vote;
        use crate::crypto::Signature;

        let v1 = Keypair::generate();
        let v2 = Keypair::generate();

        let mut stakes = HashMap::new();
        stakes.insert(v1.pubkey(), 100);

        let mut aggregator = VoteAggregator::new(stakes);
        let block_hash = Hash::hash(b"test_block");

        // Create a vote with wrong signer (v2 signs for v1's pubkey)
        let mut fake_vote = Vote::new(v1.pubkey(), 1, block_hash, 100, &v2);
        // The signature is from v2 but voter is v1 - should fail verification

        let result = aggregator.add_vote(&fake_vote);
        assert!(result.is_err());
    }

    #[test]
    fn test_vote_aggregator_detects_equivocation() {
        use crate::core::Vote;

        let v1 = Keypair::generate();

        let mut stakes = HashMap::new();
        stakes.insert(v1.pubkey(), 100);

        let mut aggregator = VoteAggregator::new(stakes);

        // Vote for block A
        let block_a = Hash::hash(b"block_a");
        let vote_a = Vote::new(v1.pubkey(), 1, block_a, 100, &v1);
        aggregator.add_vote(&vote_a).unwrap();

        // Try to vote for different block B in same slot - should fail
        let block_b = Hash::hash(b"block_b");
        let vote_b = Vote::new(v1.pubkey(), 1, block_b, 100, &v1);
        let result = aggregator.add_vote(&vote_b);

        assert!(matches!(result, Err(TowerError::Equivocation)));
        assert!(aggregator.is_equivocator(&v1.pubkey()));
    }

    #[test]
    fn test_fork_choice() {
        let mut fork_choice = ForkChoice::new();

        // Create a chain: 0 -> 1 -> 2
        fork_choice.add_block(1, Hash::hash(b"block1"), 0);
        fork_choice.add_block(2, Hash::hash(b"block2"), 1);

        assert!(fork_choice.is_ancestor(1, 2));
        assert!(!fork_choice.is_ancestor(2, 1));
    }
}
