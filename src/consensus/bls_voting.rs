//! BLS-based Vote Aggregation for Consensus
//!
//! This module provides efficient vote aggregation using BLS signatures.
//! Instead of storing N individual Ed25519 signatures (N * 64 bytes),
//! we can aggregate all votes into a single BLS signature (96 bytes).
//!
//! # Benefits
//! - O(1) signature size regardless of validator count
//! - Reduced bandwidth for vote propagation
//! - Faster verification (aggregate verify instead of N individual verifies)
//!
//! # Security
//! - All validators must have registered Proof of Possession (PoP)
//! - Equivocation detection is maintained
//! - Domain separation prevents cross-protocol attacks

use crate::core::Slot;
use crate::crypto::{
    Hash,
    bls::{
        BlsKeypair, BlsPublicKey, BlsSignature, AggregatedBlsSignature,
        ProofOfPossession, BlsError,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A BLS-signed vote for a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsVote {
    /// Voter's BLS public key
    pub voter: BlsPublicKey,
    /// Slot being voted on
    pub slot: Slot,
    /// Hash of the block being voted on
    pub block_hash: Hash,
    /// BLS signature over the vote data
    pub signature: BlsSignature,
    /// Voter's stake
    pub stake: u64,
}

impl BlsVote {
    /// Create a new BLS vote
    pub fn new(
        slot: Slot,
        block_hash: Hash,
        stake: u64,
        keypair: &BlsKeypair,
    ) -> Self {
        let message = Self::vote_message(slot, &block_hash);
        let signature = keypair.sign_vote(&message);

        BlsVote {
            voter: keypair.public_key().clone(),
            slot,
            block_hash,
            signature,
            stake,
        }
    }

    /// Create the message to sign for a vote
    pub fn vote_message(slot: Slot, block_hash: &Hash) -> Vec<u8> {
        let mut message = Vec::with_capacity(40);
        message.extend_from_slice(&slot.to_le_bytes());
        message.extend_from_slice(block_hash.as_bytes());
        message
    }

    /// Verify the vote signature
    pub fn verify(&self) -> bool {
        let message = Self::vote_message(self.slot, &self.block_hash);
        self.voter.verify_vote(&message, &self.signature)
    }
}

/// Aggregated BLS votes for a slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedVotes {
    /// Slot being voted on
    pub slot: Slot,
    /// Block hash being voted on
    pub block_hash: Hash,
    /// Aggregated signature from all voters
    #[serde(with = "aggregated_sig_serde")]
    pub aggregated_signature: AggregatedBlsSignature,
    /// Public keys of all voters (needed for verification)
    pub voters: Vec<BlsPublicKey>,
    /// Total stake of all voters
    pub total_stake: u64,
}

mod aggregated_sig_serde {
    use super::*;
    use serde::{Deserializer, Serializer, de::SeqAccess, de::Visitor, ser::SerializeStruct};

    pub fn serialize<S>(sig: &AggregatedBlsSignature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AggSigData", 2)?;
        state.serialize_field("signature", &sig.to_bytes().to_vec())?;
        state.serialize_field("signer_count", &sig.signer_count)?;
        state.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<AggregatedBlsSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AggSigVisitor;

        impl<'de> Visitor<'de> for AggSigVisitor {
            type Value = AggregatedBlsSignature;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an aggregated BLS signature")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let sig_vec: Vec<u8> = seq.next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let signer_count: usize = seq.next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                AggregatedBlsSignature::from_bytes(&sig_vec, signer_count)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_struct("AggSigData", &["signature", "signer_count"], AggSigVisitor)
    }
}

impl AggregatedVotes {
    /// Create from a list of individual votes
    ///
    /// # Security
    /// All votes must be for the same slot and block hash.
    pub fn aggregate(votes: &[BlsVote]) -> Result<Self, BlsVoteError> {
        if votes.is_empty() {
            return Err(BlsVoteError::EmptyVoteSet);
        }

        // Verify all votes are for the same slot and block
        let slot = votes[0].slot;
        let block_hash = votes[0].block_hash;

        for vote in votes.iter().skip(1) {
            if vote.slot != slot || vote.block_hash != block_hash {
                return Err(BlsVoteError::MismatchedVotes);
            }
        }

        // Verify all individual signatures
        for vote in votes {
            if !vote.verify() {
                return Err(BlsVoteError::InvalidSignature);
            }
        }

        // Collect signatures for aggregation
        let sig_pairs: Vec<(&BlsPublicKey, &BlsSignature)> = votes
            .iter()
            .map(|v| (&v.voter, &v.signature))
            .collect();

        let aggregated_signature = AggregatedBlsSignature::aggregate(&sig_pairs)
            .map_err(|e| BlsVoteError::AggregationFailed(e))?;

        let voters: Vec<BlsPublicKey> = votes.iter().map(|v| v.voter.clone()).collect();
        let total_stake: u64 = votes.iter().map(|v| v.stake).sum();

        Ok(AggregatedVotes {
            slot,
            block_hash,
            aggregated_signature,
            voters,
            total_stake,
        })
    }

    /// Verify the aggregated signature
    pub fn verify(&self) -> bool {
        if self.voters.is_empty() {
            return false;
        }

        let message = BlsVote::vote_message(self.slot, &self.block_hash);
        let voter_refs: Vec<&BlsPublicKey> = self.voters.iter().collect();

        self.aggregated_signature.verify_votes(&voter_refs, &message)
    }

    /// Get the number of voters
    pub fn voter_count(&self) -> usize {
        self.voters.len()
    }

    /// Calculate signature size savings
    ///
    /// Returns (original_size, aggregated_size, savings_percentage)
    pub fn size_savings(&self) -> (usize, usize, f64) {
        // Ed25519: 64 bytes per signature + 32 bytes per pubkey
        let original_size = self.voters.len() * (64 + 32);

        // BLS: 96 bytes aggregated + 48 bytes per pubkey
        let aggregated_size = 96 + self.voters.len() * 48;

        let savings = if original_size > 0 {
            ((original_size - aggregated_size) as f64 / original_size as f64) * 100.0
        } else {
            0.0
        };

        (original_size, aggregated_size, savings)
    }
}

/// BLS Vote Aggregator
///
/// Collects votes and produces aggregated signatures.
/// Maintains security by tracking equivocation and verifying PoPs.
#[derive(Debug)]
pub struct BlsVoteAggregator {
    /// Registered validators with verified PoPs
    /// Maps BLS pubkey (96 bytes) -> (PoP, stake)
    registered_validators: HashMap<[u8; 96], (ProofOfPossession, u64)>,

    /// Votes by slot: maps slot -> (block_hash -> Vec<BlsVote>)
    votes_by_slot: HashMap<Slot, HashMap<Hash, Vec<BlsVote>>>,

    /// Track which validators voted for which block in each slot
    /// Used for equivocation detection
    validator_votes: HashMap<Slot, HashMap<[u8; 96], Hash>>,

    /// Detected equivocators
    equivocators: HashSet<[u8; 96]>,

    /// Total registered stake
    total_stake: u64,
}

impl BlsVoteAggregator {
    /// Create a new vote aggregator
    pub fn new() -> Self {
        BlsVoteAggregator {
            registered_validators: HashMap::new(),
            votes_by_slot: HashMap::new(),
            validator_votes: HashMap::new(),
            equivocators: HashSet::new(),
            total_stake: 0,
        }
    }

    /// Register a validator with their Proof of Possession
    ///
    /// # Security
    /// The PoP must be verified before the validator can participate in voting.
    pub fn register_validator(
        &mut self,
        pubkey: &BlsPublicKey,
        pop: ProofOfPossession,
        stake: u64,
    ) -> Result<(), BlsVoteError> {
        // Verify PoP
        if !pubkey.verify_proof_of_possession(&pop) {
            return Err(BlsVoteError::InvalidProofOfPossession);
        }

        let pk_bytes = pubkey.to_bytes();

        // Check if already registered
        if self.registered_validators.contains_key(&pk_bytes) {
            return Err(BlsVoteError::AlreadyRegistered);
        }

        self.registered_validators.insert(pk_bytes, (pop, stake));
        self.total_stake += stake;

        Ok(())
    }

    /// Unregister a validator
    pub fn unregister_validator(&mut self, pubkey: &BlsPublicKey) {
        let pk_bytes = pubkey.to_bytes();
        if let Some((_, stake)) = self.registered_validators.remove(&pk_bytes) {
            self.total_stake = self.total_stake.saturating_sub(stake);
        }
    }

    /// Update a validator's stake
    pub fn update_stake(&mut self, pubkey: &BlsPublicKey, new_stake: u64) -> Result<(), BlsVoteError> {
        let pk_bytes = pubkey.to_bytes();
        if let Some((_, stake)) = self.registered_validators.get_mut(&pk_bytes) {
            self.total_stake = self.total_stake.saturating_sub(*stake);
            *stake = new_stake;
            self.total_stake += new_stake;
            Ok(())
        } else {
            Err(BlsVoteError::UnknownValidator)
        }
    }

    /// Add a vote
    pub fn add_vote(&mut self, vote: BlsVote) -> Result<(), BlsVoteError> {
        let pk_bytes = vote.voter.to_bytes();

        // Check if validator is registered
        let stake = match self.registered_validators.get(&pk_bytes) {
            Some((_, s)) => *s,
            None => return Err(BlsVoteError::UnknownValidator),
        };

        // Check if this validator is an equivocator
        if self.equivocators.contains(&pk_bytes) {
            return Err(BlsVoteError::Equivocator);
        }

        // Verify the vote signature
        if !vote.verify() {
            return Err(BlsVoteError::InvalidSignature);
        }

        // Check for equivocation
        let slot_votes = self.validator_votes.entry(vote.slot).or_default();
        if let Some(existing_hash) = slot_votes.get(&pk_bytes) {
            if *existing_hash != vote.block_hash {
                // Equivocation detected!
                self.equivocators.insert(pk_bytes);
                return Err(BlsVoteError::EquivocationDetected);
            }
            // Already voted for this block, ignore duplicate
            return Ok(());
        }

        // Record the vote
        slot_votes.insert(pk_bytes, vote.block_hash);

        // Store vote with correct stake
        let vote_with_stake = BlsVote {
            stake,
            ..vote
        };

        self.votes_by_slot
            .entry(vote_with_stake.slot)
            .or_default()
            .entry(vote_with_stake.block_hash)
            .or_default()
            .push(vote_with_stake);

        Ok(())
    }

    /// Get aggregated votes for a slot and block
    pub fn get_aggregated_votes(&self, slot: Slot, block_hash: &Hash) -> Option<AggregatedVotes> {
        let slot_votes = self.votes_by_slot.get(&slot)?;
        let votes = slot_votes.get(block_hash)?;

        if votes.is_empty() {
            return None;
        }

        AggregatedVotes::aggregate(votes).ok()
    }

    /// Get all aggregated votes for a slot
    pub fn get_all_aggregated_votes(&self, slot: Slot) -> Vec<AggregatedVotes> {
        let Some(slot_votes) = self.votes_by_slot.get(&slot) else {
            return Vec::new();
        };

        slot_votes
            .values()
            .filter_map(|votes| AggregatedVotes::aggregate(votes).ok())
            .collect()
    }

    /// Get stake that voted for a slot
    pub fn stake_for_slot(&self, slot: Slot) -> u64 {
        self.votes_by_slot
            .get(&slot)
            .map(|slot_votes| {
                slot_votes.values()
                    .flat_map(|votes| votes.iter())
                    .map(|v| v.stake)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Get stake that voted for a specific block
    pub fn stake_for_block(&self, slot: Slot, block_hash: &Hash) -> u64 {
        self.votes_by_slot
            .get(&slot)
            .and_then(|slot_votes| slot_votes.get(block_hash))
            .map(|votes| votes.iter().map(|v| v.stake).sum())
            .unwrap_or(0)
    }

    /// Check if a slot has supermajority (2/3 of stake)
    pub fn has_supermajority(&self, slot: Slot) -> bool {
        let stake = self.stake_for_slot(slot);
        let threshold = (self.total_stake as f64 * (2.0 / 3.0)) as u64;
        stake >= threshold
    }

    /// Check if a specific block has supermajority
    pub fn block_has_supermajority(&self, slot: Slot, block_hash: &Hash) -> bool {
        let stake = self.stake_for_block(slot, block_hash);
        let threshold = (self.total_stake as f64 * (2.0 / 3.0)) as u64;
        stake >= threshold
    }

    /// Get total registered stake
    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// Get number of registered validators
    pub fn validator_count(&self) -> usize {
        self.registered_validators.len()
    }

    /// Check if a validator is an equivocator
    pub fn is_equivocator(&self, pubkey: &BlsPublicKey) -> bool {
        self.equivocators.contains(&pubkey.to_bytes())
    }

    /// Get all equivocators
    pub fn get_equivocators(&self) -> Vec<BlsPublicKey> {
        self.equivocators
            .iter()
            .filter_map(|bytes| BlsPublicKey::from_bytes(bytes).ok())
            .collect()
    }

    /// Prune old votes
    pub fn prune(&mut self, before_slot: Slot) {
        self.votes_by_slot.retain(|&slot, _| slot >= before_slot);
        self.validator_votes.retain(|&slot, _| slot >= before_slot);
    }

    /// Get supermajority threshold
    pub fn supermajority_threshold(&self) -> u64 {
        (self.total_stake as f64 * (2.0 / 3.0)) as u64
    }
}

impl Default for BlsVoteAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// BLS Vote errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum BlsVoteError {
    #[error("Empty vote set")]
    EmptyVoteSet,

    #[error("Votes are for different slots or blocks")]
    MismatchedVotes,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature aggregation failed: {0}")]
    AggregationFailed(BlsError),

    #[error("Invalid Proof of Possession")]
    InvalidProofOfPossession,

    #[error("Validator already registered")]
    AlreadyRegistered,

    #[error("Unknown validator - not registered")]
    UnknownValidator,

    #[error("Validator is a known equivocator")]
    Equivocator,

    #[error("Equivocation detected - validator voted for multiple blocks")]
    EquivocationDetected,
}

/// BLS Validator Registration
///
/// Holds registration data for a validator using BLS signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsValidatorRegistration {
    /// BLS public key
    pub pubkey: BlsPublicKey,
    /// Proof of Possession
    pub proof_of_possession: ProofOfPossession,
    /// Initial stake
    pub stake: u64,
    /// Ed25519 identity pubkey (for compatibility with existing system)
    pub identity: Option<crate::crypto::Pubkey>,
}

impl BlsValidatorRegistration {
    /// Create a new registration from a keypair
    pub fn from_keypair(
        keypair: &BlsKeypair,
        stake: u64,
        identity: Option<crate::crypto::Pubkey>,
    ) -> Self {
        BlsValidatorRegistration {
            pubkey: keypair.public_key().clone(),
            proof_of_possession: keypair.proof_of_possession().clone(),
            stake,
            identity,
        }
    }

    /// Verify the registration
    pub fn verify(&self) -> bool {
        self.pubkey.verify_proof_of_possession(&self.proof_of_possession)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_vote_create_and_verify() {
        let keypair = BlsKeypair::generate().unwrap();
        let block_hash = Hash::hash(b"test_block");

        let vote = BlsVote::new(1, block_hash, 100, &keypair);

        assert!(vote.verify());
        assert_eq!(vote.slot, 1);
        assert_eq!(vote.block_hash, block_hash);
    }

    #[test]
    fn test_bls_vote_aggregation() {
        let kp1 = BlsKeypair::generate().unwrap();
        let kp2 = BlsKeypair::generate().unwrap();
        let kp3 = BlsKeypair::generate().unwrap();

        let block_hash = Hash::hash(b"test_block");

        let vote1 = BlsVote::new(1, block_hash, 100, &kp1);
        let vote2 = BlsVote::new(1, block_hash, 200, &kp2);
        let vote3 = BlsVote::new(1, block_hash, 300, &kp3);

        let aggregated = AggregatedVotes::aggregate(&[vote1, vote2, vote3]).unwrap();

        assert!(aggregated.verify());
        assert_eq!(aggregated.voter_count(), 3);
        assert_eq!(aggregated.total_stake, 600);
    }

    #[test]
    fn test_aggregated_votes_size_savings() {
        let kps: Vec<_> = (0..100).map(|_| BlsKeypair::generate().unwrap()).collect();
        let block_hash = Hash::hash(b"test_block");

        let votes: Vec<_> = kps.iter().map(|kp| BlsVote::new(1, block_hash, 100, kp)).collect();
        let aggregated = AggregatedVotes::aggregate(&votes).unwrap();

        let (original, aggregated_size, savings) = aggregated.size_savings();
        println!("Original: {} bytes, Aggregated: {} bytes, Savings: {:.1}%",
                 original, aggregated_size, savings);

        // With 100 validators: original ~9600 bytes, aggregated ~4896 bytes
        assert!(savings > 40.0);
    }

    #[test]
    fn test_bls_vote_aggregator_basic() {
        let mut aggregator = BlsVoteAggregator::new();

        let kp1 = BlsKeypair::generate().unwrap();
        let kp2 = BlsKeypair::generate().unwrap();

        // Register validators
        aggregator.register_validator(
            kp1.public_key(),
            kp1.proof_of_possession().clone(),
            100,
        ).unwrap();
        aggregator.register_validator(
            kp2.public_key(),
            kp2.proof_of_possession().clone(),
            100,
        ).unwrap();

        assert_eq!(aggregator.total_stake(), 200);
        assert_eq!(aggregator.validator_count(), 2);

        // Add votes
        let block_hash = Hash::hash(b"test_block");
        let vote1 = BlsVote::new(1, block_hash, 0, &kp1); // stake will be corrected
        let vote2 = BlsVote::new(1, block_hash, 0, &kp2);

        aggregator.add_vote(vote1).unwrap();
        assert!(!aggregator.has_supermajority(1)); // 100/200 < 2/3

        aggregator.add_vote(vote2).unwrap();
        assert!(aggregator.has_supermajority(1)); // 200/200 > 2/3
    }

    #[test]
    fn test_bls_vote_aggregator_equivocation() {
        let mut aggregator = BlsVoteAggregator::new();

        let kp1 = BlsKeypair::generate().unwrap();

        aggregator.register_validator(
            kp1.public_key(),
            kp1.proof_of_possession().clone(),
            100,
        ).unwrap();

        let block_a = Hash::hash(b"block_a");
        let block_b = Hash::hash(b"block_b");

        // Vote for block A
        let vote_a = BlsVote::new(1, block_a, 100, &kp1);
        aggregator.add_vote(vote_a).unwrap();

        // Try to vote for block B in same slot - should fail
        let vote_b = BlsVote::new(1, block_b, 100, &kp1);
        let result = aggregator.add_vote(vote_b);

        assert!(matches!(result, Err(BlsVoteError::EquivocationDetected)));
        assert!(aggregator.is_equivocator(kp1.public_key()));
    }

    #[test]
    fn test_bls_vote_aggregator_rejects_unregistered() {
        let mut aggregator = BlsVoteAggregator::new();

        let kp = BlsKeypair::generate().unwrap();
        let block_hash = Hash::hash(b"test_block");

        let vote = BlsVote::new(1, block_hash, 100, &kp);
        let result = aggregator.add_vote(vote);

        assert!(matches!(result, Err(BlsVoteError::UnknownValidator)));
    }

    #[test]
    fn test_bls_vote_aggregator_rejects_invalid_pop() {
        let mut aggregator = BlsVoteAggregator::new();

        let kp1 = BlsKeypair::generate().unwrap();
        let kp2 = BlsKeypair::generate().unwrap();

        // Try to register with wrong PoP
        let result = aggregator.register_validator(
            kp1.public_key(),
            kp2.proof_of_possession().clone(), // Wrong PoP!
            100,
        );

        assert!(matches!(result, Err(BlsVoteError::InvalidProofOfPossession)));
    }

    #[test]
    fn test_validator_registration() {
        let kp = BlsKeypair::generate().unwrap();
        let identity = crate::crypto::Keypair::generate().pubkey();

        let registration = BlsValidatorRegistration::from_keypair(&kp, 1000, Some(identity));

        assert!(registration.verify());
        assert_eq!(registration.stake, 1000);
    }
}
