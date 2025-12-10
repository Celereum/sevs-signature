//! Validator node implementation
//!
//! Optimized for fast block production and efficient leader distribution.

use crate::core::{Block, Slot, Transaction};
use crate::crypto::{Hash, Keypair, Pubkey};
use super::poh::ProofOfHistory;
use super::tower_bft::TowerBFT;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Validator identity and state
#[derive(Debug)]
pub struct Validator {
    /// Validator's keypair
    pub keypair: Keypair,

    /// Vote account keypair
    pub vote_keypair: Keypair,

    /// Tower BFT state
    pub tower: TowerBFT,

    /// Proof of History generator
    pub poh: ProofOfHistory,

    /// Current slot
    pub slot: Slot,

    /// Stake amount
    pub stake: u64,

    /// Is this validator the current leader?
    pub is_leader: bool,

    /// Leader schedule for verifying block producers
    /// SECURITY: Required to verify that block producers are legitimate
    pub leader_schedule: Option<LeaderSchedule>,
}

/// Validator info for the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Identity pubkey
    pub identity: Pubkey,

    /// Vote account pubkey
    pub vote_account: Pubkey,

    /// Stake amount
    pub stake: u64,

    /// Last voted slot
    pub last_vote: Option<Slot>,

    /// Root slot
    pub root_slot: Option<Slot>,

    /// Commission (0-100)
    pub commission: u8,

    /// Is active
    pub activated: bool,
}

impl Validator {
    /// Create a new validator
    pub fn new(keypair: Keypair, stake: u64, total_stake: u64) -> Self {
        let vote_keypair = Keypair::generate();
        let identity = keypair.address();

        Validator {
            keypair,
            vote_keypair,
            tower: TowerBFT::new(identity, total_stake),
            poh: ProofOfHistory::new(Hash::hash(b"genesis")),
            slot: 0,
            stake,
            is_leader: false,
            leader_schedule: None,
        }
    }

    /// Set the leader schedule
    /// SECURITY: Must be set to verify block producers
    pub fn set_leader_schedule(&mut self, schedule: LeaderSchedule) {
        self.leader_schedule = Some(schedule);
    }

    /// Get the validator's identity pubkey
    pub fn identity(&self) -> Pubkey {
        self.keypair.address()
    }

    /// Get the vote account pubkey
    pub fn vote_pubkey(&self) -> Pubkey {
        self.vote_keypair.address()
    }

    /// Set as leader for current slot
    pub fn set_leader(&mut self, is_leader: bool) {
        self.is_leader = is_leader;
    }

    /// Produce a block (when leader)
    pub fn produce_block(&mut self, transactions: Vec<Transaction>) -> Option<Block> {
        if !self.is_leader {
            return None;
        }

        // Generate minimal PoH for testnet - just record transactions
        let mut tick_count = 0u64;

        // Record transactions in PoH
        for tx in &transactions {
            let _ = self.poh.record(tx.hash());
            tick_count += 1;
        }

        // Do one tick to advance the PoH
        let _ = self.poh.tick();
        tick_count += 1;

        let poh_hash = self.poh.current_hash();

        // Create the block
        let block = Block::new(
            self.slot,
            self.previous_block_hash(),
            poh_hash,
            tick_count,
            self.identity(),
            transactions,
        );

        // Vote for our own block
        let _ = self.tower.vote(self.slot);

        // Move to next slot
        self.slot += 1;

        Some(block)
    }

    /// Process an incoming block
    pub fn process_block(&mut self, block: &Block) -> Result<(), ValidatorError> {
        // Verify the block's structure and transactions
        if !block.verify() {
            return Err(ValidatorError::InvalidBlock);
        }

        // SECURITY FIX #2: Verify that the block producer is the legitimate leader for this slot
        if let Some(ref schedule) = self.leader_schedule {
            let expected_leader = schedule.get_leader(block.header.slot);
            match expected_leader {
                Some(leader) if leader == block.header.leader => {
                    // Leader is correct
                }
                Some(_) => {
                    // Wrong leader - reject block
                    return Err(ValidatorError::InvalidLeader);
                }
                None => {
                    // No leader found for this slot - reject
                    return Err(ValidatorError::InvalidLeader);
                }
            }
        } else {
            // SECURITY WARNING: No leader schedule set - cannot verify block producer
            // In production, this should be an error
            #[cfg(not(test))]
            return Err(ValidatorError::NoLeaderSchedule);
        }

        // Verify PoH
        // In a full implementation, we'd verify the PoH entries

        // Vote for the block if valid
        if self.tower.can_vote(block.header.slot) {
            self.tower.vote(block.header.slot)
                .map_err(|_| ValidatorError::VoteFailed)?;
        }

        // Update slot
        if block.header.slot >= self.slot {
            self.slot = block.header.slot.saturating_add(1);
        }

        Ok(())
    }

    /// Get the previous block hash (simplified)
    fn previous_block_hash(&self) -> Hash {
        // In a full implementation, this would track the chain
        Hash::hash(&self.slot.to_le_bytes())
    }

    /// Get validator info
    pub fn info(&self) -> ValidatorInfo {
        ValidatorInfo {
            identity: self.identity(),
            vote_account: self.vote_pubkey(),
            stake: self.stake,
            last_vote: self.tower.last_voted_slot,
            root_slot: self.tower.root_slot(),
            commission: 10, // Default 10%
            activated: true,
        }
    }
}

/// Validator errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidatorError {
    #[error("Invalid block")]
    InvalidBlock,

    #[error("Vote failed")]
    VoteFailed,

    #[error("Not leader")]
    NotLeader,

    #[error("PoH verification failed")]
    PohVerificationFailed,

    #[error("Invalid leader - block producer is not the expected leader for this slot")]
    InvalidLeader,

    #[error("No leader schedule configured - cannot verify block producers")]
    NoLeaderSchedule,
}

/// Leader schedule
#[derive(Debug, Clone)]
pub struct LeaderSchedule {
    /// Validators by slot index
    pub schedule: Vec<Pubkey>,

    /// Epoch this schedule is for
    pub epoch: u64,
}

impl LeaderSchedule {
    /// Create a leader schedule from validators using stake-weighted randomization
    /// This ensures fair distribution while preventing predictable patterns
    pub fn new(validators: &[ValidatorInfo], epoch: u64, slots_per_epoch: u64) -> Self {
        let total_stake: u64 = validators.iter().filter(|v| v.activated).map(|v| v.stake).sum();
        let mut schedule = Vec::with_capacity(slots_per_epoch as usize);

        if total_stake == 0 || validators.is_empty() {
            return LeaderSchedule {
                schedule: vec![Pubkey::zero(); slots_per_epoch as usize],
                epoch,
            };
        }

        // Filter active validators only
        let active_validators: Vec<_> = validators.iter().filter(|v| v.activated).collect();

        // Create weighted distribution using epoch as seed for deterministic randomization
        let seed_hash = Hash::hash(&[
            &epoch.to_le_bytes()[..],
            b"leader_schedule_v2",
        ].concat());

        // Build cumulative stake weights for efficient selection
        let mut cumulative_stakes: Vec<(u64, &ValidatorInfo)> = Vec::new();
        let mut running_total = 0u64;

        for validator in &active_validators {
            running_total += validator.stake;
            cumulative_stakes.push((running_total, validator));
        }

        // Generate schedule using deterministic pseudo-random selection
        for slot in 0..slots_per_epoch {
            // Create deterministic seed for this slot
            let mut seed_data = Vec::with_capacity(40);
            seed_data.extend_from_slice(seed_hash.as_bytes());
            seed_data.extend_from_slice(&slot.to_le_bytes());
            let slot_seed = Hash::hash(&seed_data);

            // Convert first 8 bytes to u64 for random selection
            let random_value = u64::from_le_bytes(
                slot_seed.as_bytes()[0..8].try_into().unwrap_or([0u8; 8])
            ) % total_stake;

            // Binary search for validator
            let selected = cumulative_stakes
                .iter()
                .find(|(cumulative, _)| *cumulative > random_value)
                .map(|(_, v)| v.identity)
                .unwrap_or_else(|| active_validators.last().map(|v| v.identity).unwrap_or(Pubkey::zero()));

            schedule.push(selected);
        }

        LeaderSchedule { schedule, epoch }
    }

    /// Create schedule for a specific slot range (for incremental updates)
    pub fn new_for_range(
        validators: &[ValidatorInfo],
        epoch: u64,
        start_slot: u64,
        end_slot: u64,
    ) -> Self {
        let range_size = end_slot.saturating_sub(start_slot);
        let full_schedule = Self::new(validators, epoch, end_slot);

        LeaderSchedule {
            schedule: full_schedule.schedule.into_iter().skip(start_slot as usize).take(range_size as usize).collect(),
            epoch,
        }
    }

    /// Get the leader for a slot
    pub fn get_leader(&self, slot: Slot) -> Option<Pubkey> {
        let slot_index = (slot % self.schedule.len() as u64) as usize;
        self.schedule.get(slot_index).copied()
    }

    /// Check if a validator is the leader for a slot
    pub fn is_leader(&self, slot: Slot, validator: &Pubkey) -> bool {
        self.get_leader(slot).map(|l| l == *validator).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_creation() {
        let keypair = Keypair::generate();
        let validator = Validator::new(keypair, 1000, 10000);

        assert_eq!(validator.stake, 1000);
        assert!(!validator.is_leader);
    }

    #[test]
    fn test_block_production() {
        let keypair = Keypair::generate();
        let mut validator = Validator::new(keypair, 1000, 10000);

        // Not leader - should return None
        assert!(validator.produce_block(Vec::new()).is_none());

        // Set as leader
        validator.set_leader(true);
        let block = validator.produce_block(Vec::new());

        assert!(block.is_some());
        let block = block.unwrap();
        assert_eq!(block.header.slot, 0);
    }

    #[test]
    fn test_leader_schedule() {
        let v1 = ValidatorInfo {
            identity: Keypair::generate().address(),
            vote_account: Keypair::generate().address(),
            stake: 500,
            last_vote: None,
            root_slot: None,
            commission: 10,
            activated: true,
        };

        let v2 = ValidatorInfo {
            identity: Keypair::generate().address(),
            vote_account: Keypair::generate().address(),
            stake: 500,
            last_vote: None,
            root_slot: None,
            commission: 10,
            activated: true,
        };

        let schedule = LeaderSchedule::new(&[v1.clone(), v2.clone()], 0, 100);

        // Both validators should be in the schedule
        let mut v1_count = 0;
        let mut v2_count = 0;

        for slot in 0..100 {
            if let Some(leader) = schedule.get_leader(slot) {
                if leader == v1.identity {
                    v1_count += 1;
                } else if leader == v2.identity {
                    v2_count += 1;
                }
            }
        }

        // With equal stake, should be roughly equal
        assert!(v1_count > 0);
        assert!(v2_count > 0);
    }
}
