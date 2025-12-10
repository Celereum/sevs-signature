//! Block structure for Celereum blockchain
//!
//! # Post-Quantum Security
//! All signatures in blocks use SEVS (Seed-Expanded Verkle Signatures),
//! providing 128-bit post-quantum security.

use serde::{Deserialize, Serialize};
use crate::crypto::{
    Hash,
    quantum_safe::{Address, TxSignature, QsSigner},
    sevs::SevsKeypair,
};
use super::transaction::Transaction;
use super::slot::Slot;

/// A block in the Celereum blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,

    /// Transactions in this block
    pub transactions: Vec<Transaction>,
}

/// Block header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Slot number
    pub slot: Slot,

    /// Hash of the previous block
    pub previous_hash: Hash,

    /// Merkle root of transactions
    pub transactions_root: Hash,

    /// State root after executing this block
    pub state_root: Hash,

    /// Proof of History hash
    pub poh_hash: Hash,

    /// Number of PoH ticks in this block
    pub tick_count: u64,

    /// Block producer (leader) address
    pub leader: Address,

    /// Timestamp (unix timestamp)
    pub timestamp: i64,

    /// Block height (for easier indexing)
    pub height: u64,
}

/// Block with votes (for consensus)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotedBlock {
    /// The block
    pub block: Block,

    /// Votes from validators
    pub votes: Vec<Vote>,

    /// Total stake that voted
    pub total_stake: u64,
}

/// A vote for a block using SEVS signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Voter's address (derived from SEVS pubkey)
    pub voter: Address,

    /// Slot being voted on
    pub slot: Slot,

    /// Hash of the block being voted on
    pub block_hash: Hash,

    /// Voter's SEVS signature bundle (includes pubkey)
    pub signature: TxSignature,

    /// Voter's stake
    pub stake: u64,
}

impl Block {
    /// Create a new block
    pub fn new(
        slot: Slot,
        previous_hash: Hash,
        poh_hash: Hash,
        tick_count: u64,
        leader: Address,
        transactions: Vec<Transaction>,
    ) -> Self {
        let transactions_root = Self::compute_transactions_root(&transactions);

        Block {
            header: BlockHeader {
                slot,
                previous_hash,
                transactions_root,
                state_root: Hash::zero(), // Set after execution
                poh_hash,
                tick_count,
                leader,
                timestamp: chrono::Utc::now().timestamp(),
                height: slot, // In Celereum, slot == height for simplicity
            },
            transactions,
        }
    }

    /// Compute the hash of this block
    pub fn hash(&self) -> Hash {
        let bytes = bincode::serialize(&self.header).unwrap();
        Hash::hash(&bytes)
    }

    /// Compute merkle root of transactions
    pub fn compute_transactions_root(transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::zero();
        }

        // Simple merkle tree implementation
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

    /// Verify the block's structure
    pub fn verify(&self) -> bool {
        // Verify transactions root
        let computed_root = Self::compute_transactions_root(&self.transactions);
        if computed_root != self.header.transactions_root {
            return false;
        }

        // Verify all transactions
        for tx in &self.transactions {
            if !tx.verify() {
                return false;
            }
        }

        true
    }

    /// Get the number of transactions
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Get block size in bytes
    pub fn size(&self) -> usize {
        bincode::serialized_size(self).unwrap_or(0) as usize
    }
}

impl Vote {
    /// Create a new vote with SEVS signature
    pub fn new(
        slot: Slot,
        block_hash: Hash,
        stake: u64,
        keypair: &SevsKeypair,
    ) -> Self {
        let message = Self::vote_message(slot, &block_hash);
        let signature = keypair.sign_tx(&message);
        let voter = keypair.address();

        Vote {
            voter,
            slot,
            block_hash,
            signature,
            stake,
        }
    }

    /// Create the message to sign for a vote
    fn vote_message(slot: Slot, block_hash: &Hash) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(b"CELEREUM_VOTE_V1");
        message.extend_from_slice(&slot.to_le_bytes());
        message.extend_from_slice(block_hash.as_bytes());
        message
    }

    /// Verify the vote signature
    pub fn verify(&self) -> bool {
        let message = Self::vote_message(self.slot, &self.block_hash);

        // Verify signature
        if !self.signature.verify(&message) {
            return false;
        }

        // Verify voter address matches signature
        if self.signature.address() != &self.voter {
            return false;
        }

        true
    }
}

/// Genesis block configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Genesis timestamp
    pub creation_time: i64,

    /// Initial accounts with balances (address, balance)
    pub accounts: Vec<(Address, u64)>,

    /// Initial validators
    pub validators: Vec<ValidatorConfig>,

    /// Network name
    pub cluster_name: String,

    /// Ticks per slot
    pub ticks_per_slot: u64,

    /// Slots per epoch
    pub slots_per_epoch: u64,
}

/// Validator configuration in genesis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Validator's identity address
    pub address: Address,

    /// Validator's vote account
    pub vote_account: Address,

    /// Initial stake
    pub stake: u64,
}

/// Vesting schedule for token allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Recipient address
    pub address: Address,

    /// Total amount to vest (in celers)
    pub total_amount: u64,

    /// Amount immediately available (no cliff)
    pub initial_unlock: u64,

    /// Cliff period in slots (tokens locked until cliff)
    pub cliff_slots: u64,

    /// Total vesting duration in slots
    pub vesting_duration_slots: u64,

    /// Description (e.g., "Team", "Advisors", "Development")
    pub category: String,
}

impl VestingSchedule {
    /// Calculate unlocked amount at a given slot
    pub fn unlocked_at_slot(&self, slot: u64) -> u64 {
        // Before cliff: only initial unlock
        if slot < self.cliff_slots {
            return self.initial_unlock;
        }

        // After vesting complete: everything unlocked
        if slot >= self.vesting_duration_slots {
            return self.total_amount;
        }

        // Linear vesting after cliff
        let vestable = self.total_amount - self.initial_unlock;
        let slots_since_cliff = slot - self.cliff_slots;
        let vesting_slots = self.vesting_duration_slots - self.cliff_slots;

        let vested = if vesting_slots > 0 {
            (vestable as u128 * slots_since_cliff as u128 / vesting_slots as u128) as u64
        } else {
            vestable
        };

        self.initial_unlock + vested
    }

    /// Calculate still-locked amount at a given slot
    pub fn locked_at_slot(&self, slot: u64) -> u64 {
        self.total_amount - self.unlocked_at_slot(slot)
    }
}

impl GenesisConfig {
    /// Create the genesis block
    pub fn create_genesis_block(&self) -> Block {
        Block::new(
            0, // Slot 0
            Hash::zero(), // No previous hash
            Hash::hash(b"celereum-genesis"), // Genesis PoH
            0,
            Address::zero(), // No leader for genesis
            Vec::new(), // No transactions in genesis
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_creation() {
        let leader = SevsKeypair::generate();
        let block = Block::new(
            1,
            Hash::zero(),
            Hash::hash(b"poh"),
            64,
            leader.address(),
            Vec::new(),
        );

        assert_eq!(block.header.slot, 1);
        assert!(block.verify());
    }

    #[test]
    fn test_block_hash() {
        let leader = SevsKeypair::generate();
        let block1 = Block::new(1, Hash::zero(), Hash::hash(b"poh1"), 64, leader.address(), Vec::new());
        let block2 = Block::new(2, block1.hash(), Hash::hash(b"poh2"), 64, leader.address(), Vec::new());

        assert_ne!(block1.hash(), block2.hash());
    }

    #[test]
    fn test_vote() {
        let validator = SevsKeypair::generate();
        let block_hash = Hash::hash(b"block");

        let vote = Vote::new(
            1,
            block_hash,
            1000,
            &validator,
        );

        assert!(vote.verify());
        assert_eq!(vote.voter, validator.address());
    }

    #[test]
    fn test_vote_wrong_voter_fails() {
        let validator = SevsKeypair::generate();
        let other = SevsKeypair::generate();
        let block_hash = Hash::hash(b"block");

        let mut vote = Vote::new(1, block_hash, 1000, &validator);

        // Tamper with voter address
        vote.voter = other.address();

        // Should fail because voter doesn't match signature
        assert!(!vote.verify());
    }
}
