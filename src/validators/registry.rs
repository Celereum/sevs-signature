//! Validator Registry
//!
//! Maintains the authoritative list of validators and their stakes.
//! Provides efficient lookup and iteration over the validator set.

use crate::crypto::{
    Hash,
    Pubkey,
    bls::{BlsPublicKey, ProofOfPossession},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use parking_lot::RwLock;

/// Validator status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Validator is pending activation
    Pending,
    /// Validator is active and can vote
    Active,
    /// Validator is exiting (cooldown period)
    Exiting,
    /// Validator has exited
    Exited,
    /// Validator is slashed
    Slashed,
}

/// Registered validator with full metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredValidator {
    /// Ed25519 identity public key
    pub identity: Pubkey,
    /// BLS public key for signature aggregation
    pub bls_pubkey: BlsPublicKey,
    /// Proof of possession for BLS key
    pub bls_pop: ProofOfPossession,
    /// Vote account public key
    pub vote_account: Pubkey,
    /// Current stake amount
    pub stake: u64,
    /// Effective stake (after caps applied)
    pub effective_stake: u64,
    /// Commission rate (0-10000 = 0-100%)
    pub commission: u16,
    /// Validator status
    pub status: ValidatorStatus,
    /// Epoch when registered
    pub activation_epoch: u64,
    /// Epoch when will exit (if exiting)
    pub exit_epoch: Option<u64>,
    /// Last voted slot
    pub last_vote_slot: Option<u64>,
    /// Total blocks produced
    pub blocks_produced: u64,
    /// Total votes cast
    pub votes_cast: u64,
    /// Slashing history count
    pub slashing_count: u32,
    /// Withdrawable rewards
    pub pending_rewards: u64,
}

impl RegisteredValidator {
    /// Create a new registered validator
    pub fn new(
        identity: Pubkey,
        bls_pubkey: BlsPublicKey,
        bls_pop: ProofOfPossession,
        vote_account: Pubkey,
        stake: u64,
        commission: u16,
        activation_epoch: u64,
    ) -> Self {
        Self {
            identity,
            bls_pubkey,
            bls_pop,
            vote_account,
            stake,
            effective_stake: stake,
            commission: commission.min(10000), // Cap at 100%
            status: ValidatorStatus::Pending,
            activation_epoch,
            exit_epoch: None,
            last_vote_slot: None,
            blocks_produced: 0,
            votes_cast: 0,
            slashing_count: 0,
            pending_rewards: 0,
        }
    }

    /// Check if validator is active
    pub fn is_active(&self) -> bool {
        self.status == ValidatorStatus::Active
    }

    /// Get commission as percentage (0.0 - 100.0)
    pub fn commission_percent(&self) -> f64 {
        self.commission as f64 / 100.0
    }
}

/// Update to a validator
#[derive(Debug, Clone)]
pub enum ValidatorUpdate {
    /// Increase stake
    IncreaseStake(u64),
    /// Decrease stake
    DecreaseStake(u64),
    /// Update commission
    UpdateCommission(u16),
    /// Request exit
    RequestExit,
    /// Activate validator
    Activate,
    /// Mark as slashed
    Slash(u32),
}

/// Validator registry
pub struct ValidatorRegistry {
    /// Validators by identity pubkey
    validators: RwLock<HashMap<Pubkey, RegisteredValidator>>,
    /// BLS pubkey to identity mapping (96-byte BLS public keys)
    bls_to_identity: RwLock<HashMap<[u8; 96], Pubkey>>,
    /// Total stake
    total_stake: AtomicU64,
    /// Active validator count
    active_count: AtomicU64,
    /// Current epoch
    current_epoch: AtomicU64,
}

impl ValidatorRegistry {
    /// Create a new validator registry
    pub fn new() -> Self {
        Self {
            validators: RwLock::new(HashMap::new()),
            bls_to_identity: RwLock::new(HashMap::new()),
            total_stake: AtomicU64::new(0),
            active_count: AtomicU64::new(0),
            current_epoch: AtomicU64::new(0),
        }
    }

    /// Set current epoch
    pub fn set_epoch(&self, epoch: u64) {
        self.current_epoch.store(epoch, AtomicOrdering::SeqCst);
    }

    /// Register a new validator
    pub fn register(
        &self,
        identity: Pubkey,
        bls_pubkey: BlsPublicKey,
        bls_pop: ProofOfPossession,
        vote_account: Pubkey,
        stake: u64,
        commission: u16,
    ) -> Result<(), RegistrationError> {
        // Verify BLS proof of possession
        if !bls_pubkey.verify_proof_of_possession(&bls_pop) {
            return Err(RegistrationError::InvalidProofOfPossession);
        }

        let current_epoch = self.current_epoch.load(AtomicOrdering::SeqCst);
        let bls_bytes = bls_pubkey.to_bytes();

        let mut validators = self.validators.write();
        let mut bls_map = self.bls_to_identity.write();

        // Check for duplicate
        if validators.contains_key(&identity) {
            return Err(RegistrationError::AlreadyRegistered);
        }

        if bls_map.contains_key(&bls_bytes) {
            return Err(RegistrationError::BlsKeyAlreadyUsed);
        }

        // Create validator
        let validator = RegisteredValidator::new(
            identity,
            bls_pubkey,
            bls_pop,
            vote_account,
            stake,
            commission,
            current_epoch + 1, // Activate next epoch
        );

        bls_map.insert(bls_bytes, identity);
        validators.insert(identity, validator);

        Ok(())
    }

    /// Activate pending validators
    pub fn activate_pending(&self) {
        let current_epoch = self.current_epoch.load(AtomicOrdering::SeqCst);
        let mut validators = self.validators.write();
        let mut activated = 0u64;
        let mut stake_added = 0u64;

        for validator in validators.values_mut() {
            if validator.status == ValidatorStatus::Pending
                && validator.activation_epoch <= current_epoch
            {
                validator.status = ValidatorStatus::Active;
                activated += 1;
                stake_added += validator.effective_stake;
            }
        }

        if activated > 0 {
            drop(validators);
            self.active_count.fetch_add(activated, AtomicOrdering::SeqCst);
            self.total_stake.fetch_add(stake_added, AtomicOrdering::SeqCst);
        }
    }

    /// Update a validator
    pub fn update(
        &self,
        identity: &Pubkey,
        update: ValidatorUpdate,
    ) -> Result<(), RegistrationError> {
        let mut validators = self.validators.write();
        let validator = validators.get_mut(identity)
            .ok_or(RegistrationError::NotFound)?;

        match update {
            ValidatorUpdate::IncreaseStake(amount) => {
                validator.stake = validator.stake.saturating_add(amount);
                if validator.is_active() {
                    self.total_stake.fetch_add(amount, AtomicOrdering::SeqCst);
                }
            }
            ValidatorUpdate::DecreaseStake(amount) => {
                if amount > validator.stake {
                    return Err(RegistrationError::InsufficientStake);
                }
                validator.stake = validator.stake.saturating_sub(amount);
                if validator.is_active() {
                    self.total_stake.fetch_sub(amount, AtomicOrdering::SeqCst);
                }
            }
            ValidatorUpdate::UpdateCommission(commission) => {
                validator.commission = commission.min(10000);
            }
            ValidatorUpdate::RequestExit => {
                if validator.status != ValidatorStatus::Active {
                    return Err(RegistrationError::InvalidStatus);
                }
                validator.status = ValidatorStatus::Exiting;
                let current_epoch = self.current_epoch.load(AtomicOrdering::SeqCst);
                validator.exit_epoch = Some(current_epoch + 2); // Exit after 2 epochs
                self.active_count.fetch_sub(1, AtomicOrdering::SeqCst);
                self.total_stake.fetch_sub(validator.effective_stake, AtomicOrdering::SeqCst);
            }
            ValidatorUpdate::Activate => {
                if validator.status != ValidatorStatus::Pending {
                    return Err(RegistrationError::InvalidStatus);
                }
                validator.status = ValidatorStatus::Active;
                self.active_count.fetch_add(1, AtomicOrdering::SeqCst);
                self.total_stake.fetch_add(validator.effective_stake, AtomicOrdering::SeqCst);
            }
            ValidatorUpdate::Slash(severity) => {
                validator.slashing_count += severity;
                if validator.slashing_count >= 100 {
                    validator.status = ValidatorStatus::Slashed;
                    if validator.is_active() {
                        self.active_count.fetch_sub(1, AtomicOrdering::SeqCst);
                        self.total_stake.fetch_sub(validator.effective_stake, AtomicOrdering::SeqCst);
                    }
                }
            }
        }

        Ok(())
    }

    /// Record a vote
    pub fn record_vote(&self, identity: &Pubkey, slot: u64) {
        if let Some(validator) = self.validators.write().get_mut(identity) {
            validator.last_vote_slot = Some(slot);
            validator.votes_cast += 1;
        }
    }

    /// Record block production
    pub fn record_block(&self, identity: &Pubkey) {
        if let Some(validator) = self.validators.write().get_mut(identity) {
            validator.blocks_produced += 1;
        }
    }

    /// Add rewards to validator
    pub fn add_rewards(&self, identity: &Pubkey, amount: u64) {
        if let Some(validator) = self.validators.write().get_mut(identity) {
            validator.pending_rewards = validator.pending_rewards.saturating_add(amount);
        }
    }

    /// Withdraw rewards (returns amount withdrawn)
    pub fn withdraw_rewards(&self, identity: &Pubkey) -> u64 {
        if let Some(validator) = self.validators.write().get_mut(identity) {
            let amount = validator.pending_rewards;
            validator.pending_rewards = 0;
            amount
        } else {
            0
        }
    }

    /// Get validator by identity
    pub fn get(&self, identity: &Pubkey) -> Option<RegisteredValidator> {
        self.validators.read().get(identity).cloned()
    }

    /// Get validator by BLS pubkey
    pub fn get_by_bls(&self, bls_pubkey: &BlsPublicKey) -> Option<RegisteredValidator> {
        let identity = self.bls_to_identity.read().get(&bls_pubkey.to_bytes()).copied()?;
        self.get(&identity)
    }

    /// Get all active validators
    pub fn get_active(&self) -> Vec<RegisteredValidator> {
        self.validators.read()
            .values()
            .filter(|v| v.is_active())
            .cloned()
            .collect()
    }

    /// Get all validators
    pub fn get_all(&self) -> Vec<RegisteredValidator> {
        self.validators.read().values().cloned().collect()
    }

    /// Get total stake
    pub fn total_stake(&self) -> u64 {
        self.total_stake.load(AtomicOrdering::SeqCst)
    }

    /// Get active validator count
    pub fn active_count(&self) -> u64 {
        self.active_count.load(AtomicOrdering::SeqCst)
    }

    /// Check if validator exists
    pub fn exists(&self, identity: &Pubkey) -> bool {
        self.validators.read().contains_key(identity)
    }

    /// Update effective stakes based on consolidation rules
    pub fn update_effective_stakes(&self, effective_stakes: &HashMap<Pubkey, u64>) {
        let mut validators = self.validators.write();
        let mut stake_diff: i64 = 0;

        for (identity, &effective) in effective_stakes {
            if let Some(validator) = validators.get_mut(identity) {
                if validator.is_active() {
                    stake_diff -= validator.effective_stake as i64;
                    validator.effective_stake = effective;
                    stake_diff += effective as i64;
                }
            }
        }

        // Update total stake
        if stake_diff != 0 {
            if stake_diff > 0 {
                self.total_stake.fetch_add(stake_diff as u64, AtomicOrdering::SeqCst);
            } else {
                self.total_stake.fetch_sub((-stake_diff) as u64, AtomicOrdering::SeqCst);
            }
        }
    }
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Registration errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum RegistrationError {
    #[error("Validator already registered")]
    AlreadyRegistered,

    #[error("BLS key already in use")]
    BlsKeyAlreadyUsed,

    #[error("Invalid proof of possession")]
    InvalidProofOfPossession,

    #[error("Validator not found")]
    NotFound,

    #[error("Insufficient stake")]
    InsufficientStake,

    #[error("Invalid status for operation")]
    InvalidStatus,

    #[error("Stake exceeds maximum limit")]
    StakeExceedsLimit,

    #[error("Stake share exceeds maximum")]
    ShareExceedsLimit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Keypair, bls::BlsKeypair};

    #[test]
    fn test_validator_registration() {
        let registry = ValidatorRegistry::new();

        let identity = Keypair::generate();
        let bls = BlsKeypair::generate().unwrap();
        let vote_account = Keypair::generate();

        registry.register(
            identity.pubkey(),
            bls.public_key().clone(),
            bls.proof_of_possession().clone(),
            vote_account.pubkey(),
            1000,
            500, // 5%
        ).unwrap();

        assert!(registry.exists(&identity.pubkey()));

        let validator = registry.get(&identity.pubkey()).unwrap();
        assert_eq!(validator.stake, 1000);
        assert_eq!(validator.status, ValidatorStatus::Pending);
    }

    #[test]
    fn test_validator_activation() {
        let registry = ValidatorRegistry::new();
        registry.set_epoch(0);

        let identity = Keypair::generate();
        let bls = BlsKeypair::generate().unwrap();
        let vote_account = Keypair::generate();

        registry.register(
            identity.pubkey(),
            bls.public_key().clone(),
            bls.proof_of_possession().clone(),
            vote_account.pubkey(),
            1000,
            500,
        ).unwrap();

        // Not active yet
        assert_eq!(registry.active_count(), 0);

        // Advance epoch and activate
        registry.set_epoch(1);
        registry.activate_pending();

        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.total_stake(), 1000);

        let validator = registry.get(&identity.pubkey()).unwrap();
        assert!(validator.is_active());
    }

    #[test]
    fn test_duplicate_registration_rejected() {
        let registry = ValidatorRegistry::new();

        let identity = Keypair::generate();
        let bls = BlsKeypair::generate().unwrap();
        let vote_account = Keypair::generate();

        registry.register(
            identity.pubkey(),
            bls.public_key().clone(),
            bls.proof_of_possession().clone(),
            vote_account.pubkey(),
            1000,
            500,
        ).unwrap();

        // Try to register again
        let result = registry.register(
            identity.pubkey(),
            bls.public_key().clone(),
            bls.proof_of_possession().clone(),
            vote_account.pubkey(),
            1000,
            500,
        );

        assert!(matches!(result, Err(RegistrationError::AlreadyRegistered)));
    }

    #[test]
    fn test_validator_stake_update() {
        let registry = ValidatorRegistry::new();
        registry.set_epoch(0);

        let identity = Keypair::generate();
        let bls = BlsKeypair::generate().unwrap();
        let vote_account = Keypair::generate();

        registry.register(
            identity.pubkey(),
            bls.public_key().clone(),
            bls.proof_of_possession().clone(),
            vote_account.pubkey(),
            1000,
            500,
        ).unwrap();

        registry.set_epoch(1);
        registry.activate_pending();

        // Increase stake
        registry.update(&identity.pubkey(), ValidatorUpdate::IncreaseStake(500)).unwrap();
        assert_eq!(registry.get(&identity.pubkey()).unwrap().stake, 1500);
        assert_eq!(registry.total_stake(), 1500);

        // Decrease stake
        registry.update(&identity.pubkey(), ValidatorUpdate::DecreaseStake(200)).unwrap();
        assert_eq!(registry.get(&identity.pubkey()).unwrap().stake, 1300);
        assert_eq!(registry.total_stake(), 1300);
    }
}
