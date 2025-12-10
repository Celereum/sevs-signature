//! Validator Key Rotation for Celereum
//!
//! Allows validators to rotate their signing keys without losing stake
//! or disrupting network operations.
//!
//! # Security Features
//! - Proof of Possession required for new key
//! - Old key must sign the rotation request
//! - Configurable activation delay (prevents instant takeover)
//! - Audit trail of all rotations
//!
//! # Usage
//! ```ignore
//! let rotation = KeyRotationRequest::new(
//!     old_keypair,
//!     new_keypair,
//!     effective_slot + 100,  // Activate after 100 slots
//! );
//! registry.submit_rotation(rotation)?;
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::bls::{
    BlsKeypair, BlsPublicKey, BlsSecretKey, BlsSignature,
    ProofOfPossession, dst,
};
use super::hash::Hash;

/// Minimum slots before a key rotation becomes effective
pub const MIN_ROTATION_DELAY_SLOTS: u64 = 100;

/// Maximum slots a rotation can be scheduled in the future
pub const MAX_ROTATION_DELAY_SLOTS: u64 = 864_000;  // ~1 epoch

/// Key rotation errors
#[derive(Debug, Clone, PartialEq)]
pub enum KeyRotationError {
    /// Old key signature is invalid
    InvalidOldKeySignature,
    /// New key proof of possession is invalid
    InvalidProofOfPossession,
    /// Effective slot is too soon
    EffectiveSlotTooSoon { min_slot: u64 },
    /// Effective slot is too far in the future
    EffectiveSlotTooFar { max_slot: u64 },
    /// Validator not found
    ValidatorNotFound,
    /// Rotation already pending
    RotationAlreadyPending,
    /// Rotation not found
    RotationNotFound,
    /// Cannot cancel - already effective
    AlreadyEffective,
    /// Keys are the same
    SameKey,
}

impl std::fmt::Display for KeyRotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOldKeySignature => write!(f, "Invalid signature from old key"),
            Self::InvalidProofOfPossession => write!(f, "Invalid proof of possession for new key"),
            Self::EffectiveSlotTooSoon { min_slot } => {
                write!(f, "Effective slot too soon, minimum: {}", min_slot)
            }
            Self::EffectiveSlotTooFar { max_slot } => {
                write!(f, "Effective slot too far, maximum: {}", max_slot)
            }
            Self::ValidatorNotFound => write!(f, "Validator not found in registry"),
            Self::RotationAlreadyPending => write!(f, "A key rotation is already pending"),
            Self::RotationNotFound => write!(f, "Rotation not found"),
            Self::AlreadyEffective => write!(f, "Cannot cancel - rotation already effective"),
            Self::SameKey => write!(f, "New key is the same as old key"),
        }
    }
}

impl std::error::Error for KeyRotationError {}

/// Key rotation request submitted by validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationRequest {
    /// Current public key being replaced
    pub old_pubkey: BlsPublicKey,
    /// New public key
    pub new_pubkey: BlsPublicKey,
    /// Proof of possession for new key
    pub new_key_pop: ProofOfPossession,
    /// Signature by old key authorizing the rotation
    pub old_key_signature: BlsSignature,
    /// Slot when new key becomes effective
    pub effective_slot: u64,
    /// Slot when request was submitted
    pub submitted_slot: u64,
    /// Optional reason for rotation
    pub reason: Option<String>,
}

impl KeyRotationRequest {
    /// Create a new key rotation request
    ///
    /// # Arguments
    /// * `old_keypair` - Current validator keypair
    /// * `new_keypair` - New keypair to rotate to
    /// * `effective_slot` - Slot when new key becomes active
    /// * `current_slot` - Current blockchain slot
    pub fn new(
        old_keypair: &BlsKeypair,
        new_keypair: &BlsKeypair,
        effective_slot: u64,
        current_slot: u64,
    ) -> Result<Self, KeyRotationError> {
        // Validate effective slot
        let min_slot = current_slot + MIN_ROTATION_DELAY_SLOTS;
        if effective_slot < min_slot {
            return Err(KeyRotationError::EffectiveSlotTooSoon { min_slot });
        }

        let max_slot = current_slot + MAX_ROTATION_DELAY_SLOTS;
        if effective_slot > max_slot {
            return Err(KeyRotationError::EffectiveSlotTooFar { max_slot });
        }

        // Check keys are different
        if old_keypair.public_key().to_bytes() == new_keypair.public_key().to_bytes() {
            return Err(KeyRotationError::SameKey);
        }

        // Create proof of possession for new key
        let new_key_pop = new_keypair.create_proof_of_possession();

        // Create rotation message
        let message = Self::rotation_message(
            old_keypair.public_key(),
            new_keypair.public_key(),
            effective_slot,
        );

        // Sign with old key
        let old_key_signature = old_keypair.sign(&message, dst::MESSAGE);

        Ok(Self {
            old_pubkey: old_keypair.public_key().clone(),
            new_pubkey: new_keypair.public_key().clone(),
            new_key_pop,
            old_key_signature,
            effective_slot,
            submitted_slot: current_slot,
            reason: None,
        })
    }

    /// Add a reason for the rotation
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Verify the rotation request
    pub fn verify(&self) -> Result<(), KeyRotationError> {
        // Verify proof of possession for new key
        if !self.new_key_pop.verify(&self.new_pubkey) {
            return Err(KeyRotationError::InvalidProofOfPossession);
        }

        // Verify old key signature
        let message = Self::rotation_message(
            &self.old_pubkey,
            &self.new_pubkey,
            self.effective_slot,
        );

        if !self.old_key_signature.verify(&message, &self.old_pubkey, dst::MESSAGE) {
            return Err(KeyRotationError::InvalidOldKeySignature);
        }

        Ok(())
    }

    /// Create the message to sign for rotation
    fn rotation_message(
        old_pubkey: &BlsPublicKey,
        new_pubkey: &BlsPublicKey,
        effective_slot: u64,
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(96 + 96 + 8 + 16);
        message.extend_from_slice(b"CELEREUM_KEY_ROTATION_V1:");
        message.extend_from_slice(&old_pubkey.to_bytes());
        message.extend_from_slice(&new_pubkey.to_bytes());
        message.extend_from_slice(&effective_slot.to_le_bytes());
        message
    }
}

/// Status of a key rotation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationStatus {
    /// Rotation is pending, waiting for effective slot
    Pending,
    /// Rotation is now effective
    Effective,
    /// Rotation was cancelled
    Cancelled,
    /// Rotation failed (e.g., validator exited)
    Failed,
}

/// Record of a completed or pending rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRecord {
    /// The original request
    pub request: KeyRotationRequest,
    /// Current status
    pub status: RotationStatus,
    /// Slot when status last changed
    pub status_updated_slot: u64,
}

/// Key rotation registry
///
/// Tracks all pending and completed key rotations
#[derive(Debug, Clone, Default)]
pub struct KeyRotationRegistry {
    /// Pending rotations by old public key
    pending: HashMap<[u8; 96], RotationRecord>,
    /// History of all rotations (for audit)
    history: Vec<RotationRecord>,
    /// Current slot
    current_slot: u64,
}

impl KeyRotationRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the current slot
    pub fn set_slot(&mut self, slot: u64) {
        self.current_slot = slot;
    }

    /// Submit a key rotation request
    pub fn submit_rotation(&mut self, request: KeyRotationRequest) -> Result<(), KeyRotationError> {
        // Verify the request
        request.verify()?;

        // Check minimum delay
        let min_slot = self.current_slot + MIN_ROTATION_DELAY_SLOTS;
        if request.effective_slot < min_slot {
            return Err(KeyRotationError::EffectiveSlotTooSoon { min_slot });
        }

        // Check no pending rotation for this key
        let key = request.old_pubkey.to_bytes();
        if self.pending.contains_key(&key) {
            return Err(KeyRotationError::RotationAlreadyPending);
        }

        // Add to pending
        let record = RotationRecord {
            request,
            status: RotationStatus::Pending,
            status_updated_slot: self.current_slot,
        };
        self.pending.insert(key, record);

        Ok(())
    }

    /// Cancel a pending rotation
    ///
    /// Must be signed by the old key
    pub fn cancel_rotation(
        &mut self,
        old_pubkey: &BlsPublicKey,
        cancellation_sig: &BlsSignature,
    ) -> Result<(), KeyRotationError> {
        let key = old_pubkey.to_bytes();

        let record = self.pending.get_mut(&key)
            .ok_or(KeyRotationError::RotationNotFound)?;

        // Check not already effective
        if record.request.effective_slot <= self.current_slot {
            return Err(KeyRotationError::AlreadyEffective);
        }

        // Verify cancellation signature
        let message = format!("CELEREUM_CANCEL_ROTATION:{}", record.request.effective_slot);
        if !cancellation_sig.verify(message.as_bytes(), old_pubkey, dst::MESSAGE) {
            return Err(KeyRotationError::InvalidOldKeySignature);
        }

        // Cancel the rotation
        record.status = RotationStatus::Cancelled;
        record.status_updated_slot = self.current_slot;

        // Move to history
        let record = self.pending.remove(&key).unwrap();
        self.history.push(record);

        Ok(())
    }

    /// Process slot - activate any rotations that have reached their effective slot
    ///
    /// Returns list of newly effective rotations
    pub fn process_slot(&mut self, slot: u64) -> Vec<(BlsPublicKey, BlsPublicKey)> {
        self.current_slot = slot;
        let mut effective = Vec::new();

        let keys_to_process: Vec<_> = self.pending.keys().cloned().collect();

        for key in keys_to_process {
            if let Some(record) = self.pending.get(&key) {
                if record.request.effective_slot <= slot {
                    let old_pk = record.request.old_pubkey.clone();
                    let new_pk = record.request.new_pubkey.clone();

                    // Update status
                    if let Some(mut record) = self.pending.remove(&key) {
                        record.status = RotationStatus::Effective;
                        record.status_updated_slot = slot;
                        self.history.push(record);
                    }

                    effective.push((old_pk, new_pk));
                }
            }
        }

        effective
    }

    /// Get pending rotation for a validator
    pub fn get_pending(&self, pubkey: &BlsPublicKey) -> Option<&RotationRecord> {
        self.pending.get(&pubkey.to_bytes())
    }

    /// Get rotation history for a validator (by any of their keys)
    pub fn get_history(&self, pubkey: &BlsPublicKey) -> Vec<&RotationRecord> {
        let key_bytes = pubkey.to_bytes();
        self.history.iter()
            .filter(|r| {
                r.request.old_pubkey.to_bytes() == key_bytes ||
                r.request.new_pubkey.to_bytes() == key_bytes
            })
            .collect()
    }

    /// Get all pending rotations
    pub fn pending_rotations(&self) -> Vec<&RotationRecord> {
        self.pending.values().collect()
    }

    /// Get rotations becoming effective in the next N slots
    pub fn upcoming_rotations(&self, slots: u64) -> Vec<&RotationRecord> {
        let deadline = self.current_slot + slots;
        self.pending.values()
            .filter(|r| r.request.effective_slot <= deadline)
            .collect()
    }
}

/// Key chain - tracks the history of keys for a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyChain {
    /// Validator identity (doesn't change)
    pub validator_id: [u8; 32],
    /// Current active key
    pub current_key: BlsPublicKey,
    /// History of keys with activation slots
    pub key_history: Vec<KeyHistoryEntry>,
}

/// Entry in key history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHistoryEntry {
    /// The public key
    pub pubkey: BlsPublicKey,
    /// Slot when this key became active
    pub active_from: u64,
    /// Slot when this key was replaced (None if still active)
    pub active_until: Option<u64>,
    /// Reason for rotation (if available)
    pub rotation_reason: Option<String>,
}

impl KeyChain {
    /// Create a new key chain for a validator
    pub fn new(validator_id: [u8; 32], initial_key: BlsPublicKey, activation_slot: u64) -> Self {
        Self {
            validator_id,
            current_key: initial_key.clone(),
            key_history: vec![KeyHistoryEntry {
                pubkey: initial_key,
                active_from: activation_slot,
                active_until: None,
                rotation_reason: None,
            }],
        }
    }

    /// Apply a key rotation
    pub fn rotate(&mut self, new_key: BlsPublicKey, effective_slot: u64, reason: Option<String>) {
        // Close the current key's validity period
        if let Some(last) = self.key_history.last_mut() {
            last.active_until = Some(effective_slot);
        }

        // Add new key
        self.key_history.push(KeyHistoryEntry {
            pubkey: new_key.clone(),
            active_from: effective_slot,
            active_until: None,
            rotation_reason: reason,
        });

        self.current_key = new_key;
    }

    /// Get the key that was active at a specific slot
    pub fn key_at_slot(&self, slot: u64) -> Option<&BlsPublicKey> {
        for entry in self.key_history.iter().rev() {
            if entry.active_from <= slot {
                if let Some(until) = entry.active_until {
                    if slot < until {
                        return Some(&entry.pubkey);
                    }
                } else {
                    return Some(&entry.pubkey);
                }
            }
        }
        None
    }

    /// Number of key rotations
    pub fn rotation_count(&self) -> usize {
        self.key_history.len().saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_rotation_request() {
        let old_kp = BlsKeypair::generate();
        let new_kp = BlsKeypair::generate();
        let current_slot = 1000;
        let effective_slot = current_slot + 200;

        let request = KeyRotationRequest::new(
            &old_kp, &new_kp, effective_slot, current_slot
        ).unwrap();

        assert!(request.verify().is_ok());
    }

    #[test]
    fn test_rotation_too_soon() {
        let old_kp = BlsKeypair::generate();
        let new_kp = BlsKeypair::generate();
        let current_slot = 1000;
        let effective_slot = current_slot + 50;  // Less than MIN_ROTATION_DELAY_SLOTS

        let result = KeyRotationRequest::new(
            &old_kp, &new_kp, effective_slot, current_slot
        );

        assert!(matches!(result, Err(KeyRotationError::EffectiveSlotTooSoon { .. })));
    }

    #[test]
    fn test_same_key_rotation() {
        let kp = BlsKeypair::generate();
        let current_slot = 1000;
        let effective_slot = current_slot + 200;

        let result = KeyRotationRequest::new(
            &kp, &kp, effective_slot, current_slot
        );

        assert!(matches!(result, Err(KeyRotationError::SameKey)));
    }

    #[test]
    fn test_registry_submit_and_process() {
        let mut registry = KeyRotationRegistry::new();
        registry.set_slot(1000);

        let old_kp = BlsKeypair::generate();
        let new_kp = BlsKeypair::generate();
        let effective_slot = 1200;

        let request = KeyRotationRequest::new(
            &old_kp, &new_kp, effective_slot, 1000
        ).unwrap();

        registry.submit_rotation(request).unwrap();

        // Before effective slot
        let effective = registry.process_slot(1100);
        assert!(effective.is_empty());

        // At effective slot
        let effective = registry.process_slot(1200);
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].0, *old_kp.public_key());
        assert_eq!(effective[0].1, *new_kp.public_key());
    }

    #[test]
    fn test_duplicate_rotation() {
        let mut registry = KeyRotationRegistry::new();
        registry.set_slot(1000);

        let old_kp = BlsKeypair::generate();
        let new_kp1 = BlsKeypair::generate();
        let new_kp2 = BlsKeypair::generate();

        let request1 = KeyRotationRequest::new(
            &old_kp, &new_kp1, 1200, 1000
        ).unwrap();

        let request2 = KeyRotationRequest::new(
            &old_kp, &new_kp2, 1300, 1000
        ).unwrap();

        registry.submit_rotation(request1).unwrap();
        let result = registry.submit_rotation(request2);

        assert!(matches!(result, Err(KeyRotationError::RotationAlreadyPending)));
    }

    #[test]
    fn test_key_chain() {
        let validator_id = [1u8; 32];
        let key1 = BlsKeypair::generate().public_key().clone();
        let key2 = BlsKeypair::generate().public_key().clone();
        let key3 = BlsKeypair::generate().public_key().clone();

        let mut chain = KeyChain::new(validator_id, key1.clone(), 0);

        chain.rotate(key2.clone(), 1000, Some("Scheduled rotation".to_string()));
        chain.rotate(key3.clone(), 2000, Some("Security upgrade".to_string()));

        assert_eq!(chain.rotation_count(), 2);

        // Check key at different slots
        assert_eq!(chain.key_at_slot(500), Some(&key1));
        assert_eq!(chain.key_at_slot(1500), Some(&key2));
        assert_eq!(chain.key_at_slot(2500), Some(&key3));
    }
}
