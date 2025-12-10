//! Commit-Reveal MEV Protection
//!
//! Implements encrypted transaction submission where transactions are hidden
//! until they are committed to a block, preventing front-running.
//!
//! # How it Works
//! 1. User encrypts transaction with a random key
//! 2. User submits commitment (hash of encrypted tx + nonce)
//! 3. After commitment is included in block, user reveals (decryption key)
//! 4. Transaction is decrypted and executed
//!
//! # Security Properties
//! - Transaction content is hidden until committed
//! - Validators cannot see transaction details
//! - Prevents front-running and sandwich attacks
//! - Binding: cannot change transaction after commitment

use crate::core::{Transaction, Slot};
use crate::crypto::{Hash, Keypair, Pubkey, Signature};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use sha2::{Sha256, Digest};

/// Configuration for commit-reveal
#[derive(Debug, Clone)]
pub struct CommitRevealConfig {
    /// Minimum blocks between commit and reveal
    pub min_reveal_delay: u64,
    /// Maximum blocks to wait for reveal
    pub max_reveal_delay: u64,
    /// Maximum pending commitments
    pub max_pending: usize,
    /// Require validity proof
    pub require_validity_proof: bool,
    /// Commitment expiry (slots)
    pub commitment_expiry: u64,
}

impl Default for CommitRevealConfig {
    fn default() -> Self {
        Self {
            min_reveal_delay: 1,
            max_reveal_delay: 10,
            max_pending: 100_000,
            require_validity_proof: false,
            commitment_expiry: 100,
        }
    }
}

/// Encrypted transaction for submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTransaction {
    /// Encrypted transaction bytes
    pub ciphertext: Vec<u8>,
    /// Commitment hash
    pub commitment: TransactionCommitment,
    /// Sender public key (for accountability)
    pub sender: Pubkey,
    /// Signature over commitment (proves sender)
    pub signature: Signature,
    /// Validity proof (optional ZK proof that tx is valid)
    pub validity_proof: Option<Vec<u8>>,
}

impl EncryptedTransaction {
    /// Create a new encrypted transaction
    ///
    /// Uses XOR encryption with a random key for simplicity
    /// In production, use authenticated encryption (AES-GCM)
    pub fn encrypt(
        transaction: &Transaction,
        keypair: &Keypair,
    ) -> Result<(Self, RevealKey), CommitRevealError> {
        let tx_bytes = bincode::serialize(transaction)
            .map_err(|_| CommitRevealError::SerializationFailed)?;

        // Generate random encryption key
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key)
            .map_err(|_| CommitRevealError::KeyGenerationFailed)?;

        // Simple XOR encryption (replace with AES-GCM in production)
        let ciphertext = Self::xor_encrypt(&tx_bytes, &key);

        // Create commitment
        let commitment = TransactionCommitment::create(&ciphertext, &key);

        // Sign the commitment
        let sevs_sig = keypair.sign(commitment.hash.as_bytes());
        let signature = crate::crypto::TxSignature::new(sevs_sig, keypair.pubkey());

        let encrypted = EncryptedTransaction {
            ciphertext,
            commitment,
            sender: keypair.address(),
            signature,
            validity_proof: None,
        };

        let reveal_key = RevealKey {
            key,
            commitment_hash: encrypted.commitment.hash,
        };

        Ok((encrypted, reveal_key))
    }

    /// XOR encryption (for demonstration - use proper crypto in production)
    fn xor_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 32])
            .collect()
    }

    /// Verify the sender signature
    pub fn verify_sender(&self) -> bool {
        self.signature.verify(self.commitment.hash.as_bytes())
    }

    /// Get the commitment hash
    pub fn commitment_hash(&self) -> Hash {
        self.commitment.hash
    }
}

/// Commitment to a transaction (hash of encrypted tx + nonce)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionCommitment {
    /// Commitment hash
    pub hash: Hash,
    /// Submission slot
    pub slot: Slot,
    /// Timestamp
    pub timestamp: u64,
}

impl TransactionCommitment {
    /// Create a commitment
    pub fn create(ciphertext: &[u8], key: &[u8; 32]) -> Self {
        // commitment = H(ciphertext || key)
        let mut hasher = Sha256::new();
        hasher.update(ciphertext);
        hasher.update(key);
        let hash_bytes: [u8; 32] = hasher.finalize().into();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        TransactionCommitment {
            hash: Hash::new(hash_bytes),
            slot: 0, // Set when committed
            timestamp: now,
        }
    }

    /// Verify commitment matches encrypted data and key
    pub fn verify(&self, ciphertext: &[u8], key: &[u8; 32]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(ciphertext);
        hasher.update(key);
        let expected: [u8; 32] = hasher.finalize().into();

        self.hash.as_bytes() == &expected
    }
}

/// Key to reveal an encrypted transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealKey {
    /// Decryption key
    pub key: [u8; 32],
    /// Commitment hash this reveals
    pub commitment_hash: Hash,
}

impl RevealKey {
    /// Create a reveal message to sign
    pub fn reveal_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(64);
        msg.extend_from_slice(self.commitment_hash.as_bytes());
        msg.extend_from_slice(&self.key);
        msg
    }
}

/// Revealed transaction ready for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealedTransaction {
    /// The decrypted transaction
    pub transaction: Transaction,
    /// Original commitment
    pub commitment: TransactionCommitment,
    /// Slot revealed at
    pub reveal_slot: Slot,
    /// Sender who committed
    pub sender: Pubkey,
}

/// Pending commitment state
#[derive(Debug, Clone)]
struct PendingCommitment {
    encrypted: EncryptedTransaction,
    committed_slot: Slot,
    status: CommitmentStatus,
}

/// Commitment status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitmentStatus {
    Pending,
    Committed,
    Revealed,
    Expired,
}

/// Commit-Reveal Orderer
pub struct CommitRevealOrderer {
    /// Configuration
    config: CommitRevealConfig,
    /// Pending commitments by hash
    pending: RwLock<HashMap<Hash, PendingCommitment>>,
    /// Revealed transactions ready for execution
    revealed: RwLock<Vec<RevealedTransaction>>,
    /// Statistics
    stats: CommitRevealStats,
    /// Current slot
    current_slot: AtomicU64,
}

/// Statistics
#[derive(Debug, Default)]
struct CommitRevealStats {
    total_committed: AtomicU64,
    total_revealed: AtomicU64,
    total_expired: AtomicU64,
    invalid_reveals: AtomicU64,
}

impl CommitRevealOrderer {
    /// Create a new commit-reveal orderer
    pub fn new(config: CommitRevealConfig) -> Self {
        Self {
            config,
            pending: RwLock::new(HashMap::new()),
            revealed: RwLock::new(Vec::new()),
            stats: CommitRevealStats::default(),
            current_slot: AtomicU64::new(0),
        }
    }

    /// Update current slot
    pub fn set_slot(&self, slot: Slot) {
        self.current_slot.store(slot, AtomicOrdering::SeqCst);
    }

    /// Submit an encrypted transaction (commit phase)
    pub fn commit(
        &self,
        encrypted: EncryptedTransaction,
    ) -> Result<Hash, CommitRevealError> {
        // Verify sender signature
        if !encrypted.verify_sender() {
            return Err(CommitRevealError::InvalidSignature);
        }

        // Check capacity
        let mut pending = self.pending.write();
        if pending.len() >= self.config.max_pending {
            return Err(CommitRevealError::CapacityExceeded);
        }

        let commitment_hash = encrypted.commitment_hash();

        // Check for duplicate
        if pending.contains_key(&commitment_hash) {
            return Err(CommitRevealError::DuplicateCommitment);
        }

        let current_slot = self.current_slot.load(AtomicOrdering::SeqCst);

        let commitment = PendingCommitment {
            encrypted,
            committed_slot: current_slot,
            status: CommitmentStatus::Committed,
        };

        pending.insert(commitment_hash, commitment);
        self.stats.total_committed.fetch_add(1, AtomicOrdering::Relaxed);

        Ok(commitment_hash)
    }

    /// Reveal a committed transaction
    pub fn reveal(
        &self,
        reveal_key: RevealKey,
    ) -> Result<RevealedTransaction, CommitRevealError> {
        let current_slot = self.current_slot.load(AtomicOrdering::SeqCst);

        let mut pending = self.pending.write();

        let commitment = pending.get_mut(&reveal_key.commitment_hash)
            .ok_or(CommitRevealError::CommitmentNotFound)?;

        // Check reveal timing
        let slots_since_commit = current_slot.saturating_sub(commitment.committed_slot);

        if slots_since_commit < self.config.min_reveal_delay {
            return Err(CommitRevealError::RevealTooEarly);
        }

        if slots_since_commit > self.config.max_reveal_delay {
            commitment.status = CommitmentStatus::Expired;
            self.stats.total_expired.fetch_add(1, AtomicOrdering::Relaxed);
            return Err(CommitRevealError::RevealTooLate);
        }

        // Verify commitment matches
        if !commitment.encrypted.commitment.verify(
            &commitment.encrypted.ciphertext,
            &reveal_key.key,
        ) {
            self.stats.invalid_reveals.fetch_add(1, AtomicOrdering::Relaxed);
            return Err(CommitRevealError::InvalidReveal);
        }

        // Decrypt transaction
        let tx_bytes = EncryptedTransaction::xor_encrypt(
            &commitment.encrypted.ciphertext,
            &reveal_key.key,
        );

        let transaction: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|_| CommitRevealError::DecryptionFailed)?;

        // Verify transaction
        if !transaction.verify() {
            return Err(CommitRevealError::InvalidTransaction);
        }

        // Create revealed transaction
        let revealed = RevealedTransaction {
            transaction,
            commitment: commitment.encrypted.commitment.clone(),
            reveal_slot: current_slot,
            sender: commitment.encrypted.sender,
        };

        // Update status
        commitment.status = CommitmentStatus::Revealed;
        self.stats.total_revealed.fetch_add(1, AtomicOrdering::Relaxed);

        // Add to revealed queue
        self.revealed.write().push(revealed.clone());

        Ok(revealed)
    }

    /// Get revealed transactions for execution
    pub fn take_revealed(&self, max: usize) -> Vec<RevealedTransaction> {
        let mut revealed = self.revealed.write();
        let count = max.min(revealed.len());
        revealed.drain(..count).collect()
    }

    /// Check if a commitment exists
    pub fn has_commitment(&self, hash: &Hash) -> bool {
        self.pending.read().contains_key(hash)
    }

    /// Get commitment status
    pub fn get_commitment_status(&self, hash: &Hash) -> Option<(Slot, bool)> {
        self.pending.read().get(hash).map(|c| {
            (c.committed_slot, c.status == CommitmentStatus::Revealed)
        })
    }

    /// Clean up expired commitments
    pub fn cleanup_expired(&self) {
        let current_slot = self.current_slot.load(AtomicOrdering::SeqCst);
        let expiry_threshold = current_slot.saturating_sub(self.config.commitment_expiry);

        let mut pending = self.pending.write();
        let initial_count = pending.len();

        pending.retain(|_, c| {
            c.committed_slot > expiry_threshold && c.status != CommitmentStatus::Expired
        });

        let removed = initial_count - pending.len();
        if removed > 0 {
            self.stats.total_expired.fetch_add(removed as u64, AtomicOrdering::Relaxed);
        }
    }

    /// Get statistics
    pub fn stats(&self) -> CommitRevealStatistics {
        CommitRevealStatistics {
            total_committed: self.stats.total_committed.load(AtomicOrdering::Relaxed),
            total_revealed: self.stats.total_revealed.load(AtomicOrdering::Relaxed),
            total_expired: self.stats.total_expired.load(AtomicOrdering::Relaxed),
            invalid_reveals: self.stats.invalid_reveals.load(AtomicOrdering::Relaxed),
            pending_count: self.pending.read().len(),
            revealed_count: self.revealed.read().len(),
        }
    }
}

/// Commit-reveal errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum CommitRevealError {
    #[error("Invalid sender signature")]
    InvalidSignature,

    #[error("Maximum pending commitments exceeded")]
    CapacityExceeded,

    #[error("Duplicate commitment")]
    DuplicateCommitment,

    #[error("Commitment not found")]
    CommitmentNotFound,

    #[error("Reveal submitted too early")]
    RevealTooEarly,

    #[error("Reveal submitted too late - commitment expired")]
    RevealTooLate,

    #[error("Invalid reveal - commitment verification failed")]
    InvalidReveal,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid transaction after decryption")]
    InvalidTransaction,

    #[error("Serialization failed")]
    SerializationFailed,

    #[error("Key generation failed")]
    KeyGenerationFailed,
}

/// Commit-reveal statistics
#[derive(Debug, Clone)]
pub struct CommitRevealStatistics {
    pub total_committed: u64,
    pub total_revealed: u64,
    pub total_expired: u64,
    pub invalid_reveals: u64,
    pub pending_count: usize,
    pub revealed_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_transaction(keypair: &Keypair) -> Transaction {
        Transaction::new_transfer(
            keypair,
            Pubkey::new([2u8; 32]),
            100,
            Hash::hash(b"recent_blockhash"),
        )
    }

    #[test]
    fn test_encrypt_decrypt() {
        let keypair = Keypair::generate();
        let tx = create_test_transaction(&keypair);

        let (encrypted, reveal_key) = EncryptedTransaction::encrypt(&tx, &keypair).unwrap();

        // Verify sender
        assert!(encrypted.verify_sender());

        // Decrypt
        let tx_bytes = EncryptedTransaction::xor_encrypt(
            &encrypted.ciphertext,
            &reveal_key.key,
        );

        let decrypted: Transaction = bincode::deserialize(&tx_bytes).unwrap();
        assert!(decrypted.verify());
    }

    #[test]
    fn test_commitment_verification() {
        let keypair = Keypair::generate();
        let tx = create_test_transaction(&keypair);

        let (encrypted, reveal_key) = EncryptedTransaction::encrypt(&tx, &keypair).unwrap();

        // Correct key should verify
        assert!(encrypted.commitment.verify(&encrypted.ciphertext, &reveal_key.key));

        // Wrong key should not verify
        let wrong_key = [0u8; 32];
        assert!(!encrypted.commitment.verify(&encrypted.ciphertext, &wrong_key));
    }

    #[test]
    fn test_commit_reveal_flow() {
        let config = CommitRevealConfig {
            min_reveal_delay: 1,
            max_reveal_delay: 10,
            ..Default::default()
        };
        let orderer = CommitRevealOrderer::new(config);

        let keypair = Keypair::generate();
        let tx = create_test_transaction(&keypair);

        // Commit
        orderer.set_slot(0);
        let (encrypted, reveal_key) = EncryptedTransaction::encrypt(&tx, &keypair).unwrap();
        let commitment_hash = orderer.commit(encrypted).unwrap();

        // Try to reveal too early (same slot)
        let result = orderer.reveal(reveal_key.clone());
        assert!(matches!(result, Err(CommitRevealError::RevealTooEarly)));

        // Advance slot and reveal
        orderer.set_slot(2);
        let revealed = orderer.reveal(reveal_key).unwrap();

        assert!(revealed.transaction.verify());
        assert_eq!(revealed.commitment.hash, commitment_hash);
    }

    #[test]
    fn test_reveal_too_late() {
        let config = CommitRevealConfig {
            min_reveal_delay: 1,
            max_reveal_delay: 5,
            ..Default::default()
        };
        let orderer = CommitRevealOrderer::new(config);

        let keypair = Keypair::generate();
        let tx = create_test_transaction(&keypair);

        // Commit
        orderer.set_slot(0);
        let (encrypted, reveal_key) = EncryptedTransaction::encrypt(&tx, &keypair).unwrap();
        orderer.commit(encrypted).unwrap();

        // Try to reveal too late
        orderer.set_slot(10);
        let result = orderer.reveal(reveal_key);
        assert!(matches!(result, Err(CommitRevealError::RevealTooLate)));
    }

    #[test]
    fn test_duplicate_commitment_rejected() {
        let config = CommitRevealConfig::default();
        let orderer = CommitRevealOrderer::new(config);

        let keypair = Keypair::generate();
        let tx = create_test_transaction(&keypair);

        let (encrypted, _) = EncryptedTransaction::encrypt(&tx, &keypair).unwrap();

        // First commit succeeds
        orderer.commit(encrypted.clone()).unwrap();

        // Duplicate should fail
        let result = orderer.commit(encrypted);
        assert!(matches!(result, Err(CommitRevealError::DuplicateCommitment)));
    }
}
