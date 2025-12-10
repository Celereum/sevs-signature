//! ZK Validity Modules for Celereum
//!
//! Provides zero-knowledge validity proofs for:
//! - Transaction batch validation
//! - State transition correctness
//! - Smart contract execution verification
//! - Account balance integrity
//!
//! SECURITY CONSIDERATIONS:
//! - Proofs are bound to specific inputs
//! - Verification is constant-time to prevent timing attacks
//! - Malleability protection through canonical encoding
//! - Replay protection via nonces and timestamps

use crate::crypto::Hash;
use crate::core::{Transaction, Slot};
use super::proofs::{Proof, ProofType, Prover, ProofSystem, ProofSystemConfig, ProofError};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use parking_lot::RwLock;

/// Maximum transactions per validity proof
/// SECURITY: Limits computational cost and prevents DoS
pub const MAX_TRANSACTIONS_PER_VALIDITY_PROOF: usize = 1000;

/// Maximum age of a validity proof (seconds)
/// SECURITY: Prevents replay of old proofs
pub const VALIDITY_PROOF_MAX_AGE_SECS: u64 = 300; // 5 minutes

/// Minimum time between proof generation for same account
/// SECURITY: Rate limiting to prevent spam
pub const MIN_PROOF_INTERVAL_MS: u64 = 100;

/// Transaction Validity Proof
/// Proves that a batch of transactions is valid without revealing details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionValidityProof {
    /// The underlying ZK proof
    pub proof: Proof,

    /// Merkle root of the transactions
    pub transactions_root: Hash,

    /// Number of transactions validated
    pub transaction_count: u32,

    /// Timestamp when proof was generated
    pub timestamp_ns: u64,

    /// Slot this proof is valid for
    pub valid_for_slot: Slot,

    /// Previous state root
    pub prev_state_root: Hash,

    /// New state root after transactions
    pub new_state_root: Hash,

    /// Nonce for replay protection
    pub nonce: u64,
}

impl TransactionValidityProof {
    /// Verify the proof structure is valid
    /// SECURITY: Basic structural validation before expensive verification
    pub fn validate_structure(&self) -> Result<(), ValidityError> {
        // Check transaction count bounds
        if self.transaction_count == 0 {
            return Err(ValidityError::EmptyBatch);
        }
        if self.transaction_count as usize > MAX_TRANSACTIONS_PER_VALIDITY_PROOF {
            return Err(ValidityError::BatchTooLarge(self.transaction_count as usize));
        }

        // Check timestamp is not in the future
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Allow 10 second tolerance for clock skew
        if self.timestamp_ns > now_ns.saturating_add(10_000_000_000) {
            return Err(ValidityError::FutureTimestamp);
        }

        // Check proof is not too old
        let age_ns = now_ns.saturating_sub(self.timestamp_ns);
        let max_age_ns = VALIDITY_PROOF_MAX_AGE_SECS * 1_000_000_000;
        if age_ns > max_age_ns {
            return Err(ValidityError::ExpiredProof);
        }

        // Check state roots are different (state actually changed)
        if self.prev_state_root == self.new_state_root && self.transaction_count > 0 {
            return Err(ValidityError::NoStateChange);
        }

        Ok(())
    }

    /// Get the public inputs for verification
    pub fn public_inputs(&self) -> Vec<u8> {
        let mut inputs = Vec::new();
        inputs.extend_from_slice(self.transactions_root.as_bytes());
        inputs.extend_from_slice(&self.transaction_count.to_le_bytes());
        inputs.extend_from_slice(&self.valid_for_slot.to_le_bytes());
        inputs.extend_from_slice(self.prev_state_root.as_bytes());
        inputs.extend_from_slice(self.new_state_root.as_bytes());
        inputs.extend_from_slice(&self.nonce.to_le_bytes());
        inputs
    }

    /// Compute proof hash for caching/deduplication
    pub fn hash(&self) -> Hash {
        let data = bincode::serialize(self).unwrap_or_default();
        Hash::hash(&data)
    }
}

/// State Validity Proof
/// Proves the entire state is valid at a given point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateValidityProof {
    /// The underlying ZK proof
    pub proof: Proof,

    /// State root being validated
    pub state_root: Hash,

    /// Slot this state corresponds to
    pub slot: Slot,

    /// Number of accounts in state
    pub account_count: u64,

    /// Total balance across all accounts
    /// SECURITY: Must match sum of individual balances
    pub total_balance: u128,

    /// Timestamp of proof generation
    pub timestamp_ns: u64,

    /// Block hash this state follows
    pub block_hash: Hash,
}

impl StateValidityProof {
    /// Validate structure
    pub fn validate_structure(&self) -> Result<(), ValidityError> {
        // State root cannot be zero
        if self.state_root == Hash::zero() {
            return Err(ValidityError::InvalidStateRoot);
        }

        // Timestamp check
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        if self.timestamp_ns > now_ns.saturating_add(10_000_000_000) {
            return Err(ValidityError::FutureTimestamp);
        }

        let age_ns = now_ns.saturating_sub(self.timestamp_ns);
        let max_age_ns = VALIDITY_PROOF_MAX_AGE_SECS * 1_000_000_000;
        if age_ns > max_age_ns {
            return Err(ValidityError::ExpiredProof);
        }

        Ok(())
    }

    /// Get public inputs
    pub fn public_inputs(&self) -> Vec<u8> {
        let mut inputs = Vec::new();
        inputs.extend_from_slice(self.state_root.as_bytes());
        inputs.extend_from_slice(&self.slot.to_le_bytes());
        inputs.extend_from_slice(&self.account_count.to_le_bytes());
        inputs.extend_from_slice(&self.total_balance.to_le_bytes());
        inputs.extend_from_slice(self.block_hash.as_bytes());
        inputs
    }
}

/// Contract Execution Validity Proof
/// Proves a smart contract executed correctly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionValidityProof {
    /// The underlying ZK proof
    pub proof: Proof,

    /// Contract program ID
    pub program_id: Hash,

    /// Hash of instruction data
    pub instruction_hash: Hash,

    /// Input accounts merkle root
    pub input_accounts_root: Hash,

    /// Output accounts merkle root
    pub output_accounts_root: Hash,

    /// Compute units consumed
    pub compute_units: u64,

    /// Execution was successful
    pub success: bool,

    /// Timestamp
    pub timestamp_ns: u64,
}

impl ExecutionValidityProof {
    /// Validate structure
    pub fn validate_structure(&self) -> Result<(), ValidityError> {
        // Program ID cannot be zero
        if self.program_id == Hash::zero() {
            return Err(ValidityError::InvalidProgramId);
        }

        // Timestamp check
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        if self.timestamp_ns > now_ns.saturating_add(10_000_000_000) {
            return Err(ValidityError::FutureTimestamp);
        }

        Ok(())
    }

    /// Get public inputs
    pub fn public_inputs(&self) -> Vec<u8> {
        let mut inputs = Vec::new();
        inputs.extend_from_slice(self.program_id.as_bytes());
        inputs.extend_from_slice(self.instruction_hash.as_bytes());
        inputs.extend_from_slice(self.input_accounts_root.as_bytes());
        inputs.extend_from_slice(self.output_accounts_root.as_bytes());
        inputs.extend_from_slice(&self.compute_units.to_le_bytes());
        inputs.push(if self.success { 1 } else { 0 });
        inputs
    }
}

/// Validity Proof Generator
/// Creates zero-knowledge validity proofs for various operations
#[derive(Debug)]
pub struct ValidityProofGenerator {
    /// Underlying proof system
    proof_system: ProofSystem,
    /// Prover instance
    prover: Prover,
    /// Last proof generation time per account (for rate limiting)
    last_proof_times: Arc<RwLock<std::collections::HashMap<Hash, Instant>>>,
    /// Current nonce
    nonce: std::sync::atomic::AtomicU64,
}

impl ValidityProofGenerator {
    /// Create a new validity proof generator
    pub fn new() -> Self {
        let config = ProofSystemConfig {
            security_bits: 128,
            max_constraints: 1_000_000,
            parallel: true,
        };
        let proof_system = ProofSystem::new(config);
        let prover = Prover::new(ProofSystem::new(ProofSystemConfig::default()));

        Self {
            proof_system,
            prover,
            last_proof_times: Arc::new(RwLock::new(std::collections::HashMap::new())),
            nonce: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Check rate limiting for an account
    /// SECURITY: Prevents proof generation spam
    fn check_rate_limit(&self, account_hash: &Hash) -> Result<(), ValidityError> {
        let times = self.last_proof_times.read();
        if let Some(last_time) = times.get(account_hash) {
            if last_time.elapsed() < Duration::from_millis(MIN_PROOF_INTERVAL_MS) {
                return Err(ValidityError::RateLimited);
            }
        }
        Ok(())
    }

    /// Update rate limit tracker
    fn update_rate_limit(&self, account_hash: Hash) {
        let mut times = self.last_proof_times.write();
        times.insert(account_hash, Instant::now());

        // Cleanup old entries (> 1 minute old)
        times.retain(|_, time| time.elapsed() < Duration::from_secs(60));
    }

    /// Get next nonce
    fn next_nonce(&self) -> u64 {
        self.nonce.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Generate a transaction validity proof
    pub fn generate_transaction_proof(
        &self,
        transactions: &[Transaction],
        slot: Slot,
        prev_state_root: Hash,
        new_state_root: Hash,
    ) -> Result<TransactionValidityProof, ValidityError> {
        // Validate input
        if transactions.is_empty() {
            return Err(ValidityError::EmptyBatch);
        }
        if transactions.len() > MAX_TRANSACTIONS_PER_VALIDITY_PROOF {
            return Err(ValidityError::BatchTooLarge(transactions.len()));
        }

        // Check rate limit
        let batch_hash = self.compute_batch_hash(transactions);
        self.check_rate_limit(&batch_hash)?;

        // Compute transactions root
        let transactions_root = self.compute_transactions_root(transactions);

        // Get nonce first so we can include it in public inputs
        let nonce = self.next_nonce();

        // Create witness data (private inputs)
        let witness = self.create_transaction_witness(transactions, prev_state_root, new_state_root);

        // Create public inputs - must match public_inputs() method
        let mut public_inputs = Vec::new();
        public_inputs.extend_from_slice(transactions_root.as_bytes());
        public_inputs.extend_from_slice(&(transactions.len() as u32).to_le_bytes());
        public_inputs.extend_from_slice(&slot.to_le_bytes());
        public_inputs.extend_from_slice(prev_state_root.as_bytes());
        public_inputs.extend_from_slice(new_state_root.as_bytes());
        public_inputs.extend_from_slice(&nonce.to_le_bytes());

        // Generate proof
        let proof = self.prover.prove(&public_inputs, &witness, ProofType::StateTransition)
            .map_err(|e| ValidityError::ProofGenerationFailed(e.to_string()))?;

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Update rate limit
        self.update_rate_limit(batch_hash);

        Ok(TransactionValidityProof {
            proof,
            transactions_root,
            transaction_count: transactions.len() as u32,
            timestamp_ns,
            valid_for_slot: slot,
            prev_state_root,
            new_state_root,
            nonce,
        })
    }

    /// Generate a state validity proof
    pub fn generate_state_proof(
        &self,
        state_root: Hash,
        slot: Slot,
        account_count: u64,
        total_balance: u128,
        block_hash: Hash,
    ) -> Result<StateValidityProof, ValidityError> {
        // Validate inputs
        if state_root == Hash::zero() {
            return Err(ValidityError::InvalidStateRoot);
        }

        // Create witness
        let mut witness = Vec::new();
        witness.extend_from_slice(state_root.as_bytes());
        witness.extend_from_slice(&slot.to_le_bytes());
        witness.extend_from_slice(&account_count.to_le_bytes());
        witness.extend_from_slice(&total_balance.to_le_bytes());
        witness.extend_from_slice(block_hash.as_bytes());
        // Add some entropy
        let entropy = Hash::hash(&witness);
        witness.extend_from_slice(entropy.as_bytes());

        // Create public inputs
        let mut public_inputs = Vec::new();
        public_inputs.extend_from_slice(state_root.as_bytes());
        public_inputs.extend_from_slice(&slot.to_le_bytes());
        public_inputs.extend_from_slice(&account_count.to_le_bytes());
        public_inputs.extend_from_slice(&total_balance.to_le_bytes());
        public_inputs.extend_from_slice(block_hash.as_bytes());

        // Generate proof
        let proof = self.prover.prove(&public_inputs, &witness, ProofType::StateTransition)
            .map_err(|e| ValidityError::ProofGenerationFailed(e.to_string()))?;

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Ok(StateValidityProof {
            proof,
            state_root,
            slot,
            account_count,
            total_balance,
            timestamp_ns,
            block_hash,
        })
    }

    /// Generate execution validity proof
    pub fn generate_execution_proof(
        &self,
        program_id: Hash,
        instruction_data: &[u8],
        input_accounts: &[Hash],
        output_accounts: &[Hash],
        compute_units: u64,
        success: bool,
    ) -> Result<ExecutionValidityProof, ValidityError> {
        // Validate inputs
        if program_id == Hash::zero() {
            return Err(ValidityError::InvalidProgramId);
        }

        let instruction_hash = Hash::hash(instruction_data);
        let input_accounts_root = self.compute_accounts_root(input_accounts);
        let output_accounts_root = self.compute_accounts_root(output_accounts);

        // Create witness
        let mut witness = Vec::new();
        witness.extend_from_slice(program_id.as_bytes());
        witness.extend_from_slice(instruction_data);
        for acc in input_accounts {
            witness.extend_from_slice(acc.as_bytes());
        }
        for acc in output_accounts {
            witness.extend_from_slice(acc.as_bytes());
        }
        witness.extend_from_slice(&compute_units.to_le_bytes());
        witness.push(if success { 1 } else { 0 });

        // Create public inputs
        let mut public_inputs = Vec::new();
        public_inputs.extend_from_slice(program_id.as_bytes());
        public_inputs.extend_from_slice(instruction_hash.as_bytes());
        public_inputs.extend_from_slice(input_accounts_root.as_bytes());
        public_inputs.extend_from_slice(output_accounts_root.as_bytes());
        public_inputs.extend_from_slice(&compute_units.to_le_bytes());
        public_inputs.push(if success { 1 } else { 0 });

        // Generate proof
        let proof = self.prover.prove(&public_inputs, &witness, ProofType::StateTransition)
            .map_err(|e| ValidityError::ProofGenerationFailed(e.to_string()))?;

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Ok(ExecutionValidityProof {
            proof,
            program_id,
            instruction_hash,
            input_accounts_root,
            output_accounts_root,
            compute_units,
            success,
            timestamp_ns,
        })
    }

    /// Compute merkle root of transactions
    fn compute_transactions_root(&self, transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::zero();
        }

        let mut hashes: Vec<Hash> = transactions.iter().map(|tx| tx.hash()).collect();

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

    /// Compute merkle root of accounts
    fn compute_accounts_root(&self, accounts: &[Hash]) -> Hash {
        if accounts.is_empty() {
            return Hash::zero();
        }

        let mut hashes = accounts.to_vec();

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

    /// Compute batch hash for rate limiting
    fn compute_batch_hash(&self, transactions: &[Transaction]) -> Hash {
        let mut data = Vec::new();
        for tx in transactions {
            data.extend_from_slice(tx.hash().as_bytes());
        }
        Hash::hash(&data)
    }

    /// Create witness data for transactions
    fn create_transaction_witness(
        &self,
        transactions: &[Transaction],
        prev_state: Hash,
        new_state: Hash,
    ) -> Vec<u8> {
        let mut witness = Vec::new();

        // Add state roots
        witness.extend_from_slice(prev_state.as_bytes());
        witness.extend_from_slice(new_state.as_bytes());

        // Add each transaction's data
        for tx in transactions {
            witness.extend_from_slice(tx.hash().as_bytes());
            // Include signature data for witness
            for sig in &tx.signatures {
                witness.extend_from_slice(sig.signature.as_bytes());
            }
        }

        // Add entropy
        let entropy = Hash::hash(&witness);
        witness.extend_from_slice(entropy.as_bytes());

        witness
    }
}

impl Default for ValidityProofGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Validity Proof Verifier
/// Verifies zero-knowledge validity proofs
#[derive(Debug)]
pub struct ValidityProofVerifier {
    /// Verification key
    verification_key: Vec<u8>,
}

impl ValidityProofVerifier {
    /// Create a new verifier
    pub fn new() -> Self {
        let verification_key = Hash::hash(b"celereum_verification_key").as_bytes().to_vec();
        Self { verification_key }
    }

    /// Verify a transaction validity proof
    pub fn verify_transaction_proof(
        &self,
        proof: &TransactionValidityProof,
    ) -> Result<bool, ValidityError> {
        // First validate structure
        proof.validate_structure()?;

        // Get public inputs
        let public_inputs = proof.public_inputs();

        // Verify the underlying ZK proof
        let verifier = super::proofs::Verifier::new(self.verification_key.clone());
        verifier.verify(&proof.proof, &public_inputs)
            .map_err(|e| ValidityError::VerificationFailed(e.to_string()))
    }

    /// Verify a state validity proof
    pub fn verify_state_proof(
        &self,
        proof: &StateValidityProof,
    ) -> Result<bool, ValidityError> {
        // Validate structure
        proof.validate_structure()?;

        // Get public inputs
        let public_inputs = proof.public_inputs();

        // Verify
        let verifier = super::proofs::Verifier::new(self.verification_key.clone());
        verifier.verify(&proof.proof, &public_inputs)
            .map_err(|e| ValidityError::VerificationFailed(e.to_string()))
    }

    /// Verify an execution validity proof
    pub fn verify_execution_proof(
        &self,
        proof: &ExecutionValidityProof,
    ) -> Result<bool, ValidityError> {
        // Validate structure
        proof.validate_structure()?;

        // Get public inputs
        let public_inputs = proof.public_inputs();

        // Verify
        let verifier = super::proofs::Verifier::new(self.verification_key.clone());
        verifier.verify(&proof.proof, &public_inputs)
            .map_err(|e| ValidityError::VerificationFailed(e.to_string()))
    }

    /// Batch verify multiple proofs
    pub fn verify_batch(
        &self,
        tx_proofs: &[TransactionValidityProof],
    ) -> Vec<Result<bool, ValidityError>> {
        tx_proofs.iter().map(|p| self.verify_transaction_proof(p)).collect()
    }
}

impl Default for ValidityProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Validity Module Errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidityError {
    #[error("Empty transaction batch")]
    EmptyBatch,

    #[error("Batch too large: {0} transactions (max {})", MAX_TRANSACTIONS_PER_VALIDITY_PROOF)]
    BatchTooLarge(usize),

    #[error("Timestamp is in the future")]
    FutureTimestamp,

    #[error("Proof has expired")]
    ExpiredProof,

    #[error("No state change detected")]
    NoStateChange,

    #[error("Invalid state root")]
    InvalidStateRoot,

    #[error("Invalid program ID")]
    InvalidProgramId,

    #[error("Rate limited - too many proof requests")]
    RateLimited,

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid proof structure")]
    InvalidProofStructure,
}

/// Validity Predicate
/// Defines custom validation logic that can be proven in ZK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityPredicate {
    /// Predicate identifier
    pub id: Hash,

    /// Type of predicate
    pub predicate_type: PredicateType,

    /// Constraints that must be satisfied
    pub constraints: Vec<Constraint>,

    /// Whether this predicate is mandatory
    pub mandatory: bool,
}

/// Types of validity predicates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredicateType {
    /// Balance must be non-negative
    NonNegativeBalance,
    /// Total supply conservation
    SupplyConservation,
    /// Signature verification
    SignatureValid,
    /// Nonce increment
    NonceIncrement,
    /// Custom program logic
    CustomProgram,
}

/// A constraint in a validity predicate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    /// Constraint type
    pub constraint_type: ConstraintType,
    /// Left operand
    pub left: Operand,
    /// Right operand
    pub right: Operand,
}

/// Types of constraints
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintType {
    Equal,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
}

/// Operand in a constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operand {
    /// A constant value
    Constant(u64),
    /// Account balance at index
    AccountBalance(u8),
    /// Account nonce at index
    AccountNonce(u8),
    /// Sum of values
    Sum(Vec<Box<Operand>>),
    /// Difference of values
    Diff(Box<Operand>, Box<Operand>),
}

impl ValidityPredicate {
    /// Create a non-negative balance predicate
    pub fn non_negative_balance(account_index: u8) -> Self {
        let mut id_data = b"non_negative_balance".to_vec();
        id_data.push(account_index);
        Self {
            id: Hash::hash(&id_data),
            predicate_type: PredicateType::NonNegativeBalance,
            constraints: vec![
                Constraint {
                    constraint_type: ConstraintType::GreaterOrEqual,
                    left: Operand::AccountBalance(account_index),
                    right: Operand::Constant(0),
                }
            ],
            mandatory: true,
        }
    }

    /// Create a supply conservation predicate
    pub fn supply_conservation(input_indices: Vec<u8>, output_indices: Vec<u8>) -> Self {
        let inputs: Vec<Box<Operand>> = input_indices
            .iter()
            .map(|&i| Box::new(Operand::AccountBalance(i)))
            .collect();

        let outputs: Vec<Box<Operand>> = output_indices
            .iter()
            .map(|&i| Box::new(Operand::AccountBalance(i)))
            .collect();

        Self {
            id: Hash::hash(b"supply_conservation"),
            predicate_type: PredicateType::SupplyConservation,
            constraints: vec![
                Constraint {
                    constraint_type: ConstraintType::Equal,
                    left: Operand::Sum(inputs),
                    right: Operand::Sum(outputs),
                }
            ],
            mandatory: true,
        }
    }

    /// Create a nonce increment predicate
    pub fn nonce_increment(old_nonce_index: u8, new_nonce_index: u8) -> Self {
        Self {
            id: Hash::hash(b"nonce_increment"),
            predicate_type: PredicateType::NonceIncrement,
            constraints: vec![
                Constraint {
                    constraint_type: ConstraintType::Equal,
                    left: Operand::AccountNonce(new_nonce_index),
                    right: Operand::Sum(vec![
                        Box::new(Operand::AccountNonce(old_nonce_index)),
                        Box::new(Operand::Constant(1)),
                    ]),
                }
            ],
            mandatory: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn create_test_transaction(keypair: &Keypair) -> Transaction {
        Transaction::new_transfer(
            keypair,
            Keypair::generate().address(),
            1000,
            Hash::hash(b"blockhash"),
        )
    }

    #[test]
    fn test_transaction_validity_proof_generation() {
        let generator = ValidityProofGenerator::new();
        let keypair = Keypair::generate();

        let transactions: Vec<Transaction> = (0..5)
            .map(|_| create_test_transaction(&keypair))
            .collect();

        let prev_state = Hash::hash(b"prev_state");
        let new_state = Hash::hash(b"new_state");

        let proof = generator.generate_transaction_proof(
            &transactions,
            100,
            prev_state,
            new_state,
        );

        assert!(proof.is_ok());
        let proof = proof.unwrap();
        assert_eq!(proof.transaction_count, 5);
        assert_eq!(proof.valid_for_slot, 100);
    }

    #[test]
    fn test_transaction_validity_proof_verification() {
        let generator = ValidityProofGenerator::new();
        let verifier = ValidityProofVerifier::new();
        let keypair = Keypair::generate();

        let transactions: Vec<Transaction> = (0..3)
            .map(|_| create_test_transaction(&keypair))
            .collect();

        let prev_state = Hash::hash(b"prev");
        let new_state = Hash::hash(b"new");

        let proof = generator.generate_transaction_proof(
            &transactions,
            50,
            prev_state,
            new_state,
        ).unwrap();

        let result = verifier.verify_transaction_proof(&proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_state_validity_proof() {
        let generator = ValidityProofGenerator::new();
        let verifier = ValidityProofVerifier::new();

        let state_root = Hash::hash(b"state");
        let block_hash = Hash::hash(b"block");

        let proof = generator.generate_state_proof(
            state_root,
            100,
            1000,
            1_000_000_000,
            block_hash,
        ).unwrap();

        let result = verifier.verify_state_proof(&proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_execution_validity_proof() {
        let generator = ValidityProofGenerator::new();
        let verifier = ValidityProofVerifier::new();

        let program_id = Hash::hash(b"program");
        let instruction = b"transfer 100 tokens";
        let input_accounts = vec![Hash::hash(b"acc1"), Hash::hash(b"acc2")];
        let output_accounts = vec![Hash::hash(b"acc1_new"), Hash::hash(b"acc2_new")];

        let proof = generator.generate_execution_proof(
            program_id,
            instruction,
            &input_accounts,
            &output_accounts,
            10000,
            true,
        ).unwrap();

        let result = verifier.verify_execution_proof(&proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_empty_batch_rejected() {
        let generator = ValidityProofGenerator::new();

        let result = generator.generate_transaction_proof(
            &[],
            0,
            Hash::zero(),
            Hash::zero(),
        );

        assert!(matches!(result, Err(ValidityError::EmptyBatch)));
    }

    #[test]
    fn test_batch_too_large_rejected() {
        let generator = ValidityProofGenerator::new();
        let keypair = Keypair::generate();

        // Create more transactions than allowed
        let transactions: Vec<Transaction> = (0..MAX_TRANSACTIONS_PER_VALIDITY_PROOF + 1)
            .map(|_| create_test_transaction(&keypair))
            .collect();

        let result = generator.generate_transaction_proof(
            &transactions,
            0,
            Hash::hash(b"prev"),
            Hash::hash(b"new"),
        );

        assert!(matches!(result, Err(ValidityError::BatchTooLarge(_))));
    }

    #[test]
    fn test_validity_predicates() {
        // Test non-negative balance predicate
        let predicate = ValidityPredicate::non_negative_balance(0);
        assert_eq!(predicate.predicate_type, PredicateType::NonNegativeBalance);
        assert!(predicate.mandatory);
        assert_eq!(predicate.constraints.len(), 1);

        // Test supply conservation predicate
        let predicate = ValidityPredicate::supply_conservation(
            vec![0, 1],
            vec![2, 3],
        );
        assert_eq!(predicate.predicate_type, PredicateType::SupplyConservation);

        // Test nonce increment predicate
        let predicate = ValidityPredicate::nonce_increment(0, 1);
        assert_eq!(predicate.predicate_type, PredicateType::NonceIncrement);
    }

    #[test]
    fn test_proof_structure_validation() {
        let generator = ValidityProofGenerator::new();
        let keypair = Keypair::generate();

        let transactions: Vec<Transaction> = (0..3)
            .map(|_| create_test_transaction(&keypair))
            .collect();

        let proof = generator.generate_transaction_proof(
            &transactions,
            100,
            Hash::hash(b"prev"),
            Hash::hash(b"new"),
        ).unwrap();

        // Structure should be valid
        assert!(proof.validate_structure().is_ok());
    }

    #[test]
    fn test_invalid_state_root_rejected() {
        let generator = ValidityProofGenerator::new();

        let result = generator.generate_state_proof(
            Hash::zero(), // Invalid
            0,
            0,
            0,
            Hash::zero(),
        );

        assert!(matches!(result, Err(ValidityError::InvalidStateRoot)));
    }

    #[test]
    fn test_invalid_program_id_rejected() {
        let generator = ValidityProofGenerator::new();

        let result = generator.generate_execution_proof(
            Hash::zero(), // Invalid
            b"test",
            &[],
            &[],
            0,
            true,
        );

        assert!(matches!(result, Err(ValidityError::InvalidProgramId)));
    }
}
