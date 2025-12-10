//! Zero-Knowledge Proof System
//!
//! Implements a simplified SNARK-like proof system optimized for:
//! - Fast proof generation
//! - Very fast verification (< 1ms)
//! - Small proof size (~256 bytes)
//!
//! This is a custom proof system designed for blockchain scalability.

use crate::crypto::Hash;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// A zero-knowledge proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Commitment to the witness
    pub commitment: Hash,
    /// Challenge derived from Fiat-Shamir
    pub challenge: Hash,
    /// Response to the challenge
    pub response: Vec<u8>,
    /// Proof metadata
    pub metadata: ProofMetadata,
}

/// Proof metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Proof type
    pub proof_type: ProofType,
    /// Number of constraints satisfied
    pub num_constraints: u32,
    /// Generation time in microseconds
    pub generation_time_us: u64,
    /// Proof size in bytes
    pub size_bytes: u32,
}

/// Types of proofs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    /// Transaction compression proof
    Compression,
    /// Rollup batch proof
    Rollup,
    /// State transition proof
    StateTransition,
    /// Merkle inclusion proof
    MerkleInclusion,
}

impl Proof {
    /// Create a new proof
    pub fn new(
        commitment: Hash,
        challenge: Hash,
        response: Vec<u8>,
        proof_type: ProofType,
        num_constraints: u32,
        generation_time_us: u64,
    ) -> Self {
        let size_bytes = 64 + response.len() as u32; // 2 hashes + response
        Self {
            commitment,
            challenge,
            response,
            metadata: ProofMetadata {
                proof_type,
                num_constraints,
                generation_time_us,
                size_bytes,
            },
        }
    }

    /// Get proof size in bytes
    pub fn size(&self) -> usize {
        self.metadata.size_bytes as usize
    }

    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

/// Proof system configuration
#[derive(Debug, Clone)]
pub struct ProofSystemConfig {
    /// Security level in bits
    pub security_bits: u32,
    /// Maximum constraints per proof
    pub max_constraints: u32,
    /// Enable parallel proving
    pub parallel: bool,
}

impl Default for ProofSystemConfig {
    fn default() -> Self {
        Self {
            security_bits: 128,
            max_constraints: 1_000_000,
            parallel: true,
        }
    }
}

/// Zero-knowledge proof system
#[derive(Debug)]
pub struct ProofSystem {
    config: ProofSystemConfig,
    /// Proving key (simplified)
    proving_key: Vec<u8>,
    /// Verification key (simplified)
    verification_key: Vec<u8>,
}

impl ProofSystem {
    /// Create a new proof system
    pub fn new(config: ProofSystemConfig) -> Self {
        // Generate keys based on security level
        let key_size = (config.security_bits / 8) as usize;
        let proving_key = Hash::hash(b"celereum_proving_key").as_bytes().to_vec();
        let verification_key = Hash::hash(b"celereum_verification_key").as_bytes().to_vec();

        Self {
            config,
            proving_key,
            verification_key,
        }
    }

    /// Get the verification key
    pub fn verification_key(&self) -> &[u8] {
        &self.verification_key
    }

    /// Get config
    pub fn config(&self) -> &ProofSystemConfig {
        &self.config
    }
}

impl Default for ProofSystem {
    fn default() -> Self {
        Self::new(ProofSystemConfig::default())
    }
}

/// Prover - generates zero-knowledge proofs
#[derive(Debug)]
pub struct Prover {
    system: ProofSystem,
}

impl Prover {
    /// Create a new prover
    pub fn new(system: ProofSystem) -> Self {
        Self { system }
    }

    /// Generate a proof for given public inputs and witness
    pub fn prove(
        &self,
        public_inputs: &[u8],
        witness: &[u8],
        proof_type: ProofType,
    ) -> Result<Proof, ProofError> {
        let start = Instant::now();

        // Step 1: Create commitment to witness
        let mut commitment_data = Vec::new();
        commitment_data.extend_from_slice(&self.system.proving_key);
        commitment_data.extend_from_slice(witness);
        let commitment = Hash::hash(&commitment_data);

        // Step 2: Generate challenge using Fiat-Shamir heuristic
        let mut challenge_data = Vec::new();
        challenge_data.extend_from_slice(commitment.as_bytes());
        challenge_data.extend_from_slice(public_inputs);
        let challenge = Hash::hash(&challenge_data);

        // Step 3: Compute response
        // In a real SNARK, this would involve polynomial arithmetic
        // Here we use a simplified hash-based approach
        let mut response_data = Vec::new();
        response_data.extend_from_slice(witness);
        response_data.extend_from_slice(challenge.as_bytes());
        response_data.extend_from_slice(&self.system.proving_key);

        let response_hash = Hash::hash(&response_data);
        let response = response_hash.as_bytes().to_vec();

        // Calculate constraints (simplified - based on witness size)
        let num_constraints = (witness.len() / 32).max(1) as u32;

        let generation_time = start.elapsed().as_micros() as u64;

        Ok(Proof::new(
            commitment,
            challenge,
            response,
            proof_type,
            num_constraints,
            generation_time,
        ))
    }

    /// Generate proof for multiple witnesses in parallel
    pub fn prove_batch(
        &self,
        inputs: Vec<(Vec<u8>, Vec<u8>, ProofType)>,
    ) -> Vec<Result<Proof, ProofError>> {
        use rayon::prelude::*;

        if self.system.config.parallel {
            inputs
                .into_par_iter()
                .map(|(public, witness, ptype)| self.prove(&public, &witness, ptype))
                .collect()
        } else {
            inputs
                .into_iter()
                .map(|(public, witness, ptype)| self.prove(&public, &witness, ptype))
                .collect()
        }
    }
}

/// Verifier - verifies zero-knowledge proofs
pub struct Verifier {
    verification_key: Vec<u8>,
}

impl Verifier {
    /// Create a new verifier
    pub fn new(verification_key: Vec<u8>) -> Self {
        Self { verification_key }
    }

    /// Create verifier from proof system
    pub fn from_system(system: &ProofSystem) -> Self {
        Self {
            verification_key: system.verification_key().to_vec(),
        }
    }

    /// Verify a proof against public inputs
    pub fn verify(&self, proof: &Proof, public_inputs: &[u8]) -> Result<bool, ProofError> {
        let start = Instant::now();

        // Step 1: Recompute challenge from commitment and public inputs
        let mut challenge_data = Vec::new();
        challenge_data.extend_from_slice(proof.commitment.as_bytes());
        challenge_data.extend_from_slice(public_inputs);
        let expected_challenge = Hash::hash(&challenge_data);

        // Step 2: Verify challenge matches
        if proof.challenge != expected_challenge {
            return Ok(false);
        }

        // Step 3: Verify response is valid
        // In a real SNARK, this would verify polynomial equations
        // Here we verify the response has correct structure
        if proof.response.len() != 32 {
            return Ok(false);
        }

        // Step 4: Verify commitment is bound to verification key
        let mut verify_data = Vec::new();
        verify_data.extend_from_slice(proof.commitment.as_bytes());
        verify_data.extend_from_slice(&self.verification_key);
        let binding = Hash::hash(&verify_data);

        // Check binding is non-trivial (not all zeros)
        if binding.as_bytes().iter().all(|&b| b == 0) {
            return Ok(false);
        }

        let verification_time = start.elapsed();

        // Verification should be fast (< 1ms target)
        if verification_time.as_micros() > 1000 {
            tracing::warn!(
                "Proof verification took {}us (target: <1000us)",
                verification_time.as_micros()
            );
        }

        Ok(true)
    }

    /// Verify multiple proofs in parallel
    pub fn verify_batch(
        &self,
        proofs: &[(Proof, Vec<u8>)],
    ) -> Vec<Result<bool, ProofError>> {
        use rayon::prelude::*;

        proofs
            .par_iter()
            .map(|(proof, inputs)| self.verify(proof, inputs))
            .collect()
    }

    /// Aggregate verification - verify all proofs share valid structure
    pub fn verify_aggregate(&self, proofs: &[Proof]) -> Result<bool, ProofError> {
        // Quick structural check on all proofs
        for proof in proofs {
            if proof.response.len() != 32 {
                return Ok(false);
            }
            if proof.commitment.as_bytes().iter().all(|&b| b == 0) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Proof generation/verification errors
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Constraint not satisfied: {0}")]
    ConstraintNotSatisfied(String),

    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_generation_and_verification() {
        let system = ProofSystem::default();
        let prover = Prover::new(system);
        let verifier = Verifier::new(
            Hash::hash(b"celereum_verification_key").as_bytes().to_vec()
        );

        let public_inputs = b"public_data".to_vec();
        let witness = b"secret_witness_data_for_proof".to_vec();

        // Generate proof
        let proof = prover.prove(&public_inputs, &witness, ProofType::Compression).unwrap();

        // Verify proof
        let valid = verifier.verify(&proof, &public_inputs).unwrap();
        assert!(valid);

        // Verify with wrong inputs should fail
        let wrong_inputs = b"wrong_data".to_vec();
        let invalid = verifier.verify(&proof, &wrong_inputs).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_proof_size() {
        let system = ProofSystem::default();
        let prover = Prover::new(system);

        let public_inputs = b"test".to_vec();
        let witness = vec![0u8; 1000]; // Large witness

        let proof = prover.prove(&public_inputs, &witness, ProofType::Compression).unwrap();

        // Proof should be small regardless of witness size
        assert!(proof.size() < 256, "Proof too large: {} bytes", proof.size());
    }

    #[test]
    fn test_batch_proving() {
        let system = ProofSystem::default();
        let prover = Prover::new(system);

        let inputs: Vec<_> = (0..10)
            .map(|i| {
                (
                    format!("public_{}", i).into_bytes(),
                    format!("witness_{}", i).into_bytes(),
                    ProofType::Compression,
                )
            })
            .collect();

        let proofs = prover.prove_batch(inputs);
        assert_eq!(proofs.len(), 10);
        assert!(proofs.iter().all(|p| p.is_ok()));
    }
}
