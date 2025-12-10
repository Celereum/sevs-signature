//! Verifiable Random Function (VRF) for Celereum
//!
//! Provides unpredictable, unbiasable, and verifiable randomness for:
//! - Leader selection (MEV resistance)
//! - Validator committee selection
//! - Fair lottery/gaming applications
//! - Random sampling for audits
//!
//! # Security Properties
//! - Uniqueness: Same input always produces same output
//! - Unpredictability: Cannot predict output without secret key
//! - Verifiability: Anyone can verify output with public key
//! - Pseudorandomness: Output is computationally indistinguishable from random
//!
//! # Implementation
//! Uses SEVS-based VRF with SHA3-512 for post-quantum security.
//! This replaces ECVRF-Edwards25519 with our quantum-safe SEVS signatures.

use sha3::{Sha3_512, Digest};
use serde::{Deserialize, Serialize};
use std::fmt;

// Use SEVS for VRF (quantum-safe)
use super::sevs::{SevsKeypair, SevsPubkey, SevsSignature};
use super::quantum_safe::Address;
use super::hash::Hash;

/// VRF proof size in bytes (128 bytes SEVS signature + 16 bytes challenge = 144 bytes)
pub const VRF_PROOF_SIZE: usize = 144;

/// VRF output size in bytes (64 bytes - SHA3-512)
pub const VRF_OUTPUT_SIZE: usize = 64;

/// Domain separation tag for VRF
const VRF_SUITE: u8 = 0x10;  // SEVS-VRF-SHA3-512

/// VRF errors
#[derive(Debug, Clone, PartialEq)]
pub enum VrfError {
    /// Invalid proof format
    InvalidProofFormat,
    /// Proof verification failed
    VerificationFailed,
    /// Invalid public key
    InvalidPublicKey,
    /// Internal computation error
    ComputationError,
}

impl std::fmt::Display for VrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProofFormat => write!(f, "Invalid VRF proof format"),
            Self::VerificationFailed => write!(f, "VRF proof verification failed"),
            Self::InvalidPublicKey => write!(f, "Invalid public key for VRF"),
            Self::ComputationError => write!(f, "VRF computation error"),
        }
    }
}

impl std::error::Error for VrfError {}

/// VRF proof (144 bytes: 128-byte SEVS signature + 16-byte challenge)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VrfProof([u8; VRF_PROOF_SIZE]);

impl serde::Serialize for VrfProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for VrfProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != VRF_PROOF_SIZE {
            return Err(serde::de::Error::custom("invalid VRF proof size"));
        }
        let mut arr = [0u8; VRF_PROOF_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(VrfProof(arr))
    }
}

impl VrfProof {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; VRF_PROOF_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the bytes
    pub fn as_bytes(&self) -> &[u8; VRF_PROOF_SIZE] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, VrfError> {
        let bytes = hex::decode(s).map_err(|_| VrfError::InvalidProofFormat)?;
        if bytes.len() != VRF_PROOF_SIZE {
            return Err(VrfError::InvalidProofFormat);
        }
        let mut arr = [0u8; VRF_PROOF_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Debug for VrfProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VrfProof({}...)", &self.to_hex()[..16])
    }
}

impl fmt::Display for VrfProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// VRF output (64 bytes of pseudorandom data)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VrfOutput([u8; VRF_OUTPUT_SIZE]);

impl serde::Serialize for VrfOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for VrfOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != VRF_OUTPUT_SIZE {
            return Err(serde::de::Error::custom("invalid VRF output size"));
        }
        let mut arr = [0u8; VRF_OUTPUT_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(VrfOutput(arr))
    }
}

impl VrfOutput {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; VRF_OUTPUT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the bytes
    pub fn as_bytes(&self) -> &[u8; VRF_OUTPUT_SIZE] {
        &self.0
    }

    /// Get first 32 bytes as a Hash
    pub fn to_hash(&self) -> Hash {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.0[..32]);
        Hash::new(bytes)
    }

    /// Get as u64 (for leader selection)
    pub fn to_u64(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.0[..8]);
        u64::from_le_bytes(bytes)
    }

    /// Get as u128 (for higher precision random)
    pub fn to_u128(&self) -> u128 {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&self.0[..16]);
        u128::from_le_bytes(bytes)
    }

    /// Check if output falls below threshold (for weighted selection)
    ///
    /// # Arguments
    /// * `weight` - Validator's weight (e.g., stake)
    /// * `total_weight` - Total weight in the system
    ///
    /// # Returns
    /// `true` if this output selects the validator
    pub fn is_selected(&self, weight: u64, total_weight: u64) -> bool {
        if total_weight == 0 {
            return false;
        }

        // Use u128 for overflow safety
        let output_value = self.to_u128();
        let max_value = u128::MAX;

        // threshold = (weight / total_weight) * max_value
        let threshold = (weight as u128)
            .saturating_mul(max_value / total_weight as u128);

        output_value < threshold
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl fmt::Debug for VrfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VrfOutput({}...)", &self.to_hex()[..16])
    }
}

impl fmt::Display for VrfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Complete VRF result containing output and proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfResult {
    /// The pseudorandom output
    pub output: VrfOutput,
    /// The proof (for verification)
    pub proof: VrfProof,
}

impl VrfResult {
    /// Verify this VRF result
    pub fn verify(&self, input: &[u8], pubkey: &SevsPubkey) -> bool {
        VrfKeypair::verify_proof(input, &self.output, &self.proof, pubkey).is_ok()
    }
}

/// VRF-enabled keypair using SEVS (post-quantum)
///
/// Provides VRF functionality with quantum-safe SEVS signatures
pub struct VrfKeypair {
    /// The underlying SEVS keypair
    keypair: SevsKeypair,
}

impl VrfKeypair {
    /// Create a new VRF keypair from an existing SEVS keypair
    pub fn from_keypair(keypair: SevsKeypair) -> Self {
        Self { keypair }
    }

    /// Generate a new random VRF keypair
    pub fn generate() -> Self {
        Self {
            keypair: SevsKeypair::generate(),
        }
    }

    /// Get the SEVS public key (64 bytes)
    pub fn pubkey(&self) -> SevsPubkey {
        self.keypair.pubkey()
    }

    /// Get the address (32 bytes, derived from pubkey)
    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    /// Get the underlying keypair
    pub fn keypair(&self) -> &SevsKeypair {
        &self.keypair
    }

    /// Prove and compute VRF output
    ///
    /// # Arguments
    /// * `input` - The input to the VRF (e.g., slot number, block hash)
    ///
    /// # Returns
    /// VRF result containing output and proof
    pub fn prove(&self, input: &[u8]) -> VrfResult {
        // Create domain-separated input
        let mut hasher = Sha3_512::new();
        hasher.update(&[VRF_SUITE]);
        hasher.update(b"CELEREUM_VRF_V1:");
        hasher.update(self.keypair.pubkey().as_bytes());
        hasher.update(input);
        let h = hasher.finalize();

        // Sign the hash using SEVS
        let signature = self.keypair.sign(&h);

        // Create proof (SEVS signature + challenge)
        let mut proof_bytes = [0u8; VRF_PROOF_SIZE];
        proof_bytes[..128].copy_from_slice(signature.as_bytes());

        // Add challenge bytes (derived from inputs)
        let mut challenge_hasher = Sha3_512::new();
        challenge_hasher.update(&h);
        challenge_hasher.update(signature.as_bytes());
        let challenge = challenge_hasher.finalize();
        proof_bytes[128..144].copy_from_slice(&challenge[..16]);

        // Compute output (hash of proof)
        let mut output_hasher = Sha3_512::new();
        output_hasher.update(b"CELEREUM_VRF_OUTPUT:");
        output_hasher.update(&proof_bytes);
        let output_hash = output_hasher.finalize();

        let mut output_bytes = [0u8; VRF_OUTPUT_SIZE];
        output_bytes.copy_from_slice(&output_hash);

        VrfResult {
            output: VrfOutput(output_bytes),
            proof: VrfProof(proof_bytes),
        }
    }

    /// Verify a VRF proof
    ///
    /// # Arguments
    /// * `input` - The original input to the VRF
    /// * `output` - The claimed VRF output
    /// * `proof` - The VRF proof
    /// * `pubkey` - The SEVS public key of the prover
    pub fn verify_proof(
        input: &[u8],
        output: &VrfOutput,
        proof: &VrfProof,
        pubkey: &SevsPubkey,
    ) -> Result<(), VrfError> {
        // Reconstruct the expected hash
        let mut hasher = Sha3_512::new();
        hasher.update(&[VRF_SUITE]);
        hasher.update(b"CELEREUM_VRF_V1:");
        hasher.update(pubkey.as_bytes());
        hasher.update(input);
        let h = hasher.finalize();

        // Extract SEVS signature from proof
        let mut sig_bytes = [0u8; 128];
        sig_bytes.copy_from_slice(&proof.0[..128]);
        let signature = match SevsSignature::from_bytes(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return Err(VrfError::InvalidProofFormat),
        };

        // Verify SEVS signature
        if !signature.verify(&h, pubkey) {
            return Err(VrfError::VerificationFailed);
        }

        // Verify challenge
        let mut challenge_hasher = Sha3_512::new();
        challenge_hasher.update(&h);
        challenge_hasher.update(&sig_bytes);
        let expected_challenge = challenge_hasher.finalize();

        if proof.0[128..144] != expected_challenge[..16] {
            return Err(VrfError::VerificationFailed);
        }

        // Verify output
        let mut output_hasher = Sha3_512::new();
        output_hasher.update(b"CELEREUM_VRF_OUTPUT:");
        output_hasher.update(&proof.0);
        let expected_output = output_hasher.finalize();

        if output.0 != expected_output[..] {
            return Err(VrfError::VerificationFailed);
        }

        Ok(())
    }
}

/// Leader selector using VRF
pub struct VrfLeaderSelector {
    /// Minimum stake to be eligible
    pub min_stake: u64,
}

impl VrfLeaderSelector {
    /// Create a new leader selector
    pub fn new(min_stake: u64) -> Self {
        Self { min_stake }
    }

    /// Select leader for a slot
    ///
    /// # Arguments
    /// * `slot` - The slot number
    /// * `epoch_randomness` - Random seed for the epoch
    /// * `validators` - List of (address, stake) pairs
    /// * `vrf_keypair` - This validator's VRF keypair
    ///
    /// # Returns
    /// `Some((VrfResult, rank))` if selected, `None` otherwise
    pub fn try_select(
        &self,
        slot: u64,
        epoch_randomness: &[u8; 32],
        validators: &[(Address, u64)],
        vrf_keypair: &VrfKeypair,
    ) -> Option<(VrfResult, u64)> {
        let our_address = vrf_keypair.address();

        // Find our stake
        let our_stake = validators.iter()
            .find(|(addr, _)| addr == &our_address)
            .map(|(_, stake)| *stake)?;

        if our_stake < self.min_stake {
            return None;
        }

        // Calculate total stake
        let total_stake: u64 = validators.iter()
            .filter(|(_, stake)| *stake >= self.min_stake)
            .map(|(_, stake)| *stake)
            .sum();

        // Create VRF input
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(epoch_randomness);
        input.extend_from_slice(&slot.to_le_bytes());

        // Generate VRF proof
        let result = vrf_keypair.prove(&input);

        // Check if selected based on stake weight
        if result.output.is_selected(our_stake, total_stake) {
            // Calculate rank (lower is better)
            let rank = result.output.to_u64();
            Some((result, rank))
        } else {
            None
        }
    }

    /// Verify a leader claim
    pub fn verify_claim(
        &self,
        slot: u64,
        epoch_randomness: &[u8; 32],
        vrf_result: &VrfResult,
        claimer_pubkey: &SevsPubkey,
        claimer_stake: u64,
        total_stake: u64,
    ) -> bool {
        if claimer_stake < self.min_stake {
            return false;
        }

        // Recreate VRF input
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(epoch_randomness);
        input.extend_from_slice(&slot.to_le_bytes());

        // Verify VRF proof
        if VrfKeypair::verify_proof(&input, &vrf_result.output, &vrf_result.proof, claimer_pubkey).is_err() {
            return false;
        }

        // Check if output passes threshold
        vrf_result.output.is_selected(claimer_stake, total_stake)
    }
}

/// Sortition using VRF for committee selection
pub struct VrfSortition {
    /// Expected committee size
    pub expected_size: usize,
}

impl VrfSortition {
    /// Create a new sortition instance
    pub fn new(expected_size: usize) -> Self {
        Self { expected_size }
    }

    /// Calculate how many committee seats a validator gets
    ///
    /// Uses binomial distribution approximation for stake-weighted selection
    pub fn get_seats(
        &self,
        vrf_output: &VrfOutput,
        stake: u64,
        total_stake: u64,
    ) -> usize {
        if total_stake == 0 || stake == 0 {
            return 0;
        }

        // Calculate probability of selection
        let p = (stake as f64) / (total_stake as f64);
        let expected_seats = p * (self.expected_size as f64);

        // Use VRF output to determine actual seats
        let random_value = vrf_output.to_u64() as f64 / u64::MAX as f64;

        // Simple approximation: use Poisson distribution
        // For small probabilities and moderate expected values
        if random_value < expected_seats.fract() {
            expected_seats.ceil() as usize
        } else {
            expected_seats.floor() as usize
        }
    }

    /// Select committee members from a list of validators
    pub fn select_committee(
        &self,
        round: u64,
        epoch_randomness: &[u8; 32],
        validators: &[(Address, u64, VrfKeypair)],
    ) -> Vec<(Address, usize, VrfResult)> {
        let total_stake: u64 = validators.iter().map(|(_, stake, _)| *stake).sum();

        let mut committee = Vec::new();

        for (address, stake, vrf_keypair) in validators {
            // Create round-specific input
            let mut input = Vec::with_capacity(40);
            input.extend_from_slice(epoch_randomness);
            input.extend_from_slice(&round.to_le_bytes());

            // Generate VRF proof
            let result = vrf_keypair.prove(&input);

            // Determine number of seats
            let seats = self.get_seats(&result.output, *stake, total_stake);

            if seats > 0 {
                committee.push((*address, seats, result));
            }
        }

        committee
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_prove_verify() {
        let keypair = VrfKeypair::generate();
        let input = b"test input for VRF";

        let result = keypair.prove(input);

        // Verify the proof
        assert!(VrfKeypair::verify_proof(
            input,
            &result.output,
            &result.proof,
            &keypair.pubkey()
        ).is_ok());
    }

    #[test]
    fn test_vrf_deterministic() {
        let keypair = VrfKeypair::generate();
        let input = b"same input";

        let result1 = keypair.prove(input);
        let result2 = keypair.prove(input);

        // Same input should produce same output
        assert_eq!(result1.output, result2.output);
    }

    #[test]
    fn test_vrf_different_inputs() {
        let keypair = VrfKeypair::generate();

        let result1 = keypair.prove(b"input 1");
        let result2 = keypair.prove(b"input 2");

        // Different inputs should produce different outputs
        assert_ne!(result1.output, result2.output);
    }

    #[test]
    fn test_vrf_different_keys() {
        let keypair1 = VrfKeypair::generate();
        let keypair2 = VrfKeypair::generate();
        let input = b"same input";

        let result1 = keypair1.prove(input);
        let result2 = keypair2.prove(input);

        // Different keys should produce different outputs
        assert_ne!(result1.output, result2.output);
    }

    #[test]
    fn test_vrf_invalid_proof() {
        let keypair = VrfKeypair::generate();
        let input = b"test input";

        let result = keypair.prove(input);

        // Tamper with the proof
        let mut bad_proof = result.proof.0;
        bad_proof[0] ^= 0xFF;
        let bad_proof = VrfProof(bad_proof);

        // Should fail verification
        assert!(VrfKeypair::verify_proof(
            input,
            &result.output,
            &bad_proof,
            &keypair.pubkey()
        ).is_err());
    }

    #[test]
    fn test_vrf_wrong_pubkey() {
        let keypair1 = VrfKeypair::generate();
        let keypair2 = VrfKeypair::generate();
        let input = b"test input";

        let result = keypair1.prove(input);

        // Verify with wrong pubkey should fail
        assert!(VrfKeypair::verify_proof(
            input,
            &result.output,
            &result.proof,
            &keypair2.pubkey()
        ).is_err());
    }

    #[test]
    fn test_vrf_output_methods() {
        let keypair = VrfKeypair::generate();
        let result = keypair.prove(b"test");

        // Test conversion methods
        let _u64_val = result.output.to_u64();
        let _u128_val = result.output.to_u128();
        let _hash = result.output.to_hash();
        let _hex = result.output.to_hex();

        // All should work without panicking
    }

    #[test]
    fn test_leader_selection() {
        let selector = VrfLeaderSelector::new(100);
        let keypair = VrfKeypair::generate();
        let address = keypair.address();

        let validators = vec![
            (address, 1000),
        ];

        let epoch_randomness = [1u8; 32];

        // With 100% stake, should always be selected
        let result = selector.try_select(0, &epoch_randomness, &validators, &keypair);
        assert!(result.is_some());
    }

    #[test]
    fn test_sortition() {
        let sortition = VrfSortition::new(100);
        let keypair = VrfKeypair::generate();

        let result = keypair.prove(b"sortition test");

        // With 10% of stake and 100 expected seats, should get roughly 10 seats
        let seats = sortition.get_seats(&result.output, 100, 1000);
        // Due to randomness, we just check it's reasonable
        assert!(seats <= 20); // Allow some variance
    }
}
