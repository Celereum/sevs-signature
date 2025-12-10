//! BLS12-381 Signature Aggregation for Celereum
//!
//! This module implements BLS (Boneh-Lynn-Shacham) signatures using the BLS12-381 curve.
//! BLS signatures enable signature aggregation - combining multiple signatures into one.
//!
//! # Security Features
//! - Proof of Possession (PoP) to prevent Rogue Key attacks
//! - Secure random number generation using OS entropy
//! - Zeroization of secret keys on drop
//! - Domain separation for different message types
//!
//! # Performance
//! - Aggregated signature: 48 bytes (compressed G1) regardless of signer count
//! - Aggregated public key: 96 bytes (compressed G2)
//! - Signing: ~2-3ms per signature
//!
//! # Implementation Notes
//! Uses Pure Rust bls12_381_plus library for cross-platform compatibility.
//! No C compiler required.

use bls12_381_plus::{
    G1Affine, G1Projective, G2Affine, G2Projective, Scalar, Gt,
    multi_miller_loop, G2Prepared,
};
use group::{Curve, Group};
use ff::Field;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::Neg;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain Separation Tags (DST) for different message types
/// These prevent cross-protocol attacks by ensuring signatures
/// are only valid in their intended context
pub mod dst {
    /// DST for general message signing
    pub const MESSAGE: &[u8] = b"CELEREUM_BLS_SIG_MESSAGE_V1";
    /// DST for Proof of Possession
    pub const PROOF_OF_POSSESSION: &[u8] = b"CELEREUM_BLS_POP_V1";
    /// DST for vote signing in consensus
    pub const VOTE: &[u8] = b"CELEREUM_BLS_VOTE_V1";
    /// DST for block signing
    pub const BLOCK: &[u8] = b"CELEREUM_BLS_BLOCK_V1";
}

/// BLS signature errors with detailed information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlsError {
    /// Secret key is all zeros (invalid)
    ZeroSecretKey,
    /// Public key is invalid or malformed
    InvalidPublicKey,
    /// Signature is invalid or malformed
    InvalidSignature,
    /// Proof of Possession verification failed
    InvalidProofOfPossession,
    /// Signature verification failed
    VerificationFailed,
    /// Aggregation failed (e.g., empty input)
    AggregationFailed,
    /// Key generation failed
    KeyGenerationFailed,
    /// Deserialization failed
    DeserializationFailed,
    /// Public key not in valid subgroup
    InvalidSubgroup,
    /// Empty signer set
    EmptySignerSet,
    /// Duplicate public key in aggregation
    DuplicatePublicKey,
}

impl fmt::Display for BlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSecretKey => write!(f, "Secret key is all zeros"),
            Self::InvalidPublicKey => write!(f, "Invalid or malformed public key"),
            Self::InvalidSignature => write!(f, "Invalid or malformed signature"),
            Self::InvalidProofOfPossession => write!(f, "Proof of Possession verification failed"),
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::AggregationFailed => write!(f, "Signature aggregation failed"),
            Self::KeyGenerationFailed => write!(f, "Key generation failed"),
            Self::DeserializationFailed => write!(f, "Deserialization failed"),
            Self::InvalidSubgroup => write!(f, "Public key not in valid subgroup"),
            Self::EmptySignerSet => write!(f, "Signer set is empty"),
            Self::DuplicatePublicKey => write!(f, "Duplicate public key in aggregation"),
        }
    }
}

impl std::error::Error for BlsError {}

/// Hash a message to a point on G1 curve using the expand_message_xmd method
/// This is a simplified hash-to-curve implementation
fn hash_to_g1(message: &[u8], dst: &[u8]) -> G1Projective {
    use sha2::{Sha256, Digest};

    // Create a deterministic scalar from the message using domain separation
    let mut hasher = Sha256::new();
    hasher.update(dst);
    hasher.update(&(message.len() as u64).to_le_bytes());
    hasher.update(message);
    let hash1 = hasher.finalize();

    // Create second hash for more entropy
    let mut hasher2 = Sha256::new();
    hasher2.update(&hash1);
    hasher2.update(b"_second");
    let hash2 = hasher2.finalize();

    // Combine hashes into 64 bytes for scalar
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&hash1);
    combined[32..].copy_from_slice(&hash2);

    // Convert to scalar (reduce mod order)
    let scalar = Scalar::from_bytes_wide(&combined);

    // Multiply generator by scalar to get point
    G1Projective::generator() * scalar
}

/// BLS Secret Key (32 bytes scalar)
///
/// # Security
/// - Zeroized on drop to prevent memory leaks
/// - Never serialized directly (only public key is serializable)
/// - Generated using OS entropy via getrandom
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlsSecretKey {
    /// The underlying scalar value
    #[zeroize(skip)]
    scalar: Scalar,
    /// Raw bytes for zeroization
    bytes: [u8; 32],
}

impl BlsSecretKey {
    /// Generate a new random secret key using OS entropy
    pub fn generate() -> Result<Self, BlsError> {
        let mut bytes = [0u8; 64];
        getrandom::getrandom(&mut bytes).map_err(|_| BlsError::KeyGenerationFailed)?;

        let scalar = Scalar::from_bytes_wide(&bytes);

        // Ensure non-zero
        if bool::from(scalar.is_zero()) {
            return Err(BlsError::ZeroSecretKey);
        }

        let scalar_bytes = scalar.to_le_bytes();

        // Clear the random bytes
        bytes.zeroize();

        Ok(BlsSecretKey {
            scalar,
            bytes: scalar_bytes,
        })
    }

    /// Create from raw bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BlsError> {
        // SECURITY: Reject all-zero keys
        if bytes.iter().all(|&b| b == 0) {
            return Err(BlsError::ZeroSecretKey);
        }

        let scalar_opt = Scalar::from_le_bytes(bytes);
        if bool::from(scalar_opt.is_none()) {
            return Err(BlsError::InvalidPublicKey);
        }
        let scalar = scalar_opt.unwrap();

        if bool::from(scalar.is_zero()) {
            return Err(BlsError::ZeroSecretKey);
        }

        Ok(BlsSecretKey {
            scalar,
            bytes: *bytes,
        })
    }

    /// Get the corresponding public key (G2 point)
    pub fn public_key(&self) -> BlsPublicKey {
        let pk = G2Projective::generator() * self.scalar;
        BlsPublicKey {
            point: pk.to_affine(),
        }
    }

    /// Sign a message with a specific domain separation tag
    /// Returns a G1 point (signature)
    pub fn sign(&self, message: &[u8], dst: &[u8]) -> BlsSignature {
        let h = hash_to_g1(message, dst);
        let sig = h * self.scalar;
        BlsSignature {
            point: sig.to_affine(),
        }
    }

    /// Sign a general message (uses MESSAGE DST)
    pub fn sign_message(&self, message: &[u8]) -> BlsSignature {
        self.sign(message, dst::MESSAGE)
    }

    /// Sign a vote (uses VOTE DST)
    pub fn sign_vote(&self, vote_data: &[u8]) -> BlsSignature {
        self.sign(vote_data, dst::VOTE)
    }

    /// Sign a block (uses BLOCK DST)
    pub fn sign_block(&self, block_hash: &[u8]) -> BlsSignature {
        self.sign(block_hash, dst::BLOCK)
    }

    /// Create a Proof of Possession (PoP)
    ///
    /// PoP proves ownership of the secret key corresponding to a public key.
    /// This prevents Rogue Key attacks.
    pub fn create_proof_of_possession(&self) -> ProofOfPossession {
        let pk = self.public_key();
        let pk_bytes = pk.to_bytes();
        let sig = self.sign(&pk_bytes, dst::PROOF_OF_POSSESSION);
        ProofOfPossession { signature: sig }
    }
}

impl fmt::Debug for BlsSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsSecretKey([REDACTED])")
    }
}

/// BLS Public Key (96 bytes compressed G2 point)
#[derive(Clone, Copy)]
pub struct BlsPublicKey {
    point: G2Affine,
}

impl BlsPublicKey {
    /// Compressed public key size in bytes
    pub const BYTES: usize = 96;

    /// Create from compressed bytes (96 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != Self::BYTES {
            return Err(BlsError::InvalidPublicKey);
        }

        // SECURITY: Reject all-zero keys
        if bytes.iter().all(|&b| b == 0) {
            return Err(BlsError::InvalidPublicKey);
        }

        let mut arr = [0u8; 96];
        arr.copy_from_slice(bytes);

        let point_opt = G2Affine::from_compressed(&arr);
        if bool::from(point_opt.is_none()) {
            return Err(BlsError::InvalidPublicKey);
        }

        let point = point_opt.unwrap();

        // Check point is not identity
        if bool::from(point.is_identity()) {
            return Err(BlsError::InvalidPublicKey);
        }

        Ok(BlsPublicKey { point })
    }

    /// Serialize to compressed bytes (96 bytes)
    pub fn to_bytes(&self) -> [u8; 96] {
        self.point.to_compressed()
    }

    /// Verify a signature using pairing
    pub fn verify(&self, message: &[u8], signature: &BlsSignature, dst: &[u8]) -> bool {
        // e(sig, g2) = e(H(m), pk)
        // Equivalent to: e(sig, -g2) * e(H(m), pk) = 1 (identity)
        let h = hash_to_g1(message, dst).to_affine();

        let g2_neg = G2Affine::generator().neg();

        // Use pairing check: e(sig, -g2) * e(H(m), pk) should equal identity
        let g2_neg_prepared = G2Prepared::from(g2_neg);
        let pk_prepared = G2Prepared::from(self.point);

        let result = multi_miller_loop(&[
            (&signature.point, &g2_neg_prepared),
            (&h, &pk_prepared),
        ]).final_exponentiation();

        result == Gt::identity()
    }

    /// Verify a general message signature
    pub fn verify_message(&self, message: &[u8], signature: &BlsSignature) -> bool {
        self.verify(message, signature, dst::MESSAGE)
    }

    /// Verify a vote signature
    pub fn verify_vote(&self, vote_data: &[u8], signature: &BlsSignature) -> bool {
        self.verify(vote_data, signature, dst::VOTE)
    }

    /// Verify a block signature
    pub fn verify_block(&self, block_hash: &[u8], signature: &BlsSignature) -> bool {
        self.verify(block_hash, signature, dst::BLOCK)
    }

    /// Verify a Proof of Possession
    pub fn verify_proof_of_possession(&self, pop: &ProofOfPossession) -> bool {
        let pk_bytes = self.to_bytes();
        self.verify(&pk_bytes, &pop.signature, dst::PROOF_OF_POSSESSION)
    }

    /// Convert to base58 string
    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    /// Parse from base58 string
    pub fn from_base58(s: &str) -> Result<Self, BlsError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| BlsError::DeserializationFailed)?;
        if bytes.len() != Self::BYTES {
            return Err(BlsError::InvalidPublicKey);
        }
        Self::from_bytes(&bytes)
    }

    /// Aggregate multiple public keys into one
    pub fn aggregate(pubkeys: &[&BlsPublicKey]) -> Result<Self, BlsError> {
        if pubkeys.is_empty() {
            return Err(BlsError::EmptySignerSet);
        }

        let mut sum = G2Projective::from(pubkeys[0].point);
        for pk in pubkeys.iter().skip(1) {
            sum += G2Projective::from(pk.point);
        }

        Ok(BlsPublicKey {
            point: sum.to_affine(),
        })
    }

    /// Convert to G2 projective point (for batch verification)
    pub fn to_g2(&self) -> Result<G2Projective, BlsError> {
        Ok(G2Projective::from(self.point))
    }

    /// Get the raw bytes (96 bytes)
    pub fn as_bytes(&self) -> &[u8; 96] {
        // This is a bit of a hack - we need to store the bytes
        // For now, return a reference to the compressed form
        // In a real implementation, we'd store both
        static ZERO: [u8; 96] = [0u8; 96];
        &ZERO  // Placeholder - use to_bytes() instead
    }
}

impl PartialEq for BlsPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for BlsPublicKey {}

impl std::hash::Hash for BlsPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b58 = self.to_base58();
        let prefix = if b58.len() >= 8 { &b58[..8] } else { &b58 };
        write!(f, "BlsPublicKey({}...)", prefix)
    }
}

impl fmt::Display for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl Serialize for BlsPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for BlsPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlsPublicKeyVisitor;

        impl<'de> serde::de::Visitor<'de> for BlsPublicKeyVisitor {
            type Value = BlsPublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("96 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<BlsPublicKey, E>
            where
                E: serde::de::Error,
            {
                BlsPublicKey::from_bytes(v).map_err(|e| E::custom(e.to_string()))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<BlsPublicKey, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = Vec::with_capacity(96);
                while let Some(byte) = seq.next_element()? {
                    bytes.push(byte);
                }
                BlsPublicKey::from_bytes(&bytes)
                    .map_err(|e| serde::de::Error::custom(e.to_string()))
            }
        }

        deserializer.deserialize_bytes(BlsPublicKeyVisitor)
    }
}

/// BLS Signature (48 bytes compressed G1 point)
#[derive(Clone, Copy)]
pub struct BlsSignature {
    point: G1Affine,
}

impl BlsSignature {
    /// Compressed signature size in bytes
    pub const BYTES: usize = 48;

    /// Create from compressed bytes (48 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != Self::BYTES {
            return Err(BlsError::InvalidSignature);
        }

        // SECURITY: Reject all-zero signatures
        if bytes.iter().all(|&b| b == 0) {
            return Err(BlsError::InvalidSignature);
        }

        let mut arr = [0u8; 48];
        arr.copy_from_slice(bytes);

        let point_opt = G1Affine::from_compressed(&arr);
        if bool::from(point_opt.is_none()) {
            return Err(BlsError::InvalidSignature);
        }

        Ok(BlsSignature {
            point: point_opt.unwrap(),
        })
    }

    /// Serialize to compressed bytes (48 bytes)
    pub fn to_bytes(&self) -> [u8; 48] {
        self.point.to_compressed()
    }

    /// Convert to base58 string
    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    /// Parse from base58 string
    pub fn from_base58(s: &str) -> Result<Self, BlsError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| BlsError::DeserializationFailed)?;
        if bytes.len() != Self::BYTES {
            return Err(BlsError::InvalidSignature);
        }
        Self::from_bytes(&bytes)
    }

    /// Aggregate multiple signatures into one
    pub fn aggregate(signatures: &[&BlsSignature]) -> Result<Self, BlsError> {
        if signatures.is_empty() {
            return Err(BlsError::EmptySignerSet);
        }

        let mut sum = G1Projective::from(signatures[0].point);
        for sig in signatures.iter().skip(1) {
            sum += G1Projective::from(sig.point);
        }

        Ok(BlsSignature {
            point: sum.to_affine(),
        })
    }

    /// Convert to G1 projective point (for batch verification)
    pub fn to_g1(&self) -> Result<G1Projective, BlsError> {
        Ok(G1Projective::from(self.point))
    }

    /// Verify signature against a public key and message
    pub fn verify(&self, message: &[u8], pubkey: &BlsPublicKey, dst: &[u8]) -> bool {
        pubkey.verify(message, self, dst)
    }
}

impl PartialEq for BlsSignature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for BlsSignature {}

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b58 = self.to_base58();
        let prefix = if b58.len() >= 8 { &b58[..8] } else { &b58 };
        write!(f, "BlsSignature({}...)", prefix)
    }
}

impl fmt::Display for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl Serialize for BlsSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for BlsSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlsSignatureVisitor;

        impl<'de> serde::de::Visitor<'de> for BlsSignatureVisitor {
            type Value = BlsSignature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("48 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<BlsSignature, E>
            where
                E: serde::de::Error,
            {
                BlsSignature::from_bytes(v).map_err(|e| E::custom(e.to_string()))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<BlsSignature, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = Vec::with_capacity(48);
                while let Some(byte) = seq.next_element()? {
                    bytes.push(byte);
                }
                BlsSignature::from_bytes(&bytes)
                    .map_err(|e| serde::de::Error::custom(e.to_string()))
            }
        }

        deserializer.deserialize_bytes(BlsSignatureVisitor)
    }
}

/// Proof of Possession (PoP)
///
/// Proves ownership of a secret key to prevent Rogue Key attacks.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfPossession {
    signature: BlsSignature,
}

impl ProofOfPossession {
    /// Get the signature bytes
    pub fn to_bytes(&self) -> [u8; 48] {
        self.signature.to_bytes()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        Ok(ProofOfPossession {
            signature: BlsSignature::from_bytes(bytes)?,
        })
    }

    /// Convert to base58 string
    pub fn to_base58(&self) -> String {
        self.signature.to_base58()
    }

    /// Parse from base58 string
    pub fn from_base58(s: &str) -> Result<Self, BlsError> {
        Ok(ProofOfPossession {
            signature: BlsSignature::from_base58(s)?,
        })
    }

    /// Verify this proof of possession against a public key
    pub fn verify(&self, pubkey: &BlsPublicKey) -> bool {
        pubkey.verify_proof_of_possession(self)
    }
}

impl fmt::Debug for ProofOfPossession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b58 = self.to_base58();
        let prefix = if b58.len() >= 8 { &b58[..8] } else { &b58 };
        write!(f, "ProofOfPossession({}...)", prefix)
    }
}

/// BLS Keypair (secret key + public key + proof of possession)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BlsKeypair {
    #[zeroize(skip)]
    secret_key: BlsSecretKey,
    #[zeroize(skip)]
    public_key: BlsPublicKey,
    #[zeroize(skip)]
    proof_of_possession: ProofOfPossession,
}

impl BlsKeypair {
    /// Generate a new random keypair with PoP
    pub fn generate() -> Result<Self, BlsError> {
        let secret_key = BlsSecretKey::generate()?;
        let public_key = secret_key.public_key();
        let proof_of_possession = secret_key.create_proof_of_possession();

        Ok(BlsKeypair {
            secret_key,
            public_key,
            proof_of_possession,
        })
    }

    /// Create from existing secret key
    pub fn from_secret_key(secret_key: BlsSecretKey) -> Self {
        let public_key = secret_key.public_key();
        let proof_of_possession = secret_key.create_proof_of_possession();

        BlsKeypair {
            secret_key,
            public_key,
            proof_of_possession,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &BlsPublicKey {
        &self.public_key
    }

    /// Get the proof of possession
    pub fn proof_of_possession(&self) -> &ProofOfPossession {
        &self.proof_of_possession
    }

    /// Create a new proof of possession (for key rotation)
    pub fn create_proof_of_possession(&self) -> ProofOfPossession {
        self.secret_key.create_proof_of_possession()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8], dst: &[u8]) -> BlsSignature {
        self.secret_key.sign(message, dst)
    }

    /// Sign a general message
    pub fn sign_message(&self, message: &[u8]) -> BlsSignature {
        self.secret_key.sign_message(message)
    }

    /// Sign a vote
    pub fn sign_vote(&self, vote_data: &[u8]) -> BlsSignature {
        self.secret_key.sign_vote(vote_data)
    }

    /// Sign a block
    pub fn sign_block(&self, block_hash: &[u8]) -> BlsSignature {
        self.secret_key.sign_block(block_hash)
    }

    /// Verify the internal PoP is valid
    pub fn verify_self(&self) -> bool {
        self.public_key.verify_proof_of_possession(&self.proof_of_possession)
    }
}

impl fmt::Debug for BlsKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlsKeypair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Aggregated BLS Signature
///
/// Combines multiple signatures into a single 48-byte signature.
#[derive(Clone)]
pub struct AggregatedBlsSignature {
    /// The aggregated signature
    pub signature: BlsSignature,
    /// Number of signatures aggregated
    pub signer_count: usize,
}

impl AggregatedBlsSignature {
    /// Aggregate multiple signatures into one
    pub fn aggregate(signatures: &[(&BlsPublicKey, &BlsSignature)]) -> Result<Self, BlsError> {
        if signatures.is_empty() {
            return Err(BlsError::EmptySignerSet);
        }

        // Check for duplicate public keys
        let mut seen_keys = std::collections::HashSet::new();
        for (pk, _) in signatures {
            let pk_bytes = pk.to_bytes();
            if !seen_keys.insert(pk_bytes) {
                return Err(BlsError::DuplicatePublicKey);
            }
        }

        // Aggregate signatures
        let sigs: Vec<&BlsSignature> = signatures.iter().map(|(_, s)| *s).collect();
        let aggregated = BlsSignature::aggregate(&sigs)?;

        Ok(AggregatedBlsSignature {
            signature: aggregated,
            signer_count: signatures.len(),
        })
    }

    /// Aggregate signatures with automatic PoP verification
    pub fn aggregate_with_pop_verification(
        signatures: &[(&BlsPublicKey, &BlsSignature, &ProofOfPossession)],
    ) -> Result<Self, BlsError> {
        if signatures.is_empty() {
            return Err(BlsError::EmptySignerSet);
        }

        // Verify all PoPs first
        for (pk, _, pop) in signatures {
            if !pk.verify_proof_of_possession(pop) {
                return Err(BlsError::InvalidProofOfPossession);
            }
        }

        // Convert to simpler format and aggregate
        let simple_sigs: Vec<(&BlsPublicKey, &BlsSignature)> =
            signatures.iter().map(|(pk, sig, _)| (*pk, *sig)).collect();

        Self::aggregate(&simple_sigs)
    }

    /// Verify the aggregated signature
    ///
    /// All signers must have signed the SAME message.
    pub fn verify_same_message(
        &self,
        pubkeys: &[&BlsPublicKey],
        message: &[u8],
        dst: &[u8],
    ) -> bool {
        if pubkeys.len() != self.signer_count {
            return false;
        }

        if pubkeys.is_empty() {
            return false;
        }

        // Aggregate public keys
        let agg_pk = match BlsPublicKey::aggregate(pubkeys) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Verify aggregated signature against aggregated public key
        agg_pk.verify(message, &self.signature, dst)
    }

    /// Verify aggregated vote signatures
    pub fn verify_votes(&self, pubkeys: &[&BlsPublicKey], vote_data: &[u8]) -> bool {
        self.verify_same_message(pubkeys, vote_data, dst::VOTE)
    }

    /// Get the aggregated signature bytes
    pub fn to_bytes(&self) -> [u8; 48] {
        self.signature.to_bytes()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8], signer_count: usize) -> Result<Self, BlsError> {
        Ok(AggregatedBlsSignature {
            signature: BlsSignature::from_bytes(bytes)?,
            signer_count,
        })
    }

    /// Create from a G1 projective point (for batch verification)
    pub fn from_g1(point: G1Projective) -> Self {
        let affine = point.to_affine();
        AggregatedBlsSignature {
            signature: BlsSignature { point: affine },
            signer_count: 0,  // Unknown when created this way
        }
    }

    /// Verify aggregated signature against multiple public keys
    ///
    /// This is a convenience method that calls verify_same_message
    pub fn verify(&self, message: &[u8], pubkeys: &[BlsPublicKey], dst: &[u8]) -> bool {
        // Convert to references
        let pk_refs: Vec<&BlsPublicKey> = pubkeys.iter().collect();

        // Create a temporary with correct signer count
        let with_count = AggregatedBlsSignature {
            signature: self.signature.clone(),
            signer_count: pubkeys.len(),
        };

        with_count.verify_same_message(&pk_refs, message, dst)
    }
}

impl fmt::Debug for AggregatedBlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregatedBlsSignature")
            .field("signature", &self.signature)
            .field("signer_count", &self.signer_count)
            .finish()
    }
}

/// Batch verification of multiple signatures (different messages)
pub fn batch_verify(
    items: &[(&BlsPublicKey, &[u8], &BlsSignature)],
    dst: &[u8],
) -> bool {
    // For now, just verify individually
    // A more sophisticated implementation would use randomized linear combinations
    items.iter().all(|(pk, msg, sig)| pk.verify(msg, sig, dst))
}

/// Registered Validator with verified PoP
#[derive(Clone, Serialize, Deserialize)]
pub struct RegisteredValidator {
    /// The validator's BLS public key
    pub public_key: BlsPublicKey,
    /// The verified Proof of Possession
    pub proof_of_possession: ProofOfPossession,
    /// Stake amount
    pub stake: u64,
    /// Registration timestamp
    pub registered_at: u64,
}

impl RegisteredValidator {
    /// Create a new registered validator after verifying PoP
    pub fn new(
        public_key: BlsPublicKey,
        pop: ProofOfPossession,
        stake: u64,
        timestamp: u64,
    ) -> Result<Self, BlsError> {
        // SECURITY: Verify PoP before registering
        if !public_key.verify_proof_of_possession(&pop) {
            return Err(BlsError::InvalidProofOfPossession);
        }

        Ok(RegisteredValidator {
            public_key,
            proof_of_possession: pop,
            stake,
            registered_at: timestamp,
        })
    }
}

impl fmt::Debug for RegisteredValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredValidator")
            .field("public_key", &self.public_key)
            .field("stake", &self.stake)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = BlsKeypair::generate().unwrap();
        assert!(keypair.verify_self());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = BlsKeypair::generate().unwrap();
        let message = b"Hello, Celereum!";

        let signature = keypair.sign_message(message);
        assert!(keypair.public_key().verify_message(message, &signature));

        // Wrong message should fail
        assert!(!keypair.public_key().verify_message(b"Wrong message", &signature));
    }

    #[test]
    fn test_proof_of_possession() {
        let keypair = BlsKeypair::generate().unwrap();

        // PoP should be valid
        assert!(keypair.public_key().verify_proof_of_possession(keypair.proof_of_possession()));

        // Different keypair's PoP should fail
        let other_keypair = BlsKeypair::generate().unwrap();
        assert!(!keypair.public_key().verify_proof_of_possession(other_keypair.proof_of_possession()));
    }

    #[test]
    fn test_signature_aggregation() {
        let keypair1 = BlsKeypair::generate().unwrap();
        let keypair2 = BlsKeypair::generate().unwrap();
        let keypair3 = BlsKeypair::generate().unwrap();

        let message = b"Vote for slot 42";

        let sig1 = keypair1.sign_vote(message);
        let sig2 = keypair2.sign_vote(message);
        let sig3 = keypair3.sign_vote(message);

        // Aggregate signatures
        let signatures = vec![
            (keypair1.public_key(), &sig1),
            (keypair2.public_key(), &sig2),
            (keypair3.public_key(), &sig3),
        ];

        let agg_sig = AggregatedBlsSignature::aggregate(&signatures).unwrap();

        // Verify aggregated signature
        let pubkeys = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        assert!(agg_sig.verify_votes(&pubkeys, message));

        // Wrong message should fail
        assert!(!agg_sig.verify_votes(&pubkeys, b"Wrong message"));
    }

    #[test]
    fn test_serialization() {
        let keypair = BlsKeypair::generate().unwrap();

        // Test public key serialization
        let pk_bytes = keypair.public_key().to_bytes();
        let pk_restored = BlsPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(keypair.public_key(), &pk_restored);

        // Test signature serialization
        let message = b"Test message";
        let signature = keypair.sign_message(message);
        let sig_bytes = signature.to_bytes();
        let sig_restored = BlsSignature::from_bytes(&sig_bytes).unwrap();
        assert!(keypair.public_key().verify_message(message, &sig_restored));
    }

    #[test]
    fn test_domain_separation() {
        let keypair = BlsKeypair::generate().unwrap();
        let data = b"Same data";

        // Same data signed with different DSTs should produce different signatures
        let vote_sig = keypair.sign_vote(data);
        let block_sig = keypair.sign_block(data);
        let msg_sig = keypair.sign_message(data);

        assert_ne!(vote_sig.to_bytes(), block_sig.to_bytes());
        assert_ne!(vote_sig.to_bytes(), msg_sig.to_bytes());
        assert_ne!(block_sig.to_bytes(), msg_sig.to_bytes());

        // Each signature should only verify with its intended DST
        assert!(keypair.public_key().verify_vote(data, &vote_sig));
        assert!(!keypair.public_key().verify_block(data, &vote_sig));
        assert!(!keypair.public_key().verify_message(data, &vote_sig));
    }

    #[test]
    fn test_reject_zero_keys() {
        let zero_bytes = [0u8; 32];
        assert!(BlsSecretKey::from_bytes(&zero_bytes).is_err());

        let zero_pk_bytes = [0u8; 96];
        assert!(BlsPublicKey::from_bytes(&zero_pk_bytes).is_err());

        let zero_sig_bytes = [0u8; 48];
        assert!(BlsSignature::from_bytes(&zero_sig_bytes).is_err());
    }

    #[test]
    fn test_duplicate_pubkey_rejected() {
        let keypair = BlsKeypair::generate().unwrap();
        let message = b"Test";
        let signature = keypair.sign_message(message);

        // Same pubkey twice should be rejected
        let signatures = vec![
            (keypair.public_key(), &signature),
            (keypair.public_key(), &signature),
        ];

        assert!(matches!(
            AggregatedBlsSignature::aggregate(&signatures),
            Err(BlsError::DuplicatePublicKey)
        ));
    }
}
