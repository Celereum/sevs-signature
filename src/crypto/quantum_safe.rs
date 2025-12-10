//! Quantum-Safe Cryptography Layer for Celereum
//!
//! This module provides a unified interface for post-quantum signatures,
//! allowing seamless migration from Ed25519 to SEVS.
//!
//! # Design
//! - Uses SEVS as the primary signature scheme
//! - Maintains backward compatibility with Ed25519 during transition
//! - Provides type aliases and wrapper types for easy migration
//!
//! # Security
//! - All operations use constant-time comparisons
//! - Secret keys are zeroized on drop
//! - Deterministic signing (no RNG during sign)

use serde::{Deserialize, Serialize};
use std::fmt;
use subtle::ConstantTimeEq;

use super::sevs::{
    SevsKeypair, SevsPubkey, SevsSignature, SevsError,
    SIGNATURE_SIZE, PUBLIC_KEY_SIZE,
};
use super::hash::Hash;

// =============================================================================
// TYPE ALIASES FOR QUANTUM-SAFE CRYPTOGRAPHY
// =============================================================================

/// Quantum-safe public key (currently SEVS, 64 bytes)
pub type QsPubkey = SevsPubkey;

/// Quantum-safe signature (currently SEVS, 128 bytes)
pub type QsSignature = SevsSignature;

/// Quantum-safe keypair (currently SEVS)
pub type QsKeypair = SevsKeypair;

/// Quantum-safe error type
pub type QsError = SevsError;

// =============================================================================
// ACCOUNT ADDRESS (32 bytes, derived from QsPubkey)
// =============================================================================

/// Account address (32-byte hash of public key)
///
/// While SEVS public keys are 64 bytes, account addresses remain 32 bytes
/// for compatibility with existing infrastructure. The address is derived
/// as SHA3-256(pubkey).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// Create from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Address(bytes)
    }

    /// Create zero address (system program)
    pub fn zero() -> Self {
        Address([0u8; 32])
    }

    /// Derive address from SEVS public key
    pub fn from_pubkey(pubkey: &SevsPubkey) -> Self {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(b"CELEREUM_ADDRESS_V1");
        hasher.update(pubkey.as_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Address(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Check if address is zero using constant-time comparison
    #[inline]
    pub fn is_zero(&self) -> bool {
        let zero = [0u8; 32];
        self.0.ct_eq(&zero).into()
    }

    /// Convert to Bech32 cel1 string (preferred format)
    pub fn to_bech32(&self) -> String {
        super::bech32::encode_cel_address(&self.0)
    }

    /// Convert to base58 string (legacy format)
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Parse from either cel1 Bech32 or legacy base58 string
    ///
    /// Supports:
    /// - cel1... (Bech32 with checksum, preferred)
    /// - Base58 (legacy, for backward compatibility)
    pub fn from_base58(s: &str) -> Result<Self, AddressParseError> {
        // Try Bech32 cel1 format first (preferred)
        if super::bech32::is_cel1_format(s) {
            match super::bech32::decode_cel_address(s) {
                Ok(bytes) => return Ok(Address(bytes)),
                Err(e) => return Err(AddressParseError::Bech32(e)),
            }
        }

        // Legacy Base58 fallback
        let bytes = bs58::decode(s).into_vec()
            .map_err(|e| AddressParseError::Base58(e))?;
        if bytes.len() != 32 {
            return Err(AddressParseError::InvalidLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Address(arr))
    }

    /// Parse from Bech32 cel1 format only (strict)
    pub fn from_bech32(s: &str) -> Result<Self, super::bech32::Bech32Error> {
        let bytes = super::bech32::decode_cel_address(s)?;
        Ok(Address(bytes))
    }
}

/// Address parsing error
#[derive(Debug)]
pub enum AddressParseError {
    /// Bech32 decoding error
    Bech32(super::bech32::Bech32Error),
    /// Base58 decoding error
    Base58(bs58::decode::Error),
    /// Invalid address length
    InvalidLength(usize),
}

impl fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bech32(e) => write!(f, "Bech32 error: {}", e),
            Self::Base58(e) => write!(f, "Base58 error: {:?}", e),
            Self::InvalidLength(len) => write!(f, "Invalid address length: {} (expected 32)", len),
        }
    }
}

impl std::error::Error for AddressParseError {}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({}...)", &self.to_base58()[..8])
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::zero()
    }
}

// =============================================================================
// QUANTUM-SAFE TRANSACTION SIGNATURE
// =============================================================================

/// A complete transaction signature bundle
///
/// Contains:
/// - The SEVS signature (128 bytes)
/// - The signer's public key (64 bytes)
/// - The derived address (32 bytes, for quick lookup)
#[derive(Clone, Serialize, Deserialize)]
pub struct TxSignature {
    /// The actual signature
    pub signature: SevsSignature,
    /// The public key used to sign
    pub pubkey: SevsPubkey,
    /// Derived address (cached for efficiency)
    address: Address,
}

impl TxSignature {
    /// Create a new transaction signature
    pub fn new(signature: SevsSignature, pubkey: SevsPubkey) -> Self {
        let address = Address::from_pubkey(&pubkey);
        Self { signature, pubkey, address }
    }

    /// Get the signer's address
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Verify the signature against a message
    pub fn verify(&self, message: &[u8]) -> bool {
        self.signature.verify(message, &self.pubkey)
    }

    /// Get total size in bytes
    pub fn size(&self) -> usize {
        SIGNATURE_SIZE + PUBLIC_KEY_SIZE + 32
    }

    /// Convert signature to base58 string (uses the SEVS signature bytes)
    pub fn to_base58(&self) -> String {
        self.signature.to_base58()
    }

    /// Parse from base58 string (creates a partial TxSignature with default pubkey/address)
    /// This is mainly for lookup purposes in RPC methods
    pub fn from_base58(s: &str) -> Result<Self, bs58::decode::Error> {
        let signature = SevsSignature::from_base58(s)?;
        // Use zero pubkey and address since we're only using this for lookup
        let pubkey = SevsPubkey::zero();
        let address = Address::zero();
        Ok(Self { signature, pubkey, address })
    }

    /// Get signature bytes as slice
    pub fn as_bytes(&self) -> &[u8] {
        self.signature.as_bytes()
    }
}

impl fmt::Debug for TxSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxSignature({:?})", self.address)
    }
}

// =============================================================================
// QUANTUM-SAFE SIGNER TRAIT
// =============================================================================

/// Trait for types that can sign messages
pub trait QsSigner {
    /// Sign a message and return the signature
    fn sign(&self, message: &[u8]) -> SevsSignature;

    /// Get the public key
    fn pubkey(&self) -> SevsPubkey;

    /// Get the derived address
    fn address(&self) -> Address {
        Address::from_pubkey(&self.pubkey())
    }

    /// Sign and create a full transaction signature
    fn sign_tx(&self, message: &[u8]) -> TxSignature {
        let signature = self.sign(message);
        TxSignature::new(signature, self.pubkey())
    }
}

impl QsSigner for SevsKeypair {
    fn sign(&self, message: &[u8]) -> SevsSignature {
        SevsKeypair::sign(self, message)
    }

    fn pubkey(&self) -> SevsPubkey {
        SevsKeypair::pubkey(self)
    }
}

// =============================================================================
// MIGRATION HELPERS
// =============================================================================

/// Configuration for signature scheme migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationConfig {
    /// Whether to accept legacy Ed25519 signatures
    pub accept_legacy: bool,
    /// Slot at which to stop accepting legacy signatures
    pub legacy_cutoff_slot: Option<u64>,
    /// Whether to require SEVS for new transactions
    pub require_sevs: bool,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            accept_legacy: false,  // SEVS only by default
            legacy_cutoff_slot: None,
            require_sevs: true,
        }
    }
}

impl MigrationConfig {
    /// Create a config for SEVS-only mode (post-migration)
    pub fn sevs_only() -> Self {
        Self {
            accept_legacy: false,
            legacy_cutoff_slot: None,
            require_sevs: true,
        }
    }

    /// Check if legacy signatures should be accepted at a given slot
    pub fn accepts_legacy(&self, slot: u64) -> bool {
        if !self.accept_legacy {
            return false;
        }
        match self.legacy_cutoff_slot {
            Some(cutoff) => slot < cutoff,
            None => true,
        }
    }
}

// =============================================================================
// CONSTANTS
// =============================================================================

/// Signature size for quantum-safe signatures (SEVS)
pub const QS_SIGNATURE_SIZE: usize = SIGNATURE_SIZE;

/// Public key size for quantum-safe keys (SEVS)
pub const QS_PUBKEY_SIZE: usize = PUBLIC_KEY_SIZE;

/// Address size (always 32 bytes)
pub const ADDRESS_SIZE: usize = 32;

/// Total size of a transaction signature bundle
pub const TX_SIGNATURE_SIZE: usize = QS_SIGNATURE_SIZE + QS_PUBKEY_SIZE + ADDRESS_SIZE;

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_from_pubkey() {
        let keypair = SevsKeypair::generate();
        let address = Address::from_pubkey(&keypair.pubkey());

        // Address should be 32 bytes
        assert_eq!(address.as_bytes().len(), 32);

        // Same pubkey should give same address
        let address2 = Address::from_pubkey(&keypair.pubkey());
        assert_eq!(address, address2);

        // Different pubkey should give different address
        let keypair2 = SevsKeypair::generate();
        let address3 = Address::from_pubkey(&keypair2.pubkey());
        assert_ne!(address, address3);
    }

    #[test]
    fn test_address_base58() {
        let keypair = SevsKeypair::generate();
        let address = Address::from_pubkey(&keypair.pubkey());

        let encoded = address.to_base58();
        let decoded = Address::from_base58(&encoded).unwrap();

        assert_eq!(address, decoded);
    }

    #[test]
    fn test_tx_signature() {
        let keypair = SevsKeypair::generate();
        let message = b"test transaction";

        let tx_sig = keypair.sign_tx(message);

        // Verify works
        assert!(tx_sig.verify(message));

        // Wrong message fails
        assert!(!tx_sig.verify(b"wrong message"));

        // Address matches
        assert_eq!(tx_sig.address(), &keypair.address());
    }

    #[test]
    fn test_qs_signer_trait() {
        let keypair = SevsKeypair::generate();
        let message = b"trait test";

        // Test trait methods
        let sig = keypair.sign(message);
        let pubkey = keypair.pubkey();
        let address = keypair.address();

        // Verify signature
        assert!(sig.verify(message, &pubkey));

        // Address derived correctly
        assert_eq!(address, Address::from_pubkey(&pubkey));
    }

    #[test]
    fn test_zero_address() {
        let zero = Address::zero();
        assert!(zero.is_zero());

        let keypair = SevsKeypair::generate();
        let address = keypair.address();
        assert!(!address.is_zero());
    }

    #[test]
    fn test_migration_config() {
        let config = MigrationConfig::sevs_only();
        assert!(!config.accepts_legacy(0));
        assert!(!config.accepts_legacy(1000));

        let config_with_legacy = MigrationConfig {
            accept_legacy: true,
            legacy_cutoff_slot: Some(1000),
            require_sevs: false,
        };
        assert!(config_with_legacy.accepts_legacy(500));
        assert!(!config_with_legacy.accepts_legacy(1000));
        assert!(!config_with_legacy.accepts_legacy(1500));
    }

    #[test]
    fn test_tx_signature_size() {
        let keypair = SevsKeypair::generate();
        let tx_sig = keypair.sign_tx(b"size test");

        assert_eq!(tx_sig.size(), TX_SIGNATURE_SIZE);
        assert_eq!(TX_SIGNATURE_SIZE, 128 + 64 + 32); // 224 bytes total
    }
}
