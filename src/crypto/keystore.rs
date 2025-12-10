//! Encrypted Keystore for Celereum
//!
//! Provides secure storage of private keys with password-based encryption.
//!
//! # Security Features
//! - Argon2id key derivation (memory-hard, resistant to GPU attacks)
//! - AES-256-GCM authenticated encryption
//! - Secure memory handling with zeroization
//! - Version-tagged format for future upgrades
//!
//! # Usage
//! ```ignore
//! let keypair = Keypair::generate();
//! let keystore = EncryptedKeystore::encrypt(&keypair, "my-password")?;
//! keystore.save("validator.key")?;
//!
//! let loaded = EncryptedKeystore::load("validator.key")?;
//! let decrypted = loaded.decrypt("my-password")?;
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::SaltString,
    Argon2, Params,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Keypair, Pubkey};

/// Keystore version for format compatibility
const KEYSTORE_VERSION: u8 = 1;

/// Argon2 parameters (OWASP recommended for high-security)
const ARGON2_MEMORY_KB: u32 = 65536;  // 64 MB
const ARGON2_TIME_COST: u32 = 3;       // 3 iterations
const ARGON2_PARALLELISM: u32 = 4;     // 4 threads
const ARGON2_OUTPUT_LEN: usize = 32;   // 256-bit key

/// Salt length in bytes
const SALT_LEN: usize = 32;

/// Nonce length for AES-GCM
const NONCE_LEN: usize = 12;

/// Keystore errors
#[derive(Debug, Clone, PartialEq)]
pub enum KeystoreError {
    /// Password is too weak
    WeakPassword,
    /// Failed to derive key
    KeyDerivationFailed,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed (wrong password or corrupted data)
    DecryptionFailed,
    /// Invalid keystore format
    InvalidFormat,
    /// Version not supported
    UnsupportedVersion(u8),
    /// IO error
    IoError(String),
    /// Invalid key data
    InvalidKeyData,
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WeakPassword => write!(f, "Password must be at least 12 characters"),
            Self::KeyDerivationFailed => write!(f, "Failed to derive encryption key"),
            Self::EncryptionFailed => write!(f, "Failed to encrypt private key"),
            Self::DecryptionFailed => write!(f, "Failed to decrypt (wrong password or corrupted data)"),
            Self::InvalidFormat => write!(f, "Invalid keystore file format"),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported keystore version: {}", v),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::InvalidKeyData => write!(f, "Invalid key data after decryption"),
        }
    }
}

impl std::error::Error for KeystoreError {}

/// Encrypted keystore containing a single keypair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeystore {
    /// Keystore format version
    version: u8,
    /// Public key (stored in plaintext for identification)
    pubkey: [u8; 32],
    /// Salt for key derivation
    salt: [u8; SALT_LEN],
    /// Nonce for AES-GCM
    nonce: [u8; NONCE_LEN],
    /// Encrypted private key (32 bytes + 16 byte auth tag)
    encrypted_secret: Vec<u8>,
    /// Optional metadata
    #[serde(default)]
    metadata: KeystoreMetadata,
}

/// Keystore metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeystoreMetadata {
    /// Creation timestamp (Unix epoch)
    pub created_at: Option<u64>,
    /// Human-readable name
    pub name: Option<String>,
    /// Key purpose (e.g., "validator", "user")
    pub purpose: Option<String>,
}

/// Secure wrapper for derived key (zeroized on drop)
#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKey([u8; 32]);

impl EncryptedKeystore {
    /// Encrypt a keypair with a password
    ///
    /// # Arguments
    /// * `keypair` - The keypair to encrypt
    /// * `password` - Password for encryption (minimum 12 characters)
    ///
    /// # Security
    /// - Password must be at least 12 characters
    /// - Uses Argon2id with OWASP-recommended parameters
    /// - Random salt and nonce for each encryption
    pub fn encrypt(keypair: &Keypair, password: &str) -> Result<Self, KeystoreError> {
        Self::encrypt_with_metadata(keypair, password, KeystoreMetadata::default())
    }

    /// Encrypt a keypair with password and metadata
    pub fn encrypt_with_metadata(
        keypair: &Keypair,
        password: &str,
        metadata: KeystoreMetadata,
    ) -> Result<Self, KeystoreError> {
        // Validate password strength
        if password.len() < 12 {
            return Err(KeystoreError::WeakPassword);
        }

        // Generate random salt
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Derive encryption key using Argon2id
        let derived_key = Self::derive_key(password, &salt)?;

        // Encrypt private key with AES-256-GCM
        // Note: We store the full secret key (96 bytes: 32 seed + 64 compressed s)
        let secret_bytes = {
            let mut bytes = Vec::with_capacity(96);
            bytes.extend_from_slice(keypair.secret()); // 32-byte seed
            // We need the full secret, but only seed is exposed.
            // For now, just store seed and regenerate - TODO: expose full secret
            bytes.extend_from_slice(&[0u8; 64]); // Placeholder for s_compressed
            bytes
        };

        let cipher = Aes256Gcm::new_from_slice(&derived_key.0)
            .map_err(|_| KeystoreError::EncryptionFailed)?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted_secret = cipher
            .encrypt(nonce, secret_bytes.as_ref())
            .map_err(|_| KeystoreError::EncryptionFailed)?;

        // Add creation timestamp
        let mut metadata = metadata;
        if metadata.created_at.is_none() {
            metadata.created_at = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            );
        }

        Ok(Self {
            version: KEYSTORE_VERSION,
            pubkey: *keypair.address().as_bytes(),
            salt,
            nonce: nonce_bytes,
            encrypted_secret,
            metadata,
        })
    }

    /// Decrypt the keystore with a password
    ///
    /// # Security
    /// - Returns error on wrong password (constant-time comparison in AES-GCM)
    /// - Private key is zeroized if decryption fails
    pub fn decrypt(&self, password: &str) -> Result<Keypair, KeystoreError> {
        // Check version
        if self.version != KEYSTORE_VERSION {
            return Err(KeystoreError::UnsupportedVersion(self.version));
        }

        // Derive decryption key
        let derived_key = Self::derive_key(password, &self.salt)?;

        // Decrypt private key
        let cipher = Aes256Gcm::new_from_slice(&derived_key.0)
            .map_err(|_| KeystoreError::DecryptionFailed)?;

        let nonce = Nonce::from_slice(&self.nonce);
        let mut secret_bytes = cipher
            .decrypt(nonce, self.encrypted_secret.as_ref())
            .map_err(|_| KeystoreError::DecryptionFailed)?;

        // Validate decrypted key length (96 bytes for SEVS)
        if secret_bytes.len() != 96 {
            secret_bytes.zeroize();
            return Err(KeystoreError::InvalidKeyData);
        }

        // Create keypair from decrypted secret (96 bytes)
        let mut secret_arr = [0u8; 96];
        secret_arr.copy_from_slice(&secret_bytes);
        secret_bytes.zeroize();

        let keypair = Keypair::from_bytes(&secret_arr)
            .map_err(|_| KeystoreError::InvalidKeyData)?;

        // Zeroize the secret array
        secret_arr.zeroize();

        // Verify address matches
        if keypair.address().as_bytes() != &self.pubkey {
            return Err(KeystoreError::InvalidKeyData);
        }

        Ok(keypair)
    }

    /// Get the public key (available without decryption)
    pub fn pubkey(&self) -> Pubkey {
        Pubkey::new(self.pubkey)
    }

    /// Get keystore metadata
    pub fn metadata(&self) -> &KeystoreMetadata {
        &self.metadata
    }

    /// Save keystore to a file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), KeystoreError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| KeystoreError::IoError(e.to_string()))?;

        std::fs::write(path, json)
            .map_err(|e| KeystoreError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Load keystore from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, KeystoreError> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| KeystoreError::IoError(e.to_string()))?;

        let keystore: Self = serde_json::from_str(&json)
            .map_err(|_| KeystoreError::InvalidFormat)?;

        Ok(keystore)
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, KeystoreError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| KeystoreError::IoError(e.to_string()))
    }

    /// Deserialize from JSON string
    pub fn from_json(json: &str) -> Result<Self, KeystoreError> {
        serde_json::from_str(json)
            .map_err(|_| KeystoreError::InvalidFormat)
    }

    /// Derive encryption key using Argon2id
    fn derive_key(password: &str, salt: &[u8]) -> Result<DerivedKey, KeystoreError> {
        let params = Params::new(
            ARGON2_MEMORY_KB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(ARGON2_OUTPUT_LEN),
        ).map_err(|_| KeystoreError::KeyDerivationFailed)?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );

        let mut output = [0u8; 32];
        argon2.hash_password_into(
            password.as_bytes(),
            salt,
            &mut output,
        ).map_err(|_| KeystoreError::KeyDerivationFailed)?;

        Ok(DerivedKey(output))
    }

    /// Change the password for an existing keystore
    pub fn change_password(&self, old_password: &str, new_password: &str) -> Result<Self, KeystoreError> {
        // Decrypt with old password
        let keypair = self.decrypt(old_password)?;

        // Re-encrypt with new password, preserving metadata
        Self::encrypt_with_metadata(&keypair, new_password, self.metadata.clone())
    }
}

/// Secure keystore for multiple keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiKeystore {
    /// Individual encrypted keystores
    keystores: Vec<EncryptedKeystore>,
}

impl MultiKeystore {
    /// Create a new empty multi-keystore
    pub fn new() -> Self {
        Self { keystores: Vec::new() }
    }

    /// Add a keypair to the keystore
    pub fn add(&mut self, keypair: &Keypair, password: &str, metadata: KeystoreMetadata) -> Result<(), KeystoreError> {
        let keystore = EncryptedKeystore::encrypt_with_metadata(keypair, password, metadata)?;
        self.keystores.push(keystore);
        Ok(())
    }

    /// Get all public keys
    pub fn pubkeys(&self) -> Vec<Pubkey> {
        self.keystores.iter().map(|k| k.pubkey()).collect()
    }

    /// Find and decrypt a specific keypair by public key
    pub fn get(&self, pubkey: &Pubkey, password: &str) -> Result<Keypair, KeystoreError> {
        for keystore in &self.keystores {
            if &keystore.pubkey() == pubkey {
                return keystore.decrypt(password);
            }
        }
        Err(KeystoreError::InvalidKeyData)
    }

    /// Remove a keypair by public key
    pub fn remove(&mut self, pubkey: &Pubkey) -> bool {
        let len_before = self.keystores.len();
        self.keystores.retain(|k| &k.pubkey() != pubkey);
        self.keystores.len() < len_before
    }

    /// Number of stored keys
    pub fn len(&self) -> usize {
        self.keystores.len()
    }

    /// Check if keystore is empty
    pub fn is_empty(&self) -> bool {
        self.keystores.is_empty()
    }

    /// Save to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), KeystoreError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| KeystoreError::IoError(e.to_string()))?;
        std::fs::write(path, json)
            .map_err(|e| KeystoreError::IoError(e.to_string()))?;
        Ok(())
    }

    /// Load from file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, KeystoreError> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| KeystoreError::IoError(e.to_string()))?;
        serde_json::from_str(&json)
            .map_err(|_| KeystoreError::InvalidFormat)
    }
}

impl Default for MultiKeystore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let keypair = Keypair::generate();
        let password = "secure_password_123";

        let keystore = EncryptedKeystore::encrypt(&keypair, password).unwrap();
        let decrypted = keystore.decrypt(password).unwrap();

        assert_eq!(keypair.pubkey(), decrypted.pubkey());
        assert_eq!(keypair.secret(), decrypted.secret());
    }

    #[test]
    fn test_wrong_password() {
        let keypair = Keypair::generate();
        let password = "secure_password_123";

        let keystore = EncryptedKeystore::encrypt(&keypair, password).unwrap();
        let result = keystore.decrypt("wrong_password!!");

        assert!(matches!(result, Err(KeystoreError::DecryptionFailed)));
    }

    #[test]
    fn test_weak_password() {
        let keypair = Keypair::generate();
        let result = EncryptedKeystore::encrypt(&keypair, "short");

        assert!(matches!(result, Err(KeystoreError::WeakPassword)));
    }

    #[test]
    fn test_pubkey_available() {
        let keypair = Keypair::generate();
        let password = "secure_password_123";

        let keystore = EncryptedKeystore::encrypt(&keypair, password).unwrap();

        assert_eq!(keystore.pubkey(), keypair.pubkey());
    }

    #[test]
    fn test_json_roundtrip() {
        let keypair = Keypair::generate();
        let password = "secure_password_123";

        let keystore = EncryptedKeystore::encrypt(&keypair, password).unwrap();
        let json = keystore.to_json().unwrap();
        let loaded = EncryptedKeystore::from_json(&json).unwrap();

        let decrypted = loaded.decrypt(password).unwrap();
        assert_eq!(keypair.pubkey(), decrypted.pubkey());
    }

    #[test]
    fn test_change_password() {
        let keypair = Keypair::generate();
        let old_password = "old_secure_pass_123";
        let new_password = "new_secure_pass_456";

        let keystore = EncryptedKeystore::encrypt(&keypair, old_password).unwrap();
        let new_keystore = keystore.change_password(old_password, new_password).unwrap();

        // Old password should fail
        assert!(new_keystore.decrypt(old_password).is_err());

        // New password should work
        let decrypted = new_keystore.decrypt(new_password).unwrap();
        assert_eq!(keypair.pubkey(), decrypted.pubkey());
    }

    #[test]
    fn test_multi_keystore() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let password = "secure_password_123";

        let mut multi = MultiKeystore::new();
        multi.add(&kp1, password, KeystoreMetadata {
            name: Some("key1".to_string()),
            ..Default::default()
        }).unwrap();
        multi.add(&kp2, password, KeystoreMetadata {
            name: Some("key2".to_string()),
            ..Default::default()
        }).unwrap();

        assert_eq!(multi.len(), 2);
        assert!(multi.pubkeys().contains(&kp1.pubkey()));
        assert!(multi.pubkeys().contains(&kp2.pubkey()));

        let decrypted1 = multi.get(&kp1.pubkey(), password).unwrap();
        assert_eq!(decrypted1.pubkey(), kp1.pubkey());

        multi.remove(&kp1.pubkey());
        assert_eq!(multi.len(), 1);
    }
}
