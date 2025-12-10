//! Hash types for Celereum blockchain

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::fmt;

/// 32-byte hash used throughout Celereum
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Create a new hash from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    /// Create a zero hash
    pub fn zero() -> Self {
        Hash([0u8; 32])
    }

    /// Check if this is a zero hash
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Hash arbitrary data using SHA256
    pub fn hash(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash(bytes)
    }

    /// Hash multiple pieces of data
    pub fn hash_multiple(data: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        for d in data {
            hasher.update(d);
        }
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash(bytes)
    }

    /// Extend this hash with more data (for PoH)
    pub fn extend(&self, data: &[u8]) -> Self {
        Self::hash_multiple(&[&self.0, data])
    }

    /// Get the bytes of the hash
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to base58 string
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Parse from base58 string
    pub fn from_base58(s: &str) -> Result<Self, bs58::decode::Error> {
        let bytes = bs58::decode(s).into_vec()?;
        if bytes.len() != 32 {
            return Err(bs58::decode::Error::BufferTooSmall);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Hash(arr))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::zero()
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", &self.to_base58()[..8])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let data = b"hello celereum";
        let hash = Hash::hash(data);
        assert_ne!(hash, Hash::zero());
    }

    #[test]
    fn test_hash_extend() {
        let hash1 = Hash::hash(b"initial");
        let hash2 = hash1.extend(b"more data");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_base58_roundtrip() {
        let hash = Hash::hash(b"test");
        let encoded = hash.to_base58();
        let decoded = Hash::from_base58(&encoded).unwrap();
        assert_eq!(hash, decoded);
    }
}
