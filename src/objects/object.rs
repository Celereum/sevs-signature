//! Object Definition
//!
//! Objects are the fundamental unit of data in the object-centric model.
//! Each object has a unique ID, version, and ownership.

use crate::crypto::{Hash, Pubkey};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for an object (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    /// Create a new object ID from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a new random object ID
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).unwrap_or_default();
        Self(bytes)
    }

    /// Create from transaction digest and creation index
    pub fn derive(tx_digest: &TransactionDigest, index: u64) -> Self {
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(tx_digest.as_bytes());
        hasher.update(&index.to_le_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Zero ID (for genesis objects)
    pub fn zero() -> Self {
        Self([0u8; 32])
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({}...)", &self.to_hex()[..8])
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Object version (monotonically increasing)
pub type ObjectVersion = u64;

/// Object digest (hash of object contents)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectDigest([u8; 32]);

impl ObjectDigest {
    /// Create from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compute digest from object data
    pub fn compute(data: &[u8]) -> Self {
        let hash = Hash::hash(data);
        Self(*hash.as_bytes())
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ObjectDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectDigest({}...)", hex::encode(&self.0[..4]))
    }
}

/// Transaction digest
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionDigest([u8; 32]);

impl TransactionDigest {
    /// Create from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compute from transaction data
    pub fn compute(data: &[u8]) -> Self {
        let hash = Hash::hash(data);
        Self(*hash.as_bytes())
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TransactionDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxDigest({}...)", hex::encode(&self.0[..4]))
    }
}

/// Reference to an object at a specific version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectRef {
    /// Object ID
    pub id: ObjectId,
    /// Version
    pub version: ObjectVersion,
    /// Digest
    pub digest: ObjectDigest,
}

impl ObjectRef {
    /// Create a new object reference
    pub fn new(id: ObjectId, version: ObjectVersion, digest: ObjectDigest) -> Self {
        Self { id, version, digest }
    }
}

/// Object type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectType {
    /// Native coin (CEL)
    Coin,
    /// Custom token
    Token { mint: Pubkey },
    /// NFT
    Nft { collection: Pubkey },
    /// Data object
    Data { schema: String },
    /// Program/smart contract
    Program,
    /// Shared object (e.g., DEX pool)
    Shared { type_tag: String },
}

/// Object data (the actual content)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjectData {
    /// Coin with amount
    Coin { amount: u64 },
    /// Token with mint and amount
    Token { mint: Pubkey, amount: u64 },
    /// NFT with metadata
    Nft {
        collection: Pubkey,
        name: String,
        uri: String,
        attributes: Vec<(String, String)>,
    },
    /// Raw data
    Raw(Vec<u8>),
    /// Move-like struct data
    Struct {
        type_tag: String,
        fields: Vec<(String, Vec<u8>)>,
    },
}

impl ObjectData {
    /// Get the size of the data
    pub fn size(&self) -> usize {
        match self {
            Self::Coin { .. } => 8,
            Self::Token { .. } => 40,
            Self::Nft { name, uri, attributes, .. } => {
                32 + name.len() + uri.len() +
                attributes.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
            }
            Self::Raw(data) => data.len(),
            Self::Struct { type_tag, fields } => {
                type_tag.len() +
                fields.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
            }
        }
    }
}

/// Object metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    /// Creation transaction
    pub created_tx: TransactionDigest,
    /// Last modified transaction
    pub modified_tx: TransactionDigest,
    /// Creation timestamp
    pub created_at: u64,
    /// Last modified timestamp
    pub modified_at: u64,
}

/// Complete Object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    /// Object ID
    pub id: ObjectId,
    /// Version (incremented on each modification)
    pub version: ObjectVersion,
    /// Object type
    pub object_type: ObjectType,
    /// Owner
    pub owner: super::Owner,
    /// Data
    pub data: ObjectData,
    /// Metadata
    pub metadata: ObjectMetadata,
}

impl Object {
    /// Create a new coin object
    pub fn new_coin(
        owner: Pubkey,
        amount: u64,
        tx_digest: TransactionDigest,
        index: u64,
    ) -> Self {
        let id = ObjectId::derive(&tx_digest, index);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            id,
            version: 1,
            object_type: ObjectType::Coin,
            owner: super::Owner::Address(owner),
            data: ObjectData::Coin { amount },
            metadata: ObjectMetadata {
                created_tx: tx_digest,
                modified_tx: tx_digest,
                created_at: now,
                modified_at: now,
            },
        }
    }

    /// Create a new token object
    pub fn new_token(
        owner: Pubkey,
        mint: Pubkey,
        amount: u64,
        tx_digest: TransactionDigest,
        index: u64,
    ) -> Self {
        let id = ObjectId::derive(&tx_digest, index);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            id,
            version: 1,
            object_type: ObjectType::Token { mint },
            owner: super::Owner::Address(owner),
            data: ObjectData::Token { mint, amount },
            metadata: ObjectMetadata {
                created_tx: tx_digest,
                modified_tx: tx_digest,
                created_at: now,
                modified_at: now,
            },
        }
    }

    /// Create a shared object
    pub fn new_shared(
        type_tag: String,
        data: ObjectData,
        tx_digest: TransactionDigest,
        index: u64,
    ) -> Self {
        let id = ObjectId::derive(&tx_digest, index);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            id,
            version: 1,
            object_type: ObjectType::Shared { type_tag },
            owner: super::Owner::Shared,
            data,
            metadata: ObjectMetadata {
                created_tx: tx_digest,
                modified_tx: tx_digest,
                created_at: now,
                modified_at: now,
            },
        }
    }

    /// Get object reference
    pub fn reference(&self) -> ObjectRef {
        let data = bincode::serialize(self).unwrap_or_default();
        let digest = ObjectDigest::compute(&data);

        ObjectRef {
            id: self.id,
            version: self.version,
            digest,
        }
    }

    /// Compute digest
    pub fn digest(&self) -> ObjectDigest {
        let data = bincode::serialize(self).unwrap_or_default();
        ObjectDigest::compute(&data)
    }

    /// Check if object is owned by address
    pub fn is_owned_by(&self, address: &Pubkey) -> bool {
        matches!(&self.owner, super::Owner::Address(owner) if owner == address)
    }

    /// Check if object is shared
    pub fn is_shared(&self) -> bool {
        matches!(self.owner, super::Owner::Shared)
    }

    /// Get coin amount (if this is a coin)
    pub fn coin_amount(&self) -> Option<u64> {
        match &self.data {
            ObjectData::Coin { amount } => Some(*amount),
            _ => None,
        }
    }

    /// Get token amount (if this is a token)
    pub fn token_amount(&self) -> Option<u64> {
        match &self.data {
            ObjectData::Token { amount, .. } => Some(*amount),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn test_object_id_generation() {
        let id1 = ObjectId::generate();
        let id2 = ObjectId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_object_id_derivation() {
        let tx_digest = TransactionDigest::compute(b"test_tx");
        let id1 = ObjectId::derive(&tx_digest, 0);
        let id2 = ObjectId::derive(&tx_digest, 1);
        let id3 = ObjectId::derive(&tx_digest, 0);

        assert_ne!(id1, id2);
        assert_eq!(id1, id3); // Same inputs = same output
    }

    #[test]
    fn test_coin_object() {
        let owner = Keypair::generate().pubkey();
        let tx_digest = TransactionDigest::compute(b"test_tx");

        let coin = Object::new_coin(owner, 1000, tx_digest, 0);

        assert_eq!(coin.version, 1);
        assert!(coin.is_owned_by(&owner));
        assert_eq!(coin.coin_amount(), Some(1000));
        assert!(!coin.is_shared());
    }

    #[test]
    fn test_object_reference() {
        let owner = Keypair::generate().pubkey();
        let tx_digest = TransactionDigest::compute(b"test_tx");

        let coin = Object::new_coin(owner, 1000, tx_digest, 0);
        let reference = coin.reference();

        assert_eq!(reference.id, coin.id);
        assert_eq!(reference.version, coin.version);
    }
}
