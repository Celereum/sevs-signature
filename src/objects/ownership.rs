//! Object Ownership Model
//!
//! Defines how objects are owned and accessed in the object-centric model.

use crate::crypto::Pubkey;
use serde::{Deserialize, Serialize};

/// Owner of an object
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Owner {
    /// Owned by a single address
    Address(Pubkey),
    /// Owned by another object (nested ownership)
    Object(super::ObjectId),
    /// Shared object (accessible by anyone)
    Shared,
    /// Immutable (cannot be modified, like published packages)
    Immutable,
}

impl Owner {
    /// Check if this is an address owner
    pub fn is_address(&self) -> bool {
        matches!(self, Self::Address(_))
    }

    /// Check if this is a shared object
    pub fn is_shared(&self) -> bool {
        matches!(self, Self::Shared)
    }

    /// Check if this is immutable
    pub fn is_immutable(&self) -> bool {
        matches!(self, Self::Immutable)
    }

    /// Get the address if this is address-owned
    pub fn as_address(&self) -> Option<&Pubkey> {
        match self {
            Self::Address(addr) => Some(addr),
            _ => None,
        }
    }

    /// Check if a given address can access this object
    pub fn can_access(&self, address: &Pubkey) -> bool {
        match self {
            Self::Address(owner) => owner == address,
            Self::Shared => true,
            Self::Immutable => true,
            Self::Object(_) => false, // Need to check parent object
        }
    }
}

/// Shared object configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedObject {
    /// Object ID
    pub id: super::ObjectId,
    /// Initial shared version
    pub initial_shared_version: u64,
    /// Whether mutations require consensus
    pub mutable: bool,
}

impl SharedObject {
    /// Create a new shared object reference
    pub fn new(id: super::ObjectId, version: u64, mutable: bool) -> Self {
        Self {
            id,
            initial_shared_version: version,
            mutable,
        }
    }
}

/// Ownership transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ownership {
    /// Previous owner
    pub from: Owner,
    /// New owner
    pub to: Owner,
    /// Object being transferred
    pub object_id: super::ObjectId,
    /// Version at transfer
    pub version: u64,
}

impl Ownership {
    /// Create a new ownership transfer
    pub fn transfer(
        object_id: super::ObjectId,
        version: u64,
        from: Owner,
        to: Owner,
    ) -> Self {
        Self { from, to, object_id, version }
    }

    /// Check if this is a transfer to shared
    pub fn is_sharing(&self) -> bool {
        !self.from.is_shared() && self.to.is_shared()
    }

    /// Check if this is a transfer from shared
    pub fn is_unsharing(&self) -> bool {
        self.from.is_shared() && !self.to.is_shared()
    }
}

/// Ownership errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum OwnershipError {
    #[error("Not owner of object {0:?}")]
    NotOwner(super::ObjectId),

    #[error("Object {0:?} is immutable")]
    Immutable(super::ObjectId),

    #[error("Object {0:?} is shared and requires consensus")]
    SharedRequiresConsensus(super::ObjectId),

    #[error("Cannot transfer shared object")]
    CannotTransferShared,

    #[error("Invalid ownership transfer")]
    InvalidTransfer,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn test_owner_access() {
        let addr1 = Keypair::generate().pubkey();
        let addr2 = Keypair::generate().pubkey();

        let owned = Owner::Address(addr1);
        assert!(owned.can_access(&addr1));
        assert!(!owned.can_access(&addr2));

        let shared = Owner::Shared;
        assert!(shared.can_access(&addr1));
        assert!(shared.can_access(&addr2));

        let immutable = Owner::Immutable;
        assert!(immutable.can_access(&addr1));
    }

    #[test]
    fn test_ownership_transfer() {
        let addr1 = Keypair::generate().pubkey();
        let addr2 = Keypair::generate().pubkey();
        let object_id = super::super::ObjectId::generate();

        let transfer = Ownership::transfer(
            object_id,
            1,
            Owner::Address(addr1),
            Owner::Address(addr2),
        );

        assert!(!transfer.is_sharing());
        assert!(!transfer.is_unsharing());

        let share = Ownership::transfer(
            object_id,
            2,
            Owner::Address(addr1),
            Owner::Shared,
        );

        assert!(share.is_sharing());
    }
}
