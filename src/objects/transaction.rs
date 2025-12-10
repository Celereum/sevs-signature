//! Object Transaction Model
//!
//! Defines transactions in the object-centric model where transactions
//! explicitly declare their inputs and outputs.

use crate::crypto::{Keypair, Pubkey};
use crate::crypto::Signature;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use super::{ObjectId, ObjectRef, ObjectDigest};
use super::ownership::Owner;

/// Transaction digest (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionDigest(pub [u8; 32]);

impl TransactionDigest {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for TransactionDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// Input to an object transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjectInput {
    /// Owned object input (must be owned by sender)
    OwnedObject {
        object_ref: ObjectRef,
    },
    /// Shared object input (requires consensus ordering)
    SharedObject {
        object_id: ObjectId,
        initial_shared_version: u64,
        mutable: bool,
    },
    /// Immutable object input (read-only)
    ImmutableObject {
        object_id: ObjectId,
    },
    /// Pure value input (not an object reference)
    Pure {
        data: Vec<u8>,
    },
}

impl ObjectInput {
    /// Create an owned object input
    pub fn owned(object_ref: ObjectRef) -> Self {
        Self::OwnedObject { object_ref }
    }

    /// Create a shared object input
    pub fn shared(object_id: ObjectId, version: u64, mutable: bool) -> Self {
        Self::SharedObject {
            object_id,
            initial_shared_version: version,
            mutable,
        }
    }

    /// Create an immutable object input
    pub fn immutable(object_id: ObjectId) -> Self {
        Self::ImmutableObject { object_id }
    }

    /// Create a pure value input
    pub fn pure(data: Vec<u8>) -> Self {
        Self::Pure { data }
    }

    /// Get the object ID if this is an object input
    pub fn object_id(&self) -> Option<ObjectId> {
        match self {
            Self::OwnedObject { object_ref } => Some(object_ref.id),
            Self::SharedObject { object_id, .. } => Some(*object_id),
            Self::ImmutableObject { object_id } => Some(*object_id),
            Self::Pure { .. } => None,
        }
    }

    /// Check if this input requires consensus ordering
    pub fn requires_consensus(&self) -> bool {
        matches!(self, Self::SharedObject { mutable: true, .. })
    }

    /// Check if this is a mutable input
    pub fn is_mutable(&self) -> bool {
        match self {
            Self::OwnedObject { .. } => true,
            Self::SharedObject { mutable, .. } => *mutable,
            Self::ImmutableObject { .. } => false,
            Self::Pure { .. } => false,
        }
    }
}

/// Output from an object transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjectOutput {
    /// Create a new object
    Created {
        object_id: ObjectId,
        owner: Owner,
        object_type: String,
        data: Vec<u8>,
    },
    /// Mutate an existing object
    Mutated {
        object_id: ObjectId,
        new_version: u64,
        new_digest: ObjectDigest,
        new_owner: Option<Owner>,
    },
    /// Delete an object
    Deleted {
        object_id: ObjectId,
        version: u64,
    },
    /// Wrap an object (nested inside another)
    Wrapped {
        object_id: ObjectId,
        parent_id: ObjectId,
    },
    /// Unwrap an object (extracted from parent)
    Unwrapped {
        object_id: ObjectId,
        new_owner: Owner,
    },
}

impl ObjectOutput {
    /// Get the affected object ID
    pub fn object_id(&self) -> ObjectId {
        match self {
            Self::Created { object_id, .. } => *object_id,
            Self::Mutated { object_id, .. } => *object_id,
            Self::Deleted { object_id, .. } => *object_id,
            Self::Wrapped { object_id, .. } => *object_id,
            Self::Unwrapped { object_id, .. } => *object_id,
        }
    }
}

/// Transaction kind
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionKind {
    /// Programmable transaction (general purpose)
    Programmable {
        inputs: Vec<ObjectInput>,
        commands: Vec<Command>,
    },
    /// Transfer objects to a recipient
    Transfer {
        objects: Vec<ObjectRef>,
        recipient: Pubkey,
    },
    /// Publish a new program/package
    Publish {
        modules: Vec<Vec<u8>>,
        dependencies: Vec<ObjectId>,
    },
    /// System transaction (epoch changes, etc.)
    System {
        kind: SystemTransactionKind,
    },
}

/// Commands in a programmable transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    /// Move a specific input to output
    TransferObjects {
        objects: Vec<u16>, // indices into inputs
        recipient: Pubkey,
    },
    /// Split coins from a source
    SplitCoins {
        coin: u16, // input index
        amounts: Vec<u64>,
    },
    /// Merge coins into a target
    MergeCoins {
        destination: u16, // input index
        sources: Vec<u16>, // input indices
    },
    /// Call a Move function
    MoveCall {
        package: ObjectId,
        module: String,
        function: String,
        type_arguments: Vec<String>,
        arguments: Vec<u16>, // input indices
    },
    /// Make an object shared
    MakeShared {
        object: u16, // input index
    },
    /// Make an object immutable
    MakeImmutable {
        object: u16, // input index
    },
}

/// System transaction kinds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemTransactionKind {
    /// Genesis transaction
    Genesis,
    /// Epoch change
    EpochChange {
        new_epoch: u64,
        new_validators: Vec<Pubkey>,
    },
    /// Consensus commit prologue
    ConsensusCommitPrologue {
        round: u64,
        commit_timestamp_ms: u64,
    },
    /// Authenticator state update
    AuthenticatorStateUpdate {
        new_active_jwks: Vec<Vec<u8>>,
    },
}

/// Gas data for transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasData {
    /// Gas payment objects
    pub payment: Vec<ObjectRef>,
    /// Gas owner (who pays)
    pub owner: Pubkey,
    /// Gas price in smallest units
    pub price: u64,
    /// Maximum gas budget
    pub budget: u64,
}

impl GasData {
    /// Create new gas data
    pub fn new(payment: Vec<ObjectRef>, owner: Pubkey, price: u64, budget: u64) -> Self {
        Self { payment, owner, price, budget }
    }

    /// Calculate maximum gas cost
    pub fn max_cost(&self) -> u64 {
        self.price.saturating_mul(self.budget)
    }
}

/// Object transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectTransaction {
    /// Transaction kind
    pub kind: TransactionKind,
    /// Sender address
    pub sender: Pubkey,
    /// Gas data
    pub gas_data: GasData,
    /// Expiration epoch (optional)
    pub expiration: Option<u64>,
}

impl ObjectTransaction {
    /// Create a new object transaction
    pub fn new(
        kind: TransactionKind,
        sender: Pubkey,
        gas_data: GasData,
        expiration: Option<u64>,
    ) -> Self {
        Self { kind, sender, gas_data, expiration }
    }

    /// Create a transfer transaction
    pub fn transfer(
        objects: Vec<ObjectRef>,
        recipient: Pubkey,
        sender: Pubkey,
        gas_data: GasData,
    ) -> Self {
        Self::new(
            TransactionKind::Transfer { objects, recipient },
            sender,
            gas_data,
            None,
        )
    }

    /// Calculate transaction digest
    pub fn digest(&self) -> TransactionDigest {
        let serialized = bincode::serialize(self).unwrap_or_default();
        let hash = Sha256::digest(&serialized);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        TransactionDigest(bytes)
    }

    /// Get all input object IDs
    pub fn input_objects(&self) -> Vec<ObjectId> {
        match &self.kind {
            TransactionKind::Programmable { inputs, .. } => {
                inputs.iter().filter_map(|i| i.object_id()).collect()
            }
            TransactionKind::Transfer { objects, .. } => {
                objects.iter().map(|r| r.id).collect()
            }
            TransactionKind::Publish { dependencies, .. } => {
                dependencies.clone()
            }
            TransactionKind::System { .. } => vec![],
        }
    }

    /// Check if this transaction requires consensus ordering
    pub fn requires_consensus(&self) -> bool {
        match &self.kind {
            TransactionKind::Programmable { inputs, .. } => {
                inputs.iter().any(|i| i.requires_consensus())
            }
            TransactionKind::System { .. } => true,
            _ => false,
        }
    }

    /// Get shared object inputs
    pub fn shared_inputs(&self) -> Vec<(ObjectId, u64, bool)> {
        match &self.kind {
            TransactionKind::Programmable { inputs, .. } => {
                inputs.iter()
                    .filter_map(|i| {
                        if let ObjectInput::SharedObject {
                            object_id,
                            initial_shared_version,
                            mutable
                        } = i {
                            Some((*object_id, *initial_shared_version, *mutable))
                        } else {
                            None
                        }
                    })
                    .collect()
            }
            _ => vec![],
        }
    }
}

/// Signed transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The transaction
    pub transaction: ObjectTransaction,
    /// Signature
    pub signature: Signature,
}

impl SignedTransaction {
    /// Sign a transaction
    pub fn sign(transaction: ObjectTransaction, keypair: &Keypair) -> Self {
        let digest = transaction.digest();
        let sevs_sig = keypair.sign(digest.as_bytes());
        let signature = crate::crypto::TxSignature::new(sevs_sig, keypair.pubkey());
        Self { transaction, signature }
    }

    /// Verify the signature
    pub fn verify(&self) -> bool {
        let digest = self.transaction.digest();
        self.signature.verify(digest.as_bytes())
    }

    /// Get transaction digest
    pub fn digest(&self) -> TransactionDigest {
        self.transaction.digest()
    }
}

/// Transaction effects (result of execution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionEffects {
    /// Transaction digest
    pub transaction_digest: TransactionDigest,
    /// Status
    pub status: ExecutionStatus,
    /// Gas used
    pub gas_used: GasUsed,
    /// Objects created
    pub created: Vec<(ObjectRef, Owner)>,
    /// Objects mutated
    pub mutated: Vec<(ObjectRef, Owner)>,
    /// Objects deleted
    pub deleted: Vec<ObjectRef>,
    /// Objects wrapped
    pub wrapped: Vec<ObjectRef>,
    /// Objects unwrapped
    pub unwrapped: Vec<(ObjectRef, Owner)>,
    /// Gas object after execution
    pub gas_object: (ObjectRef, Owner),
    /// Events emitted
    pub events_digest: Option<[u8; 32]>,
    /// Dependencies (input object versions)
    pub dependencies: Vec<TransactionDigest>,
}

/// Execution status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    /// Successful execution
    Success,
    /// Execution failed
    Failure {
        error: String,
        command_index: Option<u16>,
    },
}

impl ExecutionStatus {
    /// Check if execution was successful
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

/// Gas usage breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasUsed {
    /// Computation cost
    pub computation_cost: u64,
    /// Storage cost
    pub storage_cost: u64,
    /// Storage rebate
    pub storage_rebate: u64,
    /// Non-refundable storage fee
    pub non_refundable_storage_fee: u64,
}

impl GasUsed {
    /// Calculate net gas cost
    pub fn net_cost(&self) -> i64 {
        let total_cost = self.computation_cost
            .saturating_add(self.storage_cost)
            .saturating_add(self.non_refundable_storage_fee);
        (total_cost as i64) - (self.storage_rebate as i64)
    }
}

/// Transaction certificate (signed by validators)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionCertificate {
    /// The signed transaction
    pub signed_transaction: SignedTransaction,
    /// Validator signatures (BLS aggregated in production)
    pub validator_signatures: Vec<(Pubkey, Signature)>,
    /// Total stake that signed
    pub signed_stake: u64,
}

impl TransactionCertificate {
    /// Create a new certificate
    pub fn new(
        signed_transaction: SignedTransaction,
        validator_signatures: Vec<(Pubkey, Signature)>,
        signed_stake: u64,
    ) -> Self {
        Self {
            signed_transaction,
            validator_signatures,
            signed_stake,
        }
    }

    /// Check if certificate has quorum
    pub fn has_quorum(&self, total_stake: u64) -> bool {
        // 2/3 + 1 threshold
        let threshold = (total_stake * 2) / 3 + 1;
        self.signed_stake >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_digest() {
        let keypair = Keypair::generate();
        let sender = keypair.pubkey();

        let gas_data = GasData::new(vec![], sender, 1000, 50000);
        let tx = ObjectTransaction::transfer(vec![], sender, sender, gas_data);

        let digest1 = tx.digest();
        let digest2 = tx.digest();

        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_signed_transaction() {
        let keypair = Keypair::generate();
        let sender = keypair.pubkey();

        let gas_data = GasData::new(vec![], sender, 1000, 50000);
        let tx = ObjectTransaction::transfer(vec![], sender, sender, gas_data);

        let signed = SignedTransaction::sign(tx, &keypair);
        assert!(signed.verify());
    }

    #[test]
    fn test_object_input_types() {
        let object_id = ObjectId::generate();

        let owned = ObjectInput::owned(ObjectRef {
            id: object_id,
            version: 1,
            digest: ObjectDigest::new([0u8; 32]),
        });
        assert!(owned.is_mutable());
        assert!(!owned.requires_consensus());

        let shared = ObjectInput::shared(object_id, 1, true);
        assert!(shared.is_mutable());
        assert!(shared.requires_consensus());

        let immutable = ObjectInput::immutable(object_id);
        assert!(!immutable.is_mutable());
        assert!(!immutable.requires_consensus());
    }

    #[test]
    fn test_gas_calculation() {
        let gas = GasUsed {
            computation_cost: 1000,
            storage_cost: 500,
            storage_rebate: 200,
            non_refundable_storage_fee: 50,
        };

        // 1000 + 500 + 50 - 200 = 1350
        assert_eq!(gas.net_cost(), 1350);
    }

    #[test]
    fn test_execution_status() {
        let success = ExecutionStatus::Success;
        assert!(success.is_success());

        let failure = ExecutionStatus::Failure {
            error: "out of gas".to_string(),
            command_index: Some(2),
        };
        assert!(!failure.is_success());
    }
}
