//! Zero-Knowledge Proofs Module for Celereum
//!
//! Provides ZK-based scalability and privacy features:
//! - ZK-Compression: Compress transactions with validity proofs
//! - ZK-Rollup: Batch transactions with succinct proofs
//! - ZK-State: Verify entire state with single proof
//! - ZK-Validity: Fast validity proofs for transaction batches
//!
//! Uses a simplified ZK system optimized for speed over privacy.

pub mod compression;
pub mod rollup;
pub mod state;
pub mod circuits;
pub mod proofs;
pub mod validity;

pub use compression::{ZkCompressor, CompressedTransaction, CompressionProof};
pub use rollup::{ZkRollup, RollupBatch, RollupProof, RollupConfig};
pub use state::{ZkState, StateProof, StateRoot};
pub use circuits::{Circuit, CircuitBuilder, Constraint};
pub use proofs::{Proof, ProofSystem, Verifier, Prover};
pub use validity::{
    TransactionValidityProof, StateValidityProof, ExecutionValidityProof,
    ValidityProofGenerator, ValidityProofVerifier, ValidityError,
    ValidityPredicate, PredicateType, Constraint as ValidityConstraint, ConstraintType, Operand,
    MAX_TRANSACTIONS_PER_VALIDITY_PROOF, VALIDITY_PROOF_MAX_AGE_SECS,
};
