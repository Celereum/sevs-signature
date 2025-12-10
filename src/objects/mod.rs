//! Object-Centric Model Foundations
//!
//! This module provides the foundation for a future migration from
//! account-based to object-centric transaction model (similar to Sui).
//!
//! # Why Object-Centric?
//! - True parallelism: Independent objects can be modified concurrently
//! - No account bottlenecks: Hot accounts (e.g., DEX pools) don't block others
//! - Better scaling: Linear throughput with independent objects
//!
//! # Current Implementation
//! This is a foundation layer that can coexist with the account model.
//! Full migration requires significant ecosystem changes.
//!
//! # Key Concepts
//! - **Object**: An owned piece of data with a unique ID
//! - **ObjectRef**: A reference to an object (ID, version, digest)
//! - **Ownership**: Objects can be owned by addresses or shared
//! - **Transaction**: Consumes input objects, produces output objects

pub mod object;
pub mod ownership;
pub mod transaction;
pub mod executor;

pub use object::{
    Object, ObjectId, ObjectVersion, ObjectDigest, ObjectRef,
    ObjectType,
};
pub use ownership::{
    Owner, SharedObject, Ownership, OwnershipError,
};
pub use transaction::{
    ObjectTransaction, SignedTransaction, ObjectInput, ObjectOutput,
    TransactionDigest, TransactionEffects, GasData, ExecutionStatus,
    TransactionKind, TransactionCertificate,
};
pub use executor::{
    ObjectExecutor, ExecutionContext, ExecutionError,
    DependencyGraph, ObjectStore, MemoryObjectStore,
};
