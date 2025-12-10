//! Object Transaction Executor
//!
//! Parallel execution engine for object transactions.
//! Transactions with non-overlapping object sets can execute in parallel.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use crate::crypto::Pubkey;
use super::{Object, ObjectId, ObjectRef, ObjectDigest};
use super::ownership::{Owner, OwnershipError};
use super::transaction::{
    ObjectTransaction, SignedTransaction, TransactionDigest,
    TransactionEffects, ExecutionStatus, GasUsed, ObjectInput,
};

/// Object store trait
pub trait ObjectStore: Send + Sync {
    /// Get an object by ID
    fn get_object(&self, id: &ObjectId) -> Option<Object>;

    /// Get an object with specific version
    fn get_object_version(&self, id: &ObjectId, version: u64) -> Option<Object>;

    /// Get the latest version of an object
    fn get_latest_version(&self, id: &ObjectId) -> Option<u64>;

    /// Put an object
    fn put_object(&mut self, object: Object);

    /// Delete an object
    fn delete_object(&mut self, id: &ObjectId);

    /// Check if object exists
    fn exists(&self, id: &ObjectId) -> bool;
}

/// In-memory object store for testing
#[derive(Debug, Default)]
pub struct MemoryObjectStore {
    objects: HashMap<ObjectId, Object>,
    versions: HashMap<(ObjectId, u64), Object>,
}

impl MemoryObjectStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ObjectStore for MemoryObjectStore {
    fn get_object(&self, id: &ObjectId) -> Option<Object> {
        self.objects.get(id).cloned()
    }

    fn get_object_version(&self, id: &ObjectId, version: u64) -> Option<Object> {
        self.versions.get(&(*id, version)).cloned()
    }

    fn get_latest_version(&self, id: &ObjectId) -> Option<u64> {
        self.objects.get(id).map(|o| o.version)
    }

    fn put_object(&mut self, object: Object) {
        let id = object.id;
        let version = object.version;
        self.versions.insert((id, version), object.clone());
        self.objects.insert(id, object);
    }

    fn delete_object(&mut self, id: &ObjectId) {
        self.objects.remove(id);
    }

    fn exists(&self, id: &ObjectId) -> bool {
        self.objects.contains_key(id)
    }
}

/// Thread-safe object store wrapper
pub struct SharedObjectStore<S: ObjectStore> {
    inner: Arc<RwLock<S>>,
}

impl<S: ObjectStore> SharedObjectStore<S> {
    pub fn new(store: S) -> Self {
        Self {
            inner: Arc::new(RwLock::new(store)),
        }
    }

    pub fn get_object(&self, id: &ObjectId) -> Option<Object> {
        self.inner.read().ok()?.get_object(id)
    }

    pub fn put_object(&self, object: Object) {
        if let Ok(mut store) = self.inner.write() {
            store.put_object(object);
        }
    }
}

impl<S: ObjectStore> Clone for SharedObjectStore<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Execution context for a transaction
pub struct ExecutionContext {
    /// Transaction being executed
    pub transaction: ObjectTransaction,
    /// Input objects (loaded)
    pub input_objects: HashMap<ObjectId, Object>,
    /// Gas budget remaining
    pub gas_budget: u64,
    /// Gas price
    pub gas_price: u64,
    /// Gas used so far
    pub gas_used: u64,
}

impl ExecutionContext {
    /// Create new execution context
    pub fn new(transaction: ObjectTransaction, input_objects: HashMap<ObjectId, Object>) -> Self {
        let gas_budget = transaction.gas_data.budget;
        let gas_price = transaction.gas_data.price;
        Self {
            transaction,
            input_objects,
            gas_budget,
            gas_price,
            gas_used: 0,
        }
    }

    /// Charge gas
    pub fn charge_gas(&mut self, amount: u64) -> Result<(), ExecutionError> {
        if self.gas_used.saturating_add(amount) > self.gas_budget {
            return Err(ExecutionError::OutOfGas {
                budget: self.gas_budget,
                required: self.gas_used + amount,
            });
        }
        self.gas_used += amount;
        Ok(())
    }

    /// Get remaining gas
    pub fn remaining_gas(&self) -> u64 {
        self.gas_budget.saturating_sub(self.gas_used)
    }
}

/// Execution errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExecutionError {
    #[error("Object not found: {0:?}")]
    ObjectNotFound(ObjectId),

    #[error("Version mismatch for {id:?}: expected {expected}, got {actual}")]
    VersionMismatch {
        id: ObjectId,
        expected: u64,
        actual: u64,
    },

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Out of gas: budget {budget}, required {required}")]
    OutOfGas {
        budget: u64,
        required: u64,
    },

    #[error("Ownership error: {0}")]
    OwnershipError(#[from] OwnershipError),

    #[error("Transaction expired at epoch {0}")]
    Expired(u64),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
}

/// Dependency graph for parallel execution
#[derive(Debug, Default)]
pub struct DependencyGraph {
    /// Maps object ID to transactions that use it
    object_to_txs: HashMap<ObjectId, Vec<TransactionDigest>>,
    /// Maps transaction to its dependencies
    tx_dependencies: HashMap<TransactionDigest, HashSet<TransactionDigest>>,
    /// Transaction execution order (topological)
    execution_order: Vec<TransactionDigest>,
}

impl DependencyGraph {
    /// Create a new dependency graph
    pub fn new() -> Self {
        Self::default()
    }

    /// Build dependency graph from transactions
    pub fn build(transactions: &[SignedTransaction]) -> Self {
        let mut graph = Self::new();

        // First pass: map objects to transactions
        for tx in transactions {
            let digest = tx.digest();
            let input_objects = tx.transaction.input_objects();

            for object_id in input_objects {
                graph.object_to_txs
                    .entry(object_id)
                    .or_default()
                    .push(digest);
            }
        }

        // Second pass: build dependencies
        for tx in transactions {
            let digest = tx.digest();
            let mut deps = HashSet::new();

            let input_objects = tx.transaction.input_objects();
            for object_id in input_objects {
                if let Some(txs) = graph.object_to_txs.get(&object_id) {
                    for other_digest in txs {
                        if *other_digest != digest {
                            deps.insert(*other_digest);
                        }
                    }
                }
            }

            graph.tx_dependencies.insert(digest, deps);
        }

        // Topological sort for execution order
        graph.compute_execution_order(transactions);

        graph
    }

    /// Compute topological execution order
    fn compute_execution_order(&mut self, transactions: &[SignedTransaction]) {
        let mut in_degree: HashMap<TransactionDigest, usize> = HashMap::new();
        let mut queue = Vec::new();

        // Initialize in-degrees
        for tx in transactions {
            let digest = tx.digest();
            let deps = self.tx_dependencies.get(&digest).map(|d| d.len()).unwrap_or(0);
            in_degree.insert(digest, deps);
            if deps == 0 {
                queue.push(digest);
            }
        }

        // Process queue
        while let Some(digest) = queue.pop() {
            self.execution_order.push(digest);

            // Reduce in-degree of dependent transactions
            for tx in transactions {
                let other_digest = tx.digest();
                if let Some(deps) = self.tx_dependencies.get(&other_digest) {
                    if deps.contains(&digest) {
                        if let Some(degree) = in_degree.get_mut(&other_digest) {
                            *degree = degree.saturating_sub(1);
                            if *degree == 0 {
                                queue.push(other_digest);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Get independent transaction groups (can be parallelized)
    pub fn get_parallel_groups(&self, transactions: &[SignedTransaction]) -> Vec<Vec<TransactionDigest>> {
        let mut groups: Vec<Vec<TransactionDigest>> = Vec::new();
        let mut assigned: HashSet<TransactionDigest> = HashSet::new();

        for digest in &self.execution_order {
            if assigned.contains(digest) {
                continue;
            }

            // Start a new group with this transaction
            let mut group = vec![*digest];
            assigned.insert(*digest);

            // Add other transactions that don't conflict
            for tx in transactions {
                let other_digest = tx.digest();
                if assigned.contains(&other_digest) {
                    continue;
                }

                // Check if this transaction conflicts with any in the group
                let conflicts = group.iter().any(|g| {
                    let g_deps = self.tx_dependencies.get(g);
                    let o_deps = self.tx_dependencies.get(&other_digest);

                    // Conflict if one depends on the other
                    g_deps.map(|d| d.contains(&other_digest)).unwrap_or(false) ||
                    o_deps.map(|d| d.contains(g)).unwrap_or(false)
                });

                if !conflicts {
                    group.push(other_digest);
                    assigned.insert(other_digest);
                }
            }

            groups.push(group);
        }

        groups
    }
}

/// Object transaction executor
pub struct ObjectExecutor<S: ObjectStore> {
    /// Object store
    store: SharedObjectStore<S>,
    /// Current epoch
    current_epoch: u64,
    /// Base gas cost per transaction
    base_gas_cost: u64,
    /// Gas cost per byte of data
    per_byte_gas_cost: u64,
}

impl<S: ObjectStore> ObjectExecutor<S> {
    /// Create a new executor
    pub fn new(store: S) -> Self {
        Self {
            store: SharedObjectStore::new(store),
            current_epoch: 0,
            base_gas_cost: 1000,
            per_byte_gas_cost: 10,
        }
    }

    /// Set current epoch
    pub fn set_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
    }

    /// Validate a signed transaction
    pub fn validate(&self, signed_tx: &SignedTransaction) -> Result<(), ExecutionError> {
        // Verify signature
        if !signed_tx.verify() {
            return Err(ExecutionError::InvalidSignature);
        }

        // Check expiration
        if let Some(expiration) = signed_tx.transaction.expiration {
            if expiration <= self.current_epoch {
                return Err(ExecutionError::Expired(expiration));
            }
        }

        // Validate inputs exist and have correct versions
        self.validate_inputs(&signed_tx.transaction)?;

        Ok(())
    }

    /// Validate transaction inputs
    fn validate_inputs(&self, tx: &ObjectTransaction) -> Result<(), ExecutionError> {
        let inputs = match &tx.kind {
            super::transaction::TransactionKind::Programmable { inputs, .. } => inputs.clone(),
            super::transaction::TransactionKind::Transfer { objects, .. } => {
                objects.iter().map(|r| ObjectInput::owned(r.clone())).collect()
            }
            _ => vec![],
        };

        for input in inputs {
            match input {
                ObjectInput::OwnedObject { object_ref } => {
                    let object = self.store.get_object(&object_ref.id)
                        .ok_or(ExecutionError::ObjectNotFound(object_ref.id))?;

                    if object.version != object_ref.version {
                        return Err(ExecutionError::VersionMismatch {
                            id: object_ref.id,
                            expected: object_ref.version,
                            actual: object.version,
                        });
                    }

                    // Check ownership
                    if !object.owner.can_access(&tx.sender) {
                        return Err(ExecutionError::OwnershipError(
                            OwnershipError::NotOwner(object_ref.id)
                        ));
                    }
                }
                ObjectInput::SharedObject { object_id, initial_shared_version, .. } => {
                    let object = self.store.get_object(&object_id)
                        .ok_or(ExecutionError::ObjectNotFound(object_id))?;

                    if !object.owner.is_shared() {
                        return Err(ExecutionError::InvalidInput(
                            format!("Object {:?} is not shared", object_id)
                        ));
                    }

                    if object.version < initial_shared_version {
                        return Err(ExecutionError::VersionMismatch {
                            id: object_id,
                            expected: initial_shared_version,
                            actual: object.version,
                        });
                    }
                }
                ObjectInput::ImmutableObject { object_id } => {
                    let object = self.store.get_object(&object_id)
                        .ok_or(ExecutionError::ObjectNotFound(object_id))?;

                    if !object.owner.is_immutable() {
                        return Err(ExecutionError::InvalidInput(
                            format!("Object {:?} is not immutable", object_id)
                        ));
                    }
                }
                ObjectInput::Pure { .. } => {}
            }
        }

        Ok(())
    }

    /// Load input objects for execution
    fn load_inputs(&self, tx: &ObjectTransaction) -> Result<HashMap<ObjectId, Object>, ExecutionError> {
        let mut objects = HashMap::new();

        for object_id in tx.input_objects() {
            let object = self.store.get_object(&object_id)
                .ok_or(ExecutionError::ObjectNotFound(object_id))?;
            objects.insert(object_id, object);
        }

        // Also load gas objects
        for gas_ref in &tx.gas_data.payment {
            let object = self.store.get_object(&gas_ref.id)
                .ok_or(ExecutionError::ObjectNotFound(gas_ref.id))?;
            objects.insert(gas_ref.id, object);
        }

        Ok(objects)
    }

    /// Execute a single transaction
    pub fn execute(
        &self,
        signed_tx: &SignedTransaction,
    ) -> Result<TransactionEffects, ExecutionError> {
        // Validate first
        self.validate(signed_tx)?;

        // Load inputs
        let input_objects = self.load_inputs(&signed_tx.transaction)?;

        // Create execution context
        let mut ctx = ExecutionContext::new(
            signed_tx.transaction.clone(),
            input_objects,
        );

        // Charge base gas
        ctx.charge_gas(self.base_gas_cost)?;

        // Execute based on transaction kind
        let (created, mutated, deleted) = self.execute_transaction_kind(&mut ctx)?;

        // Calculate gas used
        let gas_used = GasUsed {
            computation_cost: ctx.gas_used * ctx.gas_price,
            storage_cost: created.len() as u64 * 1000 * ctx.gas_price,
            storage_rebate: deleted.len() as u64 * 500 * ctx.gas_price,
            non_refundable_storage_fee: ctx.gas_used / 10 * ctx.gas_price,
        };

        // Create effects
        let effects = TransactionEffects {
            transaction_digest: signed_tx.digest(),
            status: ExecutionStatus::Success,
            gas_used,
            created,
            mutated,
            deleted: deleted.iter().map(|id| ObjectRef {
                id: *id,
                version: 0,
                digest: ObjectDigest::new([0u8; 32]),
            }).collect(),
            wrapped: vec![],
            unwrapped: vec![],
            gas_object: (
                signed_tx.transaction.gas_data.payment.first().cloned().unwrap_or(ObjectRef {
                    id: ObjectId::generate(),
                    version: 0,
                    digest: ObjectDigest::new([0u8; 32]),
                }),
                Owner::Address(signed_tx.transaction.sender),
            ),
            events_digest: None,
            dependencies: vec![],
        };

        Ok(effects)
    }

    /// Execute transaction based on kind
    fn execute_transaction_kind(
        &self,
        ctx: &mut ExecutionContext,
    ) -> Result<(Vec<(ObjectRef, Owner)>, Vec<(ObjectRef, Owner)>, Vec<ObjectId>), ExecutionError> {
        let mut created = Vec::new();
        let mut mutated = Vec::new();
        let deleted = Vec::new();

        // Clone the transaction kind to avoid borrow conflicts
        let tx_kind = ctx.transaction.kind.clone();
        let tx_digest = ctx.transaction.digest();
        let tx_digest_bytes = *tx_digest.as_bytes();

        match &tx_kind {
            super::transaction::TransactionKind::Transfer { objects, recipient } => {
                for object_ref in objects {
                    // Get the object
                    let object = ctx.input_objects.get(&object_ref.id)
                        .ok_or(ExecutionError::ObjectNotFound(object_ref.id))?;

                    // Update ownership
                    let mut new_object = object.clone();
                    new_object.owner = Owner::Address(*recipient);
                    new_object.version += 1;
                    // Update modified transaction in metadata
                    new_object.metadata.modified_tx = super::object::TransactionDigest::new(tx_digest_bytes);

                    let new_ref = ObjectRef {
                        id: new_object.id,
                        version: new_object.version,
                        digest: new_object.digest(),
                    };

                    mutated.push((new_ref, Owner::Address(*recipient)));

                    // Charge gas per transfer
                    ctx.charge_gas(100)?;
                }
            }
            super::transaction::TransactionKind::Programmable { commands, .. } => {
                // Simplified programmable execution
                ctx.charge_gas(commands.len() as u64 * 200)?;

                // In production, this would execute Move bytecode
                // For now, just return empty effects
            }
            super::transaction::TransactionKind::Publish { modules, .. } => {
                // Create package object - convert transaction digest
                let obj_tx_digest = super::object::TransactionDigest::new(tx_digest_bytes);
                let package_id = ObjectId::derive(&obj_tx_digest, 0);

                // Create package as a shared object with program type
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as u64;

                let package = Object {
                    id: package_id,
                    version: 1,
                    object_type: super::object::ObjectType::Program,
                    owner: Owner::Immutable,
                    data: super::object::ObjectData::Raw(modules.concat()),
                    metadata: super::object::ObjectMetadata {
                        created_tx: obj_tx_digest,
                        modified_tx: obj_tx_digest,
                        created_at: now,
                        modified_at: now,
                    },
                };

                let package_ref = ObjectRef {
                    id: package_id,
                    version: 1,
                    digest: package.digest(),
                };

                created.push((package_ref, Owner::Immutable));

                // Charge gas per module
                ctx.charge_gas(modules.len() as u64 * 5000)?;
            }
            super::transaction::TransactionKind::System { .. } => {
                // System transactions have special handling
            }
        }

        Ok((created, mutated, deleted))
    }

    /// Execute multiple transactions with parallelization
    pub fn execute_batch(
        &self,
        transactions: Vec<SignedTransaction>,
    ) -> Vec<Result<TransactionEffects, ExecutionError>> {
        // Build dependency graph
        let graph = DependencyGraph::build(&transactions);

        // Get parallel groups
        let groups = graph.get_parallel_groups(&transactions);

        // Create a map for quick lookup
        let tx_map: HashMap<TransactionDigest, &SignedTransaction> = transactions
            .iter()
            .map(|tx| (tx.digest(), tx))
            .collect();

        let mut results: HashMap<TransactionDigest, Result<TransactionEffects, ExecutionError>> =
            HashMap::new();

        // Execute groups sequentially, transactions within groups in parallel
        for group in groups {
            // In production, this would use rayon or tokio for parallelization
            // For now, execute sequentially
            for digest in group {
                if let Some(tx) = tx_map.get(&digest) {
                    let result = self.execute(tx);
                    results.insert(digest, result);
                }
            }
        }

        // Return results in original order
        transactions
            .iter()
            .map(|tx| {
                results.remove(&tx.digest())
                    .unwrap_or(Err(ExecutionError::ExecutionFailed("Not executed".to_string())))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use super::super::transaction::GasData;

    fn create_test_executor() -> ObjectExecutor<MemoryObjectStore> {
        ObjectExecutor::new(MemoryObjectStore::new())
    }

    #[test]
    fn test_memory_object_store() {
        let mut store = MemoryObjectStore::new();
        let keypair = Keypair::generate();
        let owner = keypair.pubkey();

        let tx_digest = super::super::object::TransactionDigest::compute(b"test_tx");
        let object = Object::new_coin(owner, 1000, tx_digest, 0);
        let id = object.id;

        store.put_object(object.clone());

        assert!(store.exists(&id));
        assert_eq!(store.get_latest_version(&id), Some(1));

        let retrieved = store.get_object(&id).unwrap();
        assert_eq!(retrieved.id, id);
    }

    #[test]
    fn test_dependency_graph() {
        let keypair = Keypair::generate();
        let sender = keypair.pubkey();

        let object1 = ObjectId::generate();
        let object2 = ObjectId::generate();

        // Two transactions using different objects (can parallel)
        let gas_data = GasData::new(vec![], sender, 1000, 50000);

        let tx1 = ObjectTransaction::transfer(
            vec![ObjectRef { id: object1, version: 1, digest: ObjectDigest::new([0u8; 32]) }],
            sender,
            sender,
            gas_data.clone(),
        );
        let tx2 = ObjectTransaction::transfer(
            vec![ObjectRef { id: object2, version: 1, digest: ObjectDigest::new([0u8; 32]) }],
            sender,
            sender,
            gas_data,
        );

        let signed1 = SignedTransaction::sign(tx1, &keypair);
        let signed2 = SignedTransaction::sign(tx2, &keypair);

        let graph = DependencyGraph::build(&[signed1.clone(), signed2.clone()]);
        let groups = graph.get_parallel_groups(&[signed1, signed2]);

        // Both should be in the same group (no conflicts)
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 2);
    }

    #[test]
    fn test_execution_context_gas() {
        let keypair = Keypair::generate();
        let sender = keypair.pubkey();
        let gas_data = GasData::new(vec![], sender, 1000, 100);

        let tx = ObjectTransaction::transfer(vec![], sender, sender, gas_data);

        let mut ctx = ExecutionContext::new(tx, HashMap::new());

        assert!(ctx.charge_gas(50).is_ok());
        assert_eq!(ctx.remaining_gas(), 50);

        // Should fail - exceeds budget
        assert!(ctx.charge_gas(100).is_err());
    }
}
