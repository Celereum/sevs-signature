//! ZK-State - Phase 3
//!
//! Full state verification with zero-knowledge proofs.
//! Enables instant verification of the entire blockchain state.
//!
//! Features:
//! - State root proofs: Prove entire state is valid
//! - Incremental proofs: Update state proof with new blocks
//! - Light client proofs: Verify specific accounts without full state
//!
//! This enables:
//! - Instant sync for new nodes
//! - Ultra-light clients (mobile/browser)
//! - Cross-chain state verification

use crate::core::Account;
use crate::crypto::Hash;
use crate::crypto::Pubkey;
use super::proofs::{Proof, ProofType, Prover, Verifier, ProofSystem, ProofError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use parking_lot::RwLock;

/// State root containing proof of entire state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateRoot {
    /// Root hash of the state tree
    pub root: Hash,
    /// Block height this state corresponds to
    pub block_height: u64,
    /// Number of accounts in state
    pub num_accounts: u64,
    /// Total balance in the state
    pub total_balance: u64,
    /// State version
    pub version: u32,
}

impl StateRoot {
    /// Create genesis state root
    pub fn genesis() -> Self {
        Self {
            root: Hash::hash(b"celereum_genesis_state"),
            block_height: 0,
            num_accounts: 0,
            total_balance: 0,
            version: 1,
        }
    }

    /// Serialize for hashing
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.root.as_bytes());
        bytes.extend_from_slice(&self.block_height.to_le_bytes());
        bytes.extend_from_slice(&self.num_accounts.to_le_bytes());
        bytes.extend_from_slice(&self.total_balance.to_le_bytes());
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes
    }
}

/// Proof that state is valid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    /// The state root being proven
    pub state_root: StateRoot,
    /// Zero-knowledge proof
    pub proof: Proof,
    /// Previous state root (for incremental proofs)
    pub prev_state_root: Option<Hash>,
    /// Proof generation time
    pub generation_time_us: u64,
}

impl StateProof {
    /// Get proof size
    pub fn size(&self) -> usize {
        self.proof.size() + self.state_root.to_bytes().len() + 32 + 8
    }

    /// Verify the state proof
    pub fn verify(&self, verifier: &Verifier) -> Result<bool, StateError> {
        let public_inputs = self.public_inputs();
        verifier.verify(&self.proof, &public_inputs)
            .map_err(|e| StateError::Verification(e.to_string()))
    }

    fn public_inputs(&self) -> Vec<u8> {
        self.state_root.to_bytes()
    }
}

/// Proof of account inclusion in state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInclusionProof {
    /// Account public key
    pub pubkey: Pubkey,
    /// Account data
    pub account: AccountData,
    /// Merkle path from account to root
    pub merkle_path: Vec<MerkleNode>,
    /// State root this proof is against
    pub state_root: Hash,
    /// Validity proof
    pub proof: Proof,
}

impl AccountInclusionProof {
    /// Verify account is in state
    pub fn verify(&self, verifier: &Verifier) -> Result<bool, StateError> {
        // Verify the ZK proof
        let mut public_inputs = Vec::new();
        public_inputs.extend_from_slice(self.pubkey.as_bytes());
        public_inputs.extend_from_slice(&self.account.to_bytes());
        public_inputs.extend_from_slice(self.state_root.as_bytes());

        verifier.verify(&self.proof, &public_inputs)
            .map_err(|e| StateError::Verification(e.to_string()))
    }

    /// Get proof size
    pub fn size(&self) -> usize {
        32 + self.account.to_bytes().len() + self.merkle_path.len() * 33 + 32 + self.proof.size()
    }
}

/// Simplified account data for proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountData {
    pub balance: u64,
    pub nonce: u64,
    pub data_hash: Hash,
}

impl AccountData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.balance.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(self.data_hash.as_bytes());
        bytes
    }

    pub fn hash(&self) -> Hash {
        Hash::hash(&self.to_bytes())
    }
}

/// Node in merkle path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: Hash,
    pub is_left: bool,
}

/// ZK State manager
pub struct ZkState {
    prover: Prover,
    verifier: Verifier,
    /// Current state root
    current_state: RwLock<StateRoot>,
    /// Account states
    accounts: RwLock<HashMap<Pubkey, AccountData>>,
    /// Merkle tree layers (simplified)
    merkle_layers: RwLock<Vec<Vec<Hash>>>,
    /// Statistics
    stats: RwLock<StateStats>,
}

/// State statistics
#[derive(Debug, Clone, Default)]
pub struct StateStats {
    pub state_proofs_generated: u64,
    pub inclusion_proofs_generated: u64,
    pub verifications: u64,
    pub total_proving_time_us: u64,
    pub total_verification_time_us: u64,
}

impl StateStats {
    pub fn avg_proving_time_us(&self) -> u64 {
        let total = self.state_proofs_generated + self.inclusion_proofs_generated;
        if total == 0 { 0 } else { self.total_proving_time_us / total }
    }

    pub fn avg_verification_time_us(&self) -> u64 {
        if self.verifications == 0 { 0 } else { self.total_verification_time_us / self.verifications }
    }
}

impl ZkState {
    /// Create new ZK state manager
    pub fn new() -> Self {
        let system = ProofSystem::default();
        let verifier = Verifier::from_system(&system);
        let prover = Prover::new(system);

        Self {
            prover,
            verifier,
            current_state: RwLock::new(StateRoot::genesis()),
            accounts: RwLock::new(HashMap::new()),
            merkle_layers: RwLock::new(Vec::new()),
            stats: RwLock::new(StateStats::default()),
        }
    }

    /// Get current state root
    pub fn state_root(&self) -> StateRoot {
        self.current_state.read().clone()
    }

    /// Set account data
    pub fn set_account(&self, pubkey: Pubkey, balance: u64, nonce: u64, data: &[u8]) {
        let account_data = AccountData {
            balance,
            nonce,
            data_hash: Hash::hash(data),
        };

        self.accounts.write().insert(pubkey, account_data);
        self.rebuild_merkle_tree();
    }

    /// Get account data
    pub fn get_account(&self, pubkey: &Pubkey) -> Option<AccountData> {
        self.accounts.read().get(pubkey).cloned()
    }

    /// Update state with multiple accounts
    pub fn update_accounts(&self, updates: Vec<(Pubkey, u64, u64, Vec<u8>)>) {
        {
            let mut accounts = self.accounts.write();
            for (pubkey, balance, nonce, data) in updates {
                let account_data = AccountData {
                    balance,
                    nonce,
                    data_hash: Hash::hash(&data),
                };
                accounts.insert(pubkey, account_data);
            }
        }
        self.rebuild_merkle_tree();
    }

    /// Rebuild merkle tree from accounts
    fn rebuild_merkle_tree(&self) {
        let accounts = self.accounts.read();
        let mut leaves: Vec<Hash> = Vec::new();

        // Sort accounts for deterministic ordering
        let mut sorted_keys: Vec<_> = accounts.keys().collect();
        sorted_keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        for key in &sorted_keys {
            let account = &accounts[*key];
            let mut leaf_data = Vec::new();
            leaf_data.extend_from_slice(key.as_bytes());
            leaf_data.extend_from_slice(&account.to_bytes());
            leaves.push(Hash::hash(&leaf_data));
        }

        // Pad to power of 2
        let target_size = leaves.len().next_power_of_two();
        while leaves.len() < target_size {
            leaves.push(Hash::hash(b"empty_leaf"));
        }

        // Build tree layers
        let mut layers = vec![leaves.clone()];
        let mut current_layer = leaves;

        while current_layer.len() > 1 {
            let mut next_layer = Vec::new();
            for chunk in current_layer.chunks(2) {
                let mut combined = Vec::new();
                combined.extend_from_slice(chunk[0].as_bytes());
                if chunk.len() > 1 {
                    combined.extend_from_slice(chunk[1].as_bytes());
                } else {
                    combined.extend_from_slice(chunk[0].as_bytes());
                }
                next_layer.push(Hash::hash(&combined));
            }
            layers.push(next_layer.clone());
            current_layer = next_layer;
        }

        // Update state root
        let root = current_layer.first().cloned().unwrap_or(Hash::hash(b"empty_state"));
        let total_balance: u64 = accounts.values().map(|a| a.balance).sum();

        {
            let mut state = self.current_state.write();
            state.root = root;
            state.num_accounts = accounts.len() as u64;
            state.total_balance = total_balance;
            state.block_height += 1;
        }

        *self.merkle_layers.write() = layers;
    }

    /// Generate state proof
    pub fn generate_state_proof(&self) -> Result<StateProof, StateError> {
        let start = Instant::now();

        let state_root = self.state_root();
        let accounts = self.accounts.read();

        // Create witness (all account data)
        let mut witness = Vec::new();
        for (pubkey, account) in accounts.iter() {
            witness.extend_from_slice(pubkey.as_bytes());
            witness.extend_from_slice(&account.to_bytes());
        }

        // Create public inputs
        let public_inputs = state_root.to_bytes();

        // Generate proof
        let proof = self.prover.prove(&public_inputs, &witness, ProofType::StateTransition)
            .map_err(|e| StateError::ProofGeneration(e.to_string()))?;

        let generation_time = start.elapsed().as_micros() as u64;

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.state_proofs_generated += 1;
            stats.total_proving_time_us += generation_time;
        }

        Ok(StateProof {
            state_root,
            proof,
            prev_state_root: None,
            generation_time_us: generation_time,
        })
    }

    /// Generate incremental state proof (from previous state)
    pub fn generate_incremental_proof(&self, prev_root: Hash) -> Result<StateProof, StateError> {
        let mut proof = self.generate_state_proof()?;
        proof.prev_state_root = Some(prev_root);
        Ok(proof)
    }

    /// Generate account inclusion proof
    pub fn generate_inclusion_proof(&self, pubkey: &Pubkey) -> Result<AccountInclusionProof, StateError> {
        let start = Instant::now();

        let accounts = self.accounts.read();
        let account = accounts.get(pubkey)
            .ok_or(StateError::AccountNotFound)?
            .clone();
        drop(accounts);

        let layers = self.merkle_layers.read();
        let state_root = self.state_root().root;

        // Find account index in sorted order
        let accounts = self.accounts.read();
        let mut sorted_keys: Vec<_> = accounts.keys().collect();
        sorted_keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        let account_index = sorted_keys.iter()
            .position(|k| *k == pubkey)
            .ok_or(StateError::AccountNotFound)?;
        drop(accounts);

        // Build merkle path
        let mut merkle_path = Vec::new();
        let mut index = account_index;

        for layer in layers.iter().take(layers.len().saturating_sub(1)) {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            if sibling_index < layer.len() {
                merkle_path.push(MerkleNode {
                    hash: layer[sibling_index],
                    is_left: index % 2 == 1,
                });
            }
            index /= 2;
        }

        // Create witness
        let mut witness = Vec::new();
        witness.extend_from_slice(pubkey.as_bytes());
        witness.extend_from_slice(&account.to_bytes());
        for node in &merkle_path {
            witness.extend_from_slice(node.hash.as_bytes());
            witness.push(node.is_left as u8);
        }

        // Create public inputs
        let mut public_inputs = Vec::new();
        public_inputs.extend_from_slice(pubkey.as_bytes());
        public_inputs.extend_from_slice(&account.to_bytes());
        public_inputs.extend_from_slice(state_root.as_bytes());

        // Generate proof
        let proof = self.prover.prove(&public_inputs, &witness, ProofType::MerkleInclusion)
            .map_err(|e| StateError::ProofGeneration(e.to_string()))?;

        let generation_time = start.elapsed().as_micros() as u64;

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.inclusion_proofs_generated += 1;
            stats.total_proving_time_us += generation_time;
        }

        Ok(AccountInclusionProof {
            pubkey: *pubkey,
            account,
            merkle_path,
            state_root,
            proof,
        })
    }

    /// Verify state proof
    pub fn verify_state_proof(&self, proof: &StateProof) -> Result<bool, StateError> {
        let start = Instant::now();
        let result = proof.verify(&self.verifier)?;

        let mut stats = self.stats.write();
        stats.verifications += 1;
        stats.total_verification_time_us += start.elapsed().as_micros() as u64;

        Ok(result)
    }

    /// Verify inclusion proof
    pub fn verify_inclusion_proof(&self, proof: &AccountInclusionProof) -> Result<bool, StateError> {
        let start = Instant::now();
        let result = proof.verify(&self.verifier)?;

        let mut stats = self.stats.write();
        stats.verifications += 1;
        stats.total_verification_time_us += start.elapsed().as_micros() as u64;

        Ok(result)
    }

    /// Get statistics
    pub fn stats(&self) -> StateStats {
        self.stats.read().clone()
    }

    /// Get number of accounts
    pub fn num_accounts(&self) -> usize {
        self.accounts.read().len()
    }
}

impl Default for ZkState {
    fn default() -> Self {
        Self::new()
    }
}

/// State errors
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("Account not found")]
    AccountNotFound,

    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),

    #[error("Verification failed: {0}")]
    Verification(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// Light client using ZK proofs
pub struct LightClient {
    verifier: Verifier,
    /// Trusted state root
    trusted_state: StateRoot,
}

impl LightClient {
    /// Create light client with trusted state
    pub fn new(trusted_state: StateRoot) -> Self {
        let system = ProofSystem::default();
        let verifier = Verifier::from_system(&system);

        Self {
            verifier,
            trusted_state,
        }
    }

    /// Update trusted state with proof
    pub fn update_state(&mut self, proof: &StateProof) -> Result<bool, StateError> {
        // Verify proof
        let valid = proof.verify(&self.verifier)?;

        if valid {
            // Check it builds on our trusted state
            if let Some(prev) = &proof.prev_state_root {
                if *prev != self.trusted_state.root {
                    return Err(StateError::InvalidState("State doesn't chain correctly".to_string()));
                }
            }

            self.trusted_state = proof.state_root.clone();
        }

        Ok(valid)
    }

    /// Verify account with inclusion proof
    pub fn verify_account(&self, proof: &AccountInclusionProof) -> Result<bool, StateError> {
        // Check against trusted state root
        if proof.state_root != self.trusted_state.root {
            return Err(StateError::InvalidState("Proof is against different state".to_string()));
        }

        proof.verify(&self.verifier)
    }

    /// Get trusted state
    pub fn trusted_state(&self) -> &StateRoot {
        &self.trusted_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_root_genesis() {
        let root = StateRoot::genesis();
        assert_eq!(root.block_height, 0);
        assert_eq!(root.num_accounts, 0);
    }

    #[test]
    fn test_set_and_get_account() {
        let state = ZkState::new();
        let pubkey = Pubkey([1u8; 32]);

        state.set_account(pubkey, 1000, 0, b"test_data");

        let account = state.get_account(&pubkey).unwrap();
        assert_eq!(account.balance, 1000);
        assert_eq!(account.nonce, 0);
    }

    #[test]
    fn test_state_proof_generation() {
        let state = ZkState::new();

        // Add some accounts
        for i in 0..10 {
            let pubkey = Pubkey([i as u8; 32]);
            state.set_account(pubkey, 1000 * (i as u64 + 1), i as u64, &[i as u8; 32]);
        }

        let proof = state.generate_state_proof().unwrap();

        assert!(proof.generation_time_us > 0);
        assert_eq!(proof.state_root.num_accounts, 10);

        // Verify
        let valid = state.verify_state_proof(&proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_inclusion_proof() {
        let state = ZkState::new();

        // Add accounts
        for i in 0..10 {
            let pubkey = Pubkey([i as u8; 32]);
            state.set_account(pubkey, 1000, 0, b"data");
        }

        let pubkey = Pubkey([5u8; 32]);
        let proof = state.generate_inclusion_proof(&pubkey).unwrap();

        assert_eq!(proof.pubkey, pubkey);
        assert_eq!(proof.account.balance, 1000);

        // Verify
        let valid = state.verify_inclusion_proof(&proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_light_client() {
        let state = ZkState::new();

        // Add accounts
        for i in 0..5 {
            let pubkey = Pubkey([i as u8; 32]);
            state.set_account(pubkey, 1000, 0, b"data");
        }

        // Generate state proof
        let state_proof = state.generate_state_proof().unwrap();

        // Create light client with genesis
        let mut client = LightClient::new(StateRoot::genesis());

        // Update with proof (without chain check for this test)
        let valid = state_proof.verify(&client.verifier).unwrap();
        assert!(valid);

        // Manual update
        client.trusted_state = state_proof.state_root;

        // Verify an account
        let pubkey = Pubkey([3u8; 32]);
        let inclusion_proof = state.generate_inclusion_proof(&pubkey).unwrap();

        let valid = client.verify_account(&inclusion_proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_state_stats() {
        let state = ZkState::new();

        state.set_account(Pubkey([1u8; 32]), 1000, 0, b"data");
        state.generate_state_proof().unwrap();
        state.generate_inclusion_proof(&Pubkey([1u8; 32])).unwrap();

        let stats = state.stats();
        assert_eq!(stats.state_proofs_generated, 1);
        assert_eq!(stats.inclusion_proofs_generated, 1);
    }
}
