//! Main storage engine

use std::path::Path;
use std::sync::RwLock;
use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::core::{Account, Block, Slot, Transaction};
use crate::crypto::{Hash, Signature};
use crate::crypto::Pubkey;
use crate::rpc::types::RpcPerformanceSample;

use super::accounts::AccountStore;
use super::blocks::BlockStore;

/// Validator information stored in the node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator public key
    pub pubkey: Pubkey,
    /// Validator name/identity
    pub name: String,
    /// Stake amount in celers
    pub stake: u64,
    /// Commission percentage (0-100)
    pub commission: u8,
    /// Is the validator active
    pub active: bool,
    /// Skip rate (0.0-100.0)
    pub skip_rate: f64,
    /// Number of blocks produced
    pub blocks_produced: u64,
    /// Uptime percentage (0.0-100.0)
    pub uptime: f64,
}

/// Main storage engine combining account and block stores
pub struct Storage {
    /// Account store
    accounts: AccountStore,
    /// Block store
    blocks: BlockStore,
    /// Pending transactions (mempool)
    pending_txs: RwLock<VecDeque<Transaction>>,
    /// Validators
    validators: RwLock<Vec<ValidatorInfo>>,
    /// Performance samples for TPS tracking
    performance_samples: RwLock<VecDeque<RpcPerformanceSample>>,
    /// Recent transactions count for TPS calculation (timestamp, count)
    recent_tx_counts: RwLock<VecDeque<(i64, u64)>>,
    /// Total stake
    total_stake: RwLock<u64>,
    /// Sled database
    db: Option<sled::Db>,
}

impl Storage {
    /// Create a new in-memory storage
    pub fn new_memory() -> Self {
        Self {
            accounts: AccountStore::new_memory(),
            blocks: BlockStore::new_memory(),
            pending_txs: RwLock::new(VecDeque::new()),
            validators: RwLock::new(Vec::new()),
            performance_samples: RwLock::new(VecDeque::with_capacity(720)),
            recent_tx_counts: RwLock::new(VecDeque::with_capacity(60)),
            total_stake: RwLock::new(0),
            db: None,
        }
    }

    /// Create a new persistent storage
    pub fn new_persistent<P: AsRef<Path>>(path: P) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;

        let accounts_tree = db.open_tree("accounts")?;
        let blocks_tree = db.open_tree("blocks")?;

        // Load validators from disk
        let mut validators = Vec::new();
        let mut total_stake = 0u64;
        if let Ok(Some(data)) = db.get("validators") {
            if let Ok(loaded) = bincode::deserialize::<Vec<ValidatorInfo>>(&data) {
                for v in &loaded {
                    total_stake += v.stake;
                }
                validators = loaded;
            }
        }

        Ok(Self {
            accounts: AccountStore::new_persistent(accounts_tree),
            blocks: BlockStore::new_persistent(blocks_tree),
            pending_txs: RwLock::new(VecDeque::new()),
            validators: RwLock::new(validators),
            performance_samples: RwLock::new(VecDeque::with_capacity(720)),
            recent_tx_counts: RwLock::new(VecDeque::with_capacity(60)),
            total_stake: RwLock::new(total_stake),
            db: Some(db),
        })
    }

    // ========== Account Methods ==========

    /// Get account by pubkey
    pub fn get_account(&self, pubkey: &Pubkey) -> Option<Account> {
        self.accounts.get(pubkey)
    }

    /// Get account balance
    pub fn get_balance(&self, pubkey: &Pubkey) -> Option<u64> {
        Some(self.accounts.get_balance(pubkey))
    }

    /// Set account
    pub fn set_account(&self, pubkey: &Pubkey, account: Account) {
        self.accounts.set(pubkey, account);
    }

    /// Credit account
    pub fn credit_account(&self, pubkey: &Pubkey, celers: u64) {
        self.accounts.credit(pubkey, celers);
    }

    /// Debit account
    pub fn debit_account(&self, pubkey: &Pubkey, celers: u64) -> bool {
        self.accounts.debit(pubkey, celers)
    }

    /// Transfer celers
    pub fn transfer(&self, from: &Pubkey, to: &Pubkey, celers: u64) -> bool {
        self.accounts.transfer(from, to, celers)
    }

    /// Get total supply
    pub fn get_total_supply(&self) -> u64 {
        self.accounts.total_supply()
    }

    // ========== Block Methods ==========

    /// Get block by slot
    pub fn get_block(&self, slot: Slot) -> Option<Block> {
        self.blocks.get_block(slot)
    }

    /// Store block
    pub fn store_block(&self, block: Block) {
        // Execute transactions
        for tx in &block.transactions {
            self.execute_transaction(tx);
        }

        self.blocks.store_block(block);
    }

    /// Get current slot
    pub fn get_current_slot(&self) -> Slot {
        self.blocks.get_current_slot()
    }

    /// Set current slot
    pub fn set_current_slot(&self, slot: Slot) {
        self.blocks.set_current_slot(slot);
    }

    /// Get latest blockhash
    pub fn get_latest_blockhash(&self) -> Hash {
        self.blocks.get_latest_blockhash()
    }

    /// Get transaction count
    pub fn get_transaction_count(&self) -> u64 {
        self.blocks.get_transaction_count()
    }

    /// Increment transaction count
    pub fn increment_transaction_count(&self) {
        self.blocks.increment_transaction_count()
    }

    // ========== Transaction Methods ==========

    /// Get transaction by signature
    pub fn get_transaction(&self, signature: &Signature) -> Option<(Transaction, Slot)> {
        self.blocks.get_transaction(signature)
    }

    /// Add pending transaction
    pub fn add_pending_transaction(&self, tx: Transaction) {
        let mut pending = self.pending_txs.write().unwrap();
        pending.push_back(tx);
    }

    /// Take pending transactions
    pub fn take_pending_transactions(&self, max: usize) -> Vec<Transaction> {
        let mut pending = self.pending_txs.write().unwrap();
        let count = pending.len().min(max);
        pending.drain(..count).collect()
    }

    /// Get pending transaction count
    pub fn pending_count(&self) -> usize {
        let pending = self.pending_txs.read().unwrap();
        pending.len()
    }

    /// Get all pending transactions (does not remove them)
    pub fn get_pending_transactions(&self) -> Vec<Transaction> {
        let pending = self.pending_txs.read().unwrap();
        pending.iter().cloned().collect()
    }

    /// Add block (alias for store_block)
    pub fn add_block(&self, block: Block) {
        self.store_block(block);
    }

    /// Execute a transaction
    fn execute_transaction(&self, tx: &Transaction) {
        // Simple transfer execution
        // In a full implementation, this would interpret instructions
        if tx.message.instructions.len() == 1 {
            let instruction = &tx.message.instructions[0];

            // Check if it's a transfer (program_id_index 0 = system program)
            if instruction.program_id_index == 0 && instruction.data.len() >= 12 {
                // Parse transfer instruction
                // data[0..4] = instruction type (2 = transfer)
                // data[4..12] = celers (u64)
                if instruction.data[0] == 2 {
                    let celers = u64::from_le_bytes(
                        instruction.data[4..12].try_into().unwrap_or([0; 8])
                    );

                    if instruction.accounts.len() >= 2 {
                        let from_idx = instruction.accounts[0] as usize;
                        let to_idx = instruction.accounts[1] as usize;

                        if from_idx < tx.message.account_keys.len()
                            && to_idx < tx.message.account_keys.len()
                        {
                            let from = &tx.message.account_keys[from_idx];
                            let to = &tx.message.account_keys[to_idx];
                            self.transfer(from, to, celers);
                        }
                    }
                }
            }
        }
    }

    // ========== Utility Methods ==========

    /// Flush all data to disk
    pub fn flush(&self) {
        self.accounts.flush();
        self.blocks.flush();
        if let Some(ref db) = self.db {
            let _ = db.flush();
        }
    }

    /// Get storage stats
    pub fn stats(&self) -> StorageStats {
        StorageStats {
            account_count: self.accounts.count(),
            block_count: self.blocks.block_count(),
            transaction_count: self.blocks.get_transaction_count(),
            pending_count: self.pending_count(),
            current_slot: self.get_current_slot(),
        }
    }

    // ========== Dashboard/Stats Methods ==========

    /// Get account count
    pub fn get_account_count(&self) -> u64 {
        self.accounts.count() as u64
    }

    /// Get validator count
    pub fn get_validator_count(&self) -> u64 {
        let validators = self.validators.read().unwrap();
        validators.iter().filter(|v| v.active).count() as u64
    }

    /// Get all validators
    pub fn get_validators(&self) -> Vec<ValidatorInfo> {
        let validators = self.validators.read().unwrap();
        validators.clone()
    }

    /// Add or update a validator
    pub fn add_validator(&self, validator: ValidatorInfo) {
        let mut validators = self.validators.write().unwrap();
        let mut total_stake = self.total_stake.write().unwrap();

        // Check if validator already exists
        if let Some(existing) = validators.iter_mut().find(|v| v.pubkey == validator.pubkey) {
            *total_stake = total_stake.saturating_sub(existing.stake);
            *existing = validator.clone();
            *total_stake = total_stake.saturating_add(validator.stake);
        } else {
            *total_stake = total_stake.saturating_add(validator.stake);
            validators.push(validator);
        }

        // Persist validators to disk
        if let Some(ref db) = self.db {
            if let Ok(data) = bincode::serialize(&*validators) {
                let _ = db.insert("validators", data);
            }
        }
    }

    /// Remove a validator
    pub fn remove_validator(&self, pubkey: &Pubkey) {
        let mut validators = self.validators.write().unwrap();
        let mut total_stake = self.total_stake.write().unwrap();

        if let Some(pos) = validators.iter().position(|v| &v.pubkey == pubkey) {
            let removed = validators.remove(pos);
            *total_stake = total_stake.saturating_sub(removed.stake);

            // Persist validators to disk
            if let Some(ref db) = self.db {
                if let Ok(data) = bincode::serialize(&*validators) {
                    let _ = db.insert("validators", data);
                }
            }
        }
    }

    /// Get total stake
    pub fn get_total_stake(&self) -> u64 {
        *self.total_stake.read().unwrap()
    }

    /// Record transaction count for TPS calculation
    pub fn record_tx_count(&self, count: u64) {
        let timestamp = chrono::Utc::now().timestamp();
        let mut tx_counts = self.recent_tx_counts.write().unwrap();

        // Remove old entries (older than 60 seconds)
        while tx_counts.front().map_or(false, |(ts, _)| timestamp - ts > 60) {
            tx_counts.pop_front();
        }

        tx_counts.push_back((timestamp, count));
    }

    /// Get recent TPS (transactions per second)
    pub fn get_recent_tps(&self) -> u64 {
        let tx_counts = self.recent_tx_counts.read().unwrap();

        if tx_counts.is_empty() {
            return 0;
        }

        let total_tx: u64 = tx_counts.iter().map(|(_, c)| c).sum();
        let duration = tx_counts.back().map(|(ts, _)| ts).unwrap_or(&0)
            - tx_counts.front().map(|(ts, _)| ts).unwrap_or(&0);

        if duration > 0 {
            total_tx / (duration as u64)
        } else {
            total_tx
        }
    }

    /// Add performance sample
    pub fn add_performance_sample(&self, sample: RpcPerformanceSample) {
        let mut samples = self.performance_samples.write().unwrap();

        // Keep max 720 samples (about 1 hour at 5-second intervals)
        if samples.len() >= 720 {
            samples.pop_front();
        }

        samples.push_back(sample);
    }

    /// Get performance samples
    pub fn get_performance_samples(&self, limit: usize) -> Vec<RpcPerformanceSample> {
        let samples = self.performance_samples.read().unwrap();
        samples.iter().rev().take(limit).cloned().collect()
    }

    /// Increment validator block count
    pub fn increment_validator_blocks(&self, pubkey: &Pubkey) {
        let mut validators = self.validators.write().unwrap();
        if let Some(validator) = validators.iter_mut().find(|v| &v.pubkey == pubkey) {
            validator.blocks_produced += 1;

            // Persist every 100 blocks to reduce disk writes
            if validator.blocks_produced % 100 == 0 {
                if let Some(ref db) = self.db {
                    if let Ok(data) = bincode::serialize(&*validators) {
                        let _ = db.insert("validators", data);
                    }
                }
            }
        }
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub account_count: usize,
    pub block_count: usize,
    pub transaction_count: u64,
    pub pending_count: usize,
    pub current_slot: Slot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_accounts() {
        let storage = Storage::new_memory();
        let pubkey = Pubkey::new([1u8; 32]);

        storage.credit_account(&pubkey, 1000);
        assert_eq!(storage.get_balance(&pubkey), Some(1000));

        assert!(storage.debit_account(&pubkey, 400));
        assert_eq!(storage.get_balance(&pubkey), Some(600));
    }

    #[test]
    fn test_pending_transactions() {
        let storage = Storage::new_memory();

        // Create dummy transaction
        let tx = Transaction {
            signatures: vec![],
            message: crate::core::TransactionMessage {
                header: crate::core::MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 0,
                },
                account_keys: vec![],
                recent_blockhash: Hash::hash(b"test"),
                instructions: vec![],
            },
        };

        storage.add_pending_transaction(tx.clone());
        storage.add_pending_transaction(tx.clone());

        assert_eq!(storage.pending_count(), 2);

        let taken = storage.take_pending_transactions(1);
        assert_eq!(taken.len(), 1);
        assert_eq!(storage.pending_count(), 1);
    }
}
