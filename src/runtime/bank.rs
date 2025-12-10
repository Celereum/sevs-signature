//! Bank - State management for a slot

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

use crate::core::{Account, Block, Transaction, Slot};
use crate::crypto::Hash;
use crate::crypto::Pubkey;
use crate::storage::Storage;

use super::executor::{TransactionExecutor, ExecutionResult};

/// Bank represents the state at a specific slot
pub struct Bank {
    /// Slot number
    slot: Slot,
    /// Parent bank (for forking)
    parent: Option<Arc<Bank>>,
    /// Block hash
    blockhash: Hash,
    /// Previous blockhash
    previous_blockhash: Hash,
    /// Transaction executor
    executor: TransactionExecutor,
    /// Processed transaction count
    transaction_count: RwLock<u64>,
    /// Total fees collected
    fees_collected: RwLock<u64>,
    /// Is frozen (finalized)
    frozen: RwLock<bool>,
}

impl Bank {
    /// Create genesis bank
    pub fn new_genesis(genesis_accounts: Vec<(Pubkey, u64)>) -> Self {
        let executor = TransactionExecutor::new();

        // Load genesis accounts
        let accounts: Vec<_> = genesis_accounts.iter()
            .map(|(pubkey, celers)| {
                (*pubkey, Account::new(*celers, *pubkey))
            })
            .collect();
        executor.load_accounts(accounts);

        Self {
            slot: 0,
            parent: None,
            blockhash: Hash::hash(b"genesis"),
            previous_blockhash: Hash::hash(b"genesis"),
            executor,
            transaction_count: RwLock::new(0),
            fees_collected: RwLock::new(0),
            frozen: RwLock::new(false),
        }
    }

    /// Create a new bank from parent (fork)
    pub fn new_from_parent(parent: Arc<Bank>, slot: Slot, blockhash: Hash) -> Self {
        // Clone executor state from parent
        let executor = TransactionExecutor::new();

        Self {
            slot,
            parent: Some(parent.clone()),
            blockhash,
            previous_blockhash: parent.blockhash,
            executor,
            transaction_count: RwLock::new(*parent.transaction_count.read()),
            fees_collected: RwLock::new(0),
            frozen: RwLock::new(false),
        }
    }

    /// Get slot
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Get blockhash
    pub fn blockhash(&self) -> Hash {
        self.blockhash
    }

    /// Get previous blockhash
    pub fn previous_blockhash(&self) -> Hash {
        self.previous_blockhash
    }

    /// Get account balance
    pub fn get_balance(&self, pubkey: &Pubkey) -> u64 {
        self.executor.get_account(pubkey)
            .map(|a| a.celers)
            .unwrap_or(0)
    }

    /// Get account
    pub fn get_account(&self, pubkey: &Pubkey) -> Option<Account> {
        self.executor.get_account(pubkey)
    }

    /// Set account
    pub fn set_account(&self, pubkey: &Pubkey, account: Account) {
        self.executor.set_account(pubkey, account);
    }

    /// Credit account (airdrop)
    pub fn credit(&self, pubkey: &Pubkey, celers: u64) {
        let mut account = self.get_account(pubkey)
            .unwrap_or_else(|| Account::new(0, Pubkey::zero()));
        account.celers = account.celers.saturating_add(celers);
        self.set_account(pubkey, account);
    }

    /// Process transactions
    pub fn process_transactions(&self, transactions: Vec<Transaction>) -> Vec<ExecutionResult> {
        if *self.frozen.read() {
            return transactions.iter().map(|tx| {
                ExecutionResult::failure(
                    Hash::hash(&bincode::serialize(tx).unwrap_or_default()),
                    "Bank is frozen".to_string(),
                    0,
                )
            }).collect();
        }

        let results = self.executor.execute_batch(transactions);

        // Update stats
        {
            let mut count = self.transaction_count.write();
            let mut fees = self.fees_collected.write();

            for result in &results {
                if result.success {
                    *count += 1;
                }
                *fees += result.fee;
            }
        }

        results
    }

    /// Process a single transaction
    pub fn process_transaction(&self, tx: Transaction) -> ExecutionResult {
        self.process_transactions(vec![tx]).pop().unwrap()
    }

    /// Get transaction count
    pub fn transaction_count(&self) -> u64 {
        *self.transaction_count.read()
    }

    /// Get collected fees
    pub fn collected_fees(&self) -> u64 {
        *self.fees_collected.read()
    }

    /// Freeze the bank (finalize)
    pub fn freeze(&self) {
        *self.frozen.write() = true;
    }

    /// Is frozen
    pub fn is_frozen(&self) -> bool {
        *self.frozen.read()
    }

    /// Get hash for this bank state
    pub fn hash(&self) -> Hash {
        // Simple state hash (in production, this would be a merkle root)
        Hash::hash_multiple(&[
            &self.slot.to_le_bytes(),
            self.blockhash.as_bytes(),
            &self.transaction_count().to_le_bytes(),
        ])
    }
}

/// Bank forks - manages multiple bank versions
pub struct BankForks {
    /// Banks by slot
    banks: RwLock<HashMap<Slot, Arc<Bank>>>,
    /// Root (finalized) slot
    root: RwLock<Slot>,
    /// Working bank
    working_bank: RwLock<Option<Arc<Bank>>>,
}

impl BankForks {
    /// Create new bank forks from genesis
    pub fn new(genesis_bank: Bank) -> Self {
        let genesis = Arc::new(genesis_bank);
        let mut banks = HashMap::new();
        banks.insert(0, genesis.clone());

        Self {
            banks: RwLock::new(banks),
            root: RwLock::new(0),
            working_bank: RwLock::new(Some(genesis)),
        }
    }

    /// Get bank by slot
    pub fn get(&self, slot: Slot) -> Option<Arc<Bank>> {
        let banks = self.banks.read();
        banks.get(&slot).cloned()
    }

    /// Get root bank
    pub fn root_bank(&self) -> Option<Arc<Bank>> {
        let root = *self.root.read();
        self.get(root)
    }

    /// Get working bank
    pub fn working_bank(&self) -> Option<Arc<Bank>> {
        self.working_bank.read().clone()
    }

    /// Set working bank
    pub fn set_working_bank(&self, bank: Arc<Bank>) {
        *self.working_bank.write() = Some(bank);
    }

    /// Insert a new bank
    pub fn insert(&self, bank: Bank) -> Arc<Bank> {
        let slot = bank.slot();
        let bank = Arc::new(bank);

        {
            let mut banks = self.banks.write();
            banks.insert(slot, bank.clone());
        }

        bank
    }

    /// Set root (finalize a slot)
    pub fn set_root(&self, slot: Slot) {
        let old_root = *self.root.read();
        *self.root.write() = slot;

        // Prune old banks
        let mut banks = self.banks.write();
        banks.retain(|&s, _| s >= old_root);
    }

    /// Get root slot
    pub fn root(&self) -> Slot {
        *self.root.read()
    }

    /// Get highest slot
    pub fn highest_slot(&self) -> Slot {
        let banks = self.banks.read();
        banks.keys().max().copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_bank() {
        let pubkey = Pubkey::new([1u8; 32]);
        let bank = Bank::new_genesis(vec![(pubkey, 1000)]);

        assert_eq!(bank.slot(), 0);
        assert_eq!(bank.get_balance(&pubkey), 1000);
        assert!(!bank.is_frozen());
    }

    #[test]
    fn test_bank_credit() {
        let pubkey = Pubkey::new([1u8; 32]);
        let bank = Bank::new_genesis(vec![]);

        assert_eq!(bank.get_balance(&pubkey), 0);
        bank.credit(&pubkey, 500);
        assert_eq!(bank.get_balance(&pubkey), 500);
    }

    #[test]
    fn test_bank_forks() {
        let bank = Bank::new_genesis(vec![]);
        let forks = BankForks::new(bank);

        assert_eq!(forks.root(), 0);
        assert!(forks.get(0).is_some());
        assert!(forks.get(1).is_none());
    }
}
