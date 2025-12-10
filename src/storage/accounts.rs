//! Account storage

use std::collections::HashMap;
use std::sync::RwLock;
use serde::{Deserialize, Serialize};

use crate::core::Account;
use crate::crypto::Pubkey;

/// Account store for managing account state
pub struct AccountStore {
    /// In-memory account cache
    accounts: RwLock<HashMap<Pubkey, Account>>,
    /// Sled database for persistence (optional)
    db: Option<sled::Tree>,
}

impl AccountStore {
    /// Create a new in-memory account store
    pub fn new_memory() -> Self {
        Self {
            accounts: RwLock::new(HashMap::new()),
            db: None,
        }
    }

    /// Create a new persistent account store
    pub fn new_persistent(db: sled::Tree) -> Self {
        // Load existing accounts from disk
        let mut accounts = HashMap::new();
        for item in db.iter() {
            if let Ok((key, value)) = item {
                if key.len() == 32 {
                    let mut pubkey_bytes = [0u8; 32];
                    pubkey_bytes.copy_from_slice(&key);
                    let pubkey = Pubkey::new(pubkey_bytes);
                    if let Ok(account) = bincode::deserialize::<Account>(&value) {
                        accounts.insert(pubkey, account);
                    }
                }
            }
        }

        Self {
            accounts: RwLock::new(accounts),
            db: Some(db),
        }
    }

    /// Get account by pubkey
    pub fn get(&self, pubkey: &Pubkey) -> Option<Account> {
        let accounts = self.accounts.read().unwrap();
        accounts.get(pubkey).cloned()
    }

    /// Get account balance
    pub fn get_balance(&self, pubkey: &Pubkey) -> u64 {
        self.get(pubkey).map(|a| a.celers).unwrap_or(0)
    }

    /// Set account
    pub fn set(&self, pubkey: &Pubkey, account: Account) {
        // Update in memory
        {
            let mut accounts = self.accounts.write().unwrap();
            accounts.insert(*pubkey, account.clone());
        }

        // Persist to disk if available
        if let Some(ref db) = self.db {
            if let Ok(data) = bincode::serialize(&account) {
                let _ = db.insert(pubkey.as_bytes(), data);
            }
        }
    }

    /// Credit account (add celers)
    pub fn credit(&self, pubkey: &Pubkey, celers: u64) {
        let mut accounts = self.accounts.write().unwrap();
        let account = accounts.entry(*pubkey).or_insert_with(|| {
            Account::new(0, Pubkey::zero())
        });
        account.celers = account.celers.saturating_add(celers);

        // Persist
        if let Some(ref db) = self.db {
            if let Ok(data) = bincode::serialize(account) {
                let _ = db.insert(pubkey.as_bytes(), data);
            }
        }
    }

    /// Debit account (subtract celers)
    pub fn debit(&self, pubkey: &Pubkey, celers: u64) -> bool {
        let mut accounts = self.accounts.write().unwrap();
        if let Some(account) = accounts.get_mut(pubkey) {
            if account.celers >= celers {
                account.celers -= celers;

                // Persist
                if let Some(ref db) = self.db {
                    if let Ok(data) = bincode::serialize(account) {
                        let _ = db.insert(pubkey.as_bytes(), data);
                    }
                }
                return true;
            }
        }
        false
    }

    /// Transfer celers between accounts
    pub fn transfer(&self, from: &Pubkey, to: &Pubkey, celers: u64) -> bool {
        let mut accounts = self.accounts.write().unwrap();

        // Check balance
        let from_balance = accounts.get(from).map(|a| a.celers).unwrap_or(0);
        if from_balance < celers {
            return false;
        }

        // Debit from
        if let Some(from_account) = accounts.get_mut(from) {
            from_account.celers -= celers;
        }

        // Credit to
        let to_account = accounts.entry(*to).or_insert_with(|| Account::new(0, Pubkey::zero()));
        to_account.celers += celers;

        // Persist both accounts
        if let Some(ref db) = self.db {
            if let Some(from_account) = accounts.get(from) {
                if let Ok(data) = bincode::serialize(from_account) {
                    let _ = db.insert(from.as_bytes(), data);
                }
            }
            if let Some(to_account) = accounts.get(to) {
                if let Ok(data) = bincode::serialize(to_account) {
                    let _ = db.insert(to.as_bytes(), data);
                }
            }
        }

        true
    }

    /// Get total supply (sum of all balances)
    pub fn total_supply(&self) -> u64 {
        let accounts = self.accounts.read().unwrap();
        accounts.values().map(|a| a.celers).sum()
    }

    /// Get account count
    pub fn count(&self) -> usize {
        let accounts = self.accounts.read().unwrap();
        accounts.len()
    }

    /// Flush to disk
    pub fn flush(&self) {
        if let Some(ref db) = self.db {
            let _ = db.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_store() {
        let store = AccountStore::new_memory();
        let pubkey = Pubkey::new([1u8; 32]);

        // Initial balance should be 0
        assert_eq!(store.get_balance(&pubkey), 0);

        // Credit
        store.credit(&pubkey, 1000);
        assert_eq!(store.get_balance(&pubkey), 1000);

        // Debit
        assert!(store.debit(&pubkey, 500));
        assert_eq!(store.get_balance(&pubkey), 500);

        // Over-debit should fail
        assert!(!store.debit(&pubkey, 1000));
        assert_eq!(store.get_balance(&pubkey), 500);
    }

    #[test]
    fn test_transfer() {
        let store = AccountStore::new_memory();
        let from = Pubkey::new([1u8; 32]);
        let to = Pubkey::new([2u8; 32]);

        store.credit(&from, 1000);

        // Transfer
        assert!(store.transfer(&from, &to, 300));
        assert_eq!(store.get_balance(&from), 700);
        assert_eq!(store.get_balance(&to), 300);

        // Over-transfer should fail
        assert!(!store.transfer(&from, &to, 1000));
    }
}
