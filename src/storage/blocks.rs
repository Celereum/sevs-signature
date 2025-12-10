//! Block storage

use std::collections::HashMap;
use std::sync::RwLock;

use crate::core::{Block, Slot, Transaction};
use crate::crypto::{Hash, Signature};

/// Block store for managing block history
pub struct BlockStore {
    /// Blocks by slot
    blocks: RwLock<HashMap<Slot, Block>>,
    /// Transactions by signature
    transactions: RwLock<HashMap<[u8; 64], (Transaction, Slot)>>,
    /// Current slot
    current_slot: RwLock<Slot>,
    /// Latest blockhash
    latest_blockhash: RwLock<Hash>,
    /// Transaction count
    tx_count: RwLock<u64>,
    /// Sled database for persistence
    db: Option<sled::Tree>,
}

impl BlockStore {
    /// Create a new in-memory block store
    pub fn new_memory() -> Self {
        Self {
            blocks: RwLock::new(HashMap::new()),
            transactions: RwLock::new(HashMap::new()),
            current_slot: RwLock::new(0),
            latest_blockhash: RwLock::new(Hash::hash(b"genesis")),
            tx_count: RwLock::new(0),
            db: None,
        }
    }

    /// Create a new persistent block store
    pub fn new_persistent(db: sled::Tree) -> Self {
        // Load metadata from disk
        let current_slot = db.get(b"current_slot")
            .ok()
            .flatten()
            .and_then(|v| {
                if v.len() == 8 {
                    Some(u64::from_le_bytes(v.as_ref().try_into().unwrap()))
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let latest_blockhash = db.get(b"latest_blockhash")
            .ok()
            .flatten()
            .and_then(|v| {
                if v.len() == 32 {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&v);
                    Some(Hash::new(bytes))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| Hash::hash(b"genesis"));

        let tx_count = db.get(b"tx_count")
            .ok()
            .flatten()
            .and_then(|v| {
                if v.len() == 8 {
                    Some(u64::from_le_bytes(v.as_ref().try_into().unwrap()))
                } else {
                    None
                }
            })
            .unwrap_or(0);

        Self {
            blocks: RwLock::new(HashMap::new()),
            transactions: RwLock::new(HashMap::new()),
            current_slot: RwLock::new(current_slot),
            latest_blockhash: RwLock::new(latest_blockhash),
            tx_count: RwLock::new(tx_count),
            db: Some(db),
        }
    }

    /// Get block by slot
    pub fn get_block(&self, slot: Slot) -> Option<Block> {
        // Try memory first
        {
            let blocks = self.blocks.read().unwrap();
            if let Some(block) = blocks.get(&slot) {
                return Some(block.clone());
            }
        }

        // Try disk
        if let Some(ref db) = self.db {
            let key = format!("block:{}", slot);
            if let Ok(Some(data)) = db.get(key.as_bytes()) {
                if let Ok(block) = bincode::deserialize::<Block>(&data) {
                    return Some(block);
                }
            }
        }

        None
    }

    /// Store a block
    pub fn store_block(&self, block: Block) {
        let slot = block.header.slot;

        // Update current slot
        {
            let mut current = self.current_slot.write().unwrap();
            if slot > *current {
                *current = slot;
            }
        }

        // Update latest blockhash
        {
            let mut hash = self.latest_blockhash.write().unwrap();
            *hash = block.hash();
        }

        // Index transactions
        {
            let mut tx_count = self.tx_count.write().unwrap();
            let mut transactions = self.transactions.write().unwrap();
            for tx in &block.transactions {
                if let Some(sig) = tx.signatures.first() {
                    let mut sig_bytes = [0u8; 64];
                    let sig_full = sig.signature.as_bytes();
                    sig_bytes.copy_from_slice(&sig_full[..64]);
                    transactions.insert(sig_bytes, (tx.clone(), slot));
                    *tx_count += 1;
                }
            }
        }

        // Store in memory
        {
            let mut blocks = self.blocks.write().unwrap();
            blocks.insert(slot, block.clone());
        }

        // Persist to disk
        if let Some(ref db) = self.db {
            let key = format!("block:{}", slot);
            if let Ok(data) = bincode::serialize(&block) {
                let _ = db.insert(key.as_bytes(), data);
            }

            // Update metadata
            let current = *self.current_slot.read().unwrap();
            let _ = db.insert(b"current_slot", &current.to_le_bytes());

            let hash = *self.latest_blockhash.read().unwrap();
            let _ = db.insert(b"latest_blockhash", hash.as_bytes());

            let count = *self.tx_count.read().unwrap();
            let _ = db.insert(b"tx_count", &count.to_le_bytes());
        }
    }

    /// Get transaction by signature
    pub fn get_transaction(&self, signature: &Signature) -> Option<(Transaction, Slot)> {
        let transactions = self.transactions.read().unwrap();
        let mut sig_bytes = [0u8; 64];
        let sig_full = signature.signature.as_bytes();
        sig_bytes.copy_from_slice(&sig_full[..64]);
        transactions.get(&sig_bytes).cloned()
    }

    /// Get current slot
    pub fn get_current_slot(&self) -> Slot {
        *self.current_slot.read().unwrap()
    }

    /// Set current slot
    pub fn set_current_slot(&self, slot: Slot) {
        let mut current = self.current_slot.write().unwrap();
        *current = slot;

        if let Some(ref db) = self.db {
            let _ = db.insert(b"current_slot", &slot.to_le_bytes());
        }
    }

    /// Get latest blockhash
    pub fn get_latest_blockhash(&self) -> Hash {
        *self.latest_blockhash.read().unwrap()
    }

    /// Get transaction count
    pub fn get_transaction_count(&self) -> u64 {
        *self.tx_count.read().unwrap()
    }

    /// Increment transaction count
    pub fn increment_transaction_count(&self) {
        let mut count = self.tx_count.write().unwrap();
        *count += 1;
    }

    /// Get block count
    pub fn block_count(&self) -> usize {
        let blocks = self.blocks.read().unwrap();
        blocks.len()
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
    use crate::crypto::{Pubkey, Keypair};

    fn make_test_block(slot: Slot) -> Block {
        let leader = Keypair::generate();
        Block::new(
            slot,
            Hash::hash(b"prev"),
            Hash::hash(b"poh"),
            64,
            leader.address(),
            vec![],
        )
    }

    #[test]
    fn test_block_store() {
        let store = BlockStore::new_memory();

        // Store blocks
        for i in 0..5u64 {
            let block = make_test_block(i);
            store.store_block(block);
        }

        // Retrieve
        assert_eq!(store.get_current_slot(), 4);
        assert!(store.get_block(2).is_some());
        assert!(store.get_block(10).is_none());
    }
}
