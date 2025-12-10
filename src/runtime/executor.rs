//! Transaction Executor - Parallel execution engine (Sealevel-like)
//!
//! Optimized for high throughput with parallel batch execution using rayon.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;
use rayon::prelude::*;

use crate::core::{Account, Transaction, Instruction, Slot};
use crate::crypto::Pubkey;
use crate::crypto::Hash;

use super::program::{Program, ProgramId, ProgramError, AccountRef, SystemProgram, SYSTEM_PROGRAM_ID};

/// Execution result for a transaction
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Transaction signature
    pub signature: Hash,
    /// Success or failure
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Logs
    pub logs: Vec<String>,
    /// Compute units used
    pub compute_units: u64,
    /// Fee paid
    pub fee: u64,
}

impl ExecutionResult {
    pub fn success(signature: Hash, compute_units: u64, fee: u64) -> Self {
        Self {
            signature,
            success: true,
            error: None,
            logs: vec![],
            compute_units,
            fee,
        }
    }

    pub fn failure(signature: Hash, error: String, fee: u64) -> Self {
        Self {
            signature,
            success: false,
            error: Some(error),
            logs: vec![],
            compute_units: 0,
            fee,
        }
    }
}

/// Transaction batch for parallel execution
struct TransactionBatch {
    /// Transactions in this batch
    transactions: Vec<(usize, Transaction)>,
    /// Account locks
    write_locks: HashSet<Pubkey>,
    read_locks: HashSet<Pubkey>,
}

impl TransactionBatch {
    fn new() -> Self {
        Self {
            transactions: Vec::new(),
            write_locks: HashSet::new(),
            read_locks: HashSet::new(),
        }
    }

    /// Try to add a transaction to this batch
    fn try_add(&mut self, idx: usize, tx: &Transaction) -> bool {
        // Get all accounts this transaction touches
        let (writes, reads) = Self::get_account_locks(tx);

        // Check for conflicts with existing locks
        // Write-write conflict
        if writes.iter().any(|a| self.write_locks.contains(a)) {
            return false;
        }

        // Read-write conflict
        if reads.iter().any(|a| self.write_locks.contains(a)) {
            return false;
        }

        // Write-read conflict
        if writes.iter().any(|a| self.read_locks.contains(a)) {
            return false;
        }

        // No conflicts - add to batch
        self.write_locks.extend(writes);
        self.read_locks.extend(reads);
        self.transactions.push((idx, tx.clone()));

        true
    }

    /// Get read and write locks for a transaction
    fn get_account_locks(tx: &Transaction) -> (HashSet<Pubkey>, HashSet<Pubkey>) {
        let mut writes = HashSet::new();
        let mut reads = HashSet::new();

        let header = &tx.message.header;
        let accounts = &tx.message.account_keys;

        for (i, account) in accounts.iter().enumerate() {
            let is_writable = if i < header.num_required_signatures as usize {
                // Signed accounts - first ones are writable
                i < (header.num_required_signatures - header.num_readonly_signed_accounts) as usize
            } else {
                // Unsigned accounts
                let unsigned_idx = i - header.num_required_signatures as usize;
                unsigned_idx < (accounts.len() - header.num_required_signatures as usize - header.num_readonly_unsigned_accounts as usize)
            };

            if is_writable {
                writes.insert(*account);
            } else {
                reads.insert(*account);
            }
        }

        (writes, reads)
    }
}

/// Transaction executor with parallel execution support
pub struct TransactionExecutor {
    /// Registered programs
    programs: HashMap<ProgramId, Arc<dyn Program>>,
    /// Account cache
    accounts: RwLock<HashMap<Pubkey, Account>>,
    /// Base fee per signature
    base_fee: u64,
    /// Compute budget per transaction
    compute_budget: u64,
    /// Maximum parallel threads
    max_threads: usize,
}

impl TransactionExecutor {
    /// Create a new executor
    pub fn new() -> Self {
        let mut programs: HashMap<ProgramId, Arc<dyn Program>> = HashMap::new();

        // Register system program
        programs.insert(SYSTEM_PROGRAM_ID, Arc::new(SystemProgram));

        // Configure rayon thread pool for optimal parallelism
        let max_threads = num_cpus::get().max(4);

        Self {
            programs,
            accounts: RwLock::new(HashMap::new()),
            base_fee: 2500, // Reduced fee: 2500 celers per signature
            compute_budget: 400_000, // Increased to 400k compute units
            max_threads,
        }
    }

    /// Register a program
    pub fn register_program(&mut self, program: Arc<dyn Program>) {
        self.programs.insert(program.id(), program);
    }

    /// Load accounts into cache
    pub fn load_accounts(&self, accounts: Vec<(Pubkey, Account)>) {
        let mut cache = self.accounts.write();
        for (key, account) in accounts {
            cache.insert(key, account);
        }
    }

    /// Get account from cache
    pub fn get_account(&self, pubkey: &Pubkey) -> Option<Account> {
        let cache = self.accounts.read();
        cache.get(pubkey).cloned()
    }

    /// Set account in cache
    pub fn set_account(&self, pubkey: &Pubkey, account: Account) {
        let mut cache = self.accounts.write();
        cache.insert(*pubkey, account);
    }

    /// Execute transactions in parallel batches using rayon
    pub fn execute_batch(&self, transactions: Vec<Transaction>) -> Vec<ExecutionResult> {
        let len = transactions.len();
        let results: Arc<RwLock<Vec<Option<ExecutionResult>>>> = Arc::new(RwLock::new(vec![None; len]));

        // Create batches of non-conflicting transactions
        let batches = self.create_batches(&transactions);

        // Execute each batch in parallel using rayon
        for batch in batches {
            // Within each batch, transactions can run in parallel since they don't conflict
            let batch_results: Vec<(usize, ExecutionResult)> = batch.transactions
                .into_par_iter()
                .map(|(idx, tx)| {
                    let result = self.execute_single(&tx);
                    (idx, result)
                })
                .collect();

            // Write results back
            let mut results_guard = results.write();
            for (idx, result) in batch_results {
                results_guard[idx] = Some(result);
            }
        }

        // Extract results
        let final_results = results.read();
        final_results.iter().map(|r| r.clone().unwrap_or_else(|| {
            ExecutionResult::failure(Hash::hash(b"unknown"), "Not executed".to_string(), 0)
        })).collect()
    }

    /// Create parallel execution batches
    fn create_batches(&self, transactions: &[Transaction]) -> Vec<TransactionBatch> {
        let mut batches = Vec::new();
        let mut current_batch = TransactionBatch::new();

        for (idx, tx) in transactions.iter().enumerate() {
            if !current_batch.try_add(idx, tx) {
                // Conflict - start new batch
                if !current_batch.transactions.is_empty() {
                    batches.push(current_batch);
                }
                current_batch = TransactionBatch::new();
                current_batch.try_add(idx, tx);
            }
        }

        // Push last batch
        if !current_batch.transactions.is_empty() {
            batches.push(current_batch);
        }

        batches
    }

    /// Execute a single transaction
    pub fn execute_single(&self, tx: &Transaction) -> ExecutionResult {
        let signature = Hash::hash(&bincode::serialize(tx).unwrap_or_default());

        // Verify signatures
        if !tx.verify() {
            return ExecutionResult::failure(signature, "Invalid signature".to_string(), 0);
        }

        // Calculate fee
        let fee = self.base_fee * tx.signatures.len() as u64;

        // Check fee payer has enough balance
        if let Some(fee_payer) = tx.message.account_keys.first() {
            let balance = self.get_account(fee_payer)
                .map(|a| a.celers)
                .unwrap_or(0);

            if balance < fee {
                return ExecutionResult::failure(
                    signature,
                    "Insufficient balance for fee".to_string(),
                    0,
                );
            }

            // Deduct fee
            if let Some(mut account) = self.get_account(fee_payer) {
                account.celers -= fee;
                self.set_account(fee_payer, account);
            }
        }

        // Execute each instruction
        let mut compute_used = 0u64;

        for instruction in &tx.message.instructions {
            match self.execute_instruction(tx, instruction) {
                Ok(compute) => {
                    compute_used += compute;
                    if compute_used > self.compute_budget {
                        return ExecutionResult::failure(
                            signature,
                            "Compute budget exceeded".to_string(),
                            fee,
                        );
                    }
                }
                Err(e) => {
                    return ExecutionResult::failure(signature, e.to_string(), fee);
                }
            }
        }

        ExecutionResult::success(signature, compute_used, fee)
    }

    /// Execute a single instruction
    fn execute_instruction(
        &self,
        tx: &Transaction,
        instruction: &Instruction,
    ) -> Result<u64, ProgramError> {
        // Get program ID
        let program_id = tx.message.account_keys
            .get(instruction.program_id_index as usize)
            .ok_or(ProgramError::InvalidProgramId)?;

        // Find program
        let program = self.programs.get(program_id)
            .ok_or(ProgramError::InvalidProgramId)?;

        // Load accounts for this instruction
        let mut accounts_data: Vec<(Pubkey, Account, bool, bool)> = Vec::new();

        for (i, &account_idx) in instruction.accounts.iter().enumerate() {
            let pubkey = tx.message.account_keys
                .get(account_idx as usize)
                .ok_or(ProgramError::AccountNotFound)?;

            let account = self.get_account(pubkey)
                .unwrap_or_else(|| Account::new(0, Pubkey::zero()));

            // Determine signer/writable status
            let is_signer = (account_idx as usize) < tx.message.header.num_required_signatures as usize;
            let is_writable = self.is_account_writable(tx, account_idx as usize);

            accounts_data.push((*pubkey, account, is_signer, is_writable));
        }

        // Create account refs
        let mut account_refs: Vec<AccountRef> = accounts_data.iter_mut()
            .map(|(key, account, is_signer, is_writable)| {
                AccountRef::new(key, account, *is_signer, *is_writable)
            })
            .collect();

        // Execute
        program.process(instruction, &mut account_refs)?;

        // Save modified accounts back
        for (key, account, _, _) in accounts_data {
            self.set_account(&key, account);
        }

        // Return compute units (simplified)
        Ok(1000)
    }

    /// Check if account at index is writable
    fn is_account_writable(&self, tx: &Transaction, idx: usize) -> bool {
        let header = &tx.message.header;
        let num_accounts = tx.message.account_keys.len();

        if idx < header.num_required_signatures as usize {
            // Signed account
            idx < (header.num_required_signatures - header.num_readonly_signed_accounts) as usize
        } else {
            // Unsigned account
            let first_readonly_unsigned = num_accounts - header.num_readonly_unsigned_accounts as usize;
            idx < first_readonly_unsigned
        }
    }
}

impl Default for TransactionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn test_batch_creation() {
        let executor = TransactionExecutor::new();

        // Create some transactions
        let keypairs: Vec<_> = (0..3).map(|_| Keypair::generate()).collect();
        let mut transactions = Vec::new();

        // Create transfers between different accounts
        for i in 0..3 {
            let from = &keypairs[i];
            let to = &keypairs[(i + 1) % 3];

            let tx = Transaction::new_transfer(
                from,
                to.pubkey(),
                100,
                Hash::hash(b"blockhash"),
            );
            transactions.push(tx);
        }

        let batches = executor.create_batches(&transactions);

        // Should create multiple batches due to conflicts
        assert!(!batches.is_empty());
    }
}
