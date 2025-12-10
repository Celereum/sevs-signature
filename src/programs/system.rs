//! System Program - Native program for account management
//!
//! Handles:
//! - Creating accounts
//! - Transferring ALT (native token)
//! - Allocating account space

use crate::crypto::Pubkey;
use crate::core::{Account, Instruction};
use serde::{Deserialize, Serialize};

/// System Program ID (all zeros)
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey([0u8; 32]);

/// System Program instructions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemInstruction {
    /// Create a new account
    /// Accounts: [payer, new_account]
    CreateAccount {
        /// Celers to transfer to new account
        celers: u64,
        /// Space to allocate for account data
        space: u64,
        /// Owner program of the new account
        owner: Pubkey,
    },

    /// Transfer celers between accounts
    /// Accounts: [from, to]
    Transfer {
        /// Amount to transfer
        celers: u64,
    },

    /// Allocate space for account data
    /// Accounts: [account]
    Allocate {
        /// Space to allocate
        space: u64,
    },

    /// Assign account to a program
    /// Accounts: [account]
    Assign {
        /// New owner program
        owner: Pubkey,
    },
}

impl SystemInstruction {
    /// Serialize instruction to bytes
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize instruction from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }

    /// Create a transfer instruction
    pub fn transfer(from: Pubkey, to: Pubkey, celers: u64) -> (Instruction, Vec<Pubkey>) {
        let instruction = Instruction {
            program_id_index: 0, // System program
            accounts: vec![0, 1], // from, to indices
            data: Self::Transfer { celers }.serialize(),
        };
        (instruction, vec![from, to, SYSTEM_PROGRAM_ID])
    }

    /// Create a create_account instruction
    pub fn create_account(
        payer: Pubkey,
        new_account: Pubkey,
        celers: u64,
        space: u64,
        owner: Pubkey,
    ) -> (Instruction, Vec<Pubkey>) {
        let instruction = Instruction {
            program_id_index: 0,
            accounts: vec![0, 1],
            data: Self::CreateAccount { celers, space, owner }.serialize(),
        };
        (instruction, vec![payer, new_account, SYSTEM_PROGRAM_ID])
    }
}

/// System Program implementation
pub struct SystemProgram;

impl SystemProgram {
    /// Process a system instruction
    pub fn process(
        instruction: &SystemInstruction,
        accounts: &mut [Account],
    ) -> Result<(), SystemError> {
        match instruction {
            SystemInstruction::CreateAccount { celers, space, owner } => {
                Self::process_create_account(accounts, *celers, *space, owner)
            }
            SystemInstruction::Transfer { celers } => {
                Self::process_transfer(accounts, *celers)
            }
            SystemInstruction::Allocate { space } => {
                Self::process_allocate(accounts, *space)
            }
            SystemInstruction::Assign { owner } => {
                Self::process_assign(accounts, owner)
            }
        }
    }

    fn process_create_account(
        accounts: &mut [Account],
        celers: u64,
        space: u64,
        owner: &Pubkey,
    ) -> Result<(), SystemError> {
        if accounts.len() < 2 {
            return Err(SystemError::NotEnoughAccounts);
        }

        // Check payer has enough celers
        if accounts[0].celers < celers {
            return Err(SystemError::InsufficientFunds);
        }

        // Check new account is empty
        if accounts[1].celers > 0 || !accounts[1].data.is_empty() {
            return Err(SystemError::AccountAlreadyExists);
        }

        // Transfer celers
        accounts[0].celers -= celers;
        accounts[1].celers = celers;

        // Allocate space and set owner
        accounts[1].data = vec![0u8; space as usize];
        accounts[1].owner = *owner;

        Ok(())
    }

    fn process_transfer(accounts: &mut [Account], celers: u64) -> Result<(), SystemError> {
        if accounts.len() < 2 {
            return Err(SystemError::NotEnoughAccounts);
        }

        let from = &mut accounts[0];

        // Check balance
        if from.celers < celers {
            return Err(SystemError::InsufficientFunds);
        }

        // Transfer
        from.celers -= celers;
        accounts[1].celers += celers;

        Ok(())
    }

    fn process_allocate(accounts: &mut [Account], space: u64) -> Result<(), SystemError> {
        if accounts.is_empty() {
            return Err(SystemError::NotEnoughAccounts);
        }

        let account = &mut accounts[0];

        // Check account is empty
        if !account.data.is_empty() {
            return Err(SystemError::AccountAlreadyExists);
        }

        account.data = vec![0u8; space as usize];
        Ok(())
    }

    fn process_assign(accounts: &mut [Account], owner: &Pubkey) -> Result<(), SystemError> {
        if accounts.is_empty() {
            return Err(SystemError::NotEnoughAccounts);
        }

        accounts[0].owner = *owner;
        Ok(())
    }
}

/// System program errors
#[derive(Debug, Clone, PartialEq)]
pub enum SystemError {
    NotEnoughAccounts,
    InsufficientFunds,
    AccountAlreadyExists,
    InvalidInstruction,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer() {
        let mut from = Account::new(1000, Pubkey::zero());
        let mut to = Account::new(0, Pubkey::zero());

        let result = SystemProgram::process(
            &SystemInstruction::Transfer { celers: 500 },
            &mut [from.clone(), to.clone()],
        );

        // Need to use mutable references properly
        let mut accounts = vec![from, to];
        let result = SystemProgram::process(
            &SystemInstruction::Transfer { celers: 500 },
            &mut accounts,
        );

        assert!(result.is_ok());
        assert_eq!(accounts[0].celers, 500);
        assert_eq!(accounts[1].celers, 500);
    }

    #[test]
    fn test_transfer_insufficient_funds() {
        let mut accounts = vec![
            Account::new(100, Pubkey::zero()),
            Account::new(0, Pubkey::zero()),
        ];

        let result = SystemProgram::process(
            &SystemInstruction::Transfer { celers: 500 },
            &mut accounts,
        );

        assert_eq!(result, Err(SystemError::InsufficientFunds));
    }
}
