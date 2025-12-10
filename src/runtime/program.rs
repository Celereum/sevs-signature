//! Program / Smart Contract support

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::core::{Account, Transaction, Instruction};
use crate::crypto::Pubkey;

/// Program ID type (same as Pubkey)
pub type ProgramId = Pubkey;

/// System program ID (all zeros)
pub const SYSTEM_PROGRAM_ID: ProgramId = Pubkey([0u8; 32]);

/// Token program ID
pub const TOKEN_PROGRAM_ID: ProgramId = Pubkey([1u8; 32]);

/// Stake program ID
pub const STAKE_PROGRAM_ID: ProgramId = Pubkey([2u8; 32]);

/// Program trait - interface for all programs
pub trait Program: Send + Sync {
    /// Get program ID
    fn id(&self) -> ProgramId;

    /// Process an instruction
    fn process(
        &self,
        instruction: &Instruction,
        accounts: &mut [AccountRef],
    ) -> Result<(), ProgramError>;
}

/// Account reference for program execution
pub struct AccountRef<'a> {
    /// Account pubkey
    pub key: &'a Pubkey,
    /// Account data (mutable if not read-only)
    pub account: &'a mut Account,
    /// Is signer
    pub is_signer: bool,
    /// Is writable
    pub is_writable: bool,
}

impl<'a> AccountRef<'a> {
    pub fn new(
        key: &'a Pubkey,
        account: &'a mut Account,
        is_signer: bool,
        is_writable: bool,
    ) -> Self {
        Self {
            key,
            account,
            is_signer,
            is_writable,
        }
    }

    /// Get celers
    pub fn celers(&self) -> u64 {
        self.account.celers
    }

    /// Set celers (requires writable)
    pub fn set_celers(&mut self, celers: u64) -> Result<(), ProgramError> {
        if !self.is_writable {
            return Err(ProgramError::ReadonlyViolation);
        }
        self.account.celers = celers;
        Ok(())
    }

    /// Add celers
    pub fn add_celers(&mut self, amount: u64) -> Result<(), ProgramError> {
        let new_balance = self.account.celers.checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        self.set_celers(new_balance)
    }

    /// Subtract celers
    pub fn sub_celers(&mut self, amount: u64) -> Result<(), ProgramError> {
        if self.account.celers < amount {
            return Err(ProgramError::InsufficientFunds);
        }
        let new_balance = self.account.celers - amount;
        self.set_celers(new_balance)
    }

    /// Get data slice
    pub fn data(&self) -> &[u8] {
        &self.account.data
    }

    /// Get mutable data slice
    pub fn data_mut(&mut self) -> Result<&mut [u8], ProgramError> {
        if !self.is_writable {
            return Err(ProgramError::ReadonlyViolation);
        }
        Ok(&mut self.account.data)
    }
}

/// Program error types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramError {
    /// Invalid instruction
    InvalidInstruction,
    /// Invalid account data
    InvalidAccountData,
    /// Missing required signature
    MissingRequiredSignature,
    /// Insufficient funds
    InsufficientFunds,
    /// Account already in use
    AccountAlreadyInUse,
    /// Account not found
    AccountNotFound,
    /// Readonly account modified
    ReadonlyViolation,
    /// Arithmetic overflow
    ArithmeticOverflow,
    /// Invalid program ID
    InvalidProgramId,
    /// Custom error
    Custom(u32),
}

impl std::fmt::Display for ProgramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgramError::InvalidInstruction => write!(f, "Invalid instruction"),
            ProgramError::InvalidAccountData => write!(f, "Invalid account data"),
            ProgramError::MissingRequiredSignature => write!(f, "Missing required signature"),
            ProgramError::InsufficientFunds => write!(f, "Insufficient funds"),
            ProgramError::AccountAlreadyInUse => write!(f, "Account already in use"),
            ProgramError::AccountNotFound => write!(f, "Account not found"),
            ProgramError::ReadonlyViolation => write!(f, "Readonly account modified"),
            ProgramError::ArithmeticOverflow => write!(f, "Arithmetic overflow"),
            ProgramError::InvalidProgramId => write!(f, "Invalid program ID"),
            ProgramError::Custom(code) => write!(f, "Custom error: {}", code),
        }
    }
}

impl std::error::Error for ProgramError {}

/// System Program - handles native SOL transfers and account creation
pub struct SystemProgram;

impl SystemProgram {
    /// Instruction types
    pub const CREATE_ACCOUNT: u32 = 0;
    pub const ASSIGN: u32 = 1;
    pub const TRANSFER: u32 = 2;
    pub const CREATE_ACCOUNT_WITH_SEED: u32 = 3;
    pub const ADVANCE_NONCE: u32 = 4;
    pub const WITHDRAW_NONCE: u32 = 5;
    pub const INITIALIZE_NONCE: u32 = 6;
    pub const AUTHORIZE_NONCE: u32 = 7;
    pub const ALLOCATE: u32 = 8;
    pub const ALLOCATE_WITH_SEED: u32 = 9;
    pub const ASSIGN_WITH_SEED: u32 = 10;
    pub const TRANSFER_WITH_SEED: u32 = 11;

    /// Create transfer instruction data
    pub fn transfer_instruction(celers: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&Self::TRANSFER.to_le_bytes());
        data.extend_from_slice(&celers.to_le_bytes());
        data
    }

    /// Create account instruction data
    pub fn create_account_instruction(celers: u64, space: u64, owner: &Pubkey) -> Vec<u8> {
        let mut data = Vec::with_capacity(52);
        data.extend_from_slice(&Self::CREATE_ACCOUNT.to_le_bytes());
        data.extend_from_slice(&celers.to_le_bytes());
        data.extend_from_slice(&space.to_le_bytes());
        data.extend_from_slice(owner.as_bytes());
        data
    }

    /// Parse instruction type
    fn parse_instruction_type(data: &[u8]) -> Option<u32> {
        if data.len() < 4 {
            return None;
        }
        Some(u32::from_le_bytes(data[..4].try_into().unwrap()))
    }

    /// Process transfer
    fn process_transfer(accounts: &mut [AccountRef], celers: u64) -> Result<(), ProgramError> {
        if accounts.len() < 2 {
            return Err(ProgramError::InvalidInstruction);
        }

        // Source must be signer and writable
        if !accounts[0].is_signer || !accounts[0].is_writable {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Destination must be writable
        if !accounts[1].is_writable {
            return Err(ProgramError::ReadonlyViolation);
        }

        // Transfer
        accounts[0].sub_celers(celers)?;
        accounts[1].add_celers(celers)?;

        Ok(())
    }

    /// Process create account
    fn process_create_account(
        accounts: &mut [AccountRef],
        celers: u64,
        space: u64,
        owner: &Pubkey,
    ) -> Result<(), ProgramError> {
        if accounts.len() < 2 {
            return Err(ProgramError::InvalidInstruction);
        }

        // Funder must be signer and writable
        if !accounts[0].is_signer || !accounts[0].is_writable {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // New account must be signer and writable
        if !accounts[1].is_signer || !accounts[1].is_writable {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Check if account already exists
        if accounts[1].account.celers > 0 || !accounts[1].account.data.is_empty() {
            return Err(ProgramError::AccountAlreadyInUse);
        }

        // Transfer celers
        accounts[0].sub_celers(celers)?;
        accounts[1].account.celers = celers;

        // Allocate space
        accounts[1].account.data = vec![0u8; space as usize];

        // Set owner
        accounts[1].account.owner = *owner;

        Ok(())
    }
}

impl Program for SystemProgram {
    fn id(&self) -> ProgramId {
        SYSTEM_PROGRAM_ID
    }

    fn process(
        &self,
        instruction: &Instruction,
        accounts: &mut [AccountRef],
    ) -> Result<(), ProgramError> {
        let instruction_type = Self::parse_instruction_type(&instruction.data)
            .ok_or(ProgramError::InvalidInstruction)?;

        match instruction_type {
            Self::TRANSFER => {
                if instruction.data.len() < 12 {
                    return Err(ProgramError::InvalidInstruction);
                }
                let celers = u64::from_le_bytes(
                    instruction.data[4..12].try_into().unwrap()
                );
                Self::process_transfer(accounts, celers)
            }

            Self::CREATE_ACCOUNT => {
                if instruction.data.len() < 52 {
                    return Err(ProgramError::InvalidInstruction);
                }
                let celers = u64::from_le_bytes(
                    instruction.data[4..12].try_into().unwrap()
                );
                let space = u64::from_le_bytes(
                    instruction.data[12..20].try_into().unwrap()
                );
                let mut owner_bytes = [0u8; 32];
                owner_bytes.copy_from_slice(&instruction.data[20..52]);
                let owner = Pubkey::new(owner_bytes);

                Self::process_create_account(accounts, celers, space, &owner)
            }

            _ => Err(ProgramError::InvalidInstruction),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_transfer() {
        let system = SystemProgram;
        let from_key = Pubkey::new([1u8; 32]);
        let to_key = Pubkey::new([2u8; 32]);

        let mut from_account = Account::new(1000, from_key);
        let mut to_account = Account::new(500, to_key);

        let instruction = Instruction {
            program_id_index: 0,
            accounts: vec![0, 1],
            data: SystemProgram::transfer_instruction(300),
        };

        let mut accounts = vec![
            AccountRef::new(&from_key, &mut from_account, true, true),
            AccountRef::new(&to_key, &mut to_account, false, true),
        ];

        assert!(system.process(&instruction, &mut accounts).is_ok());
        assert_eq!(accounts[0].celers(), 700);
        assert_eq!(accounts[1].celers(), 800);
    }

    #[test]
    fn test_insufficient_funds() {
        let system = SystemProgram;
        let from_key = Pubkey::new([1u8; 32]);
        let to_key = Pubkey::new([2u8; 32]);

        let mut from_account = Account::new(100, from_key);
        let mut to_account = Account::new(0, to_key);

        let instruction = Instruction {
            program_id_index: 0,
            accounts: vec![0, 1],
            data: SystemProgram::transfer_instruction(500),
        };

        let mut accounts = vec![
            AccountRef::new(&from_key, &mut from_account, true, true),
            AccountRef::new(&to_key, &mut to_account, false, true),
        ];

        assert_eq!(
            system.process(&instruction, &mut accounts),
            Err(ProgramError::InsufficientFunds)
        );
    }
}
