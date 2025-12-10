//! Account structure for Celereum blockchain
//!
//! # Post-Quantum Security
//! Uses 32-byte Address derived from SEVS public keys via SHA3-256 hash.

use serde::{Deserialize, Serialize};
use crate::crypto::quantum_safe::Address;

/// Account state stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Account balance in celers (1 CEL = 10^9 celers)
    pub celers: u64,

    /// Account data (for smart contracts)
    pub data: Vec<u8>,

    /// Owner program of this account (Address)
    pub owner: Address,

    /// Is this account executable (program)?
    pub executable: bool,

    /// Epoch at which this account will next owe rent
    pub rent_epoch: u64,

    /// Is this account a signer for the current transaction?
    /// SECURITY: This field is set by the runtime during transaction processing
    /// and must NOT be modifiable by programs directly
    #[serde(default)]
    pub is_signer: bool,

    /// Is this account writable in the current transaction?
    /// SECURITY: This field is set by the runtime during transaction processing
    #[serde(default)]
    pub is_writable: bool,
}

impl Account {
    /// Create a new empty account
    pub fn new(celers: u64, owner: Address) -> Self {
        Account {
            celers,
            data: Vec::new(),
            owner,
            executable: false,
            rent_epoch: 0,
            is_signer: false,
            is_writable: false,
        }
    }

    /// Create a new account with data
    pub fn new_with_data(celers: u64, data: Vec<u8>, owner: Address) -> Self {
        Account {
            celers,
            data,
            owner,
            executable: false,
            rent_epoch: 0,
            is_signer: false,
            is_writable: false,
        }
    }

    /// Create a new program account
    pub fn new_program(celers: u64, data: Vec<u8>, owner: Address) -> Self {
        Account {
            celers,
            data,
            owner,
            executable: true,
            rent_epoch: 0,
            is_signer: false,
            is_writable: false,
        }
    }

    /// Create a new signer account (for transaction processing)
    /// SECURITY: Only the runtime should create signer accounts
    pub fn new_signer(celers: u64, owner: Address) -> Self {
        Account {
            celers,
            data: Vec::new(),
            owner,
            executable: false,
            rent_epoch: 0,
            is_signer: true,
            is_writable: true,
        }
    }

    /// Get the size of this account in bytes
    pub fn size(&self) -> usize {
        // base size + data
        8 + // celers
        4 + self.data.len() + // data with length prefix
        32 + // owner (Address is 32 bytes)
        1 + // executable
        8 // rent_epoch
    }

    /// Calculate rent for this account
    pub fn rent_amount(&self, celers_per_byte_year: u64) -> u64 {
        let size = self.size() as u64;
        size * celers_per_byte_year / 365 / 24 / 60 / 60 // per second
    }

    /// Check if account is rent exempt
    pub fn is_rent_exempt(&self, celers_per_byte_year: u64, min_balance_ratio: u64) -> bool {
        let min_balance = self.size() as u64 * celers_per_byte_year * min_balance_ratio;
        self.celers >= min_balance
    }
}

impl Default for Account {
    fn default() -> Self {
        Account {
            celers: 0,
            data: Vec::new(),
            owner: Address::zero(),
            executable: false,
            rent_epoch: 0,
            is_signer: false,
            is_writable: false,
        }
    }
}

/// System program ID (all zeros)
pub const SYSTEM_PROGRAM_ID: Address = Address([0u8; 32]);

/// Native token program ID
pub const TOKEN_PROGRAM_ID: Address = Address([1u8; 32]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_creation() {
        let account = Account::new(1000, Address::zero());
        assert_eq!(account.celers, 1000);
        assert!(account.data.is_empty());
        assert!(!account.executable);
    }

    #[test]
    fn test_account_size() {
        let account = Account::new_with_data(1000, vec![0u8; 100], Address::zero());
        let size = account.size();
        assert!(size > 100); // At least the data size
    }
}
