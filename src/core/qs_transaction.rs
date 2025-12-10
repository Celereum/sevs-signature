//! Quantum-Safe Transaction types for Celereum blockchain
//!
//! This module provides post-quantum secure transactions using SEVS signatures.
//!
//! # Security Features
//! - 128-bit post-quantum security (SEVS)
//! - Constant-time signature verification
//! - Replay protection via recent blockhash
//! - Multi-signature support
//!
//! # Transaction Structure
//! ```text
//! QsTransaction {
//!     signatures: Vec<TxSignature>  // SEVS signatures (224 bytes each)
//!     message: QsTransactionMessage // The actual transaction data
//! }
//! ```

use serde::{Deserialize, Serialize};
use crate::crypto::{
    Hash,
    quantum_safe::{Address, TxSignature, QsSigner},
    sevs::{SevsKeypair, SevsSignature, SevsPubkey},
};

// =============================================================================
// QUANTUM-SAFE TRANSACTION
// =============================================================================

/// A quantum-safe signed transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QsTransaction {
    /// Signatures for this transaction (SEVS, 224 bytes each including pubkey)
    pub signatures: Vec<TxSignature>,

    /// The message containing instructions
    pub message: QsTransactionMessage,
}

/// The message part of a quantum-safe transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QsTransactionMessage {
    /// Block hash for replay protection
    pub recent_blockhash: Hash,

    /// Account addresses involved in this transaction (32 bytes each)
    pub account_keys: Vec<Address>,

    /// Instructions to execute
    pub instructions: Vec<QsInstruction>,

    /// Header with signature requirements
    pub header: QsMessageHeader,
}

/// Message header for quantum-safe transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QsMessageHeader {
    /// Number of required signatures
    pub num_required_signatures: u8,

    /// Number of readonly signed accounts
    pub num_readonly_signed_accounts: u8,

    /// Number of readonly unsigned accounts
    pub num_readonly_unsigned_accounts: u8,
}

/// A single instruction in a quantum-safe transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QsInstruction {
    /// Program ID index in account_keys
    pub program_id_index: u8,

    /// Account indices involved in this instruction
    pub accounts: Vec<u8>,

    /// Instruction data
    pub data: Vec<u8>,
}

// =============================================================================
// TRANSACTION IMPLEMENTATION
// =============================================================================

impl Default for QsTransaction {
    fn default() -> Self {
        QsTransaction {
            signatures: Vec::new(),
            message: QsTransactionMessage::default(),
        }
    }
}

impl Default for QsTransactionMessage {
    fn default() -> Self {
        QsTransactionMessage {
            recent_blockhash: Hash::zero(),
            account_keys: Vec::new(),
            instructions: Vec::new(),
            header: QsMessageHeader {
                num_required_signatures: 0,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
        }
    }
}

impl QsTransaction {
    /// Create a new transaction with SEVS signatures
    pub fn new(message: QsTransactionMessage, signers: &[&SevsKeypair]) -> Self {
        let message_bytes = match bincode::serialize(&message) {
            Ok(bytes) => bytes,
            Err(_) => return Self::default(),
        };

        let signatures: Vec<TxSignature> = signers
            .iter()
            .map(|signer| signer.sign_tx(&message_bytes))
            .collect();

        QsTransaction { signatures, message }
    }

    /// Create a new transaction from a single signer
    pub fn new_signed(message: QsTransactionMessage, signer: &SevsKeypair) -> Self {
        Self::new(message, &[signer])
    }

    /// Get the transaction hash (derived from first signature)
    pub fn hash(&self) -> Hash {
        if let Some(sig) = self.signatures.first() {
            Hash::hash(sig.signature.as_bytes())
        } else {
            Hash::zero()
        }
    }

    /// Verify all signatures
    ///
    /// # Security
    /// - Verifies each signature against the serialized message
    /// - Uses constant-time comparison internally
    /// - Fails fast on any invalid signature
    pub fn verify(&self) -> bool {
        let message_bytes = match bincode::serialize(&self.message) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let num_signers = self.message.header.num_required_signatures as usize;

        // Check signature count
        if self.signatures.len() != num_signers {
            return false;
        }

        // Check we have enough account keys
        if self.message.account_keys.len() < num_signers {
            return false;
        }

        // Verify each signature
        for (i, tx_sig) in self.signatures.iter().enumerate() {
            // Verify the signature
            if !tx_sig.verify(&message_bytes) {
                return false;
            }

            // Verify the address matches the account key
            if tx_sig.address() != &self.message.account_keys[i] {
                return false;
            }
        }

        true
    }

    /// Alias for verify()
    pub fn verify_signatures(&self) -> bool {
        self.verify()
    }

    /// Get the fee payer address (first account)
    pub fn fee_payer(&self) -> Option<&Address> {
        self.message.account_keys.first()
    }

    /// Calculate transaction size in bytes
    pub fn size(&self) -> usize {
        bincode::serialized_size(self).unwrap_or(0) as usize
    }

    /// Create a simple transfer transaction
    pub fn new_transfer(
        signer: &SevsKeypair,
        to: Address,
        celers: u64,
        recent_blockhash: Hash,
    ) -> Self {
        let from = signer.address();
        let message = QsTransactionMessage::new_transfer(
            recent_blockhash,
            from,
            to,
            celers,
        );
        QsTransaction::new_signed(message, signer)
    }

    /// Get all signer addresses
    pub fn signers(&self) -> Vec<&Address> {
        self.signatures.iter().map(|s| s.address()).collect()
    }

    /// Get all signer public keys
    pub fn signer_pubkeys(&self) -> Vec<&SevsPubkey> {
        self.signatures.iter().map(|s| &s.pubkey).collect()
    }
}

// =============================================================================
// MESSAGE IMPLEMENTATION
// =============================================================================

impl QsTransactionMessage {
    /// Create a new message
    pub fn new(
        recent_blockhash: Hash,
        instructions: Vec<QsInstruction>,
        payer: Address,
    ) -> Self {
        let account_keys = vec![payer];

        QsTransactionMessage {
            recent_blockhash,
            account_keys,
            instructions,
            header: QsMessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
        }
    }

    /// Create a simple transfer message
    pub fn new_transfer(
        recent_blockhash: Hash,
        from: Address,
        to: Address,
        celers: u64,
    ) -> Self {
        let instruction = QsInstruction {
            program_id_index: 2, // System program
            accounts: vec![0, 1], // from, to
            data: celers.to_le_bytes().to_vec(),
        };

        QsTransactionMessage {
            recent_blockhash,
            account_keys: vec![from, to, Address::zero()], // from, to, system program
            instructions: vec![instruction],
            header: QsMessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
        }
    }

    /// Add an account key
    pub fn add_account(&mut self, account: Address) -> u8 {
        let index = self.account_keys.len() as u8;
        self.account_keys.push(account);
        index
    }

    /// Add an instruction
    pub fn add_instruction(&mut self, instruction: QsInstruction) {
        self.instructions.push(instruction);
    }
}

// =============================================================================
// INSTRUCTION BUILDER
// =============================================================================

impl QsInstruction {
    /// Create a new instruction
    pub fn new(program_id_index: u8, accounts: Vec<u8>, data: Vec<u8>) -> Self {
        Self {
            program_id_index,
            accounts,
            data,
        }
    }

    /// Create a system program transfer instruction
    pub fn transfer(from_index: u8, to_index: u8, amount: u64) -> Self {
        Self {
            program_id_index: 0, // System program is always index 0
            accounts: vec![from_index, to_index],
            data: amount.to_le_bytes().to_vec(),
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::quantum_safe::QsSigner;

    #[test]
    fn test_qs_transaction_creation() {
        let payer = SevsKeypair::generate();
        let recipient = SevsKeypair::generate();

        let tx = QsTransaction::new_transfer(
            &payer,
            recipient.address(),
            1000,
            Hash::zero(),
        );

        assert_eq!(tx.signatures.len(), 1);
        assert!(tx.verify());
    }

    #[test]
    fn test_qs_transaction_hash() {
        let payer = SevsKeypair::generate();
        let recipient = SevsKeypair::generate();

        let tx = QsTransaction::new_transfer(
            &payer,
            recipient.address(),
            1000,
            Hash::zero(),
        );

        let hash = tx.hash();
        assert_ne!(hash, Hash::zero());
    }

    #[test]
    fn test_qs_transaction_fee_payer() {
        let payer = SevsKeypair::generate();
        let recipient = SevsKeypair::generate();

        let tx = QsTransaction::new_transfer(
            &payer,
            recipient.address(),
            1000,
            Hash::zero(),
        );

        let fee_payer = tx.fee_payer().expect("Should have fee payer");
        assert_eq!(fee_payer, &payer.address());
    }

    #[test]
    fn test_qs_transaction_different_blockhash() {
        let payer = SevsKeypair::generate();
        let recipient = SevsKeypair::generate();

        let tx1 = QsTransaction::new_transfer(
            &payer,
            recipient.address(),
            1000,
            Hash::zero(),
        );

        let tx2 = QsTransaction::new_transfer(
            &payer,
            recipient.address(),
            1000,
            Hash::hash(b"different"),
        );

        // Different blockhash = different signature
        assert_ne!(tx1.signatures[0].signature.as_bytes(),
                   tx2.signatures[0].signature.as_bytes());
    }

    #[test]
    fn test_qs_transaction_size() {
        let payer = SevsKeypair::generate();
        let recipient = SevsKeypair::generate();

        let tx = QsTransaction::new_transfer(
            &payer,
            recipient.address(),
            1000,
            Hash::zero(),
        );

        let size = tx.size();
        // Transaction should be reasonable size
        assert!(size > 200); // At least signature + pubkey + message
        assert!(size < 1000); // Not too large for simple transfer

        println!("QsTransaction size: {} bytes", size);
    }

    #[test]
    fn test_qs_multi_sig() {
        let signer1 = SevsKeypair::generate();
        let signer2 = SevsKeypair::generate();

        let mut message = QsTransactionMessage {
            recent_blockhash: Hash::zero(),
            account_keys: vec![signer1.address(), signer2.address(), Address::zero()],
            instructions: vec![QsInstruction::transfer(0, 2, 1000)],
            header: QsMessageHeader {
                num_required_signatures: 2,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
        };

        let tx = QsTransaction::new(message, &[&signer1, &signer2]);

        assert_eq!(tx.signatures.len(), 2);
        assert!(tx.verify());
    }

    #[test]
    fn test_qs_wrong_signer_fails() {
        let real_signer = SevsKeypair::generate();
        let wrong_signer = SevsKeypair::generate();
        let recipient = SevsKeypair::generate();

        // Create message for real_signer
        let message = QsTransactionMessage::new_transfer(
            Hash::zero(),
            real_signer.address(),  // Message expects real_signer
            recipient.address(),
            1000,
        );

        // But sign with wrong_signer
        let tx = QsTransaction::new_signed(message, &wrong_signer);

        // Verification should fail because address doesn't match
        assert!(!tx.verify());
    }
}
