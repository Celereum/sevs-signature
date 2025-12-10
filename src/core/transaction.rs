//! Transaction types for Celereum blockchain
//!
//! # Post-Quantum Security
//! This module uses SEVS (Seed-Expanded Verkle Signatures) for transaction signing,
//! providing 128-bit post-quantum security with compact 128-byte signatures.
//!
//! ## Security Features
//! - All signatures use SEVS (quantum-safe)
//! - Constant-time signature verification
//! - Deterministic signing (no RNG during sign)
//! - Secret keys zeroized on drop

use serde::{Deserialize, Serialize};
use crate::crypto::{
    Hash,
    quantum_safe::{Address, TxSignature, QsSigner},
    sevs::SevsKeypair,
};

/// A signed transaction using SEVS signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// SEVS signatures for this transaction (includes pubkey and address)
    pub signatures: Vec<TxSignature>,

    /// The message containing instructions
    pub message: TransactionMessage,
}

/// The message part of a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMessage {
    /// Block hash for replay protection
    pub recent_blockhash: Hash,

    /// Account addresses involved in this transaction
    pub account_keys: Vec<Address>,

    /// Instructions to execute
    pub instructions: Vec<Instruction>,

    /// Header with signature requirements
    pub header: MessageHeader,
}

/// Message header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Number of required signatures
    pub num_required_signatures: u8,

    /// Number of readonly signed accounts
    pub num_readonly_signed_accounts: u8,

    /// Number of readonly unsigned accounts
    pub num_readonly_unsigned_accounts: u8,
}

/// A single instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// Program ID index in account_keys
    pub program_id_index: u8,

    /// Account indices involved in this instruction
    pub accounts: Vec<u8>,

    /// Instruction data
    pub data: Vec<u8>,
}

impl Default for Transaction {
    fn default() -> Self {
        Transaction {
            signatures: Vec::new(),
            message: TransactionMessage::default(),
        }
    }
}

impl Default for TransactionMessage {
    fn default() -> Self {
        TransactionMessage {
            recent_blockhash: Hash::zero(),
            account_keys: Vec::new(),
            instructions: Vec::new(),
            header: MessageHeader {
                num_required_signatures: 0,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
        }
    }
}

impl Transaction {
    /// Create a new transaction with SEVS signatures
    ///
    /// # Security
    /// - Uses SEVS for quantum-safe signatures
    /// - Deterministic signing (no RNG used during sign)
    pub fn new(message: TransactionMessage, signers: &[&SevsKeypair]) -> Self {
        let message_bytes = bincode::serialize(&message).unwrap();
        let signatures: Vec<TxSignature> = signers
            .iter()
            .map(|signer| signer.sign_tx(&message_bytes))
            .collect();

        Transaction { signatures, message }
    }

    /// Get the transaction hash (derived from first signature)
    pub fn hash(&self) -> Hash {
        if let Some(sig) = self.signatures.first() {
            Hash::hash(sig.signature.as_bytes())
        } else {
            Hash::zero()
        }
    }

    /// Verify all signatures (alias for verify)
    pub fn verify_signatures(&self) -> bool {
        self.verify()
    }

    /// Verify all SEVS signatures
    ///
    /// # Security
    /// - Uses constant-time signature verification
    /// - Validates signature count matches required
    /// - Validates account keys exist for all signers
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
            // Verify the cryptographic signature
            if !tx_sig.verify(&message_bytes) {
                return false;
            }

            // Verify the signer's address matches the account key
            if tx_sig.address() != &self.message.account_keys[i] {
                return false;
            }
        }

        true
    }

    /// Get the fee payer (first account address)
    pub fn fee_payer(&self) -> Option<&Address> {
        self.message.account_keys.first()
    }

    /// Calculate transaction size
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
        let message = TransactionMessage::new_transfer(
            recent_blockhash,
            signer.address(),
            to,
            celers,
        );
        Transaction::new(message, &[signer])
    }
}

impl TransactionMessage {
    /// Create a new message
    pub fn new(
        recent_blockhash: Hash,
        instructions: Vec<Instruction>,
        payer: Address,
    ) -> Self {
        // Collect all unique accounts
        let mut account_keys = vec![payer];

        for instruction in &instructions {
            for &account_idx in &instruction.accounts {
                // This is simplified - in reality we'd need proper account collection
                let _ = account_idx;
            }
        }

        TransactionMessage {
            recent_blockhash,
            account_keys,
            instructions,
            header: MessageHeader {
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
        let instruction = Instruction {
            program_id_index: 2, // System program
            accounts: vec![0, 1], // from, to
            data: celers.to_le_bytes().to_vec(),
        };

        TransactionMessage {
            recent_blockhash,
            account_keys: vec![from, to, Address::zero()], // from, to, system program
            instructions: vec![instruction],
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::quantum_safe::QsSigner;

    #[test]
    fn test_transaction_creation() {
        let payer = SevsKeypair::generate();
        let to = SevsKeypair::generate();

        let message = TransactionMessage::new_transfer(
            Hash::zero(),
            payer.address(),
            to.address(),
            1000,
        );

        let tx = Transaction::new(message, &[&payer]);
        assert_eq!(tx.signatures.len(), 1);
        assert!(tx.verify());
    }

    #[test]
    fn test_transaction_hash() {
        let payer = SevsKeypair::generate();
        let to = SevsKeypair::generate();

        let message = TransactionMessage::new_transfer(
            Hash::zero(),
            payer.address(),
            to.address(),
            1000,
        );

        let tx = Transaction::new(message, &[&payer]);
        let hash = tx.hash();
        assert_ne!(hash, Hash::zero());
    }

    #[test]
    fn test_invalid_signature_fails() {
        let payer = SevsKeypair::generate();
        let attacker = SevsKeypair::generate();
        let to = SevsKeypair::generate();

        // Create message with payer's address
        let message = TransactionMessage::new_transfer(
            Hash::zero(),
            payer.address(),
            to.address(),
            1000,
        );

        // Sign with attacker's key - should fail verification
        let tx = Transaction::new(message, &[&attacker]);
        assert!(!tx.verify()); // Address mismatch should fail
    }

    #[test]
    fn test_wrong_message_fails() {
        let payer = SevsKeypair::generate();
        let to = SevsKeypair::generate();

        let message = TransactionMessage::new_transfer(
            Hash::zero(),
            payer.address(),
            to.address(),
            1000,
        );

        let mut tx = Transaction::new(message, &[&payer]);

        // Modify the message after signing
        tx.message.account_keys[1] = Address::zero();

        // Verification should fail due to message tampering
        assert!(!tx.verify());
    }

    #[test]
    fn test_fee_payer() {
        let payer = SevsKeypair::generate();
        let to = SevsKeypair::generate();

        let tx = Transaction::new_transfer(
            &payer,
            to.address(),
            1000,
            Hash::zero(),
        );

        assert_eq!(tx.fee_payer(), Some(&payer.address()));
    }
}
