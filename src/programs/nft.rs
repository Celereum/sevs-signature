//! CEL-721 NFT Standard for Celereum blockchain
//!
//! Non-Fungible Token implementation similar to Metaplex on Solana
//!
//! Features:
//! - NFT minting with metadata
//! - Collections
//! - Royalties
//! - Burning
//! - Transfers
//! - Editions

use crate::crypto::Pubkey;
use crate::core::Account;
use serde::{Deserialize, Serialize};

/// NFT Program ID
pub const NFT_PROGRAM_ID: Pubkey = Pubkey([
    0x4e, 0x46, 0x54, 0x50, 0x72, 0x6f, 0x67, 0x72,
    0x61, 0x6d, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
]);

/// Maximum creators per NFT
pub const MAX_CREATORS: usize = 5;

/// Maximum royalty percentage (10%)
pub const MAX_ROYALTY_BPS: u16 = 1000;

/// NFT Metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metadata {
    /// Update authority (can update metadata)
    pub update_authority: Pubkey,
    /// NFT mint address
    pub mint: Pubkey,
    /// NFT name
    pub name: String,
    /// NFT symbol
    pub symbol: String,
    /// URI to off-chain metadata (JSON)
    pub uri: String,
    /// Royalty percentage in basis points (100 = 1%)
    pub seller_fee_basis_points: u16,
    /// Creators with their share
    pub creators: Vec<Creator>,
    /// Is the metadata mutable?
    pub is_mutable: bool,
    /// Primary sale happened (affects royalty distribution)
    pub primary_sale_happened: bool,
    /// Collection this NFT belongs to
    pub collection: Option<Collection>,
    /// Edition information
    pub edition: Option<Edition>,
    /// Is this metadata initialized?
    pub is_initialized: bool,
}

impl Metadata {
    pub const LEN: usize = 512; // Fixed size for account data

    /// Create new metadata
    pub fn new(
        update_authority: Pubkey,
        mint: Pubkey,
        name: String,
        symbol: String,
        uri: String,
        seller_fee_basis_points: u16,
        creators: Vec<Creator>,
        is_mutable: bool,
    ) -> Self {
        Self {
            update_authority,
            mint,
            name,
            symbol,
            uri,
            seller_fee_basis_points,
            creators,
            is_mutable,
            primary_sale_happened: false,
            collection: None,
            edition: None,
            is_initialized: true,
        }
    }

    /// Serialize to bytes
    pub fn pack(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn unpack(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }

    /// Calculate total royalty distribution
    pub fn calculate_royalty(&self, sale_price: u64) -> u64 {
        (sale_price as u128)
            .checked_mul(self.seller_fee_basis_points as u128)
            .and_then(|v| v.checked_div(10000))
            .unwrap_or(0) as u64
    }

    /// Get creator shares for royalty distribution
    pub fn get_creator_shares(&self, royalty_amount: u64) -> Vec<(Pubkey, u64)> {
        self.creators
            .iter()
            .filter(|c| c.verified)
            .map(|c| {
                let share = (royalty_amount as u128)
                    .checked_mul(c.share as u128)
                    .and_then(|v| v.checked_div(100))
                    .unwrap_or(0) as u64;
                (c.address, share)
            })
            .collect()
    }
}

/// Creator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Creator {
    /// Creator's address
    pub address: Pubkey,
    /// Is the creator verified?
    pub verified: bool,
    /// Share percentage (0-100)
    pub share: u8,
}

impl Creator {
    pub fn new(address: Pubkey, share: u8) -> Self {
        Self {
            address,
            verified: false,
            share,
        }
    }
}

/// Collection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    /// Collection NFT mint address
    pub key: Pubkey,
    /// Is this NFT verified as part of the collection?
    pub verified: bool,
}

/// Edition information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Edition {
    /// Master edition (original)
    MasterEdition {
        /// Maximum supply (None = unlimited)
        max_supply: Option<u64>,
        /// Current supply
        supply: u64,
    },
    /// Print edition (copy)
    PrintEdition {
        /// Parent master edition
        parent: Pubkey,
        /// Edition number
        edition: u64,
    },
}

/// NFT Collection Account
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectionAccount {
    /// Collection authority
    pub authority: Pubkey,
    /// Collection name
    pub name: String,
    /// Collection symbol
    pub symbol: String,
    /// Collection description
    pub description: String,
    /// Number of items in collection
    pub size: u64,
    /// Maximum size (None = unlimited)
    pub max_size: Option<u64>,
    /// Is verified collection?
    pub verified: bool,
    /// Is initialized?
    pub is_initialized: bool,
}

impl CollectionAccount {
    pub const LEN: usize = 256;

    /// Serialize to bytes
    pub fn pack(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn unpack(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}

/// NFT Program instructions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NftInstruction {
    /// Create metadata for an NFT
    /// Accounts: [metadata, mint, mint_authority, payer, update_authority]
    CreateMetadata {
        name: String,
        symbol: String,
        uri: String,
        seller_fee_basis_points: u16,
        creators: Vec<Creator>,
        is_mutable: bool,
    },

    /// Update metadata
    /// Accounts: [metadata, update_authority]
    UpdateMetadata {
        name: Option<String>,
        symbol: Option<String>,
        uri: Option<String>,
        seller_fee_basis_points: Option<u16>,
        creators: Option<Vec<Creator>>,
        primary_sale_happened: Option<bool>,
        is_mutable: Option<bool>,
    },

    /// Create master edition
    /// Accounts: [edition, mint, update_authority, mint_authority, payer, metadata]
    CreateMasterEdition {
        max_supply: Option<u64>,
    },

    /// Mint print edition from master
    /// Accounts: [print_edition, master_edition, print_metadata, master_metadata, mint, mint_authority, payer]
    MintPrintEdition,

    /// Verify creator
    /// Accounts: [metadata, creator]
    VerifyCreator,

    /// Unverify creator
    /// Accounts: [metadata, creator]
    UnverifyCreator,

    /// Create collection
    /// Accounts: [collection, authority, payer]
    CreateCollection {
        name: String,
        symbol: String,
        description: String,
        max_size: Option<u64>,
    },

    /// Set and verify collection
    /// Accounts: [metadata, collection_authority, collection]
    SetAndVerifyCollection,

    /// Unverify collection
    /// Accounts: [metadata, collection_authority, collection]
    UnverifyCollection,

    /// Burn NFT
    /// Accounts: [metadata, owner, mint, token_account]
    Burn,

    /// Transfer NFT (with royalty)
    /// Accounts: [source, destination, owner, metadata, mint, ...creators]
    TransferWithRoyalty {
        sale_price: u64,
    },

    /// Update authority
    /// Accounts: [metadata, current_authority]
    SetUpdateAuthority {
        new_authority: Pubkey,
    },
}

impl NftInstruction {
    /// Serialize instruction to bytes
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize instruction from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}

/// NFT Program implementation
pub struct NftProgram;

impl NftProgram {
    /// Process an NFT instruction
    pub fn process(
        instruction: &NftInstruction,
        accounts: &mut [Account],
    ) -> Result<(), NftError> {
        match instruction {
            NftInstruction::CreateMetadata {
                name,
                symbol,
                uri,
                seller_fee_basis_points,
                creators,
                is_mutable,
            } => Self::process_create_metadata(
                accounts,
                name.clone(),
                symbol.clone(),
                uri.clone(),
                *seller_fee_basis_points,
                creators.clone(),
                *is_mutable,
            ),
            NftInstruction::UpdateMetadata {
                name,
                symbol,
                uri,
                seller_fee_basis_points,
                creators,
                primary_sale_happened,
                is_mutable,
            } => Self::process_update_metadata(
                accounts,
                name.clone(),
                symbol.clone(),
                uri.clone(),
                *seller_fee_basis_points,
                creators.clone(),
                *primary_sale_happened,
                *is_mutable,
            ),
            NftInstruction::CreateMasterEdition { max_supply } => {
                Self::process_create_master_edition(accounts, *max_supply)
            }
            NftInstruction::VerifyCreator => Self::process_verify_creator(accounts),
            NftInstruction::CreateCollection { name, symbol, description, max_size } => {
                Self::process_create_collection(accounts, name.clone(), symbol.clone(), description.clone(), *max_size)
            }
            NftInstruction::Burn => Self::process_burn(accounts),
            _ => Err(NftError::InvalidInstruction),
        }
    }

    fn process_create_metadata(
        accounts: &mut [Account],
        name: String,
        symbol: String,
        uri: String,
        seller_fee_basis_points: u16,
        creators: Vec<Creator>,
        is_mutable: bool,
    ) -> Result<(), NftError> {
        if accounts.len() < 5 {
            return Err(NftError::NotEnoughAccounts);
        }

        // Validate inputs
        if name.len() > 32 {
            return Err(NftError::NameTooLong);
        }
        if symbol.len() > 10 {
            return Err(NftError::SymbolTooLong);
        }
        if uri.len() > 200 {
            return Err(NftError::UriTooLong);
        }
        if seller_fee_basis_points > MAX_ROYALTY_BPS {
            return Err(NftError::InvalidRoyalty);
        }
        if creators.len() > MAX_CREATORS {
            return Err(NftError::TooManyCreators);
        }

        // Validate creator shares sum to 100
        let total_share: u8 = creators.iter().map(|c| c.share).sum();
        if total_share != 100 {
            return Err(NftError::InvalidCreatorShares);
        }

        let metadata_account = &mut accounts[0];

        // Check not already initialized
        if !metadata_account.data.is_empty() {
            if let Some(existing) = Metadata::unpack(&metadata_account.data) {
                if existing.is_initialized {
                    return Err(NftError::AlreadyInitialized);
                }
            }
        }

        // Create metadata (simplified)
        let metadata = Metadata::new(
            Pubkey::zero(), // Would be accounts[4] pubkey
            Pubkey::zero(), // Would be accounts[1] pubkey
            name,
            symbol,
            uri,
            seller_fee_basis_points,
            creators,
            is_mutable,
        );

        metadata_account.data = metadata.pack();
        metadata_account.owner = NFT_PROGRAM_ID;

        Ok(())
    }

    fn process_update_metadata(
        accounts: &mut [Account],
        name: Option<String>,
        symbol: Option<String>,
        uri: Option<String>,
        seller_fee_basis_points: Option<u16>,
        creators: Option<Vec<Creator>>,
        primary_sale_happened: Option<bool>,
        is_mutable: Option<bool>,
    ) -> Result<(), NftError> {
        if accounts.len() < 2 {
            return Err(NftError::NotEnoughAccounts);
        }

        let metadata_data = accounts[0].data.clone();
        let mut metadata = Metadata::unpack(&metadata_data).ok_or(NftError::InvalidMetadata)?;

        if !metadata.is_initialized {
            return Err(NftError::UninitializedMetadata);
        }

        if !metadata.is_mutable {
            return Err(NftError::ImmutableMetadata);
        }

        // Update fields
        if let Some(name) = name {
            if name.len() > 32 {
                return Err(NftError::NameTooLong);
            }
            metadata.name = name;
        }
        if let Some(symbol) = symbol {
            if symbol.len() > 10 {
                return Err(NftError::SymbolTooLong);
            }
            metadata.symbol = symbol;
        }
        if let Some(uri) = uri {
            if uri.len() > 200 {
                return Err(NftError::UriTooLong);
            }
            metadata.uri = uri;
        }
        if let Some(fee) = seller_fee_basis_points {
            if fee > MAX_ROYALTY_BPS {
                return Err(NftError::InvalidRoyalty);
            }
            metadata.seller_fee_basis_points = fee;
        }
        if let Some(creators) = creators {
            if creators.len() > MAX_CREATORS {
                return Err(NftError::TooManyCreators);
            }
            let total_share: u8 = creators.iter().map(|c| c.share).sum();
            if total_share != 100 {
                return Err(NftError::InvalidCreatorShares);
            }
            metadata.creators = creators;
        }
        if let Some(sold) = primary_sale_happened {
            metadata.primary_sale_happened = sold;
        }
        if let Some(mutable) = is_mutable {
            metadata.is_mutable = mutable;
        }

        accounts[0].data = metadata.pack();

        Ok(())
    }

    fn process_create_master_edition(
        accounts: &mut [Account],
        max_supply: Option<u64>,
    ) -> Result<(), NftError> {
        if accounts.len() < 6 {
            return Err(NftError::NotEnoughAccounts);
        }

        // Get metadata
        let metadata_data = accounts[5].data.clone();
        let mut metadata = Metadata::unpack(&metadata_data).ok_or(NftError::InvalidMetadata)?;

        // Create master edition
        metadata.edition = Some(Edition::MasterEdition {
            max_supply,
            supply: 0,
        });

        accounts[5].data = metadata.pack();

        Ok(())
    }

    fn process_verify_creator(accounts: &mut [Account]) -> Result<(), NftError> {
        // SECURITY FIX: Require metadata account and creator signer account
        if accounts.len() < 2 {
            return Err(NftError::NotEnoughAccounts);
        }

        let metadata_data = accounts[0].data.clone();
        let mut metadata = Metadata::unpack(&metadata_data).ok_or(NftError::InvalidMetadata)?;

        if !metadata.is_initialized {
            return Err(NftError::UninitializedMetadata);
        }

        // SECURITY FIX: The creator account (accounts[1]) MUST be a signer
        // This ensures only the actual creator can verify themselves
        let creator_account = &accounts[1];

        // SECURITY: Verify the account is a signer (has authority)
        if !creator_account.is_signer {
            return Err(NftError::Unauthorized);
        }

        // Get the creator's pubkey from the signer account
        let creator_pubkey = creator_account.owner;

        // SECURITY FIX: Find and verify only the creator who signed the transaction
        let mut found_and_verified = false;
        for creator in &mut metadata.creators {
            if creator.address == creator_pubkey {
                if creator.verified {
                    // Already verified, not an error but no action needed
                    return Ok(());
                }
                creator.verified = true;
                found_and_verified = true;
                break;
            }
        }

        if !found_and_verified {
            // The signer is not in the creators list
            return Err(NftError::Unauthorized);
        }

        accounts[0].data = metadata.pack();

        Ok(())
    }

    fn process_create_collection(
        accounts: &mut [Account],
        name: String,
        symbol: String,
        description: String,
        max_size: Option<u64>,
    ) -> Result<(), NftError> {
        if accounts.len() < 3 {
            return Err(NftError::NotEnoughAccounts);
        }

        let collection_account = &mut accounts[0];

        let collection = CollectionAccount {
            authority: Pubkey::zero(), // Would be accounts[1] pubkey
            name,
            symbol,
            description,
            size: 0,
            max_size,
            verified: true,
            is_initialized: true,
        };

        collection_account.data = collection.pack();
        collection_account.owner = NFT_PROGRAM_ID;

        Ok(())
    }

    fn process_burn(accounts: &mut [Account]) -> Result<(), NftError> {
        if accounts.len() < 4 {
            return Err(NftError::NotEnoughAccounts);
        }

        // Clear metadata
        accounts[0].data.clear();
        accounts[0].celers = 0;

        Ok(())
    }
}

/// NFT program errors
#[derive(Debug, Clone, PartialEq)]
pub enum NftError {
    NotEnoughAccounts,
    InvalidInstruction,
    AlreadyInitialized,
    UninitializedMetadata,
    InvalidMetadata,
    ImmutableMetadata,
    NameTooLong,
    SymbolTooLong,
    UriTooLong,
    InvalidRoyalty,
    TooManyCreators,
    InvalidCreatorShares,
    Unauthorized,
    InvalidCollection,
    CollectionFull,
}

impl std::fmt::Display for NftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for NftError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_creation() {
        let authority = Pubkey::new([1u8; 32]);
        let mint = Pubkey::new([2u8; 32]);

        let creators = vec![
            Creator::new(authority, 100),
        ];

        let metadata = Metadata::new(
            authority,
            mint,
            "Test NFT".to_string(),
            "TEST".to_string(),
            "https://example.com/nft.json".to_string(),
            500, // 5% royalty
            creators,
            true,
        );

        assert_eq!(metadata.name, "Test NFT");
        assert_eq!(metadata.seller_fee_basis_points, 500);
        assert!(metadata.is_initialized);
    }

    #[test]
    fn test_royalty_calculation() {
        let authority = Pubkey::new([1u8; 32]);
        let creators = vec![
            Creator { address: authority, verified: true, share: 100 },
        ];

        let mut metadata = Metadata::default();
        metadata.seller_fee_basis_points = 500; // 5%
        metadata.creators = creators;

        let royalty = metadata.calculate_royalty(1000);
        assert_eq!(royalty, 50); // 5% of 1000

        let royalty2 = metadata.calculate_royalty(10000);
        assert_eq!(royalty2, 500); // 5% of 10000
    }

    #[test]
    fn test_creator_shares() {
        let creator1 = Pubkey::new([1u8; 32]);
        let creator2 = Pubkey::new([2u8; 32]);

        let creators = vec![
            Creator { address: creator1, verified: true, share: 60 },
            Creator { address: creator2, verified: true, share: 40 },
        ];

        let mut metadata = Metadata::default();
        metadata.seller_fee_basis_points = 1000; // 10%
        metadata.creators = creators;

        let royalty = metadata.calculate_royalty(1000);
        assert_eq!(royalty, 100); // 10% of 1000

        let shares = metadata.get_creator_shares(royalty);
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].1, 60); // 60% of 100
        assert_eq!(shares[1].1, 40); // 40% of 100
    }

    #[test]
    fn test_pack_unpack() {
        let authority = Pubkey::new([1u8; 32]);
        let metadata = Metadata::new(
            authority,
            authority,
            "Test".to_string(),
            "TST".to_string(),
            "uri".to_string(),
            100,
            vec![Creator::new(authority, 100)],
            true,
        );

        let packed = metadata.pack();
        let unpacked = Metadata::unpack(&packed).unwrap();

        assert_eq!(metadata.name, unpacked.name);
        assert_eq!(metadata.symbol, unpacked.symbol);
        assert_eq!(metadata.seller_fee_basis_points, unpacked.seller_fee_basis_points);
    }
}
