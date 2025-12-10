//! RPC request/response types

use serde::{Deserialize, Serialize};
use crate::crypto::Pubkey;
use crate::core::Slot;

/// Account information returned by RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAccountInfo {
    /// Account balance in celers
    pub celers: u64,
    /// Account data (base64 encoded)
    pub data: String,
    /// Owner program
    pub owner: String,
    /// Is executable
    pub executable: bool,
    /// Rent epoch
    pub rent_epoch: u64,
}

/// Block information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockInfo {
    /// Block hash
    pub blockhash: String,
    /// Previous block hash
    pub previous_blockhash: String,
    /// Parent slot
    pub parent_slot: Slot,
    /// Block time (unix timestamp)
    pub block_time: Option<i64>,
    /// Block height
    pub block_height: Option<u64>,
    /// Transactions in the block
    pub transactions: Vec<RpcTransactionInfo>,
}

/// Transaction information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransactionInfo {
    /// Transaction signature
    pub signature: String,
    /// Slot
    pub slot: Slot,
    /// Block time
    pub block_time: Option<i64>,
    /// Transaction status
    pub status: RpcTransactionStatus,
    /// Fee paid
    pub fee: u64,
}

/// Transaction status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransactionStatus {
    /// Success or error
    pub ok: Option<()>,
    /// Error message if failed
    pub err: Option<String>,
}

/// Slot info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcSlotInfo {
    /// Current slot
    pub slot: Slot,
    /// Parent slot
    pub parent: Slot,
    /// Root slot (finalized)
    pub root: Slot,
}

/// Epoch info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcEpochInfo {
    /// Current epoch
    pub epoch: u64,
    /// Slot index within epoch
    pub slot_index: u64,
    /// Slots in epoch
    pub slots_in_epoch: u64,
    /// Absolute slot
    pub absolute_slot: Slot,
    /// Block height
    pub block_height: u64,
    /// Transaction count
    pub transaction_count: Option<u64>,
}

/// Version info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcVersionInfo {
    /// Solana-compatible version
    #[serde(rename = "solana-core")]
    pub solana_core: String,
    /// Feature set
    #[serde(rename = "feature-set")]
    pub feature_set: u32,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcHealthStatus {
    #[serde(rename = "ok")]
    Ok,
    #[serde(rename = "behind")]
    Behind { num_slots: u64 },
    #[serde(rename = "unknown")]
    Unknown,
}

/// Send transaction config
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcSendTransactionConfig {
    /// Skip preflight checks
    #[serde(default)]
    pub skip_preflight: bool,
    /// Preflight commitment
    pub preflight_commitment: Option<String>,
    /// Encoding
    pub encoding: Option<String>,
    /// Max retries
    pub max_retries: Option<u64>,
}

/// Commitment level
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Commitment {
    /// Processed (not finalized)
    Processed,
    /// Confirmed (supermajority)
    #[default]
    Confirmed,
    /// Finalized (rooted)
    Finalized,
}

/// Generic RPC config with commitment
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcConfig {
    /// Commitment level
    pub commitment: Option<Commitment>,
    /// Encoding
    pub encoding: Option<String>,
}

/// Signature status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcSignatureStatus {
    /// Slot the transaction was processed
    pub slot: Slot,
    /// Number of confirmations
    pub confirmations: Option<u64>,
    /// Error if any
    pub err: Option<String>,
    /// Confirmation status
    pub confirmation_status: Option<String>,
}

/// Recent blockhash response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockhash {
    /// Blockhash
    pub blockhash: String,
    /// Last valid block height
    pub last_valid_block_height: u64,
}

/// Supply info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcSupply {
    /// Total supply
    pub total: u64,
    /// Circulating supply
    pub circulating: u64,
    /// Non-circulating supply
    pub non_circulating: u64,
    /// Non-circulating accounts
    pub non_circulating_accounts: Vec<String>,
}

/// Network statistics for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcNetworkStats {
    /// Current TPS (transactions per second)
    pub tps: u64,
    /// Block height
    pub block_height: u64,
    /// Slot height
    pub slot_height: u64,
    /// Number of active validators
    pub validators: u64,
    /// Number of active accounts
    pub active_accounts: u64,
    /// Total transactions processed
    pub total_transactions: u64,
    /// Average block time in milliseconds
    pub avg_block_time_ms: u64,
    /// Current epoch
    pub epoch: u64,
    /// Total staked amount in celers
    pub total_stake: u64,
    /// Network version
    pub version: String,
}

/// Validator info for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcValidatorInfo {
    /// Validator pubkey
    pub pubkey: String,
    /// Validator name/identity
    pub name: String,
    /// Stake amount in celers
    pub stake: u64,
    /// Commission percentage
    pub commission: u8,
    /// Validator status
    pub status: String,
    /// Skip rate percentage
    pub skip_rate: f64,
    /// Blocks produced
    pub blocks_produced: u64,
    /// Uptime percentage
    pub uptime: f64,
}

/// Recent block info for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcRecentBlock {
    /// Slot number
    pub slot: u64,
    /// Block hash
    pub hash: String,
    /// Number of transactions
    pub tx_count: u64,
    /// Block timestamp
    pub timestamp: i64,
    /// Leader validator
    pub leader: String,
}

/// Performance sample for TPS calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcPerformanceSample {
    /// Slot
    pub slot: u64,
    /// Number of transactions
    pub num_transactions: u64,
    /// Number of slots
    pub num_slots: u64,
    /// Sample period in seconds
    pub sample_period_secs: u64,
}

/// Simple transfer request for wallet integration
/// Uses SEVS post-quantum signatures (128 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransferRequest {
    /// Sender's address (base58, 32 bytes - SHA3-256 of public key)
    pub from: String,
    /// Recipient's address (base58, 32 bytes)
    pub to: String,
    /// Amount in celers (1 CEL = 1_000_000_000 celers)
    pub amount: u64,
    /// SEVS signature of: from_address + to_address + amount (base58, 128 bytes)
    pub signature: String,
    /// Sender's SEVS public key for verification (base58, 64 bytes)
    #[serde(default)]
    pub public_key: Option<String>,
}

/// Transfer response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransferResponse {
    /// Transaction signature/hash
    pub signature: String,
    /// Slot number
    pub slot: u64,
}

/// Validator registration request (testnet)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcRegisterValidatorRequest {
    /// Validator's public key (base58)
    pub pubkey: String,
    /// Validator name/identity
    pub name: String,
    /// Stake amount in celers (minimum 1000 CEL for testnet)
    pub stake: u64,
    /// Commission percentage (0-100)
    pub commission: u8,
}

/// Validator registration response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcRegisterValidatorResponse {
    /// Success message
    pub message: String,
    /// Validator pubkey
    pub pubkey: String,
}

/// Config for getSignaturesForAddress
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcSignaturesConfig {
    /// Maximum number of results to return
    pub limit: Option<usize>,
}

/// Signature info returned by getSignaturesForAddress
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcSignatureInfo {
    /// Transaction signature
    pub signature: String,
    /// Slot number
    pub slot: u64,
    /// Block time (Unix timestamp)
    pub block_time: Option<i64>,
    /// Transaction type: transfer, airdrop, etc.
    #[serde(rename = "type")]
    pub tx_type: String,
    /// Amount in celers
    pub amount: u64,
    /// Sender address
    pub from: String,
    /// Recipient address
    pub to: String,
    /// Transaction status
    pub status: String,
}
