//! RPC method implementations

use std::sync::Arc;
use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{ErrorCode, ErrorObject};

use crate::storage::Storage;
use crate::crypto::Pubkey;
use crate::core::Slot;
use crate::programs::vesting::TOTAL_SUPPLY;
use crate::{CELEREUM_VERSION, SLOTS_PER_EPOCH, CELERS_PER_CEL};
use super::types::*;

/// Celereum RPC API trait
#[rpc(server)]
pub trait CelereumRpc {
    /// Get account balance
    #[method(name = "getBalance")]
    async fn get_balance(&self, pubkey: String, config: Option<RpcConfig>) -> RpcResult<u64>;

    /// Get account info
    #[method(name = "getAccountInfo")]
    async fn get_account_info(&self, pubkey: String, config: Option<RpcConfig>) -> RpcResult<Option<RpcAccountInfo>>;

    /// Get recent blockhash
    #[method(name = "getRecentBlockhash")]
    async fn get_recent_blockhash(&self, config: Option<RpcConfig>) -> RpcResult<RpcBlockhash>;

    /// Get latest blockhash
    #[method(name = "getLatestBlockhash")]
    async fn get_latest_blockhash(&self, config: Option<RpcConfig>) -> RpcResult<RpcBlockhash>;

    /// Get slot
    #[method(name = "getSlot")]
    async fn get_slot(&self, config: Option<RpcConfig>) -> RpcResult<Slot>;

    /// Get block height
    #[method(name = "getBlockHeight")]
    async fn get_block_height(&self, config: Option<RpcConfig>) -> RpcResult<u64>;

    /// Get epoch info
    #[method(name = "getEpochInfo")]
    async fn get_epoch_info(&self, config: Option<RpcConfig>) -> RpcResult<RpcEpochInfo>;

    /// Get version
    #[method(name = "getVersion")]
    async fn get_version(&self) -> RpcResult<RpcVersionInfo>;

    /// Get health
    #[method(name = "getHealth")]
    async fn get_health(&self) -> RpcResult<String>;

    /// Send transaction
    #[method(name = "sendTransaction")]
    async fn send_transaction(&self, data: String, config: Option<RpcSendTransactionConfig>) -> RpcResult<String>;

    /// Get transaction
    #[method(name = "getTransaction")]
    async fn get_transaction(&self, signature: String, config: Option<RpcConfig>) -> RpcResult<Option<RpcTransactionInfo>>;

    /// Get signature statuses
    #[method(name = "getSignatureStatuses")]
    async fn get_signature_statuses(&self, signatures: Vec<String>, config: Option<RpcConfig>) -> RpcResult<Vec<Option<RpcSignatureStatus>>>;

    /// Get block
    #[method(name = "getBlock")]
    async fn get_block(&self, slot: Slot, config: Option<RpcConfig>) -> RpcResult<Option<RpcBlockInfo>>;

    /// Get supply
    #[method(name = "getSupply")]
    async fn get_supply(&self, config: Option<RpcConfig>) -> RpcResult<RpcSupply>;

    /// Request airdrop (testnet only)
    #[method(name = "requestAirdrop")]
    async fn request_airdrop(&self, pubkey: String, celers: u64, config: Option<RpcConfig>) -> RpcResult<String>;

    /// Get minimum balance for rent exemption
    #[method(name = "getMinimumBalanceForRentExemption")]
    async fn get_minimum_balance_for_rent_exemption(&self, data_len: usize, config: Option<RpcConfig>) -> RpcResult<u64>;

    // ========== Dashboard/Stats APIs ==========

    /// Get network statistics for dashboard
    #[method(name = "getNetworkStats")]
    async fn get_network_stats(&self) -> RpcResult<RpcNetworkStats>;

    /// Get validator list
    #[method(name = "getValidators")]
    async fn get_validators(&self) -> RpcResult<Vec<RpcValidatorInfo>>;

    /// Get recent blocks
    #[method(name = "getRecentBlocks")]
    async fn get_recent_blocks(&self, limit: Option<u64>) -> RpcResult<Vec<RpcRecentBlock>>;

    /// Get performance samples (for TPS calculation)
    #[method(name = "getRecentPerformanceSamples")]
    async fn get_recent_performance_samples(&self, limit: Option<u64>) -> RpcResult<Vec<RpcPerformanceSample>>;

    // ========== Wallet APIs (Testnet) ==========

    /// Transfer CEL with SEVS post-quantum signature
    /// SEVS signatures are 128 bytes, providing 128-bit quantum security
    #[method(name = "transfer")]
    async fn transfer(&self, request: RpcTransferRequest) -> RpcResult<RpcTransferResponse>;

    // ========== Validator APIs (Testnet) ==========

    /// Register a new validator (testnet only)
    #[method(name = "registerValidator")]
    async fn register_validator(&self, request: RpcRegisterValidatorRequest) -> RpcResult<RpcRegisterValidatorResponse>;

    /// Deactivate/unregister a validator (testnet only)
    #[method(name = "deactivateValidator")]
    async fn deactivate_validator(&self, pubkey: String) -> RpcResult<String>;

    /// Get transaction signatures for an address
    #[method(name = "getSignaturesForAddress")]
    async fn get_signatures_for_address(&self, address: String, config: Option<RpcSignaturesConfig>) -> RpcResult<Vec<RpcSignatureInfo>>;
}

/// RPC implementation
pub struct CelereumRpcImpl {
    storage: Arc<Storage>,
    indexer_url: String,
    http_client: reqwest::Client,
}

impl CelereumRpcImpl {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self {
            storage,
            indexer_url: std::env::var("INDEXER_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8890".to_string()),
            http_client: reqwest::Client::new(),
        }
    }

    /// Send transaction to indexer for storage
    async fn index_transaction(
        &self,
        signature: &str,
        tx_type: &str,
        from: &str,
        to: &str,
        amount: u64,
        slot: u64,
    ) {
        let payload = serde_json::json!({
            "signature": signature,
            "type": tx_type,
            "from": from,
            "to": to,
            "amount": amount,
            "slot": slot,
            "block_time": chrono::Utc::now().timestamp(),
            "status": "confirmed"
        });

        // Fire and forget - don't block on indexer response
        let url = format!("{}/tx", self.indexer_url);
        let _ = self.http_client.post(&url)
            .json(&payload)
            .send()
            .await;
    }

    /// Fetch transactions from indexer
    async fn fetch_transactions_from_indexer(&self, address: &str, limit: usize) -> Vec<RpcSignatureInfo> {
        let url = format!("{}/address/{}/transactions?limit={}", self.indexer_url, address, limit);

        match self.http_client.get(&url).send().await {
            Ok(response) => {
                if let Ok(txs) = response.json::<Vec<serde_json::Value>>().await {
                    txs.into_iter().filter_map(|tx| {
                        Some(RpcSignatureInfo {
                            signature: tx.get("signature")?.as_str()?.to_string(),
                            slot: tx.get("slot")?.as_u64()?,
                            block_time: tx.get("block_time").and_then(|v| v.as_i64()),
                            tx_type: tx.get("type")?.as_str()?.to_string(),
                            amount: tx.get("amount")?.as_u64()?,
                            from: tx.get("from")?.as_str()?.to_string(),
                            to: tx.get("to")?.as_str()?.to_string(),
                            status: tx.get("status").and_then(|v| v.as_str()).unwrap_or("confirmed").to_string(),
                        })
                    }).collect()
                } else {
                    vec![]
                }
            }
            Err(_) => vec![]
        }
    }
}

#[async_trait]
impl CelereumRpcServer for CelereumRpcImpl {
    async fn get_balance(&self, pubkey: String, _config: Option<RpcConfig>) -> RpcResult<u64> {
        let pubkey = Pubkey::from_base58(&pubkey)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid pubkey",
                None::<()>,
            ))?;

        let balance = self.storage.get_balance(&pubkey).unwrap_or(0);
        Ok(balance)
    }

    async fn get_account_info(&self, pubkey: String, _config: Option<RpcConfig>) -> RpcResult<Option<RpcAccountInfo>> {
        let pubkey = Pubkey::from_base58(&pubkey)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid pubkey",
                None::<()>,
            ))?;

        match self.storage.get_account(&pubkey) {
            Some(account) => Ok(Some(RpcAccountInfo {
                celers: account.celers,
                data: bs58::encode(&account.data).into_string(),
                owner: account.owner.to_base58(),
                executable: account.executable,
                rent_epoch: account.rent_epoch,
            })),
            None => Ok(None),
        }
    }

    async fn get_recent_blockhash(&self, _config: Option<RpcConfig>) -> RpcResult<RpcBlockhash> {
        self.get_latest_blockhash(None).await
    }

    async fn get_latest_blockhash(&self, _config: Option<RpcConfig>) -> RpcResult<RpcBlockhash> {
        let blockhash = self.storage.get_latest_blockhash();
        let slot = self.storage.get_current_slot();

        Ok(RpcBlockhash {
            blockhash: blockhash.to_base58(),
            last_valid_block_height: slot + 150, // Valid for ~150 blocks
        })
    }

    async fn get_slot(&self, _config: Option<RpcConfig>) -> RpcResult<Slot> {
        Ok(self.storage.get_current_slot())
    }

    async fn get_block_height(&self, _config: Option<RpcConfig>) -> RpcResult<u64> {
        Ok(self.storage.get_current_slot())
    }

    async fn get_epoch_info(&self, _config: Option<RpcConfig>) -> RpcResult<RpcEpochInfo> {
        let slot = self.storage.get_current_slot();
        let epoch = slot / SLOTS_PER_EPOCH;
        let slot_index = slot % SLOTS_PER_EPOCH;

        Ok(RpcEpochInfo {
            epoch,
            slot_index,
            slots_in_epoch: SLOTS_PER_EPOCH,
            absolute_slot: slot,
            block_height: slot,
            transaction_count: Some(self.storage.get_transaction_count()),
        })
    }

    async fn get_version(&self) -> RpcResult<RpcVersionInfo> {
        Ok(RpcVersionInfo {
            solana_core: format!("celereum-{}", CELEREUM_VERSION),
            feature_set: 1,
        })
    }

    async fn get_health(&self) -> RpcResult<String> {
        Ok("ok".to_string())
    }

    async fn send_transaction(&self, data: String, _config: Option<RpcSendTransactionConfig>) -> RpcResult<String> {
        // Decode transaction from base58 or base64
        let tx_bytes = bs58::decode(&data).into_vec()
            .or_else(|_| base64::decode(&data))
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid transaction encoding",
                None::<()>,
            ))?;

        // Deserialize transaction
        let tx: crate::core::Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid transaction format",
                None::<()>,
            ))?;

        // Verify signature
        if !tx.verify() {
            return Err(ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid transaction signature",
                None::<()>,
            ).into());
        }

        // Get signature for response
        let signature = tx.signatures.first()
            .map(|s| s.signature.to_base58())
            .unwrap_or_default();

        // Add to pending transactions
        self.storage.add_pending_transaction(tx);

        Ok(signature)
    }

    async fn get_transaction(&self, signature: String, _config: Option<RpcConfig>) -> RpcResult<Option<RpcTransactionInfo>> {
        let sig = crate::crypto::Signature::from_base58(&signature)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid signature",
                None::<()>,
            ))?;

        match self.storage.get_transaction(&sig) {
            Some((tx, slot)) => Ok(Some(RpcTransactionInfo {
                signature,
                slot,
                block_time: Some(chrono::Utc::now().timestamp()),
                status: RpcTransactionStatus {
                    ok: Some(()),
                    err: None,
                },
                fee: 5000, // Standard fee
            })),
            None => Ok(None),
        }
    }

    async fn get_signature_statuses(&self, signatures: Vec<String>, _config: Option<RpcConfig>) -> RpcResult<Vec<Option<RpcSignatureStatus>>> {
        let mut statuses = Vec::with_capacity(signatures.len());

        for sig_str in signatures {
            let status = if let Ok(sig) = crate::crypto::Signature::from_base58(&sig_str) {
                self.storage.get_transaction(&sig).map(|(_, slot)| {
                    RpcSignatureStatus {
                        slot,
                        confirmations: Some(32),
                        err: None,
                        confirmation_status: Some("finalized".to_string()),
                    }
                })
            } else {
                None
            };
            statuses.push(status);
        }

        Ok(statuses)
    }

    async fn get_block(&self, slot: Slot, _config: Option<RpcConfig>) -> RpcResult<Option<RpcBlockInfo>> {
        match self.storage.get_block(slot) {
            Some(block) => Ok(Some(RpcBlockInfo {
                blockhash: block.hash().to_base58(),
                previous_blockhash: block.header.previous_hash.to_base58(),
                parent_slot: if slot > 0 { slot - 1 } else { 0 },
                block_time: Some(block.header.timestamp),
                block_height: Some(slot),
                transactions: block.transactions.iter().map(|tx| {
                    RpcTransactionInfo {
                        signature: tx.signatures.first()
                            .map(|s| s.signature.to_base58())
                            .unwrap_or_default(),
                        slot,
                        block_time: Some(block.header.timestamp),
                        status: RpcTransactionStatus {
                            ok: Some(()),
                            err: None,
                        },
                        fee: 5000,
                    }
                }).collect(),
            })),
            None => Ok(None),
        }
    }

    async fn get_supply(&self, _config: Option<RpcConfig>) -> RpcResult<RpcSupply> {
        let total = TOTAL_SUPPLY; // 210M CEL (defined in programs/vesting.rs)
        let circulating = self.storage.get_total_supply();

        Ok(RpcSupply {
            total,
            circulating,
            non_circulating: total - circulating,
            non_circulating_accounts: vec![],
        })
    }

    async fn request_airdrop(&self, pubkey: String, celers: u64, _config: Option<RpcConfig>) -> RpcResult<String> {
        let pk = Pubkey::from_base58(&pubkey)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid pubkey",
                None::<()>,
            ))?;

        // Limit airdrop amount (10 CEL max)
        let celers = celers.min(10 * CELERS_PER_CEL);

        // Credit the account
        self.storage.credit_account(&pk, celers);

        // Create transaction signature
        let slot = self.storage.get_current_slot();
        let mut data = Vec::new();
        data.extend_from_slice(pk.as_bytes());
        data.extend_from_slice(&celers.to_le_bytes());
        data.extend_from_slice(&chrono::Utc::now().timestamp().to_le_bytes());
        let sig = crate::crypto::Hash::hash(&data);
        let signature = sig.to_base58();

        // Index the faucet transaction
        self.index_transaction(
            &signature,
            "faucet",
            "Faucet",
            &pubkey,
            celers,
            slot,
        ).await;

        // Record transaction
        self.storage.increment_transaction_count();

        Ok(signature)
    }

    async fn get_minimum_balance_for_rent_exemption(&self, data_len: usize, _config: Option<RpcConfig>) -> RpcResult<u64> {
        // ~0.00089 CEL per byte + base
        let bytes_fee = (data_len as u64) * 6960;
        let base_fee = 890880;
        Ok(base_fee + bytes_fee)
    }

    // ========== Dashboard/Stats API implementations ==========

    async fn get_network_stats(&self) -> RpcResult<RpcNetworkStats> {
        let slot = self.storage.get_current_slot();
        let epoch = slot / SLOTS_PER_EPOCH;
        let tx_count = self.storage.get_transaction_count();
        let account_count = self.storage.get_account_count();

        // Calculate TPS from recent transactions (simplified)
        let tps = self.storage.get_recent_tps();

        Ok(RpcNetworkStats {
            tps,
            block_height: slot,
            slot_height: slot,
            validators: self.storage.get_validator_count(),
            active_accounts: account_count,
            total_transactions: tx_count,
            avg_block_time_ms: 400, // Target 400ms
            epoch,
            total_stake: self.storage.get_total_stake(),
            version: CELEREUM_VERSION.to_string(),
        })
    }

    async fn get_validators(&self) -> RpcResult<Vec<RpcValidatorInfo>> {
        Ok(self.storage.get_validators().iter().map(|v| {
            RpcValidatorInfo {
                pubkey: v.pubkey.to_base58(),
                name: v.name.clone(),
                stake: v.stake,
                commission: v.commission,
                status: if v.active { "active".to_string() } else { "inactive".to_string() },
                skip_rate: v.skip_rate,
                blocks_produced: v.blocks_produced,
                uptime: v.uptime,
            }
        }).collect())
    }

    async fn get_recent_blocks(&self, limit: Option<u64>) -> RpcResult<Vec<RpcRecentBlock>> {
        let limit = limit.unwrap_or(10).min(50) as usize;
        let current_slot = self.storage.get_current_slot();

        let mut blocks = Vec::new();
        for i in 0..limit {
            let slot = current_slot.saturating_sub(i as u64);
            if let Some(block) = self.storage.get_block(slot) {
                blocks.push(RpcRecentBlock {
                    slot,
                    hash: block.hash().to_base58(),
                    tx_count: block.transactions.len() as u64,
                    timestamp: block.header.timestamp,
                    leader: block.header.leader.to_base58(),
                });
            }
        }

        Ok(blocks)
    }

    async fn get_recent_performance_samples(&self, limit: Option<u64>) -> RpcResult<Vec<RpcPerformanceSample>> {
        let limit = limit.unwrap_or(10).min(720) as usize;
        Ok(self.storage.get_performance_samples(limit))
    }

    // ========== Wallet API implementations ==========

    async fn transfer(&self, request: RpcTransferRequest) -> RpcResult<RpcTransferResponse> {
        use crate::crypto::sevs::{SevsPubkey, SevsSignature};

        // Parse addresses (SEVS addresses are 32-byte SHA3-256 hashes)
        let from = Pubkey::from_base58(&request.from)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid sender address",
                None::<()>,
            ))?;

        let to = Pubkey::from_base58(&request.to)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid recipient address",
                None::<()>,
            ))?;

        // Parse SEVS signature (128 bytes)
        let signature_bytes = bs58::decode(&request.signature).into_vec()
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid signature encoding",
                None::<()>,
            ))?;

        // SEVS signatures are 128 bytes
        if signature_bytes.len() != 128 {
            return Err(ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                format!("Invalid SEVS signature length: expected 128 bytes, got {}", signature_bytes.len()),
                None::<()>,
            ).into());
        }

        // Get SEVS public key for verification
        let public_key_str = request.public_key.as_ref()
            .ok_or_else(|| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Missing public_key field for SEVS signature verification",
                None::<()>,
            ))?;

        let pubkey_bytes = bs58::decode(public_key_str).into_vec()
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid public key encoding",
                None::<()>,
            ))?;

        // SEVS public keys are 64 bytes
        if pubkey_bytes.len() != 64 {
            return Err(ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                format!("Invalid SEVS public key length: expected 64 bytes, got {}", pubkey_bytes.len()),
                None::<()>,
            ).into());
        }

        // Create SEVS public key
        let sevs_pubkey = SevsPubkey::from_bytes(&pubkey_bytes)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid SEVS public key format",
                None::<()>,
            ))?;

        // Verify that public key derives to the sender's address
        use crate::crypto::quantum_safe::Address as SevsAddress;
        let derived_address = SevsAddress::from_pubkey(&sevs_pubkey);
        if derived_address.as_bytes() != from.as_bytes() {
            return Err(ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Public key does not match sender address",
                None::<()>,
            ).into());
        }

        // Create SEVS signature
        let sevs_sig = SevsSignature::from_bytes(&signature_bytes)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid SEVS signature format",
                None::<()>,
            ))?;

        // Create message to verify: from_address + to_address + amount
        // This matches the WASM signing format
        let mut message = Vec::new();
        message.extend_from_slice(from.as_bytes());   // 32 bytes (address)
        message.extend_from_slice(to.as_bytes());     // 32 bytes (address)
        message.extend_from_slice(&request.amount.to_le_bytes()); // 8 bytes (amount)

        // Verify SEVS signature (verify is on SevsSignature, not SevsPubkey)
        if !sevs_sig.verify(&message, &sevs_pubkey) {
            return Err(ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "SEVS signature verification failed",
                None::<()>,
            ).into());
        }

        // Check balance
        let balance = self.storage.get_balance(&from).unwrap_or(0);
        let fee = 5000; // 0.000005 CEL fee
        let total_needed = request.amount.saturating_add(fee);

        if balance < total_needed {
            return Err(ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                format!("Insufficient balance. Have: {}, need: {}", balance, total_needed),
                None::<()>,
            ).into());
        }

        // Execute transfer
        if !self.storage.debit_account(&from, total_needed) {
            return Err(ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Failed to debit account",
                None::<()>,
            ).into());
        }
        self.storage.credit_account(&to, request.amount);

        // Create transaction hash
        let slot = self.storage.get_current_slot();
        let mut hash_data = Vec::new();
        hash_data.extend_from_slice(&message);
        hash_data.extend_from_slice(&slot.to_le_bytes());
        hash_data.extend_from_slice(&signature_bytes);
        let tx_hash = crate::crypto::Hash::hash(&hash_data);

        // Record transaction
        self.storage.increment_transaction_count();

        let signature = tx_hash.to_base58();

        // Index the transfer transaction
        self.index_transaction(
            &signature,
            "transfer",
            &request.from,
            &request.to,
            request.amount,
            slot,
        ).await;

        Ok(RpcTransferResponse {
            signature,
            slot,
        })
    }

    // ========== Validator API implementations ==========

    async fn register_validator(&self, request: RpcRegisterValidatorRequest) -> RpcResult<RpcRegisterValidatorResponse> {
        use crate::storage::ValidatorInfo;

        // Parse pubkey
        let pubkey = Pubkey::from_base58(&request.pubkey)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid validator public key",
                None::<()>,
            ))?;

        // Validate commission (0-100)
        if request.commission > 100 {
            return Err(ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Commission must be between 0 and 100",
                None::<()>,
            ).into());
        }

        // Minimum stake: 1000 CEL for testnet
        let min_stake = 1000 * CELERS_PER_CEL;
        if request.stake < min_stake {
            return Err(ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                format!("Minimum stake is 1000 CEL ({} celers)", min_stake),
                None::<()>,
            ).into());
        }

        // Validate name
        let name = if request.name.is_empty() {
            format!("Validator-{}", &request.pubkey[..8])
        } else if request.name.len() > 64 {
            return Err(ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Name must be 64 characters or less",
                None::<()>,
            ).into());
        } else {
            request.name
        };

        // Create validator info
        let validator_info = ValidatorInfo {
            pubkey: pubkey.clone(),
            name,
            stake: request.stake,
            commission: request.commission,
            active: true,
            skip_rate: 0.0,
            blocks_produced: 0,
            uptime: 100.0,
        };

        // Register validator
        self.storage.add_validator(validator_info);

        Ok(RpcRegisterValidatorResponse {
            message: "Validator registered successfully".to_string(),
            pubkey: pubkey.to_base58(),
        })
    }

    async fn deactivate_validator(&self, pubkey: String) -> RpcResult<String> {
        // Parse pubkey
        let pubkey = Pubkey::from_base58(&pubkey)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid validator public key",
                None::<()>,
            ))?;

        // Remove validator
        self.storage.remove_validator(&pubkey);

        Ok(format!("Validator {} deactivated", pubkey.to_base58()))
    }

    async fn get_signatures_for_address(&self, address: String, config: Option<RpcSignaturesConfig>) -> RpcResult<Vec<RpcSignatureInfo>> {
        // Validate address
        let _ = Pubkey::from_base58(&address)
            .map_err(|_| ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Invalid address",
                None::<()>,
            ))?;

        let limit = config.and_then(|c| c.limit).unwrap_or(20).min(100);

        // Fetch from indexer
        let txs = self.fetch_transactions_from_indexer(&address, limit).await;
        Ok(txs)
    }
}

// Helper for base64 decoding
mod base64 {
    pub fn decode(input: &str) -> Result<Vec<u8>, ()> {
        // Simple base64 decode
        let input = input.trim();
        let len = input.len();
        if len % 4 != 0 {
            return Err(());
        }

        let mut output = Vec::with_capacity(len * 3 / 4);
        let bytes = input.as_bytes();

        for chunk in bytes.chunks(4) {
            let mut buf = [0u8; 4];
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = match b {
                    b'A'..=b'Z' => b - b'A',
                    b'a'..=b'z' => b - b'a' + 26,
                    b'0'..=b'9' => b - b'0' + 52,
                    b'+' => 62,
                    b'/' => 63,
                    b'=' => 0,
                    _ => return Err(()),
                };
            }

            output.push((buf[0] << 2) | (buf[1] >> 4));
            if chunk[2] != b'=' {
                output.push((buf[1] << 4) | (buf[2] >> 2));
            }
            if chunk[3] != b'=' {
                output.push((buf[2] << 6) | buf[3]);
            }
        }

        Ok(output)
    }
}
