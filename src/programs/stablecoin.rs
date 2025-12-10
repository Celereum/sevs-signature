//! CUSD Stablecoin Program for Celereum blockchain
//!
//! Algorithmic stablecoin pegged to $1 USD
//!
//! Features:
//! - Collateralized minting (over-collateralized with ALT)
//! - Liquidation mechanism
//! - Interest rate (stability fee)
//! - Price oracle integration
//! - Emergency shutdown

use crate::crypto::Pubkey;
use crate::core::Account;
use serde::{Deserialize, Serialize};

/// Stablecoin Program ID
pub const STABLECOIN_PROGRAM_ID: Pubkey = Pubkey([
    0x41, 0x55, 0x4c, 0x54, 0x53, 0x74, 0x61, 0x62,
    0x6c, 0x65, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
]);

/// Minimum collateralization ratio (150% = 15000 basis points)
pub const MIN_COLLATERAL_RATIO_BPS: u64 = 15000;

/// Liquidation threshold (130% = 13000 basis points)
pub const LIQUIDATION_THRESHOLD_BPS: u64 = 13000;

/// Liquidation penalty (10% = 1000 basis points)
pub const LIQUIDATION_PENALTY_BPS: u64 = 1000;

/// Stability fee (annual interest rate, 2% = 200 basis points)
pub const STABILITY_FEE_BPS: u64 = 200;

/// Price precision (8 decimals)
pub const PRICE_PRECISION: u64 = 100_000_000;

/// AULT decimals (same as USDC)
pub const AULT_DECIMALS: u8 = 6;

/// Global stablecoin state
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StablecoinState {
    /// Admin authority
    pub admin: Pubkey,
    /// AULT mint address
    pub ault_mint: Pubkey,
    /// Collateral mint (ALT)
    pub collateral_mint: Pubkey,
    /// Total AULT minted
    pub total_supply: u64,
    /// Total collateral locked
    pub total_collateral: u64,
    /// Current ALT/USD price (8 decimals)
    pub collateral_price: u64,
    /// Price oracle address
    pub oracle: Pubkey,
    /// Last price update timestamp
    pub last_price_update: i64,
    /// Is system active?
    pub is_active: bool,
    /// Emergency shutdown triggered
    pub emergency_shutdown: bool,
    /// Is initialized?
    pub is_initialized: bool,
}

impl StablecoinState {
    pub const LEN: usize = 256;

    /// Serialize to bytes
    pub fn pack(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn unpack(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }

    /// Calculate global collateralization ratio (in basis points)
    pub fn global_collateral_ratio(&self) -> Option<u64> {
        if self.total_supply == 0 {
            return Some(u64::MAX);
        }

        // collateral_value = total_collateral * collateral_price / PRICE_PRECISION
        // ratio = collateral_value * 10000 / total_supply
        let collateral_value = (self.total_collateral as u128)
            .checked_mul(self.collateral_price as u128)?
            .checked_div(PRICE_PRECISION as u128)?;

        let ratio = collateral_value
            .checked_mul(10000)?
            .checked_div(self.total_supply as u128)?;

        Some(ratio as u64)
    }
}

/// Individual vault (CDP - Collateralized Debt Position)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Vault {
    /// Vault owner
    pub owner: Pubkey,
    /// Collateral deposited (in celers)
    pub collateral: u64,
    /// AULT debt (in AULT smallest unit)
    pub debt: u64,
    /// Accumulated stability fee
    pub accumulated_fee: u64,
    /// Last fee update timestamp
    pub last_fee_update: i64,
    /// Is vault active?
    pub is_active: bool,
    /// Vault ID
    pub vault_id: u64,
}

impl Vault {
    pub const LEN: usize = 128;

    /// Create new vault
    pub fn new(owner: Pubkey, vault_id: u64) -> Self {
        Self {
            owner,
            collateral: 0,
            debt: 0,
            accumulated_fee: 0,
            last_fee_update: 0,
            is_active: true,
            vault_id,
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

    /// Calculate collateralization ratio (in basis points)
    pub fn collateral_ratio(&self, collateral_price: u64) -> Option<u64> {
        if self.debt == 0 {
            return Some(u64::MAX);
        }

        // collateral_value = collateral * collateral_price / PRICE_PRECISION
        // ratio = collateral_value * 10000 / debt
        let collateral_value = (self.collateral as u128)
            .checked_mul(collateral_price as u128)?
            .checked_div(PRICE_PRECISION as u128)?;

        let ratio = collateral_value
            .checked_mul(10000)?
            .checked_div(self.debt as u128)?;

        Some(ratio as u64)
    }

    /// Check if vault is safe (above minimum collateral ratio)
    pub fn is_safe(&self, collateral_price: u64) -> bool {
        self.collateral_ratio(collateral_price)
            .map(|r| r >= MIN_COLLATERAL_RATIO_BPS)
            .unwrap_or(true)
    }

    /// Check if vault can be liquidated
    pub fn can_liquidate(&self, collateral_price: u64) -> bool {
        self.collateral_ratio(collateral_price)
            .map(|r| r < LIQUIDATION_THRESHOLD_BPS)
            .unwrap_or(false)
    }

    /// Calculate maximum AULT that can be minted
    pub fn max_mintable(&self, collateral_price: u64) -> u64 {
        // max_debt = collateral_value * 10000 / MIN_COLLATERAL_RATIO_BPS
        let collateral_value = (self.collateral as u128)
            .saturating_mul(collateral_price as u128)
            / PRICE_PRECISION as u128;

        let max_debt = collateral_value
            .saturating_mul(10000)
            / MIN_COLLATERAL_RATIO_BPS as u128;

        max_debt.saturating_sub(self.debt as u128) as u64
    }

    /// Calculate stability fee since last update
    pub fn calculate_fee(&self, current_time: i64) -> u64 {
        if self.debt == 0 || self.last_fee_update == 0 {
            return 0;
        }

        let time_elapsed = (current_time - self.last_fee_update).max(0) as u64;
        let seconds_per_year: u128 = 365 * 24 * 60 * 60;

        // fee = debt * rate * time / year
        let fee = (self.debt as u128)
            .saturating_mul(STABILITY_FEE_BPS as u128)
            .saturating_mul(time_elapsed as u128)
            / (10000u128 * seconds_per_year);

        fee as u64
    }
}

/// Stablecoin instructions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StablecoinInstruction {
    /// Initialize the stablecoin system
    /// Accounts: [state, ault_mint, collateral_mint, oracle, admin]
    Initialize,

    /// Create a new vault
    /// Accounts: [state, vault, owner, payer]
    CreateVault,

    /// Deposit collateral into vault
    /// Accounts: [state, vault, user_collateral, vault_collateral, owner]
    DepositCollateral { amount: u64 },

    /// Withdraw collateral from vault
    /// Accounts: [state, vault, user_collateral, vault_collateral, owner]
    WithdrawCollateral { amount: u64 },

    /// Mint AULT against collateral
    /// Accounts: [state, vault, ault_mint, user_ault, owner]
    MintAult { amount: u64 },

    /// Repay AULT debt
    /// Accounts: [state, vault, ault_mint, user_ault, owner]
    RepayAult { amount: u64 },

    /// Liquidate an undercollateralized vault
    /// Accounts: [state, vault, liquidator_ault, liquidator_collateral, ault_mint, vault_collateral]
    Liquidate { debt_to_cover: u64 },

    /// Update price from oracle
    /// Accounts: [state, oracle]
    UpdatePrice { new_price: u64 },

    /// Emergency shutdown (admin only)
    /// Accounts: [state, admin]
    EmergencyShutdown,

    /// Redeem collateral after emergency shutdown
    /// Accounts: [state, vault, user_ault, user_collateral, ault_mint, vault_collateral, owner]
    EmergencyRedeem,
}

impl StablecoinInstruction {
    /// Serialize instruction to bytes
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize instruction from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}

/// Stablecoin Program implementation
pub struct StablecoinProgram;

impl StablecoinProgram {
    /// Process a stablecoin instruction
    pub fn process(
        instruction: &StablecoinInstruction,
        accounts: &mut [Account],
    ) -> Result<(), StablecoinError> {
        match instruction {
            StablecoinInstruction::Initialize => Self::process_initialize(accounts),
            StablecoinInstruction::CreateVault => Self::process_create_vault(accounts),
            StablecoinInstruction::DepositCollateral { amount } => {
                Self::process_deposit_collateral(accounts, *amount)
            }
            StablecoinInstruction::WithdrawCollateral { amount } => {
                Self::process_withdraw_collateral(accounts, *amount)
            }
            StablecoinInstruction::MintAult { amount } => {
                Self::process_mint_ault(accounts, *amount)
            }
            StablecoinInstruction::RepayAult { amount } => {
                Self::process_repay_ault(accounts, *amount)
            }
            StablecoinInstruction::Liquidate { debt_to_cover } => {
                Self::process_liquidate(accounts, *debt_to_cover)
            }
            StablecoinInstruction::UpdatePrice { new_price } => {
                Self::process_update_price(accounts, *new_price)
            }
            StablecoinInstruction::EmergencyShutdown => {
                Self::process_emergency_shutdown(accounts)
            }
            StablecoinInstruction::EmergencyRedeem => {
                Self::process_emergency_redeem(accounts)
            }
        }
    }

    fn process_initialize(accounts: &mut [Account]) -> Result<(), StablecoinError> {
        if accounts.len() < 5 {
            return Err(StablecoinError::NotEnoughAccounts);
        }

        let state_account = &mut accounts[0];

        // Check not already initialized
        if !state_account.data.is_empty() {
            if let Some(existing) = StablecoinState::unpack(&state_account.data) {
                if existing.is_initialized {
                    return Err(StablecoinError::AlreadyInitialized);
                }
            }
        }

        let state = StablecoinState {
            admin: Pubkey::zero(), // Would be accounts[4] pubkey
            ault_mint: Pubkey::zero(),
            collateral_mint: Pubkey::zero(),
            total_supply: 0,
            total_collateral: 0,
            collateral_price: PRICE_PRECISION, // Start at $1
            oracle: Pubkey::zero(),
            last_price_update: 0,
            is_active: true,
            emergency_shutdown: false,
            is_initialized: true,
        };

        state_account.data = state.pack();
        state_account.owner = STABLECOIN_PROGRAM_ID;

        Ok(())
    }

    fn process_create_vault(accounts: &mut [Account]) -> Result<(), StablecoinError> {
        if accounts.len() < 4 {
            return Err(StablecoinError::NotEnoughAccounts);
        }

        let state_data = accounts[0].data.clone();
        let state = StablecoinState::unpack(&state_data).ok_or(StablecoinError::InvalidState)?;

        if !state.is_active || state.emergency_shutdown {
            return Err(StablecoinError::SystemInactive);
        }

        let vault_account = &mut accounts[1];

        // Generate vault ID (simplified)
        let vault_id = state.total_supply.wrapping_add(1);

        let vault = Vault::new(Pubkey::zero(), vault_id); // Would be accounts[2] pubkey

        vault_account.data = vault.pack();
        vault_account.owner = STABLECOIN_PROGRAM_ID;

        Ok(())
    }

    fn process_deposit_collateral(
        accounts: &mut [Account],
        amount: u64,
    ) -> Result<(), StablecoinError> {
        if accounts.len() < 5 {
            return Err(StablecoinError::NotEnoughAccounts);
        }

        let state_data = accounts[0].data.clone();
        let mut state = StablecoinState::unpack(&state_data).ok_or(StablecoinError::InvalidState)?;

        if !state.is_active || state.emergency_shutdown {
            return Err(StablecoinError::SystemInactive);
        }

        let vault_data = accounts[1].data.clone();
        let mut vault = Vault::unpack(&vault_data).ok_or(StablecoinError::InvalidVault)?;

        // Update vault
        vault.collateral = vault.collateral.checked_add(amount)
            .ok_or(StablecoinError::MathError)?;

        // Update global state
        state.total_collateral = state.total_collateral.checked_add(amount)
            .ok_or(StablecoinError::MathError)?;

        accounts[0].data = state.pack();
        accounts[1].data = vault.pack();

        Ok(())
    }

    fn process_withdraw_collateral(
        accounts: &mut [Account],
        amount: u64,
    ) -> Result<(), StablecoinError> {
        if accounts.len() < 5 {
            return Err(StablecoinError::NotEnoughAccounts);
        }

        let state_data = accounts[0].data.clone();
        let mut state = StablecoinState::unpack(&state_data).ok_or(StablecoinError::InvalidState)?;

        if !state.is_active {
            return Err(StablecoinError::SystemInactive);
        }

        let vault_data = accounts[1].data.clone();
        let mut vault = Vault::unpack(&vault_data).ok_or(StablecoinError::InvalidVault)?;

        // Check vault has enough collateral
        if vault.collateral < amount {
            return Err(StablecoinError::InsufficientCollateral);
        }

        // Check vault remains safe after withdrawal
        let new_collateral = vault.collateral.saturating_sub(amount);
        let temp_vault = Vault {
            collateral: new_collateral,
            ..vault.clone()
        };

        if !temp_vault.is_safe(state.collateral_price) {
            return Err(StablecoinError::UnsafeWithdrawal);
        }

        // Update vault
        vault.collateral = new_collateral;

        // Update global state
        state.total_collateral = state.total_collateral.saturating_sub(amount);

        accounts[0].data = state.pack();
        accounts[1].data = vault.pack();

        Ok(())
    }

    fn process_mint_ault(accounts: &mut [Account], amount: u64) -> Result<(), StablecoinError> {
        if accounts.len() < 5 {
            return Err(StablecoinError::NotEnoughAccounts);
        }

        let state_data = accounts[0].data.clone();
        let mut state = StablecoinState::unpack(&state_data).ok_or(StablecoinError::InvalidState)?;

        if !state.is_active || state.emergency_shutdown {
            return Err(StablecoinError::SystemInactive);
        }

        let vault_data = accounts[1].data.clone();
        let mut vault = Vault::unpack(&vault_data).ok_or(StablecoinError::InvalidVault)?;

        // Check max mintable
        let max_mintable = vault.max_mintable(state.collateral_price);
        if amount > max_mintable {
            return Err(StablecoinError::ExceedsMaxMintable);
        }

        // Update vault
        vault.debt = vault.debt.checked_add(amount)
            .ok_or(StablecoinError::MathError)?;

        // Update global state
        state.total_supply = state.total_supply.checked_add(amount)
            .ok_or(StablecoinError::MathError)?;

        accounts[0].data = state.pack();
        accounts[1].data = vault.pack();

        Ok(())
    }

    fn process_repay_ault(accounts: &mut [Account], amount: u64) -> Result<(), StablecoinError> {
        if accounts.len() < 5 {
            return Err(StablecoinError::NotEnoughAccounts);
        }

        let state_data = accounts[0].data.clone();
        let mut state = StablecoinState::unpack(&state_data).ok_or(StablecoinError::InvalidState)?;

        let vault_data = accounts[1].data.clone();
        let mut vault = Vault::unpack(&vault_data).ok_or(StablecoinError::InvalidVault)?;

        // Calculate actual repayment (can't repay more than debt + fees)
        let total_debt = vault.debt.saturating_add(vault.accumulated_fee);
        let actual_repay = amount.min(total_debt);

        // First pay off accumulated fees, then debt
        if actual_repay <= vault.accumulated_fee {
            vault.accumulated_fee = vault.accumulated_fee.saturating_sub(actual_repay);
        } else {
            let debt_payment = actual_repay.saturating_sub(vault.accumulated_fee);
            vault.accumulated_fee = 0;
            vault.debt = vault.debt.saturating_sub(debt_payment);
        }

        // Update global state
        state.total_supply = state.total_supply.saturating_sub(actual_repay);

        accounts[0].data = state.pack();
        accounts[1].data = vault.pack();

        Ok(())
    }

    fn process_liquidate(
        accounts: &mut [Account],
        debt_to_cover: u64,
    ) -> Result<(), StablecoinError> {
        if accounts.len() < 6 {
            return Err(StablecoinError::NotEnoughAccounts);
        }

        let state_data = accounts[0].data.clone();
        let mut state = StablecoinState::unpack(&state_data).ok_or(StablecoinError::InvalidState)?;

        let vault_data = accounts[1].data.clone();
        let mut vault = Vault::unpack(&vault_data).ok_or(StablecoinError::InvalidVault)?;

        // Check vault can be liquidated
        if !vault.can_liquidate(state.collateral_price) {
            return Err(StablecoinError::VaultNotLiquidatable);
        }

        // Calculate collateral to seize (debt + penalty)
        // collateral = debt_to_cover * (10000 + penalty) / 10000 / price * PRICE_PRECISION
        let debt_value = (debt_to_cover as u128)
            .checked_mul(10000 + LIQUIDATION_PENALTY_BPS as u128)
            .ok_or(StablecoinError::MathError)?
            .checked_div(10000)
            .ok_or(StablecoinError::MathError)?;

        let collateral_to_seize = debt_value
            .checked_mul(PRICE_PRECISION as u128)
            .ok_or(StablecoinError::MathError)?
            .checked_div(state.collateral_price as u128)
            .ok_or(StablecoinError::MathError)? as u64;

        let actual_seize = collateral_to_seize.min(vault.collateral);
        let actual_debt_covered = debt_to_cover.min(vault.debt);

        // Update vault
        vault.collateral = vault.collateral.saturating_sub(actual_seize);
        vault.debt = vault.debt.saturating_sub(actual_debt_covered);

        // Update global state
        state.total_collateral = state.total_collateral.saturating_sub(actual_seize);
        state.total_supply = state.total_supply.saturating_sub(actual_debt_covered);

        accounts[0].data = state.pack();
        accounts[1].data = vault.pack();

        Ok(())
    }

    fn process_update_price(
        accounts: &mut [Account],
        new_price: u64,
    ) -> Result<(), StablecoinError> {
        if accounts.len() < 2 {
            return Err(StablecoinError::NotEnoughAccounts);
        }

        let state_data = accounts[0].data.clone();
        let mut state = StablecoinState::unpack(&state_data).ok_or(StablecoinError::InvalidState)?;

        // SECURITY FIX: Verify oracle authorization
        let oracle_account = &accounts[1];

        // SECURITY: Oracle account must be a signer
        if !oracle_account.is_signer {
            return Err(StablecoinError::Unauthorized);
        }

        // SECURITY: Verify the signer is the authorized oracle
        if oracle_account.owner != state.oracle {
            return Err(StablecoinError::Unauthorized);
        }

        // SECURITY: Validate price is not zero
        if new_price == 0 {
            return Err(StablecoinError::InvalidPrice);
        }

        // Validate price (sanity check - shouldn't change more than 50% at once)
        // SECURITY FIX: Use checked arithmetic to prevent overflow
        if state.collateral_price > 0 {
            let price_change_ratio = if new_price > state.collateral_price {
                (new_price as u128)
                    .checked_mul(100)
                    .and_then(|v| v.checked_div(state.collateral_price as u128))
                    .unwrap_or(u128::MAX)
            } else {
                (state.collateral_price as u128)
                    .checked_mul(100)
                    .and_then(|v| v.checked_div(new_price as u128))
                    .unwrap_or(u128::MAX)
            };

            if price_change_ratio > 150 {
                return Err(StablecoinError::PriceChangeTooBig);
            }
        }

        state.collateral_price = new_price;
        // state.last_price_update = current_time; // Would need timestamp

        accounts[0].data = state.pack();

        Ok(())
    }

    fn process_emergency_shutdown(accounts: &mut [Account]) -> Result<(), StablecoinError> {
        if accounts.len() < 2 {
            return Err(StablecoinError::NotEnoughAccounts);
        }

        let state_data = accounts[0].data.clone();
        let mut state = StablecoinState::unpack(&state_data).ok_or(StablecoinError::InvalidState)?;

        // SECURITY FIX: Verify admin is the signer
        let admin_account = &accounts[1];

        // SECURITY: Admin account must be a signer
        if !admin_account.is_signer {
            return Err(StablecoinError::Unauthorized);
        }

        // SECURITY: Verify the signer is the actual admin
        if admin_account.owner != state.admin {
            return Err(StablecoinError::Unauthorized);
        }

        state.emergency_shutdown = true;
        state.is_active = false;

        accounts[0].data = state.pack();

        Ok(())
    }

    fn process_emergency_redeem(accounts: &mut [Account]) -> Result<(), StablecoinError> {
        if accounts.len() < 7 {
            return Err(StablecoinError::NotEnoughAccounts);
        }

        let state_data = accounts[0].data.clone();
        let state = StablecoinState::unpack(&state_data).ok_or(StablecoinError::InvalidState)?;

        if !state.emergency_shutdown {
            return Err(StablecoinError::NotInEmergency);
        }

        let vault_data = accounts[1].data.clone();
        let mut vault = Vault::unpack(&vault_data).ok_or(StablecoinError::InvalidVault)?;

        // Calculate collateral to return based on AULT held
        // This is a simplified emergency redemption

        // Clear vault
        vault.collateral = 0;
        vault.debt = 0;
        vault.is_active = false;

        accounts[1].data = vault.pack();

        Ok(())
    }
}

/// Stablecoin program errors
#[derive(Debug, Clone, PartialEq)]
pub enum StablecoinError {
    NotEnoughAccounts,
    InvalidState,
    InvalidVault,
    AlreadyInitialized,
    SystemInactive,
    InsufficientCollateral,
    UnsafeWithdrawal,
    ExceedsMaxMintable,
    VaultNotLiquidatable,
    MathError,
    PriceChangeTooBig,
    NotInEmergency,
    Unauthorized,
    /// Price cannot be zero
    InvalidPrice,
}

impl std::fmt::Display for StablecoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for StablecoinError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_collateral_ratio() {
        let mut vault = Vault::default();
        vault.collateral = 1_000_000_000; // 1 ALT
        vault.debt = 500_000; // 0.5 AULT

        // At $1 ALT price
        let ratio = vault.collateral_ratio(PRICE_PRECISION).unwrap();
        assert_eq!(ratio, 200000); // 2000% (20x collateralized)

        // At $0.10 ALT price
        let ratio2 = vault.collateral_ratio(PRICE_PRECISION / 10).unwrap();
        assert_eq!(ratio2, 20000); // 200%
    }

    #[test]
    fn test_vault_safety() {
        let mut vault = Vault::default();
        vault.collateral = 1_500_000_000; // 1.5 ALT
        vault.debt = 1_000_000; // 1 AULT

        // At $1 ALT price - exactly 150% collateralized
        assert!(vault.is_safe(PRICE_PRECISION));

        // At $0.90 ALT price - undercollateralized
        assert!(!vault.is_safe(PRICE_PRECISION * 9 / 10));
    }

    #[test]
    fn test_max_mintable() {
        let mut vault = Vault::default();
        vault.collateral = 1_500_000_000; // 1.5 ALT
        vault.debt = 0;

        // At $1 ALT price, can mint 1.5 / 1.5 = 1 AULT
        let max = vault.max_mintable(PRICE_PRECISION);
        assert_eq!(max, 1_000_000); // 1 AULT (6 decimals)
    }

    #[test]
    fn test_liquidation_threshold() {
        let mut vault = Vault::default();
        vault.collateral = 1_300_000_000; // 1.3 ALT
        vault.debt = 1_000_000; // 1 AULT

        // At $1 ALT price - exactly at liquidation threshold
        assert!(!vault.can_liquidate(PRICE_PRECISION));

        // At $0.99 ALT price - can liquidate
        assert!(vault.can_liquidate(PRICE_PRECISION * 99 / 100));
    }

    #[test]
    fn test_global_collateral_ratio() {
        let mut state = StablecoinState::default();
        state.total_collateral = 10_000_000_000; // 10 ALT
        state.total_supply = 5_000_000; // 5 AULT
        state.collateral_price = PRICE_PRECISION; // $1

        let ratio = state.global_collateral_ratio().unwrap();
        assert_eq!(ratio, 20000); // 200%
    }
}
