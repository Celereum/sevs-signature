//! AMM (Automated Market Maker) DEX Program for Celereum
//!
//! Implements constant product AMM (x * y = k) similar to Uniswap V2 / Raydium
//!
//! Features:
//! - Liquidity pools with two tokens
//! - Swap tokens with automatic price discovery
//! - Add/remove liquidity
//! - LP token minting/burning
//! - Fee collection (0.3% default)

use crate::crypto::Pubkey;
use crate::core::{Account, Instruction};
use serde::{Deserialize, Serialize};

/// AMM Program ID
pub const AMM_PROGRAM_ID: Pubkey = Pubkey([
    0x41, 0x4d, 0x4d, 0x50, 0x72, 0x6f, 0x67, 0x72,
    0x61, 0x6d, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
]);

/// Default swap fee (0.3% = 30 basis points)
pub const DEFAULT_FEE_NUMERATOR: u64 = 3;
pub const DEFAULT_FEE_DENOMINATOR: u64 = 1000;

/// Maximum allowed fee (10% = 100 basis points)
/// SECURITY: Prevents pool admins from setting exploitative fees
pub const MAX_FEE_NUMERATOR: u64 = 100;
pub const MAX_FEE_DENOMINATOR: u64 = 1000;

/// Minimum liquidity locked forever (prevents division by zero attacks)
pub const MINIMUM_LIQUIDITY: u64 = 1000;

/// Liquidity Pool state
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Pool {
    /// Pool authority (PDA)
    pub authority: Pubkey,
    /// Token A mint
    pub token_a_mint: Pubkey,
    /// Token B mint
    pub token_b_mint: Pubkey,
    /// Pool's token A account
    pub token_a_account: Pubkey,
    /// Pool's token B account
    pub token_b_account: Pubkey,
    /// LP token mint
    pub lp_mint: Pubkey,
    /// Token A reserve amount
    pub reserve_a: u64,
    /// Token B reserve amount
    pub reserve_b: u64,
    /// Total LP tokens minted
    pub lp_supply: u64,
    /// Fee numerator (e.g., 3 for 0.3%)
    pub fee_numerator: u64,
    /// Fee denominator (e.g., 1000 for 0.3%)
    pub fee_denominator: u64,
    /// Is pool initialized?
    pub is_initialized: bool,
    /// Pool bump seed for PDA
    pub bump: u8,
    /// Pool admin who can update fees
    /// SECURITY: Only admin can modify pool parameters
    #[serde(default)]
    pub admin: Pubkey,
}

impl Pool {
    pub const LEN: usize = 256;

    /// Create a new pool
    pub fn new(
        authority: Pubkey,
        token_a_mint: Pubkey,
        token_b_mint: Pubkey,
        token_a_account: Pubkey,
        token_b_account: Pubkey,
        lp_mint: Pubkey,
        bump: u8,
        admin: Pubkey,
    ) -> Self {
        Self {
            authority,
            token_a_mint,
            token_b_mint,
            token_a_account,
            token_b_account,
            lp_mint,
            reserve_a: 0,
            reserve_b: 0,
            lp_supply: 0,
            fee_numerator: DEFAULT_FEE_NUMERATOR,
            fee_denominator: DEFAULT_FEE_DENOMINATOR,
            is_initialized: true,
            bump,
            admin,
        }
    }

    /// Serialize pool to bytes
    pub fn pack(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize pool from bytes
    pub fn unpack(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }

    /// Calculate the amount of token B received for swapping amount_a of token A
    /// Uses constant product formula: (x + dx)(y - dy) = xy
    /// dy = y * dx / (x + dx)
    pub fn calculate_swap_output(&self, amount_in: u64, is_a_to_b: bool) -> Option<u64> {
        let (reserve_in, reserve_out) = if is_a_to_b {
            (self.reserve_a, self.reserve_b)
        } else {
            (self.reserve_b, self.reserve_a)
        };

        if reserve_in == 0 || reserve_out == 0 {
            return None;
        }

        // Apply fee
        let amount_in_with_fee = (amount_in as u128)
            .checked_mul(self.fee_denominator.saturating_sub(self.fee_numerator) as u128)?;

        let numerator = amount_in_with_fee.checked_mul(reserve_out as u128)?;
        let denominator = (reserve_in as u128)
            .checked_mul(self.fee_denominator as u128)?
            .checked_add(amount_in_with_fee)?;

        let amount_out = numerator.checked_div(denominator)?;

        // Ensure output doesn't exceed reserves
        if amount_out >= reserve_out as u128 {
            return None;
        }

        Some(amount_out as u64)
    }

    /// Calculate LP tokens to mint for adding liquidity
    pub fn calculate_lp_tokens(
        &self,
        amount_a: u64,
        amount_b: u64,
    ) -> Option<(u64, u64, u64)> {
        if self.lp_supply == 0 {
            // Initial liquidity: LP tokens = sqrt(amount_a * amount_b) - MINIMUM_LIQUIDITY
            let liquidity = integer_sqrt(
                (amount_a as u128).checked_mul(amount_b as u128)?
            )?.saturating_sub(MINIMUM_LIQUIDITY as u128);

            if liquidity == 0 {
                return None;
            }

            Some((amount_a, amount_b, liquidity as u64))
        } else {
            // Proportional liquidity
            let liquidity_a = (amount_a as u128)
                .checked_mul(self.lp_supply as u128)?
                .checked_div(self.reserve_a as u128)?;

            let liquidity_b = (amount_b as u128)
                .checked_mul(self.lp_supply as u128)?
                .checked_div(self.reserve_b as u128)?;

            // Take minimum to maintain ratio
            let liquidity = liquidity_a.min(liquidity_b);

            // Calculate actual amounts needed
            let actual_a = if liquidity == liquidity_a {
                amount_a
            } else {
                ((liquidity as u128)
                    .checked_mul(self.reserve_a as u128)?
                    .checked_div(self.lp_supply as u128)? as u64)
                    .saturating_add(1) // Round up
            };

            let actual_b = if liquidity == liquidity_b {
                amount_b
            } else {
                ((liquidity as u128)
                    .checked_mul(self.reserve_b as u128)?
                    .checked_div(self.lp_supply as u128)? as u64)
                    .saturating_add(1) // Round up
            };

            Some((actual_a, actual_b, liquidity as u64))
        }
    }

    /// Calculate tokens to return when removing liquidity
    pub fn calculate_withdraw_amounts(&self, lp_tokens: u64) -> Option<(u64, u64)> {
        if self.lp_supply == 0 || lp_tokens > self.lp_supply {
            return None;
        }

        let amount_a = (lp_tokens as u128)
            .checked_mul(self.reserve_a as u128)?
            .checked_div(self.lp_supply as u128)? as u64;

        let amount_b = (lp_tokens as u128)
            .checked_mul(self.reserve_b as u128)?
            .checked_div(self.lp_supply as u128)? as u64;

        Some((amount_a, amount_b))
    }

    /// Get current price of token A in terms of token B
    pub fn get_price_a_to_b(&self) -> Option<f64> {
        if self.reserve_a == 0 {
            return None;
        }
        Some(self.reserve_b as f64 / self.reserve_a as f64)
    }

    /// Get current price of token B in terms of token A
    pub fn get_price_b_to_a(&self) -> Option<f64> {
        if self.reserve_b == 0 {
            return None;
        }
        Some(self.reserve_a as f64 / self.reserve_b as f64)
    }
}

/// AMM Program instructions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AmmInstruction {
    /// Initialize a new liquidity pool
    /// Accounts: [pool, authority, token_a_mint, token_b_mint, token_a_account, token_b_account, lp_mint, payer]
    InitializePool {
        /// Fee numerator
        fee_numerator: u64,
        /// Fee denominator
        fee_denominator: u64,
        /// Bump seed
        bump: u8,
    },

    /// Add liquidity to pool
    /// Accounts: [pool, user_token_a, user_token_b, pool_token_a, pool_token_b, lp_mint, user_lp, user, token_program]
    AddLiquidity {
        /// Maximum amount of token A to deposit
        amount_a_max: u64,
        /// Maximum amount of token B to deposit
        amount_b_max: u64,
        /// Minimum LP tokens to receive
        min_lp_tokens: u64,
    },

    /// Remove liquidity from pool
    /// Accounts: [pool, user_token_a, user_token_b, pool_token_a, pool_token_b, lp_mint, user_lp, user, token_program]
    RemoveLiquidity {
        /// LP tokens to burn
        lp_tokens: u64,
        /// Minimum token A to receive
        min_amount_a: u64,
        /// Minimum token B to receive
        min_amount_b: u64,
    },

    /// Swap tokens
    /// Accounts: [pool, user_token_in, user_token_out, pool_token_in, pool_token_out, user, token_program]
    Swap {
        /// Amount of input tokens
        amount_in: u64,
        /// Minimum amount of output tokens (slippage protection)
        minimum_amount_out: u64,
        /// Swap direction: true = A to B, false = B to A
        a_to_b: bool,
    },

    /// Update pool fees (admin only)
    /// Accounts: [pool, admin]
    UpdateFees {
        fee_numerator: u64,
        fee_denominator: u64,
    },
}

impl AmmInstruction {
    /// Serialize instruction to bytes
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize instruction from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}

/// AMM Program implementation
pub struct AmmProgram;

impl AmmProgram {
    /// Process an AMM instruction
    pub fn process(
        instruction: &AmmInstruction,
        accounts: &mut [Account],
    ) -> Result<(), AmmError> {
        match instruction {
            AmmInstruction::InitializePool { fee_numerator, fee_denominator, bump } => {
                Self::process_initialize_pool(accounts, *fee_numerator, *fee_denominator, *bump)
            }
            AmmInstruction::AddLiquidity { amount_a_max, amount_b_max, min_lp_tokens } => {
                Self::process_add_liquidity(accounts, *amount_a_max, *amount_b_max, *min_lp_tokens)
            }
            AmmInstruction::RemoveLiquidity { lp_tokens, min_amount_a, min_amount_b } => {
                Self::process_remove_liquidity(accounts, *lp_tokens, *min_amount_a, *min_amount_b)
            }
            AmmInstruction::Swap { amount_in, minimum_amount_out, a_to_b } => {
                Self::process_swap(accounts, *amount_in, *minimum_amount_out, *a_to_b)
            }
            AmmInstruction::UpdateFees { fee_numerator, fee_denominator } => {
                Self::process_update_fees(accounts, *fee_numerator, *fee_denominator)
            }
        }
    }

    fn process_initialize_pool(
        accounts: &mut [Account],
        fee_numerator: u64,
        fee_denominator: u64,
        bump: u8,
    ) -> Result<(), AmmError> {
        if accounts.len() < 8 {
            return Err(AmmError::NotEnoughAccounts);
        }

        // Validate fee
        if fee_denominator == 0 || fee_numerator >= fee_denominator {
            return Err(AmmError::InvalidFee);
        }

        // Check not already initialized
        if !accounts[0].data.is_empty() {
            if let Some(existing) = Pool::unpack(&accounts[0].data) {
                if existing.is_initialized {
                    return Err(AmmError::AlreadyInitialized);
                }
            }
        }

        // Get admin from payer account first (before mutable borrow)
        let admin = accounts[7].owner;

        // Create pool (simplified - in real impl would extract pubkeys from accounts)
        // The payer (accounts[7]) becomes the pool admin
        let pool = Pool {
            authority: Pubkey::zero(),
            token_a_mint: Pubkey::zero(),
            token_b_mint: Pubkey::zero(),
            token_a_account: Pubkey::zero(),
            token_b_account: Pubkey::zero(),
            lp_mint: Pubkey::zero(),
            reserve_a: 0,
            reserve_b: 0,
            lp_supply: 0,
            fee_numerator,
            fee_denominator,
            is_initialized: true,
            bump,
            admin,
        };

        let pool_account = &mut accounts[0];
        pool_account.data = pool.pack();
        pool_account.owner = AMM_PROGRAM_ID;

        Ok(())
    }

    fn process_add_liquidity(
        accounts: &mut [Account],
        amount_a_max: u64,
        amount_b_max: u64,
        min_lp_tokens: u64,
    ) -> Result<(), AmmError> {
        if accounts.len() < 9 {
            return Err(AmmError::NotEnoughAccounts);
        }

        let pool_data = accounts[0].data.clone();
        let mut pool = Pool::unpack(&pool_data).ok_or(AmmError::InvalidPool)?;

        if !pool.is_initialized {
            return Err(AmmError::UninitializedPool);
        }

        // Calculate LP tokens to mint
        let (actual_a, actual_b, lp_tokens) = pool
            .calculate_lp_tokens(amount_a_max, amount_b_max)
            .ok_or(AmmError::MathError)?;

        if lp_tokens < min_lp_tokens {
            return Err(AmmError::SlippageExceeded);
        }

        // Update pool state
        pool.reserve_a = pool.reserve_a.checked_add(actual_a).ok_or(AmmError::MathError)?;
        pool.reserve_b = pool.reserve_b.checked_add(actual_b).ok_or(AmmError::MathError)?;
        pool.lp_supply = pool.lp_supply.checked_add(lp_tokens).ok_or(AmmError::MathError)?;

        accounts[0].data = pool.pack();

        Ok(())
    }

    fn process_remove_liquidity(
        accounts: &mut [Account],
        lp_tokens: u64,
        min_amount_a: u64,
        min_amount_b: u64,
    ) -> Result<(), AmmError> {
        if accounts.len() < 9 {
            return Err(AmmError::NotEnoughAccounts);
        }

        let pool_data = accounts[0].data.clone();
        let mut pool = Pool::unpack(&pool_data).ok_or(AmmError::InvalidPool)?;

        if !pool.is_initialized {
            return Err(AmmError::UninitializedPool);
        }

        // Calculate tokens to return
        let (amount_a, amount_b) = pool
            .calculate_withdraw_amounts(lp_tokens)
            .ok_or(AmmError::MathError)?;

        if amount_a < min_amount_a || amount_b < min_amount_b {
            return Err(AmmError::SlippageExceeded);
        }

        // Update pool state
        pool.reserve_a = pool.reserve_a.checked_sub(amount_a).ok_or(AmmError::MathError)?;
        pool.reserve_b = pool.reserve_b.checked_sub(amount_b).ok_or(AmmError::MathError)?;
        pool.lp_supply = pool.lp_supply.checked_sub(lp_tokens).ok_or(AmmError::MathError)?;

        accounts[0].data = pool.pack();

        Ok(())
    }

    fn process_swap(
        accounts: &mut [Account],
        amount_in: u64,
        minimum_amount_out: u64,
        a_to_b: bool,
    ) -> Result<(), AmmError> {
        if accounts.len() < 7 {
            return Err(AmmError::NotEnoughAccounts);
        }

        let pool_data = accounts[0].data.clone();
        let mut pool = Pool::unpack(&pool_data).ok_or(AmmError::InvalidPool)?;

        if !pool.is_initialized {
            return Err(AmmError::UninitializedPool);
        }

        // Calculate output amount
        let amount_out = pool
            .calculate_swap_output(amount_in, a_to_b)
            .ok_or(AmmError::InsufficientLiquidity)?;

        if amount_out < minimum_amount_out {
            return Err(AmmError::SlippageExceeded);
        }

        // Update reserves
        if a_to_b {
            pool.reserve_a = pool.reserve_a.checked_add(amount_in).ok_or(AmmError::MathError)?;
            pool.reserve_b = pool.reserve_b.checked_sub(amount_out).ok_or(AmmError::MathError)?;
        } else {
            pool.reserve_b = pool.reserve_b.checked_add(amount_in).ok_or(AmmError::MathError)?;
            pool.reserve_a = pool.reserve_a.checked_sub(amount_out).ok_or(AmmError::MathError)?;
        }

        accounts[0].data = pool.pack();

        Ok(())
    }

    fn process_update_fees(
        accounts: &mut [Account],
        fee_numerator: u64,
        fee_denominator: u64,
    ) -> Result<(), AmmError> {
        if accounts.len() < 2 {
            return Err(AmmError::NotEnoughAccounts);
        }

        let pool_data = accounts[0].data.clone();
        let mut pool = Pool::unpack(&pool_data).ok_or(AmmError::InvalidPool)?;

        // SECURITY FIX: Verify admin authorization
        let admin_account = &accounts[1];

        // SECURITY: Admin account must be a signer
        if !admin_account.is_signer {
            return Err(AmmError::Unauthorized);
        }

        // SECURITY: Verify the signer is the pool admin
        if admin_account.owner != pool.admin {
            return Err(AmmError::Unauthorized);
        }

        // Validate fee denominator is not zero
        if fee_denominator == 0 {
            return Err(AmmError::InvalidFee);
        }

        // SECURITY FIX: Validate fee is within bounds
        // fee_numerator/fee_denominator must be <= MAX_FEE_NUMERATOR/MAX_FEE_DENOMINATOR (10%)
        // Cross multiply to avoid floating point: fee_num * MAX_FEE_DEN <= MAX_FEE_NUM * fee_den
        let fee_check = (fee_numerator as u128)
            .checked_mul(MAX_FEE_DENOMINATOR as u128)
            .ok_or(AmmError::MathError)?;
        let max_fee_check = (MAX_FEE_NUMERATOR as u128)
            .checked_mul(fee_denominator as u128)
            .ok_or(AmmError::MathError)?;

        if fee_check > max_fee_check {
            return Err(AmmError::FeeTooHigh);
        }

        // SECURITY: Fee numerator must be less than denominator
        if fee_numerator >= fee_denominator {
            return Err(AmmError::InvalidFee);
        }

        pool.fee_numerator = fee_numerator;
        pool.fee_denominator = fee_denominator;

        accounts[0].data = pool.pack();

        Ok(())
    }
}

/// Integer square root
fn integer_sqrt(n: u128) -> Option<u128> {
    if n == 0 {
        return Some(0);
    }

    let mut x = n;
    let mut y = (x + 1) / 2;

    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }

    Some(x)
}

/// AMM program errors
#[derive(Debug, Clone, PartialEq)]
pub enum AmmError {
    NotEnoughAccounts,
    InvalidPool,
    UninitializedPool,
    AlreadyInitialized,
    InvalidFee,
    /// Fee exceeds maximum allowed (10%)
    FeeTooHigh,
    InsufficientLiquidity,
    SlippageExceeded,
    MathError,
    Unauthorized,
    InvalidInstruction,
}

impl std::fmt::Display for AmmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for AmmError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swap_calculation() {
        let mut pool = Pool::default();
        pool.reserve_a = 1000000; // 1M token A
        pool.reserve_b = 1000000; // 1M token B
        pool.fee_numerator = 3;
        pool.fee_denominator = 1000;
        pool.is_initialized = true;

        // Swap 1000 token A for token B
        let output = pool.calculate_swap_output(1000, true).unwrap();

        // Should get ~996 tokens (minus 0.3% fee and slippage)
        assert!(output > 990 && output < 1000);

        // Larger swap should have more slippage
        let large_output = pool.calculate_swap_output(100000, true).unwrap();
        let ratio = large_output as f64 / 100000.0;
        assert!(ratio < 0.92); // More than 8% slippage for 10% of pool
    }

    #[test]
    fn test_liquidity_calculation() {
        let mut pool = Pool::default();
        pool.is_initialized = true;

        // Initial liquidity
        let (a, b, lp) = pool.calculate_lp_tokens(10000, 10000).unwrap();
        assert_eq!(a, 10000);
        assert_eq!(b, 10000);
        assert_eq!(lp, 10000 - MINIMUM_LIQUIDITY); // sqrt(10000*10000) - 1000

        // Set pool state
        pool.reserve_a = 10000;
        pool.reserve_b = 10000;
        pool.lp_supply = lp;

        // Add more liquidity (proportional)
        let (a2, b2, lp2) = pool.calculate_lp_tokens(5000, 5000).unwrap();
        assert!(a2 <= 5000);
        assert!(b2 <= 5000);
        assert!(lp2 > 0);
    }

    #[test]
    fn test_withdraw_calculation() {
        let mut pool = Pool::default();
        pool.reserve_a = 10000;
        pool.reserve_b = 20000;
        pool.lp_supply = 10000;
        pool.is_initialized = true;

        // Withdraw 10% of LP tokens
        let (a, b) = pool.calculate_withdraw_amounts(1000).unwrap();
        assert_eq!(a, 1000); // 10% of 10000
        assert_eq!(b, 2000); // 10% of 20000
    }

    #[test]
    fn test_price() {
        let mut pool = Pool::default();
        pool.reserve_a = 1000;
        pool.reserve_b = 2000;
        pool.is_initialized = true;

        let price_a_to_b = pool.get_price_a_to_b().unwrap();
        assert!((price_a_to_b - 2.0).abs() < 0.001);

        let price_b_to_a = pool.get_price_b_to_a().unwrap();
        assert!((price_b_to_a - 0.5).abs() < 0.001);
    }
}
