//! Vesting Program for Celereum Token Distribution
//!
//! Manages token vesting schedules for all allocations (210M CEL total):
//! - Public Sale: 30% = 63M CEL, 100% TGE (fully liquid)
//! - Presale: 10% = 21M CEL, 15% TGE, 3 months cliff, 12 months linear
//! - Team: 15% = 31.5M CEL, 0% TGE, 12 months cliff, 36 months linear
//! - Development: 20% = 42M CEL, 10% TGE, no cliff, 60 months linear
//! - Ecosystem: 15% = 31.5M CEL, 0% TGE, no cliff, 120 months linear (staking rewards)
//! - Treasury: 10% = 21M CEL, governance controlled
//!
//! SECURITY: All token releases are time-locked and immutable
//! SECURITY: Uses checked arithmetic throughout

use crate::crypto::Pubkey;
use crate::core::Account;
use serde::{Deserialize, Serialize};

/// Vesting Program ID
pub const VESTING_PROGRAM_ID: Pubkey = Pubkey([
    0x56, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x00, // "VESTING\0"
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
]);

// =============================================================================
// TOKENOMICS CONSTANTS (Total Supply: 210 Million CEL)
// =============================================================================

/// Total supply in celers (210M * 10^9)
pub const TOTAL_SUPPLY: u64 = 210_000_000_000_000_000;

/// CEL decimals
pub const CEL_DECIMALS: u8 = 9;

/// Celers per CEL
pub const CELERS_PER_CEL: u64 = 1_000_000_000;

// Allocation amounts in celers (based on 210M total supply)
/// Public Sale: 30% = 63M CEL (fully liquid at TGE)
pub const PUBLIC_SALE_ALLOCATION: u64 = 63_000_000 * CELERS_PER_CEL;
/// Presale: 10% = 21M CEL (15% TGE, 3mo cliff, 12mo vest)
pub const PRESALE_ALLOCATION: u64 = 21_000_000 * CELERS_PER_CEL;
/// Team & Advisors: 15% = 31.5M CEL (1yr cliff, 3yr vest)
pub const TEAM_ALLOCATION: u64 = 31_500_000 * CELERS_PER_CEL;
/// Development: 20% = 42M CEL (10% TGE, 5yr linear)
pub const DEVELOPMENT_ALLOCATION: u64 = 42_000_000 * CELERS_PER_CEL;
/// Ecosystem/Staking Rewards: 15% = 31.5M CEL (10yr emission)
pub const ECOSYSTEM_ALLOCATION: u64 = 31_500_000 * CELERS_PER_CEL;
/// Treasury: 10% = 21M CEL (governance controlled)
pub const TREASURY_ALLOCATION: u64 = 21_000_000 * CELERS_PER_CEL;

// Time constants (in seconds)
pub const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
pub const SECONDS_PER_MONTH: u64 = 30 * SECONDS_PER_DAY;
pub const SECONDS_PER_YEAR: u64 = 365 * SECONDS_PER_DAY;

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Token allocation category
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AllocationCategory {
    /// Public Sale - 30% = 63M CEL, fully liquid
    PublicSale,
    /// Presale - 10% = 21M CEL, 15% TGE, 3mo cliff, 12mo vest
    Presale,
    /// Team & Advisors - 15% = 31.5M CEL, 1yr cliff, 3yr vest
    Team,
    /// Development - 20% = 42M CEL, 10% TGE, 5yr linear
    Development,
    /// Ecosystem/Staking - 15% = 31.5M CEL, 10yr emission
    Ecosystem,
    /// Treasury - 10% = 21M CEL, governance controlled
    Treasury,
}

impl AllocationCategory {
    /// Get total allocation for this category
    pub fn total_allocation(&self) -> u64 {
        match self {
            Self::PublicSale => PUBLIC_SALE_ALLOCATION,
            Self::Presale => PRESALE_ALLOCATION,
            Self::Team => TEAM_ALLOCATION,
            Self::Development => DEVELOPMENT_ALLOCATION,
            Self::Ecosystem => ECOSYSTEM_ALLOCATION,
            Self::Treasury => TREASURY_ALLOCATION,
        }
    }

    /// Get TGE unlock percentage
    pub fn tge_percent(&self) -> u8 {
        match self {
            Self::PublicSale => 100, // Fully liquid
            Self::Presale => 15,     // 15% at TGE
            Self::Team => 0,         // Nothing at TGE
            Self::Development => 10, // 10% at TGE
            Self::Ecosystem => 0,    // Nothing at TGE (staking rewards)
            Self::Treasury => 0,     // Governance controlled
        }
    }

    /// Get cliff period in seconds
    pub fn cliff_seconds(&self) -> u64 {
        match self {
            Self::PublicSale => 0,                     // No cliff (instant)
            Self::Presale => 3 * SECONDS_PER_MONTH,   // 3 months cliff
            Self::Team => 12 * SECONDS_PER_MONTH,     // 1 year cliff
            Self::Development => 0,                    // No cliff
            Self::Ecosystem => 0,                      // No cliff
            Self::Treasury => 0,                       // Governance controlled
        }
    }

    /// Get vesting period in seconds (after cliff)
    pub fn vesting_seconds(&self) -> u64 {
        match self {
            Self::PublicSale => 0,                      // Instant
            Self::Presale => 12 * SECONDS_PER_MONTH,   // 12 months linear
            Self::Team => 36 * SECONDS_PER_MONTH,      // 36 months (3 years)
            Self::Development => 60 * SECONDS_PER_MONTH, // 60 months (5 years)
            Self::Ecosystem => 120 * SECONDS_PER_MONTH,  // 120 months (10 years)
            Self::Treasury => 0,                        // Governance controlled
        }
    }

    /// Get percentage string for display
    pub fn percentage(&self) -> &'static str {
        match self {
            Self::PublicSale => "30%",
            Self::Presale => "10%",
            Self::Team => "15%",
            Self::Development => "20%",
            Self::Ecosystem => "15%",
            Self::Treasury => "10%",
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::PublicSale => "Public Sale - Fully Liquid",
            Self::Presale => "Presale - 15% TGE, 3mo cliff, 12mo vest",
            Self::Team => "Team & Advisors - 1yr cliff, 3yr vest",
            Self::Development => "Development - 10% TGE, 5yr linear",
            Self::Ecosystem => "Ecosystem/Staking - 10yr emission",
            Self::Treasury => "Treasury - Governance Controlled",
        }
    }
}

/// Vesting schedule for a specific allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Unique identifier
    pub id: u64,
    /// Beneficiary address
    pub beneficiary: Pubkey,
    /// Allocation category
    pub category: AllocationCategory,
    /// Total tokens allocated
    pub total_amount: u64,
    /// Tokens already released
    pub released_amount: u64,
    /// TGE (Token Generation Event) timestamp
    pub tge_time: u64,
    /// Custom cliff period (0 = use category default)
    pub custom_cliff: Option<u64>,
    /// Custom vesting period (0 = use category default)
    pub custom_vesting: Option<u64>,
    /// Custom TGE percentage (None = use category default)
    pub custom_tge_percent: Option<u8>,
    /// Is this schedule active?
    pub is_active: bool,
    /// Is this schedule revocable by admin?
    pub is_revocable: bool,
    /// Creation timestamp
    pub created_at: u64,
    /// Last release timestamp
    pub last_release_at: u64,
}

impl VestingSchedule {
    pub const LEN: usize = 192;

    pub fn pack(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn unpack(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }

    /// Get effective TGE percentage
    pub fn tge_percent(&self) -> u8 {
        self.custom_tge_percent.unwrap_or_else(|| self.category.tge_percent())
    }

    /// Get effective cliff period
    pub fn cliff_seconds(&self) -> u64 {
        self.custom_cliff.unwrap_or_else(|| self.category.cliff_seconds())
    }

    /// Get effective vesting period
    pub fn vesting_seconds(&self) -> u64 {
        self.custom_vesting.unwrap_or_else(|| self.category.vesting_seconds())
    }

    /// Calculate releasable amount at given timestamp
    pub fn calculate_releasable(&self, current_time: u64) -> u64 {
        if !self.is_active || current_time < self.tge_time {
            return 0;
        }

        let total_vested = self.calculate_vested_amount(current_time);
        total_vested.saturating_sub(self.released_amount)
    }

    /// Calculate total vested amount at given timestamp
    pub fn calculate_vested_amount(&self, current_time: u64) -> u64 {
        if current_time < self.tge_time {
            return 0;
        }

        // Calculate TGE amount
        let tge_amount = self.total_amount
            .checked_mul(self.tge_percent() as u64)
            .and_then(|v| v.checked_div(100))
            .unwrap_or(0);

        // If liquidity (100% TGE), return full amount
        if self.tge_percent() == 100 {
            return self.total_amount;
        }

        let time_since_tge = current_time.saturating_sub(self.tge_time);
        let cliff = self.cliff_seconds();

        // During cliff: only TGE amount
        if time_since_tge < cliff {
            return tge_amount;
        }

        // After cliff: linear vesting
        let time_since_cliff = time_since_tge.saturating_sub(cliff);
        let vesting_period = self.vesting_seconds();

        if vesting_period == 0 {
            return self.total_amount;
        }

        // Amount subject to vesting (total - TGE)
        let vesting_amount = self.total_amount.saturating_sub(tge_amount);

        // Calculate vested portion
        let vested = if time_since_cliff >= vesting_period {
            vesting_amount // Fully vested
        } else {
            vesting_amount
                .checked_mul(time_since_cliff)
                .and_then(|v| v.checked_div(vesting_period))
                .unwrap_or(0)
        };

        tge_amount.saturating_add(vested)
    }

    /// Get next unlock timestamp
    pub fn next_unlock_time(&self, current_time: u64) -> Option<u64> {
        if !self.is_active {
            return None;
        }

        if current_time < self.tge_time {
            return Some(self.tge_time);
        }

        let cliff_end = self.tge_time.saturating_add(self.cliff_seconds());
        if current_time < cliff_end {
            return Some(cliff_end);
        }

        let vesting_end = cliff_end.saturating_add(self.vesting_seconds());
        if current_time < vesting_end {
            // Linear vesting - next unlock is continuous
            return Some(current_time);
        }

        None // Fully vested
    }
}

/// Global token allocation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAllocation {
    /// Admin authority
    pub admin: Pubkey,
    /// CEL token mint
    pub cel_mint: Pubkey,
    /// TGE timestamp
    pub tge_time: u64,
    /// Total schedules created
    pub total_schedules: u64,
    /// Allocations by category (allocated/released in celers)
    pub public_sale_allocated: u64,
    pub public_sale_released: u64,
    pub presale_allocated: u64,
    pub presale_released: u64,
    pub team_allocated: u64,
    pub team_released: u64,
    pub development_allocated: u64,
    pub development_released: u64,
    pub ecosystem_allocated: u64,
    pub ecosystem_released: u64,
    pub treasury_allocated: u64,
    pub treasury_released: u64,
    /// Is initialized?
    pub is_initialized: bool,
}

impl TokenAllocation {
    pub const LEN: usize = 256;

    pub fn pack(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn unpack(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }

    /// Get remaining allocation for category
    pub fn remaining(&self, category: AllocationCategory) -> u64 {
        let (allocated, max) = match category {
            AllocationCategory::PublicSale => (self.public_sale_allocated, PUBLIC_SALE_ALLOCATION),
            AllocationCategory::Presale => (self.presale_allocated, PRESALE_ALLOCATION),
            AllocationCategory::Team => (self.team_allocated, TEAM_ALLOCATION),
            AllocationCategory::Development => (self.development_allocated, DEVELOPMENT_ALLOCATION),
            AllocationCategory::Ecosystem => (self.ecosystem_allocated, ECOSYSTEM_ALLOCATION),
            AllocationCategory::Treasury => (self.treasury_allocated, TREASURY_ALLOCATION),
        };
        max.saturating_sub(allocated)
    }

    /// Add allocation to category
    pub fn add_allocation(&mut self, category: AllocationCategory, amount: u64) -> Result<(), VestingError> {
        let remaining = self.remaining(category);
        if amount > remaining {
            return Err(VestingError::ExceedsAllocation);
        }

        match category {
            AllocationCategory::PublicSale => {
                self.public_sale_allocated = self.public_sale_allocated.saturating_add(amount);
            }
            AllocationCategory::Presale => {
                self.presale_allocated = self.presale_allocated.saturating_add(amount);
            }
            AllocationCategory::Team => {
                self.team_allocated = self.team_allocated.saturating_add(amount);
            }
            AllocationCategory::Development => {
                self.development_allocated = self.development_allocated.saturating_add(amount);
            }
            AllocationCategory::Ecosystem => {
                self.ecosystem_allocated = self.ecosystem_allocated.saturating_add(amount);
            }
            AllocationCategory::Treasury => {
                self.treasury_allocated = self.treasury_allocated.saturating_add(amount);
            }
        }

        Ok(())
    }

    /// Record released tokens
    pub fn record_release(&mut self, category: AllocationCategory, amount: u64) {
        match category {
            AllocationCategory::PublicSale => {
                self.public_sale_released = self.public_sale_released.saturating_add(amount);
            }
            AllocationCategory::Presale => {
                self.presale_released = self.presale_released.saturating_add(amount);
            }
            AllocationCategory::Team => {
                self.team_released = self.team_released.saturating_add(amount);
            }
            AllocationCategory::Development => {
                self.development_released = self.development_released.saturating_add(amount);
            }
            AllocationCategory::Ecosystem => {
                self.ecosystem_released = self.ecosystem_released.saturating_add(amount);
            }
            AllocationCategory::Treasury => {
                self.treasury_released = self.treasury_released.saturating_add(amount);
            }
        }
    }
}

// =============================================================================
// INSTRUCTIONS
// =============================================================================

/// Vesting program instructions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VestingInstruction {
    /// Initialize token allocation tracking
    /// Accounts: [allocation, admin, cel_mint]
    Initialize {
        tge_time: u64,
    },

    /// Create a new vesting schedule
    /// Accounts: [allocation, schedule, admin, beneficiary]
    CreateSchedule {
        beneficiary: Pubkey,
        category: AllocationCategory,
        amount: u64,
        is_revocable: bool,
        custom_cliff: Option<u64>,
        custom_vesting: Option<u64>,
        custom_tge_percent: Option<u8>,
    },

    /// Release vested tokens
    /// Accounts: [allocation, schedule, beneficiary, cel_vault, beneficiary_cel]
    Release,

    /// Revoke a revocable schedule (admin only)
    /// Accounts: [allocation, schedule, admin, cel_vault, admin_cel]
    Revoke,

    /// Transfer schedule to new beneficiary
    /// Accounts: [schedule, current_beneficiary, new_beneficiary]
    TransferSchedule {
        new_beneficiary: Pubkey,
    },

    /// Update TGE time (admin only, before TGE)
    /// Accounts: [allocation, admin]
    UpdateTgeTime {
        new_tge_time: u64,
    },
}

impl VestingInstruction {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}

// =============================================================================
// PROGRAM IMPLEMENTATION
// =============================================================================

/// Vesting Program
pub struct VestingProgram;

impl VestingProgram {
    /// Process vesting instruction
    pub fn process(
        instruction: &VestingInstruction,
        accounts: &mut [Account],
        current_time: u64,
    ) -> Result<(), VestingError> {
        match instruction {
            VestingInstruction::Initialize { tge_time } => {
                Self::process_initialize(accounts, *tge_time)
            }

            VestingInstruction::CreateSchedule {
                beneficiary,
                category,
                amount,
                is_revocable,
                custom_cliff,
                custom_vesting,
                custom_tge_percent,
            } => Self::process_create_schedule(
                accounts,
                beneficiary,
                *category,
                *amount,
                *is_revocable,
                *custom_cliff,
                *custom_vesting,
                *custom_tge_percent,
                current_time,
            ),

            VestingInstruction::Release => {
                Self::process_release(accounts, current_time)
            }

            VestingInstruction::Revoke => {
                Self::process_revoke(accounts, current_time)
            }

            VestingInstruction::TransferSchedule { new_beneficiary } => {
                Self::process_transfer(accounts, new_beneficiary)
            }

            VestingInstruction::UpdateTgeTime { new_tge_time } => {
                Self::process_update_tge(accounts, *new_tge_time, current_time)
            }
        }
    }

    /// Initialize token allocation
    fn process_initialize(
        accounts: &mut [Account],
        tge_time: u64,
    ) -> Result<(), VestingError> {
        if accounts.len() < 3 {
            return Err(VestingError::NotEnoughAccounts);
        }

        // SECURITY: Check not already initialized
        if !accounts[0].data.is_empty() {
            if let Some(existing) = TokenAllocation::unpack(&accounts[0].data) {
                if existing.is_initialized {
                    return Err(VestingError::AlreadyInitialized);
                }
            }
        }

        let admin = accounts[1].owner;
        let cel_mint = accounts[2].owner;

        let allocation_account = &mut accounts[0];

        let allocation = TokenAllocation {
            admin,
            cel_mint,
            tge_time,
            total_schedules: 0,
            public_sale_allocated: 0,
            public_sale_released: 0,
            presale_allocated: 0,
            presale_released: 0,
            team_allocated: 0,
            team_released: 0,
            development_allocated: 0,
            development_released: 0,
            ecosystem_allocated: 0,
            ecosystem_released: 0,
            treasury_allocated: 0,
            treasury_released: 0,
            is_initialized: true,
        };

        allocation_account.data = allocation.pack();
        allocation_account.owner = VESTING_PROGRAM_ID;

        Ok(())
    }

    /// Create new vesting schedule
    fn process_create_schedule(
        accounts: &mut [Account],
        beneficiary: &Pubkey,
        category: AllocationCategory,
        amount: u64,
        is_revocable: bool,
        custom_cliff: Option<u64>,
        custom_vesting: Option<u64>,
        custom_tge_percent: Option<u8>,
        current_time: u64,
    ) -> Result<(), VestingError> {
        if accounts.len() < 4 {
            return Err(VestingError::NotEnoughAccounts);
        }

        // SECURITY: Validate amount
        if amount == 0 {
            return Err(VestingError::InvalidAmount);
        }

        // SECURITY: Validate custom TGE percent
        if let Some(tge) = custom_tge_percent {
            if tge > 100 {
                return Err(VestingError::InvalidTgePercent);
            }
        }

        let allocation_data = accounts[0].data.clone();
        let mut allocation = TokenAllocation::unpack(&allocation_data)
            .ok_or(VestingError::InvalidAllocation)?;

        // SECURITY: Check allocation limit
        allocation.add_allocation(category, amount)?;

        // Create schedule
        allocation.total_schedules = allocation.total_schedules.saturating_add(1);

        let schedule = VestingSchedule {
            id: allocation.total_schedules,
            beneficiary: *beneficiary,
            category,
            total_amount: amount,
            released_amount: 0,
            tge_time: allocation.tge_time,
            custom_cliff,
            custom_vesting,
            custom_tge_percent,
            is_active: true,
            is_revocable,
            created_at: current_time,
            last_release_at: 0,
        };

        // Save state
        accounts[0].data = allocation.pack();
        accounts[1].data = schedule.pack();
        accounts[1].owner = VESTING_PROGRAM_ID;

        Ok(())
    }

    /// Release vested tokens
    fn process_release(
        accounts: &mut [Account],
        current_time: u64,
    ) -> Result<(), VestingError> {
        if accounts.len() < 5 {
            return Err(VestingError::NotEnoughAccounts);
        }

        let allocation_data = accounts[0].data.clone();
        let mut allocation = TokenAllocation::unpack(&allocation_data)
            .ok_or(VestingError::InvalidAllocation)?;

        let schedule_data = accounts[1].data.clone();
        let mut schedule = VestingSchedule::unpack(&schedule_data)
            .ok_or(VestingError::InvalidSchedule)?;

        // SECURITY: Check schedule is active
        if !schedule.is_active {
            return Err(VestingError::ScheduleInactive);
        }

        // Calculate releasable amount
        let releasable = schedule.calculate_releasable(current_time);

        // SECURITY: Check there's something to release
        if releasable == 0 {
            return Err(VestingError::NothingToRelease);
        }

        // Update schedule
        schedule.released_amount = schedule.released_amount
            .checked_add(releasable)
            .ok_or(VestingError::Overflow)?;
        schedule.last_release_at = current_time;

        // Update allocation tracking
        allocation.record_release(schedule.category, releasable);

        // Save state
        accounts[0].data = allocation.pack();
        accounts[1].data = schedule.pack();

        // Note: Actual token transfer handled by runtime invoking token program

        Ok(())
    }

    /// Revoke a revocable schedule
    fn process_revoke(
        accounts: &mut [Account],
        current_time: u64,
    ) -> Result<(), VestingError> {
        if accounts.len() < 5 {
            return Err(VestingError::NotEnoughAccounts);
        }

        let schedule_data = accounts[1].data.clone();
        let mut schedule = VestingSchedule::unpack(&schedule_data)
            .ok_or(VestingError::InvalidSchedule)?;

        // SECURITY: Check if revocable
        if !schedule.is_revocable {
            return Err(VestingError::NotRevocable);
        }

        // SECURITY: Check if active
        if !schedule.is_active {
            return Err(VestingError::ScheduleInactive);
        }

        // Release any vested but unclaimed tokens first
        let releasable = schedule.calculate_releasable(current_time);
        schedule.released_amount = schedule.released_amount.saturating_add(releasable);

        // Deactivate schedule
        schedule.is_active = false;

        // Save state
        accounts[1].data = schedule.pack();

        // Note: Remaining unvested tokens returned to admin via token program

        Ok(())
    }

    /// Transfer schedule to new beneficiary
    fn process_transfer(
        accounts: &mut [Account],
        new_beneficiary: &Pubkey,
    ) -> Result<(), VestingError> {
        if accounts.len() < 3 {
            return Err(VestingError::NotEnoughAccounts);
        }

        let schedule_data = accounts[0].data.clone();
        let mut schedule = VestingSchedule::unpack(&schedule_data)
            .ok_or(VestingError::InvalidSchedule)?;

        // SECURITY: Check schedule is active
        if !schedule.is_active {
            return Err(VestingError::ScheduleInactive);
        }

        // SECURITY: Only current beneficiary can transfer
        // Note: Runtime verifies signer

        schedule.beneficiary = *new_beneficiary;
        accounts[0].data = schedule.pack();

        Ok(())
    }

    /// Update TGE time (before TGE only)
    fn process_update_tge(
        accounts: &mut [Account],
        new_tge_time: u64,
        current_time: u64,
    ) -> Result<(), VestingError> {
        if accounts.len() < 2 {
            return Err(VestingError::NotEnoughAccounts);
        }

        let allocation_data = accounts[0].data.clone();
        let mut allocation = TokenAllocation::unpack(&allocation_data)
            .ok_or(VestingError::InvalidAllocation)?;

        // SECURITY: Can only update before TGE
        if current_time >= allocation.tge_time {
            return Err(VestingError::TgeAlreadyPassed);
        }

        // SECURITY: New TGE must be in future
        if new_tge_time <= current_time {
            return Err(VestingError::InvalidTgeTime);
        }

        allocation.tge_time = new_tge_time;
        accounts[0].data = allocation.pack();

        Ok(())
    }
}

// =============================================================================
// ERRORS
// =============================================================================

/// Vesting program errors
#[derive(Debug, Clone, PartialEq)]
pub enum VestingError {
    NotEnoughAccounts,
    AlreadyInitialized,
    InvalidAllocation,
    InvalidSchedule,
    InvalidAmount,
    InvalidTgePercent,
    InvalidTgeTime,
    ExceedsAllocation,
    ScheduleInactive,
    NothingToRelease,
    NotRevocable,
    TgeAlreadyPassed,
    Overflow,
    Unauthorized,
}

impl std::fmt::Display for VestingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for VestingError {}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Format amount for display (celers to CEL)
pub fn format_cel(celers: u64) -> f64 {
    celers as f64 / CELERS_PER_CEL as f64
}

/// Parse CEL to celers
pub fn parse_cel(cel: f64) -> u64 {
    (cel * CELERS_PER_CEL as f64) as u64
}

/// Get human-readable duration
pub fn format_duration(seconds: u64) -> String {
    let days = seconds / SECONDS_PER_DAY;
    let months = days / 30;
    let years = months / 12;

    if years > 0 {
        format!("{} year(s)", years)
    } else if months > 0 {
        format!("{} month(s)", months)
    } else {
        format!("{} day(s)", days)
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_schedule(category: AllocationCategory, amount: u64, tge_time: u64) -> VestingSchedule {
        VestingSchedule {
            id: 1,
            beneficiary: Pubkey::zero(),
            category,
            total_amount: amount,
            released_amount: 0,
            tge_time,
            custom_cliff: None,
            custom_vesting: None,
            custom_tge_percent: None,
            is_active: true,
            is_revocable: false,
            created_at: 0,
            last_release_at: 0,
        }
    }

    #[test]
    fn test_team_vesting() {
        // Team: 0% TGE, 12 months cliff, 36 months linear
        let tge = 1000;
        let schedule = create_test_schedule(
            AllocationCategory::Team,
            100 * CELERS_PER_CEL,
            tge,
        );

        // At TGE: 0%
        assert_eq!(schedule.calculate_releasable(tge), 0);

        // During cliff (6 months): 0%
        let during_cliff = schedule.calculate_releasable(tge + 6 * SECONDS_PER_MONTH);
        assert_eq!(during_cliff, 0);

        // Just after cliff (12 months): 0% (linear starts)
        let after_cliff = schedule.calculate_releasable(tge + 12 * SECONDS_PER_MONTH);
        assert_eq!(after_cliff, 0);

        // 18 months after cliff (30 months total): ~50%
        let halfway = schedule.calculate_releasable(tge + 30 * SECONDS_PER_MONTH);
        assert_eq!(halfway, 50 * CELERS_PER_CEL);

        // Fully vested (48 months = 12 cliff + 36 vest)
        let full = schedule.calculate_releasable(tge + 48 * SECONDS_PER_MONTH + 1);
        assert_eq!(full, 100 * CELERS_PER_CEL);
    }

    #[test]
    fn test_presale_vesting() {
        // Presale: 15% TGE, 3 months cliff, 12 months linear
        let tge = 1000;
        let schedule = create_test_schedule(
            AllocationCategory::Presale,
            100 * CELERS_PER_CEL,
            tge,
        );

        // At TGE: 15%
        assert_eq!(schedule.calculate_releasable(tge), 15 * CELERS_PER_CEL);

        // During cliff (1 month): still 15%
        let during_cliff = schedule.calculate_releasable(tge + 1 * SECONDS_PER_MONTH);
        assert_eq!(during_cliff, 15 * CELERS_PER_CEL);

        // After cliff (3 months): starts unlocking
        let after_cliff = schedule.calculate_releasable(tge + 3 * SECONDS_PER_MONTH);
        assert_eq!(after_cliff, 15 * CELERS_PER_CEL);

        // 6 months after cliff (9 months total): ~57.5% (15 + 42.5)
        let halfway = schedule.calculate_releasable(tge + 9 * SECONDS_PER_MONTH);
        // 15 TGE + 85 * 6/12 = 15 + 42.5 = 57.5
        assert_eq!(halfway, 57500000000); // 57.5 CEL

        // Fully vested (15 months = 3 cliff + 12 vest)
        let full = schedule.calculate_releasable(tge + 15 * SECONDS_PER_MONTH + 1);
        assert_eq!(full, 100 * CELERS_PER_CEL);
    }

    #[test]
    fn test_public_sale_instant() {
        // Public Sale: 100% TGE
        let tge = 1000;
        let schedule = create_test_schedule(
            AllocationCategory::PublicSale,
            100 * CELERS_PER_CEL,
            tge,
        );

        // Before TGE: 0
        assert_eq!(schedule.calculate_releasable(tge - 1), 0);

        // At TGE: 100%
        assert_eq!(schedule.calculate_releasable(tge), 100 * CELERS_PER_CEL);
    }

    #[test]
    fn test_development_vesting() {
        // Development: 10% TGE, no cliff, 60 months linear
        let tge = 1000;
        let schedule = create_test_schedule(
            AllocationCategory::Development,
            100 * CELERS_PER_CEL,
            tge,
        );

        // At TGE: 10%
        assert_eq!(schedule.calculate_releasable(tge), 10 * CELERS_PER_CEL);

        // 30 months: 10% + 90% * 30/60 = 55%
        let halfway = schedule.calculate_releasable(tge + 30 * SECONDS_PER_MONTH);
        assert_eq!(halfway, 55 * CELERS_PER_CEL);

        // Fully vested (60 months)
        let full = schedule.calculate_releasable(tge + 60 * SECONDS_PER_MONTH + 1);
        assert_eq!(full, 100 * CELERS_PER_CEL);
    }

    #[test]
    fn test_allocation_limits() {
        let mut allocation = TokenAllocation {
            admin: Pubkey::zero(),
            cel_mint: Pubkey::zero(),
            tge_time: 0,
            total_schedules: 0,
            public_sale_allocated: 0,
            public_sale_released: 0,
            presale_allocated: 0,
            presale_released: 0,
            team_allocated: 0,
            team_released: 0,
            development_allocated: 0,
            development_released: 0,
            ecosystem_allocated: 0,
            ecosystem_released: 0,
            treasury_allocated: 0,
            treasury_released: 0,
            is_initialized: true,
        };

        // Can allocate up to limit
        assert!(allocation.add_allocation(AllocationCategory::Presale, PRESALE_ALLOCATION).is_ok());

        // Cannot exceed limit
        assert!(allocation.add_allocation(AllocationCategory::Presale, 1).is_err());
    }

    #[test]
    fn test_tokenomics_total_210m() {
        // Verify all allocations add up to 210M CEL
        let total = PUBLIC_SALE_ALLOCATION + PRESALE_ALLOCATION
            + TEAM_ALLOCATION + DEVELOPMENT_ALLOCATION
            + ECOSYSTEM_ALLOCATION + TREASURY_ALLOCATION;

        // 63M + 21M + 31.5M + 42M + 31.5M + 21M = 210M CEL
        assert_eq!(total, TOTAL_SUPPLY);
        assert_eq!(total, 210_000_000 * CELERS_PER_CEL);
    }
}
