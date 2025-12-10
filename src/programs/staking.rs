//! Staking Program - Native program for CEL staking and delegation
//!
//! Handles:
//! - Creating stake accounts
//! - Delegating stake to validators
//! - Deactivating/withdrawing stake
//! - Earning staking rewards

use crate::crypto::Pubkey;
use crate::core::Account;
use serde::{Deserialize, Serialize};

/// Staking Program ID
pub const STAKING_PROGRAM_ID: Pubkey = Pubkey([
    0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a,
    0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
    0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b,
    0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x01,
]);

/// Minimum stake amount (10 CEL)
pub const MIN_STAKE_AMOUNT: u64 = 10_000_000_000;

/// Warmup epochs for stake activation
pub const WARMUP_EPOCHS: u64 = 2;

/// Cooldown epochs for stake deactivation
pub const COOLDOWN_EPOCHS: u64 = 2;

/// Staking instruction types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StakingInstruction {
    /// Initialize a stake account
    /// Accounts: [stake_account, staker]
    Initialize {
        /// The staker's pubkey (authorized to stake/unstake)
        staker: Pubkey,
        /// The withdrawer's pubkey (authorized to withdraw)
        withdrawer: Pubkey,
    },

    /// Delegate stake to a validator
    /// Accounts: [stake_account, validator_vote_account, staker]
    Delegate {
        /// Amount to delegate
        amount: u64,
    },

    /// Deactivate stake (start cooldown period)
    /// Accounts: [stake_account, staker]
    Deactivate,

    /// Withdraw stake after cooldown
    /// Accounts: [stake_account, destination, withdrawer]
    Withdraw {
        /// Amount to withdraw
        amount: u64,
    },

    /// Split stake account
    /// Accounts: [stake_account, new_stake_account, staker]
    Split {
        /// Amount to move to new stake account
        amount: u64,
    },

    /// Merge two stake accounts
    /// Accounts: [destination_stake, source_stake, staker]
    Merge,

    /// Set stake authority
    /// Accounts: [stake_account, current_authority]
    SetAuthority {
        /// New authority type
        authority_type: StakeAuthorityType,
        /// New authority pubkey
        new_authority: Pubkey,
    },
}

/// Stake authority types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum StakeAuthorityType {
    /// Can delegate/deactivate
    Staker,
    /// Can withdraw
    Withdrawer,
}

/// Stake account state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeState {
    /// The stake account type
    pub state: StakeStateType,
    /// Staker authority
    pub staker: Pubkey,
    /// Withdrawer authority
    pub withdrawer: Pubkey,
    /// Validator vote account we're delegated to
    pub validator: Option<Pubkey>,
    /// Amount staked
    pub stake_amount: u64,
    /// Activation epoch
    pub activation_epoch: Option<u64>,
    /// Deactivation epoch
    pub deactivation_epoch: Option<u64>,
    /// Rewards earned
    pub rewards_earned: u64,
}

/// Stake state types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum StakeStateType {
    /// Uninitialized
    Uninitialized,
    /// Initialized but not delegated
    Initialized,
    /// Stake is activating (warmup)
    Activating,
    /// Stake is active
    Active,
    /// Stake is deactivating (cooldown)
    Deactivating,
    /// Stake is deactivated, can be withdrawn
    Deactivated,
}

impl Default for StakeState {
    fn default() -> Self {
        Self {
            state: StakeStateType::Uninitialized,
            staker: Pubkey::zero(),
            withdrawer: Pubkey::zero(),
            validator: None,
            stake_amount: 0,
            activation_epoch: None,
            deactivation_epoch: None,
            rewards_earned: 0,
        }
    }
}

impl StakingInstruction {
    /// Serialize instruction to bytes
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize instruction from bytes
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}

/// Staking Program implementation
pub struct StakingProgram;

impl StakingProgram {
    /// Process a staking instruction
    pub fn process(
        instruction: &StakingInstruction,
        accounts: &mut [Account],
        current_epoch: u64,
    ) -> Result<(), StakingError> {
        match instruction {
            StakingInstruction::Initialize { staker, withdrawer } => {
                Self::process_initialize(accounts, staker, withdrawer)
            }
            StakingInstruction::Delegate { amount } => {
                Self::process_delegate(accounts, *amount, current_epoch)
            }
            StakingInstruction::Deactivate => {
                Self::process_deactivate(accounts, current_epoch)
            }
            StakingInstruction::Withdraw { amount } => {
                Self::process_withdraw(accounts, *amount, current_epoch)
            }
            StakingInstruction::Split { amount } => {
                Self::process_split(accounts, *amount)
            }
            StakingInstruction::Merge => {
                Self::process_merge(accounts)
            }
            StakingInstruction::SetAuthority { authority_type, new_authority } => {
                Self::process_set_authority(accounts, *authority_type, new_authority)
            }
        }
    }

    fn process_initialize(
        accounts: &mut [Account],
        staker: &Pubkey,
        withdrawer: &Pubkey,
    ) -> Result<(), StakingError> {
        if accounts.is_empty() {
            return Err(StakingError::NotEnoughAccounts);
        }

        let stake_account = &mut accounts[0];

        // Check if already initialized
        if let Ok(state) = Self::get_stake_state(stake_account) {
            if state.state != StakeStateType::Uninitialized {
                return Err(StakingError::AlreadyInitialized);
            }
        }

        // Initialize stake state
        let state = StakeState {
            state: StakeStateType::Initialized,
            staker: *staker,
            withdrawer: *withdrawer,
            validator: None,
            stake_amount: 0,
            activation_epoch: None,
            deactivation_epoch: None,
            rewards_earned: 0,
        };

        Self::set_stake_state(stake_account, &state);
        Ok(())
    }

    fn process_delegate(
        accounts: &mut [Account],
        amount: u64,
        current_epoch: u64,
    ) -> Result<(), StakingError> {
        if accounts.len() < 3 {
            return Err(StakingError::NotEnoughAccounts);
        }

        if amount < MIN_STAKE_AMOUNT {
            return Err(StakingError::InsufficientStake);
        }

        // Get validator owner before mutable borrow
        let validator_owner = accounts[1].owner.clone();
        // accounts[2] is staker (signer)

        let stake_account = &mut accounts[0];
        let mut state = Self::get_stake_state(stake_account)?;

        // Check state allows delegation
        if state.state != StakeStateType::Initialized && state.state != StakeStateType::Deactivated {
            return Err(StakingError::InvalidStakeState);
        }

        // Check sufficient balance
        if stake_account.celers < amount {
            return Err(StakingError::InsufficientFunds);
        }

        // Update state - use validator's owner as the validator pubkey
        state.state = StakeStateType::Activating;
        state.validator = Some(validator_owner);
        state.stake_amount = amount;
        state.activation_epoch = Some(current_epoch);
        state.deactivation_epoch = None;

        Self::set_stake_state(stake_account, &state);
        Ok(())
    }

    fn process_deactivate(
        accounts: &mut [Account],
        current_epoch: u64,
    ) -> Result<(), StakingError> {
        if accounts.is_empty() {
            return Err(StakingError::NotEnoughAccounts);
        }

        let stake_account = &mut accounts[0];
        let mut state = Self::get_stake_state(stake_account)?;

        // Check state allows deactivation
        if state.state != StakeStateType::Active && state.state != StakeStateType::Activating {
            return Err(StakingError::InvalidStakeState);
        }

        // Start deactivation
        state.state = StakeStateType::Deactivating;
        state.deactivation_epoch = Some(current_epoch);

        Self::set_stake_state(stake_account, &state);
        Ok(())
    }

    fn process_withdraw(
        accounts: &mut [Account],
        amount: u64,
        current_epoch: u64,
    ) -> Result<(), StakingError> {
        if accounts.len() < 2 {
            return Err(StakingError::NotEnoughAccounts);
        }

        let stake_account = &mut accounts[0];
        let state = Self::get_stake_state(stake_account)?;

        // Check state allows withdrawal
        match state.state {
            StakeStateType::Initialized | StakeStateType::Deactivated => {
                // Can withdraw freely
            }
            StakeStateType::Deactivating => {
                // Check cooldown period
                if let Some(deactivation_epoch) = state.deactivation_epoch {
                    if current_epoch < deactivation_epoch + COOLDOWN_EPOCHS {
                        return Err(StakingError::StakeInCooldown);
                    }
                }
            }
            _ => return Err(StakingError::StakeStillActive),
        }

        // Check sufficient balance
        if stake_account.celers < amount {
            return Err(StakingError::InsufficientFunds);
        }

        // Transfer funds
        stake_account.celers = stake_account.celers.saturating_sub(amount);
        accounts[1].celers = accounts[1].celers.saturating_add(amount);

        Ok(())
    }

    fn process_split(
        accounts: &mut [Account],
        amount: u64,
    ) -> Result<(), StakingError> {
        if accounts.len() < 2 {
            return Err(StakingError::NotEnoughAccounts);
        }

        let source_state = Self::get_stake_state(&accounts[0])?;

        if source_state.stake_amount < amount {
            return Err(StakingError::InsufficientStake);
        }

        // Create new stake state with portion of stake
        let mut new_state = source_state.clone();
        new_state.stake_amount = amount;

        // Update source stake amount
        let mut updated_source = source_state;
        updated_source.stake_amount = updated_source.stake_amount.saturating_sub(amount);

        Self::set_stake_state(&mut accounts[0], &updated_source);
        Self::set_stake_state(&mut accounts[1], &new_state);

        // Transfer celers
        let transfer_amount = amount;
        accounts[0].celers = accounts[0].celers.saturating_sub(transfer_amount);
        accounts[1].celers = accounts[1].celers.saturating_add(transfer_amount);

        Ok(())
    }

    fn process_merge(accounts: &mut [Account]) -> Result<(), StakingError> {
        if accounts.len() < 2 {
            return Err(StakingError::NotEnoughAccounts);
        }

        let dest_state = Self::get_stake_state(&accounts[0])?;
        let source_state = Self::get_stake_state(&accounts[1])?;

        // Both must be same state and delegated to same validator
        if dest_state.state != source_state.state {
            return Err(StakingError::InvalidStakeState);
        }

        if dest_state.validator != source_state.validator {
            return Err(StakingError::DifferentValidators);
        }

        // Merge stake amounts
        let mut new_state = dest_state;
        new_state.stake_amount = new_state.stake_amount.saturating_add(source_state.stake_amount);
        new_state.rewards_earned = new_state.rewards_earned.saturating_add(source_state.rewards_earned);

        Self::set_stake_state(&mut accounts[0], &new_state);

        // Clear source and transfer remaining celers
        accounts[0].celers = accounts[0].celers.saturating_add(accounts[1].celers);
        accounts[1].celers = 0;
        accounts[1].data.clear();

        Ok(())
    }

    fn process_set_authority(
        accounts: &mut [Account],
        authority_type: StakeAuthorityType,
        new_authority: &Pubkey,
    ) -> Result<(), StakingError> {
        if accounts.is_empty() {
            return Err(StakingError::NotEnoughAccounts);
        }

        let stake_account = &mut accounts[0];
        let mut state = Self::get_stake_state(stake_account)?;

        match authority_type {
            StakeAuthorityType::Staker => {
                state.staker = *new_authority;
            }
            StakeAuthorityType::Withdrawer => {
                state.withdrawer = *new_authority;
            }
        }

        Self::set_stake_state(stake_account, &state);
        Ok(())
    }

    /// Update stake state for epoch progression
    pub fn update_stake_for_epoch(
        stake_account: &mut Account,
        current_epoch: u64,
    ) -> Result<(), StakingError> {
        let mut state = Self::get_stake_state(stake_account)?;

        match state.state {
            StakeStateType::Activating => {
                if let Some(activation_epoch) = state.activation_epoch {
                    if current_epoch >= activation_epoch + WARMUP_EPOCHS {
                        state.state = StakeStateType::Active;
                    }
                }
            }
            StakeStateType::Deactivating => {
                if let Some(deactivation_epoch) = state.deactivation_epoch {
                    if current_epoch >= deactivation_epoch + COOLDOWN_EPOCHS {
                        state.state = StakeStateType::Deactivated;
                    }
                }
            }
            _ => {}
        }

        Self::set_stake_state(stake_account, &state);
        Ok(())
    }

    /// Get stake state from account
    fn get_stake_state(account: &Account) -> Result<StakeState, StakingError> {
        if account.data.is_empty() {
            return Ok(StakeState::default());
        }
        bincode::deserialize(&account.data).map_err(|_| StakingError::InvalidData)
    }

    /// Set stake state in account
    fn set_stake_state(account: &mut Account, state: &StakeState) {
        account.data = bincode::serialize(state).unwrap_or_default();
    }

    /// Calculate effective stake at current epoch
    pub fn effective_stake(state: &StakeState, current_epoch: u64) -> u64 {
        match state.state {
            StakeStateType::Active => state.stake_amount,
            StakeStateType::Activating => {
                // Linear warmup
                if let Some(activation_epoch) = state.activation_epoch {
                    let epochs_since_activation = current_epoch.saturating_sub(activation_epoch);
                    let warmup_fraction = epochs_since_activation.min(WARMUP_EPOCHS) as f64 / WARMUP_EPOCHS as f64;
                    (state.stake_amount as f64 * warmup_fraction) as u64
                } else {
                    0
                }
            }
            StakeStateType::Deactivating => {
                // Linear cooldown
                if let Some(deactivation_epoch) = state.deactivation_epoch {
                    let epochs_since_deactivation = current_epoch.saturating_sub(deactivation_epoch);
                    let remaining_fraction = 1.0 - (epochs_since_deactivation.min(COOLDOWN_EPOCHS) as f64 / COOLDOWN_EPOCHS as f64);
                    (state.stake_amount as f64 * remaining_fraction) as u64
                } else {
                    state.stake_amount
                }
            }
            _ => 0,
        }
    }
}

/// Staking errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum StakingError {
    #[error("Not enough accounts provided")]
    NotEnoughAccounts,

    #[error("Stake account already initialized")]
    AlreadyInitialized,

    #[error("Invalid stake state for this operation")]
    InvalidStakeState,

    #[error("Insufficient funds")]
    InsufficientFunds,

    #[error("Insufficient stake amount (minimum: 10 CEL)")]
    InsufficientStake,

    #[error("Stake is still active, deactivate first")]
    StakeStillActive,

    #[error("Stake is in cooldown period")]
    StakeInCooldown,

    #[error("Invalid account data")]
    InvalidData,

    #[error("Cannot merge stakes with different validators")]
    DifferentValidators,

    #[error("Unauthorized")]
    Unauthorized,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stake_state_default() {
        let state = StakeState::default();
        assert_eq!(state.state, StakeStateType::Uninitialized);
        assert_eq!(state.stake_amount, 0);
    }

    #[test]
    fn test_effective_stake_active() {
        let state = StakeState {
            state: StakeStateType::Active,
            stake_amount: 1000,
            ..Default::default()
        };
        assert_eq!(StakingProgram::effective_stake(&state, 10), 1000);
    }

    #[test]
    fn test_effective_stake_activating() {
        let state = StakeState {
            state: StakeStateType::Activating,
            stake_amount: 1000,
            activation_epoch: Some(0),
            ..Default::default()
        };
        // At epoch 0, 0% effective
        assert_eq!(StakingProgram::effective_stake(&state, 0), 0);
        // At epoch 1, 50% effective (linear over 2 epochs)
        assert_eq!(StakingProgram::effective_stake(&state, 1), 500);
        // At epoch 2+, 100% effective
        assert_eq!(StakingProgram::effective_stake(&state, 2), 1000);
    }

    #[test]
    fn test_min_stake_amount() {
        assert_eq!(MIN_STAKE_AMOUNT, 10_000_000_000); // 10 CEL
    }
}
