//! Native programs for Celereum blockchain
//!
//! Similar to Solana's native programs (System, Token, etc.)

pub mod system;
pub mod token;
pub mod amm;
pub mod bridge;
pub mod vesting;
pub mod staking;

pub use system::SystemProgram;
pub use token::{TokenProgram, CEL20_PROGRAM_ID};
pub use amm::{AmmProgram, AMM_PROGRAM_ID, Pool};
pub use bridge::{BridgeProgram, BRIDGE_PROGRAM_ID, BridgeConfig, BridgeTransfer};
pub use vesting::{VestingProgram, VESTING_PROGRAM_ID, VestingSchedule, TokenAllocation};
pub use staking::{
    StakingProgram, STAKING_PROGRAM_ID, StakingInstruction, StakeState, StakeStateType,
    StakeAuthorityType, StakingError, MIN_STAKE_AMOUNT, WARMUP_EPOCHS, COOLDOWN_EPOCHS,
};
