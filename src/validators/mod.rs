//! Validator Management Module for Celereum
//!
//! This module handles validator registration, stake management,
//! and implements Validator Consolidation for reduced network overhead.
//!
//! # Validator Consolidation
//! Instead of having thousands of small validators (each sending messages),
//! consolidation allows larger stakes per validator, reducing network load
//! while maintaining decentralization through stake caps and penalties.
//!
//! # Features
//! - Maximum stake limits to prevent over-centralization
//! - Maximum share of total stake per validator
//! - Progressive slashing for larger validators
//! - Auto-compounding of rewards
//! - Efficient reward distribution

pub mod registry;
pub mod consolidation;
pub mod rewards;
pub mod slashing;

pub use registry::{
    ValidatorRegistry, RegisteredValidator, ValidatorStatus,
    RegistrationError, ValidatorUpdate,
};
pub use consolidation::{
    ConsolidationConfig, ValidatorConsolidation,
    EffectiveStake, ConsolidationStats,
};
pub use rewards::{
    RewardDistributor, RewardConfig, RewardResult,
    ValidatorReward, EpochRewards,
};
pub use slashing::{
    SlashingEngine, SlashingConfig, Offense,
    SlashingPenalty, SlashEvent,
};
