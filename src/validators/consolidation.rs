//! Validator Consolidation
//!
//! Implements stake consolidation rules to reduce network overhead while
//! maintaining decentralization through caps and limits.
//!
//! # Key Concepts
//! - **Max Stake**: Maximum stake per validator
//! - **Max Share**: Maximum percentage of total stake
//! - **Effective Balance Increment**: Granularity for stake accounting
//! - **Auto-Compounding**: Automatic reward reinvestment up to max

use crate::crypto::Pubkey;
use super::registry::{ValidatorRegistry, RegisteredValidator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for validator consolidation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsolidationConfig {
    /// Minimum stake to be a validator
    pub min_stake: u64,
    /// Maximum stake per validator
    pub max_stake: u64,
    /// Maximum share of total stake (basis points: 10000 = 100%)
    pub max_stake_share_bps: u32,
    /// Effective balance increment (granularity)
    pub effective_balance_increment: u64,
    /// Enable auto-compounding of rewards
    pub auto_compound: bool,
    /// Target validator count (for dynamic adjustment)
    pub target_validator_count: usize,
}

impl Default for ConsolidationConfig {
    fn default() -> Self {
        Self {
            min_stake: 1_000_000_000_000,        // 1,000 CEL
            max_stake: 100_000_000_000_000_000,  // 100,000 CEL
            max_stake_share_bps: 1000,           // 10% max
            effective_balance_increment: 1_000_000_000_000, // 1,000 CEL
            auto_compound: true,
            target_validator_count: 1000,
        }
    }
}

/// Effective stake calculation result
#[derive(Debug, Clone)]
pub struct EffectiveStake {
    /// Original stake
    pub stake: u64,
    /// Effective stake after applying caps
    pub effective: u64,
    /// Stake capped due to max stake
    pub capped_by_max: u64,
    /// Stake capped due to max share
    pub capped_by_share: u64,
    /// Rounding adjustment
    pub rounding_adjustment: u64,
}

impl EffectiveStake {
    /// Calculate effective stake for a validator
    pub fn calculate(
        stake: u64,
        total_stake: u64,
        config: &ConsolidationConfig,
    ) -> Self {
        let mut effective = stake;
        let mut capped_by_max = 0u64;
        let mut capped_by_share = 0u64;

        // Apply minimum stake requirement
        if effective < config.min_stake {
            return Self {
                stake,
                effective: 0,
                capped_by_max: 0,
                capped_by_share: 0,
                rounding_adjustment: stake,
            };
        }

        // Apply maximum stake cap
        if effective > config.max_stake {
            capped_by_max = effective - config.max_stake;
            effective = config.max_stake;
        }

        // Apply maximum share cap
        if total_stake > 0 {
            let max_share_stake = (total_stake as u128 * config.max_stake_share_bps as u128 / 10000) as u64;
            if effective > max_share_stake {
                let share_cap = effective - max_share_stake;
                capped_by_share = share_cap.saturating_sub(capped_by_max);
                effective = max_share_stake;
            }
        }

        // Round down to effective balance increment
        let rounding_adjustment = effective % config.effective_balance_increment;
        effective = (effective / config.effective_balance_increment) * config.effective_balance_increment;

        Self {
            stake,
            effective,
            capped_by_max,
            capped_by_share,
            rounding_adjustment,
        }
    }

    /// Check if stake is capped
    pub fn is_capped(&self) -> bool {
        self.capped_by_max > 0 || self.capped_by_share > 0
    }
}

/// Validator Consolidation Manager
pub struct ValidatorConsolidation {
    /// Configuration
    config: ConsolidationConfig,
}

impl ValidatorConsolidation {
    /// Create a new consolidation manager
    pub fn new(config: ConsolidationConfig) -> Self {
        Self { config }
    }

    /// Calculate effective stakes for all validators
    pub fn calculate_effective_stakes(
        &self,
        validators: &[RegisteredValidator],
    ) -> HashMap<Pubkey, EffectiveStake> {
        // First pass: calculate total stake
        let total_stake: u64 = validators.iter()
            .filter(|v| v.is_active())
            .map(|v| v.stake)
            .sum();

        // Second pass: calculate effective stakes
        validators.iter()
            .filter(|v| v.is_active())
            .map(|v| {
                let effective = EffectiveStake::calculate(
                    v.stake,
                    total_stake,
                    &self.config,
                );
                (v.identity, effective)
            })
            .collect()
    }

    /// Apply consolidation rules to registry
    pub fn apply_to_registry(&self, registry: &ValidatorRegistry) {
        let validators = registry.get_active();
        let effective_stakes = self.calculate_effective_stakes(&validators);

        // Convert to simple map
        let simple_map: HashMap<Pubkey, u64> = effective_stakes.iter()
            .map(|(k, v)| (*k, v.effective))
            .collect();

        registry.update_effective_stakes(&simple_map);
    }

    /// Check if a validator can increase stake
    pub fn can_increase_stake(
        &self,
        current_stake: u64,
        increase: u64,
        total_network_stake: u64,
    ) -> Result<(), ConsolidationError> {
        let new_stake = current_stake.saturating_add(increase);

        // Check max stake
        if new_stake > self.config.max_stake {
            return Err(ConsolidationError::ExceedsMaxStake {
                requested: new_stake,
                max: self.config.max_stake,
            });
        }

        // Check max share
        let new_total = total_network_stake.saturating_add(increase);
        let share_bps = (new_stake as u128 * 10000 / new_total as u128) as u32;
        if share_bps > self.config.max_stake_share_bps {
            return Err(ConsolidationError::ExceedsMaxShare {
                share_bps,
                max_bps: self.config.max_stake_share_bps,
            });
        }

        Ok(())
    }

    /// Calculate auto-compound amount (respecting caps)
    pub fn calculate_auto_compound(
        &self,
        current_stake: u64,
        rewards: u64,
        total_network_stake: u64,
    ) -> (u64, u64) { // (compound_amount, overflow)
        if !self.config.auto_compound || rewards == 0 {
            return (0, rewards);
        }

        let max_compound = self.config.max_stake.saturating_sub(current_stake);

        // Also check share limit
        let max_by_share = {
            let new_total = total_network_stake.saturating_add(rewards);
            let max_share_stake = (new_total as u128 * self.config.max_stake_share_bps as u128 / 10000) as u64;
            max_share_stake.saturating_sub(current_stake)
        };

        let max_allowed = max_compound.min(max_by_share);
        let compound = rewards.min(max_allowed);
        let overflow = rewards.saturating_sub(compound);

        (compound, overflow)
    }

    /// Get configuration
    pub fn config(&self) -> &ConsolidationConfig {
        &self.config
    }

    /// Calculate statistics
    pub fn calculate_stats(&self, validators: &[RegisteredValidator]) -> ConsolidationStats {
        let effective_stakes = self.calculate_effective_stakes(validators);

        let active_count = validators.iter().filter(|v| v.is_active()).count();
        let total_stake: u64 = validators.iter()
            .filter(|v| v.is_active())
            .map(|v| v.stake)
            .sum();
        let total_effective: u64 = effective_stakes.values().map(|e| e.effective).sum();

        let capped_count = effective_stakes.values().filter(|e| e.is_capped()).count();

        let (min_stake, max_stake) = if active_count > 0 {
            let stakes: Vec<u64> = validators.iter()
                .filter(|v| v.is_active())
                .map(|v| v.stake)
                .collect();
            (*stakes.iter().min().unwrap_or(&0), *stakes.iter().max().unwrap_or(&0))
        } else {
            (0, 0)
        };

        let gini = self.calculate_gini_coefficient(&effective_stakes);

        ConsolidationStats {
            active_validators: active_count,
            total_stake,
            total_effective_stake: total_effective,
            capped_validators: capped_count,
            min_stake,
            max_stake,
            avg_stake: if active_count > 0 { total_stake / active_count as u64 } else { 0 },
            stake_reduction: total_stake.saturating_sub(total_effective),
            gini_coefficient: gini,
        }
    }

    /// Calculate Gini coefficient for stake distribution
    fn calculate_gini_coefficient(&self, stakes: &HashMap<Pubkey, EffectiveStake>) -> f64 {
        let mut effective: Vec<f64> = stakes.values()
            .map(|s| s.effective as f64)
            .filter(|&s| s > 0.0)
            .collect();

        if effective.len() < 2 {
            return 0.0;
        }

        effective.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = effective.len() as f64;
        let sum: f64 = effective.iter().sum();

        if sum == 0.0 {
            return 0.0;
        }

        let mut weighted_sum = 0.0;
        for (i, &stake) in effective.iter().enumerate() {
            weighted_sum += (i as f64 + 1.0) * stake;
        }

        (2.0 * weighted_sum / (n * sum)) - ((n + 1.0) / n)
    }
}

/// Consolidation errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConsolidationError {
    #[error("Stake {requested} exceeds maximum {max}")]
    ExceedsMaxStake { requested: u64, max: u64 },

    #[error("Stake share {share_bps} bps exceeds maximum {max_bps} bps")]
    ExceedsMaxShare { share_bps: u32, max_bps: u32 },

    #[error("Stake {stake} below minimum {min}")]
    BelowMinimum { stake: u64, min: u64 },
}

/// Consolidation statistics
#[derive(Debug, Clone)]
pub struct ConsolidationStats {
    /// Number of active validators
    pub active_validators: usize,
    /// Total stake
    pub total_stake: u64,
    /// Total effective stake
    pub total_effective_stake: u64,
    /// Number of validators hitting caps
    pub capped_validators: usize,
    /// Minimum stake
    pub min_stake: u64,
    /// Maximum stake
    pub max_stake: u64,
    /// Average stake
    pub avg_stake: u64,
    /// Stake reduced due to caps
    pub stake_reduction: u64,
    /// Gini coefficient (0 = perfect equality, 1 = perfect inequality)
    pub gini_coefficient: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Keypair, bls::BlsKeypair};

    fn create_test_validator(stake: u64) -> RegisteredValidator {
        let identity = Keypair::generate();
        let bls = BlsKeypair::generate().unwrap();
        let vote = Keypair::generate();

        RegisteredValidator {
            identity: identity.pubkey(),
            bls_pubkey: bls.public_key().clone(),
            bls_pop: bls.proof_of_possession().clone(),
            vote_account: vote.pubkey(),
            stake,
            effective_stake: stake,
            commission: 500,
            status: super::super::registry::ValidatorStatus::Active,
            activation_epoch: 0,
            exit_epoch: None,
            last_vote_slot: None,
            blocks_produced: 0,
            votes_cast: 0,
            slashing_count: 0,
            pending_rewards: 0,
        }
    }

    #[test]
    fn test_effective_stake_calculation() {
        let config = ConsolidationConfig {
            min_stake: 1000,
            max_stake: 10000,
            max_stake_share_bps: 2000, // 20%
            effective_balance_increment: 100,
            ..Default::default()
        };

        // Normal stake
        let effective = EffectiveStake::calculate(5000, 100000, &config);
        assert_eq!(effective.effective, 5000);
        assert!(!effective.is_capped());

        // Exceeds max stake
        let effective = EffectiveStake::calculate(15000, 100000, &config);
        assert_eq!(effective.effective, 10000);
        assert!(effective.is_capped());
        assert_eq!(effective.capped_by_max, 5000);

        // Exceeds max share
        let effective = EffectiveStake::calculate(5000, 10000, &config);
        // 5000 / 10000 = 50% > 20%
        assert_eq!(effective.effective, 2000); // 20% of 10000
        assert!(effective.is_capped());
    }

    #[test]
    fn test_below_minimum_stake() {
        let config = ConsolidationConfig {
            min_stake: 1000,
            ..Default::default()
        };

        let effective = EffectiveStake::calculate(500, 100000, &config);
        assert_eq!(effective.effective, 0);
    }

    #[test]
    fn test_consolidation_stats() {
        let config = ConsolidationConfig {
            min_stake: 100,
            max_stake: 10000,
            max_stake_share_bps: 5000, // 50%
            effective_balance_increment: 100,
            ..Default::default()
        };

        let consolidation = ValidatorConsolidation::new(config);

        let validators = vec![
            create_test_validator(1000),
            create_test_validator(2000),
            create_test_validator(3000),
            create_test_validator(4000),
        ];

        let stats = consolidation.calculate_stats(&validators);

        assert_eq!(stats.active_validators, 4);
        assert_eq!(stats.total_stake, 10000);
        assert!(stats.gini_coefficient >= 0.0 && stats.gini_coefficient <= 1.0);
    }

    #[test]
    fn test_can_increase_stake() {
        let config = ConsolidationConfig {
            min_stake: 100,
            max_stake: 10000,
            max_stake_share_bps: 2000, // 20%
            ..Default::default()
        };

        let consolidation = ValidatorConsolidation::new(config);

        // Can increase within limits
        assert!(consolidation.can_increase_stake(5000, 1000, 100000).is_ok());

        // Exceeds max stake
        assert!(consolidation.can_increase_stake(9000, 2000, 100000).is_err());

        // Exceeds max share
        assert!(consolidation.can_increase_stake(1000, 9000, 50000).is_err());
    }

    #[test]
    fn test_auto_compound() {
        let config = ConsolidationConfig {
            min_stake: 100,
            max_stake: 10000,
            max_stake_share_bps: 2000,
            auto_compound: true,
            ..Default::default()
        };

        let consolidation = ValidatorConsolidation::new(config);

        // Normal compound
        let (compound, overflow) = consolidation.calculate_auto_compound(5000, 1000, 100000);
        assert_eq!(compound, 1000);
        assert_eq!(overflow, 0);

        // Compound limited by max stake
        let (compound, overflow) = consolidation.calculate_auto_compound(9500, 1000, 100000);
        assert_eq!(compound, 500);
        assert_eq!(overflow, 500);
    }
}
