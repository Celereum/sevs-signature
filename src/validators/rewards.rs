//! Validator Reward Distribution
//!
//! Handles reward calculation and distribution for validators.
//! Supports commission-based staker rewards and auto-compounding.

use crate::core::Slot;
use crate::crypto::Pubkey;
use super::registry::{ValidatorRegistry, RegisteredValidator};
use super::consolidation::{ValidatorConsolidation, ConsolidationConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for rewards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    /// Base reward per slot (celers)
    pub base_reward_per_slot: u64,
    /// Block production bonus (celers)
    pub block_reward: u64,
    /// Vote reward (celers per vote)
    pub vote_reward: u64,
    /// Maximum annual inflation rate (basis points)
    pub max_inflation_bps: u32,
    /// Target inflation rate (basis points)
    pub target_inflation_bps: u32,
    /// Epoch duration in slots
    pub slots_per_epoch: u64,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            base_reward_per_slot: 100_000_000,     // 0.1 CEL
            block_reward: 500_000_000,              // 0.5 CEL
            vote_reward: 10_000_000,                // 0.01 CEL
            max_inflation_bps: 800,                 // 8%
            target_inflation_bps: 500,              // 5%
            slots_per_epoch: 864_000,               // ~2 days at 200ms slots
        }
    }
}

/// Reward for a single validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReward {
    /// Validator identity
    pub identity: Pubkey,
    /// Base staking reward
    pub staking_reward: u64,
    /// Block production reward
    pub block_reward: u64,
    /// Voting reward
    pub vote_reward: u64,
    /// Commission taken
    pub commission: u64,
    /// Net reward (after commission)
    pub net_reward: u64,
    /// Amount auto-compounded
    pub auto_compounded: u64,
    /// Amount to withdrawal queue
    pub to_withdrawal: u64,
}

impl ValidatorReward {
    /// Total gross reward
    pub fn gross_reward(&self) -> u64 {
        self.staking_reward
            .saturating_add(self.block_reward)
            .saturating_add(self.vote_reward)
    }
}

/// Rewards for an entire epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRewards {
    /// Epoch number
    pub epoch: u64,
    /// Total rewards distributed
    pub total_rewards: u64,
    /// Total commission taken
    pub total_commission: u64,
    /// Total auto-compounded
    pub total_compounded: u64,
    /// Individual validator rewards
    pub validator_rewards: Vec<ValidatorReward>,
    /// Effective inflation rate (basis points)
    pub inflation_bps: u32,
}

/// Result of reward calculation
#[derive(Debug, Clone)]
pub struct RewardResult {
    /// Rewards for this epoch
    pub epoch_rewards: EpochRewards,
    /// New stake totals per validator
    pub new_stakes: HashMap<Pubkey, u64>,
    /// Withdrawal amounts
    pub withdrawals: HashMap<Pubkey, u64>,
}

/// Reward distributor
pub struct RewardDistributor {
    /// Configuration
    config: RewardConfig,
    /// Consolidation config for auto-compound limits
    consolidation: ValidatorConsolidation,
}

impl RewardDistributor {
    /// Create a new reward distributor
    pub fn new(config: RewardConfig, consolidation_config: ConsolidationConfig) -> Self {
        Self {
            config,
            consolidation: ValidatorConsolidation::new(consolidation_config),
        }
    }

    /// Calculate rewards for an epoch
    pub fn calculate_epoch_rewards(
        &self,
        epoch: u64,
        validators: &[RegisteredValidator],
        blocks_produced: &HashMap<Pubkey, u64>,
        votes_cast: &HashMap<Pubkey, u64>,
        total_supply: u64,
    ) -> RewardResult {
        let total_stake: u64 = validators.iter()
            .filter(|v| v.is_active())
            .map(|v| v.effective_stake)
            .sum();

        if total_stake == 0 {
            return RewardResult {
                epoch_rewards: EpochRewards {
                    epoch,
                    total_rewards: 0,
                    total_commission: 0,
                    total_compounded: 0,
                    validator_rewards: Vec::new(),
                    inflation_bps: 0,
                },
                new_stakes: HashMap::new(),
                withdrawals: HashMap::new(),
            };
        }

        // Calculate total epoch rewards based on inflation target
        let target_annual_rewards = (total_supply as u128 * self.config.target_inflation_bps as u128 / 10000) as u64;
        let epochs_per_year = 365 * 24 * 60 * 60 * 1000 / (self.config.slots_per_epoch * 200); // 200ms slots
        let epoch_reward_pool = target_annual_rewards / epochs_per_year.max(1) as u64;

        let mut validator_rewards = Vec::new();
        let mut new_stakes = HashMap::new();
        let mut withdrawals = HashMap::new();
        let mut total_rewards = 0u64;
        let mut total_commission = 0u64;
        let mut total_compounded = 0u64;

        for validator in validators.iter().filter(|v| v.is_active()) {
            let stake_share = validator.effective_stake as f64 / total_stake as f64;

            // Base staking reward
            let staking_reward = (epoch_reward_pool as f64 * stake_share) as u64;

            // Block production reward
            let blocks = blocks_produced.get(&validator.identity).copied().unwrap_or(0);
            let block_reward = blocks * self.config.block_reward;

            // Vote reward
            let votes = votes_cast.get(&validator.identity).copied().unwrap_or(0);
            let vote_reward = votes * self.config.vote_reward;

            // Gross reward
            let gross = staking_reward.saturating_add(block_reward).saturating_add(vote_reward);

            // Commission
            let commission_rate = validator.commission as f64 / 10000.0;
            let commission = (gross as f64 * commission_rate) as u64;
            let net_reward = gross.saturating_sub(commission);

            // Auto-compound calculation
            let (auto_compounded, to_withdrawal) = self.consolidation.calculate_auto_compound(
                validator.stake,
                net_reward,
                total_stake,
            );

            // Update new stake
            let new_stake = validator.stake.saturating_add(auto_compounded);
            new_stakes.insert(validator.identity, new_stake);

            if to_withdrawal > 0 {
                withdrawals.insert(validator.identity, to_withdrawal);
            }

            // Track totals
            total_rewards = total_rewards.saturating_add(gross);
            total_commission = total_commission.saturating_add(commission);
            total_compounded = total_compounded.saturating_add(auto_compounded);

            validator_rewards.push(ValidatorReward {
                identity: validator.identity,
                staking_reward,
                block_reward,
                vote_reward,
                commission,
                net_reward,
                auto_compounded,
                to_withdrawal,
            });
        }

        // Calculate effective inflation
        let inflation_bps = if total_supply > 0 {
            ((total_rewards as u128 * 10000 * epochs_per_year as u128) / total_supply as u128) as u32
        } else {
            0
        };

        RewardResult {
            epoch_rewards: EpochRewards {
                epoch,
                total_rewards,
                total_commission,
                total_compounded,
                validator_rewards,
                inflation_bps,
            },
            new_stakes,
            withdrawals,
        }
    }

    /// Apply rewards to the registry
    pub fn apply_rewards(
        &self,
        registry: &ValidatorRegistry,
        result: &RewardResult,
    ) {
        for (identity, &new_stake) in &result.new_stakes {
            if let Some(validator) = registry.get(identity) {
                let increase = new_stake.saturating_sub(validator.stake);
                if increase > 0 {
                    let _ = registry.update(
                        identity,
                        super::registry::ValidatorUpdate::IncreaseStake(increase),
                    );
                }
            }
        }

        // Add withdrawal amounts to pending rewards
        for (identity, &amount) in &result.withdrawals {
            registry.add_rewards(identity, amount);
        }
    }

    /// Calculate single slot rewards (for real-time updates)
    pub fn calculate_slot_reward(
        &self,
        validator_stake: u64,
        total_stake: u64,
        produced_block: bool,
        voted: bool,
    ) -> u64 {
        if total_stake == 0 {
            return 0;
        }

        let stake_share = validator_stake as f64 / total_stake as f64;
        let mut reward = (self.config.base_reward_per_slot as f64 * stake_share) as u64;

        if produced_block {
            reward = reward.saturating_add(self.config.block_reward);
        }

        if voted {
            reward = reward.saturating_add(self.config.vote_reward);
        }

        reward
    }

    /// Get configuration
    pub fn config(&self) -> &RewardConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Keypair, bls::BlsKeypair};

    fn create_test_validator(stake: u64, commission: u16) -> RegisteredValidator {
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
            commission,
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
    fn test_epoch_reward_calculation() {
        let reward_config = RewardConfig::default();
        let consolidation_config = ConsolidationConfig::default();
        let distributor = RewardDistributor::new(reward_config, consolidation_config);

        let validators = vec![
            create_test_validator(10_000_000_000_000, 500),  // 10000 CEL, 5% commission
            create_test_validator(5_000_000_000_000, 1000),  // 5000 CEL, 10% commission
        ];

        let mut blocks = HashMap::new();
        blocks.insert(validators[0].identity, 100);
        blocks.insert(validators[1].identity, 50);

        let mut votes = HashMap::new();
        votes.insert(validators[0].identity, 1000);
        votes.insert(validators[1].identity, 1000);

        let result = distributor.calculate_epoch_rewards(
            0,
            &validators,
            &blocks,
            &votes,
            1_000_000_000_000_000_000, // 1 billion CEL supply
        );

        assert!(!result.epoch_rewards.validator_rewards.is_empty());
        assert!(result.epoch_rewards.total_rewards > 0);

        // Higher stake should get higher rewards
        let reward_0 = &result.epoch_rewards.validator_rewards[0];
        let reward_1 = &result.epoch_rewards.validator_rewards[1];
        assert!(reward_0.staking_reward > reward_1.staking_reward);
    }

    #[test]
    fn test_commission_calculation() {
        let reward_config = RewardConfig::default();
        let consolidation_config = ConsolidationConfig::default();
        let distributor = RewardDistributor::new(reward_config, consolidation_config);

        let validator = create_test_validator(10_000_000_000_000, 2000); // 20% commission

        let validators = vec![validator.clone()];
        let blocks = HashMap::new();
        let votes = HashMap::new();

        let result = distributor.calculate_epoch_rewards(
            0,
            &validators,
            &blocks,
            &votes,
            1_000_000_000_000_000_000,
        );

        let reward = &result.epoch_rewards.validator_rewards[0];
        let expected_commission = reward.gross_reward() * 20 / 100;

        assert_eq!(reward.commission, expected_commission);
        assert_eq!(reward.net_reward, reward.gross_reward() - expected_commission);
    }

    #[test]
    fn test_slot_reward() {
        let reward_config = RewardConfig {
            base_reward_per_slot: 1_000_000,
            block_reward: 5_000_000,
            vote_reward: 100_000,
            ..Default::default()
        };
        let consolidation_config = ConsolidationConfig::default();
        let distributor = RewardDistributor::new(reward_config, consolidation_config);

        // 10% stake share, produced block, voted
        let reward = distributor.calculate_slot_reward(
            1000,   // stake
            10000,  // total
            true,   // produced block
            true,   // voted
        );

        // Base: 1M * 0.1 = 100k
        // Block: 5M
        // Vote: 100k
        // Total: 5.2M
        assert_eq!(reward, 5_200_000);
    }
}
