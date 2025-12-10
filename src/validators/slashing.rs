//! Slashing Engine for Validator Misbehavior
//!
//! Implements progressive slashing penalties based on offense severity
//! and validator stake size. Larger validators face proportionally
//! higher penalties to maintain decentralization incentives.
//!
//! # Offense Types
//! - **Equivocation**: Signing conflicting blocks/votes (severe)
//! - **Downtime**: Extended periods without participation (minor)
//! - **Invalid Attestations**: Attesting to invalid state (moderate)
//! - **Censorship**: Deliberately excluding valid transactions (severe)
//!
//! # Progressive Penalties
//! Penalty scales with sqrt(stake) to discourage stake concentration
//! while not being overly punitive to small validators.

use crate::core::Slot;
use crate::crypto::Pubkey;
use super::registry::{ValidatorRegistry, RegisteredValidator, ValidatorUpdate};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Configuration for slashing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// Minimum stake to slash
    pub min_stake: u64,
    /// Base penalty for equivocation (basis points)
    pub equivocation_penalty_bps: u32,
    /// Base penalty for downtime (per epoch, basis points)
    pub downtime_penalty_bps: u32,
    /// Base penalty for invalid attestations (basis points)
    pub invalid_attestation_penalty_bps: u32,
    /// Base penalty for censorship (basis points)
    pub censorship_penalty_bps: u32,
    /// Stake size multiplier (for progressive penalties)
    pub stake_size_multiplier: f64,
    /// Maximum penalty per offense (basis points)
    pub max_penalty_bps: u32,
    /// Cooldown between penalties for same offense (slots)
    pub penalty_cooldown_slots: u64,
    /// Downtime threshold (missed slots before penalty)
    pub downtime_threshold_slots: u64,
    /// Correlation penalty multiplier (multiple validators misbehaving)
    pub correlation_multiplier: f64,
    /// Evidence expiry (slots)
    pub evidence_expiry_slots: u64,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            min_stake: 1_000_000_000_000, // 1000 CEL
            equivocation_penalty_bps: 10000, // 100% of stake
            downtime_penalty_bps: 100,       // 1% per epoch
            invalid_attestation_penalty_bps: 1000, // 10%
            censorship_penalty_bps: 5000,    // 50%
            stake_size_multiplier: 1.5,
            max_penalty_bps: 10000, // 100%
            penalty_cooldown_slots: 864_000, // ~1 epoch
            downtime_threshold_slots: 4320,  // ~1 hour
            correlation_multiplier: 3.0,     // Triple penalty if correlated
            evidence_expiry_slots: 864_000 * 7, // ~1 week
        }
    }
}

/// Type of offense
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Offense {
    /// Signed conflicting blocks or votes
    Equivocation,
    /// Extended downtime
    Downtime,
    /// Invalid attestations
    InvalidAttestation,
    /// Transaction censorship
    Censorship,
}

impl Offense {
    /// Get base severity (0-100)
    pub fn severity(&self) -> u32 {
        match self {
            Self::Equivocation => 100,
            Self::Censorship => 80,
            Self::InvalidAttestation => 50,
            Self::Downtime => 20,
        }
    }
}

/// Evidence of misbehavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvidence {
    /// Validator being accused
    pub validator: Pubkey,
    /// Type of offense
    pub offense: Offense,
    /// Slot where offense occurred
    pub slot: Slot,
    /// Additional data (e.g., conflicting signatures)
    pub data: Vec<u8>,
    /// Timestamp of evidence submission
    pub timestamp: u64,
    /// Reporter (optional)
    pub reporter: Option<Pubkey>,
}

impl SlashingEvidence {
    /// Create new evidence
    pub fn new(validator: Pubkey, offense: Offense, slot: Slot, data: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            validator,
            offense,
            slot,
            data,
            timestamp,
            reporter: None,
        }
    }

    /// Add reporter
    pub fn with_reporter(mut self, reporter: Pubkey) -> Self {
        self.reporter = Some(reporter);
        self
    }
}

/// Calculated slashing penalty
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingPenalty {
    /// Validator
    pub validator: Pubkey,
    /// Original stake
    pub original_stake: u64,
    /// Base penalty amount
    pub base_penalty: u64,
    /// Stake size adjustment
    pub size_adjustment: u64,
    /// Correlation adjustment
    pub correlation_adjustment: u64,
    /// Final penalty amount
    pub final_penalty: u64,
    /// Penalty as basis points
    pub penalty_bps: u32,
    /// Remaining stake after slash
    pub remaining_stake: u64,
}

/// Slashing event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashEvent {
    /// Event ID
    pub id: u64,
    /// Validator slashed
    pub validator: Pubkey,
    /// Offense type
    pub offense: Offense,
    /// Slot of offense
    pub offense_slot: Slot,
    /// Slot when slashed
    pub slash_slot: Slot,
    /// Penalty details
    pub penalty: SlashingPenalty,
    /// Evidence hash
    pub evidence_hash: [u8; 32],
    /// Reporter (if bounty applies)
    pub reporter: Option<Pubkey>,
}

/// Slashing engine
pub struct SlashingEngine {
    /// Configuration
    config: SlashingConfig,
    /// Pending evidence
    pending_evidence: VecDeque<SlashingEvidence>,
    /// Processed slashing events
    slash_events: Vec<SlashEvent>,
    /// Recent offenses by validator (for correlation)
    recent_offenses: HashMap<Slot, Vec<Pubkey>>,
    /// Last slash slot by validator (for cooldown)
    last_slash: HashMap<Pubkey, Slot>,
    /// Next event ID
    next_event_id: u64,
    /// Current slot
    current_slot: Slot,
}

impl SlashingEngine {
    /// Create a new slashing engine
    pub fn new(config: SlashingConfig) -> Self {
        Self {
            config,
            pending_evidence: VecDeque::new(),
            slash_events: Vec::new(),
            recent_offenses: HashMap::new(),
            last_slash: HashMap::new(),
            next_event_id: 1,
            current_slot: 0,
        }
    }

    /// Set current slot
    pub fn set_slot(&mut self, slot: Slot) {
        self.current_slot = slot;
        self.cleanup_expired();
    }

    /// Submit slashing evidence
    pub fn submit_evidence(&mut self, evidence: SlashingEvidence) -> Result<(), SlashingError> {
        // Check evidence is not expired
        let evidence_age = self.current_slot.saturating_sub(evidence.slot);
        if evidence_age > self.config.evidence_expiry_slots {
            return Err(SlashingError::EvidenceExpired);
        }

        // Check cooldown
        if let Some(&last) = self.last_slash.get(&evidence.validator) {
            if self.current_slot.saturating_sub(last) < self.config.penalty_cooldown_slots {
                return Err(SlashingError::CooldownActive);
            }
        }

        self.pending_evidence.push_back(evidence);
        Ok(())
    }

    /// Process pending evidence and return penalties to apply
    pub fn process_evidence(
        &mut self,
        registry: &ValidatorRegistry,
    ) -> Vec<SlashingPenalty> {
        let mut penalties = Vec::new();

        while let Some(evidence) = self.pending_evidence.pop_front() {
            if let Some(validator) = registry.get(&evidence.validator) {
                if let Some(penalty) = self.calculate_penalty(&evidence, &validator, registry) {
                    // Record for correlation tracking
                    self.recent_offenses
                        .entry(evidence.slot)
                        .or_default()
                        .push(evidence.validator);

                    // Record slash time
                    self.last_slash.insert(evidence.validator, self.current_slot);

                    // Create slash event
                    let event = SlashEvent {
                        id: self.next_event_id,
                        validator: evidence.validator,
                        offense: evidence.offense,
                        offense_slot: evidence.slot,
                        slash_slot: self.current_slot,
                        penalty: penalty.clone(),
                        evidence_hash: crate::crypto::Hash::hash(&evidence.data).as_bytes().clone(),
                        reporter: evidence.reporter,
                    };
                    self.next_event_id += 1;
                    self.slash_events.push(event);

                    penalties.push(penalty);
                }
            }
        }

        penalties
    }

    /// Calculate penalty for an offense
    fn calculate_penalty(
        &self,
        evidence: &SlashingEvidence,
        validator: &RegisteredValidator,
        registry: &ValidatorRegistry,
    ) -> Option<SlashingPenalty> {
        if validator.stake < self.config.min_stake {
            return None;
        }

        let stake = validator.stake;
        let total_stake = registry.total_stake();

        // Get base penalty rate
        let base_rate_bps = match evidence.offense {
            Offense::Equivocation => self.config.equivocation_penalty_bps,
            Offense::Downtime => self.config.downtime_penalty_bps,
            Offense::InvalidAttestation => self.config.invalid_attestation_penalty_bps,
            Offense::Censorship => self.config.censorship_penalty_bps,
        };

        // Calculate base penalty
        let base_penalty = (stake as u128 * base_rate_bps as u128 / 10000) as u64;

        // Calculate stake size adjustment (sqrt scaling)
        let stake_ratio = if total_stake > 0 {
            stake as f64 / total_stake as f64
        } else {
            0.0
        };
        let size_factor = stake_ratio.sqrt() * self.config.stake_size_multiplier;
        let size_adjustment = (base_penalty as f64 * size_factor) as u64;

        // Calculate correlation adjustment
        let correlated_validators = self.recent_offenses
            .get(&evidence.slot)
            .map(|v| v.len())
            .unwrap_or(0);

        let correlation_factor = if correlated_validators > 1 {
            (correlated_validators as f64).min(self.config.correlation_multiplier)
        } else {
            1.0
        };
        let correlation_base = base_penalty.saturating_add(size_adjustment);
        let correlation_adjustment = ((correlation_base as f64 * (correlation_factor - 1.0)) as u64)
            .min(stake); // Cap at full stake

        // Calculate final penalty
        let mut final_penalty = base_penalty
            .saturating_add(size_adjustment)
            .saturating_add(correlation_adjustment);

        // Apply maximum cap
        let max_penalty = (stake as u128 * self.config.max_penalty_bps as u128 / 10000) as u64;
        final_penalty = final_penalty.min(max_penalty);

        let penalty_bps = ((final_penalty as u128 * 10000) / stake as u128) as u32;
        let remaining_stake = stake.saturating_sub(final_penalty);

        Some(SlashingPenalty {
            validator: evidence.validator,
            original_stake: stake,
            base_penalty,
            size_adjustment,
            correlation_adjustment,
            final_penalty,
            penalty_bps,
            remaining_stake,
        })
    }

    /// Apply penalties to registry
    pub fn apply_penalties(
        &self,
        registry: &ValidatorRegistry,
        penalties: &[SlashingPenalty],
    ) {
        for penalty in penalties {
            // Decrease stake
            let _ = registry.update(
                &penalty.validator,
                ValidatorUpdate::DecreaseStake(penalty.final_penalty),
            );

            // Add slash count
            let severity = ((penalty.penalty_bps / 1000) as u32).max(1);
            let _ = registry.update(
                &penalty.validator,
                ValidatorUpdate::Slash(severity),
            );
        }
    }

    /// Clean up expired data
    fn cleanup_expired(&mut self) {
        let expiry = self.current_slot.saturating_sub(self.config.evidence_expiry_slots);

        // Clean up old offense records
        self.recent_offenses.retain(|&slot, _| slot > expiry);

        // Clean up old evidence
        self.pending_evidence.retain(|e| e.slot > expiry);
    }

    /// Get recent slash events
    pub fn recent_events(&self, count: usize) -> Vec<SlashEvent> {
        self.slash_events.iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }

    /// Get slash events for a validator
    pub fn events_for_validator(&self, validator: &Pubkey) -> Vec<SlashEvent> {
        self.slash_events.iter()
            .filter(|e| e.validator == *validator)
            .cloned()
            .collect()
    }

    /// Get total slashed amount
    pub fn total_slashed(&self) -> u64 {
        self.slash_events.iter()
            .map(|e| e.penalty.final_penalty)
            .sum()
    }

    /// Get configuration
    pub fn config(&self) -> &SlashingConfig {
        &self.config
    }
}

/// Slashing errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum SlashingError {
    #[error("Evidence has expired")]
    EvidenceExpired,

    #[error("Penalty cooldown active")]
    CooldownActive,

    #[error("Validator not found")]
    ValidatorNotFound,

    #[error("Insufficient stake to slash")]
    InsufficientStake,

    #[error("Invalid evidence")]
    InvalidEvidence,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Keypair, bls::BlsKeypair};

    fn create_test_validator(identity: Pubkey, stake: u64) -> RegisteredValidator {
        let bls = BlsKeypair::generate().unwrap();
        let vote = Keypair::generate();

        RegisteredValidator {
            identity,
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
    fn test_penalty_calculation() {
        let config = SlashingConfig::default();
        let engine = SlashingEngine::new(config);

        let identity = Keypair::generate().pubkey();
        let validator = create_test_validator(identity, 10_000_000_000_000); // 10000 CEL

        // Create mock registry
        let registry = super::super::registry::ValidatorRegistry::new();

        let evidence = SlashingEvidence::new(
            identity,
            Offense::InvalidAttestation,
            100,
            vec![],
        );

        let penalty = engine.calculate_penalty(&evidence, &validator, &registry);
        assert!(penalty.is_some());

        let penalty = penalty.unwrap();
        assert!(penalty.final_penalty > 0);
        assert!(penalty.remaining_stake < validator.stake);
    }

    #[test]
    fn test_equivocation_severe() {
        let config = SlashingConfig::default();
        let engine = SlashingEngine::new(config);

        let identity = Keypair::generate().pubkey();
        let validator = create_test_validator(identity, 10_000_000_000_000);

        let registry = super::super::registry::ValidatorRegistry::new();

        // Equivocation evidence
        let evidence = SlashingEvidence::new(
            identity,
            Offense::Equivocation,
            100,
            vec![],
        );

        let penalty = engine.calculate_penalty(&evidence, &validator, &registry).unwrap();

        // Equivocation should have high penalty
        assert!(penalty.penalty_bps >= 10000); // At least 100%
    }

    #[test]
    fn test_evidence_expiry() {
        let config = SlashingConfig {
            evidence_expiry_slots: 100,
            ..Default::default()
        };
        let mut engine = SlashingEngine::new(config);
        engine.set_slot(200);

        let identity = Keypair::generate().pubkey();

        // Old evidence (slot 50, current is 200)
        let evidence = SlashingEvidence::new(
            identity,
            Offense::Downtime,
            50,
            vec![],
        );

        let result = engine.submit_evidence(evidence);
        assert!(matches!(result, Err(SlashingError::EvidenceExpired)));
    }

    #[test]
    fn test_cooldown() {
        let config = SlashingConfig {
            penalty_cooldown_slots: 100,
            evidence_expiry_slots: 1000,
            ..Default::default()
        };
        let mut engine = SlashingEngine::new(config);

        let identity = Keypair::generate().pubkey();

        // First offense
        engine.set_slot(100);
        engine.last_slash.insert(identity, 100);

        // Try again too soon
        engine.set_slot(150);
        let evidence = SlashingEvidence::new(
            identity,
            Offense::Downtime,
            150,
            vec![],
        );

        let result = engine.submit_evidence(evidence);
        assert!(matches!(result, Err(SlashingError::CooldownActive)));

        // After cooldown
        engine.set_slot(250);
        let evidence = SlashingEvidence::new(
            identity,
            Offense::Downtime,
            250,
            vec![],
        );

        assert!(engine.submit_evidence(evidence).is_ok());
    }
}
