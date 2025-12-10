//! Slot and epoch types for Celereum

use serde::{Deserialize, Serialize};
use crate::SLOTS_PER_EPOCH;

/// A slot number (time unit in Celereum)
pub type Slot = u64;

/// An epoch number (collection of slots)
pub type Epoch = u64;

/// Information about the current slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotInfo {
    /// Current slot number
    pub slot: Slot,

    /// Parent slot number
    pub parent: Slot,

    /// Root slot (finalized)
    pub root: Slot,

    /// Current epoch
    pub epoch: Epoch,

    /// Slot within the current epoch
    pub slot_index: u64,

    /// Total slots in this epoch
    pub slots_in_epoch: u64,
}

impl SlotInfo {
    /// Create slot info for a given slot
    pub fn new(slot: Slot, parent: Slot, root: Slot) -> Self {
        let epoch = slot / SLOTS_PER_EPOCH;
        let slot_index = slot % SLOTS_PER_EPOCH;

        SlotInfo {
            slot,
            parent,
            root,
            epoch,
            slot_index,
            slots_in_epoch: SLOTS_PER_EPOCH,
        }
    }

    /// Get the first slot of this epoch
    pub fn first_slot_in_epoch(&self) -> Slot {
        self.epoch * SLOTS_PER_EPOCH
    }

    /// Get the last slot of this epoch
    pub fn last_slot_in_epoch(&self) -> Slot {
        (self.epoch + 1) * SLOTS_PER_EPOCH - 1
    }

    /// Check if this is the first slot of the epoch
    pub fn is_first_slot_in_epoch(&self) -> bool {
        self.slot_index == 0
    }

    /// Check if this is the last slot of the epoch
    pub fn is_last_slot_in_epoch(&self) -> bool {
        self.slot_index == SLOTS_PER_EPOCH - 1
    }
}

/// Leader schedule for a slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderSchedule {
    /// Epoch this schedule is for
    pub epoch: Epoch,

    /// Slot leaders (validator pubkeys) indexed by slot_index
    pub leaders: Vec<crate::crypto::Pubkey>,
}

impl LeaderSchedule {
    /// Get the leader for a specific slot
    pub fn get_leader(&self, slot: Slot) -> Option<&crate::crypto::Pubkey> {
        let slot_index = (slot % SLOTS_PER_EPOCH) as usize;
        self.leaders.get(slot_index)
    }
}

/// Calculate epoch for a slot
pub fn slot_to_epoch(slot: Slot) -> Epoch {
    slot / SLOTS_PER_EPOCH
}

/// Get the first slot of an epoch
pub fn epoch_first_slot(epoch: Epoch) -> Slot {
    epoch * SLOTS_PER_EPOCH
}

/// Get the last slot of an epoch
pub fn epoch_last_slot(epoch: Epoch) -> Slot {
    (epoch + 1) * SLOTS_PER_EPOCH - 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_info() {
        let info = SlotInfo::new(1000, 999, 900);
        assert_eq!(info.slot, 1000);
        assert_eq!(info.parent, 999);
        assert_eq!(info.root, 900);
    }

    #[test]
    fn test_epoch_calculation() {
        let slot = SLOTS_PER_EPOCH + 100;
        assert_eq!(slot_to_epoch(slot), 1);
    }
}
