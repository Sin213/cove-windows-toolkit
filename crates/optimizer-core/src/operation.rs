use serde::{Deserialize, Serialize};
use crate::types::{RegistryHive, RegValue, SafetyTier};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    RegWrite {
        hive: RegistryHive,
        path: String,
        name: String,
        value: RegValue,
        previous: Option<RegValue>,
    },
    RegDelete {
        hive: RegistryHive,
        path: String,
        name: String,
        previous: Option<RegValue>,
    },
    ServiceStateChange {
        name: String,
        new_start_type: u32,
        previous_start_type: u32,
        stop_now: bool,
    },
    TaskToggle {
        path: String,
        enabled: bool,
        previous_enabled: bool,
    },
    FileDelete {
        path: String,
        category: String,
    },
    PowerSchemeChange {
        new_guid: String,
        previous_guid: String,
    },
    RestorePointCreate {
        description: String,
    },
}

impl Operation {
    pub fn inverse(&self) -> Option<Operation> {
        match self {
            Operation::RegWrite { hive, path, name, value: _, previous: Some(prev) } => {
                Some(Operation::RegWrite {
                    hive: *hive,
                    path: path.clone(),
                    name: name.clone(),
                    value: prev.clone(),
                    previous: None,
                })
            }
            Operation::RegWrite { hive, path, name, value: _, previous: None } => {
                Some(Operation::RegDelete {
                    hive: *hive,
                    path: path.clone(),
                    name: name.clone(),
                    previous: None,
                })
            }
            Operation::RegDelete { hive, path, name, previous: Some(prev) } => {
                Some(Operation::RegWrite {
                    hive: *hive,
                    path: path.clone(),
                    name: name.clone(),
                    value: prev.clone(),
                    previous: None,
                })
            }
            Operation::ServiceStateChange { name, new_start_type: _, previous_start_type, stop_now: _ } => {
                Some(Operation::ServiceStateChange {
                    name: name.clone(),
                    new_start_type: *previous_start_type,
                    previous_start_type: 0,
                    stop_now: false,
                })
            }
            Operation::TaskToggle { path, enabled, previous_enabled } => {
                Some(Operation::TaskToggle {
                    path: path.clone(),
                    enabled: *previous_enabled,
                    previous_enabled: *enabled,
                })
            }
            Operation::PowerSchemeChange { new_guid: _, previous_guid } => {
                Some(Operation::PowerSchemeChange {
                    new_guid: previous_guid.clone(),
                    previous_guid: String::new(),
                })
            }
            _ => None,
        }
    }

    pub fn safety_tier(&self) -> SafetyTier {
        match self {
            Operation::RegWrite { hive: RegistryHive::HKCU, .. } => SafetyTier::Green,
            Operation::RegWrite { hive: RegistryHive::HKLM, .. } => SafetyTier::Yellow,
            Operation::RegDelete { .. } => SafetyTier::Yellow,
            Operation::ServiceStateChange { .. } => SafetyTier::Yellow,
            Operation::TaskToggle { .. } => SafetyTier::Green,
            Operation::FileDelete { .. } => SafetyTier::Green,
            Operation::PowerSchemeChange { .. } => SafetyTier::Yellow,
            Operation::RestorePointCreate { .. } => SafetyTier::Green,
        }
    }
}
