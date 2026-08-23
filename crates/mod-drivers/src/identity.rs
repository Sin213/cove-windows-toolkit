//! Driver identity domain types and normalization helpers.
//!
//! This module is pure: no process invocation, no file I/O, no networking. It
//! owns the identity contracts every later Drivers slice consumes, plus the
//! bounded constants that constrain the PnPUtil parser.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Parser bounds (finite, sized for real Windows systems)
// ---------------------------------------------------------------------------

/// Maximum bytes of decoded console output the PnPUtil parser will accept.
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Maximum number of device instances in one enumeration.
pub const MAX_DEVICES: usize = 4_096;

/// Maximum hardware IDs retained for one device instance.
pub const MAX_HARDWARE_IDS_PER_DEVICE: usize = 64;

/// Maximum compatible IDs retained for one device instance.
pub const MAX_COMPATIBLE_IDS_PER_DEVICE: usize = 256;

/// Maximum matching-driver entries retained for one device instance.
pub const MAX_MATCHING_DRIVERS_PER_DEVICE: usize = 128;

/// Maximum decoded character length of any single scalar field value.
pub const MAX_FIELD_LENGTH: usize = 1_024;

/// Maximum decoded character length of a single device-instance identifier.
pub const MAX_INSTANCE_ID_LENGTH: usize = 1_024;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A single Windows device instance and its exact identity fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Device-instance primary key. Never replaced by the first hardware ID.
    pub instance_id: String,

    /// Ordered, most-specific-first hardware IDs (original display casing).
    #[serde(default)]
    pub hardware_ids: Vec<String>,

    /// Ordered compatible IDs, kept separate from hardware IDs.
    #[serde(default)]
    pub compatible_ids: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_guid: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,

    /// Windows PnP problem code, when the source exposes one (0 is valid).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem_code: Option<u32>,

    /// The installed (best-ranked / installed) driver, when deterministically
    /// marked by Windows output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<InstalledDriver>,

    /// All matching-driver entries in Windows-reported order.
    #[serde(default)]
    pub matching: Vec<MatchingDriver>,
}

/// Windows-reported information for the installed (current) driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledDriver {
    pub inf_name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_inf_name: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_date: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,

    /// Windows-reported matching rank (decimal value). Lower is better.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<u32>,
}

/// A single matching-driver candidate (installed or outranked alternative).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchingDriver {
    pub inf_name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_date: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<u32>,
}

/// Deterministic local machine facts needed by later slices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineContext {
    pub arch: String,
    pub os_build: String,
    pub os_version: String,
}

/// The additive identity-inventory result, kept separate from the legacy
/// [`crate::DriverReport`] export shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverIdentityReport {
    pub complete: bool,
    pub degraded: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    pub machine: MachineContext,
    pub devices: Vec<DeviceIdentity>,
}

// ---------------------------------------------------------------------------
// Normalization helpers
// ---------------------------------------------------------------------------

/// Trim surrounding whitespace only. Preserve internal backslashes, `&`, `_`,
/// order, and original casing. Returns `None` for an empty result.
pub fn normalize_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Case-insensitive equality for two device IDs.
pub fn ids_equal_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_id_trims_and_preserves_internal_structure() {
        assert_eq!(
            normalize_id("  PCI\\VEN_10EC&DEV_8168&SUBSYS_86771043  "),
            Some("PCI\\VEN_10EC&DEV_8168&SUBSYS_86771043".to_string())
        );
        assert_eq!(normalize_id("   "), None);
        assert_eq!(normalize_id(""), None);
    }

    #[test]
    fn ids_equal_ci_is_case_insensitive() {
        assert!(ids_equal_ci("PCI\\VEN_1022", "pci\\ven_1022"));
        assert!(!ids_equal_ci("PCI\\VEN_1022", "PCI\\VEN_1023"));
    }
}
