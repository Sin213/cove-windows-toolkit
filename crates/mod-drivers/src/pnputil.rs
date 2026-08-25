//! Pure PnPUtil `/enum-devices` output parser.
//!
//! The executable is trusted, but its textual output is still treated as
//! structured external input: parsing is bounded, malformed structure fails
//! closed, and no candidate-recommendation logic lives here.
//!
//! # Localization boundary
//!
//! The parser is keyed to the English PnPUtil headings observed on the current
//! Windows host. PnPUtil's `/enum-devices` family does not provide a stable
//! locale-independent output mode, so on a localized host the English-label
//! headings may not match and parsing will fail closed (an `Err`, never a
//! fabricated inventory). Installed-driver detection also depends on the
//! English `Installed`/`Extension` status substrings, and is intentionally
//! case-insensitive. This is an accepted limitation of the read-only PnPUtil
//! approach for this slice; a SetupAPI/CfgMgr32 source is explicitly out of
//! scope unless separately authorized.

use crate::identity::{
    ids_equal_ci, normalize_id, DeviceIdentity, InstalledDriver, MatchingDriver,
    MAX_COMPATIBLE_IDS_PER_DEVICE, MAX_DEVICES, MAX_FIELD_LENGTH, MAX_HARDWARE_IDS_PER_DEVICE,
    MAX_INSTANCE_ID_LENGTH, MAX_MATCHING_DRIVERS_PER_DEVICE, MAX_OUTPUT_BYTES,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PnputilParseError {
    EmptyInput,
    OutputTooLarge,
    DeviceCountExceeded,
    IdsPerDeviceExceeded,
    MatchingDriversExceeded,
    FieldTooLong,
    MissingInstanceId,
    Malformed(String),
}

impl std::fmt::Display for PnputilParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "PnPUtil produced no output"),
            Self::OutputTooLarge => write!(f, "PnPUtil output exceeded the accepted size"),
            Self::DeviceCountExceeded => write!(f, "PnPUtil reported more devices than accepted"),
            Self::IdsPerDeviceExceeded => {
                write!(f, "PnPUtil reported more IDs for one device than accepted")
            }
            Self::MatchingDriversExceeded => {
                write!(f, "PnPUtil reported more matching drivers than accepted")
            }
            Self::FieldTooLong => write!(f, "a PnPUtil field exceeded the accepted length"),
            Self::MissingInstanceId => write!(f, "a device block is missing its instance ID"),
            Self::Malformed(detail) => write!(f, "malformed PnPUtil output: {detail}"),
        }
    }
}

impl std::error::Error for PnputilParseError {}

/// Result of a bounded, fidelity-aware parse of one `/enum-devices` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEnumeration {
    /// True when the full `/drivers /properties` shape was present.
    pub complete: bool,
    /// True when the reduced (identity-only) shape was parsed.
    pub degraded: bool,
    pub devices: Vec<DeviceIdentity>,
}

/// Which PnPUtil enumeration form the output was expected to use. The parser
/// must not conflate "legitimately reduced output" with "truncated full output".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumMode {
    /// Full `/drivers /properties` enumeration. Missing properties = truncation.
    Full,
    /// `/deviceids` enumeration. Hardware/compatible IDs present, no properties.
    IdentityOnly,
    /// Bare `/enum-devices` enumeration. Minimal identity, no IDs/properties.
    Degraded,
}

#[derive(Debug)]
enum Section {
    Header,
    Device,
    HardwareIds,
    CompatibleIds,
    ExtensionDriverNames,
    MatchingDrivers,
    Properties,
}

#[derive(Default)]
struct MatchingBuilder {
    inf_name: Option<String>,
    original_inf_name: Option<String>,
    provider: Option<String>,
    class: Option<String>,
    driver_date: Option<String>,
    driver_version: Option<String>,
    signer: Option<String>,
    rank: Option<u32>,
    status: Option<String>,
}

struct DeviceBuilder {
    instance_id: Option<String>,
    hardware_ids: Vec<String>,
    compatible_ids: Vec<String>,
    class_guid: Option<String>,
    class_name: Option<String>,
    description: Option<String>,
    manufacturer: Option<String>,
    problem_code: Option<u32>,
    top_level_driver_name: Option<String>,
    matching: Vec<MatchingBuilder>,
    saw_properties: bool,
    property_value_lines: usize,
}

impl DeviceBuilder {
    fn new(instance_id: String) -> Self {
        Self {
            instance_id: Some(instance_id),
            hardware_ids: Vec::new(),
            compatible_ids: Vec::new(),
            class_guid: None,
            class_name: None,
            description: None,
            manufacturer: None,
            problem_code: None,
            top_level_driver_name: None,
            matching: Vec::new(),
            saw_properties: false,
            property_value_lines: 0,
        }
    }

    fn has_identity_content(&self) -> bool {
        !self.hardware_ids.is_empty()
            || !self.compatible_ids.is_empty()
            || self.problem_code.is_some()
            || self.description.is_some()
            || self.class_name.is_some()
            || self.top_level_driver_name.is_some()
            || self.property_value_lines > 0
    }

    fn push_hardware_id(&mut self, raw: &str) -> Result<(), PnputilParseError> {
        push_id_checked(
            &mut self.hardware_ids,
            raw,
            MAX_HARDWARE_IDS_PER_DEVICE,
            PnputilParseError::IdsPerDeviceExceeded,
        )
    }

    fn push_compatible_id(&mut self, raw: &str) -> Result<(), PnputilParseError> {
        push_id_checked(
            &mut self.compatible_ids,
            raw,
            MAX_COMPATIBLE_IDS_PER_DEVICE,
            PnputilParseError::IdsPerDeviceExceeded,
        )
    }

    fn push_matching(&mut self, entry: MatchingBuilder) -> Result<(), PnputilParseError> {
        if self.matching.len() >= MAX_MATCHING_DRIVERS_PER_DEVICE {
            return Err(PnputilParseError::MatchingDriversExceeded);
        }
        self.matching.push(entry);
        Ok(())
    }

    fn finish(self) -> Result<(DeviceIdentity, bool), PnputilParseError> {
        let saw_properties = self.saw_properties;

        // A device block with no identity content was truncated immediately
        // after its instance ID (or before any property), which must fail
        // closed rather than surface a fabricated partial device.
        if !self.has_identity_content() {
            return Err(PnputilParseError::Malformed(
                "device block is truncated before any identity content".into(),
            ));
        }

        // When a full `/properties` enumeration was selected, the property
        // section must be structurally complete: at least one property value
        // line must follow a header, otherwise the section was truncated right
        // after its opening header.
        if saw_properties && self.property_value_lines == 0 {
            return Err(PnputilParseError::Malformed(
                "device block is truncated inside its properties section".into(),
            ));
        }

        let instance_id = self
            .instance_id
            .ok_or(PnputilParseError::MissingInstanceId)?;

        let mut matching: Vec<MatchingDriver> = Vec::with_capacity(self.matching.len());
        for entry in &self.matching {
            let inf_name = entry.inf_name.clone().ok_or_else(|| {
                PnputilParseError::Malformed("matching driver is missing a name".into())
            })?;
            // Every observed matching entry carries a rank and a status; their
            // absence means the entry was truncated, which must not become
            // partial success or silently lose installed-driver ownership.
            let rank = entry.rank.ok_or_else(|| {
                PnputilParseError::Malformed("matching driver is missing a rank".into())
            })?;
            if entry.status.is_none() {
                return Err(PnputilParseError::Malformed(
                    "matching driver is missing a status".into(),
                ));
            }
            matching.push(MatchingDriver {
                inf_name,
                provider: entry.provider.clone(),
                driver_date: entry.driver_date.clone(),
                driver_version: entry.driver_version.clone(),
                rank: Some(rank),
            });
        }

        // Installed marker: "Installed" present and (preferentially) not an
        // extension driver. Degraded output has no matching section, so fall
        // back to the top-level driver name only when no matching entries exist.
        let installed = if self.matching.is_empty() {
            self.top_level_driver_name.map(|inf_name| InstalledDriver {
                inf_name,
                original_inf_name: None,
                provider: None,
                class: None,
                driver_date: None,
                driver_version: None,
                signer: None,
                rank: None,
            })
        } else {
            let base_installed = self
                .matching
                .iter()
                .find(|entry| installed_status(entry) && !is_extension(entry));
            let any_installed = base_installed
                .or_else(|| self.matching.iter().find(|entry| installed_status(entry)));
            any_installed.map(|entry| InstalledDriver {
                inf_name: entry.inf_name.clone().unwrap_or_default(),
                original_inf_name: entry.original_inf_name.clone(),
                provider: entry.provider.clone(),
                class: entry.class.clone(),
                driver_date: entry.driver_date.clone(),
                driver_version: entry.driver_version.clone(),
                signer: entry.signer.clone(),
                rank: entry.rank,
            })
        };

        Ok((
            DeviceIdentity {
                instance_id,
                hardware_ids: self.hardware_ids,
                compatible_ids: self.compatible_ids,
                class_guid: self.class_guid,
                class_name: self.class_name,
                description: self.description,
                manufacturer: self.manufacturer,
                problem_code: self.problem_code,
                installed,
                matching,
            },
            saw_properties,
        ))
    }
}

fn installed_status(entry: &MatchingBuilder) -> bool {
    entry
        .status
        .as_deref()
        .is_some_and(|status| status.to_ascii_lowercase().contains("installed"))
}

fn is_extension(entry: &MatchingBuilder) -> bool {
    entry
        .status
        .as_deref()
        .is_some_and(|status| status.to_ascii_lowercase().contains("extension"))
}

/// Parse a bounded `/enum-devices` output into a fidelity-aware report.
///
/// `mode` declares the enumeration form the output was expected to use, so a
/// missing properties section is reported as truncation for full mode rather
/// than silently downgraded to a degraded success.
pub fn parse_enum_devices(
    input: &str,
    mode: EnumMode,
) -> Result<ParsedEnumeration, PnputilParseError> {
    if input.len() > MAX_OUTPUT_BYTES {
        return Err(PnputilParseError::OutputTooLarge);
    }
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(PnputilParseError::EmptyInput);
    }

    let mut devices: Vec<DeviceIdentity> = Vec::new();
    let mut current: Option<DeviceBuilder> = None;
    let mut section = Section::Header;
    let mut current_matching: Option<MatchingBuilder> = None;
    let mut pending_problem_value = false;
    let mut saw_any_property_header = false;
    let mut awaiting_property_value = false;
    let mut all_complete = true;
    let mut saw_properties_any = false;
    let mut saw_instance_label = false;

    for line in trimmed.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let is_column0 = !line.starts_with(' ') && !line.starts_with('\t');
        if is_column0 {
            // Flush any in-progress matching entry before switching sections.
            if let (Some(entry), Some(dev)) = (current_matching.take(), current.as_mut()) {
                dev.push_matching(entry)?;
            }
            // Leaving the properties section while a header still awaits its
            // value means that property was truncated. Host evidence confirms
            // empty values never appear at a section boundary (they are always
            // followed by another header), so this is a reliable fail-closed
            // signal in all enumeration modes.
            if pending_problem_value || awaiting_property_value {
                return Err(PnputilParseError::Malformed(
                    "property header is missing its value".into(),
                ));
            }
            saw_any_property_header = false;

            let (label, value) = split_label(line);
            match label {
                "Microsoft PnP Utility" => {
                    section = Section::Header;
                }
                "Instance ID" => {
                    if let Some(dev) = current.take() {
                        let (identity, device_complete) = dev.finish()?;
                        all_complete &= device_complete;
                        devices.push(identity);
                    }
                    if devices.len() >= MAX_DEVICES {
                        return Err(PnputilParseError::DeviceCountExceeded);
                    }
                    saw_instance_label = true;
                    let instance_id = parse_required_field(value, PnputilParseError::MissingInstanceId)?;
                    if instance_id.len() > MAX_INSTANCE_ID_LENGTH {
                        return Err(PnputilParseError::FieldTooLong);
                    }
                    current = Some(DeviceBuilder::new(instance_id));
                    section = Section::Device;
                }
                "Device Description" => {
                    current.as_mut().ok_or_malformed("description outside a device")?
                        .description = normalize_optional_scalar(value)?;
                    section = Section::Device;
                }
                "Class Name" => {
                    current.as_mut().ok_or_malformed("class name outside a device")?
                        .class_name = normalize_optional_scalar(value)?;
                    section = Section::Device;
                }
                "Class GUID" => {
                    current.as_mut().ok_or_malformed("class GUID outside a device")?
                        .class_guid = normalize_optional_scalar(value)?;
                    section = Section::Device;
                }
                "Manufacturer Name" => {
                    current.as_mut().ok_or_malformed("manufacturer outside a device")?
                        .manufacturer = normalize_optional_scalar(value)?;
                    section = Section::Device;
                }
                "Driver Name" => {
                    current.as_mut().ok_or_malformed("driver name outside a device")?
                        .top_level_driver_name = normalize_scalar_checked(value)?;
                    section = Section::Device;
                }
                "Extension Driver Names" => {
                    current.as_ref().ok_or_malformed("extension driver names outside a device")?;
                    section = Section::ExtensionDriverNames;
                }
                "Status" | "Problem Status" => {
                    // Informational status text; still bounded parsed input.
                    if value.len() > MAX_FIELD_LENGTH {
                        return Err(PnputilParseError::FieldTooLong);
                    }
                    section = Section::Device;
                }
                "Problem Code" => {
                    let device = current.as_mut().ok_or_malformed("problem code outside a device")?;
                    device.problem_code = Some(parse_uint_token(value)?);
                    section = Section::Device;
                }
                "Hardware IDs" => {
                    let device = current.as_mut().ok_or_malformed("hardware IDs outside a device")?;
                    device.push_hardware_id(value)?;
                    section = Section::HardwareIds;
                }
                "Compatible IDs" => {
                    let device = current.as_mut().ok_or_malformed("compatible IDs outside a device")?;
                    device.push_compatible_id(value)?;
                    section = Section::CompatibleIds;
                }
                "Matching Drivers" => {
                    current.as_ref().ok_or_malformed("matching drivers outside a device")?;
                    section = Section::MatchingDrivers;
                }
                "Properties" => {
                    current.as_ref().ok_or_malformed("properties outside a device")?;
                    section = Section::Properties;
                    if let Some(dev) = current.as_mut() {
                        dev.saw_properties = true;
                    }
                    saw_properties_any = true;
                }
                _ => {
                    return Err(PnputilParseError::Malformed(format!(
                        "unexpected top-level label: {label}"
                    )));
                }
            }
            continue;
        }

        // Indented continuation line — interpret by the active section.
        match section {
            Section::HardwareIds => {
                let device = current.as_mut().ok_or_malformed("hardware ID without a device")?;
                device.push_hardware_id(line.trim())?;
            }
            Section::CompatibleIds => {
                let device = current.as_mut().ok_or_malformed("compatible ID without a device")?;
                device.push_compatible_id(line.trim())?;
            }
            Section::ExtensionDriverNames => {
                // Extension INF names are informational only, but are still
                // parsed input and must respect the declared length bound.
                if line.trim().len() > MAX_FIELD_LENGTH {
                    return Err(PnputilParseError::FieldTooLong);
                }
            }
            Section::MatchingDrivers => {
                let (label, value) = split_label(line.trim());
                if label == "Driver Name" {
                    if let (Some(entry), Some(dev)) = (current_matching.take(), current.as_mut()) {
                        dev.push_matching(entry)?;
                    }
                    current_matching = Some(MatchingBuilder {
                        inf_name: normalize_scalar_checked(value)?,
                        ..MatchingBuilder::default()
                    });
                } else if let Some(entry) = current_matching.as_mut() {
                    apply_matching_field(entry, label, value)?;
                } else {
                    // A matching-driver field with no active driver entry means
                    // the entry was truncated before its name; fail closed.
                    return Err(PnputilParseError::Malformed(
                        "matching-driver field appears without a driver name".into(),
                    ));
                }
            }
            Section::Properties => {
                let trimmed_line = line.trim();
                let is_header = trimmed_line.contains("]:")
                    && (trimmed_line.starts_with("DEVPKEY_") || trimmed_line.starts_with('{'));
                if is_header {
                    // A new header while the previous header still awaits its
                    // value is fine: empty list/scalar values are legitimate
                    // and always followed by another header on this host.
                    pending_problem_value = trimmed_line.starts_with("DEVPKEY_Device_ProblemCode");
                    awaiting_property_value = true;
                    saw_any_property_header = true;
                } else {
                    if !saw_any_property_header {
                        return Err(PnputilParseError::Malformed(
                            "property value without a preceding header".into(),
                        ));
                    }
                    if trimmed_line.len() > MAX_FIELD_LENGTH {
                        return Err(PnputilParseError::FieldTooLong);
                    }
                    awaiting_property_value = false;
                    if pending_problem_value {
                        let device =
                            current.as_mut().ok_or_malformed("problem code without a device")?;
                        device.problem_code = Some(parse_uint_token(trimmed_line)?);
                        pending_problem_value = false;
                    }
                    if let Some(device) = current.as_mut() {
                        device.property_value_lines += 1;
                    }
                }
            }
            Section::Device | Section::Header => {
                return Err(PnputilParseError::Malformed(
                    "indented line outside an ID/matching/properties section".into(),
                ));
            }
        }
    }

    if let (Some(entry), Some(dev)) = (current_matching, current.as_mut()) {
        dev.push_matching(entry)?;
    }
    // A trailing property header at EOF with no following value is truncation.
    if pending_problem_value || awaiting_property_value {
        return Err(PnputilParseError::Malformed(
            "property header is missing its value".into(),
        ));
    }
    if let Some(dev) = current {
        let (identity, device_complete) = dev.finish()?;
        all_complete &= device_complete;
        devices.push(identity);
    }

    if !saw_instance_label || devices.is_empty() {
        return Err(PnputilParseError::Malformed(
            "no device instances found in non-empty output".into(),
        ));
    }

    let complete = saw_properties_any && all_complete;

    if mode == EnumMode::Full && !complete {
        // In full mode a missing properties section is truncation, not a
        // legitimate degraded capability.
        return Err(PnputilParseError::Malformed(
            "full enumeration output is missing properties sections".into(),
        ));
    }

    Ok(ParsedEnumeration {
        complete,
        degraded: !complete,
        devices,
    })
}

fn split_label(line: &str) -> (&str, &str) {
    match line.split_once(':') {
        Some((label, value)) => (label.trim(), value.trim()),
        None => (line.trim(), ""),
    }
}

fn normalize_scalar(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_scalar_checked(raw: &str) -> Result<Option<String>, PnputilParseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_FIELD_LENGTH {
        return Err(PnputilParseError::FieldTooLong);
    }
    Ok(Some(trimmed.to_string()))
}

/// `Unknown` is PnPUtil's placeholder for an absent scalar; model it as `None`.
fn normalize_optional_scalar(raw: &str) -> Result<Option<String>, PnputilParseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        return Ok(None);
    }
    if trimmed.len() > MAX_FIELD_LENGTH {
        return Err(PnputilParseError::FieldTooLong);
    }
    Ok(Some(trimmed.to_string()))
}

fn parse_required_field(raw: &str, error: PnputilParseError) -> Result<String, PnputilParseError> {
    let value = normalize_scalar(raw).ok_or(error)?;
    if value.len() > MAX_INSTANCE_ID_LENGTH {
        return Err(PnputilParseError::FieldTooLong);
    }
    Ok(value)
}

fn push_id_checked(
    list: &mut Vec<String>,
    raw: &str,
    cap: usize,
    error: PnputilParseError,
) -> Result<(), PnputilParseError> {
    let Some(id) = normalize_id(raw) else {
        return Ok(());
    };
    if id.len() > MAX_FIELD_LENGTH {
        return Err(PnputilParseError::FieldTooLong);
    }
    if list.iter().any(|existing| ids_equal_ci(existing, &id)) {
        return Ok(());
    }
    if list.len() >= cap {
        return Err(error);
    }
    list.push(id);
    Ok(())
}

fn apply_matching_field(
    entry: &mut MatchingBuilder,
    label: &str,
    value: &str,
) -> Result<(), PnputilParseError> {
    match label {
        "Original Name" => entry.original_inf_name = normalize_scalar_checked(value)?,
        "Provider Name" => entry.provider = normalize_scalar_checked(value)?,
        "Class Name" => entry.class = normalize_optional_scalar(value)?,
        "Class GUID" | "Matching Device ID" | "Extension ID" => {
            // These fields are not surfaced in the domain model, but they are
            // still parsed input and must respect the declared length bound.
            if value.trim().len() > MAX_FIELD_LENGTH {
                return Err(PnputilParseError::FieldTooLong);
            }
        }
        "Driver Version" => {
            let (date, version) = split_driver_version(value)?;
            entry.driver_date = date;
            entry.driver_version = version;
        }
        "Signer Name" => entry.signer = normalize_scalar_checked(value)?,
        "Driver Rank" => entry.rank = Some(parse_rank(value)?),
        "Driver Status" => entry.status = normalize_scalar_checked(value)?,
        _ => {
            // Unknown matching-driver fields are not surfaced, but are still
            // parsed input and must respect the declared length bound.
            if value.len() > MAX_FIELD_LENGTH {
                return Err(PnputilParseError::FieldTooLong);
            }
        }
    }
    Ok(())
}

fn split_driver_version(value: &str) -> Result<(Option<String>, Option<String>), PnputilParseError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok((None, None));
    }
    if trimmed.len() > MAX_FIELD_LENGTH {
        return Err(PnputilParseError::FieldTooLong);
    }
    if let Some(index) = trimmed.find(char::is_whitespace) {
        let (first, rest) = trimmed.split_at(index);
        let rest = rest.trim();
        match classify_date_token(first) {
            // Valid date prefix: split into (date, version).
            DateCheck::Valid => Ok((
                Some(first.to_string()),
                if rest.is_empty() {
                    None
                } else {
                    Some(rest.to_string())
                },
            )),
            // Date-shaped but impossible (e.g. 2025-99-99): fail closed
            // rather than storing corrupted version data.
            DateCheck::Malformed => Err(PnputilParseError::Malformed(format!(
                "invalid Driver Version date: {first}"
            ))),
            // Not date-shaped at all: keep as a version-only value.
            DateCheck::NotADate => Ok((None, Some(trimmed.to_string()))),
        }
    } else {
        // No whitespace: a lone token. If it is date-shaped it must still be
        // a real calendar date; otherwise keep the whole value as version.
        match classify_date_token(trimmed) {
            DateCheck::Valid | DateCheck::NotADate => Ok((None, Some(trimmed.to_string()))),
            DateCheck::Malformed => Err(PnputilParseError::Malformed(format!(
                "invalid Driver Version date: {trimmed}"
            ))),
        }
    }
}

enum DateCheck {
    Valid,
    Malformed,
    NotADate,
}

/// Recognize the date forms PnPUtil emits in Driver Version values:
/// slash form (`09/16/2025`) and ISO form (`2025-09-16`). Anything that is
/// not date-shaped is `NotADate` (kept version-only); anything date-shaped
/// but calendar-impossible is `Malformed` and fails parsing closed.
fn classify_date_token(token: &str) -> DateCheck {
    fn parse_u32(s: &str) -> Option<u32> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    }

    fn is_leap_year(y: u32) -> bool {
        (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
    }

    fn days_in_month(y: u32, m: u32) -> u32 {
        match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if is_leap_year(y) => 29,
            2 => 28,
            _ => 0,
        }
    }

    let (year, month, day): (u32, u32, u32);
    if token.contains('/') {
        // Slash form: MM/DD/YYYY.
        let parts: Vec<&str> = token.split('/').collect();
        if parts.len() != 3 || parts[0].len() != 2 || parts[1].len() != 2 || parts[2].len() != 4 {
            return DateCheck::NotADate;
        }
        let (Some(m), Some(d), Some(y)) = (
            parse_u32(parts[0]),
            parse_u32(parts[1]),
            parse_u32(parts[2]),
        ) else {
            return DateCheck::NotADate;
        };
        year = y;
        month = m;
        day = d;
    } else if token.contains('-') {
        // ISO form: YYYY-MM-DD.
        let parts: Vec<&str> = token.split('-').collect();
        if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
            return DateCheck::NotADate;
        }
        let (Some(y), Some(m), Some(d)) = (
            parse_u32(parts[0]),
            parse_u32(parts[1]),
            parse_u32(parts[2]),
        ) else {
            return DateCheck::NotADate;
        };
        year = y;
        month = m;
        day = d;
    } else {
        return DateCheck::NotADate;
    }
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return DateCheck::Malformed;
    }
    DateCheck::Valid
}

/// Parse a rank token. Observed PnPUtil emits bare hexadecimal (e.g. `00FF0001`).
fn parse_rank(value: &str) -> Result<u32, PnputilParseError> {
    let trimmed = value.trim();
    u32::from_str_radix(trimmed, 16).map_err(|_| {
        PnputilParseError::Malformed(format!("invalid driver rank: {trimmed}"))
    })
}

/// Parse a numeric field that may be decimal or `0x`-prefixed hexadecimal.
fn parse_uint_token(value: &str) -> Result<u32, PnputilParseError> {
    let token = value
        .split_whitespace()
        .next()
        .ok_or_else(|| PnputilParseError::Malformed("missing numeric value".into()))?;
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
            .map_err(|_| PnputilParseError::Malformed(format!("invalid hex value: {token}")))
    } else {
        token
            .parse::<u32>()
            .map_err(|_| PnputilParseError::Malformed(format!("invalid decimal value: {token}")))
    }
}

trait OrMalformed<T> {
    fn ok_or_malformed(self, detail: &str) -> Result<T, PnputilParseError>;
}

impl<T> OrMalformed<T> for Option<T> {
    fn ok_or_malformed(self, detail: &str) -> Result<T, PnputilParseError> {
        self.ok_or_else(|| PnputilParseError::Malformed(detail.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_driver_version_parses_date_and_version() {
        assert_eq!(
            split_driver_version("09/16/2025 6.0.9888.1").unwrap(),
            (Some("09/16/2025".into()), Some("6.0.9888.1".into()))
        );
        assert_eq!(
            split_driver_version("2025-09-16 6.0.9888.1").unwrap(),
            (Some("2025-09-16".into()), Some("6.0.9888.1".into()))
        );
        assert_eq!(
            split_driver_version("6.0.9888.1").unwrap(),
            (None, Some("6.0.9888.1".into()))
        );
        assert_eq!(split_driver_version("").unwrap(), (None, None));

        // Impossible calendar values are date-shaped but invalid: they must
        // fail parsing closed, never silently become version-only strings.
        assert!(matches!(
            split_driver_version("2025-99-99 6.0.9888.1"),
            Err(PnputilParseError::Malformed(_))
        ));
        assert!(matches!(
            split_driver_version("99/99/2025 6.0.9888.1"),
            Err(PnputilParseError::Malformed(_))
        ));
        // Day must exist in its month (leap years included).
        assert!(matches!(
            split_driver_version("02/30/2024 1.0.0.0"),
            Err(PnputilParseError::Malformed(_))
        ));
        assert_eq!(
            split_driver_version("02/29/2024 1.0.0.0").unwrap(),
            (Some("02/29/2024".into()), Some("1.0.0.0".into()))
        );
        assert!(matches!(
            split_driver_version("2025-02-29 1.0.0.0"),
            Err(PnputilParseError::Malformed(_))
        ));
        // Pre-1980 dates remain valid; no artificial year floor.
        assert_eq!(
            split_driver_version("07/18/1968 1.0.0.0").unwrap(),
            (Some("07/18/1968".into()), Some("1.0.0.0".into()))
        );
        // A lone date-shaped impossible token also fails closed.
        assert!(matches!(
            split_driver_version("2025-99-99"),
            Err(PnputilParseError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rank_accepts_hex() {
        assert_eq!(parse_rank("00FF0001").unwrap(), 0x00FF_0001);
        assert_eq!(parse_rank("00000000").unwrap(), 0);
        assert!(parse_rank("not-hex").is_err());
    }

    #[test]
    fn parse_uint_token_accepts_hex_and_decimal() {
        assert_eq!(parse_uint_token("0x00000000 (0)").unwrap(), 0);
        assert_eq!(parse_uint_token("0x0000001C (28)").unwrap(), 28);
        assert_eq!(parse_uint_token("28 (0x1C)").unwrap(), 28);
        assert_eq!(parse_uint_token("10").unwrap(), 10);
    }
}
