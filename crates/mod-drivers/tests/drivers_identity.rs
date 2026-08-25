// Integration tests for the drivers identity inventory slice.
//
// Fixture origin: reduced, sanitized captures of real `pnputil /enum-devices`
// output from a Windows 11 host (see the slice's output-format reconnaissance).
// Section structure and field syntax are preserved; concrete instance/device
// identifiers are representative but synthetic where possible.

use mod_drivers::identity::{
    DeviceIdentity, DriverIdentityReport, InstalledDriver, MachineContext, MatchingDriver,
};
use mod_drivers::pnputil::{parse_enum_devices, EnumMode, PnputilParseError};
use mod_drivers::{DriverEntry, DriverReport};

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read_to_string(path).expect("fixture should read")
}

fn parse_full_fixture(name: &str) -> Vec<DeviceIdentity> {
    let output = fixture(name);
    parse_enum_devices(&output, EnumMode::Full)
        .expect("fixture should parse")
        .devices
}

fn parse_identity_fixture(name: &str) -> Vec<DeviceIdentity> {
    let output = fixture(name);
    parse_enum_devices(&output, EnumMode::IdentityOnly)
        .expect("fixture should parse")
        .devices
}

// ---------------------------------------------------------------------------
// R1 — Ordered multi-ID parsing
// ---------------------------------------------------------------------------

#[test]
fn r1_ordered_multi_id_parsing() {
    let devices = parse_full_fixture("full_multi_id.txt");
    assert_eq!(devices.len(), 1, "exactly one device expected");
    let device = &devices[0];

    assert_eq!(
        device.instance_id,
        "HDAUDIO\\FUNC_01&VEN_10EC&DEV_0897&SUBSYS_104387FB&REV_1005\\5&305ca84b&0&0001"
    );

    // At least 4 hardware IDs, in source order, not merged with compatible IDs.
    assert!(device.hardware_ids.len() >= 4);
    assert_eq!(
        device.hardware_ids,
        vec![
            "HDAUDIO\\FUNC_01&VEN_10EC&DEV_0897&SUBSYS_104387FB&REV_1005",
            "HDAUDIO\\FUNC_01&VEN_10EC&DEV_0897&SUBSYS_104387FB",
            "HDAUDIO\\FUNC_01&VEN_10EC&DEV_0897&REV_1005",
            "HDAUDIO\\FUNC_01&VEN_10EC&DEV_0897",
        ]
    );

    // At least 3 compatible IDs, in source order, kept separate.
    assert!(device.compatible_ids.len() >= 3);
    assert_eq!(
        device.compatible_ids,
        vec![
            "HDAUDIO\\FUNC_01&CTLR_VEN_1022&VEN_10EC&DEV_0897",
            "HDAUDIO\\FUNC_01&VEN_10EC&DEV_0897",
            "HDAUDIO\\FUNC_01",
        ]
    );
}

// ---------------------------------------------------------------------------
// R1-ISO — ISO-style Driver Version dates (Tab 2a-1R / P2-BACKEND-1)
// ---------------------------------------------------------------------------

#[test]
fn r1iso_driver_version_iso_date_parsed() {
    let devices = parse_full_fixture("iso_driver_date.txt");
    assert_eq!(devices.len(), 1, "exactly one device expected");

    // The installed driver's Driver Version carries an ISO-style date.
    let installed = devices[0].installed.as_ref().expect("installed driver expected");
    assert_eq!(installed.driver_date.as_deref(), Some("2025-09-16"));
    assert_eq!(installed.driver_version.as_deref(), Some("6.0.9888.1"));

    // The matching-driver list must agree with the installed entry.
    assert_eq!(devices[0].matching.len(), 1);
    assert_eq!(devices[0].matching[0].driver_date.as_deref(), Some("2025-09-16"));
    assert_eq!(
        devices[0].matching[0].driver_version.as_deref(),
        Some("6.0.9888.1")
    );
}

/// Pin existing slash-date and version-only behavior so the ISO repair
/// cannot regress it (exercised through the realistic parse path).
#[test]
fn driver_version_slash_and_version_only_regression() {
    let devices = parse_full_fixture("rank_formats.txt");
    let installed = devices[0].installed.as_ref().expect("installed driver expected");
    assert_eq!(installed.driver_date.as_deref(), Some("03/04/2026"));
    assert_eq!(installed.driver_version.as_deref(), Some("1.4.40.0"));
}

// ---------------------------------------------------------------------------
// R2 — Case-insensitive identity comparison / casing preservation
// ---------------------------------------------------------------------------

#[test]
fn r2_case_insensitive_comparison_casing_preserved() {
    let devices = parse_identity_fixture("case_duplicate_ids.txt");
    let device = &devices[0];

    // The lowercase duplicate is deduplicated case-insensitively, first value
    // and its original casing survive, and the list is not globally lowercased.
    assert_eq!(
        device.hardware_ids,
        vec![
            "PCI\\VEN_1022&DEV_1649&SUBSYS_88771043",
            "PCI\\VEN_1022&DEV_1649",
            "PCI\\VEN_1022&DEV_1649&REV_00",
        ]
    );
}

// ---------------------------------------------------------------------------
// R3 — Windows driver rank parsing
// ---------------------------------------------------------------------------

#[test]
fn r3_driver_rank_parsing() {
    let devices = parse_full_fixture("rank_formats.txt");
    let device = &devices[0];

    assert_eq!(device.matching.len(), 3, "three matching drivers expected");

    // Ranks are captured exactly (hex -> integer), not recalculated.
    assert_eq!(device.matching[0].rank, Some(0x00FF_0000));
    assert_eq!(device.matching[1].rank, Some(0x00FF_3000));
    assert_eq!(device.matching[2].rank, Some(0x00FF_3001));

    // Lower rank remains lower; source ordering is preserved.
    assert!(device.matching[0].rank.unwrap() < device.matching[1].rank.unwrap());
    assert!(device.matching[1].rank.unwrap() < device.matching[2].rank.unwrap());

    // The installed entry is distinguished from outranked alternatives.
    let installed = device.installed.as_ref().expect("installed driver expected");
    assert_eq!(installed.inf_name, "oem12.inf");
    assert_eq!(installed.rank, Some(0x00FF_0000));
    assert_eq!(installed.driver_version.as_deref(), Some("1.4.40.0"));
    assert_eq!(installed.driver_date.as_deref(), Some("03/04/2026"));

    // Outranked entries are never conflated with the installed driver.
    assert_eq!(device.matching[1].inf_name, "c_swcomponent.inf");
    assert_eq!(device.matching[2].inf_name, "c_swdevice.inf");
    assert_ne!(device.matching[1].inf_name, installed.inf_name);
}

// ---------------------------------------------------------------------------
// R4 — Problem-code extraction
// ---------------------------------------------------------------------------

#[test]
fn r4_problem_code_extraction() {
    let devices = parse_full_fixture("problem_codes.txt");
    assert_eq!(devices.len(), 4);

    // Healthy device represented as explicit zero.
    assert_eq!(devices[0].instance_id, "ACPI\\PNP0B00\\4&11544ea4&0");
    assert_eq!(devices[0].problem_code, Some(0));

    // Code 28 stays code 28 (not collapsed into a string-only missing state).
    assert_eq!(devices[1].problem_code, Some(28));

    // A different non-zero problem code stays exact.
    assert_eq!(devices[2].problem_code, Some(10));

    // Absent problem-code field is represented as None, not fabricated.
    assert_eq!(devices[3].problem_code, None);
}

// ---------------------------------------------------------------------------
// R5 — Duplicate hardware across distinct devices
// ---------------------------------------------------------------------------

#[test]
fn r5_duplicate_hardware_distinct_devices() {
    let devices = parse_identity_fixture("duplicate_hardware_two_devices.txt");
    assert_eq!(devices.len(), 2, "two distinct devices expected");

    assert_ne!(devices[0].instance_id, devices[1].instance_id);
    assert_eq!(devices[0].hardware_ids, devices[1].hardware_ids);
}

// ---------------------------------------------------------------------------
// R6 — Malformed / truncated output
// ---------------------------------------------------------------------------

#[test]
fn r6_empty_output_is_err() {
    assert!(matches!(
        parse_enum_devices("", EnumMode::Full),
        Err(PnputilParseError::EmptyInput)
    ));
    assert!(matches!(
        parse_enum_devices("   \r\n\t ", EnumMode::Full),
        Err(PnputilParseError::EmptyInput)
    ));
}

#[test]
fn r6_missing_instance_identity_is_err() {
    // Truncated right after the label with no instance-id value.
    let truncated = "Microsoft PnP Utility\n\nInstance ID:                \n";
    assert!(matches!(
        parse_enum_devices(truncated, EnumMode::Full),
        Err(PnputilParseError::MissingInstanceId)
    ));
}

#[test]
fn r6_impossible_section_ordering_is_err() {
    // Properties before any device block is structurally impossible.
    let impossible = "Microsoft PnP Utility\n\nProperties:\n    DEVPKEY_Device_DeviceDesc [String]:\n";
    assert!(matches!(
        parse_enum_devices(impossible, EnumMode::Full),
        Err(PnputilParseError::Malformed(_))
    ));
}

#[test]
fn r6_truncated_device_after_complete_device_fails_closed() {
    // One complete device with Properties, then a second device truncated
    // immediately after its instance ID (no identity content). This must not
    // return a fabricated partial device or a full report.
    let mut input = String::from(fixture("full_multi_id.txt"));
    input.push_str("\nInstance ID:                TEST\\DEVICE\\TRUNCATED\n");
    assert!(parse_enum_devices(&input, EnumMode::Full).is_err());
}

#[test]
fn r6_trailing_property_header_fails_closed() {
    // A property header with no following value and no further header, ending
    // at EOF, is truncation. Empty values on this host are always followed by
    // another header, never by a section boundary.
    let input = "Microsoft PnP Utility\n\nInstance ID:                TEST\\DEVICE\\0\nHardware IDs:               TEST\\HW0\nProperties:\n    DEVPKEY_Device_DeviceDesc [String]:\n";
    assert!(matches!(
        parse_enum_devices(input, EnumMode::Full),
        Err(PnputilParseError::Malformed(_))
    ));
}

#[test]
fn r6_full_mode_missing_properties_is_err() {
    // A device with identity content but no Properties section is fine in
    // identity-only mode, but must fail closed in full mode (truncation).
    let input = "Microsoft PnP Utility\n\nInstance ID:                TEST\\DEVICE\\0\nHardware IDs:               TEST\\HW0\n";
    assert!(matches!(
        parse_enum_devices(input, EnumMode::Full),
        Err(PnputilParseError::Malformed(_))
    ));
    assert!(parse_enum_devices(input, EnumMode::IdentityOnly).is_ok());
}

// ---------------------------------------------------------------------------
// R7 — Parser bounds
// ---------------------------------------------------------------------------

#[test]
fn r7_device_count_cap_exceeded() {
    let cap = mod_drivers::identity::MAX_DEVICES;
    let mut input = String::from("Microsoft PnP Utility\n");
    for i in 0..=cap {
        input.push_str(&format!(
            "\nInstance ID:                TEST\\DEVICE\\{i}\nHardware IDs:               TEST\\HW{i}\n"
        ));
    }
    assert!(matches!(
        parse_enum_devices(&input, EnumMode::IdentityOnly),
        Err(PnputilParseError::DeviceCountExceeded)
    ));
}

#[test]
fn r7_field_length_cap_exceeded() {
    let cap = mod_drivers::identity::MAX_FIELD_LENGTH;
    let long_id = "A".repeat(cap + 1);
    let input = format!(
        "Microsoft PnP Utility\n\nInstance ID:                TEST\\DEVICE\\0\nHardware IDs:               {long_id}\n"
    );
    assert!(matches!(
        parse_enum_devices(&input, EnumMode::IdentityOnly),
        Err(PnputilParseError::FieldTooLong)
    ));
}

#[test]
fn r7_ids_per_device_cap_exceeded() {
    let cap = mod_drivers::identity::MAX_HARDWARE_IDS_PER_DEVICE;
    let mut input = String::from(
        "Microsoft PnP Utility\n\nInstance ID:                TEST\\DEVICE\\0\nHardware IDs:               TEST\\HW0\n",
    );
    for i in 1..=cap {
        input.push_str(&format!("                            TEST\\HW{i}\n"));
    }
    assert!(matches!(
        parse_enum_devices(&input, EnumMode::IdentityOnly),
        Err(PnputilParseError::IdsPerDeviceExceeded)
    ));
}

// ---------------------------------------------------------------------------
// R8 — Older/limited Windows degradation
// ---------------------------------------------------------------------------

#[test]
fn r8_limited_windows_degradation() {
    let report = parse_enum_devices(&fixture("degraded_limited.txt"), EnumMode::IdentityOnly)
        .expect("degraded fixture should parse");
    assert!(report.degraded, "report must mark limited output as degraded");
    assert_eq!(report.devices.len(), 2);

    // Available identity is retained.
    assert_eq!(report.devices[0].instance_id, "ACPI\\PNP0B00\\4&11544ea4&0");
    assert_eq!(report.devices[0].hardware_ids.len(), 3);

    // Missing ID collections are empty; missing scalar metadata is None.
    assert!(report.devices[0].compatible_ids.is_empty());
    assert_eq!(report.devices[0].problem_code, None);
    assert!(report.devices[0].matching.is_empty());

    // The installed driver name (the only available signal) is retained.
    assert_eq!(
        report.devices[0].installed.as_ref().map(|d| d.inf_name.as_str()),
        Some("machine.inf")
    );

    // A problem device still exposes its explicit problem code.
    assert_eq!(report.devices[1].problem_code, Some(28));
    assert_eq!(
        report.devices[1].compatible_ids,
        vec!["ACPI\\AMDIF031", "AMDIF031"]
    );
}

// ---------------------------------------------------------------------------
// R9 — Existing DriverReport JSON compatibility
// ---------------------------------------------------------------------------

#[test]
fn r9_existing_driver_report_json_shape_unchanged() {
    let report = DriverReport {
        complete: true,
        error: None,
        total: 2,
        unsigned: 1,
        outdated: None,
        problematic: vec![DriverEntry {
            name: "Problem Device".into(),
            device: "Net".into(),
            version: "1.0".into(),
            date: "2024-01-01".into(),
            signed: Some(false),
            status: "unsigned".into(),
        }],
        healthy: vec![DriverEntry {
            name: "Healthy Device".into(),
            device: "System".into(),
            version: "2.0".into(),
            date: "2024-01-02".into(),
            signed: Some(true),
            status: "ok".into(),
        }],
    };

    let actual = serde_json::to_value(&report).expect("legacy report serializes");
    let expected = serde_json::json!({
        "complete": true,
        "error": null,
        "total": 2,
        "unsigned": 1,
        "outdated": null,
        "problematic": [{
            "name": "Problem Device",
            "device": "Net",
            "version": "1.0",
            "date": "2024-01-01",
            "signed": false,
            "status": "unsigned"
        }],
        "healthy": [{
            "name": "Healthy Device",
            "device": "System",
            "version": "2.0",
            "date": "2024-01-02",
            "signed": true,
            "status": "ok"
        }]
    });

    assert_eq!(actual, expected, "legacy DriverReport JSON shape changed");
}

// ---------------------------------------------------------------------------
// Cross-field sanity for the new identity types (serializable + present)
// ---------------------------------------------------------------------------

#[test]
fn identity_types_are_serializable() {
    let report = DriverIdentityReport {
        complete: true,
        degraded: false,
        error: None,
        machine: MachineContext {
            arch: "x64".into(),
            os_build: "26200".into(),
            os_version: "10.0".into(),
        },
        devices: vec![DeviceIdentity {
            instance_id: "TEST\\0".into(),
            hardware_ids: vec!["TEST\\HW0".into()],
            compatible_ids: vec![],
            class_guid: Some("{00000000-0000-0000-0000-000000000000}".into()),
            class_name: Some("System".into()),
            description: Some("Test device".into()),
            manufacturer: Some("Test".into()),
            problem_code: Some(0),
            installed: Some(InstalledDriver {
                inf_name: "test.inf".into(),
                original_inf_name: None,
                provider: None,
                class: None,
                driver_date: None,
                driver_version: None,
                signer: None,
                rank: Some(0),
            }),
            matching: vec![MatchingDriver {
                inf_name: "test.inf".into(),
                provider: None,
                driver_date: None,
                driver_version: None,
                rank: Some(0),
            }],
        }],
    };

    let value = serde_json::to_value(&report).expect("identity report serializes");
    assert!(value.get("machine").is_some());
    assert!(value.get("devices").is_some());
    assert_eq!(value.get("complete").and_then(|v| v.as_bool()), Some(true));
}
