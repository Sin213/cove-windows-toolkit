// Integration tests for Tab 2a-3: device → SDIO catalog candidate matching.
//
// The matcher performs candidate DISCOVERY only. It never classifies a candidate
// as newer / better / recommended / an update, and never derives a Windows rank.
// `Candidate::inf_pos` is SDIO metadata, preserved verbatim.
//
// R1/R2/R3/R7 exercise the committed real SDIO fixture (`valid_small.bin`, the
// `DP_Display_SDIO01_26082` display pack). Scenarios the real fixture cannot
// expose (multiple IDs resolving to one model row, cross-INF collisions, >cap
// buckets) are built as in-memory `SdioCatalog` values through the public record
// constructors — no fake SDW binary grammar, no fixture mutation.

use std::collections::HashMap;

use mod_drivers::identity::DeviceIdentity;
use mod_drivers::sdio::{
    Candidate, CatalogCandidateMatch, DataDesc, DataHwid, DataInfFile, DataManuf,
    DeviceCatalogMatches, DeviceIdKind, MAX_CANDIDATES_PER_DEVICE, MAX_CATALOGS_PER_MATCH,
    MAX_DEVICES_PER_MATCH, MAX_EVIDENCE_PER_CANDIDATE, MatchError, MatchEvidence, SdioCatalog,
    match_device_to_catalogs, match_devices_to_catalogs,
};

const VALID_BYTES: &[u8] = include_bytes!("../fixtures/sdio/valid_small.bin");

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Parse the committed real SDIO fixture with an explicit pack name.
fn fixture_catalog(pack_name: &str) -> SdioCatalog {
    SdioCatalog::parse_bytes(VALID_BYTES, pack_name.to_string()).expect("fixture must parse")
}

/// Real GPU hardware ID present in the fixture (`u0202099.inf`,
/// `ati2mtag_StrixHalo` / `ati2mtag_strixhalo`).
const GPU_HWID: &str = "PCI\\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1";

fn device(instance_id: &str, hardware_ids: &[&str], compatible_ids: &[&str]) -> DeviceIdentity {
    DeviceIdentity {
        instance_id: instance_id.to_string(),
        hardware_ids: hardware_ids.iter().map(|s| s.to_string()).collect(),
        compatible_ids: compatible_ids.iter().map(|s| s.to_string()).collect(),
        class_guid: None,
        class_name: None,
        description: None,
        manufacturer: None,
        problem_code: None,
        installed: None,
        matching: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// In-memory synthetic catalog builder (matching-domain level)
// ---------------------------------------------------------------------------

/// Build a catalog with one INF (`synth.inf`, provider "Synth Corp", class
/// "Display") and one model row per unique `(install, picked)` tuple. Every row
/// is `(hwid, install, picked, inf_pos)`. Multiple rows may share an exact hwid
/// string (to model an untrusted oversized bucket) and multiple hwids may share
/// a tuple (to model one logical candidate reachable via several IDs).
fn synthetic_catalog(pack_name: &str, rows: &[(&str, &str, &str, i32)]) -> SdioCatalog {
    let inf = DataInfFile {
        inf_path: "synth\\synth.inf".to_string(),
        inf_filename: "synth.inf".to_string(),
        fields: {
            let mut f: [Option<String>; 10] = Default::default();
            f[mod_drivers::sdio::FIELD_PROVIDER] = Some("Synth Corp".to_string());
            f[mod_drivers::sdio::FIELD_CLASS] = Some("Display".to_string());
            f
        },
        cats: Default::default(),
        date: Some((2026, 6, 29)),
        version: Some((1, 0, 0, 0)),
        infsize: Some(1),
        infcrc: Some(1),
        reserved_a: 0,
        reserved_b: 0,
    };

    let mut desc_records: Vec<DataDesc> = Vec::new();
    let mut tuple_to_desc: HashMap<(String, String), usize> = HashMap::new();
    let mut hwid_records: Vec<DataHwid> = Vec::new();
    let mut hash_map: HashMap<String, Vec<usize>> = HashMap::new();

    for (hwid, install, picked, inf_pos) in rows {
        let key = (install.to_string(), picked.to_string());
        let desc_index = *tuple_to_desc.entry(key).or_insert_with(|| {
            let idx = desc_records.len();
            desc_records.push(DataDesc {
                manufacturer_index: 0,
                sect_pos: 0,
                desc: format!("{install} model"),
                install: install.to_string(),
                install_picked: picked.to_string(),
                feature: 0,
            });
            idx
        });
        let hwid_index = hwid_records.len();
        hwid_records.push(DataHwid {
            desc_index: desc_index as u32,
            inf_pos: *inf_pos,
            hwid: hwid.to_string(),
        });
        hash_map
            .entry(hwid.to_uppercase())
            .or_default()
            .push(hwid_index);
    }

    SdioCatalog {
        pack_name: pack_name.to_string(),
        inf_records: vec![inf],
        manuf_records: vec![DataManuf {
            inffile_index: 0,
            manufacturer: "Synth Corp".to_string(),
            sections: vec!["synth".to_string()],
            sections_n: 1,
        }],
        desc_records,
        hwid_records,
        text_pool: Vec::new(),
        hash_map,
    }
}

/// Reject a match error that must be the named variant. Works for both the
/// single-device and the batch result shape.
fn assert_err_kind<T>(result: Result<T, MatchError>, kind: &str) {
    match result {
        Err(e) => {
            let name = match e {
                MatchError::TooManyDevices(_) => "TooManyDevices",
                MatchError::TooManyCatalogs(_) => "TooManyCatalogs",
                MatchError::TooManyDeviceIds(_) => "TooManyDeviceIds",
                MatchError::TooManyCandidates => "TooManyCandidates",
                MatchError::TooManyTotalCandidates => "TooManyTotalCandidates",
                MatchError::TooMuchEvidence => "TooMuchEvidence",
                MatchError::Catalog(_) => "Catalog",
            };
            assert_eq!(name, kind, "expected {kind}, got {name}: {e}");
        }
        Ok(_) => panic!("expected {kind} error, got Ok"),
    }
}

// ---------------------------------------------------------------------------
// R1 — exact hardware-ID match (real fixture)
// ---------------------------------------------------------------------------

#[test]
fn r1_exact_hardware_id_match() {
    let cat = fixture_catalog("DP_Display_SDIO01_26082");
    let dev = device(
        "PCI\\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1\\0",
        &[GPU_HWID],
        &[],
    );

    let result = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");
    assert!(
        !result.candidates.is_empty(),
        "candidate count > 0 expected"
    );

    let m = &result.candidates[0];
    assert_eq!(m.pack_name, "DP_Display_SDIO01_26082");
    assert_eq!(m.candidate.inf_filename, "u0202099.inf");
    assert_eq!(m.candidate.install_section, "ati2mtag_StrixHalo");
    assert_eq!(m.candidate.picked_section, "ati2mtag_strixhalo");

    let ev = &m.evidence[0];
    assert_eq!(ev.kind, DeviceIdKind::Hardware);
    assert_eq!(ev.ordinal, 0, "GPU ID is hardware_ids[0]");
    assert_eq!(ev.device_id, GPU_HWID);
    // SDIO metadata is preserved, not turned into a rank.
    assert_eq!(ev.inf_pos, 0);
}

// ---------------------------------------------------------------------------
// R2 — case-insensitive lookup, device-side casing preserved
// ---------------------------------------------------------------------------

#[test]
fn r2_case_insensitive_lookup_preserves_device_casing() {
    let cat = fixture_catalog("DP_Display_SDIO01_26082");
    let lower = GPU_HWID.to_lowercase();
    let dev = device("PCI\\0", &[&lower], &[]);

    let result = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");
    assert_eq!(result.candidates.len(), 1, "lowercase ID must resolve");
    let ev = &result.candidates[0].evidence[0];
    assert_eq!(ev.kind, DeviceIdKind::Hardware);
    // The stored display value keeps the device's original casing verbatim.
    assert_eq!(ev.device_id, lower, "device-side casing must be preserved");
    assert_ne!(ev.device_id, GPU_HWID.to_string());
}

// ---------------------------------------------------------------------------
// R3 — compatible-ID match (real fixture) + inf_pos preservation (synthetic)
// ---------------------------------------------------------------------------

#[test]
fn r3_compatible_id_match_real_fixture() {
    let cat = fixture_catalog("DP_Display_SDIO01_26082");
    // hardware_ids produce no match; compatible_ids[1] holds a real fixture ID.
    let dev = device(
        "PCI\\0",
        &["PCI\\VEN_FFFF&DEV_FFFF"],
        &["PCI\\VEN_EEEE&DEV_EEEE", GPU_HWID],
    );

    let result = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");
    assert_eq!(result.candidates.len(), 1);
    let ev = &result.candidates[0].evidence[0];
    assert_eq!(ev.kind, DeviceIdKind::Compatible);
    assert_eq!(ev.ordinal, 1, "GPU ID is compatible_ids[1]");
    assert_eq!(result.candidates[0].candidate.inf_filename, "u0202099.inf");
    // inf_pos preserved verbatim from SDIO metadata (0 for this fixture record).
    assert_eq!(ev.inf_pos, 0);
}

#[test]
fn r3b_compatible_inf_pos_preserved_as_sdio_metadata_not_rank() {
    // A synthetic catalog row whose SDIO metadata carries inf_pos = 5. The
    // matcher must surface it unchanged and must not derive any Windows rank.
    let cat = synthetic_catalog(
        "synth",
        &[
            ("PCI\\VEN_AAAA&DEV_0001", "M1", "m1", 0),
            ("PCI\\VEN_BBBB&DEV_0001", "M2", "m2", 5),
        ],
    );
    let dev = device(
        "PCI\\0",
        &["PCI\\VEN_AAAA&DEV_0001"],
        &["PCI\\VEN_BBBB&DEV_0001"],
    );

    let result = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");
    assert_eq!(result.candidates.len(), 2);

    let compat = &result.candidates[1];
    assert_eq!(compat.evidence[0].kind, DeviceIdKind::Compatible);
    assert_eq!(
        compat.evidence[0].inf_pos, 5,
        "SDIO inf_pos must be preserved"
    );
    // The matching result type carries discovery metadata only — no rank field
    // exists to compare against. inf_pos remains an `i32` provenance value.
    assert_eq!(compat.candidate.inf_pos, 5);
}

// ---------------------------------------------------------------------------
// R4 — hardware evidence precedes compatible evidence for one candidate
// ---------------------------------------------------------------------------

#[test]
fn r4_hardware_evidence_precedes_compatible_evidence() {
    // One logical candidate (tuple M1) reachable via hardware ID "H1" and
    // compatible ID "C1".
    let cat = synthetic_catalog(
        "synth",
        &[
            ("H1", "M1", "m1", 0),
            ("C1", "M1", "m1", 1),
            ("H2", "M2", "m2", 0),
        ],
    );
    let dev = device("PCI\\0", &["H1"], &["C1"]);

    let result = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");
    assert_eq!(result.candidates.len(), 1, "one logical candidate expected");
    let m = &result.candidates[0];
    assert_eq!(m.evidence.len(), 2, "both discovery paths retained");
    assert_eq!(m.evidence[0].kind, DeviceIdKind::Hardware);
    assert_eq!(m.evidence[0].ordinal, 0);
    assert_eq!(m.evidence[0].device_id, "H1");
    assert_eq!(m.evidence[1].kind, DeviceIdKind::Compatible);
    assert_eq!(m.evidence[1].ordinal, 0);
    assert_eq!(m.evidence[1].device_id, "C1");
}

// ---------------------------------------------------------------------------
// R5 — same candidate via multiple hardware IDs dedupes
// ---------------------------------------------------------------------------

#[test]
fn r5_same_candidate_via_multiple_ids_dedupes() {
    let cat = synthetic_catalog(
        "synth",
        &[
            ("H1", "M1", "m1", 0),
            ("H2", "M1", "m1", 0),
            ("H3", "M1", "m1", 0),
        ],
    );
    let dev = device("PCI\\0", &["H1", "H2", "H3"], &[]);

    let result = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");
    assert_eq!(result.candidates.len(), 1, "dedupe to one candidate");
    let m = &result.candidates[0];
    assert_eq!(m.evidence.len(), 3, "no evidence discarded");
    for (i, ev) in m.evidence.iter().enumerate() {
        assert_eq!(ev.kind, DeviceIdKind::Hardware);
        assert_eq!(ev.ordinal, i);
    }
}

// ---------------------------------------------------------------------------
// R6 — different model/install sections on the same INF remain distinct
// ---------------------------------------------------------------------------

#[test]
fn r6_distinct_install_sections_do_not_collapse() {
    // Two tuples share the same INF (synth.inf) but differ in install/picked.
    let cat = synthetic_catalog(
        "synth",
        &[
            ("H1", "ati2mtag_StrixHalo", "ati2mtag_strixhalo", 0),
            ("H2", "ati2mtag_Legacy", "ati2mtag_legacy", 0),
        ],
    );
    let dev = device("PCI\\0", &["H1", "H2"], &[]);

    let result = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");
    assert_eq!(
        result.candidates.len(),
        2,
        "install/picked sections must not collapse"
    );
    assert_eq!(
        result.candidates[0].candidate.install_section,
        "ati2mtag_StrixHalo"
    );
    assert_eq!(
        result.candidates[1].candidate.install_section,
        "ati2mtag_Legacy"
    );
    assert_eq!(result.candidates[0].candidate.inf_filename, "synth.inf");
    assert_eq!(result.candidates[1].candidate.inf_filename, "synth.inf");
}

// ---------------------------------------------------------------------------
// R7 — cross-pack candidates remain distinct (real fixture, two pack names)
// ---------------------------------------------------------------------------

#[test]
fn r7_cross_pack_candidates_remain_distinct() {
    let cat_a = fixture_catalog("pack-a");
    let cat_b = fixture_catalog("pack-b");
    let dev = device("PCI\\0", &[GPU_HWID], &[]);

    let result = match_device_to_catalogs(&dev, &[cat_a, cat_b]).expect("match must succeed");
    assert_eq!(result.candidates.len(), 2, "packs must not be merged");
    assert_eq!(result.candidates[0].pack_name, "pack-a");
    assert_eq!(result.candidates[1].pack_name, "pack-b");
    assert_eq!(
        result.candidates[0].candidate.inf_filename,
        result.candidates[1].candidate.inf_filename
    );
    assert_eq!(
        result.candidates[0].candidate.install_section,
        result.candidates[1].candidate.install_section
    );
}

// ---------------------------------------------------------------------------
// R8 — distinct device instances remain distinct in batch output
// ---------------------------------------------------------------------------

#[test]
fn r8_distinct_instances_remain_distinct() {
    let cat = synthetic_catalog("synth", &[("H1", "M1", "m1", 0)]);
    let dev_a = device("PCI\\A\\1", &["H1"], &[]);
    let dev_b = device("PCI\\A\\2", &["H1"], &[]);

    let results = match_devices_to_catalogs(&[dev_a, dev_b], &[cat]).expect("match must succeed");
    assert_eq!(results.len(), 2, "two device results expected");
    assert_eq!(results[0].instance_id, "PCI\\A\\1");
    assert_eq!(results[1].instance_id, "PCI\\A\\2");
    assert_eq!(results[0].candidates.len(), 1);
    assert_eq!(results[1].candidates.len(), 1);
    assert_eq!(
        results[0].candidates[0].candidate.install_section,
        results[1].candidates[0].candidate.install_section
    );
}

// ---------------------------------------------------------------------------
// R9 — unknown IDs yield zero candidates, not an error
// ---------------------------------------------------------------------------

#[test]
fn r9_unknown_id_yields_empty_device_result() {
    let cat = fixture_catalog("DP_Display_SDIO01_26082");
    let dev = device("PCI\\0", &["PCI\\VEN_FFFF&DEV_FFFF"], &["ACPI\\UNKNOWN"]);

    let result = match_device_to_catalogs(&dev, &[cat]).expect("no error expected");
    assert_eq!(result.instance_id, "PCI\\0");
    assert!(result.candidates.is_empty(), "zero candidates expected");
}

// ---------------------------------------------------------------------------
// R10 — exact match only; near-misses never match
// ---------------------------------------------------------------------------

#[test]
fn r10_exact_match_only() {
    let cat = fixture_catalog("DP_Display_SDIO01_26082");

    let near_misses = [
        "PCI\\VEN_1002&DEV_1586&SUBSYS_15141043", // missing REV_
        "PCI\\VEN_1002&DEV_1586",                 // missing SUBSYS_ + REV_
        "PCI\\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C", // prefix of REV value
        "PCI\\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1X", // extra trailing char
        "PCI\\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1&X", // extra segment
        "VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1", // stripped bus prefix
        "PCI\\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1ZZZ", // suffix
    ];
    for miss in near_misses {
        let cat = fixture_catalog("DP_Display_SDIO01_26082");
        let dev = device("PCI\\0", &[miss], &[]);
        let result = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");
        assert!(
            result.candidates.is_empty(),
            "near-miss {miss:?} must not match"
        );
    }

    // The exact ID (even as a later hardware ID) still matches exactly.
    let dev = device("PCI\\0", &["PCI\\VEN_FFFF&DEV_FFFF", GPU_HWID], &[]);
    let result = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");
    assert_eq!(result.candidates.len(), 1);
    assert_eq!(result.candidates[0].evidence[0].ordinal, 1);
}

// ---------------------------------------------------------------------------
// R11 — deterministic order
// ---------------------------------------------------------------------------

#[test]
fn r11_deterministic_order_across_runs() {
    let rows: &[(&str, &str, &str, i32)] = &[
        ("H0", "M0", "m0", 0),
        ("H1", "M1", "m1", 0),
        ("C0", "M0", "m0", 1),
        ("C1", "M2", "m2", 2),
    ];
    let dev = device("PCI\\0", &["H0", "H1", "H0"], &["C0", "C1", "C0", "C0"]);

    // Rebuild a fresh catalog on every run so HashMap construction cannot leak
    // iteration order into the public output ordering.
    let run = |d: &DeviceIdentity| {
        match_device_to_catalogs(d, &[synthetic_catalog("synth", rows)])
            .expect("match must succeed")
    };

    let first = run(&dev);
    let second = run(&dev);
    assert_eq!(first, second, "identical runs must be identical");

    // Ordering: hardware ordinals ascend, then compatible ordinals ascend.
    let m0 = first
        .candidates
        .iter()
        .find(|c| c.candidate.install_section == "M0")
        .expect("M0 present");
    // M0 is reachable via H0 (hardware, ordinal 0), H0 again (ordinal 2), and
    // C0 (compatible, ordinals 0, 2, 3): 5 evidence records, deduped to one row.
    assert_eq!(m0.evidence.len(), 5);
    assert_eq!(m0.evidence[0].kind, DeviceIdKind::Hardware);
    assert_eq!(m0.evidence[0].ordinal, 0);
    assert_eq!(m0.evidence[1].kind, DeviceIdKind::Hardware);
    assert_eq!(m0.evidence[1].ordinal, 2);
    assert_eq!(m0.evidence[2].kind, DeviceIdKind::Compatible);
    assert_eq!(m0.evidence[2].ordinal, 0);
    assert_eq!(m0.evidence[3].kind, DeviceIdKind::Compatible);
    assert_eq!(m0.evidence[3].ordinal, 2);
    assert_eq!(m0.evidence[4].kind, DeviceIdKind::Compatible);
    assert_eq!(m0.evidence[4].ordinal, 3);

    // Candidate discovery order follows device ID order (H0 -> H1 -> C1), not
    // any hash/version ordering.
    assert_eq!(first.candidates[0].candidate.install_section, "M0");
    assert_eq!(first.candidates[1].candidate.install_section, "M1");
    assert_eq!(first.candidates[2].candidate.install_section, "M2");
}

// ---------------------------------------------------------------------------
// R12 — device / catalog limits
// ---------------------------------------------------------------------------

#[test]
fn r12_device_count_over_cap() {
    let cat = synthetic_catalog("synth", &[("H1", "M1", "m1", 0)]);
    let dev = device("PCI\\0", &["H1"], &[]);
    let devices = vec![dev; MAX_DEVICES_PER_MATCH + 1];

    let result = match_devices_to_catalogs(&devices, &[cat]);
    assert_err_kind(result, "TooManyDevices");
}

#[test]
fn r12_catalog_count_over_cap() {
    let dev = device("PCI\\0", &["H1"], &[]);
    let cats: Vec<SdioCatalog> = (0..MAX_CATALOGS_PER_MATCH + 1)
        .map(|i| synthetic_catalog(&format!("synth{i}"), &[("H1", "M1", "m1", 0)]))
        .collect();

    let result = match_device_to_catalogs(&dev, &cats);
    assert_err_kind(result, "TooManyCatalogs");
}

// ---------------------------------------------------------------------------
// R13 — candidate explosion bound (checked before large allocation)
// ---------------------------------------------------------------------------

#[test]
fn r13_candidate_explosion_rejected_before_allocation() {
    // One exact hwid bucket with more records than the per-device candidate cap.
    let big_bucket: Vec<(&str, &str, &str, i32)> = (0..MAX_CANDIDATES_PER_DEVICE + 10)
        .map(|_| ("EXPLODE\\ID", "M1", "m1", 0))
        .collect();
    let cat = synthetic_catalog("synth", &big_bucket);
    let dev = device("PCI\\0", &["EXPLODE\\ID"], &[]);

    let result = match_device_to_catalogs(&dev, &[cat]);
    // Fail closed: explicit error, never truncated output.
    assert_err_kind(result, "TooManyCandidates");
}

#[test]
fn r13_bounded_lookup_seam_rejects_before_allocating() {
    let big_bucket: Vec<(&str, &str, &str, i32)> =
        (0..600).map(|_| ("EXPLODE\\ID", "M1", "m1", 0)).collect();
    let cat = synthetic_catalog("synth", &big_bucket);

    // Direct seam check: cap below the bucket size must reject up front.
    let err = cat
        .find_by_hwid_bounded("EXPLODE\\ID", 100)
        .expect_err("must reject");
    assert!(
        matches!(
            err,
            mod_drivers::sdio::SdioError::LookupBucketTooLarge {
                bucket: 600,
                max: 100,
                ..
            }
        ),
        "got {err:?}"
    );

    // A cap above the bucket size must behave exactly like find_by_hwid.
    let bounded = cat
        .find_by_hwid_bounded("EXPLODE\\ID", 600)
        .expect("within cap resolves");
    assert_eq!(bounded.len(), 600);
}

// ---------------------------------------------------------------------------
// R14 — evidence limit
// ---------------------------------------------------------------------------

#[test]
fn r14_evidence_limit_exceeded_fails_closed() {
    // One logical candidate reachable by MAX_EVIDENCE_PER_CANDIDATE + 1 distinct
    // compatible IDs. All rows share tuple M1 -> one candidate.
    let ids: Vec<String> = (0..MAX_EVIDENCE_PER_CANDIDATE + 1)
        .map(|i| format!("PCI\\VEN_{i:04X}&DEV_0001"))
        .collect();
    let rows: Vec<(&str, &str, &str, i32)> =
        ids.iter().map(|id| (id.as_str(), "M1", "m1", 0)).collect();
    let cat = synthetic_catalog("synth", &rows);
    let comp: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
    let dev = device("PCI\\0", &[], &comp);

    let result = match_device_to_catalogs(&dev, &[cat]);
    assert_err_kind(result, "TooMuchEvidence");
}

// ---------------------------------------------------------------------------
// R15 — no classification semantics
// ---------------------------------------------------------------------------

#[test]
fn r15_no_classification_semantics() {
    // Two INFs with very different versions. Discovery order (device input
    // order) must win; nothing may reorder by version/date/provider.
    let inf_old = DataInfFile {
        inf_path: "a\\old.inf".to_string(),
        inf_filename: "old.inf".to_string(),
        fields: {
            let mut f: [Option<String>; 10] = Default::default();
            f[mod_drivers::sdio::FIELD_PROVIDER] = Some("Old Corp".to_string());
            f[mod_drivers::sdio::FIELD_CLASS] = Some("Display".to_string());
            f
        },
        cats: Default::default(),
        date: Some((2000, 1, 1)),
        version: Some((1, 0, 0, 0)),
        infsize: Some(1),
        infcrc: Some(1),
        reserved_a: 0,
        reserved_b: 0,
    };
    let inf_new = DataInfFile {
        inf_path: "b\\new.inf".to_string(),
        inf_filename: "new.inf".to_string(),
        fields: {
            let mut f: [Option<String>; 10] = Default::default();
            f[mod_drivers::sdio::FIELD_PROVIDER] = Some("New Corp".to_string());
            f[mod_drivers::sdio::FIELD_CLASS] = Some("Display".to_string());
            f
        },
        cats: Default::default(),
        date: Some((2026, 6, 29)),
        version: Some((9, 9, 9, 9)),
        infsize: Some(1),
        infcrc: Some(1),
        reserved_a: 0,
        reserved_b: 0,
    };

    let cat = SdioCatalog {
        pack_name: "synth".to_string(),
        inf_records: vec![inf_old, inf_new],
        manuf_records: vec![
            DataManuf {
                inffile_index: 0,
                manufacturer: "Old Corp".to_string(),
                sections: vec!["old".to_string()],
                sections_n: 1,
            },
            DataManuf {
                inffile_index: 1,
                manufacturer: "New Corp".to_string(),
                sections: vec!["new".to_string()],
                sections_n: 1,
            },
        ],
        desc_records: vec![
            DataDesc {
                manufacturer_index: 0,
                sect_pos: 0,
                desc: "old".to_string(),
                install: "OLD_Install".to_string(),
                install_picked: "old_install".to_string(),
                feature: 0,
            },
            DataDesc {
                manufacturer_index: 1,
                sect_pos: 0,
                desc: "new".to_string(),
                install: "NEW_Install".to_string(),
                install_picked: "new_install".to_string(),
                feature: 0,
            },
        ],
        hwid_records: vec![
            DataHwid {
                desc_index: 0,
                inf_pos: 0,
                hwid: "OLD\\ID".to_string(),
            },
            DataHwid {
                desc_index: 1,
                inf_pos: 0,
                hwid: "NEW\\ID".to_string(),
            },
        ],
        hash_map: {
            let mut m = HashMap::new();
            m.insert("OLD\\ID".to_string(), vec![0]);
            m.insert("NEW\\ID".to_string(), vec![1]);
            m
        },
        text_pool: Vec::new(),
    };

    // Device lists the NEWER candidate first, then the OLDER one. Pure discovery
    // order must win: output is [new, old] with no version/date reordering.
    let dev = device("PCI\\0", &["NEW\\ID", "OLD\\ID"], &[]);
    let result = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");
    assert_eq!(result.candidates.len(), 2);
    assert_eq!(result.candidates[0].candidate.inf_filename, "new.inf");
    assert_eq!(result.candidates[1].candidate.inf_filename, "old.inf");

    // Reverse the input order: discovery order reverses with it. If a ranking
    // layer were present, the (older) candidate could never lead.
    let dev_rev = device("PCI\\0", &["OLD\\ID", "NEW\\ID"], &[]);
    let cat2 = SdioCatalog {
        pack_name: "synth".to_string(),
        inf_records: vec![
            DataInfFile {
                inf_path: "a\\old.inf".to_string(),
                inf_filename: "old.inf".to_string(),
                fields: {
                    let mut f: [Option<String>; 10] = Default::default();
                    f[mod_drivers::sdio::FIELD_PROVIDER] = Some("Old Corp".to_string());
                    f[mod_drivers::sdio::FIELD_CLASS] = Some("Display".to_string());
                    f
                },
                cats: Default::default(),
                date: Some((2000, 1, 1)),
                version: Some((1, 0, 0, 0)),
                infsize: Some(1),
                infcrc: Some(1),
                reserved_a: 0,
                reserved_b: 0,
            },
            DataInfFile {
                inf_path: "b\\new.inf".to_string(),
                inf_filename: "new.inf".to_string(),
                fields: {
                    let mut f: [Option<String>; 10] = Default::default();
                    f[mod_drivers::sdio::FIELD_PROVIDER] = Some("New Corp".to_string());
                    f[mod_drivers::sdio::FIELD_CLASS] = Some("Display".to_string());
                    f
                },
                cats: Default::default(),
                date: Some((2026, 6, 29)),
                version: Some((9, 9, 9, 9)),
                infsize: Some(1),
                infcrc: Some(1),
                reserved_a: 0,
                reserved_b: 0,
            },
        ],
        manuf_records: vec![
            DataManuf {
                inffile_index: 0,
                manufacturer: "Old Corp".to_string(),
                sections: vec!["old".to_string()],
                sections_n: 1,
            },
            DataManuf {
                inffile_index: 1,
                manufacturer: "New Corp".to_string(),
                sections: vec!["new".to_string()],
                sections_n: 1,
            },
        ],
        desc_records: vec![
            DataDesc {
                manufacturer_index: 0,
                sect_pos: 0,
                desc: "old".to_string(),
                install: "OLD_Install".to_string(),
                install_picked: "old_install".to_string(),
                feature: 0,
            },
            DataDesc {
                manufacturer_index: 1,
                sect_pos: 0,
                desc: "new".to_string(),
                install: "NEW_Install".to_string(),
                install_picked: "new_install".to_string(),
                feature: 0,
            },
        ],
        hwid_records: vec![
            DataHwid {
                desc_index: 0,
                inf_pos: 0,
                hwid: "OLD\\ID".to_string(),
            },
            DataHwid {
                desc_index: 1,
                inf_pos: 0,
                hwid: "NEW\\ID".to_string(),
            },
        ],
        hash_map: {
            let mut m = HashMap::new();
            m.insert("OLD\\ID".to_string(), vec![0]);
            m.insert("NEW\\ID".to_string(), vec![1]);
            m
        },
        text_pool: Vec::new(),
    };
    let result_rev = match_device_to_catalogs(&dev_rev, &[cat2]).expect("match must succeed");
    assert_eq!(result_rev.candidates[0].candidate.inf_filename, "old.inf");
    assert_eq!(result_rev.candidates[1].candidate.inf_filename, "new.inf");
}

// ---------------------------------------------------------------------------
// Structural: the domain types carry discovery metadata, never derived
// classification. The result is the join of (pack, candidate, evidence).
// ---------------------------------------------------------------------------

#[test]
fn r15b_result_type_shape_is_discovery_only() {
    let cat = synthetic_catalog("synth", &[("H1", "M1", "m1", 0)]);
    let dev = device("PCI\\0", &["H1"], &[]);
    let result = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");

    // Evidence carries kind + ordinal + preserved ID + SDIO inf_pos only.
    let ev = &result.candidates[0].evidence[0];
    let _: DeviceIdKind = ev.kind;
    let _: usize = ev.ordinal;
    let _: &str = ev.device_id.as_str();
    let _: i32 = ev.inf_pos;

    // Candidate metadata is the parsed SDIO candidate (no derived fields).
    let cand: &Candidate = &result.candidates[0].candidate;
    let _: &str = &cand.inf_filename;

    // Provenance is explicit.
    let _: &CatalogCandidateMatch = &result.candidates[0];
    let _: &DeviceCatalogMatches = &result;
    let _: &str = &result.candidates[0].pack_name;
    let _: &str = &result.instance_id;
    let _: &MatchEvidence = ev;
    let _: &[MatchEvidence] = &result.candidates[0].evidence;
    let _: &[CatalogCandidateMatch] = &result.candidates;

    // No field on any matching type can even be *named* recommended/rank/update:
    // the structs above are exhaustive structs with the fields shown.
    assert_eq!(result.candidates.len(), 1);
}
