// Integration tests for Tab 2a-4: catalog-level OS applicability assessment.
//
// This slice derives **catalog OS applicability only** from already-parsed local
// SDIO index metadata. It never claims a candidate is an update, recommended,
// installable, signed, or better; it never fabricates a Windows rank; it never
// compares candidate version/date to anything. Windows remains authoritative.
//
// Tri-state: HostCompatible (metadata PROVES the Models target permits host),
// HostIncompatible (metadata PROVES exclusion), Indeterminate (index alone
// cannot prove either way — never converted to compatible via hardware match).
//
// R1/R2 exercise the committed real fixture (`valid_small.bin`); the rest are
// pure domain constructions plus in-memory `SdioCatalog` values (no fixture
// mutation, no fake SDW grammar).

use std::collections::HashMap;

use mod_drivers::identity::{DeviceIdentity, MachineContext};
use mod_drivers::sdio::{
    Candidate, CatalogCandidateMatch, DataDesc, DataHwid, DataInfFile, DataManuf, DeviceIdKind,
    DeviceCatalogMatches, MatchEvidence, SdioCatalog,
};
use mod_drivers::sdio::applicability::{
    ApplicabilityError, ApplicabilityReason, AssessedCatalogCandidate, CatalogApplicabilityEvidence,
    CatalogOsApplicability, TargetArch, TargetOsDecoration, assess_device_matches, assess_matches,
    parse_machine_context, parse_target_os_version,
};

const VALID_BYTES: &[u8] = include_bytes!("../fixtures/sdio/valid_small.bin");

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn fixture_catalog(pack_name: &str) -> SdioCatalog {
    SdioCatalog::parse_bytes(VALID_BYTES, pack_name.to_string()).expect("fixture must parse")
}

/// Real GPU hardware ID present in the fixture (`u0202099.inf`,
/// `ati2mtag_StrixHalo` / `ati2mtag_strixhalo`, models target
/// `ntamd64.10.0.1..19044`).
const GPU_HWID: &str = "PCI\\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1";

fn machine(arch: &str, os_version: &str, os_build: &str) -> MachineContext {
    MachineContext {
        arch: arch.to_string(),
        os_build: os_build.to_string(),
        os_version: os_version.to_string(),
    }
}

/// The realistic current host: x64 / 10.0 / build 26200.
fn host_x64_26200() -> MachineContext {
    machine("x64", "10.0", "26200")
}

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

/// Build a synthetic catalog with one INF (`synth.inf`) and one model row per
/// unique `(install, picked, models_section)` tuple. Each row is
/// `(hwid, install, picked, models_section, inf_pos)`.
#[allow(clippy::too_many_arguments)]
fn synthetic_catalog_with_models(
    pack_name: &str,
    rows: &[(&str, &str, &str, &str, i32)],
) -> SdioCatalog {
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

    // Collect unique (install, picked, models_section) tuples; each becomes one
    // DataDesc with a deterministic sect_pos = index of the decoration in the
    // manuf sections array. The manuf sections array always starts with the
    // plain base name (index 0), then one entry per distinct decoration.
    let mut desc_records: Vec<DataDesc> = Vec::new();
    let mut key_to_desc: HashMap<(String, String, String), usize> = HashMap::new();
    let mut sect_by_deco: HashMap<String, i32> = HashMap::new();
    let mut hwid_records: Vec<DataHwid> = Vec::new();
    let mut hash_map: HashMap<String, Vec<usize>> = HashMap::new();

    for (hwid, install, picked, models_section, inf_pos) in rows {
        let key = (
            install.to_string(),
            picked.to_string(),
            models_section.to_string(),
        );
        let desc_index = *key_to_desc.entry(key).or_insert_with(|| {
            // section 0 is the plain base name; decorations start at 1.
            let next = sect_by_deco.len() as i32 + 1;
            let pos = *sect_by_deco
                .entry(models_section.to_string())
                .or_insert(next);
            let idx = desc_records.len();
            desc_records.push(DataDesc {
                manufacturer_index: 0,
                sect_pos: pos,
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

    // Build the manuf sections array in deterministic sect_pos order.
    let mut sections: Vec<String> = vec!["synth".to_string()];
    let mut decos: Vec<(i32, String)> = sect_by_deco
        .iter()
        .map(|(s, p)| (*p, s.clone()))
        .collect();
    decos.sort_by_key(|(p, _)| *p);
    sections.extend(decos.into_iter().map(|(_, s)| s));
    let sections_n = sections.len() as u32;

    SdioCatalog {
        pack_name: pack_name.to_string(),
        inf_records: vec![inf],
        manuf_records: vec![DataManuf {
            inffile_index: 0,
            manufacturer: "Synth Corp".to_string(),
            sections,
            sections_n,
        }],
        desc_records,
        hwid_records,
        text_pool: Vec::new(),
        hash_map,
    }
}

/// Resolve a matched candidate for one (device, catalog) pair.
fn one_match(
    instance_id: &str,
    hwids: &[&str],
    cat: SdioCatalog,
) -> CatalogCandidateMatch {
    let dev = device(instance_id, hwids, &[]);
    let matched = mod_drivers::sdio::match_device_to_catalogs(&dev, &[cat])
        .expect("match must succeed");
    assert_eq!(
        matched.candidates.len(),
        1,
        "exactly one candidate expected for {instance_id}"
    );
    matched.candidates.into_iter().next().unwrap()
}

/// A minimal candidate with the given models section, for evidence-shape tests.
/// `sect_pos` defaults to 1 (a decoration position).
fn mk_candidate(models_section: Option<&str>) -> CatalogCandidateMatch {
    mk_candidate_at(models_section, 1)
}

fn mk_candidate_at(models_section: Option<&str>, sect_pos: i32) -> CatalogCandidateMatch {
    CatalogCandidateMatch {
        pack_name: "p".into(),
        candidate: Candidate {
            inf_path: "i".into(),
            inf_filename: "f.inf".into(),
            provider: None,
            class: None,
            class_guid: None,
            catalog_file: None,
            version: None,
            date: None,
            install_section: "inst".into(),
            picked_section: "picked".into(),
            sect_pos,
            models_section: models_section.map(str::to_string),
            inf_pos: 0,
        },
        evidence: vec![MatchEvidence {
            kind: DeviceIdKind::Hardware,
            device_id: "d".into(),
            ordinal: 0,
            inf_pos: 0,
        }],
    }
}

/// A catalog whose rows land in all three statuses on the x64 host: H1 →
/// incompatible (NTx86), H2 → compatible (NTamd64.10.0...22000), H3 →
/// indeterminate (plain name).
fn mixed_status_catalog() -> SdioCatalog {
    synthetic_catalog_with_models(
        "synth",
        &[
            ("H1", "M1", "m1", "NTx86.10.0", 0),           // incompatible
            ("H2", "M2", "m2", "NTamd64.10.0...22000", 0), // compatible
            ("H3", "M3", "m3", "plain", 0),                // indeterminate
        ],
    )
}

// R1 — Models-section provenance (real fixture pin)

#[test]
fn r1_models_section_provenance_from_fixture() {
    let cat = fixture_catalog("DP_Display_SDIO01_26082");
    let dev = device(
        "PCI\\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1\\0",
        &[GPU_HWID],
        &[],
    );
    let matched = mod_drivers::sdio::match_device_to_catalogs(&dev, &[cat])
        .expect("match must succeed");
    let m = &matched.candidates[0];

    // Gate A4 evidence: desc0 in the fixture resolves to manuf0,
    // sections[sect_pos=1] == "ntamd64.10.0.1..19044". The positional index is
    // retained so provenance is never guessed from the text.
    assert_eq!(m.candidate.sect_pos, 1);
    assert_eq!(
        m.candidate.models_section.as_deref(),
        Some("ntamd64.10.0.1..19044"),
        "fixture candidate must expose the exact real models target"
    );
}

// R2 — sect_pos cross-reference fails closed (real fixture-derived malformed)

#[test]
fn r2_sect_pos_out_of_range_rejected_fail_closed() {
    // Patch a real-fixture desc record so its sect_pos no longer indexes the
    // referenced manufacturer's section array. The parser must reject the
    // catalog fail-closed (CrossRefInvalid kind "sect_pos") — no unchecked
    // index read into applicability, no guessed provenance.
    let mut input = std::io::Cursor::new(&VALID_BYTES[8..]);
    let mut pay = Vec::new();
    lzma_rs::lzma_decompress(&mut input, &mut pay).expect("fixture must decode");

    // Walk the six-block layout to find the desc block data start.
    let inf_cnt = u32::from_le_bytes(pay[4..8].try_into().unwrap()) as usize;
    let man_off = 8 + inf_cnt * 132;
    let man_cnt = u32::from_le_bytes(pay[man_off + 4..man_off + 8].try_into().unwrap()) as usize;
    let desc_off = man_off + 8 + man_cnt * 16;
    let first_desc = desc_off + 8;
    // DataDesc layout: manufacturer_index @ +0, sect_pos @ +4.
    let first_manuf_index =
        u32::from_le_bytes(pay[first_desc..first_desc + 4].try_into().unwrap()) as usize;
    assert!(first_manuf_index < man_cnt);
    pay[first_desc + 4..first_desc + 8].copy_from_slice(&0x7FFF_FFFFi32.to_le_bytes());

    let mut enc = std::io::Cursor::new(Vec::new());
    lzma_rs::lzma_compress(&mut std::io::Cursor::new(&pay), &mut enc).expect("re-encode");
    let stream = enc.into_inner();
    let mut out = Vec::with_capacity(8 + stream.len());
    out.extend_from_slice(b"SDW");
    out.extend_from_slice(&mod_drivers::sdio::FORMAT_VERSION.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(&stream);

    let err = match SdioCatalog::parse_bytes(&out, "patched".to_string()) {
        Err(e) => e,
        Ok(_) => panic!("out-of-range sect_pos must be rejected"),
    };
    assert!(
        matches!(
            err,
            mod_drivers::sdio::SdioError::CrossRefInvalid { kind: "sect_pos", .. }
        ),
        "got {err:?}"
    );
}

// R3 — amd64 host / amd64 target

#[test]
fn r3_amd64_host_amd64_target_compatible() {
    let host = host_x64_26200();
    let deco = parse_target_os_version("NTamd64").expect("must parse");
    assert_eq!(deco.architecture, Some(TargetArch::Amd64));
    assert_eq!(deco.major, None);
    assert_eq!(deco.minor, None);
    assert_eq!(deco.build, None);

    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::HostCompatible);
    assert_eq!(ev.reason, ApplicabilityReason::TargetSatisfied);
}

// R4 — architecture mismatch

#[test]
fn r4_architecture_mismatch_incompatible() {
    let host = host_x64_26200();
    for (target, expected_arch) in [("NTx86", TargetArch::X86), ("NTarm64", TargetArch::Arm64)] {
        let deco = parse_target_os_version(target).expect("must parse");
        assert_eq!(deco.architecture, Some(expected_arch));
        let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
        assert_eq!(
            ev.status,
            CatalogOsApplicability::HostIncompatible,
            "target {target} on x64 host"
        );
        assert_eq!(ev.reason, ApplicabilityReason::ArchitectureMismatch);
    }
}

// R5 — case insensitivity

#[test]
fn r5_target_parsing_is_ascii_case_insensitive() {
    let a = parse_target_os_version("NTAMD64").expect("must parse");
    let b = parse_target_os_version("ntamd64").expect("must parse");
    let c = parse_target_os_version("NtAmD64").expect("must parse");
    assert_eq!(a, b);
    assert_eq!(b, c);
    assert_eq!(a.architecture, Some(TargetArch::Amd64));

    let v1 = parse_target_os_version("NTamd64.10.0...22000").expect("must parse");
    let v2 = parse_target_os_version("ntAMD64.10.0...22000").expect("must parse");
    assert_eq!(v1, v2);
    assert_eq!(v1.major, Some(10));
    assert_eq!(v1.minor, Some(0));
    assert_eq!(v1.build, Some(22000));
}

// R6 — same major/minor build threshold

#[test]
fn r6_same_major_minor_build_threshold() {
    let host = host_x64_26200();

    let at_or_below = parse_target_os_version("NTamd64.10.0...22000").unwrap();
    let ev = mod_drivers::sdio::applicability::evaluate_target(&at_or_below, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::HostCompatible);

    let above = parse_target_os_version("NTamd64.10.0...30000").unwrap();
    let ev = mod_drivers::sdio::applicability::evaluate_target(&above, &host).unwrap();
    assert_eq!(
        ev.status,
        CatalogOsApplicability::HostIncompatible,
        "host build 26200 < target build 30000 on same 10.0"
    );
    assert_eq!(ev.reason, ApplicabilityReason::BuildTooOld);
}

// R7 — build is relative to its major/minor pair (never naïve tuple compare)

#[test]
fn r7_build_relative_to_major_minor_not_tuple() {
    // Host is a NEWER OS version (11.0) with a numerically LOWER build.
    let host = machine("x64", "11.0", "100");
    let target = parse_target_os_version("NTamd64.10.0...99999").unwrap();
    let ev = mod_drivers::sdio::applicability::evaluate_target(&target, &host).unwrap();
    // Microsoft rule: build is evaluated only when major/minor match. The host
    // major/minor (11.0) is GREATER than target (10.0) → threshold satisfied.
    assert_eq!(
        ev.status,
        CatalogOsApplicability::HostCompatible,
        "host 11.0 must not be rejected because 100 < 99999"
    );
}

// R8 — lower host OS version

#[test]
fn r8_lower_host_os_version_incompatible() {
    let host = machine("x64", "10.0", "99999"); // old major/minor, huge build
    let target = parse_target_os_version("NTamd64.11.0").unwrap();
    let ev = mod_drivers::sdio::applicability::evaluate_target(&target, &host).unwrap();
    assert_eq!(
        ev.status,
        CatalogOsApplicability::HostIncompatible,
        "host 10.0 < target 11.0 regardless of build"
    );
    assert_eq!(ev.reason, ApplicabilityReason::OsVersionTooOld);
}

// R9 — ProductType requires unknown context

#[test]
fn r9_product_type_indeterminate_not_guessed() {
    let host = host_x64_26200();
    // NTamd64.10.0.1 (major.minor.producttype)
    let deco = parse_target_os_version("NTamd64.10.0.1").unwrap();
    assert_eq!(deco.product_type, Some(1));
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::Indeterminate);
    assert_eq!(ev.reason, ApplicabilityReason::ProductTypeUnavailable);
}

// R10 — SuiteMask requires unknown context

#[test]
fn r10_suite_mask_indeterminate_not_guessed() {
    let host = host_x64_26200();
    // NTamd64.10.0.1.0x80 has both ProductType and SuiteMask. The strict
    // ProductType-first check keeps it Indeterminate; the evaluator must never
    // assume a workstation value or a zero suite mask.
    let deco = parse_target_os_version("NTamd64.10.0.1.0x80").unwrap();
    assert_eq!(deco.product_type, Some(1));
    assert_eq!(deco.suite_mask, Some(0x80));
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::Indeterminate);
    assert_eq!(ev.reason, ApplicabilityReason::ProductTypeUnavailable);
}

#[test]
fn r10b_suite_mask_only_indeterminate_not_guessed() {
    let host = host_x64_26200();
    // NTamd64.10.0..0x80: product type absent, suite mask present (empty
    // product slot, then suite). MachineContext lacks SuiteMask → Indeterminate.
    let deco = parse_target_os_version("NTamd64.10.0..0x80").unwrap();
    assert_eq!(deco.product_type, None);
    assert_eq!(deco.suite_mask, Some(0x80));
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::Indeterminate);
    assert_eq!(ev.reason, ApplicabilityReason::SuiteMaskUnavailable);
}

// R11 — no trustworthy target → Indeterminate, not compatible

#[test]
fn r11_no_trustworthy_target_indeterminate() {
    let host = host_x64_26200();
    // No decoration at all: the parser must not invent "works everywhere".
    let ev = mod_drivers::sdio::applicability::evaluate_target(&TargetOsDecoration::default(), &host)
        .unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::Indeterminate);
    assert_eq!(ev.reason, ApplicabilityReason::MissingTargetMetadata);
}

#[test]
fn r11b_plain_models_section_is_indeterminate() {
    // A plain (non-NT) value at a DECORATION position (sect_pos > 0) is
    // malformed decoration metadata → Indeterminate(UnsupportedTargetSyntax).
    // The position, not the text, proves it was meant to be a decoration.
    let cat = synthetic_catalog_with_models("synth", &[("H1", "M1", "m1", "plainmodel", 0)]);
    let m = one_match("PCI\\0", &["H1"], cat);
    assert_eq!(m.candidate.models_section.as_deref(), Some("plainmodel"));
    assert!(m.candidate.sect_pos > 0);

    let host = host_x64_26200();
    let assessed = assess_device_matches(
        &DeviceCatalogMatches {
            instance_id: "PCI\\0".to_string(),
            candidates: vec![m],
        },
        &host,
    )
    .expect("assessment must succeed");
    assert_eq!(
        assessed.candidates[0].os.status,
        CatalogOsApplicability::Indeterminate
    );
    assert_eq!(
        assessed.candidates[0].os.reason,
        ApplicabilityReason::UnsupportedTargetSyntax
    );

    // The same plain name at sect_pos 0 (undecorated base) carries no OS
    // evidence at all → MissingTargetMetadata.
    let assessed = assess_device_matches(
        &DeviceCatalogMatches {
            instance_id: "PCI\\0".to_string(),
            candidates: vec![mk_candidate_at(Some("plainmodel"), 0)],
        },
        &host,
    )
    .expect("assessment must succeed");
    assert_eq!(
        assessed.candidates[0].os.status,
        CatalogOsApplicability::Indeterminate
    );
    assert_eq!(
        assessed.candidates[0].os.reason,
        ApplicabilityReason::MissingTargetMetadata
    );
}

// R12 — malformed / unsupported target → Indeterminate, never compatible

#[test]
fn r12_malformed_targets_never_compatible() {
    let host = host_x64_26200();
    let bad_targets = [
        "NTamd64.10.0...abc",      // bad numeric component
        "NTamd64.10.0.1.0.0.0.0.9", // too many components
        "NTsparc64.10.0",           // unknown architecture token
        "NTamd64.10.0...99999999999", // overflowing integer
        "NTamd64.10.0..",           // trailing empty component
        "NTamd64.10.0..x22000",     // empty component with junk
        "",                          // empty string
    ];
    for bad in bad_targets {
        match parse_target_os_version(bad) {
            Ok(deco) => {
                // If it somehow parsed, the evaluator must still fail closed.
                let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
                assert_ne!(
                    ev.status,
                    CatalogOsApplicability::HostCompatible,
                    "malformed target {bad:?} must never be compatible"
                );
            }
            Err(_) => {
                // explicit non-panicking rejection is acceptable
            }
        }
    }
}

#[test]
fn r12b_unknown_architecture_token_is_indeterminate_or_rejected() {
    let host = host_x64_26200();
    match parse_target_os_version("NTsparc64") {
        Ok(deco) => {
            let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
            assert_eq!(ev.status, CatalogOsApplicability::Indeterminate);
            assert_eq!(ev.reason, ApplicabilityReason::UnsupportedTargetSyntax);
        }
        Err(_) => {}
    }
}

// R13 — invalid machine context → explicit error, no panic

#[test]
fn r13_invalid_machine_context_errors() {
    let bad_hosts = [
        machine("x64", "", "26200"),
        machine("x64", "10", "26200"),
        machine("x64", "10.x", "26200"),
        machine("x64", "10.0", "abc"),
        machine("x64", "10.0", "99999999999999"),
        machine("", "10.0", "26200"),
        // "10.0" is NOT parsed as float 10.0; trailing junk must fail.
        machine("x64", "10.0.0", "26200"),
        machine("x64", "10,0", "26200"),
        machine("x64", "10.0abc", "26200"),
    ];
    for h in bad_hosts {
        let res = parse_machine_context(&h);
        assert!(
            matches!(res, Err(ApplicabilityError::InvalidMachineContext))
                || matches!(res, Err(ApplicabilityError::UnknownHostArchitecture(_))),
            "expected explicit context error for {h:?}, got {res:?}"
        );
    }

    // The valid host parses exactly, integer-exact.
    let ok = parse_machine_context(&host_x64_26200()).expect("valid host");
    assert_eq!((ok.major, ok.minor, ok.build), (10, 0, 26200));
}

// R14 — candidate version irrelevant · R15 — date irrelevant · R16 — inf_pos
// irrelevant (all prove candidate metadata never drives OS applicability).

fn assess_single(cat: SdioCatalog, host: &MachineContext) -> AssessedCatalogCandidate {
    let m = one_match("PCI\\0", &["H1"], cat);
    assess_device_matches(
        &DeviceCatalogMatches {
            instance_id: "PCI\\0".into(),
            candidates: vec![m],
        },
        host,
    )
    .unwrap()
    .candidates
    .into_iter()
    .next()
    .unwrap()
}

#[test]
fn r14_candidate_version_irrelevant() {
    let host = host_x64_26200();
    let mk = |version: Option<(u16, u16, u16, u16)>| {
        let mut cat = synthetic_catalog_with_models(
            "synth",
            &[("H1", "M1", "m1", "NTamd64.10.0...22000", 0)],
        );
        cat.inf_records[0].version = version;
        cat
    };
    let a = assess_single(mk(Some((1, 0, 0, 0))), &host);
    let b = assess_single(mk(Some((99, 99, 99, 99))), &host);
    assert_eq!(a.os.status, b.os.status);
    assert_eq!(a.os.reason, b.os.reason);
}

#[test]
fn r15_candidate_date_irrelevant() {
    let host = host_x64_26200();
    let mk = |date: Option<(u16, u8, u8)>| {
        let mut cat = synthetic_catalog_with_models(
            "synth",
            &[("H1", "M1", "m1", "NTamd64.10.0...22000", 0)],
        );
        cat.inf_records[0].date = date;
        cat
    };
    let a = assess_single(mk(Some((2000, 1, 1))), &host);
    let b = assess_single(mk(Some((2026, 6, 29))), &host);
    assert_eq!(a.os.status, b.os.status);
    assert_eq!(a.os.reason, b.os.reason);
}

#[test]
fn r16_inf_pos_irrelevant() {
    let host = host_x64_26200();
    let mk = |inf_pos: i32| {
        synthetic_catalog_with_models("synth", &[("H1", "M1", "m1", "NTamd64.10.0...22000", inf_pos)])
    };
    let a = assess_single(mk(0), &host);
    let b = assess_single(mk(7), &host);
    assert_eq!(a.os.status, b.os.status);
    assert_eq!(a.os.reason, b.os.reason);
    // inf_pos stays in evidence as SDIO metadata only.
    assert_eq!(a.matched.evidence[0].inf_pos, 0);
    assert_eq!(b.matched.evidence[0].inf_pos, 7);
}

// R17 — match evidence kind is irrelevant

#[test]
fn r17_evidence_kind_irrelevant() {
    let host = host_x64_26200();
    // Same logical candidate (install/picked/models) reachable via hardware and
    // via compatible evidence. Both must get the same OS applicability.
    let build = || {
        synthetic_catalog_with_models(
            "synth",
            &[
                ("H1", "M1", "m1", "NTamd64.10.0...22000", 0),
                ("C1", "M1", "m1", "NTamd64.10.0...22000", 1),
            ],
        )
    };
    let dev_hw = device("PCI\\HW", &["H1"], &[]);
    let dev_compat = device("PCI\\C", &["PCI\\VEN_FFFF&DEV_FFFF"], &["C1"]);
    let m_hw = mod_drivers::sdio::match_device_to_catalogs(&dev_hw, &[build()]).unwrap();
    let m_comp = mod_drivers::sdio::match_device_to_catalogs(&dev_compat, &[build()]).unwrap();
    assert_eq!(m_hw.candidates[0].evidence[0].kind, DeviceIdKind::Hardware);
    assert_eq!(
        m_comp.candidates[0].evidence[0].kind,
        DeviceIdKind::Compatible
    );
    let a = assess_device_matches(&m_hw, &host).unwrap();
    let b = assess_device_matches(&m_comp, &host).unwrap();
    assert_eq!(a.candidates[0].os.status, b.candidates[0].os.status);
    assert_eq!(a.candidates[0].os.reason, b.candidates[0].os.reason);
    assert_eq!(a.candidates[0].os.status, CatalogOsApplicability::HostCompatible);
}

// R18 — order preserved

#[test]
fn r18_order_preserved() {
    let host = host_x64_26200();
    let dev_a = device("PCI\\A", &["H1", "H2", "H3"], &[]);
    let dev_b = device("PCI\\B", &["H3", "H2"], &[]);

    let results = assess_matches(
        &[
            mod_drivers::sdio::match_device_to_catalogs(&dev_a, &[mixed_status_catalog()]).unwrap(),
            mod_drivers::sdio::match_device_to_catalogs(&dev_b, &[mixed_status_catalog()]).unwrap(),
        ],
        &host,
    )
    .expect("batch must succeed");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].instance_id, "PCI\\A");
    assert_eq!(results[1].instance_id, "PCI\\B");
    // Device A candidate order [M1, M2, M3] preserved; no sorting by status.
    assert_eq!(results[0].candidates.len(), 3);
    assert_eq!(
        results[0].candidates[0].os.status,
        CatalogOsApplicability::HostIncompatible
    );
    assert_eq!(
        results[0].candidates[1].os.status,
        CatalogOsApplicability::HostCompatible
    );
    assert_eq!(
        results[0].candidates[2].os.status,
        CatalogOsApplicability::Indeterminate
    );
    // Device B candidate order [M3, M2] preserved.
    assert_eq!(results[1].candidates.len(), 2);
    assert_eq!(
        results[1].candidates[0].os.status,
        CatalogOsApplicability::Indeterminate
    );
    assert_eq!(
        results[1].candidates[1].os.status,
        CatalogOsApplicability::HostCompatible
    );
}

// R19 — distinct target sections do not collapse (real dedupe collision)

#[test]
fn r19_distinct_target_sections_do_not_collapse() {
    // Gate A4 corpus proof: identical (pack, inf, install, picked) rows differ
    // by sect_pos / models target. A synthetic catalog with two rows sharing
    // (install, picked) but different models targets must yield TWO candidate
    // matches through the matcher — the dedupe key includes models_section.
    let cat = synthetic_catalog_with_models(
        "synth",
        &[
            ("H1", "M1", "m1", "ntamd64.10.0", 0),
            ("H2", "M1", "m1", "ntamd64.6.3.1", 1),
        ],
    );
    let dev = device("PCI\\0", &["H1", "H2"], &[]);
    let matched = mod_drivers::sdio::match_device_to_catalogs(&dev, &[cat])
        .expect("match must succeed");
    assert_eq!(
        matched.candidates.len(),
        2,
        "rows differing only by models target must not collapse"
    );
    let t0 = matched.candidates[0]
        .candidate
        .models_section
        .as_deref()
        .expect("target 0");
    let t1 = matched.candidates[1]
        .candidate
        .models_section
        .as_deref()
        .expect("target 1");
    assert_ne!(t0, t1, "the two candidates must carry distinct targets");
    // The two rows also differ by the positional sect_pos (1 vs 2).
    assert_ne!(
        matched.candidates[0].candidate.sect_pos,
        matched.candidates[1].candidate.sect_pos
    );
}

// R20 — real fixture end-to-end

#[test]
fn r20_real_fixture_end_to_end() {
    let cat = fixture_catalog("DP_Display_SDIO01_26082");
    let dev = device("PCI\\0", &[GPU_HWID], &[]);
    let matched = mod_drivers::sdio::match_device_to_catalogs(&dev, &[cat])
        .expect("match must succeed");
    assert_eq!(matched.candidates.len(), 1);
    let m = &matched.candidates[0];

    // Pack provenance + matching evidence retained.
    assert_eq!(m.pack_name, "DP_Display_SDIO01_26082");
    assert_eq!(m.evidence[0].kind, DeviceIdKind::Hardware);
    assert_eq!(m.evidence[0].device_id, GPU_HWID);
    // Models target provenance retained.
    assert_eq!(
        m.candidate.models_section.as_deref(),
        Some("ntamd64.10.0.1..19044")
    );

    let assessed = assess_device_matches(&matched, &host_x64_26200()).expect("must assess");
    assert_eq!(assessed.instance_id, "PCI\\0");
    assert_eq!(assessed.candidates.len(), 1);
    let c = &assessed.candidates[0];
    assert_eq!(c.matched.pack_name, "DP_Display_SDIO01_26082");
    assert_eq!(c.matched.candidate.inf_filename, "u0202099.inf");
    assert_eq!(
        c.os.models_section.as_deref(),
        Some("ntamd64.10.0.1..19044")
    );
    // The fixture target (10.0.1..19044) carries a ProductType component
    // (major.minor.producttype..build) → MachineContext lacks ProductType →
    // Indeterminate. Deterministic, never "update".
    assert_eq!(c.os.status, CatalogOsApplicability::Indeterminate);
    assert_eq!(c.os.reason, ApplicabilityReason::ProductTypeUnavailable);
    assert!(c.os.target.is_some());
}

// R21 — no update-classification type exists in the public domain

#[test]
fn r21_no_update_classification_types() {
    // The public domain exposes only the tri-state + reasons; the variants
    // below are the complete set (no recommended/update/better/rank type can be
    // named). Result structs carry evidence only.
    let _: CatalogOsApplicability = CatalogOsApplicability::HostCompatible;
    let _: CatalogOsApplicability = CatalogOsApplicability::HostIncompatible;
    let _: CatalogOsApplicability = CatalogOsApplicability::Indeterminate;
    let _: ApplicabilityReason = ApplicabilityReason::TargetSatisfied;
    let _: ApplicabilityReason = ApplicabilityReason::ArchitectureMismatch;
    let _: ApplicabilityReason = ApplicabilityReason::OsVersionTooOld;
    let _: ApplicabilityReason = ApplicabilityReason::BuildTooOld;
    let _: ApplicabilityReason = ApplicabilityReason::ProductTypeUnavailable;
    let _: ApplicabilityReason = ApplicabilityReason::SuiteMaskUnavailable;
    let _: ApplicabilityReason = ApplicabilityReason::MissingTargetMetadata;
    let _: ApplicabilityReason = ApplicabilityReason::UnsupportedTargetSyntax;
    let _: ApplicabilityReason = ApplicabilityReason::UnknownHostArchitecture;

    let ev: CatalogApplicabilityEvidence = CatalogApplicabilityEvidence {
        models_section: None,
        target: None,
        status: CatalogOsApplicability::Indeterminate,
        reason: ApplicabilityReason::MissingTargetMetadata,
    };
    assert_eq!(ev.models_section, None);
    let _: AssessedCatalogCandidate = AssessedCatalogCandidate {
        matched: mk_candidate(None),
        os: ev,
    };
}

// R22 — batch determinism (deep equality across runs)

#[test]
fn r22_batch_determinism() {
    let host = host_x64_26200();
    let dev_a = device("PCI\\A", &["H1", "H2", "H3"], &[]);
    let dev_b = device("PCI\\B", &["H3", "H2"], &[]);
    let inputs = vec![
        mod_drivers::sdio::match_device_to_catalogs(&dev_a, &[mixed_status_catalog()]).unwrap(),
        mod_drivers::sdio::match_device_to_catalogs(&dev_b, &[mixed_status_catalog()]).unwrap(),
    ];

    let run = || assess_matches(&inputs, &host).expect("must assess");
    let first = run();
    let second = run();
    assert_eq!(first, second, "identical input must yield identical output");
    assert_eq!(first.len(), 2);
    // No HashMap iteration order leaks into results.
    assert_eq!(first, run());
}

// Parser contracts (domain-level)

#[test]
fn target_parser_bounds_are_finite() {
    // Extremely long input must not hang or panic; it either parses exactly or
    // returns an explicit error. No unbounded component allocation.
    let huge = format!("NTamd64.{}", "9".repeat(10_000));
    match parse_target_os_version(&huge) {
        Ok(deco) => {
            assert_eq!(deco.major, None, "overflowing major must not be Some");
        }
        Err(_) => {}
    }
    let _ = parse_target_os_version(&"NT".repeat(10_000));
}

#[test]
fn architecture_normalization_mapping() {
    assert_eq!(
        mod_drivers::sdio::applicability::normalize_host_arch("x64"),
        Some(TargetArch::Amd64)
    );
    assert_eq!(
        mod_drivers::sdio::applicability::normalize_host_arch("x86"),
        Some(TargetArch::X86)
    );
    assert_eq!(
        mod_drivers::sdio::applicability::normalize_host_arch("arm64"),
        Some(TargetArch::Arm64)
    );
    // Unknown host architectures are never treated as compatible.
    let unknown = machine("mips", "10.0", "26200");
    let ev = mod_drivers::sdio::applicability::evaluate_target(
        &parse_target_os_version("NTamd64").unwrap(),
        &unknown,
    );
    assert!(ev.is_err(), "unknown host arch must be an explicit error");
}

#[test]
fn no_candidate_is_dropped_by_assessment() {
    let host = host_x64_26200();
    let dev = device("PCI\\0", &["H1", "H2", "H3"], &[]);
    let matched = mod_drivers::sdio::match_device_to_catalogs(&dev, &[mixed_status_catalog()]).unwrap();
    let count_before = matched.candidates.len();
    assert_eq!(count_before, 3);
    let assessed = assess_device_matches(&matched, &host).unwrap();
    assert_eq!(
        assessed.candidates.len(),
        count_before,
        "assessment must not drop candidates"
    );
}

#[test]
fn host_compatible_carries_no_install_semantics() {
    // The applicability enum is the ONLY classification; HostCompatible must not
    // imply installable/update/rank. Evidence fields are exactly
    // models_section/target/status/reason.
    let host = host_x64_26200();
    let deco = parse_target_os_version("NTamd64").unwrap();
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::HostCompatible);
    assert_eq!(ev.models_section, None);
    assert_eq!(ev.reason, ApplicabilityReason::TargetSatisfied);
    assert!(ev.target.is_some());

    // Full path: matched candidate with models_section "ntamd64" at a
    // decoration position on an x64 host is HostCompatible and keeps target
    // provenance.
    let cat = synthetic_catalog_with_models("synth", &[("H1", "M1", "m1", "ntamd64", 0)]);
    let m = one_match("PCI\\0", &["H1"], cat);
    let assessed = assess_device_matches(
        &DeviceCatalogMatches {
            instance_id: "PCI\\0".into(),
            candidates: vec![m],
        },
        &host,
    )
    .unwrap();
    assert_eq!(
        assessed.candidates[0].os.status,
        CatalogOsApplicability::HostCompatible
    );
    assert_eq!(
        assessed.candidates[0].os.models_section.as_deref(),
        Some("ntamd64")
    );
    assert!(assessed.candidates[0].os.target.is_some());
}

#[test]
fn all_recognized_architectures_parse() {
    // Every arch token Microsoft documents is recognized (Cove need not run on
    // all of them; the evaluator interprets the target).
    let x86 = parse_target_os_version("NTx86").unwrap();
    assert_eq!(x86.architecture, Some(TargetArch::X86));
    let ia64 = parse_target_os_version("NTia64").unwrap();
    assert_eq!(ia64.architecture, Some(TargetArch::Ia64));
    let amd64 = parse_target_os_version("NTamd64").unwrap();
    assert_eq!(amd64.architecture, Some(TargetArch::Amd64));
    let arm = parse_target_os_version("NTarm").unwrap();
    assert_eq!(arm.architecture, Some(TargetArch::Arm));
    let arm64 = parse_target_os_version("NTarm64").unwrap();
    assert_eq!(arm64.architecture, Some(TargetArch::Arm64));

    // Explicit matching architecture without version is compatible.
    let host = machine("arm64", "10.0", "26200");
    let ev = mod_drivers::sdio::applicability::evaluate_target(&arm64, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::HostCompatible);
}

#[test]
fn os_version_without_build_is_a_threshold() {
    let host = host_x64_26200();
    // NTamd64.10.0 (no build): host 10.0 equals target 10.0 → satisfied.
    let deco = parse_target_os_version("NTamd64.10.0").unwrap();
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::HostCompatible);

    // NTamd64.10.1: host 10.0 < target 10.1 → incompatible.
    let deco = parse_target_os_version("NTamd64.10.1").unwrap();
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::HostIncompatible);
    assert_eq!(ev.reason, ApplicabilityReason::OsVersionTooOld);
}

#[test]
fn empty_component_positions_are_exact() {
    // Dotted slots are strictly positional (Microsoft grammar). An empty
    // component never "skips to the build slot".
    // NTamd64....22000 == major absent, minor absent, product empty, SUITE=22000
    // (a suite-mask value, not a build). MachineContext lacks SuiteMask →
    // Indeterminate.
    let deco = parse_target_os_version("NTamd64....22000").unwrap();
    assert_eq!(deco.major, None);
    assert_eq!(deco.minor, None);
    assert_eq!(deco.product_type, None);
    assert_eq!(deco.suite_mask, Some(22000));
    assert_eq!(deco.build, None);
    let host = host_x64_26200();
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::Indeterminate);

    // Codex example: NTamd64.10...0x80 == major=10, minor empty, product empty,
    // SUITE=0x80 (not build 128).
    let deco = parse_target_os_version("NTamd64.10...0x80").unwrap();
    assert_eq!(deco.major, Some(10));
    assert_eq!(deco.minor, None);
    assert_eq!(deco.suite_mask, Some(0x80));
    assert_eq!(deco.build, None);
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::Indeterminate);

    // The real build form NTamd64.10.0...22000 keeps its five positional slots.
    let deco = parse_target_os_version("NTamd64.10.0...22000").unwrap();
    assert_eq!(deco.major, Some(10));
    assert_eq!(deco.minor, Some(0));
    assert_eq!(deco.product_type, None);
    assert_eq!(deco.suite_mask, None);
    assert_eq!(deco.build, Some(22000));
}

#[test]
fn build_floor_and_decimal_only_enforced() {
    // Microsoft: build decorations require Windows 10 (10.0) and build >= 14310.
    // A build below the floor or on the wrong OS version is malformed.
    for bad in [
        "NTamd64.10.0...1",
        "NTamd64.10.0...14309",
        "NTamd64.6.1...16299",
        "NTamd64.11.0...22000",
    ] {
        match parse_target_os_version(bad) {
            Ok(deco) => {
                let host = host_x64_26200();
                let ev =
                    mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
                assert_ne!(
                    ev.status,
                    CatalogOsApplicability::HostCompatible,
                    "build-decoration floor violated for {bad:?}"
                );
            }
            Err(_) => {}
        }
    }

    // Hex is only valid in the ProductType / SuiteMask slots; a hex major or
    // build must be rejected, not silently accepted.
    assert!(parse_target_os_version("NTamd64.0xA.0").is_err());
    assert!(parse_target_os_version("NTamd64.10.0...0x55F0").is_err());
    // Decimal product/suite remain accepted.
    assert_eq!(
        parse_target_os_version("NTamd64.10.0.1.128").unwrap().suite_mask,
        Some(128)
    );

    // A minor version without a major version is not a valid OS-version pair
    // and must be rejected (it cannot express a threshold). (Codex round-4.)
    assert!(parse_target_os_version("NTamd64..99").is_err());
}

#[test]
fn undecorated_base_named_like_nt_is_not_a_decoration() {
    // Gate A4: sect_pos == 0 is the undecorated Models-section base name and
    // carries no OS evidence, even when its text begins with `NT` (e.g. a
    // manufacturer section literally named "NTamd64"). Provenance is
    // positional; the assessment must not guess from the text.
    let assessed = assess_device_matches(
        &DeviceCatalogMatches {
            instance_id: "PCI\\0".into(),
            candidates: vec![mk_candidate_at(Some("NTamd64"), 0)],
        },
        &host_x64_26200(),
    )
    .unwrap();
    assert_eq!(
        assessed.candidates[0].os.status,
        CatalogOsApplicability::Indeterminate
    );
    assert_eq!(
        assessed.candidates[0].os.reason,
        ApplicabilityReason::MissingTargetMetadata
    );

    // The same text at sect_pos 1 IS a decoration and evaluates normally.
    let assessed = assess_device_matches(
        &DeviceCatalogMatches {
            instance_id: "PCI\\0".into(),
            candidates: vec![mk_candidate_at(Some("NTamd64"), 1)],
        },
        &host_x64_26200(),
    )
    .unwrap();
    assert_eq!(
        assessed.candidates[0].os.status,
        CatalogOsApplicability::HostCompatible
    );
}

#[test]
fn version_negative_beats_unknown_product_type() {
    // The OS-version threshold is independently provable: a target that already
    // excludes the host by version must be HostIncompatible even though its
    // ProductType is unknown to MachineContext. (Codex round-1 finding.)
    let host = host_x64_26200(); // 10.0 build 26200
    let deco = parse_target_os_version("NTamd64.11.0.1").unwrap(); // 11.0 + product type
    assert_eq!(deco.product_type, Some(1));
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(
        ev.status,
        CatalogOsApplicability::HostIncompatible,
        "11.0 minimum excludes a 10.0 host regardless of unknown ProductType"
    );
    assert_eq!(ev.reason, ApplicabilityReason::OsVersionTooOld);

    // Same-version build threshold also beats unknown ProductType.
    let deco = parse_target_os_version("NTamd64.10.0.1..30000").unwrap();
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(
        ev.status,
        CatalogOsApplicability::HostIncompatible,
        "build 30000 > host build 26200 regardless of unknown ProductType"
    );
    assert_eq!(ev.reason, ApplicabilityReason::BuildTooOld);

    // Architecture-optional decoration: the version threshold applies on any
    // platform, so an absent architecture must NOT turn a provable version
    // negative into Indeterminate. (Codex round-2 finding.)
    let host_61 = machine("x64", "6.1", "7601");
    let deco = parse_target_os_version("NT.7.8").unwrap(); // no architecture
    assert_eq!(deco.architecture, None);
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host_61).unwrap();
    assert_eq!(
        ev.status,
        CatalogOsApplicability::HostIncompatible,
        "NT.7.8 minimum excludes a 6.1 host regardless of architecture"
    );
    assert_eq!(ev.reason, ApplicabilityReason::OsVersionTooOld);

    // Architecture-absent + version satisfied + ProductType: the version
    // threshold is satisfied on any platform, so the remaining unknown is the
    // ProductType → Indeterminate(ProductTypeUnavailable), NOT
    // MissingTargetMetadata. (Codex round-3 finding.)
    let host_78 = machine("x64", "7.8", "5000");
    let deco = parse_target_os_version("NT.7.8.1").unwrap(); // no arch, product type
    assert_eq!(deco.architecture, None);
    assert_eq!(deco.product_type, Some(1));
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host_78).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::Indeterminate);
    assert_eq!(ev.reason, ApplicabilityReason::ProductTypeUnavailable);
}

#[test]
fn architecture_absent_version_satisfied_is_indeterminate_on_non_x86() {
    // Architecture-absent TargetOSVersion (`NT.10.0`) cannot PROVE
    // compatibility on a non-x86 host: since Windows Server 2003 SP1,
    // architecture is optional in Models-section names only for x86-based
    // target OS versions, so an arch-less decoration is not a deterministic
    // compatibility proof for x64/ARM64. It must be Indeterminate, never
    // HostCompatible via a satisfied version threshold alone.
    let host = host_x64_26200(); // x64 10.0 build 26200
    let deco = parse_target_os_version("NT.10.0").unwrap(); // no architecture
    assert_eq!(deco.architecture, None);
    assert_eq!(deco.major, Some(10));
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host).unwrap();
    assert_eq!(
        ev.status,
        CatalogOsApplicability::Indeterminate,
        "NT.10.0 on x64 must not prove compatibility"
    );
    assert_eq!(ev.reason, ApplicabilityReason::MissingTargetMetadata);

    // Same on ARM64: arch-absent + satisfied threshold is Indeterminate.
    let host_arm = machine("arm64", "10.0", "26200");
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco, &host_arm).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::Indeterminate);
    assert_eq!(ev.reason, ApplicabilityReason::MissingTargetMetadata);

    // The version threshold still proves negatives regardless of architecture.
    let deco_11 = parse_target_os_version("NT.11.0").unwrap();
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco_11, &host).unwrap();
    assert_eq!(
        ev.status,
        CatalogOsApplicability::HostIncompatible,
        "NT.11.0 minimum excludes a 10.0 host even without an architecture"
    );
    assert_eq!(ev.reason, ApplicabilityReason::OsVersionTooOld);

    // An explicit matching architecture keeps proving compatibility.
    let deco_amd = parse_target_os_version("NTamd64.10.0").unwrap();
    let ev = mod_drivers::sdio::applicability::evaluate_target(&deco_amd, &host).unwrap();
    assert_eq!(ev.status, CatalogOsApplicability::HostCompatible);
    assert_eq!(ev.reason, ApplicabilityReason::TargetSatisfied);
}

#[test]
fn non_ascii_nt_prefix_never_panics() {
    // The NT-prefix check is byte-safe: a leading multi-byte character must not
    // panic, and the string is rejected as not-an-NT-decoration.
    let evil = "𝒩Tamd64"; // U+1D4A9 MATHEMATICAL SCRIPT CAPITAL N
    assert!(parse_target_os_version(evil).is_err());
}
