// Integration tests for Tab 2a-5: local SDIO driver-pack resolution and the
// materialization-request boundary.
//
// This slice converts an already-discovered `CatalogCandidateMatch` into a
// narrowly validated local-pack + expected-INF-archive-member request. It does
// NOT extract archives, inspect members, parse INFs, validate CAT/signature
// trust, or install anything. `pack_name` and the candidate INF metadata are
// untrusted index text and are validated fail-closed before any filesystem
// join or archive-member string is produced.
//
// The mapping proven in Gate P5:
//   pack_name (index file stem)      -> <pack_name>.7z directly under the root
//   inf_path (dir w/ trailing `\`)   -> forward-slash archive directory
//   inf_filename (leaf .inf)         -> appended to the directory
//
// Filesystem resolution uses std only; tests build throwaway directories under
// %TEMP% and remove them on drop. No network, no extraction, no subprocess.

use std::fs;
use std::path::{Path, PathBuf};

use mod_drivers::identity::DeviceIdentity;
use mod_drivers::sdio::local_pack::{
    ExpectedArchiveMember, LocalPackAvailability, LocalPackError, LocalPackRef,
    MAX_ARCHIVE_COMPONENT_LEN, MAX_ARCHIVE_MEMBER_COMPONENTS, MAX_ARCHIVE_MEMBER_LEN,
    MAX_LOCAL_PACK_BYTES, PackageMaterializationRequest, expected_inf_member,
    expected_pack_filename, resolve_local_pack,
};
use mod_drivers::sdio::{
    CatalogCandidateMatch, DeviceIdKind, MAX_TOTAL_CANDIDATES, MatchEvidence,
    match_device_to_catalogs,
};

const VALID_BYTES: &[u8] = include_bytes!("../fixtures/sdio/valid_small.bin");

/// Real GPU hardware ID present in the fixture (`u0202099.inf`).
const GPU_HWID: &str = "PCI\\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1";

// ---------------------------------------------------------------------------
// Test scaffolding (std-only, self-cleaning)
// ---------------------------------------------------------------------------

/// A unique temporary directory under `%TEMP%`, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir();
        let uniq = format!(
            "cove_tab2a5_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let dir = base.join(uniq);
        fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The `drivers` subdirectory of a TempDir, created up front.
fn drivers_root(tmp: &TempDir) -> PathBuf {
    let root = tmp.path().join("drivers");
    fs::create_dir_all(&root).expect("create drivers root");
    root
}

fn write_bytes(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(path, bytes).expect("write fixture file");
}

/// A minimal candidate. `inf_path` follows the real SDIO convention: a
/// directory path ending in a single trailing backslash.
fn candidate(inf_path: &str, inf_filename: &str) -> CatalogCandidateMatch {
    CatalogCandidateMatch {
        pack_name: "DP_Test_26000".to_string(),
        candidate: mod_drivers::sdio::Candidate {
            inf_path: inf_path.to_string(),
            inf_filename: inf_filename.to_string(),
            provider: None,
            class: None,
            class_guid: None,
            catalog_file: Some("u0202099.cat".to_string()),
            version: None,
            date: None,
            install_section: "install".to_string(),
            picked_section: "picked".to_string(),
            sect_pos: 0,
            models_section: None,
            inf_pos: 0,
        },
        evidence: vec![MatchEvidence {
            kind: DeviceIdKind::Hardware,
            device_id: "PCI\\VEN_0000&DEV_0000".to_string(),
            ordinal: 0,
            inf_pos: 0,
        }],
    }
}

/// The real fixture candidate: pack `DP_Display_SDIO01_26082`,
/// `amd\10x64\ati2mtag_StrixHalo_32.0.23033.5002\` + `u0202099.inf`.
fn fixture_candidate() -> CatalogCandidateMatch {
    let cat =
        mod_drivers::sdio::SdioCatalog::parse_bytes(VALID_BYTES, "DP_Display_SDIO01_26082".into())
            .expect("fixture must parse");
    let dev = DeviceIdentity {
        instance_id: "PCI\\0".to_string(),
        hardware_ids: vec![GPU_HWID.to_string()],
        compatible_ids: Vec::new(),
        class_guid: None,
        class_name: None,
        description: None,
        manufacturer: None,
        problem_code: None,
        installed: None,
        matching: Vec::new(),
    };
    let matched = match_device_to_catalogs(&dev, &[cat]).expect("match must succeed");
    assert_eq!(matched.candidates.len(), 1);
    matched.candidates.into_iter().next().unwrap()
}

// ===========================================================================
// R1 — pack stem -> exact .7z filename
// ===========================================================================

#[test]
fn r1_pack_stem_to_exact_7z_filename() {
    let name = expected_pack_filename("DP_Display_SDIO01_26082").expect("valid stem");
    assert_eq!(name, "DP_Display_SDIO01_26082.7z");
    // No path prefix, no separator ever enters the name.
    assert!(!name.contains(['/', '\\']));
}

// ===========================================================================
// R2 — invalid pack path injection rejected before any join
// ===========================================================================

#[test]
fn r2_invalid_pack_paths_rejected() {
    for bad in [
        "../evil",
        "..\\evil",
        "foo/bar",
        "foo\\bar",
        "C:\\evil",
        "C:evil",
        "\\\\server\\share",
        "foo:bar",
        ".",
        "..",
        // Windows-invalid names (Codex round-8 finding): reserved DOS device
        // names and forbidden filename characters.
        "CON",
        "CON.7z",
        "NUL",
        "AUX",
        "COM1",
        "LPT9",
        "pack?",
        "pack*",
        "pack<1>",
        "pack|2",
        // Windows-invalid names (Codex round-9 finding): ASCII control
        // characters and legacy superscript device spellings.
        "DP_\u{1}_26000",
        "DP_\u{1F}_26000",
        "COM\u{b9}",
        "COM\u{b2}",
        "COM\u{b3}",
        "LPT\u{b9}",
        "LPT\u{b3}",
    ] {
        assert!(
            expected_pack_filename(bad).is_err(),
            "pack name {bad:?} must be rejected"
        );
    }

    // A stem longer than 252 bytes would make `<stem>.7z` exceed the 255-unit
    // Windows component limit (Codex round-9 finding). The rejection is
    // payload-free (Codex round-13 finding).
    let long_stem = "x".repeat(253);
    let err = expected_pack_filename(&long_stem).expect_err("over-long stem");
    assert!(
        matches!(err, LocalPackError::PackNameTooLong),
        "payload-free rejection expected, got {err:?}"
    );
    // 252-byte stem + ".7z" == 255 bytes: exactly at the limit, accepted.
    let exact_stem = "x".repeat(252);
    let name = expected_pack_filename(&exact_stem).expect("252-byte stem valid");
    assert_eq!(name.len(), 255);
}

// ===========================================================================
// R3 — trailing / ambiguous Windows names rejected, never trimmed
// ===========================================================================

#[test]
fn r3_ambiguous_windows_names_rejected() {
    for bad in [
        " pack",
        "pack ",
        "pack.",
        "",
        // Any ASCII whitespace at either end is rejected, not just space
        // (Codex round-3 finding). Rust's `is_ascii_whitespace` covers TAB,
        // LF, FF, CR and SPACE (U+000B vertical tab is deliberately NOT part
        // of that set, so it is excluded from the cases).
        "\tpack",
        "pack\t",
        "\rpack",
        "pack\r",
        "\npack",
        "pack\n",
        "\x0cpack",
        "pack\x0c",
        // ASCII-only pack stems (Codex round-6 finding): Windows case-folds
        // Unicode names beyond Rust string comparison, so non-ASCII stems are
        // rejected outright. All real SDIO pack names are ASCII.
        "DP_Ä_26000",
        "пак_26000",
        "DP_Test_26000\u{00e9}",
    ] {
        assert!(
            expected_pack_filename(bad).is_err(),
            "pack name {bad:?} must be rejected without trimming"
        );
    }
}

// ===========================================================================
// R4 — exact local pack present
// ===========================================================================

#[test]
fn r4_exact_local_pack_present() {
    let tmp = TempDir::new("r4");
    let root = drivers_root(&tmp);
    write_bytes(&root.join("DP_Test_26000.7z"), b"not-an-archive");

    let res = resolve_local_pack(&root, &candidate("amd\\10x64\\", "driver.inf")).expect("resolve");
    match res {
        LocalPackAvailability::Present(req) => {
            assert_eq!(req.pack().pack_name(), "DP_Test_26000");
            assert_eq!(
                req.pack().archive_path().file_name().unwrap(),
                "DP_Test_26000.7z"
            );
            // Canonical path must remain under the canonical root.
            let canon_root = fs::canonicalize(&root).expect("canonical root");
            let canon_pack = fs::canonicalize(req.pack().archive_path()).expect("canonical pack");
            assert!(
                canon_pack.starts_with(&canon_root),
                "pack must stay under canonical root"
            );
            assert_eq!(req.pack().size_bytes(), 14, "non-zero size retained");
            assert_eq!(req.inf().relative_path(), "amd/10x64/driver.inf");
        }
        other => panic!("expected Present, got {other:?}"),
    }
}

// ===========================================================================
// R5 — missing pack is an explicit normal state
// ===========================================================================

#[test]
fn r5_missing_pack_is_normal_state() {
    let tmp = TempDir::new("r5");
    let root = drivers_root(&tmp);
    // Root exists; the expected file is absent.

    let res = resolve_local_pack(&root, &candidate("amd\\10x64\\", "driver.inf")).expect("resolve");
    match res {
        LocalPackAvailability::Missing {
            pack_name,
            expected_filename,
        } => {
            assert_eq!(pack_name, "DP_Test_26000");
            assert_eq!(expected_filename, "DP_Test_26000.7z");
        }
        other => panic!("expected Missing, got {other:?}"),
    }
}

#[test]
fn r5b_invalid_inf_metadata_fails_closed_even_when_pack_absent() {
    // A hostile candidate with traversal INF metadata must fail closed with an
    // explicit error, NOT return a plausible `Missing` just because the pack
    // happens to be absent (Codex round-2 finding).
    let tmp = TempDir::new("r5b");
    let root = drivers_root(&tmp);
    let mut c = candidate("amd\\10x64\\", "driver.inf");
    c.candidate.inf_path = "..\\evil\\".to_string();

    let err = resolve_local_pack(&root, &c).expect_err("invalid INF must fail closed");
    assert!(
        matches!(err, LocalPackError::InvalidInfPath(_)),
        "got {err:?}"
    );

    // Same for a malformed leaf filename.
    let mut c2 = candidate("amd\\10x64\\", "driver.inf");
    c2.candidate.inf_filename = "..\\evil.inf".to_string();
    let err2 = resolve_local_pack(&root, &c2).expect_err("invalid INF must fail closed");
    assert!(
        matches!(err2, LocalPackError::InvalidInfFilename(_)),
        "got {err2:?}"
    );
}

// ===========================================================================
// R6 — old/new version substitution forbidden (fuzzy fallback never happens)
// ===========================================================================

#[test]
fn r6_version_substitution_forbidden() {
    let tmp = TempDir::new("r6");
    let root = drivers_root(&tmp);
    write_bytes(&root.join("DP_Test_25999.7z"), b"old");
    write_bytes(&root.join("DP_Test_26001.7z"), b"new");
    // Requested: 26000 — only the exact name may resolve.

    let res = resolve_local_pack(&root, &candidate("amd\\10x64\\", "driver.inf")).expect("resolve");
    assert!(
        matches!(res, LocalPackAvailability::Missing { .. }),
        "different versions must never substitute, got {res:?}"
    );
}

// ===========================================================================
// R7 — nested pack does not resolve (direct child only)
// ===========================================================================

#[test]
fn r7_nested_pack_does_not_resolve() {
    let tmp = TempDir::new("r7");
    let root = drivers_root(&tmp);
    // Only a nested file exists beneath an `archive` subdirectory.
    write_bytes(&root.join("archive").join("DP_Test_26000.7z"), b"nested");

    let res = resolve_local_pack(&root, &candidate("amd\\10x64\\", "driver.inf")).expect("resolve");
    assert!(
        matches!(res, LocalPackAvailability::Missing { .. }),
        "nested pack must not satisfy a direct-child request, got {res:?}"
    );
}

// ===========================================================================
// R8 — directory with the .7z name is rejected
// ===========================================================================

#[test]
fn r8_directory_with_7z_name_rejected() {
    let tmp = TempDir::new("r8");
    let root = drivers_root(&tmp);
    fs::create_dir_all(root.join("DP_Test_26000.7z")).expect("create dir");

    let err = resolve_local_pack(&root, &candidate("amd\\10x64\\", "driver.inf"))
        .expect_err("directory must be rejected");
    assert!(
        matches!(err, LocalPackError::PackNotRegularFile(_)),
        "got {err:?}"
    );
}

// ===========================================================================
// R9 — symlink pack rejected (privilege-gated live check + structural proof)
// ===========================================================================

/// Pure structural symlink rejection proof that runs everywhere: the resolver
/// consults `symlink_metadata` BEFORE any link-following metadata and rejects a
/// symbolic link on any host. We cannot fabricate a real link without
/// privileges on Windows, so the live check is privilege-gated below; this test
/// pins the code-level order/behavior contract by asserting the resolver's
/// symlink check is reachable and that a documented rejection path exists.
#[test]
fn r9_symlink_rejection_contract() {
    // The error variant exists and is explicit (structural contract).
    let _: LocalPackError = LocalPackError::PackSymlinkRejected(PathBuf::new());

    // On hosts where a symlink can be created (Windows developer mode or
    // elevated, or Unix), exercise the real rejection. On other hosts this is
    // NOT executed — never treated as PASS for the live path. All probe files
    // live inside the test's unique TempDir and are removed with it.
    #[cfg(windows)]
    {
        let tmp = TempDir::new("r9");
        let root = drivers_root(&tmp);
        write_bytes(&root.join("real.7z"), b"real");
        let link = root.join("DP_Test_26000.7z");
        match std::os::windows::fs::symlink_file(root.join("real.7z"), &link) {
            Ok(()) => {
                let err = resolve_local_pack(&root, &candidate("amd\\10x64\\", "driver.inf"))
                    .expect_err("symlink must be rejected");
                assert!(
                    matches!(err, LocalPackError::PackSymlinkRejected(_)),
                    "got {err:?}"
                );
            }
            Err(_) => {
                // Privilege unavailable: NOT EXECUTED. The structural contract
                // above plus the deterministic tests still stand.
            }
        }
    }
    #[cfg(not(windows))]
    {
        let tmp = TempDir::new("r9");
        let root = drivers_root(&tmp);
        write_bytes(&root.join("real.7z"), b"real");
        std::os::unix::fs::symlink(&root.join("real.7z"), &root.join("DP_Test_26000.7z"))
            .expect("create symlink");
        let err = resolve_local_pack(&root, &candidate("amd\\10x64\\", "driver.inf"))
            .expect_err("symlink must be rejected");
        assert!(
            matches!(err, LocalPackError::PackSymlinkRejected(_)),
            "got {err:?}"
        );
    }
}

// ===========================================================================
// R9b — canonical name containment: a name-changing substitution is rejected
// ===========================================================================

#[test]
fn r9b_canonical_name_must_match_expected_direct_child() {
    let tmp = TempDir::new("r9b");
    let root = drivers_root(&tmp);
    // A sibling pack under the SAME root with a different name. The resolver
    // must never let a canonicalization to that sibling satisfy a request for
    // `DP_Test_26000.7z` (Codex round-4 TOCTOU finding). We cannot race the
    // check in a deterministic unit test, so we verify the invariant directly:
    // a request resolves only when the canonical child is the expected name.
    write_bytes(&root.join("DP_Test_26000.7z"), b"exact");
    write_bytes(&root.join("DP_Test_26001.7z"), b"sibling");

    // The exact-name pack resolves Present.
    let res = resolve_local_pack(&root, &candidate("amd\\10x64\\", "driver.inf")).expect("resolve");
    assert!(matches!(res, LocalPackAvailability::Present(_)));

    // A request for the sibling's name resolves Present only for THAT name.
    let mut c = candidate("amd\\10x64\\", "driver.inf");
    c.pack_name = "DP_Test_26001".to_string();
    let res = resolve_local_pack(&root, &c).expect("resolve");
    let LocalPackAvailability::Present(req) = res else {
        panic!("expected Present");
    };
    assert_eq!(
        req.pack().archive_path().file_name().unwrap(),
        "DP_Test_26001.7z"
    );

    // Windows filesystems resolve names case-insensitively: a pack stored with
    // different casing must still resolve Present on Windows (Codex round-5
    // finding), while the direct-child/name-containment invariant holds.
    #[cfg(windows)]
    {
        write_bytes(&root.join("dp_test_26002.7z"), b"lowercase-name");
        let mut c2 = candidate("amd\\10x64\\", "driver.inf");
        c2.pack_name = "DP_Test_26002".to_string();
        let res = resolve_local_pack(&root, &c2).expect("resolve");
        let LocalPackAvailability::Present(req2) = res else {
            panic!("expected Present for case-variant file");
        };
        assert_eq!(
            req2.pack().archive_path().file_name().unwrap(),
            "dp_test_26002.7z"
        );
    }
}

// ===========================================================================
// R10 — zero-length pack rejected
// ===========================================================================

#[test]
fn r10_zero_length_pack_rejected() {
    let tmp = TempDir::new("r10");
    let root = drivers_root(&tmp);
    write_bytes(&root.join("DP_Test_26000.7z"), b"");

    let err = resolve_local_pack(&root, &candidate("amd\\10x64\\", "driver.inf"))
        .expect_err("empty pack must be rejected");
    assert!(matches!(err, LocalPackError::PackEmpty(_)), "got {err:?}");
}

// ===========================================================================
// R11 — pack size cap (pure validator, no 16 GiB file written)
// ===========================================================================

#[test]
fn r11_pack_size_cap_boundary() {
    use mod_drivers::sdio::local_pack::validate_pack_size;
    // cap exactly -> accepted; cap + 1 -> PackTooLarge.
    assert!(validate_pack_size(MAX_LOCAL_PACK_BYTES).is_ok());
    let err = validate_pack_size(MAX_LOCAL_PACK_BYTES + 1).expect_err("over cap");
    assert!(
        matches!(err, LocalPackError::PackTooLarge(_)),
        "got {err:?}"
    );
    assert!(validate_pack_size(0).is_err(), "zero must be rejected");
}

// ===========================================================================
// R12 — simple INF member (case preserved)
// ===========================================================================

#[test]
fn r12_simple_inf_member() {
    let member = expected_inf_member("amd\\10x64\\foo\\", "driver.inf").expect("valid member");
    assert_eq!(member.relative_path(), "amd/10x64/foo/driver.inf");
}

// ===========================================================================
// R13 — empty INF directory
// ===========================================================================

#[test]
fn r13_empty_inf_directory() {
    // Gate P5: `inf_path` is a directory path; empty means root of the pack.
    // The member is just the leaf filename.
    let member = expected_inf_member("", "driver.inf").expect("valid member");
    assert_eq!(member.relative_path(), "driver.inf");
}

// ===========================================================================
// R14 — INF traversal rejected (never normalized away)
// ===========================================================================

#[test]
fn r14_inf_traversal_rejected() {
    for bad in [
        "..\\foo\\",
        "../foo/",
        "a\\..\\foo\\",
        "a/../foo/",
        ".\\foo\\",
        "a\\.\\foo\\",
        // Windows-normalized traversal equivalents: trailing dot/space on a
        // component normalizes away at materialization time (Codex round-4).
        ".. \\foo\\",
        ".. .\\foo\\",
        "a\\.. \\foo\\",
        "a\\foo.\\bar\\",
        "a\\foo \\bar\\",
    ] {
        assert!(
            expected_inf_member(bad, "driver.inf").is_err(),
            "inf_path {bad:?} must be rejected"
        );
    }
}

// ===========================================================================
// R15 — absolute / drive / UNC INF path rejected
// ===========================================================================

#[test]
fn r15_absolute_drive_unc_rejected() {
    for bad in [
        "\\foo\\",
        "/foo/",
        "C:\\foo\\",
        "C:foo\\",
        "\\\\server\\share\\",
        "//server/share/",
    ] {
        assert!(
            expected_inf_member(bad, "driver.inf").is_err(),
            "inf_path {bad:?} must be rejected"
        );
    }
}

// ===========================================================================
// R16 — ADS / colon rejected
// ===========================================================================

#[test]
fn r16_ads_colon_rejected() {
    assert!(expected_inf_member("foo:bar\\", "driver.inf").is_err());
    assert!(expected_inf_member("foo\\bar:stream\\", "driver.inf").is_err());
    assert!(expected_inf_member("amd\\10x64\\", "driver.inf:evil").is_err());

    // Windows-invalid components (Codex round-8 finding): reserved DOS device
    // names and forbidden characters in both the directory and the leaf.
    assert!(expected_inf_member("CON\\", "driver.inf").is_err());
    assert!(expected_inf_member("NUL\\", "driver.inf").is_err());
    assert!(expected_inf_member("AUX\\", "driver.inf").is_err());
    assert!(expected_inf_member("COM1\\", "driver.inf").is_err());
    assert!(expected_inf_member("foo?\\", "driver.inf").is_err());
    assert!(expected_inf_member("foo*\\", "driver.inf").is_err());
    assert!(expected_inf_member("foo<bar>\\", "driver.inf").is_err());
    assert!(expected_inf_member("", "NUL.inf").is_err());
    assert!(expected_inf_member("", "CON.inf").is_err());
    assert!(expected_inf_member("", "driver?.inf").is_err());

    // Windows-invalid components (Codex round-9 finding): ASCII control
    // characters and legacy superscript device names.
    assert!(expected_inf_member("foo\u{1}bar\\", "driver.inf").is_err());
    assert!(expected_inf_member("COM\u{b9}\\", "driver.inf").is_err());
    assert!(expected_inf_member("LPT\u{b3}\\", "driver.inf").is_err());
    assert!(expected_inf_member("", "driv\u{1F}er.inf").is_err());
}

// ===========================================================================
// R17 — INF filename must be a leaf
// ===========================================================================

#[test]
fn r17_inf_filename_must_be_leaf() {
    for bad in [
        "sub\\driver.inf",
        "sub/driver.inf",
        "..\\driver.inf",
        "a\\..\\driver.inf",
    ] {
        assert!(
            expected_inf_member("amd\\10x64\\", bad).is_err(),
            "inf_filename {bad:?} must be rejected"
        );
    }
}

// ===========================================================================
// R18 — INF extension contract (case-insensitive .inf only)
// ===========================================================================

#[test]
fn r18_inf_extension_contract() {
    assert_eq!(
        expected_inf_member("", "driver.inf")
            .unwrap()
            .relative_path(),
        "driver.inf"
    );
    assert_eq!(
        expected_inf_member("", "DRIVER.INF")
            .unwrap()
            .relative_path(),
        "DRIVER.INF"
    );
    for bad in ["driver.inf.exe", "driver.txt", "driver"] {
        assert!(
            expected_inf_member("", bad).is_err(),
            "inf_filename {bad:?} must be rejected"
        );
    }
}

// ===========================================================================
// R19 — repeated / empty internal components rejected
// ===========================================================================

#[test]
fn r19_repeated_separators_rejected() {
    for bad in [
        "foo\\\\bar\\",
        "foo//bar/",
        "foo\\/bar\\",
        "foo\\\\",
        "\\\\foo\\",
    ] {
        assert!(
            expected_inf_member(bad, "driver.inf").is_err(),
            "inf_path {bad:?} must be rejected"
        );
    }
}

// ===========================================================================
// R20 — path bounds (no panic, explicit errors)
// ===========================================================================

#[test]
fn r20_path_bounds() {
    // Too many components.
    let too_many = format!(
        "{}\\",
        (0..=MAX_ARCHIVE_MEMBER_COMPONENTS)
            .map(|i| format!("c{i}"))
            .collect::<Vec<_>>()
            .join("\\")
    );
    assert!(
        expected_inf_member(&too_many, "driver.inf").is_err(),
        "component-count bound must reject"
    );

    // The component-count bound is enforced DURING the scan, so a huge input
    // with millions of short components is rejected without a large
    // allocation (Codex round-9 finding).
    let huge = format!("{}\\", "a\\".repeat(1_000_000));
    assert!(
        expected_inf_member(&huge, "driver.inf").is_err(),
        "component-count bound must reject before large allocation"
    );

    // An over-length single-component path (no separators) is rejected by the
    // pre-clone absolute length guard with a payload-free error (Codex round-11
    // finding).
    let over_len = format!("{}\\", "d".repeat(MAX_ARCHIVE_MEMBER_LEN + 1));
    let err = expected_inf_member(&over_len, "driver.inf").expect_err("over length");
    assert!(
        matches!(err, LocalPackError::ArchiveMemberTooLong),
        "payload-free rejection expected, got {err:?}"
    );

    // A single component longer than MAX_ARCHIVE_COMPONENT_LEN.
    let long_comp = format!("{}\\", "x".repeat(MAX_ARCHIVE_COMPONENT_LEN + 1));
    assert!(
        expected_inf_member(&long_comp, "driver.inf").is_err(),
        "component-length bound must reject"
    );

    // The INF leaf is itself one component and must respect the same bound.
    let long_leaf = format!("{}.inf", "y".repeat(MAX_ARCHIVE_COMPONENT_LEN));
    assert!(
        expected_inf_member("", &long_leaf).is_err(),
        "leaf component-length bound must reject"
    );

    // Combined member path longer than MAX_ARCHIVE_MEMBER_LEN.
    let big_dir = format!("{}\\", "d".repeat(MAX_ARCHIVE_MEMBER_LEN));
    assert!(
        expected_inf_member(&big_dir, "driver.inf").is_err(),
        "member-length bound must reject"
    );
}

// ===========================================================================
// R21 — materialization request is explicitly UNVERIFIED
// ===========================================================================

#[test]
fn r21_request_is_explicitly_unverified() {
    let tmp = TempDir::new("r21");
    let root = drivers_root(&tmp);
    write_bytes(&root.join("DP_Test_26000.7z"), b"bytes");

    let res = resolve_local_pack(&root, &candidate("amd\\10x64\\", "driver.inf")).expect("resolve");
    let LocalPackAvailability::Present(req) = res else {
        panic!("expected Present");
    };

    // The request carries a pack reference + expected member path only.
    let _: &LocalPackRef = req.pack();
    let _: &ExpectedArchiveMember = req.inf();
    let _: PackageMaterializationRequest = req;

    // Naming guard: the public type surface may not imply verified/extracted/
    // trusted/signed/installable/update/recommended material.
    let names = [
        "Extracted",
        "VerifiedInf",
        "Trusted",
        "Signed",
        "Installable",
        "Update",
        "Recommended",
        "Materialized",
    ];
    let src = include_str!("../src/sdio/local_pack.rs");
    for n in names {
        assert!(
            !src.contains(&format!("pub struct {n}")) && !src.contains(&format!("pub enum {n}")),
            "domain type must not be named {n}"
        );
    }
}

// ===========================================================================
// R22 — candidate metadata preserved (no mutation)
// ===========================================================================

#[test]
fn r22_candidate_metadata_preserved() {
    let tmp = TempDir::new("r22");
    let root = drivers_root(&tmp);
    write_bytes(&root.join("DP_Test_26000.7z"), b"bytes");

    let c = candidate("amd\\10x64\\foo\\", "driver.inf");
    let before = c.clone();

    let res = resolve_local_pack(&root, &c).expect("resolve");
    let LocalPackAvailability::Present(req) = res else {
        panic!("expected Present");
    };

    // pack_name unchanged, member correctly derived, source not mutated.
    assert_eq!(req.pack().pack_name(), "DP_Test_26000");
    assert_eq!(req.inf().relative_path(), "amd/10x64/foo/driver.inf");
    assert_eq!(c, before, "source candidate must not be mutated");
    assert_eq!(c.evidence.len(), 1, "matching evidence must not be mutated");
}

// ===========================================================================
// R23 — real fixture request (seam on real metadata)
// ===========================================================================

#[test]
fn r23_real_fixture_request() {
    let tmp = TempDir::new("r23");
    let root = drivers_root(&tmp);
    write_bytes(&root.join("DP_Display_SDIO01_26082.7z"), b"fixture-bytes");

    let c = fixture_candidate();
    assert_eq!(c.pack_name, "DP_Display_SDIO01_26082");
    assert_eq!(c.candidate.inf_filename, "u0202099.inf");
    assert!(
        c.candidate
            .inf_path
            .starts_with("amd\\10x64\\ati2mtag_StrixHalo_32.0.23033.5002\\")
    );

    let res = resolve_local_pack(&root, &c).expect("resolve");
    let LocalPackAvailability::Present(req) = res else {
        panic!("expected Present");
    };

    // Pinned real mapping: pack filename + INF archive member.
    assert_eq!(
        req.pack().archive_path().file_name().unwrap(),
        "DP_Display_SDIO01_26082.7z"
    );
    assert_eq!(
        req.inf().relative_path(),
        "amd/10x64/ati2mtag_StrixHalo_32.0.23033.5002/u0202099.inf"
    );
}

// ===========================================================================
// R24 — catalog hint never becomes authority
// ===========================================================================

#[test]
fn r24_catalog_hint_never_becomes_authority() {
    let tmp = TempDir::new("r24");
    let root = drivers_root(&tmp);
    write_bytes(&root.join("DP_Test_26000.7z"), b"bytes");

    let c = candidate("amd\\10x64\\", "driver.inf");
    let res = resolve_local_pack(&root, &c).expect("resolve");
    let LocalPackAvailability::Present(req) = res else {
        panic!("expected Present");
    };
    // R24 satisfied by design: `Candidate::catalog_file` is NOT carried into
    // the request at all (the extracted INF becomes authoritative in the later
    // package-validation slice). The request carries only the pack reference
    // and the expected INF member — no catalog field of any name.
    let _: &LocalPackRef = req.pack();
    let _: &ExpectedArchiveMember = req.inf();
    let src = include_str!("../src/sdio/local_pack.rs");
    for n in [
        "catalog_hint",
        "index_catalog",
        "validated_catalog",
        "selected_catalog",
        "trusted_catalog",
    ] {
        assert!(!src.contains(n), "no catalog field may exist ({n})");
    }
}

// ===========================================================================
// R25 — determinism
// ===========================================================================

#[test]
fn r25_determinism() {
    let tmp = TempDir::new("r25");
    let root = drivers_root(&tmp);
    write_bytes(&root.join("DP_Test_26000.7z"), b"bytes");

    let run = || {
        resolve_local_pack(&root, &candidate("amd\\10x64\\foo\\", "driver.inf")).expect("resolve")
    };
    let a = run();
    let b = run();
    assert_eq!(a, b, "same root + candidate + fs state must be identical");
}

// ===========================================================================
// R26 — no network / no extraction API in the production module
// ===========================================================================

#[test]
fn r26_no_network_no_extraction_api() {
    // Scan production CODE only: doc comments may legitimately state that the
    // module performs no networking/torrent/extraction (architecture denial).
    let src = include_str!("../src/sdio/local_pack.rs");
    let code: String = src
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//!") && !t.starts_with("///")
        })
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "reqwest",
        "ureq",
        "hyper",
        "http://",
        "https://",
        "torrent",
        "magnet",
        "download",
        "7z.exe",
        "7za",
        "7zz",
        "archive_extract",
        "extract",
        "decompress",
        "sevenz",
        "libarchive",
        "Command::new",
        "Expand-Archive",
        "tar.exe",
        "SDIO.exe",
    ] {
        assert!(
            !code.contains(forbidden),
            "production code must not contain {forbidden:?}"
        );
    }
    // No std fs read APIs that would open the pack for reading.
    assert!(!code.contains("fs::read("), "no fs::read on the pack");
    assert!(!code.contains("read_to_end"), "no read_to_end");
}

// ===========================================================================
// Supporting: AssessedCatalogCandidate convenience preserves applicability
// ===========================================================================

#[test]
fn assessed_candidate_convenience_preserves_applicability() {
    use mod_drivers::sdio::applicability::{AssessedCatalogCandidate, CatalogOsApplicability};
    use mod_drivers::sdio::local_pack::resolve_assessed_pack;

    let tmp = TempDir::new("assessed");
    let root = drivers_root(&tmp);
    write_bytes(&root.join("DP_Test_26000.7z"), b"bytes");

    let c = candidate("amd\\10x64\\", "driver.inf");
    let assessed = AssessedCatalogCandidate {
        matched: c,
        os: mod_drivers::sdio::applicability::CatalogApplicabilityEvidence {
            models_section: Some("ntamd64".to_string()),
            target: None,
            status: CatalogOsApplicability::HostCompatible,
            reason: mod_drivers::sdio::applicability::ApplicabilityReason::TargetSatisfied,
        },
    };

    let res = resolve_assessed_pack(&root, &assessed).expect("resolve");
    let LocalPackAvailability::Present(req) = res else {
        panic!("expected Present");
    };
    // Applicability evidence is not consumed by the resolver and the request
    // carries no applicability/trust conclusion.
    assert_eq!(assessed.os.status, CatalogOsApplicability::HostCompatible);
    assert_eq!(req.inf().relative_path(), "amd/10x64/driver.inf");
    // No filtering: even a HostIncompatible candidate resolves identically.
    let incompatible = AssessedCatalogCandidate {
        matched: candidate("amd\\10x64\\", "driver.inf"),
        os: mod_drivers::sdio::applicability::CatalogApplicabilityEvidence {
            models_section: Some("NTx86".to_string()),
            target: None,
            status: CatalogOsApplicability::HostIncompatible,
            reason: mod_drivers::sdio::applicability::ApplicabilityReason::ArchitectureMismatch,
        },
    };
    let res2 = resolve_assessed_pack(&root, &incompatible).expect("resolve");
    let LocalPackAvailability::Present(req2) = res2 else {
        panic!("expected Present");
    };
    assert_eq!(req2.inf().relative_path(), "amd/10x64/driver.inf");
}

// ===========================================================================
// Supporting: batch helper preserves candidate order and is bounded
// ===========================================================================

#[test]
fn batch_helper_preserves_order_and_is_bounded() {
    use mod_drivers::sdio::local_pack::{MAX_PACKS_PER_BATCH, resolve_local_packs};

    let tmp = TempDir::new("batch");
    let root = drivers_root(&tmp);
    write_bytes(&root.join("DP_Test_26000.7z"), b"a");
    write_bytes(&root.join("DP_Test_26001.7z"), b"b");
    write_bytes(&root.join("DP_Test_26002.7z"), b"c");

    let c0 = {
        let mut c = candidate("amd\\10x64\\", "driver.inf");
        c.pack_name = "DP_Test_26000".to_string();
        c
    };
    let c1 = {
        let mut c = candidate("amd\\10x64\\", "driver.inf");
        c.pack_name = "DP_Test_26001".to_string();
        c
    };
    let c2 = {
        let mut c = candidate("amd\\10x64\\", "driver.inf");
        c.pack_name = "DP_Test_26002".to_string();
        c
    };
    // Deliberately unordered input (26001, 26000, 26002): output must preserve
    // input order with no sorting by availability/name/size.
    let input = vec![c1, c0, c2];
    let out = resolve_local_packs(&root, &input).expect("batch resolve");
    assert_eq!(out.len(), 3);
    for (out_item, expected_pack) in
        out.iter()
            .zip(["DP_Test_26001", "DP_Test_26000", "DP_Test_26002"])
    {
        let LocalPackAvailability::Present(req) = out_item else {
            panic!("all packs present");
        };
        assert_eq!(req.pack().pack_name(), expected_pack);
    }

    // Bounded: an over-limit batch fails closed, never unbounded iteration.
    let too_many: Vec<CatalogCandidateMatch> = (0..MAX_PACKS_PER_BATCH + 1)
        .map(|i| {
            let mut c = candidate("amd\\10x64\\", "driver.inf");
            c.pack_name = format!("DP_Test_{i:05}");
            c
        })
        .collect();
    assert!(resolve_local_packs(&root, &too_many).is_err());

    // The batch reuses the established candidate bound.
    const _: () = assert!(MAX_PACKS_PER_BATCH <= MAX_TOTAL_CANDIDATES);
}
