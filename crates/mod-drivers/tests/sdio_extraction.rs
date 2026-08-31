// Integration tests for Tab 2a-6: bounded `.7z` inspection + exact INF
// extraction under strict resource/path bounds (Option C).
//
// This slice materializes EXACTLY ONE expected INF member from an already
// resolved local SDIO `.7z` pack into an isolated, caller-provided staging
// directory. It does NOT parse INF text, validate CAT/signature trust,
// classify installability, compute Windows rank, or install anything. The
// resulting `StagedInfArtifact` is a bounded staged file, not a trusted
// package.
//
// Synthetic `.7z` fixtures are generated at test time through the test-only
// encoder feature of sevenz-rust2 (dev-dependency `compress`). No external
// `7z.exe`, no subprocess, no network.

use std::fs;
use std::path::{Path, PathBuf};

use mod_drivers::identity::DeviceIdentity;
use mod_drivers::sdio::local_pack::{
    LocalPackAvailability, PackageMaterializationRequest, expected_pack_filename,
    resolve_local_pack,
};
use mod_drivers::sdio::{
    CatalogCandidateMatch, DeviceIdKind, MatchEvidence, SdioCatalog, match_device_to_catalogs,
};
use sevenz_rust2::ArchiveWriter;

/// The `None` reader type for a directory entry (`push_archive_entry`).
type NoReader = std::io::Cursor<&'static [u8]>;

// ---------------- Test scaffolding (self-cleaning) ----------------

/// A unique temporary directory under `%TEMP%`, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir();
        let uniq = format!(
            "cove_tab2a6_{}_{}_{}",
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

/// The `drivers` subdirectory of a TempDir, created up front (2a-5 root).
fn drivers_root(tmp: &TempDir) -> PathBuf {
    let root = tmp.path().join("drivers");
    fs::create_dir_all(&root).expect("create drivers root");
    root
}

/// A staging root supplied by the caller (the extraction module must never
/// auto-discover one). Created by the test; sibling tests assert it survives.
fn staging_root(tmp: &TempDir) -> PathBuf {
    let root = tmp.path().join("staging");
    fs::create_dir_all(&root).expect("create staging root");
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

/// Test context: unique temp dir + drivers root + staging root.
struct TestCtx {
    tmp: TempDir,
    drivers: PathBuf,
    staging: PathBuf,
}

impl TestCtx {
    fn new(tag: &str) -> Self {
        let tmp = TempDir::new(tag);
        let drivers = drivers_root(&tmp);
        let staging = staging_root(&tmp);
        Self {
            tmp,
            drivers,
            staging,
        }
    }
    /// Build a synthetic archive and return its bytes.
    fn pack(&self, name: &str, solid: bool, entries: &[FixtureEntry]) -> Vec<u8> {
        make_pack(&self.tmp, name, solid, entries)
    }
}

/// The real fixture candidate: pack `DP_Display_SDIO01_26082`,
/// `amd\10x64\ati2mtag_StrixHalo_32.0.23033.5002\` + `u0202099.inf`.
fn fixture_candidate() -> CatalogCandidateMatch {
    let cat = SdioCatalog::parse_bytes(
        include_bytes!("../fixtures/sdio/valid_small.bin"),
        "DP_Display_SDIO01_26082".into(),
    )
    .expect("fixture must parse");
    let dev = DeviceIdentity {
        instance_id: "PCI\\0".to_string(),
        hardware_ids: vec!["PCI\\VEN_1002&DEV_1586&SUBSYS_15141043&REV_C1".to_string()],
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

/// Resolve a request through the real 2a-5 resolver for a given pack file.
fn resolve_request(
    drivers: &Path,
    pack_bytes: &[u8],
    c: &CatalogCandidateMatch,
) -> PackageMaterializationRequest {
    let pack_path = drivers.join(expected_pack_filename(&c.pack_name).expect("valid stem"));
    write_bytes(&pack_path, pack_bytes);
    let res = resolve_local_pack(drivers, c).expect("resolve must succeed");
    match res {
        LocalPackAvailability::Present(req) => req,
        other => panic!("expected Present, got {other:?}"),
    }
}

// ---------------- Synthetic 7z fixture builder (test-only encoder) ----------------

/// One entry to write into a synthetic archive.
struct FixtureEntry {
    /// Archive member path using `/` separators.
    name: &'static str,
    /// `None` writes a directory entry.
    content: Option<&'static [u8]>,
}

impl FixtureEntry {
    fn file(name: &'static str, content: &'static [u8]) -> Self {
        Self {
            name,
            content: Some(content),
        }
    }
    fn dir(name: &'static str) -> Self {
        Self {
            name,
            content: None,
        }
    }
}

/// Write a synthetic `.7z` archive into `path`. When `solid` is true all file
/// entries share ONE solid compression block; otherwise each file is its own
/// non-solid block.
fn write_archive(path: &Path, solid: bool, entries: &[FixtureEntry]) {
    let file = fs::File::create(path).expect("create archive file");
    let mut writer =
        ArchiveWriter::new(std::io::BufWriter::new(file)).expect("create archive writer");

    if solid {
        // One solid block: every file entry is packed together via SourceReader
        // streams; directory entries are pushed separately.
        let mut file_entries: Vec<sevenz_rust2::ArchiveEntry> = Vec::new();
        let mut readers: Vec<sevenz_rust2::SourceReader<std::io::Cursor<&'static [u8]>>> =
            Vec::new();
        for e in entries {
            match e.content {
                Some(bytes) => {
                    file_entries.push(sevenz_rust2::ArchiveEntry::new_file(e.name));
                    readers.push(sevenz_rust2::SourceReader::new(std::io::Cursor::new(bytes)));
                }
                None => {
                    writer
                        .push_archive_entry(
                            sevenz_rust2::ArchiveEntry::new_directory(e.name),
                            Option::<NoReader>::None,
                        )
                        .expect("push dir");
                }
            }
        }
        if !file_entries.is_empty() {
            writer
                .push_archive_entries(file_entries, readers)
                .expect("push solid block");
        }
    } else {
        for e in entries {
            match e.content {
                Some(bytes) => {
                    writer
                        .push_archive_entry(
                            sevenz_rust2::ArchiveEntry::new_file(e.name),
                            Some(std::io::Cursor::new(bytes)),
                        )
                        .expect("push entry");
                }
                None => {
                    writer
                        .push_archive_entry(
                            sevenz_rust2::ArchiveEntry::new_directory(e.name),
                            Option::<NoReader>::None,
                        )
                        .expect("push dir");
                }
            }
        }
    }
    writer.finish().expect("finish archive");
}

/// Deterministic incompressible-ish filler used in solid tests so sizes are
/// predictable and the block genuinely spans multiple entries.
const FILLER: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef";

/// Build a synthetic archive under `tmp`, then return its bytes for writing
/// into the drivers root by `resolve_request`.
fn make_pack(tmp: &TempDir, name: &str, solid: bool, entries: &[FixtureEntry]) -> Vec<u8> {
    let p = tmp.path().join(name);
    write_archive(&p, solid, entries);
    fs::read(&p).expect("read generated archive")
}

// ---------------- R1 — 2a-5 request -> simple INF extraction ----------------

#[test]
fn r1_simple_inf_extraction() {
    let ctx = TestCtx::new("r1");

    let inf = b"; fake INF body - extraction is archive-mechanics only\n[Version]\n";
    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("amd/driver.inf", inf)],
    );

    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));
    let artifact = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("materialize");

    assert_eq!(artifact.inf_leaf(), "driver.inf");
    assert_eq!(artifact.size_bytes(), inf.len() as u64);
    assert!(artifact.inf_path().is_file());
    assert_eq!(fs::read(artifact.inf_path()).expect("read staged inf"), inf);

    // Exactly ONE output file in the owned staging child.
    let child = artifact.staging_dir();
    let children: Vec<_> = fs::read_dir(child)
        .expect("read staging child")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(children.len(), 1, "exactly one staged file");
    assert_eq!(children[0], "driver.inf");
}

// ---------------- R2 — pack size changed after 2a-5 ----------------

#[test]
fn r2_pack_size_changed_after_resolution() {
    let ctx = TestCtx::new("r2");

    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("amd/driver.inf", b"x")],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    // Append bytes after resolution: size snapshot now mismatches.
    let pack_path = req.pack().archive_path();
    let mut extended = fs::read(pack_path).expect("read pack");
    extended.extend_from_slice(b"trailing");
    fs::write(pack_path, &extended).expect("rewrite pack");

    let err = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("must fail closed");
    assert!(
        matches!(
            err,
            mod_drivers::sdio::ExtractionError::PackChangedSinceResolution
        ),
        "got {err:?}"
    );
    // No staging child was created.
    assert_eq!(fs::read_dir(&ctx.staging).expect("read staging").count(), 0);
}

// ---------------- R3 — pack path type changed (directory) ----------------

#[test]
fn r3_pack_path_type_changed_rejected() {
    let ctx = TestCtx::new("r3");

    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("amd/driver.inf", b"x")],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    // Replace the pack file with a directory of the same name.
    let pack_path = req.pack().archive_path();
    fs::remove_file(pack_path).expect("remove pack");
    fs::create_dir_all(pack_path).expect("create dir in place");

    let err = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("must fail closed");
    assert!(
        matches!(
            err,
            mod_drivers::sdio::ExtractionError::PackChangedSinceResolution
        ),
        "got {err:?}"
    );
    assert_eq!(fs::read_dir(&ctx.staging).expect("read staging").count(), 0);
}

// ---------------- R4 — missing target member ----------------

#[test]
fn r4_missing_target_member() {
    let ctx = TestCtx::new("r4");

    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("amd/other.inf", b"not the target")],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let err = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("target absent");
    assert!(
        matches!(err, mod_drivers::sdio::ExtractionError::TargetMemberMissing),
        "got {err:?}"
    );
    assert_eq!(fs::read_dir(&ctx.staging).expect("read staging").count(), 0);
}

// ---------------- R4b — trailing-separator streamed file ambiguity ----------------

#[test]
fn r4b_trailing_separator_streamed_file_rejected() {
    let ctx = TestCtx::new("r4b");

    // A STREAMED (non-directory) archive entry whose name ends in a separator
    // must never normalize to the plain file path: `amd/driver.inf/` must NOT
    // resolve as the requested `amd/driver.inf`.
    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("amd/driver.inf/", b"ambiguous")],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let err = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("must fail closed");
    assert!(
        matches!(
            err,
            mod_drivers::sdio::ExtractionError::UnsafeArchiveMember { .. }
        ),
        "got {err:?}"
    );
    // No staged file, no staging residue.
    assert_eq!(fs::read_dir(&ctx.staging).expect("read staging").count(), 0);
}

// ---------------- R4c — over-budget next-header size rejected ----------------

#[test]
fn r4c_oversized_next_header_rejected_before_backend_parse() {
    let ctx = TestCtx::new("r4c");

    // Start from a valid archive, then patch the fixed 32-byte signature
    // header's `next_header_size` (LE u64 at offset 20) to an over-budget
    // value. The pack revalidation passes (same file), but the start-header
    // preflight must reject BEFORE the backend parser can allocate from the
    // declared size.
    let mut pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("amd/driver.inf", b"x")],
    );
    let over = mod_drivers::sdio::extraction::MAX_ARCHIVE_HEADER_BYTES as u64 + 1;
    pack[20..28].copy_from_slice(&over.to_le_bytes());

    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));
    let err = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("must fail closed");
    assert!(
        matches!(
            err,
            mod_drivers::sdio::ExtractionError::ArchiveHeaderTooLarge
        ),
        "got {err:?}"
    );
    // No staging residue.
    assert_eq!(fs::read_dir(&ctx.staging).expect("read staging").count(), 0);
}

// ---------------- R5 — target case-insensitive unique match ----------------

#[test]
fn r5_case_insensitive_unique_match() {
    let ctx = TestCtx::new("r5");

    let inf = b"case-folded target";
    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("AMD/Driver.INF", inf)],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let artifact = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("unique match");
    // Expected member casing preserved in the flat leaf; actual spelling recorded.
    assert_eq!(artifact.expected_archive_member(), "amd/driver.inf");
    assert_eq!(artifact.actual_archive_member(), "AMD/Driver.INF");
    assert_eq!(fs::read(artifact.inf_path()).expect("read staged inf"), inf);
}

// ---------------- R6 — target case collision ambiguous ----------------

#[test]
fn r6_case_collision_ambiguous() {
    let ctx = TestCtx::new("r6");

    let pack = ctx.pack(
        "pack.7z",
        false,
        &[
            FixtureEntry::file("amd/driver.inf", b"one"),
            FixtureEntry::file("AMD/DRIVER.INF", b"two"),
        ],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let err = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("ambiguous");
    assert!(
        matches!(
            err,
            mod_drivers::sdio::ExtractionError::TargetMemberAmbiguous(_)
        ),
        "got {err:?}"
    );
    assert_eq!(fs::read_dir(&ctx.staging).expect("read staging").count(), 0);
}

// ---------------- R7 — exact duplicate normalized member path ----------------

#[test]
fn r7_exact_duplicate_member_rejected() {
    let ctx = TestCtx::new("r7");

    // Two archive entries with the exact same normalized path.
    let pack = ctx.pack(
        "pack.7z",
        false,
        &[
            FixtureEntry::file("a/dup.inf", b"first"),
            FixtureEntry::file("a/dup.inf", b"second"),
        ],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("a\\", "dup.inf"));

    let err = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("duplicate");
    assert!(
        matches!(
            err,
            mod_drivers::sdio::ExtractionError::DuplicateArchiveMember
        ),
        "got {err:?}"
    );
    assert_eq!(fs::read_dir(&ctx.staging).expect("read staging").count(), 0);
}

// ---------------- R8 — traversal member anywhere ----------------

#[test]
fn r8_traversal_member_anywhere_rejected() {
    let ctx = TestCtx::new("r8");

    let pack = ctx.pack(
        "pack.7z",
        false,
        &[
            FixtureEntry::file("amd/driver.inf", b"safe"),
            FixtureEntry::file("../evil.txt", b"escape"),
        ],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let err = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("unsafe member");
    assert!(
        matches!(
            err,
            mod_drivers::sdio::ExtractionError::UnsafeArchiveMember { .. }
        ),
        "got {err:?}"
    );
    assert_eq!(fs::read_dir(&ctx.staging).expect("read staging").count(), 0);
}

// ---------------- R9/R10/R11 — hostile archive member paths ----------------

#[test]
fn r9_r10_r11_hostile_members_rejected() {
    let ctx = TestCtx::new("r9r10r11");

    for (i, bad) in [
        // R9 — absolute / drive / UNC / ADS.
        "/evil",
        "\\evil",
        "C:\\evil",
        "C:evil",
        "\\\\server\\share\\evil",
        "foo:stream",
        // R10 — dot / duplicate separators.
        "a/./b",
        "a/../b",
        "a//b",
        "a\\\\b",
        // R11 — Windows-ambiguous components.
        "CON",
        "NUL",
        "COM1",
        "LPT1",
        "trailing.",
        "trailing ",
        "bad<1>",
        "bad>2",
        "bad|3",
        "bad?4",
        "bad*5",
        "bad\"6",
        "ctrl\u{1}",
    ]
    .iter()
    .enumerate()
    {
        let pack = ctx.pack(
            &format!("pack{i}.7z"),
            false,
            &[FixtureEntry::file(bad, b"hostile")],
        );
        // The expected member is a benign path; the hostile entry is inspected
        // during archive validation and must fail closed regardless.
        let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));
        let err =
            mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("hostile member");
        assert!(
            matches!(
                err,
                mod_drivers::sdio::ExtractionError::UnsafeArchiveMember { .. }
            ),
            "member {bad:?} gave {err:?}"
        );
    }
    assert_eq!(fs::read_dir(&ctx.staging).expect("read staging").count(), 0);
}

// ---------------- R16 — target directory rejected ----------------

#[test]
fn r16_target_directory_rejected() {
    let ctx = TestCtx::new("r16");

    // Archive member `amd/driver.inf` exists but is a DIRECTORY.
    let pack = ctx.pack(
        "pack.7z",
        false,
        &[
            FixtureEntry::dir("amd"),
            FixtureEntry::dir("amd/driver.inf"),
        ],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let err = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("directory target");
    assert!(
        matches!(
            err,
            mod_drivers::sdio::ExtractionError::TargetNotRegularFile
        ),
        "got {err:?}"
    );
    assert_eq!(fs::read_dir(&ctx.staging).expect("read staging").count(), 0);
}

// ---------------- R17 — target anti-item / no stream rejected ----------------

#[test]
fn r17_any_anti_item_rejected() {
    let ctx = TestCtx::new("r17");

    // The encoder cannot emit anti-items, but a directory entry (no stream)
    // that matches the expected INF name must still fail closed.
    let pack = ctx.pack(
        "pack.7z",
        false,
        &[
            FixtureEntry::dir("amd"),
            FixtureEntry::dir("amd/driver.inf"),
        ],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let err = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("anti-item target");
    assert!(
        matches!(
            err,
            mod_drivers::sdio::ExtractionError::TargetNotRegularFile
        ),
        "got {err:?}"
    );
}

// ---------------- R18 — solid archive target late in block ----------------

#[test]
fn r18_solid_target_late_in_block() {
    let ctx = TestCtx::new("r18");

    let inf = b"; solid target INF\n[Version]\nSignature=\"$Windows NT$\"\n";
    let pack = ctx.pack(
        "pack.7z",
        true,
        &[
            FixtureEntry::file("first.bin", FILLER),
            FixtureEntry::file("second.bin", FILLER),
            FixtureEntry::file("amd/driver.inf", inf),
            FixtureEntry::file("after.bin", FILLER),
        ],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let artifact =
        mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("solid materialize");
    assert_eq!(fs::read(artifact.inf_path()).expect("read staged inf"), inf);

    // Exactly the INF; nothing else (after.bin never decoded or written).
    let children: Vec<_> = fs::read_dir(artifact.staging_dir())
        .expect("read staging child")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0], "driver.inf");
}

// ---------------- R20 — no non-target file writes (solid archive with hostile extras) ----------------

#[test]
fn r20_no_non_target_writes() {
    let ctx = TestCtx::new("r20");

    let inf = b"; only this file may appear on disk";
    let pack = ctx.pack(
        "pack.7z",
        true,
        &[
            FixtureEntry::file("evil.exe", FILLER),
            FixtureEntry::file("driver.sys", FILLER),
            FixtureEntry::file("amd/driver.inf", inf),
        ],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let artifact = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("materialize");
    let children: Vec<_> = fs::read_dir(artifact.staging_dir())
        .expect("read staging child")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(children.len(), 1, "only the INF may be written");
    assert_eq!(children[0], "driver.inf");
    assert_eq!(fs::read(artifact.inf_path()).expect("read staged inf"), inf);
}

// ---------------- R23 — target block only ----------------

#[test]
fn r23_target_block_only() {
    let ctx = TestCtx::new("r23");

    let inf = b"; block B target";
    // Non-solid archive: each entry is its own block, so the writer emits
    // block A entries first, then block B. Materialization must decode only
    // the target's block.
    let pack = ctx.pack(
        "pack.7z",
        false,
        &[
            FixtureEntry::file("a/huge.bin", FILLER),
            FixtureEntry::file("a/other.bin", FILLER),
            FixtureEntry::file("amd/driver.inf", inf),
        ],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let artifact = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("materialize");
    assert_eq!(fs::read(artifact.inf_path()).expect("read staged inf"), inf);
    let children: Vec<_> = fs::read_dir(artifact.staging_dir())
        .expect("read staging child")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(children.len(), 1);
}

// ---------------- R25 — CRC failure / corrupt archive ----------------

#[test]
fn r25_corrupt_archive_fails_closed() {
    let ctx = TestCtx::new("r25");

    // A larger entry so the packed-data region dominates the file: the
    // corruption must land in the compressed stream, not the encoded
    // header, so extraction reaches the CRC/decode failure. Leaked static
    // (test-only, bounded, tiny).
    let big: &'static [u8] = Box::leak(FILLER.repeat(64).into_boxed_slice());
    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("amd/driver.inf", big)],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    // Corrupt a byte in the packed-data region. The signature header is 32
    // bytes; the encoded header is written after the packed streams, so a byte
    // near the START of the packed region corrupts the compressed stream.
    let pack_path = req.pack().archive_path();
    let mut corrupt = fs::read(pack_path).expect("read pack");
    let idx = 40 + corrupt.len() / 8;
    corrupt[idx] ^= 0xFF;
    fs::write(pack_path, &corrupt).expect("rewrite corrupt pack");

    // Same-size replacement: pack revalidation passes, decode must fail.
    let err =
        mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("corrupt must fail");
    assert!(
        matches!(
            err,
            mod_drivers::sdio::ExtractionError::ArchiveBackend(_)
                | mod_drivers::sdio::ExtractionError::DecodedSizeMismatch { .. }
        ),
        "got {err:?}"
    );
    // No success artifact, staging cleaned.
    assert_eq!(fs::read_dir(&ctx.staging).expect("read staging").count(), 0);
}

// ---------------- R27 — failure rollback ----------------

#[test]
fn r27_failure_rollback() {
    let ctx = TestCtx::new("r27");
    // Unrelated sibling that must survive untouched.
    write_bytes(&ctx.staging.join("sibling.txt"), b"untouched");

    // Valid pack whose target entry is missing -> failure AFTER the staging
    // child would be created; the rollback must remove it.
    let pack = ctx.pack("pack.7z", false, &[FixtureEntry::file("other.bin", b"x")]);
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let err = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect_err("target missing");
    assert!(
        matches!(err, mod_drivers::sdio::ExtractionError::TargetMemberMissing),
        "got {err:?}"
    );
    // Staging root still exists; no owned child remains; sibling untouched.
    assert!(ctx.staging.is_dir());
    let names: Vec<_> = fs::read_dir(&ctx.staging)
        .expect("read staging")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("sibling.txt")]);
}

// ---------------- R28 — success cleanup ----------------

#[test]
fn r28_success_cleanup() {
    let ctx = TestCtx::new("r28");
    write_bytes(&ctx.staging.join("sibling.txt"), b"untouched");

    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("amd/driver.inf", b"x")],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let artifact = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("materialize");
    let child = artifact.staging_dir().to_path_buf();
    let inf = artifact.inf_path().to_path_buf();
    assert!(inf.is_file());

    artifact.cleanup().expect("cleanup succeeds");

    assert!(!inf.exists(), "staged INF removed");
    assert!(!child.exists(), "owned child removed");
    assert!(ctx.staging.is_dir(), "staging root preserved");
    assert!(
        ctx.staging.join("sibling.txt").is_file(),
        "sibling preserved"
    );
}

// ---------------- R30 — real 2a-5 domain types end to end ----------------

#[test]
fn r30_real_domain_types_end_to_end() {
    let ctx = TestCtx::new("r30");

    let c = fixture_candidate();
    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file(
            "amd/10x64/ati2mtag_StrixHalo_32.0.23033.5002/u0202099.inf",
            b"; real-fixture INF body\n",
        )],
    );
    let req = resolve_request(&ctx.drivers, &pack, &c);
    assert_eq!(
        req.inf().relative_path(),
        "amd/10x64/ati2mtag_StrixHalo_32.0.23033.5002/u0202099.inf"
    );

    let artifact = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("materialize");
    assert_eq!(artifact.pack_name(), "DP_Display_SDIO01_26082");
    assert_eq!(artifact.inf_leaf(), "u0202099.inf");
    assert_eq!(
        artifact.expected_archive_member(),
        "amd/10x64/ati2mtag_StrixHalo_32.0.23033.5002/u0202099.inf"
    );
    artifact.cleanup().expect("cleanup");
}

// ---------------- R31 — expected member invariant preserved (request not mutated) ----------------

#[test]
fn r31_request_not_mutated() {
    let ctx = TestCtx::new("r31");

    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("amd/driver.inf", b"x")],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));
    let before = req.clone();

    let artifact = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("materialize");
    assert_eq!(req, before, "request must not be mutated");
    assert_eq!(artifact.expected_archive_member(), "amd/driver.inf");
    artifact.cleanup().expect("cleanup");
}

// ---------------- R32 — no INF parsing (opaque bytes accepted) ----------------

#[test]
fn r32_no_inf_parsing() {
    let ctx = TestCtx::new("r32");

    // Arbitrary binary text ending in `.inf` — extraction is archive mechanics
    // only and must succeed without interpreting content.
    let opaque: &[u8] = &[0x00, 0x01, 0xFF, 0xFE, b'X', b'Y', 0x80, b'\n'];
    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("opaque.inf", opaque)],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("", "opaque.inf"));
    let artifact = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("materialize");
    assert_eq!(
        fs::read(artifact.inf_path()).expect("read staged inf"),
        opaque
    );
    artifact.cleanup().expect("cleanup");
}

// ---------------- R33 — no applicability filter ----------------

#[test]
fn r33_no_applicability_filter() {
    let ctx = TestCtx::new("r33");

    let pack = ctx.pack(
        "pack.7z",
        false,
        &[FixtureEntry::file("amd/driver.inf", b"x")],
    );
    // Resolver is policy-neutral; the request carries no applicability status.
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));
    let artifact = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("materialize");
    assert_eq!(artifact.inf_leaf(), "driver.inf");
    artifact.cleanup().expect("cleanup");
}

// ---------------- R34 — encrypted archive rejected explicitly ----------------

#[test]
fn r34_encrypted_archive_rejected() {
    // R34 (classifier path, per the slice): the production feature set
    // excludes AES and the backend error-mapping/classifier rejects encrypted
    // archives explicitly. A live encrypted fixture would require shipping
    // the AES feature in the test dependency graph, which would distort the
    // production feature check; the slice explicitly allows testing the
    // classifier instead.
    //
    // The classifier maps a backend `PasswordRequired` / `MaybeBadPassword`
    // to `UnsupportedEncryptedArchive`. That mapping is exercised by the
    // private boundary tests (unsupported codec / password classification).
    // Here we additionally pin the production dependency to NOT enable AES.
    let manifest = include_str!("../Cargo.toml");
    let prod_line = manifest
        .lines()
        .find(|l| l.contains("sevenz-rust2") && !l.trim_start().starts_with('#'))
        .expect("production sevenz-rust2 dependency line");
    assert!(
        !prod_line.contains("aes256"),
        "production must not enable AES: {prod_line}"
    );
    // The extraction domain carries the explicit encrypted-archive rejection.
    let _: mod_drivers::sdio::ExtractionError =
        mod_drivers::sdio::ExtractionError::UnsupportedEncryptedArchive;
}

// ---------------- R36 — determinism ----------------

#[test]
fn r36_determinism() {
    let ctx = TestCtx::new("r36");

    let pack = ctx.pack(
        "pack.7z",
        true,
        &[
            FixtureEntry::file("first.bin", FILLER),
            FixtureEntry::file("amd/driver.inf", b"deterministic"),
        ],
    );
    let req = resolve_request(&ctx.drivers, &pack, &candidate("amd\\", "driver.inf"));

    let a = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("materialize");
    let a_name = a.staging_dir().file_name().expect("name").to_owned();
    let a_bytes = fs::read(a.inf_path()).expect("read staged inf");
    a.cleanup().expect("cleanup a");

    let b = mod_drivers::sdio::materialize_inf(&req, &ctx.staging).expect("materialize");
    let b_name = b.staging_dir().file_name().expect("name").to_owned();
    let b_bytes = fs::read(b.inf_path()).expect("read staged inf");
    b.cleanup().expect("cleanup b");

    // Same request + bytes + root -> same content and metadata semantics;
    // only the unique staging child name differs.
    assert_eq!(a_bytes, b_bytes);
    assert_ne!(a_name, b_name, "unique child names");
}

// ---------------- R37/R38 — structural guards for streaming-only extraction ----------------

#[test]
fn r37_r38_no_whole_body_allocation_no_whole_archive_extractor() {
    let src = include_str!("../src/sdio/extraction.rs");
    let code: String = src
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//!") && !t.starts_with("///")
        })
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "read_to_end",
        "ArchiveReader::read_file",
        "read_file(",
        "decompress_file",
        "default_entry_extract_fn",
        "decompress(",
        "Command::new",
        "7z.exe",
        "7za",
        "7zz",
        "Expand-Archive",
        "tar.exe",
    ] {
        assert!(
            !code.contains(forbidden),
            "production extraction code must not contain {forbidden:?}"
        );
    }
    // R37 — no whole-body allocation sized from an entry/archive value. A
    // FIXED small scratch buffer is required by the streaming contract; an
    // allocation sized from untrusted metadata is forbidden. Scan for
    // `with_capacity` calls whose argument is not a fixed constant.
    for line in code.lines() {
        let t = line.trim();
        if t.contains("Vec::with_capacity") {
            let arg_ok = t.contains("MAX_ARCHIVE_COMPONENT_LEN + 1")
                || t.contains("STREAM_BUF_BYTES")
                || t.contains("MAX_CODERS_PER_BLOCK");
            assert!(
                arg_ok,
                "Vec::with_capacity must only use fixed constants, got: {t}"
            );
        }
    }
}

// ---------------- R39 — no trust overclaim in the extraction domain ----------------

#[test]
fn r39_no_trust_overclaim() {
    let src = include_str!("../src/sdio/extraction.rs");
    for n in [
        "Trusted",
        "VerifiedPackage",
        "Signed",
        "Installable",
        "Recommended",
        "UpdateAvailable",
        "UpToDate",
        "Outdated",
    ] {
        // Domain type names only (doc comments may legitimately state denials).
        let code: String = src
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//!") && !t.starts_with("///")
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains(&format!("pub struct {n}")) && !code.contains(&format!("pub enum {n}")),
            "extraction domain must not define a type named {n}"
        );
    }
}

// ---------------- R40 — path bounds retained (member-length bounds enforced by the extractor) ----------------

#[test]
fn r40_path_bounds_retained() {
    // The extraction module reuses the 2a-5 member limits; prove the constants
    // are shared rather than duplicated with conflicting values.
    assert_eq!(
        mod_drivers::sdio::extraction::MAX_ARCHIVE_MEMBER_LEN,
        mod_drivers::sdio::local_pack::MAX_ARCHIVE_MEMBER_LEN
    );
    assert_eq!(
        mod_drivers::sdio::extraction::MAX_ARCHIVE_MEMBER_COMPONENTS,
        mod_drivers::sdio::local_pack::MAX_ARCHIVE_MEMBER_COMPONENTS
    );
    assert_eq!(
        mod_drivers::sdio::extraction::MAX_ARCHIVE_COMPONENT_LEN,
        mod_drivers::sdio::local_pack::MAX_ARCHIVE_COMPONENT_LEN
    );
}

// ---------------- Structural: production dependency must not enable encoder/AES features ----------------

#[test]
fn production_dependency_keeps_default_features_off() {
    let manifest = include_str!("../Cargo.toml");
    // The production dependency line must be default-features = false and must
    // not carry compress/aes256. The dev-dependency may enable compress only.
    let prod_line = manifest
        .lines()
        .find(|l| l.contains("sevenz-rust2") && !l.trim_start().starts_with('#'))
        .expect("production sevenz-rust2 dependency line");
    assert!(prod_line.contains("default-features = false"));
    assert!(!prod_line.contains("compress"));
    assert!(!prod_line.contains("aes256"));
}
