//! Tab 2a-10 - payload inventory + content fingerprint gate.
//!
//! Given a live token-bound `ResolvedSourceReferences`, every referenced
//! payload must exist uniquely in the SAME local `.7z`, be streamed under
//! bounded archive/decompression limits, and be recorded as an exact decoded
//! length plus a SHA-256 content fingerprint. Nothing here is staged, written,
//! trusted or installed: the inventory is an expected-content contract for the
//! later materialization slice, not a package-completeness claim.

#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use mod_drivers::sdio::Candidate;
use mod_drivers::sdio::extraction::materialize_inf;
use mod_drivers::sdio::local_pack::{
    LocalPackAvailability, PackageMaterializationRequest, resolve_local_pack,
};
use mod_drivers::sdio::matching::{CatalogCandidateMatch, DeviceIdKind, MatchEvidence};
use mod_drivers::sdio::payload_inventory::{
    MAX_PAYLOAD_FILE_BYTES, MAX_PAYLOAD_FILES, MAX_PAYLOAD_TOTAL_BYTES,
    MAX_PAYLOAD_TOTAL_DECODE_BYTES, PayloadInventoryError as PE, ResolvedPayloadInventory,
    inspect_payload_inventory, test_accumulate_decode_bytes, test_accumulate_total_bytes,
    test_block_decode_count, test_charge_runtime_bytes, test_expected_archive_member,
    test_inspect_with_attestation, test_payload_size_within_cap, test_reset_block_decode_count,
    test_validate_source_path,
};
use mod_drivers::sdio::signature::{
    DriverPackageVerifier, TrustError, TrustResult, VerifiedDriverPackage,
};
use mod_drivers::sdio::source_manifest::{
    ResolvedSourceReferences, SourceManifest, derive_source_manifest,
};
use sevenz_rust2::{ArchiveEntry, ArchiveWriter, SourceReader};

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

/// The verifier seam and the block-decode counter are process-global.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A live verified token plus the tree it was materialized from. `token` is
/// declared first so its locks and pins drop before the temp tree goes.
struct Fixture {
    token: VerifiedDriverPackage,
    pack_path: PathBuf,
    _tmp: TempDir,
}

const HEADER: &str = "[Version]\nSignature=\"$WINDOWS NT$\"\nClass=System\n\
    ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\nProvider=%Mfg%\n\
    DriverVer=01/01/2024,1.0.0.0\n\n[Strings]\nMfg=\"Cove\"\nDisk=\"Disk\"\n\n";

/// INF body naming `driver.sys` at the package root and `bin/helper.dll`.
const TWO_PAYLOADS: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n\
    [SourceDisksFiles]\ndriver.sys = 1\nhelper.dll = 1,bin\n\n\
    [Install.NTamd64]\nCopyFiles = L\n\n[L]\ndriver.sys\nhelper.dll\n";

/// INF body naming exactly one root-relative payload.
const ONE_PAYLOAD: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n\
    [SourceDisksFiles]\ndriver.sys = 1\n\n\
    [Install.NTamd64]\nCopyFiles = L\n\n[L]\ndriver.sys\n";

/// INF body naming exactly one payload under `bin/`.
const ONE_NESTED_PAYLOAD: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n\
    [SourceDisksFiles]\ndriver.sys = 1,bin\n\n\
    [Install.NTamd64]\nCopyFiles = L\n\n[L]\ndriver.sys\n";

fn inf_bytes(body: &str) -> Vec<u8> {
    format!("{HEADER}{body}").replace('\n', "\r\n").into_bytes()
}

/// One solid compression block's worth of file entries.
type Group<'a> = &'a [(&'a str, &'a [u8])];

/// Write a synthetic `.7z` whose blocks are EXACTLY the supplied groups, in
/// order: every group becomes one solid block via a single multi-entry push.
fn write_archive(path: &Path, groups: &[Group<'_>]) {
    let file = fs::File::create(path).expect("create archive file");
    let mut writer = ArchiveWriter::new(std::io::BufWriter::new(file)).expect("writer");
    for group in groups {
        let mut entries = Vec::new();
        let mut readers = Vec::new();
        for (name, content) in group.iter() {
            entries.push(ArchiveEntry::new_file(name));
            readers.push(SourceReader::new(std::io::Cursor::new(content.to_vec())));
        }
        writer
            .push_archive_entries(entries, readers)
            .expect("push block");
    }
    writer.finish().expect("finish archive");
}

fn candidate(inf_path: &str) -> CatalogCandidateMatch {
    candidate_with_catalog(inf_path, None)
}

fn candidate_with_catalog(inf_path: &str, catalog_file: Option<&str>) -> CatalogCandidateMatch {
    CatalogCandidateMatch {
        pack_name: "fake_pack".into(),
        candidate: Candidate {
            inf_path: inf_path.into(),
            inf_filename: "driver.inf".into(),
            provider: None,
            class: None,
            class_guid: None,
            catalog_file: catalog_file.map(str::to_string),
            version: None,
            date: None,
            install_section: "Install".into(),
            picked_section: "Install".into(),
            sect_pos: 0,
            models_section: None,
            inf_pos: 0,
        },
        evidence: vec![MatchEvidence {
            kind: DeviceIdKind::Hardware,
            device_id: "PCI\\VEN_FAKE".into(),
            ordinal: 0,
            inf_pos: 0,
        }],
    }
}

fn request(drivers: &Path, inf_path: &str) -> PackageMaterializationRequest {
    match resolve_local_pack(drivers, &candidate(inf_path)).expect("resolve_local_pack") {
        LocalPackAvailability::Present(req) => req,
        other => panic!("expected Present, got {other:?}"),
    }
}

fn unique_root(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("cove_tab2a10_{tag}_{}_{nanos}", std::process::id()))
}

/// Build a live token from an archive already written at `pack_path`.
fn token_for(drivers: &Path, staging: &Path, inf_dir: &str) -> VerifiedDriverPackage {
    let artifact = materialize_inf(&request(drivers, inf_dir), staging).expect("materialize");
    DriverPackageVerifier::with_check_fn(|_| TrustResult::Trusted {
        catalog_name: String::new(),
        signer: None,
        reported_catalog_path: None,
    })
    .verify(artifact)
    .expect("verify must produce a live token")
}

/// Build a fixture whose archive contains the INF (in its own first block) and
/// then one block per supplied group.
///
/// `inf_dir` is the SDIO candidate directory using `\` separators (empty for an
/// archive-root INF); every group entry name is a FULL archive member path, so
/// each test states the exact archive layout under inspection.
fn fixture_with(tag: &str, inf_dir: &str, body: &str, groups: &[Group<'_>]) -> Fixture {
    let root = unique_root(tag);
    let (drivers, staging) = (root.join("drivers"), root.join("staging"));
    fs::create_dir_all(&drivers).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let tmp = TempDir(root);

    let inf_member = if inf_dir.is_empty() {
        "driver.inf".to_string()
    } else {
        format!("{}/driver.inf", inf_dir.replace('\\', "/"))
    };
    let inf = inf_bytes(body);
    let inf_group: Vec<(&str, &[u8])> = vec![(inf_member.as_str(), inf.as_slice())];
    let mut all: Vec<Group<'_>> = vec![inf_group.as_slice()];
    all.extend_from_slice(groups);

    let pack_path = drivers.join("fake_pack.7z");
    write_archive(&pack_path, &all);

    let token = token_for(&drivers, &staging, inf_dir);
    Fixture {
        token,
        pack_path: fs::canonicalize(&pack_path).expect("canonical pack"),
        _tmp: tmp,
    }
}

fn sources(f: &Fixture) -> ResolvedSourceReferences<'_> {
    match derive_source_manifest(&f.token, "Install") {
        SourceManifest::ResolvedReferences(r) => r,
        other => panic!("expected ResolvedReferences, got {other:?}"),
    }
}

fn inventory(f: &Fixture) -> Result<ResolvedPayloadInventory<'_>, PE> {
    inspect_payload_inventory(&sources(f))
}

/// `(source_path, actual_archive_member, size, hex sha256)` in inventory order.
fn rows(inv: &ResolvedPayloadInventory<'_>) -> Vec<(String, String, u64, String)> {
    inv.entries()
        .iter()
        .map(|e| {
            (
                e.source_path().to_string(),
                e.actual_archive_member().to_string(),
                e.fingerprint().size_bytes(),
                hex(e.fingerprint().sha256()),
            )
        })
        .collect()
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn members(inv: &ResolvedPayloadInventory<'_>) -> Vec<String> {
    inv.entries()
        .iter()
        .map(|e| e.actual_archive_member().to_string())
        .collect()
}

const SYS: &[u8] = b"cove-payload-driver-sys-bytes-0123456789";
const DLL: &[u8] = b"cove-payload-helper-dll-bytes-abcdefghij";
const FILLER: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef";

// ---------------------------------------------------------------------------
// P1 / P2 - INF-directory member mapping
// ---------------------------------------------------------------------------

#[test]
fn p1_root_inf_directory_maps_source_to_archive_root() {
    let _g = serial();
    let f = fixture_with("p1", "", ONE_PAYLOAD, &[&[("driver.sys", SYS)]]);
    let inv = inventory(&f).expect("inventory");
    assert_eq!(members(&inv), ["driver.sys"]);
}

#[test]
fn p2_nested_inf_directory_prefixes_the_source_path_exactly_once() {
    let _g = serial();
    let f = fixture_with(
        "p2",
        "amd\\10x64\\pkg",
        ONE_NESTED_PAYLOAD,
        &[&[("amd/10x64/pkg/bin/driver.sys", SYS)]],
    );
    let inv = inventory(&f).expect("inventory");
    assert_eq!(rows(&inv)[0].0, "bin/driver.sys");
    assert_eq!(members(&inv), ["amd/10x64/pkg/bin/driver.sys"]);

    // The pure composer is the exact production seam: the prefix is taken from
    // the verified INF member's DIRECTORY and applied once, never doubled and
    // never dropped.
    assert_eq!(
        test_expected_archive_member("amd/10x64/pkg/driver.inf", "bin/driver.sys").as_deref(),
        Ok("amd/10x64/pkg/bin/driver.sys")
    );
    assert_eq!(
        test_expected_archive_member("driver.inf", "bin/driver.sys").as_deref(),
        Ok("bin/driver.sys")
    );
}

// ---------------------------------------------------------------------------
// P3 / P4 - multiple payloads, deterministic order, source casing
// ---------------------------------------------------------------------------

#[test]
fn p3_multiple_payloads_keep_source_manifest_order() {
    let _g = serial();
    let f = fixture_with(
        "p3",
        "",
        TWO_PAYLOADS,
        &[&[("driver.sys", SYS)], &[("bin/helper.dll", DLL)]],
    );
    let inv = inventory(&f).expect("inventory");
    let got = rows(&inv);
    assert_eq!(
        got.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        ["driver.sys", "bin/helper.dll"],
        "inventory order is the source-manifest discovery order"
    );
    assert_eq!(got[0].2, SYS.len() as u64);
    assert_eq!(got[1].2, DLL.len() as u64);
}

#[test]
fn p4_case_insensitive_match_retains_the_actual_archive_spelling() {
    let _g = serial();
    let f = fixture_with("p4", "", ONE_PAYLOAD, &[&[("DRIVER.SYS", SYS)]]);
    let inv = inventory(&f).expect("a unique ASCII case-insensitive match resolves");
    let row = &rows(&inv)[0];
    assert_eq!(row.0, "driver.sys", "the INF's source casing is preserved");
    assert_eq!(
        row.1, "DRIVER.SYS",
        "the archive's own spelling is recorded separately"
    );
}

#[test]
fn p4_actual_member_keeps_the_archive_separator_spelling() {
    let _g = serial();
    // A Windows-authored archive may store `\` separators. Matching normalizes
    // them, but the reported member must be the archive's OWN spelling, not
    // the normalized key, or a caller cannot address the entry it names.
    let f = fixture_with(
        "p4sep",
        "",
        ONE_NESTED_PAYLOAD,
        &[&[("bin\\driver.sys", SYS)]],
    );
    let inv = inventory(&f).expect("a `\\`-separated member still matches");
    let row = &rows(&inv)[0];
    assert_eq!(row.0, "bin/driver.sys", "the source path stays normalized");
    assert_eq!(
        row.1, "bin\\driver.sys",
        "the archive's own separator spelling is reported verbatim"
    );
}

// ---------------------------------------------------------------------------
// P5 / P6 - ambiguity and absence both fail the whole operation
// ---------------------------------------------------------------------------

#[test]
fn p5_case_colliding_archive_members_are_ambiguous() {
    let _g = serial();
    let f = fixture_with(
        "p5",
        "",
        ONE_NESTED_PAYLOAD,
        &[&[("bin/driver.sys", SYS), ("BIN/DRIVER.SYS", DLL)]],
    );
    assert!(
        matches!(inventory(&f), Err(PE::PayloadMemberAmbiguous { matches, .. }) if matches == 2),
        "a case collision is never resolved by preference"
    );
}

#[test]
fn p6_one_missing_member_fails_the_whole_inventory() {
    let _g = serial();
    let f = fixture_with(
        "p6",
        "",
        TWO_PAYLOADS,
        // `bin/helper.dll` is absent from the archive.
        &[&[("driver.sys", SYS)]],
    );
    assert!(
        matches!(inventory(&f), Err(PE::PayloadMemberMissing { index: 1 })),
        "no partial inventory is ever returned"
    );
}

// ---------------------------------------------------------------------------
// P7 / P8 - inherited archive security contract and the payload contract
// ---------------------------------------------------------------------------

#[test]
fn p7_unrelated_unsafe_archive_member_fails_closed() {
    let _g = serial();
    // The archive the INF was materialized from is safe; the pack is then
    // replaced at the same canonical path with one that also carries an
    // unrelated traversal member. The requested payload is still present and
    // safe, so only the inherited archive-wide contract can reject this.
    let f = fixture_with("p7", "", ONE_PAYLOAD, &[&[("driver.sys", SYS)]]);
    let inf = inf_bytes(ONE_PAYLOAD);
    write_archive(
        &f.pack_path,
        &[
            &[("driver.inf", inf.as_slice())],
            &[("driver.sys", SYS), ("../escape.sys", DLL)],
        ],
    );
    assert!(
        matches!(inventory(&f), Err(PE::Archive(_))),
        "the inherited unsafe-member rejection still governs the whole archive"
    );
}

#[test]
fn p8_zero_length_payload_is_not_a_valid_payload() {
    let _g = serial();
    let f = fixture_with("p8", "", ONE_PAYLOAD, &[&[("driver.sys", b"")]]);
    assert!(matches!(
        inventory(&f),
        Err(PE::PayloadNotRegularFile { index: 0 })
    ));
}

#[test]
fn p8_directory_entry_is_not_a_valid_payload() {
    let _g = serial();
    // `driver.sys` exists only as a DIRECTORY member: no stream, no payload.
    let root = unique_root("p8dir");
    let (drivers, staging) = (root.join("drivers"), root.join("staging"));
    fs::create_dir_all(&drivers).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let tmp = TempDir(root);
    let inf = inf_bytes(ONE_PAYLOAD);
    let pack_path = drivers.join("fake_pack.7z");
    {
        let file = fs::File::create(&pack_path).unwrap();
        let mut w = ArchiveWriter::new(std::io::BufWriter::new(file)).unwrap();
        w.push_archive_entry(
            ArchiveEntry::new_file("driver.inf"),
            Some(std::io::Cursor::new(inf.clone())),
        )
        .unwrap();
        w.push_archive_entry(
            ArchiveEntry::new_directory("driver.sys"),
            Option::<std::io::Cursor<Vec<u8>>>::None,
        )
        .unwrap();
        w.finish().unwrap();
    }
    let f = Fixture {
        token: token_for(&drivers, &staging, ""),
        pack_path: fs::canonicalize(&pack_path).unwrap(),
        _tmp: tmp,
    };
    assert!(matches!(
        inventory(&f),
        Err(PE::PayloadNotRegularFile { index: 0 })
    ));
}

// ---------------------------------------------------------------------------
// P9 / P10 / P14 / P15 - bounds, checked arithmetic and runtime accounting
// ---------------------------------------------------------------------------

#[test]
fn p9_per_file_payload_cap_boundary_is_exact() {
    assert_eq!(test_payload_size_within_cap(MAX_PAYLOAD_FILE_BYTES), Ok(()));
    assert_eq!(
        test_payload_size_within_cap(MAX_PAYLOAD_FILE_BYTES + 1),
        Err(PE::PayloadTooLarge { index: 0 })
    );
    assert_eq!(
        test_payload_size_within_cap(u64::MAX),
        Err(PE::PayloadTooLarge { index: 0 })
    );
}

#[test]
fn p10_total_payload_byte_cap_is_checked() {
    assert_eq!(
        test_accumulate_total_bytes(MAX_PAYLOAD_TOTAL_BYTES - 1, 1),
        Ok(MAX_PAYLOAD_TOTAL_BYTES)
    );
    assert_eq!(
        test_accumulate_total_bytes(MAX_PAYLOAD_TOTAL_BYTES, 1),
        Err(PE::PayloadTotalBytesExceeded)
    );
    assert_eq!(
        test_accumulate_total_bytes(u64::MAX, 1),
        Err(PE::PayloadTotalBytesExceeded),
        "overflow fails closed instead of wrapping"
    );
}

#[test]
fn p14_decode_budget_boundary_is_checked() {
    assert_eq!(
        test_accumulate_decode_bytes(MAX_PAYLOAD_TOTAL_DECODE_BYTES - 1, 1),
        Ok(MAX_PAYLOAD_TOTAL_DECODE_BYTES)
    );
    assert_eq!(
        test_accumulate_decode_bytes(MAX_PAYLOAD_TOTAL_DECODE_BYTES, 1),
        Err(PE::PayloadDecodeBudgetExceeded)
    );
    assert_eq!(
        test_accumulate_decode_bytes(u64::MAX, 1),
        Err(PE::PayloadDecodeBudgetExceeded)
    );
}

#[test]
fn p14_solid_prerequisite_bytes_are_charged_to_the_decode_budget() {
    let _g = serial();
    // One solid block: a large prerequisite precedes the only requested
    // payload, so the block's DECODED bytes exceed the payload's own size.
    let prereq = vec![b'p'; 4096];
    let f = fixture_with(
        "p14b",
        "",
        ONE_PAYLOAD,
        &[&[("prereq.bin", &prereq), ("driver.sys", SYS)]],
    );
    let inv = inventory(&f).expect("inventory");
    assert_eq!(rows(&inv)[0].2, SYS.len() as u64);
    assert!(
        inv.declared_decode_bytes() >= (prereq.len() + SYS.len()) as u64,
        "the DECLARED budget runs from the block's first entry, so the \
         prerequisite is charged before any decoding: {}",
        inv.declared_decode_bytes()
    );
    assert!(
        inv.decode_bytes() >= (prereq.len() + SYS.len()) as u64,
        "the prerequisite's ACTUAL decoded bytes are charged too: {}",
        inv.decode_bytes()
    );
}

#[test]
fn p15_runtime_byte_accounting_cannot_exceed_the_cap() {
    // The runtime counter is charged per streamed chunk and is independent of
    // any declared metadata, so a lying archive cannot spend past the cap.
    assert_eq!(test_charge_runtime_bytes(0, 10, 10), Ok(10));
    assert_eq!(
        test_charge_runtime_bytes(10, 1, 10),
        Err(PE::PayloadDecodeBudgetExceeded)
    );
    assert_eq!(
        test_charge_runtime_bytes(u64::MAX, 1, u64::MAX),
        Err(PE::PayloadDecodeBudgetExceeded)
    );
}

// ---------------------------------------------------------------------------
// P11 / P12 / P13 - solid multi-target block grouping
// ---------------------------------------------------------------------------

#[test]
fn p11_two_targets_in_one_solid_block_are_both_fingerprinted() {
    let _g = serial();
    let f = fixture_with(
        "p11",
        "",
        TWO_PAYLOADS,
        &[&[
            ("prereq-a.bin", FILLER),
            ("driver.sys", SYS),
            ("intermediate.bin", FILLER),
            ("bin/helper.dll", DLL),
            ("after.bin", FILLER),
        ]],
    );
    let inv = inventory(&f).expect("inventory");
    let got = rows(&inv);
    assert_eq!(got[0].2, SYS.len() as u64);
    assert_eq!(got[1].2, DLL.len() as u64);
    assert_ne!(got[0].3, got[1].3, "distinct payloads, distinct digests");
    assert!(
        inv.decode_bytes() < (FILLER.len() * 3 + SYS.len() + DLL.len()) as u64,
        "decode stops after the LAST requested target: after.bin is never decoded"
    );
}

#[test]
fn p12_one_block_with_two_targets_is_decoded_exactly_once() {
    let _g = serial();
    let f = fixture_with(
        "p12",
        "",
        TWO_PAYLOADS,
        &[&[("driver.sys", SYS), ("bin/helper.dll", DLL)]],
    );
    test_reset_block_decode_count();
    let inv = inventory(&f).expect("inventory");
    assert_eq!(inv.entries().len(), 2);
    assert_eq!(
        test_block_decode_count(),
        1,
        "targets sharing a block are grouped into ONE block traversal"
    );
}

#[test]
fn p13_unrelated_blocks_are_never_decoded() {
    let _g = serial();
    let unrelated = vec![b'u'; 8192];
    let f = fixture_with(
        "p13",
        "",
        TWO_PAYLOADS,
        &[
            &[("driver.sys", SYS)],
            &[("unrelated.bin", &unrelated)],
            &[("bin/helper.dll", DLL)],
        ],
    );
    test_reset_block_decode_count();
    let inv = inventory(&f).expect("inventory");
    assert_eq!(
        test_block_decode_count(),
        2,
        "blocks A and C are decoded, block B is skipped"
    );
    assert!(
        inv.decode_bytes() < unrelated.len() as u64,
        "block B's bytes are never decoded: {}",
        inv.decode_bytes()
    );
}

// ---------------------------------------------------------------------------
// P16 / P17 / P18 - corruption and cryptographic content identity
// ---------------------------------------------------------------------------

#[test]
fn p16_same_size_stream_corruption_fails_the_inventory() {
    let _g = serial();
    let f = fixture_with("p16", "", ONE_PAYLOAD, &[&[("driver.sys", SYS)]]);
    // Replace the pack at the same canonical path with one whose ONLY packed
    // stream is the requested payload, then flip a byte in the middle of that
    // stream. The file keeps its exact length and canonical path, so every
    // path preflight still passes and only the decode/CRC contract can reject
    // it. (The INF is not needed in the archive: it is already staged.)
    let payload: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(31) >> 3) as u8)
        .collect();
    write_archive(&f.pack_path, &[&[("driver.sys", &payload)]]);
    let mut bytes = fs::read(&f.pack_path).expect("read pack");
    let before = bytes.len();
    let packed_len = u64::from_le_bytes(bytes[12..20].try_into().unwrap()) as usize;
    assert!(packed_len > 64, "packed stream must be substantial");
    bytes[32 + packed_len / 2] ^= 0xFF;
    fs::write(&f.pack_path, &bytes).expect("rewrite pack");
    assert_eq!(fs::read(&f.pack_path).unwrap().len(), before);
    let got = inventory(&f);
    assert!(
        matches!(&got, Err(PE::Archive(_))),
        "a decode/CRC failure surfaces as an ARCHIVE error, never as a \
         missing member and never as a partial success: {got:?}"
    );
}

#[test]
fn p17_sha256_matches_a_known_answer() {
    let _g = serial();
    let f = fixture_with("p17", "", ONE_PAYLOAD, &[&[("driver.sys", b"abc")]]);
    let inv = inventory(&f).expect("inventory");
    let row = &rows(&inv)[0];
    assert_eq!(row.2, 3);
    assert_eq!(
        row.3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256(\"abc\") is compared against the published vector, not against \
         a second call to this same implementation"
    );
}

#[test]
fn p18_same_name_same_size_different_bytes_yields_a_different_digest() {
    let _g = serial();
    let a = fixture_with("p18a", "", ONE_PAYLOAD, &[&[("driver.sys", b"AAAAAAAA")]]);
    let da = rows(&inventory(&a).expect("inventory a"))[0].clone();
    let b = fixture_with("p18b", "", ONE_PAYLOAD, &[&[("driver.sys", b"AAAAAAAB")]]);
    let db = rows(&inventory(&b).expect("inventory b"))[0].clone();
    assert_eq!((da.1.as_str(), da.2), (db.1.as_str(), db.2));
    assert_ne!(
        da.3, db.3,
        "identical member path and size, changed bytes: the digest must differ"
    );
}

// ---------------------------------------------------------------------------
// P19 / P20 - the pack is hostile CURRENT input
// ---------------------------------------------------------------------------

#[test]
fn p19_pack_path_replaced_by_a_directory_fails_before_any_decode() {
    let _g = serial();
    let f = fixture_with("p19", "", ONE_PAYLOAD, &[&[("driver.sys", SYS)]]);
    fs::remove_file(&f.pack_path).expect("remove pack");
    fs::create_dir(&f.pack_path).expect("substitute a directory");
    test_reset_block_decode_count();
    assert!(matches!(
        inventory(&f),
        Err(PE::PackChangedSinceVerification)
    ));
    assert_eq!(
        test_block_decode_count(),
        0,
        "no archive block is decoded after a pack substitution"
    );
}

#[test]
fn p19_pack_open_denies_write_sharing_for_the_whole_decode() {
    let _g = serial();
    let f = fixture_with("p19w", "", ONE_PAYLOAD, &[&[("driver.sys", SYS)]]);
    // Baseline: with nobody writing, the inventory succeeds.
    assert_eq!(members(&inventory(&f).expect("baseline")), ["driver.sys"]);

    // A concurrent WRITER holding the pack must make the inventory fail
    // closed rather than fingerprint an archive somebody else is mutating.
    let writer = fs::OpenOptions::new()
        .write(true)
        .open(&f.pack_path)
        .expect("open pack for writing");
    test_reset_block_decode_count();
    let got = inventory(&f);
    assert!(
        matches!(got, Err(PE::PackChangedSinceVerification)),
        "a writer holding the pack must fail the open, not be decoded around: {got:?}"
    );
    assert_eq!(
        test_block_decode_count(),
        0,
        "nothing is decoded once the read-locked open is refused"
    );
    drop(writer);

    // ...and the refusal is transient, not a poisoned token.
    assert_eq!(
        members(&inventory(&f).expect("after writer closed")),
        ["driver.sys"]
    );
}

#[test]
fn p20_same_path_replacement_fingerprints_the_bytes_decoded_now() {
    let _g = serial();
    let f = fixture_with("p20", "", ONE_PAYLOAD, &[&[("driver.sys", SYS)]]);
    let first = rows(&inventory(&f).expect("first inventory"))[0].clone();

    // Replace the archive at the SAME canonical path with an otherwise valid
    // one whose payload bytes differ. The verified token pins the pack PATH,
    // not the pack's bytes, so this succeeds - and must report the new bytes.
    let inf = inf_bytes(ONE_PAYLOAD);
    let replaced: &[u8] = b"replaced-payload-bytes";
    write_archive(
        &f.pack_path,
        &[
            &[("driver.inf", inf.as_slice())],
            &[("driver.sys", replaced)],
        ],
    );
    let second = rows(&inventory(&f).expect("second inventory"))[0].clone();
    assert_eq!(second.1, "driver.sys");
    assert_ne!(
        first.3, second.3,
        "the inventory records the bytes decoded NOW, never a historical claim"
    );
    assert_eq!(second.2, replaced.len() as u64);
}

// ---------------------------------------------------------------------------
// P21 / P22 - re-attestation brackets every archive access
// ---------------------------------------------------------------------------

fn stale() -> Result<(), TrustError> {
    Err(TrustError::StagedBytesChanged)
}

#[test]
fn p21_failed_pre_attestation_opens_no_archive() {
    let _g = serial();
    let f = fixture_with("p21", "", ONE_PAYLOAD, &[&[("driver.sys", SYS)]]);
    test_reset_block_decode_count();
    let mut post_calls = 0;
    let r = test_inspect_with_attestation(&sources(&f), &mut stale, &mut || {
        post_calls += 1;
        Ok(())
    });
    assert!(matches!(
        r,
        Err(PE::Attestation(TrustError::StagedBytesChanged))
    ));
    assert_eq!(post_calls, 0);
    assert_eq!(
        test_block_decode_count(),
        0,
        "no archive open or decode before the pre-attestation passes"
    );
}

#[test]
fn p22_failed_post_attestation_yields_no_inventory() {
    let _g = serial();
    let f = fixture_with("p22", "", ONE_PAYLOAD, &[&[("driver.sys", SYS)]]);
    let r = test_inspect_with_attestation(&sources(&f), &mut || Ok(()), &mut stale);
    assert!(
        matches!(r, Err(PE::Attestation(TrustError::StagedBytesChanged))),
        "successful decode evidence is discarded when the lease no longer holds"
    );
}

#[test]
fn p22_production_path_reattests_the_live_token_and_leaves_it_usable() {
    let _g = serial();
    let f = fixture_with("p22b", "", ONE_PAYLOAD, &[&[("driver.sys", SYS)]]);
    assert_eq!(members(&inventory(&f).expect("first")), ["driver.sys"]);
    assert_eq!(members(&inventory(&f).expect("second")), ["driver.sys"]);
    f.token
        .reattest()
        .expect("inventory must not disturb the lease");
}

// ---------------------------------------------------------------------------
// Defense-in-depth source-path revalidation and declared bounds
// ---------------------------------------------------------------------------

#[test]
fn source_paths_are_revalidated_at_the_archive_boundary() {
    for hostile in [
        "",
        "/abs.sys",
        "\\abs.sys",
        "c:/x.sys",
        "a:x.sys",
        "../escape.sys",
        "./same.sys",
        "a//b.sys",
        "a/../b.sys",
        "a/",
        "file.sys ",
        "file.sys.",
        "CON/x.sys",
        "nul.sys",
        "a/b\0c.sys",
        "stream.sys:ads",
        "\\\\server\\share\\x.sys",
        "caf\u{e9}.sys",
    ] {
        assert!(
            test_validate_source_path(hostile).is_err(),
            "{hostile:?} must be rejected at the archive boundary"
        );
    }
    for ok in ["a.sys", "bin/a.sys", "a/b/c/d.sys", "A.SYS"] {
        assert_eq!(test_validate_source_path(ok), Ok(()), "{ok:?}");
    }
}

#[test]
fn payload_bounds_are_ordered_and_stated() {
    assert_eq!(MAX_PAYLOAD_FILES, 1024);
    assert_eq!(MAX_PAYLOAD_FILE_BYTES, 512 * 1024 * 1024);
    assert_eq!(MAX_PAYLOAD_TOTAL_BYTES, 4 * 1024 * 1024 * 1024);
    assert_eq!(MAX_PAYLOAD_TOTAL_DECODE_BYTES, 8 * 1024 * 1024 * 1024);
    // The ordering the bounds depend on, checked at compile time: a payload
    // cannot exceed the total, and the total cannot exceed the decode budget
    // that must also cover solid prerequisites.
    const _: () = assert!(MAX_PAYLOAD_FILE_BYTES < MAX_PAYLOAD_TOTAL_BYTES);
    const _: () = assert!(MAX_PAYLOAD_TOTAL_BYTES <= MAX_PAYLOAD_TOTAL_DECODE_BYTES);
}

// ---------------------------------------------------------------------------
// P24 - no production filesystem output
// ---------------------------------------------------------------------------

#[test]
fn p24_production_inventory_contains_no_filesystem_write_call() {
    let src = include_str!("../src/sdio/payload_inventory.rs");
    // Strip doc and line comments so prose about the contract can neither
    // satisfy nor trip this structural guard.
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "File::create",
        "OpenOptions",
        "create_dir",
        "remove_file",
        "remove_dir",
        "fs::write",
        "write_all",
        "set_permissions",
        "fs::copy",
        "fs::rename",
        // The native open must never request write or delete access, and must
        // never create anything.
        "GENERIC_WRITE",
        "FILE_GENERIC_WRITE",
        "DELETE",
        "CREATE_ALWAYS",
        "CREATE_NEW",
        "OPEN_ALWAYS",
        "TRUNCATE_EXISTING",
    ] {
        assert!(
            !code.contains(forbidden),
            "production payload inventory must never call or request {forbidden}"
        );
    }
    // Read-only archive access, bound to the object rather than the pathname.
    assert!(code.contains("FILE_GENERIC_READ"));
    assert!(code.contains("OPEN_EXISTING"));
    assert!(
        code.contains("FILE_SHARE_READ"),
        "write and delete sharing must be withheld for the whole decode"
    );
    assert!(
        code.contains("FILE_FLAG_OPEN_REPARSE_POINT"),
        "a raced reparse point must be opened as the link and rejected, never traversed"
    );
    assert!(
        code.contains("GetFinalPathNameByHandleW"),
        "the opened object's own final path must be proven against the token"
    );
}

#[test]
fn p24_inventory_creates_no_files_on_disk() {
    let _g = serial();
    let root = unique_root("p24");
    let (drivers, staging) = (root.join("drivers"), root.join("staging"));
    fs::create_dir_all(&drivers).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let tmp = TempDir(root);
    let inf = inf_bytes(ONE_PAYLOAD);
    let pack_path = drivers.join("fake_pack.7z");
    write_archive(
        &pack_path,
        &[&[("driver.inf", inf.as_slice())], &[("driver.sys", SYS)]],
    );
    let f = Fixture {
        token: token_for(&drivers, &staging, ""),
        pack_path: fs::canonicalize(&pack_path).unwrap(),
        _tmp: tmp,
    };

    let before = tree(&drivers);
    let staged_before = tree(&staging);
    let inv = inventory(&f).expect("inventory");
    assert_eq!(inv.entries().len(), 1);
    assert_eq!(tree(&drivers), before, "the drivers root is untouched");
    assert_eq!(
        tree(&staging),
        staged_before,
        "no payload is staged anywhere"
    );
}

// ---------------------------------------------------------------------------
// Realistic end-to-end: pack -> resolve -> materialize -> verify -> manifest
// -> inventory, over a package that also carries a catalog.
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_inf_cat_sys_dll_package_inventories_both_payloads() {
    let _g = serial();
    let root = unique_root("e2e");
    let (drivers, staging) = (root.join("drivers"), root.join("staging"));
    fs::create_dir_all(&drivers).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let tmp = TempDir(root);

    let inf = inf_bytes(TWO_PAYLOADS);
    let cat: &[u8] = b"cove-synthetic-catalog-bytes";
    let pack_path = drivers.join("fake_pack.7z");
    // One solid block holding the whole package, exactly as an SDIO pack does.
    write_archive(
        &pack_path,
        &[&[
            ("amd/10x64/pkg/driver.inf", inf.as_slice()),
            ("amd/10x64/pkg/driver.cat", cat),
            ("amd/10x64/pkg/driver.sys", SYS),
            ("amd/10x64/pkg/bin/helper.dll", DLL),
        ]],
    );
    let req = match resolve_local_pack(
        &drivers,
        &candidate_with_catalog("amd\\10x64\\pkg", Some("driver.cat")),
    )
    .expect("resolve_local_pack")
    {
        LocalPackAvailability::Present(r) => r,
        other => panic!("expected Present, got {other:?}"),
    };
    let artifact = materialize_inf(&req, &staging).expect("materialize");
    let token = DriverPackageVerifier::with_check_fn(|_| TrustResult::Trusted {
        catalog_name: "driver.cat".into(),
        signer: None,
        reported_catalog_path: None,
    })
    .verify(artifact)
    .expect("verify");
    let f = Fixture {
        token,
        pack_path: fs::canonicalize(&pack_path).unwrap(),
        _tmp: tmp,
    };

    test_reset_block_decode_count();
    let inv = inventory(&f).expect("inventory");
    let got = rows(&inv);
    assert_eq!(
        got.iter().map(|r| r.1.as_str()).collect::<Vec<_>>(),
        ["amd/10x64/pkg/driver.sys", "amd/10x64/pkg/bin/helper.dll"],
        "the source manifest is the authority for which payloads are requested"
    );
    assert_eq!((got[0].2, got[1].2), (SYS.len() as u64, DLL.len() as u64));
    assert_ne!(got[0].3, got[1].3);
    assert_eq!(
        test_block_decode_count(),
        1,
        "the whole package shares one solid block: one traversal"
    );
    // The catalog is NOT a CopyFiles source, so it is not in the inventory:
    // this proves no package-completeness claim is being made.
    assert_eq!(inv.entries().len(), 2);
}

/// Recursive `(relative path, len)` snapshot, sorted.
fn tree(root: &Path) -> Vec<(String, u64)> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, u64)>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let rel = p
                .strip_prefix(base)
                .unwrap_or(&p)
                .to_string_lossy()
                .into_owned();
            match e.metadata() {
                Ok(m) if m.is_dir() => {
                    out.push((rel, 0));
                    walk(base, &p, out);
                }
                Ok(m) => out.push((rel, m.len())),
                Err(_) => out.push((rel, u64::MAX)),
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}
