//! Tab 2a-11b - digest-bound package population.
//!
//! Populates the committed Tab 2a-11a owned package tree from a live
//! `ResolvedPayloadInventory`. The tree substrate itself (ownership, rollback,
//! cleanup races) is proven by `sdio_package_tree`; this suite proves what 11b
//! adds: verified INF/CAT provenance, CURRENT-pack digest binding, one-pass
//! streaming, destination sealing and the capability's own contract.

#![cfg(windows)]

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use mod_drivers::sdio::Candidate;
use mod_drivers::sdio::extraction::materialize_inf;
use mod_drivers::sdio::local_pack::{
    LocalPackAvailability, PackageMaterializationRequest, resolve_local_pack,
};
use mod_drivers::sdio::matching::{CatalogCandidateMatch, DeviceIdKind, MatchEvidence};
use mod_drivers::sdio::package_materialization::{
    MaterializedDriverSource, MaterializedPackageFileKind as Kind,
    PackageMaterializationError as PME, materialize_driver_source,
    test_materialize_with_attestation, test_write_through_retained_handle,
};
use mod_drivers::sdio::package_tree_seam::{
    PackageTreeError, test_build_tree_streamed, test_handle_path_queries,
};
use mod_drivers::sdio::payload_inventory::{
    PayloadInventoryError, ResolvedPayloadInventory, inspect_payload_inventory,
    test_block_decode_count, test_reset_block_decode_count,
};
use mod_drivers::sdio::signature::{
    DriverPackageVerifier, TrustError, TrustResult, VerifiedDriverPackage,
};
use mod_drivers::sdio::source_manifest::{
    ResolvedSourceReferences, SourceManifest, derive_source_manifest,
};
use sevenz_rust2::{ArchiveEntry, ArchiveWriter, SourceReader};

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

/// `token` is declared first so its locks and pins drop before the tree root.
struct Fixture {
    token: VerifiedDriverPackage,
    pack_path: PathBuf,
    /// Caller staging root the package is materialized into.
    pkg: PathBuf,
    inf_dir: String,
    inf: Vec<u8>,
    _tmp: TempDir,
}

const HEADER: &str = "[Version]\nSignature=\"$WINDOWS NT$\"\nClass=System\n\
    ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\nProvider=%Mfg%\n\
    DriverVer=01/01/2024,1.0.0.0\n\n[Strings]\nMfg=\"Cove\"\nDisk=\"Disk\"\n\n";
const TWO: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n\
    [SourceDisksFiles]\ndriver.sys = 1\nhelper.dll = 1,bin\n\n\
    [Install.NTamd64]\nCopyFiles = L\n\n[L]\ndriver.sys\nhelper.dll\n";
/// Same two payloads, but the INF names the archive's LATER block first.
const TWO_REVERSED: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n\
    [SourceDisksFiles]\nhelper.dll = 1,bin\ndriver.sys = 1\n\n\
    [Install.NTamd64]\nCopyFiles = L\n\n[L]\nhelper.dll\ndriver.sys\n";
const THREE: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n\
    [SourceDisksFiles]\ndriver.sys = 1,bin\nhelper.dll = 1,co\nfile.dat = 1,deep\\a\\b\n\n\
    [Install.NTamd64]\nCopyFiles = L\n\n[L]\ndriver.sys\nhelper.dll\nfile.dat\n";
const ONE: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n\
    [SourceDisksFiles]\ndriver.sys = 1\n\n\
    [Install.NTamd64]\nCopyFiles = L\n\n[L]\ndriver.sys\n";
const SELF_INF: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n\
    [SourceDisksFiles]\ndriver.inf = 1\n\n\
    [Install.NTamd64]\nCopyFiles = L\n\n[L]\ndriver.inf\n";
const SELF_CAT: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n\
    [SourceDisksFiles]\ndriver.cat = 1\n\n\
    [Install.NTamd64]\nCopyFiles = L\n\n[L]\ndriver.cat\n";

const SYS: &[u8] = b"cove-payload-driver-sys-bytes-0123456789";
const DLL: &[u8] = b"cove-payload-helper-dll-bytes-abcdefghij";
const DAT: &[u8] = b"cove-payload-deep-file-dat-bytes-zyxwvut";
const CAT: &[u8] = b"cove-catalog-bytes-original";
const FILLER: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef";
// Independent known answers (sha256sum of the constants above).
const SYS_SHA: &str = "3e35fef7963cc45fa78a1b0165cb377f20de151aac74afd1e985a81b28304619";
const DLL_SHA: &str = "c37b9a7209a5bb815d06a91657b15818cda629168c20e0996c43ab202cc42ee5";
const DAT_SHA: &str = "9240e88514ac34227eacc4569167046fb5f0c090aaad7b51917a2ab22e0415fa";
const CAT_SHA: &str = "108a7764b427f5f2053a297ffc1d0a1e11ef662c407f4728a54eca54c9154f24";

fn inf_bytes(body: &str) -> Vec<u8> {
    format!("{HEADER}{body}").replace('\n', "\r\n").into_bytes()
}

type Group<'a> = &'a [(&'a str, &'a [u8])];

/// Write a synthetic `.7z` whose blocks are EXACTLY the supplied groups.
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
            .expect("block");
    }
    writer.finish().expect("finish archive");
}

fn candidate(inf_path: &str, catalog: Option<&str>) -> CatalogCandidateMatch {
    CatalogCandidateMatch {
        pack_name: "fake_pack".into(),
        candidate: Candidate {
            inf_path: inf_path.into(),
            inf_filename: "driver.inf".into(),
            provider: None,
            class: None,
            class_guid: None,
            catalog_file: catalog.map(str::to_string),
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

fn request(drivers: &Path, inf_dir: &str, cat: bool) -> PackageMaterializationRequest {
    let c = candidate(inf_dir, cat.then_some("driver.cat"));
    match resolve_local_pack(drivers, &c).expect("resolve_local_pack") {
        LocalPackAvailability::Present(req) => req,
        other => panic!("expected Present, got {other:?}"),
    }
}

fn unique_root(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cove_tab2a11b_{tag}_{}_{nanos}",
        std::process::id()
    ))
}

fn member(inf_dir: &str, leaf: &str) -> String {
    if inf_dir.is_empty() {
        leaf.to_string()
    } else {
        format!("{}/{leaf}", inf_dir.replace('\\', "/"))
    }
}

/// (Re)write the fixture pack: the INF (and catalog) share block 0, then one
/// block per supplied group.
fn write_pack(path: &Path, inf_dir: &str, inf: &[u8], cat: Option<&[u8]>, groups: &[Group<'_>]) {
    let inf_name = member(inf_dir, "driver.inf");
    let cat_name = member(inf_dir, "driver.cat");
    let mut first: Vec<(&str, &[u8])> = vec![(inf_name.as_str(), inf)];
    if let Some(c) = cat {
        first.push((cat_name.as_str(), c));
    }
    let mut all: Vec<Group<'_>> = vec![first.as_slice()];
    all.extend_from_slice(groups);
    write_archive(path, &all);
}

fn fixture(
    tag: &str,
    inf_dir: &str,
    body: &str,
    cat: Option<&[u8]>,
    groups: &[Group<'_>],
) -> Fixture {
    let root = unique_root(tag);
    let (drivers, staging, pkg) = (root.join("drivers"), root.join("staging"), root.join("pkg"));
    for d in [&drivers, &staging, &pkg] {
        fs::create_dir_all(d).unwrap();
    }
    let tmp = TempDir(root);
    let inf = inf_bytes(body);
    let pack_path = drivers.join("fake_pack.7z");
    write_pack(&pack_path, inf_dir, &inf, cat, groups);
    let artifact =
        materialize_inf(&request(&drivers, inf_dir, cat.is_some()), &staging).expect("materialize");
    let token = DriverPackageVerifier::with_check_fn(|_| TrustResult::Trusted {
        catalog_name: String::new(),
        signer: None,
        reported_catalog_path: None,
    })
    .verify(artifact)
    .expect("verify must produce a live token");
    Fixture {
        token,
        pack_path: fs::canonicalize(&pack_path).expect("canonical pack"),
        pkg: fs::canonicalize(&pkg).expect("canonical pkg"),
        inf_dir: inf_dir.to_string(),
        inf,
        _tmp: tmp,
    }
}

/// Replace the pack in place, keeping the SAME layout.
fn rewrite(f: &Fixture, inf: &[u8], cat: Option<&[u8]>, groups: &[Group<'_>]) {
    write_pack(&f.pack_path, &f.inf_dir, inf, cat, groups);
}

fn sources(f: &Fixture) -> ResolvedSourceReferences<'_> {
    match derive_source_manifest(&f.token, "Install") {
        SourceManifest::ResolvedReferences(r) => r,
        other => panic!("expected ResolvedReferences, got {other:?}"),
    }
}

fn inventory(f: &Fixture) -> Result<ResolvedPayloadInventory<'_>, PayloadInventoryError> {
    inspect_payload_inventory(&sources(f))
}

fn children(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// The one Cove package root under the caller staging root (a sibling the test
/// planted is tolerated; a second Cove root is not).
fn package_root(f: &Fixture) -> PathBuf {
    let kids: Vec<String> = children(&f.pkg)
        .into_iter()
        .filter(|k| k.starts_with("cove-driver-package-"))
        .collect();
    assert_eq!(kids.len(), 1, "exactly one Cove package root: {kids:?}");
    f.pkg.join(&kids[0])
}

fn fail(r: Result<MaterializedDriverSource<'_>, PME>) -> PME {
    match r {
        Ok(_) => panic!("materialization must fail"),
        Err(e) => e,
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// -- B1 / B2 / B5 / B15 / B16 / B20 / B22 / B23 / B24 / B30 -----------------------

/// The whole synthetic pipeline through the DEFAULT entry point (real
/// attestation, no seams): pack -> INF -> verified token -> source manifest ->
/// inventory -> populated tree -> re-attest -> cleanup.
#[test]
fn b1_b2_b30_full_pipeline_populates_exact_bytes_in_slot_order_and_cleans_up() {
    let _g = serial();
    let f = fixture(
        "b1",
        "amd\\pkg",
        THREE,
        Some(CAT),
        &[&[
            ("amd/pkg/bin/driver.sys", SYS),
            ("amd/pkg/co/helper.dll", DLL),
            ("amd/pkg/deep/a/b/file.dat", DAT),
        ]],
    );
    let inv = inventory(&f).expect("inventory");
    fs::create_dir(f.pkg.join("sibling")).unwrap();
    let m = materialize_driver_source(&inv, &f.pkg).expect("materialize_driver_source");
    assert!(std::ptr::eq(m.verified_package(), &f.token));

    // Slot order: INF, CAT, then payloads in inventory order (B1, B20).
    let listing: Vec<_> = m
        .files()
        .iter()
        .map(|x| (x.relative_path(), x.kind()))
        .collect();
    assert_eq!(
        listing,
        [
            ("driver.inf", Kind::Inf),
            ("driver.cat", Kind::Catalog),
            ("bin/driver.sys", Kind::Payload),
            ("co/helper.dll", Kind::Payload),
            ("deep/a/b/file.dat", Kind::Payload),
        ]
    );
    // B5 / B15: the destination baseline IS the inventory identity, and it is
    // the independently known answer, not merely self-consistent.
    for (e, p) in inv.entries().iter().zip(&m.files()[2..]) {
        assert_eq!(e.source_path(), p.relative_path());
        assert_eq!(e.fingerprint().size_bytes(), p.size_bytes());
        assert_eq!(e.fingerprint().sha256(), p.sha256());
    }
    let hashes: Vec<String> = m.files().iter().map(|x| hex(x.sha256())).collect();
    assert_eq!(&hashes[1..], [CAT_SHA, SYS_SHA, DLL_SHA, DAT_SHA]);
    // B16: INF/CAT metadata describes the verified bytes that were copied.
    assert_eq!(m.files()[0].size_bytes(), f.inf.len() as u64);
    assert_eq!(m.files()[1].size_bytes(), CAT.len() as u64);

    // Exact bytes on disk at exact source-relative destinations (B1, B2).
    let root = package_root(&f);
    assert_eq!(fs::read(root.join("driver.inf")).unwrap(), f.inf);
    assert_eq!(fs::read(root.join("driver.cat")).unwrap(), CAT);
    assert_eq!(fs::read(root.join("bin/driver.sys")).unwrap(), SYS);
    assert_eq!(fs::read(root.join("co/helper.dll")).unwrap(), DLL);
    assert_eq!(fs::read(root.join("deep/a/b/file.dat")).unwrap(), DAT);

    // B22 / B23: the paths name the LIVE owned objects. (On this host the
    // retained guards refuse any rename of the staging root or of an ancestor,
    // OS error 32, so movement cannot be staged here; 11a's a15 covers that
    // arm tolerantly. What is provable is that neither path is the verified
    // token's own foreign staging path or any other captured location.)
    // Movement being unobservable, freshness is proven by INSTRUMENTATION: each
    // accessor call must query a retained handle again, so a cached creation
    // path (the only thing that could go stale) cannot satisfy this.
    let queries = test_handle_path_queries();
    let now_root = m.current_root_path().expect("root path");
    assert_eq!(
        test_handle_path_queries(),
        queries + 1,
        "root path: live handle query"
    );
    assert_eq!(now_root, fs::canonicalize(package_root(&f)).unwrap());
    assert_eq!(now_root.parent().unwrap(), f.pkg.as_path());
    let now_inf = m.current_inf_path().expect("inf path");
    assert_eq!(
        test_handle_path_queries(),
        queries + 2,
        "INF path: live handle query"
    );
    assert_eq!(now_inf, now_root.join("driver.inf"));
    assert_ne!(now_inf, f.token.inf_path(), "not the verified source");
    assert_eq!(fs::read(&now_inf).unwrap(), f.inf);

    m.reattest().expect("package reattest");
    // B24: cleanup removes only package-owned objects.
    m.cleanup().expect("cleanup");
    assert_eq!(children(&f.pkg), ["sibling"]);
    assert!(f.pkg.is_dir());
}

// -- B3 / B4: the INF and CAT are the verified staged bytes ------------------------

#[test]
fn b3_b4_inf_and_catalog_come_from_the_verified_source_not_the_current_archive() {
    let _g = serial();
    let f = fixture("b3", "", ONE, Some(CAT), &[&[("driver.sys", SYS)]]);
    let inv = inventory(&f).expect("inventory");
    // The archive's INF and CAT change AFTER verification; payloads stay valid.
    rewrite(
        &f,
        b"; attacker INF",
        Some(b"attacker catalog"),
        &[&[("driver.sys", SYS)]],
    );
    let m = materialize_driver_source(&inv, &f.pkg).expect("materialize");
    let root = package_root(&f);
    assert_eq!(fs::read(root.join("driver.inf")).unwrap(), f.inf);
    assert_eq!(fs::read(root.join("driver.cat")).unwrap(), CAT);
    m.cleanup().expect("cleanup");
}

// -- B6 / B7 / B8 / B9 / B10: the current pack is hostile input ---------------------

#[test]
fn b6_same_member_same_size_changed_bytes_is_payload_drift_and_never_refreshed() {
    let _g = serial();
    let f = fixture("b6", "", ONE, None, &[&[("driver.sys", SYS)]]);
    let inv = inventory(&f).expect("inventory");
    let before = inv.entries()[0].fingerprint().clone();
    let mut evil = SYS.to_vec();
    evil[3] ^= 0x55;
    assert_eq!(evil.len(), SYS.len());
    rewrite(&f, &f.inf, None, &[&[("driver.sys", &evil)]]);
    let e = fail(materialize_driver_source(&inv, &f.pkg));
    assert!(matches!(e, PME::PayloadDrift { index: 0 }), "{e:?}");
    assert!(children(&f.pkg).is_empty(), "rollback leaves nothing");
    // The inventory is never silently refreshed to accept the new bytes.
    assert_eq!(inv.entries()[0].fingerprint(), &before);
}

#[test]
fn b7_raw_archive_member_spelling_drift_is_a_stale_inventory() {
    let _g = serial();
    let f = fixture(
        "b7",
        "",
        TWO,
        None,
        &[&[("driver.sys", SYS), ("bin/Helper.dll", DLL)]],
    );
    let inv = inventory(&f).expect("inventory");
    assert_eq!(inv.entries()[1].actual_archive_member(), "bin/Helper.dll");
    // Still resolves case-insensitively, uniquely, with identical bytes.
    rewrite(
        &f,
        &f.inf,
        None,
        &[&[("driver.sys", SYS), ("bin/helper.dll", DLL)]],
    );
    test_reset_block_decode_count();
    let e = fail(materialize_driver_source(&inv, &f.pkg));
    assert!(matches!(e, PME::InventoryStale { index: 1 }), "{e:?}");
    assert!(children(&f.pkg).is_empty());
    assert_eq!(
        test_block_decode_count(),
        0,
        "stale provenance is refused before any decode"
    );
}

#[test]
fn b8_b9_missing_or_case_colliding_current_members_fail_the_whole_package() {
    let _g = serial();
    let f = fixture(
        "b8",
        "",
        TWO,
        None,
        &[&[("driver.sys", SYS), ("bin/helper.dll", DLL)]],
    );
    let inv = inventory(&f).expect("inventory");
    rewrite(&f, &f.inf, None, &[&[("driver.sys", SYS)]]);
    let e = fail(materialize_driver_source(&inv, &f.pkg));
    assert!(matches!(e, PME::PayloadMemberMissing { index: 1 }), "{e:?}");
    assert!(children(&f.pkg).is_empty());

    rewrite(
        &f,
        &f.inf,
        None,
        &[&[
            ("driver.sys", SYS),
            ("bin/helper.dll", DLL),
            ("BIN/HELPER.DLL", DLL),
        ]],
    );
    let e = fail(materialize_driver_source(&inv, &f.pkg));
    assert!(
        matches!(e, PME::PayloadMemberAmbiguous { index: 1, .. }),
        "{e:?}"
    );
    assert!(children(&f.pkg).is_empty());

    fs::remove_file(&f.pack_path).unwrap();
    let e = fail(materialize_driver_source(&inv, &f.pkg));
    assert!(matches!(e, PME::PackChangedSinceInventory), "{e:?}");
    assert!(children(&f.pkg).is_empty());
}

#[test]
fn b10_a_corrupt_payload_stream_rolls_back_and_is_an_archive_error() {
    let _g = serial();
    let payload: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(31) >> 3) as u8)
        .collect();
    let f = fixture("b10", "", ONE, None, &[&[("driver.sys", &payload)]]);
    let inv = inventory(&f).expect("inventory");
    // Same layout and length; only the decode/CRC contract can reject it.
    write_archive(&f.pack_path, &[&[("driver.sys", &payload)]]);
    let mut bytes = fs::read(&f.pack_path).unwrap();
    let packed_len = u64::from_le_bytes(bytes[12..20].try_into().unwrap()) as usize;
    bytes[32 + packed_len / 2] ^= 0xFF;
    fs::write(&f.pack_path, &bytes).unwrap();
    let e = fail(materialize_driver_source(&inv, &f.pkg));
    assert!(matches!(e, PME::Archive(_)), "{e:?}");
    assert!(
        children(&f.pkg).is_empty(),
        "no success capability, no residue"
    );
}

// -- B11 / B12: the committed 11a planner decides collisions before any root ---------

#[test]
fn b11_b12_payload_named_like_the_root_inf_or_catalog_fails_before_root_creation() {
    let _g = serial();
    let f = fixture("b11", "", SELF_INF, None, &[]);
    let inv = inventory(&f).expect("inventory");
    test_reset_block_decode_count();
    let e = fail(materialize_driver_source(&inv, &f.pkg));
    assert!(matches!(e, PME::PathCollision { .. }), "{e:?}");
    assert!(children(&f.pkg).is_empty(), "no package root was created");
    assert_eq!(test_block_decode_count(), 0);

    let f = fixture("b12", "", SELF_CAT, Some(CAT), &[]);
    let inv = inventory(&f).expect("inventory");
    let e = fail(materialize_driver_source(&inv, &f.pkg));
    assert!(matches!(e, PME::PathCollision { .. }), "{e:?}");
    assert!(children(&f.pkg).is_empty());
}

// -- B13 / B14: attestation brackets every filesystem write --------------------------

#[test]
fn b13_b14_pre_and_post_attestation_bracket_the_population_and_fail_closed() {
    let _g = serial();
    let f = fixture("b13", "", ONE, Some(CAT), &[&[("driver.sys", SYS)]]);
    let inv = inventory(&f).expect("inventory");
    fs::create_dir(f.pkg.join("sibling")).unwrap();
    test_reset_block_decode_count();

    // Pre-attestation fails: no root, no destination, no archive decode.
    let saw_no_root = Cell::new(false);
    let r = test_materialize_with_attestation(
        &inv,
        &f.pkg,
        &mut || {
            saw_no_root.set(children(&f.pkg) == ["sibling"]);
            Err(TrustError::StagedBytesChanged)
        },
        &mut || Ok(()),
    );
    assert!(matches!(r, Err(PME::Attestation(_))));
    assert!(saw_no_root.get());
    assert_eq!(children(&f.pkg), ["sibling"]);
    assert_eq!(test_block_decode_count(), 0);

    // Post-attestation fails after a COMPLETE population: nothing succeeds and
    // exactly the owned tree is removed; the staging root and sibling survive.
    let saw_tree = Cell::new(false);
    let r = test_materialize_with_attestation(&inv, &f.pkg, &mut || Ok(()), &mut || {
        saw_tree.set(children(&f.pkg).len() == 2);
        Err(TrustError::StagedBytesChanged)
    });
    assert!(matches!(r, Err(PME::Attestation(_))));
    assert!(saw_tree.get(), "post ran after the tree was fully built");
    assert_eq!(children(&f.pkg), ["sibling"]);
    assert!(f.pkg.is_dir());
}

// -- B17 / B18 / B19 / B20: one-pass traversal and unchanged accounting ---------------

#[test]
fn b17_b18_a_shared_solid_block_is_decoded_once_and_unrelated_blocks_never() {
    let _g = serial();
    let f = fixture(
        "b17",
        "",
        TWO,
        None,
        &[
            &[("driver.sys", SYS), ("bin/helper.dll", DLL)],
            &[("unrelated.bin", FILLER)],
        ],
    );
    let inv = inventory(&f).expect("inventory");
    test_reset_block_decode_count();
    let m = materialize_driver_source(&inv, &f.pkg).expect("materialize");
    assert_eq!(
        test_block_decode_count(),
        1,
        "one traversal for two payloads"
    );
    m.cleanup().expect("cleanup");

    let f = fixture(
        "b18",
        "",
        TWO,
        None,
        &[
            &[("driver.sys", SYS)],
            &[("unrelated.bin", FILLER)],
            &[("bin/helper.dll", DLL)],
        ],
    );
    let inv = inventory(&f).expect("inventory");
    test_reset_block_decode_count();
    let m = materialize_driver_source(&inv, &f.pkg).expect("materialize");
    assert_eq!(
        test_block_decode_count(),
        2,
        "the unrelated middle block is skipped"
    );
    m.cleanup().expect("cleanup");
}

#[test]
fn b19_solid_prerequisites_are_charged_exactly_as_the_inventory_charged_them() {
    let _g = serial();
    let f = fixture(
        "b19",
        "",
        ONE,
        None,
        &[&[("prereq.bin", FILLER), ("driver.sys", SYS)]],
    );
    let inv = inventory(&f).expect("inventory");
    let m = materialize_driver_source(&inv, &f.pkg).expect("materialize");
    let payload_bytes: u64 = m.files()[1..].iter().map(|x| x.size_bytes()).sum();
    assert_eq!(m.decode_bytes(), inv.decode_bytes());
    assert_eq!(m.declared_decode_bytes(), inv.declared_decode_bytes());
    assert_eq!(m.decode_bytes(), (FILLER.len() + SYS.len()) as u64);
    assert!(
        m.decode_bytes() > payload_bytes,
        "the prerequisite is charged"
    );
    m.cleanup().expect("cleanup");
}

#[test]
fn b20_public_order_is_inventory_order_not_archive_or_block_order() {
    let _g = serial();
    let f = fixture(
        "b20",
        "",
        TWO_REVERSED,
        None,
        &[&[("driver.sys", SYS)], &[("bin/helper.dll", DLL)]],
    );
    let inv = inventory(&f).expect("inventory");
    let order: Vec<_> = inv.entries().iter().map(|e| e.source_path()).collect();
    assert_eq!(
        order,
        ["bin/helper.dll", "driver.sys"],
        "precondition: INF order"
    );
    let m = materialize_driver_source(&inv, &f.pkg).expect("materialize");
    let got: Vec<_> = m.files()[1..].iter().map(|x| x.relative_path()).collect();
    assert_eq!(
        got, order,
        "the archive decodes driver.sys first; metadata does not follow"
    );
    m.cleanup().expect("cleanup");
}

// -- B21 / B25: continuity and rollback of a partial population ------------------------

#[test]
fn b21_reattest_detects_a_destination_mutation_that_keeps_identity() {
    let _g = serial();
    let f = fixture("b21", "", ONE, Some(CAT), &[&[("driver.sys", SYS)]]);
    let inv = inventory(&f).expect("inventory");
    let m = materialize_driver_source(&inv, &f.pkg).expect("materialize");
    m.reattest().expect("baseline holds");
    assert!(test_write_through_retained_handle(&m, 2, 0, b'X'));
    let e = m.reattest().expect_err("mutated payload");
    assert!(matches!(e, PME::PackageChanged { .. }), "{e:?}");
    m.cleanup().expect("the same object is still removable");
}

#[test]
fn b25_failure_after_inf_cat_and_earlier_payloads_rolls_back_exactly_the_owned_tree() {
    let _g = serial();
    let f = fixture(
        "b25",
        "",
        THREE,
        Some(CAT),
        &[
            &[("bin/driver.sys", SYS)],
            &[("co/helper.dll", DLL)],
            &[("deep/a/b/file.dat", DAT)],
        ],
    );
    let inv = inventory(&f).expect("inventory");
    let mut evil = DAT.to_vec();
    evil[0] ^= 1;
    rewrite(
        &f,
        &f.inf,
        Some(CAT),
        &[
            &[("bin/driver.sys", SYS)],
            &[("co/helper.dll", DLL)],
            &[("deep/a/b/file.dat", &evil)],
        ],
    );
    fs::create_dir(f.pkg.join("sibling")).unwrap();
    fs::write(f.pkg.join("sibling").join("keep.txt"), b"keep").unwrap();
    let e = fail(materialize_driver_source(&inv, &f.pkg));
    assert!(matches!(e, PME::PayloadDrift { index: 2 }), "{e:?}");
    assert_eq!(
        children(&f.pkg),
        ["sibling"],
        "root, dirs and files all removed"
    );
    assert_eq!(fs::read(f.pkg.join("sibling/keep.txt")).unwrap(), b"keep");
}

// -- Streaming substrate: seal binds the destination, not the producer's claim ---------

#[test]
fn b15_seal_holds_the_destination_to_the_claim_and_a_lying_producer_is_refused() {
    let _g = serial();
    let root = unique_root("seal");
    fs::create_dir_all(&root).unwrap();
    let _tmp = TempDir(root.clone());
    let stage = fs::canonicalize(&root).unwrap();
    let pieces = |_slot: usize| vec![b"abc".to_vec(), b"def".to_vec(), b"g".to_vec()];

    // Honest: chunks accumulate and the baseline is the real digest.
    let t = test_build_tree_streamed(&[], &["a.bin"], &stage, &pieces, &|_, len, sha| (len, sha))
        .expect("honest producer");
    let (len, sha) = t.baseline(0).unwrap();
    assert_eq!(len, 7);
    t.reattest().expect("reattest");
    t.cleanup().expect("cleanup");

    // The producer claims a different digest, or a different length, than the
    // bytes the destination handle actually holds: refused, and rolled back.
    for lie in [
        (len, {
            let mut s = sha;
            s[0] ^= 1;
            s
        }),
        (len + 1, sha),
        (len - 1, sha),
    ] {
        let r = test_build_tree_streamed(&[], &["a.bin"], &stage, &pieces, &|_, _, _| lie);
        assert!(
            matches!(r, Err(PackageTreeError::PackageChanged { .. })),
            "{:?}",
            r.err()
        );
        assert!(
            children(&stage).is_empty(),
            "a refused seal leaves no residue"
        );
    }
}

// -- Structural guards (B26 / B29) ------------------------------------------------------

fn code_of(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/sdio")
        .join(rel);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
    // Code only: prose in comments may name what is forbidden.
    text.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn b26_no_whole_payload_buffering_and_no_path_copy_in_package_data_flow() {
    let code = code_of("package_materialization.rs");
    for needle in [
        "read_to_end",
        "read_to_string",
        "fs::copy",
        "fs::read(",
        "fs::write",
        "Vec::with_capacity",
        "vec![",
        "extend_from_slice",
        "remove_dir_all",
        "File::create",
    ] {
        assert!(
            !code.contains(needle),
            "materialization must not use {needle}"
        );
    }
    let tree = code_of("package_tree/tree.rs");
    for needle in ["remove_dir_all", "read_to_end", "fs::copy"] {
        assert!(!tree.contains(needle), "tree must not use {needle}");
    }
}

#[test]
fn b29_no_installation_no_driver_store_no_device_mutation() {
    let code = code_of("package_materialization.rs");
    for needle in [
        "pnputil",
        "SetupCopyOEMInf",
        "DiInstallDriver",
        "UpdateDriverForPlugAndPlayDevices",
        "SRSetRestorePoint",
        "Command::new",
        "SetupDi",
        "DriverStore",
    ] {
        assert!(!code.contains(needle), "11b must not touch {needle}");
    }
}

#[test]
fn b34_off_windows_secure_population_is_platform_unsupported() {
    // This host cannot compile the non-Windows arm, so it is pinned structurally.
    let code = code_of("package_materialization.rs");
    assert!(code.contains("#[cfg(not(windows))]"));
    assert!(code.contains("PackageMaterializationError::PlatformUnsupported"));
}
