// Integration tests for Tab 2a-9: actual-INF source manifest.
//
// Every INF is interpreted by the REAL Windows SetupAPI against a live
// `VerifiedDriverPackage` built through the existing test-only trust seam and
// the real 2a-6 materialization path: only the trust RESULT is injected; the
// staged bytes, namespace pins, file locks and native parse are all real.
//
// Native execution is x64 only: SetupAPI picks architecture-decorated sections
// from the running platform, so a synthetic `.arm64`/`.x86` fixture here would
// not prove a native ARM64/x86 lookup and is not claimed (NOT EXECUTED).
#![cfg(all(windows, target_arch = "x86_64"))]

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use mod_drivers::sdio::Candidate;
use mod_drivers::sdio::applicability::{
    ApplicabilityReason, AssessedCatalogCandidate, AssessedDeviceMatches,
    CatalogApplicabilityEvidence, CatalogOsApplicability,
};
use mod_drivers::sdio::extraction::materialize_inf;
use mod_drivers::sdio::install_plan::InstallPlanBuilder;
use mod_drivers::sdio::local_pack::{
    LocalPackAvailability, PackageMaterializationRequest, resolve_local_pack,
};
use mod_drivers::sdio::matching::{CatalogCandidateMatch, DeviceIdKind, MatchEvidence};
use mod_drivers::sdio::signature::{
    DriverPackageVerifier, TrustError, TrustResult, VerifiedDriverPackage,
};
use mod_drivers::sdio::source_manifest::{
    BoundKind, MAX_COPYFILES_REFERENCES, MAX_FIELDS_PER_LINE, MAX_LINES_INSPECTED,
    MAX_NATIVE_RETRIES, MAX_SECTIONS_INSPECTED, MAX_UNIQUE_SOURCE_FILES, PathReject,
    SourceManifest, SourceManifestError as E, UnsupportedReason as U, derive_source_manifest,
    test_bounded_native_string, test_checked_charge, test_derive_with_attestation,
    test_native_open_calls, test_normalize_source_path, test_open_inf_handles,
};
use sevenz_rust2::ArchiveWriter;

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

/// Native-call and open-handle counters are process-global: native tests run
/// one at a time.
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

/// A live verified token plus its directories. `token` is declared first so it
/// drops (releasing its locks and pins) before the temp tree goes.
struct Fixture {
    token: VerifiedDriverPackage,
    staging: PathBuf,
    drivers: PathBuf,
    _tmp: TempDir,
}

const HEADER: &str = "[Version]\nSignature=\"$WINDOWS NT$\"\nClass=System\n\
    ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\nProvider=%Mfg%\n\
    DriverVer=01/01/2024,1.0.0.0\n\n[Strings]\nMfg=\"Cove\"\nDisk=\"Disk\"\n\n";
/// Disk 1 with an empty source path.
const D1: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n";

fn fixture_bytes(tag: &str, inf: &[u8]) -> Fixture {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("cove_tab2a9_{tag}_{}_{nanos}", std::process::id()));
    let (drivers, staging) = (root.join("drivers"), root.join("staging"));
    fs::create_dir_all(&drivers).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let tmp = TempDir(root);
    let req = make_pack(&drivers, inf);
    let artifact = materialize_inf(&req, &staging).expect("materialize");
    let token = DriverPackageVerifier::with_check_fn(|_| TrustResult::Trusted {
        catalog_name: String::new(),
        signer: None,
        reported_catalog_path: None,
    })
    .verify(artifact)
    .expect("verify must produce a live token");
    Fixture {
        token,
        staging,
        drivers,
        _tmp: tmp,
    }
}

/// SetupAPI expects CRLF; fixtures are written with `\n`.
fn fixture(tag: &str, body: &str) -> Fixture {
    fixture_bytes(
        tag,
        format!("{HEADER}{body}").replace('\n', "\r\n").as_bytes(),
    )
}

fn make_pack(root: &Path, inf: &[u8]) -> PackageMaterializationRequest {
    let file = fs::File::create(root.join("fake_pack.7z")).expect("create archive");
    let mut writer = ArchiveWriter::new(std::io::BufWriter::new(file)).expect("writer");
    let entry = sevenz_rust2::ArchiveEntry::new_file("driver.inf");
    writer
        .push_archive_entry(entry, Some(std::io::Cursor::new(inf.to_vec())))
        .expect("push entry");
    let _ = writer.finish().expect("finish archive");
    match resolve_local_pack(root, &candidate()).expect("resolve_local_pack") {
        LocalPackAvailability::Present(req) => req,
        LocalPackAvailability::Missing { .. } => panic!("pack missing"),
    }
}

fn candidate() -> CatalogCandidateMatch {
    CatalogCandidateMatch {
        pack_name: "fake_pack".into(),
        candidate: Candidate {
            inf_path: String::new(),
            inf_filename: "driver.inf".into(),
            provider: None,
            class: None,
            class_guid: None,
            catalog_file: None,
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

fn derive<'v>(f: &'v Fixture, section: &str) -> SourceManifest<'v> {
    derive_source_manifest(&f.token, section)
}

fn paths(m: &SourceManifest<'_>) -> Vec<String> {
    match m {
        SourceManifest::ResolvedReferences(r) => r
            .references()
            .iter()
            .map(|x| x.source_path().to_string())
            .collect(),
        other => panic!("expected ResolvedReferences, got {other:?}"),
    }
}

fn refused(m: &SourceManifest<'_>) -> U {
    match m {
        SourceManifest::Unsupported(r) => *r,
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// Serialized one-shot helpers for tests that hold no counter state.
fn sources(tag: &str, body: &str) -> Vec<String> {
    let _g = serial();
    let f = fixture(tag, body);
    paths(&derive(&f, "Install"))
}

fn refusal(tag: &str, body: &str) -> U {
    let _g = serial();
    let f = fixture(tag, body);
    refused(&derive(&f, "Install"))
}

fn bound(tag: &str, body: &str) -> Option<BoundKind> {
    let _g = serial();
    let f = fixture(tag, body);
    match derive(&f, "Install") {
        SourceManifest::Error(E::Bound(k)) => Some(k),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// R1 / R2 - direct + named CopyFiles; source differs from destination
// ---------------------------------------------------------------------------

#[test]
fn r1_direct_and_named_copyfiles_resolve_with_provenance() {
    let _g = serial();
    let f = fixture(
        "r1",
        &format!(
            "{D1}[SourceDisksFiles]\ndirect.sys = 1\nlisted.dll = 1,bin\n\n\
             [Install.NTamd64]\nCopyFiles = @direct.sys, Named.Copy\n\n[Named.Copy]\nlisted.dll\n"
        ),
    );
    let m = derive(&f, "Install");
    assert_eq!(paths(&m), ["direct.sys", "bin/listed.dll"]);
    let SourceManifest::ResolvedReferences(r) = &m else {
        unreachable!()
    };
    let (d, l) = (
        &r.references()[0].provenance()[0],
        &r.references()[1].provenance()[0],
    );
    assert_eq!(
        (d.section.as_str(), d.direct, d.destination_name.as_str()),
        ("Install.NTamd64", true, "direct.sys")
    );
    assert_eq!((l.section.as_str(), l.direct), ("Named.Copy", false));
}

#[test]
fn r2_source_differs_from_destination() {
    let _g = serial();
    // `dest_name.sys` is NOT defined in SourceDisksFiles: a destination-keyed
    // lookup cannot resolve it, only the source name can.
    let f = fixture(
        "r2",
        &format!(
            "{D1}[SourceDisksFiles]\nsrcname.sys = 1\n\n\
             [Install.NTamd64]\nCopyFiles = Renamed.Copy\n\n[Renamed.Copy]\ndest_name.sys, srcname.sys\n"
        ),
    );
    let m = derive(&f, "Install");
    assert_eq!(paths(&m), ["srcname.sys"]);
    let SourceManifest::ResolvedReferences(r) = &m else {
        unreachable!()
    };
    assert_eq!(
        r.references()[0].provenance()[0].destination_name,
        "dest_name.sys"
    );
}

// ---------------------------------------------------------------------------
// R3 / R4 / R5 - architecture lookup, path composition, disk id
// ---------------------------------------------------------------------------

#[test]
fn r3_arch_definition_beats_generic_and_generic_is_the_fallback() {
    // A generic-only file still resolves; its disk path comes from the amd64 names.
    assert_eq!(
        sources(
            "r3",
            "[SourceDisksNames]\n1 = %Disk%,,,\\generic_root\n\n\
             [SourceDisksNames.amd64]\n1 = %Disk%,,,\\arch_root\n\n\
             [SourceDisksFiles]\ngeneric_only.sys = 1,gsub\nboth.sys = 1,generic_sub\n\n\
             [SourceDisksFiles.amd64]\narch_only.sys = 1,asub\nboth.sys = 1,arch_sub\n\n\
             [Install.NTamd64]\nCopyFiles = L\n\n[L]\narch_only.sys\nboth.sys\ngeneric_only.sys\n",
        ),
        [
            "arch_root/asub/arch_only.sys",
            "arch_root/arch_sub/both.sys",
            "arch_root/gsub/generic_only.sys"
        ]
    );
}

#[test]
fn r4_source_path_composed_exactly_once() {
    assert_eq!(
        sources(
            "r4",
            "[SourceDisksNames]\n1 = %Disk%,,,\\rootrel\n2 = %Disk%,,,plainrel\n\n\
             [SourceDisksFiles]\na.sys = 1,sub\nb.sys = 2,sub\nc.sys = 1\n\n\
             [Install.NTamd64]\nCopyFiles = L\n\n[L]\na.sys\nb.sys\nc.sys\n",
        ),
        ["rootrel/sub/a.sys", "plainrel/sub/b.sys", "rootrel/c.sys"]
    );
    for (media, sub, want) in [
        ("", "", "a.sys"),
        ("\\x64", "", "x64/a.sys"),
        ("\\", "sub", "sub/a.sys"),
        ("plain", "sub", "plain/sub/a.sys"),
        ("x64\\", "", "x64/a.sys"),
        ("a\\b", "c\\d", "a/b/c/d/a.sys"),
    ] {
        assert_eq!(
            test_normalize_source_path(media, sub, "a.sys").as_deref(),
            Ok(want)
        );
    }
}

#[test]
fn r5_disk_id_two_is_a_valid_local_source() {
    let _g = serial();
    let f = fixture(
        "r5",
        "[SourceDisksNames]\n1 = %Disk%,,,\n2 = %Disk%,,,disk2\n\n\
         [SourceDisksFiles]\nd.sys = 2\n\n[Install.NTamd64]\nCopyFiles = @d.sys\n",
    );
    let m = derive(&f, "Install");
    assert_eq!(paths(&m), ["disk2/d.sys"]);
    let SourceManifest::ResolvedReferences(r) = &m else {
        unreachable!()
    };
    assert_eq!(r.references()[0].disk_id(), 2);
}

// ---------------------------------------------------------------------------
// R6 - documented media-relative form accepted, hostile forms fail closed
// ---------------------------------------------------------------------------

#[test]
fn r6_hostile_media_paths_fail_closed_natively() {
    for hostile in [
        "\\\\server\\share",
        "\\\\?\\C:\\x",
        "C:\\x",
        "..\\up",
        "a\\..\\b",
        "\\..\\up",
    ] {
        let body = format!(
            "[SourceDisksNames]\n1 = %Disk%,,,{hostile}\n\n[SourceDisksFiles]\nx.sys = 1\n\n[Install.NTamd64]\nCopyFiles = @x.sys\n"
        );
        assert_eq!(
            refusal("r6", &body),
            U::UnsafeSourceMediaPath,
            "{hostile:?}"
        );
    }
    for entry in ["@..\\evil.sys", "@sub\\x.sys"] {
        let body = format!("[Install.NTamd64]\nCopyFiles = {entry}\n");
        assert_eq!(refusal("r6f", &body), U::UnsafeFileName, "{entry:?}");
    }
}

#[test]
fn r6_pure_hostile_matrix_and_path_bounds() {
    for hostile in [
        "\\\\server\\share",
        "\\\\?\\C:\\x",
        "C:\\x",
        "C:x",
        "..\\x",
        "a\\..\\b",
        "\\..",
        ".",
        "a\\.\\b",
        "a/b",
        "a:$DATA",
        "NUL",
        "con\\x",
        "aux.txt",
        "a.",
        "a ",
        "a\\\\b",
        "a\0b",
        "a<b",
    ] {
        assert_eq!(
            test_normalize_source_path(hostile, "", "f.sys"),
            Err(PathReject::Unsafe),
            "{hostile:?}"
        );
    }
    // A leading separator on the SUBDIRECTORY is ambiguous, not media-root form.
    assert_eq!(
        test_normalize_source_path("", "\\sub", "f.sys"),
        Err(PathReject::Unsafe)
    );
    for file in ["", "..", "a\\b.sys", "a/b.sys", "C:f.sys", "NUL", "f."] {
        assert_eq!(
            test_normalize_source_path("", "", file),
            Err(PathReject::Unsafe),
            "{file:?}"
        );
    }
    let bounded = |media: &str| test_normalize_source_path(media, "", "f.sys");
    assert_eq!(
        bounded(&vec!["a"; 65].join("\\")),
        Err(PathReject::Bound(BoundKind::PathComponents))
    );
    assert_eq!(
        bounded(&"a".repeat(256)),
        Err(PathReject::Bound(BoundKind::ComponentLength))
    );
    assert_eq!(
        bounded(&vec!["a".repeat(255); 40].join("\\")),
        Err(PathReject::Bound(BoundKind::SourcePathLength))
    );
    assert!(
        bounded(&"a".repeat(255)).is_ok(),
        "exactly at the component cap is accepted"
    );
}

// ---------------------------------------------------------------------------
// R7 / R8 / R9 / R10 - scope, distinct results, unsupported, missing/ambiguous
// ---------------------------------------------------------------------------

#[test]
fn r7_coinstaller_copyfiles_resolve_and_out_of_scope_relationships_are_never_omitted() {
    let files =
        "[SourceDisksNames]\n1 = %Disk%,,,\n\n[SourceDisksFiles]\nmain.sys = 1\nextra.dll = 1\n\n";
    let with = |sub: &str| {
        format!(
            "{files}[Install.NTamd64]\nCopyFiles = M\n\n[Install.NTamd64.{sub}]\nCopyFiles = X\n\n[M]\nmain.sys\n\n[X]\nextra.dll\n"
        )
    };
    assert_eq!(
        sources("r7a", &with("CoInstallers")),
        ["main.sys", "extra.dll"]
    );
    // Same shape in a subsection v1 does not traverse: never a "resolved" result.
    assert_eq!(
        refusal("r7b", &with("Software")),
        U::UnsupportedSubsection("Software")
    );
}

#[test]
fn r8_no_copyfiles_missing_sections_and_invalid_names() {
    let _g = serial();
    let f = fixture(
        "r8a",
        "[Install.NTamd64]\nAddReg = Reg\n\n[Reg]\nHKR,,Value,,1\n",
    );
    assert!(matches!(
        derive(&f, "Install"),
        SourceManifest::NoCopyFiles(_)
    ));
    assert_eq!(
        refused(&derive(&f, "NoSuchInstallSection")),
        U::InstallSectionMissing
    );
    let long = "s".repeat(300);
    for bad in ["", "a\0b", long.as_str()] {
        assert!(matches!(
            derive(&f, bad),
            SourceManifest::Error(E::InvalidInstallSectionName)
        ));
    }
    drop(_g);
    // A missing referenced list must not be mistaken for "no CopyFiles".
    let body = "[Install.NTamd64]\nCopyFiles = Absent.Copy\n";
    assert_eq!(refusal("r8b", body), U::MissingCopySection);
}

#[test]
fn r9_unsupported_matrix_is_never_resolved() {
    let files = "[SourceDisksFiles]\na.sys = 1\n\n";
    let cases: Vec<(String, U)> = vec![
        (format!("{D1}{files}[Install.NTamd64]\nInclude = o.inf\nNeeds = O.Install\nCopyFiles = @a.sys\n"), U::IncludeNeeds),
        ("[Install.NTamd64]\nCopyINF = other.inf\n".into(), U::CopyInf),
        (format!("[SourceDisksNames]\n1 = %Disk%,driver.cab,,\n\n{files}[Install.NTamd64]\nCopyFiles = @a.sys\n"), U::ExternalMedia),
        ("[Install.NTamd64]\nAddReg = R\n\n[Install.NTamd64.Components]\nAddComponent = C\n\n[R]\nHKR,,V,,1\n".into(), U::UnsupportedSubsection("Components")),
        ("[Install.NTamd64]\nAddReg = R\n\n[InterfaceInstall32]\n{00000000-0000-0000-0000-000000000000} = I\n\n[I]\nAddReg = R\n\n[R]\nHKR,,V,,1\n".into(), U::UnsupportedSubsection("InterfaceInstall32")),
        (format!("{D1}{files}[Install.NTamd64]\nCopyFiles = L\n\n[L]\nkeyed = 1\n"), U::KeyedFileListLine),
        (format!("{D1}{files}[Install.NTamd64]\nCopyFiles = L\n\n[L]\na.sys\n\n[L.NTamd64]\na.sys\n"), U::DecoratedFileListSection),
    ];
    for (i, (body, want)) in cases.iter().enumerate() {
        assert_eq!(refusal(&format!("r9_{i}"), body), *want, "case {i}");
    }
}

/// Review-2 finding 2, characterized: SetupAPI cannot tell `a.sys = a.sys` from
/// the keyless `a.sys` (same field count, same field 0, same line text), and it
/// copies both identically, so both resolve the same; a key that DIFFERS from
/// the first field is still refused (r9 `keyed = 1`).
#[test]
fn r9_equal_key_line_is_the_same_as_the_keyless_form() {
    let body = format!(
        "{D1}[SourceDisksFiles]\na.sys = 1\nb.sys = 1\n\n\
         [Install.NTamd64]\nCopyFiles = L\n\n[L]\na.sys = a.sys\nb.sys\n"
    );
    assert_eq!(sources("r9_eq", &body), ["a.sys", "b.sys"]);
}

#[test]
fn r10_missing_and_ambiguous_definitions_are_never_guessed() {
    let install = "[Install.NTamd64]\nCopyFiles = @dup.sys\n";
    let cases = [
        (
            format!("{D1}[SourceDisksFiles]\nother.sys = 1\n\n{install}"),
            U::MissingSourceDefinition,
        ),
        // Two definitions in one section: not first-entry-wins.
        (
            format!("{D1}[SourceDisksFiles]\ndup.sys = 1,first\ndup.sys = 1,second\n\n{install}"),
            U::AmbiguousSourceDefinition,
        ),
        (
            format!(
                "{D1}[SourceDisksFiles.amd64]\ndup.sys = 1,first\ndup.sys = 1,second\n\n{install}"
            ),
            U::AmbiguousSourceDefinition,
        ),
    ];
    for (i, (body, want)) in cases.iter().enumerate() {
        assert_eq!(refusal(&format!("r10_{i}"), body), *want, "case {i}");
    }
}

/// Review-1 finding 1: documented `\subdir` syntax (SetupAPI returns the
/// subdirectory without leading/trailing separators) is not "ambiguous".
#[test]
fn r10_documented_subdir_separator_forms_resolve() {
    let body = format!(
        "{D1}[SourceDisksFiles]\nlead.sys = 1,\\x86\ntrail.sys = 1,tsub\\,\nboth.sys = 1,\\a\\b\\,\n\n\
         [Install.NTamd64]\nCopyFiles = @lead.sys, @trail.sys, @both.sys\n"
    );
    assert_eq!(
        sources("r10_sep", &body),
        ["x86/lead.sys", "tsub/trail.sys", "a/b/both.sys"]
    );
}

/// Review-1 finding 2: a hostile over-wide SourceDisksFiles line obeys the
/// same field bound as every other interpreted line.
#[test]
fn r10_source_definition_line_obeys_the_field_bound() {
    let wide = (0..=MAX_FIELDS_PER_LINE)
        .map(|i| format!("f{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        "{D1}[SourceDisksFiles]\nover.sys = 1,sub,{wide}\n\n[Install.NTamd64]\nCopyFiles = @over.sys\n"
    );
    assert_eq!(bound("r10_wide", &body), Some(BoundKind::FieldsPerLine));
}

/// Review-3 finding: the SourceDisksNames line SetupAPI resolved a disk id
/// from obeys the same field bound, and a duplicate disk id is ambiguous
/// rather than first-entry-wins.
#[test]
fn r10_source_disks_names_line_is_bounded_and_unambiguous() {
    let wide = "x,".repeat(MAX_FIELDS_PER_LINE + 2);
    let files = "[SourceDisksFiles]\na.sys = 1\n\n[Install.NTamd64]\nCopyFiles = @a.sys\n";
    let over = format!("[SourceDisksNames]\n1 = %Disk%,,,,,,{wide}\n\n{files}");
    assert_eq!(
        bound("r10_names_wide", &over),
        Some(BoundKind::FieldsPerLine)
    );
    let dup = format!("[SourceDisksNames]\n1 = %Disk%,,,first\n1 = %Disk%,,,second\n\n{files}");
    assert_eq!(refusal("r10_names_dup", &dup), U::AmbiguousSourceDefinition);
}

// ---------------------------------------------------------------------------
// R11 - native allocation and accounting bounds (production helpers)
// ---------------------------------------------------------------------------

/// Native fake that always claims `required` units and never fits; records the
/// size of every buffer it is offered.
fn lying(
    required: u32,
    seen: &RefCell<Vec<usize>>,
) -> impl FnMut(&mut [u16]) -> (bool, u32, u32) + '_ {
    move |buf| {
        seen.borrow_mut().push(buf.len());
        (false, required, 122)
    }
}

#[test]
fn r11_native_string_cap_boundary_and_required_size_abuse() {
    let cap = 512usize;
    let mut at_cap = |buf: &mut [u16]| {
        if buf.len() < cap {
            return (false, cap as u32, 122);
        }
        buf[..cap - 1].fill(b'a' as u16);
        buf[cap - 1] = 0;
        (true, cap as u32, 0)
    };
    assert_eq!(
        test_bounded_native_string(cap, &mut at_cap).unwrap().len(),
        cap - 1
    );

    // cap + 1 and hostile RequiredSize values: refused, and no buffer above
    // the cap is ever offered (RequiredSize never drives allocation).
    for required in [cap as u32 + 1, u32::MAX, u32::MAX - 1, 0x8000_0000, 1 << 20] {
        let seen = RefCell::new(Vec::new());
        assert_eq!(
            test_bounded_native_string(cap, &mut lying(required, &seen)),
            Err(E::Bound(BoundKind::NativeStringUnits)),
            "required={required}"
        );
        assert!(
            seen.borrow().iter().all(|&n| n <= cap),
            "{:?}",
            seen.borrow()
        );
    }
}

#[test]
fn r11_native_retries_and_inconsistent_replies() {
    // A plausible size that never fits: initial call plus MAX_NATIVE_RETRIES only.
    let seen = RefCell::new(Vec::new());
    assert_eq!(
        test_bounded_native_string(1024, &mut lying(600, &seen)),
        Err(E::Bound(BoundKind::NativeRetries))
    );
    assert_eq!(seen.borrow().len(), 1 + MAX_NATIVE_RETRIES);
    // "Too small" with no size to retry with cannot be acted on.
    let seen = RefCell::new(Vec::new());
    assert!(matches!(
        test_bounded_native_string(1024, &mut lying(0, &seen)),
        Err(E::NativeCall { code: 122, .. })
    ));
    assert_eq!(seen.borrow().len(), 1);
    // Success claiming more units than the buffer holds is not trusted.
    let mut lies = |buf: &mut [u16]| (true, buf.len() as u32 + 10, 0);
    assert!(matches!(
        test_bounded_native_string(1024, &mut lies),
        Err(E::NativeCall { code: 0, .. })
    ));
    let mut fails = |_: &mut [u16]| (false, 0, 0xE000_0102);
    assert!(matches!(
        test_bounded_native_string(1024, &mut fails),
        Err(E::NativeCall {
            code: 0xE000_0102,
            ..
        })
    ));
}

#[test]
fn r11_checked_accounting_never_wraps() {
    assert_eq!(test_checked_charge(0, 5, 5), Ok(5));
    assert_eq!(test_checked_charge(4, 1, 5), Ok(5));
    assert!(test_checked_charge(5, 1, 5).is_err());
    assert!(test_checked_charge(usize::MAX, 1, usize::MAX).is_err());
    assert!(test_checked_charge(usize::MAX - 1, 5, usize::MAX).is_err());
}

#[test]
fn r11_bounds_on_real_infs() {
    let repeat = |line: &str, n: usize| line.repeat(n);
    let list = |lines: String| format!("[Install.NTamd64]\nCopyFiles = L\n\n[L]\n{lines}");
    let uniq: String = (0..=MAX_UNIQUE_SOURCE_FILES)
        .map(|i| format!("f{i}.sys\n"))
        .collect();
    let fields = (0..=MAX_FIELDS_PER_LINE)
        .map(|i| format!("L{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let names: Vec<String> = (0..MAX_SECTIONS_INSPECTED + 6)
        .map(|i| format!("S{i}"))
        .collect();
    // Ten names per line keeps each line under the field bound, so only the
    // distinct-section bound can trip.
    let many_sections: String = names
        .chunks(10)
        .map(|c| format!("CopyFiles = {}\n", c.join(", ")))
        .collect();
    let empty_sections: String = names.iter().map(|n| format!("[{n}]\n\n")).collect();
    let cases = [
        (
            list(repeat("same.sys\n", MAX_COPYFILES_REFERENCES + 1)),
            BoundKind::CopyFilesReferences,
        ),
        (list(uniq), BoundKind::UniqueSourceFiles),
        (
            format!(
                "[Install.NTamd64]\n{}\n[R]\nHKR,,V,,1\n",
                repeat("AddReg = R\n", MAX_LINES_INSPECTED + 1)
            ),
            BoundKind::Lines,
        ),
        (
            format!("[Install.NTamd64]\nCopyFiles = {fields}\n"),
            BoundKind::FieldsPerLine,
        ),
        (
            format!("[Install.NTamd64]\n{many_sections}\n{empty_sections}"),
            BoundKind::Sections,
        ),
    ];
    for (i, (body, want)) in cases.iter().enumerate() {
        assert_eq!(bound(&format!("r11_{i}"), body), Some(*want), "case {i}");
    }
}

// ---------------------------------------------------------------------------
// R12 - token lifetime and re-attestation bracketing
// ---------------------------------------------------------------------------

const SIMPLE: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n[SourceDisksFiles]\na.sys = 1\n\n\
                      [Install.NTamd64]\nCopyFiles = @a.sys\n";

fn stale() -> Result<(), TrustError> {
    Err(TrustError::StagedBytesChanged)
}

#[test]
fn r12_default_path_reattests_the_live_token_and_succeeds() {
    let _g = serial();
    let f = fixture("r12a", SIMPLE);
    // Production default (no injected attestation): the real reattest, twice.
    assert_eq!(paths(&derive(&f, "Install")), ["a.sys"]);
    assert_eq!(paths(&derive(&f, "Install")), ["a.sys"]);
    f.token
        .reattest()
        .expect("derivation must not disturb the lease");
}

#[test]
fn r12_attestation_brackets_native_interpretation() {
    let _g = serial();
    let f = fixture("r12b", SIMPLE);
    let log = RefCell::new(Vec::new());
    let mut pre = || {
        log.borrow_mut()
            .push(("pre", test_native_open_calls(), test_open_inf_handles()));
        Ok(())
    };
    let mut post = || {
        log.borrow_mut()
            .push(("post", test_native_open_calls(), test_open_inf_handles()));
        Ok(())
    };
    let m = test_derive_with_attestation(&f.token, "Install", &mut pre, &mut post);
    assert_eq!(paths(&m), ["a.sys"]);
    let log = log.borrow();
    assert_eq!(log.len(), 2, "exactly one pre and one post attestation");
    assert_eq!((log[0].0, log[1].0), ("pre", "post"));
    assert_eq!(
        log[1].1,
        log[0].1 + 1,
        "native interpretation happens BETWEEN the attestations"
    );
    assert_eq!(
        log[0].2, log[1].2,
        "the native handle is closed before the post attestation"
    );
}

#[test]
fn r12_failed_attestation_never_yields_evidence() {
    let _g = serial();
    let f = fixture("r12c", SIMPLE);
    let before = test_native_open_calls();
    let mut post_calls = 0;
    let m = test_derive_with_attestation(&f.token, "Install", &mut stale, &mut || {
        post_calls += 1;
        Ok(())
    });
    assert!(matches!(
        m,
        SourceManifest::Error(E::Attestation(TrustError::StagedBytesChanged))
    ));
    assert_eq!(
        test_native_open_calls(),
        before,
        "no native work after a failed pre-attestation"
    );
    assert_eq!(post_calls, 0);

    let m = test_derive_with_attestation(&f.token, "Install", &mut || Ok(()), &mut stale);
    assert!(
        matches!(
            m,
            SourceManifest::Error(E::Attestation(TrustError::StagedBytesChanged))
        ),
        "a failed post-attestation must never yield a manifest: {m:?}"
    );
    // ...and it outranks an Unsupported result too.
    let g = fixture("r12d", "[Install.NTamd64]\nCopyINF = x.inf\n");
    let m = test_derive_with_attestation(&g.token, "Install", &mut || Ok(()), &mut stale);
    assert!(matches!(m, SourceManifest::Error(E::Attestation(_))));
}

// ---------------------------------------------------------------------------
// R13 - the native INF handle is always closed
// ---------------------------------------------------------------------------

#[test]
fn r13_native_handle_is_closed_on_every_outcome() {
    let _g = serial();
    let baseline = test_open_inf_handles();
    let lines = "AddReg = R\n".repeat(MAX_LINES_INSPECTED + 1);
    type Expect = fn(&SourceManifest<'_>) -> bool;
    let cases: Vec<(&str, String, Expect)> = vec![
        ("ok", format!("{HEADER}{SIMPLE}"), |m| {
            matches!(m, SourceManifest::ResolvedReferences(_))
        }),
        (
            "unsupported",
            format!("{HEADER}[Install.NTamd64]\nCopyINF = x.inf\n"),
            |m| matches!(m, SourceManifest::Unsupported(_)),
        ),
        (
            "bound",
            format!("{HEADER}[Install.NTamd64]\n{lines}\n[R]\nHKR,,V,,1\n"),
            |m| matches!(m, SourceManifest::Error(E::Bound(_))),
        ),
        ("open-failure", "X".to_string(), |m| {
            matches!(m, SourceManifest::Error(E::NativeOpen { .. }))
        }),
    ];
    for (tag, inf, expect) in cases {
        let f = fixture_bytes(tag, inf.replace('\n', "\r\n").as_bytes());
        let opened = test_native_open_calls();
        assert!(expect(&derive(&f, "Install")), "{tag}");
        assert_eq!(
            test_native_open_calls(),
            opened + 1,
            "{tag}: one native open attempt"
        );
        assert_eq!(test_open_inf_handles(), baseline, "{tag}: handle closed");
    }
    // A failing post-attestation happens after the handle is closed.
    let f = fixture("r13e", SIMPLE);
    let _ = test_derive_with_attestation(&f.token, "Install", &mut || Ok(()), &mut stale);
    assert_eq!(test_open_inf_handles(), baseline);
}

// ---------------------------------------------------------------------------
// R14 - end to end through the established trusted-package construction
// ---------------------------------------------------------------------------

const REALISTIC: &str = "[Version]\nSignature=\"$WINDOWS NT$\"\nClass=System\n\
ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\nProvider=%Mfg%\nDriverVer=01/01/2024,1.0.0.0\n\n\
[SourceDisksNames]\n1 = %Disk%,,,\\x64\n2 = %Disk%,,,extras\n\n\
[SourceDisksNames.amd64]\n1 = %Disk%,,,\\x64\n\n\
[SourceDisksFiles]\ncovedrv.sys = 1\ncoveco.dll = 1,coinst\nsupport.dll = 2\n\n\
[DestinationDirs]\nDefaultDestDir = 12\nCoveCo.Copy = 11\n\n\
[Manufacturer]\n%Mfg% = Models,NTamd64\n\n\
[Models.NTamd64]\n%Dev% = Cove_Install, ROOT\\COVETEST\n\n\
[Cove_Install.NTamd64]\nCopyFiles = Cove.Copy, @support.dll\nAddReg = Cove.AddReg\n\n\
[Cove_Install.NTamd64.CoInstallers]\nCopyFiles = CoveCo.Copy\nAddReg = CoveCo.AddReg\n\n\
[Cove_Install.NTamd64.Services]\nAddService = CoveSvc, 2, Cove.Service\n\n\
[Cove.Copy]\ncovedrv.sys\n\n[CoveCo.Copy]\ncoveco.dll\n\n\
[Cove.Service]\nServiceType = 1\nStartType = 3\nErrorControl = 1\nServiceBinary = %12%\\covedrv.sys\n\n\
[Cove.AddReg]\nHKR,,Flag,0x10001,1\n\n[CoveCo.AddReg]\nHKR,,CoInstallers32,0x10000,\"coveco.dll,Entry\"\n\n\
[Strings]\nMfg=\"Cove\"\nDisk=\"Disk\"\nDev=\"Cove Test Device\"\n";

#[test]
fn r14_end_to_end_real_native_parse_of_a_realistic_inf() {
    let _g = serial();
    let f = fixture_bytes("r14", REALISTIC.replace('\n', "\r\n").as_bytes());
    let m = derive(&f, "Cove_Install");
    assert_eq!(
        paths(&m),
        [
            "x64/covedrv.sys",
            "extras/support.dll",
            "x64/coinst/coveco.dll"
        ]
    );

    // The same derivation through an install-plan entry that borrows the token.
    let device = AssessedDeviceMatches {
        instance_id: "DEV1".into(),
        candidates: vec![AssessedCatalogCandidate {
            matched: candidate(),
            os: CatalogApplicabilityEvidence {
                models_section: None,
                target: None,
                status: CatalogOsApplicability::HostCompatible,
                reason: ApplicabilityReason::TargetSatisfied,
            },
        }],
    };
    let entry = InstallPlanBuilder::new(&device, &f.drivers)
        .build(&device.candidates[0], Some(&f.token))
        .expect("build")
        .expect("ready entry");
    let via_entry = derive_source_manifest(entry.verified_package(), "Cove_Install");
    assert_eq!(paths(&via_entry), paths(&m));
}

// ---------------------------------------------------------------------------
// R15 - non-mutation, determinism, provenance, source hygiene
// ---------------------------------------------------------------------------

fn snapshot(dir: &Path) -> Vec<(String, u64, std::time::SystemTime)> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, u64, std::time::SystemTime)>) {
        for e in fs::read_dir(dir).expect("read_dir") {
            let e = e.expect("entry");
            let md = e.metadata().expect("metadata");
            let name = format!("{prefix}/{}", e.file_name().to_string_lossy());
            if md.is_dir() {
                walk(&e.path(), &name, out);
            } else {
                out.push((name, md.len(), md.modified().expect("mtime")));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, "", &mut out);
    out.sort();
    out
}

#[test]
fn r15_derivation_mutates_nothing_and_is_deterministic() {
    let _g = serial();
    let f = fixture(
        "r15",
        &format!(
            "{D1}[SourceDisksFiles]\nshared.sys = 1\nonly.dll = 1\n\n\
             [Install.NTamd64]\nCopyFiles = One.Copy, Two.Copy\n\n\
             [One.Copy]\nshared.sys\nonly.dll\n\n[Two.Copy]\nrenamed.sys, shared.sys\n"
        ),
    );
    let before = snapshot(&f.staging);
    let (first, second) = (derive(&f, "Install"), derive(&f, "Install"));
    let after = snapshot(&f.staging);
    assert_eq!(
        after, before,
        "no create, change or removal in the staging tree"
    );
    assert!(
        after
            .iter()
            .all(|(n, _, _)| !n.to_ascii_lowercase().ends_with(".pnf")),
        "no .pnf cache"
    );

    // A source named from two lists appears once, with both provenances, in order.
    assert_eq!(paths(&first), ["shared.sys", "only.dll"]);
    let (SourceManifest::ResolvedReferences(a), SourceManifest::ResolvedReferences(b)) =
        (&first, &second)
    else {
        panic!("expected resolved")
    };
    let shared = a.references()[0].provenance();
    let seen: Vec<_> = shared
        .iter()
        .map(|p| (p.section.as_str(), p.destination_name.as_str()))
        .collect();
    assert_eq!(
        seen,
        [("One.Copy", "shared.sys"), ("Two.Copy", "renamed.sys")]
    );
    assert_eq!(
        a.references(),
        b.references(),
        "ordering and provenance are deterministic"
    );
    f.token.reattest().expect("token still live and intact");
}

#[test]
fn r15_production_source_is_read_only_and_never_consumes_the_token() {
    let src = include_str!("../src/sdio/source_manifest.rs");
    for forbidden in [
        concat!("Setup", "CopyOEMInf"),
        concat!("Setup", "CommitFileQueue"),
        concat!("Setup", "InstallFiles"),
        concat!("DiInstall", "Driver"),
        concat!("UpdateDriverForPlugAndPlay", "Devices"),
        concat!("pnpu", "til"),
        concat!("std::process", "::Command"),
        concat!("fs", "::write"),
        concat!("fs", "::create"),
        concat!("Reg", "SetValue"),
        concat!("Create", "ServiceW"),
        concat!("into_", "artifact"),
    ] {
        assert!(
            !src.contains(forbidden),
            "source_manifest.rs must not contain {forbidden:?}"
        );
    }
}
