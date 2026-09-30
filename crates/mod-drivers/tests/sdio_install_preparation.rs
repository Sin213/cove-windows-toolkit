// Integration tests for Tab 2a-12a: exact-target install preparation
// (read-only, no-force gate).
//
// This module has no separate trust seam of its own: VerifiedDriverPackage
// tokens are built exactly as Tab 2a-7's suite builds them (a fake
// DriverPackageVerifier check function), and MaterializedDriverSource values
// are built exactly as Tab 2a-11b's suite builds them (the real
// materialize_driver_source entry point over a synthetic archive). This
// suite adds nothing to either trust boundary; it only proves the NEW
// install-preparation gate built on top of both.

#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};

use mod_drivers::identity::MAX_INSTANCE_ID_LENGTH;
use mod_drivers::sdio::Candidate;
use mod_drivers::sdio::applicability::{
    ApplicabilityReason, AssessedCatalogCandidate, AssessedDeviceMatches,
    CatalogApplicabilityEvidence, CatalogOsApplicability,
};
use mod_drivers::sdio::extraction::materialize_inf;
use mod_drivers::sdio::install_plan::{InstallPlanBuilder, InstallPlanEntry};
use mod_drivers::sdio::install_preparation::{
    BestSelection, DriverSelectionSummary, InstallPreparation, InstallPreparationError,
    MAX_DRIVER_DETAIL_BYTES, MAX_DRIVER_NODES, NoActionReason, NodeComparison,
    compare_driver_nodes, encode_driver_path, normalize_local_setupapi_path,
    prepare_driver_install, select_unique_best, setupapi_inf_paths_match, test_collect_bounded,
    test_decide, test_validate_driver_detail_required_size, validate_target_instance_id,
};
use mod_drivers::sdio::local_pack::{LocalPackAvailability, resolve_local_pack};
use mod_drivers::sdio::matching::{CatalogCandidateMatch, DeviceIdKind, MatchEvidence};
use mod_drivers::sdio::package_materialization::{
    MaterializedDriverSource, materialize_driver_source,
};
use mod_drivers::sdio::payload_inventory::inspect_payload_inventory;
use mod_drivers::sdio::signature::{DriverPackageVerifier, TrustResult, VerifiedDriverPackage};
use mod_drivers::sdio::source_manifest::{SourceManifest, derive_source_manifest};
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};

// ---------------------------------------------------------------------------
// Fixture scaffolding (same shape as sdio_signature.rs / sdio_package_materialization.rs)
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir();
        let uniq = format!(
            "cove_tab2a12a_{}_{}_{}",
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

const HEADER: &str = "[Version]\nSignature=\"$WINDOWS NT$\"\nClass=System\n\
    ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\nProvider=%Mfg%\n\
    DriverVer=01/01/2024,1.0.0.0\n\n[Strings]\nMfg=\"Cove\"\nDisk=\"Disk\"\n\n";
const ONE_PAYLOAD: &str = "[SourceDisksNames]\n1 = %Disk%,,,\n\n\
    [SourceDisksFiles]\ndriver.sys = 1\n\n\
    [Install.NTamd64]\nCopyFiles = L\n\n[L]\ndriver.sys\n";
const SYS: &[u8] = b"cove-tab2a12a-payload-bytes-0123456789";

fn inf_bytes() -> Vec<u8> {
    format!("{HEADER}{ONE_PAYLOAD}")
        .replace('\n', "\r\n")
        .into_bytes()
}

/// A complete fixture: one VerifiedDriverPackage token plus the real
/// InstallPlanEntry and MaterializedDriverSource built over it, exactly the
/// pair 12a's production entry point consumes.
struct Fixture {
    token: VerifiedDriverPackage,
    _tmp: TempDir,
    pkg_root: PathBuf,
}

fn write_pack(pack_path: &Path, leaf: &str, body: &[u8], payload: &[u8]) {
    fs::create_dir_all(pack_path.parent().unwrap()).unwrap();
    let file = fs::File::create(pack_path).expect("create archive");
    let mut writer = ArchiveWriter::new(std::io::BufWriter::new(file)).expect("writer");
    writer
        .push_archive_entry(
            ArchiveEntry::new_file(leaf),
            Some(std::io::Cursor::new(body.to_vec())),
        )
        .expect("push inf");
    writer
        .push_archive_entry(
            ArchiveEntry::new_file("driver.sys"),
            Some(std::io::Cursor::new(payload.to_vec())),
        )
        .expect("push payload");
    writer.finish().expect("finish archive");
}

fn fake_candidate(pack: &str, inf_filename: &str) -> CatalogCandidateMatch {
    let candidate = Candidate {
        inf_path: String::new(),
        inf_filename: inf_filename.to_string(),
        provider: Some("Cove Test".into()),
        class: Some("System".into()),
        class_guid: None,
        catalog_file: None,
        version: None,
        date: None,
        install_section: "Install".into(),
        picked_section: "Install".into(),
        sect_pos: 0,
        models_section: None,
        inf_pos: 0,
    };
    CatalogCandidateMatch {
        pack_name: pack.to_string(),
        candidate,
        evidence: vec![MatchEvidence {
            kind: DeviceIdKind::Hardware,
            device_id: "ROOT_COVE_TEST_FAKE".into(),
            ordinal: 0,
            inf_pos: 0,
        }],
    }
}

fn host_compatible_applicability() -> CatalogApplicabilityEvidence {
    CatalogApplicabilityEvidence {
        models_section: Some("ntamd64.10.0...19041".into()),
        target: None,
        status: CatalogOsApplicability::HostCompatible,
        reason: ApplicabilityReason::TargetSatisfied,
    }
}

fn device_assessment(device_id: &str, candidate: CatalogCandidateMatch) -> AssessedDeviceMatches {
    let cand = AssessedCatalogCandidate {
        matched: candidate,
        os: host_compatible_applicability(),
    };
    AssessedDeviceMatches {
        instance_id: device_id.to_string(),
        candidates: vec![cand],
    }
}

/// Build one complete fixture: an archive with INF + one payload, resolved,
/// materialized, verified through the fake trust seam.
fn build_token(root: &Path, pack_name: &str) -> (VerifiedDriverPackage, PathBuf) {
    let drivers = root.join("drivers");
    let staging = root.join("staging");
    fs::create_dir_all(&drivers).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let pack_path = drivers.join(format!("{pack_name}.7z"));
    let inf = inf_bytes();
    write_pack(&pack_path, "driver.inf", &inf, SYS);
    let candidate = fake_candidate(pack_name, "driver.inf");
    let req = match resolve_local_pack(&drivers, &candidate).expect("resolve_local_pack") {
        LocalPackAvailability::Present(r) => r,
        other => panic!("expected Present, got {other:?}"),
    };
    let artifact = materialize_inf(&req, &staging).expect("materialize_inf");
    let token = DriverPackageVerifier::with_check_fn(|_| TrustResult::Trusted {
        catalog_name: String::new(),
        signer: None,
        reported_catalog_path: None,
    })
    .verify(artifact)
    .expect("verify");
    (token, drivers)
}

fn plan_for<'v>(
    token: &'v VerifiedDriverPackage,
    device_id: &str,
    pack_name: &str,
    drivers: &Path,
) -> InstallPlanEntry<'v> {
    let candidate = fake_candidate(pack_name, "driver.inf");
    let device = device_assessment(device_id, candidate);
    let builder = InstallPlanBuilder::new(&device, drivers);
    builder
        .build(&device.candidates[0], Some(token))
        .expect("build must not error")
        .expect("build must produce a ready entry")
}

fn source_for<'v>(
    token: &'v VerifiedDriverPackage,
    pkg_root: &Path,
) -> MaterializedDriverSource<'v> {
    let resolved = match derive_source_manifest(token, "Install") {
        SourceManifest::ResolvedReferences(r) => r,
        other => panic!("expected ResolvedReferences, got {other:?}"),
    };
    let inventory = inspect_payload_inventory(&resolved).expect("inspect_payload_inventory");
    materialize_driver_source(&inventory, pkg_root).expect("materialize_driver_source")
}

fn fixture(tag: &str) -> Fixture {
    let tmp = TempDir::new(tag);
    let (token, _drivers) = build_token(tmp.path(), "fake_pack");
    let pkg_root = tmp.path().join("pkg");
    fs::create_dir_all(&pkg_root).unwrap();
    Fixture {
        token,
        _tmp: tmp,
        pkg_root,
    }
}

fn drivers_root_of(f: &Fixture) -> PathBuf {
    f._tmp.path().join("drivers")
}

// ---------------------------------------------------------------------------
// Real-host device discovery (dynamic; never hardcoded; never printed)
// ---------------------------------------------------------------------------

mod host {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation as sa;

    struct DeviceInfoSet(sa::HDEVINFO);
    impl Drop for DeviceInfoSet {
        fn drop(&mut self) {
            unsafe {
                sa::SetupDiDestroyDeviceInfoList(self.0);
            }
        }
    }

    fn wide_to_string(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    /// Whether a present device was found. Distinguishes genuine "this host
    /// enumerates zero present devices" (ERROR_NO_MORE_ITEMS on the very
    /// first index) from an actual native API failure. The two are NOT the
    /// same: silently converting every failure into "no device" would let a
    /// broken SetupAPI call masquerade as a skipped test instead of failing
    /// it, which is exactly the false-confidence Astra HARDENED challenge
    /// repair 2 flagged.
    pub enum Discovery {
        Found(String),
        NoDevicesPresent,
    }

    fn last_error() -> u32 {
        // SAFETY: plain thread-local error read.
        unsafe { windows_sys::Win32::Foundation::GetLastError() }
    }

    /// Discover SOME present device's instance ID on THIS host, at test run
    /// time. Never hardcoded, never printed. Used only to prove the
    /// production exact-open/round-trip mechanics against a real device;
    /// the synthetic INF used elsewhere in this suite never matches its
    /// hardware ID, so no compatible candidate is ever produced against it.
    ///
    /// PANICS on a genuine native API failure at any step (SetupDiGetClassDevsW,
    /// SetupDiEnumDeviceInfo with an error other than ERROR_NO_MORE_ITEMS, or
    /// SetupDiGetDeviceInstanceIdW): a real machine always enumerates at least
    /// one present device, so any of these failing is an actual defect, not a
    /// benign empty result, and must fail the test loudly rather than being
    /// silently absorbed into a skip.
    pub fn discover_any_present_device_instance_id() -> Discovery {
        // SAFETY: no class restriction; enumerator null selects all.
        let hdevinfo = unsafe {
            sa::SetupDiGetClassDevsW(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                sa::DIGCF_PRESENT | sa::DIGCF_ALLCLASSES,
            )
        };
        if hdevinfo == -1 {
            panic!(
                "SetupDiGetClassDevsW failed unexpectedly: GetLastError={}",
                last_error()
            );
        }
        let _guard = DeviceInfoSet(hdevinfo);
        let mut devinfo: sa::SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
        devinfo.cbSize = std::mem::size_of::<sa::SP_DEVINFO_DATA>() as u32;
        // SAFETY: live handle; index 0 is only read if it exists.
        let ok = unsafe { sa::SetupDiEnumDeviceInfo(hdevinfo, 0, &mut devinfo) };
        if ok == 0 {
            let code = last_error();
            if code == windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS {
                return Discovery::NoDevicesPresent;
            }
            panic!("SetupDiEnumDeviceInfo failed unexpectedly: GetLastError={code}");
        }
        let mut buf = vec![0u16; 1024];
        let mut required = 0u32;
        // SAFETY: live handle/element; buffer length passed exactly.
        let ok = unsafe {
            sa::SetupDiGetDeviceInstanceIdW(
                hdevinfo,
                &devinfo,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut required,
            )
        };
        if ok == 0 {
            panic!(
                "SetupDiGetDeviceInstanceIdW failed unexpectedly: GetLastError={}",
                last_error()
            );
        }
        Discovery::Found(wide_to_string(&buf))
    }
}

// ---------------------------------------------------------------------------
// PREP-R1 / PREP-R2 - package binding
// ---------------------------------------------------------------------------

#[test]
fn prep_r1_same_live_package_binding_passes() {
    let f = fixture("r1");
    let plan = plan_for(
        &f.token,
        "ROOT_COVE_TEST_R1",
        "fake_pack",
        &drivers_root_of(&f),
    );
    let source = source_for(&f.token, &f.pkg_root);
    assert!(std::ptr::eq(
        plan.verified_package(),
        source.verified_package()
    ));

    // Proceeding through the real gate must NOT fail on the binding check
    // (it may still fail later, e.g. because the instance id does not name
    // a real device — that is expected and is a DIFFERENT error).
    let result = prepare_driver_install(&plan, &source);
    if let Err(InstallPreparationError::PackageBindingMismatch) = result {
        panic!("binding check must pass for the same live token")
    }
}

#[test]
fn prep_r2_cross_package_substitution_rejected() {
    let tmp = TempDir::new("r2");
    let (token_a, drivers_a) = build_token(tmp.path(), "fake_pack");
    let (token_b, _drivers_b) = build_token(&tmp.path().join("other"), "fake_pack");

    let plan_a = plan_for(&token_a, "ROOT_COVE_TEST_R2", "fake_pack", &drivers_a);
    let pkg_b = tmp.path().join("pkg_b");
    fs::create_dir_all(&pkg_b).unwrap();
    let source_b = source_for(&token_b, &pkg_b);

    // Same pack name, same INF leaf, same evidence shape — but a DIFFERENT
    // physical archive (different VerifiedDriverPackage). Binding must fail
    // BEFORE any native device operation.
    let result = prepare_driver_install(&plan_a, &source_b);
    assert!(matches!(
        result,
        Err(InstallPreparationError::PackageBindingMismatch)
    ));
}

// ---------------------------------------------------------------------------
// PREP-R3 - target input validation
// ---------------------------------------------------------------------------

#[test]
fn prep_r3_empty_instance_id_rejected() {
    assert!(matches!(
        validate_target_instance_id(""),
        Err(InstallPreparationError::InvalidTargetInstanceId)
    ));
}

#[test]
fn prep_r3_embedded_nul_rejected() {
    let id = format!("ROOT{}FAKE", '\0');
    assert!(matches!(
        validate_target_instance_id(&id),
        Err(InstallPreparationError::InvalidTargetInstanceId)
    ));
}

#[test]
fn prep_r3_over_bound_rejected_without_truncation() {
    let id: String = "A".repeat(MAX_INSTANCE_ID_LENGTH + 1);
    assert!(matches!(
        validate_target_instance_id(&id),
        Err(InstallPreparationError::InvalidTargetInstanceId)
    ));
}

#[test]
fn prep_r3_exactly_at_bound_accepted() {
    let id: String = "A".repeat(MAX_INSTANCE_ID_LENGTH - 1);
    assert!(validate_target_instance_id(&id).is_ok());
}

// ---------------------------------------------------------------------------
// PREP-R4 / PREP-R6 / PREP-R7 / PREP-R8 - real host end-to-end
// ---------------------------------------------------------------------------

/// The single real-native-host test in this suite: discovers SOME present
/// device on THIS machine at run time (never hardcoded, never printed),
/// proves the production exact-open + instance-ID round-trip succeeds
/// against it (PREP-R4), proves the materialized INF still parses under
/// SetupAPI while the 11c permanent read lease is fully live (PREP-R6),
/// proves the single-INF candidate search is actually configured and run
/// against that real device (PREP-R7, observed via reaching the
/// zero-candidates outcome rather than an instance-id/native-open error),
/// and proves a synthetic INF whose hardware ID cannot match any real
/// device correctly reports no compatible candidate rather than a false
/// match (PREP-R8).
#[test]
fn prep_r4_r6_r7_r8_real_host_no_compatible_candidate_is_safe() {
    let real_instance_id = match host::discover_any_present_device_instance_id() {
        host::Discovery::Found(id) => id,
        host::Discovery::NoDevicesPresent => {
            eprintln!("prep_r4_r6_r7_r8: no present device found on this host; skipping");
            return;
        }
    };

    let f = fixture("r4");
    let plan = plan_for(
        &f.token,
        &real_instance_id,
        "fake_pack",
        &drivers_root_of(&f),
    );
    let source = source_for(&f.token, &f.pkg_root);

    let result = prepare_driver_install(&plan, &source).expect(
        "exact-device open, round-trip and INF probe must succeed against a real present device",
    );
    match result {
        InstallPreparation::NoAction(NoActionReason::CandidateNotCompatible) => {}
        InstallPreparation::NoAction(other) => {
            panic!("expected CandidateNotCompatible, got {other:?}")
        }
        InstallPreparation::Ready(_) => {
            panic!("a synthetic Cove-test INF must never compatibly match a real host device")
        }
    }
}

// ---------------------------------------------------------------------------
// PREP-R5 - no alternate targeting (structural)
// ---------------------------------------------------------------------------

#[test]
fn prep_r5_no_alternate_targeting_structural() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_preparation.rs"),
    )
    .expect("read production source");
    // The only device-targeting call sites use the plan's own instance id;
    // there is no fallback expression naming hardware/compatible id, class
    // or description as an alternate SetupDiOpenDeviceInfoW argument.
    assert!(
        src.contains("SetupDiOpenDeviceInfoW"),
        "production must still call SetupDiOpenDeviceInfoW"
    );
    for forbidden in ["hardware_id", "compatible_id", "HardwareID", "CompatibleID"] {
        assert!(
            !src.contains(forbidden),
            "production must never reference {forbidden} as a targeting fallback"
        );
    }
}

// ---------------------------------------------------------------------------
// PREP-R9 / R10 / R11 - pure comparator ordering
// ---------------------------------------------------------------------------

fn node(rank: u32, date: u64, version: u64) -> DriverSelectionSummary {
    DriverSelectionSummary::from_native(rank, date, version)
}

#[test]
fn prep_r9_lower_rank_wins() {
    let better = node(1, 100, 100);
    let worse = node(2, 999, 999);
    assert_eq!(compare_driver_nodes(better, worse), NodeComparison::First);
    assert_eq!(compare_driver_nodes(worse, better), NodeComparison::Second);
}

#[test]
fn prep_r10_newer_date_wins_on_equal_rank() {
    let newer = node(5, 200, 1);
    let older = node(5, 100, 999);
    assert_eq!(compare_driver_nodes(newer, older), NodeComparison::First);
    assert_eq!(compare_driver_nodes(older, newer), NodeComparison::Second);
}

#[test]
fn prep_r11_higher_version_wins_on_equal_rank_and_date() {
    let higher = node(5, 100, 20);
    let lower = node(5, 100, 10);
    assert_eq!(compare_driver_nodes(higher, lower), NodeComparison::First);
    assert_eq!(compare_driver_nodes(lower, higher), NodeComparison::Second);
}

#[test]
fn prep_r9_r10_r11_mutation_reverse_ordering_fails() {
    // A reversed-ordering mutant (higher rank wins, or older date wins, or
    // lower version wins) would flip these assertions; they must hold as
    // written against the documented Windows ordering.
    assert_eq!(
        compare_driver_nodes(node(1, 0, 0), node(2, 0, 0)),
        NodeComparison::First
    );
    assert_eq!(
        compare_driver_nodes(node(1, 200, 0), node(1, 100, 0)),
        NodeComparison::First
    );
    assert_eq!(
        compare_driver_nodes(node(1, 100, 20), node(1, 100, 10)),
        NodeComparison::First
    );
}

// ---------------------------------------------------------------------------
// PREP-R12 / R13 - unique best selection and ambiguity
// ---------------------------------------------------------------------------

#[test]
fn prep_r12_exact_tie_is_ambiguous_never_first_wins() {
    let a = node(3, 500, 7);
    let b = node(3, 500, 7);
    assert_eq!(select_unique_best(&[a, b]), BestSelection::Ambiguous);
    assert_eq!(select_unique_best(&[b, a]), BestSelection::Ambiguous);
}

#[test]
fn prep_r13_multiple_candidate_models_unique_best_selected() {
    let worst = node(9, 0, 0);
    let mid = node(3, 100, 1);
    let best = node(3, 200, 1);
    let nodes = [worst, mid, best];
    assert_eq!(select_unique_best(&nodes), BestSelection::Unique(2));
}

#[test]
fn prep_r13_multiple_candidate_models_exact_tie_still_refuses() {
    let irrelevant = node(9, 0, 0);
    let tie_a = node(3, 100, 1);
    let tie_b = node(3, 100, 1);
    let nodes = [irrelevant, tie_a, tie_b];
    assert_eq!(select_unique_best(&nodes), BestSelection::Ambiguous);
}

#[test]
fn prep_r_not_compatible_on_empty_slice() {
    let nodes: [DriverSelectionSummary; 0] = [];
    assert_eq!(select_unique_best(&nodes), BestSelection::NotCompatible);
}

// ---------------------------------------------------------------------------
// PREP-R14..R19 - strict no-force decision (pure)
// ---------------------------------------------------------------------------

#[test]
fn prep_r14_r15_r16_r17_r18_r19_strict_no_force_decision() {
    let f = fixture("r14");
    let plan = plan_for(
        &f.token,
        "ROOT_COVE_TEST_R14",
        "fake_pack",
        &drivers_root_of(&f),
    );
    let source = source_for(&f.token, &f.pkg_root);

    // R16 — better rank => Ready.
    let candidate = node(1, 100, 1);
    let current = node(2, 100, 1);
    assert!(matches!(
        test_decide(&plan, &source, candidate, Some(current)),
        InstallPreparation::Ready(_)
    ));

    // R17 — same rank, newer date => Ready.
    let candidate = node(2, 200, 1);
    let current = node(2, 100, 1);
    assert!(matches!(
        test_decide(&plan, &source, candidate, Some(current)),
        InstallPreparation::Ready(_)
    ));

    // R18 — same rank/date, higher version => Ready.
    let candidate = node(2, 100, 5);
    let current = node(2, 100, 1);
    assert!(matches!(
        test_decide(&plan, &source, candidate, Some(current)),
        InstallPreparation::Ready(_)
    ));

    // R19 — current list empty => Ready.
    let candidate = node(9, 0, 0);
    assert!(matches!(
        test_decide(&plan, &source, candidate, None),
        InstallPreparation::Ready(_)
    ));

    // R14 — worse rank => NotBetterThanCurrent.
    let candidate = node(3, 100, 1);
    let current = node(2, 100, 1);
    assert!(matches!(
        test_decide(&plan, &source, candidate, Some(current)),
        InstallPreparation::NoAction(NoActionReason::NotBetterThanCurrent)
    ));

    // R15 — exactly equal => EquivalentDriverAlreadyAvailable, never Ready.
    let candidate = node(2, 100, 1);
    let current = node(2, 100, 1);
    assert!(matches!(
        test_decide(&plan, &source, candidate, Some(current)),
        InstallPreparation::NoAction(NoActionReason::EquivalentDriverAlreadyAvailable)
    ));
}

// ---------------------------------------------------------------------------
// PREP-R21 - driver detail buffer bound
// ---------------------------------------------------------------------------

#[test]
fn prep_r21_driver_detail_required_size_bound() {
    assert!(test_validate_driver_detail_required_size(0).is_ok());
    assert!(test_validate_driver_detail_required_size(MAX_DRIVER_DETAIL_BYTES).is_ok());
    assert!(matches!(
        test_validate_driver_detail_required_size(MAX_DRIVER_DETAIL_BYTES + 1),
        Err(InstallPreparationError::DriverDetailTooLarge)
    ));
}

// ---------------------------------------------------------------------------
// PREP-R22 - node count bound
// ---------------------------------------------------------------------------

#[test]
fn prep_r22_node_count_bound() {
    let at_cap = test_collect_bounded(MAX_DRIVER_NODES).expect("exactly at cap must succeed");
    assert_eq!(at_cap.len(), MAX_DRIVER_NODES);

    assert!(matches!(
        test_collect_bounded(MAX_DRIVER_NODES + 1),
        Err(InstallPreparationError::TooManyDriverNodes)
    ));
}

// ---------------------------------------------------------------------------
// PREP-R23 - DriverPath UTF-16 boundary
// ---------------------------------------------------------------------------

#[test]
fn prep_r23_driver_path_exact_fit_accepted() {
    // Capacity is 260 units including the terminating NUL, so 259 content
    // units fits exactly (drive-colon-backslash is 3 units + 256 more 'a's).
    let backslash = char::from_u32(0x5c).unwrap();
    let normalized = format!("C:{backslash}{}", "a".repeat(256));
    assert_eq!(normalized.encode_utf16().count(), 259);
    assert!(encode_driver_path(&normalized).is_ok());
}

#[test]
fn prep_r23_driver_path_one_unit_too_long_rejected_without_truncation() {
    let backslash = char::from_u32(0x5c).unwrap();
    let normalized = format!("C:{backslash}{}", "a".repeat(257));
    assert_eq!(normalized.encode_utf16().count(), 260);
    assert!(matches!(
        encode_driver_path(&normalized),
        Err(InstallPreparationError::SourcePathTooLong)
    ));
}

// ---------------------------------------------------------------------------
// PREP-R24 / PREP-R25 - SetupAPI path form and candidate INF path binding
// ---------------------------------------------------------------------------

fn bs() -> char {
    char::from_u32(0x5c).unwrap()
}

#[test]
fn prep_r24_extended_length_prefix_stripped_and_accepted() {
    let b = bs();
    let bare = format!("C:{b}drivers{b}pkg{b}driver.inf");
    let extended = format!("{b}{b}?{b}{bare}");
    let normalized = normalize_local_setupapi_path(Path::new(&extended)).expect("must accept");
    assert_eq!(normalized, bare);

    let bare_normalized =
        normalize_local_setupapi_path(Path::new(&bare)).expect("bare must accept");
    assert_eq!(bare_normalized, bare);
}

#[test]
fn prep_r24_unc_share_rejected() {
    let b = bs();
    let unc = format!("{b}{b}server{b}share{b}driver.inf");
    assert!(matches!(
        normalize_local_setupapi_path(Path::new(&unc)),
        Err(InstallPreparationError::PathFormUnsupported)
    ));
}

#[test]
fn prep_r24_extended_unc_rejected() {
    let b = bs();
    let unc_extended = format!("{b}{b}?{b}UNC{b}server{b}share{b}driver.inf");
    assert!(matches!(
        normalize_local_setupapi_path(Path::new(&unc_extended)),
        Err(InstallPreparationError::PathFormUnsupported)
    ));
}

#[test]
fn prep_r24_device_namespace_rejected() {
    let b = bs();
    let device_ns = format!("{b}{b}.{b}PhysicalDrive0");
    assert!(matches!(
        normalize_local_setupapi_path(Path::new(&device_ns)),
        Err(InstallPreparationError::PathFormUnsupported)
    ));
}

#[test]
fn prep_r24_relative_path_rejected() {
    assert!(matches!(
        normalize_local_setupapi_path(Path::new("drivers/pkg/driver.inf")),
        Err(InstallPreparationError::PathFormUnsupported)
    ));
}

#[test]
fn prep_r25_candidate_inf_path_case_insensitive_match_accepted() {
    let b = bs();
    let expected = format!("C:{b}drivers{b}pkg{b}driver.inf");
    let reported = format!("c:{b}DRIVERS{b}pkg{b}DRIVER.INF");
    assert!(setupapi_inf_paths_match(&expected, &reported).expect("normalize must succeed"));
}

#[test]
fn prep_r25_candidate_inf_path_mismatch_rejected() {
    let b = bs();
    let expected = format!("C:{b}drivers{b}pkg{b}driver.inf");
    let different = format!("C:{b}drivers{b}other_pkg{b}driver.inf");
    assert!(!setupapi_inf_paths_match(&expected, &different).expect("normalize must succeed"));
}

#[test]
fn prep_r25_candidate_inf_path_extended_prefix_reported_still_matches() {
    let b = bs();
    let expected = format!("C:{b}drivers{b}pkg{b}driver.inf");
    let reported_extended = format!("{b}{b}?{b}c:{b}drivers{b}pkg{b}driver.inf");
    assert!(setupapi_inf_paths_match(&expected, &reported_extended).expect("must normalize"));
}

// ---------------------------------------------------------------------------
// PREP-R31 - forbidden mutation surface (structural)
// ---------------------------------------------------------------------------

#[test]
fn prep_r31_no_forbidden_mutation_api_present() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_preparation.rs"),
    )
    .expect("read production source");
    // Exclude comment lines: the module's own doc comment intentionally
    // NAMES every forbidden API as documentation of what is absent, which
    // would otherwise trip this same check on its own prose. The gate must
    // examine actual code, not commentary about the gate.
    let code_only: String = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join(
            "
",
        );
    let src = code_only;
    let forbidden = [
        "SetupCopyOEMInf",
        "SetupUninstallOEMInf",
        "DiInstallDevice",
        "DiInstallDriver",
        "UpdateDriverForPlugAndPlayDevices",
        "SetupDiCallClassInstaller",
        "pnputil",
        "/add-driver",
        "/delete-driver",
        "/disable-device",
        "/enable-device",
        "/restart-device",
        "/remove-device",
        "RegSetValue",
        "RegCreateKey",
        "InitiateSystemRestore",
        "SRSetRestorePoint",
        "ExitWindowsEx",
        "ShellExecute",
        "runas",
    ];
    for token in forbidden {
        assert!(
            !src.contains(token),
            "forbidden mutation surface token found in production source: {token}"
        );
    }
}

// ---------------------------------------------------------------------------
// Astra HARDENED challenge repair 1 - current-store excluded-driver baseline
// ---------------------------------------------------------------------------

#[test]
fn repair1_current_store_search_allows_excluded_pnp_drivers_structural() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_preparation.rs"),
    )
    .expect("read production source");
    assert!(
        src.contains("fn configure_current_store_search"),
        "device set B must configure DI_FLAGSEX_ALLOWEXCLUDEDDRVS via a dedicated function; \
         without it, an already-installed PnP driver (normally Exclude-From-Select) is \
         silently omitted from the current-store baseline, and an absent baseline is treated \
         as None, unconditionally authorizing Ready"
    );
    let start = src
        .find("fn configure_current_store_search")
        .expect("function present");
    let body_start = src[start..].find('{').unwrap() + start;
    let mut depth = 1i32;
    let mut end = body_start + 1;
    for (offset, ch) in src[body_start + 1..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = body_start + 1 + offset;
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &src[body_start..=end];
    assert!(
        body.contains("DI_FLAGSEX_ALLOWEXCLUDEDDRVS"),
        "configure_current_store_search must set DI_FLAGSEX_ALLOWEXCLUDEDDRVS"
    );
    assert!(
        !body.contains("DI_ENUMSINGLEINF"),
        "device set B must never gain DI_ENUMSINGLEINF: that would reintroduce \
         single-INF contamination into the independent current-store search (PREP-R20)"
    );
    assert!(
        !body.contains("DriverPath"),
        "device set B must never set DriverPath: that is candidate-search-only state (PREP-R20)"
    );

    // The call site: prepare_driver_install must invoke this configuration on
    // device set B BEFORE building its driver list, not merely define the
    // function without using it.
    let call_site = src
        .find("configure_current_store_search(device_b.0, &devinfo_b)")
        .expect("prepare_driver_install must call configure_current_store_search on device set B");
    let build_call = src
        .find("enumerate_compat_driver_nodes(device_b.0, &devinfo_b, None)")
        .expect("device set B must still build its compatible list");
    assert!(
        call_site < build_call,
        "device set B configuration must happen BEFORE its driver list is built"
    );
}
