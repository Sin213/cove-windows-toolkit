// Integration tests for Tab 2a-12b2: exact-device driver installation. NO
// test here mutates this development machine: every selection/install test
// drives the orchestrator through `test_install_with_scripted_backend`,
// never a real `DiInstallDevice` call. Fixture scaffolding is intentionally
// the same shape as sdio_install_staging.rs / sdio_install_preparation.rs.

#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};

use mod_drivers::sdio::Candidate;
use mod_drivers::sdio::applicability::{
    ApplicabilityReason, AssessedCatalogCandidate, AssessedDeviceMatches,
    CatalogApplicabilityEvidence, CatalogOsApplicability,
};
use mod_drivers::sdio::extraction::materialize_inf;
use mod_drivers::sdio::install_device::{
    InstallEvent, InstallExecutionOutcome, InstallScript, MAX_INSTALLED_INF_PROPERTY_BYTES,
    PreInstallRefusal, ReadInstalledInfScript, ScriptedInstallBackend, SelectScript,
    TEST_DEVPROP_TYPE_STRING_VALUE, install_staged_driver, test_install_with_scripted_backend,
    test_parse_property_result,
};
use mod_drivers::sdio::install_plan::{InstallPlanBuilder, InstallPlanEntry};
use mod_drivers::sdio::install_preparation::{
    DriverSelectionSummary, InstallPreparation, test_decide,
};
use mod_drivers::sdio::install_staging::{
    AuthorizationResult, FreshPrepareScript, InstallDecision, RestorePointDisposition,
    ScriptedNode, ScriptedStage, ScriptedStagingBackend, StagedDriverInstall, StagingOutcome,
    authorize_driver_install, test_stage_with_scripted_backend,
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
// Fixture scaffolding
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir();
        let uniq = format!(
            "cove_tab2a12b2_{}_{}_{}",
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
const SYS: &[u8] = b"cove-tab2a12b2-payload-bytes-0123456789";

fn inf_bytes() -> Vec<u8> {
    format!("{HEADER}{ONE_PAYLOAD}")
        .replace('\n', "\r\n")
        .into_bytes()
}

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

fn node(rank: u32, date: u64, version: u64) -> DriverSelectionSummary {
    DriverSelectionSummary::from_native(rank, date, version)
}

/// Drive the FULL 12b1 pipeline (authorize -> scripted staging) to produce
/// a real, one-shot `StagedDriverInstall` for 12b2's own tests. 12b2 never
/// constructs this capability any other way.
fn staged_for<'a, 'v>(
    plan: &'a InstallPlanEntry<'v>,
    source: &'a MaterializedDriverSource<'v>,
    candidate: DriverSelectionSummary,
    leaf: &str,
) -> StagedDriverInstall<'a, 'v> {
    let prepared = match test_decide(plan, source, candidate, None) {
        InstallPreparation::Ready(p) => p,
        InstallPreparation::NoAction(r) => panic!("fixture must be Ready, got {r:?}"),
    };
    let authorized = match authorize_driver_install(
        prepared,
        InstallDecision::Confirmed,
        RestorePointDisposition::Created,
    ) {
        AuthorizationResult::Authorized(a) => a,
        AuthorizationResult::Cancelled => panic!("Confirmed must never yield Cancelled"),
    };
    let mut backend = ScriptedStagingBackend::new();
    backend.fresh_prepare = Some(FreshPrepareScript::Ready {
        candidate,
        current_best: None,
    });
    backend.stage = Some(ScriptedStage::Ok(format!(r"C:\Windows\INF\{leaf}")));
    backend.post_stage_nodes = Some(Ok(vec![ScriptedNode {
        summary: candidate,
        matches_published_inf: true,
    }]));
    let (result, _ledger) = test_stage_with_scripted_backend(authorized, &mut backend);
    match result.expect("staging must not error") {
        StagingOutcome::Staged(staged) => staged,
        other => panic!("fixture must stage cleanly, got {other:?}"),
    }
}

/// A scripted 2a-12b2 backend that proceeds all the way to a clean
/// `Installed { reboot_required: false }`.
fn happy_path_install_backend(leaf: &str) -> ScriptedInstallBackend {
    let mut b = ScriptedInstallBackend::new();
    b.elevated = true;
    b.select = Some(SelectScript::Ok);
    b.install = Some(InstallScript::Ok {
        reboot_required: false,
    });
    b.read_installed_inf = Some(ReadInstalledInfScript::Present(leaf.to_string()));
    b
}

// ---------------------------------------------------------------------------
// DEV-R1 - test-inject mutation lockout
// ---------------------------------------------------------------------------

#[test]
fn dev_r1_test_inject_public_entry_point_never_reaches_real_backend() {
    let f = fixture("r1");
    let plan = plan_for(&f.token, "ROOT_COVE_R1", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let candidate = node(1, 100, 1);
    let staged = staged_for(&plan, &source, candidate, "oem1.inf");

    let result = install_staged_driver(staged);
    assert!(matches!(
        result,
        Err(mod_drivers::sdio::InstallExecutionError::MutationDisabledInTestBuild)
    ));
}

// ---------------------------------------------------------------------------
// DEV-R3 - elevation lost after staging
// ---------------------------------------------------------------------------

#[test]
fn dev_r3_not_elevated_refuses_before_any_backend_mutation_call() {
    let f = fixture("r3");
    let plan = plan_for(&f.token, "ROOT_COVE_R3", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let candidate = node(1, 100, 1);
    let staged = staged_for(&plan, &source, candidate, "oem3.inf");

    let mut backend = happy_path_install_backend("oem3.inf");
    backend.elevated = false;
    let (outcome, ledger) = test_install_with_scripted_backend(staged, &mut backend);

    match outcome {
        InstallExecutionOutcome::DriverStoreStagedButInstallRefused { reason, .. } => {
            assert_eq!(reason, PreInstallRefusal::ElevationRequired);
        }
        other => panic!("expected refusal, got {other:?}"),
    }
    assert_eq!(ledger, vec![InstallEvent::RequireElevation]);
}

// ---------------------------------------------------------------------------
// DEV-R4 - pre-install source reattestation failure
//
// A REAL `MaterializedDriverSource::reattest()` failure cannot be forced to
// occur ONLY after staging-time re-attestation already passed (12b1's own
// pipeline inside `staged_for`): `test_corrupt_recorded_digest` needs `&mut
// source`, unavailable once `StagedDriverInstall` borrows it, and the
// sealed lease (Tab 2a-11c) makes external corruption impossible by design.
// Proven structurally instead, exactly like 12b1's own equivalent gate:
// `source.reattest()` runs once, strictly between `RequireElevation` and
// `BindFreshStagedNode`, and its failure path reports `SourceInvalidated`.
// ---------------------------------------------------------------------------

#[test]
fn dev_r4_pre_install_reattest_call_exists_between_elevation_and_bind() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_device.rs"),
    )
    .expect("read production source");
    let elevation_at = src
        .find("backend.is_elevated()")
        .expect("is_elevated call site");
    let bind_at = src
        .find("InstallEvent::BindFreshStagedNode")
        .expect("BindFreshStagedNode ledger push");
    let reattest_calls_between = src[elevation_at..bind_at]
        .matches("source.reattest()")
        .count();
    assert_eq!(
        reattest_calls_between, 1,
        "exactly one source.reattest() must sit strictly between elevation and bind"
    );
    assert!(src.contains("PreInstallRefusal::SourceInvalidated"));
}

// ---------------------------------------------------------------------------
// DEV-R5 - exact target reopened (structural: no alternate targeting)
// ---------------------------------------------------------------------------

#[test]
fn dev_r5_select_fresh_staged_node_uses_only_plan_instance_id() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_device.rs"),
    )
    .expect("read production source");
    assert!(src.contains("prep_win::open_exact_device(instance_id)"));
    assert!(src.contains("target_device_instance_id()"));
}

// ---------------------------------------------------------------------------
// DEV-R6..R10 - post-stage refusal matrix (fresh re-proof before install)
// ---------------------------------------------------------------------------

#[test]
fn dev_r6_r7_r8_r9_r10_pre_install_refusal_matrix() {
    let cases = [
        PreInstallRefusal::ExactDeviceUnavailable,
        PreInstallRefusal::EnumerationFailed,
        PreInstallRefusal::PublishedNodeMissing,
        PreInstallRefusal::BestNodeTie,
        PreInstallRefusal::PublishedInfMismatch,
        PreInstallRefusal::RankingChanged,
    ];
    for reason in cases {
        let f = fixture("r6r10");
        let plan = plan_for(
            &f.token,
            "ROOT_COVE_R6R10",
            "fake_pack",
            &drivers_root_of(&f),
        );
        let source = source_for(&f.token, &f.pkg_root);
        let candidate = node(1, 100, 1);
        let staged = staged_for(&plan, &source, candidate, "oem6.inf");

        let mut backend = ScriptedInstallBackend::new();
        backend.select = Some(SelectScript::Refuse(reason));
        let (outcome, ledger) = test_install_with_scripted_backend(staged, &mut backend);

        match outcome {
            InstallExecutionOutcome::DriverStoreStagedButInstallRefused {
                reason: observed,
                ..
            } => assert_eq!(observed, reason),
            other => panic!("expected refusal({reason:?}), got {other:?}"),
        }
        assert_eq!(
            ledger,
            vec![
                InstallEvent::RequireElevation,
                InstallEvent::PreInstallReattest,
                InstallEvent::BindFreshStagedNode,
            ]
        );
    }
}

// ---------------------------------------------------------------------------
// DEV-R11 - unique best succeeds; DEV-R12 - bind/install adjacency
// ---------------------------------------------------------------------------

#[test]
fn dev_r11_r12_unique_best_proceeds_immediately_to_install() {
    let f = fixture("r11");
    let plan = plan_for(&f.token, "ROOT_COVE_R11", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let candidate = node(1, 100, 1);
    let staged = staged_for(&plan, &source, candidate, "oem11.inf");

    let mut backend = happy_path_install_backend("oem11.inf");
    let (outcome, ledger) = test_install_with_scripted_backend(staged, &mut backend);

    assert!(matches!(outcome, InstallExecutionOutcome::Installed { .. }));
    let bind_pos = ledger
        .iter()
        .position(|e| *e == InstallEvent::BindFreshStagedNode)
        .expect("bind event");
    let install_pos = ledger
        .iter()
        .position(|e| *e == InstallEvent::InstallExactNode)
        .expect("install event");
    assert_eq!(
        install_pos,
        bind_pos + 1,
        "InstallExactNode must be the event immediately after BindFreshStagedNode"
    );
}

// ---------------------------------------------------------------------------
// DEV-R2 - Staged capability consumed (type-system proof)
//
// `install_staged_driver` takes `StagedDriverInstall` BY VALUE and there is
// no API that returns it back. The real proof is the `compile_fail` doctest
// on `install_staged_driver` itself (cargo never runs doctests from files
// under `tests/`); this is a structural cross-check that the signature
// still takes it by value, not by reference.
// ---------------------------------------------------------------------------

#[test]
fn dev_r2_install_staged_driver_takes_staged_driver_install_by_value() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_device.rs"),
    )
    .expect("read production source");
    assert!(src.contains(
        "pub fn install_staged_driver<'a, 'v>(
    staged: StagedDriverInstall<'a, 'v>,
) -> InstallExecutionResult {"
    ));
    assert!(!src.contains("staged: &StagedDriverInstall"));
}

// ---------------------------------------------------------------------------
// DEV-R13 - raw native node lifetime (structural)
// ---------------------------------------------------------------------------

#[test]
fn dev_r13_live_selected_driver_owns_list_and_device_set() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_device.rs"),
    )
    .expect("read production source");
    assert!(src.contains("struct LiveSelectedDriver"));
    assert!(src.contains("_driver_list: prep_win::DriverInfoList"));
    assert!(src.contains("device_set: prep_win::DeviceInfoSet"));
    assert!(src.contains("selected: sa::SP_DRVINFO_DATA_V2_W"));
    // The raw node is captured during the SAME enumeration pass that
    // produces the evidence used to pick it (`&raw` from `&nodes[..]`),
    // never re-enumerated by index afterward.
    assert!(src.contains("let (summary, inf_path, raw) = &nodes[winner_index];"));
    assert!(src.contains("selected: *raw,"));
}

// ---------------------------------------------------------------------------
// DEV-R14 - DI_QUIETINSTALL handling
// ---------------------------------------------------------------------------

#[test]
fn dev_r14_quietinstall_preserves_existing_params() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_device.rs"),
    )
    .expect("read production source");
    let get_at = src
        .find("SetupDiGetDeviceInstallParamsW(")
        .expect("params must be read before DiInstallDevice");
    let set_at = src
        .find("SetupDiSetDeviceInstallParamsW(")
        .expect("params must be written back");
    assert!(get_at < set_at, "params must be read, then written back");
    let between = &src[get_at..set_at];
    assert!(between.contains("params.Flags |= sa::DI_QUIETINSTALL;"));
    // No other semantic flag is OR'd into the install params here.
    for forbidden in [
        "DI_ENUMSINGLEINF",
        "DI_NOFILECOPY",
        "DI_DONOTCALLCONFIGMG",
        "DI_NOWRITE_IDS",
        "DI_INSTALLDISABLED",
    ] {
        assert!(!between.contains(forbidden), "must not inject {forbidden}");
    }
}

// ---------------------------------------------------------------------------
// DEV-R15 - exact DiInstallDevice arguments
// ---------------------------------------------------------------------------

#[test]
fn dev_r15_exact_diinstalldevice_call_shape() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_device.rs"),
    )
    .expect("read production source");
    let call_at = src
        .find("sa::DiInstallDevice(")
        .expect("DiInstallDevice call");
    let call_end = src[call_at..].find(");").expect("call terminator") + call_at;
    let call = &src[call_at..call_end];
    assert!(call.contains("std::ptr::null_mut(),"));
    assert!(call.contains("selected.device_set.handle(),"));
    assert!(call.contains("&selected.devinfo,"));
    assert!(call.contains("&selected.selected,"));
    assert!(call.contains("0,"));
    assert!(call.contains("&mut need_reboot,"));
}

// ---------------------------------------------------------------------------
// DEV-R16 - no force path (structural; behavioral covered by R6-R10)
// ---------------------------------------------------------------------------

#[test]
fn dev_r16_no_force_override_identifiers_present() {
    let src = production_source_code_only();
    for forbidden in ["Force", "FORCE", "ignore_rank", "downgrade", "force_"] {
        assert!(!src.contains(forbidden), "must not reference {forbidden}");
    }
}

// ---------------------------------------------------------------------------
// DEV-R17 - native install failure
// ---------------------------------------------------------------------------

#[test]
fn dev_r17_native_install_failure_is_staged_but_device_install_failed() {
    let f = fixture("r17");
    let plan = plan_for(&f.token, "ROOT_COVE_R17", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let candidate = node(1, 100, 1);
    let staged = staged_for(&plan, &source, candidate, "oem17.inf");

    let mut backend = ScriptedInstallBackend::new();
    backend.select = Some(SelectScript::Ok);
    backend.install = Some(InstallScript::Err(31));
    let (outcome, ledger) = test_install_with_scripted_backend(staged, &mut backend);

    match outcome {
        InstallExecutionOutcome::DriverStoreStagedButDeviceInstallFailed {
            native_error, ..
        } => {
            assert_eq!(native_error, 31);
        }
        other => panic!("expected DriverStoreStagedButDeviceInstallFailed, got {other:?}"),
    }
    assert_eq!(
        ledger,
        vec![
            InstallEvent::RequireElevation,
            InstallEvent::PreInstallReattest,
            InstallEvent::BindFreshStagedNode,
            InstallEvent::InstallExactNode,
        ]
    );
}

// ---------------------------------------------------------------------------
// Outcome matrix: DEV-R18..R23 - DiInstallDevice success + reconciliation
// ---------------------------------------------------------------------------

#[test]
fn dev_r18_r19_r20_r21_r22_r23_reconciliation_outcome_matrix() {
    enum Prop {
        Matches,
        Mismatches,
        Absent,
    }
    let cases = [
        // (reboot_required, property, expected outcome tag)
        (false, Prop::Matches, "installed_no_reboot"),
        (true, Prop::Matches, "installed_reboot"),
        (true, Prop::Mismatches, "pending_reboot"),
        (true, Prop::Absent, "pending_reboot"),
        (false, Prop::Mismatches, "postcondition_mismatch"),
        (false, Prop::Absent, "postcondition_mismatch"),
    ];
    for (reboot_required, prop, tag) in cases {
        let f = fixture("r18r23");
        let plan = plan_for(
            &f.token,
            "ROOT_COVE_R18R23",
            "fake_pack",
            &drivers_root_of(&f),
        );
        let source = source_for(&f.token, &f.pkg_root);
        let candidate = node(1, 100, 1);
        let staged = staged_for(&plan, &source, candidate, "oem18.inf");

        let mut backend = ScriptedInstallBackend::new();
        backend.select = Some(SelectScript::Ok);
        backend.install = Some(InstallScript::Ok { reboot_required });
        backend.read_installed_inf = Some(match prop {
            Prop::Matches => ReadInstalledInfScript::Present("oem18.inf".to_string()),
            Prop::Mismatches => ReadInstalledInfScript::Present("oem99.inf".to_string()),
            Prop::Absent => ReadInstalledInfScript::Absent,
        });
        let (outcome, ledger) = test_install_with_scripted_backend(staged, &mut backend);
        assert_eq!(
            ledger,
            vec![
                InstallEvent::RequireElevation,
                InstallEvent::PreInstallReattest,
                InstallEvent::BindFreshStagedNode,
                InstallEvent::InstallExactNode,
                InstallEvent::PostInstallReattest,
                InstallEvent::ReopenExactDevice,
                InstallEvent::ReadInstalledInf,
            ],
            "case {tag}"
        );

        match (tag, outcome) {
            (
                "installed_no_reboot",
                InstallExecutionOutcome::Installed {
                    reboot_required: r, ..
                },
            ) => {
                assert!(!r);
            }
            (
                "installed_reboot",
                InstallExecutionOutcome::Installed {
                    reboot_required: r, ..
                },
            ) => {
                assert!(r);
            }
            ("pending_reboot", InstallExecutionOutcome::InstalledPendingReboot { .. }) => {}
            (
                "postcondition_mismatch",
                InstallExecutionOutcome::InstalledButPostconditionMismatch { .. },
            ) => {}
            (tag, other) => panic!("case {tag}: unexpected outcome {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// DEV-R24 - reconciliation read failure is not device-install failure
// ---------------------------------------------------------------------------

#[test]
fn dev_r24_post_install_reconciliation_native_failure() {
    let f = fixture("r24");
    let plan = plan_for(&f.token, "ROOT_COVE_R24", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let candidate = node(1, 100, 1);
    let staged = staged_for(&plan, &source, candidate, "oem24.inf");

    let mut backend = ScriptedInstallBackend::new();
    backend.select = Some(SelectScript::Ok);
    backend.install = Some(InstallScript::Ok {
        reboot_required: false,
    });
    backend.read_installed_inf = Some(ReadInstalledInfScript::Err(
        1168, /* ERROR_NOT_FOUND reused as a native failure code here, distinct from Absent */
    ));
    let (outcome, _ledger) = test_install_with_scripted_backend(staged, &mut backend);

    match outcome {
        InstallExecutionOutcome::InstalledButReconciliationFailed { native_error, .. } => {
            assert_eq!(native_error, 1168);
        }
        other => panic!("expected InstalledButReconciliationFailed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// DEV-R25 - post-install source invalidation (structural; see DEV-R4)
// ---------------------------------------------------------------------------

#[test]
fn dev_r25_post_install_reattest_call_exists_between_install_and_reconciliation() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_device.rs"),
    )
    .expect("read production source");
    let install_at = src
        .find("InstallEvent::InstallExactNode")
        .expect("InstallExactNode ledger push");
    let postreattest_at = src
        .find("InstallEvent::PostInstallReattest")
        .expect("PostInstallReattest ledger push");
    assert!(install_at < postreattest_at);
    let between_and_after = &src[postreattest_at..];
    assert!(between_and_after.contains("source.reattest()"));
    assert!(between_and_after.contains("InstalledButSourceInvalidated"));
}

// ---------------------------------------------------------------------------
// DEV-R26 - exact-device post-install reopen
// ---------------------------------------------------------------------------

#[test]
fn dev_r26_read_installed_inf_reopens_exact_device() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_device.rs"),
    )
    .expect("read production source");
    let read_fn_at = src
        .find("fn read_installed_inf(&mut self, instance_id: &str)")
        .expect("read_installed_inf fn");
    let body = &src[read_fn_at..];
    assert!(body.contains("prep_win::open_exact_device(instance_id)"));
}

// ---------------------------------------------------------------------------
// DEV-R27, R28, R29 - installed-INF property parsing (pure, no native call)
// ---------------------------------------------------------------------------

fn present_wide_bytes(s: &str) -> Vec<u8> {
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0);
    wide.iter().flat_map(|c| c.to_le_bytes()).collect()
}

#[test]
fn dev_r27_wrong_property_type_fails_reconciliation() {
    let buf = present_wide_bytes("oem27.inf");
    let required = buf.len() as u32;
    let result =
        test_parse_property_result(true, 0, TEST_DEVPROP_TYPE_STRING_VALUE + 1, &buf, required);
    assert!(result.is_err());
}

#[test]
fn dev_r28_property_size_bound_normal_cap_and_cap_plus_one() {
    // Normal: well under the cap.
    let normal = present_wide_bytes("oem28.inf");
    let required = normal.len() as u32;
    let mut buf = vec![0u8; MAX_INSTALLED_INF_PROPERTY_BYTES];
    buf[..normal.len()].copy_from_slice(&normal);
    assert_eq!(
        test_parse_property_result(true, 0, TEST_DEVPROP_TYPE_STRING_VALUE, &buf, required),
        Ok(true)
    );

    // Exact cap: required == buffer length, every byte used.
    let leaf_wide: Vec<u16> = {
        let mut w: Vec<u16> = Vec::new();
        while w.len() * 2 < MAX_INSTALLED_INF_PROPERTY_BYTES - 2 {
            w.push('a' as u16);
        }
        w.push(0);
        w
    };
    let cap_buf: Vec<u8> = leaf_wide.iter().flat_map(|c| c.to_le_bytes()).collect();
    assert_eq!(cap_buf.len(), MAX_INSTALLED_INF_PROPERTY_BYTES);
    let cap_required = cap_buf.len() as u32;
    assert!(
        test_parse_property_result(
            true,
            0,
            TEST_DEVPROP_TYPE_STRING_VALUE,
            &cap_buf,
            cap_required
        )
        .is_ok()
    );

    // Cap + 1 (odd) and cap + 2 (even): required exceeds the buffer;
    // bounded failure, no retry. The even case isolates the size bound
    // from the odd-length check.
    for over_required in [cap_required + 1, cap_required + 2] {
        assert!(
            test_parse_property_result(
                true,
                0,
                TEST_DEVPROP_TYPE_STRING_VALUE,
                &cap_buf,
                over_required
            )
            .is_err(),
            "required {over_required} must fail"
        );
    }

    // Odd required, within the buffer: isolates the odd-length check from
    // the size bound (a dropped trailing byte would otherwise parse).
    assert!(
        test_parse_property_result(true, 0, TEST_DEVPROP_TYPE_STRING_VALUE, &buf, required + 1)
            .is_err()
    );
    assert_eq!(MAX_INSTALLED_INF_PROPERTY_BYTES, 4096);
}

#[test]
fn dev_r29_missing_nul_terminator_fails_reconciliation() {
    let mut wide: Vec<u16> = "oem29.inf".encode_utf16().collect();
    // Deliberately NOT NUL-terminated.
    let buf: Vec<u8> = wide.drain(..).flat_map(|c| c.to_le_bytes()).collect();
    let required = buf.len() as u32;
    assert!(
        test_parse_property_result(true, 0, TEST_DEVPROP_TYPE_STRING_VALUE, &buf, required)
            .is_err()
    );
}

#[test]
fn dev_r29_data_after_first_nul_fails_reconciliation() {
    // "oem29.inf\0other.inf\0": the whole extent is NUL-terminated, but the
    // value is not a single string. Must not be read as just "oem29.inf".
    let buf = present_wide_bytes("oem29.inf\0other.inf");
    let required = buf.len() as u32;
    assert!(
        test_parse_property_result(true, 0, TEST_DEVPROP_TYPE_STRING_VALUE, &buf, required)
            .is_err()
    );
}

#[test]
fn dev_r29_property_absent_is_ok_none() {
    let result = test_parse_property_result(false, 1168, 0, &[], 0);
    assert_eq!(result, Ok(false));
}

#[test]
fn dev_r29_native_error_other_than_not_found_is_err() {
    let result = test_parse_property_result(false, 5, 0, &[], 0);
    assert_eq!(result, Err(5));
}

// ---------------------------------------------------------------------------
// DEV-R30, R31 - installed INF leaf case handling
// ---------------------------------------------------------------------------

#[test]
fn dev_r30_installed_inf_leaf_case_insensitive_match() {
    let f = fixture("r30");
    let plan = plan_for(&f.token, "ROOT_COVE_R30", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let candidate = node(1, 100, 1);
    let staged = staged_for(&plan, &source, candidate, "oem30.inf");

    let mut backend = ScriptedInstallBackend::new();
    backend.select = Some(SelectScript::Ok);
    backend.install = Some(InstallScript::Ok {
        reboot_required: false,
    });
    backend.read_installed_inf = Some(ReadInstalledInfScript::Present("OEM30.INF".to_string()));
    let (outcome, _ledger) = test_install_with_scripted_backend(staged, &mut backend);

    assert!(matches!(outcome, InstallExecutionOutcome::Installed { .. }));
}

#[test]
fn dev_r31_installed_inf_leaf_different_file_mismatches() {
    let f = fixture("r31");
    let plan = plan_for(&f.token, "ROOT_COVE_R31", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let candidate = node(1, 100, 1);
    let staged = staged_for(&plan, &source, candidate, "oem31.inf");

    let mut backend = ScriptedInstallBackend::new();
    backend.select = Some(SelectScript::Ok);
    backend.install = Some(InstallScript::Ok {
        reboot_required: false,
    });
    backend.read_installed_inf = Some(ReadInstalledInfScript::Present("oem32.inf".to_string()));
    let (outcome, _ledger) = test_install_with_scripted_backend(staged, &mut backend);

    assert!(matches!(
        outcome,
        InstallExecutionOutcome::InstalledButPostconditionMismatch { .. }
    ));
}

// ---------------------------------------------------------------------------
// Structural safety gates (source-text proofs, comments excluded)
// ---------------------------------------------------------------------------

fn production_source_code_only() -> String {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_device.rs"),
    )
    .expect("read production source");
    src.lines()
        .filter(|line| {
            !line.trim_start().starts_with("//") && !line.trim_start().starts_with("///")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// DEV-R4/R25/R6-R10 guard shape. The pre/post-install reattestation and
/// the native selection proofs cannot be forced to fail from a test (sealed
/// lease; no live device), so each guard is pinned as an exact,
/// unconditional condition (whitespace-insensitive). A `false &&` or a
/// swapped reason breaks the match.
#[test]
fn dev_r37_install_guards_are_exact_and_unconditional() {
    let src: String = production_source_code_only()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    for guard in [
        "if!backend.is_elevated(){",
        "ledger.push(InstallEvent::PreInstallReattest);ifsource.reattest().is_err(){returnrefuse(published,PreInstallRefusal::SourceInvalidated);}",
        "ledger.push(InstallEvent::PostInstallReattest);ifsource.reattest().is_err(){letpostcondition_observed=observe_postcondition(backend,&instance_id,&published,ledger).ok().flatten();",
        "BestSelection::Ambiguous=>{returnErr(PreInstallRefusal::BestNodeTie);}",
        "if!install_preparation::setupapi_inf_paths_match(expected,inf_path).unwrap_or(false){returnErr(PreInstallRefusal::PublishedInfMismatch);}",
        "if*summary!=expected_candidate{returnErr(PreInstallRefusal::RankingChanged);}",
    ] {
        assert!(src.contains(guard), "guard missing or altered: {guard}");
    }
}

#[test]
fn dev_r32_r33_r34_r35_r36_production_structural_gates() {
    let src = production_source_code_only();

    // DEV-R15: exact DiInstallDevice contract present.
    assert!(src.contains("DiInstallDevice"));
    assert!(src.contains("DEVPKEY_Device_DriverInfPath"));

    let forbidden = [
        // DEV-R32: no second staging call in this slice at all.
        "SetupCopyOEMInfW",
        // DEV-R33: no automatic Driver Store/driver rollback.
        "SetupUninstallOEMInf",
        "DiUninstallDriver",
        "DiRollbackDriver",
        "/delete-driver",
        "pnputil",
        // DEV-R34: no automatic reboot.
        "InitiateSystemShutdown",
        "ExitWindowsEx",
        "InitiateSystemRestore",
        "shutdown.exe",
        "RestartComputer",
        // DEV-R35: no broad/alternate install APIs.
        "DiInstallDriver",
        "UpdateDriverForPlugAndPlayDevices",
        "SetupDiCallClassInstaller",
        // DEV-R36: no cancellation path after staging.
        "InstallDecision",
        "Cancel",
        "Abort",
        "UserChangedMind",
        // DEV-R16/26: no force/search-UI/null-driver install flags.
        "DIIDFLAG_INSTALLNULLDRIVER",
        "DIIDFLAG_SHOWSEARCHUI",
        "DIIDFLAG_INSTALLCOPYINFDRIVERS",
        // No elevation launcher.
        "ShellExecuteEx",
        "runas",
        "RunAs",
        "-Verb",
    ];
    for api in forbidden {
        assert!(!src.contains(api), "must not reference {api}");
    }
}
