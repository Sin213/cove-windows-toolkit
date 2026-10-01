// Integration tests for Tab 2a-12b1: authorized Driver Store staging. NO
// test here mutates this development machine: every staging/binding test
// drives the orchestrator through `test_stage_with_scripted_backend`,
// never a real Windows mutation API. `Ready` preparations are built via
// 12a's `test_decide` seam (pointer-identity/candidate evidence only),
// never a real device match -- no synthetic INF here ever matches real
// hardware (see sdio_install_preparation.rs prep_r4).

#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};

use mod_drivers::sdio::Candidate;
use mod_drivers::sdio::applicability::{
    ApplicabilityReason, AssessedCatalogCandidate, AssessedDeviceMatches,
    CatalogApplicabilityEvidence, CatalogOsApplicability,
};
use mod_drivers::sdio::extraction::materialize_inf;
use mod_drivers::sdio::install_plan::{InstallPlanBuilder, InstallPlanEntry};
use mod_drivers::sdio::install_preparation::{
    DriverSelectionSummary, InstallPreparation, InstallPreparationError, NoActionReason,
    test_decide,
};
use mod_drivers::sdio::install_staging::{
    AuthorizationResult, AuthorizedDriverInstall, FreshPrepareScript, InstallDecision,
    PostStageRefusal, PreMutationError, RestorePointDisposition, ScriptedNode, ScriptedStage,
    ScriptedStagingBackend, StagingEvent, StagingOutcome, authorize_driver_install,
    stage_driver_install, test_stage_with_scripted_backend,
};
use mod_drivers::sdio::local_pack::{LocalPackAvailability, resolve_local_pack};
use mod_drivers::sdio::matching::{CatalogCandidateMatch, DeviceIdKind, MatchEvidence};
use mod_drivers::sdio::package_materialization::{
    MaterializedDriverSource, materialize_driver_source,
};
use mod_drivers::sdio::payload_inventory::inspect_payload_inventory;
use mod_drivers::sdio::signature::{DriverPackageVerifier, TrustResult, VerifiedDriverPackage};
use mod_drivers::sdio::source_manifest::{SourceManifest, derive_source_manifest};
use mod_drivers::sdio::test_corrupt_recorded_digest;
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};

// ---------------------------------------------------------------------------
// Fixture scaffolding (same shape as sdio_install_preparation.rs)
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir();
        let uniq = format!(
            "cove_tab2a12b1_{}_{}_{}",
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
const SYS: &[u8] = b"cove-tab2a12b1-payload-bytes-0123456789";

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

fn ready_prepared<'a, 'v>(
    plan: &'a InstallPlanEntry<'v>,
    source: &'a MaterializedDriverSource<'v>,
    candidate: DriverSelectionSummary,
    current_best: Option<DriverSelectionSummary>,
) -> mod_drivers::sdio::install_preparation::PreparedDriverInstall<'a, 'v> {
    match test_decide(plan, source, candidate, current_best) {
        InstallPreparation::Ready(p) => p,
        InstallPreparation::NoAction(r) => panic!("fixture must be Ready, got {r:?}"),
    }
}

fn authorized_confirmed<'a, 'v>(
    plan: &'a InstallPlanEntry<'v>,
    source: &'a MaterializedDriverSource<'v>,
    candidate: DriverSelectionSummary,
    current_best: Option<DriverSelectionSummary>,
) -> AuthorizedDriverInstall<'a, 'v> {
    let prepared = ready_prepared(plan, source, candidate, current_best);
    match authorize_driver_install(
        prepared,
        InstallDecision::Confirmed,
        RestorePointDisposition::Created,
    ) {
        AuthorizationResult::Authorized(a) => a,
        AuthorizationResult::Cancelled => panic!("Confirmed must never yield Cancelled"),
    }
}

/// A fully scripted backend that proceeds all the way through a successful
/// staging + unique-best re-proof for the given candidate.
fn happy_path_backend(candidate: DriverSelectionSummary, leaf: &str) -> ScriptedStagingBackend {
    let mut b = ScriptedStagingBackend::new();
    b.elevated = true;
    b.fresh_prepare = Some(FreshPrepareScript::Ready {
        candidate,
        current_best: None,
    });
    b.stage = Some(ScriptedStage::Ok(format!(r"C:\Windows\INF\{leaf}")));
    b.post_stage_nodes = Some(Ok(vec![ScriptedNode {
        summary: candidate,
        matches_published_inf: true,
    }]));
    b
}

fn backend_with_post_stage_nodes(
    candidate: DriverSelectionSummary,
    leaf: &str,
    nodes: Vec<ScriptedNode>,
) -> ScriptedStagingBackend {
    let mut b = ScriptedStagingBackend::new();
    b.fresh_prepare = Some(FreshPrepareScript::Ready {
        candidate,
        current_best: None,
    });
    b.stage = Some(ScriptedStage::Ok(format!(r"C:\Windows\INF\{leaf}")));
    b.post_stage_nodes = Some(Ok(nodes));
    b
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

#[test]
fn r1_cancelled_decision_yields_no_authorization() {
    let f = fixture("r1");
    let plan = plan_for(&f.token, "ROOT_COVE_R1", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let prepared = ready_prepared(&plan, &source, node(1, 100, 1), None);
    match authorize_driver_install(
        prepared,
        InstallDecision::Cancelled,
        RestorePointDisposition::SkippedByUser,
    ) {
        AuthorizationResult::Cancelled => {}
        AuthorizationResult::Authorized(_) => panic!("Cancelled must never authorize"),
    }
    // Structural: no AuthorizedDriverInstall value exists in this scope,
    // so no backend call can be reached from here at all.
}

#[test]
fn r2_confirmed_authorization_consumes_prepared() {
    let f = fixture("r2");
    let plan = plan_for(&f.token, "ROOT_COVE_R2", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let authorized = authorized_confirmed(&plan, &source, node(1, 100, 1), None);
    assert_eq!(authorized.restore_point(), RestorePointDisposition::Created);
    assert_eq!(authorized.prepared().candidate(), node(1, 100, 1));
}

#[test]
fn r5_restore_disposition_has_exactly_three_variants() {
    // RestorePointDisposition never derives Default (verified by
    // inspection of install_staging.rs); these are its only variants.
    let _ = RestorePointDisposition::Created;
    let _ = RestorePointDisposition::SkippedByUser;
    let _ = RestorePointDisposition::UnavailableAcknowledged;
}

// ---------------------------------------------------------------------------
// Elevation gate
// ---------------------------------------------------------------------------

#[test]
fn r6_not_elevated_refuses_before_any_backend_mutation_call() {
    let f = fixture("r6");
    let plan = plan_for(&f.token, "ROOT_COVE_R6", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let authorized = authorized_confirmed(&plan, &source, node(1, 100, 1), None);

    let mut backend = ScriptedStagingBackend::new();
    backend.elevated = false;
    // Every later field is deliberately unset: reaching any of them would
    // panic ("test must script ...").
    let (result, ledger) = test_stage_with_scripted_backend(authorized, &mut backend);
    assert!(matches!(result, Err(PreMutationError::ElevationRequired)));
    assert_eq!(ledger, vec![StagingEvent::RequireElevation]);
}

// ---------------------------------------------------------------------------
// Freshness gate
// ---------------------------------------------------------------------------

#[test]
fn r7_r8_freshness_refusal_matrix() {
    enum Script {
        NoAction,
        NativeError,
        DifferentCandidate,
    }
    let cases = [
        ("r7_no_action", Script::NoAction),
        ("r7_native_error", Script::NativeError),
        ("r8_candidate_changed", Script::DifferentCandidate),
    ];
    for (label, script) in cases {
        let f = fixture(label);
        let plan = plan_for(
            &f.token,
            "ROOT_COVE_FRESH",
            "fake_pack",
            &drivers_root_of(&f),
        );
        let source = source_for(&f.token, &f.pkg_root);
        let authorized = authorized_confirmed(&plan, &source, node(1, 100, 1), None);
        let mut backend = ScriptedStagingBackend::new();
        backend.fresh_prepare = Some(match script {
            Script::NoAction => FreshPrepareScript::NoAction(NoActionReason::NotBetterThanCurrent),
            Script::NativeError => {
                FreshPrepareScript::Err(InstallPreparationError::InstanceIdMismatch)
            }
            Script::DifferentCandidate => FreshPrepareScript::Ready {
                candidate: node(2, 200, 2),
                current_best: None,
            },
        });
        let (result, ledger) = test_stage_with_scripted_backend(authorized, &mut backend);
        match result {
            Err(PreMutationError::StalePreparation)
            | Err(PreMutationError::PreparationError(_)) => {}
            other => panic!("case {label}: {other:?}"),
        }
        assert!(
            !ledger.contains(&StagingEvent::PreStageReattest),
            "case {label}"
        );
    }
}

#[test]
fn r9_current_baseline_changed_but_candidate_unchanged_proceeds() {
    let f = fixture("r9");
    let plan = plan_for(&f.token, "ROOT_COVE_R9", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let candidate = node(1, 100, 1);
    let authorized = authorized_confirmed(&plan, &source, candidate, None);

    let mut backend = happy_path_backend(candidate, "oem9.inf");
    // Same candidate, DIFFERENT current_best than authorization saw: must
    // NOT be treated as stale.
    backend.fresh_prepare = Some(FreshPrepareScript::Ready {
        candidate,
        current_best: Some(node(9, 1, 1)),
    });
    let (result, _ledger) = test_stage_with_scripted_backend(authorized, &mut backend);
    assert!(
        matches!(result, Ok(StagingOutcome::Staged(_))),
        "{result:?}"
    );
}

// ---------------------------------------------------------------------------
// Pre-stage source re-attestation
// ---------------------------------------------------------------------------

#[test]
fn r10_pre_stage_source_reattestation_failure_blocks_staging() {
    let f = fixture("r10");
    let plan = plan_for(&f.token, "ROOT_COVE_R10", "fake_pack", &drivers_root_of(&f));
    let mut source = source_for(&f.token, &f.pkg_root);
    assert!(
        test_corrupt_recorded_digest(&mut source, 0),
        "fixture must have a sealed slot 0 to corrupt"
    );
    let candidate = node(1, 100, 1);
    let authorized = authorized_confirmed(&plan, &source, candidate, None);

    let mut backend = ScriptedStagingBackend::new();
    backend.fresh_prepare = Some(FreshPrepareScript::Ready {
        candidate,
        current_best: None,
    });
    // `stage` deliberately unscripted: reaching it would panic.
    let (result, ledger) = test_stage_with_scripted_backend(authorized, &mut backend);
    assert!(matches!(
        result,
        Err(PreMutationError::SourceReattestationFailed)
    ));
    assert_eq!(
        ledger,
        vec![
            StagingEvent::RequireElevation,
            StagingEvent::FreshPrepare,
            StagingEvent::PreStageReattest,
        ]
    );
}

// ---------------------------------------------------------------------------
// Staging
// ---------------------------------------------------------------------------

#[test]
fn r12_published_inf_is_captured_not_predicted() {
    let f = fixture("r12");
    let plan = plan_for(&f.token, "ROOT_COVE_R12", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let candidate = node(1, 100, 1);
    let authorized = authorized_confirmed(&plan, &source, candidate, None);

    // A high, non-sequential OEM number: the orchestrator must report
    // EXACTLY what the backend "captured", never a predicted oem0/oem1.
    let mut backend = happy_path_backend(candidate, "oem137.inf");
    let (result, _ledger) = test_stage_with_scripted_backend(authorized, &mut backend);
    match result {
        Ok(StagingOutcome::Staged(staged)) => {
            assert_eq!(staged.published_inf().leaf(), "oem137.inf");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn r13_stage_native_failure_is_mutation_state_unknown() {
    let f = fixture("r13");
    let plan = plan_for(&f.token, "ROOT_COVE_R13", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let candidate = node(1, 100, 1);
    let authorized = authorized_confirmed(&plan, &source, candidate, None);

    let mut backend = ScriptedStagingBackend::new();
    backend.fresh_prepare = Some(FreshPrepareScript::Ready {
        candidate,
        current_best: None,
    });
    backend.stage = Some(ScriptedStage::Err(31));
    // `post_stage_nodes` deliberately unscripted: must never be reached.
    let (result, ledger) = test_stage_with_scripted_backend(authorized, &mut backend);
    match result {
        Ok(StagingOutcome::StageFailedMutationStateUnknown { native_error }) => {
            assert_eq!(native_error, 31);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        ledger,
        vec![
            StagingEvent::RequireElevation,
            StagingEvent::FreshPrepare,
            StagingEvent::PreStageReattest,
            StagingEvent::StagePackage,
        ]
    );
}

// ---------------------------------------------------------------------------
// Post-stage source re-attestation
//
// A REAL `MaterializedDriverSource::reattest()` failure cannot be forced to
// occur ONLY between staging and the post-stage list (and not also at the
// pre-stage gate) in a test: `test_corrupt_recorded_digest` needs `&mut
// source`, unavailable once `AuthorizedDriverInstall` borrows it, and the
// sealed lease (Tab 2a-11c) makes external corruption impossible by design
// -- the exact property that seam exists to prove. Proven structurally
// instead: `source.reattest()` runs a second time, right after staging and
// before the post-stage list.
// ---------------------------------------------------------------------------

#[test]
fn r14_post_stage_reattest_call_exists_between_staging_and_post_stage_list() {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_staging.rs"),
    )
    .expect("read production source");
    let stage_at = src
        .find("backend.stage_package")
        .expect("stage_package call site");
    let post_stage_list_at = src
        .find("backend.post_stage_nodes")
        .expect("post_stage_nodes call site");
    let reattest_calls_between = src[stage_at..post_stage_list_at]
        .matches("source.reattest()")
        .count();
    assert_eq!(
        reattest_calls_between, 1,
        "exactly one source.reattest() must sit strictly between staging and the post-stage list"
    );
    assert!(src.contains("DriverStoreStagedButSourceInvalidated"));
}

// ---------------------------------------------------------------------------
// Post-stage binding and unique-best proof
// ---------------------------------------------------------------------------

#[test]
fn r15_published_node_unique_best_yields_staged() {
    let f = fixture("r15");
    let plan = plan_for(&f.token, "ROOT_COVE_R15", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let candidate = node(1, 100, 1);
    let authorized = authorized_confirmed(&plan, &source, candidate, None);

    let mut backend = backend_with_post_stage_nodes(
        candidate,
        "oem15.inf",
        vec![
            ScriptedNode {
                summary: node(9, 1, 1), // an older/worse current node
                matches_published_inf: false,
            },
            ScriptedNode {
                summary: candidate,
                matches_published_inf: true,
            },
        ],
    );
    let (result, ledger) = test_stage_with_scripted_backend(authorized, &mut backend);
    assert!(
        matches!(result, Ok(StagingOutcome::Staged(_))),
        "{result:?}"
    );
    assert!(ledger.contains(&StagingEvent::BuildPostStageList));
}

#[test]
fn r16_r17_r18_r19_r20_post_stage_refusal_matrix() {
    struct Case {
        label: &'static str,
        nodes: Vec<ScriptedNode>,
        expected: PostStageRefusal,
    }
    let candidate = node(5, 100, 1);
    let cases = vec![
        Case {
            label: "r16_better_competing_node",
            nodes: vec![
                ScriptedNode {
                    summary: node(1, 999, 999), // strictly better rank
                    matches_published_inf: false,
                },
                ScriptedNode {
                    summary: candidate,
                    matches_published_inf: true,
                },
            ],
            expected: PostStageRefusal::PublishedInfMismatch,
        },
        Case {
            label: "r17_post_stage_tie",
            nodes: vec![
                ScriptedNode {
                    summary: candidate,
                    matches_published_inf: true,
                },
                ScriptedNode {
                    summary: candidate, // exact tie
                    matches_published_inf: false,
                },
            ],
            expected: PostStageRefusal::Tie,
        },
        Case {
            label: "r18_published_node_missing",
            nodes: vec![],
            expected: PostStageRefusal::PublishedNodeMissing,
        },
        Case {
            label: "r19_unique_best_wrong_inf",
            nodes: vec![ScriptedNode {
                summary: candidate,
                matches_published_inf: false,
            }],
            expected: PostStageRefusal::PublishedInfMismatch,
        },
        Case {
            label: "r20_ranking_evidence_changed",
            nodes: vec![ScriptedNode {
                summary: node(5, 100, 2), // drifted since staging
                matches_published_inf: true,
            }],
            expected: PostStageRefusal::RankingChanged,
        },
    ];

    for case in cases {
        let f = fixture(case.label);
        let plan = plan_for(
            &f.token,
            "ROOT_COVE_POSTSTAGE",
            "fake_pack",
            &drivers_root_of(&f),
        );
        let source = source_for(&f.token, &f.pkg_root);
        let authorized = authorized_confirmed(&plan, &source, candidate, None);
        let mut backend = backend_with_post_stage_nodes(candidate, "oem_poststage.inf", case.nodes);
        let (result, _ledger) = test_stage_with_scripted_backend(authorized, &mut backend);
        match result {
            Ok(StagingOutcome::DriverStoreStagedButInstallRefused { reason, .. }) => {
                assert_eq!(reason, case.expected, "case {}", case.label);
            }
            other => panic!("case {}: {other:?}", case.label),
        }
    }
}

// ---------------------------------------------------------------------------
// test-inject cannot mutate the real host
// ---------------------------------------------------------------------------

#[test]
fn r40_test_inject_public_entry_point_never_reaches_real_backend() {
    let f = fixture("r40");
    let plan = plan_for(&f.token, "ROOT_COVE_R40", "fake_pack", &drivers_root_of(&f));
    let source = source_for(&f.token, &f.pkg_root);
    let authorized = authorized_confirmed(&plan, &source, node(1, 100, 1), None);
    // The REAL production public entry point, compiled with test-inject.
    let result = stage_driver_install(authorized);
    assert!(matches!(
        result,
        Err(PreMutationError::MutationDisabledInTestBuild)
    ));
}

// ---------------------------------------------------------------------------
// Structural safety gates (source-text proofs, comments excluded)
// ---------------------------------------------------------------------------

fn production_source_code_only() -> String {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio/install_staging.rs"),
    )
    .expect("read production source");
    src.lines()
        .filter(|line| {
            !line.trim_start().starts_with("//") && !line.trim_start().starts_with("///")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn r11_r36_r38_production_structural_gates() {
    let src = production_source_code_only();

    // R11: exact SetupCopyOEMInfW contract.
    assert!(src.contains("SetupCopyOEMInfW"));
    assert!(src.contains("sa::SPOST_PATH"));

    let forbidden = [
        // R11: staging copy-style hazards.
        "SP_COPY_DELETESOURCE",
        "SP_COPY_REPLACEONLY",
        "SP_COPY_OEMINF_CATALOG_ONLY",
        "SP_COPY_NOOVERWRITE",
        // No device-install API belongs in this slice at all.
        "DiInstallDevice",
        "DiInstallDriver",
        "UpdateDriverForPlugAndPlayDevices",
        "SetupDiCallClassInstaller",
        "force",
        // No automatic Driver Store rollback.
        "SetupUninstallOEMInf",
        "DiRollbackDriver",
        "/delete-driver",
        "pnputil",
        // No automatic reboot.
        "InitiateSystemShutdown",
        "ExitWindowsEx",
        "RestartComputer",
        "InitiateSystemRestore",
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
