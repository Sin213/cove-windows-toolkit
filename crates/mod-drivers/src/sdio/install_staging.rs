//! Tab 2a-12b1 - authorized Driver Store staging.
//!
//! Cove's FIRST production mutation code: `SetupCopyOEMInfW` (Driver Store
//! staging). Builds strictly on 12a's read-only `PreparedDriverInstall`; no
//! instance id, INF path or candidate evidence is ever accepted as a
//! separate argument.
//!
//! ```text
//! PreparedDriverInstall
//!   -> authorize_driver_install (Confirmed + restore disposition)
//!   -> AuthorizedDriverInstall (one-shot, non-Clone)
//!   -> stage_driver_install
//!        elevation -> fresh re-preparation (same candidate)
//!        -> pre-stage reattest -> SetupCopyOEMInfW <- FIRST MUTATION
//!        -> post-stage reattest -> fresh post-stage list + INF binding
//!        -> unique-best proof -> StagedDriverInstall
//! ```
//!
//! Stops after proving the staged Cove node is still the unique best match;
//! it never calls `DiInstallDevice`. The exact-device install itself is a
//! separate slice (2a-12b2) that consumes the `StagedDriverInstall`
//! capability this module returns and re-proves everything it needs
//! immediately before installing (Section 41 TOCTOU minimization: this
//! module's own proof is not treated as still valid across a slice/session
//! boundary).
//!
//! Off Windows: `PreMutationError::PlatformUnsupported`. Under `test-inject`
//! the PUBLIC entry point (`stage_driver_install`) fails closed with
//! `PreMutationError::MutationDisabledInTestBuild` instead of routing to the
//! real backend, which still compiles and links. Tests drive the same
//! state machine through `test_stage_with_scripted_backend`.

use std::path::Path;

use crate::sdio::install_plan::InstallPlanEntry;
use crate::sdio::install_preparation::{
    self, BestSelection, DriverSelectionSummary, InstallPreparation, InstallPreparationError,
    PreparedDriverInstall, select_unique_best, setupapi_inf_paths_match,
};
use crate::sdio::package_materialization::MaterializedDriverSource;

// ---------------------------------------------------------------------------
// Authorization (one-shot; consumes PreparedDriverInstall)
// ---------------------------------------------------------------------------

/// The user/orchestrator's one-shot decision on whether to proceed. Never
/// stored, replayed or defaulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallDecision {
    Confirmed,
    Cancelled,
}

/// What happened to the system-restore-point decision before this
/// transaction was authorized. This slice never calls `mod-restore` itself.
/// No `Unknown`/`Default`/`NotConsidered` variant: a restore-point decision
/// must already have happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePointDisposition {
    Created,
    SkippedByUser,
    UnavailableAcknowledged,
}

/// A one-shot, non-Clone authorization token binding a proven
/// `PreparedDriverInstall` to an explicit user decision and restore-point
/// disposition. The only way to obtain one is `authorize_driver_install`
/// with `InstallDecision::Confirmed`.
///
/// Not Clone. Compiler RED: fails only because AuthorizedDriverInstall does
/// not implement Clone.
///
/// ```compile_fail
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<mod_drivers::sdio::install_staging::AuthorizedDriverInstall<'static, 'static>>();
/// ```
///
/// Cannot outlive the PreparedDriverInstall it consumes. Compiler RED:
/// fails only because 'a cannot be extended to 'static.
///
/// ```compile_fail
/// use mod_drivers::sdio::install_staging::AuthorizedDriverInstall;
/// fn escape<'a, 'v>(a: AuthorizedDriverInstall<'a, 'v>) -> AuthorizedDriverInstall<'static, 'static> { a }
/// ```
///
/// Companion positive case, confirming the failure above is the lifetime:
///
/// ```
/// use mod_drivers::sdio::install_staging::AuthorizedDriverInstall;
/// fn keep<'a, 'v>(a: AuthorizedDriverInstall<'a, 'v>) -> AuthorizedDriverInstall<'a, 'v> { a }
/// ```
pub struct AuthorizedDriverInstall<'a, 'v> {
    prepared: PreparedDriverInstall<'a, 'v>,
    restore_point: RestorePointDisposition,
}

impl std::fmt::Debug for AuthorizedDriverInstall<'_, '_> {
    /// Redacted: delegates to `PreparedDriverInstall`'s own redacted Debug.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedDriverInstall")
            .field("prepared", &self.prepared)
            .field("restore_point", &self.restore_point)
            .finish()
    }
}

impl<'a, 'v> AuthorizedDriverInstall<'a, 'v> {
    pub fn prepared(&self) -> &PreparedDriverInstall<'a, 'v> {
        &self.prepared
    }
    pub fn restore_point(&self) -> RestorePointDisposition {
        self.restore_point
    }
    /// Consume this one-shot token. Used only by the staging executor.
    fn into_parts(self) -> (PreparedDriverInstall<'a, 'v>, RestorePointDisposition) {
        (self.prepared, self.restore_point)
    }
}

/// The outcome of an authorization attempt.
#[derive(Debug)]
pub enum AuthorizationResult<'a, 'v> {
    Authorized(AuthorizedDriverInstall<'a, 'v>),
    Cancelled,
}

/// Authorize (or refuse to authorize) mutating a system from an already
/// proven `PreparedDriverInstall`. ALWAYS consumes `prepared`: `Cancelled`
/// drops it with zero backend calls; `Confirmed` (with its mandatory
/// restore-point disposition) produces exactly one `AuthorizedDriverInstall`.
pub fn authorize_driver_install<'a, 'v>(
    prepared: PreparedDriverInstall<'a, 'v>,
    decision: InstallDecision,
    restore_point: RestorePointDisposition,
) -> AuthorizationResult<'a, 'v> {
    match decision {
        InstallDecision::Cancelled => AuthorizationResult::Cancelled,
        InstallDecision::Confirmed => AuthorizationResult::Authorized(AuthorizedDriverInstall {
            prepared,
            restore_point,
        }),
    }
}

// ---------------------------------------------------------------------------
// Pre-mutation errors (guarantee zero mutating native calls)
// ---------------------------------------------------------------------------

/// Every variant here guarantees zero mutating native calls occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PreMutationError {
    #[error("driver install staging needs Windows object handles")]
    PlatformUnsupported,
    /// Built with `test-inject`: refuses to touch real Driver Store state.
    #[error("mutation is disabled in a test-inject build")]
    MutationDisabledInTestBuild,
    /// Fail-closed: a failure to even query elevation counts as "not elevated".
    #[error("administrator elevation is required before driver installation")]
    ElevationRequired,
    /// Fresh re-preparation returned NoAction or a different candidate than
    /// the one authorized.
    #[error("the authorized preparation is no longer fresh")]
    StalePreparation,
    #[error("re-running install preparation failed: {0}")]
    PreparationError(InstallPreparationErrorKind),
    #[error("materialized source failed re-attestation before staging")]
    SourceReattestationFailed,
    #[error("materialized INF path uses an unsupported namespace form")]
    InvalidCurrentInfPath,
}

/// A Copy-able summary of `InstallPreparationError`'s discriminant (kept
/// distinct so `PreMutationError` can stay `Copy`); the specific
/// native/precondition cause is not needed past this pre-mutation boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallPreparationErrorKind(pub(crate) &'static str);

impl std::fmt::Display for InstallPreparationErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl From<&InstallPreparationError> for InstallPreparationErrorKind {
    fn from(e: &InstallPreparationError) -> Self {
        InstallPreparationErrorKind(match e {
            InstallPreparationError::PlatformUnsupported => "platform_unsupported",
            InstallPreparationError::PackageBindingMismatch => "package_binding_mismatch",
            InstallPreparationError::Source(_) => "source",
            InstallPreparationError::InvalidTargetInstanceId => "invalid_target_instance_id",
            InstallPreparationError::PathFormUnsupported => "path_form_unsupported",
            InstallPreparationError::SourcePathTooLong => "source_path_too_long",
            InstallPreparationError::NativeCall { .. } => "native_call",
            InstallPreparationError::InstanceIdMismatch => "instance_id_mismatch",
            InstallPreparationError::CandidatePathMismatch => "candidate_path_mismatch",
            InstallPreparationError::DriverDetailTooLarge => "driver_detail_too_large",
            InstallPreparationError::TooManyDriverNodes => "too_many_driver_nodes",
        })
    }
}

// ---------------------------------------------------------------------------
// Published INF (the Driver Store's own answer, never predicted)
// ---------------------------------------------------------------------------

/// The INF `SetupCopyOEMInfW` actually published into the Driver Store,
/// captured from Windows, never predicted. Only the leaf (`oemNN.inf`) is
/// public; the full path stays crate-internal (privacy contract).
#[derive(Clone, PartialEq, Eq)]
pub struct PublishedInf {
    full_path: String,
    leaf: String,
}

impl PublishedInf {
    pub fn leaf(&self) -> &str {
        &self.leaf
    }
    /// Used only to bind a post-stage node's reported INF path against this
    /// exact published file; never logged or displayed.
    pub(crate) fn normalized_full_path(&self) -> &str {
        &self.full_path
    }
}

impl std::fmt::Debug for PublishedInf {
    /// Redacted: never formats the full system Driver Store path.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublishedInf")
            .field("leaf", &self.leaf)
            .finish_non_exhaustive()
    }
}

/// Parse and validate the string `SetupCopyOEMInfW` reported as the
/// destination INF file name: non-empty, a supported local drive-absolute
/// form, and a non-empty filename component. Shared by the real backend
/// (parsing the native wide-string buffer) and the scripted test backend
/// (parsing a fixture string), so a test can never take a shortcut the
/// production parser would reject.
fn parse_published_inf(reported: &str) -> Option<PublishedInf> {
    if reported.is_empty() {
        return None;
    }
    let normalized =
        install_preparation::normalize_local_setupapi_path(Path::new(reported)).ok()?;
    let leaf = Path::new(&normalized)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())?;
    if leaf.is_empty() {
        return None;
    }
    Some(PublishedInf {
        full_path: normalized,
        leaf,
    })
}

// ---------------------------------------------------------------------------
// Staged capability (non-Clone; consumed by 2a-12b2)
// ---------------------------------------------------------------------------

/// Why a staged package was refused device installation (the staging IS
/// NOT rolled back for any of these: staging already happened and Cove
/// never auto-reverses it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostStageRefusal {
    /// The fresh post-stage compatible list has no node at all.
    PublishedNodeMissing,
    /// Two or more nodes tie for best in the fresh post-stage list.
    Tie,
    /// The unique best node's INF does not bind to the published Cove INF.
    PublishedInfMismatch,
    /// Unique-best and INF-bound, but rank/date/version drifted since staging.
    RankingChanged,
    /// Enumerating the fresh post-stage list itself failed natively.
    EnumerationFailed,
}

/// A one-shot, non-Clone capability proving: the package is staged in the
/// Driver Store (`published_inf`), AND immediately afterward the staged
/// Cove node was re-proven the unique best match against a fresh
/// independent compatible-list rebuild. Consumed by 2a-12b2's
/// `DiInstallDevice` step, which re-opens/re-proves everything itself
/// rather than trusting this proof to still hold (Section 41).
///
/// Not Clone. Compiler RED: fails only because StagedDriverInstall does
/// not implement Clone.
///
/// ```compile_fail
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<mod_drivers::sdio::install_staging::StagedDriverInstall<'static, 'static>>();
/// ```
pub struct StagedDriverInstall<'a, 'v> {
    prepared: PreparedDriverInstall<'a, 'v>,
    published_inf: PublishedInf,
}

impl std::fmt::Debug for StagedDriverInstall<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedDriverInstall")
            .field("prepared", &self.prepared)
            .field("published_inf", &self.published_inf)
            .finish()
    }
}

impl<'a, 'v> StagedDriverInstall<'a, 'v> {
    pub fn prepared(&self) -> &PreparedDriverInstall<'a, 'v> {
        &self.prepared
    }
    pub fn published_inf(&self) -> &PublishedInf {
        &self.published_inf
    }
}

/// The full mutation-aware outcome domain for the staging phase. Every
/// variant past a successful `SetupCopyOEMInfW` call reports the captured
/// `PublishedInf`: the Driver Store is never claimed unaffected past that
/// point.
#[derive(Debug)]
pub enum StagingOutcome<'a, 'v> {
    /// Staged and re-proven unique-best; ready for 2a-12b2.
    Staged(StagedDriverInstall<'a, 'v>),
    /// `SetupCopyOEMInfW`'s failure contract does not let Cove distinguish
    /// "definitely untouched" from "partially touched".
    StageFailedMutationStateUnknown { native_error: u32 },
    /// Staged, but the source failed re-attestation right after.
    DriverStoreStagedButSourceInvalidated { published_inf: PublishedInf },
    /// Staged, but the post-stage unique-best proof refused.
    DriverStoreStagedButInstallRefused {
        published_inf: PublishedInf,
        reason: PostStageRefusal,
    },
}

pub type StagingResult<'a, 'v> = Result<StagingOutcome<'a, 'v>, PreMutationError>;

// ---------------------------------------------------------------------------
// Backend seam (production Windows APIs vs. scripted test state machine)
// ---------------------------------------------------------------------------

/// One post-stage compatible-list node's evidence, as seen by the
/// orchestrator: enough to run the unique-best proof, without exposing any
/// raw native handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PostStageNode {
    pub(crate) summary: DriverSelectionSummary,
    pub(crate) matches_published_inf: bool,
}

/// The seam separating orchestration (this module's pure state machine)
/// from its native effects. `WindowsNativeBackend` is the only production
/// implementation; `ScriptedStagingBackend` (test-inject only) is a
/// deterministic fake modeling the SAME phase ordering without ever
/// calling a real mutating API.
pub(crate) trait StagingBackend {
    /// Fail-closed: query failure counts as "not elevated".
    fn is_elevated(&mut self) -> bool;

    /// Real backend calls `prepare_driver_install`; scripted backend
    /// reconstructs a real `InstallPreparation` via 12a's `test_decide`.
    fn fresh_prepare<'a, 'v>(
        &mut self,
        plan: &'a InstallPlanEntry<'v>,
        source: &'a MaterializedDriverSource<'v>,
    ) -> Result<InstallPreparation<'a, 'v>, InstallPreparationError>;

    /// THE FIRST MUTATION. `inf_path` is freshly normalized/re-attested.
    fn stage_package(&mut self, inf_path: &str) -> Result<PublishedInf, u32>;

    /// Fresh normal Driver Store compatible list, bound to the published INF.
    fn post_stage_nodes(
        &mut self,
        instance_id: &str,
        published: &PublishedInf,
    ) -> Result<Vec<PostStageNode>, u32>;
}

// ---------------------------------------------------------------------------
// Staging ledger (auditable phase ordering; exposed under test-inject)
// ---------------------------------------------------------------------------

#[cfg(feature = "test-inject")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingEvent {
    RequireElevation,
    FreshPrepare,
    PreStageReattest,
    StagePackage,
    PostStageReattest,
    BuildPostStageList,
}

#[cfg(not(feature = "test-inject"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StagingEvent {
    RequireElevation,
    FreshPrepare,
    PreStageReattest,
    StagePackage,
    PostStageReattest,
    BuildPostStageList,
}

// ---------------------------------------------------------------------------
// Orchestrator (pure state machine over the StagingBackend seam)
// ---------------------------------------------------------------------------

fn run_staging<'a, 'v>(
    authorized: AuthorizedDriverInstall<'a, 'v>,
    backend: &mut impl StagingBackend,
    ledger: &mut Vec<StagingEvent>,
) -> StagingResult<'a, 'v> {
    let (prepared, _restore_point) = authorized.into_parts();
    let plan = prepared.plan();
    let source = prepared.source();
    let instance_id = prepared.target_device_instance_id().to_string();
    let original_candidate = prepared.candidate();

    ledger.push(StagingEvent::RequireElevation);
    if !backend.is_elevated() {
        return Err(PreMutationError::ElevationRequired);
    }

    // current_best MAY differ from authorization; only candidate equality
    // is required.
    ledger.push(StagingEvent::FreshPrepare);
    let fresh_result = backend
        .fresh_prepare(plan, source)
        .map_err(|e| PreMutationError::PreparationError(InstallPreparationErrorKind::from(&e)))?;
    let fresh = match fresh_result {
        InstallPreparation::Ready(fresh_prepared) => fresh_prepared,
        InstallPreparation::NoAction(_reason) => return Err(PreMutationError::StalePreparation),
    };
    if fresh.candidate() != original_candidate {
        return Err(PreMutationError::StalePreparation);
    }

    ledger.push(StagingEvent::PreStageReattest);
    source
        .reattest()
        .map_err(|_| PreMutationError::SourceReattestationFailed)?;
    // The freshly re-attested current INF path, never a cached path.
    let inf_path = source
        .current_inf_path()
        .map_err(|_| PreMutationError::SourceReattestationFailed)?;
    let normalized_inf = install_preparation::normalize_local_setupapi_path(&inf_path)
        .map_err(|_| PreMutationError::InvalidCurrentInfPath)?;

    // ---- PRE-MUTATION boundary: every return above guarantees zero
    // mutating native calls occurred. ----

    ledger.push(StagingEvent::StagePackage);
    let published = match backend.stage_package(&normalized_inf) {
        Ok(p) => p,
        Err(native_error) => {
            return Ok(StagingOutcome::StageFailedMutationStateUnknown { native_error });
        }
    };

    ledger.push(StagingEvent::PostStageReattest);
    if source.reattest().is_err() {
        return Ok(StagingOutcome::DriverStoreStagedButSourceInvalidated {
            published_inf: published,
        });
    }

    ledger.push(StagingEvent::BuildPostStageList);
    let refuse = |published: PublishedInf, reason| {
        Ok(StagingOutcome::DriverStoreStagedButInstallRefused {
            published_inf: published,
            reason,
        })
    };
    let nodes = match backend.post_stage_nodes(&instance_id, &published) {
        Ok(n) => n,
        Err(_native_error) => return refuse(published, PostStageRefusal::EnumerationFailed),
    };

    let summaries: Vec<DriverSelectionSummary> = nodes.iter().map(|n| n.summary).collect();
    let winner_index = match select_unique_best(&summaries) {
        BestSelection::NotCompatible => {
            return refuse(published, PostStageRefusal::PublishedNodeMissing);
        }
        BestSelection::Ambiguous => return refuse(published, PostStageRefusal::Tie),
        BestSelection::Unique(i) => i,
    };
    let winner = nodes[winner_index];

    if !winner.matches_published_inf {
        return refuse(published, PostStageRefusal::PublishedInfMismatch);
    }
    if winner.summary != fresh.candidate() {
        return refuse(published, PostStageRefusal::RankingChanged);
    }

    Ok(StagingOutcome::Staged(StagedDriverInstall {
        prepared,
        published_inf: published,
    }))
}

// ---------------------------------------------------------------------------
// Production entry point
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
pub fn stage_driver_install<'a, 'v>(
    _authorized: AuthorizedDriverInstall<'a, 'v>,
) -> StagingResult<'a, 'v> {
    Err(PreMutationError::PlatformUnsupported)
}

/// The test-inject build's public entry point NEVER routes to the real
/// Windows backend, even though that backend is fully compiled below.
/// Changing this function to call `WindowsNativeBackend` is exactly the
/// mutant this gate exists to kill.
#[cfg(all(windows, feature = "test-inject"))]
pub fn stage_driver_install<'a, 'v>(
    _authorized: AuthorizedDriverInstall<'a, 'v>,
) -> StagingResult<'a, 'v> {
    Err(PreMutationError::MutationDisabledInTestBuild)
}

#[cfg(all(windows, not(feature = "test-inject")))]
pub fn stage_driver_install<'a, 'v>(
    authorized: AuthorizedDriverInstall<'a, 'v>,
) -> StagingResult<'a, 'v> {
    let mut backend = win::WindowsNativeBackend;
    let mut ledger = Vec::new();
    run_staging(authorized, &mut backend, &mut ledger)
}

// ---------------------------------------------------------------------------
// Test-only seam: drive the SAME orchestrator through a scripted backend
// ---------------------------------------------------------------------------

#[cfg(feature = "test-inject")]
pub use test_seam::{
    FreshPrepareScript, ScriptedNode, ScriptedStage, ScriptedStagingBackend,
    test_stage_with_scripted_backend,
};

#[cfg(feature = "test-inject")]
mod test_seam {
    use super::*;
    use crate::sdio::install_preparation::NoActionReason;

    /// What the scripted backend's `fresh_prepare` should report.
    pub enum FreshPrepareScript {
        Ready {
            candidate: DriverSelectionSummary,
            current_best: Option<DriverSelectionSummary>,
        },
        NoAction(NoActionReason),
        Err(InstallPreparationError),
    }

    /// What `stage_package` should report.
    pub enum ScriptedStage {
        Ok(String),
        Err(u32),
    }

    /// One post-stage compatible-list node, as scripted by a test.
    #[derive(Clone)]
    pub struct ScriptedNode {
        pub summary: DriverSelectionSummary,
        pub matches_published_inf: bool,
    }

    /// A fully deterministic, in-memory `StagingBackend`. Every field is
    /// scripted explicitly by the test; there is no implicit "jump
    /// straight to Staged".
    pub struct ScriptedStagingBackend {
        pub elevated: bool,
        pub fresh_prepare: Option<FreshPrepareScript>,
        pub stage: Option<ScriptedStage>,
        pub post_stage_nodes: Option<Result<Vec<ScriptedNode>, u32>>,
    }

    impl ScriptedStagingBackend {
        pub fn new() -> Self {
            Self {
                elevated: true,
                fresh_prepare: None,
                stage: None,
                post_stage_nodes: None,
            }
        }
    }

    impl Default for ScriptedStagingBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl StagingBackend for ScriptedStagingBackend {
        fn is_elevated(&mut self) -> bool {
            self.elevated
        }

        fn fresh_prepare<'a, 'v>(
            &mut self,
            plan: &'a InstallPlanEntry<'v>,
            source: &'a MaterializedDriverSource<'v>,
        ) -> Result<InstallPreparation<'a, 'v>, InstallPreparationError> {
            match self
                .fresh_prepare
                .take()
                .expect("test must script fresh_prepare")
            {
                FreshPrepareScript::Ready {
                    candidate,
                    current_best,
                } => Ok(install_preparation::test_decide(
                    plan,
                    source,
                    candidate,
                    current_best,
                )),
                FreshPrepareScript::NoAction(reason) => Ok(InstallPreparation::NoAction(reason)),
                FreshPrepareScript::Err(e) => Err(e),
            }
        }

        fn stage_package(&mut self, _inf_path: &str) -> Result<PublishedInf, u32> {
            match self.stage.take().expect("test must script stage") {
                ScriptedStage::Ok(reported) => {
                    Ok(parse_published_inf(&reported).expect("scripted path must be valid"))
                }
                ScriptedStage::Err(code) => Err(code),
            }
        }

        fn post_stage_nodes(
            &mut self,
            _instance_id: &str,
            _published: &PublishedInf,
        ) -> Result<Vec<PostStageNode>, u32> {
            let scripted = self
                .post_stage_nodes
                .take()
                .expect("test must script post_stage_nodes")?;
            Ok(scripted
                .into_iter()
                .map(|n| PostStageNode {
                    summary: n.summary,
                    matches_published_inf: n.matches_published_inf,
                })
                .collect())
        }
    }

    /// Drive the SAME orchestrator (`run_staging`) the production entry
    /// point uses, through a caller-supplied `ScriptedStagingBackend`.
    pub fn test_stage_with_scripted_backend<'a, 'v>(
        authorized: AuthorizedDriverInstall<'a, 'v>,
        backend: &mut ScriptedStagingBackend,
    ) -> (StagingResult<'a, 'v>, Vec<StagingEvent>) {
        let mut ledger = Vec::new();
        let result = run_staging(authorized, backend, &mut ledger);
        (result, ledger)
    }
}

// ---------------------------------------------------------------------------
// Production Windows backend
// ---------------------------------------------------------------------------

// Under `test-inject`, `stage_driver_install` never reaches this backend
// (lockout by design); it still compiles and links on every Windows build.
#[cfg_attr(feature = "test-inject", allow(dead_code))]
#[cfg(windows)]
mod win {
    //! The real native surface: elevation query and Driver Store staging
    //! (`SetupCopyOEMInfW`) plus the fresh post-stage compatible-list
    //! rebuild used to re-prove unique-best. No device-install API lives
    //! here; that is 2a-12b2's job.

    use super::*;
    use std::ffi::c_void;

    use windows_sys::Win32::Devices::DeviceAndDriverInstallation as sa;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::sdio::install_preparation::win as prep_win;

    fn wide_nul(s: &str) -> Vec<u16> {
        prep_win::wide_nul(s)
    }

    fn wide_to_string(buf: &[u16]) -> String {
        prep_win::wide_to_string(buf)
    }

    fn last_error() -> u32 {
        prep_win::last_error()
    }

    struct TokenHandle(HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            // SAFETY: a live handle from a successful OpenProcessToken,
            // closed at most once.
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }

    /// Fail-closed elevation proof: any native failure counts as "not
    /// elevated", never as "elevated". No relaunch, no manifest mutation.
    fn is_elevated_native() -> bool {
        // SAFETY: GetCurrentProcess is a pseudo-handle; no cleanup needed.
        let process = unsafe { GetCurrentProcess() };
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: process is a valid pseudo-handle.
        let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
        if ok == 0 {
            return false;
        }
        let _guard = TokenHandle(token);
        let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
        let mut returned = 0u32;
        // SAFETY: token is live; struct sized exactly.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        };
        ok != 0 && elevation.TokenIsElevated != 0
    }

    pub(crate) struct WindowsNativeBackend;

    impl StagingBackend for WindowsNativeBackend {
        fn is_elevated(&mut self) -> bool {
            is_elevated_native()
        }

        fn fresh_prepare<'a, 'v>(
            &mut self,
            plan: &'a InstallPlanEntry<'v>,
            source: &'a MaterializedDriverSource<'v>,
        ) -> Result<InstallPreparation<'a, 'v>, InstallPreparationError> {
            install_preparation::prepare_driver_install(plan, source)
        }

        fn stage_package(&mut self, inf_path: &str) -> Result<PublishedInf, u32> {
            let source_wide = wide_nul(inf_path);
            const CAP: usize = 260;
            let mut dest_buf = vec![0u16; CAP];
            let mut required = 0u32;
            // SAFETY: source_wide is NUL-terminated; OEMSourceMediaLocation
            // NULL is valid for SPOST_PATH; dest_buf sized exactly, its
            // length passed exactly; no destination-component pointer
            // requested (last arg NULL) since the returned buffer already
            // contains the full path this function itself parses.
            let ok = unsafe {
                sa::SetupCopyOEMInfW(
                    source_wide.as_ptr(),
                    std::ptr::null(),
                    sa::SPOST_PATH,
                    0, // CopyStyle: no delete-source/replace-only/catalog-only/no-overwrite
                    dest_buf.as_mut_ptr(),
                    dest_buf.len() as u32,
                    &mut required,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            let reported = wide_to_string(&dest_buf);
            parse_published_inf(&reported).ok_or(0)
        }

        fn post_stage_nodes(
            &mut self,
            instance_id: &str,
            published: &PublishedInf,
        ) -> Result<Vec<PostStageNode>, u32> {
            let (device, devinfo) =
                prep_win::open_exact_device(instance_id).map_err(|_| last_error())?;
            prep_win::configure_current_store_search(device.handle(), &devinfo)
                .map_err(|_| last_error())?;
            let raw_nodes =
                prep_win::enumerate_compat_driver_nodes_with_inf_paths(device.handle(), &devinfo)
                    .map_err(|_| last_error())?;

            let expected = published.normalized_full_path();
            Ok(raw_nodes
                .into_iter()
                .map(|(summary, inf_path)| PostStageNode {
                    summary,
                    matches_published_inf: setupapi_inf_paths_match(expected, &inf_path)
                        .unwrap_or(false),
                })
                .collect())
        }
    }
}
