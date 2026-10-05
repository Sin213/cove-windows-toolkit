//! Tab 2a-13a1: process-local local-SDIO driver-update orchestration core.
//!
//! The session/restore/IPC state machine, the untrusted SDIO-root and index
//! corpus boundary, fresh-device selection, candidate accounting, native
//! unique-best selection and exact freshness binding. The production engine
//! that composes the reviewed `mod_drivers::sdio` pipeline behind
//! [`DriverUpdateEngine`], the lower authorize/stage/install mapping, the real
//! restore-point seam and the Tauri commands are Tab 2a-13a2.
//!
//! A preview never crosses IPC as a live capability: only an owned snapshot
//! (exact candidate, native selection summary, complete package digests)
//! survives, keyed by an opaque one-shot UUID v4. Install consumes the session,
//! applies the restore-point policy, and hands the snapshot to the engine,
//! which must re-prove it from a fresh inventory before any mutation. Device
//! and hardware IDs, the SDIO root, digests and session tokens are never logged
//! or returned (the token is returned only as `session_id`).

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use mod_drivers::identity::{DeviceIdentity, DriverIdentityReport};
use mod_drivers::sdio::{
    AssessedCatalogCandidate, BestSelection, CatalogCandidateMatch, CatalogOsApplicability,
    DriverSelectionSummary, MAX_CATALOGS_PER_MATCH, MaterializedPackageFileKind, PreMutationError,
    RestorePointDisposition, SdioCatalog, select_unique_best,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Preview authorization lifetime. Never refreshed by queries or retries.
pub const SESSION_TTL: Duration = Duration::from_secs(10 * 60);
/// Live preview sessions held at once. A live session is never evicted.
pub const MAX_DRIVER_UPDATE_SESSIONS: usize = 4;
/// Bound on the untrusted SDIO root text, in UTF-16 code units.
pub const MAX_SDIO_ROOT_UTF16: usize = 1024;
/// Fixed restore-point description: no device, path or token data.
const RESTORE_POINT_DESCRIPTION: &str = "Cove driver update";

// ---------------------------------------------------------------------------
// IPC contract (consumed by Tab 2a-13b)
// ---------------------------------------------------------------------------

/// Every status the three driver-update commands can return.
#[derive(Serialize, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    Ready,
    NoUpdate,
    AmbiguousLocalUpdate,
    InvalidRequest,
    InvalidSdioRoot,
    InvalidIndexCorpus,
    InventoryUnavailable,
    DegradedInventory,
    DeviceNotFound,
    UnsupportedHost,
    Busy,
    SessionExpired,
    SessionNotFound,
    SessionCapacity,
    Cancelled,
    StalePreview,
    RestorePointFailed,
    RestoreAckNotAllowed,
    ElevationRequired,
    MutationDisabledInTestBuild,
    Installed,
    InstalledPendingReboot,
    InstalledPostconditionMismatch,
    InstalledReconciliationFailed,
    InstalledSourceInvalidated,
    DriverStoreStagedInstallRefused,
    DriverStoreStagedDeviceInstallFailed,
    DriverStoreStagedSourceInvalidated,
    StageFailedUnknown,
    TemporaryCleanupFailed,
    #[default]
    InternalError,
}

impl UpdateStatus {
    /// (success, partial). `partial` marks every state past Driver Store
    /// staging that is not a clean final success; nothing implies rollback.
    fn flags(self) -> (bool, bool) {
        use UpdateStatus::*;
        match self {
            Ready | NoUpdate | Cancelled | Installed | InstalledPendingReboot => (true, false),
            InstalledPostconditionMismatch
            | InstalledReconciliationFailed
            | InstalledSourceInvalidated
            | DriverStoreStagedInstallRefused
            | DriverStoreStagedDeviceInstallFailed
            | DriverStoreStagedSourceInvalidated
            | StageFailedUnknown => (false, true),
            _ => (false, false),
        }
    }

    /// Whether the Driver Store or the device may already have been changed.
    fn system_may_be_mutated(self) -> bool {
        self.flags().1 || matches!(self, Self::Installed | Self::InstalledPendingReboot)
    }
}

/// Why a Ready candidate beats the current best, from native summaries only.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BetterBy {
    NoCurrentDriver,
    Rank,
    Date,
    Version,
}

/// Safe preview facts. `provider`, `candidate_version` and `candidate_date`
/// are SDIO display metadata only; the install decision rests on the native
/// `DriverSelectionSummary` (`candidate_rank`, `current_rank`, `better_by`).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct PreviewView {
    pub provider: Option<String>,
    pub signer: Option<String>,
    pub pack_name: String,
    pub inf_name: String,
    pub candidate_version: Option<String>,
    pub candidate_date: Option<String>,
    pub candidate_rank: u32,
    pub current_rank: Option<u32>,
    pub better_by: BetterBy,
    pub package_file_count: usize,
    pub package_total_bytes: u64,
}

/// Bounded per-preview candidate accounting.
#[derive(Serialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Diagnostics {
    pub catalogs: usize,
    pub host_compatible_candidates: usize,
    pub missing_packs: usize,
    pub unsupported_candidates: usize,
    pub rejected_candidates: usize,
    pub failed_candidates: usize,
    pub no_action_candidates: usize,
    pub ready_candidates: usize,
}

/// The one response shape of all three commands; every field is always
/// serialized (null when absent). Never carries the SDIO root, device or
/// hardware IDs, full INF/Driver Store paths or digests. `message` echoes the
/// status for the generic invoke logger; user-facing text belongs to the UI.
#[derive(Serialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct DriverUpdateResponse {
    pub success: bool,
    pub partial: bool,
    pub status: UpdateStatus,
    pub message: String,
    /// Bounded reason category (lower refusal reason, corpus problem, ...).
    pub detail: Option<String>,
    pub session_id: Option<String>,
    pub retry_session_id: Option<String>,
    pub expires_in_seconds: Option<u64>,
    pub preview: Option<PreviewView>,
    pub diagnostics: Option<Diagnostics>,
    /// `oemNN.inf` leaf only, once the Driver Store has been touched.
    pub published_inf: Option<String>,
    pub reboot_required: Option<bool>,
    pub native_error: Option<u32>,
    pub postcondition_observed: Option<bool>,
    /// Cove's own temp cleanup failed AFTER a possible system mutation; the
    /// primary status still describes what happened to the system.
    pub cleanup_warning: bool,
}

type Resp = DriverUpdateResponse;

impl DriverUpdateResponse {
    fn of(status: UpdateStatus) -> Self {
        let (success, partial) = status.flags();
        let message = snake(&status);
        Self {
            success,
            partial,
            status,
            message,
            ..Self::default()
        }
    }
    fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
    fn inf(mut self, leaf: &str) -> Self {
        self.published_inf = Some(leaf.to_owned());
        self
    }
    fn reboot(mut self, reboot: bool) -> Self {
        self.reboot_required = Some(reboot);
        self
    }
    fn code(mut self, code: u32) -> Self {
        self.native_error = Some(code);
        self
    }
}

/// `PublishedNodeMissing` -> `published_node_missing` (bounded categories).
fn snake(value: &dyn std::fmt::Debug) -> String {
    let mut out = String::new();
    for (i, ch) in format!("{value:?}").chars().enumerate() {
        if ch.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

/// The user's explicit install decision.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateDecision {
    Confirmed,
    Cancelled,
}

/// App-layer restore action, mapped to the lower disposition only after the
/// policy in `DriverUpdateService::install` holds; the UI can never claim
/// `RestorePointDisposition::Created`.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestoreAction {
    Create,
    Skip,
    AcknowledgeUnavailable,
}

// ---------------------------------------------------------------------------
// Owned snapshot domain (no live capability, no lifetime)
// ---------------------------------------------------------------------------

/// One materialized package file, owned. The digest stays internal.
#[derive(Clone, PartialEq, Eq)]
struct PackageFileSnapshot {
    relative_path: String,
    kind: MaterializedPackageFileKind,
    size: u64,
    sha256: [u8; 32],
}

/// A Ready candidate captured while live, owned after cleanup.
#[derive(Clone)]
struct CandidateSnapshot {
    candidate: CatalogCandidateMatch,
    summary: DriverSelectionSummary,
    current_best: Option<DriverSelectionSummary>,
    files: Vec<PackageFileSnapshot>,
    signer: Option<String>,
}

/// Exact freshness binding: same candidate, same native summary, same
/// complete ordered package bytes. The current Driver Store baseline and the
/// display signer may legitimately change.
fn snapshot_binds(session: &CandidateSnapshot, fresh: &CandidateSnapshot) -> bool {
    session.candidate == fresh.candidate
        && session.summary == fresh.summary
        && session.files == fresh.files
}

/// What a session authorizes install to re-prove.
#[derive(Clone)]
struct SessionSnapshot {
    canonical_sdio_root: PathBuf,
    device_instance_id: String,
    winner: CandidateSnapshot,
}

/// A process-local preview session. Never persisted, never logged.
struct DriverUpdateSession {
    expires_at: Instant,
    snapshot: SessionSnapshot,
    restore_unavailable_ack_allowed: bool,
}

impl std::fmt::Debug for DriverUpdateSession {
    /// Redacted: no root, device, candidate or digest data.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriverUpdateSession")
            .field("files", &self.snapshot.winner.files.len())
            .field("ack_allowed", &self.restore_unavailable_ack_allowed)
            .finish_non_exhaustive()
    }
}

/// Presentation reason for an already-proven (strictly better) candidate.
fn better_by(new: DriverSelectionSummary, current: Option<DriverSelectionSummary>) -> BetterBy {
    match current {
        None => BetterBy::NoCurrentDriver,
        Some(c) if c.rank() != new.rank() => BetterBy::Rank,
        Some(c) if c.driver_date_native() != new.driver_date_native() => BetterBy::Date,
        Some(_) => BetterBy::Version,
    }
}

fn preview_view(winner: &CandidateSnapshot) -> PreviewView {
    let c = &winner.candidate.candidate;
    let total = winner
        .files
        .iter()
        .fold(0u64, |t, f| t.saturating_add(f.size));
    PreviewView {
        provider: c.provider.clone(),
        signer: winner.signer.clone(),
        pack_name: winner.candidate.pack_name.clone(),
        inf_name: c.inf_filename.clone(),
        candidate_version: c.version.map(|(a, b, d, e)| format!("{a}.{b}.{d}.{e}")),
        candidate_date: c.date.map(|(y, m, d)| format!("{y:04}-{m:02}-{d:02}")),
        candidate_rank: winner.summary.rank(),
        current_rank: winner.current_best.map(|s| s.rank()),
        better_by: better_by(winner.summary, winner.current_best),
        package_file_count: winner.files.len(),
        package_total_bytes: total,
    }
}

// ---------------------------------------------------------------------------
// Engine seam
// ---------------------------------------------------------------------------

/// A zero-mutation refusal raised before any lower transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    InvalidRequest,
    InvalidSdioRoot(&'static str),
    InvalidIndexCorpus(&'static str),
    InventoryUnavailable,
    DegradedInventory,
    DeviceNotFound,
    UnsupportedHost,
    TemporaryCleanupFailed,
    Internal(&'static str),
}

impl Refusal {
    fn response(self) -> Resp {
        use UpdateStatus as S;
        let (status, detail) = match self {
            Refusal::InvalidRequest => (S::InvalidRequest, None),
            Refusal::InvalidSdioRoot(d) => (S::InvalidSdioRoot, Some(d)),
            Refusal::InvalidIndexCorpus(d) => (S::InvalidIndexCorpus, Some(d)),
            Refusal::InventoryUnavailable => (S::InventoryUnavailable, None),
            Refusal::DegradedInventory => (S::DegradedInventory, None),
            Refusal::DeviceNotFound => (S::DeviceNotFound, None),
            Refusal::UnsupportedHost => (S::UnsupportedHost, None),
            Refusal::TemporaryCleanupFailed => (S::TemporaryCleanupFailed, None),
            Refusal::Internal(d) => (S::InternalError, Some(d)),
        };
        let mut r = Resp::of(status);
        r.detail = detail.map(str::to_owned);
        r
    }
}

struct PreviewRequest {
    device_instance_id: String,
    sdio_root: String,
}

enum PreviewFound {
    Ready(Box<SessionSnapshot>, Diagnostics),
    NoUpdate(Diagnostics),
    Ambiguous(Diagnostics),
}

/// A transaction's response plus whether Cove's temp cleanup failed.
type TransactionReport = (Resp, bool);

/// The application seam. Production composes the real lower pipeline; tests
/// drive the same session/restore state machine with scripted results.
trait DriverUpdateEngine: Sync {
    fn preview(&self, request: &PreviewRequest) -> Result<PreviewFound, Refusal>;
    fn execute(&self, s: &SessionSnapshot, d: RestorePointDisposition) -> TransactionReport;
}

trait RestorePointCreator: Sync {
    fn create(&self, description: &str) -> Result<(), ()>;
}

/// A post-mutation temp-cleanup failure becomes `cleanup_warning`, never a
/// replacement status; without mutation it is a hard error.
fn finish((response, cleanup_failed): TransactionReport) -> Resp {
    match (cleanup_failed, response.status.system_may_be_mutated()) {
        (false, _) => response,
        (true, true) => Resp {
            cleanup_warning: true,
            ..response
        },
        (true, false) => Resp::of(UpdateStatus::TemporaryCleanupFailed),
    }
}

/// Lower pre-mutation errors guarantee zero mutating native calls.
fn pre_mutation(error: PreMutationError) -> Resp {
    use PreMutationError as P;
    use UpdateStatus as S;
    let status = match error {
        P::ElevationRequired => S::ElevationRequired,
        P::MutationDisabledInTestBuild => S::MutationDisabledInTestBuild,
        P::StalePreparation | P::SourceReattestationFailed => S::StalePreview,
        P::PlatformUnsupported | P::PreparationError(_) | P::InvalidCurrentInfPath => {
            S::InternalError
        }
    };
    match error {
        P::PreparationError(kind) => Resp::of(status).detail(kind.to_string()),
        other => Resp::of(status).detail(snake(&other)),
    }
}

// ---------------------------------------------------------------------------
// Session + operation state machine
// ---------------------------------------------------------------------------

type Sessions = HashMap<Uuid, DriverUpdateSession>;

struct DriverUpdateService {
    /// Serializes expensive preview/install work; fail-fast, never queued.
    operation: Mutex<()>,
    /// Held only for map operations, never across disk or native work.
    sessions: Mutex<Sessions>,
}

/// An early-exit response (boxed: it is large and travels in `Err`).
type Halt = Box<Resp>;

fn halt(status: UpdateStatus) -> Halt {
    Box::new(Resp::of(status))
}

fn poisoned<T>(_: T) -> Halt {
    Box::new(Resp::of(UpdateStatus::InternalError).detail("poisoned"))
}

impl DriverUpdateService {
    fn new() -> Self {
        let sessions = Mutex::new(HashMap::new());
        Self {
            operation: Mutex::new(()),
            sessions,
        }
    }

    /// A poisoned guard (a previous operation panicked, possibly mid-
    /// mutation) is never recovered.
    fn begin(&self) -> Result<MutexGuard<'_, ()>, Halt> {
        self.operation.try_lock().map_err(|e| match e {
            TryLockError::WouldBlock => halt(UpdateStatus::Busy),
            TryLockError::Poisoned(p) => poisoned(p),
        })
    }

    /// Prune expired sessions; refuse when still full. Live sessions are
    /// never evicted.
    fn room(&self, now: Instant) -> Result<MutexGuard<'_, Sessions>, Halt> {
        let mut sessions = self.sessions.lock().map_err(poisoned)?;
        sessions.retain(|_, s| s.expires_at > now);
        if sessions.len() >= MAX_DRIVER_UPDATE_SESSIONS {
            return Err(halt(UpdateStatus::SessionCapacity));
        }
        Ok(sessions)
    }

    fn insert(
        &self,
        snapshot: SessionSnapshot,
        expires: Instant,
        ack: bool,
        now: Instant,
    ) -> Result<Uuid, Halt> {
        let id = Uuid::new_v4();
        let session = DriverUpdateSession {
            expires_at: expires,
            snapshot,
            restore_unavailable_ack_allowed: ack,
        };
        self.room(now)?.insert(id, session);
        Ok(id)
    }

    fn check(
        &self,
        engine: &dyn DriverUpdateEngine,
        request: PreviewRequest,
        now: Instant,
    ) -> Resp {
        let _operation = match self.begin() {
            Ok(guard) => guard,
            Err(r) => return *r,
        };
        // No pipeline work when no session could be issued anyway.
        if let Err(r) = self.room(now) {
            return *r;
        }
        let (status, snapshot, diagnostics) = match engine.preview(&request) {
            Err(refusal) => return refusal.response(),
            Ok(PreviewFound::NoUpdate(d)) => (UpdateStatus::NoUpdate, None, d),
            Ok(PreviewFound::Ambiguous(d)) => (UpdateStatus::AmbiguousLocalUpdate, None, d),
            Ok(PreviewFound::Ready(s, d)) => (UpdateStatus::Ready, Some(*s), d),
        };
        tracing::info!(
            target: "cove::drivers",
            status = ?status,
            candidates = diagnostics.host_compatible_candidates,
            ready = diagnostics.ready_candidates,
            "local driver update preview finished"
        );
        let mut r = Resp::of(status);
        r.diagnostics = Some(diagnostics);
        if let Some(snapshot) = snapshot {
            r.preview = Some(preview_view(&snapshot.winner));
            match self.insert(snapshot, now + SESSION_TTL, false, now) {
                Ok(id) => r.session_id = Some(id.to_string()),
                Err(full) => return *full,
            }
            r.expires_in_seconds = Some(SESSION_TTL.as_secs());
        }
        r
    }

    /// One-shot: the session leaves the cache before any restore/driver work.
    fn consume(&self, session_id: &str, now: Instant) -> Result<DriverUpdateSession, Halt> {
        let not_found = || halt(UpdateStatus::SessionNotFound);
        let id = Uuid::parse_str(session_id).map_err(|_| not_found())?;
        let mut sessions = self.sessions.lock().map_err(poisoned)?;
        let session = sessions.remove(&id).ok_or_else(not_found)?;
        sessions.retain(|_, s| s.expires_at > now);
        if session.expires_at <= now {
            return Err(halt(UpdateStatus::SessionExpired));
        }
        Ok(session)
    }

    fn install(
        &self,
        engine: &dyn DriverUpdateEngine,
        restore: &dyn RestorePointCreator,
        session_id: &str,
        decision: UpdateDecision,
        action: RestoreAction,
        now: Instant,
    ) -> Resp {
        let _operation = match self.begin() {
            Ok(guard) => guard,
            Err(r) => return *r,
        };
        let session = match self.consume(session_id, now) {
            Ok(session) => session,
            Err(r) => return *r,
        };
        if decision == UpdateDecision::Cancelled {
            return Resp::of(UpdateStatus::Cancelled);
        }
        let disposition = match action {
            RestoreAction::Skip => RestorePointDisposition::SkippedByUser,
            RestoreAction::AcknowledgeUnavailable if session.restore_unavailable_ack_allowed => {
                RestorePointDisposition::UnavailableAcknowledged
            }
            RestoreAction::AcknowledgeUnavailable => {
                return Resp::of(UpdateStatus::RestoreAckNotAllowed);
            }
            RestoreAction::Create => match restore.create(RESTORE_POINT_DESCRIPTION) {
                Ok(()) => RestorePointDisposition::Created,
                // Same snapshot, same deadline, new token; zero driver work.
                Err(()) => {
                    let expires = session.expires_at;
                    let mut r = Resp::of(UpdateStatus::RestorePointFailed);
                    match self.insert(session.snapshot, expires, true, now) {
                        Ok(id) => r.retry_session_id = Some(id.to_string()),
                        Err(full) => return *full,
                    }
                    r.expires_in_seconds = Some(expires.saturating_duration_since(now).as_secs());
                    return r;
                }
            },
        };
        let r = finish(engine.execute(&session.snapshot, disposition));
        tracing::info!(
            target: "cove::drivers",
            status = ?r.status,
            cleanup_warning = r.cleanup_warning,
            "local driver update install finished"
        );
        r
    }

    /// Remove a session without any lower work. Unknown/expired is a no-op.
    fn cancel(&self, session_id: &str) -> Resp {
        if let Ok(id) = Uuid::parse_str(session_id) {
            match self.sessions.lock() {
                Ok(mut sessions) => drop(sessions.remove(&id)),
                Err(p) => return *poisoned(p),
            }
        }
        Resp::of(UpdateStatus::Cancelled)
    }
}

// ---------------------------------------------------------------------------
// SDIO root and index corpus (untrusted local filesystem boundary)
// ---------------------------------------------------------------------------

/// A validated layout: canonical drive-absolute, non-reparse paths; the
/// derived directories are direct children of `root`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SdioRoot {
    root: PathBuf,
    sdi: PathBuf,
    drivers: PathBuf,
}

/// Validate the single user-supplied root as untrusted text, then derive
/// exactly `indexes\SDI` and `drivers`. Nothing is trimmed or created.
fn validate_sdio_root(raw: &str) -> Result<SdioRoot, Refusal> {
    let invalid = Refusal::InvalidSdioRoot;
    if raw.is_empty() || raw.contains('\0') || raw.encode_utf16().count() > MAX_SDIO_ROOT_UTF16 {
        return Err(invalid("invalid_text"));
    }
    if raw.trim() != raw {
        return Err(invalid("surrounding_whitespace"));
    }
    let path = Path::new(raw);
    let mut parts = path.components();
    let (first, second) = (parts.next(), parts.next());
    let disk = matches!(first, Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)));
    if !disk || second != Some(Component::RootDir) {
        return Err(invalid("not_local_drive_absolute"));
    }
    // On the raw text: `components()` silently drops interior/trailing `.`.
    if raw.split(['\\', '/']).any(|s| s == "." || s == "..") {
        return Err(invalid("relative_component"));
    }
    plain_dir(path)?;
    let canonical = std::fs::canonicalize(path).map_err(|_| invalid("unresolvable"))?;
    let root = drive_form(&canonical)?;
    plain_dir(&root)?;
    let sdi = child_dir(&child_dir(&root, "indexes")?, "SDI")?;
    let drivers = child_dir(&root, "drivers")?;
    Ok(SdioRoot { root, sdi, drivers })
}

/// An existing real directory that is not a symlink or any reparse point.
fn plain_dir(path: &Path) -> Result<(), Refusal> {
    let invalid = Refusal::InvalidSdioRoot;
    let meta = std::fs::symlink_metadata(path).map_err(|_| invalid("missing"))?;
    if optimizer_core::storage::is_reparse_point(path) || meta.file_type().is_symlink() {
        return Err(invalid("reparse_point"));
    }
    if !meta.is_dir() {
        return Err(invalid("not_directory"));
    }
    Ok(())
}

/// A non-reparse direct child directory that canonicalizes inside `parent`.
fn child_dir(parent: &Path, name: &str) -> Result<PathBuf, Refusal> {
    let invalid = Refusal::InvalidSdioRoot;
    let joined = parent.join(name);
    plain_dir(&joined)?;
    let child = drive_form(&std::fs::canonicalize(&joined).map_err(|_| invalid("missing"))?)?;
    let leaf_ok = child
        .file_name()
        .is_some_and(|n| n.eq_ignore_ascii_case(name));
    if child.parent() != Some(parent) || !leaf_ok {
        return Err(invalid("escapes_root"));
    }
    plain_dir(&child)?;
    Ok(child)
}

/// `\\?\C:\x` (what canonicalize returns) -> `C:\x`; anything else refused.
fn drive_form(canonical: &Path) -> Result<PathBuf, Refusal> {
    let invalid = Refusal::InvalidSdioRoot;
    let text = canonical.to_str().ok_or(invalid("not_unicode"))?;
    let rest = text.strip_prefix(r"\\?\").unwrap_or(text);
    let b = rest.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && &b[1..3] == b":\\" {
        Ok(PathBuf::from(rest))
    } else {
        Err(invalid("not_local_drive_absolute"))
    }
}

/// `.bin` direct children of `indexes\SDI`: bounded, deterministically
/// ordered, never recursive. A non-regular or reparse `.bin` fails closed.
fn discover_index_files(sdi: &Path) -> Result<Vec<PathBuf>, Refusal> {
    let corpus = Refusal::InvalidIndexCorpus;
    let mut found = Vec::new();
    for entry in std::fs::read_dir(sdi).map_err(|_| corpus("unreadable"))? {
        let path = entry.map_err(|_| corpus("unreadable"))?.path();
        let ext = path.extension().unwrap_or_default();
        if !ext.eq_ignore_ascii_case("bin") {
            continue;
        }
        let meta = std::fs::symlink_metadata(&path).map_err(|_| corpus("unreadable"))?;
        if optimizer_core::storage::is_reparse_point(&path) || !meta.file_type().is_file() {
            return Err(corpus("index_not_regular"));
        }
        if found.len() == MAX_CATALOGS_PER_MATCH {
            return Err(corpus("too_many_indexes"));
        }
        found.push(path);
    }
    if found.is_empty() {
        return Err(corpus("no_indexes"));
    }
    found.sort_by_cached_key(|p| index_sort_key(p));
    Ok(found)
}

/// ASCII case-insensitive file name, then the exact name as tie breaker.
fn index_sort_key(path: &Path) -> (String, std::ffi::OsString) {
    let name = path.file_name().unwrap_or_default();
    let folded = name.to_string_lossy().to_ascii_lowercase();
    (folded, name.to_os_string())
}

/// Open the object at `path` itself (a link is opened as the link, never
/// followed), shared for reading only so it cannot be written, renamed or
/// deleted while held, and prove from the handle that it is a plain file or
/// directory.
#[cfg(windows)]
fn open_plain(path: &Path, dir: bool) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const SHARE_READ: u32 = 0x1;
    const ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let flags = OPEN_REPARSE_POINT | if dir { BACKUP_SEMANTICS } else { 0 };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .share_mode(SHARE_READ)
        .custom_flags(flags);
    let file = options.open(path)?;
    let meta = file.metadata()?;
    let kind_ok = if dir { meta.is_dir() } else { meta.is_file() };
    if meta.file_attributes() & ATTRIBUTE_REPARSE_POINT != 0 || !kind_ok {
        return Err(std::io::Error::other("not a plain object"));
    }
    Ok(file)
}

#[cfg(not(windows))]
fn open_plain(_: &Path, _: bool) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::other("handle-bound reads need Windows"))
}

/// Pin `indexes\SDI`: while held, it and every ancestor cannot be renamed or
/// replaced, so a re-validation of the chain under the pin stays true.
fn pin_index_dir(root: &SdioRoot) -> Result<std::fs::File, Refusal> {
    open_plain(&root.sdi, true).map_err(|_| Refusal::InvalidIndexCorpus("index_dir_changed"))
}

/// Read one index through a handle bound to the validated object: size-capped
/// read from the same handle that proved it a plain file, then parsed.
fn read_catalog(path: &Path) -> Result<SdioCatalog, Refusal> {
    use std::io::Read;
    let corpus = Refusal::InvalidIndexCorpus;
    let stem = path.file_stem().and_then(|s| s.to_str());
    let stem = stem.ok_or(corpus("malformed_index"))?.to_owned();
    let file = open_plain(path, false).map_err(|_| corpus("index_not_regular"))?;
    let mut data = Vec::new();
    let cap = mod_drivers::sdio::MAX_COMPRESSED_BYTES as u64 + 1;
    file.take(cap)
        .read_to_end(&mut data)
        .map_err(|_| corpus("unreadable"))?;
    SdioCatalog::parse_bytes(&data, stem).map_err(|_| corpus("malformed_index"))
}

/// Load the whole corpus under a pinned, re-validated index directory. Every
/// accepted index is part of the corpus; one malformed index fails the whole
/// load rather than yielding a partial candidate set.
fn load_index_corpus(root: &SdioRoot) -> Result<Vec<SdioCatalog>, Refusal> {
    let changed = Refusal::InvalidIndexCorpus("index_dir_changed");
    let pin = pin_index_dir(root)?;
    let again = root.root.to_str().map(validate_sdio_root);
    if again != Some(Ok(root.clone())) {
        return Err(changed);
    }
    let paths = discover_index_files(&root.sdi)?;
    let catalogs = paths
        .iter()
        .map(|p| read_catalog(p))
        .collect::<Result<Vec<_>, _>>()?;
    drop(pin);
    Ok(catalogs)
}

// ---------------------------------------------------------------------------
// Live device authority and candidate selection
// ---------------------------------------------------------------------------

/// Select the caller's device from a FRESH, complete, non-degraded report.
/// The instance ID only selects; the fresh identity is authoritative.
fn select_live_device(report: &DriverIdentityReport, id: &str) -> Result<DeviceIdentity, Refusal> {
    if report.error.is_some() {
        return Err(Refusal::InventoryUnavailable);
    }
    if report.degraded {
        return Err(Refusal::DegradedInventory);
    }
    if !report.complete {
        return Err(Refusal::InventoryUnavailable);
    }
    let mut hits = report.devices.iter().filter(|d| d.instance_id == id);
    match (hits.next(), hits.next()) {
        (Some(device), None) => Ok(device.clone()),
        _ => Err(Refusal::DeviceNotFound),
    }
}

enum CandidateEval<R> {
    Missing,
    Unsupported,
    Rejected,
    Failed,
    Evaluated(R),
}

/// One live candidate evaluation and whether every temp object it created
/// was removed again.
type LiveRun<R> = (CandidateEval<R>, bool);

/// Preview body result: `Ok(Some)` Ready, `Ok(None)` NoAction, `Err` failure.
type PreparedSnapshot = Result<Option<CandidateSnapshot>, ()>;

#[derive(Default)]
struct Evaluation {
    /// (index into the assessed candidates, Ready snapshot)
    ready: Vec<(usize, CandidateSnapshot)>,
    diagnostics: Diagnostics,
}

/// Evaluate every HostCompatible candidate. A temp-cleanup failure aborts
/// the whole operation; other candidate failures are counted, never hidden.
fn evaluate_loop(
    candidates: &[AssessedCatalogCandidate],
    mut evaluate: impl FnMut(&AssessedCatalogCandidate) -> LiveRun<PreparedSnapshot>,
) -> Result<Evaluation, Refusal> {
    let mut out = Evaluation::default();
    let d = &mut out.diagnostics;
    for (index, candidate) in candidates.iter().enumerate() {
        // Indeterminate is never promoted; HostIncompatible is policy-ignored.
        if candidate.os.status != CatalogOsApplicability::HostCompatible {
            continue;
        }
        d.host_compatible_candidates += 1;
        let (eval, cleanup_ok) = evaluate(candidate);
        if !cleanup_ok {
            return Err(Refusal::TemporaryCleanupFailed);
        }
        match eval {
            CandidateEval::Missing => d.missing_packs += 1,
            CandidateEval::Unsupported => d.unsupported_candidates += 1,
            CandidateEval::Rejected => d.rejected_candidates += 1,
            CandidateEval::Failed | CandidateEval::Evaluated(Err(())) => d.failed_candidates += 1,
            CandidateEval::Evaluated(Ok(None)) => d.no_action_candidates += 1,
            CandidateEval::Evaluated(Ok(Some(snapshot))) => {
                d.ready_candidates += 1;
                out.ready.push((index, snapshot));
            }
        }
    }
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
enum Winner {
    None,
    Ambiguous,
    Unique(usize),
}

/// Unique best Ready candidate under the native ordering; never first-wins.
fn select_winner(ready: &[(usize, CandidateSnapshot)]) -> Winner {
    let summaries: Vec<_> = ready.iter().map(|(_, s)| s.summary).collect();
    match select_unique_best(&summaries) {
        BestSelection::NotCompatible => Winner::None,
        BestSelection::Ambiguous => Winner::Ambiguous,
        BestSelection::Unique(i) => Winner::Unique(i),
    }
}

/// The fresh unique winner must bind exactly to the session winner; returns
/// its assessed index.
fn revalidate_winner(session: &CandidateSnapshot, fresh: &Evaluation) -> Option<usize> {
    let Winner::Unique(i) = select_winner(&fresh.ready) else {
        return None;
    };
    let (index, winner) = &fresh.ready[i];
    snapshot_binds(session, winner).then_some(*index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use CatalogOsApplicability::{HostCompatible as Fit, HostIncompatible, Indeterminate};
    use MaterializedPackageFileKind as K;
    use RestoreAction::{AcknowledgeUnavailable as Ack, Create, Skip};
    use RestorePointDisposition::{Created, SkippedByUser, UnavailableAcknowledged};
    use UpdateDecision::{Cancelled as No, Confirmed as Yes};
    use UpdateStatus as S;
    use mod_drivers::sdio::{ApplicabilityReason, Candidate, CatalogApplicabilityEvidence};
    use std::collections::VecDeque;
    use std::sync::{Arc, mpsc};

    const ROOT_SECRET: &str = r"C:\PRIVATE-SDIO-ROOT";
    const DEVICE_SECRET: &str = r"PCI\VEN_PRIV&DEV_0001\4&SECRETINSTANCE";
    const WAIT: Duration = Duration::from_secs(20);
    const RANK: u32 = 0x00FF_0000;

    type Queue<T> = Mutex<VecDeque<T>>;
    type Previews = Vec<Result<PreviewFound, Refusal>>;
    type Parked = (std::thread::JoinHandle<Resp>, mpsc::Sender<()>);

    fn sum(rank: u32, date: u64, version: u64) -> DriverSelectionSummary {
        DriverSelectionSummary::from_native(rank, date, version)
    }

    fn file(path: &str, kind: K, fill: u8) -> PackageFileSnapshot {
        let (relative_path, size, sha256) = (path.to_owned(), u64::from(fill), [fill; 32]);
        PackageFileSnapshot {
            relative_path,
            kind,
            size,
            sha256,
        }
    }

    fn snap(pack: &str, summary: DriverSelectionSummary) -> CandidateSnapshot {
        let candidate = Candidate {
            inf_path: r"net\intel".into(),
            inf_filename: "e1d.inf".into(),
            provider: Some("Cove Vendor".into()),
            class: None,
            class_guid: None,
            catalog_file: Some("e1d.cat".into()),
            version: Some((12, 19, 2, 45)),
            date: Some((2024, 3, 7)),
            install_section: "E1D.ndi".into(),
            picked_section: "E1D.ndi".into(),
            sect_pos: 0,
            models_section: None,
            inf_pos: 0,
        };
        let (pack_name, evidence) = (pack.to_owned(), Vec::new());
        let files = vec![
            file("e1d.inf", K::Inf, 0xA1),
            file("e1d.cat", K::Catalog, 0xB2),
        ];
        let mut s = CandidateSnapshot {
            candidate: CatalogCandidateMatch {
                pack_name,
                candidate,
                evidence,
            },
            summary,
            current_best: Some(sum(summary.rank() + 1, 1, 1)),
            files,
            signer: Some("Cove Test Signer".into()),
        };
        s.files.push(file("e1d.sys", K::Payload, 0xC3));
        s
    }

    fn winner() -> CandidateSnapshot {
        snap("DP_LAN_Intel", sum(RANK, 50, 50))
    }

    fn session_snapshot() -> SessionSnapshot {
        let (canonical_sdio_root, winner) = (PathBuf::from(ROOT_SECRET), winner());
        let device_instance_id = DEVICE_SECRET.to_owned();
        SessionSnapshot {
            canonical_sdio_root,
            device_instance_id,
            winner,
        }
    }

    fn ready() -> Result<PreviewFound, Refusal> {
        let found = PreviewFound::Ready(Box::new(session_snapshot()), Diagnostics::default());
        Ok(found)
    }

    fn installed() -> Resp {
        Resp::of(S::Installed).inf("oem42.inf").reboot(false)
    }

    fn request() -> PreviewRequest {
        let (device_instance_id, sdio_root) = (DEVICE_SECRET.into(), ROOT_SECRET.into());
        PreviewRequest {
            device_instance_id,
            sdio_root,
        }
    }

    fn pop<T>(queue: &Queue<T>) -> T {
        queue.lock().unwrap().pop_front().expect("unscripted call")
    }

    // -- scripted seams: a Ready snapshot in, a lower-shaped response out ----

    #[derive(Default)]
    struct Scripted {
        previews: Queue<Result<PreviewFound, Refusal>>,
        executes: Queue<Resp>,
        restores: Queue<Result<(), ()>>,
        preview_calls: Mutex<Vec<(String, String)>>,
        executed: Mutex<Vec<RestorePointDisposition>>,
        restore_calls: Mutex<Vec<String>>,
        hold: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
        panic_inside: Mutex<bool>,
    }

    impl Scripted {
        fn pause(&self) {
            if let Some((entered, release)) = self.hold.lock().unwrap().take() {
                entered.send(()).unwrap();
                release.recv_timeout(WAIT).unwrap();
            }
            assert!(!*self.panic_inside.lock().unwrap(), "scripted engine panic");
        }
    }

    impl DriverUpdateEngine for Scripted {
        fn preview(&self, request: &PreviewRequest) -> Result<PreviewFound, Refusal> {
            let seen = (
                request.device_instance_id.clone(),
                request.sdio_root.clone(),
            );
            self.preview_calls.lock().unwrap().push(seen);
            self.pause();
            pop(&self.previews)
        }
        fn execute(&self, _: &SessionSnapshot, d: RestorePointDisposition) -> TransactionReport {
            self.executed.lock().unwrap().push(d);
            self.pause();
            (pop(&self.executes), false)
        }
    }

    impl RestorePointCreator for Scripted {
        fn create(&self, description: &str) -> Result<(), ()> {
            self.restore_calls.lock().unwrap().push(description.into());
            pop(&self.restores)
        }
    }

    /// One service and its scripted seams, at a fixed clock `t0`.
    #[derive(Clone)]
    struct H {
        svc: Arc<DriverUpdateService>,
        seam: Arc<Scripted>,
        t0: Instant,
    }

    impl H {
        fn new(previews: Previews, executes: Vec<Resp>, restores: Vec<Result<(), ()>>) -> Self {
            let seam = Scripted::default();
            *seam.previews.lock().unwrap() = previews.into();
            *seam.executes.lock().unwrap() = executes.into();
            *seam.restores.lock().unwrap() = restores.into();
            let (svc, seam) = (Arc::new(DriverUpdateService::new()), Arc::new(seam));
            H {
                svc,
                seam,
                t0: Instant::now(),
            }
        }
        fn check(&self) -> Resp {
            self.svc.check(&*self.seam, request(), self.t0)
        }
        /// Issue a Ready session through a separate scripted preview.
        fn issue_at(&self, at: Instant) -> String {
            let seam = Scripted::default();
            seam.previews.lock().unwrap().push_back(ready());
            let r = self.svc.check(&seam, request(), at);
            assert_eq!(r.status, S::Ready);
            r.session_id.expect("session id")
        }
        fn issue(&self) -> String {
            self.issue_at(self.t0)
        }
        fn install_at(&self, t: &str, d: UpdateDecision, a: RestoreAction, at: Instant) -> Resp {
            self.svc.install(&*self.seam, &*self.seam, t, d, a, at)
        }
        fn install(&self, token: &str, d: UpdateDecision, a: RestoreAction) -> Resp {
            self.install_at(token, d, a, self.t0)
        }
        fn executed(&self) -> Vec<RestorePointDisposition> {
            self.seam.executed.lock().unwrap().clone()
        }
        fn restores(&self) -> usize {
            self.seam.restore_calls.lock().unwrap().len()
        }
        fn session(&self, token: &str) -> Option<(Instant, bool)> {
            let sessions = self.svc.sessions.lock().unwrap();
            let s = sessions.get(&Uuid::parse_str(token).unwrap())?;
            Some((s.expires_at, s.restore_unavailable_ack_allowed))
        }
        fn live(&self) -> usize {
            self.svc.sessions.lock().unwrap().len()
        }
        /// Run `job` on another thread, parked inside the next engine call.
        fn parked(&self, job: impl FnOnce(H) -> Resp + Send + 'static) -> Parked {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            *self.seam.hold.lock().unwrap() = Some((entered_tx, release_rx));
            let h = self.clone();
            let worker = std::thread::spawn(move || job(h));
            entered_rx.recv_timeout(WAIT).expect("parked");
            (worker, release_tx)
        }
    }

    // -- SESSION / INSTALL / LOCK -------------------------------------------

    #[test]
    fn session_r1_r2_uuid_v4_token_held_process_locally() {
        let h = H::new(vec![], vec![], vec![]);
        let token = h.issue();
        assert_eq!(Uuid::parse_str(&token).unwrap().get_version_num(), 4);
        assert_eq!(h.live(), 1);
        assert_eq!(h.session(&token), Some((h.t0 + SESSION_TTL, false)));
    }

    #[test]
    fn session_r3_r4_one_shot_consume_and_replay_fails() {
        let h = H::new(vec![], vec![installed()], vec![]);
        let token = h.issue();
        assert_eq!(h.install(&token, Yes, Skip).status, S::Installed);
        assert_eq!(h.install(&token, Yes, Skip).status, S::SessionNotFound);
        assert_eq!(h.executed().len(), 1);
    }

    #[test]
    fn session_r5_cancel_removes_token_and_is_idempotent() {
        let h = H::new(vec![], vec![], vec![]);
        let token = h.issue();
        for t in [token.as_str(), token.as_str(), "not-a-uuid"] {
            assert_eq!(h.svc.cancel(t).status, S::Cancelled);
        }
        assert_eq!(h.live(), 0);
        assert_eq!(h.install(&token, Yes, Skip).status, S::SessionNotFound);
        assert!(h.executed().is_empty());
    }

    #[test]
    fn session_r6_r7_inst_r3_expired_rejected_pruned_and_never_refreshed() {
        let h = H::new(vec![], vec![], vec![]);
        let (token, other) = (h.issue(), h.issue());
        h.svc.cancel(&other);
        assert_eq!(
            h.install(&h.issue(), Yes, Ack).status,
            S::RestoreAckNotAllowed
        );
        // Neither the cancel nor the refused install refreshed `token`'s TTL.
        assert_eq!(h.session(&token), Some((h.t0 + SESSION_TTL, false)));
        let r = h.install_at(&token, Yes, Create, h.t0 + SESSION_TTL);
        assert_eq!((r.status, h.live()), (S::SessionExpired, 0));
        assert!(h.executed().is_empty() && h.restores() == 0);
    }

    #[test]
    fn session_r8_r9_cap_of_four_and_expired_free_capacity() {
        let h = H::new(vec![ready()], vec![], vec![]);
        for _ in 0..MAX_DRIVER_UPDATE_SESSIONS {
            h.issue();
        }
        let full = h.check();
        assert_eq!((full.status, full.session_id), (S::SessionCapacity, None));
        assert_eq!(
            h.seam.preview_calls.lock().unwrap().len(),
            0,
            "no pipeline work when full"
        );
        assert_eq!(h.live(), MAX_DRIVER_UPDATE_SESSIONS);
        h.issue_at(h.t0 + SESSION_TTL);
        assert_eq!(h.live(), 1);
    }

    #[test]
    fn session_r10_r11_inst_r14_r15_restore_failure_new_token_same_expiry() {
        let h = H::new(vec![], vec![], vec![Err(())]);
        let token = h.issue();
        let r = h.install_at(&token, Yes, Create, h.t0 + Duration::from_secs(120));
        assert_eq!(
            (r.status, r.success, r.partial),
            (S::RestorePointFailed, false, false)
        );
        assert!(
            h.executed().is_empty(),
            "zero driver work after restore failure"
        );
        assert_eq!(
            *h.seam.restore_calls.lock().unwrap(),
            [RESTORE_POINT_DESCRIPTION]
        );
        let retry = r.retry_session_id.expect("retry token");
        assert!(retry != token && r.session_id.is_none());
        assert_eq!(r.expires_in_seconds, Some(SESSION_TTL.as_secs() - 120));
        assert_eq!(h.session(&token), None);
        let same_deadline = Some((h.t0 + SESSION_TTL, true));
        assert_eq!(h.session(&retry), same_deadline, "no expiry extension");
        let sessions = h.svc.sessions.lock().unwrap();
        let kept = &sessions[&Uuid::parse_str(&retry).unwrap()].snapshot;
        assert!(snapshot_binds(&kept.winner, &winner()));
    }

    #[test]
    fn session_r12_inst_r16_ack_unavailable_only_on_flagged_retry() {
        let h = H::new(vec![], vec![installed()], vec![Err(())]);
        assert_eq!(
            h.install(&h.issue(), Yes, Ack).status,
            S::RestoreAckNotAllowed
        );
        assert!(h.executed().is_empty());
        let retry = h.install(&h.issue(), Yes, Create).retry_session_id.unwrap();
        assert_eq!(h.install(&retry, Yes, Ack).status, S::Installed);
        assert_eq!(h.executed(), [UnavailableAcknowledged]);
        assert_eq!(h.restores(), 1, "ack does not retry the restore point");
    }

    #[test]
    fn inst_r1_r2_cancelled_or_invalid_token_does_zero_work() {
        let h = H::new(vec![], vec![], vec![]);
        let r = h.install(&h.issue(), No, Create);
        assert_eq!((r.status, r.success, h.live()), (S::Cancelled, true, 0));
        for token in ["", "garbage", &Uuid::new_v4().to_string()] {
            assert_eq!(h.install(token, Yes, Create).status, S::SessionNotFound);
        }
        assert!(h.executed().is_empty() && h.restores() == 0);
    }

    #[test]
    fn inst_r12_r13_restore_create_maps_created_and_skip_maps_skipped() {
        let h = H::new(vec![], vec![installed(), installed()], vec![Ok(())]);
        h.install(&h.issue(), Yes, Create);
        h.install(&h.issue(), Yes, Skip);
        assert_eq!(h.executed(), [Created, SkippedByUser]);
        assert_eq!(h.restores(), 1, "skip never creates a restore point");
    }

    #[test]
    fn inst_r4_lock_r2_r3_concurrent_duplicate_install_has_one_winner() {
        let h = H::new(vec![ready()], vec![installed()], vec![]);
        let token = h.issue();
        let t = token.clone();
        let (worker, release) = h.parked(move |h| h.install(&t, Yes, Skip));
        assert_eq!(h.install(&token, Yes, Skip).status, S::Busy);
        assert_eq!(h.check().status, S::Busy);
        release.send(()).unwrap();
        assert_eq!(worker.join().unwrap().status, S::Installed);
        assert_eq!(h.install(&token, Yes, Skip).status, S::SessionNotFound);
        assert_eq!(h.executed().len(), 1);
    }

    #[test]
    fn lock_r1_preview_conflict_is_busy_and_lock_r4_released_on_error() {
        let h = H::new(vec![Err(Refusal::DeviceNotFound), ready()], vec![], vec![]);
        let (worker, release) = h.parked(|h| h.check());
        assert_eq!(h.check().status, S::Busy);
        release.send(()).unwrap();
        assert_eq!(worker.join().unwrap().status, S::DeviceNotFound);
        assert_eq!(h.check().status, S::Ready);
    }

    #[test]
    fn lock_r5_poisoned_operation_lock_fails_closed() {
        let h = H::new(vec![ready()], vec![installed()], vec![]);
        let token = h.issue();
        *h.seam.panic_inside.lock().unwrap() = true;
        let worker = h.clone();
        assert!(std::thread::spawn(move || worker.check()).join().is_err());
        *h.seam.panic_inside.lock().unwrap() = false;
        let r = h.install(&token, Yes, Skip);
        assert_eq!(
            (r.status, r.detail.as_deref()),
            (S::InternalError, Some("poisoned"))
        );
        assert!(
            h.executed().is_empty(),
            "never mutate after a poisoned operation"
        );
        assert_eq!(h.check().status, S::InternalError);
        assert_eq!(h.live(), 1, "a refused install does not consume the token");
    }

    // -- PREVIEW -------------------------------------------------------------

    fn report(devices: &[(&str, &str)]) -> DriverIdentityReport {
        let device = |&(id, hwid): &(&str, &str)| DeviceIdentity {
            instance_id: id.into(),
            hardware_ids: vec![hwid.into()],
            compatible_ids: Vec::new(),
            class_guid: None,
            class_name: None,
            description: Some("Same Description".into()),
            manufacturer: None,
            problem_code: None,
            installed: None,
            matching: Vec::new(),
        };
        let (arch, os_build, os_version) = ("x64".into(), "26200".into(), "10.0".into());
        let machine = mod_drivers::identity::MachineContext {
            arch,
            os_build,
            os_version,
        };
        let devices = devices.iter().map(device).collect();
        DriverIdentityReport {
            complete: true,
            degraded: false,
            error: None,
            machine,
            devices,
        }
    }

    #[test]
    fn prev_r1_r2_r3_r4_fresh_complete_inventory_is_sole_device_authority() {
        let pick = |r: &DriverIdentityReport| select_live_device(r, DEVICE_SECRET);
        let mut r = report(&[(DEVICE_SECRET, "A")]);
        r.degraded = true;
        assert_eq!(pick(&r), Err(Refusal::DegradedInventory));
        r.error = Some("pnputil failed".into());
        assert_eq!(pick(&r), Err(Refusal::InventoryUnavailable));
        let mut r = report(&[(DEVICE_SECRET, "A")]);
        r.complete = false;
        assert_eq!(pick(&r), Err(Refusal::InventoryUnavailable));
        let lower = DEVICE_SECRET.to_lowercase();
        let dup = [(DEVICE_SECRET, "A"), (DEVICE_SECRET, "B")];
        for devices in [&[("PCI\\OTHER", "A")][..], &dup, &[(lower.as_str(), "A")]] {
            assert_eq!(pick(&report(devices)), Err(Refusal::DeviceNotFound));
        }
        // Only the fresh identity (fresh hardware IDs) is used, never UI data.
        let fresh = report(&[("PCI\\X", "OLD"), (DEVICE_SECRET, "FRESH")]);
        assert_eq!(pick(&fresh).unwrap().hardware_ids, ["FRESH"]);
    }

    fn assessed(pack: &str, status: CatalogOsApplicability) -> AssessedCatalogCandidate {
        let (models_section, target) = (None, None);
        let reason = ApplicabilityReason::TargetSatisfied;
        let os = CatalogApplicabilityEvidence {
            models_section,
            target,
            status,
            reason,
        };
        AssessedCatalogCandidate {
            matched: snap(pack, sum(1, 1, 1)).candidate,
            os,
        }
    }

    #[test]
    fn prev_r5_r6_r7_only_host_compatible_ready_enters_pool_all_counted() {
        use CandidateEval::{Evaluated, Failed, Missing, Rejected, Unsupported};
        type Step = fn() -> CandidateEval<PreparedSnapshot>;
        let plan: [(_, _, Step); 9] = [
            ("missing", Fit, || Missing),
            ("indeterminate", Indeterminate, || Missing),
            ("incompatible", HostIncompatible, || Missing),
            ("unsupported", Fit, || Unsupported),
            ("rejected", Fit, || Rejected),
            ("failed", Fit, || Failed),
            ("noaction", Fit, || Evaluated(Ok(None))),
            ("preperror", Fit, || Evaluated(Err(()))),
            ("ready", Fit, || Evaluated(Ok(Some(winner())))),
        ];
        let list: Vec<_> = plan.iter().map(|(p, s, _)| assessed(p, *s)).collect();
        let mut seen = Vec::new();
        let eval = evaluate_loop(&list, |c| {
            let i = list.iter().position(|x| std::ptr::eq(x, c)).unwrap();
            seen.push(i);
            (plan[i].2(), true)
        });
        let eval = eval.unwrap();
        assert_eq!(
            seen,
            [0, 3, 4, 5, 6, 7, 8],
            "Indeterminate/incompatible never evaluated"
        );
        let d = eval.diagnostics;
        let counts = [
            d.host_compatible_candidates,
            d.missing_packs,
            d.unsupported_candidates,
        ];
        assert_eq!(counts, [7, 1, 1]);
        let counts = [
            d.rejected_candidates,
            d.failed_candidates,
            d.no_action_candidates,
        ];
        assert_eq!((counts, d.ready_candidates), ([1, 2, 1], 1));
        let indexes: Vec<_> = eval.ready.iter().map(|(i, _)| *i).collect();
        assert_eq!(indexes, [8], "assessed index retained for the live rebuild");
    }

    #[test]
    fn prev_r14_r15_any_candidate_cleanup_failure_aborts_before_session() {
        let list: Vec<_> = (0..5).map(|i| assessed(&format!("p{i}"), Fit)).collect();
        let mut calls = 0;
        let r = evaluate_loop(&list, |_| {
            calls += 1;
            (CandidateEval::Evaluated(Ok(Some(winner()))), calls != 3)
        });
        assert!(matches!(r, Err(Refusal::TemporaryCleanupFailed)));
        assert_eq!(
            calls, 3,
            "no further candidate work after a cleanup failure"
        );
        let h = H::new(vec![Err(Refusal::TemporaryCleanupFailed)], vec![], vec![]);
        let resp = h.check();
        assert_eq!(
            (resp.status, resp.session_id),
            (S::TemporaryCleanupFailed, None)
        );
        assert_eq!(h.live(), 0);
    }

    #[test]
    fn prev_no_update_ambiguous_and_refusals_issue_no_session() {
        let d = Diagnostics {
            missing_packs: 2,
            ..Diagnostics::default()
        };
        let previews = vec![
            Ok(PreviewFound::NoUpdate(d)),
            Ok(PreviewFound::Ambiguous(d)),
            Err(Refusal::InvalidRequest),
            Err(Refusal::UnsupportedHost),
            Err(Refusal::Internal("match_bounds")),
            Err(Refusal::InvalidSdioRoot("reparse_point")),
        ];
        let h = H::new(previews, vec![], vec![]);
        let r = h.check();
        let got = (r.status, r.success, r.diagnostics, r.session_id.is_some());
        assert_eq!(got, (S::NoUpdate, true, Some(d), false));
        let r = h.check();
        let got = (r.status, r.success, r.diagnostics, r.session_id.is_some());
        assert_eq!(got, (S::AmbiguousLocalUpdate, false, Some(d), false));
        let expected = [
            (S::InvalidRequest, None),
            (S::UnsupportedHost, None),
            (S::InternalError, Some("match_bounds")),
            (S::InvalidSdioRoot, Some("reparse_point")),
        ];
        for (status, detail) in expected {
            let r = h.check();
            assert_eq!(
                (r.status, r.detail.as_deref(), r.preview),
                (status, detail, None)
            );
        }
        assert_eq!(h.live(), 0);
        // The untrusted request reaches the engine verbatim (never trimmed).
        let seen = h.seam.preview_calls.lock().unwrap();
        assert!(
            seen.iter()
                .all(|s| *s == (DEVICE_SECRET.into(), ROOT_SECRET.into()))
        );
    }

    #[test]
    fn prev_r8_r9_native_unique_best_across_ready_candidates() {
        let pick = |s: &[DriverSelectionSummary]| {
            let pool: Vec<_> = s.iter().map(|x| (0, snap("p", *x))).collect();
            select_winner(&pool)
        };
        assert_eq!(pick(&[]), Winner::None);
        // Not first, not newest SDIO metadata: lowest native rank wins.
        assert_eq!(
            pick(&[sum(9, 99, 99), sum(2, 1, 1), sum(5, 50, 50)]),
            Winner::Unique(1)
        );
        assert_eq!(pick(&[sum(2, 1, 1), sum(2, 3, 1)]), Winner::Unique(1));
        assert_eq!(pick(&[sum(2, 3, 1), sum(2, 3, 7)]), Winner::Unique(1));
        assert_eq!(
            pick(&[sum(2, 3, 7), sum(9, 9, 9), sum(2, 3, 7)]),
            Winner::Ambiguous
        );
    }

    #[test]
    fn prev_r10_r11_r12_exact_snapshot_retained_and_sha_never_serialized() {
        let h = H::new(vec![ready()], vec![], vec![]);
        let r = h.check();
        let id = Uuid::parse_str(r.session_id.as_deref().unwrap()).unwrap();
        {
            let sessions = h.svc.sessions.lock().unwrap();
            let s = &sessions[&id].snapshot;
            assert!(snapshot_binds(&s.winner, &winner()) && s.winner.files.len() == 3);
            assert_eq!(s.canonical_sdio_root, PathBuf::from(ROOT_SECRET));
            assert_eq!(s.device_instance_id, DEVICE_SECRET);
        }
        let json = serde_json::to_string(&r).unwrap();
        for leak in [
            "a1a1",
            "A1A1",
            "161,",
            "PRIVATE",
            "SECRET",
            r"net\\intel",
            "sha",
        ] {
            assert!(!json.contains(leak), "leaked {leak}: {json}");
        }
        let p = r.preview.unwrap();
        assert_eq!(
            (p.package_file_count, p.package_total_bytes),
            (3, 0xA1 + 0xB2 + 0xC3)
        );
        let version = (p.candidate_version.as_deref(), p.candidate_date.as_deref());
        assert_eq!(version, (Some("12.19.2.45"), Some("2024-03-07")));
        assert_eq!(
            (p.inf_name.as_str(), r.expires_in_seconds),
            ("e1d.inf", Some(600))
        );
    }

    #[test]
    fn prev_r13_privacy_session_holds_no_live_capability_and_debug_is_redacted() {
        fn owned<T: 'static + Send>() {}
        owned::<DriverUpdateSession>();
        let src = production_source();
        let start = src.find("struct DriverUpdateSession {").unwrap();
        let body = &src[start..start + src[start..].find('}').unwrap()];
        for live in [
            "Verified",
            "Materialized",
            "Prepared",
            "InstallPlan",
            "Staged",
            "<'",
        ] {
            assert!(!body.contains(live), "{live}");
        }
        let (snapshot, expires_at) = (session_snapshot(), Instant::now());
        let restore_unavailable_ack_allowed = false;
        let session = DriverUpdateSession {
            expires_at,
            snapshot,
            restore_unavailable_ack_allowed,
        };
        let dbg = format!("{session:?}");
        for leak in ["PRIVATE", "SECRET", "a1", "161", "e1d", "Intel"] {
            assert!(!dbg.contains(leak), "{dbg}");
        }
    }

    #[test]
    fn better_by_derives_from_native_summaries_only() {
        assert_eq!(better_by(sum(5, 1, 1), None), BetterBy::NoCurrentDriver);
        assert_eq!(better_by(sum(4, 1, 1), Some(sum(5, 9, 9))), BetterBy::Rank);
        assert_eq!(better_by(sum(5, 9, 1), Some(sum(5, 8, 9))), BetterBy::Date);
        assert_eq!(
            better_by(sum(5, 9, 9), Some(sum(5, 9, 8))),
            BetterBy::Version
        );
    }

    #[test]
    fn inst_r5_to_r11_fresh_winner_must_bind_exactly() {
        let check = |list: Vec<CandidateSnapshot>| {
            let ready = list
                .into_iter()
                .enumerate()
                .map(|(i, s)| (i + 3, s))
                .collect();
            let diagnostics = Diagnostics::default();
            revalidate_winner(&winner(), &Evaluation { ready, diagnostics })
        };
        let edit = |f: &dyn Fn(&mut CandidateSnapshot)| {
            let mut s = winner();
            f(&mut s);
            vec![s]
        };
        assert_eq!((check(vec![winner()]), check(vec![])), (Some(3), None));
        assert_eq!(
            check(edit(&|s| s.candidate.candidate.inf_path = "x".into())),
            None,
            "R5"
        );
        assert_eq!(check(edit(&|s| s.summary = sum(RANK, 51, 50))), None, "R6");
        assert_eq!(check(edit(&|s| drop(s.files.pop()))), None, "R7 count");
        assert_eq!(check(edit(&|s| s.files.swap(1, 2))), None, "order");
        let path = |s: &mut CandidateSnapshot| s.files[2].relative_path = "evil.sys".into();
        assert_eq!(check(edit(&path)), None, "R8");
        assert_eq!(check(edit(&|s| s.files[2].kind = K::Catalog)), None, "kind");
        assert_eq!(check(edit(&|s| s.files[2].size += 1)), None, "R9 size");
        assert_eq!(
            check(edit(&|s| s.files[1].sha256[31] ^= 1)),
            None,
            "R10 sha"
        );
        let better = snap("DP_LAN_Better", sum(RANK - 1, 1, 1));
        assert_eq!(
            check(vec![winner(), better]),
            None,
            "R11 new better candidate"
        );
        let moved = edit(&|s| (s.current_best, s.signer) = (None, None));
        assert_eq!(check(moved), Some(3), "the current baseline may move");
    }

    // -- MAP -----------------------------------------------------------------

    #[test]
    fn map_r1_to_r12_every_outcome_status_keeps_its_mutation_meaning() {
        // (status, success, partial, may be mutated)
        let table = [
            (S::Installed, true, false, true),
            (S::InstalledPendingReboot, true, false, true),
            (S::InstalledPostconditionMismatch, false, true, true),
            (S::InstalledReconciliationFailed, false, true, true),
            (S::InstalledSourceInvalidated, false, true, true),
            (S::DriverStoreStagedInstallRefused, false, true, true),
            (S::DriverStoreStagedDeviceInstallFailed, false, true, true),
            (S::DriverStoreStagedSourceInvalidated, false, true, true),
            (S::StageFailedUnknown, false, true, true),
            (S::ElevationRequired, false, false, false),
            (S::StalePreview, false, false, false),
            (S::NoUpdate, true, false, false),
            (S::Cancelled, true, false, false),
        ];
        for (status, success, partial, mutated) in table {
            let r = Resp::of(status);
            let got = (r.success, r.partial, status.system_may_be_mutated());
            assert_eq!(got, (success, partial, mutated), "{status:?}");
        }
        use PreMutationError as P;
        let cases = [
            (P::ElevationRequired, S::ElevationRequired),
            (P::StalePreparation, S::StalePreview),
            (P::SourceReattestationFailed, S::StalePreview),
            (
                P::MutationDisabledInTestBuild,
                S::MutationDisabledInTestBuild,
            ),
            (P::PlatformUnsupported, S::InternalError),
            (P::InvalidCurrentInfPath, S::InternalError),
        ];
        for (error, status) in cases {
            let r = pre_mutation(error);
            assert_eq!(
                (r.status, r.partial, r.published_inf),
                (status, false, None)
            );
        }
        let stale = pre_mutation(P::StalePreparation);
        assert_eq!(stale.detail.as_deref(), Some("stale_preparation"));
        let refusal = mod_drivers::sdio::PostStageRefusal::PublishedNodeMissing;
        assert_eq!(snake(&refusal), "published_node_missing");
    }

    #[test]
    fn map_r13_cleanup_warning_never_erases_primary_mutation_status() {
        let r = finish((installed(), true));
        assert_eq!(
            (r.status, r.success, r.cleanup_warning),
            (S::Installed, true, true)
        );
        let leaf = (r.published_inf.as_deref(), r.reboot_required);
        assert_eq!(leaf, (Some("oem42.inf"), Some(false)));
        let r = finish((Resp::of(S::StageFailedUnknown).code(1), true));
        let got = (r.status, r.cleanup_warning, r.native_error);
        assert_eq!(got, (S::StageFailedUnknown, true, Some(1)));
        // No mutation happened: residue is a hard error, not a warning.
        let r = finish((Resp::of(S::StalePreview), true));
        assert_eq!(
            (r.status, r.cleanup_warning),
            (S::TemporaryCleanupFailed, false)
        );
        assert_eq!(finish((installed(), false)), installed());
    }

    #[test]
    fn ipc_schema_field_names_and_status_spellings_are_pinned() {
        let keys = |v: &serde_json::Value| {
            let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
            keys.sort();
            keys.join(" ")
        };
        let v = serde_json::to_value(H::new(vec![ready()], vec![], vec![]).check()).unwrap();
        let fields = "cleanup_warning detail diagnostics expires_in_seconds message \
            native_error partial postcondition_observed preview published_inf reboot_required \
            retry_session_id session_id status success";
        assert_eq!(
            keys(&v),
            fields.split_whitespace().collect::<Vec<_>>().join(" ")
        );
        let preview = "better_by candidate_date candidate_rank candidate_version current_rank \
            inf_name pack_name package_file_count package_total_bytes provider signer";
        let preview_keys = preview.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(keys(&v["preview"]), preview_keys);
        let spelled = [&v["status"], &v["message"], &v["preview"]["better_by"]];
        assert_eq!(spelled, ["ready", "ready", "rank"]);
        let long = serde_json::to_value(S::DriverStoreStagedDeviceInstallFailed).unwrap();
        assert_eq!(long, "driver_store_staged_device_install_failed");
        assert_eq!(
            Resp::of(S::InstalledPendingReboot).message,
            "installed_pending_reboot"
        );
        let action = serde_json::from_str::<RestoreAction>;
        assert_eq!(action("\"acknowledge_unavailable\"").unwrap(), Ack);
        assert!(
            action("\"created\"").is_err(),
            "the UI cannot claim Created"
        );
        assert_eq!(
            serde_json::from_str::<UpdateDecision>("\"confirmed\"").unwrap(),
            Yes
        );
        let staged = Resp::of(S::DriverStoreStagedSourceInvalidated).inf("oem7.inf");
        let staged = serde_json::to_value(staged).unwrap();
        assert!(staged["partial"] == true && staged["published_inf"] == "oem7.inf");
        assert!(staged["session_id"].is_null() && staged["reboot_required"].is_null());
    }

    // -- ROOT ----------------------------------------------------------------

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(layout: bool) -> Self {
            let p = std::env::temp_dir().join(format!("cove-13a-{}", Uuid::new_v4()));
            std::fs::create_dir(&p).unwrap();
            if layout {
                std::fs::create_dir_all(p.join("indexes").join("SDI")).unwrap();
                std::fs::create_dir(p.join("drivers")).unwrap();
            }
            Self(p)
        }
        fn s(&self) -> &str {
            self.0.to_str().unwrap()
        }
        fn sdi(&self) -> PathBuf {
            self.0.join("indexes").join("SDI")
        }
        fn write(&self, name: &str) {
            std::fs::write(self.sdi().join(name), b"not an SDW index").unwrap();
        }
        fn corpus(&self) -> Option<&'static str> {
            corpus_err(discover_index_files(&self.sdi()))
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            // Junctions are removed as links; targets live inside this root.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn junction(link: &Path, target: &Path) {
        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/C", "mklink", "/J"]).arg(link).arg(target);
        let status = cmd.stdout(std::process::Stdio::null()).status().unwrap();
        assert!(status.success(), "mklink /J failed");
    }

    fn corpus_err<V>(r: Result<V, Refusal>) -> Option<&'static str> {
        match r {
            Err(Refusal::InvalidIndexCorpus(d)) => Some(d),
            _ => None,
        }
    }

    fn root_err(raw: &str) -> bool {
        matches!(validate_sdio_root(raw), Err(Refusal::InvalidSdioRoot(_)))
    }

    #[test]
    fn root_r1_valid_layout_accepted_and_children_derived() {
        let t = TempRoot::new(true);
        let root = validate_sdio_root(t.s()).unwrap();
        assert!(
            !root.root.to_string_lossy().starts_with(r"\\"),
            "drive-absolute form"
        );
        assert_eq!(root.sdi, root.root.join("indexes").join("SDI"));
        assert_eq!(root.drivers, root.root.join("drivers"));
        // The canonical spelling re-validates to itself (the install path).
        assert_eq!(
            validate_sdio_root(root.root.to_str().unwrap()).unwrap(),
            root
        );
    }

    #[test]
    fn root_r2_to_r6_missing_children_and_untrusted_text_rejected() {
        let t = TempRoot::new(false);
        std::fs::create_dir_all(t.0.join("indexes")).unwrap();
        std::fs::create_dir(t.0.join("drivers")).unwrap();
        assert!(root_err(t.s()) && !t.sdi().exists(), "R2, never created");
        let t = TempRoot::new(false);
        std::fs::create_dir_all(t.sdi()).unwrap();
        assert!(
            root_err(t.s()) && !t.0.join("drivers").exists(),
            "R3, never created"
        );
        let t = TempRoot::new(true);
        let file = t.0.join("file");
        std::fs::write(&file, b"x").unwrap();
        let fixed = [
            "",
            r"\\srv\share\SDIO",
            r"\\?\UNC\srv\s",
            r"\\.\C:\SDIO",
            "SDIO",
            "C:SDIO",
        ];
        let mut bad: Vec<String> = fixed.map(String::from).into();
        bad.push(format!(r"C:\SD{}IO", '\0'));
        bad.push(format!(r"C:\{}", "a".repeat(MAX_SDIO_ROOT_UTF16)));
        let s = t.s();
        bad.extend([
            format!(r"\\?\{s}"),
            format!("{s} "),
            format!(" {s}"),
            format!(r"\{s}"),
        ]);
        bad.extend([
            format!(r"{s}\indexes\.."),
            file.to_string_lossy().into_owned(),
        ]);
        // Dot segments that `Path::components` would silently normalize away.
        bad.extend([
            format!(r"{s}\."),
            format!(r"{s}/."),
            format!(r"C:\.{}", &s[2..]),
        ]);
        for raw in bad {
            assert!(root_err(&raw), "{raw:?}");
        }
    }

    #[test]
    fn root_r7_to_r10_reparse_root_or_children_rejected() {
        let t = TempRoot::new(true);
        let link = t.0.join("root-link");
        junction(&link, &t.0);
        // Rejected as a reparse point, not merely as "not a directory".
        let reparse = Err(Refusal::InvalidSdioRoot("reparse_point"));
        assert_eq!(
            validate_sdio_root(link.to_str().unwrap()),
            reparse,
            "R7 root"
        );
        for child in [&["indexes"][..], &["indexes", "SDI"], &["drivers"]] {
            let t = TempRoot::new(true);
            let real = t.0.join("real-target");
            std::fs::create_dir_all(real.join("SDI")).unwrap();
            let path = child.iter().fold(t.0.clone(), |p, c| p.join(c));
            std::fs::remove_dir_all(&path).unwrap();
            junction(&path, &real);
            assert_eq!(validate_sdio_root(t.s()), reparse, "{child:?}");
        }
    }

    #[test]
    fn root_r11_r12_r16_direct_bin_children_only_in_deterministic_order() {
        let t = TempRoot::new(true);
        for name in ["C.Bin", "a.bin", "B.BIN", "notes.txt", "a.bin.bak", "noext"] {
            t.write(name);
        }
        std::fs::create_dir(t.sdi().join("nested")).unwrap();
        std::fs::write(t.sdi().join("nested").join("deep.bin"), b"x").unwrap();
        let found = discover_index_files(&t.sdi()).unwrap();
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["a.bin", "B.BIN", "C.Bin"]);
        let key = |n: &str| index_sort_key(Path::new(n));
        assert!(key("B.bin") < key("b.bin") && key("a.bin") < key("B.bin"));
    }

    #[test]
    fn root_r13_r14_r15_r17_corpus_fails_closed() {
        let t = TempRoot::new(true);
        assert_eq!(t.corpus(), Some("no_indexes"));
        std::fs::create_dir(t.sdi().join("dir.bin")).unwrap();
        assert_eq!(t.corpus(), Some("index_not_regular"), "R14");
        let t = TempRoot::new(true);
        std::fs::create_dir(t.0.join("elsewhere")).unwrap();
        junction(&t.sdi().join("linked.bin"), &t.0.join("elsewhere"));
        assert_eq!(t.corpus(), Some("index_not_regular"), "R13");
        let t = TempRoot::new(true);
        t.write("broken.bin");
        let root = validate_sdio_root(t.s()).unwrap();
        let r17 = corpus_err(load_index_corpus(&root));
        assert_eq!(r17, Some("malformed_index"), "R17");
        for i in 1..MAX_CATALOGS_PER_MATCH {
            t.write(&format!("p{i:03}.bin"));
        }
        assert_eq!(
            discover_index_files(&t.sdi()).unwrap().len(),
            MAX_CATALOGS_PER_MATCH
        );
        t.write("extra.bin");
        assert_eq!(t.corpus(), Some("too_many_indexes"), "R15");
    }

    #[test]
    fn root_r13_catalog_reads_are_handle_bound_under_a_pinned_index_dir() {
        let t = TempRoot::new(true);
        std::fs::create_dir(t.0.join("elsewhere")).unwrap();
        let linked = t.sdi().join("linked.bin");
        junction(&linked, &t.0.join("elsewhere"));
        let mut via_link = validate_sdio_root(t.s()).unwrap();
        via_link.sdi = linked.clone();
        assert!(
            pin_index_dir(&via_link).is_err(),
            "a junction is pinned as itself"
        );
        let read = read_catalog(&linked).map(|c| c.pack_name().to_owned());
        assert_eq!(
            corpus_err(read),
            Some("index_not_regular"),
            "link object itself is read"
        );
        // While pinned, neither SDI nor any ancestor can be renamed or swapped.
        let t = TempRoot::new(true);
        let root = validate_sdio_root(t.s()).unwrap();
        let pin = pin_index_dir(&root).unwrap();
        let moved = |p: &Path| std::fs::rename(p, p.with_extension("moved")).is_ok();
        let ancestors = [root.sdi.clone(), t.0.join("indexes"), t.0.clone()];
        assert!(ancestors.iter().all(|p| !moved(p)), "pinned chain renamed");
        drop(pin);
        assert!(moved(&root.sdi), "pin released");
        // An ancestor swapped for a junction after validation is caught under the pin.
        let t = TempRoot::new(true);
        let root = validate_sdio_root(t.s()).unwrap();
        let away = t.0.join("away");
        std::fs::rename(t.0.join("indexes"), &away).unwrap();
        std::fs::write(away.join("SDI").join("p.bin"), b"x").unwrap();
        junction(&t.0.join("indexes"), &away);
        let swapped = corpus_err(load_index_corpus(&root));
        assert_eq!(swapped, Some("index_dir_changed"));
    }

    // -- structural security gates -------------------------------------------

    fn production_source() -> &'static str {
        let src = include_str!("driver_updates.rs");
        &src[..src.find("#[cfg(test)]\nmod tests").unwrap()]
    }

    #[test]
    fn security_privacy_structural_no_mutation_ffi_network_or_identifier_logging() {
        let forbidden = "SetupCopyOEMInf DiInstallDevice DiInstallDriver UpdateDriverForPlugAndPlay \
            SetupUninstallOEMInf DiRollbackDriver remove_dir_all reqwest http: https: download \
            torrent Command::new windows_sys with_check_fn test-inject shutdown Box::leak \
            transmute unsafe println!";
        for word in forbidden.split_whitespace() {
            assert!(!production_source().contains(word), "{word}");
        }
        let mut rest = production_source();
        while let Some(i) = rest.find("tracing::") {
            let stmt = rest[i..i + rest[i..].find(';').unwrap()].to_lowercase();
            for leak in [
                "instance", "root", "session", "token", "hardware", "path", "id =",
            ] {
                assert!(!stmt.contains(leak), "{stmt}");
            }
            rest = &rest[i + 1..];
        }
    }

    #[test]
    fn split_structural_13a1_holds_no_lower_mutation_entry_point() {
        // Tab 2a-13a1: authorize/stage/install wiring is deferred to 13a2.
        let src = production_source();
        for call in [
            "authorize_driver_install",
            "stage_driver_install",
            "install_staged_driver",
        ] {
            assert!(!src.contains(call), "{call}");
        }
        assert!(!src.contains("tauri::command") && !src.contains("create_restore_point"));
    }
}
