//! Tab 2a-12a - exact-target install preparation (read-only, no-force gate).
//!
//! Given a per-device InstallPlanEntry and the MaterializedDriverSource it
//! was built for, this module proves entirely READ-ONLY that the
//! materialized package is the EXACT candidate Windows would compatibly
//! match against the EXACT target device instance, that it is uniquely the
//! best candidate under Windows' own documented selection ordering, and that
//! it is STRICTLY better than whatever the device's normal Driver Store
//! compatible list already offers. Only then is a PreparedDriverInstall
//! produced.
//!
//! Nothing here mutates the Driver Store, the registry, device state, restore
//! points or reboot state. No class installer is invoked. The only native
//! surface touched is device-information-set construction, compatible driver
//! list enumeration and INF parsing, all read-only per the SetupAPI contract.
//!
//! Windows selection ordering (verified against current Microsoft
//! documentation, "How Windows Selects Drivers" / "How Windows Ranks Driver
//! Packages"):
//!
//! 1. The driver package match with the LOWEST rank value wins.
//! 2. For matches with EQUAL rank, the MOST RECENT date wins.
//! 3. For matches with equal rank and date, the HIGHEST version wins.
//! 4. For matches equal in rank, date and version, Windows may select either.
//!    Cove refuses this case as ambiguous rather than picking one.
//!
//! DI_ENUMSINGLEINF restricts SetupDiBuildDriverInfoList to a single named
//! INF file (SP_DEVINSTALL_PARAMS.DriverPath) instead of a directory scan.
//! DI_FLAGSEX_ALLOWEXCLUDEDDRVS is required because PnP devices' driver
//! nodes are typically marked "Exclude From Select" (Microsoft documents that
//! a caller building a driver list for a PnP device must set this flag, or
//! the compatible list is empty even for a genuinely matching INF).
//!
//! Windows only: native preparation needs SetupAPI device-information-set
//! objects. Off Windows the entry point is
//! InstallPreparationError::PlatformUnsupported.

use std::path::Path;

use crate::sdio::install_plan::InstallPlanEntry;
use crate::sdio::package_materialization::{MaterializedDriverSource, PackageMaterializationError};

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use windows_sys::Win32::Devices::DeviceAndDriverInstallation as sa;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, GetLastError,
};

// ---------------------------------------------------------------------------
// Bounds (fail-closed caps; never sized from an untrusted native count)
// ---------------------------------------------------------------------------

/// Maximum compatible driver nodes evaluated per device set.
pub const MAX_DRIVER_NODES: usize = 256;

/// Maximum bytes accepted for one SetupDiGetDriverInfoDetailW result.
pub const MAX_DRIVER_DETAIL_BYTES: u32 = 64 * 1024;

/// Fixed capacity of SP_DEVINSTALL_PARAMS_W.DriverPath ([u16; 260]),
/// including the terminating NUL.
pub const DRIVER_PATH_CAPACITY: usize = 260;

// ---------------------------------------------------------------------------
// Errors (fail closed)
// ---------------------------------------------------------------------------

/// Why a PreparedDriverInstall could not even be attempted. Every variant is
/// a hard stop before any native device operation that could matter, or a
/// bounded/defensive rejection during one. Distinct from NoActionReason:
/// these are integrity/precondition failures, not benign "nothing to do"
/// outcomes.
#[derive(Debug, thiserror::Error)]
pub enum InstallPreparationError {
    /// Install preparation needs Windows SetupAPI device-information-set
    /// objects; there is no path-only fallback.
    #[error("install preparation needs Windows object handles")]
    PlatformUnsupported,
    /// The plan and the materialized source do not borrow the SAME live
    /// VerifiedDriverPackage. Names, leaves and digests are deliberately
    /// never accepted as a substitute for this check: only pointer identity
    /// of the live token is authoritative.
    #[error("plan and materialized source do not share the same verified package")]
    PackageBindingMismatch,
    /// Re-attestation of the materialized source, or reading its current INF
    /// path, failed. The original 2a-11 reason is preserved.
    #[error("materialized source check failed: {0}")]
    Source(#[from] PackageMaterializationError),
    /// The plan's target device-instance ID is empty, contains an embedded
    /// NUL, or exceeds the project's device-instance bound.
    #[error("target device instance id is invalid")]
    InvalidTargetInstanceId,
    /// The materialized INF's current path is not a supported local
    /// drive-absolute form.
    #[error("materialized INF path uses an unsupported namespace form")]
    PathFormUnsupported,
    /// The normalized INF path does not fit SP_DEVINSTALL_PARAMS_W.DriverPath
    /// ([u16; 260], including the terminating NUL). Never truncated.
    #[error("materialized INF path is too long for the native DriverPath field")]
    SourcePathTooLong,
    /// A named native SetupAPI call failed; `code` is the raw
    /// GetLastError() value.
    #[error("native call {api} failed with error {code}")]
    NativeCall { api: &'static str, code: u32 },
    /// Windows reported a device instance ID different from the one the plan
    /// requested, for the SAME opened device-information element.
    #[error("Windows reported a different device instance id than requested")]
    InstanceIdMismatch,
    /// A driver node returned while DI_ENUMSINGLEINF was configured for the
    /// materialized INF reported a different INF path.
    #[error("a candidate driver node's INF path did not match the materialized INF")]
    CandidatePathMismatch,
    /// SetupDiGetDriverInfoDetailW reported a RequiredSize beyond
    /// MAX_DRIVER_DETAIL_BYTES.
    #[error("native driver detail exceeded the bounded size limit")]
    DriverDetailTooLarge,
    /// A compatible driver list produced more than MAX_DRIVER_NODES entries.
    #[error("native driver node enumeration exceeded the bounded count limit")]
    TooManyDriverNodes,
}

use InstallPreparationError as Error;

// ---------------------------------------------------------------------------
// Pure evidence + ordering (portable; no native calls)
// ---------------------------------------------------------------------------

/// Bounded, immutable evidence for one Windows compatible-driver-list node:
/// exactly the three fields Windows' own documented selection ordering
/// depends on. No opaque native handle, pointer or Reserved field is ever
/// retained past the native list's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverSelectionSummary {
    rank: u32,
    driver_date_native: u64,
    driver_version: u64,
}

impl DriverSelectionSummary {
    /// Construct evidence directly from Windows-native values. Exposed (not
    /// test-only) because 2a-12b's authorization/staging step needs to
    /// reconstruct/compare the SAME evidence shape after Cove's own
    /// mutation, without this module inventing a second constructor there.
    pub fn from_native(rank: u32, driver_date_native: u64, driver_version: u64) -> Self {
        Self {
            rank,
            driver_date_native,
            driver_version,
        }
    }
    /// The native SP_DRVINSTALL_PARAMS.Rank (lower is better).
    pub fn rank(&self) -> u32 {
        self.rank
    }
    /// The native SP_DRVINFO_DATA_V2_W.DriverDate, packed as
    /// (dwHighDateTime << 32) | dwLowDateTime (higher is more recent).
    pub fn driver_date_native(&self) -> u64 {
        self.driver_date_native
    }
    /// The native SP_DRVINFO_DATA_V2_W.DriverVersion (higher is newer).
    pub fn driver_version(&self) -> u64 {
        self.driver_version
    }
}

/// The result of comparing two DriverSelectionSummary values under Windows'
/// documented ordering (lowest rank, then newest date, then highest
/// version).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeComparison {
    /// The first argument is the better match.
    First,
    /// The second argument is the better match.
    Second,
    /// Equal under every documented selection dimension. Windows itself may
    /// select either; Cove treats this as a tie requiring refusal, never a
    /// silent first-wins pick.
    Tie,
}

/// Compare two driver nodes under Windows' documented selection ordering.
/// Pure and total: for any a, b exactly one of First, Second, Tie is
/// returned, and swapping the arguments swaps First/Second and preserves
/// Tie.
pub fn compare_driver_nodes(
    a: DriverSelectionSummary,
    b: DriverSelectionSummary,
) -> NodeComparison {
    if a.rank != b.rank {
        return if a.rank < b.rank {
            NodeComparison::First
        } else {
            NodeComparison::Second
        };
    }
    if a.driver_date_native != b.driver_date_native {
        return if a.driver_date_native > b.driver_date_native {
            NodeComparison::First
        } else {
            NodeComparison::Second
        };
    }
    if a.driver_version != b.driver_version {
        return if a.driver_version > b.driver_version {
            NodeComparison::First
        } else {
            NodeComparison::Second
        };
    }
    NodeComparison::Tie
}

/// The outcome of selecting a unique best node from a bounded evidence
/// slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BestSelection {
    /// The slice was empty: nothing compatible.
    NotCompatible,
    /// Exactly one node is the (strict) best under compare_driver_nodes; its
    /// index into the input slice is carried.
    Unique(usize),
    /// Two or more DISTINCT nodes tie for best under every documented
    /// selection dimension. Windows may pick either; Cove refuses to.
    Ambiguous,
}

/// Select the unique best node, or report why none exists. Single pass,
/// bounded by the input slice length; never allocates beyond the final
/// index lookup. `nodes` is never re-ordered: enumeration order is not
/// selection order.
pub fn select_unique_best(nodes: &[DriverSelectionSummary]) -> BestSelection {
    let mut iter = nodes.iter();
    let Some(first) = iter.next() else {
        return BestSelection::NotCompatible;
    };
    let mut best = *first;
    let mut ambiguous = false;
    for &node in iter {
        match compare_driver_nodes(node, best) {
            NodeComparison::First => {
                best = node;
                ambiguous = false;
            }
            NodeComparison::Second => {}
            NodeComparison::Tie => {
                ambiguous = true;
            }
        }
    }
    if ambiguous {
        BestSelection::Ambiguous
    } else {
        let idx = nodes
            .iter()
            .position(|n| *n == best)
            .expect("best came from this slice");
        BestSelection::Unique(idx)
    }
}

/// Why no PreparedDriverInstall was produced, even though the gate ran
/// cleanly to completion. Distinct from InstallPreparationError: these are
/// legitimate, non-error outcomes of a correct read-only evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoActionReason {
    /// The single-INF compatible search produced zero nodes for the target
    /// device: the materialized package does not compatibly match it.
    CandidateNotCompatible,
    /// Two or more candidate nodes tie for best; Cove refuses to force a
    /// choice Windows itself would not make deterministically.
    CandidateAmbiguous,
    /// Two or more CURRENT Driver Store nodes tie for best; the baseline is
    /// itself ambiguous, so no claim of "strictly better" can be made.
    CurrentAmbiguous,
    /// The unique candidate is not strictly better than the unique current
    /// best (worse rank, or same rank with an older date, or same
    /// rank/date with a lower version).
    NotBetterThanCurrent,
    /// The unique candidate and the unique current best compare exactly
    /// equal under every documented selection dimension.
    EquivalentDriverAlreadyAvailable,
}

// ---------------------------------------------------------------------------
// Prepared capability
// ---------------------------------------------------------------------------

/// A proven, read-only install authorization capability: the candidate is
/// uniquely the best compatible match for the exact target device AND
/// strictly better than whatever the device's normal Driver Store compatible
/// list currently offers (or nothing currently applies).
///
/// Borrows both the plan and the materialized source, so it cannot outlive
/// either, and therefore cannot outlive the live VerifiedDriverPackage both
/// of them are bound to. Deliberately not Clone/Copy: this is a one-shot
/// proof of a point-in-time native state, not a value to be duplicated and
/// replayed later without re-proving it.
///
/// PREP-R30 - not Clone. Compiler RED: the snippet fails only because
/// PreparedDriverInstall does not implement Clone.
///
/// ```compile_fail
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<mod_drivers::sdio::install_preparation::PreparedDriverInstall<'static, 'static>>();
/// ```
///
/// PREP-R29 - cannot outlive the plan/source it borrows. Compiler RED: the
/// snippet fails only because 'a cannot be extended to 'static.
///
/// ```compile_fail
/// use mod_drivers::sdio::install_preparation::PreparedDriverInstall;
/// fn escape<'a, 'v>(p: PreparedDriverInstall<'a, 'v>) -> PreparedDriverInstall<'static, 'static> { p }
/// ```
///
/// The companion positive case compiles, confirming the failure above is the
/// lifetime and not a typo in the path:
///
/// ```
/// use mod_drivers::sdio::install_preparation::PreparedDriverInstall;
/// fn keep<'a, 'v>(p: PreparedDriverInstall<'a, 'v>) -> PreparedDriverInstall<'a, 'v> { p }
/// ```
pub struct PreparedDriverInstall<'a, 'v> {
    plan: &'a InstallPlanEntry<'v>,
    source: &'a MaterializedDriverSource<'v>,
    candidate: DriverSelectionSummary,
    current_best: Option<DriverSelectionSummary>,
}

impl std::fmt::Debug for PreparedDriverInstall<'_, '_> {
    /// Redacted: never formats the target device instance ID. Callers that
    /// genuinely need it (2a-12b) use
    /// PreparedDriverInstall::target_device_instance_id explicitly.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedDriverInstall")
            .field("candidate", &self.candidate)
            .field("current_best", &self.current_best)
            .finish_non_exhaustive()
    }
}

impl<'a, 'v> PreparedDriverInstall<'a, 'v> {
    /// The exact target device-instance ID this preparation was proven
    /// against. Explicit accessor for 2a-12b; ordinary logging should prefer
    /// counts/reasons over this value.
    pub fn target_device_instance_id(&self) -> &str {
        self.plan.target_device_instance_id()
    }
    /// The proven-unique candidate evidence.
    pub fn candidate(&self) -> DriverSelectionSummary {
        self.candidate
    }
    /// The current Driver Store unique-best evidence, or None when the
    /// device's normal compatible list had no node.
    pub fn current_best(&self) -> Option<DriverSelectionSummary> {
        self.current_best
    }
    /// The install-plan entry this preparation borrows.
    pub fn plan(&self) -> &'a InstallPlanEntry<'v> {
        self.plan
    }
    /// The materialized source this preparation borrows.
    pub fn source(&self) -> &'a MaterializedDriverSource<'v> {
        self.source
    }
}

/// The outcome of a complete, successful (non-error) preparation attempt.
#[derive(Debug)]
pub enum InstallPreparation<'a, 'v> {
    /// The candidate is authorized to be prepared for install.
    Ready(PreparedDriverInstall<'a, 'v>),
    /// The gate completed but no install may be prepared.
    NoAction(NoActionReason),
}

/// Strict no-force decision: pure, and identical for both the production
/// native path and tests. `candidate` must already be the proven unique
/// best; `current_best` must already be the proven unique current best (or
/// None when the current compatible list was empty).
fn decide<'a, 'v>(
    plan: &'a InstallPlanEntry<'v>,
    source: &'a MaterializedDriverSource<'v>,
    candidate: DriverSelectionSummary,
    current_best: Option<DriverSelectionSummary>,
) -> InstallPreparation<'a, 'v> {
    match current_best {
        None => InstallPreparation::Ready(PreparedDriverInstall {
            plan,
            source,
            candidate,
            current_best: None,
        }),
        Some(current) => match compare_driver_nodes(candidate, current) {
            NodeComparison::First => InstallPreparation::Ready(PreparedDriverInstall {
                plan,
                source,
                candidate,
                current_best: Some(current),
            }),
            NodeComparison::Tie => {
                InstallPreparation::NoAction(NoActionReason::EquivalentDriverAlreadyAvailable)
            }
            NodeComparison::Second => {
                InstallPreparation::NoAction(NoActionReason::NotBetterThanCurrent)
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Pure input validation (portable; no native calls)
// ---------------------------------------------------------------------------

/// Validate a target device-instance ID BEFORE any native conversion:
/// non-empty, no embedded NUL, and within the project's existing
/// device-instance bound (crate::identity::MAX_INSTANCE_ID_LENGTH). Never
/// trims, reformats or otherwise alters the string.
pub fn validate_target_instance_id(id: &str) -> Result<(), Error> {
    if id.is_empty() || id.contains('\0') {
        return Err(Error::InvalidTargetInstanceId);
    }
    if id.encode_utf16().count() >= crate::identity::MAX_INSTANCE_ID_LENGTH {
        return Err(Error::InvalidTargetInstanceId);
    }
    Ok(())
}

/// Normalize ONE narrowly-supported local SetupAPI path form.
///
/// Accepted:
/// - a bare drive-absolute path, e.g. `C:\foo\bar.inf`;
/// - the same path with an extended-length `\\?\` prefix, e.g.
///   `\\?\C:\foo\bar.inf`, stripped to the bare form.
///
/// Rejected (fail closed, never guessed): any other `\`-prefixed form
/// (UNC shares, `\\?\UNC\...`, device namespaces like `\\.\`), and any
/// non-drive-absolute path. No trimming, no case folding of the drive
/// letter beyond what the caller already has, no relative-path handling.
pub fn normalize_local_setupapi_path(path: &Path) -> Result<String, Error> {
    let s = path.to_str().ok_or(Error::PathFormUnsupported)?;
    normalize_local_setupapi_path_str(s)
}

fn normalize_local_setupapi_path_str(s: &str) -> Result<String, Error> {
    let candidate = match s.strip_prefix(r"\\?\") {
        Some(rest) => rest,
        None => s,
    };
    if candidate.starts_with('\\') {
        // Any remaining leading backslash after stripping exactly one
        // `\\?\` prefix means this was UNC, `\\?\UNC\...`, or a device
        // namespace; none of those are the local drive-absolute form this
        // gate supports.
        return Err(Error::PathFormUnsupported);
    }
    let bytes = candidate.as_bytes();
    let is_drive_absolute =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    if !is_drive_absolute {
        return Err(Error::PathFormUnsupported);
    }
    Ok(candidate.to_string())
}

/// Compare an ALREADY-normalized expected local path against a raw string
/// SetupAPI reported for a candidate driver node. Applies the SAME narrow
/// normalization to the reported side (so a `\\?\`-prefixed echo is handled
/// identically), then compares the two supported local forms with an
/// ASCII/ordinal CASE-INSENSITIVE comparison: Windows is known to report the
/// same local path with different letter case. No trimming, no
/// prefix/substring matching, no relative-path equivalence.
pub fn setupapi_inf_paths_match(expected_normalized: &str, reported: &str) -> Result<bool, Error> {
    let reported_normalized = normalize_local_setupapi_path_str(reported)?;
    Ok(expected_normalized.eq_ignore_ascii_case(&reported_normalized))
}

/// Encode an already-normalized local path into the fixed
/// SP_DEVINSTALL_PARAMS_W.DriverPath buffer shape. Fails closed
/// (InstallPreparationError::SourcePathTooLong) rather than truncating when
/// the UTF-16 encoding plus its terminating NUL would not fit.
pub fn encode_driver_path(normalized: &str) -> Result<[u16; DRIVER_PATH_CAPACITY], Error> {
    let wide: Vec<u16> = normalized.encode_utf16().collect();
    if wide.len() >= DRIVER_PATH_CAPACITY {
        return Err(Error::SourcePathTooLong);
    }
    let mut buf = [0u16; DRIVER_PATH_CAPACITY];
    buf[..wide.len()].copy_from_slice(&wide);
    Ok(buf)
}

/// Validate an already-read native RequiredSize against
/// MAX_DRIVER_DETAIL_BYTES. Pure so the bound itself is directly testable
/// without a native call.
fn validate_driver_detail_required_size(required: u32) -> Result<(), Error> {
    if required > MAX_DRIVER_DETAIL_BYTES {
        return Err(Error::DriverDetailTooLarge);
    }
    Ok(())
}

/// Generic bounded collector shared by both the candidate and current-store
/// enumeration loops: calls `next(index)` for `index` `0..`, treating
/// `Ok(None)` as a clean end-of-list and failing closed the moment a caller
/// would need to retain more than MAX_DRIVER_NODES items. Kept generic and
/// free of any native type so it is directly unit-testable with a fake
/// `next`.
fn collect_bounded<T>(
    mut next: impl FnMut(usize) -> Result<Option<T>, Error>,
) -> Result<Vec<T>, Error> {
    // Deliberately unbounded index range: the ONLY defense against an
    // untrusted/hostile `next` that never reports end-of-list is the
    // explicit length check below, not an outer loop cap that would let a
    // second bound silently do the real work.
    let mut out = Vec::new();
    let mut index = 0usize;
    loop {
        match next(index)? {
            Some(item) => {
                if out.len() >= MAX_DRIVER_NODES {
                    return Err(Error::TooManyDriverNodes);
                }
                out.push(item);
            }
            None => return Ok(out),
        }
        index += 1;
    }
}

#[cfg(feature = "test-inject")]
pub fn test_validate_driver_detail_required_size(
    required: u32,
) -> Result<(), InstallPreparationError> {
    validate_driver_detail_required_size(required)
}

#[cfg(feature = "test-inject")]
pub fn test_collect_bounded(count: usize) -> Result<Vec<usize>, InstallPreparationError> {
    collect_bounded(|i| if i < count { Ok(Some(i)) } else { Ok(None) })
}

#[cfg(feature = "test-inject")]
pub fn test_decide<'a, 'v>(
    plan: &'a InstallPlanEntry<'v>,
    source: &'a MaterializedDriverSource<'v>,
    candidate: DriverSelectionSummary,
    current_best: Option<DriverSelectionSummary>,
) -> InstallPreparation<'a, 'v> {
    decide(plan, source, candidate, current_best)
}

// ---------------------------------------------------------------------------
// Forbidden mutation surface (structural gate; PREP-R31)
// ---------------------------------------------------------------------------
//
// This module contains NONE of: SetupCopyOEMInf, SetupUninstallOEMInf,
// DiInstallDevice, DiInstallDriver, UpdateDriverForPlugAndPlayDevices,
// SetupDiCallClassInstaller, pnputil install/delete/enable/disable/restart/
// remove, registry writes, device property writes, restore-point creation,
// reboot, or elevation. The integration suite asserts this against the
// SOURCE TEXT of this file (PREP-R31), not just against behavior, so the
// gate holds even if a future edit stops exercising the forbidden call.

#[cfg(not(windows))]
pub fn prepare_driver_install<'a, 'v>(
    _plan: &'a InstallPlanEntry<'v>,
    _source: &'a MaterializedDriverSource<'v>,
) -> Result<InstallPreparation<'a, 'v>, InstallPreparationError> {
    Err(InstallPreparationError::PlatformUnsupported)
}

#[cfg(windows)]
pub use win::prepare_driver_install;

#[cfg(windows)]
pub(crate) mod win {
    //! The complete native surface: device-information-set construction,
    //! compatible driver list enumeration, and INF-open readability probing.
    //! No file queue, copy, commit, install, registry or class-installer API
    //! is referenced.

    use super::*;
    use std::iter::once;

    pub(crate) fn wide_nul(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(once(0))
            .collect()
    }

    fn wide_nul_path(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(once(0)).collect()
    }

    pub(crate) fn wide_to_string(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    pub(crate) fn last_error() -> u32 {
        // SAFETY: plain thread-local error read.
        unsafe { GetLastError() }
    }

    fn native_error(api: &'static str) -> Error {
        Error::NativeCall {
            api,
            code: last_error(),
        }
    }

    /// A device-information-set handle, destroyed exactly once on every
    /// path (success, native error, early return) via Drop.
    pub(crate) struct DeviceInfoSet(sa::HDEVINFO);

    impl DeviceInfoSet {
        /// The raw device-information-set handle. 2a-12b1 reuses this
        /// guard so the exact-device-open + instance-round-trip proof
        /// (`open_exact_device`) is never re-implemented.
        pub(crate) fn handle(&self) -> sa::HDEVINFO {
            self.0
        }
    }

    impl Drop for DeviceInfoSet {
        fn drop(&mut self) {
            // SAFETY: self.0 was returned by a successful
            // SetupDiCreateDeviceInfoList and is destroyed at most once.
            unsafe {
                sa::SetupDiDestroyDeviceInfoList(self.0);
            }
        }
    }

    /// A built compatible-driver list, destroyed exactly once via Drop.
    /// Always built with SPDIT_COMPATDRIVER; there is no other driver-type
    /// use in this module.
    struct DriverInfoList {
        hdevinfo: sa::HDEVINFO,
        devinfo: sa::SP_DEVINFO_DATA,
    }

    impl Drop for DriverInfoList {
        fn drop(&mut self) {
            // SAFETY: devinfo is the same element the list was built for;
            // destroyed at most once.
            unsafe {
                sa::SetupDiDestroyDriverInfoList(
                    self.hdevinfo,
                    &self.devinfo,
                    sa::SPDIT_COMPATDRIVER,
                );
            }
        }
    }

    /// An open INF probe handle, closed exactly once via Drop. Proves the
    /// materialized INF is still readable by SetupAPI while the 11c
    /// permanent read lease is live; nothing is parsed beyond the open.
    struct HinfProbe(*mut c_void);

    impl Drop for HinfProbe {
        fn drop(&mut self) {
            // SAFETY: a live handle from a successful open, closed once.
            unsafe {
                sa::SetupCloseInfFile(self.0);
            }
        }
    }

    /// Prove the materialized INF still opens under SetupAPI while the 11c
    /// lease remains fully live. The probe handle is closed before this
    /// function returns; nothing is retained.
    fn probe_inf_readable(path: &Path) -> Result<(), Error> {
        let wide = wide_nul_path(path);
        let mut error_line = 0u32;
        // SAFETY: NUL-terminated path; a null class accepts any INF class.
        let h = unsafe {
            sa::SetupOpenInfFileW(
                wide.as_ptr(),
                std::ptr::null(),
                sa::INF_STYLE_WIN4,
                &mut error_line,
            )
        };
        if h.is_null() || h as isize == -1 {
            return Err(native_error("SetupOpenInfFileW"));
        }
        let _guard = HinfProbe(h);
        Ok(())
    }

    /// Read the device-instance ID Windows associates with an already-open
    /// device-information element, bounded to the project's own
    /// instance-ID capacity. No growth loop: an instance ID at or beyond
    /// crate::identity::MAX_INSTANCE_ID_LENGTH is rejected, not retried with
    /// a larger buffer.
    fn read_device_instance_id(
        hdevinfo: sa::HDEVINFO,
        devinfo: &sa::SP_DEVINFO_DATA,
    ) -> Result<String, Error> {
        const CAP: usize = crate::identity::MAX_INSTANCE_ID_LENGTH + 1;
        let mut buf = vec![0u16; CAP];
        let mut required = 0u32;
        // SAFETY: live handle/element; buffer length passed exactly.
        let ok = unsafe {
            sa::SetupDiGetDeviceInstanceIdW(
                hdevinfo,
                devinfo,
                buf.as_mut_ptr(),
                CAP as u32,
                &mut required,
            )
        };
        if ok == 0 {
            return Err(native_error("SetupDiGetDeviceInstanceIdW"));
        }
        Ok(wide_to_string(&buf))
    }

    /// Open the EXACT target device by its plan instance ID (never by
    /// hardware ID, compatible ID, class or description), then round-trip
    /// Windows' own reported instance ID and require EXACT (ordinal)
    /// equality; no documented case-insensitive equivalence exists for this
    /// specific SetupDiOpenDeviceInfoW / SetupDiGetDeviceInstanceIdW pair, so
    /// none is invented here.
    pub(crate) fn open_exact_device(
        instance_id: &str,
    ) -> Result<(DeviceInfoSet, sa::SP_DEVINFO_DATA), Error> {
        // SAFETY: no class GUID restriction, no parent window.
        let hdevinfo =
            unsafe { sa::SetupDiCreateDeviceInfoList(std::ptr::null(), std::ptr::null_mut()) };
        if hdevinfo == -1 {
            return Err(native_error("SetupDiCreateDeviceInfoList"));
        }
        let guard = DeviceInfoSet(hdevinfo);
        let wide = wide_nul(instance_id);
        let mut devinfo: sa::SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
        devinfo.cbSize = std::mem::size_of::<sa::SP_DEVINFO_DATA>() as u32;
        // SAFETY: hdevinfo freshly created; NUL-terminated instance ID.
        let ok = unsafe {
            sa::SetupDiOpenDeviceInfoW(
                hdevinfo,
                wide.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut devinfo,
            )
        };
        if ok == 0 {
            return Err(native_error("SetupDiOpenDeviceInfoW"));
        }
        let reported = read_device_instance_id(hdevinfo, &devinfo)?;
        if reported != instance_id {
            return Err(Error::InstanceIdMismatch);
        }
        Ok((guard, devinfo))
    }

    /// Configure device set A for the single-INF candidate search: read the
    /// current install params (never blindly overwritten), OR-in
    /// DI_ENUMSINGLEINF and DI_FLAGSEX_ALLOWEXCLUDEDDRVS (required: PnP
    /// device driver nodes are normally Exclude-From-Select), and set the
    /// bounded DriverPath to the exact materialized INF.
    fn configure_single_inf_search(
        hdevinfo: sa::HDEVINFO,
        devinfo: &sa::SP_DEVINFO_DATA,
        driver_path: &[u16; DRIVER_PATH_CAPACITY],
    ) -> Result<(), Error> {
        let mut params: sa::SP_DEVINSTALL_PARAMS_W = unsafe { std::mem::zeroed() };
        params.cbSize = std::mem::size_of::<sa::SP_DEVINSTALL_PARAMS_W>() as u32;
        // SAFETY: live handle/element; struct sized per contract.
        let ok = unsafe { sa::SetupDiGetDeviceInstallParamsW(hdevinfo, devinfo, &mut params) };
        if ok == 0 {
            return Err(native_error("SetupDiGetDeviceInstallParamsW"));
        }
        params.Flags |= sa::DI_ENUMSINGLEINF;
        params.FlagsEx |= sa::DI_FLAGSEX_ALLOWEXCLUDEDDRVS;
        params.DriverPath = *driver_path;
        // SAFETY: as above.
        let ok = unsafe { sa::SetupDiSetDeviceInstallParamsW(hdevinfo, devinfo, &params) };
        if ok == 0 {
            return Err(native_error("SetupDiSetDeviceInstallParamsW"));
        }
        Ok(())
    }

    /// Configure device set B for the independent normal Driver Store search:
    /// read the current install params and OR-in ONLY
    /// DI_FLAGSEX_ALLOWEXCLUDEDDRVS, leaving Flags (no DI_ENUMSINGLEINF) and
    /// DriverPath (empty) untouched. Without this flag, PnP driver nodes
    /// marked Exclude-From-Select (the normal state for an already-installed
    /// PnP driver, per Microsoft's SetupDiBuildDriverInfoList documentation)
    /// are silently omitted from the compatible list, which would let an
    /// existing better-or-equal driver disappear from `current_best` and
    /// defeat the strict no-force policy.
    pub(crate) fn configure_current_store_search(
        hdevinfo: sa::HDEVINFO,
        devinfo: &sa::SP_DEVINFO_DATA,
    ) -> Result<(), Error> {
        let mut params: sa::SP_DEVINSTALL_PARAMS_W = unsafe { std::mem::zeroed() };
        params.cbSize = std::mem::size_of::<sa::SP_DEVINSTALL_PARAMS_W>() as u32;
        // SAFETY: live handle/element; struct sized per contract.
        let ok = unsafe { sa::SetupDiGetDeviceInstallParamsW(hdevinfo, devinfo, &mut params) };
        if ok == 0 {
            return Err(native_error("SetupDiGetDeviceInstallParamsW"));
        }
        params.FlagsEx |= sa::DI_FLAGSEX_ALLOWEXCLUDEDDRVS;
        // SAFETY: as above.
        let ok = unsafe { sa::SetupDiSetDeviceInstallParamsW(hdevinfo, devinfo, &params) };
        if ok == 0 {
            return Err(native_error("SetupDiSetDeviceInstallParamsW"));
        }
        Ok(())
    }

    fn build_driver_info_list(
        hdevinfo: sa::HDEVINFO,
        devinfo: &sa::SP_DEVINFO_DATA,
    ) -> Result<DriverInfoList, Error> {
        let mut d = *devinfo;
        // SAFETY: live handle/element; read-only list construction.
        let ok =
            unsafe { sa::SetupDiBuildDriverInfoList(hdevinfo, &mut d, sa::SPDIT_COMPATDRIVER) };
        if ok == 0 {
            return Err(native_error("SetupDiBuildDriverInfoList"));
        }
        Ok(DriverInfoList {
            hdevinfo,
            devinfo: d,
        })
    }

    /// Read one candidate node's INF path evidence and cross-check it
    /// against the materialized INF, bounded to MAX_DRIVER_DETAIL_BYTES.
    /// cbSize is the FIXED struct size; the documented gotcha is that it
    /// must NOT be set to the buffer size parameter, so those two are kept
    /// as distinct values here even though they happen to share the same
    /// expression.
    /// Read one driver node's reported INF path, bounded to
    /// MAX_DRIVER_DETAIL_BYTES. Returns the RAW string SetupAPI reported;
    /// callers compare it via `setupapi_inf_paths_match`, which normalizes
    /// the reported side itself. Shared by the single-INF candidate check
    /// below and 2a-12b1's post-stage published-INF binding.
    fn get_driver_inf_path(
        hdevinfo: sa::HDEVINFO,
        devinfo: &sa::SP_DEVINFO_DATA,
        drv: &sa::SP_DRVINFO_DATA_V2_W,
    ) -> Result<String, Error> {
        let mut detail: sa::SP_DRVINFO_DETAIL_DATA_W = unsafe { std::mem::zeroed() };
        detail.cbSize = std::mem::size_of::<sa::SP_DRVINFO_DETAIL_DATA_W>() as u32;
        let buffer_size = std::mem::size_of::<sa::SP_DRVINFO_DETAIL_DATA_W>() as u32;
        let mut required = 0u32;
        // SAFETY: live handle/element/node; buffer sized to the fixed struct.
        let ok = unsafe {
            sa::SetupDiGetDriverInfoDetailW(
                hdevinfo,
                devinfo,
                drv,
                &mut detail,
                buffer_size,
                &mut required,
            )
        };
        if ok == 0 {
            let code = last_error();
            if code != ERROR_INSUFFICIENT_BUFFER {
                return Err(Error::NativeCall {
                    api: "SetupDiGetDriverInfoDetailW",
                    code,
                });
            }
            validate_driver_detail_required_size(required)?;
        }
        Ok(wide_to_string(&detail.InfFileName))
    }

    /// Read one candidate node's INF path evidence and cross-check it
    /// against the materialized INF, bounded to MAX_DRIVER_DETAIL_BYTES.
    fn check_candidate_inf_path(
        hdevinfo: sa::HDEVINFO,
        devinfo: &sa::SP_DEVINFO_DATA,
        drv: &sa::SP_DRVINFO_DATA_V2_W,
        expected_normalized: &str,
    ) -> Result<(), Error> {
        let reported = get_driver_inf_path(hdevinfo, devinfo, drv)?;
        if !setupapi_inf_paths_match(expected_normalized, &reported).unwrap_or(false) {
            return Err(Error::CandidatePathMismatch);
        }
        Ok(())
    }

    /// Enumerate a device's compatible driver list, bounded to
    /// MAX_DRIVER_NODES. When expected_inf_normalized is Some, every
    /// returned node is cross-checked against it (the single-INF candidate
    /// search); when None, no INF binding is checked (the independent
    /// normal Driver Store search).
    fn enumerate_compat_driver_nodes(
        hdevinfo: sa::HDEVINFO,
        devinfo: &sa::SP_DEVINFO_DATA,
        expected_inf_normalized: Option<&str>,
    ) -> Result<Vec<DriverSelectionSummary>, Error> {
        let _list = build_driver_info_list(hdevinfo, devinfo)?;
        collect_bounded(|index| {
            let mut drv: sa::SP_DRVINFO_DATA_V2_W = unsafe { std::mem::zeroed() };
            drv.cbSize = std::mem::size_of::<sa::SP_DRVINFO_DATA_V2_W>() as u32;
            // SAFETY: live handle/element; bounded index; struct sized.
            let ok = unsafe {
                sa::SetupDiEnumDriverInfoW(
                    hdevinfo,
                    devinfo,
                    sa::SPDIT_COMPATDRIVER,
                    index as u32,
                    &mut drv,
                )
            };
            if ok == 0 {
                let code = last_error();
                return if code == ERROR_NO_MORE_ITEMS {
                    Ok(None)
                } else {
                    Err(Error::NativeCall {
                        api: "SetupDiEnumDriverInfoW",
                        code,
                    })
                };
            }
            let mut params: sa::SP_DRVINSTALL_PARAMS = unsafe { std::mem::zeroed() };
            params.cbSize = std::mem::size_of::<sa::SP_DRVINSTALL_PARAMS>() as u32;
            // SAFETY: drv came from the successful enum call above.
            let ok =
                unsafe { sa::SetupDiGetDriverInstallParamsW(hdevinfo, devinfo, &drv, &mut params) };
            if ok == 0 {
                return Err(native_error("SetupDiGetDriverInstallParamsW"));
            }
            if let Some(expected) = expected_inf_normalized {
                check_candidate_inf_path(hdevinfo, devinfo, &drv, expected)?;
            }
            let date = drv.DriverDate;
            let driver_date_native =
                ((date.dwHighDateTime as u64) << 32) | date.dwLowDateTime as u64;
            Ok(Some(DriverSelectionSummary::from_native(
                params.Rank,
                driver_date_native,
                drv.DriverVersion,
            )))
        })
    }

    /// Tab 2a-12b1 counterpart of `enumerate_compat_driver_nodes`: the SAME
    /// bounded enumeration and rank/date/version extraction, but returning
    /// each node's raw reported INF path alongside its summary instead of
    /// failing closed on a mismatch. The native driver list is built and
    /// destroyed entirely within this call (never retained past return);
    /// 12b1 never needs to keep a live native list across calls, since it
    /// stops after the unique-best proof rather than calling
    /// DiInstallDevice. Never called by 12a's own read-only gate.
    pub(crate) fn enumerate_compat_driver_nodes_with_inf_paths(
        hdevinfo: sa::HDEVINFO,
        devinfo: &sa::SP_DEVINFO_DATA,
    ) -> Result<Vec<(DriverSelectionSummary, String)>, Error> {
        let _list = build_driver_info_list(hdevinfo, devinfo)?;
        collect_bounded(|index| {
            let mut drv: sa::SP_DRVINFO_DATA_V2_W = unsafe { std::mem::zeroed() };
            drv.cbSize = std::mem::size_of::<sa::SP_DRVINFO_DATA_V2_W>() as u32;
            // SAFETY: live handle/element; bounded index; struct sized.
            let ok = unsafe {
                sa::SetupDiEnumDriverInfoW(
                    hdevinfo,
                    devinfo,
                    sa::SPDIT_COMPATDRIVER,
                    index as u32,
                    &mut drv,
                )
            };
            if ok == 0 {
                let code = last_error();
                return if code == ERROR_NO_MORE_ITEMS {
                    Ok(None)
                } else {
                    Err(Error::NativeCall {
                        api: "SetupDiEnumDriverInfoW",
                        code,
                    })
                };
            }
            let mut params: sa::SP_DRVINSTALL_PARAMS = unsafe { std::mem::zeroed() };
            params.cbSize = std::mem::size_of::<sa::SP_DRVINSTALL_PARAMS>() as u32;
            // SAFETY: drv came from the successful enum call above.
            let ok =
                unsafe { sa::SetupDiGetDriverInstallParamsW(hdevinfo, devinfo, &drv, &mut params) };
            if ok == 0 {
                return Err(native_error("SetupDiGetDriverInstallParamsW"));
            }
            let inf_path = get_driver_inf_path(hdevinfo, devinfo, &drv)?;
            let date = drv.DriverDate;
            let driver_date_native =
                ((date.dwHighDateTime as u64) << 32) | date.dwLowDateTime as u64;
            Ok(Some((
                DriverSelectionSummary::from_native(
                    params.Rank,
                    driver_date_native,
                    drv.DriverVersion,
                ),
                inf_path,
            )))
        })
    }

    /// The complete, read-only preparation gate. See the module
    /// documentation for the full contract.
    pub fn prepare_driver_install<'a, 'v>(
        plan: &'a InstallPlanEntry<'v>,
        source: &'a MaterializedDriverSource<'v>,
    ) -> Result<InstallPreparation<'a, 'v>, InstallPreparationError> {
        // Gate 1: exact live package binding, pointer identity only.
        if !std::ptr::eq(plan.verified_package(), source.verified_package()) {
            return Err(Error::PackageBindingMismatch);
        }
        // Gate 2: re-prove the materialized source from its retained
        // handles.
        source.reattest()?;
        // Gate 3: validate the plan's target instance ID before ANY native
        // conversion.
        validate_target_instance_id(plan.target_device_instance_id())?;
        // Gate 4: the materialized INF's CURRENT path, from the retained
        // handle, never a captured/pathname value.
        let inf_path = source.current_inf_path()?;
        // Gate 5: prove the INF is still readable by SetupAPI while the 11c
        // lease remains fully live.
        probe_inf_readable(&inf_path)?;
        let normalized_inf = normalize_local_setupapi_path(&inf_path)?;
        let driver_path = encode_driver_path(&normalized_inf)?;

        // Gate 6/7: exact-device open + round-trip, candidate search, on an
        // ISOLATED device-information set (set A).
        let (device_a, devinfo_a) = open_exact_device(plan.target_device_instance_id())?;
        configure_single_inf_search(device_a.0, &devinfo_a, &driver_path)?;
        let candidate_nodes =
            enumerate_compat_driver_nodes(device_a.0, &devinfo_a, Some(&normalized_inf))?;
        drop(device_a);

        let candidate_best = match select_unique_best(&candidate_nodes) {
            BestSelection::NotCompatible => {
                return Ok(InstallPreparation::NoAction(
                    NoActionReason::CandidateNotCompatible,
                ));
            }
            BestSelection::Ambiguous => {
                return Ok(InstallPreparation::NoAction(
                    NoActionReason::CandidateAmbiguous,
                ));
            }
            BestSelection::Unique(i) => candidate_nodes[i],
        };

        // Gate 8: the SAME exact-device proof, on a completely INDEPENDENT
        // device-information set (set B): the normal local Driver Store
        // compatible search. No DI_ENUMSINGLEINF, no DriverPath -- but
        // DI_FLAGSEX_ALLOWEXCLUDEDDRVS IS set (configure_current_store_search)
        // so an already-installed, normally Exclude-From-Select PnP driver
        // is not silently dropped from the baseline.
        let (device_b, devinfo_b) = open_exact_device(plan.target_device_instance_id())?;
        configure_current_store_search(device_b.0, &devinfo_b)?;
        let current_nodes = enumerate_compat_driver_nodes(device_b.0, &devinfo_b, None)?;
        drop(device_b);

        let current_best = match select_unique_best(&current_nodes) {
            BestSelection::NotCompatible => None,
            BestSelection::Ambiguous => {
                return Ok(InstallPreparation::NoAction(
                    NoActionReason::CurrentAmbiguous,
                ));
            }
            BestSelection::Unique(i) => Some(current_nodes[i]),
        };

        Ok(decide(plan, source, candidate_best, current_best))
    }
}
