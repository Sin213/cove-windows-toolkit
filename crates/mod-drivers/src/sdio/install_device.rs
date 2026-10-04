//! Tab 2a-12b2 - exact-device driver installation.
//!
//! Begins ONLY from an already-StagedDriverInstall capability (Tab
//! 2a-12b1): the Driver Store is ALREADY mutated before any code in this
//! module runs. This module never calls SetupCopyOEMInfW again; it owns
//! Cove's SECOND and LAST production mutation call, DiInstallDevice, and
//! the read-only reconciliation that follows it.
//!
//! ```text
//! StagedDriverInstall (consumed, one-shot)
//!   -> elevation re-check
//!   -> pre-install source re-attestation
//!   -> fresh exact-device reopen + fresh normal compatible list
//!      -> re-prove unique-best / published-INF-bound / candidate-unchanged
//!   -> DiInstallDevice <- SECOND AND LAST MUTATION
//!   -> post-install source re-attestation
//!   -> fresh exact-device reopen + DEVPKEY_Device_DriverInfPath read
//!   -> partial-success-aware outcome
//! ```
//!
//! Because StagedDriverInstall means the Driver Store is already mutated,
//! every runtime/native refusal or failure past that point is reported as
//! a mutation-aware InstallExecutionOutcome variant, never as a plain
//! Err. Err is reserved for platform/test-lockout cases that are true
//! regardless of staged's own history.
//!
//! No restaging, no rollback, no reboot, no cancellation path exists
//! here: once a StagedDriverInstall exists, this module either refuses to
//! install it (Driver Store remains staged, unmodified) or completes the
//! bounded install transaction.
//!
//! Off Windows: InstallExecutionError::PlatformUnsupported. Under
//! test-inject the PUBLIC entry point (install_staged_driver) fails
//! closed with InstallExecutionError::MutationDisabledInTestBuild instead
//! of routing to the real backend, which still compiles and links. Tests
//! drive the same state machine through
//! test_install_with_scripted_backend.

use crate::sdio::install_preparation::DriverSelectionSummary;
use crate::sdio::install_staging::{PublishedInf, StagedDriverInstall};

// ---------------------------------------------------------------------------
// Property-read bound (portable; no native call)
// ---------------------------------------------------------------------------

/// Bounded cap on the DEVPKEY_Device_DriverInfPath property buffer. Never
/// retried with a larger buffer: a property that does not fit is a
/// reconciliation failure, not a reason to grow and ask Windows again.
pub const MAX_INSTALLED_INF_PROPERTY_BYTES: usize = 4096;

/// The native DEVPROP_TYPE_STRING value
/// (windows_sys::Win32::Devices::Properties::DEVPROP_TYPE_STRING),
/// duplicated as a portable constant so the pure parser below never needs
/// a Windows-only type for a value it only ever compares.
const DEVPROP_TYPE_STRING_VALUE: u32 = 18;

/// A fixed, legitimate Win32 error code reused (never invented) to report
/// a malformed/wrong-type property buffer through the same u32 native-
/// error channel every other reconciliation failure uses.
const ERROR_INVALID_DATA: u32 = 13;

/// A fixed, legitimate Win32 error code identifying "property does not
/// exist on this device object" (ERROR_NOT_FOUND).
const ERROR_NOT_FOUND: u32 = 1168;

/// What SetupDiGetDevicePropertyW reported for
/// DEVPKEY_Device_DriverInfPath, already reduced to the orchestrator's
/// two meaningful cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PropertyReadOutcome {
    /// The property exists and was a well-formed, bounded, NUL-terminated
    /// DEVPROP_TYPE_STRING. Only the file-name component is kept; the
    /// property is not logged or displayed verbatim.
    Present(String),
    /// Windows reports the device object has no
    /// DEVPKEY_Device_DriverInfPath value at all.
    Absent,
}

/// Pure, portable parse/validate of one SetupDiGetDevicePropertyW
/// result. Exposed under test-inject (see test_parse_property_result) so
/// DEV-R27/R28/R29 never need a real device object. native_succeeded
/// mirrors the raw BOOL return value; buf/required mirror exactly what
/// Windows wrote/reported, with NO growth loop on this side: a required
/// beyond buf.len() is a bounded failure, never a retry.
fn parse_property_result(
    native_succeeded: bool,
    last_error: u32,
    prop_type: u32,
    buf: &[u8],
    required: u32,
) -> Result<PropertyReadOutcome, u32> {
    if !native_succeeded {
        return if last_error == ERROR_NOT_FOUND {
            Ok(PropertyReadOutcome::Absent)
        } else {
            Err(last_error)
        };
    }
    if prop_type != DEVPROP_TYPE_STRING_VALUE {
        return Err(ERROR_INVALID_DATA);
    }
    let required = required as usize;
    if required == 0 || !required.is_multiple_of(2) || required > buf.len() {
        return Err(ERROR_INVALID_DATA);
    }
    let wide: Vec<u16> = buf[..required]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if wide.last() != Some(&0) {
        return Err(ERROR_INVALID_DATA);
    }
    // The value is ONE string: the first NUL must be the terminating one.
    // Anything after it is data Cove would otherwise silently discard.
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    if len == 0 || len != wide.len() - 1 {
        return Err(ERROR_INVALID_DATA);
    }
    let s = String::from_utf16_lossy(&wide[..len]);
    // Only the file-name component: Microsoft's own documented value is
    // typically a bare leaf, but a defensive leaf-extraction matches
    // PublishedInf::leaf()'s own shape rather than trusting the raw form.
    let leaf = std::path::Path::new(&s)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .filter(|f| !f.is_empty())
        .ok_or(ERROR_INVALID_DATA)?;
    Ok(PropertyReadOutcome::Present(leaf))
}

#[cfg(feature = "test-inject")]
pub fn test_parse_property_result(
    native_succeeded: bool,
    last_error: u32,
    prop_type: u32,
    buf: &[u8],
    required: u32,
) -> Result<bool, u32> {
    parse_property_result(native_succeeded, last_error, prop_type, buf, required)
        .map(|r| matches!(r, PropertyReadOutcome::Present(_)))
}

#[cfg(feature = "test-inject")]
pub const TEST_DEVPROP_TYPE_STRING_VALUE: u32 = DEVPROP_TYPE_STRING_VALUE;

// ---------------------------------------------------------------------------
// Refusal / outcome domain
// ---------------------------------------------------------------------------

/// Why installation was refused before DiInstallDevice was ever called.
/// Every variant means the Driver Store remains staged, unmodified:
/// 2a-12b1 already mutated it, and this module never reverses that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreInstallRefusal {
    /// Fail-closed: a failure to even query elevation counts as "not
    /// elevated".
    ElevationRequired,
    /// The materialized source failed re-attestation immediately before
    /// re-proving the fresh exact-device list.
    SourceInvalidated,
    /// The exact target device could not be reopened (or its reported
    /// instance ID no longer round-trips).
    ExactDeviceUnavailable,
    /// Building/enumerating the fresh normal compatible list failed
    /// natively.
    EnumerationFailed,
    /// The fresh compatible list has no node at all.
    PublishedNodeMissing,
    /// Two or more nodes tie for best in the fresh list.
    BestNodeTie,
    /// The unique best node's INF does not bind to the staged, published
    /// Cove INF.
    PublishedInfMismatch,
    /// Unique-best and INF-bound, but rank/date/version drifted since
    /// staging.
    RankingChanged,
}

/// The full mutation-aware outcome domain. Every variant past a
/// successful DiInstallDevice call carries the published INF: device
/// mutation may already be complete, and no later failure here is
/// reported as "nothing happened".
#[derive(Debug)]
pub enum InstallExecutionOutcome {
    /// Refused before DiInstallDevice; Driver Store remains staged.
    DriverStoreStagedButInstallRefused {
        published_inf: PublishedInf,
        reason: PreInstallRefusal,
    },
    /// DiInstallDevice itself failed; Windows' failure contract does not
    /// let Cove distinguish "definitely untouched" from "partially
    /// touched". No retry, no rollback.
    DriverStoreStagedButDeviceInstallFailed {
        published_inf: PublishedInf,
        native_error: u32,
    },
    /// DiInstallDevice succeeded, post-install source re-attestation
    /// passed, and the fresh DEVPKEY_Device_DriverInfPath reconciliation
    /// matches the published Cove INF.
    Installed {
        published_inf: PublishedInf,
        reboot_required: bool,
    },
    /// DiInstallDevice succeeded and reported NeedReboot, but the
    /// installed-INF property does not (yet) match or is absent -- a
    /// legitimate pending-reboot state, not a failure.
    InstalledPendingReboot { published_inf: PublishedInf },
    /// DiInstallDevice succeeded, no reboot was reported, but the
    /// installed-INF property does not match (or is absent). No retry,
    /// no force, no rollback.
    InstalledButPostconditionMismatch { published_inf: PublishedInf },
    /// DiInstallDevice succeeded but the exact-device postcondition read
    /// itself failed natively (reopen or property read). The device
    /// install is NOT reclassified as failed.
    InstalledButReconciliationFailed {
        published_inf: PublishedInf,
        reboot_required: bool,
        native_error: u32,
    },
    /// DiInstallDevice succeeded, but the materialized source failed
    /// re-attestation immediately afterward. postcondition_observed is
    /// Some(bool) only when a best-effort read-only reconciliation
    /// afterward could still determine a match; None otherwise.
    InstalledButSourceInvalidated {
        published_inf: PublishedInf,
        reboot_required: bool,
        postcondition_observed: Option<bool>,
    },
}

fn refuse(published_inf: PublishedInf, reason: PreInstallRefusal) -> InstallExecutionOutcome {
    InstallExecutionOutcome::DriverStoreStagedButInstallRefused {
        published_inf,
        reason,
    }
}

/// Why install_staged_driver could not even be attempted. Distinct from
/// InstallExecutionOutcome: every variant here is true regardless of
/// staged's own history, so it never implies anything about the Driver
/// Store's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InstallExecutionError {
    #[error("device installation needs Windows object handles")]
    PlatformUnsupported,
    /// Built with test-inject: refuses to touch real device state.
    #[error("mutation is disabled in a test-inject build")]
    MutationDisabledInTestBuild,
}

pub type InstallExecutionResult = Result<InstallExecutionOutcome, InstallExecutionError>;

// ---------------------------------------------------------------------------
// Native result shapes shared by both backends
// ---------------------------------------------------------------------------

/// What DiInstallDevice reported on success.
pub(crate) struct InstallNativeResult {
    pub(crate) reboot_required: bool,
}

// ---------------------------------------------------------------------------
// Backend seam (production Windows APIs vs. scripted test state machine)
// ---------------------------------------------------------------------------

/// The seam separating orchestration (this module's pure state machine)
/// from its native effects. WindowsNativeBackend is the only production
/// implementation; ScriptedInstallBackend (test-inject only) is a
/// deterministic fake modeling the SAME phase ordering without ever
/// calling DiInstallDevice.
///
/// Selected is the live-native-node binding capability: production binds
/// it to the exact raw SP_DRVINFO_DATA_V2_W from a still-live compatible
/// list (see win::LiveSelectedDriver); the scripted backend's Selected
/// carries no native state at all.
pub(crate) trait InstallBackend {
    type Selected;

    /// Fail-closed: query failure counts as "not elevated".
    fn is_elevated(&mut self) -> bool;

    /// Fresh exact-device reopen, fresh normal compatible list, and the
    /// complete unique-best / published-INF / candidate-unchanged proof,
    /// all in one bounded step so nothing can run between binding the
    /// winning node and installing it.
    fn select_fresh_staged_node(
        &mut self,
        instance_id: &str,
        published: &PublishedInf,
        expected_candidate: DriverSelectionSummary,
    ) -> Result<Self::Selected, PreInstallRefusal>;

    /// THE SECOND AND LAST MUTATION.
    fn install_selected(&mut self, selected: Self::Selected) -> Result<InstallNativeResult, u32>;

    /// Fresh exact-device reopen + bounded DEVPKEY_Device_DriverInfPath
    /// read.
    fn read_installed_inf(&mut self, instance_id: &str) -> Result<PropertyReadOutcome, u32>;
}

// ---------------------------------------------------------------------------
// Install ledger (auditable phase ordering; exposed under test-inject)
// ---------------------------------------------------------------------------

#[cfg(feature = "test-inject")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallEvent {
    RequireElevation,
    PreInstallReattest,
    BindFreshStagedNode,
    InstallExactNode,
    PostInstallReattest,
    ReopenExactDevice,
    ReadInstalledInf,
}

#[cfg(not(feature = "test-inject"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallEvent {
    RequireElevation,
    PreInstallReattest,
    BindFreshStagedNode,
    InstallExactNode,
    PostInstallReattest,
    ReopenExactDevice,
    ReadInstalledInf,
}

// ---------------------------------------------------------------------------
// Orchestrator (pure state machine over the InstallBackend seam)
// ---------------------------------------------------------------------------

/// Best-effort, read-only postcondition observation: None whenever the
/// property is absent OR the reconciliation read itself failed (the
/// Result::Err path is still surfaced to callers who need to
/// distinguish a hard reconciliation failure from "could not
/// determine").
fn observe_postcondition<B: InstallBackend>(
    backend: &mut B,
    instance_id: &str,
    published: &PublishedInf,
    ledger: &mut Vec<InstallEvent>,
) -> Result<Option<bool>, u32> {
    ledger.push(InstallEvent::ReopenExactDevice);
    ledger.push(InstallEvent::ReadInstalledInf);
    match backend.read_installed_inf(instance_id)? {
        PropertyReadOutcome::Absent => Ok(None),
        PropertyReadOutcome::Present(leaf) => Ok(Some(leaf.eq_ignore_ascii_case(published.leaf()))),
    }
}

fn run_install<'a, 'v, B: InstallBackend>(
    staged: StagedDriverInstall<'a, 'v>,
    backend: &mut B,
    ledger: &mut Vec<InstallEvent>,
) -> InstallExecutionOutcome {
    let published = staged.published_inf().clone();
    let prepared = staged.prepared();
    let instance_id = prepared.target_device_instance_id().to_string();
    let expected_candidate = prepared.candidate();
    let source = prepared.source();

    ledger.push(InstallEvent::RequireElevation);
    if !backend.is_elevated() {
        return refuse(published, PreInstallRefusal::ElevationRequired);
    }

    ledger.push(InstallEvent::PreInstallReattest);
    if source.reattest().is_err() {
        return refuse(published, PreInstallRefusal::SourceInvalidated);
    }

    // ---- bind/install adjacency: nothing else may run between these
    // two ledger events. ----
    ledger.push(InstallEvent::BindFreshStagedNode);
    let selected =
        match backend.select_fresh_staged_node(&instance_id, &published, expected_candidate) {
            Err(reason) => return refuse(published, reason),
            Ok(s) => s,
        };

    ledger.push(InstallEvent::InstallExactNode);
    let install_result = match backend.install_selected(selected) {
        Err(native_error) => {
            return InstallExecutionOutcome::DriverStoreStagedButDeviceInstallFailed {
                published_inf: published,
                native_error,
            };
        }
        Ok(r) => r,
    };
    let reboot_required = install_result.reboot_required;

    // ---- past this point, device mutation has occurred. ----

    ledger.push(InstallEvent::PostInstallReattest);
    if source.reattest().is_err() {
        let postcondition_observed =
            observe_postcondition(backend, &instance_id, &published, ledger)
                .ok()
                .flatten();
        return InstallExecutionOutcome::InstalledButSourceInvalidated {
            published_inf: published,
            reboot_required,
            postcondition_observed,
        };
    }

    match observe_postcondition(backend, &instance_id, &published, ledger) {
        Err(native_error) => InstallExecutionOutcome::InstalledButReconciliationFailed {
            published_inf: published,
            reboot_required,
            native_error,
        },
        Ok(Some(true)) => InstallExecutionOutcome::Installed {
            published_inf: published,
            reboot_required,
        },
        Ok(Some(false)) | Ok(None) => {
            if reboot_required {
                InstallExecutionOutcome::InstalledPendingReboot {
                    published_inf: published,
                }
            } else {
                InstallExecutionOutcome::InstalledButPostconditionMismatch {
                    published_inf: published,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Production entry point
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
pub fn install_staged_driver<'a, 'v>(
    _staged: StagedDriverInstall<'a, 'v>,
) -> InstallExecutionResult {
    Err(InstallExecutionError::PlatformUnsupported)
}

/// The test-inject build's public entry point NEVER routes to the real
/// Windows backend, even though that backend is fully compiled below.
/// Changing this function to call WindowsNativeBackend is exactly the
/// mutant this gate exists to kill.
#[cfg(all(windows, feature = "test-inject"))]
pub fn install_staged_driver<'a, 'v>(
    _staged: StagedDriverInstall<'a, 'v>,
) -> InstallExecutionResult {
    Err(InstallExecutionError::MutationDisabledInTestBuild)
}

/// DEV-R2 - `staged` is consumed by value; there is no way to install it
/// twice. Compiler RED: fails only because `staged` was already moved into
/// the first call.
///
/// ```compile_fail
/// # #[cfg(windows)]
/// fn use_twice<'a, 'v>(
///     staged: mod_drivers::sdio::install_staging::StagedDriverInstall<'a, 'v>,
/// ) {
///     let _ = mod_drivers::sdio::install_device::install_staged_driver(staged);
///     let _ = mod_drivers::sdio::install_device::install_staged_driver(staged);
/// }
/// ```
#[cfg(all(windows, not(feature = "test-inject")))]
pub fn install_staged_driver<'a, 'v>(
    staged: StagedDriverInstall<'a, 'v>,
) -> InstallExecutionResult {
    let mut backend = win::WindowsNativeBackend;
    let mut ledger = Vec::new();
    Ok(run_install(staged, &mut backend, &mut ledger))
}

// ---------------------------------------------------------------------------
// Test-only seam: drive the SAME orchestrator through a scripted backend
// ---------------------------------------------------------------------------

#[cfg(feature = "test-inject")]
pub use test_seam::{
    InstallScript, ReadInstalledInfScript, ScriptedInstallBackend, ScriptedSelected, SelectScript,
    test_install_with_scripted_backend,
};

#[cfg(feature = "test-inject")]
mod test_seam {
    use super::*;

    /// The scripted backend's Selected token: carries no native state at
    /// all, unlike production's LiveSelectedDriver.
    pub struct ScriptedSelected;

    /// What select_fresh_staged_node should report.
    pub enum SelectScript {
        Ok,
        Refuse(PreInstallRefusal),
    }

    /// What install_selected should report.
    pub enum InstallScript {
        Ok { reboot_required: bool },
        Err(u32),
    }

    /// What read_installed_inf should report.
    pub enum ReadInstalledInfScript {
        Present(String),
        Absent,
        Err(u32),
    }

    /// A fully deterministic, in-memory InstallBackend. Every field is
    /// scripted explicitly by the test; there is no implicit "jump
    /// straight to Installed".
    pub struct ScriptedInstallBackend {
        pub elevated: bool,
        pub select: Option<SelectScript>,
        pub install: Option<InstallScript>,
        pub read_installed_inf: Option<ReadInstalledInfScript>,
    }

    impl ScriptedInstallBackend {
        pub fn new() -> Self {
            Self {
                elevated: true,
                select: None,
                install: None,
                read_installed_inf: None,
            }
        }
    }

    impl Default for ScriptedInstallBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl InstallBackend for ScriptedInstallBackend {
        type Selected = ScriptedSelected;

        fn is_elevated(&mut self) -> bool {
            self.elevated
        }

        fn select_fresh_staged_node(
            &mut self,
            _instance_id: &str,
            _published: &PublishedInf,
            _expected_candidate: DriverSelectionSummary,
        ) -> Result<ScriptedSelected, PreInstallRefusal> {
            match self.select.take().expect("test must script select") {
                SelectScript::Ok => Ok(ScriptedSelected),
                SelectScript::Refuse(reason) => Err(reason),
            }
        }

        fn install_selected(
            &mut self,
            _selected: ScriptedSelected,
        ) -> Result<InstallNativeResult, u32> {
            match self.install.take().expect("test must script install") {
                InstallScript::Ok { reboot_required } => {
                    Ok(InstallNativeResult { reboot_required })
                }
                InstallScript::Err(code) => Err(code),
            }
        }

        fn read_installed_inf(&mut self, _instance_id: &str) -> Result<PropertyReadOutcome, u32> {
            match self
                .read_installed_inf
                .take()
                .expect("test must script read_installed_inf")
            {
                ReadInstalledInfScript::Present(s) => Ok(PropertyReadOutcome::Present(s)),
                ReadInstalledInfScript::Absent => Ok(PropertyReadOutcome::Absent),
                ReadInstalledInfScript::Err(code) => Err(code),
            }
        }
    }

    /// Drive the SAME orchestrator (run_install) the production entry
    /// point uses, through a caller-supplied ScriptedInstallBackend.
    /// Consumes staged by value: there is no reusable install token.
    pub fn test_install_with_scripted_backend<'a, 'v>(
        staged: StagedDriverInstall<'a, 'v>,
        backend: &mut ScriptedInstallBackend,
    ) -> (InstallExecutionOutcome, Vec<InstallEvent>) {
        let mut ledger = Vec::new();
        let outcome = run_install(staged, backend, &mut ledger);
        (outcome, ledger)
    }
}

// ---------------------------------------------------------------------------
// Production Windows backend
// ---------------------------------------------------------------------------

// Under test-inject, install_staged_driver never reaches this backend
// (lockout by design); it still compiles and links on every Windows
// build.
#[cfg_attr(feature = "test-inject", allow(dead_code))]
#[cfg(windows)]
mod win {
    //! The real native surface: elevation re-check (reused from 12b1),
    //! fresh exact-device compatible-list rebinding (reused from 12a),
    //! the single DiInstallDevice call, and the fresh postcondition read
    //! of DEVPKEY_Device_DriverInfPath. No Driver Store staging/rollback
    //! API and no reboot API live here.

    use super::*;

    use windows_sys::Win32::Devices::DeviceAndDriverInstallation as sa;
    use windows_sys::Win32::Devices::Properties as props;
    use windows_sys::Win32::Foundation::BOOL;

    use crate::sdio::install_preparation::{self, win as prep_win};
    use crate::sdio::install_staging::win as stage_win;

    fn last_error() -> u32 {
        prep_win::last_error()
    }

    /// The live-native-node binding capability: owns the exact driver
    /// list, device-information set and raw selected node together, so
    /// Drop order (list, then device set) always destroys the compatible
    /// list before the device set it was built against, and the raw
    /// SP_DRVINFO_DATA_V2_W passed to DiInstallDevice is guaranteed to
    /// come from a list that is still alive at the point of that call.
    pub(crate) struct LiveSelectedDriver {
        // Held only for its Drop side effect (destroying the compatible
        // list before `device_set`); never read directly. The raw
        // `selected` node captured from it is what DiInstallDevice
        // actually uses.
        _driver_list: prep_win::DriverInfoList,
        device_set: prep_win::DeviceInfoSet,
        devinfo: sa::SP_DEVINFO_DATA,
        selected: sa::SP_DRVINFO_DATA_V2_W,
    }

    pub(crate) struct WindowsNativeBackend;

    impl InstallBackend for WindowsNativeBackend {
        type Selected = LiveSelectedDriver;

        fn is_elevated(&mut self) -> bool {
            stage_win::is_elevated_native()
        }

        fn select_fresh_staged_node(
            &mut self,
            instance_id: &str,
            published: &PublishedInf,
            expected_candidate: DriverSelectionSummary,
        ) -> Result<LiveSelectedDriver, PreInstallRefusal> {
            let (device_set, devinfo) = prep_win::open_exact_device(instance_id)
                .map_err(|_| PreInstallRefusal::ExactDeviceUnavailable)?;
            prep_win::configure_current_store_search(device_set.handle(), &devinfo)
                .map_err(|_| PreInstallRefusal::EnumerationFailed)?;
            let (driver_list, nodes) =
                prep_win::enumerate_compat_driver_nodes_live(device_set.handle(), &devinfo)
                    .map_err(|_| PreInstallRefusal::EnumerationFailed)?;

            let summaries: Vec<DriverSelectionSummary> = nodes.iter().map(|(s, _, _)| *s).collect();
            let winner_index = match install_preparation::select_unique_best(&summaries) {
                install_preparation::BestSelection::NotCompatible => {
                    return Err(PreInstallRefusal::PublishedNodeMissing);
                }
                install_preparation::BestSelection::Ambiguous => {
                    return Err(PreInstallRefusal::BestNodeTie);
                }
                install_preparation::BestSelection::Unique(i) => i,
            };
            let (summary, inf_path, raw) = &nodes[winner_index];

            let expected = published.normalized_full_path();
            if !install_preparation::setupapi_inf_paths_match(expected, inf_path).unwrap_or(false) {
                return Err(PreInstallRefusal::PublishedInfMismatch);
            }
            if *summary != expected_candidate {
                return Err(PreInstallRefusal::RankingChanged);
            }

            Ok(LiveSelectedDriver {
                _driver_list: driver_list,
                device_set,
                devinfo,
                selected: *raw,
            })
        }

        fn install_selected(
            &mut self,
            selected: LiveSelectedDriver,
        ) -> Result<InstallNativeResult, u32> {
            // Preserve existing device-install params; OR in ONLY the
            // documented silent-install bit. No other semantic flag is
            // injected, and DriverPath/Flags (DI_ENUMSINGLEINF etc.) from
            // any prior single-INF search are never read here at all --
            // this device-information set was opened fresh, specifically
            // for this call, and never configured for a single-INF
            // search.
            let mut params: sa::SP_DEVINSTALL_PARAMS_W = unsafe { std::mem::zeroed() };
            params.cbSize = std::mem::size_of::<sa::SP_DEVINSTALL_PARAMS_W>() as u32;
            // SAFETY: live handle/element; struct sized per contract.
            let ok = unsafe {
                sa::SetupDiGetDeviceInstallParamsW(
                    selected.device_set.handle(),
                    &selected.devinfo,
                    &mut params,
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            params.Flags |= sa::DI_QUIETINSTALL;
            // SAFETY: as above.
            let ok = unsafe {
                sa::SetupDiSetDeviceInstallParamsW(
                    selected.device_set.handle(),
                    &selected.devinfo,
                    &params,
                )
            };
            if ok == 0 {
                return Err(last_error());
            }

            let mut need_reboot: BOOL = 0;
            // SAFETY: hwndParent NULL (no UI owner); deviceinfoset/
            // devicedata/driverinfodata all come from the still-live
            // selected guard; Flags = 0 (no force/null-driver/search-UI
            // bit); needreboot is a valid non-NULL out pointer.
            let ok = unsafe {
                sa::DiInstallDevice(
                    std::ptr::null_mut(),
                    selected.device_set.handle(),
                    &selected.devinfo,
                    &selected.selected,
                    0,
                    &mut need_reboot,
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            Ok(InstallNativeResult {
                reboot_required: need_reboot != 0,
            })
        }

        fn read_installed_inf(&mut self, instance_id: &str) -> Result<PropertyReadOutcome, u32> {
            let (device_set, devinfo) =
                prep_win::open_exact_device(instance_id).map_err(|e| native_error_code(&e))?;
            let mut buf = vec![0u8; MAX_INSTALLED_INF_PROPERTY_BYTES];
            let mut prop_type: props::DEVPROPTYPE = 0;
            let mut required = 0u32;
            // SAFETY: live handle/element; buffer length passed exactly;
            // flags = 0 (no documented flag this slice needs).
            let ok = unsafe {
                sa::SetupDiGetDevicePropertyW(
                    device_set.handle(),
                    &devinfo,
                    &props::DEVPKEY_Device_DriverInfPath,
                    &mut prop_type,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut required,
                    0,
                )
            };
            let code = if ok == 0 { last_error() } else { 0 };
            parse_property_result(ok != 0, code, prop_type, &buf, required)
        }
    }

    fn native_error_code(e: &install_preparation::InstallPreparationError) -> u32 {
        match e {
            install_preparation::InstallPreparationError::NativeCall { code, .. } => *code,
            _ => u32::MAX,
        }
    }
}
