//! Actual-INF source manifest (Tab 2a-9, Option C).
//!
//! Interprets the exact, live-verified INF through bounded, read-only Windows
//! SetupAPI semantics and lists the driver-package SOURCE files it names.
//!
//! # What "resolved" means
//!
//! [`SourceManifest::ResolvedReferences`] means ONLY that every source reference
//! inside the scope below was resolved. It does NOT mean the package is
//! complete, that any payload exists, was extracted or is trusted, that the
//! Driver Store would accept it, or that installation is authorized.
//!
//! # Supported scope (v1)
//!
//! - `CopyFiles` (`@file` and named file-list sections) in the actual,
//!   platform-decorated install section and in `<actual>.CoInstallers`.
//! - Everything else file-bearing is `Unsupported`, never omitted: `Include`,
//!   `Needs`, `CopyINF`, `.Software`/`.Components`/`.Interfaces`, class and
//!   interface install sections, platform-decorated file lists, cabinet or
//!   tag-file media, and missing or ambiguous `SourceDisksFiles` definitions.
//!
//! # Token binding
//!
//! Derivation borrows the live [`VerifiedDriverPackage`], reads the INF only
//! through its stable verified path, re-attests before native interpretation and
//! again before returning, and the evidence borrows the token.
//!
//! The INF is read by pathname under the same lease `SetupVerifyInfFileW`
//! relied on, so the trust model is identical to the verification itself: while
//! the token lives the lease withholds write sharing, and a writable view taken
//! before the lease denies the lease outright (test `r62` in `sdio_signature`),
//! so no writable view can coexist with a live token. The pre/post digest
//! re-attestation is defense in depth, not the primary control. Evidence cannot
//! outlive the trust lease that justified it:
//!
//! ```compile_fail
//! use mod_drivers::sdio::source_manifest::ResolvedSourceReferences;
//! fn escape<'a>(r: ResolvedSourceReferences<'a>) -> ResolvedSourceReferences<'static> { r }
//! ```
//!
//! The companion positive case compiles, so the failure above is the lifetime:
//!
//! ```
//! use mod_drivers::sdio::source_manifest::ResolvedSourceReferences;
//! fn keep<'a>(r: ResolvedSourceReferences<'a>) -> ResolvedSourceReferences<'a> { r }
//! ```
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::sdio::local_pack::{
    MAX_ARCHIVE_COMPONENT_LEN, MAX_ARCHIVE_MEMBER_COMPONENTS, MAX_ARCHIVE_MEMBER_LEN,
};
use crate::sdio::signature::{TrustError, VerifiedDriverPackage};

// Bounds. Sections/lines count every scan; references include duplicates.
pub const MAX_SECTIONS_INSPECTED: usize = 64;
pub const MAX_LINES_INSPECTED: usize = 8192;
pub const MAX_FIELDS_PER_LINE: usize = 16;
pub const MAX_COPYFILES_REFERENCES: usize = 2048;
pub const MAX_UNIQUE_SOURCE_FILES: usize = 1024;
pub const MAX_PROVENANCE_ENTRIES: usize = 2048;
pub const MAX_RETAINED_STRING_BYTES: usize = 512 * 1024;
/// UTF-16 units (terminator included) accepted from one native string.
pub const MAX_NATIVE_STRING_UNITS: usize = 4096;
/// Retries after the first native string call (one, sized from RequiredSize).
pub const MAX_NATIVE_RETRIES: usize = 1;
// Path bounds match the archive-member bounds the later phase must satisfy.
const MAX_PATH_COMPONENTS: usize = MAX_ARCHIVE_MEMBER_COMPONENTS;
const MAX_COMPONENT_LEN: usize = MAX_ARCHIVE_COMPONENT_LEN;
const MAX_PATH_LEN: usize = MAX_ARCHIVE_MEMBER_LEN;
const MAX_SECTION_NAME_UNITS: usize = 255;
const INITIAL_NATIVE_UNITS: usize = 260;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_LINE_NOT_FOUND: u32 = 0xE000_0102;
const ERROR_SECTION_NOT_FOUND: u32 = 0xE000_0101;

/// Which bound a derivation ran into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundKind {
    Sections,
    Lines,
    FieldsPerLine,
    CopyFilesReferences,
    UniqueSourceFiles,
    ProvenanceEntries,
    RetainedStringBytes,
    NativeStringUnits,
    NativeRetries,
    PathComponents,
    ComponentLength,
    SourcePathLength,
}

/// Why a derivation failed outright; no manifest evidence was produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceManifestError {
    /// Pre- or post-derivation re-attestation of the live token failed.
    #[error("verified package attestation failed: {0}")]
    Attestation(TrustError),
    #[error("invalid install section name")]
    InvalidInstallSectionName,
    #[error("native INF open failed (code {code:#x})")]
    NativeOpen { code: u32 },
    #[error("native call {api} failed (code {code:#x})")]
    NativeCall { api: &'static str, code: u32 },
    #[error("native string was not valid UTF-16")]
    NativeStringInvalid,
    #[error("bound exceeded: {0:?}")]
    Bound(BoundKind),
    #[error("source manifest derivation requires Windows")]
    PlatformUnsupported,
}

/// Why the INF is outside the supported scope. Never success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedReason {
    InstallSectionMissing,
    IncludeNeeds,
    CopyInf,
    /// A file-bearing relationship outside the v1 traversal exists.
    UnsupportedSubsection(&'static str),
    MissingCopySection,
    /// A file-list section also exists in a platform-decorated form.
    DecoratedFileListSection,
    /// A file-list line whose key differs from its first field. SetupAPI
    /// reports a keyless line by repeating its first field as the key, so
    /// `a.sys = a.sys` is indistinguishable from `a.sys` through SetupAPI, and
    /// SetupAPI copies both identically (it reads only fields 1 and up).
    KeyedFileListLine,
    MalformedFileListLine,
    /// A file name is not one safe path component.
    UnsafeFileName,
    MissingSourceDefinition,
    /// Several definitions, or one SetupAPI resolved differently.
    AmbiguousSourceDefinition,
    /// Cabinet, tag-file or flagged source media.
    ExternalMedia,
    /// UNC, drive-qualified, device, traversing or otherwise unsafe path.
    UnsafeSourceMediaPath,
}

/// Why a source path could not be normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathReject {
    Unsafe,
    Bound(BoundKind),
}

/// One place a source was named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceProvenance {
    /// The install section for `@file`, the file-list section otherwise.
    pub section: String,
    /// `true` for `CopyFiles=@file`.
    pub direct: bool,
    /// The destination file name the INF copies this source to.
    pub destination_name: String,
}

/// One resolved source: a package-relative source member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReference {
    source_path: String,
    disk_id: u32,
    provenance: Vec<SourceProvenance>,
}

impl SourceReference {
    /// Normalized `/`-separated path relative to the INF's directory.
    pub fn source_path(&self) -> &str {
        &self.source_path
    }
    /// The `SourceDisksNames` disk id the file is defined on.
    pub fn disk_id(&self) -> u32 {
        self.disk_id
    }
    /// Every place it was named, in discovery order.
    pub fn provenance(&self) -> &[SourceProvenance] {
        &self.provenance
    }
}

/// Resolved sources (unique, in INF discovery order), bound to the live token.
#[derive(Debug)]
pub struct ResolvedSourceReferences<'v> {
    verified: &'v VerifiedDriverPackage,
    references: Vec<SourceReference>,
}

impl<'v> ResolvedSourceReferences<'v> {
    pub fn references(&self) -> &[SourceReference] {
        &self.references
    }
    pub fn verified_package(&self) -> &'v VerifiedDriverPackage {
        self.verified
    }
}

/// The outcome of interpreting the verified INF.
#[derive(Debug)]
pub enum SourceManifest<'v> {
    ResolvedReferences(ResolvedSourceReferences<'v>),
    /// The v1 scope names no CopyFiles source. NOT an empty complete package.
    NoCopyFiles(&'v VerifiedDriverPackage),
    Unsupported(UnsupportedReason),
    Error(SourceManifestError),
}

/// Internal early exit: an unsupported construct or a hard error.
enum Stop {
    Unsupported(UnsupportedReason),
    Error(SourceManifestError),
}

impl From<UnsupportedReason> for Stop {
    fn from(r: UnsupportedReason) -> Self {
        Stop::Unsupported(r)
    }
}

impl From<SourceManifestError> for Stop {
    fn from(e: SourceManifestError) -> Self {
        Stop::Error(e)
    }
}

impl From<PathReject> for Stop {
    fn from(p: PathReject) -> Self {
        match p {
            PathReject::Unsafe => UnsupportedReason::UnsafeSourceMediaPath.into(),
            PathReject::Bound(k) => SourceManifestError::Bound(k).into(),
        }
    }
}

type Step<T> = Result<T, Stop>;

/// Derive the source manifest of the live verified package's actual INF.
///
/// `install_section` is the INF install (DDInstall) section named by the
/// catalog candidate; SetupAPI resolves its platform decoration.
pub fn derive_source_manifest<'v>(
    verified: &'v VerifiedDriverPackage,
    install_section: &str,
) -> SourceManifest<'v> {
    derive_with(
        verified,
        install_section,
        &mut || verified.reattest(),
        &mut || verified.reattest(),
    )
}

fn derive_with<'v>(
    verified: &'v VerifiedDriverPackage,
    install_section: &str,
    pre: &mut dyn FnMut() -> Result<(), TrustError>,
    post: &mut dyn FnMut() -> Result<(), TrustError>,
) -> SourceManifest<'v> {
    if !valid_section_name(install_section) {
        return SourceManifest::Error(SourceManifestError::InvalidInstallSectionName);
    }
    if let Err(e) = pre() {
        return SourceManifest::Error(SourceManifestError::Attestation(e));
    }
    // The native handle lives and dies inside `interpret`, and the token is
    // borrowed throughout, so the lease cannot end underneath it.
    let outcome = interpret(verified.inf_path(), install_section);
    // The post-attestation outranks every outcome, Unsupported included: a
    // token whose bytes moved during interpretation vouches for nothing.
    if let Err(e) = post() {
        return SourceManifest::Error(SourceManifestError::Attestation(e));
    }
    match outcome {
        Ok(refs) if refs.is_empty() => SourceManifest::NoCopyFiles(verified),
        Ok(references) => SourceManifest::ResolvedReferences(ResolvedSourceReferences {
            verified,
            references,
        }),
        Err(Stop::Unsupported(r)) => SourceManifest::Unsupported(r),
        Err(Stop::Error(e)) => SourceManifest::Error(e),
    }
}

fn valid_section_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('\0')
        && name.encode_utf16().count() <= MAX_SECTION_NAME_UNITS
}

// ---------------------------------------------------------------------------
// Bounded accounting and native strings (pure, directly testable)
// ---------------------------------------------------------------------------

/// Checked, capped increment. Never wraps; the cap is inclusive.
fn charge(
    current: usize,
    add: usize,
    cap: usize,
    kind: BoundKind,
) -> Result<usize, SourceManifestError> {
    match current.checked_add(add) {
        Some(total) if total <= cap => Ok(total),
        _ => Err(SourceManifestError::Bound(kind)),
    }
}

fn bump(
    counter: &mut usize,
    add: usize,
    cap: usize,
    kind: BoundKind,
) -> Result<(), SourceManifestError> {
    *counter = charge(*counter, add, cap, kind)?;
    Ok(())
}

#[derive(Default)]
struct Budget {
    seen_sections: HashSet<String>,
    lines: usize,
    references: usize,
    unique: usize,
    provenance: usize,
    string_bytes: usize,
}

impl Budget {
    fn section(&mut self, name: &str) -> Result<(), SourceManifestError> {
        if self.seen_sections.insert(name.to_ascii_lowercase()) {
            charge(
                self.seen_sections.len() - 1,
                1,
                MAX_SECTIONS_INSPECTED,
                BoundKind::Sections,
            )?;
        }
        Ok(())
    }
    fn line(&mut self) -> Result<(), SourceManifestError> {
        bump(&mut self.lines, 1, MAX_LINES_INSPECTED, BoundKind::Lines)
    }
    fn strings(&mut self, bytes: usize) -> Result<(), SourceManifestError> {
        bump(
            &mut self.string_bytes,
            bytes,
            MAX_RETAINED_STRING_BYTES,
            BoundKind::RetainedStringBytes,
        )
    }
}

/// A native string filler: fills the buffer, reports `(ok, required, error)`.
type NativeFill<'a> = &'a mut dyn FnMut(&mut [u16]) -> (bool, u32, u32);

/// Fetch one native UTF-16 string under a hard size cap.
///
/// `call` fills the offered buffer and reports `(ok, required_units, error)`.
/// `required_units` is validated against `max_units` BEFORE any buffer of that
/// size is allocated, so a native-reported length never drives allocation, and
/// at most [`MAX_NATIVE_RETRIES`] retries follow the first call.
fn bounded_native_string(
    api: &'static str,
    max_units: usize,
    call: NativeFill<'_>,
) -> Result<String, SourceManifestError> {
    let mut buf = vec![0u16; INITIAL_NATIVE_UNITS.min(max_units)];
    let mut attempts = 0;
    loop {
        let (ok, required, error) = call(&mut buf);
        let required = usize::try_from(required).unwrap_or(usize::MAX);
        if ok {
            if required == 0 || required > buf.len() {
                return Err(SourceManifestError::NativeCall { api, code: 0 });
            }
            return String::from_utf16(&buf[..required - 1])
                .ok()
                .filter(|s| !s.contains('\0'))
                .ok_or(SourceManifestError::NativeStringInvalid);
        }
        if error != ERROR_INSUFFICIENT_BUFFER || required == 0 {
            return Err(SourceManifestError::NativeCall { api, code: error });
        }
        if required > max_units {
            return Err(SourceManifestError::Bound(BoundKind::NativeStringUnits));
        }
        if attempts == MAX_NATIVE_RETRIES {
            return Err(SourceManifestError::Bound(BoundKind::NativeRetries));
        }
        attempts += 1;
        buf = vec![0u16; required];
    }
}

// ---------------------------------------------------------------------------
// INF media-path semantics -> safe package-relative path
// ---------------------------------------------------------------------------

/// One safe component: ASCII, no separators/ADS/wildcards/controls, no trailing
/// dot or space, not a reserved DOS device name.
fn valid_component(c: &str) -> Result<(), PathReject> {
    if c.is_empty() || c == "." || c == ".." || !c.is_ascii() {
        return Err(PathReject::Unsafe);
    }
    if c.len() > MAX_COMPONENT_LEN {
        return Err(PathReject::Bound(BoundKind::ComponentLength));
    }
    if c.bytes().any(|b| b < 0x20 || b"<>:\"/\\|?*".contains(&b)) || c.ends_with(['.', ' ']) {
        return Err(PathReject::Unsafe);
    }
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = c.split('.').next().unwrap_or(c);
    if RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r)) {
        return Err(PathReject::Unsafe);
    }
    Ok(())
}

/// Split one INF media or sub directory into components.
///
/// `root_relative` allows the documented source-root-relative form: exactly ONE
/// leading `\` (`\x64` is relative to the media root, i.e. the INF directory).
/// A second leading separator is UNC/device syntax. Nothing is blindly trimmed:
/// only that one form is interpreted and every remaining component must still
/// be safe.
fn split_dir(dir: &str, root_relative: bool) -> Result<Vec<&str>, PathReject> {
    if dir.starts_with("\\\\") {
        return Err(PathReject::Unsafe);
    }
    let dir = match dir.strip_prefix('\\') {
        Some(rest) if root_relative => rest,
        Some(_) => return Err(PathReject::Unsafe),
        None => dir,
    };
    let dir = dir.strip_suffix('\\').unwrap_or(dir);
    Ok(if dir.is_empty() {
        Vec::new()
    } else {
        dir.split('\\').collect()
    })
}

/// Compose `media path + subdirectory + file` under INF semantics, exactly
/// once, into a normalized `/`-separated path relative to the INF directory.
fn normalize_source_path(media: &str, subdir: &str, file: &str) -> Result<String, PathReject> {
    let mut parts = split_dir(media, true)?;
    parts.extend(split_dir(subdir, false)?);
    parts.push(file);
    if parts.len() > MAX_PATH_COMPONENTS {
        return Err(PathReject::Bound(BoundKind::PathComponents));
    }
    parts.iter().try_for_each(|p| valid_component(p))?;
    let joined = parts.join("/");
    if joined.len() > MAX_PATH_LEN {
        return Err(PathReject::Bound(BoundKind::SourcePathLength));
    }
    Ok(joined)
}

/// A CopyFiles file name: exactly one safe component.
fn file_name(name: &str) -> Step<&str> {
    valid_component(name).map_err(|r| match r {
        PathReject::Unsafe => Stop::from(UnsupportedReason::UnsafeFileName),
        PathReject::Bound(k) => SourceManifestError::Bound(k).into(),
    })?;
    Ok(name)
}

// ---------------------------------------------------------------------------
// Interpretation
// ---------------------------------------------------------------------------

/// The decoration SetupAPI applies to `SourceDisksFiles` on this platform.
const ARCH_SUFFIX: &str = if cfg!(target_arch = "x86_64") {
    "amd64"
} else if cfg!(target_arch = "x86") {
    "x86"
} else {
    "arm64"
};
/// File-bearing subsections of the actual install section not traversed in v1;
/// their mere presence makes the result unsupported.
const UNSUPPORTED_SUBSECTIONS: &[&str] = &["Software", "Components", "Interfaces"];
const UNSUPPORTED_TOP_LEVEL: &[&str] = &["InterfaceInstall32", "ClassInstall32"];

#[cfg(not(windows))]
fn interpret(_inf_path: &Path, _install_section: &str) -> Step<Vec<SourceReference>> {
    Err(SourceManifestError::PlatformUnsupported.into())
}

#[cfg(windows)]
use win::interpret;

#[cfg(feature = "test-inject")]
static OPEN_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "test-inject")]
static OPEN_HANDLES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(windows)]
mod win {
    //! The complete native surface: open, close and read-only queries. No file
    //! queue, copy, commit, install, registry or device API is referenced.

    use super::*;
    use std::collections::hash_map::Entry;
    use std::ffi::{OsStr, c_void};
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    #[cfg(feature = "test-inject")]
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation as sa;
    use windows_sys::Win32::Foundation::GetLastError;

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(once(0)).collect()
    }

    fn last_error() -> u32 {
        // SAFETY: plain thread-local error read.
        unsafe { GetLastError() }
    }

    /// An open INF, closed exactly once on every path by `Drop`.
    struct Hinf(*mut c_void);

    impl Hinf {
        fn open(path: &Path) -> Result<Self, SourceManifestError> {
            let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
            #[cfg(feature = "test-inject")]
            OPEN_CALLS.fetch_add(1, Ordering::SeqCst);
            let mut error_line = 0u32;
            // SAFETY: NUL-terminated path; a null class accepts any INF class.
            let h = unsafe {
                sa::SetupOpenInfFileW(
                    wide_path.as_ptr(),
                    null(),
                    sa::INF_STYLE_WIN4,
                    &mut error_line,
                )
            };
            if h.is_null() || h as isize == -1 {
                return Err(SourceManifestError::NativeOpen { code: last_error() });
            }
            #[cfg(feature = "test-inject")]
            OPEN_HANDLES.fetch_add(1, Ordering::SeqCst);
            Ok(Hinf(h))
        }

        /// Whether the section exists (an empty section still exists).
        fn has(&self, section: &str) -> bool {
            let w = wide(section);
            // SAFETY: live handle, NUL-terminated name.
            unsafe { sa::SetupGetLineCountW(self.0, w.as_ptr()) >= 0 }
        }

        /// One native string via the capped RequiredSize protocol.
        fn string(
            api: &'static str,
            mut f: impl FnMut(*mut u16, u32, *mut u32) -> i32,
        ) -> Result<String, SourceManifestError> {
            bounded_native_string(api, MAX_NATIVE_STRING_UNITS, &mut |buf| {
                let mut required = 0u32;
                let ok = f(buf.as_mut_ptr(), buf.len() as u32, &mut required);
                (ok != 0, required, if ok != 0 { 0 } else { last_error() })
            })
        }

        /// SetupAPI's platform-decorated form of an install section name.
        fn actual_section(&self, name: &str) -> Result<String, SourceManifestError> {
            let w = wide(name);
            Self::string("SetupDiGetActualSectionToInstallW", |p, n, r| {
                // SAFETY: live handle; the buffer length is passed exactly.
                unsafe {
                    sa::SetupDiGetActualSectionToInstallW(self.0, w.as_ptr(), p, n, r, null_mut())
                }
            })
        }

        /// Every line of `section` (only those keyed `key` when given), each
        /// charged to the line budget. Contexts are plain values valid while
        /// this handle is open.
        fn lines(
            &self,
            section: &str,
            key: Option<&str>,
            budget: &mut Budget,
        ) -> Step<Vec<sa::INFCONTEXT>> {
            let (section_w, key_w) = (wide(section), key.map(wide));
            let key_p = key_w.as_ref().map_or(null(), |k| k.as_ptr());
            let mut out = Vec::new();
            // SAFETY: INFCONTEXT is plain data; zeroed is a valid empty value.
            let mut ctx: sa::INFCONTEXT = unsafe { std::mem::zeroed() };
            // SAFETY: live handle, NUL-terminated strings, valid out pointer.
            let mut more =
                unsafe { sa::SetupFindFirstLineW(self.0, section_w.as_ptr(), key_p, &mut ctx) };
            while more != 0 {
                budget.line()?;
                out.push(ctx);
                // SAFETY: as above.
                let mut next: sa::INFCONTEXT = unsafe { std::mem::zeroed() };
                // SAFETY: `ctx` came from a successful find on this handle.
                more = unsafe {
                    match &key_w {
                        Some(k) => sa::SetupFindNextMatchLineW(&ctx, k.as_ptr(), &mut next),
                        None => sa::SetupFindNextLine(&ctx, &mut next),
                    }
                };
                ctx = next;
            }
            match last_error() {
                ERROR_LINE_NOT_FOUND | ERROR_SECTION_NOT_FOUND => Ok(out),
                code => Err(SourceManifestError::NativeCall {
                    api: "SetupFindLine",
                    code,
                }
                .into()),
            }
        }

        fn field_count(ctx: &sa::INFCONTEXT) -> usize {
            // SAFETY: `ctx` is a context from an open handle.
            unsafe { sa::SetupGetFieldCount(ctx) as usize }
        }

        /// Field `index` (0 is the key); `None` when the line has no such field.
        fn field(
            ctx: &sa::INFCONTEXT,
            index: usize,
        ) -> Result<Option<String>, SourceManifestError> {
            if index > Self::field_count(ctx) {
                return Ok(None);
            }
            match Self::string("SetupGetStringFieldW", |p, n, r| {
                // SAFETY: `ctx` is valid; the buffer length is passed exactly.
                unsafe { sa::SetupGetStringFieldW(ctx, index as u32, p, n, r) }
            }) {
                // SetupAPI reports a keyless line's field 0 as invalid.
                Err(SourceManifestError::NativeCall {
                    code: ERROR_INVALID_PARAMETER,
                    ..
                }) if index == 0 => Ok(None),
                other => other.map(Some),
            }
        }

        /// SetupAPI's own `(disk id, subdirectory)` for a source file name.
        fn source_location(
            &self,
            file: &str,
        ) -> Result<Option<(u32, String)>, SourceManifestError> {
            let w = wide(file);
            let mut disk = 0u32;
            match Self::string("SetupGetSourceFileLocationW", |p, n, r| {
                // SAFETY: live handle; a null line context selects a name lookup.
                unsafe {
                    sa::SetupGetSourceFileLocationW(self.0, null(), w.as_ptr(), &mut disk, p, n, r)
                }
            }) {
                Ok(subdir) => Ok(Some((disk, subdir))),
                Err(SourceManifestError::NativeCall {
                    code: ERROR_LINE_NOT_FOUND,
                    ..
                }) => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// One `SourceDisksNames` property of a disk id.
        fn source_info(&self, disk: u32, info: u32) -> Result<String, SourceManifestError> {
            Self::string("SetupGetSourceInfoW", |p, n, r| {
                // SAFETY: live handle; the buffer length is passed exactly.
                unsafe { sa::SetupGetSourceInfoW(self.0, disk, info, p, n, r) }
            })
        }
    }

    impl Drop for Hinf {
        fn drop(&mut self) {
            // SAFETY: a live handle from a successful open, closed once.
            unsafe { sa::SetupCloseInfFile(self.0) };
            #[cfg(feature = "test-inject")]
            OPEN_HANDLES.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub(super) fn interpret(inf_path: &Path, install_section: &str) -> Step<Vec<SourceReference>> {
        let inf = Hinf::open(inf_path)?;
        Interp {
            inf: &inf,
            budget: Budget::default(),
            order: Vec::new(),
            index: HashMap::new(),
            provenance: Vec::new(),
        }
        .run(install_section)
    }

    /// Unique sources (case-insensitive) in discovery order, with provenance.
    struct Interp<'a> {
        inf: &'a Hinf,
        budget: Budget,
        order: Vec<String>,
        index: HashMap<String, usize>,
        provenance: Vec<Vec<SourceProvenance>>,
    }

    impl Interp<'_> {
        fn run(mut self, install: &str) -> Step<Vec<SourceReference>> {
            let inf = self.inf;
            let actual = inf.actual_section(install)?;
            if !inf.has(&actual) {
                return Err(UnsupportedReason::InstallSectionMissing.into());
            }
            for sub in UNSUPPORTED_SUBSECTIONS {
                if inf.has(&format!("{actual}.{sub}")) {
                    return Err(UnsupportedReason::UnsupportedSubsection(sub).into());
                }
            }
            for top in UNSUPPORTED_TOP_LEVEL {
                if inf.has(&inf.actual_section(top)?) {
                    return Err(UnsupportedReason::UnsupportedSubsection(top).into());
                }
            }
            let coinstallers = format!("{actual}.CoInstallers");
            let mut scan = vec![actual];
            if inf.has(&coinstallers) {
                scan.push(coinstallers);
            }
            for section in &scan {
                self.scan_install_section(section)?;
            }
            self.resolve()
        }

        /// Walk one install-like section: collect CopyFiles, refuse dependency keys.
        fn scan_install_section(&mut self, section: &str) -> Step<()> {
            self.budget.section(section)?;
            for ctx in self.inf.lines(section, None, &mut self.budget)? {
                let count = Hinf::field_count(&ctx);
                if count > MAX_FIELDS_PER_LINE {
                    return Err(SourceManifestError::Bound(BoundKind::FieldsPerLine).into());
                }
                let key = Hinf::field(&ctx, 0)?
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                match key.as_str() {
                    "include" | "needs" => return Err(UnsupportedReason::IncludeNeeds.into()),
                    "copyinf" => return Err(UnsupportedReason::CopyInf.into()),
                    "copyfiles" => {
                        for i in 1..=count {
                            let item = Hinf::field(&ctx, i)?.unwrap_or_default();
                            self.copy_item(section, &item)?;
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        }

        /// One CopyFiles field: `@file` or a named file-list section.
        fn copy_item(&mut self, install_section: &str, item: &str) -> Step<()> {
            if let Some(name) = item.strip_prefix('@') {
                let name = file_name(name)?;
                return self.add(install_section, true, name, name);
            }
            if !valid_section_name(item) {
                return Err(UnsupportedReason::MissingCopySection.into());
            }
            // A platform-decorated variant would change which entries apply;
            // v1 does not model that, so it is refused rather than guessed.
            if !self.inf.actual_section(item)?.eq_ignore_ascii_case(item) {
                return Err(UnsupportedReason::DecoratedFileListSection.into());
            }
            if !self.inf.has(item) {
                return Err(UnsupportedReason::MissingCopySection.into());
            }
            self.budget.section(item)?;
            for ctx in self.inf.lines(item, None, &mut self.budget)? {
                let count = Hinf::field_count(&ctx);
                if count > MAX_FIELDS_PER_LINE {
                    return Err(SourceManifestError::Bound(BoundKind::FieldsPerLine).into());
                }
                let first =
                    Hinf::field(&ctx, 1)?.ok_or(UnsupportedReason::MalformedFileListLine)?;
                // SetupAPI repeats a keyless single field as the key; a key that
                // differs from the first field marks a keyed line.
                if Hinf::field(&ctx, 0)?.is_some_and(|key| key != first) {
                    return Err(UnsupportedReason::KeyedFileListLine.into());
                }
                let source = match Hinf::field(&ctx, 2)? {
                    Some(s) if !s.is_empty() => s,
                    _ => first.clone(),
                };
                self.add(item, false, file_name(&first)?, file_name(&source)?)?;
            }
            Ok(())
        }

        fn add(
            &mut self,
            section: &str,
            direct: bool,
            destination: &str,
            source: &str,
        ) -> Step<()> {
            let b = &mut self.budget;
            bump(
                &mut b.references,
                1,
                MAX_COPYFILES_REFERENCES,
                BoundKind::CopyFilesReferences,
            )?;
            bump(
                &mut b.provenance,
                1,
                MAX_PROVENANCE_ENTRIES,
                BoundKind::ProvenanceEntries,
            )?;
            b.strings(section.len() + destination.len())?;
            let key = source.to_ascii_lowercase();
            let idx = match self.index.get(&key) {
                Some(&i) => i,
                None => {
                    bump(
                        &mut b.unique,
                        1,
                        MAX_UNIQUE_SOURCE_FILES,
                        BoundKind::UniqueSourceFiles,
                    )?;
                    b.strings(source.len())?;
                    self.order.push(source.to_string());
                    self.provenance.push(Vec::new());
                    self.index.insert(key, self.order.len() - 1);
                    self.order.len() - 1
                }
            };
            self.provenance[idx].push(SourceProvenance {
                section: section.to_string(),
                direct,
                destination_name: destination.to_string(),
            });
            Ok(())
        }

        /// Resolve every unique source through SetupAPI's own source-media
        /// lookup, cross-checked against an independent count of definitions.
        fn resolve(mut self) -> Step<Vec<SourceReference>> {
            let mut media: HashMap<u32, (String, bool)> = HashMap::new();
            let mut out = Vec::with_capacity(self.order.len());
            let sources = std::mem::take(&mut self.order);
            for (name, provenance) in sources
                .into_iter()
                .zip(std::mem::take(&mut self.provenance))
            {
                let (disk_id, subdir) = self
                    .inf
                    .source_location(&name)?
                    .ok_or(UnsupportedReason::MissingSourceDefinition)?;
                self.check_single_definition(&name, disk_id, &subdir)?;
                if let Entry::Vacant(slot) = media.entry(disk_id) {
                    let path = self.inf.source_info(disk_id, sa::SRCINFO_PATH)?;
                    let tag = self.inf.source_info(disk_id, sa::SRCINFO_TAGFILE)?;
                    let flags = self.inf.source_info(disk_id, sa::SRCINFO_FLAGS)?;
                    self.check_media_definition(disk_id, &path)?;
                    slot.insert((path, !tag.is_empty() || !flags.is_empty()));
                }
                let (path, external) = &media[&disk_id];
                if *external {
                    return Err(UnsupportedReason::ExternalMedia.into());
                }
                let source_path = normalize_source_path(path, &subdir, &name)?;
                self.budget.strings(source_path.len())?;
                out.push(SourceReference {
                    source_path,
                    disk_id,
                    provenance,
                });
            }
            Ok(out)
        }

        /// The one definition line for `key` in the platform-decorated `base`
        /// section when it defines the key, otherwise in the generic one. Exactly
        /// one line must apply (no first-entry-wins guess is ever made) and it
        /// obeys the same field bound as every other interpreted line.
        fn single_definition(&mut self, base: &str, key: &str) -> Step<sa::INFCONTEXT> {
            let mut found = Vec::new();
            for section in [format!("{base}.{ARCH_SUFFIX}"), base.to_string()] {
                if self.inf.has(&section) {
                    self.budget.section(&section)?;
                    found = self.inf.lines(&section, Some(key), &mut self.budget)?;
                }
                if !found.is_empty() {
                    break;
                }
            }
            let [ctx] = found.as_slice() else {
                return Err(UnsupportedReason::AmbiguousSourceDefinition.into());
            };
            if Hinf::field_count(ctx) > MAX_FIELDS_PER_LINE {
                return Err(SourceManifestError::Bound(BoundKind::FieldsPerLine).into());
            }
            Ok(*ctx)
        }

        /// The `SourceDisksNames` line for a disk id must be unique, bounded and
        /// agree with the path SetupAPI reported for it.
        fn check_media_definition(&mut self, disk_id: u32, path: &str) -> Step<()> {
            let ctx = self.single_definition("SourceDisksNames", &disk_id.to_string())?;
            if Hinf::field(&ctx, 4)?.unwrap_or_default() != path {
                return Err(UnsupportedReason::AmbiguousSourceDefinition.into());
            }
            Ok(())
        }

        /// The `SourceDisksFiles` line for a file must be the one SetupAPI
        /// resolved.
        fn check_single_definition(&mut self, name: &str, disk_id: u32, subdir: &str) -> Step<()> {
            let ctx = &self.single_definition("SourceDisksFiles", name)?;
            let scanned_disk = Hinf::field(ctx, 1)?.and_then(|d| d.parse::<u32>().ok());
            // SetupAPI documents its returned subdirectory as having no leading
            // or trailing backslash, while INF syntax allows `\x86` and `x86\`.
            // Strip exactly one of each from the raw field before comparing; any
            // other difference stays a mismatch (fail closed).
            let raw_subdir = Hinf::field(ctx, 2)?.unwrap_or_default();
            let scanned_subdir = raw_subdir.strip_prefix('\\').unwrap_or(&raw_subdir);
            let scanned_subdir = scanned_subdir.strip_suffix('\\').unwrap_or(scanned_subdir);
            if scanned_disk != Some(disk_id) || scanned_subdir != subdir {
                return Err(UnsupportedReason::AmbiguousSourceDefinition.into());
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Test seams (feature-gated; a release build cannot compile the feature in)
// ---------------------------------------------------------------------------

/// Derive with injected pre/post attestation, to prove the ordering and the
/// fail-closed handling a live lease cannot be made to exercise.
#[cfg(feature = "test-inject")]
pub fn test_derive_with_attestation<'v>(
    verified: &'v VerifiedDriverPackage,
    install_section: &str,
    pre: &mut dyn FnMut() -> Result<(), TrustError>,
    post: &mut dyn FnMut() -> Result<(), TrustError>,
) -> SourceManifest<'v> {
    derive_with(verified, install_section, pre, post)
}

#[cfg(feature = "test-inject")]
pub fn test_bounded_native_string(
    max_units: usize,
    call: NativeFill<'_>,
) -> Result<String, SourceManifestError> {
    bounded_native_string("test_native", max_units, call)
}

#[cfg(feature = "test-inject")]
pub fn test_normalize_source_path(
    media_path: &str,
    subdir: &str,
    file: &str,
) -> Result<String, PathReject> {
    normalize_source_path(media_path, subdir, file)
}

#[cfg(feature = "test-inject")]
pub fn test_checked_charge(
    current: usize,
    add: usize,
    cap: usize,
) -> Result<usize, SourceManifestError> {
    charge(current, add, cap, BoundKind::Lines)
}

/// Total native INF open attempts so far.
#[cfg(feature = "test-inject")]
pub fn test_native_open_calls() -> usize {
    OPEN_CALLS.load(std::sync::atomic::Ordering::SeqCst)
}

/// Native INF handles currently open.
#[cfg(feature = "test-inject")]
pub fn test_open_inf_handles() -> usize {
    OPEN_HANDLES.load(std::sync::atomic::Ordering::SeqCst)
}
