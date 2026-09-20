//! Tab 2a-10 - payload inventory + content fingerprint gate.
//!
//! Given a live, token-bound [`ResolvedSourceReferences`] from Tab 2a-9, this
//! module proves that every referenced payload exists UNIQUELY in the same
//! local SDIO `.7z`, streams those payloads under the inherited archive and
//! decompression bounds plus explicit payload bounds, and records each one's
//! exact decoded length and SHA-256.
//!
//! # What a successful inventory means
//!
//! ONLY this: every source reference in the input was uniquely located in the
//! CURRENT local pack, the corresponding archive bytes were streamed
//! successfully under Cove's bounds, and their exact decoded length and
//! SHA-256 were recorded.
//!
//! It does NOT mean the payload signatures are trusted, that the catalog
//! covers those files, that anything is staged, that the package is complete
//! beyond Tab 2a-9's supported source-manifest scope, that the Driver Store
//! would accept it, that an install is authorized, or that the driver is
//! recommended or an update. SHA-256 here is CONTENT IDENTITY, never
//! authenticity, trust or publisher proof.
//!
//! # The pack is hostile CURRENT input
//!
//! The verified token preserves the canonical pack path, the pack name and the
//! INF/archive-member provenance. It does NOT cryptographically pin the whole
//! `.7z`, and it retains no size snapshot of it. A same-path pack replacement
//! after INF verification is therefore possible, and this module makes no
//! claim that the bytes it reads are the bytes an earlier extraction saw. If
//! the archive changed but still contains matching source names, the inventory
//! records the bytes decoded NOW and asserts nothing about their authenticity.
//! The digests produced here are the anchor the later digest-bound
//! materialization slice must require equality against; that slice, not this
//! one, owns the trust decision.
//!
//! # No filesystem output
//!
//! The only production filesystem interaction is READ-ONLY access to the
//! existing local `.7z`. Nothing is staged, copied, created or deleted.
//!
//! # The inventory cannot outlive the trust lease
//!
//! [`ResolvedPayloadInventory`] borrows the live [`VerifiedDriverPackage`], so
//! evidence cannot escape the lease that justified reading the pack:
//!
//! ```compile_fail
//! use mod_drivers::sdio::payload_inventory::ResolvedPayloadInventory;
//! fn escape<'a>(i: ResolvedPayloadInventory<'a>) -> ResolvedPayloadInventory<'static> { i }
//! ```
//!
//! The companion positive case compiles, so the failure above is the lifetime:
//!
//! ```
//! use mod_drivers::sdio::payload_inventory::ResolvedPayloadInventory;
//! fn keep<'a>(i: ResolvedPayloadInventory<'a>) -> ResolvedPayloadInventory<'a> { i }
//! ```

use std::fs::{self, File};
use std::path::Path;

use crate::sdio::extraction::{ExtractionError, MemberFingerprint, PayloadLimits};
use crate::sdio::local_pack::{
    MAX_ARCHIVE_COMPONENT_LEN, MAX_ARCHIVE_MEMBER_COMPONENTS, MAX_ARCHIVE_MEMBER_LEN,
    MAX_LOCAL_PACK_BYTES,
};
use crate::sdio::signature::{TrustError, VerifiedDriverPackage};
use crate::sdio::source_manifest::ResolvedSourceReferences;

// ---------------------------------------------------------------------------
// Bounds
//
// Safety baselines, not product promises. Raising one because a fixture or a
// corpus needs it is a measured decision, not a convenience.
// ---------------------------------------------------------------------------

/// Most payloads one inventory may describe.
pub const MAX_PAYLOAD_FILES: usize = 1024;
/// Largest single payload, by declared and decoded length.
pub const MAX_PAYLOAD_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// Largest aggregate of the requested payloads themselves.
pub const MAX_PAYLOAD_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Largest aggregate DECODE cost, including the solid prerequisites that have
/// to be decoded to reach a requested payload.
pub const MAX_PAYLOAD_TOTAL_DECODE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Largest total of the path text this module retains.
pub const MAX_PAYLOAD_RETAINED_PATH_BYTES: usize = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Errors (fail closed)
// ---------------------------------------------------------------------------

/// Fail-closed reasons a payload inventory was not produced.
///
/// `index` is always the position of the failing reference in the input
/// [`ResolvedSourceReferences`], so a caller can name the source it came from.
#[derive(Debug, thiserror::Error)]
pub enum PayloadInventoryError {
    #[error("verified package re-attestation failed: {0}")]
    Attestation(TrustError),
    #[error("the local pack changed since verification")]
    PackChangedSinceVerification,
    #[error("source reference {index} has an unsafe path")]
    UnsafeSourcePath { index: usize },
    #[error("the resolved source references name no payload")]
    NoSourceReferences,
    #[error("too many payloads (limit {MAX_PAYLOAD_FILES})")]
    TooManyPayloads,
    #[error("expected archive member exceeds the member length bound")]
    ExpectedMemberTooLong,
    #[error("retained payload path budget exceeded (limit {MAX_PAYLOAD_RETAINED_PATH_BYTES})")]
    RetainedPathBudgetExceeded,
    #[error("two source references resolve to the same expected archive member")]
    DuplicateExpectedMember,
    #[error("payload {index} is missing from the archive")]
    PayloadMemberMissing { index: usize },
    #[error("payload {index} is ambiguous ({matches} archive members match)")]
    PayloadMemberAmbiguous { index: usize, matches: usize },
    #[error("payload {index} is not a regular streamed file")]
    PayloadNotRegularFile { index: usize },
    #[error("payload {index} exceeds the per-payload cap of {MAX_PAYLOAD_FILE_BYTES} bytes")]
    PayloadTooLarge { index: usize },
    #[error("total payload bytes exceed {MAX_PAYLOAD_TOTAL_BYTES}")]
    PayloadTotalBytesExceeded,
    #[error("payload decode budget of {MAX_PAYLOAD_TOTAL_DECODE_BYTES} bytes exceeded")]
    PayloadDecodeBudgetExceeded,
    #[error("archive error: {0}")]
    Archive(ExtractionError),
}

/// Structural equality for assertions and caller-side matching.
///
/// The wrapped `TrustError`/`ExtractionError` carry non-comparable payloads
/// (`std::io::Error`), so those two variants compare by their debug rendering.
/// Every variant this module produces on its own compares field by field.
impl PartialEq for PayloadInventoryError {
    fn eq(&self, other: &Self) -> bool {
        format!("{self:?}") == format!("{other:?}")
    }
}

impl From<ExtractionError> for PayloadInventoryError {
    /// Map the archive layer's payload-specific refusals onto this module's
    /// domain; everything else stays an opaque archive error so the inherited
    /// 7z security contract is never re-interpreted here.
    fn from(e: ExtractionError) -> Self {
        match e {
            ExtractionError::PayloadMemberMissing { index } => Self::PayloadMemberMissing { index },
            ExtractionError::PayloadMemberAmbiguous { index, matches } => {
                Self::PayloadMemberAmbiguous { index, matches }
            }
            ExtractionError::PayloadNotRegularFile { index } => {
                Self::PayloadNotRegularFile { index }
            }
            ExtractionError::PayloadTooLarge { index } => Self::PayloadTooLarge { index },
            ExtractionError::PayloadTotalBytesExceeded => Self::PayloadTotalBytesExceeded,
            ExtractionError::PayloadDecodeBudgetExceeded => Self::PayloadDecodeBudgetExceeded,
            other => Self::Archive(other),
        }
    }
}

type PayloadResult<T> = Result<T, PayloadInventoryError>;

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/// One payload's content identity: the exact decoded length and the SHA-256 of
/// the bytes decoded NOW. Not a signature, not authenticity, not trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadFingerprint {
    size_bytes: u64,
    sha256: [u8; 32],
}

impl PayloadFingerprint {
    /// Exact number of bytes decoded for this payload.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
    /// SHA-256 over the decoded bytes. Content identity only.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// One inventory row: the INF's source name, the archive's own spelling of the
/// member it resolved to, and that member's fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadInventoryEntry {
    source_path: String,
    actual_archive_member: String,
    fingerprint: PayloadFingerprint,
}

impl PayloadInventoryEntry {
    /// The Tab 2a-9 source path, relative to the INF's directory, source
    /// casing preserved.
    pub fn source_path(&self) -> &str {
        &self.source_path
    }
    /// The archive's own spelling of the member this resolved to, which may
    /// differ from the composed expected member by ASCII case.
    pub fn actual_archive_member(&self) -> &str {
        &self.actual_archive_member
    }
    pub fn fingerprint(&self) -> &PayloadFingerprint {
        &self.fingerprint
    }
}

/// Every requested payload's fingerprint, in Tab 2a-9 discovery order, bound
/// to the live verified package.
///
/// This is NOT a package-completeness claim, NOT a catalog-trust claim for the
/// payloads, and NOT an installability claim. It is exactly the set of source
/// references it was given, proven to exist uniquely in the current pack and
/// fingerprinted.
#[derive(Debug)]
pub struct ResolvedPayloadInventory<'v> {
    verified: &'v VerifiedDriverPackage,
    entries: Vec<PayloadInventoryEntry>,
    declared_decode_bytes: u64,
    decode_bytes: u64,
}

impl<'v> ResolvedPayloadInventory<'v> {
    pub fn entries(&self) -> &[PayloadInventoryEntry] {
        &self.entries
    }
    /// The live token this inventory is bound to.
    pub fn verified_package(&self) -> &'v VerifiedDriverPackage {
        self.verified
    }
    /// Bytes actually decoded to produce this inventory, including the solid
    /// prerequisites that had to be decoded to reach a requested payload.
    pub fn decode_bytes(&self) -> u64 {
        self.decode_bytes
    }
    /// The DECLARED decode cost the budget was checked against before any
    /// decoding started: for each required block, the declared unpacked sizes
    /// from the block's first entry through its last requested target, so
    /// solid prerequisites are charged, not just the payloads.
    pub fn declared_decode_bytes(&self) -> u64 {
        self.declared_decode_bytes
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Inventory every payload the resolved source references name.
///
/// All or nothing: if any reference is missing, ambiguous, oversized, not a
/// regular streamed file, or undecodable, NO inventory is returned. A caller
/// can therefore never mistake a partial result for a package-ready set.
///
/// The live token is re-attested before the pack is opened and again before
/// the evidence is returned; the trust lease is never weakened or released to
/// read payloads.
pub fn inspect_payload_inventory<'v>(
    sources: &ResolvedSourceReferences<'v>,
) -> PayloadResult<ResolvedPayloadInventory<'v>> {
    let verified = sources.verified_package();
    inspect_with(sources, &mut || verified.reattest(), &mut || {
        verified.reattest()
    })
}

fn inspect_with<'v>(
    sources: &ResolvedSourceReferences<'v>,
    pre: &mut dyn FnMut() -> Result<(), TrustError>,
    post: &mut dyn FnMut() -> Result<(), TrustError>,
) -> PayloadResult<ResolvedPayloadInventory<'v>> {
    let verified = sources.verified_package();
    let references = sources.references();
    if references.is_empty() {
        return Err(PayloadInventoryError::NoSourceReferences);
    }
    if references.len() > MAX_PAYLOAD_FILES {
        return Err(PayloadInventoryError::TooManyPayloads);
    }

    // Compose the expected archive members BEFORE any attestation or IO: a
    // hostile source path must never reach the archive boundary, and pure
    // rejection costs nothing.
    let inf_member = verified.expected_archive_member();
    let mut expected: Vec<String> = Vec::with_capacity(references.len());
    let mut retained: usize = 0;
    for (index, r) in references.iter().enumerate() {
        let member = expected_member(index, inf_member, r.source_path())?;
        retained = retained
            .checked_add(member.len())
            .and_then(|v| v.checked_add(r.source_path().len()))
            .ok_or(PayloadInventoryError::RetainedPathBudgetExceeded)?;
        if retained > MAX_PAYLOAD_RETAINED_PATH_BYTES {
            return Err(PayloadInventoryError::RetainedPathBudgetExceeded);
        }
        // Tab 2a-9 already deduplicates source paths; two DIFFERENT source
        // paths colliding here (case-insensitively) would silently coalesce
        // semantically distinct references, so it fails closed instead.
        if expected.iter().any(|e| e.eq_ignore_ascii_case(&member)) {
            return Err(PayloadInventoryError::DuplicateExpectedMember);
        }
        expected.push(member);
    }

    // Pre-attestation: nothing is opened or decoded until the lease holds.
    pre().map_err(PayloadInventoryError::Attestation)?;

    let mut file = reopen_pack(verified.pack_archive_path())?;
    let limits = PayloadLimits {
        max_file_bytes: MAX_PAYLOAD_FILE_BYTES,
        max_total_bytes: MAX_PAYLOAD_TOTAL_BYTES,
        max_total_decode_bytes: MAX_PAYLOAD_TOTAL_DECODE_BYTES,
    };
    let (fingerprints, declared_decode_bytes, decode_bytes) =
        crate::sdio::extraction::fingerprint_archive_members(&mut file, &expected, &limits)?;
    drop(file);

    // Post-attestation: decode evidence is discarded if the lease that
    // justified reading the pack no longer holds.
    post().map_err(PayloadInventoryError::Attestation)?;

    let entries = references
        .iter()
        .zip(fingerprints)
        .map(|(r, f)| {
            let MemberFingerprint {
                actual_member,
                size_bytes,
                sha256,
            } = f;
            PayloadInventoryEntry {
                source_path: r.source_path().to_string(),
                actual_archive_member: actual_member,
                fingerprint: PayloadFingerprint { size_bytes, sha256 },
            }
        })
        .collect();
    Ok(ResolvedPayloadInventory {
        verified,
        entries,
        declared_decode_bytes,
        decode_bytes,
    })
}

// ---------------------------------------------------------------------------
// Archive-member composition
// ---------------------------------------------------------------------------

/// Compose one expected archive member from the verified INF member's
/// DIRECTORY plus the source path, applied exactly once.
///
/// `amd/10x64/pkg/driver.inf` + `bin/driver.sys` -> `amd/10x64/pkg/bin/driver.sys`;
/// `driver.inf` + `bin/driver.sys` -> `bin/driver.sys`.
///
/// The destination filename, the staged INF's filesystem path, the
/// `SourceDisks` disk id and the pack filename are all irrelevant here and
/// must never contribute to the archive location.
pub(crate) fn expected_member(
    index: usize,
    inf_member: &str,
    source_path: &str,
) -> PayloadResult<String> {
    validate_source_path(index, source_path)?;
    let prefix = match inf_member.rfind('/') {
        Some(i) => &inf_member[..=i],
        None => "",
    };
    let member = format!("{prefix}{source_path}");
    if member.len() > MAX_ARCHIVE_MEMBER_LEN {
        return Err(PayloadInventoryError::ExpectedMemberTooLong);
    }
    Ok(member)
}

/// Revalidate one Tab 2a-9 source path at the archive boundary.
///
/// Tab 2a-9 already validates it; this is defense in depth at the trust
/// boundary between the INF interpretation and the archive. Hostile input is
/// REJECTED, never normalized into safety, and the source casing is preserved.
pub(crate) fn validate_source_path(index: usize, path: &str) -> PayloadResult<()> {
    let bad = || PayloadInventoryError::UnsafeSourcePath { index };
    if path.is_empty() || path.len() > MAX_ARCHIVE_MEMBER_LEN {
        return Err(bad());
    }
    // The current domain is ASCII; a non-ASCII source path is refused rather
    // than case-folded under unproved Unicode rules.
    if !path.is_ascii() {
        return Err(bad());
    }
    if path.contains('\0') || path.contains(':') || path.contains('\\') {
        return Err(bad());
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(bad());
    }
    let mut components = 0usize;
    for comp in path.split('/') {
        components += 1;
        if components > MAX_ARCHIVE_MEMBER_COMPONENTS {
            return Err(bad());
        }
        if comp.is_empty() || comp.len() > MAX_ARCHIVE_COMPONENT_LEN {
            return Err(bad());
        }
        if comp == "." || comp == ".." {
            return Err(bad());
        }
        let last = comp.as_bytes()[comp.len() - 1];
        if last == b'.' || last.is_ascii_whitespace() {
            return Err(bad());
        }
        if comp.contains(['<', '>', '"', '|', '?', '*']) {
            return Err(bad());
        }
        if comp.bytes().any(|b| (1..=0x1F).contains(&b)) {
            return Err(bad());
        }
        if is_reserved_component(comp) {
            return Err(bad());
        }
    }
    Ok(())
}

/// Windows reserved DOS device names, matched on the component's stem.
fn is_reserved_component(comp: &str) -> bool {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = comp.split('.').next().unwrap_or(comp);
    RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r))
}

// ---------------------------------------------------------------------------
// Pack reopen (TOCTOU boundary)
// ---------------------------------------------------------------------------

/// Reopen the pack the verified token names, fail-closed on any substitution.
///
/// The verified token pins the canonical PATH, not the bytes, and retains no
/// size snapshot from the 2a-5 resolution, so no historical size-equality check
/// is possible and none is fabricated.
///
/// The pathname prechecks below are advisory only: every one of them is a
/// TOCTOU race against the open that follows. The binding checks are the ones
/// made THROUGH the retained handle in [`open_pack_read_locked`], which is what
/// actually decides which object gets decoded.
pub(crate) fn reopen_pack(expected: &Path) -> PayloadResult<File> {
    let changed = || PayloadInventoryError::PackChangedSinceVerification;
    let meta = fs::symlink_metadata(expected).map_err(|_| changed())?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(changed());
    }
    let canonical = fs::canonicalize(expected).map_err(|_| changed())?;
    if canonical != expected {
        return Err(changed());
    }
    if meta.len() == 0 || meta.len() > MAX_LOCAL_PACK_BYTES {
        return Err(changed());
    }

    let file = open_pack_read_locked(&canonical)?;

    // Everything below is proven THROUGH the retained handle, so it describes
    // the object that will actually be decoded rather than a pathname that may
    // already have been swapped.
    let handle_meta = file.metadata().map_err(|_| changed())?;
    if !handle_meta.is_file() || handle_meta.len() == 0 {
        return Err(changed());
    }
    if handle_meta.len() > MAX_LOCAL_PACK_BYTES {
        return Err(changed());
    }
    Ok(file)
}

/// Open the pack read-only, bound to the exact canonical object, and hold it
/// that way for the whole decode.
///
/// Three properties the pathname prechecks cannot provide, all proven from the
/// handle itself:
///
/// 1. `FILE_FLAG_OPEN_REPARSE_POINT` means a reparse point raced into the path
///    is opened as the LINK object, never traversed; the attribute proof then
///    rejects it. Without this, a substitution between `canonicalize` and the
///    open would silently redirect the whole inventory to another file.
/// 2. `FILE_SHARE_READ` alone withholds write and delete sharing, so no writer
///    can mutate the archive while its blocks are being decoded and hashed. A
///    writer already holding the pack makes this open fail with
///    `ERROR_SHARING_VIOLATION`, which is the desired fail-closed outcome and
///    not a condition to retry around.
/// 3. The handle's own final path must still equal the canonical path the
///    verified token names, which closes the gap between resolving the name
///    and opening it.
///
/// This is strictly stronger than the pathname-only revalidation the
/// INF-materialization path performs; nothing there is relaxed by it.
#[cfg(windows)]
fn open_pack_read_locked(canonical: &Path) -> PayloadResult<File> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_NAME_NORMALIZED, FILE_SHARE_READ, GetFileInformationByHandle,
        GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_DOS,
    };

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    /// Bounds the final-path buffer: a substitution cannot make this loop or
    /// drive an unbounded allocation.
    const MAX_FINAL_PATH_UNITS: u32 = 32 * 1024;

    let changed = || PayloadInventoryError::PackChangedSinceVerification;

    let wide: Vec<u16> = canonical
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    if wide.iter().rev().skip(1).any(|u| *u == 0) {
        return Err(changed());
    }

    // SAFETY: `wide` is a live NUL-terminated wide string for the duration of
    // the call; every other argument is a constant or a null optional.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(changed());
    }

    // From here every early return must close the handle.
    let close = |h| {
        // SAFETY: `h` is the live handle opened just above, not used again.
        unsafe {
            let _ = CloseHandle(h);
        }
    };

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `handle` is live; `info` is a valid out-param.
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
    {
        close(handle);
        return Err(changed());
    }

    // The opened object's own final path must still be the canonical path.
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: `handle` is live; `buf` is a valid writable slice of the
        // length passed.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if n == 0 || n > MAX_FINAL_PATH_UNITS {
            close(handle);
            return Err(changed());
        }
        if (n as usize) < buf.len() {
            buf.truncate(n as usize);
            break;
        }
        buf = vec![0u16; n as usize + 1];
    }
    let final_path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buf));
    if final_path != canonical {
        close(handle);
        return Err(changed());
    }

    // SAFETY: `handle` is a live file handle; `File` takes ownership of it and
    // is the only owner from here on.
    Ok(unsafe { File::from_raw_handle(handle as std::os::windows::io::RawHandle) })
}

/// No native handle-binding surface off Windows; the pathname prechecks in
/// [`reopen_pack`] are all that exist there.
#[cfg(not(windows))]
fn open_pack_read_locked(canonical: &Path) -> PayloadResult<File> {
    File::open(canonical).map_err(|_| PayloadInventoryError::PackChangedSinceVerification)
}

// ---------------------------------------------------------------------------
// Test-only seams
// ---------------------------------------------------------------------------

/// Drive the inventory with injected pre/post attestations.
#[cfg(feature = "test-inject")]
pub fn test_inspect_with_attestation<'v>(
    sources: &ResolvedSourceReferences<'v>,
    pre: &mut dyn FnMut() -> Result<(), TrustError>,
    post: &mut dyn FnMut() -> Result<(), TrustError>,
) -> PayloadResult<ResolvedPayloadInventory<'v>> {
    inspect_with(sources, pre, post)
}

#[cfg(feature = "test-inject")]
pub fn test_expected_archive_member(inf_member: &str, source_path: &str) -> PayloadResult<String> {
    expected_member(0, inf_member, source_path)
}

#[cfg(feature = "test-inject")]
pub fn test_validate_source_path(path: &str) -> PayloadResult<()> {
    validate_source_path(0, path)
}

/// The four bound helpers below are the EXACT production call sites inside the
/// archive layer, driven here with this module's caps. They are not re-checks.
#[cfg(feature = "test-inject")]
pub fn test_payload_size_within_cap(size: u64) -> PayloadResult<()> {
    crate::sdio::extraction::payload_size_within_cap(0, size, MAX_PAYLOAD_FILE_BYTES)
        .map_err(PayloadInventoryError::from)
}

#[cfg(feature = "test-inject")]
pub fn test_accumulate_total_bytes(running: u64, add: u64) -> PayloadResult<u64> {
    crate::sdio::extraction::accumulate_payload_bytes(running, add, MAX_PAYLOAD_TOTAL_BYTES)
        .map_err(PayloadInventoryError::from)
}

#[cfg(feature = "test-inject")]
pub fn test_accumulate_decode_bytes(running: u64, add: u64) -> PayloadResult<u64> {
    crate::sdio::extraction::accumulate_payload_decode_bytes(
        running,
        add,
        MAX_PAYLOAD_TOTAL_DECODE_BYTES,
    )
    .map_err(PayloadInventoryError::from)
}

#[cfg(feature = "test-inject")]
pub fn test_charge_runtime_bytes(running: u64, add: u64, cap: u64) -> PayloadResult<u64> {
    crate::sdio::extraction::charge_runtime_payload_bytes(running, add, cap)
        .map_err(PayloadInventoryError::from)
}

#[cfg(feature = "test-inject")]
pub use crate::sdio::extraction::{test_block_decode_count, test_reset_block_decode_count};
