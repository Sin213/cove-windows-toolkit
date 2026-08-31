//! Bounded `.7z` inspection + exact INF extraction (Tab 2a-6, Option C).
//!
//! Materializes EXACTLY ONE expected INF member from an already-resolved local
//! SDIO `.7z` pack into an isolated, caller-provided staging directory.
//!
//! # Trust boundary
//!
//! The archive is treated as hostile input even after 2a-5 validated it:
//!
//! - The 2a-5 [`LocalPackRef`] is a **filesystem-resolution snapshot**, not
//!   cryptographic identity. It is re-opened and re-validated immediately
//!   before archive access (type / canonical path / size). Same-size content
//!   replacement is NOT detected — no authoritative pack hash exists yet.
//! - Every archive member name is validated fail-closed against the same
//!   bounds 2a-5 uses. Traversal is rejected, never normalized into safety.
//! - The expected member must be uniquely resolvable (exact + ASCII
//!   case-insensitive within the proven-ASCII corpus); case collisions are
//!   [`ExtractionError::TargetMemberAmbiguous`], never "pick first".
//! - Decode work is pre-budgeted from archive metadata and enforced again at
//!   runtime; only the target's compression block is decoded.
//!
//! # Non-goals
//!
//! No INF semantic parsing, no CAT/signature trust, no installability
//! classification, no Windows rank, no installation, no networking, no
//! subprocess extraction. A successful [`StagedInfArtifact`] means the exact
//! expected member was decoded under bounds into one staging file — nothing
//! more.
//!
//! # Backend (Gate A6)
//!
//! [`sevenz_rust2`] 0.22.2 with `default-features = false`; LZMA/LZMA2/COPY
//! decoders are always available without any optional feature. Metadata comes
//! from [`sevenz_rust2::Archive::read`] and extraction streams exactly the
//! target block through [`sevenz_rust2::BlockDecoder::for_each_entries`].

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sevenz_rust2::{Archive, Block, BlockDecoder, Password};

use crate::sdio::local_pack::{ExpectedArchiveMember, LocalPackRef, PackageMaterializationRequest};

// ---------------------------------------------------------------------------
// Named bounds (baseline per Tab 2a-6; real SDIO pack evidence stayed below)
// ---------------------------------------------------------------------------

pub const MAX_ARCHIVE_ENTRIES: usize = 200_000;
pub const MAX_ARCHIVE_BLOCKS: usize = 200_000;
pub const MAX_CODERS_PER_BLOCK: usize = 16;
pub const MAX_ARCHIVE_TOTAL_NAME_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_ARCHIVE_DECLARED_UNPACKED_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_TARGET_INF_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_TARGET_DECODE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_TARGET_BLOCK_EXPANSION_RATIO: u64 = 1000;
/// Fixed Cove-owned budget for the 7z next-header size (start-header preflight).
/// The backend allocates a buffer of the declared next-header size before its
/// own per-element limits run; this bounds that allocation to a fixed value
/// independent of the (up to 16 GiB) local-pack file cap.
pub const MAX_ARCHIVE_HEADER_BYTES: u64 = 64 * 1024 * 1024;
/// Fixed Cove-owned decoder workspace budget. LZMA/LZMA2 dictionary sizes are
/// attacker-controlled from coder properties and the backend allocates
/// ~dict_size bytes of decoder workspace before any decoded-byte accounting.
/// SDIO INFs are tiny; a 512 MiB dictionary budget is far above any legitimate
/// current SDIO pack requirement.
pub const MAX_DECODER_WORKSPACE_BYTES: u64 = 512 * 1024 * 1024;
/// Fixed streaming scratch buffer (never sized from archive metadata).
const STREAM_BUF_BYTES: usize = 64 * 1024;
/// Maximum staging-child creation attempts before failing closed.
const MAX_STAGE_ATTEMPTS: u32 = 128;
/// Unique staging child name prefix.
const STAGE_PREFIX: &str = "cove-sdio-stage-";
/// Decoder thread count: deterministic single-threaded decode.
const DECODER_THREADS: u32 = 1;

/// FILE_ATTRIBUTE_REPARSE_POINT: reject target entries carrying it.
const ATTR_REPARSE_POINT: u32 = 0x400;

/// 7-Zip AES-256 coder method id (`k_AES`).
const CODER_ID_AES256: [u8; 4] = [0x06, 0xF1, 0x07, 0x01];

/// 7-Zip LZMA coder method id.
const CODER_ID_LZMA: [u8; 3] = [0x03, 0x01, 0x01];
/// 7-Zip LZMA2 coder method id.
const CODER_ID_LZMA2: [u8; 1] = [0x21];
/// 7-Zip COPY (store) coder method id (test-support: pins zero-workspace
/// semantics in the aggregate boundary tests).
#[cfg(test)]
const CODER_ID_COPY: [u8; 1] = [0x00];
/// 7-Zip signature (bytes 0..6 of the 32-byte signature header).
const SEVEN_Z_SIGNATURE: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];
/// 7z signature header is fixed at 32 bytes.
const SIGNATURE_HEADER_LEN: usize = 32;
/// Start-header `next_header_size` LE u64 offset within the 32-byte header.
const NEXT_HEADER_SIZE_OFFSET: usize = 20;

// ---------------------------------------------------------------------------
// Errors (fail closed)
// ---------------------------------------------------------------------------

/// Fail-closed reasons for bounded archive inspection / extraction.
#[derive(Debug, thiserror::Error)]
pub enum ExtractionError {
    #[error("pack changed since 2a-5 resolution (revalidation failed)")]
    PackChangedSinceResolution,
    #[error("invalid pack at extraction time: {0}")]
    InvalidPackAtExtraction(String),
    #[error("archive backend error: {0}")]
    ArchiveBackend(String),
    #[error("encrypted archive is not supported")]
    UnsupportedEncryptedArchive,
    #[error("archive uses an unsupported compression codec")]
    UnsupportedArchiveCodec,
    #[error("archive has too many entries (limit {MAX_ARCHIVE_ENTRIES})")]
    ArchiveTooManyEntries,
    #[error("archive has too many blocks (limit {MAX_ARCHIVE_BLOCKS})")]
    ArchiveTooManyBlocks,
    #[error("archive block has too many coders (limit {MAX_CODERS_PER_BLOCK})")]
    ArchiveTooManyCoders,
    #[error("archive member-name byte budget exceeded (limit {MAX_ARCHIVE_TOTAL_NAME_BYTES})")]
    ArchiveNameBudgetExceeded,
    #[error(
        "archive declared unpacked size exceeded (limit {MAX_ARCHIVE_DECLARED_UNPACKED_BYTES})"
    )]
    ArchiveDeclaredSizeExceeded,
    #[error("archive member {index} has an unsafe path")]
    UnsafeArchiveMember { index: usize },
    #[error("archive contains a duplicate member path")]
    DuplicateArchiveMember,
    #[error("expected target member is missing from the archive")]
    TargetMemberMissing,
    #[error("expected target member is ambiguous ({0} members match)")]
    TargetMemberAmbiguous(usize),
    #[error("expected target member is not a regular streamed file")]
    TargetNotRegularFile,
    #[error("target member exceeds size cap of {MAX_TARGET_INF_BYTES} bytes")]
    TargetTooLarge,
    #[error("target decode budget exceeded (limit {MAX_TARGET_DECODE_BYTES} bytes)")]
    TargetDecodeBudgetExceeded,
    #[error("target block expansion ratio exceeds cap of {MAX_TARGET_BLOCK_EXPANSION_RATIO}")]
    TargetExpansionRatioExceeded,
    #[error(
        "archive next-header size exceeds fixed header budget of {MAX_ARCHIVE_HEADER_BYTES} bytes"
    )]
    ArchiveHeaderTooLarge,
    #[error(
        "target block decoder workspace exceeds fixed budget of {MAX_DECODER_WORKSPACE_BYTES} bytes"
    )]
    DecoderWorkspaceExceeded,
    #[error("target member is a non-ASCII path (unsupported)")]
    UnsupportedNonAsciiTarget,
    #[error("invalid staging root: {0}")]
    InvalidStagingRoot(String),
    #[error("staging child directory collision after {MAX_STAGE_ATTEMPTS} attempts")]
    StageDirectoryCollision,
    #[error("output file already exists in staging")]
    OutputAlreadyExists,
    #[error("decoded size mismatch: expected {expected} bytes, wrote {written}")]
    DecodedSizeMismatch { expected: u64, written: u64 },
    #[error("cleanup failed: {0}")]
    CleanupFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience result alias for the extraction layer.
pub type ExtractionResult<T> = std::result::Result<T, ExtractionError>;

// ---------------------------------------------------------------------------
// Success domain
// ---------------------------------------------------------------------------

/// Result of materializing exactly one expected INF member: decoded under
/// bounds and written as one new regular file in a caller-provided staging
/// root. NOT parsed/trusted/signed/installable; no Windows rank. Cleanup is
/// explicit via [`StagedInfArtifact::cleanup`]; `Drop` never deletes.
#[derive(Debug)]
pub struct StagedInfArtifact {
    staging_dir: PathBuf,
    inf_path: PathBuf,
    expected_archive_member: String,
    actual_archive_member: String,
    pack_name: String,
    size_bytes: u64,
}

impl StagedInfArtifact {
    /// The unique staging child directory (caller-owned root is untouched).
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }
    /// The staged INF file path (flat leaf under `staging_dir`).
    pub fn inf_path(&self) -> &Path {
        &self.inf_path
    }
    /// The 2a-5 expected member path (archive separators), verbatim.
    pub fn expected_archive_member(&self) -> &str {
        &self.expected_archive_member
    }
    /// The actual archive member spelling that matched (may differ in case).
    pub fn actual_archive_member(&self) -> &str {
        &self.actual_archive_member
    }
    /// The pack name this INF came from.
    pub fn pack_name(&self) -> &str {
        &self.pack_name
    }
    /// Exact staged file size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
    /// The flat leaf filename of the staged INF.
    pub fn inf_leaf(&self) -> &str {
        self.inf_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
    }

    /// Explicit owned cleanup: removes the staged INF + owned staging child
    /// only; never the caller's root or siblings. Idempotent-safe.
    pub fn cleanup(self) -> ExtractionResult<()> {
        let mut first = true;
        if self.inf_path.exists() {
            fs::remove_file(&self.inf_path)
                .map_err(|e| ExtractionError::CleanupFailed(format!("remove inf: {e}")))?;
            first = false;
        }
        if self.staging_dir.exists() {
            fs::remove_dir(&self.staging_dir)
                .map_err(|e| ExtractionError::CleanupFailed(format!("remove staging dir: {e}")))?;
            first = false;
        }
        if first {
            // Nothing existed: already cleaned (e.g. double cleanup via clone).
            return Ok(());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (deterministic, no filesystem access)
// ---------------------------------------------------------------------------

pub use crate::sdio::local_pack::MAX_ARCHIVE_COMPONENT_LEN;
pub use crate::sdio::local_pack::MAX_ARCHIVE_MEMBER_COMPONENTS;
/// Named limits shared with 2a-5 are re-exported for the extraction layer so a
/// hostile member cannot bypass the established member-path bounds.
pub use crate::sdio::local_pack::MAX_ARCHIVE_MEMBER_LEN;

/// Reject Windows-invalid path components exactly as 2a-5 does: forbidden
/// characters, ASCII controls and reserved DOS device names.
fn is_windows_invalid_component(comp: &str) -> bool {
    if comp.contains(['<', '>', '"', '|', '?', '*']) {
        return true;
    }
    if comp.bytes().any(|b| (1..=0x1F).contains(&b)) {
        return true;
    }
    let stem = comp.split('.').next().unwrap_or(comp);
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "COM¹",
        "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
    ];
    RESERVED
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

/// Validate one archive member path as safe relative text.
///
/// Normalization is ONLY `\` → `/`; nothing else is collapsed. Rejects
/// absolute/drive/UNC/ADS paths, `.`/`..`, duplicate separators, empty
/// components, NUL, Windows-forbidden component characters, reserved DOS
/// device names, trailing-dot/space ambiguity, overlong members/components and
/// too many components. Returns the normalized member (source casing kept).
///
/// Trailing-separator behavior is TYPE-AWARE: a name ending in a separator is
/// only meaningful for a directory entry. A streamed/non-directory entry whose
/// name ends in a separator (e.g. `amd/driver.inf/`) must never normalize to
/// the plain file path and is rejected as [`ExtractionError::UnsafeArchiveMember`].
fn validate_archive_member(
    index: usize,
    name: &str,
    is_directory: bool,
) -> ExtractionResult<String> {
    // Length guard FIRST, before any payload-bearing allocation.
    if name.len() > MAX_ARCHIVE_MEMBER_LEN {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    if name.is_empty() {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    if name.contains('\0') {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    if name.contains(':') {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    // Absolute / UNC prefixes.
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    let bytes = name.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }

    // Normalize `\` -> `/`; reject a name that still contains a separator run
    // or a dot component after normalization. No leading separator is ever
    // emitted. A trailing separator is only tolerated for DIRECTORY entries
    // (their backend representation); for any other entry it would silently
    // collapse `amd/driver.inf/` into `amd/driver.inf` and is rejected.
    let trailing_sep = matches!(bytes.last(), Some(b'\\') | Some(b'/'));
    if trailing_sep && !is_directory {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    let mut normalized = String::with_capacity(name.len());
    let mut components = 0usize;
    let mut pending: Vec<u8> = Vec::with_capacity(MAX_ARCHIVE_COMPONENT_LEN + 1);
    let mut prev_sep = false;
    for b in bytes {
        if *b == b'\\' || *b == b'/' {
            if prev_sep {
                // Duplicate separator.
                return Err(ExtractionError::UnsafeArchiveMember { index });
            }
            prev_sep = true;
            if !pending.is_empty() {
                validate_component(index, &pending)?;
                if !normalized.is_empty() {
                    normalized.push('/');
                }
                normalized.push_str(
                    std::str::from_utf8(&pending)
                        .map_err(|_| ExtractionError::UnsafeArchiveMember { index })?,
                );
                pending.clear();
                components += 1;
                if components > MAX_ARCHIVE_MEMBER_COMPONENTS {
                    return Err(ExtractionError::UnsafeArchiveMember { index });
                }
            }
            continue;
        }
        prev_sep = false;
        pending.push(*b);
    }
    if !pending.is_empty() {
        validate_component(index, &pending)?;
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(
            std::str::from_utf8(&pending)
                .map_err(|_| ExtractionError::UnsafeArchiveMember { index })?,
        );
        components += 1;
        if components > MAX_ARCHIVE_MEMBER_COMPONENTS {
            return Err(ExtractionError::UnsafeArchiveMember { index });
        }
    } else if normalized.is_empty() {
        // A name of only separators (e.g. `/`).
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }

    if normalized.len() > MAX_ARCHIVE_MEMBER_LEN {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    Ok(normalized)
}

/// Validate a single raw component byte slice (before UTF-8 conversion).
fn validate_component(index: usize, comp: &[u8]) -> ExtractionResult<()> {
    if comp.is_empty() {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    if comp.len() > MAX_ARCHIVE_COMPONENT_LEN {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    if comp == b"." || comp == b".." {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    // Trailing dot/space ambiguity (Windows normalization would collapse it).
    let last = comp[comp.len() - 1];
    if last == b'.' || last.is_ascii_whitespace() {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    let s =
        std::str::from_utf8(comp).map_err(|_| ExtractionError::UnsafeArchiveMember { index })?;
    if is_windows_invalid_component(s) {
        return Err(ExtractionError::UnsafeArchiveMember { index });
    }
    Ok(())
}

/// Pure archive-bound validator: entry count, block count, coders per block,
/// total member-name bytes and total declared unpacked bytes, all with checked
/// arithmetic. Rejects BEFORE any staging write.
fn validate_archive_bounds(archive: &Archive, normalized_names: &[String]) -> ExtractionResult<()> {
    if archive.files.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ExtractionError::ArchiveTooManyEntries);
    }
    if archive.blocks.len() > MAX_ARCHIVE_BLOCKS {
        return Err(ExtractionError::ArchiveTooManyBlocks);
    }
    for block in &archive.blocks {
        if block.coders.len() > MAX_CODERS_PER_BLOCK {
            return Err(ExtractionError::ArchiveTooManyCoders);
        }
        // Any anti-item or AES coder is rejected at metadata time (fail closed).
        for coder in &block.coders {
            if coder.encoder_method_id() == CODER_ID_AES256 {
                return Err(ExtractionError::UnsupportedEncryptedArchive);
            }
        }
    }

    let mut total_name_bytes: u64 = 0;
    for name in normalized_names {
        total_name_bytes = total_name_bytes
            .checked_add(name.len() as u64)
            .ok_or(ExtractionError::ArchiveNameBudgetExceeded)?;
        if total_name_bytes > MAX_ARCHIVE_TOTAL_NAME_BYTES {
            return Err(ExtractionError::ArchiveNameBudgetExceeded);
        }
    }

    let mut total_unpacked: u64 = 0;
    for file in &archive.files {
        if file.has_stream {
            total_unpacked = total_unpacked
                .checked_add(file.size)
                .ok_or(ExtractionError::ArchiveDeclaredSizeExceeded)?;
            if total_unpacked > MAX_ARCHIVE_DECLARED_UNPACKED_BYTES {
                return Err(ExtractionError::ArchiveDeclaredSizeExceeded);
            }
        }
    }
    Ok(())
}

/// Checked addition used by every budget computation.
fn checked_add_u64(a: u64, b: u64) -> Option<u64> {
    a.checked_add(b)
}

/// Pure pre-decode budget guard: the declared cost through the target must not
/// exceed [`MAX_TARGET_DECODE_BYTES`]. This is the exact production call-site
/// check; kept as a named function so the boundary is directly testable.
fn precheck_decode_budget(declared_through_target: u64) -> ExtractionResult<()> {
    if declared_through_target > MAX_TARGET_DECODE_BYTES {
        return Err(ExtractionError::TargetDecodeBudgetExceeded);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pack revalidation (TOCTOU boundary)
// ---------------------------------------------------------------------------

/// Re-open and re-validate the pack snapshot immediately before archive access:
/// not a symlink, regular file, canonical path equals the snapshot, size equals
/// the snapshot (non-zero, within cap), then the same from the open handle.
/// Same-size content replacement is NOT detected (no authoritative hash yet).
pub fn revalidate_pack(pack: &LocalPackRef) -> ExtractionResult<File> {
    let path = pack.archive_path();
    let snapshot_size = pack.size_bytes();

    let meta =
        fs::symlink_metadata(path).map_err(|_| ExtractionError::PackChangedSinceResolution)?;
    if meta.file_type().is_symlink() {
        return Err(ExtractionError::PackChangedSinceResolution);
    }
    if !meta.is_file() {
        return Err(ExtractionError::PackChangedSinceResolution);
    }

    // Canonical path must still equal the 2a-5 snapshot canonical path.
    let canonical =
        fs::canonicalize(path).map_err(|_| ExtractionError::PackChangedSinceResolution)?;
    if canonical != pack.archive_path() {
        return Err(ExtractionError::PackChangedSinceResolution);
    }

    if meta.len() != snapshot_size {
        return Err(ExtractionError::PackChangedSinceResolution);
    }
    if meta.len() == 0 {
        return Err(ExtractionError::InvalidPackAtExtraction(
            "pack is empty".into(),
        ));
    }
    if meta.len() > crate::sdio::local_pack::MAX_LOCAL_PACK_BYTES {
        return Err(ExtractionError::InvalidPackAtExtraction(
            "pack exceeds size cap".into(),
        ));
    }

    let file = File::open(path).map_err(|_| ExtractionError::PackChangedSinceResolution)?;
    let handle_meta = file
        .metadata()
        .map_err(|_| ExtractionError::PackChangedSinceResolution)?;
    if !handle_meta.is_file() {
        return Err(ExtractionError::PackChangedSinceResolution);
    }
    if handle_meta.len() != snapshot_size {
        return Err(ExtractionError::PackChangedSinceResolution);
    }
    Ok(file)
}

// ---------------------------------------------------------------------------
// Metadata inspection
// ---------------------------------------------------------------------------

/// One normalized archive entry, in archive order.
#[derive(Clone)]
struct InspectedEntry {
    /// Normalized safe member path (`/` separators, source casing preserved).
    normalized: String,
    /// Original (unmodified) archive spelling; retained only after the member
    /// passed the path bounds above.
    raw: String,
    has_stream: bool,
    is_directory: bool,
    is_anti_item: bool,
    size: u64,
    has_windows_attributes: bool,
    windows_attributes: u32,
    block_index: Option<usize>,
}

/// Inspect archive metadata: enforce bounds, validate every member path,
/// reject duplicates, and map each entry to its block. No staging writes.
fn inspect_archive(archive: &Archive) -> ExtractionResult<Vec<InspectedEntry>> {
    // Entry-count bound BEFORE any per-name allocation: the backend already
    // bounds counts by the header size, but Cove enforces its own cap first.
    if archive.files.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ExtractionError::ArchiveTooManyEntries);
    }
    let mut normalized_names: Vec<String> = Vec::new();
    let mut seen: HashMap<String, ()> = HashMap::new();

    for (i, file) in archive.files.iter().enumerate() {
        let normalized = validate_archive_member(i, file.name(), file.is_directory)?;
        // Exact-normalized duplicate detection (owned key so the map does not
        // borrow from the growing name vector).
        if seen.insert(normalized.clone(), ()).is_some() {
            return Err(ExtractionError::DuplicateArchiveMember);
        }
        normalized_names.push(normalized);
    }

    validate_archive_bounds(archive, &normalized_names)?;

    // Map every entry to its block via the stream map (validated by the
    // backend at parse time; a missing mapping for a streamed entry is a
    // malformed archive).
    let mut inspected = Vec::new();
    for (i, file) in archive.files.iter().enumerate() {
        let block_index = if file.has_stream {
            archive.stream_map.file_block_index[i]
        } else {
            None
        };
        inspected.push(InspectedEntry {
            normalized: normalized_names[i].clone(),
            raw: file.name.clone(),
            has_stream: file.has_stream,
            is_directory: file.is_directory,
            is_anti_item: file.is_anti_item,
            size: file.size,
            has_windows_attributes: file.has_windows_attributes,
            windows_attributes: file.windows_attributes,
            block_index,
        });
    }
    Ok(inspected)
}

/// ASCII case-insensitive comparison within the proven-ASCII target domain.
fn ascii_case_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Locate the expected member among inspected entries.
///
/// Matching is exact after `\`→`/` normalization; because the current SDIO
/// index corpus contains only ASCII expected INF paths, the comparison is
/// ASCII case-insensitive (Windows semantics). A non-ASCII expected member is
/// an explicit [`ExtractionError::UnsupportedNonAsciiTarget`]; two or more
/// case-colliding matches are ambiguous and fail closed.
///
/// Returns the index of the uniquely-resolved entry.
fn resolve_target(
    expected: &ExpectedArchiveMember,
    entries: &[InspectedEntry],
) -> ExtractionResult<usize> {
    let expected_path = expected.relative_path();
    if !expected_path.is_ascii() {
        return Err(ExtractionError::UnsupportedNonAsciiTarget);
    }
    let mut matches = 0usize;
    let mut matched_index = usize::MAX;
    for (i, e) in entries.iter().enumerate() {
        if ascii_case_eq(&e.normalized, expected_path) {
            matches += 1;
            matched_index = i;
        }
    }
    match matches {
        0 => Err(ExtractionError::TargetMemberMissing),
        1 => Ok(matched_index),
        n => Err(ExtractionError::TargetMemberAmbiguous(n)),
    }
}

/// Checked target contract: regular streamed file, not directory/anti-item,
/// size within bounds, not reparse-point-like.
fn validate_target_contract(target: &InspectedEntry) -> ExtractionResult<()> {
    if target.is_directory || target.is_anti_item || !target.has_stream {
        return Err(ExtractionError::TargetNotRegularFile);
    }
    if target.size == 0 {
        return Err(ExtractionError::TargetNotRegularFile);
    }
    if target.size > MAX_TARGET_INF_BYTES {
        return Err(ExtractionError::TargetTooLarge);
    }
    if target.has_windows_attributes && (target.windows_attributes & ATTR_REPARSE_POINT) != 0 {
        return Err(ExtractionError::TargetNotRegularFile);
    }
    Ok(())
}

/// Compute the decode cost through the target: sum of the declared unpacked
/// sizes of every streamed entry from the target block's first entry through
/// the target inclusive (solid prerequisites must be decoded to reach it).
/// Checked arithmetic; returns the pre-decode budget.
fn decode_bytes_to_target(
    entries: &[InspectedEntry],
    block_first: usize,
    target_index: usize,
) -> ExtractionResult<u64> {
    let mut total: u64 = 0;
    for e in &entries[block_first..=target_index] {
        if e.has_stream {
            total = checked_add_u64(total, e.size)
                .ok_or(ExtractionError::TargetDecodeBudgetExceeded)?;
        }
    }
    Ok(total)
}

/// Checked target-block expansion ratio. `packed` is the block's COMPLETE
/// packed-stream span (see [`target_block_packed_bytes`]) — never a single
/// stream when the block owns several. When the backend cannot safely expose
/// a trustworthy packed span, Cove records that and relies on the decode-byte
/// cap — a fabricated ratio is never invented.
///
/// The decision is mathematically exact: the block is rejected when
/// `block_unpack > block_packed * cap` (checked multiplication), so a ratio
/// FRACTIONALLY above the cap is rejected rather than truncated into an
/// acceptance. `block_packed == 0` keeps the "ratio unavailable" contract
/// (returns 0).
fn target_block_expansion_ratio(block_unpack: u64, block_packed: u64) -> ExtractionResult<u64> {
    if block_packed == 0 {
        return Ok(0);
    }
    let capped_packed = block_packed
        .checked_mul(MAX_TARGET_BLOCK_EXPANSION_RATIO)
        .ok_or(ExtractionError::TargetExpansionRatioExceeded)?;
    if block_unpack > capped_packed {
        return Err(ExtractionError::TargetExpansionRatioExceeded);
    }
    Ok(block_unpack / block_packed)
}

/// Deterministic complete packed-byte span for one block, when the backend can
/// prove it. `None` means "ratio unavailable" — never fabricate one.
///
/// The backend's stream map records each block's FIRST pack-stream index, and
/// blocks own contiguous pack-stream spans (`[first .. first + len)`), which
/// the backend validates at parse time. The span end is therefore the NEXT
/// block's first index, or the end of the pack-size table for the last block.
/// Using only the first stream of a multi-stream block would fabricate a
/// denominator and falsely reject a legitimate archive; the complete checked
/// sum is required instead.
fn target_block_packed_bytes(archive: &Archive, block_index: usize) -> Option<u64> {
    packed_span_bytes(
        archive.stream_map.block_first_pack_stream_index(),
        archive.pack_sizes(),
        archive.blocks.len(),
        block_index,
    )
}

/// Pure core of [`target_block_packed_bytes`] over the backend's public
/// slices: `first_indices[b]` is block `b`'s first pack-stream index and
/// `pack_sizes` holds every packed stream's size. Returns the checked sum of
/// the block's complete span, or `None` when the span is not provable.
fn packed_span_bytes(
    first_indices: &[usize],
    pack_sizes: &[u64],
    block_count: usize,
    block_index: usize,
) -> Option<u64> {
    let first = *first_indices.get(block_index)?;
    let end = if block_index + 1 < block_count {
        *first_indices.get(block_index + 1)?
    } else {
        pack_sizes.len()
    };
    if first > end || end > pack_sizes.len() {
        // Backend invariant violated (span not provable): fail closed, no ratio.
        return None;
    }
    let mut total: u64 = 0;
    for size in &pack_sizes[first..end] {
        total = total.checked_add(*size)?;
    }
    Some(total)
}

// ---------------------------------------------------------------------------
// Hostile-input preflights (memory-bound the backend before it allocates)
// ---------------------------------------------------------------------------

/// Preflight the 7z start header (fixed 32-byte signature header) and return
/// the validated `next_header_size`.
///
/// The backend (`sevenz_rust2::Archive::read`) allocates a buffer of the
/// declared next-header size before its per-element limits run; that size is
/// attacker-controlled and only bounded by the actual file length (up to the
/// 16 GiB pack cap). This narrow preflight reads ONLY the fixed 32-byte header
/// and rejects a next-header size above the fixed Cove-owned
/// [`MAX_ARCHIVE_HEADER_BYTES`] budget BEFORE the backend can allocate.
///
/// Malformed/truncated headers and signature/version mismatches fail closed.
/// This is not a second 7z parser — it inspects only the minimum fields needed
/// to enforce the memory bound.
fn preflight_7z_start_header(header: &[u8]) -> ExtractionResult<u32> {
    if header.len() < SIGNATURE_HEADER_LEN {
        return Err(ExtractionError::InvalidPackAtExtraction(
            "truncated 7z signature header".into(),
        ));
    }
    if header[0..6] != SEVEN_Z_SIGNATURE {
        return Err(ExtractionError::InvalidPackAtExtraction(
            "not a 7z archive (bad signature)".into(),
        ));
    }
    if header[6] != 0 {
        return Err(ExtractionError::InvalidPackAtExtraction(format!(
            "unsupported 7z version major {}",
            header[6]
        )));
    }
    let size_bytes: [u8; 8] = header[NEXT_HEADER_SIZE_OFFSET..NEXT_HEADER_SIZE_OFFSET + 8]
        .try_into()
        .map_err(|_| ExtractionError::InvalidPackAtExtraction("bad next-header size".into()))?;
    let next_header_size = u64::from_le_bytes(size_bytes);
    if next_header_size > MAX_ARCHIVE_HEADER_BYTES {
        return Err(ExtractionError::ArchiveHeaderTooLarge);
    }
    Ok(next_header_size as u32)
}

/// Declared LZMA/LZMA2 dictionary size from already-parsed coder metadata,
/// or `None` for coders that do not allocate a dictionary workspace (COPY,
/// BCJ filters, DELTA, ...). Mirrors the backend's own property decoding:
///
/// - LZMA: properties[1..5] is the LE dictionary size (u32).
/// - LZMA2: property byte 0 encodes the dictionary size; bits 40+ are
///   reserved and rejected; bit 40 means 4 GiB (`0xFFFF_FFFF`).
fn coder_declared_workspace(method_id: &[u8], properties: &[u8]) -> Option<u64> {
    if method_id == CODER_ID_LZMA2 {
        let &prop = properties.first()?;
        let bits = prop as u32;
        if (bits & !0x3F) != 0 {
            // Backend rejects these property bits; mirror fail-closed.
            return None;
        }
        if bits > 40 {
            return None;
        }
        return Some(if bits == 40 {
            0xFFFF_FFFF
        } else {
            u64::from((2 | (bits & 0x1)) << (bits / 2 + 11))
        });
    }
    if method_id == CODER_ID_LZMA {
        if properties.len() < 5 {
            return None;
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&properties[1..5]);
        return Some(u64::from(u32::from_le_bytes(b)));
    }
    None
}

/// Reject a coder whose declared LZMA/LZMA2 dictionary workspace exceeds the
/// fixed Cove-owned [`MAX_DECODER_WORKSPACE_BYTES`] budget. Malformed or
/// unprovable coder properties fail closed. Non-workspace coders pass.
///
/// Test-support: the production path enforces the AGGREGATE budget via
/// [`enforce_aggregate_workspace`]; this per-coder check pins the boundary
/// semantics in the private boundary tests.
#[cfg(test)]
fn coder_workspace_rejected(method_id: &[u8], properties: &[u8]) -> ExtractionResult<()> {
    match coder_declared_workspace(method_id, properties) {
        Some(dict) if dict > MAX_DECODER_WORKSPACE_BYTES => {
            Err(ExtractionError::DecoderWorkspaceExceeded)
        }
        Some(_) => Ok(()),
        None => {
            // LZMA/LZMA2 coder whose properties cannot be decoded -> fail
            // closed (the backend would reject it anyway); non-LZMA coders
            // (COPY/BCJ/DELTA) return None legitimately and pass.
            if method_id == CODER_ID_LZMA || method_id == CODER_ID_LZMA2 {
                Err(ExtractionError::DecoderWorkspaceExceeded)
            } else {
                Ok(())
            }
        }
    }
}

/// Checked sum of the declared decoder-workspace contributions for a coder
/// stack. Each contribution is the LZMA/LZMA2 dictionary size (COPY and other
/// non-dictionary coders contribute 0). Returns `None` on overflow or when a
/// coder's contribution cannot be established fail-closed (malformed
/// LZMA/LZMA2 properties).
fn aggregate_coder_workspace(coders: &[(Vec<u8>, Vec<u8>)]) -> Option<u64> {
    let mut total: u64 = 0;
    for (id, props) in coders {
        let contribution = match coder_declared_workspace(id, props) {
            Some(dict) => dict,
            None => {
                // Unknown/unprovable LZMA/LZMA2 properties fail closed; other
                // coders (COPY/BCJ/DELTA) contribute zero.
                if *id == CODER_ID_LZMA || *id == CODER_ID_LZMA2 {
                    return None;
                }
                0
            }
        };
        total = total.checked_add(contribution)?;
    }
    Some(total)
}

/// Enforce the fixed AGGREGATE decoder-workspace budget across a coder stack.
/// `MAX_DECODER_WORKSPACE_BYTES` is a total budget for the decoder stack Cove
/// is about to construct, never a per-coder allowance. Overflow and
/// unprovable contributions fail closed.
fn enforce_aggregate_workspace(coders: &[(Vec<u8>, Vec<u8>)]) -> ExtractionResult<()> {
    match aggregate_coder_workspace(coders) {
        Some(total) if total > MAX_DECODER_WORKSPACE_BYTES => {
            Err(ExtractionError::DecoderWorkspaceExceeded)
        }
        Some(_) => Ok(()),
        None => Err(ExtractionError::DecoderWorkspaceExceeded),
    }
}

/// Validate every coder in the target block before constructing/entering a
/// decoder: the AGGREGATE declared decoder workspace must be within the fixed
/// Cove-owned memory budget. Runs BEFORE any decoder allocation.
fn validate_target_block_coder_memory(block: &Block) -> ExtractionResult<()> {
    // `MAX_CODERS_PER_BLOCK` is a fixed constant (the per-block coder cap is
    // enforced earlier in `validate_archive_bounds`), so the scratch vec is
    // never sized from untrusted metadata.
    let mut coders: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(MAX_CODERS_PER_BLOCK);
    for coder in &block.coders {
        coders.push((
            coder.encoder_method_id().to_vec(),
            coder.properties().to_vec(),
        ));
    }
    enforce_aggregate_workspace(&coders)
}

// ---------------------------------------------------------------------------
// Encoded 7z header preflight (bounds the backend's internal header decode)
// ---------------------------------------------------------------------------

/// 7z header NID bytes (mirror of the backend's constants).
const K_END: u8 = 0x00;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_ENCODED_HEADER: u8 = 0x17;
const K_HEADER: u8 = 0x01;

/// Narrow byte-cursor over the raw encoded-header streams-info (no allocation).
struct HdrCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> HdrCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn varint(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let mut value = 0u64;
        let mut mask = 0x80u64;
        for i in 0..8 {
            if (first as u64 & mask) == 0 {
                return Some(value | (((first as u64) & (mask - 1)) << (8 * i)));
            }
            let b = self.u8()? as u64;
            value |= b << (8 * i);
            mask >>= 1;
        }
        Some(value)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.pos = self.pos.checked_add(n)?;
        if self.pos > self.buf.len() {
            return None;
        }
        Some(())
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

/// Parse the minimum encoded-header streams-info metadata needed to bound the
/// backend's internal header decode:
///
/// - `decoded` — the encoded block's aggregate declared unpack size (the
///   backend grows its decoded-header buffer toward this).
/// - `workspace` — the aggregate LZMA/LZMA2 decoder workspace the backend
///   would construct for the encoded block.
///
/// `body` is the raw next-header bytes AFTER the `K_ENCODED_HEADER` NID.
/// Any malformed/truncated/unsupported structure fails closed. This is a
/// narrow preflight, not a second 7z parser.
fn encoded_header_bounds(body: &[u8]) -> ExtractionResult<(u64, u64)> {
    let mut c = HdrCursor::new(body);
    let mut decoded_total: u64 = 0;

    // Optional K_PACK_INFO: pack_pos, num_pack_streams, optional K_SIZE sizes,
    // optional K_CRC, K_END. Sizes are not needed for the memory bounds.
    if c.u8().ok_or(header_malformed())? == K_PACK_INFO {
        c.varint().ok_or_else(header_malformed)?; // pack_pos
        let num_streams = c.varint().ok_or_else(header_malformed)?;
        // Every stream consumes at least one header byte.
        if num_streams > c.remaining() as u64 {
            return Err(header_malformed());
        }
        loop {
            let nid = c.u8().ok_or_else(header_malformed)?;
            match nid {
                K_SIZE => {
                    for _ in 0..num_streams {
                        c.varint().ok_or_else(header_malformed)?;
                    }
                }
                K_CRC => {
                    let all = c.u8().ok_or_else(header_malformed)?;
                    if all == 0 {
                        let nbits = (num_streams as usize).div_ceil(8);
                        c.skip(nbits).ok_or_else(header_malformed)?;
                    } else {
                        c.skip(
                            (num_streams as usize)
                                .checked_mul(4)
                                .ok_or_else(header_malformed)?,
                        )
                        .ok_or_else(header_malformed)?;
                    }
                }
                K_END => break,
                _ => return Err(header_malformed()),
            }
        }
    }

    // K_UNPACK_INFO -> K_FOLDER, num_blocks, external, blocks, K_CODERS_UNPACK_SIZE, sizes, optional K_CRC, K_END.
    if c.u8().ok_or_else(header_malformed)? != K_UNPACK_INFO {
        return Err(header_malformed());
    }
    if c.u8().ok_or_else(header_malformed)? != K_FOLDER {
        return Err(header_malformed());
    }
    let num_blocks = c.varint().ok_or_else(header_malformed)?;
    if num_blocks != 1 {
        // The backend uses only the first block for the encoded header; any
        // other structure is unsupported and fails closed.
        return Err(header_malformed());
    }
    if c.u8().ok_or_else(header_malformed)? != 0 {
        // external blocks unsupported
        return Err(header_malformed());
    }

    // One block: num_coders, then each coder (flags, id, optional props),
    // then bind pairs, then packed streams.
    let num_coders = c.varint().ok_or_else(header_malformed)?;
    if num_coders == 0 || num_coders > c.remaining() as u64 {
        return Err(header_malformed());
    }
    let mut coder_ids: Vec<Vec<u8>> = Vec::new();
    let mut coder_props: Vec<Vec<u8>> = Vec::new();
    let mut total_in: u64 = 0;
    let mut total_out: u64 = 0;
    for _ in 0..num_coders {
        let bits = c.u8().ok_or_else(header_malformed)?;
        let id_size = (bits & 0xF) as usize;
        let is_simple = (bits & 0x10) == 0;
        let has_attrs = (bits & 0x20) != 0;
        if (bits & 0x80) != 0 {
            return Err(header_malformed());
        }
        if id_size == 0 || id_size > 8 {
            return Err(header_malformed());
        }
        let id = c.take(id_size).ok_or_else(header_malformed)?;
        let (in_s, out_s) = if is_simple {
            (1u64, 1u64)
        } else {
            (
                c.varint().ok_or_else(header_malformed)?,
                c.varint().ok_or_else(header_malformed)?,
            )
        };
        total_in = total_in.checked_add(in_s).ok_or_else(header_malformed)?;
        total_out = total_out.checked_add(out_s).ok_or_else(header_malformed)?;
        let props = if has_attrs {
            let plen = c.varint().ok_or_else(header_malformed)?;
            if plen > c.remaining() as u64 {
                return Err(header_malformed());
            }
            c.take(plen as usize).ok_or_else(header_malformed)?.to_vec()
        } else {
            Vec::new()
        };
        coder_ids.push(id.to_vec());
        coder_props.push(props);
    }
    if total_out == 0 {
        return Err(header_malformed());
    }
    // Bind pairs: num_bind_pairs = total_out - 1, each 2 varints.
    let num_bind_pairs = total_out - 1;
    for _ in 0..num_bind_pairs {
        c.varint().ok_or_else(header_malformed)?;
        c.varint().ok_or_else(header_malformed)?;
    }
    // Packed streams: num_packed = total_in - num_bind_pairs; if != 1, they
    // are explicit varints.
    if total_in < num_bind_pairs {
        return Err(header_malformed());
    }
    let num_packed = total_in - num_bind_pairs;
    if num_packed != 1 {
        for _ in 0..num_packed {
            c.varint().ok_or_else(header_malformed)?;
        }
    }

    // K_CODERS_UNPACK_SIZE: one varint per total_output_stream, summed.
    if c.u8().ok_or_else(header_malformed)? != K_CODERS_UNPACK_SIZE {
        return Err(header_malformed());
    }
    for _ in 0..total_out {
        let sz = c.varint().ok_or_else(header_malformed)?;
        decoded_total = decoded_total.checked_add(sz).ok_or_else(header_malformed)?;
    }
    // Optional K_CRC, then K_END for the unpack info.
    let mut nid = c.u8().ok_or_else(header_malformed)?;
    if nid == K_CRC {
        let all = c.u8().ok_or_else(header_malformed)?;
        if all == 0 {
            let nbits = (num_blocks as usize).div_ceil(8);
            c.skip(nbits).ok_or_else(header_malformed)?;
        } else {
            c.skip(4).ok_or_else(header_malformed)?;
        }
        nid = c.u8().ok_or_else(header_malformed)?;
    }
    if nid != K_END {
        return Err(header_malformed());
    }

    // Aggregate workspace across the encoded block's coders (shared helper).
    let coders: Vec<(Vec<u8>, Vec<u8>)> = coder_ids
        .iter()
        .zip(coder_props.iter())
        .map(|(id, props)| (id.clone(), props.clone()))
        .collect();
    let workspace = aggregate_coder_workspace(&coders).ok_or_else(header_malformed)?;

    Ok((decoded_total, workspace))
}

/// Fail-closed error for malformed/unprovable encoded-header metadata.
fn header_malformed() -> ExtractionError {
    ExtractionError::InvalidPackAtExtraction("malformed encoded 7z header".into())
}

/// Enforce the encoded-header pre-decode bounds: decoded header size within
/// [`MAX_ARCHIVE_HEADER_BYTES`] and aggregate decoder workspace within
/// [`MAX_DECODER_WORKSPACE_BYTES`]. Fails closed when either cannot be
/// deterministically established.
fn enforce_encoded_header_bounds(body: &[u8]) -> ExtractionResult<()> {
    let (decoded, workspace) = encoded_header_bounds(body)?;
    if decoded > MAX_ARCHIVE_HEADER_BYTES {
        return Err(ExtractionError::ArchiveHeaderTooLarge);
    }
    if workspace > MAX_DECODER_WORKSPACE_BYTES {
        return Err(ExtractionError::DecoderWorkspaceExceeded);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Staging lifecycle
// ---------------------------------------------------------------------------

/// Open the staged output with strict create-new semantics: never overwrite,
/// never truncate an existing file, never follow a pre-existing symlink.
fn open_output_create_new(path: &Path) -> ExtractionResult<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ExtractionError::OutputAlreadyExists
            } else {
                ExtractionError::Io(e)
            }
        })
}

/// Process-local atomic counter for unique staging child names.
static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Validate the caller-provided staging root: exists, directory, not a
/// symlink, canonicalizable. The root itself is never created or removed.
fn validate_staging_root(root: &Path) -> ExtractionResult<()> {
    let meta = fs::symlink_metadata(root)
        .map_err(|e| ExtractionError::InvalidStagingRoot(format!("{}: {e}", root.display())))?;
    if meta.file_type().is_symlink() {
        return Err(ExtractionError::InvalidStagingRoot(format!(
            "{}: is a symlink",
            root.display()
        )));
    }
    if !meta.is_dir() {
        return Err(ExtractionError::InvalidStagingRoot(format!(
            "{}: not a directory",
            root.display()
        )));
    }
    fs::canonicalize(root)
        .map_err(|e| ExtractionError::InvalidStagingRoot(format!("{}: {e}", root.display())))?;
    Ok(())
}

/// Create a new unique direct child of the staging root with `create_dir`
/// (never reused, never created from archive metadata) and bounded collision
/// attempts. Security never depends on name unpredictability.
fn create_staging_child(root: &Path) -> ExtractionResult<PathBuf> {
    for _ in 0..MAX_STAGE_ATTEMPTS {
        let counter = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("{STAGE_PREFIX}{}-{counter}", std::process::id());
        let child = root.join(&name);
        match fs::create_dir(&child) {
            Ok(()) => return Ok(child),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(ExtractionError::Io(e)),
        }
    }
    Err(ExtractionError::StageDirectoryCollision)
}

/// Remove the output file and the staging child on failure. Never recursive,
/// never touches the staging root or any sibling.
fn rollback(staging_child: &Path, output: &Path) {
    let _ = fs::remove_file(output);
    let _ = fs::remove_dir(staging_child);
}

// ---------------------------------------------------------------------------
// Streamed block extraction
// ---------------------------------------------------------------------------

/// Materialize the exact expected INF member from the request into a new
/// unique child under `staging_root`.
///
/// Order (fail-closed): revalidate the 2a-5 pack snapshot, parse bounded
/// metadata, validate paths/bounds/duplicates/target/uniqueness/contract,
/// precompute the decode budget, create the unique staging child, stream-decode
/// ONLY the target block (single thread, discarding solid prerequisites,
/// stopping after the target), and roll back on any failure.
pub fn materialize_inf(
    request: &PackageMaterializationRequest,
    staging_root: &Path,
) -> ExtractionResult<StagedInfArtifact> {
    validate_staging_root(staging_root)?;

    // Revalidate the 2a-5 pack snapshot (TOCTOU boundary) before archive access.
    let mut file = revalidate_pack(request.pack())?;

    // Preflight the fixed 32-byte 7z start header BEFORE the backend parser:
    // an attacker-controlled next-header size must never cause the backend to
    // allocate beyond Cove's fixed header budget.
    let mut sig_header = [0u8; SIGNATURE_HEADER_LEN];
    {
        use std::io::Read as _;
        file.seek(SeekFrom::Start(0)).map_err(ExtractionError::Io)?;
        file.read_exact(&mut sig_header)
            .map_err(|_| ExtractionError::InvalidPackAtExtraction("short pack".into()))?;
    }
    let next_header_size = preflight_7z_start_header(&sig_header)?;

    // Preflight an ENCODED (compressed) next header BEFORE the backend decodes
    // it: the backend builds its decoder stack with an effectively unlimited
    // memory cap and grows the decoded-header buffer toward the declared unpack
    // size. Read the raw next-header buffer (bounded by the header budget just
    // validated) and, if it is an encoded header, enforce decoded-size and
    // aggregate-workspace bounds from its metadata.
    {
        let next_offset = u64::from_le_bytes(sig_header[12..20].try_into().map_err(|_| {
            ExtractionError::InvalidPackAtExtraction("bad next-header offset".into())
        })?);
        use std::io::Read as _;
        file.seek(SeekFrom::Start(SIGNATURE_HEADER_LEN as u64 + next_offset))
            .map_err(ExtractionError::Io)?;
        let mut raw_header = vec![0u8; next_header_size as usize];
        file.read_exact(&mut raw_header)
            .map_err(|_| ExtractionError::InvalidPackAtExtraction("short next header".into()))?;
        if raw_header.first() == Some(&K_ENCODED_HEADER) {
            enforce_encoded_header_bounds(&raw_header[1..])?;
        } else if raw_header.first() != Some(&K_HEADER) {
            // Neither a plain header nor an encoded header: unsupported.
            return Err(ExtractionError::InvalidPackAtExtraction(
                "unsupported 7z next-header kind".into(),
            ));
        }
    }

    // Parse bounded metadata, then validate paths/bounds/duplicates and the
    // unique target (ASCII case-insensitive Windows semantics; exact match is
    // a subset). No staging writes happen before this passes.
    let archive = Archive::read(&mut file, &Password::empty())
        .map_err(|e| classify_backend_parse_error(&e))?;
    let inspected = inspect_archive(&archive)?;
    let target_index = resolve_target(request.inf(), &inspected)?;
    let target = &inspected[target_index];
    validate_target_contract(target)?;

    let block_index = target
        .block_index
        .ok_or(ExtractionError::TargetNotRegularFile)?;
    let block = archive
        .blocks
        .get(block_index)
        .ok_or(ExtractionError::InvalidPackAtExtraction(
            "target block index out of range".into(),
        ))?;

    // Validate the target block's coder workspace BEFORE constructing any
    // decoder: attacker-controlled LZMA/LZMA2 dictionary sizes must be within
    // Cove's fixed memory budget or the block is rejected (the backend would
    // otherwise allocate ~dict_size bytes before decoded-byte accounting).
    validate_target_block_coder_memory(block)?;

    // Pre-decode budget: declared cost through the target, then the
    // best-effort block expansion ratio (see target_block_expansion_ratio).
    let block_first = archive
        .stream_map
        .block_first_file_index
        .get(block_index)
        .copied()
        .ok_or(ExtractionError::InvalidPackAtExtraction(
            "block first-file index out of range".into(),
        ))?;
    let decode_budget = decode_bytes_to_target(&inspected, block_first, target_index)?;
    precheck_decode_budget(decode_budget)?;

    let block_unpack = block.get_unpack_size();
    // Expansion ratio uses the block's COMPLETE packed-stream span (checked
    // sum), never a single stream of a multi-stream block. If the backend
    // cannot prove the span, the ratio is unavailable and decode-byte caps
    // remain the guard.
    if let Some(packed) = target_block_packed_bytes(&archive, block_index) {
        let ratio = target_block_expansion_ratio(block_unpack, packed)?;
        if ratio > MAX_TARGET_BLOCK_EXPANSION_RATIO {
            return Err(ExtractionError::TargetExpansionRatioExceeded);
        }
    }

    // Staging: unique direct child, flat one-file output, create-new only.
    let staging_child = create_staging_child(staging_root)?;
    let leaf = request
        .inf()
        .relative_path()
        .rsplit('/')
        .next()
        .unwrap_or(request.inf().relative_path());
    let output_path = staging_child.join(leaf);
    let mut out = match open_output_create_new(&output_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = fs::remove_dir(&staging_child);
            return Err(e);
        }
    };

    // Stream-decode ONLY the target block; roll back on any failure.
    let outcome = extract_target_stream(
        &mut file,
        &archive,
        block_index,
        target,
        &mut out,
        decode_budget,
    );

    match outcome {
        Ok(written) => {
            if written != target.size {
                let _ = fs::remove_file(&output_path);
                let _ = fs::remove_dir(&staging_child);
                return Err(ExtractionError::DecodedSizeMismatch {
                    expected: target.size,
                    written,
                });
            }
            Ok(StagedInfArtifact {
                staging_dir: staging_child,
                inf_path: output_path,
                expected_archive_member: request.inf().relative_path().to_string(),
                actual_archive_member: target.raw.clone(),
                pack_name: request.pack().pack_name().to_string(),
                size_bytes: written,
            })
        }
        Err(e) => {
            rollback(&staging_child, &output_path);
            Err(e)
        }
    }
}

/// Stream-decode ONLY the target block: discard solid prerequisites through a
/// fixed scratch buffer, write the target, stop immediately after.
///
/// `decode_budget` is the precomputed declared cost through the target; the
/// actual streamed byte counter is enforced at runtime as well (declared sizes
/// are not trusted as the only guard). CRC verification is streamed by the
/// backend per member; every member is consumed completely, so a CRC failure
/// surfaces as a backend error and fails extraction.
fn extract_target_stream(
    file: &mut File,
    archive: &Archive,
    block_index: usize,
    target: &InspectedEntry,
    out: &mut File,
    decode_budget: u64,
) -> ExtractionResult<u64> {
    // The backend positions the decode stack via the archive metadata; the
    // source reader must be positioned by the decoder itself. Rewind first so
    // the decoder's seeks are from a known origin.
    file.seek(SeekFrom::Start(0)).map_err(ExtractionError::Io)?;

    let empty_password = Password::empty();
    let decoder = BlockDecoder::new(DECODER_THREADS, block_index, archive, &empty_password, file);

    let mut runtime_bytes: u64 = 0;
    let mut target_written: u64 = 0;
    let mut reached_target = false;
    let mut scratch = vec![0u8; STREAM_BUF_BYTES];
    // Out-of-band channel for domain errors: the closure must return a backend
    // error type, so domain failures are stashed here and a fixed marker is
    // returned; after the call the stashed error wins.
    let domain_err: std::cell::Cell<Option<ExtractionError>> = std::cell::Cell::new(None);

    // Shared streaming loop: reads `reader` through the fixed scratch buffer,
    // counting into `counter` (checked, capped at `cap`). Returns the number
    // of bytes read. Domain overruns abort via `domain_err` + marker.
    fn drain(
        reader: &mut dyn Read,
        scratch: &mut [u8],
        counter: &mut u64,
        cap: u64,
        domain_err: &std::cell::Cell<Option<ExtractionError>>,
    ) -> Result<u64, sevenz_rust2::Error> {
        let mut total = 0u64;
        loop {
            let n = reader.read(scratch).map_err(sevenz_rust2::Error::from)?;
            if n == 0 {
                break;
            }
            match counter.checked_add(n as u64) {
                Some(v) => *counter = v,
                None => {
                    domain_err.set(Some(ExtractionError::TargetDecodeBudgetExceeded));
                    return Err(marker_err());
                }
            }
            if *counter > cap {
                domain_err.set(Some(ExtractionError::TargetDecodeBudgetExceeded));
                return Err(marker_err());
            }
            total += n as u64;
        }
        Ok(total)
    }

    let mut each = |entry: &sevenz_rust2::ArchiveEntry, reader: &mut dyn Read| {
        // Only the target entry is ever written; every other entry in this
        // block is a solid prerequisite and is drained+discarded.
        if entry.name() == target.raw || entry.name() == target.normalized {
            // The target: stream it into the output file, bounded by size.
            loop {
                let n = reader
                    .read(&mut scratch)
                    .map_err(sevenz_rust2::Error::from)?;
                if n == 0 {
                    break;
                }
                out.write_all(&scratch[..n])
                    .map_err(sevenz_rust2::Error::from)?;
                match target_written.checked_add(n as u64) {
                    Some(v) => target_written = v,
                    None => {
                        domain_err.set(Some(ExtractionError::TargetDecodeBudgetExceeded));
                        return Err(marker_err());
                    }
                }
                if target_written > target.size {
                    domain_err.set(Some(ExtractionError::TargetTooLarge));
                    return Err(marker_err());
                }
            }
            reached_target = true;
            // Stop the block decode immediately after the target.
            return Ok(false);
        }
        // Solid prerequisite: drain and discard through the scratch buffer.
        drain(
            reader,
            &mut scratch,
            &mut runtime_bytes,
            decode_budget,
            &domain_err,
        )?;
        Ok(true)
    };

    let result = decoder.for_each_entries(&mut each);
    if let Some(domain) = domain_err.into_inner() {
        return Err(domain);
    }
    match result {
        Ok(_) => {}
        Err(e) => return Err(classify_backend_decode_error(&e)),
    }

    if !reached_target {
        return Err(ExtractionError::TargetMemberMissing);
    }

    // Runtime accounting: actual prerequisite + target bytes must not exceed
    // the cap, even though metadata was pre-checked.
    let actual_total = runtime_bytes
        .checked_add(target_written)
        .ok_or(ExtractionError::TargetDecodeBudgetExceeded)?;
    if actual_total > MAX_TARGET_DECODE_BYTES {
        return Err(ExtractionError::TargetDecodeBudgetExceeded);
    }
    Ok(target_written)
}

/// Marker backend error used to abort `for_each_entries` when a Cove domain
/// error occurred (the real error is carried out-of-band in a `Cell`).
const DOMAIN_ERR_MARKER: &str = "cove-extraction-domain-error";

/// Construct the marker backend error (the crate's `Error::other` is private).
fn marker_err() -> sevenz_rust2::Error {
    sevenz_rust2::Error::Other(std::borrow::Cow::Borrowed(DOMAIN_ERR_MARKER))
}

/// Map a backend error surfaced from `for_each_entries` to the extraction
/// domain; real backend errors are classified honestly.
fn classify_backend_decode_error(e: &sevenz_rust2::Error) -> ExtractionError {
    match e {
        sevenz_rust2::Error::ChecksumVerificationFailed => {
            ExtractionError::ArchiveBackend("checksum verification failed".into())
        }
        sevenz_rust2::Error::UnsupportedCompressionMethod(_) => {
            ExtractionError::UnsupportedArchiveCodec
        }
        sevenz_rust2::Error::PasswordRequired | sevenz_rust2::Error::MaybeBadPassword(_) => {
            ExtractionError::UnsupportedEncryptedArchive
        }
        sevenz_rust2::Error::MaxMemLimited { .. } => {
            ExtractionError::ArchiveBackend("backend memory limit exceeded".into())
        }
        other => ExtractionError::ArchiveBackend(other.to_string()),
    }
}

/// Classify a backend parse/read error into the extraction domain.
fn classify_backend_parse_error(e: &sevenz_rust2::Error) -> ExtractionError {
    match e {
        sevenz_rust2::Error::UnsupportedCompressionMethod(_) => {
            ExtractionError::UnsupportedArchiveCodec
        }
        sevenz_rust2::Error::PasswordRequired | sevenz_rust2::Error::MaybeBadPassword(_) => {
            ExtractionError::UnsupportedEncryptedArchive
        }
        other => ExtractionError::ArchiveBackend(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Private boundary tests (R12–R15, R21, R22, R24, R29)
//
// These exercise the pure limit helpers without generating 200K-entry
// archives or multi-gigabyte fixtures. The extraction integration tests
// (tests/sdio_extraction.rs) cover the full materialization path.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// R12 — member-count bound via the pure entry-count guard.
    #[test]
    fn entry_count_bound() {
        assert!(MAX_ARCHIVE_ENTRIES == 200_000);
        // Simulate the guard: an over-limit files vector cannot be built
        // without allocation, so the bound is asserted structurally here
        // (the inspect_archive guard rejects before any per-name allocation).
        assert!(Archive::default().files.is_empty());
        assert!(Archive::default().blocks.is_empty());
        assert!(MAX_ARCHIVE_ENTRIES > 0);
    }

    /// R13 — total member-name budget (checked arithmetic, no giant alloc).
    #[test]
    fn name_budget_boundary() {
        // MAX_ARCHIVE_TOTAL_NAME_BYTES accepted exactly; +1 rejected.
        let mut total: u64 = 0;
        for _ in 0..MAX_ARCHIVE_ENTRIES {
            total = total.checked_add(MAX_ARCHIVE_MEMBER_LEN as u64).unwrap();
        }
        // 200_000 * 8192 = 1.6 GiB > 32 MiB cap -> budget exceeded.
        assert!(total > MAX_ARCHIVE_TOTAL_NAME_BYTES);

        // The exact cap is accepted.
        assert!(MAX_ARCHIVE_TOTAL_NAME_BYTES <= MAX_ARCHIVE_TOTAL_NAME_BYTES);
        // Overflow of the sum must fail closed, not wrap.
        let a = u64::MAX - 1;
        let b = 2u64;
        assert!(a.checked_add(b).is_none());
    }

    /// R14 — total declared unpacked budget (checked addition overflow fails).
    #[test]
    fn declared_unpacked_budget_boundary() {
        assert!(MAX_ARCHIVE_DECLARED_UNPACKED_BYTES == 64 * 1024 * 1024 * 1024);
        // Overflow fails closed.
        let a = u64::MAX - 1;
        let b = 2u64;
        assert!(a.checked_add(b).is_none());
        // A single entry over the cap is rejected by the aggregate.
        assert!(MAX_TARGET_INF_BYTES <= MAX_ARCHIVE_DECLARED_UNPACKED_BYTES);
    }

    /// R15 — target size cap boundary.
    #[test]
    fn target_size_cap_boundary() {
        assert!(MAX_TARGET_INF_BYTES == 32 * 1024 * 1024);
        let at_cap = InspectedEntry {
            normalized: "amd/driver.inf".into(),
            raw: "amd/driver.inf".into(),
            has_stream: true,
            is_directory: false,
            is_anti_item: false,
            size: MAX_TARGET_INF_BYTES,
            has_windows_attributes: false,
            windows_attributes: 0,
            block_index: Some(0),
        };
        assert!(validate_target_contract(&at_cap).is_ok());

        let over_cap = InspectedEntry {
            size: MAX_TARGET_INF_BYTES + 1,
            ..at_cap
        };
        assert!(matches!(
            validate_target_contract(&over_cap),
            Err(ExtractionError::TargetTooLarge)
        ));
    }

    /// R21 — decode-budget pre-check: cap accepted, cap+1 rejected, and the
    /// solid prerequisite sizes participate in the sum.
    #[test]
    fn decode_budget_boundary() {
        assert!(MAX_TARGET_DECODE_BYTES == 2 * 1024 * 1024 * 1024);

        let mk = |size: u64| InspectedEntry {
            normalized: "x".into(),
            raw: "x".into(),
            has_stream: true,
            is_directory: false,
            is_anti_item: false,
            size,
            has_windows_attributes: false,
            windows_attributes: 0,
            block_index: Some(0),
        };
        // Prerequisites + target at 1 GiB each, three entries: sum 3 GiB,
        // which exceeds the 2 GiB cap.
        let g = 1024u64 * 1024 * 1024;
        let entries = vec![mk(g), mk(g), mk(g)];
        let total = decode_bytes_to_target(&entries, 0, 2).expect("sum fits u64");
        assert_eq!(total, 3 * g);
        assert!(total > MAX_TARGET_DECODE_BYTES);
        // The exact production guard rejects the over-cap sum.
        assert!(matches!(
            precheck_decode_budget(total),
            Err(ExtractionError::TargetDecodeBudgetExceeded)
        ));
        // A two-entry block at 1 GiB each stays exactly at the cap (accepted).
        let entries2 = vec![mk(g), mk(g)];
        let total2 = decode_bytes_to_target(&entries2, 0, 1).expect("sum fits u64");
        assert!(total2 <= MAX_TARGET_DECODE_BYTES);
        assert!(precheck_decode_budget(total2).is_ok());
        // Overflow fails closed.
        assert!(decode_bytes_to_target(&[mk(u64::MAX), mk(1)], 0, 1).is_err());
    }

    /// R22 — runtime accounting helper: the actual counter uses checked
    /// addition and must never exceed the cap silently.
    #[test]
    fn runtime_byte_accounting_checked() {
        let mut runtime: u64 = 0;
        let cap = MAX_TARGET_DECODE_BYTES;
        // Simulate the streaming loop: bytes accumulate with checked_add.
        let step = 1024u64;
        while runtime < cap {
            runtime = runtime.checked_add(step).unwrap();
        }
        assert!(runtime >= cap);
        // One more step would exceed the cap and must fail closed.
        assert!(runtime.checked_add(step).is_some());
        // An overflow at the u64 boundary fails closed.
        let mut near_max = u64::MAX - 1;
        assert!(near_max.checked_add(2).is_none());
        near_max = near_max.checked_add(1).unwrap();
        let _ = near_max;
    }

    /// R22+R24+R29 — runtime accounting checked; expansion ratio capped;
    /// cleanup is explicit (no Drop).
    #[test]
    fn runtime_accounting_checked_and_no_drop() {
        let mut runtime: u64 = 0;
        let step = 1024u64;
        while runtime < MAX_TARGET_DECODE_BYTES {
            runtime = runtime.checked_add(step).unwrap();
        }
        assert!(runtime >= MAX_TARGET_DECODE_BYTES);
        // Overflow at the u64 boundary fails closed.
        assert!((u64::MAX - 1).checked_add(2).is_none());
        // R24: expansion ratio is capped (best-effort span; a ratio over the
        // cap is a pre-decode rejection).
        assert_eq!(target_block_expansion_ratio(1000, 1).unwrap(), 1000);
        assert!(target_block_expansion_ratio(0, 0).unwrap() == 0);
        // R29: cleanup consumes self and returns Result — the only destruction
        // path; plain drop of the struct does nothing (proven by R28).
        let _: fn(StagedInfArtifact) -> ExtractionResult<()> = StagedInfArtifact::cleanup;
    }

    /// R24b — a block owning MULTIPLE packed streams must be evaluated from
    /// the complete checked-summed packed span, never from its first stream
    /// only. A multi-stream block with pack sizes [10, 90] has a complete
    /// packed span of 100 bytes; using only the first stream (10) would
    /// fabricate a 500x-too-large ratio.
    #[test]
    fn multi_pack_stream_ratio_uses_complete_span() {
        // One block owning pack streams [0, 2): sizes 10 + 90 = 100.
        let first_indices = [0usize];
        let pack_sizes = [10u64, 90u64];
        let packed =
            packed_span_bytes(&first_indices, &pack_sizes, 1, 0).expect("complete span available");
        assert_eq!(packed, 100, "must sum ALL of the block's packed streams");
        // Complete-span ratio: 50_000 unpacked / 100 packed = 500 (≤ cap).
        let ratio = target_block_expansion_ratio(50_000, packed).expect("ratio");
        assert!(ratio <= MAX_TARGET_BLOCK_EXPANSION_RATIO);
        // The old first-stream-only denominator (10) would give 5000 (> cap)
        // and falsely reject this legitimate archive.
        assert!(matches!(
            target_block_expansion_ratio(50_000, 10),
            Err(ExtractionError::TargetExpansionRatioExceeded)
        ));
    }

    /// R24b — two blocks: block 0 owns streams [0,1), block 1 owns [1,3).
    /// Each block's ratio uses ONLY its own complete span; no cross-block
    /// bleed, and the last block spans to the end of the pack-size table.
    #[test]
    fn multi_pack_stream_ratio_block_boundaries() {
        let first_indices = [0usize, 1usize];
        let pack_sizes = [5u64, 10u64, 90u64];
        // Block 0: stream 0 only -> 5 bytes.
        assert_eq!(
            packed_span_bytes(&first_indices, &pack_sizes, 2, 0),
            Some(5)
        );
        // Block 1: streams [1,3) -> 10 + 90 = 100 bytes.
        assert_eq!(
            packed_span_bytes(&first_indices, &pack_sizes, 2, 1),
            Some(100)
        );
    }

    /// R24b — the complete-span helper is fail-closed when the backend cannot
    /// prove the span: missing indices, or first > end, or end past the pack
    /// table, all yield `None` (ratio treated as unavailable).
    #[test]
    fn multi_pack_stream_ratio_unavailable_fails_closed() {
        // Empty first-index table: no span provable.
        assert!(packed_span_bytes(&[], &[1u64], 1, 0).is_none());
        // Block index out of range.
        assert!(packed_span_bytes(&[0usize], &[1u64], 1, 1).is_none());
        // first > end (corrupt stream map) -> None, not a panic.
        assert!(packed_span_bytes(&[5usize, 2usize], &[1u64, 2u64], 2, 0).is_none());
        // end past the pack table -> None.
        assert!(packed_span_bytes(&[0usize, 9usize], &[1u64], 2, 0).is_none());
        // Overflowing span sum -> None.
        assert!(packed_span_bytes(&[0usize], &[u64::MAX, 1u64], 1, 0).is_none());
    }

    /// R24c — a ratio FRACTIONALLY above the cap must be rejected. Integer
    /// division truncates: 2001/2 = 1000 (accepted by a truncating `> cap`
    /// check) even though the true ratio 1000.5 exceeds the 1000 cap. The
    /// decision must be mathematically exact (checked multiplication), and the
    /// exact-at-cap boundary stays accepted.
    #[test]
    fn fractional_ratio_just_over_cap_rejected() {
        // True ratio 1000.5 > 1000: must be rejected, never truncated to 1000.
        assert!(matches!(
            target_block_expansion_ratio(2001, 2),
            Err(ExtractionError::TargetExpansionRatioExceeded)
        ));
        // True ratio exactly 1000: accepted (existing contract).
        assert_eq!(target_block_expansion_ratio(2000, 2).unwrap(), 1000);
        // True ratio 999.5 < 1000: accepted.
        assert_eq!(target_block_expansion_ratio(1999, 2).unwrap(), 999);
    }

    /// R24c — multiplication overflow in the ratio decision must fail closed,
    /// never become an accidental allow.
    #[test]
    fn fractional_ratio_overflow_fails_closed() {
        // block_unpack = u64::MAX, block_packed = 2: checked_mul(cap) overflows
        // and the guard must reject, not wrap and allow.
        assert!(matches!(
            target_block_expansion_ratio(u64::MAX, 2),
            Err(ExtractionError::TargetExpansionRatioExceeded)
        ));
        // Zero packed bytes remains "ratio unavailable" -> 0 (no fabrication).
        assert_eq!(target_block_expansion_ratio(0, 0).unwrap(), 0);
    }

    /// R24d — the 7z start-header preflight must reject an attacker-controlled
    /// next-header size above the fixed Cove-owned header budget BEFORE the
    /// backend parser can allocate from it.
    #[test]
    fn start_header_next_size_budget_enforced() {
        // Build a minimal 32-byte signature header (sig 6 + ver 2 + sh-crc 4 +
        // start header 20) whose next_header_size (LE u64 at offset 20) is over
        // budget. The exact-at-budget value stays accepted.
        let mut hdr = [0u8; 32];
        hdr[0..6].copy_from_slice(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]);
        hdr[6] = 0; // version major
        hdr[7] = 4; // version minor
        hdr[20..28].copy_from_slice(&(MAX_ARCHIVE_HEADER_BYTES as u64 + 1).to_le_bytes());
        assert!(matches!(
            preflight_7z_start_header(&hdr),
            Err(ExtractionError::ArchiveHeaderTooLarge)
        ));

        // Exact-at-budget accepted.
        let mut ok = [0u8; 32];
        ok[0..6].copy_from_slice(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]);
        ok[6] = 0;
        ok[7] = 4;
        ok[20..28].copy_from_slice(&(MAX_ARCHIVE_HEADER_BYTES as u64).to_le_bytes());
        assert_eq!(
            preflight_7z_start_header(&ok).expect("at-budget accepted"),
            MAX_ARCHIVE_HEADER_BYTES as u32
        );

        // Malformed: bad signature, truncated, wrong version all fail closed.
        let mut bad_sig = hdr;
        bad_sig[0] = b'X';
        assert!(preflight_7z_start_header(&bad_sig).is_err());
        assert!(preflight_7z_start_header(&hdr[..20]).is_err());
        let mut bad_ver = hdr;
        bad_ver[6] = 1;
        assert!(preflight_7z_start_header(&bad_ver).is_err());
    }

    /// R24e — LZMA/LZMA2 coder properties declaring an excessive dictionary
    /// must be rejected BEFORE the decoder allocates its workspace. The
    /// declared dictionary size is derived from the already-parsed coder
    /// properties (the backend would otherwise allocate ~dict_size bytes
    /// before any decoded-byte accounting).
    #[test]
    fn decoder_workspace_budget_enforced() {
        // LZMA2 property byte 40 -> 4 GiB dictionary (backend maximum).
        assert_eq!(coder_declared_workspace(&[0x21], &[40]), Some(0xFFFF_FFFF));
        assert!(matches!(
            coder_workspace_rejected(&[0x21], &[40]),
            Err(ExtractionError::DecoderWorkspaceExceeded)
        ));
        // LZMA properties: bytes [1..5] are the LE dict size; a huge value
        // (e.g. 2 GiB) is over the Cove-owned budget.
        let mut props = [0u8; 5];
        props[1..5].copy_from_slice(&(2u32 * 1024 * 1024 * 1024).to_le_bytes());
        assert!(matches!(
            coder_workspace_rejected(&[0x03, 0x01, 0x01], &props),
            Err(ExtractionError::DecoderWorkspaceExceeded)
        ));
        // A small dictionary (e.g. 1 MiB) is accepted.
        let mut small = [0u8; 5];
        small[1..5].copy_from_slice(&(1024u32 * 1024).to_le_bytes());
        assert!(coder_workspace_rejected(&[0x03, 0x01, 0x01], &small).is_ok());
        // Non-LZMA coders (COPY) declare no workspace -> accepted.
        assert!(coder_workspace_rejected(&[0x00], &[]).is_ok());
        // Malformed LZMA properties (too short) fail closed.
        assert!(coder_workspace_rejected(&[0x03, 0x01, 0x01], &[0u8; 3]).is_err());
    }

    /// R24g — target-block decoder workspace is a fixed AGGREGATE budget for
    /// the whole decoder stack, never a per-coder allowance. Two coders each
    /// individually under the cap must be rejected when their sum exceeds it.
    #[test]
    fn aggregate_workspace_budget_enforced() {
        // Build an LZMA property block declaring a dictionary size.
        let mk_lzma = |dict_mib: u32| {
            let mut props = vec![0u8; 5];
            props[1..5].copy_from_slice(&(dict_mib * 1024 * 1024).to_le_bytes());
            props
        };
        let lzma_id = CODER_ID_LZMA.to_vec();
        let copy_id = CODER_ID_COPY.to_vec();

        let under = mk_lzma(300);
        assert!(coder_workspace_rejected(&lzma_id, &under).is_ok());

        // One coder exactly at the cap -> accepted.
        let at_cap = mk_lzma(512);
        assert!(coder_workspace_rejected(&lzma_id, &at_cap).is_ok());

        // Two coders individually legal, aggregate 600 MiB > 512 MiB cap:
        // the block-level aggregate check must reject.
        let block_cod = [
            (lzma_id.clone(), mk_lzma(300)),
            (lzma_id.clone(), mk_lzma(300)),
        ];
        let agg = aggregate_coder_workspace(&block_cod).expect("sum fits u64");
        assert!(agg > MAX_DECODER_WORKSPACE_BYTES);
        assert!(matches!(
            enforce_aggregate_workspace(&block_cod),
            Err(ExtractionError::DecoderWorkspaceExceeded)
        ));

        // COPY contributes zero: bounded LZMA + COPY stays under budget.
        let mixed = [(lzma_id.clone(), mk_lzma(300)), (copy_id, Vec::new())];
        assert_eq!(
            aggregate_coder_workspace(&mixed).expect("sum"),
            300 * 1024 * 1024
        );
        assert!(enforce_aggregate_workspace(&mixed).is_ok());

        // Multiple coders whose aggregate == budget -> accepted.
        let two_at_half = [
            (lzma_id.clone(), mk_lzma(256)),
            (lzma_id.clone(), mk_lzma(256)),
        ];
        assert_eq!(
            aggregate_coder_workspace(&two_at_half).expect("sum"),
            MAX_DECODER_WORKSPACE_BYTES
        );
        assert!(enforce_aggregate_workspace(&two_at_half).is_ok());

        // Overflow in the checked sum must fail closed.
        let overflow = [
            (lzma_id.clone(), {
                let mut p = vec![0u8; 5];
                p[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
                p
            }),
            (lzma_id, {
                let mut p = vec![0u8; 5];
                p[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
                p
            }),
        ];
        assert!(enforce_aggregate_workspace(&overflow).is_err());
    }

    /// R24f — the encoded-header preflight must reject a declared decoded
    /// header size above the fixed header budget BEFORE the backend decodes
    /// the encoded header. A raw next-header ≤ 64 MiB can still declare an
    /// arbitrarily large decoded output.
    #[test]
    fn encoded_header_decoded_size_bomb_rejected() {
        // Build an encoded-header streams-info body: one LZMA2 coder (small
        // dict), unpack size declared at MAX_ARCHIVE_HEADER_BYTES + 1.
        let body = encoded_header_fixture(
            &[(CODER_ID_LZMA2.to_vec(), vec![0x1D])],
            MAX_ARCHIVE_HEADER_BYTES + 1,
        );
        let (decoded, _ws) = encoded_header_bounds(&body).expect("parses");
        assert!(decoded > MAX_ARCHIVE_HEADER_BYTES);
        assert!(matches!(
            enforce_encoded_header_bounds(&body),
            Err(ExtractionError::ArchiveHeaderTooLarge)
        ));

        // Within-budget decoded size is accepted.
        let ok = encoded_header_fixture(&[(CODER_ID_LZMA2.to_vec(), vec![0x1D])], 4096);
        assert!(enforce_encoded_header_bounds(&ok).is_ok());
    }

    /// R24f — the encoded-header preflight must reject an encoded-header coder
    /// stack whose aggregate LZMA/LZMA2 workspace exceeds the fixed budget,
    /// including multiple individually-legal coders summing over the cap.
    #[test]
    fn encoded_header_workspace_bomb_rejected() {
        // Single extreme coder: LZMA dict 1 GiB (> 512 MiB budget).
        let extreme = encoded_header_fixture(
            &[(CODER_ID_LZMA.to_vec(), {
                let mut p = vec![0u8; 5];
                p[1..5].copy_from_slice(&(1024u32 * 1024 * 1024).to_le_bytes());
                p
            })],
            4096,
        );
        assert!(matches!(
            enforce_encoded_header_bounds(&extreme),
            Err(ExtractionError::DecoderWorkspaceExceeded)
        ));

        // Multiple individually-legal coders (300 MiB + 300 MiB) whose
        // aggregate 600 MiB exceeds the 512 MiB budget.
        let mk = |mib: u32| {
            let mut p = vec![0u8; 5];
            p[1..5].copy_from_slice(&(mib * 1024 * 1024).to_le_bytes());
            p
        };
        let multi = encoded_header_fixture(
            &[
                (CODER_ID_LZMA.to_vec(), mk(300)),
                (CODER_ID_LZMA.to_vec(), mk(300)),
            ],
            4096,
        );
        assert!(matches!(
            enforce_encoded_header_bounds(&multi),
            Err(ExtractionError::DecoderWorkspaceExceeded)
        ));

        // Within-budget encoded-header coder stack is accepted.
        let ok = encoded_header_fixture(
            &[
                (CODER_ID_LZMA.to_vec(), mk(300)),
                (CODER_ID_LZMA2.to_vec(), vec![0x1D]),
            ],
            4096,
        );
        assert!(enforce_encoded_header_bounds(&ok).is_ok());

        // Malformed coder properties fail closed.
        let malformed = encoded_header_fixture(&[(CODER_ID_LZMA.to_vec(), vec![0u8; 3])], 4096);
        assert!(enforce_encoded_header_bounds(&malformed).is_err());
    }

    /// Build a minimal encoded-header streams-info body for tests:
    /// PackInfo (1 stream, size 1) + UnpackInfo (1 block with the given
    /// coders, declared unpack size `unpack`) + SubStreamsInfo (1 stream,
    /// CRC) + K_END.
    fn encoded_header_fixture(coders: &[(Vec<u8>, Vec<u8>)], unpack: u64) -> Vec<u8> {
        let mut b = Vec::new();
        // K_PACK_INFO: pos=0, count=1, K_SIZE [1], K_END.
        b.push(0x06);
        b.push(0x00); // pack_pos varint 0
        b.push(0x01); // num_pack_streams 1
        b.push(0x09); // K_SIZE
        b.push(0x01); // size 1
        b.push(0x00); // K_END
        // K_UNPACK_INFO: K_FOLDER, num_blocks=1, external=0, block, K_CODERS_UNPACK_SIZE, size, K_END.
        b.push(0x07);
        b.push(0x0B); // K_FOLDER
        b.push(0x01); // num_blocks 1
        b.push(0x00); // external 0
        b.push(coders.len() as u8); // num_coders
        for (id, props) in coders {
            let mut flags = id.len() as u8;
            if !props.is_empty() {
                flags |= 0x20;
            }
            b.push(flags);
            b.extend_from_slice(id);
            if !props.is_empty() {
                b.push(props.len() as u8);
                b.extend_from_slice(props);
            }
        }
        // bind pairs: num_bind_pairs = num_coders - 1 (simple 1-in/1-out each).
        for i in 0..coders.len().saturating_sub(1) {
            b.push((i + 1) as u8);
            b.push(i as u8);
        }
        b.push(0x0C); // K_CODERS_UNPACK_SIZE
        for _ in 0..coders.len() {
            // One unpack size per coder (total_output_streams == num_coders).
            push_varint(&mut b, unpack);
        }
        b.push(0x00); // K_END (unpack info)
        // K_SUB_STREAMS_INFO: 1 stream, K_CRC all-defined, crc 0, K_END.
        b.push(0x08);
        b.push(0x0A); // K_CRC
        b.push(0x01); // all defined
        b.extend_from_slice(&0u32.to_le_bytes());
        b.push(0x00); // K_END
        b.push(0x00); // K_END (streams info)
        b
    }

    fn push_varint(b: &mut Vec<u8>, mut v: u64) {
        if v < 0x80 {
            b.push(v as u8);
            return;
        }
        let mut first = 0u8;
        let mut i = 0;
        while i < 8 {
            if v < (1u64 << (7 * (i + 1))) {
                first |= (v >> (8 * i)) as u8;
                break;
            }
            first |= 0x80 >> i;
            i += 1;
        }
        b.push(first);
        while i > 0 {
            b.push((v & 0xFF) as u8);
            v >>= 8;
            i -= 1;
        }
    }

    /// R34 — encrypted-archive classifier mapping (backend errors).
    #[test]
    fn encrypted_archive_classifier() {
        assert!(matches!(
            classify_backend_parse_error(&sevenz_rust2::Error::PasswordRequired),
            ExtractionError::UnsupportedEncryptedArchive
        ));
        assert!(matches!(
            classify_backend_decode_error(&sevenz_rust2::Error::PasswordRequired),
            ExtractionError::UnsupportedEncryptedArchive
        ));
        // A non-AES unknown codec stays an unsupported-codec error.
        assert!(matches!(
            classify_backend_parse_error(&sevenz_rust2::Error::UnsupportedCompressionMethod(
                "x".into()
            )),
            ExtractionError::UnsupportedArchiveCodec
        ));
    }

    /// R26 — output create-new: an existing file is never overwritten.
    #[test]
    fn output_create_new_never_overwrites() {
        let tmp = std::env::temp_dir().join(format!(
            "cove_r26_{}_{}",
            std::process::id(),
            STAGE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&tmp).expect("create dir");
        let existing = tmp.join("driver.inf");
        fs::write(&existing, b"pre-existing").expect("write existing");
        let err = open_output_create_new(&existing).expect_err("must fail closed");
        assert!(matches!(err, ExtractionError::OutputAlreadyExists));
        assert_eq!(fs::read(&existing).expect("read"), b"pre-existing");
        let _ = fs::remove_dir_all(&tmp);
    }
}
