//! Local SDIO driver-pack resolution + materialization-request boundary
//! (Tab 2a-5, Option C).
//!
//! Converts an already-discovered [`CatalogCandidateMatch`] into a narrowly
//! validated local-pack + expected-INF-archive-member request that a later
//! extraction layer can consume. This slice does **not** extract archives,
//! inspect archive members, parse INFs, validate CAT/signature/package trust,
//! or install anything.
//!
//! # Trust boundary
//!
//! The SDIO index is untrusted local metadata. A matching index entry must
//! NEVER be allowed to choose arbitrary filesystem paths. The only permitted
//! relationships are:
//!
//! ```text
//! validated pack stem -> <drivers_root>\<pack_stem>.7z   (direct child only)
//! validated INF dir   + validated INF leaf -> expected relative archive member
//! ```
//!
//! `pack_name`, `inf_path` and `inf_filename` are validated fail-closed before
//! any join; hostile input is rejected, never normalized into safety.
//!
//! # TOCTOU contract
//!
//! A successful [`LocalPackRef`] is a **bounded filesystem-resolution
//! snapshot**, not a permanent trust token. A later extraction layer
//! (Tab 2a-6) MUST reopen and revalidate the file immediately before archive
//! access. Nothing here implies "once resolved, forever safe".
//!
//! # Non-goals
//!
//! No networking, no download, no torrent, no archive parsing, no subprocess,
//! no 7z library, no install. No dependency changes: this module uses `std`
//! only. No directory enumeration and no fuzzy/version fallback: the index
//! names exactly one pack; its absence is the explicit [`LocalPackAvailability::Missing`]
//! state, never a nearest match.

use std::fs;
use std::path::{Path, PathBuf};

use crate::sdio::applicability::AssessedCatalogCandidate;
use crate::sdio::catalog::MAX_PACK_FILENAME_LEN;
use crate::sdio::matching::CatalogCandidateMatch;
use crate::sdio::matching::MAX_TOTAL_CANDIDATES;

// ---------------------------------------------------------------------------
// Named bounds
// ---------------------------------------------------------------------------

/// Maximum accepted local driver-pack size (filesystem metadata only; the pack
/// is never hashed or read in this slice). Baseline: 16 GiB, per Tab 2a-5.
/// Gate P5 found no legitimate current pack exceeding it.
pub const MAX_LOCAL_PACK_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Maximum total length (bytes) of the normalized archive member path.
pub const MAX_ARCHIVE_MEMBER_LEN: usize = 8192;
/// Maximum number of path components (directories + leaf) in an archive member.
pub const MAX_ARCHIVE_MEMBER_COMPONENTS: usize = 64;
/// Maximum length of one archive member path component.
pub const MAX_ARCHIVE_COMPONENT_LEN: usize = 255;

/// Maximum number of packs resolved in one batch helper call. Reuses the
/// established total-candidate bound; a batch must never exceed it.
pub const MAX_PACKS_PER_BATCH: usize = MAX_TOTAL_CANDIDATES;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A validated, filesystem-resolved reference to one local `.7z` driver pack.
///
/// **TOCTOU:** this is a bounded resolution snapshot taken at call time. The
/// archive may change afterwards; the future extraction layer must reopen and
/// revalidate the file immediately before archive access.
///
/// Invariant-bearing fields are private: instances can only be produced by the
/// validated resolver, so downstream code cannot fabricate a pack reference
/// with an arbitrary path or false size metadata (Codex round-12 finding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPackRef {
    pack_name: String,
    /// Canonical path of `<root>\<pack_name>.7z`.
    archive_path: PathBuf,
    /// Non-zero size in bytes, from filesystem metadata.
    size_bytes: u64,
}

impl LocalPackRef {
    pub fn pack_name(&self) -> &str {
        &self.pack_name
    }
    pub fn archive_path(&self) -> &Path {
        &self.archive_path
    }
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// One validated *expected* INF archive member. The member is NOT verified to
/// exist inside the archive; the archive layer must prove that later.
///
/// The path is invariant-bearing (validated relative member); instances are
/// only produced by [`expected_inf_member`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedArchiveMember {
    /// Normalized relative member path using `/` as the archive separator,
    /// source casing preserved.
    relative_path: String,
}

impl ExpectedArchiveMember {
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
}

/// A bounded materialization request: the exact local pack plus the expected
/// INF member inside it.
///
/// Contains no verified/trusted/signed/installable claims and no
/// catalog/trust metadata: the extracted INF becomes authoritative in the later
/// package-validation slice, so `Candidate::catalog_file` is deliberately not
/// carried here (Codex round-10 finding — an unbounded index-metadata clone
/// would break this boundary's boundedness).
///
/// Construction is restricted to the validated resolver; downstream code
/// cannot fabricate a request with an unvalidated member path or pack
/// reference (Codex round-12 finding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMaterializationRequest {
    pack: LocalPackRef,
    inf: ExpectedArchiveMember,
}

impl PackageMaterializationRequest {
    pub fn pack(&self) -> &LocalPackRef {
        &self.pack
    }
    pub fn inf(&self) -> &ExpectedArchiveMember {
        &self.inf
    }
}

/// Result of resolving one candidate's pack under an explicit drivers root.
///
/// A missing pack is a normal domain state under Option C (an index may exist
/// without the corresponding local pack), so it is a distinct variant rather
/// than an error for the whole batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalPackAvailability {
    Present(PackageMaterializationRequest),
    Missing {
        pack_name: String,
        expected_filename: String,
    },
}

// ---------------------------------------------------------------------------
// Errors (fail closed)
// ---------------------------------------------------------------------------

/// Explicit rejection reasons for local-pack resolution.
#[derive(Debug, thiserror::Error)]
pub enum LocalPackError {
    #[error("invalid drivers root: {0}")]
    InvalidDriversRoot(String),
    #[error("invalid pack name: {0:?}")]
    InvalidPackName(String),
    /// Payload-free: an overlong `pack_name` must not be cloned into the error
    /// (Codex round-13 finding).
    #[error("pack name exceeds max length of {MAX_PACK_FILENAME_LEN}")]
    PackNameTooLong,
    #[error("invalid INF directory path: {0:?}")]
    InvalidInfPath(String),
    #[error("invalid INF filename: {0:?}")]
    InvalidInfFilename(String),
    #[error("expected pack path is not a regular file: {0}")]
    PackNotRegularFile(PathBuf),
    #[error("expected pack path is a symbolic link: {0}")]
    PackSymlinkRejected(PathBuf),
    #[error("resolved pack escapes the configured drivers root: {0}")]
    PackEscapesRoot(PathBuf),
    #[error("expected pack is empty: {0}")]
    PackEmpty(PathBuf),
    #[error("expected pack exceeds size cap of {MAX_LOCAL_PACK_BYTES} bytes: {0}")]
    PackTooLarge(u64),
    #[error("archive member path exceeds max length of {MAX_ARCHIVE_MEMBER_LEN}")]
    ArchiveMemberTooLong,
    #[error("archive member has too many components (max {MAX_ARCHIVE_MEMBER_COMPONENTS})")]
    TooManyArchiveComponents,
    #[error("archive member component exceeds max length of {MAX_ARCHIVE_COMPONENT_LEN}")]
    ArchiveComponentTooLong,
    #[error("too many packs in one batch (max {MAX_PACKS_PER_BATCH})")]
    TooManyPacks,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience result alias for the local-pack layer.
pub type LocalPackResult<T> = std::result::Result<T, LocalPackError>;

// ---------------------------------------------------------------------------
// Pure validators (deterministic, no filesystem access)
// ---------------------------------------------------------------------------

/// Validate a pack stem as untrusted text, then build the exact expected
/// `.7z` filename: `<pack_name>.7z`.
///
/// Required: non-empty, within [`MAX_PACK_FILENAME_LEN`], ASCII-only, exactly
/// one filename stem, no `/`, no `\`, no `:`, no NUL, not `.`, not `..`, no
/// leading/trailing ASCII whitespace, no trailing dot. Hostile input is
/// rejected — never trimmed, never normalized. ASCII-only keeps the later
/// canonical-name containment check deterministic on Windows filesystems
/// (which case-fold Unicode names beyond Rust string comparison rules).
pub fn expected_pack_filename(pack_name: &str) -> LocalPackResult<String> {
    validate_pack_stem(pack_name)?;
    let mut name = String::with_capacity(pack_name.len() + 3);
    name.push_str(pack_name);
    name.push_str(".7z");
    Ok(name)
}

/// Windows-reserved DOS device names (case-insensitive, with or without an
/// extension). A file or directory named `CON`, `NUL`, `AUX`, `COM1`, etc.
/// would address the device namespace on Windows instead of a real path.
/// The superscript legacy spellings `COM¹/COM²/COM³` and `LPT¹/LPT²/LPT³`
/// are also device names on Windows (Codex round-9 finding).
const RESERVED_WINDOWS_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "COM¹", "COM²",
    "COM³", "LPT¹", "LPT²", "LPT³",
];

/// Reject Windows-invalid path components: forbidden characters `<>"|?*`,
/// ASCII control characters `U+0001..U+001F`, and reserved DOS device names
/// (Codex round-8/9 findings).
fn is_windows_invalid_component(comp: &str) -> bool {
    if comp.contains(['<', '>', '"', '|', '?', '*']) {
        return true;
    }
    if comp.bytes().any(|b| (1..=0x1F).contains(&b)) {
        return true;
    }
    let stem = comp.split('.').next().unwrap_or(comp);
    RESERVED_WINDOWS_NAMES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

/// Pure pack-stem validator shared by [`expected_pack_filename`].
fn validate_pack_stem(pack_name: &str) -> LocalPackResult<()> {
    if pack_name.is_empty() {
        return Err(LocalPackError::InvalidPackName(pack_name.to_string()));
    }
    // The stem plus the appended `.7z` must fit the Windows 255-unit component
    // limit, so the stem itself is capped at 252 bytes (255 - ".7z".len()).
    // Payload-free: the attacker-controlled string is never cloned here.
    if pack_name.len() > MAX_PACK_FILENAME_LEN - 4 {
        return Err(LocalPackError::PackNameTooLong);
    }
    if pack_name == "." || pack_name == ".." {
        return Err(LocalPackError::InvalidPackName(pack_name.to_string()));
    }
    // ASCII-only: Windows filesystems case-fold Unicode names with rules that
    // cannot be reproduced by a Rust string comparison, which would make the
    // canonical-name containment check non-deterministic. Every real SDIO pack
    // name is ASCII (`DP_*` + digits/underscores); Gate P5 found zero non-ASCII
    // names across the corpus (Codex round-6 finding).
    if !pack_name.is_ascii() {
        return Err(LocalPackError::InvalidPackName(pack_name.to_string()));
    }
    if is_windows_invalid_component(pack_name) {
        // Reserved DOS device name or forbidden Windows filename character.
        return Err(LocalPackError::InvalidPackName(pack_name.to_string()));
    }
    let bytes = pack_name.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    // Any ASCII whitespace at either end is rejected (space, tab, CR, LF,
    // vertical tab, form feed).
    if first.is_ascii_whitespace() || last.is_ascii_whitespace() {
        return Err(LocalPackError::InvalidPackName(pack_name.to_string()));
    }
    if last == b'.' {
        // Windows trailing-dot ambiguity.
        return Err(LocalPackError::InvalidPackName(pack_name.to_string()));
    }
    if pack_name.contains(['/', '\\', ':', '\0']) {
        return Err(LocalPackError::InvalidPackName(pack_name.to_string()));
    }
    Ok(())
}

/// Pure size-bound validator. `0` is rejected here (empty) so the filesystem
/// resolver and tests share one fail-closed rule; the resolver reports the
/// path-specific [`LocalPackError::PackEmpty`] for a zero-length file.
pub fn validate_pack_size(size_bytes: u64) -> LocalPackResult<()> {
    if size_bytes == 0 {
        // Callers map this to PackEmpty; the pure validator is shared by tests.
        return Err(LocalPackError::PackEmpty(PathBuf::new()));
    }
    if size_bytes > MAX_LOCAL_PACK_BYTES {
        return Err(LocalPackError::PackTooLarge(size_bytes));
    }
    Ok(())
}

/// Validate `inf_filename` as exactly one leaf `.inf` component.
fn validate_inf_leaf(inf_filename: &str) -> LocalPackResult<()> {
    if inf_filename.is_empty() {
        return Err(LocalPackError::InvalidInfFilename(inf_filename.to_string()));
    }
    if inf_filename.len() > MAX_ARCHIVE_COMPONENT_LEN {
        // The leaf is one archive component; it must respect the same
        // component-length bound as directory components.
        return Err(LocalPackError::ArchiveComponentTooLong);
    }
    if inf_filename.contains(['/', '\\', ':', '\0']) {
        return Err(LocalPackError::InvalidInfFilename(inf_filename.to_string()));
    }
    if is_windows_invalid_component(inf_filename) {
        // Reserved DOS device name or forbidden Windows filename character
        // (e.g. `NUL.inf`).
        return Err(LocalPackError::InvalidInfFilename(inf_filename.to_string()));
    }
    if inf_filename == "." || inf_filename == ".." {
        return Err(LocalPackError::InvalidInfFilename(inf_filename.to_string()));
    }
    if !inf_filename.to_ascii_lowercase().ends_with(".inf") {
        return Err(LocalPackError::InvalidInfFilename(inf_filename.to_string()));
    }
    Ok(())
}

/// Build the validated expected archive member from the candidate's INF
/// directory + leaf filename.
///
/// `inf_path` is the SDIO directory convention (Gate P5): components separated
/// by `\`, with a single trailing `\` as the directory terminator; the real
/// index values end in `\` (e.g. `amd\10x64\foo\`). An empty `inf_path` means
/// the archive root, so the member is just the leaf. A non-empty `inf_path`
/// without a trailing `\` is accepted verbatim as the directory text (the
/// corpus always carries the terminator; both forms map to the same member).
///
/// Normalization rule: ONLY `\` → `/`. Dot/dot-dot components (including
/// Windows-normalized equivalents ending in `.`/space), duplicate separators,
/// colons, absolute prefixes and NUL are rejected, never resolved or
/// collapsed. Case is preserved; nothing is Unicode-normalized.
pub fn expected_inf_member(
    inf_path: &str,
    inf_filename: &str,
) -> LocalPackResult<ExpectedArchiveMember> {
    // Absolute length guards FIRST, before any payload-bearing error clone: an
    // arbitrarily large malformed input must be rejected without cloning the
    // whole string into an error (Codex round-11 finding). The payload-free
    // variants keep the rejection bounded.
    if inf_path.len() > MAX_ARCHIVE_MEMBER_LEN {
        return Err(LocalPackError::ArchiveMemberTooLong);
    }
    if inf_filename.len() > MAX_ARCHIVE_COMPONENT_LEN {
        return Err(LocalPackError::ArchiveComponentTooLong);
    }
    if inf_path.contains('\0') {
        return Err(LocalPackError::InvalidInfPath(inf_path.to_string()));
    }
    if inf_filename.contains('\0') {
        return Err(LocalPackError::InvalidInfFilename(inf_filename.to_string()));
    }
    if inf_path.contains('/') {
        // Mixed/forward separators are rejected outright; only `\` is the
        // index separator and only `\` is normalized to `/`.
        return Err(LocalPackError::InvalidInfPath(inf_path.to_string()));
    }
    if inf_path.contains(':') {
        return Err(LocalPackError::InvalidInfPath(inf_path.to_string()));
    }
    if inf_filename.contains(':') {
        return Err(LocalPackError::InvalidInfFilename(inf_filename.to_string()));
    }
    // Absolute/UNC prefixes: leading separator or drive prefix.
    let bytes = inf_path.as_bytes();
    if inf_path.starts_with('\\') || inf_path.starts_with('/') {
        return Err(LocalPackError::InvalidInfPath(inf_path.to_string()));
    }
    if bytes.len() >= 2 && bytes[1] == b':' {
        return Err(LocalPackError::InvalidInfPath(inf_path.to_string()));
    }
    if inf_path.contains("\\\\") {
        return Err(LocalPackError::InvalidInfPath(inf_path.to_string()));
    }

    // A single trailing `\` is the directory terminator; strip it before
    // splitting so no empty component is produced.
    let dir = inf_path.strip_suffix('\\').unwrap_or(inf_path);

    let mut components: Vec<&str> = Vec::new();
    if !dir.is_empty() {
        for comp in dir.split('\\') {
            if comp.is_empty() {
                return Err(LocalPackError::InvalidInfPath(inf_path.to_string()));
            }
            if comp == "." || comp == ".." {
                return Err(LocalPackError::InvalidInfPath(inf_path.to_string()));
            }
            // Windows path normalization strips trailing dots/spaces from a
            // component, so `".. "` or `".. ."` would normalize into traversal
            // components at materialization time. Reject any component whose
            // last byte is `.` or ASCII whitespace (Codex round-4 finding).
            let last = comp.as_bytes()[comp.len() - 1];
            if last == b'.' || last.is_ascii_whitespace() {
                return Err(LocalPackError::InvalidInfPath(inf_path.to_string()));
            }
            // Windows-invalid components: forbidden characters and reserved
            // DOS device names (Codex round-8 finding).
            if is_windows_invalid_component(comp) {
                return Err(LocalPackError::InvalidInfPath(inf_path.to_string()));
            }
            if comp.len() > MAX_ARCHIVE_COMPONENT_LEN {
                return Err(LocalPackError::ArchiveComponentTooLong);
            }
            // Enforce the component-count bound BEFORE the push so an untrusted
            // input with millions of short components cannot force a large
            // allocation before rejection (Codex round-9 finding).
            if components.len() + 1 >= MAX_ARCHIVE_MEMBER_COMPONENTS {
                return Err(LocalPackError::TooManyArchiveComponents);
            }
            components.push(comp);
        }
    }
    validate_inf_leaf(inf_filename)?;

    let member = if components.is_empty() {
        inf_filename.to_string()
    } else {
        let mut joined = components.join("/");
        joined.push('/');
        joined.push_str(inf_filename);
        joined
    };
    if member.len() > MAX_ARCHIVE_MEMBER_LEN {
        return Err(LocalPackError::ArchiveMemberTooLong);
    }
    Ok(ExpectedArchiveMember {
        relative_path: member,
    })
}

// ---------------------------------------------------------------------------
// Filesystem resolver (explicit root, canonical containment)
// ---------------------------------------------------------------------------

/// Resolve the exact local pack for a matched candidate under an explicit root.
///
/// Root contract: the supplied root must exist, be a directory, and
/// canonicalize successfully; errors are explicit. The root is never created,
/// searched recursively, or replaced by a fallback (no CWD fallback, no drive
/// scan, no registry/config discovery).
///
/// Direct child only: only `<canonical_root>\<pack_name>.7z` is considered.
/// A nested or differently-versioned file is [`LocalPackAvailability::Missing`],
/// never a nearest match.
///
/// Present-pack validation: regular file, not a symlink (checked with
/// `symlink_metadata` before any link-following metadata), canonicalizes
/// successfully, canonical parent == canonical root, non-zero size, size <=
/// [`MAX_LOCAL_PACK_BYTES`]. Metadata only — the pack is never opened/read.
pub fn resolve_local_pack(
    drivers_root: &Path,
    matched: &CatalogCandidateMatch,
) -> LocalPackResult<LocalPackAvailability> {
    // Explicit root: must exist and be a directory.
    let root_meta = fs::symlink_metadata(drivers_root).map_err(|e| {
        LocalPackError::InvalidDriversRoot(format!("{}: {e}", drivers_root.display()))
    })?;
    if !root_meta.is_dir() {
        return Err(LocalPackError::InvalidDriversRoot(format!(
            "{}: not a directory",
            drivers_root.display()
        )));
    }
    let canonical_root = fs::canonicalize(drivers_root).map_err(|e| {
        LocalPackError::InvalidDriversRoot(format!("{}: {e}", drivers_root.display()))
    })?;

    let expected_filename = expected_pack_filename(&matched.pack_name)?;
    let expected_path = canonical_root.join(&expected_filename);

    // Validate the expected INF member FIRST so invalid candidate metadata
    // fails closed regardless of pack availability. An absent pack must never
    // turn malformed INF metadata into a plausible `Missing` result.
    let inf = expected_inf_member(&matched.candidate.inf_path, &matched.candidate.inf_filename)?;

    // Missing pack is a normal domain state.
    let child_meta = match fs::symlink_metadata(&expected_path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LocalPackAvailability::Missing {
                pack_name: matched.pack_name.clone(),
                expected_filename,
            });
        }
        Err(e) => return Err(LocalPackError::Io(e)),
    };

    // Reject symlinks before any link-following metadata read.
    if child_meta.file_type().is_symlink() {
        return Err(LocalPackError::PackSymlinkRejected(expected_path));
    }
    if !child_meta.is_file() {
        return Err(LocalPackError::PackNotRegularFile(expected_path));
    }

    // Canonical containment: canonical child parent == canonical root.
    let canonical_child = fs::canonicalize(&expected_path)?;
    let parent = canonical_child
        .parent()
        .ok_or_else(|| LocalPackError::PackEscapesRoot(canonical_child.clone()))?;
    if parent != canonical_root {
        return Err(LocalPackError::PackEscapesRoot(canonical_child));
    }
    // The canonical file name must still be the expected direct-child name. A
    // same-root sibling swap (e.g. a symlink inserted between the
    // `symlink_metadata` check and `canonicalize`) would change the canonical
    // name; a name-changing substitution is therefore rejected here. A
    // same-name swap within the TOCTOU window remains possible and is
    // explicitly deferred to Tab 2a-6's reopen/revalidate contract.
    //
    // Windows filesystems resolve names case-insensitively, so the comparison
    // is case-insensitive there (a pack stored as `dp_test_26000.7z` for a
    // request of `DP_Test_26000.7z` is the same file under Windows semantics);
    // on case-sensitive hosts the comparison stays exact (Codex round-5
    // finding).
    let canonical_name = canonical_child.file_name().and_then(|n| n.to_str());
    let name_matches = match canonical_name {
        Some(name) => names_equal_for_host(name, expected_filename.as_str()),
        None => false,
    };
    if !name_matches {
        return Err(LocalPackError::PackEscapesRoot(canonical_child));
    }

    let size_bytes = child_meta.len();
    if size_bytes == 0 {
        return Err(LocalPackError::PackEmpty(expected_path));
    }
    if size_bytes > MAX_LOCAL_PACK_BYTES {
        return Err(LocalPackError::PackTooLarge(size_bytes));
    }

    let pack = LocalPackRef {
        pack_name: matched.pack_name.clone(),
        archive_path: canonical_child,
        size_bytes,
    };

    Ok(LocalPackAvailability::Present(
        PackageMaterializationRequest { pack, inf },
    ))
}

/// Filesystem-aware file-name equality for the canonical-name containment
/// check. Windows resolves names case-insensitively; other hosts (Linux,
/// macOS with default settings) are case-sensitive.
fn names_equal_for_host(a: &str, b: &str) -> bool {
    #[cfg(windows)]
    {
        a.eq_ignore_ascii_case(b)
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

/// Convenience wrapper over [`resolve_local_pack`] accepting an assessed
/// candidate. Applicability evidence is preserved untouched; the resolver never
/// filters by applicability status (that policy belongs to orchestration).
pub fn resolve_assessed_pack(
    drivers_root: &Path,
    assessed: &AssessedCatalogCandidate,
) -> LocalPackResult<LocalPackAvailability> {
    resolve_local_pack(drivers_root, &assessed.matched)
}

/// Batch helper: resolve one pack per candidate, preserving input order
/// exactly (no sorting by availability/name/size). Bounded by
/// [`MAX_PACKS_PER_BATCH`]; over-limit batches fail closed. No recursion, no
/// parallel filesystem walking.
pub fn resolve_local_packs(
    drivers_root: &Path,
    matches: &[CatalogCandidateMatch],
) -> LocalPackResult<Vec<LocalPackAvailability>> {
    if matches.len() > MAX_PACKS_PER_BATCH {
        return Err(LocalPackError::TooManyPacks);
    }
    matches
        .iter()
        .map(|m| resolve_local_pack(drivers_root, m))
        .collect()
}
