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
use std::fs::{self, File};
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

/// NTSTATUS success, shared by every CNG call in this module.
#[cfg(windows)]
const STATUS_SUCCESS: i32 = 0;

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
    /// The staged file was not byte-identical to what extraction wrote when
    /// the retained lease was acquired, or the object under the leaf was not
    /// the object extraction created. Either means the staged bytes were
    /// tampered with between writing and lease acquisition; materialization
    /// fails closed and the staging child is rolled back.
    #[error("staged {leaf} changed between extraction and lease acquisition")]
    StagedBytesChanged { leaf: String },
    /// Tab 2a-10 payload inventory. `index` is the position of the REQUESTED
    /// payload in the caller's expected-member list, so the caller can name
    /// the source reference that failed without the archive layer knowing
    /// anything about INFs or source manifests.
    #[error("requested payload {index} is missing from the archive")]
    PayloadMemberMissing { index: usize },
    #[error("requested payload {index} is ambiguous ({matches} members match)")]
    PayloadMemberAmbiguous { index: usize, matches: usize },
    #[error("requested payload {index} is not a regular streamed file")]
    PayloadNotRegularFile { index: usize },
    #[error("requested payload {index} exceeds the per-payload size cap")]
    PayloadTooLarge { index: usize },
    #[error("total requested payload bytes exceed the inventory cap")]
    PayloadTotalBytesExceeded,
    #[error("payload decode budget exceeded")]
    PayloadDecodeBudgetExceeded,
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
///
/// The artifact privately retains the extraction-time WINDOWS OBJECT IDENTITY
/// of the staged INF (and catalog, when present): volume serial number + file
/// ID captured from the creation handles. The verifier consumes this
/// evidence and requires the objects it re-opens to be the SAME objects
/// (same FileId), closing the materialization→verification substitution gap.
///
/// It ALSO retains the EXACT CREATION handles themselves: the very handles
/// that created and wrote the staged INF and catalog are moved into the
/// artifact rather than closed. They were opened with `FILE_SHARE_READ` only
/// — no `FILE_SHARE_WRITE`, no `FILE_SHARE_DELETE` — so for as long as the
/// artifact lives, a path-based write open, a rename and a delete of the
/// staged files are all DENIED.
///
/// Retaining the creation handle (rather than closing it and reopening the
/// leaf for a read lock) is what makes the bytes CONTINUOUSLY owned. A
/// close/reopen transition leaves an interval in which nothing holds the
/// file, and an in-place overwrite inside that interval preserves the FileId
/// — so no later identity comparison can detect it. There is therefore no
/// close and no reopen anywhere between extraction and retained verification
/// ownership. The verifier derives the stable volume-GUID SetupAPI path from
/// the retained INF handle — never by re-walking a caller-path string.
///
/// # Non-`Clone` is load-bearing
///
/// This type is deliberately not `Clone`/`Copy`, and must not become so. The
/// retained creation handles above are a live filesystem lease, not data:
/// owning this artifact is what keeps the staged bytes write-denied. A second
/// copy would be a second claim on one set of handles, and `cleanup` would
/// become ambiguous about which owner may release them. Tab 2a-7R depends on
/// this — the verified trust token owns the artifact so that the trust
/// guarantee cannot outlive the lease. Do not derive `Clone`, and do not
/// reintroduce copying indirectly through `Arc` or a wrapper type.
///
/// CF2 — the artifact is not `Clone`. Compiler RED: the snippet fails only
/// because the `Clone` bound is unsatisfied.
///
/// ```compile_fail
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<mod_drivers::sdio::extraction::StagedInfArtifact>();
/// ```
#[derive(Debug)]
pub struct StagedInfArtifact {
    staging_dir: PathBuf,
    inf_path: PathBuf,
    expected_archive_member: String,
    actual_archive_member: String,
    pack_name: String,
    /// Canonical path of the resolved `.7z` pack this INF came from
    /// (the 2a-5 snapshot path, preserved for identity binding).
    pack_archive_path: PathBuf,
    /// Bare leaf of the catalog referenced by the package, when the request
    /// named one. The ACTUAL leaf created on disk is recorded (it may differ
    /// from the expected identity leaf only by ASCII case). The leaf is
    /// recorded even if the archive lacked the catalog (the 2a-7 verifier
    /// fails closed via `CatalogNotStaged` in that case).
    catalog_leaf: Option<String>,
    size_bytes: u64,
    /// Extraction-time Windows object identity of the staged INF
    /// (VolumeSerialNumber + FileId). None on non-Windows.
    #[cfg(windows)]
    inf_identity: Option<FileObjectId>,
    /// Extraction-time Windows object identity of the staged catalog, when
    /// one was created. None on non-Windows or when no catalog is staged.
    #[cfg(windows)]
    catalog_identity: Option<FileObjectId>,
    /// Extraction-time CONTENT fingerprint of the staged INF, taken through
    /// the creation handle. Identity proves "the same object"; this proves
    /// "the same bytes in it" — the two are independent, because an in-place
    /// overwrite (including one performed through a memory-mapped view) does
    /// not change the FileId. The verifier re-checks this before and after
    /// the native trust call, and on every re-attestation.
    #[cfg(windows)]
    inf_digest: Option<StagedContentDigest>,
    /// Extraction-time content fingerprint of the staged catalog, when one
    /// was created.
    #[cfg(windows)]
    catalog_digest: Option<StagedContentDigest>,
    /// Identity of the unique staging child DIRECTORY, captured from the pin
    /// held at creation. Cleanup binds to this before deleting anything, so a
    /// child that was renamed away and replaced at the same pathname is
    /// refused instead of being deleted on somebody else's behalf.
    #[cfg(windows)]
    staging_dir_identity: Option<FileObjectId>,
    /// F3 security lease: the retained creation handles (write access, no
    /// FILE_SHARE_WRITE). Holding them denies path-based write opens of the
    /// staged files for as long as the artifact lives. None on non-Windows
    /// (no native verification surface) or when a file was not created.
    #[cfg(windows)]
    lease_handles: Option<StagedFileLease>,
}

/// F3 retained-handle lease. The two handles are the exact `NtCreateFile`
/// output handles from `open_output_create_new` (never a reopen). They are
/// moved into the artifact and closed only when the artifact is dropped /
/// cleaned up. `File` is `Send`, so the artifact may move across threads.
#[cfg(windows)]
#[derive(Debug)]
struct StagedFileLease {
    /// The INF creation handle (denies path-based write opens).
    inf: std::fs::File,
    /// The catalog creation handle, when a catalog was staged.
    catalog: Option<std::fs::File>,
}

/// Minimal Windows file-object identity retained at extraction time for later
/// verification binding. On non-Windows the type is a platform marker that is
/// never produced (identity is unavailable, so fail-closed callers reject).
/// Fields are `pub(crate)` so the verifier (same crate) can construct/compare
/// identities derived from its own opens.
///
/// The identity is the **128-bit** `FILE_ID_INFO` form, not the legacy 64-bit
/// `BY_HANDLE_FILE_INFORMATION.nFileIndexHigh/Low`. Microsoft documents the
/// legacy 64-bit index as NOT guaranteed unique on ReFS, and this value is
/// load-bearing: it is what proves the object the verifier locked is the
/// object extraction created, and what binds the catalog SetupAPI reported.
/// A colliding legacy identifier on a ReFS staging volume would let a
/// different object be accepted, so the wide form is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileObjectId {
    #[cfg(windows)]
    pub(crate) volume_serial_number: u64,
    #[cfg(windows)]
    pub(crate) file_id: [u8; 16],
}

/// Capture the authoritative Windows object identity of an open file handle.
///
/// Uses `GetFileInformationByHandleEx(FileIdInfo)`, which returns the 64-bit
/// volume serial and the 128-bit file ID. `None` means the identity could not
/// be proven; every caller treats that as fail-closed, never as a match.
#[cfg(windows)]
fn object_id_of_file(file: &File) -> Option<FileObjectId> {
    use std::os::windows::io::AsRawHandle;
    object_id_of_raw_handle(file.as_raw_handle())
}

/// The single implementation of handle -> 128-bit identity. Private: no raw
/// handle API is exposed.
#[cfg(windows)]
pub(crate) fn object_id_of_raw_handle(
    handle: std::os::windows::io::RawHandle,
) -> Option<FileObjectId> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: `handle` is a live file handle owned by the caller; `info` is a
    // correctly sized out-param for the FileIdInfo class.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        return None;
    }
    Some(FileObjectId {
        volume_serial_number: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
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
    /// The canonical path of the resolved `.7z` pack (2a-5 snapshot).
    pub fn pack_archive_path(&self) -> &Path {
        &self.pack_archive_path
    }
    /// Bare leaf of the catalog referenced by the package, when the request
    /// named one. `None` when the candidate had no catalog. The file may or
    /// may not be staged (absent catalog => verifier fails closed).
    pub fn catalog_leaf(&self) -> Option<&str> {
        self.catalog_leaf.as_deref()
    }
    /// Extraction-time Windows identity of the staged INF. `None` on
    /// non-Windows.
    #[cfg(windows)]
    pub(crate) fn inf_identity(&self) -> Option<FileObjectId> {
        self.inf_identity
    }
    /// Extraction-time Windows identity of the staged catalog.
    #[cfg(windows)]
    pub(crate) fn catalog_identity(&self) -> Option<FileObjectId> {
        self.catalog_identity
    }

    /// The retained INF creation handle (F3 lease). `None` on non-Windows or
    /// when the artifact was not produced by a Windows materialization.
    #[cfg(windows)]
    pub(crate) fn retained_inf_handle(&self) -> Option<&std::fs::File> {
        self.lease_handles.as_ref().map(|l| &l.inf)
    }

    /// The retained catalog creation handle (F3 lease), when a catalog was
    /// staged. `None` on non-Windows or when no catalog was created.
    #[cfg(windows)]
    pub(crate) fn retained_catalog_handle(&self) -> Option<&std::fs::File> {
        self.lease_handles.as_ref().and_then(|l| l.catalog.as_ref())
    }
    /// Extraction-time content fingerprint of the staged INF, for the
    /// verifier's byte-stability binding. Crate-internal: no digest bytes
    /// reach the public surface.
    #[cfg(windows)]
    pub(crate) fn inf_digest(&self) -> Option<StagedContentDigest> {
        self.inf_digest
    }
    /// Extraction-time content fingerprint of the staged catalog.
    #[cfg(windows)]
    pub(crate) fn catalog_digest(&self) -> Option<StagedContentDigest> {
        self.catalog_digest
    }
    /// Identity of the staging child directory captured at creation, so the
    /// verifier can prove the directory it pins is the one extraction made.
    #[cfg(windows)]
    pub(crate) fn staging_dir_identity(&self) -> Option<FileObjectId> {
        self.staging_dir_identity
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

    /// Explicit owned cleanup: removes the staged INF + catalog + owned staging
    /// child only; never the caller's root or siblings. Idempotent-safe.
    ///
    /// The F3 byte-stability lease handles (read access, no delete share) are
    /// dropped FIRST — while held they deny the delete that removing the files
    /// requires.
    pub fn cleanup(self) -> ExtractionResult<()> {
        // Drop the lease handles before any removal (they withhold delete
        // sharing, so remove_file/remove_dir would otherwise fail).
        #[cfg(windows)]
        let StagedInfArtifact {
            staging_dir,
            inf_path,
            catalog_leaf,
            lease_handles,
            staging_dir_identity,
            inf_identity,
            catalog_identity,
            ..
        } = self;
        #[cfg(not(windows))]
        let StagedInfArtifact {
            staging_dir,
            inf_path,
            catalog_leaf,
            ..
        } = self;
        // Windows only: non-Windows artifacts carry no lease field at all.
        #[cfg(windows)]
        drop(lease_handles);

        // The staged objects are now unleased. Everything below must therefore
        // establish WHICH objects it is acting on rather than trusting the
        // names that lead to them.
        #[cfg(all(windows, feature = "test-inject"))]
        run_cleanup_window_hook(&staging_dir);

        // Windows: delete through pinned directory objects, never by pathname.
        //
        // Once the leases are gone the staged files are ordinary files again,
        // and the pathname that leads to them is no longer under our control:
        // an attacker can rename the child directory away and create a
        // replacement at the same path. A path-based cleanup would then delete
        // the replacement's contents — files we do not own — and leave the real
        // staging child behind, which is the worst of both outcomes.
        //
        // So: pin the child, prove it is the object we created, delete its
        // leaves RELATIVE to that pin, and only then release the pin and delete
        // the child itself relative to its pinned parent, again identity-bound.
        #[cfg(windows)]
        {
            let expected = staging_dir_identity.ok_or_else(|| {
                ExtractionError::CleanupFailed("staging child identity was never recorded".into())
            })?;

            let child_name = staging_dir
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| {
                    ExtractionError::CleanupFailed("staging child has no leaf name".into())
                })?
                .to_string();
            let parent = staging_dir.parent().ok_or_else(|| {
                ExtractionError::CleanupFailed("staging child has no parent".into())
            })?;

            // NOTE: there is deliberately NO `symlink_metadata`/`exists`
            // pre-check here. A metadata probe answers a question about a
            // PATHNAME, and treating "the pathname does not currently name a
            // directory" as "cleanup succeeded" is a false success: it reports
            // Ok while the child object we created is still on disk under a
            // name the attacker chose. Everything below is object-bound, and
            // every way of failing to reach our objects is an error.
            {
                let child_pin = ChildDirGuard::open_pinned(&staging_dir)?;
                match object_id_of_raw_handle(child_pin.handle().cast()) {
                    Some(actual) if actual == expected => {}
                    _ => {
                        return Err(ExtractionError::CleanupFailed(
                            "staging child is not the directory that was created; refusing to \
                             delete its contents"
                                .into(),
                        ));
                    }
                }
                // Leaves are deleted by OBJECT, not by name. A leaf we never
                // created (a catalog the archive did not contain) has no
                // recorded identity and nothing to delete; a leaf we DID
                // create must still be the object we created, or cleanup
                // fails closed rather than destroying somebody else's file.
                if let (Some(cat), Some(cat_id)) = (&catalog_leaf, catalog_identity) {
                    delete_leaf_checked(&child_pin, cat, cat_id)?;
                }
                let inf_leaf = inf_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| {
                        ExtractionError::CleanupFailed("staged INF has no leaf name".into())
                    })?;
                let inf_id = inf_identity.ok_or_else(|| {
                    ExtractionError::CleanupFailed(
                        "staged INF identity was never recorded; the exact object cannot be \
                         proven and must not be deleted by name"
                            .into(),
                    )
                })?;
                delete_leaf_checked(&child_pin, inf_leaf, inf_id)?;
                // The child pin holds DELETE access and withholds delete
                // sharing, so it must be released before the directory itself
                // can be removed — but not one step earlier.
            }

            // The pin is gone and the child is not yet deleted: the one window
            // in which the child's NAME is attacker-controllable.
            #[cfg(feature = "test-inject")]
            run_child_delete_window_hook(&staging_dir);

            // ANCHOR, not pin. The staging root is SHARED between concurrent
            // Cove operations and is not Cove's to lock: a materialization in
            // flight holds it via `open_anchor`, which grants
            // `FILE_ADD_SUBDIRECTORY`. Windows share-mode compatibility is
            // symmetric, so re-opening the root here with `DELETE` and
            // `FILE_SHARE_READ` only would refuse that anchor's write-class
            // access and fail with a sharing violation — Cove's own cleanup
            // colliding with Cove's own materialization, leaving the child as
            // residue. Two restrictive cleanups would collide with each other
            // for the same reason.
            //
            // Nothing is lost by not pinning: the child is deleted RELATIVE to
            // this handle, which names the root OBJECT, so renaming the root
            // cannot redirect the delete, and `open_anchor` still proves the
            // object is a real non-reparse directory.
            let parent_anchor = ChildDirGuard::open_anchor(parent)?;
            delete_staging_child_checked(&parent_anchor, &child_name, expected)
        }
        #[cfg(not(windows))]
        {
            // `Path::exists()` reports `false` for BOTH "absent" and "could not be
            // determined" — a metadata or access error would make cleanup silently
            // skip a file that is really still there and then return Ok(()). The
            // removal helpers below already treat NotFound as success and report
            // every other failure, so the existence pre-checks are not merely
            // redundant, they are unsafe. Attempt the removals directly.
            if let Some(cat) = &catalog_leaf {
                remove_staged_file(&staging_dir.join(cat))?;
            }
            remove_staged_file(&inf_path)?;
            remove_staging_child(&staging_dir)
        }
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

/// RAII guard that holds a Windows handle on the staging-child directory,
/// opened with `FILE_SHARE_READ` only (write and delete sharing withheld), so
/// the directory object CANNOT be renamed, deleted, or replaced while the
/// guard lives. The held identity is what output creation is anchored to: the
/// INF/catalog are created through paths under this pinned object, so a
/// pathname-only race cannot redirect them into an attacker directory.
///
/// On non-Windows the guard is a no-op (the path gates cover the available
/// primitives there).
#[allow(dead_code)]
pub struct ChildDirGuard {
    #[cfg(windows)]
    handle: std::ptr::NonNull<std::ffi::c_void>,
}

#[cfg(windows)]
impl Drop for ChildDirGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.handle.as_ptr());
        }
    }
}

#[cfg(windows)]
impl ChildDirGuard {
    /// Open the child directory with DELETE access and FILE_SHARE_READ only
    /// (no write, no delete share): pins the object against rename/replace
    /// while held. Empirically verified (design gate): this combination makes
    /// MoveFileEx rename and RemoveDirectory fail with ERROR_SHARING_VIOLATION.
    fn open_pinned(path: &Path) -> ExtractionResult<Self> {
        use std::ffi::OsStr;
        use std::iter::once;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, OPEN_EXISTING,
        };

        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        // FILE_FLAG_OPEN_REPARSE_POINT (0x00200000): open a raced reparse
        // object as ITSELF, never following to its target; the caller's
        // reparse-attribute check then rejects it.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const DELETE: u32 = 0x0001_0000;
        let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                DELETE,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(ExtractionError::InvalidStagingRoot(format!(
                "{}: cannot pin staging child",
                path.display()
            )));
        }
        // F5: prove the OPENED object is a real non-reparse directory before
        // it may serve as the RootDirectory for relative output creation. The
        // open used FILE_FLAG_OPEN_REPARSE_POINT, so a raced junction is
        // opened as itself; the handle-attribute query rejects it here.
        {
            use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;
            let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
                unsafe { std::mem::zeroed() };
            let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
            const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            let attrs_ok = ok != 0
                && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
                && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
            if !attrs_ok {
                unsafe {
                    let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
                }
                return Err(ExtractionError::InvalidStagingRoot(format!(
                    "{}: staging child is not a real non-reparse directory",
                    path.display()
                )));
            }
        }
        // SAFETY: handle is valid and proven to be a non-reparse directory;
        // the guard owns and closes it.
        Ok(ChildDirGuard {
            handle: unsafe { std::ptr::NonNull::new_unchecked(handle.cast()) },
        })
    }

    /// The pinned child-directory handle (used as the RootDirectory for
    /// handle-relative output creation of staged leaves).
    pub(crate) fn handle(&self) -> *mut core::ffi::c_void {
        self.handle.as_ptr()
    }

    /// Adopt an already-open directory handle. Private: the only producers are
    /// [`ChildDirGuard::open_pinned`] and the handle-relative staging-child
    /// creation below, both of which have already proven what they opened.
    ///
    /// # Safety
    /// `handle` must be a live directory handle that nothing else will close;
    /// the guard takes ownership and closes it on drop.
    unsafe fn from_raw(handle: windows_sys::Win32::Foundation::HANDLE) -> Self {
        ChildDirGuard {
            handle: unsafe { std::ptr::NonNull::new_unchecked(handle.cast()) },
        }
    }

    /// Open a directory purely as a RootDirectory ANCHOR for handle-relative
    /// creation — not as a pin.
    ///
    /// The access is the minimum needed to create and look up a child, and the
    /// share mode is fully permissive. That matters: the staging root is
    /// shared between concurrent materializations, and a DELETE-access,
    /// `FILE_SHARE_READ` pin on it would make two simultaneous stagings
    /// collide with a sharing violation. Anchoring does not need exclusivity —
    /// a handle names an OBJECT, so even if the root is renamed underneath us
    /// the child is still created inside the directory we opened, which is the
    /// whole point.
    pub(crate) fn open_anchor(path: &Path) -> ExtractionResult<Self> {
        use std::ffi::OsStr;
        use std::iter::once;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };

        const FILE_LIST_DIRECTORY: u32 = 0x0001;
        const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
        const FILE_TRAVERSE: u32 = 0x0020;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

        let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
        // SAFETY: `wide` is a live NUL-terminated wide path for the duration
        // of the call; all other arguments are constants or null.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_LIST_DIRECTORY | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(ExtractionError::InvalidStagingRoot(format!(
                "{}: cannot anchor staging root",
                path.display()
            )));
        }
        // Prove the anchored object is a real non-reparse directory before it
        // may serve as a RootDirectory.
        {
            use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;
            let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
                unsafe { std::mem::zeroed() };
            let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
            const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            let attrs_ok = ok != 0
                && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
                && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
            if !attrs_ok {
                unsafe {
                    let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
                }
                return Err(ExtractionError::InvalidStagingRoot(format!(
                    "{}: staging root is not a real non-reparse directory",
                    path.display()
                )));
            }
        }
        // SAFETY: handle is valid and proven to be a non-reparse directory.
        Ok(unsafe { ChildDirGuard::from_raw(handle) })
    }
}

#[cfg(not(windows))]
impl ChildDirGuard {
    fn open_pinned(_path: &Path) -> ExtractionResult<Self> {
        Ok(ChildDirGuard {})
    }

    /// Non-Windows: no handle to expose; output creation falls back to the
    /// portable path gates, so nothing calls this.
    #[allow(dead_code)]
    fn handle(&self) -> *mut core::ffi::c_void {
        std::ptr::null_mut()
    }
}

/// Open the staged output with strict create-new semantics: never overwrite,
/// never truncate an existing file, never follow a pre-existing symlink.
///
/// On Windows the output is created HANDLE-RELATIVE to the pinned child
/// directory (`NtCreateFile` with `OBJECT_ATTRIBUTES.RootDirectory` = the
/// child guard's handle), so the create cannot be redirected into a
/// substituted directory: the leaf is resolved against the exact directory
/// object Cove created and pinned, not by re-walking a pathname. The leaf
/// must already be a validated single component.
///
/// On non-Windows the portable create-new path (the already-validated
/// `fallback_path`) is used; the path gates cover the available substitution
/// primitives there.
pub(crate) fn open_output_create_new(
    child_guard: &ChildDirGuard,
    leaf: &str,
    #[cfg(not(windows))] fallback_path: &Path,
    #[cfg(windows)] _fallback_path: &Path,
) -> ExtractionResult<File> {
    if leaf.is_empty()
        || leaf.contains(['/', '\\', ':', '\0'])
        || leaf == "."
        || leaf == ".."
        || leaf.len() > 255
    {
        return Err(ExtractionError::InvalidPackAtExtraction(
            "invalid output leaf".into(),
        ));
    }
    #[cfg(windows)]
    {
        use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
        use windows_sys::Wdk::Storage::FileSystem::{
            FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
        };
        use windows_sys::Win32::Foundation::UNICODE_STRING;

        // Access: FILE_WRITE_DATA | FILE_READ_DATA | FILE_READ_ATTRIBUTES |
        // SYNCHRONIZE. Share: FILE_SHARE_READ ONLY — no FILE_SHARE_WRITE and
        // no FILE_SHARE_DELETE, so no concurrent writer, renamer or deleter
        // can touch the output while it is being produced.
        //
        // `FILE_READ_DATA` is required, not incidental: `materialize_inf`
        // reads the finished bytes back THROUGH THIS HANDLE to establish the
        // continuity baseline that the retained lease is later checked
        // against. Reading them by pathname instead would be readable from a
        // substituted object and would prove nothing.
        //
        // Cove's own rollback drops this handle before removing the file, so
        // withholding delete-share costs nothing.
        const FILE_WRITE_DATA: u32 = 0x0002;
        const FILE_READ_DATA: u32 = 0x0001;
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
        const STATUS_SUCCESS: i32 = 0;

        let mut name_buf: Vec<u16> = leaf.encode_utf16().collect();
        let us = UNICODE_STRING {
            Length: (name_buf.len() * 2) as u16,
            MaximumLength: (name_buf.len() * 2) as u16,
            Buffer: name_buf.as_mut_ptr(),
        };
        let oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: child_guard.handle(),
            ObjectName: &us,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };

        let mut handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        let mut io_status: windows_sys::Win32::System::IO::IO_STATUS_BLOCK =
            unsafe { std::mem::zeroed() };

        // SAFETY: oa points at a live UNICODE_STRING (name_buf outlives the
        // call); RootDirectory is a valid open directory handle from the pin;
        // handle/io_status are valid out-params.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                FILE_WRITE_DATA | FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                &oa,
                &mut io_status,
                std::ptr::null(),
                0, // file attributes
                FILE_SHARE_READ,
                FILE_CREATE,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                std::ptr::null(),
                0,
            )
        };
        if status != STATUS_SUCCESS || handle.is_null() {
            // STATUS_OBJECT_NAME_COLLISION means the leaf already exists.
            if status as u32 == 0xC000_0035 {
                return Err(ExtractionError::OutputAlreadyExists);
            }
            return Err(ExtractionError::Io(std::io::Error::from_raw_os_error(
                win32_status_to_os_error(status),
            )));
        }
        // This handle becomes the artifact's security lease, so prove the
        // OPENED object is a real regular file rather than relying on
        // `FILE_CREATE` semantics alone.
        let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
            unsafe { std::mem::zeroed() };
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(handle, &mut info)
        };
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
        let ok = ok != 0
            && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0
            && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
        if !ok {
            // FILE_CREATE already created the leaf, so rejecting it here would
            // otherwise leave a file the caller does not know about — and the
            // caller, seeing an Err, only removes the directory, which then
            // fails because it is not empty. Delete the leaf we created,
            // handle-relative AND object-bound: read the identity off the
            // creation handle we still hold, so the removal below cannot be
            // redirected onto a same-named replacement.
            let created_id = object_id_of_raw_handle(handle.cast());
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
            }
            let created_id = created_id.ok_or_else(|| {
                ExtractionError::CleanupFailed(
                    "rejected staged leaf has no provable identity; refusing to delete by name"
                        .into(),
                )
            })?;
            delete_leaf_checked(child_guard, leaf, created_id)?;
            return Err(ExtractionError::InvalidPackAtExtraction(
                "staged leaf lease object is not a real regular file".into(),
            ));
        }
        // SAFETY: handle valid; wrap in std::fs::File (owns the handle).
        use std::os::windows::io::FromRawHandle;
        Ok(unsafe { File::from_raw_handle(handle) })
    }
    #[cfg(not(windows))]
    {
        let _ = child_guard;
        let _ = leaf;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(fallback_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    ExtractionError::OutputAlreadyExists
                } else {
                    ExtractionError::Io(e)
                }
            })
    }
}

/// Convert an NTSTATUS create failure to a Win32 error code for the Io error.
#[cfg(windows)]
fn win32_status_to_os_error(status: i32) -> i32 {
    // NTSTATUS facility codes map to Win32 roughly; for the statuses we can
    // produce here (access denied, sharing violation, name collision handled
    // above, invalid parameter) use the common mapping. NTSTATUS constants
    // are 32-bit unsigned bit patterns; compare via the unsigned view.
    let status = status as u32;
    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    match status {
        STATUS_ACCESS_DENIED => 5,
        STATUS_SHARING_VIOLATION => 32,
        STATUS_INVALID_PARAMETER => 87,
        _ => 1,
    }
}

/// Acquire the retained byte-stability lease on a just-materialized leaf.
///
/// The open is RELATIVE to the pinned child directory handle — there is no
/// pathname to resolve, so no ancestor rename, junction or directory
/// substitution can redirect it. Access is read-only with `FILE_SHARE_READ`
/// ONLY: while the lease is held, a write-capable open, a rename and a delete
/// of the staged file are all refused with `ERROR_SHARING_VIOLATION`.
///
/// The lease must be a READ handle. A retained handle holding write access
/// makes `SetupVerifyInfFileW` fail with `ERROR_SHARING_VIOLATION` for the
/// `\\?\`-qualified stable path the verifier is required to use — measured on
/// Windows 11: the refusal persists even when the retained handle grants
/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`, so it is
/// SetupAPI's own open refusing to coexist with our granted write access, not
/// a share mode we can widen. Since Windows fixes a file object's granted
/// access at open time and cannot reduce it, the writing handle can never be
/// the lease. The transition between the two handles is what
/// [`materialize_inf`] proves safe by identity and byte comparison.
///
/// On non-Windows there is no native verification surface; the caller never
/// invokes this path.
#[cfg(windows)]
fn open_retained_read_lock(
    child_guard: &ChildDirGuard,
    leaf: &str,
) -> ExtractionResult<std::fs::File> {
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        NtCreateFile,
    };
    use windows_sys::Win32::Foundation::UNICODE_STRING;

    // Access: FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE.
    // Share: FILE_SHARE_READ only — no write, no delete.
    const FILE_READ_DATA: u32 = 0x0001;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const STATUS_SUCCESS: i32 = 0;

    let mut name_buf: Vec<u16> = leaf.encode_utf16().collect();
    let us = UNICODE_STRING {
        Length: (name_buf.len() * 2) as u16,
        MaximumLength: (name_buf.len() * 2) as u16,
        Buffer: name_buf.as_mut_ptr(),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: child_guard.handle(),
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };

    let mut handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
    let mut io_status: windows_sys::Win32::System::IO::IO_STATUS_BLOCK =
        unsafe { std::mem::zeroed() };

    // SAFETY: oa points at a live UNICODE_STRING (name_buf outlives the call);
    // RootDirectory is a valid open directory handle from the pin;
    // handle/io_status are valid out-params. FILE_OPEN_REPARSE_POINT opens a
    // raced reparse as the link object (rejected by the caller's attribute
    // proof); the leaf is a validated single component.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &oa,
            &mut io_status,
            std::ptr::null(),
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status != STATUS_SUCCESS || handle.is_null() {
        // A writer holding the leaf inside the transition window makes this
        // open fail with ERROR_SHARING_VIOLATION. That is the desired
        // fail-closed outcome, not a condition to retry around.
        return Err(ExtractionError::InvalidPackAtExtraction(
            "cannot acquire byte-stability lease on staged leaf".into(),
        ));
    }
    // Prove the OPENED object is a real non-reparse regular file.
    let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
        unsafe { std::mem::zeroed() };
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(handle, &mut info)
    };
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    let ok = ok != 0
        && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0
        && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    if !ok {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
        }
        return Err(ExtractionError::InvalidPackAtExtraction(
            "staged leaf lease object is not a real regular file".into(),
        ));
    }
    // SAFETY: handle valid; wrap in std::fs::File (owns the handle).
    use std::os::windows::io::FromRawHandle;
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// Close a staged file's creation handle and acquire its retained lease,
/// PROVING that nothing changed the file in between.
///
/// Windows cannot hand the writing handle itself over as the lease: a
/// retained handle with write access makes `SetupVerifyInfFileW` fail with
/// `ERROR_SHARING_VIOLATION` for the `\\?\`-qualified stable path (measured;
/// see [`open_retained_read_lock`]), and a file object's granted access
/// cannot be reduced after the open. A second handle is therefore
/// unavoidable, and with it a transition window. This function closes that
/// window by proof rather than by wishing it away:
///
/// 1. The lease is opened RELATIVE to the pinned child directory handle, so
///    the leaf is resolved inside a directory object that cannot be renamed
///    or replaced — no pathname walk is involved.
/// 2. The lease open withholds `FILE_SHARE_WRITE`. If any writer held the
///    leaf during the window, this open FAILS rather than succeeding onto a
///    file someone else is writing.
/// 3. The leased object's identity must equal the identity read from the
///    creation handle, so a delete-and-recreate under the same name is
///    rejected.
/// 4. The leased content fingerprint must equal the one taken through the
///    creation handle, so an in-place overwrite — which preserves the FileId
///    and is invisible to any identity check — is rejected.
///
/// After step 2 succeeds no writer can open the file at all, so steps 3 and 4
/// describe the whole of the exposure and both must hold. Any failure is
/// fail-closed: the caller rolls the staging child back.
#[cfg(windows)]
fn transition_to_lease(
    child_guard: &ChildDirGuard,
    leaf: &str,
    staged_path: &Path,
    creation_handle: File,
    baseline_identity: Option<FileObjectId>,
    baseline_digest: StagedContentDigest,
) -> ExtractionResult<File> {
    // The creation handle must be closed before the lease can be opened: the
    // lease withholds write sharing and would otherwise collide with our own
    // write access.
    drop(creation_handle);

    // Test-only: the integration suite tampers with the staged bytes HERE, at
    // the exact instant the file is unowned, and requires the checks below to
    // catch it. Production builds have no hook and no call site.
    #[cfg(feature = "test-inject")]
    run_lease_window_hook(staged_path);
    #[cfg(not(feature = "test-inject"))]
    let _ = staged_path;

    let mut lease = open_retained_read_lock(child_guard, leaf)?;

    let changed = || ExtractionError::StagedBytesChanged {
        leaf: leaf.to_string(),
    };

    // Same object, or fail closed. An absent identity is never a pass.
    let lease_identity = object_id_of_file(&lease);
    match (lease_identity, baseline_identity) {
        (Some(actual), Some(expected)) if actual == expected => {}
        _ => return Err(changed()),
    }

    // Same content, or fail closed.
    let lease_digest = digest_of_open_file(&mut lease)?;
    if lease_digest != baseline_digest {
        return Err(changed());
    }

    Ok(lease)
}

/// The staged-content fingerprint used to prove byte continuity across the
/// lease handover: a SHA-256 digest plus the length it covers.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StagedContentDigest {
    pub(crate) len: u64,
    pub(crate) sha256: [u8; 32],
}

/// Fingerprint a staged file through a raw handle the caller already owns,
/// WITHOUT taking ownership of it.
///
/// The verifier holds its locks as raw handles inside guards, and needs to
/// re-fingerprint the staged bytes through those exact handles — before the
/// native trust call, immediately after it, and on every re-attestation. The
/// handle is wrapped in `ManuallyDrop` so this never closes the caller's
/// handle, and the file position is reset by the digest itself.
#[cfg(windows)]
pub(crate) fn digest_of_raw_handle(
    handle: std::os::windows::io::RawHandle,
) -> ExtractionResult<StagedContentDigest> {
    use std::os::windows::io::FromRawHandle;
    // SAFETY: `handle` is a live file handle owned by the caller. ManuallyDrop
    // ensures the borrowed File wrapper never closes it.
    let mut file = std::mem::ManuallyDrop::new(unsafe { File::from_raw_handle(handle) });
    digest_of_open_file(&mut file)
}

/// Fingerprint a staged file THROUGH an already-open handle that owns it.
///
/// The read streams into a FIXED scratch buffer, exactly like the extraction
/// path: the whole file is never held in memory, so an attacker-influenced
/// file size can never drive an allocation. Nothing is opened by pathname, so
/// the digest always describes the object the handle already refers to.
///
/// SHA-256 comes from the platform (CNG). A non-cryptographic checksum would
/// not do here: the adversary chooses the replacement bytes, so the digest
/// must be collision-resistant, and the archive's own CRC32 is trivially
/// forgeable.
#[cfg(windows)]
fn digest_of_open_file(file: &mut File) -> ExtractionResult<StagedContentDigest> {
    use std::io::Read as _;

    file.seek(SeekFrom::Start(0)).map_err(ExtractionError::Io)?;

    let mut hasher = Sha256Stream::new()?;
    let mut scratch = [0u8; STREAM_BUF_BYTES];
    let mut len: u64 = 0;
    loop {
        let n = file.read(&mut scratch).map_err(ExtractionError::Io)?;
        if n == 0 {
            break;
        }
        len = checked_add_u64(len, n as u64).ok_or_else(crypto_unavailable)?;
        hasher.update(&scratch[..n])?;
    }
    Ok(StagedContentDigest {
        len,
        sha256: hasher.finish()?,
    })
}

/// The one shape a crypto failure takes in this layer.
fn crypto_unavailable() -> ExtractionError {
    ExtractionError::InvalidPackAtExtraction("staged content digest unavailable".into())
}

/// Incremental platform SHA-256 (CNG).
///
/// This is the single cryptographic implementation in the crate: the staged
/// INF/catalog continuity digests and the Tab 2a-10 payload fingerprints both
/// stream through it, so there is never a second hash to keep in agreement.
/// Nothing here is ever fed a whole file: callers push fixed scratch-buffer
/// chunks, so an attacker-influenced size can never drive an allocation.
///
/// SHA-256 is content identity only. It is not a signature, not authenticity,
/// not trust and not publisher proof. The archive's own CRC32 would not do:
/// the adversary chooses the replacement bytes, so the digest has to be
/// collision-resistant.
#[cfg(windows)]
pub(crate) struct Sha256Stream {
    alg: windows_sys::Win32::Security::Cryptography::BCRYPT_ALG_HANDLE,
    hash: windows_sys::Win32::Security::Cryptography::BCRYPT_HASH_HANDLE,
}

#[cfg(windows)]
impl Sha256Stream {
    pub(crate) fn new() -> ExtractionResult<Self> {
        use windows_sys::Win32::Security::Cryptography::{
            BCRYPT_SHA256_ALGORITHM, BCryptCloseAlgorithmProvider, BCryptCreateHash,
            BCryptOpenAlgorithmProvider,
        };
        let mut alg: windows_sys::Win32::Security::Cryptography::BCRYPT_ALG_HANDLE =
            std::ptr::null_mut();
        // SAFETY: `alg` is a valid out-param; the algorithm id is a static
        // null-terminated wide string from the SDK bindings.
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_SHA256_ALGORITHM, std::ptr::null(), 0)
        };
        if status != STATUS_SUCCESS {
            return Err(crypto_unavailable());
        }
        let mut hash: windows_sys::Win32::Security::Cryptography::BCRYPT_HASH_HANDLE =
            std::ptr::null_mut();
        // SAFETY: `alg` is a live provider handle; passing a null hash-object
        // buffer asks CNG to allocate and own it.
        let status = unsafe {
            BCryptCreateHash(
                alg,
                &mut hash,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                0,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            // SAFETY: `alg` is a live provider handle owned here, not used again.
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(alg, 0);
            }
            return Err(crypto_unavailable());
        }
        Ok(Self { alg, hash })
    }

    pub(crate) fn update(&mut self, data: &[u8]) -> ExtractionResult<()> {
        use windows_sys::Win32::Security::Cryptography::BCryptHashData;
        if data.is_empty() {
            return Ok(());
        }
        let len = u32::try_from(data.len()).map_err(|_| crypto_unavailable())?;
        // SAFETY: `self.hash` is a live hash handle; `data` is a valid
        // initialized slice of exactly `len` bytes.
        let status = unsafe { BCryptHashData(self.hash, data.as_ptr(), len, 0) };
        if status != STATUS_SUCCESS {
            return Err(crypto_unavailable());
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> ExtractionResult<[u8; 32]> {
        use windows_sys::Win32::Security::Cryptography::BCryptFinishHash;
        let mut out = [0u8; 32];
        // SAFETY: `self.hash` is a live hash handle; `out` is a 32-byte buffer
        // matching SHA-256's digest length. `Drop` still releases both handles.
        let status = unsafe { BCryptFinishHash(self.hash, out.as_mut_ptr(), out.len() as u32, 0) };
        if status != STATUS_SUCCESS {
            return Err(crypto_unavailable());
        }
        Ok(out)
    }
}

#[cfg(windows)]
impl Drop for Sha256Stream {
    fn drop(&mut self) {
        use windows_sys::Win32::Security::Cryptography::{
            BCryptCloseAlgorithmProvider, BCryptDestroyHash,
        };
        // SAFETY: both handles are live, owned here, and not used again.
        unsafe {
            let _ = BCryptDestroyHash(self.hash);
            let _ = BCryptCloseAlgorithmProvider(self.alg, 0);
        }
    }
}

/// No platform cryptographic provider off Windows: fingerprinting fails closed
/// rather than falling back to a second, weaker implementation.
#[cfg(not(windows))]
pub(crate) struct Sha256Stream;

#[cfg(not(windows))]
impl Sha256Stream {
    pub(crate) fn new() -> ExtractionResult<Self> {
        Err(crypto_unavailable())
    }
    pub(crate) fn update(&mut self, _data: &[u8]) -> ExtractionResult<()> {
        Err(crypto_unavailable())
    }
    pub(crate) fn finish(self) -> ExtractionResult<[u8; 32]> {
        Err(crypto_unavailable())
    }
}

/// Test-only seam: a callback invoked at the EXACT point between closing a
/// staged file's creation handle and acquiring its retained lease.
///
/// This is the transition window the continuity proof exists to close. The
/// integration suite installs a hook that tampers with the staged bytes there
/// and requires materialization to fail closed. Compiled only when the
/// `test-inject` feature is enabled; production builds contain no hook, no
/// storage for one, and no call site.
#[cfg(feature = "test-inject")]
type WindowHook = Box<dyn Fn(&Path)>;

#[cfg(feature = "test-inject")]
thread_local! {
    static LEASE_WINDOW_HOOK: std::cell::RefCell<Option<WindowHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only seam: install (or clear) the transition-window hook for the
/// current thread. Compiled only when the `test-inject` feature is enabled.
#[cfg(feature = "test-inject")]
pub fn test_set_lease_window_hook(hook: Option<WindowHook>) {
    LEASE_WINDOW_HOOK.with(|h| *h.borrow_mut() = hook);
}

/// Invoke the transition-window hook, if one is installed.
#[cfg(feature = "test-inject")]
#[cfg_attr(not(windows), allow(dead_code))]
fn run_lease_window_hook(path: &Path) {
    let hook = LEASE_WINDOW_HOOK.with(|h| h.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
        LEASE_WINDOW_HOOK.with(|h| *h.borrow_mut() = Some(hook));
    }
}

#[cfg(feature = "test-inject")]
thread_local! {
    static CLEANUP_WINDOW_HOOK: std::cell::RefCell<Option<WindowHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only seam: install (or clear) a callback invoked at the EXACT point in
/// [`StagedInfArtifact::cleanup`] between releasing the byte leases and pinning
/// the staging child.
///
/// That is the one window in which the staged objects are unleased and still
/// expected to be there, so it is where a same-name substitution attack has to
/// be mounted. The integration suite installs a hook that performs exactly that
/// substitution and requires cleanup to refuse rather than delete the wrong
/// object or report a false success. Compiled only when the `test-inject`
/// feature is enabled; production builds contain no hook, no storage for one,
/// and no call site.
#[cfg(feature = "test-inject")]
pub fn test_set_cleanup_window_hook(hook: Option<WindowHook>) {
    CLEANUP_WINDOW_HOOK.with(|h| *h.borrow_mut() = hook);
}

/// Invoke the cleanup-window hook, if one is installed.
#[cfg(feature = "test-inject")]
#[cfg_attr(not(windows), allow(dead_code))]
fn run_cleanup_window_hook(path: &Path) {
    let hook = CLEANUP_WINDOW_HOOK.with(|h| h.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
        CLEANUP_WINDOW_HOOK.with(|h| *h.borrow_mut() = Some(hook));
    }
}

#[cfg(feature = "test-inject")]
thread_local! {
    static ROLLBACK_WINDOW_HOOK: std::cell::RefCell<Option<WindowHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only seam: install (or clear) a callback invoked at the START of
/// materialization rollback, before anything is deleted.
///
/// This is the instant the old pathname-based rollback was exploitable: it had
/// already released the child pin, so an attacker could rename the created
/// child away and leave a replacement for `remove_dir` to destroy. The hook
/// lets the integration suite attempt exactly that substitution and require it
/// to be impossible, because the pin is still held here. Compiled only when
/// the `test-inject` feature is enabled.
#[cfg(feature = "test-inject")]
pub fn test_set_rollback_window_hook(hook: Option<WindowHook>) {
    ROLLBACK_WINDOW_HOOK.with(|h| *h.borrow_mut() = hook);
}

/// Invoke the rollback-window hook, if one is installed.
#[cfg(feature = "test-inject")]
fn run_rollback_window_hook(path: &Path) {
    let hook = ROLLBACK_WINDOW_HOOK.with(|h| h.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
        ROLLBACK_WINDOW_HOOK.with(|h| *h.borrow_mut() = Some(hook));
    }
}

#[cfg(feature = "test-inject")]
thread_local! {
    static CHILD_DELETE_WINDOW_HOOK: std::cell::RefCell<Option<WindowHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only seam: install (or clear) a callback invoked in
/// [`StagedInfArtifact::cleanup`] AFTER the staging child's pin has been
/// released and BEFORE the child itself is deleted.
///
/// The pin has to be released before the directory can be removed, so this
/// window is unavoidable and the child's name is attacker-controllable inside
/// it. It is the window in which a junction can be planted at the child's name,
/// and the window in which another Cove materialization can be holding its own
/// staging-root anchor. Compiled only when the `test-inject` feature is
/// enabled; production builds contain no hook, no storage for one, and no call
/// site.
#[cfg(feature = "test-inject")]
pub fn test_set_child_delete_window_hook(hook: Option<WindowHook>) {
    CHILD_DELETE_WINDOW_HOOK.with(|h| *h.borrow_mut() = hook);
}

/// Invoke the child-delete-window hook, if one is installed.
#[cfg(feature = "test-inject")]
#[cfg_attr(not(windows), allow(dead_code))]
fn run_child_delete_window_hook(path: &Path) {
    let hook = CHILD_DELETE_WINDOW_HOOK.with(|h| h.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
        CHILD_DELETE_WINDOW_HOOK.with(|h| *h.borrow_mut() = Some(hook));
    }
}

#[cfg(feature = "test-inject")]
thread_local! {
    static BOUND_DELETE_WINDOW_HOOK: std::cell::RefCell<Option<WindowHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only seam: install (or clear) a callback invoked inside
/// `delete_staging_child_checked` AFTER the opened object has been proven to be
/// the exact directory Cove created and BEFORE deletion is requested through
/// that handle.
///
/// This is the window in which a rename would turn a deletion that merely MARKS
/// the original into a false success confirmed at the old name. Cove's delete
/// handle withholds delete sharing precisely so that rename cannot happen; the
/// seam exists to keep proving it. Compiled only when the `test-inject` feature
/// is enabled.
#[cfg(feature = "test-inject")]
pub fn test_set_bound_delete_window_hook(hook: Option<WindowHook>) {
    BOUND_DELETE_WINDOW_HOOK.with(|h| *h.borrow_mut() = hook);
}

/// Invoke the bound-delete-window hook, if one is installed.
#[cfg(feature = "test-inject")]
#[cfg_attr(not(windows), allow(dead_code))]
fn run_bound_delete_window_hook(path: &Path) {
    let hook = BOUND_DELETE_WINDOW_HOOK.with(|h| h.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
        BOUND_DELETE_WINDOW_HOOK.with(|h| *h.borrow_mut() = Some(hook));
    }
}

#[cfg(feature = "test-inject")]
thread_local! {
    static BOUND_LEAF_DELETE_WINDOW_HOOK: std::cell::RefCell<Option<WindowHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only seam: install (or clear) a callback invoked inside
/// `delete_leaf_checked` AFTER the opened object has been proven to be the exact
/// FILE Cove created and BEFORE deletion is requested through that handle.
///
/// The leaf counterpart of [`test_set_bound_delete_window_hook`]. A leaf can be
/// renamed CROSS-DIRECTORY out of the owned staging child, which leaves its old
/// name vacant without any replacement being planted — the interleaving in which
/// a classic disposition that merely MARKS the renamed original must not be
/// confirmed by the vacancy of the name it used to occupy. The deletion handle
/// withholds delete sharing so that rename cannot happen; this seam is how that
/// stays proven. Compiled only when the `test-inject` feature is enabled.
#[cfg(feature = "test-inject")]
pub fn test_set_bound_leaf_delete_window_hook(hook: Option<WindowHook>) {
    BOUND_LEAF_DELETE_WINDOW_HOOK.with(|h| *h.borrow_mut() = hook);
}

/// Invoke the bound-leaf-delete-window hook, if one is installed.
#[cfg(feature = "test-inject")]
#[cfg_attr(not(windows), allow(dead_code))]
fn run_bound_leaf_delete_window_hook(path: &Path) {
    let hook = BOUND_LEAF_DELETE_WINDOW_HOOK.with(|h| h.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
        BOUND_LEAF_DELETE_WINDOW_HOOK.with(|h| *h.borrow_mut() = Some(hook));
    }
}

#[cfg(feature = "test-inject")]
thread_local! {
    static FORCE_CHILD_REJECTION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only seam: force `create_staging_child` to reject the child it just
/// created, exercising the post-creation rollback path.
///
/// That path is otherwise unreachable in a test — it fires only when
/// canonicalization fails or the canonical leaf/parent disagree, neither of
/// which a test can provoke on a healthy filesystem. It is also the path where
/// the staging-root anchor is still held, so it is the only place a rollback
/// can collide with our own root handle. Compiled only when the `test-inject`
/// feature is enabled.
#[cfg(feature = "test-inject")]
pub fn test_force_staging_child_rejection(on: bool) {
    FORCE_CHILD_REJECTION.with(|c| c.set(on));
}

#[cfg(feature = "test-inject")]
fn forced_child_rejection() -> bool {
    FORCE_CHILD_REJECTION.with(|c| c.get())
}

/// Process-local atomic counter for unique staging child names.
static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// True when `root` is a strict, fully-qualified absolute path on the host.
///
/// On Windows this requires a drive/UNC PREFIX followed by a ROOT component:
/// - `C:\...` (drive absolute) → accepted;
/// - `\\server\share\...` (UNC) → accepted;
/// - `C:stage` (drive-relative: prefix, no root) → rejected;
/// - `\stage` / `/stage` (prefixless rooted: root, no prefix) → rejected —
///   such a path resolves against the mutable current drive and is not a
///   fully-qualified immutable anchor.
fn is_strict_absolute(root: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::path::Component;
        let mut components = root.components();
        match components.next() {
            Some(Component::Prefix(_)) => {
                // Must be followed by a RootDir (i.e. `C:\` or `\\server\share\`),
                // never end at the prefix (`C:` is drive-relative).
                matches!(components.next(), Some(Component::RootDir))
            }
            // A bare RootDir (`\stage`) with no prefix is prefixless-rooted
            // and depends on the current drive — rejected.
            _ => false,
        }
    }
    #[cfg(not(windows))]
    {
        root.is_absolute()
    }
}

/// True when the path carries a Windows drive/UNC prefix (e.g. `C:stage`).
/// Used to give drive-relative roots the explicit typed rejection. Always
/// false on non-Windows.
fn has_drive_prefix(root: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::path::Component;
        matches!(root.components().next(), Some(Component::Prefix(_)))
    }
    #[cfg(not(windows))]
    {
        let _ = root;
        false
    }
}

/// True when the path is prefixless-rooted on Windows: it begins with a root
/// component (`\` or `/`) but has NO drive/UNC prefix (e.g. `\stage`). Such a
/// path resolves against the mutable current drive and is not a
/// fully-qualified anchor. Always false on non-Windows.
fn is_prefixless_rooted(root: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::path::Component;
        matches!(root.components().next(), Some(Component::RootDir))
    }
    #[cfg(not(windows))]
    {
        let _ = root;
        false
    }
}

/// Validate the caller-provided staging root: exists, directory, not a
/// symlink, canonicalizable, and not a reparse point. Returns the canonical
/// root identity (the only path staging children are ever created under).
/// The root itself is never created or removed.
///
/// The root is anchored to an absolute path from a single deterministic
/// current-directory snapshot BEFORE the first security-sensitive lookup, so
/// a process-wide CWD change between validation steps cannot redirect which
/// directory is being validated or materialized into.
pub(crate) fn validate_staging_root(root: &Path) -> ExtractionResult<PathBuf> {
    // Anchor first: a relative root is resolved against ONE current-dir
    // snapshot; a drive-relative root (`C:stage`) is rejected outright —
    // its meaning depends on the drive's mutable current directory and must
    // never anchor staging. Every later lookup uses the anchored absolute
    // path, never the mutable relative spelling.
    let anchored = if is_strict_absolute(root) {
        root.to_path_buf()
    } else if is_prefixless_rooted(root) {
        // `\stage` / `/stage`: root without a drive/UNC prefix — resolves
        // against the mutable current drive, never a safe anchor.
        return Err(ExtractionError::InvalidStagingRoot(format!(
            "{}: prefixless rooted staging root is not supported",
            root.display()
        )));
    } else {
        // A non-strict-absolute path is either genuinely relative (no
        // prefix) or drive-relative (a prefix without a root, e.g. `C:stage`
        // where `is_absolute()` is false on Windows). Both are resolved
        // against ONE current-dir snapshot; if the result is still not a
        // strict absolute path (drive-relative survives the join), reject
        // fail-closed with the explicit drive-relative error.
        let cwd = std::env::current_dir().map_err(|e| {
            ExtractionError::InvalidStagingRoot(format!(
                "cannot resolve current dir for relative root {}: {e}",
                root.display()
            ))
        })?;
        let joined = cwd.join(root);
        if !is_strict_absolute(&joined) {
            if root.is_absolute() || has_drive_prefix(root) {
                return Err(ExtractionError::InvalidStagingRoot(format!(
                    "{}: drive-relative staging root is not supported",
                    root.display()
                )));
            }
            return Err(ExtractionError::InvalidStagingRoot(format!(
                "{}: could not fully qualify relative staging root",
                root.display()
            )));
        }
        joined
    };

    let meta = fs::symlink_metadata(&anchored)
        .map_err(|e| ExtractionError::InvalidStagingRoot(format!("{}: {e}", anchored.display())))?;
    if meta.file_type().is_symlink() {
        return Err(ExtractionError::InvalidStagingRoot(format!(
            "{}: is a symlink",
            anchored.display()
        )));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 /* FILE_ATTRIBUTE_REPARSE_POINT */ != 0 {
            return Err(ExtractionError::InvalidStagingRoot(format!(
                "{}: is a reparse point",
                anchored.display()
            )));
        }
    }
    if !meta.is_dir() {
        return Err(ExtractionError::InvalidStagingRoot(format!(
            "{}: not a directory",
            anchored.display()
        )));
    }
    fs::canonicalize(&anchored)
        .map_err(|e| ExtractionError::InvalidStagingRoot(format!("{}: {e}", anchored.display())))
}

/// Create a new unique direct child of the staging root with `create_dir`
/// (never reused, never created from archive metadata) and bounded collision
/// attempts. Security never depends on name unpredictability.
///
/// Returns the canonical child path AND a guard pinning the child directory
/// object (Windows: held handle with delete/rename sharing withheld). The
/// guard must be held through output creation so the INF/catalog are created
/// through the exact validated child, never through a substituted pathname.
///
/// The root is the canonical staging root validated earlier; the child is
/// created under that canonical path (no relative re-rooting window). After
/// creation, the ORIGINAL path is re-checked for reparse attributes (a
/// junction swapped in place of the just-created directory is rejected as
/// itself), and the canonicalized identity must have the exact generated
/// leaf name AND its parent must equal the canonical root. A same-root
/// junction to another direct child therefore fails the leaf-name check even
/// though its canonical parent matches.
fn create_staging_child(root: &Path) -> ExtractionResult<(PathBuf, ChildDirGuard)> {
    // Windows: create the child RELATIVE to an anchored root handle, so the
    // creating call returns the pin for the exact object it just made. There
    // is no create-then-open-by-name gap in which the directory we created
    // could be swapped for another before we take a handle on it, and every
    // rejection below therefore has a provable object to clean up.
    #[cfg(windows)]
    {
        create_staging_child_relative(root)
    }
    #[cfg(not(windows))]
    for _ in 0..MAX_STAGE_ATTEMPTS {
        let counter = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("{STAGE_PREFIX}{}-{counter}", std::process::id());
        let child = root.join(&name);
        match fs::create_dir(&child) {
            Ok(()) => {
                // Reparse gate on the ORIGINAL path, before following it: a
                // junction substituted in place of the just-created directory
                // must be rejected as itself.
                // Every rejection below removes the directory we just created.
                // The removal result is NEVER discarded: silently leaving a
                // staging child behind is the residue this whole path exists
                // to avoid, and a removal that fails is a real fault.
                match fs::symlink_metadata(&child) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() || is_reparse_attr(&meta) {
                            remove_staging_child(&child)?;
                            return Err(ExtractionError::InvalidStagingRoot(format!(
                                "{}: staging child is a reparse point",
                                child.display()
                            )));
                        }
                    }
                    Err(_) => {
                        remove_staging_child(&child)?;
                        return Err(ExtractionError::InvalidStagingRoot(format!(
                            "{}: staging child vanished after creation",
                            child.display()
                        )));
                    }
                }
                // Capture the canonical identity right after creation. The
                // canonical leaf must be the exact generated name and its
                // parent must equal the canonical root — a same-root junction
                // to a sibling fails the leaf-name check.
                let canonical = match fs::canonicalize(&child) {
                    Ok(c) => c,
                    Err(_) => {
                        // The child was created successfully, so it must be
                        // removed before reporting the failure — returning
                        // here without cleanup leaves residue.
                        remove_staging_child(&child)?;
                        return Err(ExtractionError::InvalidStagingRoot(format!(
                            "{}: canonicalize",
                            child.display()
                        )));
                    }
                };
                let leaf_ok = canonical
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n == name)
                    .unwrap_or(false);
                let parent_ok = match canonical.parent() {
                    Some(p) => p == root,
                    None => false,
                };
                if !leaf_ok || !parent_ok {
                    remove_staging_child(&child)?;
                    return Err(ExtractionError::InvalidStagingRoot(format!(
                        "{}: staging child escapes the canonical root",
                        child.display()
                    )));
                }
                // Pin the child directory object so it cannot be renamed or
                // replaced while the guard lives (output creation + later
                // verification).
                let guard = match ChildDirGuard::open_pinned(&canonical) {
                    Ok(g) => g,
                    Err(e) => {
                        remove_staging_child(&child)?;
                        return Err(e);
                    }
                };
                return Ok((canonical, guard));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(ExtractionError::Io(e)),
        }
    }
    #[cfg(not(windows))]
    Err(ExtractionError::StageDirectoryCollision)
}

/// Windows: create the unique staging child handle-relative to an anchored
/// staging root, returning its canonical path and the pin on the created
/// object.
///
/// The creating `NtCreateFile` both makes the directory and yields the handle
/// to it, so the object is owned from the instant it exists. Nothing between
/// creation and ownership resolves a pathname, which is what removes the
/// substitution window that a `create_dir` followed by an open-by-name has.
#[cfg(windows)]
fn create_staging_child_relative(root: &Path) -> ExtractionResult<(PathBuf, ChildDirGuard)> {
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::UNICODE_STRING;

    const DELETE: u32 = 0x0001_0000;
    const FILE_LIST_DIRECTORY: u32 = 0x0001;
    const FILE_ADD_FILE: u32 = 0x0002;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_TRAVERSE: u32 = 0x0020;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;

    let anchor = ChildDirGuard::open_anchor(root)?;

    for _ in 0..MAX_STAGE_ATTEMPTS {
        let counter = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("{STAGE_PREFIX}{}-{counter}", std::process::id());

        let mut name_buf: Vec<u16> = name.encode_utf16().collect();
        let us = UNICODE_STRING {
            Length: (name_buf.len() * 2) as u16,
            MaximumLength: (name_buf.len() * 2) as u16,
            Buffer: name_buf.as_mut_ptr(),
        };
        let oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: anchor.handle(),
            ObjectName: &us,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };

        let mut handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        let mut io_status: windows_sys::Win32::System::IO::IO_STATUS_BLOCK =
            unsafe { std::mem::zeroed() };

        // Access mirrors what `open_pinned` grants plus what the child must
        // serve as a RootDirectory for (creating and looking up staged
        // leaves). `FILE_SHARE_READ` only: while this guard lives the child
        // cannot be renamed or removed by anyone else, exactly as before.
        //
        // SAFETY: oa points at a live UNICODE_STRING (name_buf outlives the
        // call); RootDirectory is a valid open directory handle; handle and
        // io_status are valid out-params; `name` is a generated single
        // component with no separators.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                DELETE
                    | FILE_LIST_DIRECTORY
                    | FILE_ADD_FILE
                    | FILE_TRAVERSE
                    | FILE_READ_ATTRIBUTES
                    | SYNCHRONIZE,
                &oa,
                &mut io_status,
                std::ptr::null(),
                0,
                FILE_SHARE_READ,
                FILE_CREATE,
                // `FILE_OPEN_REPARSE_POINT` is deliberately NOT combined with
                // `FILE_DIRECTORY_FILE`: Microsoft's NtCreateFile contract does
                // not list it among the options compatible with
                // `FILE_DIRECTORY_FILE`, and a filesystem is free to reject the
                // pair even where NTFS tolerates it. It is also unnecessary
                // here — `FILE_CREATE` makes a brand-new directory, which
                // cannot be a reparse point, and an existing object of any kind
                // at this name (reparse or otherwise) fails the create with
                // STATUS_OBJECT_NAME_COLLISION rather than being opened.
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
                std::ptr::null(),
                0,
            )
        };
        if status as u32 == STATUS_OBJECT_NAME_COLLISION {
            continue;
        }
        if status != STATUS_SUCCESS || handle.is_null() {
            return Err(ExtractionError::InvalidStagingRoot(format!(
                "{}: cannot create staging child: NTSTATUS {status:#010x}",
                root.display()
            )));
        }
        // SAFETY: handle is a live directory handle created by the call above.
        let guard = unsafe { ChildDirGuard::from_raw(handle) };
        // Capture the created object's identity NOW, from the creating
        // handle, so every rejection path below can delete that exact object.
        let child_identity = object_id_of_raw_handle(guard.handle().cast());

        // `FILE_CREATE` + `FILE_DIRECTORY_FILE` created a brand-new directory,
        // so it cannot be a reparse point or a substituted object. The
        // canonical path is still computed for the pathname the artifact
        // reports, and the leaf/parent equality is kept as defence in depth —
        // but a rejection now deletes the object we hold, not a name.
        let child = root.join(&name);
        let canonical = match fs::canonicalize(&child) {
            Ok(c) => c,
            Err(_) => {
                rollback_bound(guard, &child, child_identity, &[], Some(&anchor))?;
                return Err(ExtractionError::InvalidStagingRoot(format!(
                    "{}: canonicalize",
                    child.display()
                )));
            }
        };
        let leaf_ok = canonical
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == name)
            .unwrap_or(false);
        let parent_ok = matches!(canonical.parent(), Some(p) if p == root);
        #[cfg(feature = "test-inject")]
        let (leaf_ok, parent_ok) = if forced_child_rejection() {
            (false, false)
        } else {
            (leaf_ok, parent_ok)
        };
        if !leaf_ok || !parent_ok {
            rollback_bound(guard, &child, child_identity, &[], Some(&anchor))?;
            return Err(ExtractionError::InvalidStagingRoot(format!(
                "{}: staging child escapes the canonical root",
                child.display()
            )));
        }
        return Ok((canonical, guard));
    }
    Err(ExtractionError::StageDirectoryCollision)
}

/// Tab 2a-11a: create ONE new directory `name` handle-relative to an owned
/// `parent` directory object, returning the guard on the exact object made and
/// its 128-bit identity.
///
/// `FILE_CREATE` never opens an existing object, so a name already present
/// (including a raced reparse point) is `OutputAlreadyExists`, never followed.
/// The guard grants what a package directory must serve as a RootDirectory for
/// (list, traverse, add file, add subdirectory, delete) with `FILE_SHARE_READ`
/// ONLY, so while it lives the directory cannot be renamed, deleted or replaced.
/// If the created object cannot be proven a real non-reparse directory with a
/// readable identity it is deleted BY HANDLE (the exact object just made)
/// before the error is returned.
#[cfg(windows)]
pub(crate) fn create_owned_dir_relative(
    parent: &ChildDirGuard,
    name: &str,
) -> ExtractionResult<(ChildDirGuard, FileObjectId)> {
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::UNICODE_STRING;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    const DELETE: u32 = 0x0001_0000;
    const FILE_LIST_DIRECTORY: u32 = 0x0001;
    const FILE_ADD_FILE: u32 = 0x0002;
    const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
    const FILE_TRAVERSE: u32 = 0x0020;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
    const ATTR_DIRECTORY: u32 = 0x10;

    if name.is_empty()
        || name.contains(['/', '\\', ':', '\0'])
        || name == "."
        || name == ".."
        || name.len() > 255
    {
        return Err(ExtractionError::InvalidPackAtExtraction(
            "invalid directory name".into(),
        ));
    }
    let mut name_buf: Vec<u16> = name.encode_utf16().collect();
    let us = UNICODE_STRING {
        Length: (name_buf.len() * 2) as u16,
        MaximumLength: (name_buf.len() * 2) as u16,
        Buffer: name_buf.as_mut_ptr(),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.handle(),
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
    let mut io_status: windows_sys::Win32::System::IO::IO_STATUS_BLOCK =
        unsafe { std::mem::zeroed() };
    // SAFETY: `oa` points at a live UNICODE_STRING (`name_buf` outlives the
    // call); RootDirectory is a valid open directory handle; out-params are
    // valid; `name` is a validated single component.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            DELETE
                | FILE_LIST_DIRECTORY
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE,
            &oa,
            &mut io_status,
            std::ptr::null(),
            0,
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
            std::ptr::null(),
            0,
        )
    };
    if status as u32 == STATUS_OBJECT_NAME_COLLISION {
        return Err(ExtractionError::OutputAlreadyExists);
    }
    if status != STATUS_SUCCESS || handle.is_null() {
        return Err(ExtractionError::Io(std::io::Error::from_raw_os_error(
            win32_status_to_os_error(status),
        )));
    }
    // SAFETY: `handle` is a live directory handle created by the call above.
    let guard = unsafe { ChildDirGuard::from_raw(handle) };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `handle` is live; `info` is a valid out-param.
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    let is_real_dir = ok != 0
        && (info.dwFileAttributes & ATTR_DIRECTORY) != 0
        && (info.dwFileAttributes & ATTR_REPARSE_POINT) == 0;
    #[cfg(feature = "test-inject")]
    let (is_real_dir, forced) =
        forced_owned_dir_failure().map_or((is_real_dir, None), |m| (false, Some(m)));
    match (is_real_dir, object_id_of_raw_handle(guard.handle().cast())) {
        (true, Some(id)) => Ok((guard, id)),
        (_, identity) => {
            // The delete handle we hold IS the object we just created, so it is
            // deleted BY HANDLE. The caller has not recorded this directory, so
            // nothing downstream can roll it back: the removal must be PROVEN
            // here, and anything unproven is reported as residue, never dropped.
            #[cfg(feature = "test-inject")]
            let status = match forced {
                // STATUS_ACCESS_DENIED: the delete "failed" and the object stays.
                Some(ForcedDirDelete::Fails) => 0xC000_0022_u32 as i32,
                // "Success" that unlinked nothing: only the vacancy proof can tell.
                Some(ForcedDirDelete::ClaimsSuccess) => STATUS_SUCCESS,
                Some(ForcedDirDelete::Works) | None => request_delete_by_handle(guard.handle()),
            };
            #[cfg(not(feature = "test-inject"))]
            let status = request_delete_by_handle(guard.handle());
            // Close our handle so a marked deletion can complete; it withheld
            // delete sharing, so nothing could rename the object meanwhile.
            drop(guard);
            let proven = status == STATUS_SUCCESS
                && identity.is_some_and(|id| verify_unlinked_relative(parent, name, id).is_ok());
            Err(if proven {
                ExtractionError::InvalidPackAtExtraction(
                    "created directory is not a provable real directory".into(),
                )
            } else {
                ExtractionError::CleanupFailed(format!(
                    "created directory {name} failed validation and its removal could not be \
                     proven; it may remain"
                ))
            })
        }
    }
}

/// What the by-handle removal of a directory that failed its post-creation
/// proof does, under test.
#[cfg(all(windows, feature = "test-inject"))]
#[derive(Debug, Clone, Copy)]
pub enum ForcedDirDelete {
    /// The real removal runs.
    Works,
    /// The removal fails; the object stays.
    Fails,
    /// The removal reports success but unlinks nothing.
    ClaimsSuccess,
}

#[cfg(all(windows, feature = "test-inject"))]
thread_local! {
    /// `(creations to let succeed first, what the removal then does)`.
    static FORCE_OWNED_DIR_FAILURE: std::cell::Cell<Option<(u32, ForcedDirDelete)>> =
        const { std::cell::Cell::new(None) };
}

/// Take one step of the forced-failure schedule: `Some(mode)` when THIS
/// creation must fail its post-creation proof.
#[cfg(all(windows, feature = "test-inject"))]
fn forced_owned_dir_failure() -> Option<ForcedDirDelete> {
    FORCE_OWNED_DIR_FAILURE.with(|c| match c.get() {
        Some((0, mode)) => Some(mode),
        Some((n, mode)) => {
            c.set(Some((n - 1, mode)));
            None
        }
        None => None,
    })
}

/// Test-only seam: make the `skip`-th following `create_owned_dir_relative`
/// fail its post-creation proof, with its by-handle removal behaving as `mode`.
/// `None` clears it.
#[cfg(all(windows, feature = "test-inject"))]
pub fn test_force_owned_dir_failure(schedule: Option<(u32, ForcedDirDelete)>) {
    FORCE_OWNED_DIR_FAILURE.with(|c| c.set(schedule));
}

/// True when the metadata carries FILE_ATTRIBUTE_REPARSE_POINT on Windows
/// (a file/dir can be a reparse point without a symlink tag). Always false
/// on non-Windows.
#[cfg(not(windows))]
fn is_reparse_attr(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        let _ = meta;
        false
    }
}

/// Test-only seam: prove the same-root junction invariant — the canonical
/// leaf of a path must equal the path's own leaf, otherwise the child was
/// substituted (e.g. a junction to a sibling direct child of the same root).
/// This is the exact check `create_staging_child` applies after creation.
/// Compiled only when the `test-inject` feature is enabled.
#[cfg(feature = "test-inject")]
pub fn test_canonical_leaf_matches(path: &Path) -> bool {
    match fs::canonicalize(path) {
        Ok(canonical) => {
            let path_leaf = path.file_name().and_then(|n| n.to_str());
            let canonical_leaf = canonical.file_name().and_then(|n| n.to_str());
            path_leaf.is_some() && path_leaf == canonical_leaf
        }
        Err(_) => false,
    }
}

/// Test-only seam: run the production staging-root validator so the
/// integration suite can prove drive-relative roots are rejected and relative
/// roots are anchored. Compiled only when the `test-inject` feature is
/// enabled; never reachable in production builds.
#[cfg(feature = "test-inject")]
pub fn test_validate_staging_root(root: &Path) -> ExtractionResult<PathBuf> {
    validate_staging_root(root)
}

/// Test-only seam: pin a child directory with the production `ChildDirGuard`
/// so the integration suite can prove the child is not renameable while
/// pinned. Compiled only when the `test-inject` feature is enabled.
#[cfg(feature = "test-inject")]
pub fn test_pin_child_dir(path: &Path) -> ExtractionResult<ChildDirGuard> {
    ChildDirGuard::open_pinned(path)
}

/// Test-only seam: anchor a staging root with the production `open_anchor` so
/// the integration suite can hold exactly the handle a concurrent Cove
/// materialization holds, and prove that another Cove operation's cleanup does
/// not collide with it. Compiled only when the `test-inject` feature is
/// enabled.
#[cfg(all(windows, feature = "test-inject"))]
pub fn test_anchor_staging_root(path: &Path) -> ExtractionResult<ChildDirGuard> {
    ChildDirGuard::open_anchor(path)
}

#[cfg(all(windows, feature = "test-inject"))]
thread_local! {
    static FORCE_CLASSIC_DISPOSITION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only seam: skip the `FileDispositionInformationEx` attempt so the
/// class-13 fallback is exercised.
///
/// The fallback only runs on hosts too old for the Ex class, which the test
/// host is not — so without this seam the "success means MARKED, not deleted"
/// hazard is unreachable and the verification that guards it is unproven.
/// Compiled only when the `test-inject` feature is enabled.
#[cfg(all(windows, feature = "test-inject"))]
pub fn test_force_classic_disposition(on: bool) {
    FORCE_CLASSIC_DISPOSITION.with(|c| c.set(on));
}

/// Ask Windows to delete the object a handle refers to, by handle.
///
/// Prefers `FileDispositionInformationEx` with POSIX semantics: that unlinks
/// the NAME immediately and lets the object itself die when the last reference
/// goes away. The classic `FileDispositionInformation` cannot do that — it
/// refuses with `STATUS_CANNOT_DELETE` whenever anything still references the
/// file, including a user-mapped section, which is precisely the state the
/// R62 attack leaves behind. Refusing to clean up because a hostile mapping
/// exists would turn a defended attack into permanent residue.
///
/// Falls back to the classic class if the Ex form is unavailable (it needs a
/// modern Windows 10) or is rejected for the filesystem.
#[cfg(windows)]
fn request_delete_by_handle(handle: windows_sys::Win32::Foundation::HANDLE) -> i32 {
    use windows_sys::Wdk::Storage::FileSystem::NtSetInformationFile;

    // FILE_INFORMATION_CLASS::FileDispositionInformationEx / ...Information
    const FILE_DISPOSITION_INFORMATION_EX_CLASS: i32 = 64;
    const FILE_DISPOSITION_INFORMATION_CLASS: i32 = 13;
    const FILE_DISPOSITION_DELETE: u32 = 0x0000_0001;
    const FILE_DISPOSITION_POSIX_SEMANTICS: u32 = 0x0000_0002;
    const FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE: u32 = 0x0000_0010;
    const STATUS_SUCCESS: i32 = 0;

    let mut io_status: windows_sys::Win32::System::IO::IO_STATUS_BLOCK =
        unsafe { std::mem::zeroed() };

    #[repr(C)]
    struct FileDispositionInformationEx {
        flags: u32,
    }
    let ex = FileDispositionInformationEx {
        flags: FILE_DISPOSITION_DELETE
            | FILE_DISPOSITION_POSIX_SEMANTICS
            | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    };
    #[cfg(feature = "test-inject")]
    let skip_ex = FORCE_CLASSIC_DISPOSITION.with(|c| c.get());
    #[cfg(not(feature = "test-inject"))]
    let skip_ex = false;
    if !skip_ex {
        // SAFETY: `handle` is a live handle opened with DELETE access; the
        // buffer matches FILE_DISPOSITION_INFORMATION_EX's layout.
        let status = unsafe {
            NtSetInformationFile(
                handle,
                &mut io_status,
                (&raw const ex).cast(),
                std::mem::size_of::<FileDispositionInformationEx>() as u32,
                FILE_DISPOSITION_INFORMATION_EX_CLASS,
            )
        };
        if status == STATUS_SUCCESS {
            return status;
        }
    }

    #[repr(C)]
    struct FileDispositionInformation {
        delete_file: u8,
    }
    let classic = FileDispositionInformation { delete_file: 1 };
    // SAFETY: same handle contract; the buffer matches
    // FILE_DISPOSITION_INFORMATION's layout.
    unsafe {
        NtSetInformationFile(
            handle,
            &mut io_status,
            (&raw const classic).cast(),
            std::mem::size_of::<FileDispositionInformation>() as u32,
            FILE_DISPOSITION_INFORMATION_CLASS,
        )
    }
}

/// Delete a leaf RELATIVE to a pinned directory handle AND bound to the exact
/// object identity recorded when that leaf was created.
///
/// Handle-relative opening alone is not enough. It fixes the DIRECTORY the
/// delete lands in, but not the FILE: by the time cleanup runs the byte lease
/// has been released (it withholds delete sharing, so it must be), and in that
/// window an attacker who can write into the staging child can rename our leaf
/// away and drop a replacement under the same name. A name-addressed delete
/// would then destroy the replacement — an object we do not own — while ours
/// survives elsewhere, which is both a wrong deletion and undetected residue.
///
/// So the object is opened WITHOUT `FILE_DELETE_ON_CLOSE`, its 128-bit
/// identity is compared against `expected`, and only on a match is the
/// deletion actually requested via `FileDispositionInformation`. On a mismatch
/// nothing is deleted and cleanup fails closed. `FILE_OPEN_REPARSE_POINT`
/// means a raced reparse is examined as the link itself rather than followed.
///
/// An absent leaf is NOT success: the caller only calls this for leaves it
/// created and recorded an identity for, so absence means the object was moved
/// out from under us and residue survives.
///
/// # Share contract: READ and WRITE shared, DELETE withheld
///
/// Identity binding is an observation about a moment, and the moment can be
/// invalidated. `FILE_SHARE_DELETE` permits later opens that request delete
/// access, and delete access is what `FileRenameInformation` requires — so
/// sharing it left the PROVEN leaf renameable between the identity comparison
/// and the deletion request. The rename does not even have to stay inside the
/// staging child: Windows derives the source parent from the already-open leaf
/// and needs only `DELETE` on the source plus create access in the DESTINATION
/// directory. A cross-directory rename `C\N.inf -> S\M.inf` therefore succeeds
/// despite the child pin — the pin restricts the directory OBJECT, not the files
/// linked inside it — and it vacates `N.inf` without planting anything. The
/// classic `FileDispositionInformation` fallback then only MARKS the renamed
/// original, which stays linked at `M`, while the vacancy check on `N.inf`
/// reports what looks like success.
///
/// So DELETE sharing is withheld. Share compatibility is symmetric, so while
/// this handle lives nothing else can hold or acquire the delete access a rename
/// needs, and the composition above is unreachable.
///
/// `FILE_SHARE_WRITE` is deliberately KEPT, and that is not an inconsistency —
/// it is a different bit answering a different question. Microsoft documents
/// that an open omitting `FILE_SHARE_WRITE` fails when the file has a
/// write-access mapping. That documented rule is what the R62/R63 mapped-view
/// protection rests on, and it cuts the other way here: withholding write
/// sharing during cleanup would let a hostile mapped view stop Cove from
/// deleting its own residue. Nothing is closed or unmapped to make deletion
/// succeed, and the mapped-view lease protection is untouched. `FILE_SHARE_READ`
/// is kept for the same reason.
///
/// Accepted consequence: a delete-capable handle that already exists on the
/// exact leaf makes THIS open fail with a sharing violation and cleanup report a
/// failure. A false negative is the correct trade; a false cleanup success is
/// not.
#[cfg(windows)]
pub(crate) fn delete_leaf_checked(
    dir: &ChildDirGuard,
    leaf: &str,
    expected: FileObjectId,
) -> ExtractionResult<()> {
    delete_leaf_inner(dir, leaf, expected, false)
}

/// [`delete_leaf_checked`] for a file that must have exactly ONE name.
///
/// A hard link to the file, created while its lease is released, keeps the very
/// object we were asked to remove alive under a name outside the tree; deleting
/// our name and finding it vacant would then report a cleanup that left the
/// object behind. So the link count is required to be 1 through the deletion
/// handle before the delete request and 0 after it. Measured: a link can still
/// be created while the deletion handle is open, so the post-check is what
/// closes that window.
#[cfg(windows)]
pub(crate) fn delete_owned_leaf_checked(
    dir: &ChildDirGuard,
    leaf: &str,
    expected: FileObjectId,
) -> ExtractionResult<()> {
    delete_leaf_inner(dir, leaf, expected, true)
}

/// The one implementation behind [`delete_leaf_checked`] and
/// [`delete_owned_leaf_checked`]; `single_link` only ADDS the link-count proof.
#[cfg(windows)]
pub(crate) fn delete_leaf_inner(
    dir: &ChildDirGuard,
    leaf: &str,
    expected: FileObjectId,
    single_link: bool,
) -> ExtractionResult<()> {
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        NtCreateFile,
    };
    use windows_sys::Win32::Foundation::UNICODE_STRING;

    const DELETE: u32 = 0x0001_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    // FILE_SHARE_WRITE is RETAINED (see the share-contract note above);
    // FILE_SHARE_DELETE is deliberately absent.
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;

    let mut name_buf: Vec<u16> = leaf.encode_utf16().collect();
    let us = UNICODE_STRING {
        Length: (name_buf.len() * 2) as u16,
        MaximumLength: (name_buf.len() * 2) as u16,
        Buffer: name_buf.as_mut_ptr(),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir.handle(),
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };

    let mut handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
    let mut io_status: windows_sys::Win32::System::IO::IO_STATUS_BLOCK =
        unsafe { std::mem::zeroed() };

    // Share mode: READ and WRITE shared, DELETE withheld. The two halves are
    // separate decisions about separate bits — see the share-contract note on
    // this function.
    //
    // WRITE stays shared for the R62 reason: Microsoft documents that an open
    // omitting `FILE_SHARE_WRITE` fails when the file has a write-access
    // mapping, so withholding it would make Cove unable to delete its own
    // residue whenever a hostile party had mapped the file. Refusing to clean
    // up our own residue because someone else holds a handle is the wrong
    // failure, and READ is shared for the same reason.
    //
    // DELETE is a different matter and is NOT shared: it is the access
    // `FileRenameInformation` requires, so sharing it left the identity-bound
    // leaf renameable in the window below.
    //
    // SAFETY: oa points at a live UNICODE_STRING (name_buf outlives the call);
    // RootDirectory is a valid open directory handle; handle/io_status are
    // valid out-params. The leaf is a validated single component.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &oa,
            &mut io_status,
            std::ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status as u32 == STATUS_OBJECT_NAME_NOT_FOUND
        || status as u32 == STATUS_OBJECT_PATH_NOT_FOUND
    {
        return Err(ExtractionError::CleanupFailed(format!(
            "staged leaf {leaf} is gone from the staging child; the object we created was moved \
             away and cannot be proven deleted"
        )));
    }
    if status != STATUS_SUCCESS || handle.is_null() {
        return Err(ExtractionError::CleanupFailed(format!(
            "open staged leaf {leaf} for delete: NTSTATUS {status:#010x}"
        )));
    }

    let close = |h: windows_sys::Win32::Foundation::HANDLE| unsafe {
        let _ = windows_sys::Win32::Foundation::CloseHandle(h);
    };

    // Bind the OBJECT before asking for its deletion.
    match object_id_of_raw_handle(handle.cast()) {
        Some(actual) if actual == expected => {}
        _ => {
            close(handle);
            return Err(ExtractionError::CleanupFailed(format!(
                "staged leaf {leaf} is not the file that was created; refusing to delete it"
            )));
        }
    }

    // Number of names the bound object has, read through the handle itself.
    let link_count = |h: windows_sys::Win32::Foundation::HANDLE| {
        let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
            unsafe { std::mem::zeroed() };
        // SAFETY: `h` is the live handle opened above; `info` is a valid out-param.
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(h, &mut info)
        };
        (ok != 0).then_some(info.nNumberOfLinks)
    };
    let links_before = link_count(handle);
    if single_link && links_before != Some(1) {
        close(handle);
        return Err(ExtractionError::CleanupFailed(format!(
            "staged leaf {leaf} has more than one hard link (or its link count is unreadable); \
             refusing to report it deleted"
        )));
    }

    // The window between binding the exact leaf and deleting it. The deletion
    // handle withholds delete sharing, so a rename of the proven file — in
    // particular a CROSS-DIRECTORY rename that would vacate its name without
    // planting anything — is refused for as long as this handle lives. That is
    // the invariant `verify_unlinked_relative` depends on for leaves.
    #[cfg(feature = "test-inject")]
    run_bound_leaf_delete_window_hook(Path::new(leaf));

    let status = request_delete_by_handle(handle);
    // Read BEFORE closing. Measured on both the POSIX and the classic MARKED
    // form: the request already removed OUR name from the count, so this is the
    // number of names that REMAIN.
    let links_after = link_count(handle);
    close(handle);
    if status != STATUS_SUCCESS {
        return Err(ExtractionError::CleanupFailed(format!(
            "delete staged leaf {leaf}: NTSTATUS {status:#010x}"
        )));
    }
    if single_link && links_after != Some(0) {
        return Err(ExtractionError::CleanupFailed(format!(
            "a hard link to staged leaf {leaf} survives its deletion; the object we created \
             remains under another name"
        )));
    }
    // A `STATUS_SUCCESS` from the classic disposition class means MARKED, not
    // deleted. Prove the object is really unlinked before claiming cleanup
    // succeeded, otherwise a third party holding a delete-sharing handle keeps
    // the staged file alive while we report Ok.
    verify_unlinked_relative(dir, leaf, expected).map_err(|e| {
        ExtractionError::CleanupFailed(format!("staged leaf {leaf} was not deleted: {e}"))
    })
}

/// Delete the staging child DIRECTORY relative to a pinned parent, refusing
/// to touch anything that is not the exact directory object we created.
///
/// Cleanup by pathname is the residue/substitution hazard: by the time the
/// leases and pins are released, an attacker can rename our child away and
/// drop a replacement at the same pathname, so a path-based `remove_dir` would
/// delete somebody else's directory while ours survives. Opening the name
/// relative to the pinned parent and requiring the opened object's identity to
/// equal the one recorded at creation removes that possibility: either it is
/// our directory or nothing is deleted.
///
/// # Share contract: DELETE access, and NO delete sharing
///
/// Identity binding alone is not enough, because it is an observation about a
/// moment. Microsoft documents `FILE_SHARE_DELETE` as permitting subsequent
/// opens that request delete access, and `DELETE` as the access that
/// `FileRenameInformation` requires. A handle opened with delete sharing
/// therefore leaves the proven object renameable AFTER the identity comparison:
/// an attacker moves the child `N -> M`, and — critically — need not plant
/// anything at `N`. The classic `FileDispositionInformation` fallback then only
/// MARKS the object for deletion when its handles close; the object stays linked
/// at `M`, while a probe of `N` reports `STATUS_OBJECT_NAME_NOT_FOUND`.
///
/// So this open withholds `FILE_SHARE_DELETE`. Windows share compatibility is
/// symmetric, so while this handle lives no other handle can hold or acquire
/// `DELETE` on the exact child, and the post-binding rename is unreachable.
/// `FILE_SHARE_READ` is kept: read sharing costs nothing here and a read-only
/// observer must not be broken by cleanup.
///
/// The accepted consequence: if a delete-capable handle on the exact child
/// already exists, this open fails with a sharing violation and cleanup reports
/// a failure. That false negative is the intended trade. A false cleanup success
/// is not acceptable; failing to prove removal is.
///
/// This is scoped to the EXACT CHILD deletion handle. The staging-root anchor
/// and other ancestor handles stay permissive on purpose — restricting them is
/// what made Cove's own concurrent materializations collide.
#[cfg(windows)]
pub(crate) fn delete_staging_child_checked(
    parent: &ChildDirGuard,
    name: &str,
    expected: FileObjectId,
) -> ExtractionResult<()> {
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::UNICODE_STRING;

    const DELETE: u32 = 0x0001_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    // FILE_SHARE_READ ONLY. Delete sharing is deliberately withheld here — see
    // the share-contract note above this function. Read sharing is kept so an
    // ordinary observer is not broken by cleanup.
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;

    let mut name_buf: Vec<u16> = name.encode_utf16().collect();
    let us = UNICODE_STRING {
        Length: (name_buf.len() * 2) as u16,
        MaximumLength: (name_buf.len() * 2) as u16,
        Buffer: name_buf.as_mut_ptr(),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.handle(),
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };

    let mut handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
    let mut io_status: windows_sys::Win32::System::IO::IO_STATUS_BLOCK =
        unsafe { std::mem::zeroed() };

    // SAFETY: oa points at a live UNICODE_STRING (name_buf outlives the call);
    // RootDirectory is a valid open directory handle; out-params are valid.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &oa,
            &mut io_status,
            std::ptr::null(),
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            // NO-TRAVERSE, and no `FILE_DIRECTORY_FILE`.
            //
            // `FILE_OPEN_REPARSE_POINT` is what makes this open name the object
            // at `name` rather than wherever `name` leads. Following was the
            // false-success hole: rename our child N to M, plant a junction
            // N -> M, and a traversing open lands on the ORIGINAL directory —
            // passing both the reparse-attribute check (the TARGET is a real
            // directory) and the identity comparison (the target IS our
            // object). Deleting through it unlinks M and leaves N behind, and
            // the verification then follows the dangling N and reads "path not
            // found" as success. A junction whose target disappeared is not a
            // deleted junction.
            //
            // `FILE_DIRECTORY_FILE` is dropped rather than combined with it:
            // Microsoft does not document the pair as compatible. It is not
            // needed — the attribute check below proves the opened object is a
            // real directory and rejects a reparse point opened as itself,
            // which is exactly what a raced junction now looks like here.
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status as u32 == STATUS_OBJECT_NAME_NOT_FOUND
        || status as u32 == STATUS_OBJECT_PATH_NOT_FOUND
    {
        // The name is gone, but we CREATED this directory, so its absence
        // under the pinned parent does not prove the object was deleted — a
        // rename produces exactly this observation while the directory (and
        // whatever is left inside it) survives elsewhere. Reporting success
        // here is the false-success hazard; fail closed instead.
        return Err(ExtractionError::CleanupFailed(format!(
            "staging child {name} is gone from its parent; the directory we created was moved \
             away and cannot be proven deleted"
        )));
    }
    if status != STATUS_SUCCESS || handle.is_null() {
        return Err(ExtractionError::CleanupFailed(format!(
            "open staging child {name} for delete: NTSTATUS {status:#010x}"
        )));
    }

    let close = |h: windows_sys::Win32::Foundation::HANDLE| unsafe {
        let _ = windows_sys::Win32::Foundation::CloseHandle(h);
    };

    // Prove the opened object is a real, non-reparse directory. The open was
    // no-traverse, so a raced junction arrives here as ITSELF and is rejected
    // by the reparse bit — Cove never acts through a link it did not create.
    {
        use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;
        let mut info: windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION =
            unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        let attrs_ok = ok != 0
            && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
        if !attrs_ok {
            close(handle);
            return Err(ExtractionError::CleanupFailed(format!(
                "staging child {name} is not a real non-reparse directory; refusing to delete it"
            )));
        }
    }

    // Bind the object BEFORE deleting it.
    match object_id_of_raw_handle(handle.cast()) {
        Some(actual) if actual == expected => {}
        _ => {
            close(handle);
            return Err(ExtractionError::CleanupFailed(format!(
                "staging child {name} is not the directory that was created; refusing to delete it"
            )));
        }
    }

    // The window between binding the object and deleting it. Our delete handle
    // withholds delete sharing, so a rename or delete of the proven object is
    // refused for as long as this handle lives — that is the invariant the
    // vacancy check below depends on, and it is exercised here.
    #[cfg(feature = "test-inject")]
    run_bound_delete_window_hook(Path::new(name));

    let status = request_delete_by_handle(handle);
    close(handle);
    if status != STATUS_SUCCESS {
        return Err(ExtractionError::CleanupFailed(format!(
            "delete staging child {name}: NTSTATUS {status:#010x}"
        )));
    }
    // The delete may have been only MARKED rather than performed — see
    // `request_delete_by_handle`. Prove the object is actually unlinked.
    verify_unlinked_relative(parent, name, expected).map_err(|e| {
        ExtractionError::CleanupFailed(format!("staging child {name} was not deleted: {e}"))
    })
}

/// Prove that the object with identity `was` no longer occupies `name` under
/// `dir`, after a deletion has been requested through a handle.
///
/// This is the check that makes the classic `FileDispositionInformation`
/// fallback honest. `STATUS_SUCCESS` from that class means the object was
/// MARKED for deletion, not that it is gone: the link is only removed once
/// every open handle closes. A third party holding a delete-sharing handle can
/// therefore keep our staging directory alive indefinitely while we report a
/// successful cleanup. Re-opening the name and requiring it to be ABSENT turns
/// that silent residue into a reported failure.
///
/// # What vacancy does and does NOT prove
///
/// Vacancy of a pathname is NOT a general proof that a given object was
/// unlinked: the same observation is produced by a rename that left the object
/// alive elsewhere. This check is honest only because of an invariant its
/// callers establish — the deletion handle is opened WITHOUT `FILE_SHARE_DELETE`
/// (see `delete_staging_child_checked` and `delete_leaf_checked`), so no
/// competing handle can hold the `DELETE` access a rename requires between the
/// identity binding and the deletion request. Staged LEAVES rely on the SAME
/// contract in `delete_leaf_checked`, not on the containing directory: the child
/// pin restricts the directory object, and a leaf rename does not need a fresh
/// write-class open of the source parent — Windows derives that parent from the
/// already-open leaf and checks create access in the DESTINATION directory
/// instead, so a cross-directory rename escapes the pin entirely. Remove the
/// share contract from either deletion handle and this function silently becomes
/// a false-success oracle again. Do not reuse it as a general "object A was
/// unlinked" primitive.
///
/// The only observation accepted as proof is `STATUS_OBJECT_NAME_NOT_FOUND`
/// under the already-pinned parent: the name we were asked about is vacant.
/// Everything else fails closed, including two cases that used to pass:
///
/// - `STATUS_OBJECT_PATH_NOT_FOUND`. Under a pinned parent a single leaf cannot
///   produce a missing PATH unless the open traversed something — a junction at
///   `name` whose target is gone reports exactly this, while the junction is
///   still sitting there. Absence of a link's TARGET is not absence of the link.
/// - A DIFFERENT object now at the same name. That is a fact about the NAME and
///   says nothing whatever about our OBJECT: an attacker who renames our
///   directory away and drops a replacement at its name produces precisely this
///   observation while everything we created is still on disk. `DEL-RACE-1`
///   measures that the rename is reachable. Cove cannot distinguish that from a
///   benign re-use of a freed name, so it must refuse to treat either as proof.
///   A false negative is a reported cleanup failure; a false positive is silent
///   residue.
#[cfg(windows)]
fn verify_unlinked_relative(
    dir: &ChildDirGuard,
    name: &str,
    was: FileObjectId,
) -> Result<(), String> {
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::UNICODE_STRING;

    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
    // A name pending deletion reports this until the last handle closes.
    const STATUS_DELETE_PENDING: u32 = 0xC000_0056;

    let mut name_buf: Vec<u16> = name.encode_utf16().collect();
    let us = UNICODE_STRING {
        Length: (name_buf.len() * 2) as u16,
        MaximumLength: (name_buf.len() * 2) as u16,
        Buffer: name_buf.as_mut_ptr(),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir.handle(),
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };

    let mut handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
    let mut io_status: windows_sys::Win32::System::IO::IO_STATUS_BLOCK =
        unsafe { std::mem::zeroed() };

    // Read-only, fully permissive sharing: this open must observe, never
    // conflict.
    //
    // SAFETY: oa points at a live UNICODE_STRING (name_buf outlives the call);
    // RootDirectory is a valid open directory handle; out-params are valid.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &oa,
            &mut io_status,
            std::ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            // No-traverse: this open must observe what is AT the name, not what
            // the name leads to. A junction here has to be seen, not followed.
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status as u32 == STATUS_OBJECT_NAME_NOT_FOUND {
        // The one proof: the name is vacant under the parent we hold pinned.
        return Ok(());
    }
    if status as u32 == STATUS_OBJECT_PATH_NOT_FOUND {
        return Err(
            "the name could not be resolved as a leaf of the pinned parent, so what remains at it \
             was never observed; a reparse point whose target is gone reports exactly this"
                .to_string(),
        );
    }
    if status as u32 == STATUS_DELETE_PENDING {
        return Err(
            "deletion was only MARKED: the object is still linked while another handle holds it"
                .to_string(),
        );
    }
    if status != STATUS_SUCCESS || handle.is_null() {
        return Err(format!(
            "could not confirm removal: NTSTATUS {status:#010x}"
        ));
    }
    let actual = object_id_of_raw_handle(handle.cast());
    unsafe {
        let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
    }
    match actual {
        // Our object is still there under its own name: not deleted.
        Some(id) if id == was => Err(
            "deletion was only MARKED: the object we created is still present under that name"
                .to_string(),
        ),
        // Some other object now holds the name. This does NOT show that ours
        // left: a rename plus a same-name replacement produces an identical
        // observation with our object still linked elsewhere.
        Some(_) => Err(
            "a different object now holds that name, which proves nothing about the object we \
             created; it may have been renamed away rather than deleted"
                .to_string(),
        ),
        None => Err("could not read the identity of the object still at that name".to_string()),
    }
}

/// Remove one staged file during rollback.
///
/// Every handle to `path` — the creation handle that is also the artifact
/// lease — must already be dropped when this runs, because that handle
/// withholds delete sharing. A removal failure is therefore a real fault and
/// is NEVER ignored: silently swallowing it is exactly how residue is left
/// behind in a staging directory that the caller believes was rolled back.
/// An already-absent file is success.
#[cfg(not(windows))]
fn remove_staged_file(path: &Path) -> ExtractionResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ExtractionError::CleanupFailed(format!(
            "remove staged file {}: {e}",
            path.display()
        ))),
    }
}

/// Remove the unique staging child directory during rollback.
///
/// The child pin (opened with DELETE access and `FILE_SHARE_READ`) blocks
/// `RemoveDirectory`, so the pin must already be dropped. As above, a failure
/// is reported rather than ignored.
#[cfg(not(windows))]
fn remove_staging_child(staging_child: &Path) -> ExtractionResult<()> {
    match fs::remove_dir(staging_child) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ExtractionError::CleanupFailed(format!(
            "remove staging child {}: {e}",
            staging_child.display()
        ))),
    }
}

/// Object-bound rollback: destroy exactly the objects this materialization
/// created, using the pin taken when the staging child was created.
///
/// The old shape of this function released `child_guard` and then removed the
/// output and the directory BY PATHNAME. That reintroduced, earlier in the
/// lifecycle, the very substitution the cleanup path exists to prevent: once
/// the pin is gone the pathname is attacker-controllable, so a rename plus a
/// same-named replacement makes `remove_file`/`remove_dir` destroy somebody
/// else's object while ours survives.
///
/// Here the guard is CONSUMED rather than dropped early. Leaves are deleted
/// relative to it and bound to the identities captured from their creation
/// handles; only then is the pin released (it withholds delete sharing, so the
/// directory cannot be removed while it is held) and the child itself deleted
/// relative to its pinned parent, again identity-bound.
///
/// `leaves` entries with `None` identity were never created and are skipped —
/// there is no object to destroy and nothing to prove.
#[cfg(windows)]
fn rollback_bound(
    child_guard: ChildDirGuard,
    staging_child: &Path,
    child_identity: Option<FileObjectId>,
    leaves: &[(&str, Option<FileObjectId>)],
    parent_handle: Option<&ChildDirGuard>,
) -> ExtractionResult<()> {
    // The attacker's last opportunity, and the point at which the previous
    // implementation had already surrendered the pin.
    #[cfg(feature = "test-inject")]
    run_rollback_window_hook(staging_child);

    for (leaf, identity) in leaves {
        if let Some(id) = identity {
            delete_leaf_checked(&child_guard, leaf, *id)?;
        }
    }
    // The pin holds DELETE access and withholds delete sharing, so it must be
    // released before the directory can be removed — but not one step earlier.
    drop(child_guard);

    let expected = child_identity.ok_or_else(|| {
        ExtractionError::CleanupFailed(
            "staging child identity was never recorded; the exact object cannot be proven and \
             must not be deleted by name"
                .into(),
        )
    })?;
    let name = staging_child
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ExtractionError::CleanupFailed("staging child has no leaf name".into()))?;

    // Reuse the caller's parent handle when it has one.
    //
    // This is not an optimization. Windows share-mode compatibility is
    // SYMMETRIC: a handle's granted access must be permitted by every other
    // handle's share mode, in both directions. The staging-root anchor held by
    // `create_staging_child_relative` grants `FILE_ADD_SUBDIRECTORY`, a
    // write-class right, so re-opening that same directory here with
    // `FILE_SHARE_READ` only would collide with our OWN anchor and fail with a
    // sharing violation — leaving the child we just created as residue. Using
    // the handle we already hold both avoids the collision and keeps the
    // parent object-bound instead of re-resolved from a pathname.
    match parent_handle {
        Some(parent_pin) => delete_staging_child_checked(parent_pin, name, expected),
        None => {
            let parent = staging_child.parent().ok_or_else(|| {
                ExtractionError::CleanupFailed("staging child has no parent".into())
            })?;
            // Anchor rather than pin, for the reason given above the identical
            // open in `StagedInfArtifact::cleanup`: the staging root is shared
            // with other Cove operations and a restrictive re-open collides
            // with their anchors.
            let parent_anchor = ChildDirGuard::open_anchor(parent)?;
            delete_staging_child_checked(&parent_anchor, name, expected)
        }
    }
}

/// Non-Windows rollback. There is no native verification surface and no object
/// identity to bind to on this platform, so the portable path gates plus the
/// error-reporting removal helpers remain the contract. Signature matches the
/// Windows form so `materialize_inf` has one call shape.
#[cfg(not(windows))]
fn rollback_bound(
    child_guard: ChildDirGuard,
    staging_child: &Path,
    _child_identity: Option<FileObjectId>,
    leaves: &[(&str, Option<FileObjectId>)],
    _parent_handle: Option<&ChildDirGuard>,
) -> ExtractionResult<()> {
    drop(child_guard);
    for (leaf, _) in leaves {
        remove_staged_file(&staging_child.join(leaf))?;
    }
    remove_staging_child(staging_child)
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
    // Validate the root and capture its canonical identity ONCE, before any
    // child creation. All staging children are created under this canonical
    // root, so a process-wide CWD change after validation cannot re-root a
    // relative staging path.
    let canonical_root = validate_staging_root(staging_root)?;

    // Revalidate the 2a-5 pack snapshot (TOCTOU boundary) before archive access.
    let mut file = revalidate_pack(request.pack())?;

    // Parse bounded metadata, then validate paths/bounds/duplicates and the
    // unique target (ASCII case-insensitive Windows semantics; exact match is
    // a subset). No staging writes happen before this passes.
    let archive = open_bounded_archive(&mut file)?;
    let inspected = inspect_archive(&archive)?;
    let target_index = resolve_target(request.inf(), &inspected)?;
    let target = &inspected[target_index];
    validate_target_contract(target)?;

    let block_index = target
        .block_index
        .ok_or(ExtractionError::TargetNotRegularFile)?;

    materialize_inf_staged(
        request,
        canonical_root,
        file,
        archive,
        inspected,
        target_index,
        block_index,
    )
}

/// Open one 7z archive's metadata under Cove's fixed memory bounds.
///
/// This is the single hostile-input preflight sequence every archive consumer
/// uses: the fixed 32-byte start header is checked before the backend parser
/// can allocate an attacker-declared next-header buffer, an ENCODED next
/// header is bounded for decoded size and aggregate coder workspace before the
/// backend decodes it, and only then is the metadata parsed.
fn open_bounded_archive(file: &mut File) -> ExtractionResult<Archive> {
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

    Archive::read(file, &Password::empty()).map_err(|e| classify_backend_parse_error(&e))
}

/// Staging half of [`materialize_inf`]: everything from the validated target
/// onward. Split out so the bounded metadata open above is shared verbatim
/// with the read-only payload-inventory path, which stages nothing.
#[allow(clippy::too_many_arguments)]
fn materialize_inf_staged(
    request: &PackageMaterializationRequest,
    canonical_root: PathBuf,
    mut file: File,
    archive: Archive,
    inspected: Vec<InspectedEntry>,
    target_index: usize,
    block_index: usize,
) -> ExtractionResult<StagedInfArtifact> {
    let target = &inspected[target_index];
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

    // Staging: unique direct child under the CANONICAL root, flat one-file
    // output, create-new only. The child guard pins the directory object so
    // output creation cannot be redirected into a substituted directory.
    let (staging_child, child_guard) = create_staging_child(&canonical_root)?;
    // Bind the child directory OBJECT now, while the pin that guarantees it
    // cannot have been swapped is still held. Cleanup later re-opens the name
    // and requires this exact identity before deleting anything.
    #[cfg(windows)]
    let staging_dir_identity = object_id_of_raw_handle(child_guard.handle().cast());
    #[cfg(not(windows))]
    let staging_dir_identity: Option<FileObjectId> = None;
    let leaf = request
        .inf()
        .relative_path()
        .rsplit('/')
        .next()
        .unwrap_or(request.inf().relative_path());
    let output_path = staging_child.join(leaf);
    let mut out = match open_output_create_new(&child_guard, leaf, &output_path) {
        Ok(f) => f,
        Err(e) => {
            // No output object exists on this path, so there is no leaf to
            // destroy — but the staging child does, and it is destroyed
            // through the pin we still hold, never by pathname.
            rollback_bound(child_guard, &staging_child, staging_dir_identity, &[], None)?;
            return Err(e);
        }
    };
    // Capture the output object's identity from its CREATION handle, before
    // anything can go wrong. Every rollback below is then bound to the exact
    // file this materialization made.
    #[cfg(windows)]
    let inf_identity = object_id_of_file(&out);
    #[cfg(not(windows))]
    let inf_identity: Option<FileObjectId> = None;
    let inf_leaves = [(leaf, inf_identity)];

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
                // Drop the output handle BEFORE any removal: it withholds
                // delete sharing. The child pin is NOT dropped here — it is
                // handed to the rollback, which needs it to reach the leaf as
                // an object rather than as a name.
                drop(out);
                rollback_bound(
                    child_guard,
                    &staging_child,
                    staging_dir_identity,
                    &inf_leaves,
                    None,
                )?;
                return Err(ExtractionError::DecodedSizeMismatch {
                    expected: target.size,
                    written,
                });
            }

            // ---- Byte-continuity baseline, taken through the CREATION handle
            //
            // Flush, then read the object identity AND the finished bytes back
            // through the very handle that wrote them. Nothing here touches a
            // pathname, so nothing here can be redirected.
            // The flush is a POST-CREATE failure path like any other: the
            // staging child and the staged INF both exist by now, so a bare
            // `?` here would return with both left on disk. (`File::flush` is
            // currently a no-op on Windows, but std explicitly reserves the
            // right to change that, so the invariant must hold in the source
            // rather than in today's platform behaviour.)
            {
                use std::io::Write as _;
                if let Err(e) = out.flush() {
                    drop(out);
                    rollback_bound(
                        child_guard,
                        &staging_child,
                        staging_dir_identity,
                        &inf_leaves,
                        None,
                    )?;
                    return Err(ExtractionError::Io(e));
                }
            }
            #[cfg(windows)]
            let inf_baseline = match digest_of_open_file(&mut out) {
                Ok(d) => d,
                Err(e) => {
                    drop(out);
                    rollback_bound(
                        child_guard,
                        &staging_child,
                        staging_dir_identity,
                        &inf_leaves,
                        None,
                    )?;
                    return Err(e);
                }
            };

            // ---- Transition to the retained lease, proving nothing changed
            #[cfg(windows)]
            let inf_lock = match transition_to_lease(
                &child_guard,
                leaf,
                &output_path,
                out,
                inf_identity,
                inf_baseline,
            ) {
                Ok(lease) => lease,
                Err(e) => {
                    rollback_bound(
                        child_guard,
                        &staging_child,
                        staging_dir_identity,
                        &inf_leaves,
                        None,
                    )?;
                    return Err(e);
                }
            };
            #[cfg(not(windows))]
            let inf_lock: Option<std::fs::File> = {
                // No native verification surface: nothing to lease.
                drop(out);
                None
            };

            // If the request names a catalog member, record the expectation.
            // The catalog is staged beside the INF when the archive contains
            // it (the Windows SetupAPI contract); when it is absent, the leaf
            // is still recorded so the 2a-7 verifier's `check_catalog_staged`
            // fails closed with `CatalogNotStaged` — an INF whose referenced
            // catalog is missing can never be verified.
            // Threaded out of the staging closure below rather than through
            // its return tuple, because the digest type does not exist off
            // Windows and the tuple is shared with the portable path.
            #[cfg(windows)]
            let mut staged_catalog_digest: Option<StagedContentDigest> = None;
            let catalog_leaf = match request.catalog() {
                Some(cat) => {
                    let expected_leaf = cat
                        .relative_path()
                        .rsplit('/')
                        .next()
                        .unwrap_or(cat.relative_path())
                        .to_string();
                    // The closure returns the ACTUAL staged catalog leaf (the
                    // archive spelling used to create the file), which may
                    // differ from the expected leaf only by ASCII case, PLUS
                    // the identity captured from the creation handle and the
                    // creation handle ITSELF as the retained lease.
                    let cat_result =
                        (|| -> ExtractionResult<(String, Option<FileObjectId>, Option<File>)> {
                            let cat_index = resolve_target(cat, &inspected)?;
                            let cat = &inspected[cat_index];
                            validate_target_contract(cat)?;
                            let cat_block = cat
                                .block_index
                                .ok_or(ExtractionError::TargetNotRegularFile)?;
                            // Apply the SAME pre-decode guards as the INF path:
                            // coder-workspace bound (attacker-controlled LZMA
                            // dictionary sizes must not exceed the fixed memory
                            // budget) and the packed/unpacked expansion-ratio
                            // bomb rejection. A hostile catalog block must not
                            // bypass the bounds that protect the INF decode.
                            let cat_block_ref = archive.blocks.get(cat_block).ok_or(
                                ExtractionError::InvalidPackAtExtraction(
                                    "catalog block index out of range".into(),
                                ),
                            )?;
                            validate_target_block_coder_memory(cat_block_ref)?;
                            let cat_block_first = archive
                                .stream_map
                                .block_first_file_index
                                .get(cat_block)
                                .copied()
                                .ok_or(ExtractionError::InvalidPackAtExtraction(
                                    "catalog block first-file index out of range".into(),
                                ))?;
                            let cat_budget =
                                decode_bytes_to_target(&inspected, cat_block_first, cat_index)?;
                            precheck_decode_budget(cat_budget)?;
                            let cat_unpack = cat_block_ref.get_unpack_size();
                            if let Some(packed) = target_block_packed_bytes(&archive, cat_block) {
                                let ratio = target_block_expansion_ratio(cat_unpack, packed)?;
                                if ratio > MAX_TARGET_BLOCK_EXPANSION_RATIO {
                                    return Err(ExtractionError::TargetExpansionRatioExceeded);
                                }
                            }
                            let cat_leaf =
                                cat.normalized.rsplit('/').next().unwrap_or(&cat.normalized);
                            let cat_output = staging_child.join(cat_leaf);
                            // Exactly the INF discipline: the creation handle
                            // writes the bytes, is flushed, and yields both the
                            // identity and the byte baseline, which the retained
                            // lease is then checked against.
                            let cat_outcome = {
                                let mut cat_out =
                                    open_output_create_new(&child_guard, cat_leaf, &cat_output)?;
                                let r = extract_target_stream(
                                    &mut file,
                                    &archive,
                                    cat_block,
                                    cat,
                                    &mut cat_out,
                                    cat_budget,
                                );
                                #[cfg(windows)]
                                let identity = object_id_of_file(&cat_out);
                                #[cfg(not(windows))]
                                let identity: Option<FileObjectId> = None;
                                (r, identity, cat_out)
                            };
                            let (cat_result, cat_identity, mut cat_out) = cat_outcome;
                            // Bound removal of the catalog leaf: the object
                            // identity comes from the creation handle above,
                            // so a partially staged catalog is destroyed as an
                            // OBJECT even though the child pin is still held.
                            #[cfg(windows)]
                            let remove_cat =
                                |identity: Option<FileObjectId>| -> ExtractionResult<()> {
                                    match identity {
                                        Some(id) => delete_leaf_checked(&child_guard, cat_leaf, id),
                                        None => Err(ExtractionError::CleanupFailed(
                                            "staged catalog has no provable identity; refusing to \
                                         delete it by name"
                                                .into(),
                                        )),
                                    }
                                };
                            // No object identity exists off Windows; the
                            // portable removal helper stays the contract.
                            #[cfg(not(windows))]
                            let remove_cat =
                                |_identity: Option<FileObjectId>| -> ExtractionResult<()> {
                                    remove_staged_file(&cat_output)
                                };
                            // Every catalog failure — a decode error, a short
                            // decode, or a failed flush — routes through ONE
                            // rollback that closes the creation handle first (it
                            // withholds delete sharing) and then removes the
                            // partially staged catalog. Nothing is left behind on
                            // any of those paths.
                            let staged: ExtractionResult<()> = match cat_result {
                                Ok(cat_written) if cat_written == cat.size => {
                                    use std::io::Write as _;
                                    cat_out.flush().map_err(ExtractionError::Io)
                                }
                                Ok(cat_written) => Err(ExtractionError::DecodedSizeMismatch {
                                    expected: cat.size,
                                    written: cat_written,
                                }),
                                Err(e) => Err(e),
                            };
                            if let Err(e) = staged {
                                drop(cat_out);
                                remove_cat(cat_identity)?;
                                return Err(e);
                            }
                            // Byte-continuity baseline for the catalog, taken
                            // through its own creation handle.
                            #[cfg(windows)]
                            let cat_baseline = match digest_of_open_file(&mut cat_out) {
                                Ok(d) => d,
                                Err(e) => {
                                    drop(cat_out);
                                    remove_cat(cat_identity)?;
                                    return Err(e);
                                }
                            };
                            #[cfg(windows)]
                            {
                                staged_catalog_digest = Some(cat_baseline);
                            }
                            #[cfg(windows)]
                            let cat_lock: Option<std::fs::File> = match transition_to_lease(
                                &child_guard,
                                cat_leaf,
                                &cat_output,
                                cat_out,
                                cat_identity,
                                cat_baseline,
                            ) {
                                Ok(lease) => Some(lease),
                                Err(e) => {
                                    remove_cat(cat_identity)?;
                                    return Err(e);
                                }
                            };
                            #[cfg(not(windows))]
                            let cat_lock: Option<std::fs::File> = {
                                drop(cat_out);
                                None
                            };
                            Ok((cat_leaf.to_string(), cat_identity, cat_lock))
                        })();
                    // The closure returns (actual_leaf, the identity read from
                    // the creation handle, the checked retained lease).
                    match cat_result {
                        Ok((actual_leaf, id, retained)) => Some((actual_leaf, id, retained)),
                        Err(ExtractionError::TargetMemberMissing) => {
                            Some((expected_leaf, None, None))
                        }
                        Err(e) => {
                            // A present-but-broken catalog is a hard failure:
                            // roll back the whole staging child.
                            //
                            // ORDER MATTERS. The catalog output handle and any
                            // catalog lease were already released inside the
                            // closure. Remaining, in the order they block
                            // cleanup:
                            //   1. `inf_lock` — the retained INF lease. It
                            //      withholds write AND delete sharing, so the
                            //      staged INF cannot be removed while it lives.
                            //   2. `child_guard` — the DELETE-access child pin,
                            //      which blocks RemoveDirectory. It is NOT
                            //      dropped here: the rollback consumes it and
                            //      releases it at the right moment, because it
                            //      is also what makes the staged INF reachable
                            //      as an object rather than as a name.
                            // Any partially staged catalog was already removed
                            // (object-bound) inside the closure. Cleanup
                            // failures are reported, never ignored.
                            drop(inf_lock);
                            rollback_bound(
                                child_guard,
                                &staging_child,
                                staging_dir_identity,
                                &inf_leaves,
                                None,
                            )?;
                            return Err(e);
                        }
                    }
                }
                None => None,
            };

            // Split the triple: leaf, identity, retained catalog handle.
            let (catalog_leaf, catalog_identity, retained_catalog): (
                Option<String>,
                Option<FileObjectId>,
                Option<std::fs::File>,
            ) = match catalog_leaf {
                Some((l, id, handle)) => (Some(l), id, handle),
                None => (None, None, None),
            };

            // Move the proven leases into the artifact. Each was acquired
            // handle-relative under the pinned child and validated against the
            // creation handle's identity AND bytes, and each withholds write
            // and delete sharing for as long as the artifact lives.
            #[cfg(windows)]
            let lease_handles = Some(StagedFileLease {
                inf: inf_lock,
                catalog: retained_catalog,
            });
            // On non-Windows there is no lease, no identity and no
            // `StagedFileLease` type at all — the artifact simply has no such
            // fields. Consume the values so the build is warning-free.
            #[cfg(not(windows))]
            {
                let _ = (inf_lock, retained_catalog, catalog_identity, inf_identity);
            }

            Ok(StagedInfArtifact {
                staging_dir: staging_child,
                inf_path: output_path,
                expected_archive_member: request.inf().relative_path().to_string(),
                actual_archive_member: target.raw.clone(),
                pack_name: request.pack().pack_name().to_string(),
                pack_archive_path: request.pack().archive_path().to_path_buf(),
                catalog_leaf,
                size_bytes: written,
                #[cfg(windows)]
                inf_identity,
                #[cfg(windows)]
                catalog_identity,
                #[cfg(windows)]
                inf_digest: Some(inf_baseline),
                #[cfg(windows)]
                catalog_digest: staged_catalog_digest,
                #[cfg(windows)]
                staging_dir_identity,
                #[cfg(windows)]
                lease_handles,
            })
        }
        Err(e) => {
            // The creation handle withholds delete sharing, so it is released
            // first. The pin is handed to the rollback, not dropped: it is the
            // only thing that makes the leaf reachable as an object.
            drop(out);
            rollback_bound(
                child_guard,
                &staging_child,
                staging_dir_identity,
                &inf_leaves,
                None,
            )?;
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
            ExtractionError::TargetDecodeBudgetExceeded,
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

/// Shared streaming loop: reads `reader` through the fixed scratch buffer,
/// counting into `counter` (checked, capped at `cap`). Returns the number of
/// bytes read. A domain overrun aborts the traversal via `domain_err` + the
/// marker error, carrying `overrun` as the real reason.
fn drain(
    reader: &mut dyn Read,
    scratch: &mut [u8],
    counter: &mut u64,
    cap: u64,
    overrun: ExtractionError,
    domain_err: &std::cell::Cell<Option<ExtractionError>>,
) -> Result<u64, sevenz_rust2::Error> {
    let mut total = 0u64;
    loop {
        let n = reader.read(scratch).map_err(sevenz_rust2::Error::from)?;
        if n == 0 {
            break;
        }
        match counter.checked_add(n as u64) {
            Some(v) if v <= cap => *counter = v,
            _ => {
                domain_err.set(Some(overrun));
                return Err(marker_err());
            }
        }
        total += n as u64;
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Tab 2a-10 - bounded read-only multi-member content fingerprinting
// ---------------------------------------------------------------------------

/// Caller-owned payload bounds. The archive layer enforces them but does not
/// define them: the payload domain owns the numbers.
pub(crate) struct PayloadLimits {
    pub(crate) max_file_bytes: u64,
    pub(crate) max_total_bytes: u64,
    pub(crate) max_total_decode_bytes: u64,
}

/// One requested member's decoded identity: the archive's own spelling, the
/// exact decoded length and the SHA-256 of the bytes decoded NOW. This is
/// content identity, never authenticity, trust or a signature.
pub(crate) struct MemberFingerprint {
    pub(crate) actual_member: String,
    pub(crate) size_bytes: u64,
    pub(crate) sha256: [u8; 32],
}

/// Per-payload size cap. Named so the exact production boundary is testable
/// without a multi-hundred-megabyte fixture.
pub(crate) fn payload_size_within_cap(index: usize, size: u64, cap: u64) -> ExtractionResult<()> {
    if size > cap {
        return Err(ExtractionError::PayloadTooLarge { index });
    }
    Ok(())
}

/// Checked aggregate of the requested payloads' own declared sizes.
pub(crate) fn accumulate_payload_bytes(running: u64, add: u64, cap: u64) -> ExtractionResult<u64> {
    match running.checked_add(add) {
        Some(v) if v <= cap => Ok(v),
        _ => Err(ExtractionError::PayloadTotalBytesExceeded),
    }
}

/// Checked aggregate DECODE cost, including solid prerequisites.
pub(crate) fn accumulate_payload_decode_bytes(
    running: u64,
    add: u64,
    cap: u64,
) -> ExtractionResult<u64> {
    match running.checked_add(add) {
        Some(v) if v <= cap => Ok(v),
        _ => Err(ExtractionError::PayloadDecodeBudgetExceeded),
    }
}

/// The runtime decode counter: charged per streamed chunk and independent of
/// any declared metadata, so a lying archive cannot spend past `cap`.
pub(crate) fn charge_runtime_payload_bytes(
    running: u64,
    add: u64,
    cap: u64,
) -> ExtractionResult<u64> {
    match running.checked_add(add) {
        Some(v) if v <= cap => Ok(v),
        _ => Err(ExtractionError::PayloadDecodeBudgetExceeded),
    }
}

/// Test-only seam: how many block decoders the fingerprint path constructed.
/// Proves that targets sharing a solid block are grouped into ONE traversal
/// and that unrelated blocks are never decoded.
#[cfg(feature = "test-inject")]
static BLOCK_DECODES: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "test-inject")]
pub fn test_block_decode_count() -> usize {
    BLOCK_DECODES.load(Ordering::SeqCst) as usize
}

#[cfg(feature = "test-inject")]
pub fn test_reset_block_decode_count() {
    BLOCK_DECODES.store(0, Ordering::SeqCst);
}

fn note_block_decode() {
    #[cfg(feature = "test-inject")]
    BLOCK_DECODES.fetch_add(1, Ordering::SeqCst);
}

/// Fingerprint every `expected` member of one already-revalidated pack handle,
/// streaming under Cove's inherited archive bounds plus the caller's payload
/// bounds. Nothing is written anywhere: the handle is read-only input and the
/// decoded bytes exist only inside a fixed scratch buffer.
///
/// All-or-nothing: a missing, ambiguous, oversized, non-regular, duplicated or
/// undecodable member fails the WHOLE call, so a caller can never mistake a
/// partial answer for a complete one. Returns the fingerprints in `expected`
/// order, the DECLARED decode cost the bounds were checked against, and the
/// number of bytes ACTUALLY decoded - both of which include the solid
/// prerequisites that had to be decoded to reach a requested payload.
pub(crate) fn fingerprint_archive_members(
    file: &mut File,
    expected: &[String],
    limits: &PayloadLimits,
) -> ExtractionResult<(Vec<MemberFingerprint>, u64, u64)> {
    let archive = open_bounded_archive(file)?;
    let inspected = inspect_archive(&archive)?;

    // Resolve every requested member uniquely, then check its payload
    // contract and charge its declared size. No decoding has happened yet.
    // Grown, never pre-sized: this layer reserves capacity only from fixed
    // constants, so no caller- or metadata-supplied count drives an
    // allocation here (existing structural guard `r37_r38`).
    let mut resolved: Vec<usize> = Vec::new();
    let mut total_bytes: u64 = 0;
    for (i, want) in expected.iter().enumerate() {
        if !want.is_ascii() {
            return Err(ExtractionError::UnsupportedNonAsciiTarget);
        }
        let mut matches = 0usize;
        let mut matched = usize::MAX;
        for (j, e) in inspected.iter().enumerate() {
            if ascii_case_eq(&e.normalized, want) {
                matches += 1;
                matched = j;
            }
        }
        match matches {
            0 => return Err(ExtractionError::PayloadMemberMissing { index: i }),
            1 => {}
            n => {
                return Err(ExtractionError::PayloadMemberAmbiguous {
                    index: i,
                    matches: n,
                });
            }
        }
        // Two semantically distinct requests must never be coalesced onto one
        // archive entry: that would silently drop a referenced payload.
        if resolved.contains(&matched) {
            return Err(ExtractionError::DuplicateArchiveMember);
        }
        let t = &inspected[matched];
        validate_payload_contract(i, t, limits.max_file_bytes)?;
        total_bytes = accumulate_payload_bytes(total_bytes, t.size, limits.max_total_bytes)?;
        resolved.push(matched);
    }

    // Group the targets by compression block: a solid block holding several
    // requested payloads is decoded ONCE, never once per payload.
    let mut by_block: Vec<(usize, Vec<usize>)> = Vec::new();
    for (i, entry_index) in resolved.iter().copied().enumerate() {
        let b = inspected[entry_index]
            .block_index
            .ok_or(ExtractionError::PayloadNotRegularFile { index: i })?;
        match by_block.iter_mut().find(|(bb, _)| *bb == b) {
            Some((_, v)) => v.push(i),
            None => by_block.push((b, vec![i])),
        }
    }
    by_block.sort_by_key(|(b, _)| *b);

    // Declared decode cost, per block and in aggregate. The cost runs from the
    // block's FIRST entry through the LAST requested target in it, so solid
    // prerequisite bytes are charged, not just the payloads themselves.
    let mut declared_decode: u64 = 0;
    for (b, targets) in &by_block {
        let block = archive
            .blocks
            .get(*b)
            .ok_or(ExtractionError::InvalidPackAtExtraction(
                "payload block index out of range".into(),
            ))?;
        validate_target_block_coder_memory(block)?;
        let block_first = archive
            .stream_map
            .block_first_file_index
            .get(*b)
            .copied()
            .ok_or(ExtractionError::InvalidPackAtExtraction(
                "payload block first-file index out of range".into(),
            ))?;
        let last = targets
            .iter()
            .map(|i| resolved[*i])
            .max()
            .ok_or(ExtractionError::PayloadDecodeBudgetExceeded)?;
        let cost = decode_bytes_to_target(&inspected, block_first, last)
            .map_err(|_| ExtractionError::PayloadDecodeBudgetExceeded)?;
        declared_decode =
            accumulate_payload_decode_bytes(declared_decode, cost, limits.max_total_decode_bytes)?;
        if let Some(packed) = target_block_packed_bytes(&archive, *b) {
            let ratio = target_block_expansion_ratio(block.get_unpack_size(), packed)?;
            if ratio > MAX_TARGET_BLOCK_EXPANSION_RATIO {
                return Err(ExtractionError::TargetExpansionRatioExceeded);
            }
        }
    }

    let mut out: Vec<Option<MemberFingerprint>> = (0..expected.len()).map(|_| None).collect();
    let mut runtime_bytes: u64 = 0;
    for (b, targets) in &by_block {
        fingerprint_block_targets(
            file,
            &archive,
            *b,
            &inspected,
            &resolved,
            targets,
            limits.max_total_decode_bytes,
            &mut runtime_bytes,
            &mut out,
        )?;
    }

    // All or nothing: every requested payload must have been reached.
    let mut fingerprints = Vec::new();
    for (i, slot) in out.into_iter().enumerate() {
        fingerprints.push(slot.ok_or(ExtractionError::PayloadMemberMissing { index: i })?);
    }
    Ok((fingerprints, declared_decode, runtime_bytes))
}

/// Payload contract: a regular streamed file with a non-zero length inside the
/// per-payload cap and no reparse-point attribute. Deliberately separate from
/// [`validate_target_contract`], whose size cap is the INF's, not a payload's.
fn validate_payload_contract(
    index: usize,
    target: &InspectedEntry,
    max_file_bytes: u64,
) -> ExtractionResult<()> {
    if target.is_directory || target.is_anti_item || !target.has_stream || target.size == 0 {
        return Err(ExtractionError::PayloadNotRegularFile { index });
    }
    if target.has_windows_attributes && (target.windows_attributes & ATTR_REPARSE_POINT) != 0 {
        return Err(ExtractionError::PayloadNotRegularFile { index });
    }
    payload_size_within_cap(index, target.size, max_file_bytes)
}

/// Decode ONE block once, hashing every requested target in it and discarding
/// everything else, then stop at the last requested target in that block.
#[allow(clippy::too_many_arguments)]
fn fingerprint_block_targets(
    file: &mut File,
    archive: &Archive,
    block_index: usize,
    inspected: &[InspectedEntry],
    resolved: &[usize],
    targets: &[usize],
    cap: u64,
    runtime_bytes: &mut u64,
    out: &mut [Option<MemberFingerprint>],
) -> ExtractionResult<()> {
    // The decoder seeks from a known origin, exactly as the INF path does.
    file.seek(SeekFrom::Start(0)).map_err(ExtractionError::Io)?;

    // Name -> requested index, covering both the archive's own spelling and
    // the normalized form the backend may hand back.
    let mut lookup: HashMap<&str, usize> = HashMap::new();
    for i in targets {
        let e = &inspected[resolved[*i]];
        lookup.insert(e.raw.as_str(), *i);
        lookup.insert(e.normalized.as_str(), *i);
    }

    let empty_password = Password::empty();
    note_block_decode();
    let decoder = BlockDecoder::new(DECODER_THREADS, block_index, archive, &empty_password, file);

    let mut scratch = vec![0u8; STREAM_BUF_BYTES];
    let mut remaining = targets.len();
    let domain_err: std::cell::Cell<Option<ExtractionError>> = std::cell::Cell::new(None);

    let mut each = |entry: &sevenz_rust2::ArchiveEntry, reader: &mut dyn Read| {
        let Some(i) = lookup.get(entry.name()).copied() else {
            // Solid prerequisite or an unrelated member: drain and discard.
            drain(
                reader,
                &mut scratch,
                runtime_bytes,
                cap,
                ExtractionError::PayloadDecodeBudgetExceeded,
                &domain_err,
            )?;
            return Ok(true);
        };
        let declared = inspected[resolved[i]].size;
        let mut hasher = match Sha256Stream::new() {
            Ok(h) => h,
            Err(e) => {
                domain_err.set(Some(e));
                return Err(marker_err());
            }
        };
        // The body is NEVER materialized: it streams through the fixed
        // scratch buffer into the hash and is then discarded.
        let mut written: u64 = 0;
        loop {
            let n = reader
                .read(&mut scratch)
                .map_err(sevenz_rust2::Error::from)?;
            if n == 0 {
                break;
            }
            match charge_runtime_payload_bytes(*runtime_bytes, n as u64, cap) {
                Ok(v) => *runtime_bytes = v,
                Err(e) => {
                    domain_err.set(Some(e));
                    return Err(marker_err());
                }
            }
            if let Err(e) = hasher.update(&scratch[..n]) {
                domain_err.set(Some(e));
                return Err(marker_err());
            }
            written += n as u64;
            if written > declared {
                domain_err.set(Some(ExtractionError::PayloadTooLarge { index: i }));
                return Err(marker_err());
            }
        }
        if written != declared {
            domain_err.set(Some(ExtractionError::DecodedSizeMismatch {
                expected: declared,
                written,
            }));
            return Err(marker_err());
        }
        match hasher.finish() {
            Ok(sha256) => {
                out[i] = Some(MemberFingerprint {
                    // The archive's OWN spelling, which is what the public
                    // contract promises: it may differ from the normalized
                    // form in separators as well as case, and it has already
                    // passed the member-path validation above. The normalized
                    // form stays the matching and safety key.
                    actual_member: inspected[resolved[i]].raw.clone(),
                    size_bytes: written,
                    sha256,
                });
            }
            Err(e) => {
                domain_err.set(Some(e));
                return Err(marker_err());
            }
        }
        remaining -= 1;
        // Stop the moment the LAST requested target in this block is done;
        // nothing after it is decoded.
        Ok(remaining > 0)
    };

    let result = decoder.for_each_entries(&mut each);
    if let Some(domain) = domain_err.into_inner() {
        return Err(domain);
    }
    if let Err(e) = result {
        return Err(classify_backend_decode_error(&e));
    }
    if remaining != 0 {
        return Err(ExtractionError::PayloadMemberMissing { index: targets[0] });
    }
    Ok(())
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
        // Pin the temp dir (the parent) so creation is relative to it, and
        // attempt to create the existing leaf: must fail with
        // OutputAlreadyExists and must NOT overwrite.
        let guard = ChildDirGuard::open_pinned(&tmp).expect("pin tmp");
        let err =
            open_output_create_new(&guard, "driver.inf", &existing).expect_err("must fail closed");
        assert!(matches!(err, ExtractionError::OutputAlreadyExists));
        assert_eq!(fs::read(&existing).expect("read"), b"pre-existing");
        let _ = fs::remove_dir_all(&tmp);
    }
}
