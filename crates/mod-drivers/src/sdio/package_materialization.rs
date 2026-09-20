//! Tab 2a-11b - digest-bound package population.
//!
//! Given a live [`ResolvedPayloadInventory`] and a caller-provided staging root,
//! this module populates ONE Cove-owned package tree (the Tab 2a-11a substrate)
//! with the exact verified INF and catalog and every inventoried payload:
//!
//! ```text
//! slot 0      <package-root>\<verified INF leaf>
//! slot 1      <package-root>\<verified catalog leaf>      when the token has one
//! slot 2..    <package-root>\<source_path>                payloads, inventory order
//! ```
//!
//! # Where each byte comes from
//!
//! - The INF and catalog are COPIED from the verified staged files the live
//!   [`VerifiedDriverPackage`] retains, through a fixed buffer. They are never
//!   re-extracted: the pack is hostile CURRENT input, and an archive INF is not
//!   the INF Windows verified.
//! - Every payload is decoded from the CURRENT local pack (reopened through the
//!   Tab 2a-10 hardened path) and must equal the inventory's archive-member
//!   spelling, decoded size and SHA-256. A mismatch is stale-inventory /
//!   payload drift and fails the whole package; the inventory is never
//!   refreshed here. Accepting new bytes needs a fresh Tab 2a-10 inventory.
//! - The decoding pass is the Tab 2a-10 block traversal itself: one traversal
//!   per required solid block, prerequisites charged exactly as before,
//!   unrelated blocks never decoded. The same stream that is hashed is written
//!   into the leased destination file.
//!
//! # What success means
//!
//! ONLY this: a Cove-owned filesystem tree exists whose files are the verified
//! INF/catalog and payloads matching the inventory, each sealed against what
//! its own retained handle holds, and the returned object holds the ownership
//! leases. It does NOT mean the Driver Store accepts the package, a payload is
//! independently trusted, an install is authorized, or a driver is installed.
//! Nothing here installs anything.
//!
//! # Windows only
//!
//! Secure population needs Windows object handles. Elsewhere the entry point is
//! [`PackageMaterializationError::PlatformUnsupported`]; there is no weaker
//! path-only fallback.
//!
//! # Cleanup is explicit
//!
//! Dropping the capability releases its handles and deletes nothing. Removal is
//! [`MaterializedDriverSource::cleanup`], the 11a exact-object teardown. The
//! verified INF/catalog staging stays owned by the [`VerifiedDriverPackage`].
//!
//! # The capability is non-`Clone` and cannot outlive the trust lease
//!
//! ```compile_fail
//! fn assert_clone<T: Clone>() {}
//! assert_clone::<mod_drivers::sdio::package_materialization::MaterializedDriverSource<'static>>();
//! ```
//!
//! The companion positive case compiles, so the failure above is `Clone`:
//!
//! ```
//! fn assert_debug<T: std::fmt::Debug>() {}
//! assert_debug::<mod_drivers::sdio::package_materialization::MaterializedDriverSource<'static>>();
//! ```
//!
//! It borrows the live token, so it cannot escape it:
//!
//! ```compile_fail
//! use mod_drivers::sdio::package_materialization::MaterializedDriverSource;
//! fn escape<'a>(m: MaterializedDriverSource<'a>) -> MaterializedDriverSource<'static> { m }
//! ```
//!
//! ```
//! use mod_drivers::sdio::package_materialization::MaterializedDriverSource;
//! fn keep<'a>(m: MaterializedDriverSource<'a>) -> MaterializedDriverSource<'a> { m }
//! ```

use std::path::{Path, PathBuf};

use crate::sdio::extraction::ExtractionError;
use crate::sdio::package_tree::PackageTreeError;
use crate::sdio::payload_inventory::ResolvedPayloadInventory;
use crate::sdio::signature::{TrustError, VerifiedDriverPackage};

#[cfg(windows)]
use std::fs::{File, OpenOptions};
#[cfg(windows)]
use std::io::Read;
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

#[cfg(windows)]
use crate::sdio::extraction::{
    MemberFingerprint, MemberSink, PayloadLimits, Sha256Stream, stream_archive_members,
};
#[cfg(windows)]
use crate::sdio::package_tree::{OwnedTree, PlannedFile, build_owned_tree, plan_package};
#[cfg(windows)]
use crate::sdio::payload_inventory::{
    MAX_PAYLOAD_FILE_BYTES, MAX_PAYLOAD_TOTAL_BYTES, MAX_PAYLOAD_TOTAL_DECODE_BYTES,
    PayloadInventoryEntry, expected_member, reopen_pack,
};
#[cfg(windows)]
use crate::sdio::signature::MAX_STAGED_INF_BYTES;

/// Plan slots of the root leaves; payload slots follow in inventory order.
const INF_SLOT: usize = 0;
#[cfg(windows)]
const CATALOG_SLOT: usize = 1;
/// Fixed scratch buffer for the INF/catalog copy (never sized from a file).
#[cfg(windows)]
const COPY_CHUNK_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Errors (fail closed)
// ---------------------------------------------------------------------------

/// Fail-closed reasons a populated package was not produced. `index` is the
/// payload's position in the input inventory.
#[derive(Debug, thiserror::Error)]
pub enum PackageMaterializationError {
    #[error("secure package materialization needs Windows object handles")]
    PlatformUnsupported,
    #[error("verified package re-attestation failed: {0}")]
    Attestation(TrustError),
    #[error("package path {relative_path:?} is unsafe")]
    InvalidPackagePath { relative_path: String },
    #[error("package paths {first:?} and {second:?} collide")]
    PathCollision { first: String, second: String },
    #[error("too many package files")]
    TooManyFiles,
    #[error("too many package directories")]
    TooManyDirectories,
    #[error("retained package path budget exceeded")]
    RetainedPathBudgetExceeded,
    #[error("invalid package staging root: {0}")]
    InvalidStagingRoot(String),
    #[error("no unused package root name was found")]
    PackRootCollision,
    #[error("the local pack changed since the inventory")]
    PackChangedSinceInventory,
    /// The archive member the payload resolves to now is not spelled the way
    /// the inventory recorded it. A fresh inventory is required.
    #[error("payload {index} no longer resolves to the inventory's archive member")]
    InventoryStale { index: usize },
    /// The payload's size or SHA-256 is not the inventory's.
    #[error("payload {index} differs from the inventory's size or SHA-256")]
    PayloadDrift { index: usize },
    #[error("payload {index} is missing from the archive")]
    PayloadMemberMissing { index: usize },
    #[error("payload {index} is ambiguous ({matches} archive members match)")]
    PayloadMemberAmbiguous { index: usize, matches: usize },
    #[error("verified source {leaf:?} is unavailable")]
    SourceUnavailable { leaf: String },
    /// The archive or hashing layer refused; the original reason is kept.
    #[error("archive error: {0}")]
    Archive(ExtractionError),
    #[error("io error: {0}")]
    Io(std::io::Error),
    #[error("materialized object {relative_path:?} changed")]
    PackageChanged { relative_path: String },
    #[error("cleanup failed: {0}")]
    CleanupFailed(String),
    /// A failure after the package root existed, AND the exact-object rollback
    /// could not remove everything Cove had created. The residue is real.
    #[error("materialization failed ({cause}) and rollback left residue: {residue}")]
    Rollback {
        cause: Box<PackageMaterializationError>,
        residue: String,
    },
}

use PackageMaterializationError as Error;

impl From<PackageTreeError> for Error {
    fn from(e: PackageTreeError) -> Self {
        match e {
            PackageTreeError::PlatformUnsupported => Error::PlatformUnsupported,
            PackageTreeError::InvalidPackagePath { relative_path } => {
                Error::InvalidPackagePath { relative_path }
            }
            PackageTreeError::PathCollision { first, second } => {
                Error::PathCollision { first, second }
            }
            PackageTreeError::TooManyFiles => Error::TooManyFiles,
            PackageTreeError::TooManyDirectories => Error::TooManyDirectories,
            PackageTreeError::RetainedPathBudgetExceeded => Error::RetainedPathBudgetExceeded,
            PackageTreeError::InvalidStagingRoot(s) => Error::InvalidStagingRoot(s),
            PackageTreeError::PackRootCollision => Error::PackRootCollision,
            PackageTreeError::Filesystem(e) => Error::Archive(e),
            PackageTreeError::Io(e) => Error::Io(e),
            PackageTreeError::PackageChanged { relative_path } => {
                Error::PackageChanged { relative_path }
            }
            PackageTreeError::CleanupFailed(s) => Error::CleanupFailed(s),
            PackageTreeError::Rollback { cause, residue } => Error::Rollback {
                cause: Box::new((*cause).into()),
                residue,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/// What a materialized file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializedPackageFileKind {
    Inf,
    Catalog,
    Payload,
}

/// Read-only metadata for one file in the tree: its package-relative path, its
/// exact length and the SHA-256 it is held to. Content identity only, never
/// trust. For payloads it equals the inventory's; for the INF and catalog it
/// describes the verified bytes that were copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedPackageFile {
    relative_path: String,
    kind: MaterializedPackageFileKind,
    size_bytes: u64,
    sha256: [u8; 32],
}

impl MaterializedPackageFile {
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
    pub fn kind(&self) -> MaterializedPackageFileKind {
        self.kind
    }
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// The populated package: a live ownership lease over a Cove-owned tree, bound
/// to the same live token as the inventory it came from.
///
/// Files are listed INF, catalog (when present), then payloads in inventory
/// order. Deliberately not `Clone`: it owns the destination handles.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct MaterializedDriverSource<'v> {
    verified: &'v VerifiedDriverPackage,
    files: Vec<MaterializedPackageFile>,
    declared_decode_bytes: u64,
    decode_bytes: u64,
    #[cfg(windows)]
    tree: OwnedTree,
}

impl std::fmt::Debug for MaterializedDriverSource<'_> {
    /// Redacted: the retained handles must never be formatted into logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaterializedDriverSource")
            .field("files", &self.files)
            .finish_non_exhaustive()
    }
}

impl<'v> MaterializedDriverSource<'v> {
    pub fn files(&self) -> &[MaterializedPackageFile] {
        &self.files
    }

    /// The live token this package is bound to.
    pub fn verified_package(&self) -> &'v VerifiedDriverPackage {
        self.verified
    }

    /// Bytes actually decoded from the pack, solid prerequisites included.
    pub fn decode_bytes(&self) -> u64 {
        self.decode_bytes
    }

    /// The declared decode cost the bounds were checked against before decoding.
    pub fn declared_decode_bytes(&self) -> u64 {
        self.declared_decode_bytes
    }

    /// Re-prove the token, then the tree through its retained handles only,
    /// then that every exposed file still agrees with the tree's baseline, then
    /// the token again: success is impossible if the trusted source changed
    /// while the tree was being verified. No pathname reopen is authoritative.
    pub fn reattest(&self) -> Result<(), Error> {
        #[cfg(windows)]
        {
            self.verified.reattest().map_err(Error::Attestation)?;
            self.tree.reattest()?;
            for (slot, f) in self.files.iter().enumerate() {
                if self.tree.baseline(slot) != Some((f.size_bytes, f.sha256)) {
                    return Err(Error::PackageChanged {
                        relative_path: f.relative_path.clone(),
                    });
                }
            }
            self.verified.reattest().map_err(Error::Attestation)
        }
        #[cfg(not(windows))]
        Err(Error::PlatformUnsupported)
    }

    /// The package root's CURRENT path, derived from the live root handle. A
    /// pathname captured at creation would go stale if a caller-owned ancestor
    /// moved. A locator, not a security identity.
    pub fn current_root_path(&self) -> Result<PathBuf, Error> {
        #[cfg(windows)]
        {
            Ok(self.tree.root_path()?)
        }
        #[cfg(not(windows))]
        Err(Error::PlatformUnsupported)
    }

    /// The CURRENT path of the copied INF, derived from its retained handle.
    pub fn current_inf_path(&self) -> Result<PathBuf, Error> {
        #[cfg(windows)]
        {
            Ok(self.tree.file_path(INF_SLOT)?)
        }
        #[cfg(not(windows))]
        Err(Error::PlatformUnsupported)
    }

    /// Explicit exact-object cleanup (the 11a teardown): file leases released,
    /// every recorded file deleted bound to its identity, directories
    /// deepest-first, then the root relative to the retained staging-root
    /// object. Never recursive. The original verified staging is not touched.
    pub fn cleanup(self) -> Result<(), Error> {
        #[cfg(windows)]
        {
            self.tree.destroy().map_err(Error::CleanupFailed)
        }
        #[cfg(not(windows))]
        Err(Error::PlatformUnsupported)
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Populate a new Cove-named package tree under `staging_root`, which must
/// already exist as a real directory, from `inventory`.
///
/// All or nothing: any failure rolls back exactly what was created (a rollback
/// that cannot finish is [`Error::Rollback`], never swallowed). The live token
/// is re-attested before any destination object is created and again before
/// success is returned.
pub fn materialize_driver_source<'v>(
    inventory: &ResolvedPayloadInventory<'v>,
    staging_root: &Path,
) -> Result<MaterializedDriverSource<'v>, Error> {
    #[cfg(windows)]
    {
        let verified = inventory.verified_package();
        materialize_with(
            inventory,
            staging_root,
            &mut || verified.reattest(),
            &mut || verified.reattest(),
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (inventory, staging_root);
        Err(PackageMaterializationError::PlatformUnsupported)
    }
}

#[cfg(windows)]
fn materialize_with<'v>(
    inventory: &ResolvedPayloadInventory<'v>,
    staging_root: &Path,
    pre: &mut dyn FnMut() -> Result<(), TrustError>,
    post: &mut dyn FnMut() -> Result<(), TrustError>,
) -> Result<MaterializedDriverSource<'v>, Error> {
    let verified = inventory.verified_package();
    let entries = inventory.entries();
    let inf_leaf = verified
        .inf_path()
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(Error::SourceUnavailable {
            leaf: "<inf>".into(),
        })?;

    // The committed 11a planner decides namespace safety and collisions. Slot
    // order is its root-leaf order then path order: INF, catalog when present,
    // then payloads in inventory order. Nothing else is planned here.
    let root_leaves: Vec<&str> = std::iter::once(inf_leaf)
        .chain(verified.expected_catalog_leaf())
        .collect();
    let payload_paths: Vec<&str> = entries.iter().map(|e| e.source_path()).collect();
    let plan = plan_package(&root_leaves, &payload_paths)?;

    // Logical archive lookup key per payload: the verified INF member's
    // directory plus the source path, composed by the Tab 2a-10 helper.
    let mut expected: Vec<String> = Vec::new();
    for (index, e) in entries.iter().enumerate() {
        let member = expected_member(index, verified.expected_archive_member(), e.source_path())
            .map_err(|_| Error::InvalidPackagePath {
                relative_path: e.source_path().to_string(),
            })?;
        expected.push(member);
    }

    // Nothing is created or decoded until the trust lease holds.
    pre().map_err(Error::Attestation)?;

    // The current pack is reopened through the hardened Tab 2a-10 path BEFORE
    // any destination object exists, so a vanished or swapped pack creates
    // nothing.
    let mut pack =
        reopen_pack(verified.pack_archive_path()).map_err(|_| Error::PackChangedSinceInventory)?;
    let mut decoded = (0u64, 0u64);
    let built = build_owned_tree::<Error>(&plan, staging_root, &mut |tree| {
        populate(
            tree,
            inventory,
            &plan.files,
            root_leaves.len(),
            &expected,
            &mut pack,
            &mut decoded,
        )
    });
    drop(pack);
    let tree = match built {
        Ok(t) => t,
        Err((cause, residue)) => return Err(rolled_back(cause, residue)),
    };

    // The tree has re-attested; now the trusted source must still hold. If it
    // does not, the freshly built tree is destroyed and no capability returns.
    let finished = post()
        .map_err(Error::Attestation)
        .and_then(|()| public_files(&plan.files, &tree, root_leaves.len()));
    match finished {
        Ok(files) => Ok(MaterializedDriverSource {
            verified,
            files,
            declared_decode_bytes: decoded.0,
            decode_bytes: decoded.1,
            tree,
        }),
        Err(cause) => Err(rolled_back(cause, tree.destroy().err())),
    }
}

/// `cause`, or `cause` plus the residue a failed rollback left behind.
#[cfg(windows)]
fn rolled_back(cause: Error, residue: Option<String>) -> Error {
    match residue {
        None => cause,
        Some(residue) => Error::Rollback {
            cause: Box::new(cause),
            residue,
        },
    }
}

/// Fill the planned files: the verified INF and catalog by copy, then every
/// payload through the shared archive traversal.
#[cfg(windows)]
fn populate(
    tree: &mut OwnedTree,
    inventory: &ResolvedPayloadInventory<'_>,
    files: &[PlannedFile],
    first_payload: usize,
    expected: &[String],
    pack: &mut File,
    decoded: &mut (u64, u64),
) -> Result<(), Error> {
    let verified = inventory.verified_package();
    // The verified staged INF, never an INF re-extracted from the pack.
    let inf_path = verified.inf_path();
    copy_verified(tree, INF_SLOT, &files[INF_SLOT], inf_path)?;
    // The catalog is the locked file beside the verified INF, named by the
    // token's own validated leaf: never searched for, never taken from the pack.
    if let Some(cat) = verified.expected_catalog_leaf() {
        let dir = inf_path.parent().ok_or(Error::SourceUnavailable {
            leaf: cat.to_string(),
        })?;
        copy_verified(tree, CATALOG_SLOT, &files[CATALOG_SLOT], &dir.join(cat))?;
    }

    let limits = PayloadLimits {
        max_file_bytes: MAX_PAYLOAD_FILE_BYTES,
        max_total_bytes: MAX_PAYLOAD_TOTAL_BYTES,
        max_total_decode_bytes: MAX_PAYLOAD_TOTAL_DECODE_BYTES,
    };
    let mut sink = PayloadSink {
        tree,
        entries: inventory.entries(),
        files,
        first_payload,
        failure: None,
    };
    match stream_archive_members(pack, expected, &limits, &mut sink) {
        Ok(costs) => {
            *decoded = costs;
            Ok(())
        }
        // The sink's own domain reason wins over the generic abort marker.
        Err(e) => Err(sink.failure.take().unwrap_or(match e {
            ExtractionError::PayloadMemberMissing { index } => {
                Error::PayloadMemberMissing { index }
            }
            ExtractionError::PayloadMemberAmbiguous { index, matches } => {
                Error::PayloadMemberAmbiguous { index, matches }
            }
            other => Error::Archive(other),
        })),
    }
}

/// Copy one verified staged file into its leased destination through a fixed
/// buffer: read-only source, exact length, hashed as it is read, and the
/// destination sealed against what its own handle then holds.
#[cfg(windows)]
fn copy_verified(
    tree: &mut OwnedTree,
    slot: usize,
    pf: &PlannedFile,
    src: &Path,
) -> Result<(), Error> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ,
    };
    let unavailable = || Error::SourceUnavailable {
        leaf: pf.leaf.clone(),
    };
    let mut source = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(src)
        .map_err(|_| unavailable())?;
    let meta = source.metadata().map_err(|_| unavailable())?;
    let bad_attrs = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
    // The bound is the verified-source bound the trust layer already enforces.
    if !meta.is_file()
        || meta.file_attributes() & bad_attrs != 0
        || meta.len() == 0
        || meta.len() > MAX_STAGED_INF_BYTES
    {
        return Err(unavailable());
    }
    tree.create_file(slot, pf)?;
    let mut hasher = Sha256Stream::new().map_err(Error::Archive)?;
    let mut buf = [0u8; COPY_CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        let n = source.read(&mut buf).map_err(|_| unavailable())?;
        if n == 0 {
            break;
        }
        // A source that grows past the length it had when opened is refused.
        total = total
            .checked_add(n as u64)
            .filter(|t| *t <= meta.len())
            .ok_or_else(unavailable)?;
        hasher.update(&buf[..n]).map_err(Error::Archive)?;
        tree.write_file_chunk(slot, &buf[..n])?;
    }
    if total != meta.len() {
        return Err(unavailable());
    }
    let sha256 = hasher.finish().map_err(Error::Archive)?;
    Ok(tree.seal_file(slot, total, sha256)?)
}

/// Writes each requested payload into its leased destination as it is decoded
/// and holds it to the inventory's spelling, size and SHA-256.
#[cfg(windows)]
struct PayloadSink<'a> {
    tree: &'a mut OwnedTree,
    entries: &'a [PayloadInventoryEntry],
    files: &'a [PlannedFile],
    first_payload: usize,
    failure: Option<Error>,
}

#[cfg(windows)]
impl PayloadSink<'_> {
    /// Keep the domain reason out of band and abort the traversal.
    fn refuse(&mut self, reason: Error) -> Result<(), ExtractionError> {
        self.failure = Some(reason);
        Err(ExtractionError::SinkAborted)
    }

    fn slot(&self, index: usize) -> usize {
        self.first_payload + index
    }
}

#[cfg(windows)]
impl MemberSink for PayloadSink<'_> {
    /// Runs before any decode and before any payload file exists.
    fn resolved(&mut self, index: usize, raw: &str, declared: u64) -> Result<(), ExtractionError> {
        let want = &self.entries[index];
        if raw != want.actual_archive_member() {
            return self.refuse(Error::InventoryStale { index });
        }
        if declared != want.fingerprint().size_bytes() {
            return self.refuse(Error::PayloadDrift { index });
        }
        Ok(())
    }

    fn begin(&mut self, index: usize) -> Result<(), ExtractionError> {
        let slot = self.slot(index);
        match self.tree.create_file(slot, &self.files[slot]) {
            Ok(()) => Ok(()),
            Err(e) => self.refuse(e.into()),
        }
    }

    fn write(&mut self, index: usize, chunk: &[u8]) -> Result<(), ExtractionError> {
        let slot = self.slot(index);
        match self.tree.write_file_chunk(slot, chunk) {
            Ok(()) => Ok(()),
            Err(e) => self.refuse(e.into()),
        }
    }

    fn finish(&mut self, index: usize, fp: MemberFingerprint) -> Result<(), ExtractionError> {
        let want = self.entries[index].fingerprint();
        if fp.size_bytes != want.size_bytes() || fp.sha256 != *want.sha256() {
            return self.refuse(Error::PayloadDrift { index });
        }
        // The destination is sealed against what its own handle holds, not
        // against the stream's claim.
        let slot = self.slot(index);
        match self.tree.seal_file(slot, fp.size_bytes, fp.sha256) {
            Ok(()) => Ok(()),
            Err(e) => self.refuse(e.into()),
        }
    }
}

/// The public file list, from the tree's sealed baselines. A missing baseline
/// means a file was never completely populated, which is not a success.
#[cfg(windows)]
fn public_files(
    files: &[PlannedFile],
    tree: &OwnedTree,
    first_payload: usize,
) -> Result<Vec<MaterializedPackageFile>, Error> {
    files
        .iter()
        .enumerate()
        .map(|(slot, pf)| {
            let (size_bytes, sha256) = tree.baseline(slot).ok_or(Error::PackageChanged {
                relative_path: pf.rel.clone(),
            })?;
            let kind = match slot {
                INF_SLOT => MaterializedPackageFileKind::Inf,
                s if s < first_payload => MaterializedPackageFileKind::Catalog,
                _ => MaterializedPackageFileKind::Payload,
            };
            Ok(MaterializedPackageFile {
                relative_path: pf.rel.clone(),
                kind,
                size_bytes,
                sha256,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Test-only seams
// ---------------------------------------------------------------------------

/// Drive population with injected pre/post attestations.
#[cfg(feature = "test-inject")]
pub fn test_materialize_with_attestation<'v>(
    inventory: &ResolvedPayloadInventory<'v>,
    staging_root: &Path,
    pre: &mut dyn FnMut() -> Result<(), TrustError>,
    post: &mut dyn FnMut() -> Result<(), TrustError>,
) -> Result<MaterializedDriverSource<'v>, Error> {
    #[cfg(windows)]
    {
        materialize_with(inventory, staging_root, pre, post)
    }
    #[cfg(not(windows))]
    {
        let _ = (inventory, staging_root, pre, post);
        Err(Error::PlatformUnsupported)
    }
}

/// Mutate one retained file (by `files()` index) through its own creation
/// handle, to prove re-attestation detects an in-place content change that
/// preserves object identity. Returns whether the write happened.
#[cfg(feature = "test-inject")]
pub fn test_write_through_retained_handle(
    source: &MaterializedDriverSource<'_>,
    file_index: usize,
    offset: u64,
    byte: u8,
) -> bool {
    #[cfg(windows)]
    {
        source.tree.write_through(file_index, offset, byte)
    }
    #[cfg(not(windows))]
    {
        let _ = (source, file_index, offset, byte);
        false
    }
}
