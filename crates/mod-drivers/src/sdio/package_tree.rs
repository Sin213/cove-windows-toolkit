//! Tab 2a-11a - owned package tree substrate.
//!
//! The reusable filesystem ownership layer a future driver-source package is
//! built on. It can pre-plan a collision-safe namespace, create and OWN that
//! namespace under an explicit caller staging root using exact Windows object
//! handles, retain the ownership leases, prove through those handles that the
//! objects are still the ones it made, and destroy ONLY those objects.
//!
//! # What this is NOT
//!
//! It knows nothing about INFs, catalogs, payloads, archives, verified trust
//! tokens or installation, and it exposes nothing to a caller of the crate: the
//! substrate is crate-private and only a test-only seam is reachable. Files are
//! populated through a streaming primitive (create, write chunks, seal); the
//! only consumer is the package-materialization module.
//!
//! # Windows only
//!
//! Ownership needs Windows object handles. Off Windows the builder is
//! [`PackageTreeError::PlatformUnsupported`]; there is no weaker path-only
//! fallback. The pure plan is portable.

use std::path::Path;

use crate::sdio::extraction::ExtractionError;
use crate::sdio::payload_inventory::MAX_PAYLOAD_FILES;

mod plan;
#[cfg(windows)]
mod tree;

pub(crate) use plan::{PlannedFile, plan_package};
#[cfg(windows)]
pub(crate) use tree::OwnedTree;

// ---------------------------------------------------------------------------
// Bounds
//
// Safety baselines, not product promises. Path length, component length and
// component count are the archive-member bounds enforced by the shared path
// validator, so a package path is never allowed more than an archive member.
// ---------------------------------------------------------------------------

/// Root-level files a package may carry (an INF and a catalog, for the consumer).
pub(crate) const MAX_PACKAGE_ROOT_LEAVES: usize = 2;
/// Relative-path files beyond the root leaves.
pub(crate) const MAX_PACKAGE_PATH_FILES: usize = MAX_PAYLOAD_FILES;
pub(crate) const MAX_PACKAGE_FILES: usize = MAX_PACKAGE_ROOT_LEAVES + MAX_PACKAGE_PATH_FILES;
pub(crate) const MAX_PACKAGE_DIRS: usize = 4096;
pub(crate) const MAX_PACKAGE_RETAINED_PATH_BYTES: usize = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Errors (fail closed)
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PackageTreeError {
    #[error("secure package trees need Windows object handles")]
    PlatformUnsupported,
    #[error("package path {relative_path:?} is unsafe")]
    InvalidPackagePath { relative_path: String },
    #[error("package paths {first:?} and {second:?} collide")]
    PathCollision { first: String, second: String },
    #[error("too many package files (limit {MAX_PACKAGE_FILES})")]
    TooManyFiles,
    #[error("too many package directories (limit {MAX_PACKAGE_DIRS})")]
    TooManyDirectories,
    #[error("retained package path budget exceeded (limit {MAX_PACKAGE_RETAINED_PATH_BYTES})")]
    RetainedPathBudgetExceeded,
    #[error("invalid package staging root: {0}")]
    InvalidStagingRoot(String),
    #[error("no unused package root name was found")]
    PackRootCollision,
    #[error("filesystem layer refused: {0}")]
    Filesystem(ExtractionError),
    #[error("io error: {0}")]
    Io(std::io::Error),
    #[error("owned object {relative_path:?} changed")]
    PackageChanged { relative_path: String },
    #[error("cleanup failed: {0}")]
    CleanupFailed(String),
    /// A failure after the package root existed, AND the exact-object rollback
    /// could not remove everything Cove had created. The residue is real.
    #[error("build failed ({cause}) and rollback left residue: {residue}")]
    Rollback {
        cause: Box<PackageTreeError>,
        residue: String,
    },
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Create the package root and every planned directory under `staging_root`,
/// let `populate` create and fill the planned files, then require every planned
/// file to exist and the whole tree to re-attest.
///
/// All or nothing: any failure rolls back exactly the objects already recorded
/// as owned. The failure is returned as the CALLER's own error type `E` (so a
/// consumer's domain reason is never flattened into a generic tree error),
/// together with the residue text when the rollback could not finish, which is
/// never swallowed. The caller's staging root and everything else in it are
/// never touched.
#[cfg(windows)]
pub(crate) fn build_owned_tree<E: From<PackageTreeError>>(
    plan: &plan::PackagePlan,
    staging_root: &Path,
    populate: &mut dyn FnMut(&mut tree::OwnedTree) -> Result<(), E>,
) -> Result<tree::OwnedTree, (E, Option<String>)> {
    let mut tree =
        tree::OwnedTree::open(staging_root, plan.files.len()).map_err(|e| (E::from(e), None))?;
    let built = tree
        .create_root()
        .and_then(|()| tree.create_dirs(&plan.dirs))
        .map_err(E::from)
        .and_then(|()| populate(&mut tree))
        .and_then(|()| {
            tree.require_all_files(&plan.files)
                .and_then(|()| tree.reattest())
                .map_err(E::from)
        });
    match built {
        Ok(()) => Ok(tree),
        Err(cause) => Err((cause, tree.destroy().err())),
    }
}

/// Off Windows there is no owned tree: a refusal, never a path-only success.
/// (The materialization consumer refuses before it could call this.)
#[cfg(not(windows))]
#[allow(dead_code)]
fn build_owned_tree(
    _plan: &plan::PackagePlan,
    _staging_root: &Path,
) -> Result<std::convert::Infallible, PackageTreeError> {
    Err(PackageTreeError::PlatformUnsupported)
}

// ---------------------------------------------------------------------------
// Test-only seam
// ---------------------------------------------------------------------------

#[cfg(feature = "test-inject")]
pub mod seam {
    use std::path::{Path, PathBuf};

    pub use super::PackageTreeError;
    use super::plan;

    /// Moments at which the integration suite may act as an attacker or
    /// observer. Production builds have no hook and no call site.
    pub enum PackageHook<'a> {
        /// A nested directory was just created (its guard is held).
        AfterDirCreated { path: &'a Path },
        /// Every file lease is released; nothing has been deleted yet.
        AfterFilesReleased { root: &'a Path },
        /// One nested directory's own guard is released, before it is deleted.
        AfterDirGuardReleased { path: &'a Path, rel: &'a str },
        /// The package-root guard is released, before the root is deleted.
        AfterRootGuardReleased { path: &'a Path },
    }

    type HookFn = Box<dyn Fn(&PackageHook<'_>)>;

    thread_local! {
        static HOOK: std::cell::RefCell<Option<HookFn>> = const { std::cell::RefCell::new(None) };
    }

    pub fn test_set_package_hook(hook: Option<HookFn>) {
        HOOK.with(|h| *h.borrow_mut() = hook);
    }

    #[cfg(windows)]
    pub(super) fn run_hook(point: &PackageHook<'_>) {
        HOOK.with(|h| {
            if let Some(f) = h.borrow().as_ref() {
                f(point);
            }
        });
    }

    /// The pure plan's `(directories, files)` counts, or its refusal.
    pub fn test_plan_package(
        root_leaves: &[&str],
        paths: &[&str],
    ) -> Result<(usize, usize), PackageTreeError> {
        plan::plan_package(root_leaves, paths).map(|p| (p.dirs.len(), p.files.len()))
    }

    /// [`test_plan_package`] with an explicit retained-text budget, so the
    /// accounting is tested through the planner itself.
    pub fn test_plan_package_with_budget(
        root_leaves: &[&str],
        paths: &[&str],
        budget: usize,
    ) -> Result<(usize, usize), PackageTreeError> {
        plan::plan_package_with_budget(root_leaves, paths, budget)
            .map(|p| (p.dirs.len(), p.files.len()))
    }

    pub fn test_charge_retained_path_bytes(
        running: usize,
        add: usize,
    ) -> Result<usize, PackageTreeError> {
        plan::charge_retained_path_bytes(running, add)
    }

    /// Which recorded identity a test corrupts to model "the handle now names a
    /// different object than the one recorded".
    pub enum IdentityTarget {
        Root,
        Dir(usize),
        File(usize),
    }

    /// The owned tree, as the suite sees it. Deliberately not `Clone`: it owns
    /// the filesystem leases, and a second copy would be a second claim on one
    /// set of handles.
    #[cfg(windows)]
    pub struct OwnedPackageTree(super::tree::OwnedTree);

    #[cfg(windows)]
    impl OwnedPackageTree {
        pub fn reattest(&self) -> Result<(), PackageTreeError> {
            self.0.reattest()
        }
        pub fn current_root_path(&self) -> Result<PathBuf, PackageTreeError> {
            self.0.root_path()
        }
        pub fn cleanup(self) -> Result<(), PackageTreeError> {
            self.0.destroy().map_err(PackageTreeError::CleanupFailed)
        }
        /// The `(length, SHA-256)` baseline recorded for planned file `slot`.
        pub fn baseline(&self, slot: usize) -> Option<(u64, [u8; 32])> {
            self.0.baseline(slot)
        }
        /// Mutate a retained file through its own creation handle, to prove
        /// re-attestation notices an in-place change that keeps its identity.
        pub fn write_through_retained_handle(&self, slot: usize, offset: u64, byte: u8) -> bool {
            self.0.write_through(slot, offset, byte)
        }
        pub fn corrupt_recorded_identity(&mut self, target: IdentityTarget) -> bool {
            self.0.corrupt_identity(target)
        }
    }

    /// How many times a live handle's final path was queried (process-wide).
    #[cfg(windows)]
    pub fn test_handle_path_queries() -> u64 {
        super::tree::path_queries()
    }

    /// Fold the builder's `(cause, residue)` failure back into the tree error.
    #[cfg(windows)]
    fn folded(
        built: Result<super::tree::OwnedTree, (PackageTreeError, Option<String>)>,
    ) -> Result<OwnedPackageTree, PackageTreeError> {
        built
            .map(OwnedPackageTree)
            .map_err(|(cause, residue)| match residue {
                None => cause,
                Some(residue) => PackageTreeError::Rollback {
                    cause: Box::new(cause),
                    residue,
                },
            })
    }

    /// Like [`test_build_tree`], but every planned file is written as the
    /// producer's `pieces(slot)` chunks and then sealed against
    /// `claim(slot, written_len, written_sha256)`, which may lie. Proves the
    /// seal holds the destination to the claim rather than trusting it.
    #[cfg(windows)]
    pub fn test_build_tree_streamed(
        root_leaves: &[&str],
        paths: &[&str],
        staging_root: &Path,
        pieces: &dyn Fn(usize) -> Vec<Vec<u8>>,
        claim: &dyn Fn(usize, u64, [u8; 32]) -> (u64, [u8; 32]),
    ) -> Result<OwnedPackageTree, PackageTreeError> {
        use crate::sdio::extraction::Sha256Stream;
        let plan = plan::plan_package(root_leaves, paths)?;
        folded(super::build_owned_tree(&plan, staging_root, &mut |tree| {
            for (slot, pf) in plan.files.iter().enumerate() {
                tree.create_file(slot, pf)?;
                let mut hasher = Sha256Stream::new().map_err(PackageTreeError::Filesystem)?;
                let mut len = 0u64;
                for piece in pieces(slot) {
                    tree.write_file_chunk(slot, &piece)?;
                    hasher
                        .update(&piece)
                        .map_err(PackageTreeError::Filesystem)?;
                    len += piece.len() as u64;
                }
                let sha = hasher.finish().map_err(PackageTreeError::Filesystem)?;
                let claimed = claim(slot, len, sha);
                let sealed = tree.seal_file(slot, claimed.0, claimed.1);
                // The seal itself must refuse a claim its own destination
                // contradicts; the builder's later re-attestation is a second
                // line, not a substitute.
                if claimed != (len, sha) && sealed.is_ok() {
                    return Err(PackageTreeError::Io(std::io::Error::other(
                        "seal accepted a contradicted claim",
                    )));
                }
                sealed?;
            }
            Ok(())
        }))
    }

    /// Plan, then build a tree whose planned files (root leaves, then paths, by
    /// index) are filled with `contents(index)`. `fail_after_files = Some(n)`
    /// injects a failure once `n` files exist, to exercise rollback.
    #[cfg(windows)]
    pub fn test_build_tree(
        root_leaves: &[&str],
        paths: &[&str],
        staging_root: &Path,
        contents: &dyn Fn(usize) -> Vec<u8>,
        fail_after_files: Option<usize>,
    ) -> Result<OwnedPackageTree, PackageTreeError> {
        let plan = plan::plan_package(root_leaves, paths)?;
        let mut made = 0usize;
        folded(super::build_owned_tree(&plan, staging_root, &mut |tree| {
            for (slot, pf) in plan.files.iter().enumerate() {
                if fail_after_files == Some(made) {
                    return Err(PackageTreeError::Io(std::io::Error::other(
                        "injected failure",
                    )));
                }
                tree.create_file(slot, pf)?;
                tree.fill_file(slot, &contents(slot))?;
                made += 1;
            }
            Ok(())
        }))
    }
}
