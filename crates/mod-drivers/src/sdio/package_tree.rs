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
//! substrate is crate-private and only a test-only seam is reachable. The
//! population of a tree with driver bytes is a later slice's job.
//!
//! # Windows only
//!
//! Ownership needs Windows object handles. Off Windows the builder is
//! [`PackageTreeError::PlatformUnsupported`]; there is no weaker path-only
//! fallback. The pure plan is portable.
//!
//! # Transitional allowance
//!
//! The substrate has no in-crate consumer until the population slice lands, so
//! without the test seam it would be dead code. That single lint is allowed for
//! this module in non-test builds and must be removed when the consumer arrives.
#![cfg_attr(not(feature = "test-inject"), allow(dead_code))]

use std::path::Path;

use crate::sdio::extraction::ExtractionError;
use crate::sdio::payload_inventory::MAX_PAYLOAD_FILES;

mod plan;
#[cfg(windows)]
mod tree;

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
/// as owned, and a rollback that cannot finish is reported as
/// [`PackageTreeError::Rollback`], never swallowed. The caller's staging root
/// and everything else in it are never touched.
#[cfg(windows)]
fn build_owned_tree(
    plan: &plan::PackagePlan,
    staging_root: &Path,
    populate: &mut dyn FnMut(&mut tree::OwnedTree) -> Result<(), PackageTreeError>,
) -> Result<tree::OwnedTree, PackageTreeError> {
    let mut tree = tree::OwnedTree::open(staging_root, plan.files.len())?;
    let built = tree
        .create_root()
        .and_then(|()| tree.create_dirs(&plan.dirs))
        .and_then(|()| populate(&mut tree))
        .and_then(|()| tree.require_all_files(&plan.files))
        .and_then(|()| tree.reattest());
    match built {
        Ok(()) => Ok(tree),
        Err(cause) => match tree.destroy() {
            Ok(()) => Err(cause),
            Err(residue) => Err(PackageTreeError::Rollback {
                cause: Box::new(cause),
                residue,
            }),
        },
    }
}

/// Off Windows there is no owned tree: a refusal, never a path-only success.
#[cfg(not(windows))]
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
        super::build_owned_tree(&plan, staging_root, &mut |tree| {
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
        })
        .map(OwnedPackageTree)
    }
}
