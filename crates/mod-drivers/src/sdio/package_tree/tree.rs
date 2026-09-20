//! Windows ownership of the package tree.
//!
//! Every object here is created HANDLE-RELATIVE to an already-owned parent
//! directory object and retained as a live lease:
//!
//! - the caller's staging root is held as a permissive ANCHOR (it identifies
//!   the object; it is shared with other Cove operations and is not Cove's to
//!   lock), so the package root can still be deleted relative to the ORIGINAL
//!   staging-root object if the caller's pathname later moves;
//! - the package root and every nested directory are held with
//!   `FILE_SHARE_READ` only, so none can be renamed, deleted or replaced;
//! - every file keeps its CREATION handle (write+read access, `FILE_SHARE_READ`
//!   only), so a path-based overwrite, rename or delete is refused for as long
//!   as the tree lives.
//!
//! Cleanup deletes only recorded objects, files first, then directories
//! deepest-first, then the root, each bound to its recorded 128-bit identity.
//! There is no enumeration and no recursive deletion: an object Cove did not
//! record makes cleanup fail closed and stay on disk for the operator.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::PackageTreeError as Error;
use super::plan::{PlannedDir, PlannedFile};
#[cfg(feature = "test-inject")]
use crate::sdio::extraction::Sha256Stream;
use crate::sdio::extraction::{
    ChildDirGuard, ExtractionError, FileObjectId, create_owned_dir_relative,
    delete_owned_leaf_checked, delete_staging_child_checked, digest_of_raw_handle,
    object_id_of_raw_handle, open_output_create_new, validate_staging_root,
};

const PACKAGE_ROOT_PREFIX: &str = "cove-driver-package-";
const MAX_ROOT_ATTEMPTS: u32 = 128;
/// Bounds the final-path buffer so a hostile path cannot drive an unbounded loop.
const MAX_FINAL_PATH_UNITS: u32 = 32 * 1024;
#[cfg(feature = "test-inject")]
const FILL_CHUNK_BYTES: usize = 64 * 1024;

static ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn ext(e: ExtractionError) -> Error {
    match e {
        ExtractionError::Io(io) => Error::Io(io),
        ExtractionError::InvalidStagingRoot(s) => Error::InvalidStagingRoot(s),
        // Residue the filesystem layer could not prove removed: explicit, never
        // folded into an ordinary refusal.
        ExtractionError::CleanupFailed(s) => Error::CleanupFailed(s),
        other => Error::Filesystem(other),
    }
}

struct OwnedDir {
    rel: String,
    leaf: String,
    parent: Option<usize>,
    id: FileObjectId,
    guard: Option<ChildDirGuard>,
}

struct OwnedFile {
    leaf: String,
    parent: Option<usize>,
    id: FileObjectId,
    /// Bytes written through the creation handle so far (checked).
    written: u64,
    /// The baseline, meaningful only once `sealed`.
    len: u64,
    sha256: [u8; 32],
    sealed: bool,
    handle: Option<File>,
}

/// The ownership graph: what Cove created, and the leases that keep it.
pub(crate) struct OwnedTree {
    anchor: ChildDirGuard,
    root_name: String,
    root: Option<(ChildDirGuard, FileObjectId)>,
    dirs: Vec<OwnedDir>,
    /// Indexed by the plan's file index; `None` until that file is created.
    files: Vec<Option<OwnedFile>>,
}

impl OwnedTree {
    /// Validate the caller's staging root and anchor the exact directory object.
    pub(super) fn open(staging_root: &Path, file_slots: usize) -> Result<Self, Error> {
        let canonical = validate_staging_root(staging_root).map_err(ext)?;
        let anchor = ChildDirGuard::open_anchor(&canonical).map_err(ext)?;
        Ok(Self {
            anchor,
            root_name: String::new(),
            root: None,
            dirs: Vec::new(),
            files: (0..file_slots).map(|_| None).collect(),
        })
    }

    /// Create the one Cove-named package root under the anchored staging root.
    /// Security never depends on the name being unpredictable: creation is
    /// create-new, and a collision just picks the next name (bounded).
    pub(super) fn create_root(&mut self) -> Result<(), Error> {
        for _ in 0..MAX_ROOT_ATTEMPTS {
            let n = ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = format!("{PACKAGE_ROOT_PREFIX}{}-{n}", std::process::id());
            match create_owned_dir_relative(&self.anchor, &name) {
                Ok((guard, id)) => {
                    self.root_name = name;
                    self.root = Some((guard, id));
                    return Ok(());
                }
                Err(ExtractionError::OutputAlreadyExists) => continue,
                Err(e) => return Err(ext(e)),
            }
        }
        Err(Error::PackRootCollision)
    }

    fn dir_guard(&self, parent: Option<usize>) -> Result<&ChildDirGuard, Error> {
        let missing = || Error::PackageChanged {
            relative_path: "<directory guard>".into(),
        };
        match parent {
            None => self.root.as_ref().map(|(g, _)| g).ok_or_else(missing),
            Some(i) => self
                .dirs
                .get(i)
                .and_then(|d| d.guard.as_ref())
                .ok_or_else(missing),
        }
    }

    /// Create every planned directory, component by component, each relative
    /// to the parent guard already owned. The plan lists parents first.
    pub(super) fn create_dirs(&mut self, plan: &[PlannedDir]) -> Result<(), Error> {
        for d in plan {
            let (guard, id) =
                create_owned_dir_relative(self.dir_guard(d.parent)?, &d.leaf).map_err(ext)?;
            self.dirs.push(OwnedDir {
                rel: d.rel.clone(),
                leaf: d.leaf.clone(),
                parent: d.parent,
                id,
                guard: Some(guard),
            });
            #[cfg(feature = "test-inject")]
            if let Ok(root) = self.root_path() {
                super::seam::run_hook(&super::seam::PackageHook::AfterDirCreated {
                    path: &root.join(&d.rel),
                });
            }
        }
        Ok(())
    }

    /// Create-new the file for plan slot `slot` and retain its creation handle.
    pub(crate) fn create_file(&mut self, slot: usize, pf: &PlannedFile) -> Result<(), Error> {
        let file = open_output_create_new(self.dir_guard(pf.parent)?, &pf.leaf, Path::new(""))
            .map_err(ext)?;
        let id = object_id_of_raw_handle(file.as_raw_handle()).ok_or(Error::PackageChanged {
            relative_path: pf.rel.clone(),
        })?;
        self.files[slot] = Some(OwnedFile {
            leaf: pf.leaf.clone(),
            parent: pf.parent,
            id,
            written: 0,
            len: 0,
            sha256: [0; 32],
            sealed: false,
            handle: Some(file),
        });
        Ok(())
    }

    /// The open, not-yet-sealed file for `slot`.
    fn unsealed(&mut self, slot: usize) -> Result<&mut OwnedFile, Error> {
        match self.files.get_mut(slot).and_then(Option::as_mut) {
            Some(f) if !f.sealed && f.handle.is_some() => Ok(f),
            _ => Err(Error::PackageChanged {
                relative_path: format!("<file {slot}>"),
            }),
        }
    }

    /// Append `chunk` through the retained creation handle. The file is not
    /// populated, and has no baseline, until [`OwnedTree::seal_file`].
    pub(crate) fn write_file_chunk(&mut self, slot: usize, chunk: &[u8]) -> Result<(), Error> {
        let file = self.unsealed(slot)?;
        let leaf = file.leaf.clone();
        let handle = file.handle.as_mut().ok_or(Error::PackageChanged {
            relative_path: leaf.clone(),
        })?;
        handle.write_all(chunk).map_err(Error::Io)?;
        file.written =
            file.written
                .checked_add(chunk.len() as u64)
                .ok_or(Error::PackageChanged {
                    relative_path: leaf,
                })?;
        Ok(())
    }

    /// Complete `slot`: re-read what the retained handle ACTUALLY holds and
    /// require it to be exactly `expected_len` bytes hashing to
    /// `expected_sha256`. The producer's claim is never trusted; only after
    /// this agrees does the destination get a baseline.
    pub(crate) fn seal_file(
        &mut self,
        slot: usize,
        expected_len: u64,
        expected_sha256: [u8; 32],
    ) -> Result<(), Error> {
        let file = self.unsealed(slot)?;
        let changed = Error::PackageChanged {
            relative_path: file.leaf.clone(),
        };
        let handle = file.handle.as_ref().ok_or(Error::PackageChanged {
            relative_path: file.leaf.clone(),
        })?;
        if file.written != expected_len {
            return Err(changed);
        }
        match digest_of_raw_handle(handle.as_raw_handle()) {
            Ok(d) if d.len == expected_len && d.sha256 == expected_sha256 => {}
            Ok(_) => return Err(changed),
            Err(e) => return Err(ext(e)),
        }
        file.len = expected_len;
        file.sha256 = expected_sha256;
        file.sealed = true;
        Ok(())
    }

    /// Write `bytes` and seal the file against their own SHA-256 (test seam).
    #[cfg(feature = "test-inject")]
    pub(super) fn fill_file(&mut self, slot: usize, bytes: &[u8]) -> Result<(), Error> {
        let mut hasher = Sha256Stream::new().map_err(ext)?;
        for chunk in bytes.chunks(FILL_CHUNK_BYTES) {
            self.write_file_chunk(slot, chunk)?;
            hasher.update(chunk).map_err(ext)?;
        }
        let sha256 = hasher.finish().map_err(ext)?;
        self.seal_file(slot, bytes.len() as u64, sha256)
    }

    /// Every planned file must have been created AND sealed; anything less is
    /// not a tree.
    pub(super) fn require_all_files(&self, plan: &[PlannedFile]) -> Result<(), Error> {
        match plan
            .iter()
            .enumerate()
            .find(|(slot, _)| !matches!(self.files[*slot].as_ref(), Some(f) if f.sealed))
        {
            Some((_, pf)) => Err(Error::PackageChanged {
                relative_path: pf.rel.clone(),
            }),
            None => Ok(()),
        }
    }

    /// The content baseline of plan slot `slot`, once sealed.
    pub(crate) fn baseline(&self, slot: usize) -> Option<(u64, [u8; 32])> {
        let f = self.files.get(slot)?.as_ref()?;
        f.sealed.then_some((f.len, f.sha256))
    }

    /// Current path of file `slot`, derived from its retained HANDLE.
    pub(crate) fn file_path(&self, slot: usize) -> Result<PathBuf, Error> {
        let changed = || Error::PackageChanged {
            relative_path: format!("<file {slot}>"),
        };
        let handle = self
            .files
            .get(slot)
            .and_then(Option::as_ref)
            .and_then(|f| f.handle.as_ref())
            .ok_or_else(changed)?;
        final_path_of_handle(handle.as_raw_handle()).ok_or_else(changed)
    }

    /// Current path of the package root, derived from the live root HANDLE.
    pub(crate) fn root_path(&self) -> Result<PathBuf, Error> {
        let (guard, _) = self.root.as_ref().ok_or(Error::PackageChanged {
            relative_path: ".".into(),
        })?;
        final_path_of_handle(guard.handle()).ok_or(Error::PackageChanged {
            relative_path: ".".into(),
        })
    }

    /// Re-prove, through the retained handles only, that every object is the
    /// one that was created and still holds the bytes that were recorded.
    pub(crate) fn reattest(&self) -> Result<(), Error> {
        let changed = |p: &str| Error::PackageChanged {
            relative_path: p.to_string(),
        };
        let same = |h: *mut core::ffi::c_void, id: FileObjectId| {
            object_id_of_raw_handle(h.cast()) == Some(id)
        };
        match &self.root {
            Some((g, id)) if same(g.handle(), *id) => {}
            _ => return Err(changed(".")),
        }
        for d in &self.dirs {
            match &d.guard {
                Some(g) if same(g.handle(), d.id) => {}
                _ => return Err(changed(&d.rel)),
            }
        }
        for f in self.files.iter().flatten() {
            let h = f.handle.as_ref().ok_or_else(|| changed(&f.leaf))?;
            if !f.sealed || !same(h.as_raw_handle(), f.id) {
                return Err(changed(&f.leaf));
            }
            match digest_of_raw_handle(h.as_raw_handle()) {
                Ok(d) if d.len == f.len && d.sha256 == f.sha256 => {}
                _ => return Err(changed(&f.leaf)),
            }
        }
        Ok(())
    }

    /// Exact-object teardown, used for both explicit cleanup and rollback.
    /// Stops at the first object that cannot be proven deleted and reports it;
    /// everything not yet reached stays on disk.
    pub(crate) fn destroy(mut self) -> Result<(), String> {
        let fail = |e: ExtractionError| e.to_string();
        #[cfg(feature = "test-inject")]
        let root_path = self.root_path().ok();

        // Directory guards stay live; only file leases must go, because they
        // withhold the delete sharing removal needs.
        for f in self.files.iter_mut().flatten() {
            f.handle = None;
        }
        #[cfg(feature = "test-inject")]
        if let Some(root) = &root_path {
            super::seam::run_hook(&super::seam::PackageHook::AfterFilesReleased { root });
        }
        for f in self.files.iter().flatten() {
            let parent = self.dir_guard(f.parent).map_err(|e| format!("{e:?}"))?;
            delete_owned_leaf_checked(parent, &f.leaf, f.id).map_err(fail)?;
        }

        // Deepest-first: the plan lists parents before children.
        for i in (0..self.dirs.len()).rev() {
            drop(self.dirs[i].guard.take());
            #[cfg(feature = "test-inject")]
            if let Some(root) = &root_path {
                super::seam::run_hook(&super::seam::PackageHook::AfterDirGuardReleased {
                    path: &root.join(&self.dirs[i].rel),
                    rel: &self.dirs[i].rel,
                });
            }
            let d = &self.dirs[i];
            let parent = self.dir_guard(d.parent).map_err(|e| format!("{e:?}"))?;
            delete_staging_child_checked(parent, &d.leaf, d.id).map_err(fail)?;
        }

        if let Some((guard, id)) = self.root.take() {
            drop(guard);
            #[cfg(feature = "test-inject")]
            if let Some(root) = &root_path {
                super::seam::run_hook(&super::seam::PackageHook::AfterRootGuardReleased {
                    path: root,
                });
            }
            // Relative to the RETAINED original staging-root object, not a path.
            delete_staging_child_checked(&self.anchor, &self.root_name, id).map_err(fail)?;
        }
        Ok(())
    }

    /// Test seam: mutate one retained file through its own creation handle.
    #[cfg(feature = "test-inject")]
    pub(crate) fn write_through(&self, slot: usize, offset: u64, byte: u8) -> bool {
        use std::os::windows::fs::FileExt;
        self.files
            .get(slot)
            .and_then(|f| f.as_ref())
            .and_then(|f| f.handle.as_ref())
            .is_some_and(|h| h.seek_write(&[byte], offset).is_ok())
    }

    /// Test seam: corrupt one RECORDED identity, so the retained handle no
    /// longer matches what the tree believes it owns.
    #[cfg(feature = "test-inject")]
    pub(super) fn corrupt_identity(&mut self, target: super::seam::IdentityTarget) -> bool {
        use super::seam::IdentityTarget as T;
        fn flip(id: &mut FileObjectId) {
            id.file_id[0] ^= 0xFF;
        }
        match target {
            T::Root => self.root.as_mut().map(|(_, id)| flip(id)).is_some(),
            T::Dir(i) => self.dirs.get_mut(i).map(|d| flip(&mut d.id)).is_some(),
            T::File(i) => self
                .files
                .get_mut(i)
                .and_then(|f| f.as_mut())
                .map(|f| flip(&mut f.id))
                .is_some(),
        }
    }
}

/// Test seam: how many live-handle final-path queries were made, so a suite can
/// prove an accessor asks a retained handle every call rather than caching.
#[cfg(feature = "test-inject")]
static PATH_QUERIES: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "test-inject")]
pub(super) fn path_queries() -> u64 {
    PATH_QUERIES.load(Ordering::SeqCst)
}

/// Final path of an open handle (`\\?\C:\...`), bounded.
fn final_path_of_handle(handle: *mut core::ffi::c_void) -> Option<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    };
    #[cfg(feature = "test-inject")]
    PATH_QUERIES.fetch_add(1, Ordering::SeqCst);
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: `handle` is a live handle owned by a retained guard; `buf`
        // is a writable slice of exactly the length passed.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if n == 0 || n > MAX_FINAL_PATH_UNITS {
            return None;
        }
        if (n as usize) < buf.len() {
            buf.truncate(n as usize);
            return Some(PathBuf::from(OsString::from_wide(&buf)));
        }
        buf = vec![0u16; n as usize + 1];
    }
}
