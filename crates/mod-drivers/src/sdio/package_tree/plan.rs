//! Pure package tree plan: which directories and files a package root must
//! contain, decided (and refused) BEFORE any destination filesystem object
//! exists. No IO happens here.
//!
//! Windows names compare case-insensitively, so every collision check folds
//! ASCII case (every accepted path is ASCII). Hostile input is REJECTED, never
//! normalized into safety: a collision is an error, not something to merge.
//!
//! The planner is generic. It knows "root leaves" (single-component names that
//! live directly in the package root) and "paths" (relative, `/`-separated,
//! possibly nested). What those files MEAN is not its concern.

use std::collections::HashMap;

use super::{
    MAX_PACKAGE_DIRS, MAX_PACKAGE_PATH_FILES, MAX_PACKAGE_RETAINED_PATH_BYTES,
    MAX_PACKAGE_ROOT_LEAVES, PackageTreeError as Error,
};
use crate::sdio::payload_inventory::validate_source_path;

/// One directory to create, parent before child. `parent` is an index into
/// [`PackagePlan::dirs`]; `None` means the package root itself.
pub(super) struct PlannedDir {
    pub(super) rel: String,
    pub(super) parent: Option<usize>,
    pub(super) leaf: String,
}

/// One file to create, in the order root leaves then paths. `rel` keeps the
/// caller's spelling; the on-disk directory spelling is the first one planned.
pub(super) struct PlannedFile {
    pub(super) rel: String,
    pub(super) parent: Option<usize>,
    pub(super) leaf: String,
}

pub(super) struct PackagePlan {
    pub(super) dirs: Vec<PlannedDir>,
    pub(super) files: Vec<PlannedFile>,
}

enum Slot {
    File(String),
    Dir(usize),
}

struct Builder {
    seen: HashMap<String, Slot>,
    dirs: Vec<PlannedDir>,
    files: Vec<PlannedFile>,
    retained: usize,
    budget: usize,
}

/// Checked running total of retained path text, against `budget`.
fn charge_within(running: usize, add: usize, budget: usize) -> Result<usize, Error> {
    match running.checked_add(add) {
        Some(v) if v <= budget => Ok(v),
        _ => Err(Error::RetainedPathBudgetExceeded),
    }
}

/// [`charge_within`] against the finite package budget.
pub(super) fn charge_retained_path_bytes(running: usize, add: usize) -> Result<usize, Error> {
    charge_within(running, add, MAX_PACKAGE_RETAINED_PATH_BYTES)
}

/// Plan the tree for the given root leaves and relative paths (revalidated
/// here at this filesystem boundary even when a caller already validated them).
pub(super) fn plan_package(root_leaves: &[&str], paths: &[&str]) -> Result<PackagePlan, Error> {
    plan_package_with_budget(root_leaves, paths, MAX_PACKAGE_RETAINED_PATH_BYTES)
}

/// [`plan_package`] with an explicit retained-text budget. The budget covers
/// EVERY path string the returned plan keeps: each file's path AND its leaf
/// copy, each directory's path AND its leaf copy. (The transient collision
/// index is dropped before returning and is bounded by the same figures.)
pub(super) fn plan_package_with_budget(
    root_leaves: &[&str],
    paths: &[&str],
    budget: usize,
) -> Result<PackagePlan, Error> {
    if root_leaves.len() > MAX_PACKAGE_ROOT_LEAVES || paths.len() > MAX_PACKAGE_PATH_FILES {
        return Err(Error::TooManyFiles);
    }
    let mut b = Builder {
        seen: HashMap::new(),
        dirs: Vec::new(),
        files: Vec::new(),
        retained: 0,
        budget,
    };
    for leaf in root_leaves {
        // A root leaf is ONE component: a separator would place it in a
        // subdirectory the caller never asked for.
        if leaf.contains('/') {
            return Err(Error::InvalidPackagePath {
                relative_path: leaf.to_string(),
            });
        }
        b.add_file(leaf)?;
    }
    for path in paths {
        b.add_file(path)?;
    }
    Ok(PackagePlan {
        dirs: b.dirs,
        files: b.files,
    })
}

impl Builder {
    fn add_file(&mut self, rel: &str) -> Result<(), Error> {
        validate_source_path(0, rel).map_err(|_| Error::InvalidPackagePath {
            relative_path: rel.to_string(),
        })?;
        // On volumes that generate 8.3 short names, creating `LongFileName.txt`
        // may reserve `LONGFI~1.TXT`, and creating a planned name equal to that
        // alias afterwards fails half-way through the build. Every generated
        // alias contains `~`, so refusing any planned name that contains one is
        // COMPLETE (no planned name can equal an alias, in any creation order)
        // and needs no per-volume behavior. It is deliberately conservative: a
        // legitimate name with `~` is refused rather than risked.
        if rel.contains('~') {
            return Err(Error::InvalidPackagePath {
                relative_path: rel.to_string(),
            });
        }
        let collision = |first: &str, second: &str| Error::PathCollision {
            first: first.to_string(),
            second: second.to_string(),
        };
        let comps: Vec<&str> = rel.split('/').collect();
        let mut parent = None;
        let mut prefix = String::new();
        for (i, comp) in comps.iter().enumerate() {
            if i > 0 {
                prefix.push('/');
            }
            prefix.push_str(comp);
            let key = prefix.to_ascii_lowercase();
            let is_leaf = i + 1 == comps.len();
            match self.seen.get(&key) {
                // The name is taken. A leaf can never reuse a name; a
                // directory component can only reuse a directory.
                Some(Slot::File(first)) => return Err(collision(first, rel)),
                Some(Slot::Dir(ix)) if is_leaf => {
                    return Err(collision(&self.dirs[*ix].rel, rel));
                }
                Some(Slot::Dir(ix)) => parent = Some(*ix),
                None if is_leaf => {
                    // The plan keeps both the path and the leaf copy of a file.
                    self.retained =
                        charge_within(self.retained, rel.len() + comp.len(), self.budget)?;
                    self.seen.insert(key, Slot::File(rel.to_string()));
                    self.files.push(PlannedFile {
                        rel: rel.to_string(),
                        parent,
                        leaf: (*comp).to_string(),
                    });
                }
                None => {
                    if self.dirs.len() >= MAX_PACKAGE_DIRS {
                        return Err(Error::TooManyDirectories);
                    }
                    // ...and of a directory: its path and its leaf copy.
                    self.retained =
                        charge_within(self.retained, prefix.len() + comp.len(), self.budget)?;
                    let ix = self.dirs.len();
                    self.dirs.push(PlannedDir {
                        rel: prefix.clone(),
                        parent,
                        leaf: (*comp).to_string(),
                    });
                    self.seen.insert(key, Slot::Dir(ix));
                    parent = Some(ix);
                }
            }
        }
        Ok(())
    }
}
