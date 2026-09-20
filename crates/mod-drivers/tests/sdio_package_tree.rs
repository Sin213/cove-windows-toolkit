//! Tab 2a-11a - owned package tree substrate.
//!
//! The substrate must pre-plan a collision-safe namespace, create and own that
//! namespace under an explicit caller root with exact Windows object handles,
//! retain the leases, prove through them that the objects are still the ones it
//! made, and destroy ONLY those objects. It carries synthetic bytes and knows
//! nothing about drivers, archives or trust.

use mod_drivers::sdio::package_tree_seam::{
    PackageTreeError as PTE, test_charge_retained_path_bytes, test_plan_package,
    test_plan_package_with_budget,
};

const MAX_FILES: usize = 1026;
const MAX_DIRS: usize = 4096;
const MAX_RETAINED: usize = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Pure tree plan (portable): collisions and bounds are decided before any IO.
// ---------------------------------------------------------------------------

#[test]
fn a2_a3_namespace_collisions_are_rejected_before_any_create() {
    let cases: &[(&[&str], &[&str])] = &[
        // File/file, ASCII case-insensitive.
        (&["a.bin"], &["bin/foo.sys", "BIN/FOO.SYS"]),
        (&[], &["a.sys", "A.SYS"]),
        // File/directory and path-prefix collisions, both orders.
        (&[], &["foo", "foo/bar.sys"]),
        (&[], &["foo/bar.sys", "foo"]),
        (&[], &["FOO", "foo/bar.sys"]),
        // Duplicate relative path.
        (&[], &["a/b.sys", "a/b.sys"]),
        // Reserved root-leaf names against a path, and against each other.
        (&["root.bin"], &["ROOT.BIN"]),
        (&["root.bin", "root.cat"], &["root.cat/x.sys"]),
        (&["root.bin", "ROOT.BIN"], &["a.sys"]),
    ];
    for (roots, paths) in cases {
        let r = test_plan_package(roots, paths);
        assert!(
            matches!(r, Err(PTE::PathCollision { .. })),
            "{roots:?} {paths:?} -> {r:?}"
        );
    }
}

#[test]
fn a4_unsafe_paths_are_rejected_before_any_create() {
    let long_component = "a".repeat(256);
    let too_deep = vec!["d"; 65].join("/");
    let too_long = format!("{}/f.sys", "d/".repeat(4100));
    #[rustfmt::skip]
    let hostile: Vec<String> = [
        "", ".", "..", "a/../b", "./a", "a//b", "/abs.sys", "a/", "C:\\x.sys", "C:x.sys",
        "\\\\srv\\share\\x", "\\\\?\\C:\\x", "a:b", "a\0b", "CON", "nul.txt", "a/COM1", "trail.",
        "trail ", "a<b", "a|b", "a?b", "a*b", "a\"b", "a\u{1}b", "caf\u{e9}.sys",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain([long_component, too_deep, too_long])
    .collect();
    for path in &hostile {
        let r = test_plan_package(&[], &[path.as_str()]);
        assert!(
            matches!(r, Err(PTE::InvalidPackagePath { .. })),
            "{path:?} -> {r:?}"
        );
    }
    // A name with `~` could equal a generated 8.3 short-name alias (the file
    // `LongFileName.txt` may reserve `LONGFI~1.TXT`), which would fail the build
    // half-way; refusing them all is complete, so they are rejected before any
    // create, as a file, a directory component, or a root leaf.
    for path in ["LONGFI~1.TXT", "bin/x~1.sys", "dir~2/f.sys", "a~"] {
        let r = test_plan_package(&[], &[path]);
        assert!(matches!(r, Err(PTE::InvalidPackagePath { .. })), "{path:?}");
    }
    let r = test_plan_package(&["ROOT~1.BIN"], &[]);
    assert!(matches!(r, Err(PTE::InvalidPackagePath { .. })));
    // A root leaf is ONE component.
    for leaf in ["sub/x.bin", "", "..", "a:b.bin"] {
        let r = test_plan_package(&[leaf], &["a.sys"]);
        assert!(matches!(r, Err(PTE::InvalidPackagePath { .. })), "{leaf:?}");
    }
}

#[test]
fn a1_a4_valid_plan_counts_and_finite_bounds() {
    let paths = [
        "bin/driver.sys",
        "co/helper.dll",
        "deep/a/b/file.dat",
        "bin/x.sys",
    ];
    // Every required directory exactly once; files are root leaves + paths.
    assert_eq!(
        test_plan_package(&["r.bin", "r.cat"], &paths).unwrap(),
        (5, 6)
    );
    // Directory names that differ only by case share ONE directory.
    assert_eq!(
        test_plan_package(&[], &["bin/a.sys", "BIN/b.sys"]).unwrap(),
        (1, 2)
    );

    // File bound: 1024 paths + 2 root leaves is exactly MAX_FILES.
    let ok: Vec<String> = (0..MAX_FILES - 2).map(|i| format!("f{i}.sys")).collect();
    let ok: Vec<&str> = ok.iter().map(String::as_str).collect();
    assert!(test_plan_package(&["d.inf", "d.cat"], &ok).is_ok());
    let over: Vec<String> = (0..MAX_FILES - 1).map(|i| format!("f{i}.sys")).collect();
    let over: Vec<&str> = over.iter().map(String::as_str).collect();
    assert!(matches!(
        test_plan_package(&["d.inf", "d.cat"], &over),
        Err(PTE::TooManyFiles)
    ));
    assert!(matches!(
        test_plan_package(&["a", "b", "c"], &["z"]),
        Err(PTE::TooManyFiles)
    ));

    // Directory bound: 63 unique directories per deep path.
    let deep = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| {
                let chain: Vec<String> = (0..63).map(|d| format!("d{i}x{d}")).collect();
                format!("{}/f.sys", chain.join("/"))
            })
            .collect()
    };
    let fits: Vec<String> = deep(MAX_DIRS / 63);
    let fits: Vec<&str> = fits.iter().map(String::as_str).collect();
    assert!(test_plan_package(&[], &fits).is_ok());
    let big: Vec<String> = deep(MAX_DIRS / 63 + 1);
    let big: Vec<&str> = big.iter().map(String::as_str).collect();
    assert!(matches!(
        test_plan_package(&[], &big),
        Err(PTE::TooManyDirectories)
    ));

    // The retained budget counts EVERY string the plan keeps: a file's path and
    // its leaf copy, a directory's path and its leaf copy (a directory shared by
    // two files is charged once). "a/bb.sys": 8 + 6 for the file, 1 + 1 for `a`.
    let one = ["a/bb.sys"];
    assert!(test_plan_package_with_budget(&[], &one, 16).is_ok());
    assert!(matches!(
        test_plan_package_with_budget(&[], &one, 15),
        Err(PTE::RetainedPathBudgetExceeded)
    ));
    assert!(test_plan_package_with_budget(&["x"], &[], 2).is_ok());
    assert!(test_plan_package_with_budget(&["x"], &[], 1).is_err());
    let shared = ["a/b.sys", "a/c.sys"]; // 7 + 5, 1 + 1, 7 + 5
    assert!(test_plan_package_with_budget(&[], &shared, 26).is_ok());
    assert!(test_plan_package_with_budget(&[], &shared, 25).is_err());

    // Retained path text: the exact boundary, and checked overflow.
    assert_eq!(
        test_charge_retained_path_bytes(MAX_RETAINED - 1, 1).unwrap(),
        MAX_RETAINED
    );
    for (running, add) in [(MAX_RETAINED, 1), (usize::MAX, 1)] {
        assert!(matches!(
            test_charge_retained_path_bytes(running, add),
            Err(PTE::RetainedPathBudgetExceeded)
        ));
    }
}

// ---------------------------------------------------------------------------
// Real Windows filesystem behavior.
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod native {
    use std::cell::RefCell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    use mod_drivers::sdio::extraction::{
        ForcedDirDelete, test_force_classic_disposition, test_force_owned_dir_failure,
        test_set_bound_leaf_delete_window_hook,
    };
    use mod_drivers::sdio::package_tree_seam::{
        IdentityTarget, OwnedPackageTree, PackageHook, PackageTreeError as PTE, test_build_tree,
        test_set_package_hook,
    };

    /// Root leaves then paths, by slot: 0 root.bin, 1 root.cat, 2 bin/driver.dat,
    /// 3 co/helper.dat, 4 deep/a/b/file.dat. Directories: bin, co, deep, deep/a,
    /// deep/a/b.
    const ROOTS: &[&str] = &["root.bin", "root.cat"];
    const PATHS: &[&str] = &["bin/driver.dat", "co/helper.dat", "deep/a/b/file.dat"];

    fn contents(slot: usize) -> Vec<u8> {
        format!("cove-substrate-bytes-{slot}-0123456789").into_bytes()
    }

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Clears the thread's test hooks even when an assertion unwinds.
    struct HookReset;

    impl Drop for HookReset {
        fn drop(&mut self) {
            test_set_package_hook(None);
            test_set_bound_leaf_delete_window_hook(None);
            test_force_classic_disposition(false);
            test_force_owned_dir_failure(None);
        }
    }

    /// `pkg` is the CALLER's staging root; the tree lives in a Cove child of it.
    struct Fixture {
        pkg: PathBuf,
        _tmp: TempDir,
    }

    fn fixture(tag: &str) -> Fixture {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "cove_tab2a11a_{tag}_{}_{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("pkg")).unwrap();
        let pkg = fs::canonicalize(root.join("pkg")).unwrap();
        Fixture {
            pkg,
            _tmp: TempDir(root),
        }
    }

    fn build(f: &Fixture) -> OwnedPackageTree {
        test_build_tree(ROOTS, PATHS, &f.pkg, &contents, None).expect("build")
    }

    fn fail(r: Result<OwnedPackageTree, PTE>) -> PTE {
        match r {
            Ok(_) => panic!("build must fail"),
            Err(e) => e,
        }
    }

    fn children(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// The Cove package root, tolerating extra entries an attacker test left.
    fn package_root(f: &Fixture) -> PathBuf {
        let kids = children(&f.pkg);
        let ours = kids.iter().find(|k| k.starts_with("cove-driver-package-"));
        f.pkg.join(ours.expect("package root"))
    }

    // -- A5 / A6 / A7 / A15 / A17: structure, identity, path, cleanup ------------

    #[test]
    fn a5_a6_a7_a15_a17_tree_is_exact_handle_owned_and_cleans_up() {
        let f = fixture("a5");
        fs::create_dir(f.pkg.join("sibling")).unwrap();
        let t = build(&f);
        let root = package_root(&f);
        assert_eq!(
            children(&root),
            ["bin", "co", "deep", "root.bin", "root.cat"]
        );
        for (slot, rel) in [
            (0, "root.bin"),
            (1, "root.cat"),
            (2, "bin/driver.dat"),
            (3, "co/helper.dat"),
            (4, "deep/a/b/file.dat"),
        ] {
            assert_eq!(fs::read(root.join(rel)).unwrap(), contents(slot), "{rel}");
            assert_eq!(t.baseline(slot).unwrap().0, contents(slot).len() as u64);
        }
        assert!(root.join("deep/a/b").is_dir());
        // A15: the path comes from the live handle and names the owned root.
        let now = t.current_root_path().expect("path from handle");
        assert_eq!(now, fs::canonicalize(&root).unwrap());
        assert_eq!(now.parent().unwrap(), f.pkg.as_path());
        t.reattest().expect("fresh tree re-attests");
        t.cleanup().expect("cleanup");
        // A17 / A22 / A23: only Cove's objects went; the caller root and sibling stay.
        assert_eq!(children(&f.pkg), ["sibling"]);
    }

    #[test]
    fn a15_root_path_follows_the_live_handle_when_the_caller_root_moves() {
        let f = fixture("a15");
        let t = build(&f);
        let before = t.current_root_path().unwrap();
        let moved = f.pkg.with_file_name("pkg_moved");
        match fs::rename(&f.pkg, &moved) {
            // The retained handles inside refuse it: the path is unchanged.
            Err(_) => assert_eq!(t.current_root_path().unwrap(), before),
            // A host that permits it must still report the CURRENT location.
            Ok(()) => {
                let now = t.current_root_path().unwrap();
                assert!(
                    now.starts_with(fs::canonicalize(&moved).unwrap()),
                    "{now:?}"
                );
                fs::rename(&moved, &f.pkg).unwrap();
            }
        }
        t.cleanup().expect("cleanup");
    }

    #[test]
    fn a_plan_refusal_creates_nothing() {
        let f = fixture("refuse");
        let r = test_build_tree(&[], &["foo", "foo/bar.sys"], &f.pkg, &contents, None);
        assert!(matches!(fail(r), PTE::PathCollision { .. }));
        assert!(children(&f.pkg).is_empty(), "no package root was created");
    }

    // -- A8 / A10 / A11: guards and leases ------------------------------------------

    #[test]
    fn a8_a10_a11_files_and_directories_cannot_be_overwritten_renamed_or_deleted() {
        let f = fixture("a8");
        let t = build(&f);
        let root = package_root(&f);
        // Rename targets are the UNGUARDED caller root: a rename INTO a guarded
        // directory is refused by its share mode, which is not what is tested.
        for rel in [
            "root.bin",
            "root.cat",
            "bin/driver.dat",
            "deep/a/b/file.dat",
        ] {
            let p = root.join(rel);
            assert!(
                fs::OpenOptions::new().write(true).open(&p).is_err(),
                "write {rel}"
            );
            assert!(fs::write(&p, b"x").is_err(), "truncate {rel}");
            assert!(
                fs::rename(&p, f.pkg.join("moved.tmp")).is_err(),
                "rename {rel}"
            );
            assert!(fs::remove_file(&p).is_err(), "delete {rel}");
            assert!(fs::read(&p).is_ok(), "read stays possible {rel}");
        }
        for rel in ["bin", "co", "deep", "deep/a", "deep/a/b"] {
            let p = root.join(rel);
            assert!(
                fs::rename(&p, f.pkg.join("moved_dir")).is_err(),
                "rename dir {rel}"
            );
            assert!(fs::remove_dir(&p).is_err(), "delete dir {rel}");
        }
        assert!(
            fs::rename(&root, f.pkg.join("moved_root")).is_err(),
            "rename root"
        );
        assert!(fs::remove_dir(&root).is_err(), "delete root");
        t.reattest().expect("nothing was disturbed");
        t.cleanup().expect("cleanup");
    }

    // -- A9: junction substitution during the directory window ------------------------

    #[test]
    fn a9_a_directory_cannot_be_swapped_for_a_junction_while_files_are_created() {
        let _r = HookReset;
        let f = fixture("a9");
        let elsewhere = f.pkg.parent().unwrap().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let outcomes: Rc<RefCell<Vec<(bool, bool)>>> = Rc::default();
        let (out, target, aside) = (outcomes.clone(), elsewhere.clone(), f.pkg.join("bin_aside"));
        test_set_package_hook(Some(Box::new(move |h| {
            if let PackageHook::AfterDirCreated { path } = h
                && path.ends_with("bin")
            {
                // The move targets the UNGUARDED caller root, so only the
                // directory's own guard can be what refuses it.
                let renamed = fs::rename(path, &aside).is_ok();
                let plain = path.to_string_lossy().replace("\\\\?\\", "");
                let junction = std::process::Command::new("cmd")
                    .args(["/C", "mklink", "/J", &plain, &target.to_string_lossy()])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                out.borrow_mut().push((renamed, junction));
            }
        })));
        let t = build(&f);
        assert_eq!(
            *outcomes.borrow(),
            [(false, false)],
            "hook ran, both refused"
        );
        assert!(children(&elsewhere).is_empty(), "nothing was redirected");
        assert_eq!(
            fs::read(package_root(&f).join("bin/driver.dat")).unwrap(),
            contents(2)
        );
        t.cleanup().expect("cleanup");
    }

    // -- A13 / A14: re-attestation ----------------------------------------------------

    #[test]
    fn a13_a_recorded_identity_that_no_longer_matches_fails_reattestation() {
        for target in [
            IdentityTarget::Root,
            IdentityTarget::Dir(1),
            IdentityTarget::File(3),
        ] {
            let f = fixture("a13");
            let mut t = build(&f);
            t.reattest().expect("baseline holds");
            assert!(t.corrupt_recorded_identity(target));
            let e = t.reattest().expect_err("identity mismatch");
            assert!(matches!(e, PTE::PackageChanged { .. }), "{e:?}");
        }
    }

    #[test]
    fn a14_in_place_content_mutation_is_detected_by_reattestation() {
        let f = fixture("a14");
        let t = build(&f);
        assert!(t.write_through_retained_handle(2, 0, b'X'));
        let e = t.reattest().expect_err("mutated file");
        assert!(matches!(e, PTE::PackageChanged { .. }), "{e:?}");
        // Identity is unchanged, so cleanup may still remove the exact object.
        t.cleanup().expect("cleanup of the same objects");
        assert!(children(&f.pkg).is_empty());
    }

    // -- A16: rollback -----------------------------------------------------------------

    #[test]
    fn a16_failure_after_root_dirs_and_files_removes_only_cove_objects() {
        let f = fixture("a16");
        fs::create_dir(f.pkg.join("sibling")).unwrap();
        fs::write(f.pkg.join("sibling").join("keep.txt"), b"keep").unwrap();
        // Two files exist (slots 0 and 1); the third never does.
        let r = test_build_tree(ROOTS, PATHS, &f.pkg, &contents, Some(3));
        assert!(matches!(fail(r), PTE::Io(_)));
        assert_eq!(
            children(&f.pkg),
            ["sibling"],
            "root, dirs and files all removed"
        );
        assert_eq!(fs::read(f.pkg.join("sibling/keep.txt")).unwrap(), b"keep");
        assert!(f.pkg.is_dir());
    }

    #[test]
    fn a16_a_rollback_that_cannot_finish_is_reported_not_swallowed() {
        let _r = HookReset;
        let f = fixture("a16b");
        test_set_package_hook(Some(Box::new(|h| {
            if let PackageHook::AfterFilesReleased { root } = h {
                fs::write(root.join("unknown.txt"), b"not ours").unwrap();
            }
        })));
        let r = test_build_tree(ROOTS, PATHS, &f.pkg, &contents, Some(3));
        match fail(r) {
            PTE::Rollback { cause, residue } => {
                assert!(matches!(*cause, PTE::Io(_)), "{cause:?}");
                assert!(!residue.is_empty());
            }
            other => panic!("expected Rollback, got {other:?}"),
        }
        assert_eq!(
            fs::read(package_root(&f).join("unknown.txt")).unwrap(),
            b"not ours"
        );
    }

    // -- A26: a created directory that fails its own proof ---------------------------

    #[test]
    fn a26_a_created_directory_failing_validation_is_proven_removed_or_reported_as_residue() {
        let _r = HookReset;
        // (creations that succeed first, what the by-handle removal does,
        // expect an explicit residue report). skip 0 = the ROOT fails, skip 1 =
        // a nested directory fails after the root was recorded.
        let cases = [
            (0, ForcedDirDelete::Works, false),
            (0, ForcedDirDelete::Fails, true),
            (0, ForcedDirDelete::ClaimsSuccess, true),
            (1, ForcedDirDelete::Works, false),
            (1, ForcedDirDelete::Fails, true),
            (1, ForcedDirDelete::ClaimsSuccess, true),
        ];
        for (skip, mode, residue) in cases {
            let f = fixture("a26");
            test_force_owned_dir_failure(Some((skip, mode)));
            let e = fail(test_build_tree(ROOTS, PATHS, &f.pkg, &contents, None));
            let reported = match skip {
                0 => matches!(e, PTE::CleanupFailed(_)),
                _ => matches!(e, PTE::Rollback { .. }),
            };
            assert_eq!(reported, residue, "{skip} {mode:?} -> {e:?}");
            // Residue is reported exactly when something really remains: a
            // removal that was proven leaves the caller root empty.
            assert_eq!(!children(&f.pkg).is_empty(), residue, "{skip} {mode:?}");
        }
    }

    // -- A18..A21: cleanup-window attacks ----------------------------------------------

    /// Run `cleanup` with `hook` installed; return its result.
    fn cleanup_under(t: OwnedPackageTree, hook: Box<dyn Fn(&PackageHook<'_>)>) -> Result<(), PTE> {
        test_set_package_hook(Some(hook));
        t.cleanup()
    }

    #[test]
    fn a18_an_unexpected_child_is_never_recursively_deleted() {
        let _r = HookReset;
        let f = fixture("a18");
        let t = build(&f);
        let e = cleanup_under(
            t,
            Box::new(|h| {
                if let PackageHook::AfterFilesReleased { root } = h {
                    fs::write(root.join("unknown.txt"), b"not ours").unwrap();
                }
            }),
        )
        .expect_err("must fail closed");
        assert!(matches!(e, PTE::CleanupFailed(_)), "{e:?}");
        assert_eq!(
            fs::read(package_root(&f).join("unknown.txt")).unwrap(),
            b"not ours"
        );
    }

    #[test]
    fn a19_a_replacement_root_is_never_deleted() {
        let _r = HookReset;
        let f = fixture("a19");
        let t = build(&f);
        let e = cleanup_under(
            t,
            Box::new(|h| {
                if let PackageHook::AfterRootGuardReleased { path } = h {
                    fs::rename(path, path.with_file_name("root_moved")).unwrap();
                    // EMPTY replacement: "directory not empty" cannot be what
                    // saves it, only the identity binding can.
                    fs::create_dir(path).unwrap();
                }
            }),
        )
        .expect_err("identity mismatch");
        assert!(matches!(e, PTE::CleanupFailed(_)), "{e:?}");
        let kids = children(&f.pkg);
        assert!(kids.contains(&"root_moved".to_string()), "{kids:?}");
        assert!(package_root(&f).is_dir(), "the replacement survives");
    }

    #[test]
    fn a20_a_replacement_nested_directory_is_never_deleted() {
        let _r = HookReset;
        let f = fixture("a20");
        let t = build(&f);
        // Moves target the UNGUARDED caller root (see A8).
        let aside = f.pkg.join("bin_moved");
        let e = cleanup_under(
            t,
            Box::new(move |h| {
                if let PackageHook::AfterDirGuardReleased { path, rel } = h
                    && *rel == "bin"
                {
                    fs::rename(path, &aside).unwrap();
                    // EMPTY replacement: only the identity binding can save it.
                    fs::create_dir(path).unwrap();
                }
            }),
        )
        .expect_err("identity mismatch");
        assert!(matches!(e, PTE::CleanupFailed(_)), "{e:?}");
        assert!(
            package_root(&f).join("bin").is_dir(),
            "replacement survives"
        );
        assert!(
            f.pkg.join("bin_moved").is_dir(),
            "the object we created survives, reported"
        );
    }

    #[test]
    fn a12_a21_a_vacated_or_replaced_leaf_is_never_reported_as_cleaned() {
        let _r = HookReset;
        // Original renamed away, leaf left VACANT.
        let f = fixture("a21");
        let t = build(&f);
        let aside = f.pkg.join("kept.bin");
        let e = cleanup_under(
            t,
            Box::new(move |h| {
                if let PackageHook::AfterFilesReleased { root } = h {
                    fs::rename(root.join("root.bin"), &aside).unwrap();
                }
            }),
        )
        .expect_err("vacant leaf is not a deletion");
        assert!(matches!(e, PTE::CleanupFailed(_)), "{e:?}");
        assert!(
            f.pkg.join("kept.bin").exists(),
            "the object we created survives, reported"
        );

        // A12: original renamed away, a same-named REPLACEMENT planted.
        let f = fixture("a12");
        let t = build(&f);
        let aside = f.pkg.join("kept.dat");
        let e = cleanup_under(
            t,
            Box::new(move |h| {
                if let PackageHook::AfterFilesReleased { root } = h {
                    fs::rename(root.join("bin/driver.dat"), &aside).unwrap();
                    fs::write(root.join("bin/driver.dat"), b"replacement").unwrap();
                }
            }),
        )
        .expect_err("replacement is not our object");
        assert!(matches!(e, PTE::CleanupFailed(_)), "{e:?}");
        assert_eq!(
            fs::read(package_root(&f).join("bin/driver.dat")).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn a21_delete_window_rename_is_refused_and_classic_fallback_still_proves_unlink() {
        let _r = HookReset;
        let f = fixture("a21b");
        let t = build(&f);
        let root_seen: Rc<RefCell<Option<PathBuf>>> = Rc::default();
        let attempts: Rc<RefCell<Vec<bool>>> = Rc::default();
        let seen = root_seen.clone();
        test_set_package_hook(Some(Box::new(move |h| {
            if let PackageHook::AfterFilesReleased { root } = h {
                *seen.borrow_mut() = Some(root.to_path_buf());
            }
        })));
        let (seen, log, aside) = (
            root_seen.clone(),
            attempts.clone(),
            f.pkg.join("stolen.bin"),
        );
        test_set_bound_leaf_delete_window_hook(Some(Box::new(move |leaf| {
            if leaf == Path::new("root.bin") {
                let root = seen.borrow().clone().unwrap();
                // Target is UNGUARDED, so only the delete handle's withheld
                // FILE_SHARE_DELETE can be what refuses this.
                log.borrow_mut()
                    .push(fs::rename(root.join(leaf), &aside).is_ok());
            }
        })));
        test_force_classic_disposition(true);
        t.cleanup()
            .expect("classic disposition still proves the unlink");
        assert_eq!(
            *attempts.borrow(),
            [false],
            "cross-directory rename refused"
        );
        assert!(children(&f.pkg).is_empty());
    }

    // -- A27: hard links -----------------------------------------------------------------

    #[test]
    fn a27_a_hard_link_made_during_cleanup_is_never_reported_as_a_clean_removal() {
        let _r = HookReset;
        // (link made before the delete handle binds, in the bound window with
        // the POSIX delete, in the bound window with the classic MARKED delete)
        for (in_bound_window, classic) in [(false, false), (true, false), (true, true)] {
            let f = fixture("a27");
            let t = build(&f);
            let root_seen: Rc<RefCell<Option<PathBuf>>> = Rc::default();
            let (seen, linked) = (root_seen.clone(), f.pkg.join("linked.bin"));
            let early = linked.clone();
            test_set_package_hook(Some(Box::new(move |h| {
                if let PackageHook::AfterFilesReleased { root } = h {
                    *seen.borrow_mut() = Some(root.to_path_buf());
                    if !in_bound_window {
                        fs::hard_link(root.join("root.bin"), &early).unwrap();
                    }
                }
            })));
            let (seen, late) = (root_seen.clone(), linked.clone());
            test_set_bound_leaf_delete_window_hook(Some(Box::new(move |leaf| {
                if in_bound_window && leaf == Path::new("root.bin") {
                    let root = seen.borrow().clone().unwrap();
                    fs::hard_link(root.join(leaf), &late).unwrap();
                }
            })));
            test_force_classic_disposition(classic);
            let e = t.cleanup().expect_err("a surviving link is residue");
            assert!(matches!(e, PTE::CleanupFailed(_)), "{e:?}");
            if !in_bound_window {
                // Known before the delete request, so our name is left alone.
                let root = root_seen.borrow().clone().unwrap();
                assert!(root.join("root.bin").exists(), "refused before unlinking");
            }
            assert_eq!(
                fs::read(&linked).unwrap(),
                contents(0),
                "the object survives under the link, and it was REPORTED ({in_bound_window} {classic})"
            );
        }
    }

    // -- A24 / A25: ownership type and structural guards ---------------------------------

    #[test]
    fn a24_the_owned_tree_is_not_clone() {
        // If `OwnedPackageTree` ever became `Clone`, the two blanket impls below
        // would both apply and this line would fail to COMPILE (ambiguity).
        trait AmbiguousIfClone<A> {
            fn probe() {}
        }
        impl<T> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}
        let _ = <OwnedPackageTree as AmbiguousIfClone<_>>::probe;
    }

    fn production_sources() -> String {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sdio");
        let mut out = String::new();
        for rel in [
            "package_tree.rs",
            "package_tree/plan.rs",
            "package_tree/tree.rs",
        ] {
            let text = fs::read_to_string(base.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
            // Code only: prose in comments may name what is forbidden.
            for line in text.lines().filter(|l| !l.trim_start().starts_with("//")) {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    #[test]
    fn a25_no_path_based_creation_no_recursive_deletion_and_non_windows_refuses() {
        let code = production_sources();
        for needle in [
            "remove_dir_all",
            "fs::create_dir",
            "fs::copy",
            "read_to_end",
            "File::create",
            "fs::remove_file",
            "fs::remove_dir",
            "fs::write",
            "pnputil",
            "SetupCopyOEMInf",
            "DiInstallDriver",
            "UpdateDriverForPlugAndPlayDevices",
        ] {
            assert!(
                !code.contains(needle),
                "production code must not use {needle}"
            );
        }
        // Off Windows the builder refuses; the tree cannot be compiled here, so
        // that contract is pinned structurally.
        assert!(code.contains("#[cfg(not(windows))]"));
        assert!(code.contains("PackageTreeError::PlatformUnsupported"));
    }
}
