//! Sanity tests for `FakeFs`: only the behavior that the safety tests *rely on* to be faithful to
//! the real `lstat(2)` (frugal: trivial getters/builders are not tested).
//!
//! ```text
//! Function:        FakeFs::lstat (cleaner_core::ports::Fs)
//! Contract:        Final component never followed; intermediate symlinks followed; loops end in
//!                  ELOOP; missing -> ENOENT; device inherited from nearest mount point.
//!                  (Test oracle for AC-001-6, AC-001-7, AC-001-9; INV-07, INV-08)
//! Equivalence classes: final symlink (live/dangling/self-loop); intermediate symlink (to dir,
//!                  loop); missing; device inheritance (default, mount, nested override)
//! Boundaries:      symlink as LAST component vs as a PARENT component
//! Must-never:      resolving a final symlink; hanging on a loop
//! Selected tests:  lstat_follows_intermediate_symlinks_but_never_the_final_one,
//!                  device_is_inherited_from_nearest_mount_point,
//!                  read_dir_and_attributes_model_what_the_scanner_relies_on
//! Deliberately not tested: builder ergonomics, `calls()` recording, error injection
//!                  (exercised by the guard tests that use them).
//!
//! Function:        FakeFs::read_dir and the extended `lstat` attributes (spec 002a)
//! Contract:        `read_dir` lists direct children with their kinds (ascending, or reversed on
//!                  request), FOLLOWS a final symlink like `opendir`, fails ENOTDIR on a file and
//!                  with the injected errno for `list_error_at` while `lstat` still works; `lstat`
//!                  reports len, blocks (sparse: blocks*512 < len), mtime, a shared inode and
//!                  `nlink` for hardlinks.
//! Equivalence classes: dir | final symlink to dir | file | list-error | hardlink pair | sparse file |
//!                  reversed listing
//! Must-never:      listing that silently refuses to follow the link (it would hide a scanner that
//!                  lists symlinks)
//! ```

use std::path::Path;

use cleaner_core::ports::{FileKind, Fs};
use cleaner_testkit::FakeFs;

/// # Design promise
/// The fake mirrors kernel `lstat`: it reports a final symlink as a symlink and only follows
/// symlinks that are *parents* in the path (INV-07 test oracle).
///
/// # Scenario (Given)
/// `/r/link -> /t` (live), `/r/dangling -> /nowhere`, `/r/self -> /r/self`, `/t/secret` a file.
///
/// # Action (When)
/// `lstat` each of: `/r/link`, `/r/dangling`, `/r/self`, `/r/link/secret`, `/r/self/x`, `/r/nope`.
///
/// # Expected (Then)
/// The three links are `Symlink` (not their targets); `/r/link/secret` is a `File` reached through
/// the parent link; `/r/self/x` fails (ELOOP, os error 62) instead of hanging; `/r/nope` is ENOENT.
///
/// # Must never
/// Resolve a final-component symlink; loop forever.
///
/// # Would catch
/// A fake that used `metadata()`-like following, which would make every symlink test vacuous.
///
/// # Why this test (not redundant)
/// The only test of the fake's path-resolution semantics; guard tests assume it.
#[test]
fn lstat_follows_intermediate_symlinks_but_never_the_final_one() {
    // Arrange: a live link, a dangling link, a self-loop, and a file behind the live link.
    let fs = FakeFs::builder()
        .dir("/r")
        .file("/t/secret")
        .symlink("/r/link", "/t")
        .symlink("/r/dangling", "/nowhere")
        .symlink("/r/self", "/r/self")
        .build();

    // Act + Assert
    for p in ["/r/link", "/r/dangling", "/r/self"] {
        let md = fs
            .lstat(Path::new(p))
            .expect("final symlink must be reported, not followed");
        assert_eq!(
            md.kind,
            FileKind::Symlink,
            "{p}: final component must stay a symlink"
        );
    }
    let through = fs
        .lstat(Path::new("/r/link/secret"))
        .expect("parent link is followed");
    assert_eq!(
        through.kind,
        FileKind::File,
        "/r/link/secret resolves through the parent link"
    );
    let looped = fs
        .lstat(Path::new("/r/self/x"))
        .expect_err("loop must error, not hang");
    assert_eq!(
        looped.raw_os_error(),
        Some(62),
        "symlink loop must be ELOOP"
    );
    let missing = fs
        .lstat(Path::new("/r/nope"))
        .expect_err("missing entry must error");
    assert_eq!(
        missing.kind(),
        std::io::ErrorKind::NotFound,
        "missing entry must be ENOENT"
    );
}

/// # Design promise
/// `st_dev` changes only at declared mount points and is inherited below them (INV-08 oracle).
///
/// # Scenario (Given)
/// `/a/b/c` with `/a/b` declared as device 2 and `/a/b/c` re-declared as device 1.
///
/// # Action (When)
/// `lstat` `/a`, `/a/b`, `/a/b/x` (below the mount), and `/a/b/c` (nested override).
///
/// # Expected (Then)
/// Devices are 1, 2, 2, 1 respectively.
///
/// # Must never
/// n/a
///
/// # Would catch
/// A fake that stored device per exact path only, hiding "parent on another device" scenarios.
///
/// # Why this test (not redundant)
/// Only test of device inheritance; AC-001-7 rows depend on it.
#[test]
fn device_is_inherited_from_nearest_mount_point() {
    // Arrange
    let fs = FakeFs::builder()
        .file("/a/b/x")
        .dir("/a/b/c")
        .dev("/a/b", 2)
        .dev("/a/b/c", 1)
        .build();

    // Act
    let devs: Vec<u64> = ["/a", "/a/b", "/a/b/x", "/a/b/c"]
        .iter()
        .map(|p| fs.lstat(Path::new(p)).expect("node exists").dev)
        .collect();

    // Assert
    assert_eq!(
        devs,
        vec![1, 2, 2, 1],
        "device must come from the nearest explicit ancestor"
    );
}

/// # Design promise
/// The fake offers what the scanner's tests rely on: `opendir`-faithful listing (a final symlink IS
/// followed, so a scanner that lists a link is visibly wrong), per-path listing errors that leave
/// `lstat` working (macOS TCC), and `lstat` attributes with sparse and hardlink semantics.
///
/// # Scenario (Given)
/// `/r` holding `a` (len 10, 8 blocks), `sparse` (len 1 MiB, 8 blocks), hardlinked `h1`/`h2`, a
/// directory `sub`, `link -> /t` (where `/t/x` exists) and `locked` (a directory with an injected
/// `EPERM` on listing); and a second fake with reversed listings.
///
/// # Action (When)
/// `read_dir` of `/r`, `/r/link`, `/r/locked`, `/r/a`; `lstat` of the files; `read_dir` on the
/// reversed fake.
///
/// # Expected (Then)
/// Entries of `/r` are the seven names in ascending order with the right kinds; `/r/link` lists `x`
/// (followed); `/r/locked` fails with errno 1 while `lstat` succeeds; `/r/a` fails with ENOTDIR (20);
/// `sparse` has `blocks * 512 < len`; `h1` and `h2` share `ino`, both have `nlink == 2`, `a` has
/// `nlink == 1`; the reversed fake lists in descending order.
///
/// # Must never
/// Report a link as not followed by `read_dir`; give hardlinks different inodes.
///
/// # Would catch
/// A fake that cannot express a scanner listing a symlink, or sparse/hardlink metadata, making the
/// scan safety tests vacuous.
///
/// # Why this test (not redundant)
/// The only test of the new fake behavior; the scan tests assume it.
#[test]
fn read_dir_and_attributes_model_what_the_scanner_relies_on() {
    // Arrange
    let build = |reverse: bool| {
        let mut b = FakeFs::builder()
            .file_sized("/r/a", 10, 8)
            .file_sized("/r/sparse", 1 << 20, 8)
            .file_sized("/r/h1", 4096, 8)
            .hardlink("/r/h2", "/r/h1")
            .dir("/r/sub")
            .file("/t/x")
            .symlink("/r/link", "/t")
            .dir("/r/locked")
            .list_error_at("/r/locked", 1);
        if reverse {
            b = b.reverse_read_dir();
        }
        b.build()
    };
    let fs = build(false);

    // Act
    let names = |p: &str, fs: &FakeFs| -> Vec<String> {
        fs.read_dir(Path::new(p))
            .expect("listing must work")
            .iter()
            .map(|e| e.name.to_string_lossy().into_owned())
            .collect()
    };
    let listing = fs.read_dir(Path::new("/r")).expect("listing /r");
    let locked = fs
        .read_dir(Path::new("/r/locked"))
        .expect_err("injected EPERM");
    let on_file = fs
        .read_dir(Path::new("/r/a"))
        .expect_err("a file is not listable");
    let (h1, h2) = (
        fs.lstat(Path::new("/r/h1")).expect("h1"),
        fs.lstat(Path::new("/r/h2")).expect("h2"),
    );
    let (a, sparse) = (
        fs.lstat(Path::new("/r/a")).expect("a"),
        fs.lstat(Path::new("/r/sparse")).expect("sparse"),
    );

    // Assert
    let got: Vec<(String, FileKind)> = listing
        .iter()
        .map(|e| (e.name.to_string_lossy().into_owned(), e.kind))
        .collect();
    let want = [
        ("a", FileKind::File),
        ("h1", FileKind::File),
        ("h2", FileKind::File),
        ("link", FileKind::Symlink),
        ("locked", FileKind::Dir),
        ("sparse", FileKind::File),
        ("sub", FileKind::Dir),
    ]
    .map(|(n, k)| (n.to_owned(), k));
    assert_eq!(
        got, want,
        "ascending listing with kinds (a symlink is listed as a Symlink)"
    );
    assert_eq!(
        names("/r/link", &fs),
        ["x"],
        "read_dir follows a final symlink like opendir"
    );
    assert_eq!(locked.raw_os_error(), Some(1), "injected listing error");
    assert!(
        fs.lstat(Path::new("/r/locked")).is_ok(),
        "lstat still works on a list-error dir"
    );
    assert_eq!(
        on_file.raw_os_error(),
        Some(20),
        "listing a file is ENOTDIR"
    );
    assert!(
        sparse.blocks * 512 < sparse.len,
        "a sparse file allocates less than its length"
    );
    assert_eq!(
        (h1.ino, h1.nlink, h2.nlink),
        (h2.ino, 2, 2),
        "hardlinks share the inode and nlink"
    );
    assert_eq!(
        (a.len, a.blocks, a.nlink),
        (10, 8, 1),
        "plain file attributes"
    );
    assert_eq!(
        names("/r", &build(true)),
        ["sub", "sparse", "locked", "link", "h2", "h1", "a"],
        "reverse_read_dir reverses the listing"
    );
}
