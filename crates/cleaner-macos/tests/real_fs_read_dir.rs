//! `RealFs::read_dir` and the extended `RealFs::lstat` fields on real temp directories (spec 002
//! AC-002-4, -5, -7, -16; INV-07, INV-09, INV-12). The scanner is tested against `FakeFs`; these
//! tests prove the *real* adapter delivers what the fake models.
//!
//! Every directory is a `tempfile::TempDir`; nothing outside it is read or written (INV-15). A
//! `chmod 000` directory is restored by a `Drop` guard so the temp dir can always be removed.
//!
//! # Worksheet - `RealFs::read_dir`
//! ```text
//! Function:        cleaner_macos::RealFs::read_dir(path) -> io::Result<Vec<DirEntry{name, kind}>>
//! Contract:        one batch with every entry directly inside `path` (hidden entries included, never
//!                  `.`/`..`), each with the kind of the ENTRY ITSELF (a symlink is `Symlink`, live
//!                  or dangling or looping; it is never followed); names are the raw bytes of the
//!                  directory entry (no lossy conversion, no normalization); order unspecified; errors
//!                  are the raw OS errors (ENOENT, ENOTDIR, EACCES). (AC-002-5, -7, -16; INV-07, INV-09)
//! Equivalence classes: file | dir | live/dangling/looping symlink | socket (Other) | hidden entry |
//!                  hostile names (space, newline, leading dash, NFD, emoji; non-UTF-8 where the
//!                  filesystem can hold it) | missing path | non-directory | unreadable directory
//! Boundaries:      symlink as an entry; `chmod 000` directory vs its still-`lstat`able inode
//! Must-never:      follow an entry symlink or list behind it; drop dotfiles; lossy-convert a name;
//!                  panic on an error; leave a directory un-restorable
//! Selected tests:  safety::ac_002_5_..., ac_002_16_..., safety::ac_002_7_...
//! Deliberately not tested: `read_dir` of a final symlink (std/opendir behavior, the scanner never
//!                  lists a `Symlink`); entry order (unspecified by the port); non-UTF-8 names are
//!                  not creatable on APFS (EILSEQ), so that class is asserted conditionally.
//! ```
//!
//! # Worksheet - `RealFs::lstat` (extended fields)
//! ```text
//! Function:        cleaner_macos::RealFs::lstat(path) -> io::Result<Metadata{kind,dev,ino,blocks,len,mtime,nlink}>
//! Contract:        len = st_size, blocks = st_blocks (512-byte units, so a sparse file has
//!                  blocks*512 < len), nlink = st_nlink, ino/dev identify the inode (two names of one
//!                  file are equal, different files differ), mtime = st_mtime; for a symlink all of
//!                  them describe the LINK (len = length of the target path). (AC-002-4, INV-12)
//! Equivalence classes: written file | hardlinked file | empty file | sparse file | symlink | directory
//! Boundaries:      empty file (0 blocks) vs sparse (len > 0, blocks ~ 0) vs written (blocks >= len/512)
//! Must-never:      fill a field from the symlink's target; report `nlink` 1 for a hardlink
//! Selected tests:  ac_002_4_lstat_reports_...
//! Deliberately not tested: exact block counts (filesystem policy; only the relations the scanner
//!                  relies on are asserted); atime (deliberately not exposed).
//! ```

use std::ffi::OsString;
use std::fs::{self, File, Permissions};
use std::io::Write as _;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use cleaner_core::ports::{FileKind, Fs};
use cleaner_macos::RealFs;

/// Restores `0o755` on drop so a `chmod 000` fixture directory can be removed with its temp dir,
/// even when an assertion fails.
struct RestorePerms(PathBuf);

impl Drop for RestorePerms {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, Permissions::from_mode(0o755));
    }
}

/// True when the test process can read a `chmod 000` directory anyway (root): the permission
/// scenario is then meaningless and the test must say so instead of failing.
fn bypasses_permissions(probe_dir: &Path) -> bool {
    fs::metadata(probe_dir).is_ok_and(|m| m.uid() == 0)
}

/// Create a small regular file with `content`.
fn write_file(path: &Path, content: &[u8]) {
    File::create(path)
        .and_then(|mut f| f.write_all(content))
        .unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
}

/// `(name, kind)` of a listing, sorted by raw name bytes (the port promises no order).
fn listing(path: &Path) -> Vec<(OsString, FileKind)> {
    let mut entries: Vec<(OsString, FileKind)> = RealFs
        .read_dir(path)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", path.display()))
        .into_iter()
        .map(|e| (e.name, e.kind))
        .collect();
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    entries
}

mod safety {
    use super::*;

    /// # Design promise
    /// AC-002-5 / INV-07 / INV-08: the real directory listing reports what each *entry* is - a symlink
    /// is a `Symlink` (never the kind of its target), sockets are `Other` - lists hidden entries and
    /// never `.`/`..`, and never lists behind a link.
    ///
    /// # Scenario (Given)
    /// A temp dir holding: a file, a hidden file, a subdirectory (with an inner file), a live symlink to
    /// a directory *outside* the scanned directory (that directory holds a file), a dangling symlink, a
    /// self-referencing symlink, and a unix-domain socket node.
    ///
    /// # Action (When)
    /// `RealFs.read_dir` on the directory.
    ///
    /// # Expected (Then)
    /// Exactly these `(name, kind)` pairs (sorted): `.hidden` File, `dangling` Symlink, `dir` Dir,
    /// `file` File, `live` Symlink, `loop` Symlink, `sock` Other. No `.`/`..`, nothing from `dir/inner`
    /// (the listing is flat) and nothing from the outside directory the live link points to.
    ///
    /// # Must never
    /// Report a symlink as `Dir`/`File` (the walker would then enter or count the target); include the
    /// target's contents; skip dotfiles (hidden caches would be missed).
    ///
    /// # Would catch
    /// `file_type()` taken from `fs::metadata` (follows links), filtering names starting with `.`,
    /// recursing into subdirectories, returning `.`/`..`.
    ///
    /// # Why this test (not redundant)
    /// The only real-adapter proof of the listing semantics the scanner assumes; `lstat` of links is
    /// `inv_07_lstat_reports_kind_and_device_and_never_follows_symlinks`.
    #[test]
    fn ac_002_5_read_dir_reports_each_entry_itself_and_never_follows_links() {
        // Arrange: the scanned dir and, beside it, a directory a symlink points to.
        let tmp = tempfile::tempdir().expect("temp dir");
        let scanned = tmp.path().join("scanned");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(scanned.join("dir")).expect("mkdir dir");
        fs::create_dir_all(&outside).expect("mkdir outside");
        write_file(&scanned.join("file"), b"x");
        write_file(&scanned.join(".hidden"), b"x");
        write_file(&scanned.join("dir/inner"), b"x");
        write_file(&outside.join("secret"), b"x");
        symlink(&outside, scanned.join("live")).expect("live link");
        symlink(scanned.join("nowhere"), scanned.join("dangling")).expect("dangling link");
        symlink(scanned.join("loop"), scanned.join("loop")).expect("loop link");
        let _socket = std::os::unix::net::UnixListener::bind(scanned.join("sock")).expect("socket");

        // Act
        let got = listing(&scanned);

        // Assert
        let want: Vec<(OsString, FileKind)> = [
            (".hidden", FileKind::File),
            ("dangling", FileKind::Symlink),
            ("dir", FileKind::Dir),
            ("file", FileKind::File),
            ("live", FileKind::Symlink),
            ("loop", FileKind::Symlink),
            ("sock", FileKind::Other),
        ]
        .into_iter()
        .map(|(n, k)| (OsString::from(n), k))
        .collect();
        assert_eq!(
            got, want,
            "INV-07: each entry is reported as itself (links are Symlink, never their target's kind), flat, with dotfiles and without . or .."
        );
    }

    /// # Design promise
    /// AC-002-7 / INV-09 and the port contract "errors are the raw OS errors": a missing path is
    /// `NotFound` (the scanner counts it as vanished), a non-directory is `ENOTDIR`, and a directory the
    /// user may not read is `PermissionDenied` (`EACCES`) - an error value, never a panic, never an
    /// empty listing. The locked directory itself and its own entry in the parent are still visible, and
    /// an `lstat` of something inside it fails with the same permission error.
    ///
    /// # Scenario (Given)
    /// A temp dir with a regular file, a missing name, and a directory `locked` with mode `000` that
    /// contains a file (restored by a guard afterwards).
    ///
    /// # Action (When)
    /// `read_dir` of the missing path, of the file, of `locked`; `lstat` of `locked` and of
    /// `locked/inside`; `read_dir` of the parent.
    ///
    /// # Expected (Then)
    /// `NotFound`; raw OS error 20 (`ENOTDIR`); `PermissionDenied` with raw error 13; `lstat(locked)`
    /// is `Ok` with kind `Dir`; `lstat(locked/inside)` is `PermissionDenied`; the parent still lists
    /// `locked` as a `Dir`.
    ///
    /// # Must never
    /// Return `Ok(vec![])` for an unreadable directory (the scan would report 0 bytes as if it had
    /// looked), panic, or change the permissions itself (no escalation, INV-10).
    ///
    /// # Would catch
    /// `unwrap_or_default()` on the listing error, mapping every error to `NotFound`, an adapter that
    /// tries `chmod` to read the directory.
    ///
    /// # Why this test (not redundant)
    /// Only real-adapter evidence for the error classes `ac_002_7_unreadable_entries...` feeds the
    /// scanner through `FakeFs` (it injects the same errnos).
    #[test]
    fn ac_002_7_read_dir_and_lstat_surface_raw_os_errors_for_missing_nondir_and_locked() {
        // Arrange
        let tmp = tempfile::tempdir().expect("temp dir");
        let root = tmp.path();
        write_file(&root.join("plain"), b"x");
        let locked = root.join("locked");
        fs::create_dir(&locked).expect("mkdir locked");
        write_file(&locked.join("inside"), b"x");
        if bypasses_permissions(root) {
            eprintln!("skipped: running as root, chmod 000 does not deny access");
            return;
        }
        fs::set_permissions(&locked, Permissions::from_mode(0o000)).expect("chmod 000");
        let _restore = RestorePerms(locked.clone());

        // Act
        let missing = RealFs.read_dir(&root.join("missing"));
        let not_dir = RealFs.read_dir(&root.join("plain"));
        let denied = RealFs.read_dir(&locked);
        let lstat_locked = RealFs.lstat(&locked);
        let lstat_inside = RealFs.lstat(&locked.join("inside"));
        let parent = listing(root);

        // Assert
        assert_eq!(
            missing.expect_err("missing").kind(),
            std::io::ErrorKind::NotFound,
            "ENOENT must surface as NotFound (the scanner counts it as vanished)"
        );
        assert_eq!(
            not_dir.expect_err("file").raw_os_error(),
            Some(20),
            "listing a regular file must be ENOTDIR, unchanged"
        );
        let denied = denied.expect_err("a chmod 000 directory must not be listable");
        assert_eq!(
            (denied.kind(), denied.raw_os_error()),
            (std::io::ErrorKind::PermissionDenied, Some(13)),
            "INV-09: an unreadable directory is an EACCES error, never an empty listing"
        );
        assert_eq!(
            lstat_locked.expect("lstat of the locked dir itself").kind,
            FileKind::Dir,
            "the locked directory's own inode must stay visible through its parent"
        );
        assert_eq!(
            lstat_inside.expect_err("inside").kind(),
            std::io::ErrorKind::PermissionDenied,
            "lstat below a locked directory is a permission error the scanner records"
        );
        assert!(
            parent.contains(&(OsString::from("locked"), FileKind::Dir)),
            "the parent must still list the locked directory: {parent:?}"
        );
    }
}

/// # Design promise
/// AC-002-16 / INV-07 / ADR 0002: names come back as the exact bytes stored in the directory (no lossy
/// conversion, no Unicode normalization, no trimming), so the report can carry them losslessly
/// (`path` + `path_b64`).
///
/// # Scenario (Given)
/// A temp dir with entries named: `a b` (space), `line\nbreak` (newline), `-rf` (leading dash), an NFD
/// name (`cafe` + U+0301, which APFS preserves as typed), and an emoji name. Additionally the test
/// tries to create a name containing the byte `0xFF`: APFS refuses invalid UTF-8 with `EILSEQ` (92);
/// on a filesystem that accepts it the adapter must return those exact bytes.
///
/// # Action (When)
/// `RealFs.read_dir`.
///
/// # Expected (Then)
/// The set of returned names equals the created set byte for byte; if the `0xFF` name could not be
/// created, that creation failed with `EILSEQ` (the premise of this filesystem, so the class cannot
/// occur there).
///
/// # Must never
/// Normalize NFD to NFC, replace invalid bytes with U+FFFD, panic on a non-UTF-8 name.
///
/// # Would catch
/// `file_name().to_string_lossy().into_owned().into()` (lossy), `to_str().unwrap()`, trimming or
/// Unicode normalization of names.
///
/// # Why this test (not redundant)
/// The only real-adapter test of name fidelity; the report side (`path_b64`) is core-tested.
#[test]
fn ac_002_16_read_dir_returns_names_byte_for_byte_including_hostile_ones() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let dir = tmp.path();
    let mut want: Vec<OsString> = [
        "a b",
        "line\nbreak",
        "-rf",
        "cafe\u{301}",
        "emoji-\u{1F600}",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    for name in &want {
        write_file(&dir.join(name), b"x");
    }
    let invalid = OsString::from_vec(b"bad-\xff-name".to_vec());
    match File::create(dir.join(&invalid)) {
        Ok(_) => want.push(invalid),
        Err(e) => assert_eq!(
            e.raw_os_error(),
            Some(92),
            "the only acceptable reason a non-UTF-8 name cannot exist is EILSEQ (APFS)"
        ),
    }

    // Act
    let mut got: Vec<OsString> = listing(dir).into_iter().map(|(n, _)| n).collect();

    // Assert
    got.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    want.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(
        got, want,
        "names must be returned byte for byte (no lossy conversion, no normalization)"
    );
}

/// # Design promise
/// AC-002-4 / INV-12: `lstat` hands the scanner the real inode facts it sizes and dedupes with:
/// `len` (logical), `blocks` (512-byte units: allocated < logical for a sparse file, 0 for an empty
/// file), `nlink`, the `(dev, ino)` identity shared by hardlinked names, and `mtime`; for a symlink
/// they describe the link itself.
///
/// # Scenario (Given)
/// In a temp dir: `a` (10 bytes written, mtime set to `1_000_000_000` s), `b` a hardlink of `a`, `c` a
/// different file, `empty` (0 bytes), `sparse` (1 MiB `set_len`, nothing written), `link` a symlink to
/// `a` through its absolute path, and a directory `d`.
///
/// # Action (When)
/// `RealFs.lstat` on each.
///
/// # Expected (Then)
/// `a`: len 10, mtime exactly the one set, nlink 2, `blocks*512 >= 10`; `b`: same `(dev, ino)` as `a`,
/// nlink 2; `c`: a different `ino`; `empty`: len 0 and 0 blocks; `sparse`: len 1 MiB and
/// `blocks*512 < len`; `link`: kind `Symlink`, len equal to the byte length of its target path (not
/// 10), a different `ino` than `a`, nlink 1; `d`: kind `Dir` and the same `dev` as `a`.
///
/// # Must never
/// Fill fields from the link's target; report nlink 1 for a hardlinked file; derive `blocks` from
/// `len`.
///
/// # Would catch
/// `metadata` instead of `symlink_metadata`, `blocks = len / 512`, `ino`/`dev` swapped or zeroed,
/// `nlink` hard-coded to 1 (hardlinks would be counted twice), mtime taken from atime/ctime.
///
/// # Why this test (not redundant)
/// The existing `inv_07_...` test only covers `kind` and `dev`; this is the only real-adapter test of
/// the size/identity/time fields the scanner's accounting depends on.
#[test]
#[allow(
    clippy::many_single_char_names,
    reason = "fixture names a, b, c, d mirror the doc"
)]
fn ac_002_4_lstat_reports_size_blocks_links_identity_and_mtime_of_the_inode_itself() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let p = tmp.path();
    write_file(&p.join("a"), b"0123456789");
    let stamp = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    File::options()
        .write(true)
        .open(p.join("a"))
        .and_then(|f| f.set_modified(stamp))
        .expect("set mtime");
    fs::hard_link(p.join("a"), p.join("b")).expect("hardlink");
    write_file(&p.join("c"), b"other");
    write_file(&p.join("empty"), b"");
    let sparse_len = 1024 * 1024;
    File::create(p.join("sparse"))
        .and_then(|f| f.set_len(sparse_len))
        .expect("sparse file");
    symlink(p.join("a"), p.join("link")).expect("symlink");
    fs::create_dir(p.join("d")).expect("mkdir");

    // Act
    let at = |name: &str| {
        RealFs
            .lstat(&p.join(name))
            .unwrap_or_else(|e| panic!("lstat {name}: {e}"))
    };
    let (a, b, c, empty, sparse, link, d) = (
        at("a"),
        at("b"),
        at("c"),
        at("empty"),
        at("sparse"),
        at("link"),
        at("d"),
    );

    // Assert
    assert_eq!(a.len, 10, "len is st_size");
    assert_eq!(a.mtime, stamp, "mtime is st_mtime, to the second");
    assert_eq!(
        a.nlink, 2,
        "a file with two names has nlink 2 (hardlink dedupe relies on it)"
    );
    assert!(
        a.blocks * 512 >= 10,
        "a written file has at least its content allocated, got {} blocks",
        a.blocks
    );
    assert_eq!(
        (b.dev, b.ino, b.nlink),
        (a.dev, a.ino, 2),
        "INV-12: two names of one inode share (dev, ino)"
    );
    assert_ne!(
        c.ino, a.ino,
        "a different file has a different inode number"
    );
    assert_eq!(
        (empty.len, empty.blocks),
        (0, 0),
        "an empty file allocates nothing"
    );
    assert_eq!(
        sparse.len, sparse_len,
        "a sparse file keeps its logical length"
    );
    assert!(
        sparse.blocks * 512 < sparse.len,
        "INV-12: allocated ({} bytes) must be below logical ({}) for a sparse file",
        sparse.blocks * 512,
        sparse.len
    );
    assert_eq!(
        link.kind,
        FileKind::Symlink,
        "a symlink is reported as itself"
    );
    assert_eq!(
        link.len,
        p.join("a").as_os_str().as_bytes().len() as u64,
        "a symlink's size is the length of its target path, not the target's size"
    );
    assert_ne!(
        link.ino, a.ino,
        "INV-07: the link's own inode, not the target's"
    );
    assert_eq!(link.nlink, 1, "the link itself has one name");
    assert_eq!(
        (d.kind, d.dev),
        (FileKind::Dir, a.dev),
        "a directory in the same directory is on the same device"
    );
}
