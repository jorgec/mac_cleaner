//! `RealVolume`, the Foundation-backed `VolumeCapacity` adapter (ADR 0002, spec 002 AC-002-1/-2/-3).
//! Only read-only queries about a temp directory (or paths that do not exist) are made: nothing
//! outside the temp dir is read or written (INV-15). The values themselves drift while the machine
//! runs, so the tests assert **relations** the contract promises, never absolute numbers; the one
//! comparison with a real number is the opt-in Swift oracle test (ignored by default).
//!
//! # Worksheet - `RealVolume::query`
//! ```text
//! Function:        cleaner_macos::RealVolume::query(path) -> Result<VolumeCaps, VolumeError>
//! Contract:        describes the volume that HOLDS `path` (directory or file): mount_point is an
//!                  absolute directory on the same device (`st_dev`) as the path (NOT necessarily a
//!                  lexical ancestor: firmlinks make `/private/var/..` live on
//!                  `/System/Volumes/Data`) and the same for every node of that volume; total >= 1 GiB (not 0, not a constant); available <= total; the purgeable value derived
//!                  by core (`volume::purgeable`) never exceeds total. A missing path is
//!                  `NotFound{path}` (path as queried); a path the OS refuses to resolve (inside a `chmod 000`
//!                  directory) is `PermissionDenied`; a path Foundation cannot be given (empty,
//!                  interior NUL, non-UTF-8) is an `Err` too. Never a panic; a failure is never
//!                  reported as zero capacity (INV-13). (ADR 0002, AC-002-1, -2, -3)
//! Equivalence classes: directory | file in that directory | nested directory | missing path |
//!                  unrepresentable path
//! Boundaries:      existing vs missing path; missing vs unreadable
//! Must-never:      panic; return Ok with total 0 for a failed query; describe another volume than
//!                  the one holding the path
//! Selected tests:  ac_002_3_..., ac_002_2_..., ac_002_3_..._swift_oracle (ignored)
//! Deliberately not tested: `important >= available` (expected, but NOT an Apple guarantee, so a
//!                  test of it would flake on a perfectly valid machine); absolute values (drift);
//!                  external/network volumes (no safe fixture); the exact `QueryFailed` text.
//! ```
//!
//! # How to run the Swift oracle test (opt-in, needs `/usr/bin/swift`)
//! `scripts/with-scratch-home.sh cargo nextest run -p cleaner-macos --run-ignored ignored-only -E 'test(swift_oracle)'`
//! (the script `tests/oracle/volume_oracle.swift` prints Foundation's own four numbers for a path;
//! the test requires every field to agree within 1 MiB because free space moves while tests run).

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use cleaner_core::ports::{VolumeCapacity, VolumeCaps, VolumeError};
use cleaner_core::volume::purgeable;
use cleaner_macos::RealVolume;

/// Restores `0o755` on drop so a `chmod 000` fixture directory can always be removed.
struct RestorePerms(PathBuf);

impl Drop for RestorePerms {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
    }
}

/// One gibibyte: any volume that can hold macOS (and the temp dir under test) is at least this big.
const GIB: u64 = 1024 * 1024 * 1024;
/// One mebibyte: the tolerance ADR 0002 grants the oracle comparison.
const MIB: u64 = 1024 * 1024;

/// Query `path` and fail the test with the error if the adapter refuses.
fn query_ok(path: &Path) -> VolumeCaps {
    RealVolume
        .query(path)
        .unwrap_or_else(|e| panic!("query {}: {e}", path.display()))
}

/// # Design promise
/// AC-002-3 / ADR 0002: the adapter describes the volume that holds the queried path - whatever kind of
/// node it is - with the relations the contract promises: `total >= 1 GiB`, `available <= total`, an
/// absolute `mount_point` that contains the path, and a derived purgeable value that can never exceed
/// `total` (AC-002-1).
///
/// # Scenario (Given)
/// A temp dir containing a nested directory and a regular file (all on the same volume).
///
/// # Action (When)
/// `RealVolume.query` on the directory, the nested directory and the file.
///
/// # Expected (Then)
/// For each: `total` is at least 1 GiB and `available <= total`; `mount_point` is absolute and its `st_dev` equals the queried path's `st_dev` (same volume, firmlinks
/// make a lexical prefix test wrong); `purgeable(&caps).bytes <= total`; and the three queries report the same
/// `mount_point` and `total` (one volume).
///
/// # Must never
/// Report zero capacity for a healthy volume; report a mount point that does not contain the path
/// (the wrong volume would be shown to the user); let purgeable exceed the volume size.
///
/// # Would catch
/// Querying `/` instead of the path, swapped keys (total vs available), failing to convert Foundation
/// numbers (all zeros), a mount point read from the wrong key.
///
/// # Why this test (not redundant)
/// The only real-adapter test of the success class; the arithmetic is core-tested with a fake, and
/// agreement with an independent source is the ignored oracle test.
#[test]
fn ac_002_3_volume_adapter_describes_the_volume_holding_the_path() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let nested = tmp.path().join("nested");
    fs::create_dir(&nested).expect("mkdir");
    let file = nested.join("file");
    File::create(&file)
        .and_then(|mut f| f.write_all(b"x"))
        .expect("create file");

    let mut seen: Vec<(PathBuf, VolumeCaps)> = Vec::new();
    for path in [tmp.path(), nested.as_path(), file.as_path()] {
        // Act
        let caps = query_ok(path);

        // Assert
        assert!(
            caps.total >= GIB,
            "{}: a volume that holds macOS and a temp dir has at least 1 GiB, got {}",
            path.display(),
            caps.total
        );
        let numbers = [
            caps.total,
            caps.available,
            caps.available_important,
            caps.available_opportunistic,
        ];
        assert!(
            numbers.iter().any(|n| *n != caps.total),
            "{}: the four capacity numbers must come from different keys, got {numbers:?}",
            path.display()
        );
        assert!(
            caps.available <= caps.total,
            "{}: available ({}) must not exceed total ({})",
            path.display(),
            caps.available,
            caps.total
        );
        let dev_of = |p: &Path| fs::metadata(p).map(|m| m.dev());
        assert!(
            caps.mount_point.is_absolute() && dev_of(&caps.mount_point).ok() == dev_of(path).ok(),
            "{}: mount point {:?} must be a directory on the same device as the path",
            path.display(),
            caps.mount_point
        );
        assert!(
            purgeable(&caps).bytes <= caps.total,
            "{}: purgeable must never exceed the volume size",
            path.display()
        );
        seen.push((path.to_path_buf(), caps));
    }
    let first = seen.first().map(|(_, c)| (c.mount_point.clone(), c.total));
    assert!(
        seen.iter()
            .all(|(_, c)| Some((c.mount_point.clone(), c.total)) == first),
        "every node of one volume must report the same mount point and total: {seen:?}"
    );
}

/// # Design promise
/// AC-002-2 / INV-13: a query that cannot succeed is a typed `Err`, never a panic and never an `Ok`
/// with zeros: a missing path is `NotFound` carrying the path as queried; a path that cannot even be
/// handed to Foundation (empty, interior NUL, non-UTF-8 bytes) is an `Err`.
///
/// # Scenario (Given)
/// A path below a temp dir that does not exist; a path inside a `chmod 000` directory (restored by a
/// guard; skipped when running as root); the empty path; a path with an interior NUL; a path
/// with the byte `0xFF`.
///
/// # Action (When)
/// `RealVolume.query` for each.
///
/// # Expected (Then)
/// `Err(NotFound{path})` with `path` equal to the queried path (and `kind() == "not_found"`) for the
/// missing path; `Err(PermissionDenied)` (kind `permission_denied`) for the path inside the locked
/// directory; `Err(QueryFailed{..})` (kind `query_failed`) for a path whose last component is 300 bytes
/// long (`ENAMETOOLONG`: neither "missing" nor "refused"); `Err(_)` for the other three.
///
/// # Must never
/// Panic (the adapter sits behind `unsafe`/Objective-C bridging), or return `Ok` with zero capacity
/// (unknown must not look like "no space", INV-13); report an OS refusal as "not found" (the user
/// would be told the path is missing instead of that access was denied).
///
/// # Would catch
/// `unwrap()` on a failed `NSString`/`NSURL` creation, treating the `NSError` as "0 bytes", swallowing
/// the not-found class into a generic failure, mapping every `lstat`/Foundation error to `NotFound`.
///
/// # Why this test (not redundant)
/// The only real-adapter test of the failure classes; core tests only see injected `VolumeError`s.
#[test]
fn ac_002_2_volume_adapter_fails_with_typed_errors_and_never_panics_or_reports_zero() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let missing = tmp.path().join("no-such-dir");
    let locked = tmp.path().join("locked");
    fs::create_dir(&locked).expect("mkdir locked");
    File::create(locked.join("inside")).expect("file inside");
    let is_root = fs::metadata(tmp.path()).is_ok_and(|m| m.uid() == 0);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod 000");
    let _restore = RestorePerms(locked.clone());

    // Act
    let not_found = RealVolume.query(&missing);
    let denied = RealVolume.query(&locked.join("inside"));
    let too_long = RealVolume.query(&tmp.path().join("x".repeat(300)));

    // Assert
    match not_found {
        Err(e @ VolumeError::NotFound { .. }) => {
            assert_eq!(
                e,
                VolumeError::NotFound {
                    path: missing.clone()
                },
                "NotFound must carry the path as queried"
            );
            assert_eq!(e.kind(), "not_found", "stable error code");
        }
        other => panic!("a missing path must be NotFound, got {other:?}"),
    }
    if is_root {
        eprintln!("running as root: the permission-denied row is not applicable");
    } else {
        assert_eq!(
            denied,
            Err(VolumeError::PermissionDenied),
            "an OS refusal must be PermissionDenied (stable code `permission_denied`)"
        );
    }
    assert!(
        matches!(&too_long, Err(e) if e.kind() == "query_failed"),
        "any other OS failure (here ENAMETOOLONG) is `query_failed`, neither not_found nor permission_denied, got {too_long:?}"
    );
    let unrepresentable: [(&str, &OsStr); 3] = [
        ("empty path", OsStr::new("")),
        ("interior NUL", OsStr::from_bytes(b"/tmp/a\0b")),
        ("non-UTF-8", OsStr::from_bytes(b"/tmp/\xff-not-utf8")),
    ];
    for (name, raw) in unrepresentable {
        let result = RealVolume.query(Path::new(raw));
        assert!(
            result.is_err(),
            "{name}: must be an Err (never Ok with invented capacity), got {result:?}"
        );
    }
}

/// # Design promise
/// ADR 0002: the adapter reports what Foundation itself reports - checked against an independent
/// source (a throwaway Swift script using `URLResourceValues`) so a wrong key mapping or unit error on
/// a new macOS release is caught. Values move while tests run, hence the 1 MiB tolerance.
///
/// # Scenario (Given)
/// A temp dir; `/usr/bin/swift` available; the oracle script `tests/oracle/volume_oracle.swift`.
///
/// # Action (When)
/// Query the adapter, then run the oracle on the same path (run twice around the query, so the
/// tolerance also covers drift between the two reads).
///
/// # Expected (Then)
/// `total`, `available`, `available_important` and `available_opportunistic` each differ from the
/// oracle by at most 1 MiB.
///
/// # Must never
/// Run by default (it spawns `swift`, which compiles for seconds and may write module caches); touch
/// anything outside the temp dir and the scratch HOME.
///
/// # Would catch
/// Mixed-up capacity keys (e.g. important vs opportunistic), a unit error (KiB vs bytes), reading a
/// stale/cached value.
///
/// # Why this test (not redundant)
/// The only comparison of the adapter with Apple's own numbers; everything else asserts relations.
#[test]
#[ignore = "requires-swift-oracle"]
#[allow(
    clippy::disallowed_methods,
    reason = "opt-in oracle test: runs the read-only Swift script volume_oracle.swift"
)]
fn ac_002_3_volume_adapter_agrees_with_the_swift_oracle_within_1_mib() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/volume_oracle.swift");
    let oracle = || -> [u64; 4] {
        let out = std::process::Command::new("/usr/bin/swift")
            .arg(&script)
            .arg(tmp.path())
            .env("CLANG_MODULE_CACHE_PATH", tmp.path().join("module-cache"))
            .output()
            .expect("run swift");
        assert!(
            out.status.success(),
            "the Swift oracle failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let numbers: Vec<u64> = text
            .split_whitespace()
            .map(|n| {
                n.parse()
                    .unwrap_or_else(|e| panic!("oracle number {n:?}: {e}"))
            })
            .collect();
        numbers
            .try_into()
            .unwrap_or_else(|v: Vec<u64>| panic!("oracle must print 4 numbers, got {v:?}"))
    };

    // Act
    let before = oracle();
    let caps = query_ok(tmp.path());
    let after = oracle();

    // Assert
    let got = [
        ("total", caps.total),
        ("available", caps.available),
        ("available_important", caps.available_important),
        ("available_opportunistic", caps.available_opportunistic),
    ];
    for (i, (name, value)) in got.into_iter().enumerate() {
        let (lo, hi) = (
            before.get(i).copied().unwrap_or(0),
            after.get(i).copied().unwrap_or(0),
        );
        assert!(
            value.abs_diff(lo) <= MIB || value.abs_diff(hi) <= MIB,
            "{name}: adapter {value} is not within 1 MiB of the oracle ({lo} before, {hi} after)"
        );
    }
}
