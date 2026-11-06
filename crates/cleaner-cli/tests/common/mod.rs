//! Shared scaffolding for the binary-level tests (spec 002b). Not a test file.
//!
//! A [`Sandbox`] is one temp directory holding everything a scenario needs: a `home` (the child's
//! `HOME`), a `tmp` that is the child's `TMPDIR` and the parent of `home` (so the INV-15 guard accepts
//! it), and a `bin` directory for fake programs. The child gets a **cleared** environment plus
//! `HOME`, `TMPDIR`, `PATH=/usr/bin:/bin`, `CLEANER_TEST_MODE=1`, and the two hermetic seams:
//!
//! * `CLEANER_TMUTIL=<script>`: a canned `tmutil` (never the real one),
//! * `CLEANER_TEST_VOLUME=<total>:<available>:<important>`: a fixed volume (494.4 GB total, 365.8 GB
//!   available, 4.2 GB purgeable, the figures of ADR 0002).
//!
//! The seams exist only in test mode (`CLEANER_TEST_MODE` on and `HOME` inside the temp dir); tests
//! that need the real volume adapter remove `CLEANER_TEST_VOLUME`.
#![allow(dead_code)] // each test binary uses a different subset

use std::fs::{self, File, Permissions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use cleaner_core::audit::{DecodedRecord, decode_line};

/// The fixed volume the default seam reports (ADR 0002 figures): total, available, important.
pub const FIXED_VOLUME: &str = "494384795648:365789609984:369982967776";
/// Purgeable bytes of [`FIXED_VOLUME`] (`important - available`).
pub const FIXED_PURGEABLE: u64 = 4_193_357_792;

/// One scenario's directories.
pub struct Sandbox {
    _base: tempfile::TempDir,
    /// The child's `TMPDIR`.
    pub tmp: PathBuf,
    /// The child's `HOME` (inside `tmp`).
    pub home: PathBuf,
    /// Fake programs.
    pub bin: PathBuf,
}

impl Sandbox {
    /// Fresh, empty sandbox with a default canned `tmutil` (header only: zero snapshots).
    pub fn new() -> Self {
        let base = tempfile::tempdir().expect("temp dir");
        let tmp = base.path().join("tmp");
        let home = tmp.join("home");
        let bin = base.path().join("bin");
        for d in [&home, &bin] {
            fs::create_dir_all(d).expect("mkdir");
        }
        let sandbox = Self {
            _base: base,
            tmp,
            home,
            bin,
        };
        sandbox.tmutil("printf 'Snapshots for disk /:\\n'");
        sandbox
    }

    /// Write the fake `tmutil` (an executable `/bin/sh` script with `body`) and return its path.
    pub fn tmutil(&self, body: &str) -> PathBuf {
        let path = self.bin.join("tmutil");
        File::create(&path)
            .and_then(|mut f| f.write_all(format!("#!/bin/sh\n{body}\n").as_bytes()))
            .expect("write fake tmutil");
        fs::set_permissions(&path, Permissions::from_mode(0o755)).expect("chmod +x");
        path
    }

    /// Create `rel` below `home` as a file of `size` bytes (non-zero content, parents created).
    pub fn file(&self, rel: &str, size: usize) -> PathBuf {
        let path = self.home.join(rel);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir -p");
        File::create(&path)
            .and_then(|mut f| f.write_all(&vec![b'x'; size]))
            .expect("write fixture file");
        path
    }

    /// Create the directory `rel` below `home`.
    pub fn dir(&self, rel: &str) -> PathBuf {
        let path = self.home.join(rel);
        fs::create_dir_all(&path).expect("mkdir -p");
        path
    }

    /// The `cleaner` binary in test mode with the default seams (see the module doc), as a plain
    /// `std` command so a test can also spawn it in the background (SIGINT test).
    ///
    /// `std::process::Command::new` is banned by clippy.toml outside the adapters (INV-10); a test
    /// has to start the binary under test somehow, and the program is the freshly built `cleaner`
    /// (never user input, never a shell): the one reviewed exception.
    #[allow(
        clippy::disallowed_methods,
        reason = "tests start the binary under test; the program is the built `cleaner`, no shell"
    )]
    pub fn std_command(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("cleaner"));
        cmd.env_clear()
            .env("HOME", &self.home)
            .env("TMPDIR", &self.tmp)
            .env("PATH", "/usr/bin:/bin")
            .env("CLEANER_TEST_MODE", "1")
            .env("CLEANER_TMUTIL", self.bin.join("tmutil"))
            .env("CLEANER_TEST_VOLUME", FIXED_VOLUME);
        cmd
    }

    /// [`Sandbox::std_command`] wrapped for `assert_cmd` assertions.
    pub fn cleaner(&self) -> Command {
        Command::from_std(self.std_command())
    }

    /// A directory that is NOT inside the child's temp dir (a sibling of `tmp`): a `HOME` the
    /// INV-15 guard must refuse. Created empty.
    pub fn outside_home(&self) -> PathBuf {
        let dir = self.tmp.parent().expect("base dir").join("home-outside");
        fs::create_dir_all(&dir).expect("mkdir home-outside");
        dir
    }

    /// `home/Library/Logs/mac-cleaner`.
    pub fn log_dir(&self) -> PathBuf {
        self.home.join("Library/Logs/mac-cleaner")
    }

    /// Audit files (`audit-*.jsonl`) in the log directory, sorted by name.
    pub fn audit_files(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = fs::read_dir(self.log_dir())
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                            n.starts_with("audit-")
                                && Path::new(n).extension().is_some_and(|e| e == "jsonl")
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        files
    }

    /// Every record of `file`, decoded (panics on an undecodable line: that is a product bug).
    pub fn records(file: &Path) -> Vec<DecodedRecord> {
        let text = fs::read_to_string(file).expect("read audit file");
        text.lines()
            .map(|l| decode_line(l).unwrap_or_else(|e| panic!("undecodable audit line {l}: {e}")))
            .collect()
    }

    /// Everything below `home` as `(relative path, kind+size+mtime fingerprint)`, sorted, skipping
    /// the audit log directory: used to prove a scan changed nothing (INV-01).
    pub fn tree_fingerprint(&self) -> Vec<(String, String)> {
        fn walk(dir: &Path, home: &Path, skip: &Path, out: &mut Vec<(String, String)>) {
            for entry in fs::read_dir(dir).expect("read_dir").filter_map(Result::ok) {
                let path = entry.path();
                if path == skip {
                    continue;
                }
                let md = fs::symlink_metadata(&path).expect("lstat");
                let rel = path
                    .strip_prefix(home)
                    .expect("below home")
                    .display()
                    .to_string();
                out.push((
                    rel,
                    format!(
                        "{:o}:{}:{}:{}",
                        md.mode(),
                        md.len(),
                        md.mtime(),
                        md.mtime_nsec()
                    ),
                ));
                if md.is_dir() {
                    walk(&path, home, skip, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.home, &self.home, &self.log_dir(), &mut out);
        out.sort();
        out
    }
}

/// Allocated bytes (`st_blocks * 512`) of `path`: the independent oracle for what a scan must count
/// for a fixture file.
pub fn allocated(path: &Path) -> u64 {
    fs::symlink_metadata(path).expect("lstat fixture").blocks() * 512
}

/// Parse the whole of `stdout` as one JSON document (fails the test if anything else is there).
pub fn parse_json(stdout: &[u8]) -> serde_json::Value {
    serde_json::from_slice(stdout).unwrap_or_else(|e| {
        panic!(
            "stdout must be exactly one JSON document ({e}); got:\n{}",
            String::from_utf8_lossy(stdout)
        )
    })
}

/// The `rules[]` entry with `id` in a parsed report.
pub fn json_rule<'a>(report: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    report["rules"]
        .as_array()
        .and_then(|rules| rules.iter().find(|r| r["id"] == id))
        .unwrap_or_else(|| panic!("no rule `{id}` in the JSON report: {report}"))
}

/// The ids in `rules[]`, in order.
pub fn json_rule_ids(report: &serde_json::Value) -> Vec<String> {
    report["rules"]
        .as_array()
        .map(|rules| {
            rules
                .iter()
                .filter_map(|r| r["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Restores `0o755` on drop so a `chmod 000` fixture directory can always be removed.
pub struct RestorePerms(pub PathBuf);

impl Drop for RestorePerms {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, Permissions::from_mode(0o755));
    }
}

/// Make `dir` unreadable (`chmod 000`) and return the guard that restores it.
pub fn lock_dir(dir: &Path) -> RestorePerms {
    fs::set_permissions(dir, Permissions::from_mode(0o000)).expect("chmod 000");
    RestorePerms(dir.to_path_buf())
}

/// True when the test process bypasses permission checks (root): `chmod 000` scenarios are then
/// meaningless.
pub fn bypasses_permissions(probe: &Path) -> bool {
    fs::metadata(probe).is_ok_and(|m| m.uid() == 0)
}

/// Create `path` with `content` (`std::fs::write` is banned by clippy.toml outside the adapters).
pub fn put(path: &Path, content: &str) {
    File::create(path)
        .and_then(|mut f| f.write_all(content.as_bytes()))
        .unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
}

/// A background child process that is killed (and reaped) if the test unwinds before it finished,
/// so a failing assertion never leaves a `cleaner` running.
pub struct KillOnDrop(Option<std::process::Child>);

impl KillOnDrop {
    /// Spawn `cmd` (stdout/stderr configured by the caller).
    pub fn spawn(cmd: &mut std::process::Command) -> Self {
        Self(Some(cmd.spawn().expect("spawn cleaner")))
    }

    /// Send SIGINT to the child with `/bin/kill -INT <pid>` (no `libc`/`unsafe` needed).
    ///
    /// `std::process::Command::new` is banned by clippy.toml outside the adapters; `/bin/kill` with a
    /// fixed argument list and the pid of our own child is the reviewed exception (INV-10).
    #[allow(
        clippy::disallowed_methods,
        reason = "test-only: signal our own child process with /bin/kill -INT <pid>"
    )]
    pub fn send_sigint(&self) {
        let pid = self.0.as_ref().expect("child alive").id().to_string();
        let status = std::process::Command::new("/bin/kill")
            .args(["-INT", &pid])
            .status()
            .expect("run /bin/kill");
        assert!(status.success(), "kill -INT {pid} failed");
    }

    /// Wait for the child and collect its output.
    pub fn wait_with_output(mut self) -> std::process::Output {
        self.0
            .take()
            .expect("child alive")
            .wait_with_output()
            .expect("wait for cleaner")
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
