//! Real macOS adapters implementing the core ports. The only crate allowed to contain unsafe FFI.
//!
//! Spec 001: [`RealFs`] (`Fs`), [`FileAuditSink`] (`AuditSink`), [`FileLogStore`] (`LogStore`).
//! Spec 002b: [`RealFs::read_dir`], [`RealRunner`] (`CommandRunner`), [`RealVolume`]
//! (`VolumeCapacity`, ADR 0002), [`SystemClock`] (`Clock`).
//! The workspace's only `unsafe` block lives in the `volume` module (reading Foundation's
//! `NSURLVolume*Key` statics, ADR 0002); mutating `std::fs` calls and process spawning are allowed
//! here ONLY with a local `#[allow(clippy::disallowed_methods)]` carrying a reason (see
//! `clippy.toml`).

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use cleaner_core::audit::{AuditError, AuditSink, audit_file_name};
use cleaner_core::ports::{
    Clock, CommandError, CommandOutput, CommandRunner, DirEntry, FileKind, Fs, LogStore, Metadata,
};

#[allow(unsafe_code)] // the single FFI block of the workspace (ADR 0002); see the module docs.
mod volume;

pub use volume::RealVolume;

/// `lstat(2)`-backed [`Fs`]: `std::fs::symlink_metadata`, never `metadata` (INV-07).
#[derive(Debug, Clone, Copy, Default)]
pub struct RealFs;

impl Fs for RealFs {
    /// Kind and `st_dev` of the final component without following it (a live, dangling or looping
    /// symlink is `Symlink`). Errors are the raw OS errors; nothing is created or modified.
    fn lstat(&self, path: &Path) -> io::Result<Metadata> {
        let md = std::fs::symlink_metadata(path)?;
        let file_type = md.file_type();
        let kind = if file_type.is_symlink() {
            FileKind::Symlink
        } else if file_type.is_dir() {
            FileKind::Dir
        } else if file_type.is_file() {
            FileKind::File
        } else {
            FileKind::Other
        };
        Ok(Metadata {
            kind,
            dev: md.dev(),
            ino: md.ino(),
            blocks: md.blocks(),
            len: md.size(),
            mtime: md.modified()?,
            nlink: u32::try_from(md.nlink()).unwrap_or(u32::MAX),
        })
    }

    /// `opendir`/`readdir` semantics (a final symlink is followed by the OS, so callers `lstat`
    /// first). One flat batch of the entries' own names, byte for byte, without `.`/`..`; each
    /// entry's kind is the kind of the entry itself (a symlink is `Symlink`, never its target's
    /// kind). Any failure, including one while reading the listing, is the raw OS error: an
    /// unreadable directory is never an empty listing.
    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        std::fs::read_dir(path)?
            .map(|entry| {
                let entry = entry?;
                let file_type = entry.file_type()?;
                let kind = if file_type.is_symlink() {
                    FileKind::Symlink
                } else if file_type.is_dir() {
                    FileKind::Dir
                } else if file_type.is_file() {
                    FileKind::File
                } else {
                    FileKind::Other
                };
                Ok(DirEntry {
                    name: entry.file_name(),
                    kind,
                })
            })
            .collect()
    }
}

/// Append-only JSONL file `<dir>/audit-YYYY-MM-DD.jsonl` (day chosen once, at `open`, from the
/// clock). Directory created `0700` (missing parents too), file `0600`; every line is handed to
/// the OS before `write_line` returns; existing content is never truncated.
#[derive(Debug)]
pub struct FileAuditSink {
    file: File,
    path: PathBuf,
}

impl FileAuditSink {
    /// Create/open today's audit file under `dir`: the directory (and missing parents) with mode
    /// `0700` and the file with mode `0600`, both eagerly. An existing file is opened for append,
    /// never truncated; modes of already existing entries are left as they are.
    ///
    /// # Errors
    /// [`AuditError::Unavailable`] when the directory cannot be created or the file cannot be
    /// opened for append (INV-13: the caller decides the policy).
    pub fn open(dir: &Path, clock: &dyn Clock) -> Result<Self, AuditError> {
        let unavailable = |what: &str, path: &Path, e: &io::Error| AuditError::Unavailable {
            reason: format!("{what} {}: {e}", path.display()),
        };
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| unavailable("cannot create log directory", dir, &e))?;
        let path = dir.join(audit_file_name(clock.now()));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| unavailable("cannot open audit file", &path, &e))?;
        Ok(Self { file, path })
    }

    /// The audit file this sink opened: `<dir given to open>/audit-YYYY-MM-DD.jsonl`, computed once
    /// in [`FileAuditSink::open`] from the clock at that instant. It never changes afterwards, so a
    /// caller that prints it names the file actually written even if the clock crosses UTC midnight.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for FileAuditSink {
    /// Appends `line` and a `\n` with a single `write(2)` on an `O_APPEND` descriptor (so two
    /// writers never overwrite each other). `line` must not itself contain a newline: the caller
    /// (`AuditLog`) guarantees it by JSON-encoding records.
    fn write_line(&mut self, line: &str) -> Result<(), AuditError> {
        let mut buf = String::with_capacity(line.len() + 1);
        buf.push_str(line);
        buf.push('\n');
        // `File` is unbuffered: once `write_all` returns the bytes are with the OS.
        self.file
            .write_all(buf.as_bytes())
            .map_err(|e| AuditError::Io {
                reason: format!("writing audit record failed: {e}"),
            })
    }
}

/// [`LogStore`] over one real directory. `list` returns names of the entries directly inside it;
/// `remove` unlinks one plain-named entry inside it and refuses (`InvalidInput`, nothing removed)
/// any name that is empty, `.`, `..`, absolute, or contains a path separator.
#[derive(Debug, Clone)]
pub struct FileLogStore {
    dir: PathBuf,
}

impl FileLogStore {
    /// Store rooted at `dir` (must exist for `list`/`remove` to succeed).
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

/// True when `name` is exactly one ordinary path component (no separator, not `.`/`..`/empty).
fn is_plain_name(name: &str) -> bool {
    !name.contains('/')
        && matches!(
            Path::new(name).components().collect::<Vec<_>>().as_slice(),
            [Component::Normal(_)]
        )
}

impl LogStore for FileLogStore {
    /// Names of the entries directly inside the directory. Entries whose names are not valid
    /// UTF-8 are omitted (they cannot be audit files, and the port speaks `String`).
    fn list(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            if let Ok(name) = entry?.file_name().into_string() {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// Unlinks the single entry `name` inside the directory (a file or symlink; a directory is
    /// refused by the OS and left intact). Refuses non-plain names before touching anything.
    fn remove(&self, name: &str) -> io::Result<()> {
        if !is_plain_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to remove {name:?}: not a plain file name"),
            ));
        }
        // INV-06/INV-07 review: the only deletion in phase 1. `name` is a single plain component,
        // so the joined path cannot leave `self.dir`; `remove_file` never recurses and never
        // follows a final symlink.
        #[allow(clippy::disallowed_methods)]
        std::fs::remove_file(self.dir.join(name))
    }
}

/// Wall clock: `SystemTime::now()`. The composition root injects it; core never calls it.
///
/// Contract: `now()` is the current system time (within the resolution of the OS clock).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// How often [`RealRunner`] checks whether its child has finished or the timeout has elapsed.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// [`CommandRunner`] that spawns a real child process.
///
/// Contract (INV-10, INV-16): `program` is executed directly with `args` as an **argument array**
/// (never through a shell: no expansion, no word splitting, no `;`/`$()`/glob interpretation);
/// stdin is `/dev/null` so a program that reads it sees EOF instead of hanging; stdout and stderr
/// are captured completely and separately, each drained by its own thread (output larger than a
/// pipe buffer cannot deadlock); a non-zero exit status is `Ok(CommandOutput{exit_code, ..})`, not
/// an error, and a child killed by a signal reports `exit_code` `-1` (std has no code for it; the
/// port leaves this undefined); a missing program is `CommandError::NotFound`; any other spawn
/// failure (e.g. not executable) is `CommandError::Failed`; when `timeout` elapses the child is
/// **killed and reaped** (no leftover or zombie process) and the result is `CommandError::TimedOut`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealRunner;

/// Drain `stream` to its end on a background thread.
fn drain<R: io::Read + Send + 'static>(mut stream: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        // A read error ends the capture; what was read so far is kept.
        let _ = stream.read_to_end(&mut buf);
        buf
    })
}

/// Wait for `child` and collect its output, giving up at `deadline`. On any `Err` the caller kills
/// and reaps the child.
fn capture(
    child: &mut Child,
    program: &str,
    deadline: Instant,
) -> Result<CommandOutput, CommandError> {
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(CommandError::Failed {
            reason: "child pipes are not available".to_owned(),
        });
    };
    let (stdout, stderr) = (drain(out), drain(err));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => return Err(CommandError::TimedOut),
            Err(e) => {
                return Err(CommandError::Failed {
                    reason: format!("waiting for {program}: {e}"),
                });
            }
        }
    };
    // The child is gone, so both pipes reach EOF (unless a grandchild inherited them: the drain
    // threads are then left behind rather than blocking past the timeout).
    while !(stdout.is_finished() && stderr.is_finished()) {
        if Instant::now() >= deadline {
            return Err(CommandError::TimedOut);
        }
        thread::sleep(POLL_INTERVAL);
    }
    let collect = |handle: thread::JoinHandle<Vec<u8>>| handle.join().unwrap_or_default();
    Ok(CommandOutput {
        exit_code: status.code().unwrap_or(-1),
        stdout: collect(stdout),
        stderr: collect(stderr),
    })
}

impl CommandRunner for RealRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandOutput, CommandError> {
        // INV-10 review: the one place a process is spawned. `program` is executed directly with
        // an argument array (no shell), stdin is null; the callers pass fixed read-only programs.
        #[allow(clippy::disallowed_methods)]
        let spawned = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = spawned.map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => CommandError::NotFound,
            _ => CommandError::Failed {
                reason: format!("cannot start {program}: {e}"),
            },
        })?;
        let result = capture(&mut child, program, Instant::now() + timeout);
        if result.is_err() {
            // Killed *and* reaped: no leftover or zombie child (kill on an exited child is a no-op).
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
}
