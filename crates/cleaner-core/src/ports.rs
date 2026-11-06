//! Effect ports of the hexagonal core (ADR 0001). Core never touches the machine directly; the
//! adapters in `cleaner-macos` and the fakes in `cleaner-testkit` implement these traits.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Kind of a filesystem node as reported by `lstat` (symlinks are **not** followed, INV-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link (dangling or not; it is never resolved).
    Symlink,
    /// Anything else (socket, fifo, device node, ...).
    Other,
}

/// The subset of `lstat` data the safety guard and the scanner need (specs 001 and 002).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    /// What the final path component itself is.
    pub kind: FileKind,
    /// `st_dev` of the final path component (INV-08).
    pub dev: u64,
    /// `st_ino`; together with `dev` the identity used to count a hardlinked inode once (INV-12).
    pub ino: u64,
    /// `st_blocks`: allocated size in **512-byte units** (always 512, whatever the block size of the
    /// volume). Allocated bytes are `blocks * 512` (INV-12); a sparse file has fewer than `len`.
    pub blocks: u64,
    /// `st_size`: the logical length in bytes.
    pub len: u64,
    /// `st_mtime`. `atime` is deliberately not exposed: no rule may depend on it.
    pub mtime: SystemTime,
    /// `st_nlink`: number of names of this inode (a file with `nlink > 1` may be seen twice).
    pub nlink: u32,
}

/// One entry of a directory listing (never `.` or `..`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's own name (raw bytes on macOS: may be non-UTF-8).
    pub name: OsString,
    /// The kind reported by the listing (`d_type`). Only a hint: `lstat` is authoritative.
    pub kind: FileKind,
}

/// Read-only filesystem port. There is deliberately **no mutating method** on this trait: the
/// scan/guard code path cannot mutate anything by construction (INV-01).
pub trait Fs {
    /// `lstat(2)` semantics: intermediate symlinks in `path` are resolved by the OS exactly as
    /// the kernel would, but the **final** component is never followed. Any failure (including
    /// `ENOENT`, `EACCES`, `ELOOP`, `ENAMETOOLONG`) is returned as the raw `io::Error`.
    ///
    /// # Errors
    /// The underlying OS error, unchanged.
    fn lstat(&self, path: &Path) -> io::Result<Metadata>;

    /// List the entries directly inside the directory `path` (`opendir`/`readdir` semantics: the
    /// OS resolves `path` completely, **including a final symlink**, so a caller that must not
    /// follow links has to `lstat` first and never list a `Symlink`). The order is unspecified and
    /// callers must not rely on it. Entries are returned as one batch.
    ///
    /// # Errors
    /// The underlying OS error, unchanged (`ENOENT`, `EACCES`, `EPERM`, `ENOTDIR`, ...).
    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>>;
}

/// Injected wall clock (never `SystemTime::now()` inside core).
pub trait Clock: Send + Sync {
    /// Current instant.
    fn now(&self) -> SystemTime;
}

/// Opaque, sortable run identifier (ULID-style in production, sequential in tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunId(String);

impl RunId {
    /// Wrap an already-generated identifier.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier text as written to the audit log.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Injected run-id generator.
pub trait RunIds {
    /// A fresh identifier, unique within the process and sortable by creation time.
    fn next_run_id(&self) -> RunId;
}

/// The log directory as seen by retention pruning. It exposes **names only** (never paths) so a
/// store can only ever act inside its own directory. `remove` is the sole mutation allowed in
/// phase 1 (spec 001 AC-001-14).
pub trait LogStore {
    /// File names (not paths) of every entry in the log directory, in any order.
    ///
    /// # Errors
    /// The underlying I/O error.
    fn list(&self) -> io::Result<Vec<String>>;

    /// Remove the entry called `name` inside the log directory. An adapter must refuse any
    /// `name` that is not a single plain path component (`..`, `a/b`, `/abs`), returning
    /// `InvalidInput` and removing nothing.
    ///
    /// # Errors
    /// The underlying I/O error, or `InvalidInput` for a non-plain name.
    fn remove(&self, name: &str) -> io::Result<()>;
}

/// Raw capacity numbers of one volume as macOS reports them (ADR 0002). All values are bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeCaps {
    /// Mount point of the volume that holds the queried path.
    pub mount_point: PathBuf,
    /// `volumeTotalCapacity`.
    pub total: u64,
    /// `volumeAvailableCapacity` (what `df` shows; excludes purgeable space).
    pub available: u64,
    /// `volumeAvailableCapacityForImportantUsage`.
    pub available_important: u64,
    /// `volumeAvailableCapacityForOpportunisticUsage`.
    pub available_opportunistic: u64,
}

/// Why a volume could not be queried. `kind()` is the stable code used in `volume_error` (AC-002-2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VolumeError {
    /// The queried path does not exist or is not on a mounted volume.
    #[error("volume not found for {path:?}")]
    NotFound {
        /// The queried path.
        path: PathBuf,
    },
    /// The OS refused the query.
    #[error("permission denied querying the volume")]
    PermissionDenied,
    /// Any other failure of the capacity query.
    #[error("volume query failed: {reason}")]
    QueryFailed {
        /// Human-readable cause.
        reason: String,
    },
}

impl VolumeError {
    /// Stable machine code: `not_found`, `permission_denied` or `query_failed`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "not_found",
            Self::PermissionDenied => "permission_denied",
            Self::QueryFailed { .. } => "query_failed",
        }
    }
}

/// Port: capacity of the volume holding a path (ADR 0002). Read-only.
pub trait VolumeCapacity {
    /// Query the volume that holds `path`.
    ///
    /// # Errors
    /// [`VolumeError`]; callers must report an unknown value, never zero (INV-13).
    fn query(&self, path: &Path) -> Result<VolumeCaps, VolumeError>;
}

/// What a finished command produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Process exit status (0 = success).
    pub exit_code: i32,
    /// Captured standard output (raw bytes).
    pub stdout: Vec<u8>,
    /// Captured standard error (raw bytes).
    pub stderr: Vec<u8>,
}

/// Why a command produced no [`CommandOutput`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    /// The program does not exist / is not executable.
    #[error("command not found")]
    NotFound,
    /// The program did not finish within the timeout (the adapter has killed it).
    #[error("command timed out")]
    TimedOut,
    /// Spawning or reading failed for another reason.
    #[error("command failed to run: {reason}")]
    Failed {
        /// Human-readable cause.
        reason: String,
    },
}

/// Port: run one external program (INV-10: never through a shell, never with elevated privilege).
pub trait CommandRunner {
    /// Run `program` with an argument **array** (no shell parsing) and wait at most `timeout`.
    ///
    /// # Errors
    /// [`CommandError`] when no output could be obtained. A non-zero exit status is **not** an
    /// error here: it is reported in [`CommandOutput::exit_code`].
    fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandOutput, CommandError>;
}
