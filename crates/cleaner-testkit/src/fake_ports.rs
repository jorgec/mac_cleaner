//! Scripted fakes for the `VolumeCapacity` and `CommandRunner` ports.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use cleaner_core::ports::{
    CommandError, CommandOutput, CommandRunner, VolumeCapacity, VolumeCaps, VolumeError,
};

/// `VolumeCapacity` that answers every query with one fixed result and records the queried paths.
#[derive(Debug)]
pub struct FakeVolume {
    result: Result<VolumeCaps, VolumeError>,
    queries: Mutex<Vec<PathBuf>>,
}

impl FakeVolume {
    /// Always succeeds with `caps`.
    #[must_use]
    pub fn with_caps(caps: VolumeCaps) -> Self {
        Self {
            result: Ok(caps),
            queries: Mutex::new(Vec::new()),
        }
    }

    /// Convenience: a volume mounted at `mount_point` with the given byte counts
    /// (`available_opportunistic` equals `available`).
    #[must_use]
    pub fn with_numbers(
        mount_point: impl Into<PathBuf>,
        total: u64,
        available: u64,
        available_important: u64,
    ) -> Self {
        Self::with_caps(VolumeCaps {
            mount_point: mount_point.into(),
            total,
            available,
            available_important,
            available_opportunistic: available,
        })
    }

    /// Always fails with `error`.
    #[must_use]
    pub fn failing(error: VolumeError) -> Self {
        Self {
            result: Err(error),
            queries: Mutex::new(Vec::new()),
        }
    }

    /// Every path passed to `query`, in call order.
    ///
    /// # Panics
    /// If the internal lock is poisoned.
    #[must_use]
    pub fn queries(&self) -> Vec<PathBuf> {
        self.queries.lock().expect("queries lock").clone()
    }
}

impl VolumeCapacity for FakeVolume {
    fn query(&self, path: &Path) -> Result<VolumeCaps, VolumeError> {
        self.queries
            .lock()
            .expect("queries lock")
            .push(path.to_path_buf());
        self.result.clone()
    }
}

/// One recorded invocation of a [`FakeRunner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCommand {
    /// Program as passed.
    pub program: String,
    /// Argument array as passed.
    pub args: Vec<String>,
    /// Timeout as passed.
    pub timeout: Duration,
}

/// `CommandRunner` that answers every call with one scripted outcome and records the calls. It
/// never spawns anything.
#[derive(Debug)]
pub struct FakeRunner {
    outcome: Result<CommandOutput, CommandError>,
    calls: Mutex<Vec<RecordedCommand>>,
}

impl FakeRunner {
    fn new(outcome: Result<CommandOutput, CommandError>) -> Self {
        Self {
            outcome,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Exit status 0 with `stdout`.
    #[must_use]
    pub fn ok(stdout: &str) -> Self {
        Self::new(Ok(CommandOutput {
            exit_code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }))
    }

    /// Finished with a non-zero (or any) `exit_code` and `stderr`.
    #[must_use]
    pub fn exit(exit_code: i32, stderr: &str) -> Self {
        Self::new(Ok(CommandOutput {
            exit_code,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }))
    }

    /// The runner itself fails (`NotFound`, `TimedOut`, ...).
    #[must_use]
    pub fn failing(error: CommandError) -> Self {
        Self::new(Err(error))
    }

    /// Every invocation so far, in order.
    ///
    /// # Panics
    /// If the internal lock is poisoned.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCommand> {
        self.calls.lock().expect("calls lock").clone()
    }
}

impl CommandRunner for FakeRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandOutput, CommandError> {
        self.calls
            .lock()
            .expect("calls lock")
            .push(RecordedCommand {
                program: program.to_owned(),
                args: args.iter().map(|a| (*a).to_owned()).collect(),
                timeout,
            });
        self.outcome.clone()
    }
}
