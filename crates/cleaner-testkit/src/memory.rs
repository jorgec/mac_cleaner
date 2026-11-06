//! In-memory `AuditSink` and `LogStore`.

use std::io;
use std::sync::{Arc, Mutex};

use cleaner_core::audit::{AuditError, AuditSink};
use cleaner_core::ports::LogStore;

/// `AuditSink` that keeps lines in memory. Clones share the same buffer, so a test keeps one
/// handle while the `AuditLog` owns another.
#[derive(Debug, Clone, Default)]
pub struct MemorySink {
    lines: Arc<Mutex<Vec<String>>>,
    fail_next: Arc<Mutex<u32>>,
}

impl MemorySink {
    /// Empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every line written so far, in order (no trailing newlines).
    ///
    /// # Panics
    /// If the internal lock is poisoned.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().expect("lines lock").clone()
    }

    /// Make the next `n` `write_line` calls fail with `AuditError::Io` (nothing is stored).
    ///
    /// # Panics
    /// If the internal lock is poisoned.
    pub fn fail_next_writes(&self, n: u32) {
        *self.fail_next.lock().expect("fail lock") = n;
    }
}

impl AuditSink for MemorySink {
    fn write_line(&mut self, line: &str) -> Result<(), AuditError> {
        {
            let mut fail = self.fail_next.lock().expect("fail lock");
            if *fail > 0 {
                *fail -= 1;
                return Err(AuditError::Io {
                    reason: "injected failure".to_owned(),
                });
            }
        }
        self.lines.lock().expect("lines lock").push(line.to_owned());
        Ok(())
    }
}

/// `LogStore` over a set of names; records what was removed. Clones share state.
#[derive(Debug, Clone, Default)]
pub struct MemoryLogStore {
    names: Arc<Mutex<Vec<String>>>,
    removed: Arc<Mutex<Vec<String>>>,
}

impl MemoryLogStore {
    /// Store pre-populated with `names` (any order).
    #[must_use]
    pub fn with_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            names: Arc::new(Mutex::new(names.into_iter().map(Into::into).collect())),
            removed: Arc::default(),
        }
    }

    /// Names still present, sorted.
    ///
    /// # Panics
    /// If the internal lock is poisoned.
    #[must_use]
    pub fn remaining(&self) -> Vec<String> {
        let mut v = self.names.lock().expect("names lock").clone();
        v.sort();
        v
    }

    /// Names passed to `remove` that existed, sorted (the only mutation phase 1 allows).
    ///
    /// # Panics
    /// If the internal lock is poisoned.
    #[must_use]
    pub fn removed(&self) -> Vec<String> {
        let mut v = self.removed.lock().expect("removed lock").clone();
        v.sort();
        v
    }
}

impl LogStore for MemoryLogStore {
    fn list(&self) -> io::Result<Vec<String>> {
        Ok(self.names.lock().expect("names lock").clone())
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        let mut names = self.names.lock().expect("names lock");
        let Some(pos) = names.iter().position(|n| n == name) else {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        };
        names.remove(pos);
        self.removed
            .lock()
            .expect("removed lock")
            .push(name.to_owned());
        Ok(())
    }
}
