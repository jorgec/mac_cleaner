//! Production run identifiers (ULID).

use std::sync::{Mutex, PoisonError};

use cleaner_core::ports::{RunId, RunIds};
use ulid::Generator;

/// [`RunIds`] backed by a monotonic ULID generator.
///
/// Contract: every id is 26 characters of Crockford base32 (`0-9A-HJKMNP-TV-Z`, upper case);
/// successive ids from one generator compare strictly increasing as strings (monotonic even
/// within the same millisecond, and when the clock steps back).
#[derive(Debug, Default)]
pub struct UlidRunIds {
    generator: Mutex<Generator>,
}

impl UlidRunIds {
    /// A fresh generator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl RunIds for UlidRunIds {
    fn next_run_id(&self) -> RunId {
        // A poisoned lock only means another thread panicked mid-`generate`; the generator state
        // is still a valid "previous id", so keep using it.
        let mut generator = self
            .generator
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Overflow (2^80 ids within one millisecond) is committed by moving into the next
        // millisecond, which keeps the sequence strictly increasing.
        let ulid = generator
            .generate()
            .unwrap_or_else(ulid::Overflow::commit_overflow_increment);
        RunId::new(ulid.to_string())
    }
}
