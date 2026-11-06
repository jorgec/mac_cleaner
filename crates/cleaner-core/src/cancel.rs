//! Cooperative cancellation (AC-002-18). The composition root's SIGINT handler calls
//! [`CancelToken::cancel`]; long-running core code polls [`CancelToken::is_cancelled`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Shared, clone-able cancellation flag. All clones observe the same state.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    /// A token that is not cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation (idempotent, async-signal-safe in effect: one atomic store).
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// True once any clone has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}
