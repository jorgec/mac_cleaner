//! Purgeable-space arithmetic (ADR 0002, spec 002 AC-002-1). Pure.

use crate::ports::VolumeCaps;

/// Result of the purgeable computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Purgeable {
    /// Bytes macOS considers purgeable, never more than `total`.
    pub bytes: u64,
    /// True when the raw difference had to be adjusted: `available_important < available`
    /// (negative difference, reported as 0) or the difference exceeded `total` (capped).
    pub clamped: bool,
}

/// `purgeable = max(0, available_important - available)`, never above `caps.total`, computed
/// without overflow or underflow for every `u64` input (INV-12, INV-13).
///
/// Postconditions: `bytes <= caps.total`; `clamped` is `true` exactly when the raw difference had
/// to be adjusted (`available_important < available` gives `0`, a difference above `total` gives
/// `total`); `I == A` is `0` and **not** clamped, as is a difference of exactly `total`.
/// Pure: no effects, no panics.
#[must_use]
pub fn purgeable(caps: &VolumeCaps) -> Purgeable {
    match caps.available_important.checked_sub(caps.available) {
        None => Purgeable {
            bytes: 0,
            clamped: true,
        },
        Some(diff) if diff > caps.total => Purgeable {
            bytes: caps.total,
            clamped: true,
        },
        Some(diff) => Purgeable {
            bytes: diff,
            clamped: false,
        },
    }
}
