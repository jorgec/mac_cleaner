//! Test fixtures and fakes shared by the other crates. Dev-dependency only; never shipped.
//!
//! Everything here is **test infrastructure that stands in for the real machine** (INV-15):
//! * [`FakeFs`] - in-memory read-only `Fs` with OS-faithful `lstat` semantics.
//! * [`FixedClock`], [`SequentialRunIds`] - deterministic `Clock` / `RunIds`.
//! * [`MemorySink`], [`MemoryLogStore`] - in-memory `AuditSink` / `LogStore`.
//! * [`FakeVolume`], [`FakeRunner`] - scripted `VolumeCapacity` / `CommandRunner` (spec 002).
//!
//! Only behavior that is non-trivial and that other tests rely on has tests of its own
//! (`tests/fake_fs.rs`, `tests/fixed_clock.rs`).

mod clock;
mod fake_fs;
mod fake_ports;
mod memory;

pub use clock::{FixedClock, SequentialRunIds};
pub use fake_fs::{FakeFs, FakeFsBuilder, deep_path};
pub use fake_ports::{FakeRunner, FakeVolume, RecordedCommand};
pub use memory::{MemoryLogStore, MemorySink};
