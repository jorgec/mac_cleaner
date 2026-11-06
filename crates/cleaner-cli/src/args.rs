//! The `clap` (derive) command-line surface. Real, not a stub: the tests exercise it through the
//! binary. `scan` is read-only (INV-01); nothing here selects anything by default (INV-02).

use clap::{Args, Parser, Subcommand, ValueEnum};
use cleaner_core::rules::Tier;
use cleaner_core::scan::DEFAULT_TOP_N;

/// `cleaner <COMMAND>`.
#[derive(Debug, Parser)]
#[command(name = "cleaner", version = crate::VERSION, about = "Find purgeable and reclaimable disk space (read-only)")]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Sub-commands (phase 1 has only `scan`).
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan the volume holding $HOME and the known rule roots (read-only; nothing is selected).
    Scan(ScanArgs),
}

/// `cleaner scan` options (spec 002 "CLI surface").
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Limit the scan to this rule id (repeatable). Combined with `--tier` it narrows further.
    #[arg(long = "rule", value_name = "ID")]
    pub rules: Vec<String>,
    /// Limit the scan to one risk tier.
    #[arg(long, value_enum, value_name = "TIER")]
    pub tier: Option<TierArg>,
    /// How many of the largest children to list per rule (0 lists none).
    #[arg(long, value_name = "N", default_value_t = DEFAULT_TOP_N)]
    pub top: usize,
    /// Print only machine-readable JSON (schema `scan/1`) on stdout; warnings go to stderr.
    #[arg(long)]
    pub json: bool,
}

/// `--tier` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TierArg {
    /// Regenerable caches and logs.
    Safe,
    /// May be user-visible loss.
    Caution,
    /// Listed only, never deleted.
    #[value(name = "report-only")]
    ReportOnly,
}

impl TierArg {
    /// The core tier this flag value names.
    #[must_use]
    pub fn tier(self) -> Tier {
        match self {
            Self::Safe => Tier::Safe,
            Self::Caution => Tier::Caution,
            Self::ReportOnly => Tier::ReportOnly,
        }
    }
}
