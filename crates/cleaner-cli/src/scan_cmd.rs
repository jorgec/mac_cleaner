//! The `cleaner scan` command: composition of real adapters (or the hermetic seams), the SIGINT
//! handler, the scan itself and the rendering (spec 002, AC-002-14..19). Everything that reads the
//! process environment is done by `main.rs` and handed in as [`ScanEnv`]; nothing here is mutating:
//! the only thing a scan writes is its audit log (INV-01).

use std::io::{self, Write as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use cleaner_core::audit::AuditLog;
use cleaner_core::cancel::CancelToken;
use cleaner_core::ports::{Clock, CommandRunner, RunIds, VolumeCapacity};
use cleaner_core::report::ScanReport;
use cleaner_core::rules::builtin;
use cleaner_core::safety::HomeDir;
use cleaner_core::scan::{ScanOptions, ScanPorts, run_scan};
use cleaner_macos::{FileAuditSink, RealFs, RealRunner, RealVolume, SystemClock};
use signal_hook::consts::SIGINT;
use signal_hook::iterator::Signals;

use crate::VERSION;
use crate::args::ScanArgs;
use crate::fda::terminal_app;
use crate::ids::UlidRunIds;
use crate::render::{HumanContext, human, permission_hint};
use crate::seams::{TmutilOverride, VolumeSeam};
use crate::select::select_rules;

/// Exit code for a usage error (bad selectors, bad seam value).
const EXIT_USAGE: u8 = 2;
/// Exit code for a runtime error (no usable `$HOME`, no SIGINT handler, report not printable).
const EXIT_RUNTIME: u8 = 1;
/// Where the audit logs live, relative to `$HOME` (safety-invariants.md "Logging contract").
const LOG_DIR: &str = "Library/Logs/mac-cleaner";

/// What the composition root read from the process environment.
#[derive(Debug, Clone)]
pub struct ScanEnv {
    /// `$HOME` exactly as given (never canonicalized); must be absolute.
    pub home: PathBuf,
    /// `$TERM_PROGRAM`, for the Full Disk Access hint.
    pub term_program: Option<String>,
    /// The whole command line (program name first), for the `run_start` record.
    pub argv: Vec<String>,
    /// `CLEANER_TMUTIL`: honored only after the test-mode guard let it through.
    pub tmutil_override: Option<PathBuf>,
    /// `CLEANER_TEST_VOLUME`: honored only after the test-mode guard let it through.
    pub volume_override: Option<String>,
}

/// Run `cleaner scan` and return the process exit code: the report's exit code (0 ok, 4 partial or
/// unknown, 130 interrupted), 2 for invalid selectors or an invalid seam value, 1 when the scan
/// could not even start.
///
/// Order (each step before the next): select rules (nothing is created on a usage error); install
/// the SIGINT handler (so it is already active while `tmutil` runs); open the audit log under
/// `$HOME/Library/Logs/mac-cleaner` (a failure is a warning on stderr, the scan continues and the
/// exit code becomes 4); scan; print. `--json` prints only the JSON document on stdout; the
/// permission hint then goes to stderr. A scan never prunes old audit logs.
#[must_use]
pub fn run(args: &ScanArgs, env: ScanEnv) -> u8 {
    let rules = match select_rules(
        builtin(),
        &args.rules,
        args.tier.map(crate::args::TierArg::tier),
    ) {
        Ok(rules) => rules,
        Err(e) => return fail(EXIT_USAGE, &e.to_string()),
    };
    let volume_seam = match env.volume_override.as_deref().map(VolumeSeam::parse) {
        Some(Err(e)) => return fail(EXIT_USAGE, &e.to_string()),
        Some(Ok(seam)) => Some(seam),
        None => None,
    };
    if !env.home.is_absolute() {
        return fail(
            EXIT_RUNTIME,
            &format!("HOME ({}) is not an absolute path", env.home.display()),
        );
    }

    let cancel = CancelToken::new();
    if let Err(message) = install_sigint(&cancel) {
        return fail(EXIT_RUNTIME, &message);
    }

    let clock = Arc::new(SystemClock);
    let run_id = UlidRunIds::new().next_run_id();
    let log_dir = env.home.join(LOG_DIR);
    let (mut audit, audit_path) = match FileAuditSink::open(&log_dir, clock.as_ref()) {
        Ok(sink) => {
            let path = sink.path().to_path_buf();
            (
                Some(AuditLog::new(
                    Box::new(sink),
                    Arc::clone(&clock) as Arc<dyn Clock>,
                    run_id.clone(),
                )),
                Some(path),
            )
        }
        Err(e) => {
            warn(&format!("audit log unavailable ({e}); scanning without it"));
            (None, None)
        }
    };

    let real_volume = RealVolume;
    let volume: &dyn VolumeCapacity = match &volume_seam {
        Some(seam) => seam,
        None => &real_volume,
    };
    let runner: Box<dyn CommandRunner> = match env.tmutil_override {
        Some(tmutil) => Box::new(TmutilOverride {
            inner: RealRunner,
            tmutil,
        }),
        None => Box::new(RealRunner),
    };
    let ports = ScanPorts {
        fs: &RealFs,
        clock: clock.as_ref(),
        volume,
        runner: runner.as_ref(),
    };
    let opts = ScanOptions {
        home: HomeDir::new(env.home),
        rules,
        top_n: args.top,
        argv: env.argv,
        version: VERSION.to_owned(),
        run_id,
    };
    let opened = audit.is_some();
    let report = run_scan(&ports, &opts, &cancel, audit.as_mut());
    if opened && report.audit_unavailable {
        warn("audit log became unavailable during the run; the log is incomplete");
    }

    let app = terminal_app(env.term_program.as_deref());
    if args.json {
        if let Some(hint) = permission_hint(&report, &app) {
            warn_plain(&hint);
        }
        match to_json(&report) {
            Ok(json) => print_stdout(&json),
            Err(e) => return fail(EXIT_RUNTIME, &format!("cannot encode the report: {e}")),
        }
    } else {
        let ctx = HumanContext {
            audit_log: audit_path,
            terminal_app: app,
        };
        print_stdout(&human(&report, &ctx));
    }
    u8::try_from(report.exit_code()).unwrap_or(EXIT_RUNTIME)
}

/// Make SIGINT set `cancel` (safe iterator API of `signal-hook`: a thread, no signal-context code).
fn install_sigint(cancel: &CancelToken) -> Result<(), String> {
    let mut signals =
        Signals::new([SIGINT]).map_err(|e| format!("cannot install the SIGINT handler: {e}"))?;
    let cancel = cancel.clone();
    thread::spawn(move || {
        for _ in signals.forever() {
            cancel.cancel();
        }
    });
    Ok(())
}

/// The report as one pretty JSON document ending in a newline.
fn to_json(report: &ScanReport) -> Result<String, serde_json::Error> {
    let mut json = serde_json::to_string_pretty(report)?;
    json.push('\n');
    Ok(json)
}

/// Write `text` to stdout; a closed pipe is not an error worth a panic.
fn print_stdout(text: &str) {
    let _ = io::stdout().lock().write_all(text.as_bytes());
}

/// `cleaner: <message>` on stderr; returns `code` for `return fail(..)`.
fn fail(code: u8, message: &str) -> u8 {
    eprintln!("cleaner: {message}");
    code
}

/// `cleaner: warning: <message>` on stderr.
fn warn(message: &str) {
    eprintln!("cleaner: warning: {message}");
}

/// A pre-formatted line on stderr.
fn warn_plain(line: &str) {
    eprintln!("{line}");
}
