//! `RealRunner`, the real `CommandRunner` adapter (spec 002 AC-002-21; INV-10, INV-16), exercised
//! with harmless programs only: `/bin/echo`, `/usr/bin/false`, `/bin/sleep`, and tiny `/bin/sh`
//! scripts written into a temp dir. The tests never run `tmutil`, `sudo`, or anything that touches
//! the machine outside their temp dir (INV-15).
//!
//! # Worksheet - `RealRunner::run`
//! ```text
//! Function:        cleaner_macos::RealRunner::run(program, args, timeout) -> Result<CommandOutput, CommandError>
//! Contract:        program is executed DIRECTLY with `args` as an array (no shell: no expansion, no
//!                  word splitting, no `;`/`$()`/glob); stdout and stderr are captured completely and
//!                  separately even when each exceeds a pipe buffer (no deadlock); a non-zero exit is
//!                  `Ok` with its code; a missing program is `NotFound`; a non-executable file is
//!                  `Failed`; on timeout the child is KILLED AND REAPED and the result is `TimedOut`.
//!                  (AC-002-21, INV-10, INV-16)
//! Equivalence classes: success | non-zero exit | missing program | not executable | timeout |
//!                  hostile arguments | output larger than the pipe buffers on both streams |
//!                  child exited but a grandchild still holds both / only stderr / only stdout (drain must be bounded)
//! Boundaries:      exit 0 vs non-zero (Ok both); timeout elapsed vs not
//! Must-never:      interpret an argument as shell syntax; leave a timed-out child running or as a
//!                  zombie; deadlock on large output; report a non-zero exit as an error
//! Selected tests:  safety_ac_002_21_args_are_an_array..., ac_002_21_exit_and_streams...,
//!                  ac_002_21_missing_and_non_executable..., safety_ac_002_21_timeout_kills...,
//!                  ac_002_21_large_output..., safety_ac_002_21_timeout_still_bounds_the_call_when_a_grandchild_holds_the_pipes
//! Deliberately not tested: that stdin is closed (nextest already runs tests with a null stdin, so
//!                  the property is not observable here; the developer must still use
//!                  `Stdio::null()`); a child killed by a signal (the port does not define its code);
//!                  environment inheritance; process-group semantics.
//! ```

use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cleaner_core::ports::{CommandError, CommandRunner};
use cleaner_macos::RealRunner;

/// Generous bound for commands that must finish promptly.
const PROMPT: Duration = Duration::from_secs(20);

/// Create `path` with `content` (`std::fs::write` is banned by clippy.toml outside the adapters).
fn put(path: &Path, content: &str) {
    File::create(path)
        .and_then(|mut f| f.write_all(content.as_bytes()))
        .unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
}

/// Write `body` as an executable `/bin/sh` script `name` in `dir` and return its path.
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    put(&path, &format!("#!/bin/sh\n{body}\n"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod +x");
    path
}

/// Whether process `pid` still exists (including a zombie), via `kill -0`.
///
/// `std::process::Command::new` is banned by clippy.toml outside the adapters; a test probing
/// process liveness through `/bin/kill -0` is the one reviewed exception (INV-10: it sends no
/// signal, `-0` only checks existence).
#[allow(
    clippy::disallowed_methods,
    reason = "test-only liveness probe: `/bin/kill -0 <pid>` sends no signal"
)]
fn process_exists(pid: &str) -> bool {
    std::process::Command::new("/bin/kill")
        .args(["-0", pid])
        .output()
        .expect("run /bin/kill")
        .status
        .success()
}

mod safety {
    use super::*;

    /// # Design promise
    /// INV-10 / AC-002-21: arguments are an **array**, never parsed by a shell: spaces stay inside one
    /// argument, and `;`, `$VAR`, backticks, `$()` and globs are inert text. A command-injection
    /// payload in an argument must not execute.
    ///
    /// # Scenario (Given)
    /// `/bin/echo` with arguments `a b`, `;touch <marker>`, `$HOME`, `` `id` ``, `$(id)`, `*` and a
    /// marker path inside a fresh temp dir (which also contains a file the glob `*` could match).
    ///
    /// # Action (When)
    /// `RealRunner.run("/bin/echo", args, 20 s)`.
    ///
    /// # Expected (Then)
    /// `Ok`, exit 0, stdout is exactly the arguments joined by single spaces plus a newline (nothing
    /// expanded), stderr empty, and the marker file does not exist.
    ///
    /// # Must never
    /// Run any argument as a command (the marker would appear), expand `$HOME`/`*`, split `a b`.
    ///
    /// # Would catch
    /// `Command::new("sh").arg("-c").arg(joined)` (the classic injection), re-joining arguments into
    /// one string, glob expansion.
    ///
    /// # Why this test (not redundant)
    /// The only enforcement test of "args array only, never a shell"; the core test only checks what
    /// arguments are *passed*.
    #[test]
    fn safety_ac_002_21_args_are_an_array_and_never_interpreted_by_a_shell() {
        // Arrange
        let tmp = tempfile::tempdir().expect("temp dir");
        put(&tmp.path().join("globbed.txt"), "x");
        let marker = tmp.path().join("pwned");
        let injected = format!(";touch {}", marker.display());
        let args = ["a b", injected.as_str(), "$HOME", "`id`", "$(id)", "*"];

        // Act
        let out = RealRunner
            .run("/bin/echo", &args, PROMPT)
            .expect("echo must run");

        // Assert
        assert_eq!(out.exit_code, 0, "echo exits 0");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("{}\n", args.join(" ")),
            "INV-10: every argument must reach the program verbatim (no expansion, no splitting)"
        );
        assert!(out.stderr.is_empty(), "echo writes nothing to stderr");
        assert!(
            !marker.exists(),
            "INV-10: an argument was executed as shell code"
        );
    }

    /// # Design promise
    /// AC-002-21 / INV-13: when the timeout elapses the child is **killed and reaped** and the result
    /// is `TimedOut` - promptly, not after the child would have finished - so a hung `tmutil` cannot
    /// hang the scan nor leave a process behind.
    ///
    /// # Scenario (Given)
    /// A script that records its pid and then `exec`s `/bin/sleep 60` (so the recorded pid is the
    /// sleeping process), run with a 1.5 s timeout.
    ///
    /// # Action (When)
    /// `RealRunner.run(script, [], 1.5 s)`.
    ///
    /// # Expected (Then)
    /// `Err(TimedOut)`; the call took at least the timeout and far less than the child's 60 s; the
    /// recorded pid no longer exists (not running and not a zombie, i.e. killed *and* waited for).
    ///
    /// # Must never
    /// Return before the timeout; wait for the child to finish; leave the child alive or un-reaped;
    /// report a timeout as a non-zero exit.
    ///
    /// # Would catch
    /// A runner that only stops waiting (`recv_timeout`) without `kill`, one that kills without
    /// `wait` (zombie), one that blocks on `wait_with_output` (hangs 60 s).
    ///
    /// # Why this test (not redundant)
    /// The only real-process test of the timeout path; the core maps `TimedOut` to `snapshots_error`.
    #[test]
    fn safety_ac_002_21_timeout_kills_and_reaps_the_child() {
        // Arrange
        let tmp = tempfile::tempdir().expect("temp dir");
        let pid_file = tmp.path().join("pid");
        let prog = script(
            tmp.path(),
            "hang",
            &format!("echo $$ > '{}'\nexec /bin/sleep 60", pid_file.display()),
        );
        let timeout = Duration::from_millis(1500);

        // Act
        let started = Instant::now();
        let result = RealRunner.run(prog.to_str().expect("utf-8 path"), &[], timeout);
        let elapsed = started.elapsed();

        // Assert
        assert_eq!(
            result,
            Err(CommandError::TimedOut),
            "a hung child is TimedOut"
        );
        assert!(
            elapsed >= timeout && elapsed < Duration::from_secs(30),
            "the runner must wait the timeout and then give up promptly, took {elapsed:?}"
        );
        let pid = fs::read_to_string(&pid_file).expect("the script recorded its pid");
        assert!(
            !process_exists(pid.trim()),
            "the timed-out child (pid {}) must be killed and reaped, not left running or zombie",
            pid.trim()
        );
    }

    /// Kills the background process whose pid is in `pid_file` when dropped, so the 30 s `sleep`
    /// this test deliberately orphans never outlives the test, even when an assertion fails.
    struct KillOnDrop(PathBuf);

    impl Drop for KillOnDrop {
        #[allow(
            clippy::disallowed_methods,
            reason = "test-only cleanup: `/bin/kill <pid>` of the sleep this test started"
        )]
        fn drop(&mut self) {
            if let Ok(pid) = fs::read_to_string(&self.0) {
                let _ = std::process::Command::new("/bin/kill")
                    .arg(pid.trim())
                    .output();
            }
        }
    }

    /// # Design promise
    /// AC-002-21 / INV-13: the timeout bounds the WHOLE call, including draining the output pipes. A
    /// grandchild that inherited stdout and/or stderr and outlives its parent keeps those pipes open;
    /// the runner must still return `TimedOut` at the deadline instead of waiting for EOF (which only
    /// happens when the grandchild exits). Otherwise a `tmutil` helper that stays alive would hang
    /// the scan for as long as the helper lives.
    ///
    /// # Scenario (Given)
    /// Table of three scripts, each starting `/bin/sleep 30` in the background, recording its pid and
    /// exiting at once with status 0, run with a 1.5 s timeout. The direct child is gone almost
    /// immediately, so only the pipe drain is left to wait for (the case the "child hangs" test above
    /// cannot reach). Rows: `both-pipes` (`sleep 30 &`: holds stdout and stderr), `stderr-only`
    /// (`sleep 30 >/dev/null &`: stdout closes with the shell, stderr stays open), `stdout-only`
    /// (`sleep 30 2>/dev/null &`: the mirror image).
    ///
    /// # Action (When)
    /// `RealRunner.run(script, [], 1.5 s)` for each row.
    ///
    /// # Expected (Then)
    /// `Err(TimedOut)` (the output is not complete, so the runner must not claim success), after at
    /// least the timeout and well under the grandchild's 30 s (bound 10 s, ~6x the timeout, generous
    /// for a loaded CI machine yet 3x below the sleep).
    ///
    /// # Must never
    /// Block until the grandchild exits (30 s); return `Ok` with truncated output; return before the
    /// deadline.
    ///
    /// # Would catch
    /// Row `both-pipes`: an unbounded drain (`join()` on the reader threads without a deadline:
    /// ~30 s) and the deadline test flipped (`>=` -> `<`: returns at once, before the timeout).
    /// Rows `stderr-only` / `stdout-only`: the drain-wait loop condition `&&` -> `||` (the loop
    /// leaves as soon as ONE pipe is at EOF and then `join`s the other reader for ~30 s; with both
    /// pipes held the mutant still waits for the deadline, so only the one-pipe rows see it; the two
    /// rows are mirror images so that dropping either operand of the condition, or checking only one
    /// stream, is also seen).
    ///
    /// # Why this test (not redundant)
    /// The only test where the child exits but a pipe stays open; the neighbouring timeout test kills
    /// a child that is still running. The orphaned `sleep` is NOT asserted dead: the runner kills its
    /// direct child only (process groups are out of the contract, see the worksheet), so the test
    /// cleans it up itself (drop guard per row).
    #[test]
    fn safety_ac_002_21_timeout_still_bounds_the_call_when_a_grandchild_holds_the_pipes() {
        // Arrange: (name, how the background sleep is redirected)
        let rows = [
            ("both-pipes", ""),
            ("stderr-only", ">/dev/null"),
            ("stdout-only", "2>/dev/null"),
        ];
        let timeout = Duration::from_millis(1500);

        for (name, redirect) in rows {
            let tmp = tempfile::tempdir().expect("temp dir");
            let pid_file = tmp.path().join("grandchild.pid");
            let _cleanup = KillOnDrop(pid_file.clone());
            let prog = script(
                tmp.path(),
                "leaves-a-grandchild",
                &format!(
                    "/bin/sleep 30 {redirect} &\necho $! > '{}'",
                    pid_file.display()
                ),
            );

            // Act
            let started = Instant::now();
            let result = RealRunner.run(prog.to_str().expect("utf-8 path"), &[], timeout);
            let elapsed = started.elapsed();

            // Assert
            assert_eq!(
                result,
                Err(CommandError::TimedOut),
                "row `{name}`: a pipe still held by a grandchild at the deadline means incomplete output, so TimedOut"
            );
            assert!(
                elapsed >= timeout,
                "row `{name}`: the runner must not give up before the timeout, took {elapsed:?}"
            );
            assert!(
                elapsed < Duration::from_secs(10),
                "row `{name}`, INV-13: the call must be bounded by the timeout even when a grandchild \
                 holds a pipe (an unbounded or one-pipe-early drain waits ~30 s), took {elapsed:?}"
            );
        }
    }
}

/// # Design promise
/// AC-002-21: a finished program is `Ok` whatever its exit status, with stdout and stderr captured
/// separately and exactly (a non-zero status is data for the caller, not a runner error).
///
/// # Scenario (Given)
/// Three programs: `/bin/echo hello` (exit 0), `/usr/bin/false` (exit 1, no output), and a script
/// writing `out` to stdout, `err` to stderr and exiting 3.
///
/// # Action (When)
/// `RealRunner.run` for each.
///
/// # Expected (Then)
/// `(exit_code, stdout, stderr)` = `(0, "hello\n", "")`, `(1, "", "")`, `(3, "out\n", "err\n")`.
///
/// # Must never
/// Turn a non-zero exit into `Err`; merge the two streams; drop output.
///
/// # Would catch
/// `status.success()` mapped to an error, `2>&1` style merging, reading only stdout.
///
/// # Why this test (not redundant)
/// The only test of the success/non-zero classes and stream separation; failures to start are the
/// next test.
#[test]
fn ac_002_21_exit_status_and_both_streams_are_reported_not_turned_into_errors() {
    // Arrange
    type Row<'a> = (&'a str, String, Vec<&'a str>, (i32, &'a str, &'a str));
    let tmp = tempfile::tempdir().expect("temp dir");
    let noisy = script(tmp.path(), "noisy", "echo out\necho err >&2\nexit 3");
    let rows: Vec<Row<'_>> = vec![
        (
            "echo",
            "/bin/echo".to_owned(),
            vec!["hello"],
            (0, "hello\n", ""),
        ),
        ("false", "/usr/bin/false".to_owned(), vec![], (1, "", "")),
        (
            "script",
            noisy.to_str().expect("utf-8 path").to_owned(),
            vec![],
            (3, "out\n", "err\n"),
        ),
    ];

    for (name, program, args, (code, stdout, stderr)) in rows {
        // Act
        let out = RealRunner
            .run(&program, &args, PROMPT)
            .unwrap_or_else(|e| panic!("{name}: a finished program must be Ok, got {e:?}"));

        // Assert
        assert_eq!(out.exit_code, code, "{name}: exit status");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            stdout,
            "{name}: stdout"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            stderr,
            "{name}: stderr"
        );
    }
}

/// # Design promise
/// AC-002-21 / INV-13: a program that cannot be started is a typed error with the right class - a
/// missing program is `NotFound` (-> `tool_missing`), a file that exists but is not executable is
/// `Failed` (-> `spawn_failed`) - never `Ok`, never a panic.
///
/// # Scenario (Given)
/// `/nonexistent-dir/tool` (absolute, missing) and a regular file without the execute bit.
///
/// # Action (When)
/// `RealRunner.run` for each.
///
/// # Expected (Then)
/// `Err(NotFound)` and `Err(Failed{..})` respectively.
///
/// # Must never
/// Report a missing tool as a successful empty run (it would read as "no snapshots", INV-13), or
/// collapse the two classes.
///
/// # Would catch
/// `unwrap_or_default()` on the spawn result, mapping every spawn error to `NotFound`.
///
/// # Why this test (not redundant)
/// The only test of the spawn-failure classes; timeouts and exit statuses are covered by neighbors.
#[test]
fn ac_002_21_a_missing_program_is_not_found_and_a_non_executable_file_is_failed() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let plain = tmp.path().join("not-executable");
    put(&plain, "#!/bin/sh\n");
    fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).expect("chmod -x");

    // Act
    let missing = RealRunner.run("/nonexistent-dir/tool", &[], PROMPT);
    let not_exec = RealRunner.run(plain.to_str().expect("utf-8 path"), &[], PROMPT);

    // Assert
    assert_eq!(
        missing,
        Err(CommandError::NotFound),
        "a missing program is NotFound"
    );
    assert!(
        matches!(not_exec, Err(CommandError::Failed { .. })),
        "a non-executable file is a spawn failure (Failed), got {not_exec:?}"
    );
}

/// # Design promise
/// AC-002-21: output larger than an OS pipe buffer on **both** streams is captured completely without
/// deadlock (a runner must drain stdout and stderr concurrently).
///
/// # Scenario (Given)
/// A script that writes 1 MiB of NUL bytes to stderr first and then 1 MiB to stdout (a runner that
/// reads stdout to the end before touching stderr blocks forever once the stderr pipe is full).
///
/// # Action (When)
/// `RealRunner.run(script, [], 20 s)`.
///
/// # Expected (Then)
/// `Ok`, exit 0, `stdout.len() == stderr.len() == 1_048_576`.
///
/// # Must never
/// Deadlock until the timeout, truncate, or lose either stream.
///
/// # Would catch
/// Sequential `read_to_end` on stdout then stderr, `wait()` before reading, fixed-size buffers.
///
/// # Why this test (not redundant)
/// The only test of the pipe-draining class; real `tmutil` output is tiny, so only a test like this
/// exposes the bug.
#[test]
fn ac_002_21_large_output_on_both_streams_is_captured_without_deadlock() {
    // Arrange
    let tmp = tempfile::tempdir().expect("temp dir");
    let big = script(
        tmp.path(),
        "big",
        "/usr/bin/head -c 1048576 /dev/zero >&2\n/usr/bin/head -c 1048576 /dev/zero",
    );

    // Act
    let out = RealRunner
        .run(big.to_str().expect("utf-8 path"), &[], PROMPT)
        .expect("a chatty program must finish and be captured");

    // Assert
    assert_eq!(out.exit_code, 0, "the script exits 0");
    assert_eq!(
        out.stdout.len(),
        1_048_576,
        "stdout must be captured completely"
    );
    assert_eq!(
        out.stderr.len(),
        1_048_576,
        "stderr must be captured completely"
    );
}
