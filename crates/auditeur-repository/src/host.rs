//! Host capability probing.
//!
//! Distinct from [`crate::exec::CommandRunner`], which runs tools *on the
//! audited repository* under an allowlist and cache redirection. Host probes
//! answer questions about the machine Auditeur runs on — which accelerators
//! exist, which toolchains are installed — and are therefore:
//!
//! * compiled-in argv templates, never built from repository content;
//! * executed with the working directory set to the system temporary area, so a
//!   probe cannot write into a repository even if it wanted to;
//! * optional: a probe that cannot run yields `None`, and the caller reports
//!   the capability as unknown rather than as absent.
//!
//! This module shares one process-spawning implementation with the repository
//! runner, so the tricky part (draining pipes, enforcing the deadline) exists
//! exactly once.

use std::time::Duration;

use crate::error::RepositoryError;
use crate::exec::CommandOutput;

/// Default time budget for a host probe.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Outcome of a host probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProbe {
    /// Program that was run.
    pub program: String,
    /// Arguments it received.
    pub args: Vec<String>,
    /// Exit code, absent when killed by a signal.
    pub exit_code: Option<i32>,
    /// Captured stdout, trimmed.
    pub stdout: String,
    /// Captured stderr, trimmed.
    pub stderr: String,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Whether the probe exceeded its budget and was killed.
    pub timed_out: bool,
}

impl HostProbe {
    /// Whether the probe ran and exited successfully.
    pub fn succeeded(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }

    /// First non-empty line of stdout, for use in a report line.
    pub fn first_line(&self) -> Option<&str> {
        self.stdout
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
    }
}

/// Run a host probe.
///
/// Returns `None` when the program does not exist or cannot be executed: that
/// is a legitimate answer meaning "we cannot tell", and callers must report it
/// as unknown rather than as unsupported.
pub fn probe(program: &str, args: &[&str], timeout: Duration) -> Option<HostProbe> {
    probe_with_environment(program, args, timeout, true)
}

/// Run a host probe with an explicit choice about inheriting the environment.
///
/// Probing a toolchain needs `PATH` and `HOME`; nothing else of the auditor's
/// environment should reach a probe, and a probe is never given credentials.
pub fn probe_with_environment(
    program: &str,
    args: &[&str],
    timeout: Duration,
    inherit_environment: bool,
) -> Option<HostProbe> {
    let working_directory = std::env::temp_dir();

    let mut environment: Vec<(String, String)> = Vec::new();
    if inherit_environment {
        for name in ["PATH", "HOME"] {
            if let Ok(value) = std::env::var(name) {
                environment.push((name.to_string(), value));
            }
        }
    }
    environment.push(("LC_ALL".to_string(), "C".to_string()));
    environment.push(("NO_COLOR".to_string(), "1".to_string()));

    let owned_args: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    match crate::exec::capture_command(
        program,
        &owned_args,
        &working_directory,
        &environment,
        timeout,
        64 * 1024,
    ) {
        Ok(output) => Some(from_output(output, false)),
        Err(RepositoryError::CommandTimeout { .. }) => Some(HostProbe {
            program: program.to_string(),
            args: owned_args,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: timeout.as_millis() as u64,
            timed_out: true,
        }),
        Err(_) => None,
    }
}

fn from_output(output: CommandOutput, timed_out: bool) -> HostProbe {
    HostProbe {
        program: output.program,
        args: output.args,
        exit_code: output.exit_code,
        stdout: output.stdout.trim().to_string(),
        stderr: output.stderr.trim().to_string(),
        duration_ms: output.duration_ms,
        timed_out,
    }
}

/// Run the first probe in `candidates` that can be executed.
///
/// Used by `doctor`, which wants "is a Rust toolchain present, and what version"
/// without caring whether it was found as `cargo` or at an absolute path.
pub fn probe_first_available(
    candidates: &[(&str, &[&str])],
    timeout: Duration,
) -> Option<HostProbe> {
    for (program, args) in candidates {
        if let Some(probe) = probe(program, args, timeout) {
            if !probe.timed_out {
                return Some(probe);
            }
        }
    }
    None
}

/// Whether a program can be executed on this machine.
pub fn is_available(program: &str) -> bool {
    probe_first_available(&[(program, &["--version"])], PROBE_TIMEOUT).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_program_yields_none_rather_than_a_false_negative() {
        assert!(probe(
            "auditeur-definitely-not-installed",
            &["--version"],
            Duration::from_secs(5)
        )
        .is_none());
    }

    #[test]
    fn a_probe_records_its_output() {
        let probe = probe("/bin/echo", &["hello"], Duration::from_secs(5)).unwrap();
        assert!(probe.succeeded());
        assert_eq!(probe.first_line(), Some("hello"));
        assert_eq!(probe.exit_code, Some(0));
    }

    #[test]
    fn a_probe_that_hangs_times_out_instead_of_blocking() {
        let probe = probe("sleep", &["30"], Duration::from_millis(200)).unwrap();
        assert!(probe.timed_out);
        assert!(!probe.succeeded());
        assert!(probe.exit_code.is_none());
    }

    #[test]
    fn a_failing_probe_is_distinguishable_from_a_missing_one() {
        let probe = probe("sh", &["-c", "exit 7"], Duration::from_secs(5)).unwrap();
        assert!(!probe.succeeded());
        assert_eq!(probe.exit_code, Some(7));
        assert!(!probe.timed_out);
    }

    #[test]
    fn the_auditors_environment_is_not_leaked_into_a_probe() {
        let probe =
            probe_with_environment("sh", &["-c", "env"], Duration::from_secs(5), false).unwrap();
        let environment: Vec<&str> = probe.stdout.lines().collect();
        assert!(environment.iter().any(|line| line.starts_with("LC_ALL=C")));
        // Only the explicitly set variables may appear. A shell adds its own
        // internals (`_`, `PWD`, `SHLVL`); nothing of the auditor's environment
        // may reach the probe.
        const SHELL_INTERNALS: &[&str] = &["_=", "PWD=", "SHLVL=", "OLDPWD="];
        let unexpected: Vec<&&str> = environment
            .iter()
            .filter(|line| {
                !line.starts_with("LC_ALL=")
                    && !line.starts_with("NO_COLOR=")
                    && !SHELL_INTERNALS
                        .iter()
                        .any(|prefix| line.starts_with(prefix))
            })
            .collect();
        assert!(unexpected.is_empty(), "variables leaked: {unexpected:?}");
    }
}
