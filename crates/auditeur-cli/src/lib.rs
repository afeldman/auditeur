//! Auditeur's command-line front-end.
//!
//! This crate is the only place in the workspace that decides exit codes, writes
//! to the terminal and turns arguments into configuration. The engine below it
//! has no notion of a terminal, and the terminal interface beside it has no
//! notion of an exit code.

#![forbid(unsafe_code)]

pub mod cli;
pub mod commands;
pub mod error;
pub mod output;
pub mod resolve;

pub use cli::Cli;
pub use error::CliError;
pub use resolve::Resolved;

/// Start logging for a resolved run.
///
/// Best effort by design: the audit is the deliverable and the log is not. An
/// unusable log directory — an unwritable volume, a path a file occupies — is
/// reported on standard error and the command continues without a log, rather
/// than refusing to audit because it cannot write a debugging aid.
///
/// The returned guard must live as long as the process should keep logging: the
/// appender is asynchronous and dropping the guard flushes and stops it.
pub fn start_logging(resolved: &Resolved) -> Option<auditeur_logging::LoggingGuard> {
    start_logging_at(
        &resolved.home,
        resolved.config(),
        resolved.log_level,
        resolved.console,
    )
}

/// Start logging from a home and a configuration, for a command that has not
/// resolved a full run — `setup`, which runs before a configuration exists.
pub fn start_logging_at(
    home: &auditeur_config::AuditeurHome,
    config: &auditeur_config::AuditeurConfig,
    level: auditeur_config::LogLevel,
    console: crate::output::Console,
) -> Option<auditeur_logging::LoggingGuard> {
    match auditeur_logging::init(home, &config.logging, Some(level)) {
        Ok(guard) => {
            tracing::debug!(
                log_file = %guard.log_file().display(),
                level = %guard.level(),
                "logging started"
            );
            Some(guard)
        }
        Err(error) => {
            console.warn(&format!("logging disabled for this run: {error}"));
            None
        }
    }
}

/// Run a parsed command line.
///
/// Returns the process exit code: `0` clean, `1` findings at or above the
/// failure threshold, `2` usage, configuration or I/O error.
pub fn run(cli: &Cli) -> Result<u8, CliError> {
    commands::dispatch(cli)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn the_default_command_audits_a_temporary_repository() {
        let project = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(
            repo.path().join("main.go"),
            "package main\n\nfunc main() {}\n",
        )
        .unwrap();

        let cli = Cli::parse_from([
            "auditeur",
            "--home",
            project.path().to_str().unwrap(),
            "--project",
            "demo",
            "--quiet",
            repo.path().to_str().unwrap(),
        ]);

        let code = run(&cli).unwrap();
        // A tiny Go file with no findings either way: 0 or 1, never 2.
        assert!(code == 0 || code == 1, "unexpected exit code {code}");

        // The report landed in the project directory, not in the repository.
        let paths = auditeur_config::AuditeurHome::at(project.path());
        let reports: Vec<_> = std::fs::read_dir(paths.root())
            .unwrap()
            .filter_map(Result::ok)
            .flat_map(|entry| std::fs::read_dir(entry.path()).into_iter().flatten())
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("audit_"))
            .collect();
        assert_eq!(reports.len(), 1, "expected exactly one report");
        assert!(
            !repo.path().join("audit_report").exists(),
            "the repository must not receive audit output"
        );
    }

    #[test]
    fn a_missing_repository_is_a_usage_error() {
        let project = tempfile::tempdir().unwrap();
        let cli = Cli::parse_from([
            "auditeur",
            "--home",
            project.path().to_str().unwrap(),
            "/nonexistent/repository/path",
        ]);
        let error = run(&cli).unwrap_err();
        assert!(matches!(error, CliError::Usage(_)), "{error}");
        assert_eq!(error.exit_code(), 2);
        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn doctor_on_an_empty_project_succeeds() {
        let project = tempfile::tempdir().unwrap();
        let cli = Cli::parse_from([
            "auditeur",
            "--home",
            project.path().to_str().unwrap(),
            "--project",
            "demo",
            "doctor",
            "--json",
        ]);
        assert_eq!(run(&cli).unwrap(), 0);
    }
}
