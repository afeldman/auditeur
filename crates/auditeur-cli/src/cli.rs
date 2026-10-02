//! The command-line surface.
//!
//! The contract, kept deliberately small and Unix-friendly:
//!
//! ```text
//! auditeur [PATH]          audit PATH (default: the current directory)
//! auditeur audit <PATH>    the explicit form
//! auditeur setup           interactive configuration wizard
//! auditeur doctor          diagnose configuration, model, hardware, toolchains
//! auditeur update          report definition and model state
//! ```
//!
//! Exit codes: `0` clean, `1` findings at or above the failure threshold,
//! `2` usage, configuration or I/O error.

use std::path::PathBuf;
use std::process::ExitCode;

use auditeur_model::Severity;
use clap::{ArgAction, Parser, Subcommand};

/// Exit codes used by the CLI.
pub mod exit {
    /// The command completed and no threshold was breached.
    pub const OK: u8 = 0;
    /// Findings reached the configured failure threshold.
    pub const FINDINGS: u8 = 1;
    /// Usage, configuration or I/O error.
    pub const ERROR: u8 = 2;
}

/// Auditeur — local evidence-driven software auditor.
#[derive(Debug, Parser)]
#[command(
    name = "auditeur",
    version,
    about = "Local evidence-driven software auditor",
    long_about = "Auditeur analyses a local repository and writes a reproducible, evidence-based \
                  audit report. It is read-only with respect to the audited repository: everything \
                  it writes goes to its own project directory."
)]
pub struct Cli {
    /// Repository to audit. Defaults to the current directory.
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Project label recorded in the report and the configuration.
    ///
    /// It does not select a directory: there is one state root, chosen by
    /// `--home` or the environment.
    #[arg(long, global = true, value_name = "NAME")]
    pub project: Option<String>,

    /// Auditeur state directory. Defaults to `$HOME/auditeur`, or `$AUDITEUR_HOME`.
    #[arg(long, global = true, value_name = "DIR")]
    pub home: Option<PathBuf>,

    /// Log level for this process: error, warn, info, debug or trace.
    ///
    /// Overrides the configured level without changing the configuration.
    #[arg(long = "log-level", global = true, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Disable model-assisted analysis for this run.
    #[arg(long = "no-ai", global = true)]
    pub no_ai: bool,

    /// Report format: markdown (default) or json. sarif is declared, not implemented.
    #[arg(long, global = true, value_name = "FORMAT", default_value = "markdown")]
    pub format: String,

    /// Minimum severity that makes the run exit non-zero, when a violation is found.
    #[arg(
        long = "fail-on",
        global = true,
        value_name = "SEVERITY",
        default_value = "high"
    )]
    pub fail_on: String,

    /// Suppress progress output; the report is still written.
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Increase verbosity (-v for stage detail, -vv for everything).
    #[arg(long, short = 'v', global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Print the report to standard output as well as writing it.
    #[arg(long = "print", global = true)]
    pub print: bool,

    /// Subcommand. Without one, the current directory is audited.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Available commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Audit a repository.
    Audit {
        /// Repository to audit. Defaults to the current directory.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    },

    /// Configure Auditeur interactively.
    Setup {
        /// Write defaults without the wizard, using --source or the current directory.
        #[arg(long)]
        non_interactive: bool,

        /// Repository the project should audit by default.
        #[arg(long, value_name = "PATH")]
        source: Option<PathBuf>,

        /// Overwrite an existing configuration without asking.
        #[arg(long)]
        force: bool,
    },

    /// Diagnose configuration, model, hardware, toolchains and permissions.
    Doctor {
        /// Emit the diagnosis as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Report the state of audit definitions, and optionally of the model.
    Update {
        /// Also list the models the configured server offers.
        #[arg(long)]
        check_models: bool,
    },
}

impl Cli {
    /// The repository named on the command line, if the user named one.
    ///
    /// Both positional forms count: `auditeur [PATH]` and the explicit
    /// `auditeur audit <PATH>`. `None` means the target came from the
    /// configuration or from the working directory, which is what decides
    /// whether a configured `source_path` is honoured.
    pub fn command_path(&self) -> Option<&PathBuf> {
        match &self.command {
            Some(Command::Audit { path }) => path.as_ref().or(self.path.as_ref()),
            _ => self.path.as_ref(),
        }
    }

    /// The failure threshold as a typed value.
    pub fn fail_threshold(&self) -> Result<Severity, String> {
        parse_severity(&self.fail_on)
    }
}

/// Parse a severity name on the command line.
pub fn parse_severity(value: &str) -> Result<Severity, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" | "moderate" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        "none" | "never" => Ok(Severity::Critical),
        other => Err(format!(
            "unknown severity '{other}'; expected info, low, medium, high or critical"
        )),
    }
}

/// The repository a command should act on.
pub fn target_path(cli: &Cli, command_path: Option<&PathBuf>) -> PathBuf {
    command_path
        .cloned()
        .or_else(|| cli.path.clone())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// The exit code for a configuration or usage error.
pub fn error_exit() -> ExitCode {
    ExitCode::from(exit::ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn a_bare_invocation_audits_the_current_directory() {
        let cli = Cli::parse_from(["auditeur"]);
        assert!(cli.command.is_none());
        assert!(cli.path.is_none());
        assert_eq!(target_path(&cli, None), PathBuf::from("."));
    }

    #[test]
    fn a_positional_path_is_an_audit_target() {
        let cli = Cli::parse_from(["auditeur", "/tmp/repo"]);
        assert_eq!(target_path(&cli, None), PathBuf::from("/tmp/repo"));
    }

    #[test]
    fn the_explicit_form_is_equivalent() {
        let cli = Cli::parse_from(["auditeur", "audit", "/tmp/repo"]);
        match &cli.command {
            Some(Command::Audit { path }) => {
                assert_eq!(target_path(&cli, path.as_ref()), PathBuf::from("/tmp/repo"));
            }
            other => panic!("expected the audit command, got {other:?}"),
        }
    }

    #[test]
    fn the_explicit_form_prefers_its_own_path() {
        let cli = Cli::parse_from(["auditeur", "/tmp/other", "audit", "/tmp/repo"]);
        match &cli.command {
            Some(Command::Audit { path }) => {
                assert_eq!(target_path(&cli, path.as_ref()), PathBuf::from("/tmp/repo"));
            }
            other => panic!("expected the audit command, got {other:?}"),
        }
    }

    #[test]
    fn global_flags_are_accepted_before_and_after_the_subcommand() {
        let before = Cli::parse_from(["auditeur", "--no-ai", "doctor"]);
        assert!(before.no_ai);
        let after = Cli::parse_from(["auditeur", "doctor", "--no-ai"]);
        assert!(after.no_ai);
    }

    #[test]
    fn severity_parsing_is_lenient_about_case() {
        assert_eq!(parse_severity("HIGH").unwrap(), Severity::High);
        assert_eq!(parse_severity("moderate").unwrap(), Severity::Medium);
        assert!(parse_severity("enormous").is_err());
    }

    #[test]
    fn defaults_match_the_documented_contract() {
        let cli = Cli::parse_from(["auditeur"]);
        assert_eq!(cli.format, "markdown");
        assert_eq!(cli.fail_threshold().unwrap(), Severity::High);
        assert!(!cli.quiet);
        assert!(!cli.no_ai);
        assert_eq!(cli.verbose, 0);
        assert!(
            cli.home.is_none(),
            "the state root defaults to the environment"
        );
        assert!(
            cli.log_level.is_none(),
            "the level defaults to the configuration"
        );
    }

    #[test]
    fn the_home_and_log_level_flags_are_global() {
        let before = Cli::parse_from([
            "auditeur",
            "--home",
            "/tmp/state",
            "--log-level",
            "debug",
            "doctor",
        ]);
        assert_eq!(
            before.home.as_deref(),
            Some(std::path::Path::new("/tmp/state"))
        );
        assert_eq!(before.log_level.as_deref(), Some("debug"));

        let after = Cli::parse_from([
            "auditeur",
            "doctor",
            "--home",
            "/tmp/state",
            "--log-level",
            "trace",
        ]);
        assert_eq!(
            after.home.as_deref(),
            Some(std::path::Path::new("/tmp/state"))
        );
        assert_eq!(after.log_level.as_deref(), Some("trace"));
    }

    #[test]
    fn verbosity_accumulates() {
        let cli = Cli::parse_from(["auditeur", "-vv", "doctor"]);
        assert_eq!(cli.verbose, 2);
    }

    #[test]
    fn exit_codes_are_distinct_and_documented() {
        assert_eq!(exit::OK, 0);
        assert_eq!(exit::FINDINGS, 1);
        assert_eq!(exit::ERROR, 2);
        assert_ne!(error_exit(), ExitCode::from(exit::OK));
    }
}
