//! Turning command-line arguments plus configuration into a resolved run.
//!
//! Two things are resolved here, and the order between them is deliberate:
//!
//! 1. **The state root** — from `--home`, then a `.auditeur-project` pointer
//!    file inside the repository, then `AUDITEUR_HOME`, then `$HOME/auditeur`.
//!    This happens before any file is read, because the configuration lives
//!    under that root: there is nothing to load until the root is known.
//! 2. **The configuration** — the three documents under `config/`, then the
//!    `AUDITEUR_*` environment, then the flags.
//!
//! The repository being audited has no say in where state lives unless it
//! carries a pointer file, which is an explicit act rather than an inference.

use std::path::{Path, PathBuf};

use auditeur_config::{
    derive_project_name, env, validate_project_name, AuditeurConfig, AuditeurHome, LoadedConfig,
    LogLevel,
};
use auditeur_model::Severity;
use auditeur_report::{OutputFormat, ReportOptions};

use crate::cli::Cli;
use crate::error::CliError;
use crate::output::Console;

/// Optional file through which a repository names its own state root.
pub const STATE_POINTER_FILE: &str = ".auditeur-project";

/// Everything a command needs after resolution.
#[derive(Debug)]
pub struct Resolved {
    /// Where Auditeur keeps its state, with the configured layout applied.
    pub home: AuditeurHome,
    /// Loaded configuration with provenance.
    pub loaded: LoadedConfig,
    /// The repository to audit.
    pub source_path: PathBuf,
    /// Report format.
    pub format: OutputFormat,
    /// Report content preferences.
    pub report_options: ReportOptions,
    /// Whether model-assisted analysis is enabled for this run.
    pub enable_ai: bool,
    /// Severity at which the run exits non-zero.
    pub fail_threshold: Severity,
    /// Whether the read-only boundary is verified and enforced.
    pub verify_read_only: bool,
    /// Console settings.
    pub console: Console,
    /// Logging level in force: the flag, else the configuration.
    pub log_level: LogLevel,
    /// Observations about how the state root was chosen.
    pub notes: Vec<String>,
}

impl Resolved {
    /// The effective configuration.
    pub fn config(&self) -> &AuditeurConfig {
        &self.loaded.config
    }
}

/// Resolve a command invocation.
pub fn resolve(cli: &Cli, target: &Path) -> Result<Resolved, CliError> {
    let (home, notes) = resolve_home(cli, target)?;
    let mut loaded = AuditeurConfig::load(&home)?;

    // A positional path is the user's explicit choice and wins. Otherwise the
    // configured repository is honoured, which is how `AUDITEUR_SOURCE_PATH`
    // takes effect; the default configuration says "." and means the working
    // directory, exactly as a bare invocation always has.
    let source_path = if cli.command_path().is_some() {
        target.to_path_buf()
    } else if loaded.config.project.source_path != Path::new(".") {
        loaded.config.project.source_path.clone()
    } else {
        target.to_path_buf()
    };
    loaded.config.project.source_path = source_path.clone();

    // The state root must lie outside the audited repository. Reports, run
    // artifacts and the log all go under it, so a root inside the tree would make
    // Auditeur the thing it promises never to be: a writer into the repository it
    // is auditing. The guard is here, before anything is created, because the
    // logger is the first writer and it runs before the audit starts.
    if auditeur_repository::is_path_inside(home.root(), &source_path) {
        return Err(CliError::Usage(format!(
            "the state directory {} is inside the audited repository {}; Auditeur never writes \
             into the repository it audits — choose a state root outside it with --home or \
             AUDITEUR_HOME",
            home.root().display(),
            source_path.display()
        )));
    }
    if loaded.config.project.project_root.is_none() {
        loaded.config.project.project_root = Some(home.root().to_path_buf());
    }

    // `--project` labels the project; it no longer selects a directory, because
    // there is one state root and it is chosen by `--home` or the environment.
    if let Some(name) = &cli.project {
        validate_project_name(name).map_err(CliError::Config)?;
        loaded.config.project.name = name.clone();
    } else if loaded.config.project.name.trim().is_empty() {
        loaded.config.project.name = derive_project_name(&source_path);
    }

    let format: OutputFormat = cli
        .format
        .parse()
        .map_err(|error: auditeur_report::ReportError| CliError::Usage(error.to_string()))?;

    let fail_threshold = cli.fail_threshold().map_err(CliError::Usage)?;
    let log_level = cli
        .log_level
        .as_deref()
        .map(|value| value.parse::<LogLevel>().map_err(CliError::Config))
        .transpose()?
        .unwrap_or(loaded.config.logging.level);

    let enable_ai = !cli.no_ai && loaded.config.model.ai_active();

    Ok(Resolved {
        report_options: ReportOptions::from_config(&loaded.config),
        loaded,
        home,
        source_path,
        format,
        enable_ai,
        fail_threshold,
        verify_read_only: true,
        console: Console::new(cli.quiet, cli.verbose),
        log_level,
        notes,
    })
}

/// Determine the state root.
///
/// The flag wins over everything, and the pointer file wins over the
/// environment: a repository that names its state root has said something
/// specific, while `AUDITEUR_HOME` is a general preference. A blank value counts
/// as unset throughout.
pub fn resolve_home(
    cli: &Cli,
    source_path: &Path,
) -> Result<(AuditeurHome, Vec<String>), CliError> {
    if let Some(root) = cli.home.clone().filter(|path| !path.as_os_str().is_empty()) {
        return Ok((
            AuditeurHome::from_path(root).map_err(CliError::Config)?,
            Vec::new(),
        ));
    }

    if let Some(root) = pointer_root(source_path) {
        let home = AuditeurHome::from_path(root).map_err(CliError::Config)?;
        let note = format!(
            "state root {} taken from the repository pointer file {}",
            home.root().display(),
            source_path.join(STATE_POINTER_FILE).display()
        );
        return Ok((home, vec![note]));
    }

    let discovery = AuditeurHome::discover().map_err(CliError::Config)?;
    Ok((discovery.home, discovery.notes))
}

/// A state root named by the repository's own pointer file, if it has one.
fn pointer_root(source_path: &Path) -> Option<PathBuf> {
    let pointer = source_path.join(STATE_POINTER_FILE);
    if !pointer.is_file() {
        return None;
    }
    let text = std::fs::read_to_string(&pointer).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed))
}

/// The environment names this module reads, re-exported for diagnostics.
pub fn state_environment() -> [&'static str; 2] {
    [env::HOME, env::PROJECT_ROOT]
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Every test names its own state root, so no test can read or write the
    /// developer's real `~/auditeur` and none depends on the ambient
    /// environment.
    fn cli_with_home(home: &Path, extra: &[&str]) -> Cli {
        let mut arguments = vec!["auditeur", "--home", home.to_str().unwrap()];
        arguments.extend_from_slice(extra);
        Cli::parse_from(arguments)
    }

    #[test]
    fn the_current_directory_is_the_default_target() {
        let project = tempfile::tempdir().unwrap();
        let cli = cli_with_home(project.path(), &[]);
        let resolved = resolve(&cli, Path::new(".")).unwrap();

        assert_eq!(resolved.source_path, PathBuf::from("."));
        assert_eq!(resolved.home.root(), project.path());
        assert_eq!(resolved.format, OutputFormat::Markdown);
        assert_eq!(resolved.fail_threshold, Severity::High);
        assert!(resolved.verify_read_only);
        assert!(!resolved.enable_ai);
        assert_eq!(resolved.log_level, LogLevel::Info);
        assert_eq!(resolved.config().project.source_path, PathBuf::from("."));
        assert_eq!(
            resolved.config().project.project_root.as_deref(),
            Some(project.path())
        );
    }

    #[test]
    fn the_home_flag_wins() {
        let project = tempfile::tempdir().unwrap();
        let cli = Cli::parse_from([
            "auditeur",
            "--home",
            project.path().to_str().unwrap(),
            "audit",
            "/tmp/repo",
        ]);
        let resolved = resolve(&cli, Path::new("/tmp/repo")).unwrap();
        assert_eq!(resolved.home.root(), project.path());
        assert!(resolved.notes.is_empty());
    }

    #[test]
    fn a_relative_home_is_refused_with_a_usable_message() {
        let cli = Cli::parse_from(["auditeur", "--home", "state"]);
        let error = resolve(&cli, Path::new(".")).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert!(error.to_string().contains("relative"), "{error}");
    }

    #[test]
    fn the_project_flag_labels_the_project_without_moving_the_state_root() {
        let project = tempfile::tempdir().unwrap();
        let cli = cli_with_home(project.path(), &["--project", "my-audit"]);
        let resolved = resolve(&cli, Path::new("/tmp/repo")).unwrap();

        assert_eq!(resolved.config().project.name, "my-audit");
        assert_eq!(
            resolved.home.root(),
            project.path(),
            "the label must not select a directory"
        );
    }

    #[test]
    fn a_state_pointer_file_names_the_root() {
        let repo = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::write(
            repo.path().join(STATE_POINTER_FILE),
            format!("{}\n", state.path().display()),
        )
        .unwrap();

        let cli = Cli::parse_from(["auditeur"]);
        let (home, notes) = resolve_home(&cli, repo.path()).unwrap();
        assert_eq!(home.root(), state.path());
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains(STATE_POINTER_FILE), "{notes:?}");
    }

    #[test]
    fn an_empty_pointer_file_is_ignored_rather_than_an_error() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join(STATE_POINTER_FILE), "\n").unwrap();
        assert!(pointer_root(repo.path()).is_none());
    }

    #[test]
    fn the_home_flag_beats_the_pointer_file() {
        let repo = tempfile::tempdir().unwrap();
        let pointed = tempfile::tempdir().unwrap();
        let flag = tempfile::tempdir().unwrap();
        std::fs::write(
            repo.path().join(STATE_POINTER_FILE),
            format!("{}", pointed.path().display()),
        )
        .unwrap();

        let cli = cli_with_home(flag.path(), &[]);
        let (home, _) = resolve_home(&cli, repo.path()).unwrap();
        assert_eq!(home.root(), flag.path());
    }

    #[test]
    fn no_ai_disables_model_assistance_even_when_a_model_is_configured() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("config")).unwrap();
        std::fs::write(
            project.path().join("config/model.toml"),
            "model = \"qwen/qwen2.5-coder-14b\"\nendpoint = \"http://127.0.0.1:1234/v1\"\n",
        )
        .unwrap();

        let with_ai = cli_with_home(project.path(), &[]);
        assert!(resolve(&with_ai, Path::new(".")).unwrap().enable_ai);

        let without_ai = cli_with_home(project.path(), &["--no-ai"]);
        assert!(!resolve(&without_ai, Path::new(".")).unwrap().enable_ai);
    }

    #[test]
    fn the_log_level_flag_overrides_the_configuration_without_changing_it() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("config")).unwrap();
        std::fs::write(
            project.path().join("config/auditeur.toml"),
            "[project]\nname = \"demo\"\n\n[logging]\nlevel = \"warn\"\n",
        )
        .unwrap();

        let configured = cli_with_home(project.path(), &[]);
        let resolved = resolve(&configured, Path::new(".")).unwrap();
        assert_eq!(resolved.log_level, LogLevel::Warn);

        let overridden = cli_with_home(project.path(), &["--log-level", "debug"]);
        let resolved = resolve(&overridden, Path::new(".")).unwrap();
        assert_eq!(resolved.log_level, LogLevel::Debug);
        // The file is untouched: the override is for this process only.
        let text = std::fs::read_to_string(project.path().join("config/auditeur.toml")).unwrap();
        assert!(text.contains("level = \"warn\""), "{text}");
    }

    #[test]
    fn an_unknown_log_level_is_a_configuration_error() {
        let project = tempfile::tempdir().unwrap();
        let cli = cli_with_home(project.path(), &["--log-level", "loud"]);
        let error = resolve(&cli, Path::new(".")).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert!(error.to_string().contains("logging.level"), "{error}");
    }

    #[test]
    fn an_unknown_format_is_a_usage_error() {
        let project = tempfile::tempdir().unwrap();
        let cli = cli_with_home(project.path(), &["--format", "pdf"]);
        let error = resolve(&cli, Path::new(".")).unwrap_err();
        assert!(matches!(error, CliError::Usage(_)), "{error}");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn an_unknown_severity_is_a_usage_error() {
        let project = tempfile::tempdir().unwrap();
        let cli = cli_with_home(project.path(), &["--fail-on", "enormous"]);
        let error = resolve(&cli, Path::new(".")).unwrap_err();
        assert!(matches!(error, CliError::Usage(_)), "{error}");
    }

    #[test]
    fn the_format_flag_selects_the_renderer() {
        let project = tempfile::tempdir().unwrap();
        let cli = cli_with_home(project.path(), &["--format", "json"]);
        assert_eq!(
            resolve(&cli, Path::new(".")).unwrap().format,
            OutputFormat::Json
        );
    }

    #[test]
    fn console_settings_follow_the_flags() {
        let project = tempfile::tempdir().unwrap();
        let quiet = cli_with_home(project.path(), &["-q"]);
        assert!(resolve(&quiet, Path::new(".")).unwrap().console.is_quiet());

        let verbose = cli_with_home(project.path(), &["-vv"]);
        assert_eq!(
            resolve(&verbose, Path::new("."))
                .unwrap()
                .console
                .verbosity(),
            2
        );
    }

    #[test]
    fn report_options_come_from_the_configuration() {
        let config = AuditeurConfig::default();
        let options = ReportOptions::from_config(&config);
        assert!(options.include_passing);
        assert!(options.include_evidence_excerpts);
        assert_eq!(options.min_severity, Severity::Info);
    }

    #[test]
    fn the_configuration_lives_under_the_resolved_home() {
        let project = tempfile::tempdir().unwrap();
        let cli = cli_with_home(project.path(), &[]);
        let resolved = resolve(&cli, Path::new("/tmp/repo")).unwrap();
        assert_eq!(
            resolved.home.project_config_file(),
            project.path().join("config/auditeur.toml")
        );
        assert_eq!(
            resolved.home.log_file(),
            project.path().join("logs/auditeur.log")
        );
    }

    #[test]
    fn the_state_environment_is_the_documented_pair() {
        assert_eq!(
            state_environment(),
            ["AUDITEUR_HOME", "AUDITEUR_PROJECT_ROOT"]
        );
    }
}
