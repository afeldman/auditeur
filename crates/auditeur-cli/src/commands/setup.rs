//! `auditeur setup`.
//!
//! Two modes. Interactively, it hands over to the terminal wizard. With
//! `--non-interactive` it writes defaults plus the given repository, which is
//! what a script or a CI image needs. Both modes go through the configuration
//! layer, so the resulting files are identical in shape and validated the same
//! way.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use auditeur_config::{derive_project_name, validate_project_name, AuditeurConfig};

use crate::cli::Cli;
use crate::error::CliError;
use crate::resolve;

/// Run setup.
pub fn run(
    cli: &Cli,
    non_interactive: bool,
    source: Option<&Path>,
    force: bool,
) -> Result<u8, CliError> {
    let repository = source
        .map(Path::to_path_buf)
        .or_else(|| cli.path.clone())
        .unwrap_or_else(|| PathBuf::from("."));

    let (home, notes) = resolve::resolve_home(cli, &repository)?;
    let console = crate::output::Console::new(cli.quiet, cli.verbose);

    for note in &notes {
        console.info(note);
    }

    if home.project_config_file().is_file() && !force {
        return Err(CliError::Usage(format!(
            "{} already exists; pass --force to overwrite it",
            home.project_config_file().display()
        )));
    }

    let mut initial = AuditeurConfig::default();
    // `--project` is a label, and it wins over the name derived from the
    // repository — the configuration it writes must agree with what the flag
    // claimed.
    initial.project.name = match &cli.project {
        Some(name) => {
            validate_project_name(name).map_err(CliError::Config)?;
            name.clone()
        }
        None => derive_project_name(&repository),
    };
    initial.project.source_path = repository.clone();
    initial.project.project_root = Some(home.root().to_path_buf());

    // Setup logs like every other command; the level comes from the flag, or from
    // the defaults, because no configuration has been read yet.
    let level = match cli.log_level.as_deref() {
        Some(text) => text
            .parse::<auditeur_config::LogLevel>()
            .map_err(CliError::Config)?,
        None => initial.logging.level,
    };
    let _logging = crate::start_logging_at(&home, &initial, level, console);

    if non_interactive {
        return write_defaults(&initial, &home, &console);
    }

    if !std::io::stdout().is_terminal() {
        return Err(CliError::Usage(
            "the setup wizard needs a terminal; use --non-interactive to write defaults"
                .to_string(),
        ));
    }

    match auditeur_tui::run_setup_wizard(initial, home.clone())? {
        Some(written) => {
            console.result(&written.summary());
            console.result(&format!("next: `auditeur audit {}`", repository.display()));
            Ok(0)
        }
        None => {
            console.info("setup cancelled; no configuration was written");
            Ok(0)
        }
    }
}

/// Write a default configuration without the wizard.
fn write_defaults(
    config: &AuditeurConfig,
    paths: &auditeur_config::AuditeurHome,
    console: &crate::output::Console,
) -> Result<u8, CliError> {
    let files = config.save(paths)?;
    console.result(&format!(
        "configuration written to {} ({} file(s))",
        paths.root().display(),
        files.len()
    ));
    console.result(&format!(
        "no model is selected, so audits run deterministic checks only; set one in {}/config/model.toml",
        paths.root().display()
    ));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cli_for(root: &Path, repository: &Path) -> Cli {
        Cli::parse_from([
            "auditeur",
            "--home",
            root.to_str().unwrap(),
            "--project",
            "demo",
            "setup",
            "--non-interactive",
            "--source",
            repository.to_str().unwrap(),
        ])
    }

    #[test]
    fn non_interactive_setup_writes_a_usable_configuration() {
        let project = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let cli = cli_for(project.path(), repository.path());

        let code = run(&cli, true, Some(repository.path()), false).unwrap();
        assert_eq!(code, 0);

        let paths = auditeur_config::AuditeurHome::at(project.path());
        for file in [
            paths.project_config_file(),
            paths.model_config_file(),
            paths.audit_config_file(),
        ] {
            assert!(file.is_file(), "missing {file:?}");
        }

        let loaded = AuditeurConfig::load(&paths).unwrap();
        loaded.config.validate().unwrap();
        assert_eq!(loaded.config.project.source_path, repository.path());
    }

    #[test]
    fn setup_refuses_to_overwrite_without_force() {
        let project = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let cli = cli_for(project.path(), repository.path());

        run(&cli, true, Some(repository.path()), false).unwrap();
        let error = run(&cli, true, Some(repository.path()), false).unwrap_err();
        assert!(matches!(error, CliError::Usage(_)), "{error}");
        assert!(error.to_string().contains("--force"));

        assert_eq!(run(&cli, true, Some(repository.path()), true).unwrap(), 0);
    }

    #[test]
    fn the_wizard_is_refused_without_a_terminal() {
        let project = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let cli = cli_for(project.path(), repository.path());

        // Tests do not run attached to a terminal, so the wizard path must fail
        // with an actionable message rather than blocking.
        if std::io::stdout().is_terminal() {
            return;
        }
        let error = run(&cli, false, Some(repository.path()), false).unwrap_err();
        assert!(error.to_string().contains("--non-interactive"), "{error}");
    }
}
