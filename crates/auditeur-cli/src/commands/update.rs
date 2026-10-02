//! `auditeur update`.
//!
//! What this command does *not* do is as important as what it does. It does not
//! download anything, it does not replace models, and it does not touch the
//! binary. Model management is a roadmap item, and the reason is integrity: an
//! audit manifest records the checksum of the model that produced it, so
//! replacing a model under a historical run would silently invalidate the record.
//! Until download, verification and pinning exist together, this command reports
//! state and refuses to guess.

use std::path::PathBuf;

use auditeur_audit::definitions;

use crate::cli::Cli;
use crate::error::CliError;
use crate::resolve;

/// Report the state of audit definitions, and optionally of the model.
pub fn run(cli: &Cli, check_models: bool) -> Result<u8, CliError> {
    let target = cli.path.clone().unwrap_or_else(|| PathBuf::from("."));
    let resolved = resolve::resolve(cli, &target)?;
    let console = resolved.console;

    let _logging = crate::start_logging(&resolved);
    let definitions_dir = resolved.home.definitions_dir();
    let definitions = definitions::load_with_overrides(Some(definitions_dir.as_path()))?;

    console.result(&format!("audit definitions ({}):", definitions.len()));
    let mut total_checks = 0usize;
    let mut deterministic = 0usize;
    let mut model_assisted = 0usize;

    for definition in &definitions {
        let checks = definition.checks.len();
        let ai = definition
            .checks
            .iter()
            .filter(|check| check.kind.needs_model())
            .count();
        total_checks += checks;
        model_assisted += ai;
        deterministic += checks - ai;
        console.result(&format!(
            "  {:<22} version {:<8} {:>2} check(s), {} deterministic, {} model-assisted",
            definition.id,
            definition.version,
            checks,
            checks - ai,
            ai
        ));
        for check in &definition.checks {
            console.debug(&format!(
                "    {:<32} {:<10} kind={} severity={}",
                check.id,
                check.category.id(),
                check.kind.id(),
                check.severity.id()
            ));
        }
    }
    console.result(&format!(
        "  total: {total_checks} check(s), {deterministic} deterministic, {model_assisted} model-assisted"
    ));

    if definitions_dir.is_dir() {
        console.result(&format!(
            "override directory present: {} (definitions there take precedence)",
            definitions_dir.display()
        ));
    } else {
        console
            .result("no override directory; the definitions compiled into the binary are in use");
    }

    // Model state. Reported, never modified.
    let model = &resolved.config().model;
    if check_models {
        if !resolved.enable_ai {
            console.result(
                "model checks skipped: no model is enabled for this project (see config/model.toml)",
            );
        } else {
            match auditeur_inference::backends::build(model, model.api_key()) {
                Ok(backend) => match backend.list_models() {
                    Ok(models) if models.is_empty() => {
                        console.result(&format!("{}: offers no model list", backend.id()));
                    }
                    Ok(models) => {
                        console.result(&format!(
                            "{} at {} offers {} model(s):",
                            backend.id(),
                            model.endpoint,
                            models.len()
                        ));
                        for name in &models {
                            let marker = if name == &model.model { "*" } else { " " };
                            console.result(&format!("  {marker} {name}"));
                        }
                    }
                    Err(error) => console.warn(&format!("cannot list models: {error}")),
                },
                Err(error) => {
                    console.warn(&format!("the configured model cannot be used: {error}"))
                }
            }
        }
    } else {
        console.result(
            "run `auditeur update --check-models` to ask the configured server which models it offers",
        );
    }

    console.result(
        "not implemented in this version: self-update, definition download and model download. \
         Model files are never replaced automatically, because manifests record the model checksum \
         that produced them.",
    );

    Ok(crate::cli::exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn update_reports_the_embedded_definitions() {
        let project = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let cli = Cli::parse_from([
            "auditeur",
            "--home",
            project.path().to_str().unwrap(),
            "--project",
            "demo",
            "update",
        ]);

        let code = run(&cli, false).unwrap();
        assert_eq!(code, 0);

        // The embedded definitions must load and be non-empty; this is the
        // property the command reports, so it is the one worth asserting.
        let definitions = definitions::load_with_overrides(None).unwrap();
        assert!(!definitions.is_empty());
        assert!(definitions
            .iter()
            .all(|definition| !definition.checks.is_empty()));
        for definition in &definitions {
            assert!(!definition.version.trim().is_empty());
        }
        let _ = repo;
    }

    #[test]
    fn update_does_not_require_a_model() {
        let project = tempfile::tempdir().unwrap();
        let cli = Cli::parse_from([
            "auditeur",
            "--home",
            project.path().to_str().unwrap(),
            "update",
            "--check-models",
        ]);
        // No model is configured, so the model section is skipped rather than
        // failing the command.
        assert_eq!(run(&cli, true).unwrap(), 0);
    }
}
