//! `auditeur [PATH]` and `auditeur audit <PATH>`.
//!
//! The command is thin by design: resolve configuration, build a backend if one
//! is configured, run the engine, write the report. Everything interesting
//! happens in the crates below, which is what makes the engine usable from the
//! TUI and from a future desktop front-end without change.

use std::path::Path;
use std::sync::Arc;

use auditeur_audit::{AuditEngine, AuditOptions};
use auditeur_inference::backends;
use auditeur_report::{self as report, OutputFormat, ReportRenderer};

use crate::cli::Cli;
use crate::error::CliError;
use crate::output::{self, ConsoleProgress};
use crate::resolve::{self, Resolved};

/// Seconds since the Unix epoch, the run-id convention the engine also uses.
fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Audit a repository.
pub fn run(cli: &Cli, target: &Path) -> Result<u8, CliError> {
    let resolved = resolve::resolve(cli, target)?;
    audit_resolved(&resolved, cli)
}

/// Audit using an already resolved configuration.
pub fn audit_resolved(resolved: &Resolved, cli: &Cli) -> Result<u8, CliError> {
    let console = resolved.console;

    // A usage error must not leave state behind: the target is validated before
    // the logger creates the first directory.
    if !resolved.source_path.exists() {
        return Err(CliError::Usage(format!(
            "repository {} does not exist",
            resolved.source_path.display()
        )));
    }
    if !resolved.source_path.is_dir() {
        return Err(CliError::Usage(format!(
            "{} is not a directory",
            resolved.source_path.display()
        )));
    }

    // Held for the whole command: dropping the guard stops the log writer.
    let _logging = crate::start_logging(resolved);

    for note in &resolved.notes {
        console.info(note);
    }

    for warning in &resolved.loaded.warnings {
        console.warn(warning);
    }
    for override_name in &resolved.loaded.env_overrides {
        console.debug(&format!("environment override applied: {override_name}"));
    }
    if !resolved.loaded.is_configured() {
        console.info(
            "no configuration found; using defaults. Run `auditeur setup` to choose a model and scope.",
        );
    }

    // A backend that cannot be built is a configuration error, not an outage:
    // the user asked for a model and the settings cannot produce one.
    let backend = if resolved.enable_ai {
        let key = resolved.config().model.api_key();
        let backend = backends::build(&resolved.config().model, key)
            .map_err(|error| CliError::Inference(error.to_string()))?;
        console.debug(&format!(
            "backend {} for model {}",
            backend.id(),
            backend.model()
        ));
        Some(Arc::from(backend))
    } else {
        None
    };

    let mut options = AuditOptions::new(
        resolved.source_path.clone(),
        resolved.home.clone(),
        resolved.config().clone(),
    );
    options.enable_ai = resolved.enable_ai;
    options.backend = backend;
    options.verify_read_only = resolved.verify_read_only;
    options.progress = ConsoleProgress::shared(console);

    // The run id is decided here rather than inside the engine so that every line
    // of the run's log carries it, including the first. The engine records the
    // same string in the manifest, so a log line and a run directory can be
    // matched by eye.
    let run_id = unix_timestamp().to_string();
    let span = tracing::info_span!("audit", run_id = %run_id);
    let _entered = span.enter();
    tracing::info!(
        repository = %resolved.source_path.display(),
        model_assisted = resolved.enable_ai,
        "audit started"
    );
    options.run_id = Some(run_id.clone());

    let mut audit = AuditEngine::run(&options)?;
    tracing::info!(
        findings = audit.findings.len(),
        violations = audit.violations().len(),
        "audit finished"
    );

    let written = report::write_run(
        &mut audit,
        &resolved.home,
        resolved.format,
        &resolved.report_options,
    )?;

    tracing::debug!(
        report = ?written.report_path.as_ref().map(|path| path.display().to_string()),
        run_dir = %written.run_dir.display(),
        "artifacts written"
    );
    console.result(&output::summary(&audit, &written));
    let headline = output::headline_findings(&audit, 5);
    if !headline.is_empty() {
        console.result(headline.trim_end());
    }

    if cli.print {
        // Print the same document that was written, so a pipeline can consume it
        // without reading the file back.
        let rendered = match resolved.format {
            OutputFormat::Json => report::JsonRenderer::new().render(&audit)?,
            OutputFormat::Markdown => {
                report::MarkdownRenderer::new(resolved.report_options.clone()).render(&audit)?
            }
            // Declared, not implemented: fail loudly rather than print a
            // document that claims a format it does not satisfy.
            OutputFormat::Sarif => {
                return Err(CliError::Report(report::ReportError::NotImplemented {
                    format: "sarif",
                }))
            }
        };
        console.result(&rendered);
    }

    Ok(audit.exit_code(resolved.fail_threshold) as u8)
}

/// Audit straight to the terminal interface, for a `--tui` flag in a later
/// iteration. Kept here as the single place a front-end would hook in, so the
/// engine does not have to grow when that flag lands.
pub fn audit_with_tui(resolved: &Resolved, options: AuditOptions) -> Result<u8, CliError> {
    let mut audit = auditeur_tui::run_audit_screen(options)?;
    let written = report::write_run(
        &mut audit,
        &resolved.home,
        resolved.format,
        &resolved.report_options,
    )?;
    resolved.console.result(&output::summary(&audit, &written));
    Ok(audit.exit_code(resolved.fail_threshold) as u8)
}
