//! Reporting: run artifacts and human-readable reports.
//!
//! Two outputs, deliberately different in kind:
//!
//! * **Run artifacts** (`runs/<run-id>/manifest.json`, `findings.json`,
//!   `evidence.json`) are the machine-readable record. They are written on every
//!   run, whether or not a report is requested. A report is a *view*; the
//!   artifacts are the *record*.
//! * **The Markdown report** is the document a human reads
//!   (`<source-folder>/audit_<unix-timestamp>.md`).
//!
//! [`ReportRenderer`] is the extension point for further formats. JSON is
//! implemented because the model is already serialisable; SARIF is declared and
//! returns an explicit "not implemented" error rather than a placeholder file,
//! because a SARIF document that is not valid SARIF is worse than no document.

pub mod artifacts;
pub mod json;
pub mod markdown;
pub mod sarif;

use std::path::PathBuf;

use auditeur_audit::AuditReport;
use auditeur_config::AuditeurHome;

pub use artifacts::{write_run_artifacts, RunArtifacts};
pub use json::JsonRenderer;
pub use markdown::{MarkdownRenderer, ReportOptions};
pub use sarif::SarifRenderer;

/// A report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable Markdown.
    Markdown,
    /// A single JSON document containing the manifest, findings and evidence.
    Json,
    /// SARIF, the static-analysis interchange format. Not implemented yet.
    Sarif,
}

impl OutputFormat {
    /// Stable identifier used on the command line.
    pub fn id(self) -> &'static str {
        match self {
            OutputFormat::Markdown => "markdown",
            OutputFormat::Json => "json",
            OutputFormat::Sarif => "sarif",
        }
    }

    /// File extension, without the dot.
    pub fn extension(self) -> &'static str {
        match self {
            OutputFormat::Markdown => "md",
            OutputFormat::Json => "json",
            OutputFormat::Sarif => "sarif",
        }
    }

    /// All formats, including the ones that are only declared.
    pub const ALL: [OutputFormat; 3] = [
        OutputFormat::Markdown,
        OutputFormat::Json,
        OutputFormat::Sarif,
    ];
}

impl std::str::FromStr for OutputFormat {
    type Err = ReportError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            other => Err(ReportError::UnknownFormat(other.to_string())),
        }
    }
}

/// Errors raised while rendering or writing a report.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// The requested format is not implemented.
    #[error("the {format} output format is not implemented yet")]
    NotImplemented {
        /// Format that was requested.
        format: &'static str,
    },

    /// The format name was not recognised.
    #[error("unknown output format '{0}'")]
    UnknownFormat(String),

    /// The document could not be serialised.
    #[error("cannot serialise the {document} document: {message}")]
    Serialize {
        /// Which document failed.
        document: &'static str,
        /// Serialiser message.
        message: String,
    },

    /// A file could not be written.
    #[error("cannot write {path}: {source}")]
    Write {
        /// Offending path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A directory could not be created.
    #[error("cannot create directory {path}: {source}")]
    CreateDir {
        /// Offending directory.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Renders a report in one format.
pub trait ReportRenderer {
    /// The format this renderer produces.
    fn format(&self) -> OutputFormat;

    /// Render an audit report to text.
    fn render(&self, report: &AuditReport) -> Result<String, ReportError>;
}

/// What a written run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenRun {
    /// Directory holding the machine-readable artifacts.
    pub run_dir: PathBuf,
    /// Files written inside it.
    pub artifact_files: Vec<PathBuf>,
    /// The report file, when one was written.
    pub report_path: Option<PathBuf>,
}

/// Write the artifacts for a run, and optionally a report in `format`.
///
/// The report path is recorded in the manifest before it is written, so the
/// record points at the document it describes.
pub fn write_run(
    report: &mut AuditReport,
    paths: &AuditeurHome,
    format: OutputFormat,
    options: &ReportOptions,
) -> Result<WrittenRun, ReportError> {
    let source_folder = report.manifest.repository.source_folder().to_string();
    let report_path = paths.report_file(&source_folder, report.manifest.unix_timestamp);

    let rendered = match format {
        OutputFormat::Markdown => {
            let renderer = MarkdownRenderer::new(options.clone());
            Some((report_path.clone(), renderer.render(report)?))
        }
        OutputFormat::Json => {
            let renderer = JsonRenderer::new();
            Some((report_path.with_extension("json"), renderer.render(report)?))
        }
        // Declared but unimplemented: fail loudly rather than write a document
        // that claims a format it does not satisfy.
        OutputFormat::Sarif => return Err(SarifRenderer::new().render(report).unwrap_err()),
    };

    if let Some((path, _)) = &rendered {
        report.manifest.report_path = Some(path.display().to_string());
    }

    let run_dir = paths.run_dir(&report.manifest.run_id);
    let artifact_files = artifacts::write_run_artifacts(report, &run_dir)?;

    let report_path = match rendered {
        Some((path, contents)) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|source| ReportError::CreateDir {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            std::fs::write(&path, contents).map_err(|source| ReportError::Write {
                path: path.clone(),
                source,
            })?;
            Some(path)
        }
        None => None,
    };

    Ok(WrittenRun {
        run_dir,
        artifact_files,
        report_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_round_trip_through_their_ids() {
        for format in OutputFormat::ALL {
            assert_eq!(format.id().parse::<OutputFormat>().unwrap(), format);
            assert!(!format.extension().is_empty());
        }
        assert_eq!(
            "MD".parse::<OutputFormat>().unwrap(),
            OutputFormat::Markdown
        );
        assert!("pdf".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn sarif_reports_that_it_is_not_implemented() {
        let report = minimal_report();
        let error = SarifRenderer::new().render(&report).unwrap_err();
        match error {
            ReportError::NotImplemented { format } => assert_eq!(format, "sarif"),
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn an_unimplemented_format_fails_without_writing_anything() {
        let temp = tempfile::tempdir().unwrap();
        let paths = AuditeurHome::at(temp.path());
        let mut report = minimal_report();
        let error = write_run(
            &mut report,
            &paths,
            OutputFormat::Sarif,
            &ReportOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(error, ReportError::NotImplemented { .. }));
        assert!(
            !paths.runs_dir().exists(),
            "nothing may be written on failure"
        );
    }

    /// A report with no findings, for tests that exercise the writers.
    fn minimal_report() -> AuditReport {
        use auditeur_audit::AuditPlan;
        AuditReport {
            manifest: auditeur_model::RunManifest::new(
                "1700000000",
                auditeur_model::RepositoryInfo {
                    root: "/tmp/repo".to_string(),
                    name: "repo".to_string(),
                    git: None,
                    fingerprint: auditeur_model::RepositoryFingerprint {
                        digest: "d".to_string(),
                        files: 0,
                        total_bytes: 0,
                    },
                },
            ),
            findings: Vec::new(),
            evidence: Vec::new(),
            plan: AuditPlan {
                definitions: Vec::new(),
                checks: Vec::new(),
                tasks: Vec::new(),
                skipped: Vec::new(),
                categories: Vec::new(),
                ai_enabled: false,
            },
            analyses: Vec::new(),
            git: None,
            ai: None,
            repository_root: std::path::PathBuf::from("/tmp/repo"),
            read_only_verified: true,
        }
    }

    #[test]
    fn a_markdown_run_writes_artifacts_and_a_report_that_points_at_each_other() {
        let temp = tempfile::tempdir().unwrap();
        let paths = AuditeurHome::at(temp.path());
        let mut report = minimal_report();
        let written = write_run(
            &mut report,
            &paths,
            OutputFormat::Markdown,
            &ReportOptions::default(),
        )
        .unwrap();

        let report_path = written.report_path.expect("a report was requested");
        assert!(report_path.is_file());
        assert_eq!(
            report_path.file_name().unwrap().to_string_lossy(),
            "audit_1700000000.md"
        );
        assert_eq!(written.run_dir, paths.run_dir("1700000000"));
        assert_eq!(written.artifact_files.len(), 3);
        assert_eq!(
            report.manifest.report_path.as_deref(),
            Some(report_path.to_string_lossy().as_ref())
        );

        // The recorded manifest must name the report that was actually written.
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(written.run_dir.join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manifest["report_path"].as_str(),
            Some(report_path.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn a_json_run_writes_a_json_report() {
        let temp = tempfile::tempdir().unwrap();
        let paths = AuditeurHome::at(temp.path());
        let mut report = minimal_report();
        let written = write_run(
            &mut report,
            &paths,
            OutputFormat::Json,
            &ReportOptions::default(),
        )
        .unwrap();
        let path = written.report_path.unwrap();
        assert_eq!(path.extension().unwrap(), "json");
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["run_id"], "1700000000");
    }
}
