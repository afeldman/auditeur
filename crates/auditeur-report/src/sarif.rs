//! SARIF output: declared, not implemented.
//!
//! SARIF is the right interchange format for feeding findings into code-scanning
//! tooling, and it is a target for the next iteration. It is *not* implemented
//! here, and this module deliberately fails rather than emitting a document that
//! claims to be SARIF without conforming to the schema: a malformed SARIF file
//! silently breaks the consumer that ingests it, which is worse than an explicit
//! error.
//!
//! The work required is a mapping from the Auditeur model to SARIF 2.1.0:
//!
//! * `run.tool.driver` from [`auditeur_model::RunManifest::auditeur_version`].
//! * `run.invocations[0]` from the manifest's repository and limits section.
//! * one `reportingDescriptor` per check id, with `properties.severity`.
//! * one `result` per finding: `ruleId`, `level` from status/severity,
//!   `message.text` from title and description, and `locations` from each
//!   evidence reference — the piece that makes Auditeur's evidence model fit
//!   SARIF unusually well, since every finding already carries structured
//!   locations rather than prose.

use auditeur_audit::AuditReport;

use crate::{OutputFormat, ReportError, ReportRenderer};

/// Renders SARIF. Not implemented yet; see the module documentation.
#[derive(Debug, Clone, Copy, Default)]
pub struct SarifRenderer;

impl SarifRenderer {
    /// Create the renderer.
    pub fn new() -> Self {
        Self
    }
}

impl ReportRenderer for SarifRenderer {
    fn format(&self) -> OutputFormat {
        OutputFormat::Sarif
    }

    fn render(&self, _report: &AuditReport) -> Result<String, ReportError> {
        Err(ReportError::NotImplemented { format: "sarif" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_audit::AuditPlan;

    fn report() -> AuditReport {
        AuditReport {
            manifest: auditeur_model::RunManifest::new(
                "1",
                auditeur_model::RepositoryInfo {
                    root: "/tmp/x".to_string(),
                    name: "x".to_string(),
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
            repository_root: std::path::PathBuf::from("/tmp/x"),
            read_only_verified: false,
        }
    }

    #[test]
    fn sarif_reports_that_it_is_not_implemented_rather_than_faking_a_document() {
        let error = SarifRenderer::new().render(&report()).unwrap_err();
        match error {
            ReportError::NotImplemented { format } => assert_eq!(format, "sarif"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn the_format_is_still_declared() {
        assert_eq!(SarifRenderer::new().format(), OutputFormat::Sarif);
    }
}
