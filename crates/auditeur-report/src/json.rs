//! JSON report: the whole run in one document.
//!
//! The run artifacts already split the record across three files for a machine
//! that reads them from the run directory. This renderer exists for the other
//! case: a caller that wants one self-contained document (a CI job, a diff
//! between two audits, a test that asserts on a whole run).

use auditeur_audit::AuditReport;
use serde::Serialize;

use crate::{OutputFormat, ReportError, ReportRenderer};

/// One document containing manifest, findings and evidence.
#[derive(Debug, Serialize)]
struct Document<'a> {
    audit_schema_version: &'a str,
    run_id: &'a str,
    finding_count: usize,
    evidence_count: usize,
    limitation_count: usize,
    manifest: &'a auditeur_model::RunManifest,
    findings: &'a [auditeur_model::Finding],
    evidence: &'a [auditeur_model::Evidence],
}

/// Renders the report as JSON.
#[derive(Debug, Clone, Copy)]
pub struct JsonRenderer {
    pretty: bool,
}

impl Default for JsonRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonRenderer {
    /// A renderer that pretty-prints, for human inspection.
    pub fn new() -> Self {
        Self { pretty: true }
    }

    /// A renderer that emits compact JSON, for machines.
    pub fn compact() -> Self {
        Self { pretty: false }
    }
}

impl ReportRenderer for JsonRenderer {
    fn format(&self) -> OutputFormat {
        OutputFormat::Json
    }

    fn render(&self, report: &AuditReport) -> Result<String, ReportError> {
        let document = Document {
            audit_schema_version: &report.manifest.audit_schema_version,
            run_id: &report.manifest.run_id,
            finding_count: report.findings.len(),
            evidence_count: report.evidence.len(),
            limitation_count: report.manifest.limitations.len(),
            manifest: &report.manifest,
            findings: &report.findings,
            evidence: &report.evidence,
        };
        let serialize = |error: serde_json::Error| ReportError::Serialize {
            document: "report",
            message: error.to_string(),
        };
        if self.pretty {
            serde_json::to_string_pretty(&document).map_err(serialize)
        } else {
            serde_json::to_string(&document).map_err(serialize)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_audit::{AuditEngine, AuditOptions, AuditPlan};
    use auditeur_config::{AuditeurConfig, AuditeurHome};
    use std::fs;

    fn audit() -> AuditReport {
        let repo = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        fs::create_dir_all(repo.path().join("src")).unwrap();
        fs::write(
            repo.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        fs::write(repo.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();

        let mut config = AuditeurConfig::default();
        config.project.name = "demo".to_string();
        AuditEngine::run(&AuditOptions::new(
            repo.path(),
            AuditeurHome::at(project.path()),
            config,
        ))
        .unwrap()
    }

    #[test]
    fn json_is_a_single_self_describing_document() {
        let report = audit();
        let rendered = JsonRenderer::new().render(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(value["run_id"], report.manifest.run_id);
        assert_eq!(value["finding_count"], report.findings.len());
        assert!(value["manifest"]["audit_schema_version"].is_string());
        assert!(value["findings"].is_array());
        assert!(value["evidence"].is_array());
        assert_eq!(value["limitation_count"], report.manifest.limitations.len());
    }

    #[test]
    fn compact_output_is_valid_json_too() {
        let report = audit();
        let rendered = JsonRenderer::compact().render(&report).unwrap();
        assert!(!rendered.contains("\n  "));
        serde_json::from_str::<serde_json::Value>(&rendered).unwrap();
    }

    #[test]
    fn the_document_is_parseable_by_a_consumer_that_ignores_the_schema() {
        let empty = AuditReport {
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
        };
        let rendered = JsonRenderer::compact().render(&empty).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["finding_count"], 0);
    }
}
