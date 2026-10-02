//! Machine-readable run artifacts.
//!
//! Written on every run. `manifest.json` describes the run, `findings.json` and
//! `evidence.json` carry the content. Each document repeats the schema version
//! and the run id, so a file that is copied out of its directory still says what
//! it is.

use std::path::{Path, PathBuf};

use auditeur_audit::AuditReport;
use auditeur_model::{Evidence, Finding};
use serde::Serialize;

use crate::ReportError;

/// Paths of the artifacts a run wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunArtifacts {
    /// `manifest.json`.
    pub manifest: PathBuf,
    /// `findings.json`.
    pub findings: PathBuf,
    /// `evidence.json`.
    pub evidence: PathBuf,
}

impl RunArtifacts {
    /// All artifact paths.
    pub fn all(&self) -> Vec<PathBuf> {
        vec![
            self.manifest.clone(),
            self.findings.clone(),
            self.evidence.clone(),
        ]
    }
}

/// Self-describing findings document.
#[derive(Debug, Serialize)]
struct FindingsDocument<'a> {
    audit_schema_version: &'a str,
    run_id: &'a str,
    finding_count: usize,
    findings: &'a [Finding],
}

/// Self-describing evidence document.
#[derive(Debug, Serialize)]
struct EvidenceDocument<'a> {
    audit_schema_version: &'a str,
    run_id: &'a str,
    evidence_count: usize,
    evidence: &'a [Evidence],
}

/// Write the three artifacts into `run_dir`.
pub fn write_run_artifacts(
    report: &AuditReport,
    run_dir: &Path,
) -> Result<Vec<PathBuf>, ReportError> {
    std::fs::create_dir_all(run_dir).map_err(|source| ReportError::CreateDir {
        path: run_dir.to_path_buf(),
        source,
    })?;

    let manifest_path = run_dir.join("manifest.json");
    let findings_path = run_dir.join("findings.json");
    let evidence_path = run_dir.join("evidence.json");

    write_json(&manifest_path, &report.manifest, "manifest")?;
    write_json(
        &findings_path,
        &FindingsDocument {
            audit_schema_version: &report.manifest.audit_schema_version,
            run_id: &report.manifest.run_id,
            finding_count: report.findings.len(),
            findings: &report.findings,
        },
        "findings",
    )?;
    write_json(
        &evidence_path,
        &EvidenceDocument {
            audit_schema_version: &report.manifest.audit_schema_version,
            run_id: &report.manifest.run_id,
            evidence_count: report.evidence.len(),
            evidence: &report.evidence,
        },
        "evidence",
    )?;

    Ok(vec![manifest_path, findings_path, evidence_path])
}

fn write_json<T: Serialize>(
    path: &Path,
    value: &T,
    document: &'static str,
) -> Result<(), ReportError> {
    let text = serde_json::to_string_pretty(value).map_err(|error| ReportError::Serialize {
        document,
        message: error.to_string(),
    })?;
    std::fs::write(path, text).map_err(|source| ReportError::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_config::AuditeurHome;
    use auditeur_model::RunManifest;

    fn repository_info() -> auditeur_model::RepositoryInfo {
        auditeur_model::RepositoryInfo {
            root: "/tmp/repo".to_string(),
            name: "repo".to_string(),
            git: None,
            fingerprint: auditeur_model::RepositoryFingerprint {
                digest: "abc".to_string(),
                files: 0,
                total_bytes: 0,
            },
        }
    }

    /// A minimal report, built without running an audit: the writer only needs
    /// the manifest and the two collections.
    fn report(run_id: &str) -> AuditReport {
        let manifest = RunManifest::new(run_id, repository_info());
        AuditReport {
            manifest,
            findings: Vec::new(),
            evidence: Vec::new(),
            plan: auditeur_audit::AuditPlan {
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
            repository_root: PathBuf::from("/tmp/repo"),
            read_only_verified: true,
        }
    }

    #[test]
    fn artifacts_are_written_and_self_describing() {
        let temp = tempfile::tempdir().unwrap();
        let paths = AuditeurHome::at(temp.path());
        let report = report("1700000000");
        let run_dir = paths.run_dir(&report.manifest.run_id);

        let written = write_run_artifacts(&report, &run_dir).unwrap();
        assert_eq!(written.len(), 3);
        for path in &written {
            assert!(path.is_file(), "missing {path:?}");
        }

        let findings: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(run_dir.join("findings.json")).unwrap())
                .unwrap();
        assert_eq!(findings["run_id"], "1700000000");
        assert_eq!(findings["finding_count"], 0);
        assert!(findings["audit_schema_version"].is_string());

        let manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(run_dir.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["run_id"], "1700000000");
        assert!(manifest["audited"].is_null() || manifest["repository"]["name"] == "repo");
    }

    #[test]
    fn writing_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let report = report("1");
        let run_dir = temp.path().join("runs/1");
        let first = write_run_artifacts(&report, &run_dir).unwrap();
        let second = write_run_artifacts(&report, &run_dir).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn artifact_paths_are_all_reported() {
        let artifacts = RunArtifacts {
            manifest: PathBuf::from("a"),
            findings: PathBuf::from("b"),
            evidence: PathBuf::from("c"),
        };
        assert_eq!(artifacts.all().len(), 3);
    }
}
