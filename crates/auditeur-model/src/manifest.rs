//! The run manifest — the machine-readable record of what an audit did.
//!
//! The manifest is a first-class artifact, not a log. It is written on every
//! run, whether or not a report was produced, and it records everything needed
//! to judge how much weight a result deserves: what was inspected, what was
//! skipped and why, which tools ran, which model was consulted, and what the
//! audit could not do.

use serde::{Deserialize, Serialize};

use crate::category::AuditCategory;
use crate::finding::{Finding, Status};
use crate::language::Language;
use crate::version::{AUDITEUR_VERSION, AUDIT_SCHEMA_VERSION};

/// State of the audited Git repository at the time of the audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitState {
    /// Full commit hash of `HEAD`, if the repository has any commit.
    pub head_commit: Option<String>,
    /// Branch name, or a detached-head marker.
    pub branch: Option<String>,
    /// `git describe --tags --always` output, when available.
    pub describe: Option<String>,
    /// Origin remote URL, with any embedded credentials stripped.
    pub remote: Option<String>,
    /// Whether the working tree has modifications or untracked files.
    pub dirty: bool,
    /// Number of tracked files reported as modified or deleted.
    pub modified_files: u32,
    /// Number of untracked files.
    pub untracked_files: u32,
}

impl GitState {
    /// Whether the working tree matches the recorded commit.
    pub fn is_clean(&self) -> bool {
        !self.dirty
    }
}

/// A digest of the audited tree, used to detect modification.
///
/// The fingerprint is computed before and after a run. If the two differ, the
/// read-only guarantee has been violated, which is a defect to be fixed rather
/// than a warning to be printed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryFingerprint {
    /// SHA-256 over the ordered (path, size, mtime) triples of inspected files.
    pub digest: String,
    /// Number of entries contributing to `digest`.
    pub files: u32,
    /// Total bytes of the contributing entries.
    pub total_bytes: u64,
}

/// Identity and location of the audited repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryInfo {
    /// Absolute path of the audited root.
    pub root: String,
    /// Directory name of the audited root.
    pub name: String,
    /// Git metadata, absent when the path is not a Git repository.
    pub git: Option<GitState>,
    /// Fingerprint taken before analysis.
    pub fingerprint: RepositoryFingerprint,
}

impl RepositoryInfo {
    /// The source-folder component used in the report path and report header.
    pub fn source_folder(&self) -> &str {
        &self.name
    }
}

/// Which model produced AI-assisted findings, and its integrity data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRef {
    /// Backend identifier, e.g. `openai-compatible`.
    pub backend: String,
    /// Model identifier as reported by the backend.
    pub name: String,
    /// Model version, when the backend reports one.
    pub version: Option<String>,
    /// Checksum of the model artefact, when known locally.
    pub checksum: Option<String>,
}

impl ModelRef {
    /// Placeholder used when no model was consulted.
    pub fn not_used() -> Self {
        Self {
            backend: "none".to_string(),
            name: "none".to_string(),
            version: None,
            checksum: None,
        }
    }
}

/// Reference to an audit definition included in a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionRef {
    /// Definition id, e.g. `security`.
    pub id: String,
    /// Definition version, e.g. `1.0.0`.
    pub version: String,
}

/// What the audit intended to cover and what it actually ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditScope {
    /// Enabled categories.
    pub categories: Vec<AuditCategory>,
    /// Definitions that were loaded.
    pub definitions: Vec<DefinitionRef>,
    /// Number of checks selected by the planner.
    pub checks_selected: u32,
    /// Number of checks that completed without error.
    pub checks_executed: u32,
}

/// Why a path was not inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Exceeded the per-file size limit.
    TooLarge,
    /// Detected as binary content.
    Binary,
    /// Directory or file symlink; not followed.
    Symlink,
    /// Matched the ignored-directory list.
    IgnoredDirectory,
    /// Matched the ignored-file list.
    IgnoredFile,
    /// Deeper than the configured maximum depth.
    DepthExceeded,
    /// Unreadable due to permissions or I/O error.
    Unreadable,
    /// The file-count limit was reached before this entry.
    FileCountLimit,
    /// The total-bytes limit was reached before this entry.
    TotalSizeLimit,
    /// Escaped the repository root after canonicalisation.
    OutsideRoot,
}

impl SkipReason {
    /// Stable identifier for the manifest.
    pub fn id(self) -> &'static str {
        match self {
            SkipReason::TooLarge => "too_large",
            SkipReason::Binary => "binary",
            SkipReason::Symlink => "symlink",
            SkipReason::IgnoredDirectory => "ignored_directory",
            SkipReason::IgnoredFile => "ignored_file",
            SkipReason::DepthExceeded => "depth_exceeded",
            SkipReason::Unreadable => "unreadable",
            SkipReason::FileCountLimit => "file_count_limit",
            SkipReason::TotalSizeLimit => "total_size_limit",
            SkipReason::OutsideRoot => "outside_root",
        }
    }

    /// Human-readable explanation used in the report's limitations section.
    pub fn description(self) -> &'static str {
        match self {
            SkipReason::TooLarge => "larger than the configured per-file limit",
            SkipReason::Binary => "detected as binary content",
            SkipReason::Symlink => "symlink, not followed",
            SkipReason::IgnoredDirectory => "inside an ignored directory",
            SkipReason::IgnoredFile => "matched the ignored-file list",
            SkipReason::DepthExceeded => "deeper than the configured depth limit",
            SkipReason::Unreadable => "unreadable",
            SkipReason::FileCountLimit => "skipped after the file-count limit was reached",
            SkipReason::TotalSizeLimit => "skipped after the total-size limit was reached",
            SkipReason::OutsideRoot => "resolves outside the repository root",
        }
    }
}

/// A path that was not inspected, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkipRecord {
    /// Repository-relative path.
    pub path: String,
    /// Why it was skipped.
    pub reason: SkipReason,
    /// Additional detail, e.g. the offending size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// An external command executed during the audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolExecution {
    /// Program name (argv\[0\]).
    pub program: String,
    /// Arguments, exactly as passed.
    pub args: Vec<String>,
    /// Exit code, absent when the process was killed by a signal or timed out.
    pub exit_code: Option<i32>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Whether captured output was truncated at the size cap.
    pub truncated: bool,
}

/// Something the audit could not do, recorded instead of failing silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limitation {
    /// Stable machine-readable code, e.g. `backend_unreachable`.
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
}

impl Limitation {
    /// Create a limitation record.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Finding counts by status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingCounts {
    /// Findings with status `PASS`.
    pub pass: u32,
    /// Findings with status `INFO`.
    pub info: u32,
    /// Findings with status `WARN`.
    pub warn: u32,
    /// Findings with status `FAIL`.
    pub fail: u32,
}

impl FindingCounts {
    /// Count findings by status.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut counts = Self::default();
        for finding in findings {
            match finding.status {
                Status::Pass => counts.pass += 1,
                Status::Info => counts.info += 1,
                Status::Warn => counts.warn += 1,
                Status::Fail => counts.fail += 1,
            }
        }
        counts
    }

    /// Total number of findings.
    pub fn total(&self) -> u32 {
        self.pass + self.info + self.warn + self.fail
    }

    /// Number of findings that represent a violation (`WARN` + `FAIL`).
    pub fn violations(&self) -> u32 {
        self.warn + self.fail
    }
}

/// The resource policy an audit ran under.
///
/// Recorded in the manifest because it shapes the evidence: a run that stopped
/// at 20 000 files did not inspect the rest, and a reader comparing two reports
/// must be able to see that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitPolicy {
    /// Per-file size limit in bytes.
    pub max_file_bytes: u64,
    /// Maximum number of files in the repository model.
    pub max_files: u32,
    /// Total-bytes limit.
    pub max_total_bytes: u64,
    /// Maximum directory depth.
    pub max_depth: usize,
    /// Whether directory symlinks were followed.
    pub follow_symlinks: bool,
    /// Number of directory names excluded.
    pub ignored_directories: u32,
    /// Number of file names excluded.
    pub ignored_files: u32,
}

/// The complete record of an audit run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunManifest {
    /// Auditeur build version.
    pub auditeur_version: String,
    /// Version of this schema.
    pub audit_schema_version: String,
    /// Run identifier, equal to the run directory name.
    pub run_id: String,
    /// Start time, RFC 3339 / UTC.
    pub started_at: String,
    /// End time, RFC 3339 / UTC.
    pub finished_at: String,
    /// Unix timestamp of the run, used in the report filename.
    pub unix_timestamp: i64,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Whether AI-assisted analysis was enabled for this run.
    pub ai_enabled: bool,
    /// Model consulted, or [`ModelRef::not_used`].
    pub model: ModelRef,
    /// What was audited.
    pub repository: RepositoryInfo,
    /// What the audit covered.
    pub scope: AuditScope,
    /// Languages detected and included.
    pub detected_languages: Vec<Language>,
    /// Number of files included in the repository model.
    pub files_inspected: u32,
    /// Number of bytes included in the repository model.
    pub bytes_inspected: u64,
    /// Paths excluded from inspection, with reasons.
    pub skipped: Vec<SkipRecord>,
    /// External commands executed.
    pub tools_executed: Vec<ToolExecution>,
    /// Finding counts by status.
    pub counts: FindingCounts,
    /// Explicit statement of what this run could not do.
    pub limitations: Vec<Limitation>,
    /// Resource policy in effect, when the engine recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<LimitPolicy>,
    /// Absolute path of the generated report, when one was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_path: Option<String>,
}

impl RunManifest {
    /// Start a manifest for a run.
    ///
    /// When `run_id` is a Unix timestamp (which is what the engine supplies), it
    /// is also recorded as `unix_timestamp`, so the run directory
    /// (`runs/<run-id>`) and the report file name (`audit_<timestamp>.md`) agree.
    /// Otherwise the current time is recorded.
    pub fn new(run_id: impl Into<String>, repository: RepositoryInfo) -> Self {
        let run_id = run_id.into();
        let now = chrono::Utc::now();
        let unix_timestamp = run_id.parse::<i64>().unwrap_or_else(|_| now.timestamp());
        Self {
            auditeur_version: AUDITEUR_VERSION.to_string(),
            audit_schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            run_id,
            started_at: now.to_rfc3339(),
            finished_at: now.to_rfc3339(),
            unix_timestamp,
            duration_ms: 0,
            ai_enabled: false,
            model: ModelRef::not_used(),
            repository,
            scope: AuditScope {
                categories: Vec::new(),
                definitions: Vec::new(),
                checks_selected: 0,
                checks_executed: 0,
            },
            detected_languages: Vec::new(),
            files_inspected: 0,
            bytes_inspected: 0,
            skipped: Vec::new(),
            tools_executed: Vec::new(),
            counts: FindingCounts::default(),
            limitations: Vec::new(),
            limits: None,
            report_path: None,
        }
    }

    /// Record a limitation, ignoring exact duplicates.
    pub fn add_limitation(&mut self, code: impl Into<String>, message: impl Into<String>) {
        let code = code.into();
        if self
            .limitations
            .iter()
            .any(|existing| existing.code == code)
        {
            return;
        }
        self.limitations.push(Limitation::new(code, message));
    }

    /// Finish the run: stamp the end time, duration and finding counts.
    pub fn finish(&mut self, started_unix_millis: i128, findings: &[Finding]) {
        let now = chrono::Utc::now();
        self.finished_at = now.to_rfc3339();
        self.duration_ms = (now.timestamp_millis() as i128 - started_unix_millis).max(0) as u64;
        self.counts = FindingCounts::from_findings(findings);
    }

    /// Number of skipped paths with the given reason.
    pub fn skipped_count(&self, reason: SkipReason) -> u32 {
        self.skipped
            .iter()
            .filter(|record| record.reason == reason)
            .count() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    fn repository() -> RepositoryInfo {
        RepositoryInfo {
            root: "/tmp/repo".to_string(),
            name: "repo".to_string(),
            git: None,
            fingerprint: RepositoryFingerprint {
                digest: "deadbeef".to_string(),
                files: 0,
                total_bytes: 0,
            },
        }
    }

    #[test]
    fn counts_partition_findings_by_status() {
        let findings = vec![
            Finding::deterministic(
                "d",
                "c",
                AuditCategory::Testing,
                Severity::Low,
                Status::Pass,
                "a",
                "t",
                "d",
            ),
            Finding::deterministic(
                "d",
                "c",
                AuditCategory::Testing,
                Severity::Low,
                Status::Fail,
                "b",
                "t",
                "d",
            ),
            Finding::deterministic(
                "d",
                "c",
                AuditCategory::Testing,
                Severity::Low,
                Status::Warn,
                "c",
                "t",
                "d",
            ),
        ];
        let counts = FindingCounts::from_findings(&findings);
        assert_eq!(counts.total(), 3);
        assert_eq!(counts.violations(), 2);
        assert_eq!(counts.pass, 1);
        assert_eq!(counts.info, 0);
    }

    #[test]
    fn limitations_deduplicate_by_code() {
        let mut manifest = RunManifest::new("1700000000", repository());
        manifest.add_limitation("no_backend", "no backend configured");
        manifest.add_limitation("no_backend", "different message, same code");
        assert_eq!(manifest.limitations.len(), 1);
        manifest.add_limitation("other", "second code");
        assert_eq!(manifest.limitations.len(), 2);
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let mut manifest = RunManifest::new("1700000000", repository());
        manifest.detected_languages = vec![Language::Rust];
        manifest.skipped.push(SkipRecord {
            path: "vendor/x.bin".to_string(),
            reason: SkipReason::Binary,
            detail: None,
        });
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let parsed: RunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, manifest);
        assert_eq!(manifest.skipped_count(SkipReason::Binary), 1);
        assert!(json.contains("\"audit_schema_version\""));
    }

    #[test]
    fn schema_and_auditeur_versions_in_manifest() {
        let manifest = RunManifest::new("1", repository());
        assert_eq!(manifest.auditeur_version, AUDITEUR_VERSION);
        assert_eq!(manifest.audit_schema_version, AUDIT_SCHEMA_VERSION);
    }
}
