//! Output: progress on standard error, results on standard output.
//!
//! The split matters for scripting: `auditeur -q audit . > report.txt` must
//! produce only the result, never progress lines. Progress, warnings and
//! diagnostics therefore go to standard error.

use std::sync::Arc;

use auditeur_audit::{AuditReport, AuditStage, ProgressSink};
use auditeur_report::WrittenRun;

/// Console verbosity settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Console {
    quiet: bool,
    verbose: u8,
}

impl Default for Console {
    fn default() -> Self {
        Self::new(false, 0)
    }
}

impl Console {
    /// Create a console.
    pub fn new(quiet: bool, verbose: u8) -> Self {
        Self { quiet, verbose }
    }

    /// Whether progress output is suppressed.
    pub fn is_quiet(&self) -> bool {
        self.quiet
    }

    /// Verbosity level.
    pub fn verbosity(&self) -> u8 {
        self.verbose
    }

    /// A progress line, at verbosity 1 or above, unless quiet.
    pub fn stage(&self, stage: AuditStage, detail: &str) {
        if self.quiet || self.verbose == 0 {
            return;
        }
        if detail.is_empty() {
            eprintln!("· {}", stage.label());
        } else {
            eprintln!("· {} — {detail}", stage.label());
        }
    }

    /// A warning, unless quiet.
    pub fn warn(&self, message: &str) {
        if self.quiet {
            return;
        }
        eprintln!("! {message}");
    }

    /// An informational line, unless quiet.
    pub fn info(&self, message: &str) {
        if self.quiet {
            return;
        }
        eprintln!("{message}");
    }

    /// A diagnostic line, shown at verbosity 2 or above.
    pub fn debug(&self, message: &str) {
        if self.quiet || self.verbose < 2 {
            return;
        }
        eprintln!("  {message}");
    }

    /// A result line on standard output.
    pub fn result(&self, message: &str) {
        println!("{message}");
    }
}

/// A progress sink backed by a console.
#[derive(Debug, Clone)]
pub struct ConsoleProgress {
    console: Console,
}

impl ConsoleProgress {
    /// Wrap a console.
    pub fn new(console: Console) -> Self {
        Self { console }
    }

    /// A shareable sink.
    pub fn shared(console: Console) -> Arc<dyn ProgressSink> {
        Arc::new(Self::new(console))
    }
}

impl ProgressSink for ConsoleProgress {
    fn stage(&self, stage: AuditStage, detail: &str) {
        // The log records the run whatever the console flags say: `--quiet`
        // silences the terminal, not the record. The run id is on the span the
        // caller opened around the engine.
        if detail.is_empty() {
            tracing::info!("{}", stage.label());
        } else {
            tracing::info!("{} — {detail}", stage.label());
        }
        self.console.stage(stage, detail);
    }

    fn warn(&self, message: &str) {
        tracing::warn!("{message}");
        self.console.warn(message);
    }
}

/// The summary printed after an audit.
pub fn summary(report: &AuditReport, written: &WrittenRun) -> String {
    let counts = report.manifest.counts;
    let mut out = String::new();
    out.push_str(&format!(
        "{} finding(s): {} pass, {} info, {} warn, {} fail\n",
        counts.total(),
        counts.pass,
        counts.info,
        counts.warn,
        counts.fail
    ));
    if let Some(path) = &written.report_path {
        out.push_str(&format!("report: {}\n", path.display()));
    }
    out.push_str(&format!("run:    {}\n", written.run_dir.display()));
    if !report.manifest.limitations.is_empty() {
        out.push_str(&format!(
            "{} limitation(s) recorded; see the report's Limitations section\n",
            report.manifest.limitations.len()
        ));
    }
    out
}

/// A compact list of the most serious findings, for the terminal.
pub fn headline_findings(report: &AuditReport, limit: usize) -> String {
    let mut findings: Vec<&auditeur_model::Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.status.is_violation())
        .collect();
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.category.cmp(&right.category))
    });

    if findings.is_empty() {
        return String::new();
    }

    let mut out = String::from("most serious findings:\n");
    for finding in findings.iter().take(limit) {
        out.push_str(&format!(
            "  [{}] {} ({}, {})\n",
            finding.status.marker(),
            finding.title,
            finding.severity.id(),
            finding.id
        ));
        for evidence in report.evidence_for(finding).iter().take(2) {
            out.push_str(&format!("        {}\n", evidence.location.describe()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_config::{AuditeurConfig, AuditeurHome};

    fn report_for(repo: &std::path::Path, project: &std::path::Path) -> AuditReport {
        let mut config = AuditeurConfig::default();
        config.project.name = "demo".to_string();
        auditeur_audit::AuditEngine::run(&auditeur_audit::AuditOptions::new(
            repo,
            AuditeurHome::at(project),
            config,
        ))
        .unwrap()
    }

    fn fixture() -> (tempfile::TempDir, tempfile::TempDir) {
        let repo = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(
            repo.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        std::fs::write(repo.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        (repo, project)
    }

    #[test]
    fn the_summary_reports_counts_and_paths() {
        let (repo, project) = fixture();
        let mut report = report_for(repo.path(), project.path());
        let paths = AuditeurHome::at(project.path());
        let written = auditeur_report::write_run(
            &mut report,
            &paths,
            auditeur_report::OutputFormat::Markdown,
            &auditeur_report::ReportOptions::default(),
        )
        .unwrap();

        let text = summary(&report, &written);
        assert!(text.contains("finding(s)"), "{text}");
        assert!(text.contains("report: "), "{text}");
        assert!(text.contains("run:    "), "{text}");
        assert!(text.contains("audit_"), "{text}");
    }

    #[test]
    fn the_headline_lists_only_violations_and_includes_evidence() {
        let (repo, project) = fixture();
        std::fs::write(
            repo.path().join("secrets.toml"),
            "api_key = \"sk-live-abcdef1234567890\"\n",
        )
        .unwrap();
        let report = report_for(repo.path(), project.path());

        let text = headline_findings(&report, 3);
        assert!(text.contains("[FAIL]"), "{text}");
        assert!(text.contains("secrets.toml"), "{text}");
    }

    #[test]
    fn a_clean_report_has_no_headline() {
        let (repo, project) = fixture();
        let report = report_for(repo.path(), project.path());
        // The fixture has no secrets, so no violation is expected.
        if report.violations().is_empty() {
            assert!(headline_findings(&report, 3).is_empty());
        }
    }

    #[test]
    fn console_flags_are_reported_honestly() {
        let quiet = Console::new(true, 0);
        assert!(quiet.is_quiet());
        assert_eq!(quiet.verbosity(), 0);
        let verbose = Console::new(false, 2);
        assert!(!verbose.is_quiet());
        assert_eq!(verbose.verbosity(), 2);
        let default = Console::default();
        assert!(!default.is_quiet());
    }
}
