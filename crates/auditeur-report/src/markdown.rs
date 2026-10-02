//! The Markdown report.
//!
//! The report is written for a reader who has to *check* the audit, not for a
//! reader who wants a verdict. Three consequences shape it:
//!
//! * Every finding shows where to look, and — unless excerpts are switched off —
//!   a redacted excerpt of what was seen.
//! * Status, severity and confidence are printed as three separate axes.
//! * There is no overall score. A single number would hide exactly the cases
//!   that matter: a serious issue with weak evidence, and a trivial issue that
//!   is certainly true.

use std::fmt::Write as _;

use auditeur_audit::AuditReport;
use auditeur_config::AuditeurConfig;
use auditeur_model::{AuditCategory, Evidence, Finding, Severity, Status};

use crate::{OutputFormat, ReportError, ReportRenderer};

/// Preferences for the rendered report.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportOptions {
    /// Include `PASS` findings in the findings section.
    pub include_passing: bool,
    /// Include redacted evidence excerpts.
    pub include_evidence_excerpts: bool,
    /// Omit findings below this severity.
    pub min_severity: Severity,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            include_passing: true,
            include_evidence_excerpts: true,
            min_severity: Severity::Info,
        }
    }
}

impl ReportOptions {
    /// Options from a project configuration.
    pub fn from_config(config: &AuditeurConfig) -> Self {
        Self {
            include_passing: config.report.include_passing,
            include_evidence_excerpts: config.report.include_evidence_excerpts,
            min_severity: config.audit.report_min_severity,
        }
    }
}

/// Renders the Markdown report.
#[derive(Debug, Clone)]
pub struct MarkdownRenderer {
    options: ReportOptions,
}

impl Default for MarkdownRenderer {
    fn default() -> Self {
        Self::new(ReportOptions::default())
    }
}

impl MarkdownRenderer {
    /// Create a renderer.
    pub fn new(options: ReportOptions) -> Self {
        Self { options }
    }

    /// Findings this renderer will show.
    pub fn visible_findings<'a>(&self, report: &'a AuditReport) -> Vec<&'a Finding> {
        report
            .findings
            .iter()
            .filter(|finding| self.options.include_passing || finding.status != Status::Pass)
            .filter(|finding| finding.severity >= self.options.min_severity)
            .collect()
    }
}

impl ReportRenderer for MarkdownRenderer {
    fn format(&self) -> OutputFormat {
        OutputFormat::Markdown
    }

    fn render(&self, report: &AuditReport) -> Result<String, ReportError> {
        let mut out = String::with_capacity(16 * 1024);
        self.header(&mut out, report);
        self.summary(&mut out, report);
        self.repository(&mut out, report);
        self.environment(&mut out, report);
        self.languages(&mut out, report);
        self.scope(&mut out, report);
        self.methodology(&mut out);
        self.findings(&mut out, report);
        self.evidence(&mut out, report);
        self.recommendations(&mut out, report);
        self.tools(&mut out, report);
        self.limitations(&mut out, report);
        self.reproducibility(&mut out, report);
        Ok(out)
    }
}

impl MarkdownRenderer {
    fn header(&self, out: &mut String, report: &AuditReport) {
        let manifest = &report.manifest;
        let _ = writeln!(out, "# Audit report — {}\n", manifest.repository.name);
        let _ = writeln!(
            out,
            "> Evidence-based audit of `{}` run by Auditeur {}. Every violation cites evidence \
             a reader can open; a finding that rests on an absence cites the search that \
             established it. This report is not a verdict and deliberately contains no overall \
             score.\n",
            manifest.repository.root, manifest.auditeur_version
        );
        let _ = writeln!(out, "| | |");
        let _ = writeln!(out, "| --- | --- |");
        let _ = writeln!(out, "| Run id | `{}` |", manifest.run_id);
        let _ = writeln!(out, "| Started (UTC) | {} |", manifest.started_at);
        let _ = writeln!(out, "| Duration | {} ms |", manifest.duration_ms);
        let _ = writeln!(
            out,
            "| AI-assisted analysis | {} |",
            if manifest.ai_enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        let _ = writeln!(
            out,
            "| Read-only boundary verified | {} |",
            if report.read_only_verified {
                "yes"
            } else {
                "not verified"
            }
        );
        let _ = writeln!(out);
    }

    fn summary(&self, out: &mut String, report: &AuditReport) {
        let counts = report.manifest.counts;
        let _ = writeln!(out, "## Executive summary\n");
        let _ = writeln!(out, "| Status | Count |");
        let _ = writeln!(out, "| --- | --- |");
        let _ = writeln!(out, "| PASS | {} |", counts.pass);
        let _ = writeln!(out, "| INFO | {} |", counts.info);
        let _ = writeln!(out, "| WARN | {} |", counts.warn);
        let _ = writeln!(out, "| FAIL | {} |", counts.fail);
        let _ = writeln!(out, "| **total** | **{}** |\n", counts.total());

        // Most serious first. Only violations are listed: a check that was
        // satisfied is not a serious finding, however high the severity attached
        // to it. Sorting here rather than trusting report order keeps the top of
        // the summary readable when a run produces many findings.
        let mut violations = report.violations();
        violations.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then(left.category.cmp(&right.category))
                .then(left.id.cmp(&right.id))
        });
        if violations.is_empty() {
            let _ = writeln!(
                out,
                "No check reported a violation. This means the audited checks found nothing to \
                 report, not that the software is correct: the scope and the limitations below \
                 bound what this audit can say.\n"
            );
        } else {
            let _ = writeln!(
                out,
                "{} violation(s) reported ({} at FAIL). The most serious:\n",
                violations.len(),
                counts.fail
            );
            for finding in violations.iter().take(5) {
                let _ = writeln!(
                    out,
                    "- **{}** — {} (`{}`, {}, confidence {})",
                    finding.status.marker(),
                    finding.title,
                    finding.id,
                    finding.severity.id(),
                    finding.confidence.id()
                );
            }
            let _ = writeln!(out);
        }

        if !report.manifest.limitations.is_empty() {
            let _ = writeln!(
                out,
                "{} limitation(s) are recorded in this run; read them before drawing conclusions.\n",
                report.manifest.limitations.len()
            );
        }
    }

    fn repository(&self, out: &mut String, report: &AuditReport) {
        let manifest = &report.manifest;
        let _ = writeln!(out, "## Repository information\n");
        let _ = writeln!(out, "| | |");
        let _ = writeln!(out, "| --- | --- |");
        let _ = writeln!(out, "| Root | `{}` |", manifest.repository.root);
        let _ = writeln!(out, "| Name | {} |", manifest.repository.name);
        let _ = writeln!(
            out,
            "| Fingerprint | `{}` |",
            manifest.repository.fingerprint.digest
        );
        let _ = writeln!(out, "| Files inspected | {} |", manifest.files_inspected);
        let _ = writeln!(out, "| Bytes inspected | {} |", manifest.bytes_inspected);
        match &manifest.repository.git {
            Some(git) => {
                let _ = writeln!(
                    out,
                    "| Git commit | `{}` |",
                    git.head_commit
                        .clone()
                        .unwrap_or_else(|| "none (unborn HEAD)".to_string())
                );
                let _ = writeln!(
                    out,
                    "| Git branch | {} |",
                    git.branch.clone().unwrap_or_else(|| "detached".to_string())
                );
                let _ = writeln!(
                    out,
                    "| Working tree | {} |",
                    if git.is_clean() {
                        "clean".to_string()
                    } else {
                        format!(
                            "dirty ({} modified, {} untracked)",
                            git.modified_files, git.untracked_files
                        )
                    }
                );
                if let Some(remote) = &git.remote {
                    let _ = writeln!(out, "| Remote | `{remote}` |");
                }
                if let Some(describe) = &git.describe {
                    let _ = writeln!(out, "| Describe | `{describe}` |");
                }
            }
            None => {
                let _ = writeln!(
                    out,
                    "| Git | not a work tree; this audit describes the filesystem as it was |"
                );
            }
        }
        let _ = writeln!(out);

        if !manifest.skipped.is_empty() {
            let _ = writeln!(out, "### Paths not inspected\n");
            let mut by_reason: std::collections::BTreeMap<&str, u32> =
                std::collections::BTreeMap::new();
            for record in &manifest.skipped {
                *by_reason.entry(record.reason.id()).or_insert(0) += 1;
            }
            let _ = writeln!(out, "| Reason | Count | Meaning |");
            let _ = writeln!(out, "| --- | --- | --- |");
            for (reason, count) in by_reason {
                let meaning = manifest
                    .skipped
                    .iter()
                    .find(|record| record.reason.id() == reason)
                    .map(|record| record.reason.description())
                    .unwrap_or("");
                let _ = writeln!(out, "| {reason} | {count} | {meaning} |");
            }
            let _ = writeln!(out);
        }
    }

    fn environment(&self, out: &mut String, report: &AuditReport) {
        let manifest = &report.manifest;
        let _ = writeln!(out, "## Environment\n");
        let _ = writeln!(out, "| | |");
        let _ = writeln!(out, "| --- | --- |");
        let _ = writeln!(out, "| Auditeur | {} |", manifest.auditeur_version);
        let _ = writeln!(out, "| Audit schema | {} |", manifest.audit_schema_version);
        let _ = writeln!(out, "| Operating system | {} |", std::env::consts::OS);
        let _ = writeln!(out, "| Architecture | {} |", std::env::consts::ARCH);
        let _ = writeln!(out, "| Inference backend | {} |", manifest.model.backend);
        let _ = writeln!(out, "| Model | {} |", manifest.model.name);
        let _ = writeln!(
            out,
            "| Model version | {} |",
            manifest
                .model
                .version
                .clone()
                .unwrap_or_else(|| "not reported".to_string())
        );
        let _ = writeln!(
            out,
            "| Model checksum | {} |",
            manifest
                .model
                .checksum
                .clone()
                .unwrap_or_else(|| "not recorded".to_string())
        );
        if let Some(ai) = &report.ai {
            let _ = writeln!(
                out,
                "| Model tasks | {} attempted, {} answered, {} failed |",
                ai.tasks_attempted, ai.tasks_run, ai.tasks_failed
            );
            let _ = writeln!(
                out,
                "| Model drafts | {} verified, {} unverified |",
                ai.drafts_verified, ai.drafts_unverified
            );
        }
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Hardware acceleration is reported by `auditeur doctor`; it concerns the inference \
             server rather than the audit process.\n"
        );
    }

    fn languages(&self, out: &mut String, report: &AuditReport) {
        let _ = writeln!(out, "## Detected languages\n");
        if report.analyses.is_empty() {
            let _ = writeln!(
                out,
                "No supported language was detected. The structural checks still ran, but \
                 language-specific analysis did not.\n"
            );
            return;
        }
        let _ = writeln!(
            out,
            "| Language | Files | Lines | Analysis | Dependencies | Tests |"
        );
        let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- |");
        for analysis in &report.analyses {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} |",
                analysis.language.label(),
                analysis.files,
                analysis.lines.lines,
                analysis.level.label(),
                analysis.dependencies.len(),
                analysis.tests.file_count()
            );
        }
        let _ = writeln!(out);

        let metadata_only: Vec<&str> = report
            .analyses
            .iter()
            .filter(|analysis| analysis.level == auditeur_audit::AnalysisLevel::MetadataOnly)
            .map(|analysis| analysis.language.label())
            .collect();
        if !metadata_only.is_empty() {
            let _ = writeln!(
                out,
                "> {} were detected and inventoried, not analysed: their adapters do not yet parse \
                 manifests, so this report makes no claim about their dependencies or tests.\n",
                metadata_only.join(", ")
            );
        }
        let truncated: Vec<&str> = report
            .analyses
            .iter()
            .filter(|analysis| analysis.lines.truncated)
            .map(|analysis| analysis.language.label())
            .collect();
        if !truncated.is_empty() {
            let _ = writeln!(
                out,
                "> Line counting stopped at the read budget for: {}. Line counts are therefore \
                 lower bounds.\n",
                truncated.join(", ")
            );
        }
    }

    fn scope(&self, out: &mut String, report: &AuditReport) {
        let plan = &report.plan;
        let _ = writeln!(out, "## Audit scope\n");
        let categories: Vec<&str> = plan
            .categories
            .iter()
            .map(|category| category.id())
            .collect();
        let _ = writeln!(out, "Categories enabled: {}\n", categories.join(", "));

        let _ = writeln!(out, "| Definition | Version |");
        let _ = writeln!(out, "| --- | --- |");
        for definition in &plan.definitions {
            let _ = writeln!(out, "| {} | {} |", definition.id, definition.version);
        }
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Checks selected: {}. Checks executed: {}. Model-assisted tasks selected: {}.\n",
            report.manifest.scope.checks_selected,
            report.manifest.scope.checks_executed,
            plan.tasks_selected()
        );
        if !plan.skipped.is_empty() {
            let _ = writeln!(out, "Not run:\n");
            for skip in &plan.skipped {
                let _ = writeln!(out, "- `{}` — {}", skip.check_id, skip.reason);
            }
            let _ = writeln!(out);
        }
    }

    fn methodology(&self, out: &mut String) {
        let _ = writeln!(out, "## Methodology\n");
        let _ = writeln!(
            out,
            "Auditeur collects deterministic evidence first: the file inventory, Git state, \
             manifests, declared dependencies and test inventory. Checks then derive findings \
             from that evidence, and each finding cites the evidence it used.\n"
        );
        let _ = writeln!(
            out,
            "**Finding axes.** These are independent and must not be read as one number:\n"
        );
        let _ = writeln!(out, "| Axis | Values | Meaning |");
        let _ = writeln!(out, "| --- | --- | --- |");
        let _ = writeln!(out, "| status | PASS, INFO, WARN, FAIL | outcome of the check: satisfied, observation, violation to review, violation of a gate |");
        let _ = writeln!(out, "| severity | info, low, medium, high, critical | impact if the issue is real, declared by the audit definition |");
        let _ = writeln!(out, "| confidence | low, medium, high | certainty of the claim; deterministic checks are high by construction |");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "**Model-assisted findings.** A finding whose source is `ai_assisted` was proposed by \
             a model and then verified: every reference it cites had to be one Auditeur supplied \
             and had to exist in the repository. Findings marked `unverified` failed that check. \
             Severity for them still comes from the audit definition, never from the model.\n"
        );
        let _ = writeln!(
            out,
            "**No overall score.** A single number would collapse the cases that matter most: \
             a serious issue with weak evidence, and a trivial issue that is certain.\n"
        );
        let _ = writeln!(
            out,
            "**Verification.** Open any cited path and line range to confirm a finding by hand. \
             The machine-readable form of everything in this report is in the run directory.\n"
        );
    }

    fn findings(&self, out: &mut String, report: &AuditReport) {
        let _ = writeln!(out, "## Findings\n");
        let visible = self.visible_findings(report);
        if visible.is_empty() {
            let _ = writeln!(
                out,
                "No finding met the reporting threshold (minimum severity `{}`, passing findings {}).\n",
                self.options.min_severity.id(),
                if self.options.include_passing { "included" } else { "omitted" }
            );
            return;
        }

        for category in AuditCategory::ALL {
            let category_findings: Vec<&&Finding> = visible
                .iter()
                .filter(|finding| finding.category == category)
                .collect();
            if category_findings.is_empty() {
                continue;
            }
            let _ = writeln!(out, "### {}\n", category.label());
            for finding in category_findings {
                self.finding(out, report, finding);
            }
        }
    }

    fn finding(&self, out: &mut String, report: &AuditReport, finding: &Finding) {
        let _ = writeln!(
            out,
            "#### {} — {}\n",
            finding.status.marker(),
            finding.title
        );
        let _ = writeln!(
            out,
            "`{}` · severity **{}** · confidence **{}** · source {}",
            finding.id,
            finding.severity.id(),
            finding.confidence.id(),
            match &finding.source {
                auditeur_model::FindingSource::Deterministic => "deterministic".to_string(),
                auditeur_model::FindingSource::AiAssisted {
                    backend,
                    model,
                    task_id,
                    verified,
                } => format!(
                    "model-assisted ({backend}/{model}, task {task_id}, {})",
                    if *verified { "verified" } else { "unverified" }
                ),
            }
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "{}\n", finding.description);

        if let Some(recommendation) = &finding.recommendation {
            let _ = writeln!(out, "**Recommendation.** {recommendation}\n");
        }

        let evidence = report.evidence_for(finding);
        if evidence.is_empty() {
            let _ = writeln!(
                out,
                "**Evidence.** none cited — treat this finding as unconfirmed.\n"
            );
            return;
        }
        let _ = writeln!(out, "**Evidence.**");
        for item in evidence {
            self.evidence_item(out, item);
        }
        let _ = writeln!(out);
    }

    fn evidence_item(&self, out: &mut String, item: &Evidence) {
        let _ = writeln!(out, "- `{}` — {}", item.location.describe(), item.summary);
        if let Some(digest) = &item.digest {
            let _ = writeln!(out, "  - sha256 `{}`", &digest[..digest.len().min(16)]);
        }
        if self.options.include_evidence_excerpts {
            if let Some(excerpt) = &item.excerpt {
                let _ = writeln!(out, "  ```");
                for line in excerpt.lines() {
                    let _ = writeln!(out, "  {line}");
                }
                let _ = writeln!(out, "  ```");
            }
        }
    }

    fn evidence(&self, out: &mut String, report: &AuditReport) {
        let _ = writeln!(out, "## Evidence\n");
        if report.evidence.is_empty() {
            let _ = writeln!(out, "No evidence was collected.\n");
            return;
        }
        let mut by_kind: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
        for item in &report.evidence {
            *by_kind.entry(item.kind.label()).or_insert(0) += 1;
        }
        let _ = writeln!(
            out,
            "{} distinct evidence item(s):\n",
            report.evidence.len()
        );
        let _ = writeln!(out, "| Kind | Count |");
        let _ = writeln!(out, "| --- | --- |");
        for (kind, count) in by_kind {
            let _ = writeln!(out, "| {kind} | {count} |");
        }
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "The complete set, including identifiers and digests, is in `evidence.json` next to \
             this report's run directory. Excerpts are redacted: credential-shaped values are \
             replaced before they are stored.\n"
        );
    }

    fn recommendations(&self, out: &mut String, report: &AuditReport) {
        let _ = writeln!(out, "## Recommendations\n");
        let mut seen: Vec<(&str, Vec<&str>)> = Vec::new();
        for finding in self.visible_findings(report) {
            let Some(recommendation) = finding.recommendation.as_deref() else {
                continue;
            };
            match seen.iter_mut().find(|(text, _)| *text == recommendation) {
                Some((_, ids)) => ids.push(finding.id.as_str()),
                None => seen.push((recommendation, vec![finding.id.as_str()])),
            }
        }
        if seen.is_empty() {
            let _ = writeln!(out, "No recommendations were produced.\n");
            return;
        }
        for (recommendation, ids) in seen {
            let _ = writeln!(out, "- {}", recommendation);
            let _ = writeln!(out, "  - findings: {}", ids.join(", "));
        }
        let _ = writeln!(out);
    }

    fn tools(&self, out: &mut String, report: &AuditReport) {
        let _ = writeln!(out, "## Tool and command results\n");
        if report.manifest.tools_executed.is_empty() {
            let _ = writeln!(out, "No external command was executed.\n");
            return;
        }
        let _ = writeln!(out, "| Command | Exit | Duration (ms) | Output truncated |");
        let _ = writeln!(out, "| --- | --- | --- | --- |");
        for execution in &report.manifest.tools_executed {
            let _ = writeln!(
                out,
                "| `{} {}` | {} | {} | {} |",
                execution.program,
                execution.args.join(" "),
                execution
                    .exit_code
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                execution.duration_ms,
                if execution.truncated { "yes" } else { "no" }
            );
        }
        let _ = writeln!(out);
    }

    fn limitations(&self, out: &mut String, report: &AuditReport) {
        let _ = writeln!(out, "## Limitations\n");
        if report.manifest.limitations.is_empty() {
            let _ = writeln!(
                out,
                "None recorded. This does not mean the audit is exhaustive: it means no stage \
                 reported a gap.\n"
            );
            return;
        }
        for limitation in &report.manifest.limitations {
            let _ = writeln!(out, "- `{}`: {}", limitation.code, limitation.message);
        }
        let _ = writeln!(out);
    }

    fn reproducibility(&self, out: &mut String, report: &AuditReport) {
        let manifest = &report.manifest;
        let _ = writeln!(out, "## Reproducibility\n");
        let _ = writeln!(out, "| | |");
        let _ = writeln!(out, "| --- | --- |");
        let _ = writeln!(out, "| Run id | `{}` |", manifest.run_id);
        let _ = writeln!(out, "| Unix timestamp | {} |", manifest.unix_timestamp);
        let _ = writeln!(out, "| Finished (UTC) | {} |", manifest.finished_at);
        let _ = writeln!(
            out,
            "| Repository fingerprint | `{}` |",
            manifest.repository.fingerprint.digest
        );
        let _ = writeln!(out, "| Files inspected | {} |", manifest.files_inspected);
        let _ = writeln!(out, "| Bytes inspected | {} |", manifest.bytes_inspected);
        if let Some(limits) = &manifest.limits {
            let _ = writeln!(
                out,
                "| Limits | {} byte(s) per file, {} file(s), {} byte(s) total, depth {} |",
                limits.max_file_bytes, limits.max_files, limits.max_total_bytes, limits.max_depth
            );
            let _ = writeln!(
                out,
                "| Ignore policy | {} directory name(s), {} file name(s) excluded |",
                limits.ignored_directories, limits.ignored_files
            );
        }
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Re-running the same command against the same revision reproduces the deterministic \
             findings. Model-assisted findings depend on the model and its sampling settings, \
             which are recorded above; treat them as reproducible in kind, not byte for byte.\n"
        );
        let _ = writeln!(out, "| Definition | Version |");
        let _ = writeln!(out, "| --- | --- |");
        for definition in &manifest.scope.definitions {
            let _ = writeln!(out, "| {} | {} |", definition.id, definition.version);
        }
        let _ = writeln!(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_audit::{AuditEngine, AuditOptions, AuditPlan};
    use auditeur_config::AuditeurHome;
    use std::fs;

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::create_dir_all(temp.path().join("tests")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\nlicense = \"MIT\"\n\n[dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/lib.rs"),
            "pub fn add(a: u32, b: u32) -> u32 { a + b }\n// TODO: bound the inputs\n",
        )
        .unwrap();
        fs::write(temp.path().join("tests/it.rs"), "#[test]\nfn one() {}\n").unwrap();
        fs::write(temp.path().join("README.md"), "# Demo\n").unwrap();
        fs::write(temp.path().join("LICENSE"), "MIT\n").unwrap();
        fs::write(temp.path().join("Cargo.lock"), "version = 3\n").unwrap();
        fs::write(temp.path().join(".gitignore"), "/target\n").unwrap();
        temp
    }

    fn audit(repo: &std::path::Path, project: &std::path::Path) -> AuditReport {
        let mut config = AuditeurConfig::default();
        config.project.name = "demo".to_string();
        config.project.source_path = repo.to_path_buf();
        let options = AuditOptions::new(repo, AuditeurHome::at(project), config);
        AuditEngine::run(&options).unwrap()
    }

    #[test]
    fn the_summary_lists_violations_only_even_when_a_passing_finding_is_high_severity() {
        // A single Python file: no tests, no .env, which is what makes the run
        // produce both a high-severity FAIL and a high-severity PASS.
        let repo = tempfile::tempdir().unwrap();
        fs::write(repo.path().join("app.py"), "print('hello')\n").unwrap();
        let project = tempfile::tempdir().unwrap();
        let report = audit(repo.path(), project.path());

        // If the fixture stops producing a high-severity PASS finding, the case
        // this test guards has disappeared from the run, and the test must say so
        // rather than pass quietly.
        let high_passes = report
            .findings
            .iter()
            .filter(|finding| finding.status == Status::Pass && finding.severity >= Severity::High)
            .count();
        assert!(
            high_passes > 0,
            "the fixture no longer produces a high-severity PASS finding"
        );

        let markdown = MarkdownRenderer::default().render(&report).unwrap();
        let summary = markdown
            .split("## Executive summary")
            .nth(1)
            .expect("the executive summary is present")
            .split("## Repository information")
            .next()
            .unwrap();

        assert!(summary.contains("violation(s) reported"), "{summary}");
        assert!(
            summary.contains("- **FAIL**"),
            "the FAIL finding should lead the summary:\n{summary}"
        );
        assert!(
            !summary.contains("- **PASS**") && !summary.contains("- **INFO**"),
            "a satisfied check was listed as serious:\n{summary}"
        );
    }

    #[test]
    fn the_report_contains_every_required_section() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let report = audit(repo.path(), project.path());
        let markdown = MarkdownRenderer::default().render(&report).unwrap();

        for section in [
            "## Executive summary",
            "## Repository information",
            "## Environment",
            "## Detected languages",
            "## Audit scope",
            "## Methodology",
            "## Findings",
            "## Evidence",
            "## Recommendations",
            "## Tool and command results",
            "## Limitations",
            "## Reproducibility",
        ] {
            assert!(markdown.contains(section), "missing section {section}");
        }
        assert!(markdown.contains("No overall score"));
        assert!(markdown.contains(&report.manifest.run_id));
    }

    #[test]
    fn findings_are_rendered_with_status_severity_and_evidence() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let report = audit(repo.path(), project.path());
        let markdown = MarkdownRenderer::default().render(&report).unwrap();

        assert!(markdown.contains("#### "), "no finding heading");
        assert!(markdown.contains("severity **"));
        assert!(markdown.contains("confidence **"));
        assert!(markdown.contains("**Evidence.**"));
        assert!(markdown.contains("src/lib.rs"));
    }

    #[test]
    fn passing_findings_can_be_omitted() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let report = audit(repo.path(), project.path());

        let filtered = MarkdownRenderer::new(ReportOptions {
            include_passing: false,
            ..ReportOptions::default()
        })
        .render(&report)
        .unwrap();

        assert!(!filtered.contains("#### PASS —"), "{filtered}");
    }

    #[test]
    fn excerpts_can_be_omitted_and_secrets_never_appear() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        fs::write(
            repo.path().join("config.toml"),
            "api_key = \"sk-live-abcdef1234567890\"\n",
        )
        .unwrap();
        let report = audit(repo.path(), project.path());

        let with_excerpts = MarkdownRenderer::default().render(&report).unwrap();
        assert!(!with_excerpts.contains("sk-live-abcdef1234567890"));
        assert!(with_excerpts.contains("[REDACTED"));

        let without = MarkdownRenderer::new(ReportOptions {
            include_evidence_excerpts: false,
            ..ReportOptions::default()
        })
        .render(&report)
        .unwrap();
        assert!(!without.contains("```"));
    }

    #[test]
    fn the_minimum_severity_filters_the_findings_section() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let report = audit(repo.path(), project.path());

        let only_high = MarkdownRenderer::new(ReportOptions {
            min_severity: Severity::High,
            ..ReportOptions::default()
        })
        .render(&report)
        .unwrap();

        assert!(only_high.contains("severity **high**") || only_high.contains("No finding met"));
        assert!(!only_high.contains("severity **low**"));
    }

    #[test]
    fn rendered_findings_section_only_shows_visible_findings() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let report = audit(repo.path(), project.path());
        let renderer = MarkdownRenderer::new(ReportOptions {
            include_passing: false,
            min_severity: Severity::Medium,
            include_evidence_excerpts: true,
        });
        for finding in renderer.visible_findings(&report) {
            assert_ne!(finding.status, Status::Pass);
            assert!(finding.severity >= Severity::Medium);
        }
    }

    #[test]
    fn an_empty_report_is_still_well_formed() {
        let manifest = auditeur_model::RunManifest::new(
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
        );
        let report = AuditReport {
            manifest,
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
        let markdown = MarkdownRenderer::default().render(&report).unwrap();
        assert!(markdown.contains("No finding met the reporting threshold"));
        assert!(markdown.contains("No evidence was collected"));
        assert!(markdown.contains("not a work tree"));
    }
}
