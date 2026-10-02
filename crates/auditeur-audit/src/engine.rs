//! The audit pipeline.
//!
//! ```text
//! repository discovery → repository model → deterministic analysis
//!   → audit planning → deterministic checks → model-assisted analysis
//!   → evidence verification → finding validation → manifest
//! ```
//!
//! The engine writes nothing. It returns an [`AuditReport`]; persisting the run
//! artifacts and rendering the report is the caller's job. That keeps the engine
//! testable without a filesystem layout and keeps the read-only boundary honest:
//! the only filesystem writes in an audit are the ones the CLI makes, outside
//! the audited tree.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use auditeur_config::{AuditeurConfig, AuditeurHome, LimitsConfig};
use auditeur_inference::InferenceBackend;
use auditeur_languages::{LanguageAnalysis, LanguageOptions};
use auditeur_model::{
    AuditCategory, Evidence, Finding, GitState, Language, Limitation, RepositoryFingerprint,
    RunManifest, Severity, Status,
};
use auditeur_repository::{
    discover, discovery::DiscoveryOptions, fingerprint::ReadOnlyGuard, git::GitProbe,
    RepositoryModel,
};

use crate::ai::{self, AiSummary};
use crate::context::{AuditContext, AuditStage, EvidenceStore, ProgressSink, SilentProgress};
use crate::definitions;
use crate::error::AuditError;
use crate::planner::AuditPlan;

/// Everything the engine needs to run an audit.
pub struct AuditOptions {
    /// Repository to audit.
    pub source_path: PathBuf,
    /// Where Auditeur keeps its own state. Never inside the audited repository.
    pub paths: AuditeurHome,
    /// Effective configuration.
    pub config: AuditeurConfig,
    /// Whether model-assisted analysis is allowed for this run.
    pub enable_ai: bool,
    /// Whether to fingerprint the repository before and after and fail on any change.
    pub verify_read_only: bool,
    /// Model backend, when one is configured and AI is enabled.
    pub backend: Option<Arc<dyn InferenceBackend>>,
    /// Progress sink. Defaults to silence.
    pub progress: Arc<dyn ProgressSink>,
    /// Run identifier, defaulting to the start timestamp.
    pub run_id: Option<String>,
}

impl AuditOptions {
    /// Options for a run with the given configuration.
    pub fn new(
        source_path: impl Into<PathBuf>,
        paths: AuditeurHome,
        config: AuditeurConfig,
    ) -> Self {
        let enable_ai = config.model.ai_active();
        Self {
            source_path: source_path.into(),
            paths,
            config,
            enable_ai,
            verify_read_only: true,
            backend: None,
            progress: Arc::new(SilentProgress),
            run_id: None,
        }
    }

    /// Attach a backend.
    pub fn with_backend(mut self, backend: Arc<dyn InferenceBackend>) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Attach a progress sink.
    pub fn with_progress(mut self, progress: Arc<dyn ProgressSink>) -> Self {
        self.progress = progress;
        self
    }

    /// Disable model-assisted analysis.
    pub fn without_ai(mut self) -> Self {
        self.enable_ai = false;
        self
    }

    /// Skip the read-only verification (used by unit tests that audit a fixture
    /// they are about to modify themselves).
    pub fn without_read_only_verification(mut self) -> Self {
        self.verify_read_only = false;
        self
    }

    /// Whether the model will actually be consulted.
    pub fn ai_active(&self) -> bool {
        self.enable_ai && self.backend.is_some() && self.config.model.ai_active()
    }
}

/// The result of an audit.
#[derive(Debug)]
pub struct AuditReport {
    /// The run manifest, final except for `report_path`, which the writer sets.
    pub manifest: RunManifest,
    /// Validated findings, in report order.
    pub findings: Vec<Finding>,
    /// All evidence collected during the run.
    pub evidence: Vec<Evidence>,
    /// What the audit planned to do and what it skipped.
    pub plan: AuditPlan,
    /// Language analyses, for the report's repository section.
    pub analyses: Vec<LanguageAnalysis>,
    /// Git metadata, when available.
    pub git: Option<GitState>,
    /// What the model-assisted stage did, when it ran.
    pub ai: Option<AiSummary>,
    /// Repository root, canonicalised.
    pub repository_root: PathBuf,
    /// Whether the read-only boundary was verified for this run.
    pub read_only_verified: bool,
}

impl AuditReport {
    /// Findings in a category.
    pub fn findings_for(&self, category: AuditCategory) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.category == category)
            .collect()
    }

    /// Findings at or above a status.
    pub fn findings_with_status(&self, status: Status) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.status == status)
            .collect()
    }

    /// Findings that represent a violation.
    pub fn violations(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.status.is_violation())
            .collect()
    }

    /// Findings at or above a severity.
    pub fn findings_with_severity(&self, severity: Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.severity >= severity)
            .collect()
    }

    /// The evidence behind a finding.
    pub fn evidence_for<'a>(&'a self, finding: &Finding) -> Vec<&'a Evidence> {
        finding
            .evidence
            .iter()
            .filter_map(|reference| {
                self.evidence
                    .iter()
                    .find(|evidence| evidence.id == reference.evidence_id)
            })
            .collect()
    }

    /// Whether any violation reaches the configured failure threshold.
    pub fn breaches_threshold(&self, threshold: Severity) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.status.is_violation() && finding.severity >= threshold)
    }

    /// Process exit code for this result: `0` clean, `1` threshold breached.
    pub fn exit_code(&self, threshold: Severity) -> i32 {
        if self.breaches_threshold(threshold) {
            1
        } else {
            0
        }
    }

    /// Categories present in the findings.
    pub fn categories(&self) -> Vec<AuditCategory> {
        let mut categories: Vec<AuditCategory> = self
            .findings
            .iter()
            .map(|finding| finding.category)
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }

    /// Languages detected for this run.
    pub fn languages(&self) -> Vec<Language> {
        self.manifest.detected_languages.clone()
    }

    /// Whether no violation was found.
    pub fn is_clean(&self) -> bool {
        self.violations().is_empty()
    }
}

/// Runs the audit pipeline.
pub struct AuditEngine;

impl AuditEngine {
    /// Run an audit.
    pub fn run(options: &AuditOptions) -> Result<AuditReport, AuditError> {
        let started = Instant::now();
        let started_millis = chrono::Utc::now().timestamp_millis() as i128;

        let guard = ReadOnlyGuard::capture(&options.source_path)?;
        let fingerprint = guard.before().clone();
        let verify_read_only = options.verify_read_only;

        // ── discovery ────────────────────────────────────────────────────────
        options.progress.stage(
            AuditStage::Discovery,
            &options.source_path.display().to_string(),
        );
        let discovery_options = discovery_options(&options.config.audit.limits);
        let model = discover(&options.source_path, &discovery_options)?;
        let repository_root = model.root().to_path_buf();
        options.progress.stage(
            AuditStage::Discovery,
            &format!(
                "{} file(s), {} byte(s) inspected",
                model.file_count(),
                model.total_bytes()
            ),
        );

        // ── git metadata ─────────────────────────────────────────────────────
        options.progress.stage(AuditStage::GitMetadata, "");
        let git_probe = GitProbe::new(repository_root.clone(), options.paths.cache_dir()).probe();

        // ── language analysis ───────────────────────────────────────────────
        let language_options = LanguageOptions {
            run_external_tools: options.config.audit.run_external_tools,
            ..LanguageOptions::default()
        };
        let analyses = auditeur_languages::registry::analyze(&model, &language_options);
        options.progress.stage(
            AuditStage::LanguageAnalysis,
            &format!("{} language(s) detected", analyses.len()),
        );

        // ── planning ────────────────────────────────────────────────────────
        let definitions = definitions::load_with_overrides(Some(&options.paths.definitions_dir()))?;
        let ai_active = options.ai_active();
        let plan = AuditPlan::build(&definitions, &options.config.audit, ai_active)?;
        options.progress.stage(
            AuditStage::Planning,
            &format!(
                "{} check(s), {} model-assisted task(s), {} skipped",
                plan.checks_selected(),
                plan.tasks_selected(),
                plan.skipped.len()
            ),
        );

        let context = AuditContext::new(
            &model,
            &analyses,
            &options.config.audit,
            git_probe.state.as_ref(),
        );
        let mut evidence = EvidenceStore::new();
        let mut limitations: Vec<Limitation> = Vec::new();
        for note in &git_probe.notes {
            // Git notes are informational, not failures; record them so the
            // report can explain what could not be established.
            limitations.push(Limitation::new("git_metadata", note.clone()));
        }
        if options.config.audit.run_external_tools {
            limitations.push(Limitation::new(
                "external_tools_unused",
                "external tool execution is enabled, but no check in this version consumes its output",
            ));
        }

        // ── deterministic checks ────────────────────────────────────────────
        options.progress.stage(AuditStage::DeterministicChecks, "");
        let mut findings: Vec<Finding> = Vec::new();
        let mut checks_executed = 0u32;
        for planned in &plan.checks {
            let Some(check) = crate::checks::find(&planned.spec.id) else {
                return Err(AuditError::MissingImplementation {
                    definition: planned.definition_id.clone(),
                    check: planned.spec.id.clone(),
                });
            };
            match check.run(&context, &mut evidence, &planned.spec) {
                Ok(mut produced) => {
                    checks_executed += 1;
                    findings.append(&mut produced);
                }
                Err(error) => {
                    // One broken check must not lose the other results.
                    let message = format!("check '{}' failed: {error}", planned.spec.id);
                    options.progress.warn(&message);
                    limitations.push(Limitation::new("check_failed", message));
                }
            }
        }

        // ── model-assisted analysis ─────────────────────────────────────────
        let mut ai_summary = None;
        if let (true, Some(backend)) = (ai_active, options.backend.clone()) {
            options.progress.stage(
                AuditStage::AiAnalysis,
                &format!("{} task(s)", plan.tasks_selected()),
            );
            let run = ai::run_tasks(
                backend.as_ref(),
                &plan.tasks,
                &context,
                &options.config.model,
                &findings,
                &mut evidence,
            );
            for message in &run.summary.limitations {
                limitations.push(Limitation::new("ai_task_failed", message.clone()));
            }
            findings.extend(run.findings);
            ai_summary = Some(run.summary);
        } else if !plan.tasks.is_empty() {
            limitations.push(Limitation::new(
                "ai_disabled",
                "model-assisted analysis was not run, so no finding in this report is an interpretation of evidence by a model",
            ));
        }

        // ── verification and validation ─────────────────────────────────────
        options.progress.stage(AuditStage::Verification, "");
        for message in validate_findings(&mut findings, &mut evidence) {
            limitations.push(message);
        }
        for skip in plan.skip_descriptions() {
            limitations.push(Limitation::new("check_skipped", skip));
        }
        if model.truncated() {
            limitations.push(Limitation::new(
                "discovery_truncated",
                "a configured limit stopped repository discovery early; inspect the skipped paths before drawing conclusions about completeness",
            ));
        }

        // ── read-only verification ─────────────────────────────────────────
        let read_only_verified = if verify_read_only {
            match guard.verify() {
                Ok(()) => true,
                Err(error) => return Err(AuditError::ReadOnlyViolation(error.to_string())),
            }
        } else {
            false
        };

        // ── manifest ───────────────────────────────────────────────────────
        options.progress.stage(AuditStage::Assembly, "");
        let run_id = options
            .run_id
            .clone()
            // Seconds, so that the run directory and the report file name are the
            // same timestamp.
            .unwrap_or_else(|| (started_millis / 1000).to_string());
        let mut manifest = RunManifest::new(
            run_id,
            repository_info(&model, &git_probe.state, fingerprint),
        );
        manifest.ai_enabled = ai_active;
        manifest.model = match (&options.backend, ai_active) {
            (Some(backend), true) => auditeur_model::ModelRef {
                backend: backend.id().to_string(),
                name: backend.model().to_string(),
                version: None,
                checksum: None,
            },
            _ => auditeur_model::ModelRef::not_used(),
        };
        manifest.scope = auditeur_model::AuditScope {
            categories: plan.categories.clone(),
            definitions: plan.definitions.clone(),
            checks_selected: plan.checks_selected(),
            checks_executed,
        };
        manifest.detected_languages = analyses.iter().map(|analysis| analysis.language).collect();
        manifest.files_inspected = model.file_count();
        manifest.bytes_inspected = model.total_bytes();
        manifest.skipped = model.skipped().to_vec();
        manifest.tools_executed = git_probe.executions.clone();
        manifest.limits = Some(auditeur_model::LimitPolicy {
            max_file_bytes: options.config.audit.limits.max_file_bytes,
            max_files: options.config.audit.limits.max_files,
            max_total_bytes: options.config.audit.limits.max_total_bytes,
            max_depth: options.config.audit.limits.max_depth,
            follow_symlinks: options.config.audit.limits.follow_symlinks,
            ignored_directories: options.config.audit.limits.ignore_dirs.len() as u32,
            ignored_files: options.config.audit.limits.ignore_files.len() as u32,
        });
        manifest.limitations = limitations;
        manifest.finish(started_millis, &findings);
        manifest.duration_ms = started.elapsed().as_millis() as u64;

        Ok(AuditReport {
            manifest,
            findings,
            evidence: evidence.into_items(),
            plan,
            analyses,
            git: git_probe.state,
            ai: ai_summary,
            repository_root,
            read_only_verified,
        })
    }
}

/// Map configuration limits onto discovery options.
pub fn discovery_options(limits: &LimitsConfig) -> DiscoveryOptions {
    DiscoveryOptions {
        max_file_bytes: limits.max_file_bytes,
        max_files: limits.max_files,
        max_total_bytes: limits.max_total_bytes,
        max_depth: limits.max_depth,
        follow_symlinks: limits.follow_symlinks,
        ignore_dirs: limits.ignore_dirs.clone(),
        ignore_files: limits.ignore_files.clone(),
    }
}

/// Build the repository section of the manifest.
fn repository_info(
    model: &RepositoryModel,
    git: &Option<GitState>,
    fingerprint: RepositoryFingerprint,
) -> auditeur_model::RepositoryInfo {
    auditeur_model::RepositoryInfo {
        root: model.root().display().to_string(),
        name: model.name().to_string(),
        git: git.clone(),
        fingerprint,
    }
}

/// Validate findings and return the limitations that validation discovered.
///
/// Three rules are enforced:
///
/// * A **violation** must cite something a reader can open. A check that reports
///   one without citing anything is given a search-level citation naming the
///   repository root, and the run records that this happened. The invariant
///   therefore holds by construction, and the fact that a check forgot to cite
///   stays visible rather than being papered over.
/// * Identifiers must be unique; a duplicate is dropped.
/// * References must resolve; a dangling one is reported as unconfirmed.
fn validate_findings(findings: &mut Vec<Finding>, evidence: &mut EvidenceStore) -> Vec<Limitation> {
    let mut limitations = Vec::new();

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let before = findings.len();
    findings.retain(|finding| seen.insert(finding.id.clone()));
    if findings.len() != before {
        limitations.push(Limitation::new(
            "duplicate_findings",
            format!(
                "{} finding(s) shared an identifier with another finding and were removed",
                before - findings.len()
            ),
        ));
    }

    // A violation with no citation is a violation a reader cannot check. Cite the
    // search instead, and say plainly that the citation is generic: inventing a
    // precise-looking location would be worse than admitting the gap.
    let mut uncited_violations = 0usize;
    for finding in findings.iter_mut() {
        if !finding.status.is_violation() || finding.has_evidence() {
            continue;
        }
        uncited_violations += 1;
        let reference = evidence.insert(Evidence::directory(
            ".",
            format!(
                "check `{}` reported this without citing a location; the repository root was inspected",
                finding.check_id
            ),
        ));
        finding.evidence.push(reference);
    }
    if uncited_violations > 0 {
        limitations.push(Limitation::new(
            "violations_without_specific_evidence",
            format!(
                "{uncited_violations} violation(s) cited no specific location; each was given a \
                 search-level citation naming the repository root, and the checks that produced \
                 them should cite precisely"
            ),
        ));
    }

    let without_evidence = findings
        .iter()
        .filter(|finding| !finding.has_evidence())
        .count();
    if without_evidence > 0 {
        limitations.push(Limitation::new(
            "findings_without_evidence",
            format!("{without_evidence} finding(s) cite no evidence and should be treated as unconfirmed"),
        ));
    }

    let dangling = findings
        .iter()
        .flat_map(|finding| finding.evidence.iter())
        .filter(|reference| !evidence.contains(&reference.evidence_id))
        .count();
    if dangling > 0 {
        limitations.push(Limitation::new(
            "dangling_evidence",
            format!("{dangling} evidence reference(s) could not be resolved and were reported as unconfirmed"),
        ));
    }

    // Report order: category, then severity (most serious first), then id.
    findings.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then(right.severity.cmp(&left.severity))
            .then(left.id.cmp(&right.id))
    });

    limitations
}

/// Definitions referenced by a run, for display.
#[cfg(test)]
pub fn definition_refs(plan: &AuditPlan) -> &[auditeur_model::DefinitionRef] {
    &plan.definitions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::RecordingProgress;
    use auditeur_inference::MockBackend;
    use std::fs;

    fn options(root: &std::path::Path, project_root: &std::path::Path) -> AuditOptions {
        let mut config = AuditeurConfig::default();
        config.project.name = "fixture".to_string();
        config.project.source_path = root.to_path_buf();
        config.project.project_root = Some(project_root.to_path_buf());
        AuditOptions::new(root, AuditeurHome::at(project_root), config)
    }

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::create_dir_all(temp.path().join("tests")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"1.0.0\"\nlicense = \"MIT\"\n\n[dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/lib.rs"),
            "pub fn add(a: u32, b: u32) -> u32 { a + b }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("tests/it.rs"),
            "#[test]\nfn adds() { assert_eq!(1 + 1, 2); }\n",
        )
        .unwrap();
        fs::write(temp.path().join("README.md"), "# Fixture\n").unwrap();
        fs::write(temp.path().join("LICENSE"), "MIT\n").unwrap();
        fs::write(temp.path().join("Cargo.lock"), "version = 3\n").unwrap();
        fs::write(temp.path().join(".gitignore"), "/target\n").unwrap();
        temp
    }

    #[test]
    fn a_complete_audit_produces_a_manifest_and_findings() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let report = AuditEngine::run(&options(repo.path(), project.path())).unwrap();

        assert_eq!(report.manifest.files_inspected, 7);
        assert!(report.manifest.bytes_inspected > 0);
        assert_eq!(report.manifest.detected_languages, vec![Language::Rust]);
        assert!(!report.findings.is_empty());
        assert!(report.manifest.scope.checks_executed > 0);
        assert_eq!(
            report.manifest.counts.total() as usize,
            report.findings.len()
        );
        assert!(report.read_only_verified);
        assert!(report
            .findings
            .iter()
            .all(|finding| !finding.source.is_ai()));
        assert_eq!(report.manifest.model.backend, "none");
        assert!(!report.manifest.ai_enabled);
    }

    #[test]
    fn every_deterministic_finding_cites_existing_evidence() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let report = AuditEngine::run(&options(repo.path(), project.path())).unwrap();

        let evidence_ids: std::collections::HashSet<&str> = report
            .evidence
            .iter()
            .map(|item| item.id.as_str())
            .collect();
        for finding in &report.findings {
            for reference in &finding.evidence {
                assert!(
                    evidence_ids.contains(reference.evidence_id.as_str()),
                    "finding {} cites missing evidence {}",
                    finding.id,
                    reference.evidence_id
                );
            }
        }
        assert!(!report.evidence.is_empty());
    }

    #[test]
    fn the_pipeline_reports_every_stage() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let progress = Arc::new(RecordingProgress::new());
        let mut options = options(repo.path(), project.path());
        options.progress = progress.clone();
        AuditEngine::run(&options).unwrap();

        let stages = progress.stages();
        for expected in [
            AuditStage::Discovery,
            AuditStage::GitMetadata,
            AuditStage::LanguageAnalysis,
            AuditStage::Planning,
            AuditStage::DeterministicChecks,
            AuditStage::Verification,
            AuditStage::Assembly,
        ] {
            assert!(stages.contains(&expected), "missing stage {expected:?}");
        }
    }

    #[test]
    fn the_audit_does_not_modify_the_repository() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        // A misconfigured project root inside the repository must not tempt the
        // engine into writing there: it writes nothing at all.
        let report = AuditEngine::run(&options(repo.path(), project.path())).unwrap();
        assert!(report.read_only_verified);
        assert_eq!(
            std::fs::read_dir(repo.path()).unwrap().count(),
            7,
            "no entry may be added to the audited repository"
        );
    }

    #[test]
    fn a_modified_repository_fails_the_read_only_check() {
        let repo = fixture();

        // Capture a guard, modify the tree, then verify: the engine's own path
        // is tested by the integration suite, which watches a real run.
        let guard = ReadOnlyGuard::capture(repo.path()).unwrap();
        fs::write(repo.path().join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
        assert!(guard.verify().is_err());
    }

    #[test]
    fn model_assisted_findings_appear_when_a_backend_is_configured() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let backend = Arc::new(MockBackend::with_response(
            r#"{"findings":[{"title":"Dependency declared with default features","description":"serde is declared without a feature set.","evidence":[{"reference":"Cargo.toml"}]}]}"#,
        ));
        let mut options = options(repo.path(), project.path());
        options.backend = Some(backend.clone());
        options.enable_ai = true;
        options.config.model.model = "mock".to_string();

        let report = AuditEngine::run(&options).unwrap();

        let ai_findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.source.is_ai())
            .collect();
        assert!(!ai_findings.is_empty(), "expected model-assisted findings");
        assert!(report.manifest.ai_enabled);
        assert_eq!(report.manifest.model.backend, "mock");
        assert!(ai_findings.iter().any(|finding| !finding.is_unverified()));
        let summary = report.ai.expect("summary");
        assert!(summary.tasks_run > 0);
        assert!(backend.request_count() > 0);
    }

    #[test]
    fn disabled_categories_shrink_the_scope_and_are_recorded() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let mut options = options(repo.path(), project.path());
        options.config.audit.enabled_categories = vec![AuditCategory::Testing];

        let report = AuditEngine::run(&options).unwrap();
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.category == AuditCategory::Testing));
        assert!(report
            .manifest
            .limitations
            .iter()
            .any(|limitation| limitation.code == "check_skipped"));
    }

    #[test]
    fn the_exit_code_follows_the_failure_threshold() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        fs::write(
            repo.path().join("secrets.toml"),
            "api_key = \"sk-live-abcdef1234567890\"\n",
        )
        .unwrap();

        let mut options = options(repo.path(), project.path());
        options.config.audit.fail_threshold = Severity::Critical;
        let report = AuditEngine::run(&options).unwrap();
        assert!(report.breaches_threshold(Severity::High));
        assert_eq!(report.exit_code(Severity::High), 1);
        assert_eq!(report.exit_code(Severity::Critical), 0);
    }

    #[test]
    fn audited_repository_with_a_broken_manifest_still_produces_a_report() {
        let repo = tempfile::tempdir().unwrap();
        fs::write(repo.path().join("Cargo.toml"), "[dependencies\nbroken").unwrap();
        fs::write(repo.path().join("src.rs"), "fn main() {}\n").unwrap();
        let project = tempfile::tempdir().unwrap();
        let report = AuditEngine::run(&options(repo.path(), project.path())).unwrap();
        assert!(!report.findings.is_empty());
        // The unparsable manifest is reported by the dependency checks rather
        // than aborting the run.
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.description.contains("dependency")
                || finding.description.contains("manifest")));
    }

    #[test]
    fn findings_are_ordered_by_category_then_severity() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let report = AuditEngine::run(&options(repo.path(), project.path())).unwrap();
        for window in report.findings.windows(2) {
            let (left, right) = (&window[0], &window[1]);
            assert!(
                left.category < right.category
                    || (left.category == right.category && left.severity >= right.severity),
                "findings are not ordered: {} then {}",
                left.id,
                right.id
            );
        }
    }

    #[test]
    fn a_run_without_a_configuration_still_works() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let mut config = AuditeurConfig::default();
        config.project.name = "n".to_string();
        let options = AuditOptions::new(repo.path(), AuditeurHome::at(project.path()), config);
        let report = AuditEngine::run(&options).unwrap();
        assert!(!report.findings.is_empty());
    }
}
