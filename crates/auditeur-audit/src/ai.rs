//! The model-assisted stage.
//!
//! The model is given a structured task built by Auditeur: an objective from the
//! audit definition, the evidence already collected for that category, a file
//! inventory, and an explicit list of references it may cite. It is given
//! nothing else.
//!
//! Everything it returns is treated as a *draft*. A draft becomes a finding only
//! after every citation in it has been resolved: the reference must be one
//! Auditeur supplied, and the path it names must exist in the repository model.
//! A draft whose citations do not resolve is still recorded — hiding it would
//! hide model failure — but it is marked unverified and carries low confidence.
//!
//! Severity always comes from the audit definition. The model's severity
//! suggestion is recorded in the description as the suggestion it is.

use std::collections::HashMap;

use auditeur_config::ModelConfig;
use auditeur_inference::task::{BundleItem, EvidenceBundle};
use auditeur_inference::{
    completion_request, parse_draft, AuditTask, InferenceBackend, InferenceError,
};
use auditeur_model::redact::redact_text;
use auditeur_model::{AuditCategory, EvidenceRef, Finding, Severity, Status};

use crate::context::{AuditContext, EvidenceStore};
use crate::planner::PlannedTask;

/// Maximum evidence items placed in one task bundle.
pub const MAX_BUNDLE_ITEMS: usize = 24;
/// Maximum manifest excerpts added to a bundle.
pub const MAX_MANIFEST_ITEMS: usize = 4;
/// Maximum lines taken from a manifest excerpt.
pub const MAX_MANIFEST_LINES: usize = 60;
/// Maximum file paths listed in the inventory item.
pub const MAX_INVENTORY_PATHS: usize = 200;
/// Maximum drafts accepted from one task.
pub const MAX_FINDINGS_PER_TASK: usize = 20;
/// Maximum tasks run in one audit, as a cost and time bound.
pub const MAX_TASKS: usize = 8;

/// What the model-assisted stage did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AiSummary {
    /// Tasks for which a request was sent, whether or not it succeeded.
    pub tasks_attempted: u32,
    /// Tasks that produced a parsable answer.
    pub tasks_run: u32,
    /// Tasks that failed (transport, decode, parse).
    pub tasks_failed: u32,
    /// Draft findings received.
    pub drafts_received: u32,
    /// Draft findings whose citations all resolved.
    pub drafts_verified: u32,
    /// Draft findings with at least one unresolvable citation.
    pub drafts_unverified: u32,
    /// Notes from the model, redacted.
    pub notes: Vec<String>,
    /// What went wrong, for the report's limitations section.
    pub limitations: Vec<String>,
}

impl AiSummary {
    /// Total drafts received.
    pub fn drafts_total(&self) -> u32 {
        self.drafts_verified + self.drafts_unverified
    }
}

/// Result of the model-assisted stage.
#[derive(Debug, Clone, Default)]
pub struct AiRun {
    /// Findings derived from drafts.
    pub findings: Vec<Finding>,
    /// What happened.
    pub summary: AiSummary,
}

/// Run every planned task against `backend`.
///
/// Never returns an error: a task that fails becomes a recorded limitation and
/// the audit continues with the deterministic evidence it already has. An audit
/// that aborts because a model was unavailable would be worse than useless.
pub fn run_tasks(
    backend: &dyn InferenceBackend,
    tasks: &[PlannedTask],
    context: &AuditContext<'_>,
    model_config: &ModelConfig,
    findings: &[Finding],
    evidence: &mut EvidenceStore,
) -> AiRun {
    let mut run = AiRun::default();

    for task in tasks.iter().take(MAX_TASKS) {
        let objective = task.spec.objective.clone().unwrap_or_else(|| {
            format!(
                "Review the evidence collected for {}",
                task.spec.category.label()
            )
        });

        let (bundle, index) = build_bundle(task, context, findings, evidence);
        let audit_task = AuditTask::new(
            format!("{}/{}#1", task.definition_id, task.spec.id),
            task.spec.category,
            objective,
            bundle,
        );

        let request = completion_request(
            &audit_task,
            model_config.max_output_tokens,
            model_config.temperature,
        );

        let response = match backend.complete(&request) {
            Ok(response) => response,
            Err(error) => {
                run.summary.tasks_attempted += 1;
                run.summary.tasks_failed += 1;
                run.summary.limitations.push(match &error {
                    InferenceError::Timeout { seconds } => format!(
                        "task '{}' did not complete: the model did not answer within {seconds}s",
                        audit_task.id
                    ),
                    other => format!("task '{}' did not complete: {other}", audit_task.id),
                });
                continue;
            }
        };
        run.summary.tasks_attempted += 1;

        let draft = match parse_draft(&response.content) {
            Ok(draft) => draft,
            Err(error) => {
                run.summary.tasks_failed += 1;
                run.summary.limitations.push(format!(
                    "task '{}' returned an unusable answer: {error}",
                    audit_task.id
                ));
                continue;
            }
        };
        run.summary.tasks_run += 1;
        run.summary.notes.extend(draft.safe_notes());

        for (position, draft_finding) in draft
            .findings
            .iter()
            .take(MAX_FINDINGS_PER_TASK)
            .enumerate()
        {
            run.summary.drafts_received += 1;

            let cited = draft_finding.references();
            let mut resolved: Vec<EvidenceRef> = Vec::new();
            for reference in &cited {
                if let Some(reference) = resolve_reference(reference, &index, context) {
                    resolved.push(reference);
                }
            }
            let complete = !cited.is_empty() && resolved.len() == cited.len();
            if complete {
                run.summary.drafts_verified += 1;
            } else {
                run.summary.drafts_unverified += 1;
            }

            let mut description = draft_finding.safe_description();
            if !complete {
                description.push_str(&format!(
                    "\n\nVerification: {} of {} cited reference(s) could not be resolved against the repository, so this claim is unverified.",
                    cited.len() - resolved.len(),
                    cited.len()
                ));
            }
            if let Some(suggested) = &draft_finding.severity {
                if parse_severity(suggested) != Some(task.spec.severity) {
                    description.push_str(&format!(
                        "\n\nSeverity: the model suggested '{suggested}'; Auditeur reports the severity declared by the audit definition ('{}').",
                        task.spec.severity.id()
                    ));
                }
            }

            let status = draft_finding
                .status
                .as_deref()
                .and_then(parse_status)
                .unwrap_or(if complete { Status::Info } else { Status::Warn });

            let mut finding = Finding::deterministic(
                &task.definition_id,
                &task.spec.id,
                task.spec.category,
                task.spec.severity,
                status,
                &format!("{}#{position}", audit_task.id),
                draft_finding.safe_title(),
                description,
            )
            .with_evidence(resolved)
            .with_tags(&["ai-assisted"]);
            if let Some(recommendation) = &draft_finding.recommendation {
                finding = finding.with_recommendation(redact_text(recommendation));
            }
            if !complete {
                finding = finding.with_tags(&["ai-assisted", "unverified"]);
            }
            finding = finding.from_ai(
                backend.id(),
                response.model.clone(),
                audit_task.id.clone(),
                complete,
            );
            finding.language = context.languages().first().copied();
            run.findings.push(finding);
        }
    }

    if tasks.len() > MAX_TASKS {
        run.summary.limitations.push(format!(
            "{} model-assisted task(s) were not run: the per-run task limit is {MAX_TASKS}",
            tasks.len() - MAX_TASKS
        ));
    }

    run
}

/// Structural bundle items that are context rather than evidence.
///
/// They are shown to the model so it can reason about the repository shape, but
/// they are not offered as citable references: there is nothing to verify.
const STRUCTURAL_REFERENCES: &[&str] = &["repository-structure"];

/// Build the evidence bundle for a task, plus a reference→evidence index.
///
/// Manifest excerpts are inserted into the run's evidence store, so that a
/// citation of a manifest resolves to stored, redacted evidence rather than to a
/// identifier that exists only in this function.
fn build_bundle(
    task: &PlannedTask,
    context: &AuditContext<'_>,
    findings: &[Finding],
    evidence: &mut EvidenceStore,
) -> (EvidenceBundle, HashMap<String, String>) {
    let mut items: Vec<BundleItem> = Vec::new();
    let mut index: HashMap<String, String> = HashMap::new();

    // 1. Evidence that the deterministic checks produced for this category.
    for finding in findings
        .iter()
        .filter(|finding| finding.category == task.spec.category)
    {
        for reference in &finding.evidence {
            if items.len() >= MAX_BUNDLE_ITEMS {
                break;
            }
            let Some(item) = evidence.get(&reference.evidence_id) else {
                continue;
            };
            let key = item.location.describe();
            if index.contains_key(&key) {
                continue;
            }
            index.insert(key.clone(), item.id.clone());
            items.push(BundleItem::new(
                key,
                item.kind.label(),
                format!(
                    "evidence for {} ({})",
                    finding.check_id,
                    finding.status.marker()
                ),
                item.excerpt.clone().unwrap_or_else(|| item.summary.clone()),
            ));
        }
    }

    // 2. Manifests, so the model can see the declared project shape.
    let mut manifest_items = 0usize;
    for analysis in context.analyses {
        for manifest in &analysis.dependencies.manifests {
            if manifest_items >= MAX_MANIFEST_ITEMS || items.len() >= MAX_BUNDLE_ITEMS {
                break;
            }
            let Some(file) = context.model.file(manifest) else {
                continue;
            };
            let Ok(text) = context.model.read_source_text(file) else {
                continue;
            };
            let excerpt: String = text
                .lines()
                .take(MAX_MANIFEST_LINES)
                .collect::<Vec<_>>()
                .join("\n");
            let key = manifest.clone();
            if index.contains_key(&key) {
                continue;
            }
            // Redact before the text can reach a model prompt.
            let redacted = redact_text(&excerpt);
            let evidence_item = auditeur_model::Evidence::file(
                manifest.clone(),
                format!("{} manifest", analysis.language.label()),
            )
            .with_excerpt(&redacted);
            let stored = evidence.insert(evidence_item);
            index.insert(key.clone(), stored.evidence_id);
            items.push(BundleItem::new(
                key,
                "manifest",
                format!("{} project manifest", analysis.language.label()),
                redacted,
            ));
            manifest_items += 1;
        }
    }

    // 3. A bounded file inventory, so the model can reason about structure.
    let inventory: Vec<String> = context
        .model
        .files()
        .iter()
        .take(MAX_INVENTORY_PATHS)
        .map(|file| file.relative_path.clone())
        .collect();
    if !inventory.is_empty() {
        items.push(BundleItem::new(
            "repository-structure",
            "directory listing",
            "file inventory of the audited repository",
            inventory.join("\n"),
        ));
    }

    let mut bundle = EvidenceBundle::from_items(items);
    // Structural context is not citable evidence.
    bundle
        .known_references
        .retain(|reference| !STRUCTURAL_REFERENCES.contains(&reference.as_str()));
    (bundle, index)
}

/// Resolve a model citation to stored evidence.
///
/// Two conditions, both required: the reference must be one Auditeur supplied,
/// and the path it names must exist in the repository model. This is the check
/// that stops a plausible sentence from becoming an accepted fact.
fn resolve_reference(
    reference: &str,
    index: &HashMap<String, String>,
    context: &AuditContext<'_>,
) -> Option<EvidenceRef> {
    let reference = reference.trim();
    let evidence_id = index.get(reference)?;
    if evidence_id.is_empty() {
        // A structural item is context, not evidence, and is not citable.
        return None;
    }

    let path = reference.split(':').next().unwrap_or(reference);
    let path_exists = context.model.has_file(path)
        || context.model.has_dir(path)
        || context.model.has_dir(path.trim_end_matches('/'));
    if !path_exists {
        return None;
    }

    Some(EvidenceRef {
        evidence_id: evidence_id.clone(),
        note: None,
    })
}

/// Parse a severity suggestion. Never authoritative.
fn parse_severity(value: &str) -> Option<Severity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" | "moderate" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" | "severe" => Some(Severity::Critical),
        _ => None,
    }
}

/// Parse a status suggestion. Never authoritative.
fn parse_status(value: &str) -> Option<Status> {
    match value.trim().to_ascii_lowercase().as_str() {
        "pass" => Some(Status::Pass),
        "info" | "informational" => Some(Status::Info),
        "warn" | "warning" => Some(Status::Warn),
        "fail" | "error" => Some(Status::Fail),
        _ => None,
    }
}

/// Categories for which a task would be built, for diagnostics.
pub fn planned_categories(tasks: &[PlannedTask]) -> Vec<AuditCategory> {
    let mut categories: Vec<AuditCategory> = tasks.iter().map(|task| task.spec.category).collect();
    categories.sort();
    categories.dedup();
    categories
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::Fixture;
    use auditeur_inference::MockBackend;
    use std::fs;

    fn planned(category: AuditCategory) -> PlannedTask {
        let definition = crate::definitions::embedded()
            .unwrap()
            .into_iter()
            .find(|definition| {
                definition
                    .checks
                    .iter()
                    .any(|check| check.category == category)
            })
            .unwrap();
        let spec = definition
            .checks
            .iter()
            .find(|check| check.kind.needs_model() && check.category == category)
            .or_else(|| definition.checks.first())
            .unwrap()
            .clone();
        PlannedTask {
            definition_id: definition.id,
            spec,
        }
    }

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        temp
    }

    #[test]
    fn a_verified_citation_is_accepted() {
        let temp = fixture();
        let fixture = Fixture::new(temp.path());
        let mut store = EvidenceStore::new();
        let tasks = vec![planned(AuditCategory::Security)];

        // The bundle always carries the manifests, so a citation of one can be
        // resolved and verified.
        let backend = MockBackend::with_response(
            r#"{"findings":[{"title":"Dependency declared without features","description":"serde is declared with default features.","evidence":[{"reference":"Cargo.toml"}]}],"notes":["checked"]}"#,
        );

        let run = run_tasks(
            &backend,
            &tasks,
            &fixture.context(),
            &ModelConfig::default(),
            &[],
            &mut store,
        );

        assert_eq!(run.summary.tasks_run, 1);
        assert_eq!(run.summary.drafts_total(), 1);
        assert_eq!(run.findings.len(), 1);
        assert!(!run.findings[0].is_unverified());
        assert!(run.findings[0].source.is_ai());
        assert!(run.findings[0].has_evidence());
        assert!(run.summary.notes.contains(&"checked".to_string()));
    }

    #[test]
    fn a_file_outside_the_supplied_bundle_is_not_citable_even_if_it_exists() {
        let temp = fixture();
        let fixture = Fixture::new(temp.path());
        let mut store = EvidenceStore::new();
        let tasks = vec![planned(AuditCategory::Security)];

        // src/lib.rs exists, but no deterministic check supplied it for this
        // task, so it is not a citable reference: the model does not get to
        // widen its own evidence base.
        let backend = MockBackend::with_response(
            r#"{"findings":[{"title":"Something in lib.rs","description":"x","evidence":[{"reference":"src/lib.rs"}]}]}"#,
        );

        let run = run_tasks(
            &backend,
            &tasks,
            &fixture.context(),
            &ModelConfig::default(),
            &[],
            &mut store,
        );

        assert_eq!(run.findings.len(), 1);
        assert!(run.findings[0].is_unverified());
    }

    #[test]
    fn an_invented_citation_is_marked_unverified_rather_than_believed() {
        let temp = fixture();
        let fixture = Fixture::new(temp.path());
        let mut store = EvidenceStore::new();
        let tasks = vec![planned(AuditCategory::Security)];

        let backend = MockBackend::with_response(
            r#"{"findings":[{"title":"Imaginary problem","description":"In a file that does not exist.","evidence":[{"reference":"src/does-not-exist.rs:10-20"}]}]}"#,
        );

        let run = run_tasks(
            &backend,
            &tasks,
            &fixture.context(),
            &ModelConfig::default(),
            &[],
            &mut store,
        );

        assert_eq!(run.findings.len(), 1);
        assert!(run.findings[0].is_unverified());
        assert_eq!(run.findings[0].confidence, auditeur_model::Confidence::Low);
        assert!(run.findings[0].description.contains("unverified"));
        assert!(run.findings[0].tags.contains(&"unverified".to_string()));
    }

    #[test]
    fn the_model_cannot_change_the_severity_auditeur_reports() {
        let temp = fixture();
        let fixture = Fixture::new(temp.path());
        let mut store = EvidenceStore::new();
        let tasks = vec![planned(AuditCategory::Security)];

        let backend = MockBackend::with_response(
            r#"{"findings":[{"title":"Critical thing","description":"x","severity":"critical","evidence":[{"reference":"src/lib.rs"}]}]}"#,
        );

        let run = run_tasks(
            &backend,
            &tasks,
            &fixture.context(),
            &ModelConfig::default(),
            &[],
            &mut store,
        );

        let definition_severity = tasks[0].spec.severity;
        assert_eq!(run.findings[0].severity, definition_severity);
        if definition_severity != Severity::Critical {
            assert!(run.findings[0]
                .description
                .contains("the model suggested 'critical'"));
        }
    }

    #[test]
    fn a_failing_backend_becomes_a_limitation_not_an_error() {
        let temp = fixture();
        let fixture = Fixture::new(temp.path());
        let mut store = EvidenceStore::new();
        let tasks = vec![planned(AuditCategory::Security)];

        let backend = MockBackend::with_response("this is not json at all");

        let run = run_tasks(
            &backend,
            &tasks,
            &fixture.context(),
            &ModelConfig::default(),
            &[],
            &mut store,
        );

        assert_eq!(run.summary.tasks_attempted, 1);
        assert_eq!(run.summary.tasks_run, 0);
        assert_eq!(run.summary.tasks_failed, 1);
        assert!(run.findings.is_empty());
        assert!(run.summary.limitations[0].contains("unusable answer"));
    }

    #[test]
    fn the_prompt_sent_to_the_model_is_fenced_and_reference_listed() {
        let temp = fixture();
        let fixture = Fixture::new(temp.path());
        let mut store = EvidenceStore::new();
        let tasks = vec![planned(AuditCategory::Security)];

        let backend = MockBackend::empty();
        run_tasks(
            &backend,
            &tasks,
            &fixture.context(),
            &ModelConfig::default(),
            &[],
            &mut store,
        );

        let requests = backend.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].system, auditeur_inference::SYSTEM_INSTRUCTIONS);
        assert!(requests[0]
            .user
            .contains(auditeur_inference::prompt::FENCE_OPEN));
        assert!(requests[0].user.contains("Allowed evidence references"));
        assert!(requests[0].user.contains("repository-structure"));
    }

    #[test]
    fn an_empty_draft_produces_no_findings() {
        let temp = fixture();
        let fixture = Fixture::new(temp.path());
        let mut store = EvidenceStore::new();
        let tasks = vec![planned(AuditCategory::Security)];

        let run = run_tasks(
            &MockBackend::empty(),
            &tasks,
            &fixture.context(),
            &ModelConfig::default(),
            &[],
            &mut store,
        );

        assert!(run.findings.is_empty());
        assert_eq!(run.summary.tasks_run, 1);
        assert!(run
            .summary
            .notes
            .iter()
            .any(|note| note.contains("no analysis")));
    }

    #[test]
    fn severity_and_status_parsing_is_lenient_but_bounded() {
        assert_eq!(parse_severity("HIGH"), Some(Severity::High));
        assert_eq!(parse_severity("severe"), Some(Severity::Critical));
        assert_eq!(parse_severity("catastrophic"), None);
        assert_eq!(parse_status("Warning"), Some(Status::Warn));
        assert_eq!(parse_status("nonsense"), None);
    }

    #[test]
    fn planned_categories_are_deduplicated() {
        let tasks = vec![
            planned(AuditCategory::Security),
            planned(AuditCategory::Security),
        ];
        assert_eq!(planned_categories(&tasks), vec![AuditCategory::Security]);
    }
}
