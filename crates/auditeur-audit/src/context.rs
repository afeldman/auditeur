//! The audit context: what a check is allowed to see, plus the evidence store.
//!
//! A check receives the repository model, the language analyses, the audit
//! configuration and Git state. It does not receive a path it could read, nor a
//! command it could run: everything it can learn is already in these structures.
//! That is what makes a check testable from a fixture and incapable of writing
//! to the repository.

use std::collections::HashMap;

use auditeur_config::AuditConfig;
use auditeur_languages::{Dependency, LanguageAnalysis};
use auditeur_model::{AuditCategory, Evidence, EvidenceRef, GitState, Language};
use auditeur_repository::discovery::{RepositoryModel, SourceFile};

/// Collects the evidence produced during an audit.
///
/// One store per run, shared by every check and by the AI stage. Deduplication
/// happens here: two checks observing the same fact produce one evidence item
/// with two findings pointing at it.
#[derive(Debug, Default)]
pub struct EvidenceStore {
    items: Vec<Evidence>,
    index: HashMap<String, usize>,
}

impl EvidenceStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert evidence, returning a reference to it.
    ///
    /// Inserting identical evidence twice is a no-op: the existing item is
    /// referenced instead. Identifiers are content-derived, so "identical"
    /// means the same observation about the same location.
    pub fn insert(&mut self, evidence: Evidence) -> EvidenceRef {
        let reference = evidence.reference();
        if let Some(existing) = self.index.get(&evidence.id) {
            let id = self.items[*existing].id.clone();
            return EvidenceRef {
                evidence_id: id,
                note: None,
            };
        }
        self.index.insert(evidence.id.clone(), self.items.len());
        self.items.push(evidence);
        reference
    }

    /// Insert several items, returning their references in order.
    pub fn insert_all<I>(&mut self, items: I) -> Vec<EvidenceRef>
    where
        I: IntoIterator<Item = Evidence>,
    {
        items
            .into_iter()
            .map(|evidence| self.insert(evidence))
            .collect()
    }

    /// Look up evidence by id.
    pub fn get(&self, id: &str) -> Option<&Evidence> {
        self.index.get(id).map(|index| &self.items[*index])
    }

    /// Whether an id is present.
    pub fn contains(&self, id: &str) -> bool {
        self.index.contains_key(id)
    }

    /// Number of distinct items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether nothing was collected.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// All items, in insertion order.
    pub fn items(&self) -> &[Evidence] {
        &self.items
    }

    /// Consume the store, returning its items.
    pub fn into_items(self) -> Vec<Evidence> {
        self.items
    }
}

/// A stage of the audit pipeline, reported to a [`ProgressSink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStage {
    /// Walking the repository.
    Discovery,
    /// Reading Git metadata.
    GitMetadata,
    /// Building the language analyses.
    LanguageAnalysis,
    /// Selecting checks and tasks.
    Planning,
    /// Running deterministic checks.
    DeterministicChecks,
    /// Consulting the model.
    AiAnalysis,
    /// Re-resolving citations and validating findings.
    Verification,
    /// Assembling the manifest.
    Assembly,
}

impl AuditStage {
    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            AuditStage::Discovery => "repository discovery",
            AuditStage::GitMetadata => "git metadata",
            AuditStage::LanguageAnalysis => "language analysis",
            AuditStage::Planning => "audit planning",
            AuditStage::DeterministicChecks => "deterministic checks",
            AuditStage::AiAnalysis => "model-assisted analysis",
            AuditStage::Verification => "evidence verification",
            AuditStage::Assembly => "manifest assembly",
        }
    }
}

/// Receives progress and warnings from the engine.
///
/// The engine never prints: a front-end (CLI text output, TUI screen) implements
/// this trait. That keeps the engine free of terminal concerns and lets a test
/// collect the stages instead of rendering them.
pub trait ProgressSink: Send + Sync {
    /// A stage started or advanced.
    fn stage(&self, stage: AuditStage, detail: &str);

    /// Something the audit could not do. Default: ignored.
    fn warn(&self, _message: &str) {}
}

/// A sink that discards everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct SilentProgress;

impl ProgressSink for SilentProgress {
    fn stage(&self, _stage: AuditStage, _detail: &str) {}
}

/// A sink that does nothing but record stages, used by tests.
#[derive(Debug, Default)]
pub struct RecordingProgress {
    events: std::sync::Mutex<Vec<(AuditStage, String)>>,
    warnings: std::sync::Mutex<Vec<String>>,
}

impl RecordingProgress {
    /// Create a recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stages recorded, in order.
    pub fn events(&self) -> Vec<(AuditStage, String)> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    /// Warnings recorded.
    pub fn warnings(&self) -> Vec<String> {
        self.warnings
            .lock()
            .map(|warnings| warnings.clone())
            .unwrap_or_default()
    }

    /// Stages recorded, without their detail.
    pub fn stages(&self) -> Vec<AuditStage> {
        self.events().into_iter().map(|(stage, _)| stage).collect()
    }
}

impl ProgressSink for RecordingProgress {
    fn stage(&self, stage: AuditStage, detail: &str) {
        if let Ok(mut events) = self.events.lock() {
            events.push((stage, detail.to_string()));
        }
    }

    fn warn(&self, message: &str) {
        if let Ok(mut warnings) = self.warnings.lock() {
            warnings.push(message.to_string());
        }
    }
}

/// Everything a check may look at.
#[derive(Clone, Copy)]
pub struct AuditContext<'a> {
    /// The repository model.
    pub model: &'a RepositoryModel,
    /// Per-language analyses, only for detected languages.
    pub analyses: &'a [LanguageAnalysis],
    /// Audit configuration: enabled categories, thresholds, limits.
    pub config: &'a AuditConfig,
    /// Git metadata, when the repository is a work tree.
    pub git: Option<&'a GitState>,
}

impl<'a> AuditContext<'a> {
    /// Build a context.
    pub fn new(
        model: &'a RepositoryModel,
        analyses: &'a [LanguageAnalysis],
        config: &'a AuditConfig,
        git: Option<&'a GitState>,
    ) -> Self {
        Self {
            model,
            analyses,
            config,
            git,
        }
    }

    /// Whether a category is enabled.
    pub fn is_enabled(&self, category: AuditCategory) -> bool {
        self.config.is_enabled(category)
    }

    /// The analysis for one language, if it was detected.
    pub fn analysis(&self, language: Language) -> Option<&'a LanguageAnalysis> {
        self.analyses
            .iter()
            .find(|analysis| analysis.language == language)
    }

    /// Languages detected, in report order.
    pub fn languages(&self) -> Vec<Language> {
        self.analyses
            .iter()
            .map(|analysis| analysis.language)
            .collect()
    }

    /// Every declared dependency across all detected languages.
    pub fn dependencies(&self) -> Vec<&'a Dependency> {
        self.analyses
            .iter()
            .flat_map(|analysis| analysis.dependencies.dependencies.iter())
            .collect()
    }

    /// Whether any language reports tests.
    pub fn has_tests(&self) -> bool {
        self.analyses
            .iter()
            .any(|analysis| analysis.tests.has_tests())
    }

    /// Whether a lockfile was found for any language that declares dependencies.
    pub fn lockfile_present_for(&self, language: Language) -> Option<bool> {
        self.analysis(language)
            .map(|analysis| analysis.dependencies.lockfile_present)
    }

    /// All text files in the repository model.
    pub fn text_files(&self) -> Vec<&'a SourceFile> {
        self.model
            .files()
            .iter()
            .filter(|file| file.is_text())
            .collect()
    }

    /// Text files attributed to a specific language.
    pub fn text_files_of(&self, language: Language) -> Vec<&'a SourceFile> {
        self.model.text_files_for_language(language)
    }

    /// Total number of inspected source files (text files with a language).
    pub fn source_file_count(&self) -> u32 {
        self.model
            .files()
            .iter()
            .filter(|file| file.is_text() && file.language.is_some())
            .count() as u32
    }

    /// Files whose final path component is one of `names`, case-insensitively.
    pub fn files_named_any(&self, names: &[&str]) -> Vec<&'a SourceFile> {
        self.model
            .files()
            .iter()
            .filter(|file| {
                let candidate = file.file_name().to_ascii_lowercase();
                names
                    .iter()
                    .any(|name| candidate == name.to_ascii_lowercase())
            })
            .collect()
    }

    /// Determine the category a check belongs to is available via configuration.
    pub fn category_enabled_count(&self) -> usize {
        self.config.enabled_categories.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_model::EvidenceKind;

    fn evidence(path: &str) -> Evidence {
        Evidence::file(path, format!("observed {path}"))
    }

    #[test]
    fn identical_evidence_is_stored_once() {
        let mut store = EvidenceStore::new();
        let first = store.insert(evidence("a.txt"));
        let second = store.insert(evidence("a.txt"));
        assert_eq!(first.evidence_id, second.evidence_id);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn different_evidence_is_kept_separately() {
        let mut store = EvidenceStore::new();
        store.insert(evidence("a.txt"));
        store.insert(evidence("b.txt"));
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
        assert_eq!(store.items().len(), 2);
    }

    #[test]
    fn insertion_order_is_preserved() {
        let mut store = EvidenceStore::new();
        store.insert(evidence("first.txt"));
        store.insert(evidence("second.txt"));
        let paths: Vec<&str> = store
            .items()
            .iter()
            .filter_map(|evidence| match &evidence.location {
                auditeur_model::EvidenceLocation::File { path } => Some(path.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(paths, vec!["first.txt", "second.txt"]);
        assert_eq!(store.items()[0].kind, EvidenceKind::FileContent);
    }

    #[test]
    fn insertion_returns_a_usable_reference() {
        let mut store = EvidenceStore::new();
        let reference = store.insert(evidence("a.txt"));
        assert!(store.contains(&reference.evidence_id));
        assert!(store.get(&reference.evidence_id).is_some());
        assert!(store.get("missing").is_none());
    }

    #[test]
    fn insert_all_returns_references_in_order() {
        let mut store = EvidenceStore::new();
        let references = store.insert_all(vec![evidence("a"), evidence("b")]);
        assert_eq!(references.len(), 2);
        assert_ne!(references[0].evidence_id, references[1].evidence_id);
        assert_eq!(store.into_items().len(), 2);
    }

    #[test]
    fn the_recording_sink_captures_stages_and_warnings() {
        let sink = RecordingProgress::new();
        sink.stage(AuditStage::Discovery, "starting");
        sink.warn("something was skipped");
        assert_eq!(sink.stages(), vec![AuditStage::Discovery]);
        assert_eq!(sink.events()[0].1, "starting");
        assert_eq!(sink.warnings(), vec!["something was skipped".to_string()]);
    }

    #[test]
    fn stages_have_distinct_labels() {
        let stages = [
            AuditStage::Discovery,
            AuditStage::GitMetadata,
            AuditStage::LanguageAnalysis,
            AuditStage::Planning,
            AuditStage::DeterministicChecks,
            AuditStage::AiAnalysis,
            AuditStage::Verification,
            AuditStage::Assembly,
        ];
        let mut labels = std::collections::HashSet::new();
        for stage in stages {
            assert!(
                labels.insert(stage.label()),
                "duplicate label for {stage:?}"
            );
        }
    }
}
