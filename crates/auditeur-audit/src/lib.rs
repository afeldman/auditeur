//! The Auditeur audit engine.
//!
//! Layering, in the order the data flows:
//!
//! ```text
//! auditeur-repository   reads the repository (the only crate that may)
//! auditeur-languages    turns files into typed per-language analyses
//! auditeur-audit        plans, checks, interprets, validates   ← this crate
//! auditeur-report       renders and persists results
//! ```
//!
//! Two properties are load-bearing:
//!
//! * **Evidence or it did not happen.** Every finding carries evidence, and a
//!   finding that cites evidence which does not exist is reported as unconfirmed
//!   rather than presented as fact.
//! * **The model is subordinate.** [`ai`] treats model output as a draft whose
//!   citations must resolve; severity always comes from the audit definition.
//!
//! The engine performs no writes: [`AuditEngine::run`] returns an
//! [`AuditReport`], and the caller decides what to persist.

pub mod ai;
pub mod checks;
pub mod context;
pub mod definitions;
pub mod engine;
pub mod error;
pub mod planner;

pub use ai::{AiRun, AiSummary};
pub use checks::Check;
pub use context::{
    AuditContext, AuditStage, EvidenceStore, ProgressSink, RecordingProgress, SilentProgress,
};
pub use definitions::{AuditDefinition, CheckKind, CheckSpec};
pub use engine::{AuditEngine, AuditOptions, AuditReport};
pub use error::AuditError;
pub use planner::{AuditPlan, PlanSkip, PlannedCheck, PlannedTask};

/// Language-analysis types that appear in an [`AuditReport`].
///
/// Re-exported so a consumer of the report does not have to depend on the
/// language crate directly: what a report exposes is the audit layer's contract.
pub use auditeur_languages::{
    AnalysisLevel, Dependency, DependencyGraph, DependencyKind, DetectionConfidence,
    LanguageAnalysis, LineStats, TestInventory,
};

/// Test support shared by the check modules.
///
/// Compiled only for tests: it exists so that a check can be exercised against a
/// real repository model and a real declaration without every test reinventing
/// the wiring.
#[cfg(test)]
pub(crate) mod testsupport {
    use std::path::Path;

    use auditeur_config::AuditConfig;
    use auditeur_model::Finding;
    use auditeur_repository::discovery::{discover, DiscoveryOptions, RepositoryModel};

    use crate::context::{AuditContext, EvidenceStore};
    use crate::definitions::{embedded, CheckSpec};

    /// The declared check specification for a definition/check pair.
    pub fn spec(definition_id: &str, check_id: &str) -> CheckSpec {
        embedded()
            .expect("embedded definitions parse")
            .into_iter()
            .find(|definition| definition.id == definition_id)
            .unwrap_or_else(|| panic!("definition {definition_id} exists"))
            .check(check_id)
            .unwrap_or_else(|| panic!("check {check_id} exists"))
            .clone()
    }

    /// A repository model plus its language analyses and default configuration.
    pub struct Fixture {
        /// The repository model.
        pub model: RepositoryModel,
        /// Audit configuration.
        pub config: AuditConfig,
        /// Language analyses for the detected languages.
        pub analyses: Vec<auditeur_languages::LanguageAnalysis>,
    }

    impl Fixture {
        /// Discover and analyse a directory.
        pub fn new(root: &Path) -> Self {
            let model = discover(root, &DiscoveryOptions::unbounded())
                .expect("fixture should be discoverable");
            let analyses = auditeur_languages::registry::analyze(
                &model,
                &auditeur_languages::LanguageOptions::default(),
            );
            Self {
                model,
                config: AuditConfig::default(),
                analyses,
            }
        }

        /// An audit context borrowing this fixture.
        pub fn context(&self) -> AuditContext<'_> {
            AuditContext::new(&self.model, &self.analyses, &self.config, None)
        }
    }

    /// Run one check against a directory and return its findings.
    pub fn run_check(check_id: &str, definition_id: &str, root: &Path) -> (Vec<Finding>, usize) {
        let fixture = Fixture::new(root);
        let check = crate::checks::find(check_id).expect("check exists");
        let spec = spec(definition_id, check_id);
        let mut store = EvidenceStore::new();
        let findings = check
            .run(&fixture.context(), &mut store, &spec)
            .expect("check runs");
        (findings, store.len())
    }
}
