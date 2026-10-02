//! Deterministic checks and the check registry.
//!
//! A [`Check`] is a rule with an id, and nothing else. It receives the audit
//! context (repository model, language analyses, configuration, Git state) and
//! the evidence store, and returns findings that cite evidence. It cannot read a
//! file directly, cannot run a command, and cannot see the model.
//!
//! Severity, category and the recommendation text come from the *definition*
//! ([`CheckSpec`]), not from the check, so that what a report claims about
//! severity is traceable to a declarative file rather than to a constant buried
//! in Rust.

pub mod architecture;
pub mod configuration;
pub mod dependencies;
pub mod documentation;
pub mod quality;
pub mod release;
pub mod scan;
pub mod security;
pub mod testing;

use auditeur_model::{Confidence, EvidenceRef, Finding, Status};

use crate::context::{AuditContext, EvidenceStore};
use crate::definitions::CheckSpec;
use crate::error::AuditError;

/// A deterministic auditing rule.
pub trait Check: Send + Sync {
    /// Check identifier, matching a check declared in a definition.
    fn id(&self) -> &'static str;

    /// Definition the check belongs to.
    fn definition_id(&self) -> &'static str;

    /// Run the check.
    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError>;
}

/// Build a finding from its check specification.
///
/// This is the only place deterministic findings are constructed, so the
/// invariant "a deterministic finding has high confidence and carries the
/// declared severity" holds by construction.
pub fn finding(
    definition_id: &str,
    spec: &CheckSpec,
    status: Status,
    discriminator: &str,
    description: impl Into<String>,
    evidence: Vec<EvidenceRef>,
) -> Finding {
    let mut finding = Finding::deterministic(
        definition_id,
        &spec.id,
        spec.category,
        spec.severity,
        status,
        discriminator,
        &spec.title,
        description,
    );
    finding.confidence = Confidence::High;
    if let Some(recommendation) = &spec.recommendation {
        finding = finding.with_recommendation(recommendation.clone());
    }
    finding.with_evidence(evidence)
}

/// A passing finding for a check, used when nothing was found.
pub fn pass(
    definition_id: &str,
    spec: &CheckSpec,
    description: impl Into<String>,
    evidence: Vec<EvidenceRef>,
) -> Finding {
    finding(
        definition_id,
        spec,
        Status::Pass,
        "pass",
        description,
        evidence,
    )
}

/// Every check implementation, in report order.
pub fn implementations() -> Vec<Box<dyn Check>> {
    let mut checks: Vec<Box<dyn Check>> = Vec::new();
    checks.extend(security::checks());
    checks.extend(quality::checks());
    checks.extend(dependencies::checks());
    checks.extend(testing::checks());
    checks.extend(documentation::checks());
    checks.extend(architecture::checks());
    checks.extend(configuration::checks());
    checks.extend(release::checks());
    checks
}

/// Find a check by id.
pub fn find(id: &str) -> Option<Box<dyn Check>> {
    implementations().into_iter().find(|check| check.id() == id)
}

/// Ids of every implemented check.
pub fn ids() -> Vec<&'static str> {
    implementations().iter().map(|check| check.id()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_ids_are_unique_and_non_empty() {
        let mut seen = std::collections::HashSet::new();
        for check in implementations() {
            let id = check.id();
            assert!(!id.trim().is_empty());
            assert!(seen.insert(id), "duplicate check id {id}");
            assert!(!check.definition_id().trim().is_empty());
        }
        assert!(seen.len() >= 15, "MVP should implement a meaningful set");
    }

    #[test]
    fn lookup_by_id_works_and_misses_are_reported() {
        assert!(find("committed-secrets").is_some());
        assert!(find("does-not-exist").is_none());
        assert_eq!(
            find("committed-secrets").unwrap().definition_id(),
            "security"
        );
    }

    #[test]
    fn a_finding_carries_the_declared_severity_and_high_confidence() {
        use auditeur_model::{AuditCategory, Severity};
        let spec = CheckSpec {
            id: "x".to_string(),
            title: "X".to_string(),
            description: String::new(),
            kind: crate::definitions::CheckKind::Deterministic,
            category: AuditCategory::Security,
            severity: Severity::Critical,
            recommendation: Some("Fix it.".to_string()),
            objective: None,
        };
        let finding = finding("security", &spec, Status::Fail, "d", "found", Vec::new());
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(finding.category, AuditCategory::Security);
        assert_eq!(finding.recommendation.as_deref(), Some("Fix it."));
        assert_eq!(finding.status, Status::Fail);
        assert!(finding.source == auditeur_model::FindingSource::Deterministic);
    }
}
