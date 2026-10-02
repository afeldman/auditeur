//! Findings — conclusions derived from evidence.
//!
//! Three axes are recorded separately and must never be collapsed into a single
//! score:
//!
//! * [`Status`] — the outcome of the check itself.
//! * [`Severity`] — the impact if the issue is real; declared by the audit
//!   definition, never chosen by a model.
//! * [`Confidence`] — how certain the claim is.
//!
//! A `Warn`/`Critical`/`Low` finding means "if true, this is serious, and we
//! could not confirm it" — precisely the information a single number would
//! destroy.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::category::AuditCategory;
use crate::evidence::EvidenceRef;
use crate::language::Language;
use crate::redact::redact_text;

/// Outcome of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    /// The check ran and the requirement is satisfied.
    Pass,
    /// A neutral observation worth recording, with no defect implied.
    Info,
    /// A violation that warrants attention but does not block anything.
    Warn,
    /// A violation of a hard requirement.
    Fail,
}

impl Status {
    /// Ordering rank: `Pass` < `Info` < `Warn` < `Fail`.
    pub fn rank(self) -> u8 {
        match self {
            Status::Pass => 0,
            Status::Info => 1,
            Status::Warn => 2,
            Status::Fail => 3,
        }
    }

    /// Whether this status represents a violation of the check.
    pub fn is_violation(self) -> bool {
        matches!(self, Status::Warn | Status::Fail)
    }

    /// Single-character marker used in compact report tables.
    pub fn marker(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Info => "INFO",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }

    /// All statuses in rank order.
    pub const ALL: [Status; 4] = [Status::Pass, Status::Info, Status::Warn, Status::Fail];
}

impl PartialOrd for Status {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Status {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// Impact of the issue if it is real.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// No impact; recorded for completeness.
    Info,
    /// Localised, easily remediated impact.
    Low,
    /// Meaningful impact on correctness, security or operability.
    Medium,
    /// Serious impact; should be fixed before the next release.
    High,
    /// Impact that invalidates the release or threatens data or credentials.
    Critical,
}

impl Severity {
    /// Ordering rank: `Info` < `Low` < `Medium` < `High` < `Critical`.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Stable identifier used in definitions and configuration.
    pub fn id(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// All severities in rank order.
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// Certainty of the claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Plausible but unconfirmed; often an unverified model claim.
    Low,
    /// Supported by evidence but with an inferential step.
    Medium,
    /// Established directly by observation or by a deterministic check.
    High,
}

impl Confidence {
    /// Ordering rank: `Low` < `Medium` < `High`.
    pub fn rank(self) -> u8 {
        match self {
            Confidence::Low => 0,
            Confidence::Medium => 1,
            Confidence::High => 2,
        }
    }

    /// Stable identifier used in reports.
    pub fn id(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

impl PartialOrd for Confidence {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Confidence {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// How a finding came to exist.
///
/// This is recorded so that a reader can distinguish an observation Auditeur
/// made itself from an interpretation a language model offered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FindingSource {
    /// Produced by a deterministic check from observable facts.
    Deterministic,
    /// Produced by a model and then optionally verified against the repository.
    AiAssisted {
        /// Backend identifier, e.g. `openai-compatible`.
        backend: String,
        /// Model identifier as reported by the backend.
        model: String,
        /// Id of the AI task that produced the draft.
        task_id: String,
        /// Whether every evidence reference in the finding resolved against
        /// the repository model.
        verified: bool,
    },
}

impl FindingSource {
    /// Whether this finding came from a model.
    pub fn is_ai(&self) -> bool {
        matches!(self, FindingSource::AiAssisted { .. })
    }

    /// Whether an AI-assisted finding failed evidence verification.
    pub fn is_unverified_ai(&self) -> bool {
        matches!(
            self,
            FindingSource::AiAssisted {
                verified: false,
                ..
            }
        )
    }
}

/// A conclusion derived from evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Deterministic identifier: `<definition>/<check>/<discriminator>`.
    pub id: String,
    /// Audit definition that produced this finding.
    pub definition_id: String,
    /// Check that produced this finding.
    pub check_id: String,
    /// Outcome of the check.
    pub status: Status,
    /// Impact if the issue is real.
    pub severity: Severity,
    /// Certainty of the claim.
    pub confidence: Confidence,
    /// Category for report grouping.
    pub category: AuditCategory,
    /// Short, factual title.
    pub title: String,
    /// What was observed and why it matters.
    pub description: String,
    /// Concrete next step, if one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    /// Evidence supporting this finding. Empty evidence is a defect in the
    /// check, not a valid finding.
    pub evidence: Vec<EvidenceRef>,
    /// Provenance of the finding.
    pub source: FindingSource,
    /// Language this finding concerns, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    /// Free-form labels for filtering, e.g. `["secrets", "cwe-798"]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl Finding {
    /// Create a deterministic finding with a derived identifier.
    ///
    /// `discriminator` distinguishes several findings from the same check
    /// (typically a path); it must be stable across runs.
    // One parameter per field of the finding model. A builder would add ceremony
    // and buy nothing: every call site passes all of them, in the same order, and
    // the constructor is the only place that decides how a finding is identified.
    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        definition_id: impl Into<String>,
        check_id: impl Into<String>,
        category: AuditCategory,
        severity: Severity,
        status: Status,
        discriminator: &str,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let definition_id = definition_id.into();
        let check_id = check_id.into();
        let id = crate::hash::short_id(&[&definition_id, &check_id, discriminator]);
        Self {
            id,
            definition_id,
            check_id,
            status,
            severity,
            confidence: Confidence::High,
            category,
            title: redact_text(&title.into()),
            description: redact_text(&description.into()),
            recommendation: None,
            evidence: Vec::new(),
            source: FindingSource::Deterministic,
            language: None,
            tags: Vec::new(),
        }
    }

    /// Override the confidence (used for inferential deterministic checks).
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Attach a recommendation.
    pub fn with_recommendation(mut self, recommendation: impl Into<String>) -> Self {
        let text: String = recommendation.into();
        self.recommendation = Some(redact_text(&text));
        self
    }

    /// Attach evidence, replacing any previously attached evidence.
    pub fn with_evidence(mut self, evidence: Vec<EvidenceRef>) -> Self {
        self.evidence = evidence;
        self
    }

    /// Attach the language this finding concerns.
    pub fn with_language(mut self, language: Language) -> Self {
        self.language = Some(language);
        self
    }

    /// Attach labels for filtering.
    pub fn with_tags(mut self, tags: &[&str]) -> Self {
        self.tags = tags.iter().map(|tag| (*tag).to_string()).collect();
        self
    }

    /// Mark this finding as AI-assisted with its provenance.
    pub fn from_ai(
        mut self,
        backend: impl Into<String>,
        model: impl Into<String>,
        task_id: impl Into<String>,
        verified: bool,
    ) -> Self {
        self.confidence = if verified {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        self.source = FindingSource::AiAssisted {
            backend: backend.into(),
            model: model.into(),
            task_id: task_id.into(),
            verified,
        };
        self
    }

    /// Whether this finding is an AI claim that failed evidence verification.
    pub fn is_unverified(&self) -> bool {
        self.source.is_unverified_ai()
    }

    /// Whether this finding cites at least one piece of evidence.
    pub fn has_evidence(&self) -> bool {
        !self.evidence.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(status: Status, severity: Severity) -> Finding {
        Finding::deterministic(
            "security",
            "committed-secrets",
            AuditCategory::Security,
            severity,
            status,
            "config/app.toml",
            "Credentials committed to the repository",
            "A value matching a known credential shape is present in a tracked file.",
        )
    }

    #[test]
    fn severity_and_status_ordering_is_rank_order() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Info < Severity::Low);
        assert!(Status::Fail > Status::Warn);
        assert!(Status::Pass < Status::Info);
        assert!(Confidence::High > Confidence::Low);
        assert!(Status::Warn.is_violation());
        assert!(!Status::Info.is_violation());
    }

    #[test]
    fn ids_are_deterministic_and_discriminator_sensitive() {
        let a = sample(Status::Warn, Severity::High);
        let b = sample(Status::Warn, Severity::High);
        assert_eq!(a.id, b.id);
        let mut c = sample(Status::Warn, Severity::High);
        c.id = Finding::deterministic(
            "security",
            "committed-secrets",
            AuditCategory::Security,
            Severity::High,
            Status::Warn,
            "other/file.env",
            "t",
            "d",
        )
        .id;
        assert_ne!(a.id, c.id);
    }

    #[test]
    fn unverified_ai_findings_are_low_confidence() {
        let finding = sample(Status::Info, Severity::Medium).from_ai("mock", "m", "task-1", false);
        assert!(finding.is_unverified());
        assert_eq!(finding.confidence, Confidence::Low);
        assert!(finding.source.is_ai());

        let verified = sample(Status::Info, Severity::Medium).from_ai("mock", "m", "task-1", true);
        assert!(!verified.is_unverified());
        assert_eq!(verified.confidence, Confidence::Medium);
    }

    #[test]
    fn titles_and_descriptions_are_redacted() {
        let finding = Finding::deterministic(
            "security",
            "secrets",
            AuditCategory::Security,
            Severity::High,
            Status::Fail,
            "x",
            "token = abcdefghijklmnop",
            "password: hunter2hunter2",
        );
        assert!(!finding.title.contains("abcdefghijklmnop"));
        assert!(!finding.description.contains("hunter2hunter2"));
    }

    #[test]
    fn finding_round_trips_through_json() {
        let finding = sample(Status::Warn, Severity::High)
            .with_recommendation("Rotate the credential and move it to the environment.")
            .with_tags(&["secrets", "cwe-798"])
            .with_evidence(vec![crate::evidence::EvidenceRef {
                evidence_id: "abc".into(),
                note: None,
            }]);
        let json = serde_json::to_string(&finding).unwrap();
        let parsed: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, finding);
    }

    #[test]
    fn status_serde_uses_uppercase_tokens() {
        assert_eq!(serde_json::to_string(&Status::Warn).unwrap(), "\"WARN\"");
        assert_eq!(serde_json::to_string(&Status::Pass).unwrap(), "\"PASS\"");
    }
}
