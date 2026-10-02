//! Parsing of model output.
//!
//! The model is asked for a JSON object; models routinely answer with a markdown
//! code fence around it anyway. Parsing is therefore tolerant about the wrapper
//! and strict about the content: unknown fields are ignored, missing optional
//! fields default, and anything that is not JSON at all is an error.
//!
//! Nothing here decides whether a claim is true. Severity and status from the
//! model are recorded as *advisory* suggestions; the audit layer assigns the
//! authoritative severity from its definitions and verifies every reference.

use serde::Deserialize;

use crate::InferenceError;
use auditeur_model::redact::redact_text;

/// A draft finding proposed by a model.
#[derive(Debug, Clone, Deserialize)]
pub struct AiFindingDraft {
    /// Short title.
    pub title: String,
    /// Explanation.
    #[serde(default)]
    pub description: String,
    /// Advisory severity suggestion. Not authoritative.
    #[serde(default)]
    pub severity: Option<String>,
    /// Advisory status suggestion. Not authoritative.
    #[serde(default)]
    pub status: Option<String>,
    /// Advisory confidence suggestion.
    #[serde(default)]
    pub confidence: Option<String>,
    /// Cited evidence references.
    #[serde(default)]
    pub evidence: Vec<AiEvidenceDraft>,
    /// Suggested next step.
    #[serde(default)]
    pub recommendation: Option<String>,
}

impl AiFindingDraft {
    /// The references this draft cites.
    pub fn references(&self) -> Vec<&str> {
        self.evidence
            .iter()
            .map(|evidence| evidence.reference.as_str())
            .collect()
    }

    /// A redacted one-line rendering, safe for logs and reports.
    pub fn safe_title(&self) -> String {
        redact_text(&self.title)
    }

    /// A redacted description, safe for logs and reports.
    pub fn safe_description(&self) -> String {
        redact_text(&self.description)
    }
}

/// One cited reference.
#[derive(Debug, Clone, Deserialize)]
pub struct AiEvidenceDraft {
    /// The reference, which must match a reference Auditeur supplied.
    pub reference: String,
    /// Why it supports the finding.
    #[serde(default)]
    pub note: Option<String>,
}

/// A parsed model answer.
#[derive(Debug, Clone, Deserialize)]
pub struct AiResponseDraft {
    /// Proposed findings.
    #[serde(default)]
    pub findings: Vec<AiFindingDraft>,
    /// What the model could not determine.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl AiResponseDraft {
    /// An empty draft, used when a model returns nothing usable.
    pub fn empty() -> Self {
        Self {
            findings: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// All references cited by any draft finding.
    pub fn cited_references(&self) -> Vec<&str> {
        self.findings
            .iter()
            .flat_map(AiFindingDraft::references)
            .collect()
    }

    /// Redacted notes, safe for the report.
    pub fn safe_notes(&self) -> Vec<String> {
        self.notes.iter().map(|note| redact_text(note)).collect()
    }
}

/// Parse a model answer, tolerating a markdown code fence around the JSON.
pub fn parse_draft(content: &str) -> Result<AiResponseDraft, InferenceError> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(InferenceError::EmptyResponse);
    }

    let unwrapped = strip_code_fence(trimmed);
    if let Ok(draft) = serde_json::from_str::<AiResponseDraft>(unwrapped) {
        return Ok(draft);
    }

    // Second attempt: the model may have added prose before or after the object.
    if let (Some(start), Some(end)) = (unwrapped.find('{'), unwrapped.rfind('}')) {
        if end > start {
            let slice = &unwrapped[start..=end];
            if let Ok(draft) = serde_json::from_str::<AiResponseDraft>(slice) {
                return Ok(draft);
            }
        }
    }

    Err(InferenceError::InvalidJson(
        auditeur_model::redact::truncate_chars(trimmed, 200),
    ))
}

/// Remove a leading/trailing markdown code fence, if present.
fn strip_code_fence(text: &str) -> &str {
    let without_open = match text.strip_prefix("```json") {
        Some(rest) => rest.trim_start(),
        None => match text.strip_prefix("```") {
            Some(rest) => rest.trim_start(),
            None => text,
        },
    };
    match without_open.strip_suffix("```") {
        Some(rest) => rest.trim_end(),
        None => without_open,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{
      "findings": [
        {
          "title": "Module boundary bypassed",
          "description": "The handler reaches into the storage layer directly.",
          "severity": "medium",
          "status": "warn",
          "confidence": "medium",
          "evidence": [
            { "reference": "src/server.rs:42-57", "note": "direct pool access" }
          ],
          "recommendation": "Route through the repository trait."
        }
      ],
      "notes": ["Could not determine runtime behaviour."]
    }"#;

    #[test]
    fn a_plain_json_answer_parses() {
        let draft = parse_draft(GOOD).unwrap();
        assert_eq!(draft.findings.len(), 1);
        assert_eq!(draft.findings[0].references(), vec!["src/server.rs:42-57"]);
        assert_eq!(draft.safe_notes().len(), 1);
    }

    #[test]
    fn a_fenced_answer_parses() {
        let fenced = format!("```json\n{GOOD}\n```");
        assert_eq!(parse_draft(&fenced).unwrap().findings.len(), 1);

        let bare = format!("```\n{GOOD}\n```");
        assert_eq!(parse_draft(&bare).unwrap().findings.len(), 1);
    }

    #[test]
    fn an_answer_with_surrounding_prose_parses() {
        let chatty = format!("Sure, here is the JSON:\n{GOOD}\nLet me know if you need more.");
        assert_eq!(parse_draft(&chatty).unwrap().findings.len(), 1);
    }

    #[test]
    fn a_finding_without_optional_fields_parses() {
        let minimal = r#"{"findings":[{"title":"Something"}]}"#;
        let draft = parse_draft(minimal).unwrap();
        assert_eq!(draft.findings[0].title, "Something");
        assert!(draft.findings[0].evidence.is_empty());
        assert!(draft.findings[0].severity.is_none());
    }

    #[test]
    fn empty_content_is_an_empty_response_error() {
        assert!(matches!(
            parse_draft("   "),
            Err(InferenceError::EmptyResponse)
        ));
    }

    #[test]
    fn non_json_content_is_reported_with_a_bounded_redacted_message() {
        let error = parse_draft("I am sorry, I cannot help with that.").unwrap_err();
        match error {
            InferenceError::InvalidJson(message) => assert!(message.len() <= 201),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn draft_text_is_redacted_on_the_way_out() {
        let draft = parse_draft(
            r#"{"findings":[{"title":"token = abcdef123456","description":"password: hunter2hunter2"}]}"#,
        )
        .unwrap();
        assert!(!draft.findings[0].safe_title().contains("abcdef123456"));
        assert!(!draft.findings[0]
            .safe_description()
            .contains("hunter2hunter2"));
    }

    #[test]
    fn the_model_cannot_smuggle_a_path_outside_the_citation_list() {
        // Parsing does not validate references; it must not, because validation
        // belongs to the layer that owns the repository model. This test pins
        // that division: the draft simply carries what it was given.
        let draft =
            parse_draft(r#"{"findings":[{"title":"x","evidence":[{"reference":"/etc/passwd"}]}]}"#)
                .unwrap();
        assert_eq!(draft.cited_references(), vec!["/etc/passwd"]);
    }
}
