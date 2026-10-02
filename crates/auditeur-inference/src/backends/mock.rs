//! A deterministic offline backend.
//!
//! This is a **test double**, not a model. It exists so that the audit pipeline
//! around the inference layer can be tested deterministically, and so that a run
//! can be executed end-to-end without any inference server. It performs no
//! analysis whatsoever; a report produced with it says so in its limitations.
//!
//! By default it answers with an empty findings list. Tests that need a
//! particular answer give it one explicitly, which makes the injection and
//! verification paths testable without a network.

use std::sync::Mutex;

use crate::{
    BackendCapabilities, CompletionRequest, CompletionResponse, HealthReport, InferenceBackend,
};

/// Answer returned when no explicit response was configured.
pub const EMPTY_RESPONSE: &str =
    r#"{"findings":[],"notes":["mock backend: no analysis was performed"]}"#;

/// A deterministic, offline backend.
#[derive(Debug)]
pub struct MockBackend {
    model: String,
    response: String,
    requests: Mutex<Vec<CompletionRequest>>,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::empty()
    }
}

impl MockBackend {
    /// A backend that answers with an empty findings list.
    pub fn empty() -> Self {
        Self::with_response(EMPTY_RESPONSE)
    }

    /// A backend that always answers with `response`.
    ///
    /// Used by tests to exercise the parsing, verification and rejection paths
    /// with a response the test controls.
    pub fn with_response(response: impl Into<String>) -> Self {
        Self {
            model: "mock".to_string(),
            response: response.into(),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Every request this backend has received, in order.
    ///
    /// Lets a test assert what Auditeur actually sent: which task, which
    /// references, and that the system prompt was the compiled-in constant.
    pub fn requests(&self) -> Vec<CompletionRequest> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .unwrap_or_default()
    }

    /// Number of requests received.
    pub fn request_count(&self) -> usize {
        self.requests
            .lock()
            .map(|requests| requests.len())
            .unwrap_or(0)
    }
}

impl InferenceBackend for MockBackend {
    fn id(&self) -> &str {
        "mock"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::mock()
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn health(&self) -> HealthReport {
        HealthReport::new(
            self.id(),
            true,
            "mock backend: deterministic, offline, performs no analysis",
        )
    }

    fn complete(
        &self,
        request: &CompletionRequest,
    ) -> Result<CompletionResponse, crate::InferenceError> {
        if let Ok(mut requests) = self.requests.lock() {
            requests.push(request.clone());
        }
        Ok(CompletionResponse {
            backend: self.id().to_string(),
            model: self.model.clone(),
            content: self.response.clone(),
            usage: None,
            latency_ms: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{completion_request, task::AuditTask, task::EvidenceBundle};
    use auditeur_model::AuditCategory;

    fn request() -> CompletionRequest {
        let task = AuditTask::new(
            "testing/gap#1",
            AuditCategory::Testing,
            "Are tests present?",
            EvidenceBundle::default(),
        );
        completion_request(&task, 512, 0.0)
    }

    #[test]
    fn the_default_answer_is_empty_and_honest() {
        let backend = MockBackend::empty();
        let response = backend.complete(&request()).unwrap();
        let draft = crate::parse_draft(&response.content).unwrap();
        assert!(draft.findings.is_empty());
        assert!(draft.notes[0].contains("no analysis was performed"));
    }

    #[test]
    fn requests_are_recorded_for_assertions() {
        let backend = MockBackend::empty();
        assert_eq!(backend.request_count(), 0);
        backend.complete(&request()).unwrap();
        backend.complete(&request()).unwrap();
        assert_eq!(backend.request_count(), 2);
        let requests = backend.requests();
        assert_eq!(requests[0].task_id, "testing/gap#1");
        // The system prompt is always the compiled-in constant.
        assert_eq!(requests[0].system, crate::SYSTEM_INSTRUCTIONS);
        assert!(requests[0].user.contains(crate::prompt::FENCE_OPEN));
    }

    #[test]
    fn a_scripted_answer_is_returned_verbatim() {
        let backend = MockBackend::with_response(r#"{"findings":[{"title":"x"}]}"#);
        let response = backend.complete(&request()).unwrap();
        let draft = crate::parse_draft(&response.content).unwrap();
        assert_eq!(draft.findings.len(), 1);
    }

    #[test]
    fn the_mock_declares_its_limits() {
        let backend = MockBackend::default();
        let capabilities = backend.capabilities();
        assert!(!capabilities.streaming);
        assert!(!capabilities.model_listing);
        assert!(backend.health().reachable);
    }
}
