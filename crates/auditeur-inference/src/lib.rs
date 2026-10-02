//! Inference: the model layer.
//!
//! Two rules define this crate.
//!
//! **The backend is not the source of truth.** A backend receives a
//! [`CompletionRequest`] and returns text. It knows nothing about severities,
//! findings, audit scope or the repository; it cannot widen or narrow an audit.
//!
//! **Repository content is untrusted data.** Every prompt is assembled by
//! [`prompt`], which places repository text inside an unforgeable fence and
//! states in the compiled-in system instructions that fenced content is data.
//! The fence tokens are stripped from the payload, so a repository cannot close
//! the fence early and write its own instructions.
//!
//! Acceleration: hardware detection here is real and runtime-based
//! ([`hardware::detect`]). There are no `metal`/`cuda` Cargo features in this
//! iteration because the only backend is an HTTP client — acceleration applies
//! to the *server*, and a compile-time feature that gated nothing would be fake
//! support. Per-backend features arrive with the in-process `llama.cpp` backend.

// Test fixtures build configurations field by field, which reads better than a
// twelve-field struct literal. Production code is still held to the lint.
#![cfg_attr(test, allow(clippy::field_reassign_with_default))]

pub mod backends;
pub mod draft;
pub mod hardware;
pub mod prompt;
pub mod task;

use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use backends::{mock::MockBackend, openai_compat::OpenAiCompatBackend};
pub use draft::{parse_draft, AiEvidenceDraft, AiFindingDraft, AiResponseDraft};
pub use hardware::{Accelerator, Availability, HardwareReport};
pub use prompt::{render_task, SYSTEM_INSTRUCTIONS};
pub use task::{AuditTask, BundleItem, EvidenceBundle};

/// Errors raised by the inference layer.
#[derive(Debug, thiserror::Error)]
pub enum InferenceError {
    /// The backend is not configured well enough to use.
    #[error("inference is not configured: {0}")]
    NotConfigured(String),

    /// The endpoint could not be reached.
    #[error("cannot reach the inference endpoint {endpoint}: {message}")]
    Transport {
        /// Endpoint that failed.
        endpoint: String,
        /// Underlying transport message.
        message: String,
    },

    /// The endpoint answered with an error status.
    #[error("inference endpoint {endpoint} returned HTTP {status}: {body}")]
    HttpStatus {
        /// Endpoint that answered.
        endpoint: String,
        /// HTTP status code.
        status: u16,
        /// Response body, truncated and redacted.
        body: String,
    },

    /// The response could not be decoded.
    #[error("cannot decode the inference response: {0}")]
    Decode(String),

    /// The response did not contain any content.
    #[error("the model returned no content")]
    EmptyResponse,

    /// The request exceeded the configured timeout.
    #[error("the model did not answer within {seconds}s")]
    Timeout {
        /// Configured timeout in seconds.
        seconds: u64,
    },

    /// The response was not valid JSON for the requested schema.
    #[error("the model response is not valid JSON: {0}")]
    InvalidJson(String),
}

impl InferenceError {
    /// Whether the failure is a connectivity problem rather than a model problem.
    pub fn is_transport(&self) -> bool {
        matches!(
            self,
            InferenceError::Transport { .. } | InferenceError::Timeout { .. }
        )
    }
}

/// Token usage reported by a backend, when it reports any.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Tokens in the prompt.
    pub prompt_tokens: u32,
    /// Tokens generated.
    pub completion_tokens: u32,
    /// Total tokens, as reported or summed.
    pub total_tokens: u32,
}

/// What a backend can do.
///
/// Declared honestly: `doctor` prints exactly this, so a false declaration shows
/// up as a broken feature rather than as marketing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Whether the backend can stream tokens.
    pub streaming: bool,
    /// Whether the backend can be asked for JSON-only output.
    pub json_mode: bool,
    /// Whether the backend can list available models.
    pub model_listing: bool,
    /// Whether inference runs on this machine.
    pub local: bool,
    /// Whether the backend reports token usage.
    pub usage_reporting: bool,
}

impl BackendCapabilities {
    /// Capabilities of an OpenAI-compatible HTTP server.
    pub fn http_chat() -> Self {
        Self {
            streaming: true,
            json_mode: true,
            model_listing: true,
            local: true,
            usage_reporting: true,
        }
    }

    /// Capabilities of the deterministic test double.
    pub fn mock() -> Self {
        Self {
            streaming: false,
            json_mode: true,
            model_listing: false,
            local: true,
            usage_reporting: false,
        }
    }
}

/// Result of a health check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    /// Backend identifier.
    pub backend: String,
    /// Whether the backend answered.
    pub reachable: bool,
    /// Human-readable detail, including the failure reason when unreachable.
    pub detail: String,
    /// Models the backend reported, when it can list them.
    pub models: Vec<String>,
}

impl HealthReport {
    /// Build a report.
    pub fn new(backend: impl Into<String>, reachable: bool, detail: impl Into<String>) -> Self {
        Self {
            backend: backend.into(),
            reachable,
            detail: detail.into(),
            models: Vec::new(),
        }
    }

    /// Whether the configured model is among the reported models.
    pub fn offers(&self, model: &str) -> Option<bool> {
        if self.models.is_empty() {
            return None;
        }
        Some(self.models.iter().any(|candidate| candidate == model))
    }
}

/// One request to a backend.
///
/// `system` is always a compiled-in constant from [`prompt`]; repository content
/// only ever appears in `user`, inside a fence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletionRequest {
    /// Audit task this request belongs to.
    pub task_id: String,
    /// System instructions. Never assembled from repository content.
    pub system: String,
    /// The task and its fenced evidence.
    pub user: String,
    /// Maximum tokens to generate.
    pub max_output_tokens: u32,
    /// Sampling temperature.
    pub temperature: f32,
    /// Whether the caller expects a JSON object.
    pub json_mode: bool,
}

impl CompletionRequest {
    /// Total size of the request in bytes, for budgeting and diagnostics.
    pub fn size_bytes(&self) -> usize {
        self.system.len() + self.user.len()
    }
}

/// One answer from a backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletionResponse {
    /// Backend identifier.
    pub backend: String,
    /// Model that answered, as reported by the backend.
    pub model: String,
    /// Generated text.
    pub content: String,
    /// Token usage, when reported.
    pub usage: Option<TokenUsage>,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u64,
}

/// A local inference backend.
pub trait InferenceBackend: Send + Sync {
    /// Stable backend identifier, recorded in every manifest.
    fn id(&self) -> &str;

    /// What this backend can do.
    fn capabilities(&self) -> BackendCapabilities;

    /// Check whether the backend is reachable and which models it offers.
    fn health(&self) -> HealthReport;

    /// Run one completion.
    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, InferenceError>;

    /// List available models, when the backend supports it.
    fn list_models(&self) -> Result<Vec<String>, InferenceError> {
        Ok(Vec::new())
    }

    /// The model this backend will use.
    fn model(&self) -> &str;
}

/// Build a request for a task with an explicit system prompt.
pub fn completion_request(
    task: &AuditTask,
    max_output_tokens: u32,
    temperature: f32,
) -> CompletionRequest {
    CompletionRequest {
        task_id: task.id.clone(),
        system: SYSTEM_INSTRUCTIONS.to_string(),
        user: render_task(task),
        max_output_tokens,
        temperature,
        json_mode: true,
    }
}

/// Default per-request timeout, used by backends that take no explicit value.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_declared_explicitly() {
        let http = BackendCapabilities::http_chat();
        assert!(http.streaming && http.json_mode && http.model_listing && http.usage_reporting);
        let mock = BackendCapabilities::mock();
        assert!(!mock.streaming);
        assert!(!mock.model_listing);
    }

    #[test]
    fn health_knows_when_it_cannot_tell() {
        let mut report = HealthReport::new("openai_compatible", true, "ok");
        assert_eq!(report.offers("qwen2.5-coder"), None);
        report.models = vec!["qwen2.5-coder-14b".to_string()];
        assert_eq!(report.offers("qwen2.5-coder-14b"), Some(true));
        assert_eq!(report.offers("other"), Some(false));
    }

    #[test]
    fn transport_errors_are_recognised() {
        assert!(InferenceError::Transport {
            endpoint: "http://x".to_string(),
            message: "refused".to_string()
        }
        .is_transport());
        assert!(!InferenceError::EmptyResponse.is_transport());
    }
}
