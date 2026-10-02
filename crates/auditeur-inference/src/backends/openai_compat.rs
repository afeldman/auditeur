//! OpenAI-compatible HTTP backend.
//!
//! Talks to any server exposing `POST <base>/chat/completions` and
//! `GET <base>/models`: LM Studio, Ollama, `llama.cpp --server`, vLLM, and
//! anything else that implements the same shape.
//!
//! Both a plain HTTP client and a `MockBackend` exist rather than only a mock,
//! because the point of this backend is that it works against a real local
//! server today. It is used by the live end-to-end check.

use std::time::Duration;

use serde_json::{json, Value};

use auditeur_model::redact::{redact_text, truncate_chars};

use crate::{
    BackendCapabilities, CompletionRequest, CompletionResponse, HealthReport, InferenceBackend,
    InferenceError, TokenUsage,
};

/// Maximum characters of an error body kept in a message.
const MAX_ERROR_BODY_CHARS: usize = 500;

/// Settings for the HTTP backend.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiCompatSettings {
    /// Base endpoint, e.g. `http://localhost:1234/v1`.
    pub endpoint: String,
    /// Model identifier as the server knows it.
    pub model: String,
    /// API key, read from the environment by the caller. Optional: local
    /// servers commonly need none.
    pub api_key: Option<String>,
    /// Per-request timeout in seconds.
    pub request_timeout_secs: u64,
    /// Default maximum output tokens.
    pub max_output_tokens: u32,
    /// Default sampling temperature.
    pub temperature: f32,
    /// Whether to request JSON output.
    pub json_mode: bool,
}

/// An OpenAI-compatible chat backend.
pub struct OpenAiCompatBackend {
    endpoint: String,
    chat_url: String,
    models_url: String,
    model: String,
    api_key: Option<String>,
    timeout: Duration,
    json_mode: bool,
    agent: ureq::Agent,
}

impl std::fmt::Debug for OpenAiCompatBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The API key is deliberately absent from the debug representation.
        f.debug_struct("OpenAiCompatBackend")
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("has_api_key", &self.api_key.is_some())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl OpenAiCompatBackend {
    /// Create a backend from settings.
    pub fn new(settings: &OpenAiCompatSettings) -> Result<Self, InferenceError> {
        let base = settings.endpoint.trim().trim_end_matches('/').to_string();
        if base.is_empty() {
            return Err(InferenceError::NotConfigured(
                "model.endpoint is empty".to_string(),
            ));
        }
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(InferenceError::NotConfigured(format!(
                "model.endpoint must be an http(s) URL, got '{base}'"
            )));
        }
        if settings.model.trim().is_empty() {
            return Err(InferenceError::NotConfigured(
                "no model selected; set model.model or run `auditeur setup`".to_string(),
            ));
        }
        if settings.request_timeout_secs == 0 {
            return Err(InferenceError::NotConfigured(
                "model.request_timeout_secs must be at least 1".to_string(),
            ));
        }

        let chat_url = if base.ends_with("/chat/completions") {
            base.clone()
        } else {
            format!("{base}/chat/completions")
        };
        let models_url = if base.ends_with("/chat/completions") {
            format!("{}/models", base.trim_end_matches("/chat/completions"))
        } else {
            format!("{base}/models")
        };

        let timeout = Duration::from_secs(settings.request_timeout_secs);
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .user_agent(concat!("auditeur/", env!("CARGO_PKG_VERSION")))
            .build();

        Ok(Self {
            endpoint: base,
            chat_url,
            models_url,
            model: settings.model.trim().to_string(),
            api_key: settings
                .api_key
                .as_ref()
                .map(|key| key.trim().to_string())
                .filter(|key| !key.is_empty()),
            timeout,
            json_mode: settings.json_mode,
            agent,
        })
    }

    /// The configured base endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn request(&self, url: &str) -> ureq::Request {
        let request = self.agent.get(url).set("Accept", "application/json");
        match &self.api_key {
            Some(key) => request.set("Authorization", &format!("Bearer {key}")),
            None => request,
        }
    }

    /// Map a transport error, distinguishing a real timeout from a refusal.
    fn transport_error(&self, error: ureq::Error) -> InferenceError {
        match error {
            ureq::Error::Status(status, response) => {
                let body = response.into_string().unwrap_or_default();
                InferenceError::HttpStatus {
                    endpoint: self.endpoint.clone(),
                    status,
                    body: truncate_chars(&redact_text(&body), MAX_ERROR_BODY_CHARS),
                }
            }
            ureq::Error::Transport(transport) => {
                let message = transport.to_string();
                let lowered = message.to_ascii_lowercase();
                if lowered.contains("timed out") || lowered.contains("timeout") {
                    InferenceError::Timeout {
                        seconds: self.timeout.as_secs(),
                    }
                } else {
                    InferenceError::Transport {
                        endpoint: self.endpoint.clone(),
                        message: truncate_chars(&redact_text(&message), MAX_ERROR_BODY_CHARS),
                    }
                }
            }
        }
    }

    /// Build the request body for a completion.
    fn body(&self, request: &CompletionRequest) -> Value {
        let mut body = json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": request.system },
                { "role": "user", "content": request.user }
            ],
            "temperature": request.temperature,
            "max_tokens": request.max_output_tokens,
            "stream": false,
        });
        if request.json_mode && self.json_mode {
            body["response_format"] = json!({ "type": "json_object" });
        }
        body
    }

    /// Interpret a chat completion response body.
    fn interpret(
        &self,
        value: &Value,
        latency_ms: u64,
    ) -> Result<CompletionResponse, InferenceError> {
        let content = value
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                // Some servers answer with the legacy completion shape.
                value
                    .pointer("/choices/0/text")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .ok_or(InferenceError::EmptyResponse)?;

        if content.trim().is_empty() {
            return Err(InferenceError::EmptyResponse);
        }

        let model = value
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(&self.model)
            .to_string();

        let usage = value.get("usage").map(|usage| TokenUsage {
            prompt_tokens: usage
                .get("prompt_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32,
            completion_tokens: usage
                .get("completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32,
            total_tokens: usage
                .get("total_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32,
        });

        Ok(CompletionResponse {
            backend: self.id().to_string(),
            model,
            content,
            usage,
            latency_ms,
        })
    }

    /// Parse a `/models` response into model identifiers.
    fn parse_models(value: &Value) -> Vec<String> {
        value
            .get("data")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.get("id").and_then(Value::as_str).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Send a request body to the chat endpoint.
    fn post(&self, body: &Value) -> Result<Value, InferenceError> {
        let mut http = self
            .agent
            .post(&self.chat_url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json");
        if let Some(key) = &self.api_key {
            http = http.set("Authorization", &format!("Bearer {key}"));
        }

        match http.send_json(body.clone()) {
            Ok(response) => response
                .into_json::<Value>()
                .map_err(|error| InferenceError::Decode(redact_text(&error.to_string()))),
            Err(error) => Err(self.transport_error(error)),
        }
    }
}

impl InferenceBackend for OpenAiCompatBackend {
    fn id(&self) -> &str {
        "openai_compatible"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::http_chat()
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn health(&self) -> HealthReport {
        let response = match self.request(&self.models_url).call() {
            Ok(response) => response,
            Err(ureq::Error::Status(404, _)) => {
                // The server exists but does not implement /models. That is a
                // capability gap, not an outage.
                return HealthReport::new(
                    self.id(),
                    true,
                    format!(
                        "{} answered but does not expose /models; model availability cannot be checked",
                        self.endpoint
                    ),
                );
            }
            Err(error) => {
                let error = self.transport_error(error);
                return HealthReport::new(self.id(), false, error.to_string());
            }
        };

        match response.into_json::<Value>() {
            Ok(value) => {
                let mut report =
                    HealthReport::new(self.id(), true, format!("{} answered", self.endpoint));
                report.models = Self::parse_models(&value);
                if !report.models.is_empty() {
                    match report.offers(&self.model) {
                        Some(true) => report
                            .detail
                            .push_str(&format!("; configured model '{}' is available", self.model)),
                        Some(false) => report.detail.push_str(&format!(
                            "; configured model '{}' is NOT in the server's model list",
                            self.model
                        )),
                        None => {}
                    }
                }
                report
            }
            Err(error) => HealthReport::new(
                self.id(),
                false,
                format!(
                    "{} answered but the model list could not be decoded: {}",
                    self.endpoint,
                    truncate_chars(&redact_text(&error.to_string()), MAX_ERROR_BODY_CHARS)
                ),
            ),
        }
    }

    fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse, InferenceError> {
        let mut body = self.body(request);
        let started = std::time::Instant::now();

        let value = match self.post(&body) {
            Ok(value) => value,
            Err(error)
                if request.json_mode && self.json_mode && rejects_response_format(&error) =>
            {
                // OpenAI-compatible servers disagree about structured output: some
                // accept `json_object`, some only `json_schema`, and some reject the
                // field outright. Rather than guess which server this is — a probe
                // that costs a request on every run — the request is sent as
                // configured and, if the server refuses the field, resent without it.
                // Nothing is lost by the retry: the prompt already requires a single
                // JSON object, and the draft parser tolerates prose around it.
                if let Some(fields) = body.as_object_mut() {
                    fields.remove("response_format");
                }
                self.post(&body)?
            }
            Err(error) => return Err(error),
        };

        self.interpret(&value, started.elapsed().as_millis() as u64)
    }

    fn list_models(&self) -> Result<Vec<String>, InferenceError> {
        let response = self
            .request(&self.models_url)
            .call()
            .map_err(|error| self.transport_error(error))?;
        let value: Value = response
            .into_json::<Value>()
            .map_err(|error| InferenceError::Decode(redact_text(&error.to_string())))?;
        Ok(Self::parse_models(&value))
    }
}

/// Whether a server-side error means it will not accept a response format.
///
/// Deliberately narrow: a 400 that names the field. A 400 about anything else, or
/// any other status, is reported as it stands rather than retried, so a genuine
/// request error is never hidden behind a second attempt.
fn rejects_response_format(error: &InferenceError) -> bool {
    match error {
        InferenceError::HttpStatus { status, body, .. } => {
            *status == 400 && body.contains("response_format")
        }
        _ => false,
    }
}

/// Defaults applied when a request does not override them.
impl Default for OpenAiCompatSettings {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:1234/v1".to_string(),
            model: String::new(),
            api_key: None,
            request_timeout_secs: 120,
            max_output_tokens: 2048,
            temperature: 0.1,
            json_mode: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Read one HTTP request, headers and body, from a connection.
    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut raw: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => raw.extend_from_slice(&chunk[..read]),
                Err(_) => break,
            }
            let text = String::from_utf8_lossy(&raw).to_string();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let expected = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if body.len() >= expected {
                    return text;
                }
            }
        }
        String::from_utf8_lossy(&raw).to_string()
    }

    fn respond(stream: &mut std::net::TcpStream, status: &str, body: &str) {
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }

    /// A server that rejects `response_format` on the first request, like LM Studio
    /// does, and answers the retry. Returns its address and the request bodies it
    /// received.
    fn server_that_refuses_structured_output() -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());

        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for attempt in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                requests.push(read_request(&mut stream));
                if attempt == 0 {
                    respond(
                        &mut stream,
                        "400 Bad Request",
                        r#"{"error":"'response_format.type' must be 'json_schema'"}"#,
                    );
                } else {
                    respond(
                        &mut stream,
                        "200 OK",
                        r#"{"choices":[{"message":{"content":"{\"findings\":[]}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
                    );
                }
            }
            requests
        });

        (endpoint, handle)
    }

    #[test]
    fn a_server_that_refuses_structured_output_is_retried_without_it() {
        let (endpoint, handle) = server_that_refuses_structured_output();
        let backend = OpenAiCompatBackend::new(&OpenAiCompatSettings {
            endpoint,
            model: "test-model".to_string(),
            request_timeout_secs: 10,
            ..Default::default()
        })
        .unwrap();

        let request = CompletionRequest {
            task_id: "t".to_string(),
            system: "s".to_string(),
            user: "u".to_string(),
            max_output_tokens: 16,
            temperature: 0.0,
            json_mode: true,
        };

        let response = backend
            .complete(&request)
            .expect("the retry must succeed where the first attempt was refused");
        assert!(response.content.contains("findings"));

        let requests = handle.join().unwrap();
        assert_eq!(requests.len(), 2, "the request must be sent twice");
        assert!(
            requests[0].contains("response_format"),
            "the first attempt uses structured output: {}",
            requests[0]
        );
        assert!(
            !requests[1].contains("response_format"),
            "the retry must drop the field the server refused: {}",
            requests[1]
        );
    }

    #[test]
    fn an_unrelated_bad_request_is_not_retried() {
        let conflict = InferenceError::HttpStatus {
            endpoint: "http://127.0.0.1:1/v1".to_string(),
            status: 400,
            body: "{\"error\":\"model not loaded\"}".to_string(),
        };
        assert!(!rejects_response_format(&conflict));
        assert!(!rejects_response_format(&InferenceError::EmptyResponse));

        let refused = InferenceError::HttpStatus {
            endpoint: "http://127.0.0.1:1/v1".to_string(),
            status: 400,
            body: "{\"error\":\"'response_format.type' must be 'json_schema'\"}".to_string(),
        };
        assert!(rejects_response_format(&refused));
    }

    use super::*;

    fn backend() -> OpenAiCompatBackend {
        OpenAiCompatBackend::new(&OpenAiCompatSettings {
            endpoint: "http://127.0.0.1:1234/v1".to_string(),
            model: "qwen/qwen2.5-coder-14b".to_string(),
            api_key: Some("sk-test-key".to_string()),
            request_timeout_secs: 5,
            max_output_tokens: 512,
            temperature: 0.0,
            json_mode: true,
        })
        .unwrap()
    }

    #[test]
    fn urls_are_derived_from_the_configured_base() {
        let backend = backend();
        assert_eq!(
            backend.chat_url,
            "http://127.0.0.1:1234/v1/chat/completions"
        );
        assert_eq!(backend.models_url, "http://127.0.0.1:1234/v1/models");

        let full = OpenAiCompatBackend::new(&OpenAiCompatSettings {
            endpoint: "http://127.0.0.1:1234/v1/chat/completions".to_string(),
            model: "m".to_string(),
            ..OpenAiCompatSettings::default()
        })
        .unwrap();
        assert_eq!(full.chat_url, "http://127.0.0.1:1234/v1/chat/completions");
        assert_eq!(full.models_url, "http://127.0.0.1:1234/v1/models");
    }

    #[test]
    fn configuration_errors_are_reported_before_any_request() {
        let error = OpenAiCompatBackend::new(&OpenAiCompatSettings {
            model: "m".to_string(),
            endpoint: "not-a-url".to_string(),
            ..OpenAiCompatSettings::default()
        })
        .unwrap_err();
        assert!(matches!(error, InferenceError::NotConfigured(_)));

        let error = OpenAiCompatBackend::new(&OpenAiCompatSettings {
            model: "  ".to_string(),
            ..OpenAiCompatSettings::default()
        })
        .unwrap_err();
        assert!(error.to_string().contains("no model selected"), "{error}");
    }

    #[test]
    fn the_request_body_carries_instructions_and_fenced_evidence_separately() {
        let backend = backend();
        let request = CompletionRequest {
            task_id: "t".to_string(),
            system: "SYSTEM".to_string(),
            user: "USER".to_string(),
            max_output_tokens: 128,
            temperature: 0.4,
            json_mode: true,
        };
        let body = backend.body(&request);
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "SYSTEM");
        assert_eq!(body["messages"][1]["content"], "USER");
        assert_eq!(body["stream"], false);
        assert_eq!(body["max_tokens"], 128);
        assert_eq!(body["response_format"]["type"], "json_object");
    }

    #[test]
    fn json_mode_can_be_declined() {
        let backend = OpenAiCompatBackend::new(&OpenAiCompatSettings {
            model: "m".to_string(),
            json_mode: false,
            ..OpenAiCompatSettings::default()
        })
        .unwrap();
        let body = backend.body(&CompletionRequest {
            task_id: "t".to_string(),
            system: "s".to_string(),
            user: "u".to_string(),
            max_output_tokens: 10,
            temperature: 0.0,
            json_mode: true,
        });
        assert!(body.get("response_format").is_none());
    }

    #[test]
    fn responses_are_interpreted_including_usage() {
        let backend = backend();
        let value: Value = serde_json::from_str(
            r#"{
              "model": "qwen/qwen2.5-coder-14b",
              "choices": [ { "message": { "role": "assistant", "content": "{\"findings\":[]}" } } ],
              "usage": { "prompt_tokens": 120, "completion_tokens": 8, "total_tokens": 128 }
            }"#,
        )
        .unwrap();
        let response = backend.interpret(&value, 42).unwrap();
        assert_eq!(response.content, "{\"findings\":[]}");
        assert_eq!(response.model, "qwen/qwen2.5-coder-14b");
        assert_eq!(response.usage.unwrap().total_tokens, 128);
        assert_eq!(response.latency_ms, 42);
        assert_eq!(response.backend, "openai_compatible");
    }

    #[test]
    fn a_response_without_content_is_an_error_not_an_empty_answer() {
        let backend = backend();
        let value: Value =
            serde_json::from_str(r#"{"choices":[{"message":{"content":""}}]}"#).unwrap();
        assert!(matches!(
            backend.interpret(&value, 1),
            Err(InferenceError::EmptyResponse)
        ));

        let value: Value = serde_json::from_str(r#"{"error":{"message":"nope"}}"#).unwrap();
        assert!(matches!(
            backend.interpret(&value, 1),
            Err(InferenceError::EmptyResponse)
        ));
    }

    #[test]
    fn model_lists_are_parsed_and_odd_shapes_are_tolerated() {
        let value: Value =
            serde_json::from_str(r#"{"data":[{"id":"a"},{"id":"b"},{"noid":true}]}"#).unwrap();
        assert_eq!(OpenAiCompatBackend::parse_models(&value), vec!["a", "b"]);
        let value: Value = serde_json::from_str(r#"{"object":"list"}"#).unwrap();
        assert!(OpenAiCompatBackend::parse_models(&value).is_empty());
    }

    #[test]
    fn an_unreachable_endpoint_reports_unreachable_without_contacting_a_real_server() {
        // Port 9 is the discard service and is essentially never listening.
        let backend = OpenAiCompatBackend::new(&OpenAiCompatSettings {
            endpoint: "http://127.0.0.1:9/v1".to_string(),
            model: "m".to_string(),
            request_timeout_secs: 2,
            ..OpenAiCompatSettings::default()
        })
        .unwrap();
        let health = backend.health();
        assert!(!health.reachable, "{}", health.detail);

        let error = backend
            .complete(&CompletionRequest {
                task_id: "t".to_string(),
                system: "s".to_string(),
                user: "u".to_string(),
                max_output_tokens: 16,
                temperature: 0.0,
                json_mode: true,
            })
            .unwrap_err();
        assert!(error.is_transport(), "{error}");
    }

    #[test]
    fn the_api_key_never_appears_in_debug_output() {
        let rendered = format!("{:?}", backend());
        assert!(!rendered.contains("sk-test-key"), "{rendered}");
        assert!(rendered.contains("has_api_key: true"));
    }

    #[test]
    fn transport_error_messages_are_redacted_and_bounded() {
        let backend = backend();
        let error = backend.transport_error(ureq::Error::Status(
            401,
            ureq::Response::new(401, "Unauthorized", "token=sk-live-abcdef1234567890").unwrap(),
        ));
        let rendered = error.to_string();
        assert!(!rendered.contains("sk-live-abcdef1234567890"), "{rendered}");
    }
}
