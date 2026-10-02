//! Model and inference configuration (`config/model.toml`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::home::AuditeurHome;

/// Which inference backend to use.
///
/// Only real backends appear here. `InProcessLlama` is deliberately absent
/// until that backend exists, because a configuration value that selects a
/// non-existent implementation is fake support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// Any OpenAI-compatible `/v1/chat/completions` endpoint: LM Studio,
    /// Ollama, `llama.cpp --server`, vLLM.
    ///
    /// Renamed explicitly: the derived name would be `open_ai_compatible`, which
    /// is not the identifier `BackendKind::id()` prints and not what a user would
    /// write in `model.toml`.
    #[serde(rename = "openai_compatible")]
    OpenAiCompatible,
    /// Deterministic offline double used by tests and by `--no-ai` runs.
    Mock,
}

impl BackendKind {
    /// Stable identifier used in configuration and manifests.
    pub fn id(self) -> &'static str {
        match self {
            BackendKind::OpenAiCompatible => "openai_compatible",
            BackendKind::Mock => "mock",
        }
    }

    /// Human-readable label for the wizard and doctor output.
    pub fn label(self) -> &'static str {
        match self {
            BackendKind::OpenAiCompatible => "OpenAI-compatible HTTP server",
            BackendKind::Mock => "Mock (offline, deterministic)",
        }
    }

    /// All backends that exist.
    pub const ALL: [BackendKind; 2] = [BackendKind::OpenAiCompatible, BackendKind::Mock];
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

impl std::str::FromStr for BackendKind {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalised = s.trim().to_ascii_lowercase().replace(['-', ' '], "_");
        BackendKind::ALL
            .into_iter()
            .find(|kind| kind.id() == normalised)
            .ok_or_else(|| ConfigError::invalid("model.backend", format!("unknown backend '{s}'")))
    }
}

/// Local inference settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelConfig {
    /// Backend implementation to use.
    pub backend: BackendKind,
    /// Base URL of the inference server, e.g. `http://localhost:1234/v1`.
    pub endpoint: String,
    /// Model identifier as the server reports it, e.g. `qwen/qwen2.5-coder-14b`.
    pub model: String,
    /// Name of the environment variable holding the API key, if the server
    /// needs one. The key itself is never stored in configuration.
    pub api_key_env: Option<String>,
    /// Whether AI-assisted analysis is enabled at all.
    pub enabled: bool,
    /// Per-request timeout in seconds.
    pub request_timeout_secs: u64,
    /// Maximum tokens to generate per request.
    pub max_output_tokens: u32,
    /// Sampling temperature. Low by default: audit work rewards consistency.
    pub temperature: f32,
    /// Where local model artefacts live, relative to the Auditeur home.
    ///
    /// Defaults to the home's `model/` directory. A relative sub-path is allowed
    /// so that a large model store can live on a separate path *inside* the
    /// state root; an absolute path is refused, because the configuration must
    /// stay portable and every state path must derive from one root.
    pub models_dir: Option<PathBuf>,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            backend: BackendKind::OpenAiCompatible,
            endpoint: "http://localhost:1234/v1".to_string(),
            model: String::new(),
            api_key_env: None,
            enabled: true,
            request_timeout_secs: 120,
            max_output_tokens: 2048,
            temperature: 0.1,
            models_dir: None,
        }
    }
}

impl ModelConfig {
    /// Whether a specific model has been selected.
    ///
    /// An unconfigured model is not an error: the audit still runs, and the
    /// manifest records that AI-assisted analysis was skipped.
    pub fn is_configured(&self) -> bool {
        self.enabled && !self.model.trim().is_empty()
    }

    /// Whether AI-assisted analysis should run for this configuration.
    pub fn ai_active(&self) -> bool {
        self.enabled && self.backend != BackendKind::Mock && !self.model.trim().is_empty()
    }

    /// The resolved local model directory.
    pub fn resolved_models_dir(&self, home: &AuditeurHome) -> PathBuf {
        match &self.models_dir {
            Some(relative) => home.root().join(relative),
            None => home.model_dir(),
        }
    }

    /// Full URL of the chat completions endpoint.
    pub fn chat_completions_url(&self) -> String {
        let base = self.endpoint.trim().trim_end_matches('/');
        if base.ends_with("/chat/completions") {
            base.to_string()
        } else {
            format!("{base}/chat/completions")
        }
    }

    /// API key read from the configured environment variable, if any.
    pub fn api_key(&self) -> Option<String> {
        self.api_key_env
            .as_ref()
            .and_then(|name| std::env::var(name).ok())
            .filter(|value| !value.trim().is_empty())
    }

    /// Structural validation. Absence of a model is not a structural error.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let endpoint = self.endpoint.trim();
        if endpoint.is_empty() {
            return Err(ConfigError::invalid(
                "model.endpoint",
                "must not be empty when a backend is configured",
            ));
        }
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
            return Err(ConfigError::invalid(
                "model.endpoint",
                format!(
                    "must be an http(s) URL, got '{}'",
                    crate::error::echo_safe(endpoint)
                ),
            ));
        }
        if endpoint.len() <= "https://".len() {
            return Err(ConfigError::invalid(
                "model.endpoint",
                format!(
                    "must include a host, got '{}'",
                    crate::error::echo_safe(endpoint)
                ),
            ));
        }
        if self.request_timeout_secs == 0 {
            return Err(ConfigError::invalid(
                "model.request_timeout_secs",
                "must be at least 1",
            ));
        }
        if self.max_output_tokens == 0 {
            return Err(ConfigError::invalid(
                "model.max_output_tokens",
                "must be at least 1",
            ));
        }
        if !(0.0..=2.0).contains(&self.temperature) {
            return Err(ConfigError::invalid(
                "model.temperature",
                "must be between 0.0 and 2.0",
            ));
        }
        if let Some(directory) = &self.models_dir {
            let text = display_path(directory);
            if directory.as_os_str().is_empty() {
                return Err(ConfigError::invalid(
                    "model.models_dir",
                    "must name a directory when set",
                ));
            }
            if directory.is_absolute() {
                return Err(ConfigError::invalid(
                    "model.models_dir",
                    format!(
                        "must be relative to the Auditeur home, got '{}'; set AUDITEUR_HOME to move the state root",
                        crate::error::echo_safe(&text)
                    ),
                ));
            }
            if directory
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                return Err(ConfigError::invalid(
                    "model.models_dir",
                    format!(
                        "must not escape the Auditeur home, got '{}'",
                        crate::error::echo_safe(&text)
                    ),
                ));
            }
        }
        if let Some(env_name) = &self.api_key_env {
            if env_name.trim().is_empty() {
                return Err(ConfigError::invalid(
                    "model.api_key_env",
                    "must be a variable name, not an empty string",
                ));
            }
            if env_name.contains('=') || env_name.contains('\0') {
                return Err(ConfigError::invalid(
                    "model.api_key_env",
                    "must be a variable name, not a value",
                ));
            }
            if env_name.len() > 12 && crate::error::looks_like_secret(env_name) {
                return Err(ConfigError::invalid(
                    "model.api_key_env",
                    "looks like a secret value; store the variable name only",
                ));
            }
        }
        Ok(())
    }

    /// The model directory to show in diagnostics, if it exists.
    pub fn models_dir_display(&self, home: &AuditeurHome) -> String {
        display_path(&self.resolved_models_dir(home))
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_construction_handles_trailing_slashes_and_full_urls() {
        let mut config = ModelConfig::default();
        config.endpoint = "http://localhost:1234/v1".to_string();
        assert_eq!(
            config.chat_completions_url(),
            "http://localhost:1234/v1/chat/completions"
        );

        config.endpoint = "http://localhost:1234/v1/".to_string();
        assert_eq!(
            config.chat_completions_url(),
            "http://localhost:1234/v1/chat/completions"
        );

        config.endpoint = "http://localhost:1234/v1/chat/completions".to_string();
        assert_eq!(
            config.chat_completions_url(),
            "http://localhost:1234/v1/chat/completions"
        );
    }

    #[test]
    fn endpoint_must_be_http_or_https() {
        let mut config = ModelConfig::default();
        config.endpoint = "localhost:1234".to_string();
        assert!(config.validate().is_err());

        config.endpoint = "file:///etc/passwd".to_string();
        assert!(config.validate().is_err());

        config.endpoint = "http://".to_string();
        assert!(config.validate().is_err());

        config.endpoint = "https://api.example.com/v1".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn temperature_bounds_are_enforced() {
        let mut config = ModelConfig::default();
        config.temperature = 2.5;
        assert!(config.validate().is_err());
        config.temperature = 0.0;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_secret_pasted_into_api_key_env_is_rejected() {
        let mut config = ModelConfig::default();
        config.api_key_env = Some("sk-live-abcDEF1234567890".to_string());
        assert!(config.validate().is_err());

        config.api_key_env = Some("LMSTUDIO_API_KEY".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_empty_model_is_not_configured_but_is_valid() {
        let config = ModelConfig::default();
        assert!(!config.is_configured());
        assert!(!config.ai_active());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn mock_backend_is_never_active_for_ai() {
        let mut config = ModelConfig::default();
        config.model = "anything".to_string();
        config.backend = BackendKind::Mock;
        assert!(!config.ai_active());
        assert!(config.is_configured());
    }

    #[test]
    fn backend_ids_round_trip() {
        for kind in BackendKind::ALL {
            assert_eq!(kind.id().parse::<BackendKind>().unwrap(), kind);
        }
        assert!("in-process-llama".parse::<BackendKind>().is_err());
    }
}
