//! Inference backends.
//!
//! Two backends exist in this iteration:
//!
//! * [`openai_compat::OpenAiCompatBackend`] — a real HTTP client for any
//!   OpenAI-compatible `/v1/chat/completions` server (LM Studio, Ollama,
//!   `llama.cpp --server`, vLLM).
//! * [`mock::MockBackend`] — a deterministic double used by tests and by
//!   `--no-ai` runs. It is documented as a double, and it never pretends to
//!   have analysed anything.
//!
//! A backend is selected from configuration by [`build`]. Adding a backend
//! means adding one module and one match arm here; nothing else in the
//! workspace changes.

pub mod mock;
pub mod openai_compat;

use auditeur_config::{BackendKind, ModelConfig};

use crate::InferenceError;

pub use mock::MockBackend;
pub use openai_compat::{OpenAiCompatBackend, OpenAiCompatSettings};

/// Build the backend named in configuration.
///
/// `api_key` is passed separately from the configuration: the key comes from the
/// environment (the variable named by `model.api_key_env`), never from a file.
pub fn build(
    config: &ModelConfig,
    api_key: Option<String>,
) -> Result<Box<dyn crate::InferenceBackend>, InferenceError> {
    config
        .validate()
        .map_err(|error| InferenceError::NotConfigured(error.to_string()))?;

    match config.backend {
        BackendKind::OpenAiCompatible => {
            let backend = OpenAiCompatBackend::new(&OpenAiCompatSettings {
                endpoint: config.endpoint.clone(),
                model: config.model.clone(),
                api_key,
                request_timeout_secs: config.request_timeout_secs,
                max_output_tokens: config.max_output_tokens,
                temperature: config.temperature,
                json_mode: true,
            })?;
            Ok(Box::new(backend))
        }
        BackendKind::Mock => Ok(Box::new(MockBackend::empty())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unconfigured_model_is_refused_rather_than_guessed() {
        let mut config = ModelConfig::default();
        config.model = String::new();
        let error = match build(&config, None) {
            Ok(_) => panic!("an unconfigured model must not build a backend"),
            Err(error) => error,
        };
        assert!(matches!(error, InferenceError::NotConfigured(_)), "{error}");
    }

    #[test]
    fn an_invalid_endpoint_is_refused() {
        let mut config = ModelConfig::default();
        config.model = "qwen2.5-coder".to_string();
        config.endpoint = "localhost:1234".to_string();
        assert!(build(&config, None).is_err());
    }

    #[test]
    fn the_mock_backend_is_selectable_by_configuration() {
        let mut config = ModelConfig::default();
        config.backend = BackendKind::Mock;
        let backend = build(&config, None).unwrap();
        assert_eq!(backend.id(), "mock");
    }

    #[test]
    fn a_configured_openai_compatible_backend_is_built_without_contacting_anything() {
        let mut config = ModelConfig::default();
        config.model = "qwen/qwen2.5-coder-14b".to_string();
        config.endpoint = "http://127.0.0.1:9/v1".to_string();
        let backend = build(&config, None).unwrap();
        assert_eq!(backend.id(), "openai_compatible");
        assert_eq!(backend.model(), "qwen/qwen2.5-coder-14b");
    }
}
