//! Errors raised while loading, validating or writing configuration.
//!
//! Every variant that concerns a file carries the path, because a configuration
//! error without a location is a support ticket rather than a message.

use std::path::PathBuf;

/// A configured value may be echoed in a user-facing error only when it cannot be
/// a credential and is short enough to read.
///
/// Values are worth echoing — "must be relative to the Auditeur home, got
/// 'models/'" is actionable — but the same field can receive a pasted token, and
/// a parser message quotes it verbatim. Truncating by length, refusing control
/// characters and refusing anything credential-shaped keeps the actionable case
/// and drops the leak. The residual limitation is stated in SECURITY.md: a short,
/// unlabelled secret that a user typed is still echoed.
pub(crate) fn echo_safe(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "<empty>".to_string();
    }
    if trimmed.len() > 24 || trimmed.chars().any(|c| c.is_control()) || looks_like_secret(trimmed) {
        return "<redacted:value>".to_string();
    }
    trimmed.to_string()
}

/// A crude credential heuristic: mixed character classes, which is what a random
/// token looks like and what a path, a level name or a directory name does not.
pub(crate) fn looks_like_secret(value: &str) -> bool {
    let has_mixed_classes = value.chars().any(|c| c.is_ascii_lowercase())
        && value.chars().any(|c| c.is_ascii_uppercase())
        && value.chars().any(|c| c.is_ascii_digit());
    let is_upper_with_underscores = value
        .chars()
        .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit());
    has_mixed_classes && !is_upper_with_underscores
}

/// A configuration problem.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A configuration file exists but could not be read.
    #[error("cannot read configuration file {path}: {source}")]
    Read {
        /// Offending file.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A configuration file could not be parsed. The message includes the
    /// line and column reported by the TOML parser.
    #[error("cannot parse configuration file {path}: {message}")]
    Parse {
        /// Offending file.
        path: PathBuf,
        /// Parser message.
        message: String,
    },

    /// A value parsed but is not usable.
    #[error("invalid configuration value for '{key}': {message}")]
    Invalid {
        /// Dotted key path, e.g. `model.endpoint`.
        key: String,
        /// Why the value is not usable.
        message: String,
    },

    /// The project directory could not be determined.
    #[error("cannot determine a project directory: {0}")]
    Layout(String),

    /// A directory required by the layout could not be created.
    #[error("cannot create directory {path}: {source}")]
    CreateDir {
        /// Offending directory.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A configuration file could not be written.
    #[error("cannot write configuration file {path}: {source}")]
    Write {
        /// Offending file.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A configuration file could not be serialised.
    #[error("cannot serialise configuration: {0}")]
    Serialize(String),
}

impl ConfigError {
    /// Construct an invalid-value error.
    pub fn invalid(key: impl Into<String>, message: impl Into<String>) -> Self {
        ConfigError::Invalid {
            key: key.into(),
            message: message.into(),
        }
    }
}
