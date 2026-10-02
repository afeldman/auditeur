//! Audit-layer errors.

use std::path::PathBuf;

/// A failure in the audit layer.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The repository boundary failed.
    #[error(transparent)]
    Repository(#[from] auditeur_repository::RepositoryError),

    /// Configuration could not be read.
    #[error(transparent)]
    Config(#[from] auditeur_config::ConfigError),

    /// An audit definition is malformed.
    #[error("audit definition '{definition}' is invalid: {message}")]
    Definition {
        /// Definition id, or the file name when the id could not be read.
        definition: String,
        /// What is wrong with it.
        message: String,
    },

    /// A definition references a check that has no implementation.
    #[error(
        "audit definition '{definition}' declares check '{check}', which has no implementation"
    )]
    MissingImplementation {
        /// Definition id.
        definition: String,
        /// Declared check id.
        check: String,
    },

    /// Two checks or definitions share an identifier.
    #[error("duplicate {kind} id '{id}'")]
    Duplicate {
        /// What kind of thing collided, e.g. `check`.
        kind: &'static str,
        /// The colliding id.
        id: String,
    },

    /// The read-only guarantee was broken.
    ///
    /// Raised only when the caller asked the engine to verify the boundary.
    #[error("read-only guarantee violated during the audit: {0}")]
    ReadOnlyViolation(String),

    /// An inference operation failed in a way the audit cannot continue past.
    #[error(transparent)]
    Inference(#[from] auditeur_inference::InferenceError),

    /// Writing audit state failed.
    #[error("cannot write {path}: {source}")]
    Write {
        /// Offending path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The engine was asked to do something contradictory.
    #[error("invalid audit options: {0}")]
    Options(String),
}

impl AuditError {
    /// Whether this error indicates the read-only boundary was broken.
    pub fn is_read_only_violation(&self) -> bool {
        match self {
            AuditError::ReadOnlyViolation(_) => true,
            AuditError::Repository(error) => error.is_read_only_violation(),
            _ => false,
        }
    }
}
