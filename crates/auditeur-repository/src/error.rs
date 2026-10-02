//! Errors raised inside the read-only repository boundary.

use std::path::PathBuf;

/// A repository-boundary failure.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    /// The audited root does not exist or is not a directory.
    #[error("repository root {path} is not a directory")]
    NotADirectory {
        /// The offending path.
        path: PathBuf,
    },

    /// A path could not be resolved to a canonical form.
    #[error("cannot resolve {path}: {source}")]
    Canonicalize {
        /// The offending path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A path resolved outside the repository root.
    #[error("path {path} resolves outside the repository root {root}")]
    EscapesRoot {
        /// The offending path.
        path: PathBuf,
        /// The repository root it escaped.
        root: PathBuf,
    },

    /// A file could not be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The offending file.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A directory could not be traversed.
    #[error("cannot traverse {path}: {source}")]
    ReadDir {
        /// The offending directory.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A file exceeds the configured size limit.
    #[error("file {path} is {size} bytes, above the {limit}-byte limit")]
    TooLarge {
        /// The offending file.
        path: PathBuf,
        /// Actual size in bytes.
        size: u64,
        /// Configured limit in bytes.
        limit: u64,
    },

    /// A program is not permitted by the execution boundary.
    #[error("refusing to execute '{program}': {reason}")]
    CommandNotPermitted {
        /// The rejected program.
        program: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A permitted program could not be started.
    #[error("cannot execute '{program}': {source}")]
    CommandSpawn {
        /// The program that failed to start.
        program: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A command exceeded its time budget.
    #[error("command '{program}' exceeded its {seconds}s budget and was killed")]
    CommandTimeout {
        /// The program that timed out.
        program: String,
        /// The budget in seconds.
        seconds: u64,
    },

    /// The read-only guarantee was violated.
    ///
    /// This is never a warning: a run that modified the audited repository has
    /// produced evidence that cannot be trusted.
    #[error("read-only guarantee violated: {0}")]
    ReadOnlyViolation(String),

    /// A manifest-relative path could not be resolved inside the model.
    #[error("unknown repository path: {0}")]
    UnknownPath(String),
}

impl RepositoryError {
    /// Whether this error indicates the read-only boundary was broken.
    pub fn is_read_only_violation(&self) -> bool {
        matches!(self, RepositoryError::ReadOnlyViolation(_))
    }
}
