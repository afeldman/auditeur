//! Errors surfaced by the command-line layer.

use std::path::PathBuf;

/// A failure the user needs to see, with the exit code it implies.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Configuration could not be read, written or validated.
    #[error(transparent)]
    Config(#[from] auditeur_config::ConfigError),

    /// The audit failed.
    #[error(transparent)]
    Audit(#[from] auditeur_audit::AuditError),

    /// Writing the report failed.
    #[error(transparent)]
    Report(#[from] auditeur_report::ReportError),

    /// The terminal user interface failed.
    #[error(transparent)]
    Tui(#[from] auditeur_tui::TuiError),

    /// The inference backend could not be built from the configuration.
    #[error("inference backend: {0}")]
    Inference(String),

    /// The command line was used in a way that cannot work.
    #[error("{0}")]
    Usage(String),

    /// A file operation failed.
    #[error("cannot access {path}: {source}")]
    Io {
        /// Offending path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl CliError {
    /// The process exit code for this error.
    pub fn exit_code(&self) -> u8 {
        crate::cli::exit::ERROR
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_maps_to_the_error_exit_code() {
        let usage = CliError::Usage("bad usage".to_string());
        assert_eq!(usage.exit_code(), 2);
        assert!(usage.to_string().contains("bad usage"));

        let inference = CliError::Inference("no model".to_string());
        assert_eq!(inference.exit_code(), 2);
        assert!(inference.to_string().contains("inference backend"));
    }

    #[test]
    fn an_io_error_names_the_path() {
        let error = CliError::Io {
            path: PathBuf::from("/tmp/x"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        };
        assert!(error.to_string().contains("/tmp/x"));
    }
}
