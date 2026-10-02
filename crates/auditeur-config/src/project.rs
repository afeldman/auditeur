//! Project and reporting configuration (`config/auditeur.toml`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Which repository is audited and where Auditeur keeps its own state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    /// Project label, recorded in the report.
    ///
    /// It no longer names a directory: there is one state root, chosen by
    /// `--home` or `AUDITEUR_HOME` (see [`crate::home::AuditeurHome`]).
    pub name: String,
    /// Repository to audit.
    pub source_path: PathBuf,
    /// The state root, resolved from the home at load time.
    ///
    /// Never written to a file: an absolute path in the configuration would make
    /// it non-portable, and moving the home would break every run. The field
    /// exists in memory so that a caller can report where state lives.
    #[serde(skip_serializing)]
    pub project_root: Option<PathBuf>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            source_path: PathBuf::from("."),
            project_root: None,
        }
    }
}

impl ProjectConfig {
    /// The directory name used for the generated report subdirectory.
    ///
    /// Falls back to `repository` for paths such as `/` or `..` that have no
    /// final component, so the report path is always well-defined.
    pub fn source_folder(&self) -> String {
        source_folder_name(&self.source_path)
    }

    /// Reject names that cannot safely become a directory under the home directory.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_project_name(&self.name)
    }
}

/// Report content preferences (`[report]` in `auditeur.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportingConfig {
    /// Include `PASS` findings in the report body.
    pub include_passing: bool,
    /// Include evidence excerpts (redacted) in the report.
    pub include_evidence_excerpts: bool,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            include_passing: true,
            include_evidence_excerpts: true,
        }
    }
}

/// Directory name reported for an audited path.
pub fn source_folder_name(source_path: &Path) -> String {
    let name = source_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "repository".to_string());
    sanitize_component(&name)
}

/// Derive a project name from an audited path, for the no-configuration path.
pub fn derive_project_name(source_path: &Path) -> String {
    let candidate = source_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "auditeur-project".to_string());
    let sanitized = sanitize_component(&candidate);
    if sanitized.trim_matches('-').is_empty() {
        "auditeur-project".to_string()
    } else {
        sanitized
    }
}

/// Validate a project name: a single, safe path component.
pub fn validate_project_name(name: &str) -> Result<(), ConfigError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::invalid(
            "project.name",
            "must not be empty; run `auditeur setup` or pass --project",
        ));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(ConfigError::invalid(
            "project.name",
            "must not be '.' or '..'",
        ));
    }
    if trimmed.contains(['/', '\\']) || trimmed.contains('\0') {
        return Err(ConfigError::invalid(
            "project.name",
            "must be a single path component without separators",
        ));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(ConfigError::invalid(
            "project.name",
            "must not contain control characters",
        ));
    }
    Ok(())
}

/// Reduce a string to a safe single path component.
fn sanitize_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for character in input.chars() {
        // `is_alphanumeric` covers the ASCII case as well, so one branch is
        // enough for everything that survives.
        if character.is_alphanumeric() || matches!(character, '.' | '_' | '-') {
            out.push(character);
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "repository".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_folder_is_the_last_path_component() {
        let mut config = ProjectConfig::default();
        config.source_path = PathBuf::from("/Volumes/Seagate/Projects/priv/auditeur");
        assert_eq!(config.source_folder(), "auditeur");
    }

    #[test]
    fn source_folder_survives_paths_without_a_final_component() {
        let mut config = ProjectConfig::default();
        config.source_path = PathBuf::from("/");
        assert_eq!(config.source_folder(), "repository");
    }

    #[test]
    fn unsafe_project_names_are_rejected() {
        for name in ["", "  ", ".", "..", "a/b", "a\\b", "with\0nul"] {
            assert!(
                validate_project_name(name).is_err(),
                "{name:?} should be rejected"
            );
        }
        for name in ["auditeur", "my_project", "My-Project.v2", "café"] {
            assert!(
                validate_project_name(name).is_ok(),
                "{name:?} should be accepted"
            );
        }
    }

    #[test]
    fn derived_names_are_sanitized() {
        assert_eq!(
            derive_project_name(Path::new("/x/my project (v2)")),
            "my-project--v2"
        );
        assert_eq!(derive_project_name(Path::new("/")), "auditeur-project");
        assert_eq!(
            derive_project_name(Path::new("/x/normal-name")),
            "normal-name"
        );
    }

    #[test]
    fn reporting_defaults_are_inclusive() {
        let report = ReportingConfig::default();
        assert!(report.include_passing);
        assert!(report.include_evidence_excerpts);
    }
}
