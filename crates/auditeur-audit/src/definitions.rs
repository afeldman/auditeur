//! Declarative audit definitions.
//!
//! Audit knowledge lives in TOML, not in Rust. A definition names its checks and
//! declares each check's category and severity, so that severity cannot drift
//! from documentation and so that a project can override a definition without
//! recompiling Auditeur.
//!
//! Definitions are embedded in the binary (`include_str!`) so that an offline
//! audit works out of the box, and can be overridden from
//! `<project>/config/definitions/*.toml`. A definition whose id matches an
//! embedded one replaces it; a new id adds one. Nothing is merged implicitly.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use auditeur_model::{AuditCategory, DefinitionRef, Severity};
use serde::{Deserialize, Serialize};

use crate::error::AuditError;

/// How a check reaches its conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    /// Derived from observable facts only.
    Deterministic,
    /// Proposed by a model and then verified against the repository.
    AiAssisted,
    /// A deterministic part plus a model-assisted interpretation.
    Hybrid,
}

impl CheckKind {
    /// Stable identifier used in definitions and manifests.
    pub fn id(self) -> &'static str {
        match self {
            CheckKind::Deterministic => "deterministic",
            CheckKind::AiAssisted => "ai_assisted",
            CheckKind::Hybrid => "hybrid",
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            CheckKind::Deterministic => "deterministic",
            CheckKind::AiAssisted => "model-assisted",
            CheckKind::Hybrid => "deterministic + model-assisted",
        }
    }

    /// Whether the check needs a model to run at all.
    pub fn needs_model(self) -> bool {
        matches!(self, CheckKind::AiAssisted | CheckKind::Hybrid)
    }
}

/// A check declared by a definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckSpec {
    /// Check identifier, unique across all definitions.
    pub id: String,
    /// Short title used in the report.
    pub title: String,
    /// What the check looks for.
    #[serde(default)]
    pub description: String,
    /// How the check reaches its conclusion.
    pub kind: CheckKind,
    /// Category the check belongs to.
    pub category: AuditCategory,
    /// Impact if the issue is real. Declared here, never chosen by a model.
    pub severity: Severity,
    /// Suggested remedy, used when the check has nothing more specific.
    #[serde(default)]
    pub recommendation: Option<String>,
    /// Objective for model-assisted checks.
    #[serde(default)]
    pub objective: Option<String>,
}

/// A versioned audit definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditDefinition {
    /// Definition identifier, e.g. `security`.
    pub id: String,
    /// Definition version. Bumping it is required when checks change, because a
    /// run manifest records the version it used.
    pub version: String,
    /// Short title.
    pub title: String,
    /// What the definition covers.
    #[serde(default)]
    pub description: String,
    /// Declared checks.
    #[serde(default)]
    pub checks: Vec<CheckSpec>,
}

impl AuditDefinition {
    /// The reference recorded in a run manifest.
    pub fn reference(&self) -> DefinitionRef {
        DefinitionRef {
            id: self.id.clone(),
            version: self.version.clone(),
        }
    }

    /// Checks of a given kind.
    pub fn checks_of_kind(&self, kind: CheckKind) -> Vec<&CheckSpec> {
        self.checks
            .iter()
            .filter(|check| check.kind == kind)
            .collect()
    }

    /// Look up a check by id.
    pub fn check(&self, id: &str) -> Option<&CheckSpec> {
        self.checks.iter().find(|check| check.id == id)
    }
}

/// Shape of one definition file.
#[derive(Debug, Clone, Deserialize)]
struct DefinitionFile {
    audit: DefinitionMeta,
    #[serde(default)]
    checks: Vec<CheckSpec>,
}

/// The `[audit]` table of a definition file.
#[derive(Debug, Clone, Deserialize)]
struct DefinitionMeta {
    id: String,
    version: String,
    title: String,
    #[serde(default)]
    description: String,
}

/// Embedded definitions, with their source names for error messages.
const EMBEDDED: &[(&str, &str)] = &[
    (
        "security.toml",
        include_str!("../definitions/security.toml"),
    ),
    (
        "code-quality.toml",
        include_str!("../definitions/code-quality.toml"),
    ),
    (
        "dependencies.toml",
        include_str!("../definitions/dependencies.toml"),
    ),
    ("testing.toml", include_str!("../definitions/testing.toml")),
    (
        "documentation.toml",
        include_str!("../definitions/documentation.toml"),
    ),
    (
        "architecture.toml",
        include_str!("../definitions/architecture.toml"),
    ),
    (
        "configuration.toml",
        include_str!("../definitions/configuration.toml"),
    ),
    (
        "release-readiness.toml",
        include_str!("../definitions/release-readiness.toml"),
    ),
];

/// The definitions compiled into the binary.
pub fn embedded() -> Result<Vec<AuditDefinition>, AuditError> {
    let mut definitions = Vec::with_capacity(EMBEDDED.len());
    for (source, text) in EMBEDDED {
        definitions.push(parse(text, source)?);
    }
    validate(&definitions)?;
    Ok(definitions)
}

/// Parse one definition document.
pub fn parse(text: &str, source: &str) -> Result<AuditDefinition, AuditError> {
    let file: DefinitionFile = toml::from_str(text).map_err(|error| AuditError::Definition {
        definition: source.to_string(),
        message: error.to_string(),
    })?;

    let definition = AuditDefinition {
        id: file.audit.id,
        version: file.audit.version,
        title: file.audit.title,
        description: file.audit.description,
        checks: file.checks,
    };
    validate_one(&definition)?;
    Ok(definition)
}

/// Embedded definitions plus any overrides found in `override_dir`.
///
/// A file in `override_dir` replaces the definition with the same id, or adds a
/// new one. Overriding changes what an audit checks, so the caller records the
/// resulting definition versions in the manifest.
pub fn load_with_overrides(
    override_dir: Option<&Path>,
) -> Result<Vec<AuditDefinition>, AuditError> {
    let mut definitions = embedded()?;

    let Some(directory) = override_dir else {
        return Ok(definitions);
    };
    if !directory.is_dir() {
        return Ok(definitions);
    }

    let mut entries: Vec<std::path::PathBuf> = fs::read_dir(directory)
        .map_err(|source| AuditError::Write {
            path: directory.to_path_buf(),
            source,
        })?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
        })
        .collect();
    entries.sort();

    for path in entries {
        let text = fs::read_to_string(&path).map_err(|source| AuditError::Write {
            path: path.clone(),
            source,
        })?;
        let override_definition = parse(&text, &path.display().to_string())?;
        match definitions
            .iter_mut()
            .find(|existing| existing.id == override_definition.id)
        {
            Some(existing) => *existing = override_definition,
            None => definitions.push(override_definition),
        }
    }

    validate(&definitions)?;
    Ok(definitions)
}

/// Validate a single definition.
fn validate_one(definition: &AuditDefinition) -> Result<(), AuditError> {
    if definition.id.trim().is_empty() {
        return Err(AuditError::Definition {
            definition: "(unnamed)".to_string(),
            message: "audit.id must not be empty".to_string(),
        });
    }
    if definition.version.trim().is_empty() || definition.version.contains(char::is_whitespace) {
        return Err(AuditError::Definition {
            definition: definition.id.clone(),
            message: "audit.version must be a non-empty token such as \"1.0.0\"".to_string(),
        });
    }
    if definition.checks.is_empty() {
        return Err(AuditError::Definition {
            definition: definition.id.clone(),
            message: "declares no checks".to_string(),
        });
    }

    let mut seen = HashSet::new();
    for check in &definition.checks {
        if !seen.insert(check.id.as_str()) {
            return Err(AuditError::Duplicate {
                kind: "check",
                id: check.id.clone(),
            });
        }
        if check.id.trim().is_empty() || check.title.trim().is_empty() {
            return Err(AuditError::Definition {
                definition: definition.id.clone(),
                message: format!("check '{}' needs a non-empty id and title", check.id),
            });
        }
        if check.kind.needs_model()
            && check
                .objective
                .as_ref()
                .is_none_or(|objective| objective.trim().is_empty())
        {
            return Err(AuditError::Definition {
                definition: definition.id.clone(),
                message: format!(
                    "check '{}' is {} but declares no objective",
                    check.id,
                    check.kind.id()
                ),
            });
        }
    }
    Ok(())
}

/// Validate a set of definitions: ids and check ids must be unique.
fn validate(definitions: &[AuditDefinition]) -> Result<(), AuditError> {
    let mut definition_ids = HashSet::new();
    let mut check_ids = HashSet::new();

    for definition in definitions {
        if !definition_ids.insert(definition.id.as_str()) {
            return Err(AuditError::Duplicate {
                kind: "definition",
                id: definition.id.clone(),
            });
        }
        for check in &definition.checks {
            if !check_ids.insert(check.id.as_str()) {
                return Err(AuditError::Duplicate {
                    kind: "check",
                    id: check.id.clone(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_definitions_are_valid() {
        let definitions = embedded().unwrap();
        assert_eq!(definitions.len(), EMBEDDED.len());
        for definition in &definitions {
            assert!(!definition.checks.is_empty(), "{} is empty", definition.id);
            assert!(!definition.reference().version.is_empty());
        }
    }

    #[test]
    fn every_embedded_definition_declares_a_deterministic_check() {
        for definition in embedded().unwrap() {
            let deterministic = definition.checks_of_kind(CheckKind::Deterministic);
            assert!(
                !deterministic.is_empty(),
                "{} has no deterministic check",
                definition.id
            );
        }
    }

    #[test]
    fn model_assisted_checks_declare_an_objective() {
        for definition in embedded().unwrap() {
            for check in definition
                .checks
                .iter()
                .filter(|check| check.kind.needs_model())
            {
                assert!(
                    check
                        .objective
                        .as_ref()
                        .is_some_and(|objective| !objective.is_empty()),
                    "{}/{} has no objective",
                    definition.id,
                    check.id
                );
            }
        }
    }

    #[test]
    fn check_ids_are_unique_across_all_definitions() {
        let definitions = embedded().unwrap();
        let mut seen = HashSet::new();
        for definition in &definitions {
            for check in &definition.checks {
                assert!(seen.insert(check.id.clone()), "duplicate {}", check.id);
            }
        }
        assert!(seen.len() >= 15, "expected a meaningful check count");
    }

    #[test]
    fn a_malformed_definition_names_its_source() {
        let error = parse("�not toml", "custom.toml").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("custom.toml"), "{message}");
    }

    #[test]
    fn an_unknown_category_or_severity_is_rejected() {
        let text = r#"
[audit]
id = "x"
version = "1.0.0"
title = "X"

[[checks]]
id = "c"
title = "C"
kind = "deterministic"
category = "nonsense"
severity = "high"
"#;
        assert!(parse(text, "x.toml").is_err());
    }

    #[test]
    fn a_definition_without_checks_is_rejected() {
        let text = "[audit]\nid = \"x\"\nversion = \"1.0.0\"\ntitle = \"X\"\n";
        let error = parse(text, "x.toml").unwrap_err();
        assert!(error.to_string().contains("declares no checks"), "{error}");
    }

    #[test]
    fn an_ai_check_without_an_objective_is_rejected() {
        let text = r#"
[audit]
id = "x"
version = "1.0.0"
title = "X"

[[checks]]
id = "c"
title = "C"
kind = "ai_assisted"
category = "security"
severity = "low"
"#;
        let error = parse(text, "x.toml").unwrap_err();
        assert!(
            error.to_string().contains("declares no objective"),
            "{error}"
        );
    }

    #[test]
    fn overrides_replace_by_id_and_add_new_ids() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("security.toml"),
            r#"
[audit]
id = "security"
version = "2.0.0"
title = "Security (project override)"

[[checks]]
id = "committed-secrets"
title = "Credentials committed"
kind = "deterministic"
category = "security"
severity = "critical"
"#,
        )
        .unwrap();
        std::fs::write(
            temp.path().join("house-rules.toml"),
            r#"
[audit]
id = "house-rules"
version = "0.1.0"
title = "House rules"

[[checks]]
id = "house-rule-one"
title = "Rule one"
kind = "deterministic"
category = "maintainability"
severity = "info"
"#,
        )
        .unwrap();

        let definitions = load_with_overrides(Some(temp.path())).unwrap();
        let security = definitions
            .iter()
            .find(|definition| definition.id == "security")
            .unwrap();
        assert_eq!(security.version, "2.0.0");
        assert_eq!(
            security.check("committed-secrets").unwrap().severity,
            Severity::Critical
        );
        assert!(definitions
            .iter()
            .any(|definition| definition.id == "house-rules"));
        // The embedded definitions that were not overridden are still present.
        assert!(definitions
            .iter()
            .any(|definition| definition.id == "testing"));
    }

    #[test]
    fn a_missing_override_directory_is_not_an_error() {
        let definitions = load_with_overrides(Some(Path::new("/nonexistent/definitions"))).unwrap();
        assert_eq!(definitions.len(), EMBEDDED.len());
    }
}
