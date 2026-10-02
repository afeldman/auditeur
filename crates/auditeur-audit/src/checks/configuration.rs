//! Configuration checks: repository configuration hygiene.

use auditeur_model::{Evidence, Finding, Status};

use crate::checks::{finding, pass, Check};
use crate::context::{AuditContext, EvidenceStore};
use crate::definitions::CheckSpec;
use crate::error::AuditError;

/// Committed files that normally hold local secrets.
///
/// `.env.example`, `.env.sample` and `.env.template` are deliberately absent:
/// those files are meant to be committed and hold no values.
pub const ENVIRONMENT_FILE_PREFIXES: &[&str] = &[".env", "secrets.", "credentials."];

/// File names that are always treated as a leak regardless of prefix rules.
pub const ENVIRONMENT_FILE_NAMES: &[&str] = &[
    "secrets.yml",
    "secrets.yaml",
    "secrets.json",
    "credentials.json",
    "credentials.yml",
    "id_rsa",
    "id_ed25519",
];

/// Files that are examples rather than live configuration.
pub const ENVIRONMENT_EXAMPLES: &[&str] = &[".example", ".sample", ".template", ".dist"];

/// Configuration and infrastructure files worth recording.
pub const CONFIGURATION_FILES: &[&str] = &[
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Makefile",
    "justfile",
    "Taskfile.yml",
    ".editorconfig",
    "tsconfig.json",
    "deno.json",
    "vite.config.ts",
    "webpack.config.js",
    "pytest.ini",
    "tox.ini",
    ".terraform.lock.hcl",
    ".pre-commit-config.yaml",
    "rustfmt.toml",
    "clippy.toml",
    ".rustfmt.toml",
    ".eslintrc",
    ".eslintrc.json",
    "biome.json",
];

/// Checks provided by this module.
pub fn checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(CommittedEnvironmentFile),
        Box::new(IgnoreFilePresent),
        Box::new(EnvironmentConfiguration),
    ]
}

/// A committed file that is meant to hold local secrets.
pub struct CommittedEnvironmentFile;

/// Whether a file name looks like a live environment file.
pub fn is_live_environment_file(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    if ENVIRONMENT_EXAMPLES
        .iter()
        .any(|suffix| lowered.ends_with(suffix))
    {
        return false;
    }
    if ENVIRONMENT_FILE_NAMES
        .iter()
        .any(|candidate| lowered == *candidate)
    {
        return true;
    }
    ENVIRONMENT_FILE_PREFIXES
        .iter()
        .any(|prefix| lowered == *prefix || lowered.starts_with(&format!("{prefix}.")))
}

impl Check for CommittedEnvironmentFile {
    fn id(&self) -> &'static str {
        "committed-environment-file"
    }

    fn definition_id(&self) -> &'static str {
        "configuration"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let mut findings = Vec::new();

        for file in context.model.files() {
            let name = file.file_name();
            if !is_live_environment_file(name) {
                continue;
            }

            // The excerpt proves the file has content, and is redacted on the
            // way in, so a real credential never reaches the report.
            let mut evidence_item = Evidence::file(
                file.relative_path.clone(),
                format!("{} is present in the repository", file.relative_path),
            );
            if let Ok(text) = context.model.read_source_text(file) {
                let preview: String = text.lines().take(5).collect::<Vec<_>>().join("\n");
                evidence_item = evidence_item.with_excerpt(&preview);
            }
            let reference = evidence.insert(evidence_item);

            let empty = file.size == 0;
            findings.push(finding(
                "configuration",
                spec,
                if empty { Status::Warn } else { Status::Fail },
                &file.relative_path,
                if empty {
                    format!(
                        "{} is committed but empty; the file name pattern suggests it is meant to hold local secrets",
                        file.relative_path
                    )
                } else {
                    format!(
                        "{} is committed and is not empty; files of this name normally hold local secrets, and its values are in the repository history",
                        file.relative_path
                    )
                },
                vec![reference],
            ));
        }

        if findings.is_empty() {
            findings.push(pass(
                "configuration",
                spec,
                "No committed environment file was found",
                Vec::new(),
            ));
        }
        Ok(findings)
    }
}

/// Version-control ignore rules.
pub struct IgnoreFilePresent;

impl Check for IgnoreFilePresent {
    fn id(&self) -> &'static str {
        "ignore-file-present"
    }

    fn definition_id(&self) -> &'static str {
        "configuration"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let found = context.files_named_any(&[".gitignore", ".ignore", ".gitattributes"]);
        match found.first() {
            Some(file) => {
                let reference = evidence.insert(Evidence::file(
                    file.relative_path.clone(),
                    "version-control ignore rules present",
                ));
                Ok(vec![finding(
                    "configuration",
                    spec,
                    Status::Pass,
                    "ignore-file",
                    format!("Ignore rules present: {}", file.relative_path),
                    vec![reference],
                )])
            }
            None => Ok(vec![finding(
                "configuration",
                spec,
                Status::Info,
                "ignore-file",
                "No ignore file found; build output and local files can end up committed",
                Vec::new(),
            )]),
        }
    }
}

/// Configuration and infrastructure files that are present.
pub struct EnvironmentConfiguration;

impl Check for EnvironmentConfiguration {
    fn id(&self) -> &'static str {
        "environment-configuration"
    }

    fn definition_id(&self) -> &'static str {
        "configuration"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let present = context.files_named_any(CONFIGURATION_FILES);
        if present.is_empty() {
            return Ok(vec![pass(
                "configuration",
                spec,
                "No configuration or infrastructure files found at the known names",
                Vec::new(),
            )]);
        }

        let references: Vec<_> = present
            .iter()
            .take(10)
            .map(|file| {
                evidence.insert(Evidence::file(
                    file.relative_path.clone(),
                    "configuration or infrastructure file",
                ))
            })
            .collect();

        Ok(vec![finding(
            "configuration",
            spec,
            Status::Info,
            "configuration-files",
            format!(
                "{} configuration file(s) present: {}",
                present.len(),
                present
                    .iter()
                    .take(10)
                    .map(|file| file.relative_path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            references,
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::run_check;
    use std::fs;

    #[test]
    fn environment_file_names_are_classified_correctly() {
        for live in [
            ".env",
            ".env.local",
            ".env.production",
            "secrets.yaml",
            "id_rsa",
        ] {
            assert!(is_live_environment_file(live), "{live} should be live");
        }
        for example in [
            ".env.example",
            ".env.sample",
            ".env.template",
            "secrets.yaml.example",
        ] {
            assert!(
                !is_live_environment_file(example),
                "{example} is an example"
            );
        }
        for ordinary in ["environment.rs", "config.toml", "env"] {
            assert!(
                !is_live_environment_file(ordinary),
                "{ordinary} should not be treated as a secrets file"
            );
        }
    }

    #[test]
    fn a_committed_env_file_is_a_failure_with_redacted_evidence() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join(".env"),
            "DATABASE_URL=postgres://user:pw@localhost/db\nAPI_KEY=sk-live-abcdef123456\n",
        )
        .unwrap();
        let fixture = crate::testsupport::Fixture::new(temp.path());
        let check = crate::checks::find("committed-environment-file").unwrap();
        let mut store = EvidenceStore::new();
        let findings = check
            .run(
                &fixture.context(),
                &mut store,
                &crate::testsupport::spec("configuration", "committed-environment-file"),
            )
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, Status::Fail);
        let serialised = serde_json::to_string(store.items()).unwrap();
        assert!(!serialised.contains("sk-live-abcdef123456"), "{serialised}");
        assert!(serialised.contains("[REDACTED"), "{serialised}");
    }

    #[test]
    fn an_example_file_does_not_trigger_the_check() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(".env.example"), "API_KEY=your-key-here\n").unwrap();
        let (findings, _) = run_check("committed-environment-file", "configuration", temp.path());
        assert_eq!(findings[0].status, Status::Pass);
    }

    #[test]
    fn an_empty_committed_environment_file_warns_rather_than_fails() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(".env"), "").unwrap();
        let (findings, _) = run_check("committed-environment-file", "configuration", temp.path());
        assert_eq!(findings[0].status, Status::Warn);
    }

    #[test]
    fn ignore_files_are_recognised() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(".gitignore"), "/target\n").unwrap();
        let (findings, _) = run_check("ignore-file-present", "configuration", temp.path());
        assert_eq!(findings[0].status, Status::Pass);
    }

    #[test]
    fn configuration_files_are_listed() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        fs::write(temp.path().join("Makefile"), "all:\n\techo hi\n").unwrap();
        let (findings, _) = run_check("environment-configuration", "configuration", temp.path());
        assert!(findings[0].description.contains("Dockerfile"));
        assert!(findings[0].description.contains("Makefile"));
        assert_eq!(findings[0].evidence.len(), 2);
    }
}
