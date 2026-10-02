//! Architecture and delivery checks: layout, CI configuration, project shape.

use auditeur_model::{Evidence, Finding, Status};

use crate::checks::{finding, pass, Check};
use crate::context::{AuditContext, EvidenceStore};
use crate::definitions::CheckSpec;
use crate::error::AuditError;

/// CI configuration locations, as (path, directory?) pairs.
pub const CI_LOCATIONS: &[(&str, bool)] = &[
    (".github/workflows", true),
    (".gitlab-ci.yml", false),
    (".circleci/config.yml", false),
    ("azure-pipelines.yml", false),
    ("Jenkinsfile", false),
    (".travis.yml", false),
    (".woodpecker.yml", false),
    ("buildkite", true),
    ("bitbucket-pipelines.yml", false),
    ("Makefile.ci", false),
];

/// Conventional top-level source directories.
pub const SOURCE_DIRECTORIES: &[&str] = &["src", "lib", "app", "pkg", "internal", "cmd", "crates"];

/// Manifest file names that indicate a project root.
pub const PROJECT_MANIFESTS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "go.mod",
    "pyproject.toml",
    "setup.py",
    "Project.toml",
    "CMakeLists.txt",
];

/// Checks provided by this module.
pub fn checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(CiConfigurationPresent),
        Box::new(SourceLayout),
        Box::new(MultipleProjectManifests),
    ]
}

/// A CI configuration at a well-known location.
pub struct CiConfigurationPresent;

impl Check for CiConfigurationPresent {
    fn id(&self) -> &'static str {
        "ci-configuration-present"
    }

    fn definition_id(&self) -> &'static str {
        "architecture"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let mut found = Vec::new();
        for (path, is_directory) in CI_LOCATIONS {
            let present = if *is_directory {
                context.model.has_dir(path)
                    || context
                        .model
                        .dirs()
                        .iter()
                        .any(|directory| directory.starts_with(path))
            } else {
                context.model.has_file(path)
            };
            if present {
                found.push((*path, *is_directory));
            }
        }

        if found.is_empty() {
            return Ok(vec![finding(
                "architecture",
                spec,
                Status::Warn,
                "ci-configuration",
                format!(
                    "No CI configuration found at any of the {} known locations; nothing builds or tests a change automatically",
                    CI_LOCATIONS.len()
                ),
                Vec::new(),
            )]);
        }

        let references: Vec<_> = found
            .iter()
            .map(|(path, is_directory)| {
                if *is_directory {
                    evidence.insert(Evidence::directory(
                        (*path).to_string(),
                        "CI configuration directory",
                    ))
                } else {
                    evidence.insert(Evidence::file(*path, "CI configuration file"))
                }
            })
            .collect();

        let rendered: Vec<String> = found
            .iter()
            .map(|(path, _)| {
                context
                    .model
                    .files_under(path)
                    .first()
                    .map(|file| file.relative_path.clone())
                    .unwrap_or_else(|| (*path).to_string())
            })
            .collect();

        Ok(vec![finding(
            "architecture",
            spec,
            Status::Pass,
            "ci-configuration",
            format!("CI configuration present: {}", rendered.join(", ")),
            references,
        )])
    }
}

/// Whether sources live in a conventional directory.
pub struct SourceLayout;

impl Check for SourceLayout {
    fn id(&self) -> &'static str {
        "source-layout"
    }

    fn definition_id(&self) -> &'static str {
        "architecture"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let present: Vec<&str> = SOURCE_DIRECTORIES
            .iter()
            .copied()
            .filter(|directory| context.model.has_dir(directory))
            .collect();

        if present.is_empty() {
            let top_level_source_files = context
                .model
                .files()
                .iter()
                .filter(|file| file.language.is_some() && !file.relative_path.contains('/'))
                .count();
            return Ok(vec![finding(
                "architecture",
                spec,
                Status::Info,
                "layout",
                format!(
                    "No conventional source directory found; {top_level_source_files} source file(s) sit at the repository root"
                ),
                Vec::new(),
            )]);
        }

        let references: Vec<_> = present
            .iter()
            .map(|directory| {
                evidence.insert(Evidence::directory(
                    (*directory).to_string(),
                    "conventional source directory",
                ))
            })
            .collect();

        let has_tests_dir = context.model.has_dir("tests")
            || context.model.has_dir("test")
            || context.model.has_dir("spec");
        Ok(vec![finding(
            "architecture",
            spec,
            Status::Info,
            "layout",
            format!(
                "Source directories: {}{}",
                present.join(", "),
                if has_tests_dir {
                    "; a top-level test directory is present"
                } else {
                    "; no top-level test directory"
                }
            ),
            references,
        )])
    }
}

/// Repository containing several independent projects.
pub struct MultipleProjectManifests;

impl Check for MultipleProjectManifests {
    fn id(&self) -> &'static str {
        "multiple-project-manifests"
    }

    fn definition_id(&self) -> &'static str {
        "architecture"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let manifests: Vec<_> = context.files_named_any(PROJECT_MANIFESTS);
        if manifests.is_empty() {
            return Ok(vec![pass(
                "architecture",
                spec,
                "No project manifest found at any of the well-known names",
                Vec::new(),
            )]);
        }

        let references: Vec<_> = manifests
            .iter()
            .take(10)
            .map(|file| {
                evidence.insert(Evidence::file(
                    file.relative_path.clone(),
                    "project manifest",
                ))
            })
            .collect();

        let languages = context.languages().len();
        Ok(vec![finding(
            "architecture",
            spec,
            Status::Info,
            "manifests",
            format!(
                "{} project manifest(s) found across {languages} detected language(s): {}",
                manifests.len(),
                manifests
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
    fn a_repository_without_ci_warns() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        let (findings, _) = run_check("ci-configuration-present", "architecture", temp.path());
        assert_eq!(findings[0].status, Status::Warn);
    }

    #[test]
    fn github_workflows_are_recognised_as_ci() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join(".github/workflows")).unwrap();
        fs::write(
            temp.path().join(".github/workflows/ci.yml"),
            "name: CI\non: [push]\n",
        )
        .unwrap();
        let (findings, _) = run_check("ci-configuration-present", "architecture", temp.path());
        assert_eq!(findings[0].status, Status::Pass);
        assert!(findings[0].description.contains("workflows/ci.yml"));
    }

    #[test]
    fn layout_reports_a_src_directory_and_missing_tests_directory() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let (findings, _) = run_check("source-layout", "architecture", temp.path());
        assert!(findings[0].description.contains("src"));
        assert!(findings[0]
            .description
            .contains("no top-level test directory"));
    }

    #[test]
    fn several_manifests_are_reported_as_evidence_of_a_monorepo() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("api/src")).unwrap();
        fs::create_dir_all(temp.path().join("web")).unwrap();
        fs::write(
            temp.path().join("api/Cargo.toml"),
            "[package]\nname = \"api\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("api/src/lib.rs"), "pub fn f() {}\n").unwrap();
        fs::write(temp.path().join("web/package.json"), "{\"name\":\"web\"}\n").unwrap();
        let (findings, _) = run_check("multiple-project-manifests", "architecture", temp.path());
        assert!(findings[0].description.contains("2 project manifest"));
        assert_eq!(findings[0].evidence.len(), 2);
    }
}
