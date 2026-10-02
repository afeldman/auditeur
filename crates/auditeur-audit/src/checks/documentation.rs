//! Documentation checks: entry points, licence, change log, coverage.
//!
//! These checks are deliberately shallow. Auditeur does not judge whether
//! documentation is *good*, only whether it exists and where; judging quality is
//! the model-assisted path, and even there the conclusion is marked as such.

use auditeur_model::{Evidence, Finding, Status};

use crate::checks::{finding, pass, Check};
use crate::context::{AuditContext, EvidenceStore};
use crate::definitions::CheckSpec;
use crate::error::AuditError;

/// File names that count as a README.
pub const README_NAMES: &[&str] = &[
    "readme",
    "readme.md",
    "readme.rst",
    "readme.txt",
    "readme.adoc",
    "readme.markdown",
];

/// File names that count as a licence declaration.
pub const LICENSE_NAMES: &[&str] = &[
    "license",
    "license.md",
    "license.txt",
    "licence",
    "licence.md",
    "copying",
    "copying.txt",
    "unlicense",
];

/// File names that count as a change log.
pub const CHANGELOG_NAMES: &[&str] = &[
    "changelog",
    "changelog.md",
    "changelog.rst",
    "changes",
    "changes.md",
    "history",
    "history.md",
    "news.md",
];

/// Extensions treated as documentation.
const DOC_EXTENSIONS: &[&str] = &["md", "rst", "adoc", "markdown", "txt"];

/// Checks provided by this module.
pub fn checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(ReadmePresent),
        Box::new(LicensePresent),
        Box::new(ChangelogPresent),
        Box::new(DocumentationCoverage),
    ]
}

// Eight parameters, each a different fact about what to look for and what to say
// when it is absent. A struct would be a single-use type carrying the same fields
// one level down, so the flat signature is kept and the lint is silenced
// deliberately rather than by accident.
#[allow(clippy::too_many_arguments)]
fn presence_check(
    definition_id: &'static str,
    spec: &CheckSpec,
    context: &AuditContext<'_>,
    evidence: &mut EvidenceStore,
    names: &[&str],
    kind: &str,
    missing_status: Status,
    missing_description: &str,
) -> Vec<Finding> {
    let found = context.files_named_any(names);
    if let Some(file) = found.first() {
        let reference = evidence.insert(Evidence::file(
            file.relative_path.clone(),
            format!("{kind} file present"),
        ));
        return vec![finding(
            definition_id,
            spec,
            Status::Pass,
            kind,
            format!("{kind} present: {}", file.relative_path),
            vec![reference],
        )];
    }
    vec![finding(
        definition_id,
        spec,
        missing_status,
        kind,
        missing_description.to_string(),
        Vec::new(),
    )]
}

/// A README at the repository root.
pub struct ReadmePresent;

impl Check for ReadmePresent {
    fn id(&self) -> &'static str {
        "readme-present"
    }

    fn definition_id(&self) -> &'static str {
        "documentation"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        Ok(presence_check(
            "documentation",
            spec,
            context,
            evidence,
            README_NAMES,
            "README",
            Status::Warn,
            "No README found; a reader has no entry point into this repository",
        ))
    }
}

/// A licence declaration.
pub struct LicensePresent;

impl Check for LicensePresent {
    fn id(&self) -> &'static str {
        "license-present"
    }

    fn definition_id(&self) -> &'static str {
        "documentation"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        // A manifest licence field counts too: many projects declare the
        // licence in Cargo.toml or package.json and ship no LICENSE file.
        for analysis in context.analyses {
            for manifest in &analysis.dependencies.manifests {
                let Some(file) = context.model.file(manifest) else {
                    continue;
                };
                let Ok(text) = context.model.read_source_text(file) else {
                    continue;
                };
                let declares = text.lines().any(|line| {
                    let trimmed = line.trim_start();
                    trimmed.starts_with("license")
                        || trimmed.starts_with("\"license\"")
                        || trimmed.starts_with("'license'")
                });
                if declares {
                    let reference = evidence.insert(Evidence::config(
                        manifest.clone(),
                        "license",
                        format!("licence declared in {manifest}"),
                    ));
                    return Ok(vec![finding(
                        "documentation",
                        spec,
                        Status::Pass,
                        "LICENSE",
                        format!("Licence declared in {manifest}"),
                        vec![reference],
                    )]);
                }
            }
        }

        Ok(presence_check(
            "documentation",
            spec,
            context,
            evidence,
            LICENSE_NAMES,
            "LICENSE",
            Status::Warn,
            "No licence file and no licence field in a manifest; the terms of use are undefined",
        ))
    }
}

/// A change log.
pub struct ChangelogPresent;

impl Check for ChangelogPresent {
    fn id(&self) -> &'static str {
        "changelog-present"
    }

    fn definition_id(&self) -> &'static str {
        "documentation"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        Ok(presence_check(
            "documentation",
            spec,
            context,
            evidence,
            CHANGELOG_NAMES,
            "CHANGELOG",
            Status::Info,
            "No change log found",
        ))
    }
}

/// Documentation volume relative to source volume.
pub struct DocumentationCoverage;

impl Check for DocumentationCoverage {
    fn id(&self) -> &'static str {
        "documentation-coverage"
    }

    fn definition_id(&self) -> &'static str {
        "documentation"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let source_lines: u64 = context
            .analyses
            .iter()
            .map(|analysis| analysis.lines.lines)
            .sum();
        let source_files = context.source_file_count();

        let doc_files: Vec<_> = context
            .model
            .files()
            .iter()
            .filter(|file| {
                file.is_text()
                    && file
                        .extension
                        .as_deref()
                        .is_some_and(|extension| DOC_EXTENSIONS.contains(&extension))
            })
            .collect();
        let doc_lines: u64 = doc_files
            .iter()
            .filter_map(|file| context.model.line_count(file).ok())
            .map(u64::from)
            .sum();

        if source_files == 0 {
            return Ok(vec![pass(
                "documentation",
                spec,
                "No source files were attributed to a supported language",
                Vec::new(),
            )]);
        }

        let references: Vec<_> = doc_files
            .iter()
            .take(5)
            .map(|file| {
                evidence.insert(Evidence::file(
                    file.relative_path.clone(),
                    "documentation file",
                ))
            })
            .collect();

        let ratio = if source_lines == 0 {
            0.0
        } else {
            doc_lines as f64 / source_lines as f64
        };
        Ok(vec![finding(
            "documentation",
            spec,
            Status::Info,
            "coverage",
            format!(
                "{} documentation file(s) with {doc_lines} line(s) against {source_files} source file(s) with {source_lines} line(s) (ratio {ratio:.2})",
                doc_files.len()
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
    fn a_missing_readme_warns() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        let (findings, _) = run_check("readme-present", "documentation", temp.path());
        assert_eq!(findings[0].status, Status::Warn);
        assert!(findings[0].description.contains("No README"));
    }

    #[test]
    fn a_readme_passes_regardless_of_extension_case() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("README.md"), "# Project\n").unwrap();
        let (findings, _) = run_check("readme-present", "documentation", temp.path());
        assert_eq!(findings[0].status, Status::Pass);
        assert!(findings[0].description.contains("README.md"));
    }

    #[test]
    fn a_licence_file_or_a_manifest_field_both_count() {
        let with_file = tempfile::tempdir().unwrap();
        fs::write(with_file.path().join("LICENSE"), "MIT\n").unwrap();
        let (findings, _) = run_check("license-present", "documentation", with_file.path());
        assert_eq!(findings[0].status, Status::Pass);

        let with_manifest = tempfile::tempdir().unwrap();
        fs::create_dir_all(with_manifest.path().join("src")).unwrap();
        fs::write(
            with_manifest.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\nlicense = \"MIT OR Apache-2.0\"\n",
        )
        .unwrap();
        fs::write(with_manifest.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let (findings, _) = run_check("license-present", "documentation", with_manifest.path());
        assert_eq!(findings[0].status, Status::Pass);
        assert!(findings[0].description.contains("Cargo.toml"));
    }

    #[test]
    fn a_missing_licence_warns() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        let (findings, _) = run_check("license-present", "documentation", temp.path());
        assert_eq!(findings[0].status, Status::Warn);
    }

    #[test]
    fn coverage_counts_documentation_against_source() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        fs::write(temp.path().join("guide.md"), "# Guide\nmore\n").unwrap();
        let (findings, _) = run_check("documentation-coverage", "documentation", temp.path());
        assert_eq!(findings[0].status, Status::Info);
        assert!(findings[0].description.contains("1 documentation file"));
        assert!(findings[0].description.contains("ratio"));
    }

    #[test]
    fn a_missing_changelog_is_only_informational() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();
        let (findings, _) = run_check("changelog-present", "documentation", temp.path());
        assert_eq!(findings[0].status, Status::Info);
    }
}
