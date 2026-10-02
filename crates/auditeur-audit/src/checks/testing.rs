//! Testing checks: is there a test suite at all, and what does it look like.

use auditeur_model::{Evidence, Finding, Status};

use crate::checks::{finding, pass, Check};
use crate::context::{AuditContext, EvidenceStore};
use crate::definitions::CheckSpec;
use crate::error::AuditError;

/// Maximum test files cited as evidence.
const MAX_TEST_EVIDENCE: usize = 10;

/// Checks provided by this module.
pub fn checks() -> Vec<Box<dyn Check>> {
    vec![Box::new(TestsPresent), Box::new(TestInventoryCheck)]
}

/// Source without tests.
pub struct TestsPresent;

impl Check for TestsPresent {
    fn id(&self) -> &'static str {
        "tests-present"
    }

    fn definition_id(&self) -> &'static str {
        "testing"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let source_files = context.source_file_count();
        let languages = context.languages();

        if source_files == 0 {
            return Ok(vec![finding(
                "testing",
                spec,
                Status::Info,
                "no-source",
                "No source file was attributed to a supported language, so test coverage cannot be judged",
                Vec::new(),
            )]);
        }

        if context.has_tests() {
            let test_files: usize = context
                .analyses
                .iter()
                .map(|analysis| analysis.tests.file_count() as usize)
                .sum();
            let test_functions: u32 = context
                .analyses
                .iter()
                .filter_map(|analysis| analysis.tests.test_count)
                .sum();

            let references: Vec<_> = context
                .analyses
                .iter()
                .flat_map(|analysis| analysis.tests.test_files.iter())
                .take(MAX_TEST_EVIDENCE)
                .map(|path| {
                    evidence.insert(Evidence::file(
                        path.clone(),
                        "test file found by the language adapter",
                    ))
                })
                .collect();

            let mut description = format!(
                "{test_files} test file(s) and {test_functions} test function(s) found across {source_files} source file(s)"
            );
            if test_functions == 0 {
                description.push_str("; no test function was counted, which may mean the runner uses a different convention");
            }
            return Ok(vec![finding(
                "testing",
                spec,
                Status::Pass,
                "tests-present",
                description,
                references,
            )]);
        }

        let mut description = format!(
            "No test file or inline test module was found, although {source_files} source file(s) in {} language(s) are present",
            languages.len()
        );
        if !context.analyses.is_empty() {
            let notes: Vec<String> = context
                .analyses
                .iter()
                .flat_map(|analysis| analysis.tests.notes.iter().cloned())
                .collect();
            if !notes.is_empty() {
                description.push_str(&format!("; {}", notes.join("; ")));
            }
        }
        // A finding of absence still needs evidence, and the only honest evidence
        // for an absence is the search that established it. The repository root is
        // the location that was walked, and the summary states what the walk looked
        // for, so a reader can repeat it and confirm the result.
        let searches = evidence.insert(Evidence::directory(
            ".",
            format!(
                "walked for test files and inline test modules; none found among {source_files} source file(s)"
            ),
        ));

        Ok(vec![finding(
            "testing",
            spec,
            Status::Fail,
            "tests-missing",
            description,
            vec![searches],
        )])
    }
}

/// What the test suite is made of.
pub struct TestInventoryCheck;

impl Check for TestInventoryCheck {
    fn id(&self) -> &'static str {
        "test-inventory"
    }

    fn definition_id(&self) -> &'static str {
        "testing"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let mut findings = Vec::new();

        for analysis in context.analyses {
            if !analysis.tests.has_tests() {
                continue;
            }
            let references: Vec<_> = analysis
                .tests
                .test_files
                .iter()
                .take(MAX_TEST_EVIDENCE)
                .map(|path| {
                    evidence.insert(Evidence::file(
                        path.clone(),
                        format!("{} test file", analysis.language.label()),
                    ))
                })
                .collect();

            let frameworks = if analysis.tests.frameworks.is_empty() {
                "no runner identified".to_string()
            } else {
                analysis.tests.frameworks.join(", ")
            };
            let counted = match analysis.tests.test_count {
                Some(count) => format!("{count} test function(s)"),
                None => "an uncounted number of test functions".to_string(),
            };

            findings.push(finding(
                "testing",
                spec,
                Status::Info,
                &format!("inventory/{}", analysis.language.id()),
                format!(
                    "{}: {} test file(s), {counted}, runner(s): {frameworks}",
                    analysis.language.label(),
                    analysis.tests.file_count()
                ),
                references,
            ));
        }

        if findings.is_empty() {
            findings.push(pass(
                "testing",
                spec,
                "No test inventory was produced because no tests were found",
                Vec::new(),
            ));
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::run_check;
    use std::fs;

    #[test]
    fn source_without_tests_fails() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/lib.rs"),
            "pub fn add(a: u32) -> u32 { a }\n",
        )
        .unwrap();
        let (findings, _) = run_check("tests-present", "testing", temp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, Status::Fail);
        assert!(findings[0].description.contains("No test file"));
    }

    #[test]
    fn a_rust_test_module_satisfies_the_check() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/lib.rs"),
            "pub fn add(a: u32) -> u32 { a }\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn adds() {}\n}\n",
        )
        .unwrap();
        let (findings, _) = run_check("tests-present", "testing", temp.path());
        assert_eq!(findings[0].status, Status::Pass);
        assert!(findings[0].description.contains("1 test function"));
        assert!(findings[0].has_evidence());
    }

    #[test]
    fn a_repository_without_supported_sources_is_informational() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("README.md"), "# docs only\n").unwrap();
        let (findings, _) = run_check("tests-present", "testing", temp.path());
        assert_eq!(findings[0].status, Status::Info);
    }

    #[test]
    fn the_inventory_lists_runners_and_counts() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("tests")).unwrap();
        fs::write(
            temp.path().join("tests/it.rs"),
            "#[test]\nfn one() {}\n#[test]\nfn two() {}\n",
        )
        .unwrap();
        let (findings, _) = run_check("test-inventory", "testing", temp.path());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("2 test function"));
        assert!(findings[0].description.contains("cargo test"));
    }
}
