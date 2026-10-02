//! Bounded scanning of repository text.
//!
//! Checks that look for a pattern in source files all need the same three
//! things: a byte budget, a hit cap, and line numbers for evidence. Implementing
//! that once means every check behaves the same way on a large repository, and
//! that the "we stopped looking" case is explicit rather than silent.

use regex::Regex;

use auditeur_repository::discovery::SourceFile;

use crate::context::AuditContext;

/// One pattern match with its location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanHit {
    /// Repository-relative path.
    pub path: String,
    /// 1-based line number.
    pub line: u32,
    /// The matched line, trimmed. Redaction happens when it becomes evidence.
    pub text: String,
}

/// Result of a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanResult {
    /// Matches found, up to the cap.
    pub hits: Vec<ScanHit>,
    /// Files that were read.
    pub files_scanned: u32,
    /// Whether the budget or the hit cap stopped the scan early.
    pub truncated: bool,
}

impl ScanResult {
    /// Whether anything matched.
    pub fn has_hits(&self) -> bool {
        !self.hits.is_empty()
    }

    /// Number of matches found.
    pub fn len(&self) -> usize {
        self.hits.len()
    }

    /// Whether nothing matched.
    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }

    /// Distinct files with at least one hit.
    pub fn files_with_hits(&self) -> Vec<String> {
        let mut paths: Vec<String> = self.hits.iter().map(|hit| hit.path.clone()).collect();
        paths.sort();
        paths.dedup();
        paths
    }
}

/// Scan `files` for `pattern`, bounded by a byte budget and a hit cap.
///
/// Files that cannot be read are skipped rather than failing the check: a check
/// that cannot read one file should still report what it saw in the others.
pub fn scan(
    ctx: &AuditContext<'_>,
    files: &[&SourceFile],
    pattern: &Regex,
    budget_bytes: u64,
    max_hits: usize,
) -> ScanResult {
    let mut result = ScanResult::default();
    let mut bytes_read = 0u64;

    for file in files {
        if result.hits.len() >= max_hits || bytes_read + file.size > budget_bytes {
            result.truncated = true;
            break;
        }
        let Ok(text) = ctx.model.read_source_text(file) else {
            continue;
        };
        bytes_read += file.size;
        result.files_scanned += 1;

        for (index, line) in text.lines().enumerate() {
            if pattern.is_match(line) {
                result.hits.push(ScanHit {
                    path: file.relative_path.clone(),
                    line: (index + 1) as u32,
                    text: line.trim().to_string(),
                });
                if result.hits.len() >= max_hits {
                    result.truncated = true;
                    break;
                }
            }
        }
    }

    result
}

/// Default byte budget for one scan (64 MiB).
pub const DEFAULT_SCAN_BYTES: u64 = 67_108_864;

/// Directory names that hold tests, fixtures or sample data.
pub const TEST_DIRECTORIES: &[&str] = &[
    "tests",
    "test",
    "__tests__",
    "fixtures",
    "testdata",
    "spec",
    "specs",
];

/// File names that usually hold tests and fixtures.
///
/// Used by checks that would otherwise fire on deliberate test data: a fixture
/// containing a fake credential is a fixture, not a leak.
pub fn looks_like_test_path(relative_path: &str) -> bool {
    let lowered = relative_path.to_ascii_lowercase();
    let components: Vec<&str> = lowered.split('/').collect();
    let name = components.last().copied().unwrap_or(lowered.as_str());
    let directories = &components[..components.len().saturating_sub(1)];

    if directories
        .iter()
        .any(|component| TEST_DIRECTORIES.contains(component))
    {
        return true;
    }

    name.starts_with("test_")
        || name.starts_with("test-")
        || name.ends_with("_test.go")
        || name.ends_with("_test.py")
        || name.contains(".test.")
        || name.contains(".spec.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_repository::discovery::{discover, DiscoveryOptions};
    use std::fs;

    fn scan_in(root: &std::path::Path, pattern: &str, budget: u64, cap: usize) -> ScanResult {
        let model = discover(root, &DiscoveryOptions::unbounded()).unwrap();
        let config = auditeur_config::AuditConfig::default();
        let context = AuditContext::new(&model, &[], &config, None);
        let files: Vec<&SourceFile> = model.files().iter().filter(|file| file.is_text()).collect();
        let regex = Regex::new(pattern).unwrap();
        scan(&context, &files, &regex, budget, cap)
    }

    #[test]
    fn hits_carry_paths_and_line_numbers() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.txt"), "first\nneedle here\nlast\n").unwrap();
        fs::write(temp.path().join("b.txt"), "no match\n").unwrap();

        let result = scan_in(temp.path(), "needle", 1024, 10);
        assert_eq!(result.len(), 1);
        assert_eq!(result.hits[0].path, "a.txt");
        assert_eq!(result.hits[0].line, 2);
        assert_eq!(result.hits[0].text, "needle here");
        assert_eq!(result.files_scanned, 2);
        assert_eq!(result.files_with_hits(), vec!["a.txt".to_string()]);
    }

    #[test]
    fn the_hit_cap_is_reported_rather_than_silently_applied() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.txt"), "x\nx\nx\nx\n").unwrap();
        let result = scan_in(temp.path(), "x", 1024, 2);
        assert_eq!(result.len(), 2);
        assert!(result.truncated);
    }

    #[test]
    fn the_byte_budget_stops_the_scan() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("big.txt"), "x".repeat(2048)).unwrap();
        let result = scan_in(temp.path(), "x", 16, 100);
        assert_eq!(result.files_scanned, 0);
        assert!(result.truncated);
    }

    #[test]
    fn test_paths_are_recognised() {
        for path in [
            "tests/fixture.rs",
            "src/test_helper.py",
            "internal/pkg/user_test.go",
            "web/__tests__/a.test.js",
            "testdata/secret.env",
            "spec/fixtures/creds.yaml",
        ] {
            assert!(
                looks_like_test_path(path),
                "{path} should look like a test path"
            );
        }
        for path in ["src/main.rs", "docs/readme.md", "Makefile"] {
            assert!(
                !looks_like_test_path(path),
                "{path} should not look like a test path"
            );
        }
    }
}
