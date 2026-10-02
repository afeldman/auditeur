//! Code-quality checks: unfinished-work markers, debug leftovers, file size.

use std::sync::OnceLock;

use regex::Regex;

use auditeur_model::{Evidence, Finding, Status};

use crate::checks::scan::{looks_like_test_path, scan, DEFAULT_SCAN_BYTES};
use crate::checks::{finding, pass, Check};
use crate::context::{AuditContext, EvidenceStore};
use crate::definitions::CheckSpec;
use crate::error::AuditError;

/// Line count at which a file is reported as oversized.
pub const OVERSIZED_LINES: u32 = 1_000;
/// Line count at which an oversized file is escalated from info to warn.
pub const OVERSIZED_WARN_LINES: u32 = 2_000;
/// Maximum per-file findings from the file-size check.
const MAX_SIZE_FINDINGS: usize = 10;
/// Marker count above which the markers finding is escalated to warn.
const MARKER_WARN_THRESHOLD: usize = 5;
/// Maximum marker locations cited as evidence.
const MAX_MARKER_EVIDENCE: usize = 10;

/// Checks provided by this module.
pub fn checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(TodoMarkers),
        Box::new(DebugPrints),
        Box::new(OversizedFiles),
    ]
}

/// TODO/FIXME/HACK/XXX markers in source.
pub struct TodoMarkers;

fn marker_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(TODO|FIXME|HACK|XXX)\b(?:\s*[\(\[]([^)\]]*)[\)\]])?")
            .expect("valid pattern")
    })
}

impl Check for TodoMarkers {
    fn id(&self) -> &'static str {
        "todo-markers"
    }

    fn definition_id(&self) -> &'static str {
        "code-quality"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let candidates: Vec<_> = context
            .text_files()
            .into_iter()
            .filter(|file| file.language.is_some())
            .collect();

        let result = scan(
            context,
            &candidates,
            marker_pattern(),
            DEFAULT_SCAN_BYTES,
            200,
        );
        if result.is_empty() {
            return Ok(vec![pass(
                "code-quality",
                spec,
                format!(
                    "No unfinished-work markers found in {} source file(s)",
                    candidates.len()
                ),
                Vec::new(),
            )]);
        }

        let references: Vec<_> = result
            .hits
            .iter()
            .take(MAX_MARKER_EVIDENCE)
            .map(|hit| {
                evidence.insert(
                    Evidence::file_range(
                        hit.path.clone(),
                        hit.line,
                        hit.line,
                        format!("marker at {}:{}", hit.path, hit.line),
                    )
                    .with_excerpt(&hit.text),
                )
            })
            .collect();

        let status = if result.len() > MARKER_WARN_THRESHOLD {
            Status::Warn
        } else {
            Status::Info
        };
        let mut description = format!(
            "{} unfinished-work marker(s) across {} file(s)",
            result.len(),
            result.files_with_hits().len()
        );
        if result.len() > MAX_MARKER_EVIDENCE {
            description.push_str(&format!(
                "; the first {MAX_MARKER_EVIDENCE} locations are cited"
            ));
        }
        if result.truncated {
            description.push_str("; the scan stopped at its budget");
        }

        Ok(vec![finding(
            "code-quality",
            spec,
            status,
            "markers",
            description,
            references,
        )])
    }
}

/// Debug printing left in non-test source.
pub struct DebugPrints;

fn debug_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // No look-around: the regex crate does not support it, and a `console.log`
        // on an object is still a debug statement.
        Regex::new(r"(?m)\bdbg!\s*\(|\bconsole\.log\s*\(|\bbreakpoint\s*\(\s*\)")
            .expect("valid pattern")
    })
}

impl Check for DebugPrints {
    fn id(&self) -> &'static str {
        "debug-prints"
    }

    fn definition_id(&self) -> &'static str {
        "code-quality"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let candidates: Vec<_> = context
            .text_files()
            .into_iter()
            .filter(|file| file.language.is_some() && !looks_like_test_path(&file.relative_path))
            .collect();

        let result = scan(
            context,
            &candidates,
            debug_pattern(),
            DEFAULT_SCAN_BYTES,
            20,
        );
        if result.is_empty() {
            return Ok(vec![pass(
                "code-quality",
                spec,
                "No debug printing left in non-test source",
                Vec::new(),
            )]);
        }

        let references: Vec<_> = result
            .hits
            .iter()
            .map(|hit| {
                evidence.insert(
                    Evidence::file_range(
                        hit.path.clone(),
                        hit.line,
                        hit.line,
                        format!("debug output at {}:{}", hit.path, hit.line),
                    )
                    .with_excerpt(&hit.text),
                )
            })
            .collect();

        Ok(vec![finding(
            "code-quality",
            spec,
            Status::Info,
            "debug-prints",
            format!(
                "{} debug statement(s) in {} file(s)",
                result.len(),
                result.files_with_hits().len()
            ),
            references,
        )])
    }
}

/// Files above the maintainability line threshold.
pub struct OversizedFiles;

impl Check for OversizedFiles {
    fn id(&self) -> &'static str {
        "oversized-files"
    }

    fn definition_id(&self) -> &'static str {
        "code-quality"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let candidates: Vec<_> = context
            .text_files()
            .into_iter()
            .filter(|file| file.language.is_some())
            .collect();

        let mut oversized: Vec<(u32, &auditeur_repository::discovery::SourceFile)> = Vec::new();
        for file in &candidates {
            match context.model.line_count(file) {
                Ok(lines) if lines > OVERSIZED_LINES => oversized.push((lines, file)),
                _ => continue,
            }
        }
        // Most lines first.
        oversized.sort_by_key(|entry| std::cmp::Reverse(entry.0));

        if oversized.is_empty() {
            return Ok(vec![pass(
                "code-quality",
                spec,
                format!(
                    "No source file exceeds {OVERSIZED_LINES} lines ({} file(s) measured)",
                    candidates.len()
                ),
                Vec::new(),
            )]);
        }

        let mut findings = Vec::new();
        for (lines, file) in oversized.iter().take(MAX_SIZE_FINDINGS) {
            let reference = evidence.insert(Evidence::file_range(
                file.relative_path.clone(),
                1,
                *lines,
                format!("{} has {lines} lines", file.relative_path),
            ));
            findings.push(finding(
                "code-quality",
                spec,
                if *lines > OVERSIZED_WARN_LINES {
                    Status::Warn
                } else {
                    Status::Info
                },
                &file.relative_path,
                format!("{} has {lines} lines", file.relative_path),
                vec![reference],
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
    fn markers_are_counted_with_locations() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("lib.rs"),
            "// TODO: handle the error\nfn f() {}\n// FIXME later\n",
        )
        .unwrap();
        let (findings, _) = run_check("todo-markers", "code-quality", temp.path());
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .description
            .contains("2 unfinished-work marker(s)"));
        assert_eq!(findings[0].status, Status::Info);
        assert_eq!(findings[0].evidence.len(), 2);
    }

    #[test]
    fn many_markers_escalate_to_warn() {
        let temp = tempfile::tempdir().unwrap();
        let body: String = (0..8).map(|index| format!("// TODO {index}\n")).collect();
        fs::write(temp.path().join("lib.rs"), body).unwrap();
        let (findings, _) = run_check("todo-markers", "code-quality", temp.path());
        assert_eq!(findings[0].status, Status::Warn);
    }

    #[test]
    fn a_clean_source_passes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("lib.rs"),
            "pub fn add(a: u32, b: u32) -> u32 { a + b }\n",
        )
        .unwrap();
        let (findings, _) = run_check("todo-markers", "code-quality", temp.path());
        assert_eq!(findings[0].status, Status::Pass);
    }

    #[test]
    fn debug_output_is_found_but_test_files_are_ignored() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("tests")).unwrap();
        fs::write(
            temp.path().join("app.js"),
            "function run() {\n  console.log('debug');\n}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("tests/app.test.js"),
            "console.log('test output');\n",
        )
        .unwrap();
        let (findings, _) = run_check("debug-prints", "code-quality", temp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.len(), 1);
        assert!(findings[0].description.contains("1 debug statement"));
    }

    #[test]
    fn oversized_files_are_reported_with_their_size() {
        let temp = tempfile::tempdir().unwrap();
        let body: String = (0..(OVERSIZED_LINES + 50))
            .map(|index| format!("let value_{index} = {index};\n"))
            .collect();
        fs::write(temp.path().join("big.rs"), body).unwrap();
        fs::write(temp.path().join("small.rs"), "fn f() {}\n").unwrap();

        let (findings, _) = run_check("oversized-files", "code-quality", temp.path());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("big.rs"));
        assert!(
            findings[0].description.contains("1050 lines"),
            "{}",
            findings[0].description
        );
    }

    #[test]
    fn small_files_pass_the_size_check() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("small.rs"), "fn f() {}\n").unwrap();
        let (findings, _) = run_check("oversized-files", "code-quality", temp.path());
        assert_eq!(findings[0].status, Status::Pass);
    }
}
