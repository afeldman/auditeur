//! Deterministic checks that look for security-relevant content.

use std::sync::OnceLock;

use regex::Regex;

use auditeur_model::{Evidence, Finding, Status};

use crate::checks::scan::{looks_like_test_path, scan, ScanHit, ScanResult, DEFAULT_SCAN_BYTES};
use crate::checks::{finding, pass, Check};
use crate::context::{AuditContext, EvidenceStore};
use crate::definitions::CheckSpec;
use crate::error::AuditError;

/// Maximum findings produced by a single scanning check.
const MAX_FINDINGS: usize = 20;

/// Checks provided by this module.
pub fn checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(CommittedSecrets),
        Box::new(DangerousProcessExecution),
    ]
}

/// Credential-shaped content in tracked files.
pub struct CommittedSecrets;

/// Patterns that indicate a credential rather than a variable name.
///
/// Deliberately conservative: each pattern needs evidence of a *value*, not just
/// a suspicious name. The point is to find real leaks, and a check that cries
/// wolf gets ignored, which is worse than a check that misses a case.
fn credential_patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (
                "private key block",
                Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").expect("valid pattern"),
            ),
            (
                "cloud access key id",
                Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("valid pattern"),
            ),
            (
                "JSON web token",
                Regex::new(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
                    .expect("valid pattern"),
            ),
            (
                "bearer token",
                Regex::new(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/=]{16,}").expect("valid pattern"),
            ),
            (
                "secret assignment",
                Regex::new(
                    r#"(?i)\b(api[_-]?key|apikey|secret|token|password|passwd|passphrase|credential|client[_-]?secret|auth[_-]?token|access[_-]?key)\b\s*[:=]\s*["'][A-Za-z0-9/+_\-\.=]{8,}["']"#,
                )
                .expect("valid pattern"),
            ),
            (
                "secret assignment without quotes",
                Regex::new(
                    r"(?i)\b(api[_-]?key|apikey|password|passwd|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*[A-Za-z0-9/+_\-\.]{12,}\s*$",
                )
                .expect("valid pattern"),
            ),
        ]
    })
}

impl Check for CommittedSecrets {
    fn id(&self) -> &'static str {
        "committed-secrets"
    }

    fn definition_id(&self) -> &'static str {
        "security"
    }

    fn run(
        &self,
        context: &AuditContext<'_>,
        evidence: &mut EvidenceStore,
        spec: &CheckSpec,
    ) -> Result<Vec<Finding>, AuditError> {
        let all_files: Vec<&auditeur_repository::discovery::SourceFile> = context.text_files();
        let candidates: Vec<_> = all_files
            .iter()
            .copied()
            .filter(|file| !looks_like_test_path(&file.relative_path))
            .collect();
        let excluded = all_files.len() - candidates.len();

        let mut hits: Vec<(String, ScanHit)> = Vec::new();
        let mut truncated = false;
        for (kind, pattern) in credential_patterns() {
            let result = scan(
                context,
                &candidates,
                pattern,
                DEFAULT_SCAN_BYTES,
                MAX_FINDINGS.saturating_sub(hits.len()),
            );
            truncated |= result.truncated;
            for hit in result.hits {
                // One finding per location, labelled by the most specific
                // pattern that matched: `access_key = "AKIA..."` is a cloud key
                // id, not two separate problems.
                if hits
                    .iter()
                    .any(|(_, existing)| existing.path == hit.path && existing.line == hit.line)
                {
                    continue;
                }
                hits.push(((*kind).to_string(), hit));
            }
            if hits.len() >= MAX_FINDINGS {
                break;
            }
        }
        hits.sort_by(|left, right| {
            left.1
                .path
                .cmp(&right.1.path)
                .then(left.1.line.cmp(&right.1.line))
        });

        if hits.is_empty() {
            let mut description = format!(
                "No credential-shaped content found in {} text file(s)",
                candidates.len()
            );
            if excluded > 0 {
                description.push_str(&format!(
                    "; {excluded} test or fixture file(s) were excluded from the scan"
                ));
            }
            if truncated {
                description.push_str("; the scan stopped at its budget");
            }
            return Ok(vec![pass("security", spec, description, Vec::new())]);
        }

        let mut findings = Vec::new();
        for (kind, hit) in hits.iter().take(MAX_FINDINGS) {
            let reference = evidence.insert(
                Evidence::file_range(
                    hit.path.clone(),
                    hit.line,
                    hit.line,
                    format!("{kind} at {}:{}", hit.path, hit.line),
                )
                .with_excerpt(&hit.text),
            );
            findings.push(finding(
                "security",
                spec,
                Status::Fail,
                &format!("{}:{}", hit.path, hit.line),
                format!(
                    "{kind} detected in {} at line {}. The matched value is redacted in the evidence excerpt; open the file to confirm.",
                    hit.path, hit.line
                ),
                vec![reference],
            ));
        }
        Ok(findings)
    }
}

/// Shell interpretation, dynamic evaluation and shelled subprocesses.
pub struct DangerousProcessExecution;

fn execution_patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (
                "dynamic evaluation",
                Regex::new(r"(?m)(^|[^A-Za-z0-9_])eval\s*\(").expect("valid pattern"),
            ),
            (
                "shell execution from Python",
                Regex::new(r"\bos\.(system|popen)\s*\(").expect("valid pattern"),
            ),
            (
                "subprocess with shell",
                Regex::new(r"subprocess\.[A-Za-z_]+\s*\([^)]*shell\s*=\s*True").expect("valid pattern"),
            ),
            (
                "Node child_process exec",
                Regex::new(r"child_process\.(exec|execSync)\s*\(").expect("valid pattern"),
            ),
            (
                "shell launched explicitly",
                Regex::new(r#"(?i)(Command::new|exec\.Command|Popen)\s*\(\s*["'](?:/bin/)?(sh|bash|zsh|cmd|powershell|pwsh)["']"#)
                    .expect("valid pattern"),
            ),
            (
                "C system() call",
                Regex::new(r"(?m)(^|[^A-Za-z0-9_])system\s*\(").expect("valid pattern"),
            ),
        ]
    })
}

impl Check for DangerousProcessExecution {
    fn id(&self) -> &'static str {
        "dangerous-process-execution"
    }

    fn definition_id(&self) -> &'static str {
        "security"
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

        let mut results: Vec<ScanResult> = Vec::new();
        for (_, pattern) in execution_patterns() {
            results.push(scan(
                context,
                &candidates,
                pattern,
                DEFAULT_SCAN_BYTES,
                MAX_FINDINGS,
            ));
        }

        let mut hits: Vec<(&str, ScanHit)> = Vec::new();
        for ((label, _), result) in execution_patterns().iter().zip(results.iter()) {
            for hit in &result.hits {
                hits.push((label, hit.clone()));
            }
        }
        hits.sort_by(|left, right| {
            left.1
                .path
                .cmp(&right.1.path)
                .then(left.1.line.cmp(&right.1.line))
        });
        hits.dedup_by(|left, right| left.1.path == right.1.path && left.1.line == right.1.line);
        let truncated = results.iter().any(|result| result.truncated);

        if hits.is_empty() {
            let mut description = format!(
                "No dangerous execution pattern found in {} source file(s)",
                candidates.len()
            );
            if truncated {
                description.push_str("; the scan stopped at its budget");
            }
            return Ok(vec![pass("security", spec, description, Vec::new())]);
        }

        let mut findings = Vec::new();
        for (label, hit) in hits.iter().take(MAX_FINDINGS) {
            let reference = evidence.insert(
                Evidence::file_range(
                    hit.path.clone(),
                    hit.line,
                    hit.line,
                    format!("{label} at {}:{}", hit.path, hit.line),
                )
                .with_excerpt(&hit.text),
            );
            findings.push(finding(
                "security",
                spec,
                Status::Warn,
                &format!("{}:{}", hit.path, hit.line),
                format!(
                    "{label} in {} at line {}. This is not automatically a defect: review whether the input can be influenced by an attacker.",
                    hit.path, hit.line
                ),
                vec![reference],
            ));
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{run_check, spec};
    use std::fs;

    #[test]
    fn a_committed_credential_is_a_failure_with_redacted_evidence() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("config")).unwrap();
        fs::write(
            temp.path().join("config/app.toml"),
            "api_key = \"sk-live-abcdef1234567890\"\n",
        )
        .unwrap();

        let (findings, _) = run_check("committed-secrets", "security", temp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, Status::Fail);
        assert!(findings[0].description.contains("config/app.toml"));
        assert!(findings[0].has_evidence());
    }

    #[test]
    fn the_secret_value_is_not_written_into_the_finding_or_its_evidence() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("settings.py"),
            "API_KEY = 'sk-live-abcdef1234567890'\n",
        )
        .unwrap();

        let fixture = crate::testsupport::Fixture::new(temp.path());
        let check = crate::checks::find("committed-secrets").unwrap();
        let mut store = EvidenceStore::new();
        let findings = check
            .run(
                &fixture.context(),
                &mut store,
                &spec("security", "committed-secrets"),
            )
            .unwrap();

        let serialised = serde_json::to_string(&findings).unwrap();
        assert!(
            !serialised.contains("sk-live-abcdef1234567890"),
            "{serialised}"
        );
        let evidence = serde_json::to_string(store.items()).unwrap();
        assert!(!evidence.contains("sk-live-abcdef1234567890"), "{evidence}");
        assert!(evidence.contains("[REDACTED"));
    }

    #[test]
    fn a_clean_repository_passes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("main.rs"),
            "fn main() { let key = std::env::var(\"API_KEY\"); }\n",
        )
        .unwrap();
        let (findings, _) = run_check("committed-secrets", "security", temp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, Status::Pass);
    }

    #[test]
    fn test_fixtures_are_excluded_and_the_exclusion_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("tests")).unwrap();
        fs::write(
            temp.path().join("tests/fixture.env"),
            "password = \"not-a-real-secret-value\"\n",
        )
        .unwrap();
        let (findings, _) = run_check("committed-secrets", "security", temp.path());
        assert_eq!(findings[0].status, Status::Pass);
        assert!(findings[0].description.contains("excluded"));
    }

    #[test]
    fn several_credential_kinds_are_detected_once_per_location() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("cloud.tf"),
            "access_key = \"AKIAIOSFODNN7EXAMPLE\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("deploy.sh"),
            "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'\n",
        )
        .unwrap();
        let (findings, _) = run_check("committed-secrets", "security", temp.path());
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(findings
            .iter()
            .all(|finding| finding.status == Status::Fail));

        // A location must not produce two findings with the same identifier:
        // the engine would drop one and silently lose information.
        let mut ids: Vec<&str> = findings.iter().map(|finding| finding.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), findings.len());
    }

    #[test]
    fn dangerous_execution_is_warned_not_failed() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("run.py"),
            "import os\n\ndef go(name):\n    os.system('ls ' + name)\n",
        )
        .unwrap();
        let (findings, _) = run_check("dangerous-process-execution", "security", temp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, Status::Warn);
        assert!(
            findings[0].description.contains("os.system")
                || findings[0].description.contains("shell")
        );
    }

    #[test]
    fn argument_arrays_are_not_flagged_as_shell_execution() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("main.rs"),
            "use std::process::Command;\n\nfn run() {\n    let _ = Command::new(\"cargo\").arg(\"test\").status();\n}\n",
        )
        .unwrap();
        let (findings, _) = run_check("dangerous-process-execution", "security", temp.path());
        assert_eq!(findings[0].status, Status::Pass, "{findings:?}");
    }
}
