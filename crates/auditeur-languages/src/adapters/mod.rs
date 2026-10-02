//! Language adapters with manifest parsing and test inventory.
//!
//! Four languages have deep support in the MVP. Each one reads manifests that
//! are already in the repository and reports what they declare; no registry,
//! proxy or network endpoint is contacted, and no package manager is run.

pub mod go;
pub mod node;
pub mod python;
pub mod rust;

pub use go::GoAnalyzer;
pub use node::NodeAnalyzer;
pub use python::PythonAnalyzer;
pub use rust::RustAnalyzer;

use auditeur_model::{Evidence, Language};
use auditeur_repository::discovery::RepositoryModel;

use crate::{DetectionConfidence, DetectionResult};

/// Find the 1-based line on which `key` is declared in a manifest text.
///
/// Two passes, because manifests come in two shapes:
///
/// 1. Entry-start style (`serde = "1"`, `requests>=2.0`) — the first line whose
///    first non-whitespace token is the key, unquoted.
/// 2. Quoted-key style (`"express": "^4.19.0"`) — the first line containing the
///    key in quotes, which is what compact JSON manifests need.
///
/// Returns `None` rather than a guess when neither matches: a wrong line number
/// in evidence is worse than no line number.
pub fn manifest_key_line(text: &str, key: &str) -> Option<u32> {
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        // Tolerate quoted keys, e.g. `"serde" = "1"`.
        let candidate = trimmed.trim_start_matches(['"', '\'']);
        if let Some(rest) = candidate.strip_prefix(key) {
            let rest = rest.trim_start();
            let starts_new_entry = rest.is_empty()
                || !rest.chars().next().is_some_and(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
                });
            if starts_new_entry {
                return Some((index + 1) as u32);
            }
        }
    }

    let quoted = format!("\"{key}\"");
    for (index, line) in text.lines().enumerate() {
        if line.contains(&quoted) {
            return Some((index + 1) as u32);
        }
    }
    None
}

/// Look up a nested table by path.
pub fn toml_table_at<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

/// Build a detection result from attributed files and marker evidence.
pub fn detection_from_markers(
    language: Language,
    file_count: u32,
    markers: Vec<Evidence>,
    manifest_found: bool,
    notes: Vec<String>,
) -> DetectionResult {
    let detected = file_count > 0 || manifest_found;
    let confidence = if !detected {
        DetectionConfidence::Low
    } else if manifest_found || file_count >= 5 {
        DetectionConfidence::High
    } else {
        DetectionConfidence::Medium
    };
    DetectionResult {
        language,
        detected,
        confidence,
        file_count,
        markers,
        notes,
    }
}

/// Count lines matching a predicate across `files`, with a byte budget.
pub fn count_matching_lines(
    model: &RepositoryModel,
    files: &[&auditeur_repository::discovery::SourceFile],
    budget_bytes: u64,
    predicate: impl Fn(&str) -> bool,
) -> (u32, Vec<String>, bool) {
    let mut matches = 0u32;
    let mut matched_files = Vec::new();
    let mut bytes = 0u64;
    let mut truncated = false;
    for file in files {
        if bytes + file.size > budget_bytes {
            truncated = true;
            continue;
        }
        let Ok(text) = model.read_source_text(file) else {
            continue;
        };
        bytes += file.size;
        let mut file_hit = false;
        for line in text.lines() {
            if predicate(line) {
                matches += 1;
                file_hit = true;
            }
        }
        if file_hit {
            matched_files.push(file.relative_path.clone());
        }
    }
    (matches, matched_files, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_lines_are_found_in_several_manifest_styles() {
        let cargo = "[dependencies]\nserde = { version = \"1\" }\ntokio = \"1\"\n";
        assert_eq!(manifest_key_line(cargo, "serde"), Some(2));
        assert_eq!(manifest_key_line(cargo, "tokio"), Some(3));
        assert_eq!(manifest_key_line(cargo, "missing"), None);

        let requirements = "# comment\nrequests>=2.0\nflask\n";
        assert_eq!(manifest_key_line(requirements, "requests"), Some(2));
        assert_eq!(manifest_key_line(requirements, "flask"), Some(3));

        let json_like = "  \"name\": \"demo\",\n";
        assert_eq!(manifest_key_line(json_like, "name"), Some(1));
    }

    #[test]
    fn quoted_keys_are_found_inside_compact_json() {
        let compact = "{\n  \"dependencies\": { \"express\": \"^4.19.0\" },\n  \"devDependencies\": { \"vitest\": \"^1.6.0\" }\n}\n";
        assert_eq!(manifest_key_line(compact, "express"), Some(2));
        assert_eq!(manifest_key_line(compact, "vitest"), Some(3));
        assert_eq!(manifest_key_line(compact, "missing"), None);
    }

    #[test]
    fn key_lines_do_not_match_longer_keys() {
        let text = "serde_json = \"1\"\nserde = \"1\"\n";
        assert_eq!(manifest_key_line(text, "serde"), Some(2));
    }

    #[test]
    fn toml_tables_are_looked_up_by_path() {
        let value: toml::Value = "[a]\nb = { c = 1 }\n".parse().unwrap();
        assert!(toml_table_at(&value, &["a", "b", "c"]).is_some());
        assert!(toml_table_at(&value, &["a", "missing"]).is_none());
    }

    #[test]
    fn confidence_reflects_the_strength_of_evidence() {
        let low = detection_from_markers(Language::Go, 0, Vec::new(), false, Vec::new());
        assert!(!low.detected);
        assert_eq!(low.confidence, DetectionConfidence::Low);

        let medium = detection_from_markers(Language::Go, 2, Vec::new(), false, Vec::new());
        assert_eq!(medium.confidence, DetectionConfidence::Medium);

        let high = detection_from_markers(
            Language::Go,
            1,
            vec![Evidence::file("go.mod", "go module")],
            true,
            Vec::new(),
        );
        assert_eq!(high.confidence, DetectionConfidence::High);
    }
}
