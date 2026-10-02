//! Rust adapter: `Cargo.toml`, `Cargo.lock` and test inventory.

use auditeur_model::{Evidence, Language};
use auditeur_repository::discovery::{RepositoryModel, SourceFile};

use crate::adapters::{
    count_matching_lines, detection_from_markers, manifest_key_line, toml_table_at,
};
use crate::{
    AnalysisLevel, Dependency, DependencyGraph, DependencyKind, DependencySource, DetectionResult,
    LanguageAnalysis, LanguageAnalyzer, LanguageContext, Observation, TestInventory,
};

/// Rust analysis.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustAnalyzer;

impl RustAnalyzer {
    /// Create the adapter.
    pub const fn new() -> Self {
        Self
    }
}

impl LanguageAnalyzer for RustAnalyzer {
    fn id(&self) -> Language {
        Language::Rust
    }

    fn detect(&self, model: &RepositoryModel) -> DetectionResult {
        let mut markers = Vec::new();
        let mut manifest_found = false;

        for file in model.files_named("Cargo.toml") {
            manifest_found = true;
            markers.push(Evidence::file(
                file.relative_path.clone(),
                "Rust package manifest (Cargo.toml)",
            ));
        }
        for name in [
            "Cargo.lock",
            "rust-toolchain.toml",
            "rust-toolchain",
            "build.rs",
        ] {
            for file in model.files_named(name) {
                markers.push(Evidence::file(
                    file.relative_path.clone(),
                    format!("Rust build artefact ({name})"),
                ));
            }
        }
        let sources = model.files_with_extension("rs");
        if let Some(file) = sources.first() {
            markers.push(Evidence::file(
                file.relative_path.clone(),
                format!("Rust source files present: {} .rs file(s)", sources.len()),
            ));
        }

        let mut notes = Vec::new();
        if !manifest_found && !sources.is_empty() {
            notes.push("Rust sources found without a Cargo.toml".to_string());
        }
        detection_from_markers(
            Language::Rust,
            model.files_for_language(Language::Rust).len() as u32,
            markers,
            manifest_found,
            notes,
        )
    }

    fn dependencies(&self, context: &LanguageContext<'_>) -> DependencyGraph {
        let model = context.model;
        let mut graph = DependencyGraph {
            lockfile_present: model.has_file_named("Cargo.lock"),
            ..DependencyGraph::default()
        };

        for file in model.files_named("Cargo.toml") {
            let Some(text) = context.read(file) else {
                graph.unparsed_manifests.push(file.relative_path.clone());
                continue;
            };
            let Ok(value) = text.parse::<toml::Value>() else {
                graph.unparsed_manifests.push(file.relative_path.clone());
                continue;
            };
            graph.manifests.push(file.relative_path.clone());

            for (path, kind) in [
                (vec!["dependencies"], DependencyKind::Runtime),
                (vec!["dev-dependencies"], DependencyKind::Development),
                (vec!["build-dependencies"], DependencyKind::Build),
                (vec!["workspace", "dependencies"], DependencyKind::Runtime),
            ] {
                let Some(table) = toml_table_at(&value, &path).and_then(toml::Value::as_table)
                else {
                    continue;
                };
                for (name, spec) in table {
                    graph.dependencies.push(Dependency {
                        name: name.clone(),
                        requirement: requirement_of(spec),
                        kind,
                        manifest: file.relative_path.clone(),
                        line: manifest_key_line(&text, name),
                        source: DependencySource::Manifest,
                    });
                }
            }

            // Target-specific dependencies are recorded too: they are real
            // declarations, and omitting them would understate the dependency
            // surface on non-default targets.
            if let Some(targets) = value.get("target").and_then(toml::Value::as_table) {
                for (target, target_value) in targets {
                    for (key, kind) in [
                        ("dependencies", DependencyKind::Runtime),
                        ("dev-dependencies", DependencyKind::Development),
                        ("build-dependencies", DependencyKind::Build),
                    ] {
                        let Some(table) = target_value.get(key).and_then(toml::Value::as_table)
                        else {
                            continue;
                        };
                        for (name, spec) in table {
                            graph.dependencies.push(Dependency {
                                name: name.clone(),
                                requirement: requirement_of(spec),
                                kind,
                                manifest: file.relative_path.clone(),
                                line: manifest_key_line(&text, name),
                                source: DependencySource::Manifest,
                            });
                        }
                    }
                    if target.is_empty() {
                        graph
                            .notes
                            .push("empty target section in Cargo.toml".to_string());
                    }
                }
            }
        }

        graph
    }

    fn tests(&self, context: &LanguageContext<'_>) -> TestInventory {
        let model = context.model;
        let mut inventory = TestInventory {
            frameworks: vec!["cargo test".to_string()],
            ..TestInventory::default()
        };

        for file in model.files_under("tests/") {
            if file.relative_path.ends_with(".rs") {
                inventory.test_files.push(file.relative_path.clone());
            }
        }

        let sources: Vec<&SourceFile> = model
            .files_with_extension("rs")
            .into_iter()
            .filter(|file| !file.relative_path.starts_with("tests/"))
            .collect();
        let all_sources: Vec<&SourceFile> = model.files_with_extension("rs");
        let (inline_tests, inline_files, truncated) =
            count_matching_lines(model, &sources, context.options.max_read_bytes, |line| {
                line.contains("#[cfg(test)]")
            });
        inventory.test_files.extend(inline_files);
        inventory.test_files.sort();
        inventory.test_files.dedup();

        let (test_functions, _, functions_truncated) = count_matching_lines(
            model,
            &all_sources,
            context.options.max_read_bytes,
            |line| {
                let trimmed = line.trim_start();
                trimmed.starts_with("#[") && trimmed.trim_end().ends_with("test]")
            },
        );
        inventory.test_count = Some(test_functions);
        if inline_tests == 0 && inventory.test_files.is_empty() {
            inventory
                .notes
                .push("no test modules or integration tests found".to_string());
        }
        if truncated || functions_truncated {
            inventory
                .notes
                .push("test counting stopped at the read budget".to_string());
        }
        inventory
    }

    fn analyze(&self, context: &LanguageContext<'_>) -> LanguageAnalysis {
        let detection = self.detect(context.model);
        let files = self.files(context.model);
        let lines = crate::count_lines(context.model, &files, context.options.max_read_bytes);

        let mut observations = Vec::new();
        let mut declared_version: Option<String> = None;
        for file in context.model.files_named("Cargo.toml") {
            let Some(text) = context.read(file) else {
                continue;
            };
            let Ok(value) = text.parse::<toml::Value>() else {
                continue;
            };
            let Some(package) = value.get("package").and_then(toml::Value::as_table) else {
                // A virtual manifest: a workspace root without a package.
                if let Some(members) = value
                    .get("workspace")
                    .and_then(|workspace| workspace.get("members"))
                    .and_then(toml::Value::as_array)
                {
                    observations.push(Observation {
                        summary: format!("workspace manifest declares {} member(s)", members.len()),
                        evidence: Evidence::config(
                            file.relative_path.clone(),
                            "workspace.members",
                            format!("{} workspace members declared", members.len()),
                        )
                        .with_excerpt(&text),
                    });
                }
                continue;
            };

            let name = package
                .get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or("(unnamed)");
            let version = package
                .get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or("(inherited)");
            if declared_version.is_none() && version != "(inherited)" {
                declared_version = Some(version.to_string());
            }
            observations.push(Observation {
                summary: format!("crate `{name}` at version {version}"),
                evidence: Evidence::config(
                    file.relative_path.clone(),
                    "package.name",
                    format!("crate name `{name}`, version {version}"),
                ),
            });

            if let Some(edition) = package.get("edition").and_then(toml::Value::as_str) {
                observations.push(Observation {
                    summary: format!("crate `{name}` uses Rust edition {edition}"),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "package.edition",
                        format!("edition {edition}"),
                    )
                    .with_excerpt(&text),
                });
            }
            if let Some(msrv) = package.get("rust-version").and_then(toml::Value::as_str) {
                observations.push(Observation {
                    summary: format!(
                        "crate `{name}` declares a minimum supported Rust version of {msrv}"
                    ),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "package.rust-version",
                        format!("rust-version = {msrv}"),
                    ),
                });
            }
        }

        if !context.model.has_file_named("Cargo.lock") {
            observations.push(Observation {
                summary: "no Cargo.lock present".to_string(),
                evidence: Evidence::directory(
                    ".",
                    "Cargo.lock is absent from the repository".to_string(),
                ),
            });
        }

        LanguageAnalysis {
            language: Language::Rust,
            detection,
            level: AnalysisLevel::Deep,
            files: files.len() as u32,
            lines,
            version: declared_version,
            dependencies: self.dependencies(context),
            tests: self.tests(context),
            observations,
        }
    }
}

/// Look up a dependency requirement as written in a manifest.
///
/// Special forms are returned as the keyword `path`, `git` or `workspace`
/// rather than as a version, so that a check can distinguish "pinned to a
/// version" from "resolved from a local directory".
fn requirement_of(spec: &toml::Value) -> Option<String> {
    match spec {
        toml::Value::String(version) => Some(version.clone()),
        toml::Value::Table(table) => {
            if let Some(version) = table.get("version").and_then(toml::Value::as_str) {
                return Some(version.to_string());
            }
            if table.contains_key("path") {
                return Some("path".to_string());
            }
            if table.contains_key("git") {
                return Some("git".to_string());
            }
            if table.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
                return Some("workspace".to_string());
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_repository::discovery::{discover, DiscoveryOptions};
    use std::fs;

    fn context_of(root: &std::path::Path) -> (RepositoryModel, crate::LanguageOptions) {
        let model = discover(root, &DiscoveryOptions::unbounded()).unwrap();
        (model, crate::LanguageOptions::default())
    }

    fn cargo_project() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::create_dir_all(temp.path().join("tests")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            r#"[package]
name = "demo-crate"
version = "1.2.3"
edition = "2021"
rust-version = "1.75"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
local-helper = { path = "../helper" }
from-git = { git = "https://example.com/from-git" }

[dev-dependencies]
tempfile = "3"

[build-dependencies]
cc = "1"
"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/lib.rs"),
            "pub fn add(a: u32, b: u32) -> u32 { a + b }\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn adds() { assert_eq!(1 + 1, 2); }\n\n    #[tokio::test]\n    async fn async_adds() {}\n}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("tests/integration.rs"),
            "#[test]\nfn works() {}\n",
        )
        .unwrap();
        fs::write(temp.path().join("Cargo.lock"), "version = 3\n").unwrap();
        temp
    }

    #[test]
    fn detection_reports_a_cargo_project_with_high_confidence() {
        let temp = cargo_project();
        let (model, _) = context_of(temp.path());
        let result = RustAnalyzer.detect(&model);
        assert!(result.detected);
        assert_eq!(result.confidence, crate::DetectionConfidence::High);
        assert!(result
            .markers
            .iter()
            .any(|evidence| evidence.location.describe() == "Cargo.toml"));
    }

    #[test]
    fn dependency_kinds_and_special_requirements_are_distinguished() {
        let temp = cargo_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let graph = RustAnalyzer.dependencies(&context);

        assert!(graph.lockfile_present);
        assert!(graph.unparsed_manifests.is_empty());
        assert_eq!(
            graph.get("serde").unwrap().requirement.as_deref(),
            Some("1.0")
        );
        assert_eq!(graph.get("serde").unwrap().kind, DependencyKind::Runtime);
        assert_eq!(
            graph.get("local-helper").unwrap().requirement.as_deref(),
            Some("path")
        );
        assert_eq!(
            graph.get("from-git").unwrap().requirement.as_deref(),
            Some("git")
        );
        assert_eq!(
            graph.get("tempfile").unwrap().kind,
            DependencyKind::Development
        );
        assert_eq!(graph.get("cc").unwrap().kind, DependencyKind::Build);
        assert!(graph.get("serde").unwrap().line.is_some());
    }

    #[test]
    fn workspace_dependency_tables_are_included() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"a\", \"b\"]\n\n[workspace.dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let graph = RustAnalyzer.dependencies(&context);
        assert_eq!(
            graph.get("serde").unwrap().requirement.as_deref(),
            Some("1")
        );
    }

    #[test]
    fn target_specific_dependencies_are_recorded() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n",
        )
        .unwrap();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let graph = RustAnalyzer.dependencies(&context);
        assert_eq!(
            graph.get("libc").unwrap().requirement.as_deref(),
            Some("0.2")
        );
    }

    #[test]
    fn test_inventory_finds_integration_and_inline_tests() {
        let temp = cargo_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let inventory = RustAnalyzer.tests(&context);
        assert!(inventory.has_tests());
        assert!(inventory
            .test_files
            .contains(&"tests/integration.rs".to_string()));
        assert!(inventory.test_files.contains(&"src/lib.rs".to_string()));
        // Two inline tests plus the integration test: counting must cover both
        // locations, not just the non-test sources.
        assert_eq!(inventory.test_count, Some(3));
        assert_eq!(inventory.frameworks, vec!["cargo test".to_string()]);
    }

    #[test]
    fn analysis_records_package_metadata_as_observations() {
        let temp = cargo_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let analysis = RustAnalyzer.analyze(&context);
        assert_eq!(analysis.level, AnalysisLevel::Deep);
        assert!(analysis
            .observations
            .iter()
            .any(|observation| observation.summary.contains("demo-crate")));
        assert!(analysis
            .observations
            .iter()
            .any(|observation| observation.summary.contains("edition 2021")));
        assert!(analysis
            .observations
            .iter()
            .any(|observation| observation.summary.contains("1.75")));
        assert!(!analysis.evidence().is_empty());
    }

    #[test]
    fn a_malformed_manifest_is_reported_not_guessed() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("Cargo.toml"), "[dependencies\nbroken").unwrap();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let graph = RustAnalyzer.dependencies(&context);
        assert_eq!(graph.unparsed_manifests, vec!["Cargo.toml".to_string()]);
        assert!(graph.is_empty());
    }

    #[test]
    fn a_missing_lockfile_is_an_observation() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let analysis = RustAnalyzer.analyze(&context);
        assert!(analysis
            .observations
            .iter()
            .any(|observation| observation.summary.contains("no Cargo.lock")));
    }
}
