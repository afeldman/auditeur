//! Node.js adapter: `package.json`, lockfiles and test inventory.

use auditeur_model::redact::redact_text;
use auditeur_model::{Evidence, Language};
use auditeur_repository::discovery::RepositoryModel;

use crate::adapters::{count_matching_lines, detection_from_markers, manifest_key_line};
use crate::{
    AnalysisLevel, Dependency, DependencyGraph, DependencyKind, DependencySource, DetectionResult,
    LanguageAnalysis, LanguageAnalyzer, LanguageContext, Observation, TestInventory,
};

/// Test runners recognised in `devDependencies`.
pub const KNOWN_TEST_RUNNERS: &[&str] = &[
    "jest",
    "vitest",
    "mocha",
    "ava",
    "tap",
    "jasmine",
    "c8",
    "cypress",
    "playwright",
    "@playwright/test",
];

/// Node.js analysis.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeAnalyzer;

impl NodeAnalyzer {
    /// Create the adapter.
    pub const fn new() -> Self {
        Self
    }
}

/// Parse a `package.json` into a JSON value.
pub fn parse_package_json(text: &str) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_str::<serde_json::Value>(text)
}

/// Extract a dependency table from `package.json`.
fn dependency_table(
    value: &serde_json::Value,
    key: &str,
    kind: DependencyKind,
    manifest: &str,
    text: &str,
    graph: &mut DependencyGraph,
) {
    let Some(table) = value.get(key).and_then(serde_json::Value::as_object) else {
        return;
    };
    for (name, spec) in table {
        graph.dependencies.push(Dependency {
            name: name.clone(),
            requirement: spec.as_str().map(str::to_string),
            kind,
            manifest: manifest.to_string(),
            line: manifest_key_line(text, name),
            source: DependencySource::Manifest,
        });
    }
}

impl LanguageAnalyzer for NodeAnalyzer {
    fn id(&self) -> Language {
        Language::NodeJs
    }

    fn detect(&self, model: &RepositoryModel) -> DetectionResult {
        let mut markers = Vec::new();
        let mut manifest_found = false;

        for file in model.files_named("package.json") {
            manifest_found = true;
            markers.push(Evidence::file(
                file.relative_path.clone(),
                "Node.js package manifest (package.json)",
            ));
        }
        for name in [
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "tsconfig.json",
            ".nvmrc",
        ] {
            for file in model.files_named(name) {
                markers.push(Evidence::file(
                    file.relative_path.clone(),
                    format!("Node.js project artefact ({name})"),
                ));
            }
        }
        let sources = model.files_with_extension("js");
        if let Some(file) = sources.first() {
            markers.push(Evidence::file(
                file.relative_path.clone(),
                format!("JavaScript source files present: {} file(s)", sources.len()),
            ));
        }

        let mut notes = Vec::new();
        if !manifest_found && !sources.is_empty() {
            notes.push("JavaScript sources found without a package.json".to_string());
        }
        detection_from_markers(
            Language::NodeJs,
            model.files_for_language(Language::NodeJs).len() as u32,
            markers,
            manifest_found,
            notes,
        )
    }

    fn dependencies(&self, context: &LanguageContext<'_>) -> DependencyGraph {
        let model = context.model;
        let mut graph = DependencyGraph {
            lockfile_present: ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]
                .iter()
                .any(|name| model.has_file_named(name)),
            ..DependencyGraph::default()
        };

        for file in model.files_named("package.json") {
            let Some(text) = context.read(file) else {
                graph.unparsed_manifests.push(file.relative_path.clone());
                continue;
            };
            let Ok(value) = parse_package_json(&text) else {
                graph.unparsed_manifests.push(file.relative_path.clone());
                continue;
            };
            graph.manifests.push(file.relative_path.clone());

            for (key, kind) in [
                ("dependencies", DependencyKind::Runtime),
                ("devDependencies", DependencyKind::Development),
                ("peerDependencies", DependencyKind::Runtime),
                ("optionalDependencies", DependencyKind::Runtime),
            ] {
                dependency_table(&value, key, kind, &file.relative_path, &text, &mut graph);
            }

            // Workspaces: member packages are dependencies in a monorepo, and
            // omitting them would hide most of the dependency surface.
            if let Some(workspaces) = value.get("workspaces") {
                let members: Vec<String> = match workspaces {
                    serde_json::Value::Array(entries) => entries
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect(),
                    serde_json::Value::Object(table) => table
                        .get("packages")
                        .and_then(serde_json::Value::as_array)
                        .map(|entries| {
                            entries
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default(),
                    _ => Vec::new(),
                };
                if !members.is_empty() {
                    graph.notes.push(format!(
                        "{} workspace member pattern(s) declared",
                        members.len()
                    ));
                }
            }
        }

        graph
    }

    fn tests(&self, context: &LanguageContext<'_>) -> TestInventory {
        let model = context.model;
        let mut inventory = TestInventory::default();

        let candidates: Vec<_> = model
            .files()
            .iter()
            .filter(|file| {
                let name = file.file_name();
                let is_js = matches!(
                    file.extension.as_deref(),
                    Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx")
                );
                is_js
                    && (name.contains(".test.")
                        || name.contains(".spec.")
                        || file.relative_path.starts_with("__tests__/"))
            })
            .collect();
        inventory.test_files = candidates
            .iter()
            .map(|file| file.relative_path.clone())
            .collect();

        let (test_cases, _, truncated) =
            count_matching_lines(model, &candidates, context.options.max_read_bytes, |line| {
                let trimmed = line.trim_start();
                trimmed.starts_with("it(")
                    || trimmed.starts_with("test(")
                    || trimmed.starts_with("it.each")
                    || trimmed.starts_with("describe(")
            });
        inventory.test_count = Some(test_cases);

        let graph = self.dependencies(context);
        for dependency in &graph.dependencies {
            if KNOWN_TEST_RUNNERS.contains(&dependency.name.as_str())
                && !inventory.frameworks.contains(&dependency.name)
            {
                inventory.frameworks.push(dependency.name.clone());
            }
        }
        if inventory.frameworks.is_empty() && !inventory.test_files.is_empty() {
            inventory
                .notes
                .push("test files present but no known runner in dependencies".to_string());
        }
        if truncated {
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
        for file in context.model.files_named("package.json") {
            let Some(text) = context.read(file) else {
                continue;
            };
            let Ok(value) = parse_package_json(&text) else {
                continue;
            };

            let name = value.get("name").and_then(serde_json::Value::as_str);
            let version = value.get("version").and_then(serde_json::Value::as_str);
            if declared_version.is_none() {
                declared_version = version.map(str::to_string);
            }
            if let Some(name) = name {
                observations.push(Observation {
                    summary: format!(
                        "package `{name}`{}",
                        version
                            .map(|version| format!(" version {version}"))
                            .unwrap_or_default()
                    ),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "name",
                        format!("package name `{name}`"),
                    ),
                });
            }
            if value.get("private").and_then(serde_json::Value::as_bool) == Some(true) {
                observations.push(Observation {
                    summary: "package is marked private".to_string(),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "private",
                        "private: true",
                    )
                    .with_excerpt(&text),
                });
            }
            if let Some(module_type) = value.get("type").and_then(serde_json::Value::as_str) {
                observations.push(Observation {
                    summary: format!("module system: {module_type}"),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "type",
                        format!("type = {module_type}"),
                    ),
                });
            }
            if let Some(manager) = value
                .get("packageManager")
                .and_then(serde_json::Value::as_str)
            {
                observations.push(Observation {
                    summary: format!("declared package manager: {manager}"),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "packageManager",
                        format!("packageManager = {manager}"),
                    ),
                });
            }
            if let Some(scripts) = value.get("scripts").and_then(serde_json::Value::as_object) {
                observations.push(Observation {
                    summary: format!("{} npm script(s) declared", scripts.len()),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "scripts",
                        format!("{} scripts declared", scripts.len()),
                    ),
                });
                if let Some(test_script) = scripts.get("test").and_then(serde_json::Value::as_str) {
                    // Redacted: a script can embed credentials in a URL.
                    let redacted = redact_text(test_script);
                    observations.push(Observation {
                        summary: format!("test script: {redacted}"),
                        evidence: Evidence::config(
                            file.relative_path.clone(),
                            "scripts.test",
                            format!("test script: {redacted}"),
                        ),
                    });
                }
            }
            if let Some(engines) = value.get("engines").and_then(serde_json::Value::as_object) {
                let rendered = engines
                    .iter()
                    .map(|(engine, requirement)| {
                        format!(
                            "{engine} {}",
                            requirement.as_str().unwrap_or("(unspecified)")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                observations.push(Observation {
                    summary: format!("engine requirements: {rendered}"),
                    evidence: Evidence::config(file.relative_path.clone(), "engines", rendered),
                });
            }
        }

        LanguageAnalysis {
            language: Language::NodeJs,
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

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_repository::discovery::{discover, DiscoveryOptions};
    use std::fs;

    fn context_of(root: &std::path::Path) -> (RepositoryModel, crate::LanguageOptions) {
        let model = discover(root, &DiscoveryOptions::unbounded()).unwrap();
        (model, crate::LanguageOptions::default())
    }

    fn node_project() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::create_dir_all(temp.path().join("__tests__")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{
  "name": "demo-app",
  "version": "0.4.0",
  "private": true,
  "type": "module",
  "packageManager": "pnpm@9.0.0",
  "workspaces": ["packages/*"],
  "engines": { "node": ">=20" },
  "scripts": { "build": "tsc", "test": "vitest run" },
  "dependencies": { "express": "^4.19.0" },
  "devDependencies": { "vitest": "^1.6.0", "typescript": "^5.4.0" }
}
"#,
        )
        .unwrap();
        fs::write(temp.path().join("pnpm-lock.yaml"), "lockfileVersion: 9\n").unwrap();
        fs::write(temp.path().join("src/index.js"), "export const a = 1;\n").unwrap();
        fs::write(
            temp.path().join("__tests__/index.test.js"),
            "describe('index', () => {\n  it('works', () => {});\n  test('also works', () => {});\n});\n",
        )
        .unwrap();
        temp
    }

    #[test]
    fn detection_reports_a_node_project() {
        let temp = node_project();
        let (model, _) = context_of(temp.path());
        let detection = NodeAnalyzer.detect(&model);
        assert!(detection.detected);
        assert_eq!(detection.confidence, crate::DetectionConfidence::High);
    }

    #[test]
    fn dependencies_include_all_sections_and_lockfile_state() {
        let temp = node_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let graph = NodeAnalyzer.dependencies(&context);

        assert!(graph.lockfile_present);
        assert_eq!(
            graph.get("express").unwrap().requirement.as_deref(),
            Some("^4.19.0")
        );
        assert_eq!(graph.get("express").unwrap().kind, DependencyKind::Runtime);
        assert_eq!(
            graph.get("vitest").unwrap().kind,
            DependencyKind::Development
        );
        assert!(graph.get("express").unwrap().line.is_some());
        assert!(graph.notes.iter().any(|note| note.contains("workspace")));
    }

    #[test]
    fn test_inventory_finds_files_and_runner() {
        let temp = node_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let inventory = NodeAnalyzer.tests(&context);
        assert_eq!(
            inventory.test_files,
            vec!["__tests__/index.test.js".to_string()]
        );
        assert_eq!(inventory.test_count, Some(3));
        assert_eq!(inventory.frameworks, vec!["vitest".to_string()]);
    }

    #[test]
    fn observations_capture_package_metadata() {
        let temp = node_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let analysis = NodeAnalyzer.analyze(&context);
        let summaries: Vec<&str> = analysis
            .observations
            .iter()
            .map(|observation| observation.summary.as_str())
            .collect();
        assert!(
            summaries.iter().any(|summary| summary.contains("demo-app")),
            "{summaries:?}"
        );
        assert!(summaries
            .iter()
            .any(|summary| summary.contains("module system: module")));
        assert!(summaries
            .iter()
            .any(|summary| summary.contains("pnpm@9.0.0")));
        assert!(summaries
            .iter()
            .any(|summary| summary.contains("test script: vitest run")));
        assert!(summaries
            .iter()
            .any(|summary| summary.contains("node >=20")));
        assert!(summaries.iter().any(|summary| summary.contains("private")));
    }

    #[test]
    fn a_credential_in_a_script_is_redacted_in_the_observation() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"name":"x","scripts":{"deploy":"curl -H 'authorization: bearer abcdefghijklmnopqrstuvwxyz'"}}"#,
        )
        .unwrap();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let analysis = NodeAnalyzer.analyze(&context);
        let rendered: String = analysis
            .observations
            .iter()
            .map(|observation| observation.summary.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !rendered.contains("abcdefghijklmnopqrstuvwxyz"),
            "{rendered}"
        );
    }

    #[test]
    fn a_malformed_package_json_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("package.json"), "{ not json").unwrap();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let graph = NodeAnalyzer.dependencies(&context);
        assert_eq!(graph.unparsed_manifests, vec!["package.json".to_string()]);
    }
}
