//! Python adapter: `pyproject.toml`, requirements files and test inventory.
//!
//! Dependency data comes from files already in the repository. No index is
//! contacted, and no environment manager (`uv`, `pip`, `poetry`) is executed:
//! running one could write into the repository, which the read-only guarantee
//! forbids.

use auditeur_model::{Evidence, Language};
use auditeur_repository::discovery::RepositoryModel;

use crate::adapters::{
    count_matching_lines, detection_from_markers, manifest_key_line, toml_table_at,
};
use crate::{
    AnalysisLevel, Dependency, DependencyGraph, DependencyKind, DependencySource, DetectionResult,
    LanguageAnalysis, LanguageAnalyzer, LanguageContext, Observation, TestInventory,
};

/// Python analysis.
#[derive(Debug, Clone, Copy, Default)]
pub struct PythonAnalyzer;

impl PythonAnalyzer {
    /// Create the adapter.
    pub const fn new() -> Self {
        Self
    }
}

/// Parse one PEP 508 style requirement line.
///
/// Returns the distribution name and the version requirement as written.
/// Returns `None` for blank lines, comments and pip options (`-r`, `-e`, `--`).
pub fn parse_requirement(line: &str) -> Option<(String, Option<String>)> {
    let without_comment = match line.split_once(" #") {
        Some((before, _)) => before,
        None => line,
    };
    let trimmed = without_comment.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
        return None;
    }

    // The name ends at the first character that cannot appear in a distribution
    // name: extra markers, version specifiers, environment markers, direct URLs.
    let boundary = trimmed
        .char_indices()
        .find(|(_, character)| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
        })
        .map(|(index, _)| index)
        .unwrap_or(trimmed.len());

    let name = trimmed[..boundary].trim().to_string();
    if name.is_empty() {
        return None;
    }
    let rest = trimmed[boundary..].trim();
    let requirement = if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    };
    Some((name, requirement))
}

impl LanguageAnalyzer for PythonAnalyzer {
    fn id(&self) -> Language {
        Language::Python
    }

    fn detect(&self, model: &RepositoryModel) -> DetectionResult {
        let mut markers = Vec::new();
        let mut manifest_found = false;

        for name in [
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "Pipfile",
            "uv.lock",
            "poetry.lock",
            "tox.ini",
        ] {
            for file in model.files_named(name) {
                manifest_found = true;
                markers.push(Evidence::file(
                    file.relative_path.clone(),
                    format!("Python project artefact ({name})"),
                ));
            }
        }
        for file in requirements_files(model) {
            manifest_found = true;
            markers.push(Evidence::file(
                file.relative_path.clone(),
                "Python requirements file",
            ));
        }
        let sources = model.files_with_extension("py");
        if let Some(file) = sources.first() {
            markers.push(Evidence::file(
                file.relative_path.clone(),
                format!("Python source files present: {} .py file(s)", sources.len()),
            ));
        }

        let mut notes = Vec::new();
        if !manifest_found && !sources.is_empty() {
            notes.push("Python sources found without a manifest or requirements file".to_string());
        }
        detection_from_markers(
            Language::Python,
            model.files_for_language(Language::Python).len() as u32,
            markers,
            manifest_found,
            notes,
        )
    }

    fn dependencies(&self, context: &LanguageContext<'_>) -> DependencyGraph {
        let model = context.model;
        let mut graph = DependencyGraph {
            lockfile_present: model.has_file_named("uv.lock")
                || model.has_file_named("poetry.lock"),
            ..DependencyGraph::default()
        };

        for file in model.files_named("pyproject.toml") {
            let Some(text) = context.read(file) else {
                graph.unparsed_manifests.push(file.relative_path.clone());
                continue;
            };
            let Ok(value) = text.parse::<toml::Value>() else {
                graph.unparsed_manifests.push(file.relative_path.clone());
                continue;
            };
            graph.manifests.push(file.relative_path.clone());

            // PEP 621: [project] dependencies and optional dependency groups.
            if let Some(list) =
                toml_table_at(&value, &["project", "dependencies"]).and_then(toml::Value::as_array)
            {
                for entry in list.iter().filter_map(toml::Value::as_str) {
                    if let Some((name, requirement)) = parse_requirement(entry) {
                        graph.dependencies.push(Dependency {
                            line: manifest_key_line(&text, &name),
                            name,
                            requirement,
                            kind: DependencyKind::Runtime,
                            manifest: file.relative_path.clone(),
                            source: DependencySource::Manifest,
                        });
                    }
                }
            }
            if let Some(groups) = toml_table_at(&value, &["project", "optional-dependencies"])
                .and_then(toml::Value::as_table)
            {
                for (group, entries) in groups {
                    let Some(entries) = entries.as_array() else {
                        continue;
                    };
                    for entry in entries.iter().filter_map(toml::Value::as_str) {
                        if let Some((name, requirement)) = parse_requirement(entry) {
                            graph.dependencies.push(Dependency {
                                line: manifest_key_line(&text, &name),
                                name,
                                requirement,
                                kind: DependencyKind::Development,
                                manifest: format!("{}#extra:{}", file.relative_path, group),
                                source: DependencySource::Manifest,
                            });
                        }
                    }
                }
            }
            // PEP 735 dependency groups.
            if let Some(groups) = value
                .get("dependency-groups")
                .and_then(toml::Value::as_table)
            {
                for (group, entries) in groups {
                    let Some(entries) = entries.as_array() else {
                        continue;
                    };
                    for entry in entries.iter().filter_map(toml::Value::as_str) {
                        if let Some((name, requirement)) = parse_requirement(entry) {
                            graph.dependencies.push(Dependency {
                                line: manifest_key_line(&text, &name),
                                name,
                                requirement,
                                kind: DependencyKind::Development,
                                manifest: format!("{}#group:{}", file.relative_path, group),
                                source: DependencySource::Manifest,
                            });
                        }
                    }
                }
            }
            // Poetry layout.
            if let Some(table) = toml_table_at(&value, &["tool", "poetry", "dependencies"])
                .and_then(toml::Value::as_table)
            {
                for (name, spec) in table {
                    if name.eq_ignore_ascii_case("python") {
                        continue;
                    }
                    let requirement = match spec {
                        toml::Value::String(version) => Some(version.clone()),
                        toml::Value::Table(table) => table
                            .get("version")
                            .and_then(toml::Value::as_str)
                            .map(str::to_string),
                        _ => None,
                    };
                    graph.dependencies.push(Dependency {
                        line: manifest_key_line(&text, name),
                        name: name.clone(),
                        requirement,
                        kind: DependencyKind::Runtime,
                        manifest: file.relative_path.clone(),
                        source: DependencySource::Manifest,
                    });
                }
            }
            if let Some(table) =
                toml_table_at(&value, &["tool", "poetry", "group"]).and_then(toml::Value::as_table)
            {
                for (group, group_value) in table {
                    let Some(deps) = group_value
                        .get("dependencies")
                        .and_then(toml::Value::as_table)
                    else {
                        continue;
                    };
                    for (name, spec) in deps {
                        let requirement = match spec {
                            toml::Value::String(version) => Some(version.clone()),
                            toml::Value::Table(table) => table
                                .get("version")
                                .and_then(toml::Value::as_str)
                                .map(str::to_string),
                            _ => None,
                        };
                        graph.dependencies.push(Dependency {
                            line: manifest_key_line(&text, name),
                            name: name.clone(),
                            requirement,
                            kind: DependencyKind::Development,
                            manifest: format!("{}#group:{}", file.relative_path, group),
                            source: DependencySource::Manifest,
                        });
                    }
                }
            }
            // Build backend requirements.
            if let Some(entries) =
                toml_table_at(&value, &["build-system", "requires"]).and_then(toml::Value::as_array)
            {
                for entry in entries.iter().filter_map(toml::Value::as_str) {
                    if let Some((name, requirement)) = parse_requirement(entry) {
                        graph.dependencies.push(Dependency {
                            line: manifest_key_line(&text, &name),
                            name,
                            requirement,
                            kind: DependencyKind::Build,
                            manifest: file.relative_path.clone(),
                            source: DependencySource::Manifest,
                        });
                    }
                }
            }
        }

        for file in requirements_files(model) {
            let Some(text) = context.read(file) else {
                graph.unparsed_manifests.push(file.relative_path.clone());
                continue;
            };
            graph.manifests.push(file.relative_path.clone());
            let development = file.file_name().to_ascii_lowercase().contains("dev");
            for (index, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("-r") || line.trim_start().starts_with("--") {
                    graph.notes.push(format!(
                        "{}:{}: pip option not resolved",
                        file.relative_path,
                        index + 1
                    ));
                    continue;
                }
                if let Some((name, requirement)) = parse_requirement(line) {
                    graph.dependencies.push(Dependency {
                        line: Some((index + 1) as u32),
                        name,
                        requirement,
                        kind: if development {
                            DependencyKind::Development
                        } else {
                            DependencyKind::Runtime
                        },
                        manifest: file.relative_path.clone(),
                        source: DependencySource::Manifest,
                    });
                }
            }
        }

        graph
    }

    fn tests(&self, context: &LanguageContext<'_>) -> TestInventory {
        let model = context.model;
        let mut inventory = TestInventory::default();

        let sources: Vec<_> = model
            .files_with_extension("py")
            .into_iter()
            .filter(|file| {
                let name = file.file_name();
                name.starts_with("test_")
                    || name.ends_with("_test.py")
                    || name == "conftest.py"
                    || file.relative_path.starts_with("tests/")
            })
            .collect();
        inventory.test_files = sources
            .iter()
            .map(|file| file.relative_path.clone())
            .collect();

        let (test_functions, _, truncated) =
            count_matching_lines(model, &sources, context.options.max_read_bytes, |line| {
                let trimmed = line.trim_start();
                trimmed.starts_with("def test_") || trimmed.starts_with("async def test_")
            });
        inventory.test_count = Some(test_functions);

        let graph = self.dependencies(context);
        if graph.get("pytest").is_some() || model.has_file_named("conftest.py") {
            inventory.frameworks.push("pytest".to_string());
        }
        if graph.get("nose").is_some() {
            inventory.frameworks.push("nose".to_string());
        }
        let (unittest_uses, _, _) =
            count_matching_lines(model, &sources, context.options.max_read_bytes, |line| {
                line.trim_start().starts_with("import unittest")
            });
        if unittest_uses > 0 {
            inventory.frameworks.push("unittest".to_string());
        }
        if inventory.test_files.is_empty() {
            inventory
                .notes
                .push("no test files matching test_*.py or *_test.py found".to_string());
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
        for file in context.model.files_named("pyproject.toml") {
            let Some(text) = context.read(file) else {
                continue;
            };
            let Ok(value) = text.parse::<toml::Value>() else {
                continue;
            };
            let project = toml_table_at(&value, &["project"]);
            let name = project
                .and_then(|project| project.get("name"))
                .and_then(toml::Value::as_str);
            let version = project
                .and_then(|project| project.get("version"))
                .and_then(toml::Value::as_str);
            if declared_version.is_none() {
                declared_version = version.map(str::to_string).or_else(|| {
                    toml_table_at(&value, &["tool", "poetry", "version"])
                        .and_then(toml::Value::as_str)
                        .map(str::to_string)
                });
            }
            if let Some(name) = name {
                observations.push(Observation {
                    summary: format!(
                        "Python distribution `{name}`{}",
                        version
                            .map(|version| format!(" version {version}"))
                            .unwrap_or_default()
                    ),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "project.name",
                        format!("project name `{name}`"),
                    ),
                });
            }
            if let Some(requires) = project
                .and_then(|project| project.get("requires-python"))
                .and_then(toml::Value::as_str)
            {
                observations.push(Observation {
                    summary: format!("requires Python {requires}"),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "project.requires-python",
                        format!("requires-python = {requires}"),
                    ),
                });
            }
            if let Some(backend) = toml_table_at(&value, &["build-system", "build-backend"])
                .and_then(toml::Value::as_str)
            {
                observations.push(Observation {
                    summary: format!("build backend: {backend}"),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "build-system.build-backend",
                        format!("build-backend = {backend}"),
                    ),
                });
            }
        }

        for (tool, config) in [
            ("ruff", "tool.ruff"),
            ("mypy", "tool.mypy"),
            ("pytest", "tool.pytest.ini_options"),
            ("coverage", "tool.coverage"),
        ] {
            for file in context.model.files_named("pyproject.toml") {
                let Some(text) = context.read(file) else {
                    continue;
                };
                let Ok(value) = text.parse::<toml::Value>() else {
                    continue;
                };
                let path: Vec<&str> = config.split('.').collect();
                if toml_table_at(&value, &path).is_some() {
                    observations.push(Observation {
                        summary: format!("{tool} configured in pyproject.toml"),
                        evidence: Evidence::config(
                            file.relative_path.clone(),
                            config,
                            format!("{tool} configuration present"),
                        ),
                    });
                }
            }
        }

        for file in context.model.files_named("uv.lock") {
            observations.push(Observation {
                summary: "uv lockfile present".to_string(),
                evidence: Evidence::file(
                    file.relative_path.clone(),
                    "uv.lock pins the resolved environment".to_string(),
                ),
            });
        }

        LanguageAnalysis {
            language: Language::Python,
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

/// Requirement files: `requirements.txt`, `requirements-dev.txt`, and friends.
fn requirements_files(model: &RepositoryModel) -> Vec<&auditeur_repository::discovery::SourceFile> {
    model
        .files()
        .iter()
        .filter(|file| {
            let name = file.file_name().to_ascii_lowercase();
            (name.starts_with("requirements") || name.starts_with("constraints"))
                && name.ends_with(".txt")
        })
        .collect()
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

    #[test]
    fn requirements_are_parsed_with_name_and_specifier() {
        assert_eq!(
            parse_requirement("requests>=2.31.0"),
            Some(("requests".to_string(), Some(">=2.31.0".to_string())))
        );
        assert_eq!(
            parse_requirement("flask"),
            Some(("flask".to_string(), None))
        );
        assert_eq!(
            parse_requirement("uvicorn[standard]==0.29.0  # server"),
            Some((
                "uvicorn".to_string(),
                Some("[standard]==0.29.0".to_string())
            ))
        );
        assert_eq!(parse_requirement("# comment"), None);
        assert_eq!(parse_requirement("-r other.txt"), None);
        assert_eq!(parse_requirement(""), None);
    }

    fn python_project() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/demo")).unwrap();
        fs::create_dir_all(temp.path().join("tests")).unwrap();
        fs::write(
            temp.path().join("pyproject.toml"),
            r#"[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "demo"
version = "2.1.0"
requires-python = ">=3.10"
dependencies = ["requests>=2.31", "click"]

[project.optional-dependencies]
dev = ["pytest>=8", "ruff"]

[dependency-groups]
docs = ["mkdocs"]

[tool.ruff]
line-length = 100

[tool.pytest.ini_options]
addopts = "-q"
"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("requirements-dev.txt"),
            "bandit\nmypy==1.8.0\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/demo/__init__.py"),
            "VERSION = '2.1.0'\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("tests/test_demo.py"),
            "import unittest\n\n\ndef test_ok():\n    assert True\n\n\nasync def test_async():\n    assert True\n",
        )
        .unwrap();
        fs::write(temp.path().join("uv.lock"), "version = 1\n").unwrap();
        temp
    }

    #[test]
    fn detection_uses_manifests_and_sources() {
        let temp = python_project();
        let (model, _) = context_of(temp.path());
        let detection = PythonAnalyzer.detect(&model);
        assert!(detection.detected);
        assert_eq!(detection.confidence, crate::DetectionConfidence::High);
        assert!(!detection.markers.is_empty());
    }

    #[test]
    fn dependencies_cover_all_declaration_styles() {
        let temp = python_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let graph = PythonAnalyzer.dependencies(&context);

        assert_eq!(
            graph.get("requests").unwrap().requirement.as_deref(),
            Some(">=2.31")
        );
        assert_eq!(graph.get("requests").unwrap().kind, DependencyKind::Runtime);
        assert_eq!(
            graph.get("pytest").unwrap().kind,
            DependencyKind::Development
        );
        assert_eq!(graph.get("hatchling").unwrap().kind, DependencyKind::Build);
        assert_eq!(
            graph.get("mkdocs").unwrap().kind,
            DependencyKind::Development
        );
        assert_eq!(
            graph.get("bandit").unwrap().kind,
            DependencyKind::Development
        );
        assert_eq!(
            graph.get("mypy").unwrap().requirement.as_deref(),
            Some("==1.8.0")
        );
        assert!(graph.lockfile_present);
        assert!(graph.notes.is_empty(), "{:?}", graph.notes);
    }

    #[test]
    fn test_inventory_detects_frameworks_and_counts_tests() {
        let temp = python_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let inventory = PythonAnalyzer.tests(&context);
        assert!(inventory.has_tests());
        assert!(inventory.frameworks.contains(&"pytest".to_string()));
        assert!(inventory.frameworks.contains(&"unittest".to_string()));
        assert_eq!(inventory.test_count, Some(2));
    }

    #[test]
    fn observations_record_project_metadata_and_tooling() {
        let temp = python_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let analysis = PythonAnalyzer.analyze(&context);
        let summaries: Vec<&str> = analysis
            .observations
            .iter()
            .map(|observation| observation.summary.as_str())
            .collect();
        assert!(
            summaries.iter().any(|summary| summary.contains("demo")),
            "{summaries:?}"
        );
        assert!(summaries
            .iter()
            .any(|summary| summary.contains("requires Python >=3.10")));
        assert!(summaries
            .iter()
            .any(|summary| summary.contains("hatchling")));
        assert!(summaries
            .iter()
            .any(|summary| summary.contains("ruff configured")));
        assert!(summaries
            .iter()
            .any(|summary| summary.contains("uv lockfile")));
    }

    #[test]
    fn pip_options_are_noted_rather_than_dropped_silently() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("requirements.txt"),
            "requests\n-r other.txt\n--index-url https://example.com\n",
        )
        .unwrap();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let graph = PythonAnalyzer.dependencies(&context);
        assert_eq!(graph.get("requests").unwrap().requirement, None);
        assert_eq!(graph.notes.len(), 2, "{:?}", graph.notes);
    }
}
