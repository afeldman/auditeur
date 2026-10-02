//! Go adapter: `go.mod`, `go.sum` and test inventory.
//!
//! `go.mod` is parsed with a small line-oriented reader rather than by running
//! `go mod graph`: parsing is deterministic, needs no toolchain, and cannot
//! modify the module cache or the repository.

use auditeur_model::{Evidence, Language};
use auditeur_repository::discovery::RepositoryModel;

use crate::adapters::{count_matching_lines, detection_from_markers, manifest_key_line};
use crate::{
    AnalysisLevel, Dependency, DependencyGraph, DependencyKind, DependencySource, DetectionResult,
    LanguageAnalysis, LanguageAnalyzer, LanguageContext, Observation, TestInventory,
};

/// Go analysis.
#[derive(Debug, Clone, Copy, Default)]
pub struct GoAnalyzer;

impl GoAnalyzer {
    /// Create the adapter.
    pub const fn new() -> Self {
        Self
    }
}

/// What a parsed `go.mod` declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoModule {
    /// Module path from the `module` directive.
    pub module_path: Option<String>,
    /// Language version from the `go` directive.
    pub go_version: Option<String>,
    /// Toolchain directive, when present.
    pub toolchain: Option<String>,
    /// Required modules, in declaration order.
    pub requires: Vec<GoRequire>,
    /// Whether the module has been declared a main module (no `module` line).
    pub notes: Vec<String>,
}

/// One `require` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoRequire {
    /// Module path.
    pub path: String,
    /// Version as written.
    pub version: String,
    /// Whether the entry is marked `// indirect`.
    pub indirect: bool,
}

/// Parse `go.mod` text.
///
/// Handles both the single-line form (`require example.com/mod v1.2.3`) and the
/// parenthesised block form, which is what `go mod tidy` produces.
pub fn parse_go_mod(text: &str) -> GoModule {
    let mut module = GoModule::default();
    let mut in_require_block = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        if in_require_block {
            if line == ")" {
                in_require_block = false;
                continue;
            }
            if let Some(require) = parse_require_line(line) {
                module.requires.push(require);
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("module ") {
            module.module_path = Some(rest.trim().trim_matches('"').to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("go ") {
            module.go_version = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("toolchain ") {
            module.toolchain = Some(rest.trim().to_string());
            continue;
        }
        if line.starts_with("require (") || line == "require (" {
            in_require_block = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("require ") {
            if let Some(require) = parse_require_line(rest) {
                module.requires.push(require);
            }
            continue;
        }
        if line.starts_with("exclude ")
            || line.starts_with("replace ")
            || line.starts_with("retract ")
        {
            module.notes.push(format!(
                "go.mod directive not resolved: {}",
                first_token(line)
            ));
        }
    }

    if module.module_path.is_none() {
        module
            .notes
            .push("go.mod has no module directive".to_string());
    }
    module
}

fn parse_require_line(line: &str) -> Option<GoRequire> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("//") {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let path = parts.next()?.to_string();
    let version = parts.next().unwrap_or("").to_string();
    let indirect = trimmed.contains("// indirect");
    if path.starts_with("//") {
        return None;
    }
    Some(GoRequire {
        path,
        version,
        indirect,
    })
}

fn first_token(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or(line)
}

impl LanguageAnalyzer for GoAnalyzer {
    fn id(&self) -> Language {
        Language::Go
    }

    fn detect(&self, model: &RepositoryModel) -> DetectionResult {
        let mut markers = Vec::new();
        let mut manifest_found = false;

        for file in model.files_named("go.mod") {
            manifest_found = true;
            markers.push(Evidence::file(
                file.relative_path.clone(),
                "Go module definition (go.mod)",
            ));
        }
        for name in ["go.sum", "go.work"] {
            for file in model.files_named(name) {
                markers.push(Evidence::file(
                    file.relative_path.clone(),
                    format!("Go workspace/lockfile artefact ({name})"),
                ));
            }
        }
        let sources = model.files_with_extension("go");
        if let Some(file) = sources.first() {
            markers.push(Evidence::file(
                file.relative_path.clone(),
                format!("Go source files present: {} .go file(s)", sources.len()),
            ));
        }

        let mut notes = Vec::new();
        if !manifest_found && !sources.is_empty() {
            notes.push("Go sources found without a go.mod".to_string());
        }
        detection_from_markers(
            Language::Go,
            model.files_for_language(Language::Go).len() as u32,
            markers,
            manifest_found,
            notes,
        )
    }

    fn dependencies(&self, context: &LanguageContext<'_>) -> DependencyGraph {
        let model = context.model;
        let mut graph = DependencyGraph {
            lockfile_present: model.has_file_named("go.sum"),
            ..DependencyGraph::default()
        };

        for file in model.files_named("go.mod") {
            let Some(text) = context.read(file) else {
                graph.unparsed_manifests.push(file.relative_path.clone());
                continue;
            };
            let module = parse_go_mod(&text);
            graph.manifests.push(file.relative_path.clone());
            graph.notes.extend(module.notes.iter().cloned());
            for require in module.requires {
                graph.dependencies.push(Dependency {
                    line: manifest_key_line(&text, &require.path),
                    name: require.path,
                    requirement: Some(require.version),
                    // go.mod cannot express development-only dependencies.
                    kind: DependencyKind::Runtime,
                    manifest: file.relative_path.clone(),
                    source: DependencySource::Manifest,
                });
            }
        }

        graph
    }

    fn tests(&self, context: &LanguageContext<'_>) -> TestInventory {
        let model = context.model;
        let mut inventory = TestInventory {
            frameworks: vec!["go test".to_string()],
            ..TestInventory::default()
        };

        let test_files: Vec<_> = model
            .files_with_extension("go")
            .into_iter()
            .filter(|file| file.file_name().ends_with("_test.go"))
            .collect();
        inventory.test_files = test_files
            .iter()
            .map(|file| file.relative_path.clone())
            .collect();

        let (test_functions, _, truncated) =
            count_matching_lines(model, &test_files, context.options.max_read_bytes, |line| {
                let trimmed = line.trim_start();
                trimmed.starts_with("func Test")
                    || trimmed.starts_with("func Benchmark")
                    || trimmed.starts_with("func Fuzz")
            });
        inventory.test_count = Some(test_functions);
        if inventory.test_files.is_empty() {
            inventory.notes.push("no _test.go files found".to_string());
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
        for file in context.model.files_named("go.mod") {
            let Some(text) = context.read(file) else {
                continue;
            };
            let module = parse_go_mod(&text);
            if let Some(path) = &module.module_path {
                observations.push(Observation {
                    summary: format!("Go module `{path}`"),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "module",
                        format!("module {path}"),
                    ),
                });
            }
            if let Some(version) = &module.go_version {
                observations.push(Observation {
                    summary: format!("Go directive declares version {version}"),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "go",
                        format!("go {version}"),
                    ),
                });
            }
            if let Some(toolchain) = &module.toolchain {
                observations.push(Observation {
                    summary: format!("Go toolchain directive: {toolchain}"),
                    evidence: Evidence::config(
                        file.relative_path.clone(),
                        "toolchain",
                        format!("toolchain {toolchain}"),
                    ),
                });
            }
            let indirect = module
                .requires
                .iter()
                .filter(|require| require.indirect)
                .count();
            observations.push(Observation {
                summary: format!(
                    "go.mod declares {} required module(s), {indirect} of them indirect",
                    module.requires.len()
                ),
                evidence: Evidence::file(
                    file.relative_path.clone(),
                    format!("{} require entries", module.requires.len()),
                )
                .with_excerpt(&text),
            });
        }

        LanguageAnalysis {
            language: Language::Go,
            detection,
            level: AnalysisLevel::Deep,
            files: files.len() as u32,
            lines,
            version: None,
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

    fn go_project() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("pkg/service")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module github.com/example/demo\n\ngo 1.22\n\ntoolchain go1.22.1\n\nrequire (\n\tgithub.com/stretchr/testify v1.9.0\n\tgolang.org/x/text v0.14.0 // indirect\n)\n\nrequire github.com/google/uuid v1.6.0\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("go.sum"),
            "github.com/google/uuid v1.6.0 h1:abc=\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("main.go"),
            "package main\n\nfunc main() {}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("pkg/service/service_test.go"),
            "package service\n\nfunc TestService(t *testing.T) {}\n\nfunc BenchmarkService(b *testing.B) {}\n",
        )
        .unwrap();
        temp
    }

    fn context_of(root: &std::path::Path) -> (RepositoryModel, crate::LanguageOptions) {
        let model = discover(root, &DiscoveryOptions::unbounded()).unwrap();
        (model, crate::LanguageOptions::default())
    }

    #[test]
    fn go_mod_parsing_handles_both_forms() {
        let module = parse_go_mod(
            "module example.com/m\n\ngo 1.21\n\nrequire (\n\ta v1.0.0\n\tb v2.0.0 // indirect\n)\n\nrequire c v3.0.0\n",
        );
        assert_eq!(module.module_path.as_deref(), Some("example.com/m"));
        assert_eq!(module.go_version.as_deref(), Some("1.21"));
        assert_eq!(module.requires.len(), 3);
        assert_eq!(module.requires[1].path, "b");
        assert!(module.requires[1].indirect);
        assert!(!module.requires[2].indirect);
    }

    #[test]
    fn a_module_without_a_module_directive_is_noted() {
        let module = parse_go_mod("go 1.21\n");
        assert!(module.module_path.is_none());
        assert!(module
            .notes
            .iter()
            .any(|note| note.contains("no module directive")));
    }

    #[test]
    fn unhandled_directives_are_surfaced_rather_than_ignored() {
        let module = parse_go_mod("module m\n\nreplace a => ../b\n");
        assert!(module.notes.iter().any(|note| note.contains("replace")));
    }

    #[test]
    fn detection_and_dependencies_are_reported() {
        let temp = go_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);

        let detection = GoAnalyzer.detect(&model);
        assert!(detection.detected);
        assert_eq!(detection.confidence, crate::DetectionConfidence::High);

        let graph = GoAnalyzer.dependencies(&context);
        assert!(graph.lockfile_present);
        assert_eq!(graph.len(), 3);
        assert_eq!(
            graph
                .get("github.com/stretchr/testify")
                .unwrap()
                .requirement
                .as_deref(),
            Some("v1.9.0")
        );
        assert_eq!(
            graph.get("github.com/google/uuid").unwrap().kind,
            DependencyKind::Runtime
        );
    }

    #[test]
    fn test_inventory_counts_functions_and_benchmarks() {
        let temp = go_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let inventory = GoAnalyzer.tests(&context);
        assert_eq!(
            inventory.test_files,
            vec!["pkg/service/service_test.go".to_string()]
        );
        assert_eq!(inventory.test_count, Some(2));
        assert_eq!(inventory.frameworks, vec!["go test".to_string()]);
    }

    #[test]
    fn analysis_reports_module_and_toolchain_observations() {
        let temp = go_project();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let analysis = GoAnalyzer.analyze(&context);
        assert_eq!(analysis.level, AnalysisLevel::Deep);
        assert!(analysis
            .observations
            .iter()
            .any(|observation| observation.summary.contains("github.com/example/demo")));
        assert!(analysis
            .observations
            .iter()
            .any(|observation| observation.summary.contains("go1.22.1")));
        assert!(analysis
            .observations
            .iter()
            .any(|observation| observation.summary.contains("indirect")));
    }

    #[test]
    fn a_project_without_tests_says_so() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("go.mod"), "module m\n").unwrap();
        fs::write(temp.path().join("main.go"), "package main\n").unwrap();
        let (model, options) = context_of(temp.path());
        let context = LanguageContext::new(&model, &options);
        let inventory = GoAnalyzer.tests(&context);
        assert!(!inventory.has_tests());
        assert!(inventory
            .notes
            .iter()
            .any(|note| note.contains("no _test.go")));
    }
}
