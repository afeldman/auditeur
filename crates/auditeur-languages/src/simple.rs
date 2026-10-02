//! Detection-only adapters.
//!
//! Seven of the eleven supported languages are handled by one configurable
//! adapter that performs detection and file inventory and reports
//! [`AnalysisLevel::MetadataOnly`]. Writing them as seven near-identical types
//! would be duplication without information; writing them as if they had deep
//! analysis would be dishonest.
//!
//! Promotion path: when a language gains manifest parsing, it becomes a
//! dedicated adapter in [`crate::adapters`] and its declaration here is removed.

use auditeur_model::{Evidence, Language};
use auditeur_repository::discovery::RepositoryModel;

use crate::{DetectionConfidence, DetectionResult, LanguageAnalyzer};

/// Maximum number of marker evidence items reported per adapter.
pub const MAX_MARKERS: usize = 8;

/// Something whose presence indicates a language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// An exact file name, anywhere in the tree.
    File(&'static str),
    /// A directory whose final path component matches.
    Directory(&'static str),
    /// A file extension, without the dot.
    Extension(&'static str),
}

impl Marker {
    /// How the marker is described in evidence.
    pub fn describe(self) -> String {
        match self {
            Marker::File(name) => format!("marker file {name}"),
            Marker::Directory(name) => format!("marker directory {name}"),
            Marker::Extension(extension) => format!("source files with extension .{extension}"),
        }
    }
}

/// A language adapter that detects and inventories, but does not analyse.
#[derive(Debug, Clone, Copy)]
pub struct SimpleAdapter {
    language: Language,
    markers: &'static [Marker],
    notes: &'static [&'static str],
}

impl SimpleAdapter {
    /// Declare a detection-only adapter.
    pub const fn new(
        language: Language,
        markers: &'static [Marker],
        notes: &'static [&'static str],
    ) -> Self {
        Self {
            language,
            markers,
            notes,
        }
    }

    /// The markers this adapter looks for.
    pub fn markers(&self) -> &'static [Marker] {
        self.markers
    }
}

impl LanguageAnalyzer for SimpleAdapter {
    fn id(&self) -> Language {
        self.language
    }

    fn detect(&self, model: &RepositoryModel) -> DetectionResult {
        let mut markers: Vec<Evidence> = Vec::new();
        let mut manifest_like_found = false;

        for marker in self.markers {
            match *marker {
                Marker::File(name) => {
                    for file in model.files_named(name) {
                        manifest_like_found = true;
                        markers.push(Evidence::file(
                            file.relative_path.clone(),
                            format!("{} marker: {}", self.language.label(), name),
                        ));
                    }
                }
                Marker::Directory(name) => {
                    for directory in model.dirs() {
                        let last = directory.rsplit('/').next().unwrap_or(directory);
                        if last == name {
                            markers.push(Evidence::directory(
                                directory.clone(),
                                format!("{} marker directory: {}", self.language.label(), name),
                            ));
                            break;
                        }
                    }
                }
                Marker::Extension(extension) => {
                    let files = model.files_with_extension(extension);
                    if let Some(file) = files.first() {
                        markers.push(Evidence::file(
                            file.relative_path.clone(),
                            format!(
                                "{} source files present: {} file(s) with extension .{}",
                                self.language.label(),
                                files.len(),
                                extension
                            ),
                        ));
                    }
                }
            }
        }

        let attributed = model.files_for_language(self.language);
        let file_count = attributed.len() as u32;
        let detected = file_count > 0 || manifest_like_found;

        let mut notes: Vec<String> = self.notes.iter().map(|note| (*note).to_string()).collect();
        if markers.len() > MAX_MARKERS {
            notes.push(format!(
                "{0} markers found; {1} reported as evidence",
                markers.len(),
                MAX_MARKERS
            ));
        }
        markers.truncate(MAX_MARKERS);

        let confidence = if !detected {
            DetectionConfidence::Low
        } else if manifest_like_found || file_count >= 5 {
            DetectionConfidence::High
        } else {
            DetectionConfidence::Medium
        };

        DetectionResult {
            language: self.language,
            detected,
            confidence,
            file_count,
            markers,
            notes,
        }
    }
}

/// The detection-only adapters: everything except Rust, Go, Python and Node.js.
pub fn detection_only_adapters() -> Vec<SimpleAdapter> {
    vec![
        SimpleAdapter::new(
            Language::Deno,
            &[
                Marker::File("deno.json"),
                Marker::File("deno.jsonc"),
                Marker::File("deno.lock"),
                Marker::File("import_map.json"),
                Marker::Extension("ts"),
                Marker::Extension("tsx"),
            ],
            &["Deno projects are often TypeScript; a shared .ts file is not proof of Deno"],
        ),
        SimpleAdapter::new(
            Language::C,
            &[Marker::Extension("c"), Marker::Extension("h")],
            &["C and C++ share header extensions; .h is attributed to C"],
        ),
        SimpleAdapter::new(
            Language::Cpp,
            &[
                Marker::File("CMakeLists.txt"),
                Marker::File("meson.build"),
                Marker::File("Makefile"),
                Marker::File("ninja.build"),
                Marker::Extension("cpp"),
                Marker::Extension("cc"),
                Marker::Extension("hpp"),
            ],
            &["Build systems are detected by marker file; none is executed"],
        ),
        SimpleAdapter::new(
            Language::Julia,
            &[
                Marker::File("Project.toml"),
                Marker::File("Manifest.toml"),
                Marker::Extension("jl"),
            ],
            &["Project.toml is shared with other ecosystems and is not treated as a manifest here"],
        ),
        SimpleAdapter::new(
            Language::R,
            &[
                Marker::File("DESCRIPTION"),
                Marker::File("NAMESPACE"),
                Marker::File("renv.lock"),
                Marker::Extension("r"),
            ],
            &["R package metadata is not parsed in this iteration"],
        ),
        SimpleAdapter::new(
            Language::Lisp,
            &[
                Marker::File("mix.exs"),
                Marker::File("project.clj"),
                Marker::Extension("lisp"),
                Marker::Extension("el"),
                Marker::Extension("clj"),
                Marker::Extension("scm"),
                Marker::Extension("rkt"),
            ],
            &["The Lisp family spans unrelated dialects; only file inventory is reported"],
        ),
        SimpleAdapter::new(
            Language::Terraform,
            &[
                Marker::Extension("tf"),
                Marker::Extension("tfvars"),
                Marker::Extension("hcl"),
                Marker::File(".terraform.lock.hcl"),
            ],
            &["Terraform is validated only by static inspection; no provider is contacted"],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_repository::discovery::{discover, DiscoveryOptions};
    use std::fs;

    fn model(root: &std::path::Path) -> RepositoryModel {
        discover(root, &DiscoveryOptions::unbounded()).unwrap()
    }

    fn adapter_for(language: Language) -> SimpleAdapter {
        detection_only_adapters()
            .into_iter()
            .find(|adapter| adapter.id() == language)
            .expect("adapter should exist")
    }

    #[test]
    fn all_detection_only_languages_are_covered_exactly_once() {
        let adapters = detection_only_adapters();
        let expected = [
            Language::Deno,
            Language::C,
            Language::Cpp,
            Language::Julia,
            Language::R,
            Language::Lisp,
            Language::Terraform,
        ];
        assert_eq!(adapters.len(), expected.len());
        for language in expected {
            assert_eq!(
                adapters
                    .iter()
                    .filter(|adapter| adapter.id() == language)
                    .count(),
                1,
                "{language:?} should have exactly one adapter"
            );
        }
    }

    #[test]
    fn an_absent_language_is_reported_absent() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("README.md"), "# nothing here\n").unwrap();
        let model = model(temp.path());
        let result = adapter_for(Language::Terraform).detect(&model);
        assert!(!result.detected);
        assert_eq!(result.file_count, 0);
        assert!(result.markers.is_empty());
    }

    #[test]
    fn a_manifest_marker_yields_high_confidence_and_evidence() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("infra")).unwrap();
        fs::write(
            temp.path().join("infra/main.tf"),
            "resource \"x\" \"y\" {}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join(".terraform.lock.hcl"),
            "provider \"x\" {}\n",
        )
        .unwrap();
        let model = model(temp.path());
        let result = adapter_for(Language::Terraform).detect(&model);
        assert!(result.detected);
        assert_eq!(result.confidence, DetectionConfidence::High);
        assert!(result.file_count >= 1);
        assert!(!result.markers.is_empty());
        assert!(result
            .markers
            .iter()
            .all(|evidence| evidence.location.path().is_some()));
    }

    #[test]
    fn source_files_without_a_manifest_are_medium_confidence() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("infra")).unwrap();
        fs::write(
            temp.path().join("infra/main.tf"),
            "resource \"x\" \"y\" {}\n",
        )
        .unwrap();
        let model = model(temp.path());
        let result = adapter_for(Language::Terraform).detect(&model);
        assert!(result.detected);
        assert_eq!(result.confidence, DetectionConfidence::Medium);
    }

    #[test]
    fn a_single_source_file_is_medium_confidence() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("main.c"), "int main(void) { return 0; }\n").unwrap();
        let model = model(temp.path());
        let result = adapter_for(Language::C).detect(&model);
        assert!(result.detected);
        assert_eq!(result.confidence, DetectionConfidence::Medium);
        assert_eq!(result.file_count, 1);
    }

    #[test]
    fn detection_only_adapters_never_claim_deep_analysis() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("main.jl"), "println(\"hi\")\n").unwrap();
        let model = model(temp.path());
        let options = crate::LanguageOptions::default();
        let context = crate::LanguageContext::new(&model, &options);
        let analysis = adapter_for(Language::Julia).analyze(&context);
        assert_eq!(analysis.level, crate::AnalysisLevel::MetadataOnly);
        assert_eq!(analysis.lines.lines, 1);
    }

    #[test]
    fn marker_evidence_is_capped() {
        let temp = tempfile::tempdir().unwrap();
        for index in 0..20 {
            fs::write(temp.path().join(format!("mod{index}.tf")), "\n").unwrap();
        }
        let model = model(temp.path());
        let result = adapter_for(Language::Terraform).detect(&model);
        assert!(result.markers.len() <= MAX_MARKERS);
    }
}
