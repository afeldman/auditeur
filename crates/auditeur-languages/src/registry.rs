//! The adapter registry.
//!
//! One place decides which languages Auditeur understands. The audit engine asks
//! this module; it never matches on a language itself.

use auditeur_model::Language;
use auditeur_repository::discovery::RepositoryModel;

use crate::adapters::{GoAnalyzer, NodeAnalyzer, PythonAnalyzer, RustAnalyzer};
use crate::simple::detection_only_adapters;
use crate::{
    DetectionResult, LanguageAnalysis, LanguageAnalyzer, LanguageContext, LanguageOptions,
};

/// Every adapter, in report order: deep adapters first, then detection-only.
pub fn analyzers() -> Vec<Box<dyn LanguageAnalyzer>> {
    let mut list: Vec<Box<dyn LanguageAnalyzer>> = vec![
        Box::new(RustAnalyzer::new()),
        Box::new(GoAnalyzer::new()),
        Box::new(PythonAnalyzer::new()),
        Box::new(NodeAnalyzer::new()),
    ];
    for adapter in detection_only_adapters() {
        list.push(Box::new(adapter));
    }
    list
}

/// The adapter for one language, if it exists.
pub fn analyzer_for(language: Language) -> Option<Box<dyn LanguageAnalyzer>> {
    analyzers()
        .into_iter()
        .find(|adapter| adapter.id() == language)
}

/// Detection results for every adapter, whether or not the language is present.
pub fn detect_all(model: &RepositoryModel) -> Vec<DetectionResult> {
    analyzers()
        .iter()
        .map(|adapter| adapter.detect(model))
        .collect()
}

/// Languages present in the repository, in report order.
pub fn detected_languages(model: &RepositoryModel) -> Vec<Language> {
    let mut languages: Vec<Language> = detect_all(model)
        .into_iter()
        .filter(|result| result.detected)
        .map(|result| result.language)
        .collect();
    languages.sort();
    languages.dedup();
    languages
}

/// Full analysis for every detected language.
///
/// Absent languages are excluded: a report should not carry eleven sections
/// when the repository contains two languages.
pub fn analyze(model: &RepositoryModel, options: &LanguageOptions) -> Vec<LanguageAnalysis> {
    let context = LanguageContext::new(model, options);
    let mut results: Vec<LanguageAnalysis> = analyzers()
        .iter()
        .map(|adapter| adapter.analyze(&context))
        .filter(|analysis| analysis.detection.detected)
        .collect();
    results.sort_by_key(|analysis| analysis.language);
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_repository::discovery::{discover, DiscoveryOptions};
    use std::fs;

    fn model(root: &std::path::Path) -> RepositoryModel {
        discover(root, &DiscoveryOptions::unbounded()).unwrap()
    }

    #[test]
    fn every_supported_language_has_exactly_one_adapter() {
        let adapters = analyzers();
        for language in Language::ALL {
            let matching = adapters
                .iter()
                .filter(|adapter| adapter.id() == language)
                .count();
            assert_eq!(matching, 1, "{language:?} should have exactly one adapter");
        }
        assert_eq!(adapters.len(), Language::ALL.len());
    }

    #[test]
    fn analyzer_lookup_is_by_language_not_by_position() {
        assert_eq!(analyzer_for(Language::Rust).unwrap().id(), Language::Rust);
        assert_eq!(
            analyzer_for(Language::Terraform).unwrap().id(),
            Language::Terraform
        );
    }

    #[test]
    fn an_empty_directory_detects_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let model = model(temp.path());
        assert!(detected_languages(&model).is_empty());
        assert!(analyze(&model, &LanguageOptions::default()).is_empty());
    }

    #[test]
    fn a_polyglot_repository_reports_each_language_once() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("src.rs"), "fn main() {}\n").unwrap();
        fs::write(temp.path().join("go.mod"), "module m\n").unwrap();
        fs::write(temp.path().join("main.go"), "package main\n").unwrap();
        fs::write(temp.path().join("main.py"), "print('hi')\n").unwrap();
        fs::write(temp.path().join("index.js"), "console.log(1)\n").unwrap();
        fs::write(temp.path().join("main.tf"), "resource \"a\" \"b\" {}\n").unwrap();

        let model = model(temp.path());
        let languages = detected_languages(&model);
        for expected in [
            Language::Rust,
            Language::Go,
            Language::Python,
            Language::NodeJs,
            Language::Terraform,
        ] {
            assert!(
                languages.contains(&expected),
                "missing {expected:?} in {languages:?}"
            );
        }
        assert_eq!(
            languages
                .iter()
                .filter(|language| **language == Language::Rust)
                .count(),
            1
        );

        let analyses = analyze(&model, &LanguageOptions::default());
        assert_eq!(analyses.len(), languages.len());
        let rust = analyses
            .iter()
            .find(|analysis| analysis.language == Language::Rust)
            .unwrap();
        assert_eq!(rust.level, crate::AnalysisLevel::Deep);
        let terraform = analyses
            .iter()
            .find(|analysis| analysis.language == Language::Terraform)
            .unwrap();
        assert_eq!(terraform.level, crate::AnalysisLevel::MetadataOnly);
    }

    #[test]
    fn analysis_order_is_deterministic() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.py"), "x = 1\n").unwrap();
        fs::write(temp.path().join("b.go"), "package main\n").unwrap();
        let model = model(temp.path());
        let first: Vec<Language> = analyze(&model, &LanguageOptions::default())
            .into_iter()
            .map(|analysis| analysis.language)
            .collect();
        let second: Vec<Language> = analyze(&model, &LanguageOptions::default())
            .into_iter()
            .map(|analysis| analysis.language)
            .collect();
        assert_eq!(first, second);
        assert_eq!(first, vec![Language::Go, Language::Python]);
    }
}
