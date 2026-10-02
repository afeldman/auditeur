//! Language adapters.
//!
//! Every language Auditeur understands is an implementation of
//! [`LanguageAnalyzer`]. Nothing above this crate branches on a specific
//! language: the audit engine asks the registry which languages are present and
//! then works with the typed results.
//!
//! Two levels of support exist and are reported as such, never blurred:
//!
//! * [`AnalysisLevel::Deep`] — manifest parsing, dependency extraction and test
//!   inventory (Rust, Go, Python, Node.js in the MVP).
//! * [`AnalysisLevel::MetadataOnly`] — detection and file inventory only. The
//!   adapter states this explicitly so a report cannot imply analysis that did
//!   not happen.
//!
//! Adapters read files through the repository model and never write, execute or
//! fetch anything. Dependency data comes from manifests already present in the
//! repository; no package registry is contacted.

pub mod adapters;
pub mod registry;
pub mod simple;

use serde::{Deserialize, Serialize};

use auditeur_model::{Evidence, Language};
use auditeur_repository::discovery::{RepositoryModel, SourceFile};

/// How much analysis an adapter performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisLevel {
    /// Detection and file inventory only.
    MetadataOnly,
    /// Manifest parsing, dependencies and test inventory.
    Deep,
}

impl AnalysisLevel {
    /// Stable identifier used in manifests and reports.
    pub fn id(self) -> &'static str {
        match self {
            AnalysisLevel::MetadataOnly => "metadata_only",
            AnalysisLevel::Deep => "deep",
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            AnalysisLevel::MetadataOnly => "metadata only",
            AnalysisLevel::Deep => "manifest, dependencies and tests",
        }
    }
}

/// How certain detection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionConfidence {
    /// An extension or weak hint was seen.
    Low,
    /// Source files of the language were found.
    Medium,
    /// A manifest or build file was found, or source files are plentiful.
    High,
}

impl DetectionConfidence {
    /// Stable identifier used in manifests.
    pub fn id(self) -> &'static str {
        match self {
            DetectionConfidence::Low => "low",
            DetectionConfidence::Medium => "medium",
            DetectionConfidence::High => "high",
        }
    }
}

/// Result of asking one adapter whether its language is present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Language the adapter is responsible for.
    pub language: Language,
    /// Whether the language was detected.
    pub detected: bool,
    /// How certain the detection is.
    pub confidence: DetectionConfidence,
    /// Number of files attributed to the language.
    pub file_count: u32,
    /// Evidence for the detection: the markers that were found.
    pub markers: Vec<Evidence>,
    /// Anything the adapter could not determine.
    pub notes: Vec<String>,
}

impl DetectionResult {
    /// A negative result.
    pub fn absent(language: Language) -> Self {
        Self {
            language,
            detected: false,
            confidence: DetectionConfidence::Low,
            file_count: 0,
            markers: Vec::new(),
            notes: Vec::new(),
        }
    }
}

/// Bounds for adapters that read files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageOptions {
    /// Byte budget for reading files to count lines and find markers. A file
    /// beyond the budget is not read; the adapter records that in its notes.
    pub max_read_bytes: u64,
    /// Maximum size of a manifest the adapter will parse.
    pub max_manifest_bytes: u64,
    /// Whether external tools may be executed. The MVP adapters read manifests
    /// only; this flag is carried so that the configuration surface is complete
    /// and diagnosable, and it is reported in the manifest.
    pub run_external_tools: bool,
}

impl Default for LanguageOptions {
    fn default() -> Self {
        Self {
            max_read_bytes: 67_108_864,    // 64 MiB
            max_manifest_bytes: 4_194_304, // 4 MiB
            run_external_tools: false,
        }
    }
}

/// What an adapter is given to work with.
#[derive(Clone, Copy)]
pub struct LanguageContext<'a> {
    /// The repository model produced by discovery.
    pub model: &'a RepositoryModel,
    /// Bounds and switches.
    pub options: &'a LanguageOptions,
}

impl<'a> LanguageContext<'a> {
    /// Create a context.
    pub fn new(model: &'a RepositoryModel, options: &'a LanguageOptions) -> Self {
        Self { model, options }
    }

    /// Text files attributed to `language`.
    pub fn text_files(&self, language: Language) -> Vec<&'a SourceFile> {
        self.model.text_files_for_language(language)
    }

    /// Read a file's text, or `None` if it is too large or unreadable.
    pub fn read(&self, file: &SourceFile) -> Option<String> {
        if file.size > self.options.max_manifest_bytes {
            return None;
        }
        self.model.read_source_text(file).ok()
    }

    /// Read a manifest by path.
    pub fn read_manifest(&self, relative_path: &str) -> Option<String> {
        let file = self.model.file(relative_path)?;
        self.read(file)
    }

    /// Whether a file with this exact name exists anywhere in the model.
    pub fn has_file_named(&self, file_name: &str) -> bool {
        self.model.has_file_named(file_name)
    }

    /// Files with this exact name.
    pub fn files_named(&self, file_name: &str) -> Vec<&'a SourceFile> {
        self.model.files_named(file_name)
    }

    /// Whether a directory exists in the model.
    pub fn has_dir(&self, relative_path: &str) -> bool {
        self.model.has_dir(relative_path)
    }

    /// Find the first line containing `needle` in a file.
    ///
    /// Returns the 1-based line number and the trimmed line, so that evidence
    /// can cite a location a reader can open.
    pub fn find_line(&self, file: &SourceFile, needle: &str) -> Option<(u32, String)> {
        let text = self.read(file)?;
        for (index, line) in text.lines().enumerate() {
            if line.contains(needle) {
                return Some(((index + 1) as u32, line.trim().to_string()));
            }
        }
        None
    }

    /// Read a file as lines, or an empty vector if it cannot be read.
    pub fn lines(&self, file: &SourceFile) -> Vec<String> {
        self.model.read_lines(file).unwrap_or_default()
    }
}

/// Line and size statistics for a set of files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineStats {
    /// Total lines counted.
    pub lines: u64,
    /// Files that were read.
    pub files_read: u32,
    /// Bytes read.
    pub bytes_read: u64,
    /// Whether the read budget stopped the counting early.
    pub truncated: bool,
}

/// Count lines across `files`, respecting a byte budget.
pub fn count_lines(model: &RepositoryModel, files: &[&SourceFile], budget_bytes: u64) -> LineStats {
    let mut stats = LineStats::default();
    for file in files {
        if stats.bytes_read + file.size > budget_bytes {
            stats.truncated = true;
            continue;
        }
        match model.read_source_text(file) {
            Ok(text) => {
                stats.lines += text.lines().count() as u64;
                stats.bytes_read += file.size;
                stats.files_read += 1;
            }
            Err(_) => continue,
        }
    }
    stats
}

/// Kind of dependency, as declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// Required at run time.
    Runtime,
    /// Required for development, testing or documentation.
    Development,
    /// Required to build.
    Build,
    /// Kind not stated by the manifest.
    Unknown,
}

impl DependencyKind {
    /// Stable identifier used in reports.
    pub fn id(self) -> &'static str {
        match self {
            DependencyKind::Runtime => "runtime",
            DependencyKind::Development => "development",
            DependencyKind::Build => "build",
            DependencyKind::Unknown => "unknown",
        }
    }
}

/// Where a dependency was declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencySource {
    /// A manifest file such as `Cargo.toml` or `package.json`.
    Manifest,
    /// A lockfile, i.e. a resolved and pinned version.
    Lockfile,
}

/// A declared dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    /// Package name.
    pub name: String,
    /// Version requirement as written, if any. Not a resolved version.
    pub requirement: Option<String>,
    /// Declared kind.
    pub kind: DependencyKind,
    /// Manifest the declaration came from.
    pub manifest: String,
    /// 1-based line of the declaration, when the format allows locating it.
    pub line: Option<u32>,
    /// Whether this came from a manifest or a lockfile.
    pub source: DependencySource,
}

/// Dependencies declared for one language.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyGraph {
    /// Declared dependencies in manifest order.
    pub dependencies: Vec<Dependency>,
    /// Manifest files that were parsed.
    pub manifests: Vec<String>,
    /// Manifests that exist but could not be parsed.
    pub unparsed_manifests: Vec<String>,
    /// Whether a lockfile is present.
    pub lockfile_present: bool,
    /// Notes about what could not be determined.
    pub notes: Vec<String>,
}

impl DependencyGraph {
    /// Dependencies of a given kind.
    pub fn by_kind(&self, kind: DependencyKind) -> Vec<&Dependency> {
        self.dependencies
            .iter()
            .filter(|dependency| dependency.kind == kind)
            .collect()
    }

    /// Number of declared dependencies.
    pub fn len(&self) -> usize {
        self.dependencies.len()
    }

    /// Whether nothing was declared.
    pub fn is_empty(&self) -> bool {
        self.dependencies.is_empty()
    }

    /// A dependency by name.
    pub fn get(&self, name: &str) -> Option<&Dependency> {
        self.dependencies
            .iter()
            .find(|dependency| dependency.name == name)
    }
}

/// Tests present in the repository.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestInventory {
    /// Test files, relative paths.
    pub test_files: Vec<String>,
    /// Test functions found by scanning, when the adapter counts them.
    pub test_count: Option<u32>,
    /// Frameworks or runners inferred from manifests and configuration.
    pub frameworks: Vec<String>,
    /// Notes about what could not be determined.
    pub notes: Vec<String>,
}

impl TestInventory {
    /// Whether any test file was found.
    pub fn has_tests(&self) -> bool {
        !self.test_files.is_empty()
    }

    /// Number of test files.
    pub fn file_count(&self) -> u32 {
        self.test_files.len() as u32
    }
}

/// A factual observation an adapter wants recorded, with its evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// One-line statement of the observation.
    pub summary: String,
    /// Evidence supporting it.
    pub evidence: Evidence,
}

/// The typed result of analysing one language.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LanguageAnalysis {
    /// Language analysed.
    pub language: Language,
    /// Detection result, including markers.
    pub detection: DetectionResult,
    /// How much analysis was performed.
    pub level: AnalysisLevel,
    /// Number of files attributed to the language.
    pub files: u32,
    /// Line statistics.
    pub lines: LineStats,
    /// Version declared by the language's manifest, when it declares one.
    ///
    /// `None` means "the manifest does not declare a version", which is
    /// different from "we did not look": `level` says how deep the analysis was.
    pub version: Option<String>,
    /// Declared dependencies.
    pub dependencies: DependencyGraph,
    /// Test inventory.
    pub tests: TestInventory,
    /// Additional observations, each with evidence.
    pub observations: Vec<Observation>,
}

impl LanguageAnalysis {
    /// Total evidence produced by this analysis.
    pub fn evidence_count(&self) -> usize {
        self.detection.markers.len() + self.observations.len()
    }

    /// Every piece of evidence produced by this analysis.
    pub fn evidence(&self) -> Vec<&Evidence> {
        self.detection
            .markers
            .iter()
            .chain(
                self.observations
                    .iter()
                    .map(|observation| &observation.evidence),
            )
            .collect()
    }
}

/// One language adapter.
pub trait LanguageAnalyzer: Send + Sync {
    /// Language this adapter handles.
    fn id(&self) -> Language;

    /// Whether the language is present, and the markers that show it.
    fn detect(&self, model: &RepositoryModel) -> DetectionResult;

    /// Files attributed to the language.
    fn files<'a>(&self, model: &'a RepositoryModel) -> Vec<&'a SourceFile> {
        model.files_for_language(self.id())
    }

    /// Declared dependencies.
    fn dependencies(&self, _context: &LanguageContext<'_>) -> DependencyGraph {
        DependencyGraph::default()
    }

    /// Tests present.
    fn tests(&self, _context: &LanguageContext<'_>) -> TestInventory {
        TestInventory::default()
    }

    /// Full analysis. The default implementation is metadata-only and honest
    /// about it; deep adapters override it.
    fn analyze(&self, context: &LanguageContext<'_>) -> LanguageAnalysis {
        let detection = self.detect(context.model);
        let files = self.files(context.model);
        let line_stats = count_lines(context.model, &files, context.options.max_read_bytes);
        LanguageAnalysis {
            language: self.id(),
            detection,
            level: AnalysisLevel::MetadataOnly,
            files: files.len() as u32,
            lines: line_stats,
            version: None,
            dependencies: self.dependencies(context),
            tests: self.tests(context),
            observations: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_levels_are_distinguishable() {
        assert_eq!(AnalysisLevel::Deep.id(), "deep");
        assert_eq!(AnalysisLevel::MetadataOnly.id(), "metadata_only");
        assert_ne!(
            AnalysisLevel::Deep.label(),
            AnalysisLevel::MetadataOnly.label()
        );
    }

    #[test]
    fn dependency_graph_queries_are_consistent() {
        let graph = DependencyGraph {
            dependencies: vec![
                Dependency {
                    name: "serde".to_string(),
                    requirement: Some("1".to_string()),
                    kind: DependencyKind::Runtime,
                    manifest: "Cargo.toml".to_string(),
                    line: Some(12),
                    source: DependencySource::Manifest,
                },
                Dependency {
                    name: "tempfile".to_string(),
                    requirement: Some("3".to_string()),
                    kind: DependencyKind::Development,
                    manifest: "Cargo.toml".to_string(),
                    line: Some(15),
                    source: DependencySource::Manifest,
                },
            ],
            manifests: vec!["Cargo.toml".to_string()],
            unparsed_manifests: Vec::new(),
            lockfile_present: true,
            notes: Vec::new(),
        };
        assert_eq!(graph.len(), 2);
        assert!(!graph.is_empty());
        assert_eq!(graph.by_kind(DependencyKind::Runtime).len(), 1);
        assert!(graph.get("serde").is_some());
        assert!(graph.get("missing").is_none());
    }
}
