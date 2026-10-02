//! Repository discovery: build a bounded, deterministic inventory of the tree.
//!
//! Deliberately hand-written rather than delegated to a walker crate. The
//! traversal is where the resource bounds, the symlink policy, the ignore lists
//! and the skip accounting meet; owning that logic directly makes each limit
//! auditable and keeps the ordering canonical (sorted, depth-ordered).
//!
//! Never writes. The only mutation this module performs is to the in-memory
//! model.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use auditeur_model::{Language, SkipReason, SkipRecord};

use crate::classify::{classify_file, language_for_path, FileKind};
use crate::error::RepositoryError;
use crate::guard::{to_slash_path, PathGuard};

/// Default per-file size limit, in bytes (1 MiB).
///
/// Duplicated from the configuration defaults on purpose: the repository
/// boundary must be usable without depending on the configuration crate, and
/// the audit crate maps configuration onto these options explicitly.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 1_048_576;
/// Default maximum number of files in the repository model.
pub const DEFAULT_MAX_FILES: u32 = 20_000;
/// Default total-bytes limit (512 MiB).
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 536_870_912;
/// Default maximum directory depth.
pub const DEFAULT_MAX_DEPTH: usize = 24;

/// Bounds applied during discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryOptions {
    /// Maximum size of a single inspected file.
    pub max_file_bytes: u64,
    /// Maximum number of files in the model.
    pub max_files: u32,
    /// Maximum total size of inspected files.
    pub max_total_bytes: u64,
    /// Maximum directory depth below the root.
    pub max_depth: usize,
    /// Whether directory symlinks are followed. Off by default: a symlink is a
    /// way out of the repository.
    pub follow_symlinks: bool,
    /// Directory names excluded from discovery.
    pub ignore_dirs: Vec<String>,
    /// File names excluded from discovery.
    pub ignore_files: Vec<String>,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_files: DEFAULT_MAX_FILES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
            follow_symlinks: false,
            ignore_dirs: Vec::new(),
            ignore_files: Vec::new(),
        }
    }
}

impl DiscoveryOptions {
    /// Whether a directory name is excluded.
    pub fn ignores_dir(&self, name: &str) -> bool {
        self.ignore_dirs.iter().any(|ignored| ignored == name)
    }

    /// Whether a file name is excluded.
    pub fn ignores_file(&self, name: &str) -> bool {
        self.ignore_files.iter().any(|ignored| ignored == name)
    }

    /// Unbounded options, for tests that need the whole tree.
    pub fn unbounded() -> Self {
        Self {
            max_file_bytes: u64::MAX,
            max_files: u32::MAX,
            max_total_bytes: u64::MAX,
            max_depth: usize::MAX,
            follow_symlinks: false,
            ignore_dirs: Vec::new(),
            ignore_files: Vec::new(),
        }
    }
}

/// One file in the repository model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFile {
    /// Repository-relative, slash-separated path.
    pub relative_path: String,
    /// Size in bytes at discovery time.
    pub size: u64,
    /// Whether the content is text or binary.
    pub kind: FileKind,
    /// Language inferred from the file name, if any.
    pub language: Option<Language>,
    /// Lower-case extension, without the dot, if any.
    pub extension: Option<String>,
}

impl SourceFile {
    /// Final path component.
    pub fn file_name(&self) -> &str {
        self.relative_path
            .rsplit('/')
            .next()
            .unwrap_or(&self.relative_path)
    }

    /// Whether line-level analysis is meaningful.
    pub fn is_text(&self) -> bool {
        self.kind.is_text()
    }

    /// Whether a language was inferred.
    pub fn matches_language(&self, language: Language) -> bool {
        self.language == Some(language)
    }
}

/// The audited repository, as observed at discovery time.
#[derive(Debug, Clone)]
pub struct RepositoryModel {
    guard: PathGuard,
    name: String,
    files: Vec<SourceFile>,
    dirs: Vec<String>,
    skipped: Vec<SkipRecord>,
    total_bytes: u64,
    truncated: bool,
    max_file_bytes: u64,
}

impl RepositoryModel {
    /// Canonical repository root.
    pub fn root(&self) -> &Path {
        self.guard.root()
    }

    /// Path guard for this repository.
    pub fn guard(&self) -> &PathGuard {
        &self.guard
    }

    /// Directory name of the root, used for the report path.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// All inspected files, in canonical order.
    pub fn files(&self) -> &[SourceFile] {
        &self.files
    }

    /// All inspected directories, relative and slash-separated.
    pub fn dirs(&self) -> &[String] {
        &self.dirs
    }

    /// Paths excluded from inspection, with reasons.
    pub fn skipped(&self) -> &[SkipRecord] {
        &self.skipped
    }

    /// Total bytes of inspected files.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Whether a configured limit cut discovery short.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Number of inspected files.
    pub fn file_count(&self) -> u32 {
        self.files.len() as u32
    }

    /// Look up an inspected file.
    pub fn file(&self, relative_path: &str) -> Option<&SourceFile> {
        self.files
            .iter()
            .find(|file| file.relative_path == relative_path)
    }

    /// Whether a relative path is an inspected file.
    pub fn has_file(&self, relative_path: &str) -> bool {
        self.file(relative_path).is_some()
    }

    /// Whether a relative path is an inspected directory.
    pub fn has_dir(&self, relative_path: &str) -> bool {
        self.dirs.iter().any(|dir| dir == relative_path)
    }

    /// Whether an exact file name exists anywhere in the tree.
    pub fn has_file_named(&self, file_name: &str) -> bool {
        self.files.iter().any(|file| file.file_name() == file_name)
    }

    /// Files whose final path component equals `file_name`.
    pub fn files_named(&self, file_name: &str) -> Vec<&SourceFile> {
        self.files
            .iter()
            .filter(|file| file.file_name() == file_name)
            .collect()
    }

    /// Files with the given lower-case extension.
    pub fn files_with_extension(&self, extension: &str) -> Vec<&SourceFile> {
        let lowered = extension.to_ascii_lowercase();
        self.files
            .iter()
            .filter(|file| file.extension.as_deref() == Some(lowered.as_str()))
            .collect()
    }

    /// Files inferred to belong to `language`.
    pub fn files_for_language(&self, language: Language) -> Vec<&SourceFile> {
        self.files
            .iter()
            .filter(|file| file.matches_language(language))
            .collect()
    }

    /// Text files inferred to belong to `language`.
    pub fn text_files_for_language(&self, language: Language) -> Vec<&SourceFile> {
        self.files_for_language(language)
            .into_iter()
            .filter(|file| file.is_text())
            .collect()
    }

    /// Files under a directory prefix.
    pub fn files_under(&self, prefix: &str) -> Vec<&SourceFile> {
        let prefix = prefix.trim_end_matches('/');
        self.files
            .iter()
            .filter(|file| file.relative_path.starts_with(prefix))
            .collect()
    }

    /// Count of inspected files per detected language.
    pub fn language_counts(&self) -> BTreeMap<Language, u32> {
        let mut counts = BTreeMap::new();
        for file in &self.files {
            if let Some(language) = file.language {
                *counts.entry(language).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Read a text file from the repository, with the size limit enforced
    /// again at read time (the file may have grown since discovery).
    ///
    /// Non-UTF-8 content is decoded lossily rather than rejected: source files
    /// in legacy encodings still deserve analysis, and the lossy conversion is
    /// recorded by the caller as an observation if it matters.
    pub fn read_text(&self, relative_path: &str) -> Result<String, RepositoryError> {
        let file = self
            .file(relative_path)
            .ok_or_else(|| RepositoryError::UnknownPath(relative_path.to_string()))?
            .clone();
        self.read_source_text(&file)
    }

    /// Read an inspected file's text.
    pub fn read_source_text(&self, file: &SourceFile) -> Result<String, RepositoryError> {
        let path = self.guard.resolve_relative(&file.relative_path)?;
        let bytes = fs::read(&path).map_err(|source| RepositoryError::Read {
            path: path.clone(),
            source,
        })?;
        if bytes.len() as u64 > self.max_file_bytes {
            return Err(RepositoryError::TooLarge {
                path,
                size: bytes.len() as u64,
                limit: self.max_file_bytes,
            });
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Read an inspected file as lines, without trailing line terminators.
    pub fn read_lines(&self, file: &SourceFile) -> Result<Vec<String>, RepositoryError> {
        Ok(self
            .read_source_text(file)?
            .lines()
            .map(|line| line.trim_end_matches('\r').to_string())
            .collect())
    }

    /// Count the lines of an inspected text file.
    pub fn line_count(&self, file: &SourceFile) -> Result<u32, RepositoryError> {
        Ok(self.read_source_text(file)?.lines().count() as u32)
    }

    /// The configured per-file size limit.
    pub fn max_file_bytes(&self) -> u64 {
        self.max_file_bytes
    }
}

/// Build the repository model for `root`.
pub fn discover(
    root: &Path,
    options: &DiscoveryOptions,
) -> Result<RepositoryModel, RepositoryError> {
    let guard = PathGuard::new(root)?;
    let canonical_root = guard.root().to_path_buf();
    let name = canonical_root
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "repository".to_string());

    let mut files: Vec<SourceFile> = Vec::new();
    let mut dirs: Vec<String> = Vec::new();
    let mut skipped: Vec<SkipRecord> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut truncated = false;

    // Iterative depth-first traversal with an explicit stack: no recursion
    // depth limit, and pruning decisions are made exactly once per entry.
    let mut stack: Vec<(PathBuf, usize)> = vec![(canonical_root.clone(), 0)];
    let mut visited_dirs: HashSet<PathBuf> = HashSet::new();
    visited_dirs.insert(canonical_root.clone());

    while let Some((directory, depth)) = stack.pop() {
        let absolute = if directory == canonical_root {
            canonical_root.clone()
        } else {
            guard.resolve_existing(&directory)?
        };

        let read_dir = match fs::read_dir(&absolute) {
            Ok(entries) => entries,
            Err(error) => {
                skipped.push(relative_skip(
                    &guard,
                    &absolute,
                    SkipReason::Unreadable,
                    Some(error.to_string()),
                ));
                continue;
            }
        };

        let mut entries: Vec<PathBuf> = Vec::new();
        for entry in read_dir {
            match entry {
                Ok(entry) => entries.push(entry.path()),
                Err(error) => skipped.push(relative_skip(
                    &guard,
                    &absolute,
                    SkipReason::Unreadable,
                    Some(error.to_string()),
                )),
            }
        }
        entries.sort();

        for path in entries {
            let file_name = path
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_default();

            let symlink_metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    skipped.push(relative_skip(
                        &guard,
                        &path,
                        SkipReason::Unreadable,
                        Some(error.to_string()),
                    ));
                    continue;
                }
            };
            let file_type = symlink_metadata.file_type();

            if file_type.is_symlink() {
                if !options.follow_symlinks {
                    skipped.push(relative_skip(&guard, &path, SkipReason::Symlink, None));
                    continue;
                }
                // Opt-in: resolve the link and require it to stay inside the
                // repository. Anything else is refused, not silently followed.
                match guard.resolve_existing(&path) {
                    Ok(resolved) => {
                        let metadata = match fs::metadata(&resolved) {
                            Ok(metadata) => metadata,
                            Err(error) => {
                                skipped.push(relative_skip(
                                    &guard,
                                    &path,
                                    SkipReason::Unreadable,
                                    Some(error.to_string()),
                                ));
                                continue;
                            }
                        };
                        if metadata.is_dir() {
                            if options.ignores_dir(&file_name) {
                                skipped.push(relative_skip(
                                    &guard,
                                    &path,
                                    SkipReason::IgnoredDirectory,
                                    None,
                                ));
                                continue;
                            }
                            if depth + 1 > options.max_depth {
                                skipped.push(relative_skip(
                                    &guard,
                                    &path,
                                    SkipReason::DepthExceeded,
                                    None,
                                ));
                                continue;
                            }
                            if !visited_dirs.insert(resolved.clone()) {
                                skipped.push(relative_skip(
                                    &guard,
                                    &path,
                                    SkipReason::Symlink,
                                    Some("already visited; symlink cycle".to_string()),
                                ));
                                continue;
                            }
                            let relative =
                                guard.relative(&path).unwrap_or_else(|| file_name.clone());
                            dirs.push(relative);
                            stack.push((resolved, depth + 1));
                            continue;
                        }
                        visit_file(
                            &guard,
                            &path,
                            &metadata,
                            options,
                            &mut files,
                            &mut skipped,
                            &mut total_bytes,
                            &mut truncated,
                        );
                    }
                    Err(RepositoryError::EscapesRoot { .. }) => {
                        skipped.push(relative_skip(&guard, &path, SkipReason::OutsideRoot, None));
                    }
                    Err(error) => {
                        skipped.push(relative_skip(
                            &guard,
                            &path,
                            SkipReason::Unreadable,
                            Some(error.to_string()),
                        ));
                    }
                }
                continue;
            }

            if file_type.is_dir() {
                if options.ignores_dir(&file_name) {
                    skipped.push(relative_skip(
                        &guard,
                        &path,
                        SkipReason::IgnoredDirectory,
                        None,
                    ));
                    continue;
                }
                if depth + 1 > options.max_depth {
                    skipped.push(relative_skip(
                        &guard,
                        &path,
                        SkipReason::DepthExceeded,
                        None,
                    ));
                    continue;
                }
                let relative = guard
                    .relative(&path)
                    .unwrap_or_else(|| to_slash_path(&path));
                dirs.push(relative);
                stack.push((path, depth + 1));
                continue;
            }

            if !file_type.is_file() {
                skipped.push(relative_skip(
                    &guard,
                    &path,
                    SkipReason::Unreadable,
                    Some("not a regular file or directory".to_string()),
                ));
                continue;
            }

            if options.ignores_file(&file_name) {
                skipped.push(relative_skip(&guard, &path, SkipReason::IgnoredFile, None));
                continue;
            }

            visit_file(
                &guard,
                &path,
                &symlink_metadata,
                options,
                &mut files,
                &mut skipped,
                &mut total_bytes,
                &mut truncated,
            );
        }
    }

    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    dirs.sort();
    dirs.dedup();

    Ok(RepositoryModel {
        guard,
        name,
        files,
        dirs,
        skipped,
        total_bytes,
        truncated,
        max_file_bytes: options.max_file_bytes,
    })
}

/// Account for a single regular file against the configured bounds.
#[allow(clippy::too_many_arguments)]
fn visit_file(
    guard: &PathGuard,
    path: &Path,
    metadata: &fs::Metadata,
    options: &DiscoveryOptions,
    files: &mut Vec<SourceFile>,
    skipped: &mut Vec<SkipRecord>,
    total_bytes: &mut u64,
    truncated: &mut bool,
) {
    let relative = match guard.relative(path) {
        Some(relative) => relative,
        None => {
            // The canonical path is outside the root: refuse it and say so.
            skipped.push(SkipRecord {
                path: to_slash_path(path),
                reason: SkipReason::OutsideRoot,
                detail: None,
            });
            return;
        }
    };

    if files.len() as u32 >= options.max_files {
        *truncated = true;
        skipped.push(SkipRecord {
            path: relative,
            reason: SkipReason::FileCountLimit,
            detail: Some(format!("limit of {} files", options.max_files)),
        });
        return;
    }

    let size = metadata.len();
    if size > options.max_file_bytes {
        skipped.push(SkipRecord {
            path: relative,
            reason: SkipReason::TooLarge,
            detail: Some(format!("{size} bytes, limit {}", options.max_file_bytes)),
        });
        return;
    }

    if total_bytes.saturating_add(size) > options.max_total_bytes {
        *truncated = true;
        skipped.push(SkipRecord {
            path: relative,
            reason: SkipReason::TotalSizeLimit,
            detail: Some(format!("limit of {} bytes", options.max_total_bytes)),
        });
        return;
    }

    let kind = match classify_file(path) {
        Ok(kind) => kind,
        Err(error) => {
            skipped.push(SkipRecord {
                path: relative,
                reason: SkipReason::Unreadable,
                detail: Some(error.to_string()),
            });
            return;
        }
    };

    *total_bytes += size;
    let extension = path
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase());
    files.push(SourceFile {
        relative_path: relative,
        size,
        kind,
        language: language_for_path(path),
        extension,
    });
}

fn relative_skip(
    guard: &PathGuard,
    path: &Path,
    reason: SkipReason,
    detail: Option<String>,
) -> SkipRecord {
    let relative = guard.relative(path).unwrap_or_else(|| to_slash_path(path));
    SkipRecord {
        path: relative,
        reason,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        fs::write(root.join("README.md"), "# Demo\n").unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("tests/it.rs"), "#[test]\nfn t() {}\n").unwrap();
        fs::write(
            root.join("node_modules/pkg/index.js"),
            "module.exports = 1\n",
        )
        .unwrap();
        fs::write(root.join("target/debug/binary"), [0u8, 1, 2, 3]).unwrap();
        temp
    }

    fn options_with_ignores() -> DiscoveryOptions {
        DiscoveryOptions {
            ignore_dirs: vec!["node_modules".to_string(), "target".to_string()],
            ignore_files: vec![".DS_Store".to_string()],
            ..DiscoveryOptions::default()
        }
    }

    #[test]
    fn discovery_is_sorted_and_slash_separated() {
        let temp = fixture();
        let model = discover(temp.path(), &options_with_ignores()).unwrap();
        let paths: Vec<&str> = model
            .files()
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec!["Cargo.toml", "README.md", "src/main.rs", "tests/it.rs"]
        );

        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted, "discovery order must be canonical");
    }

    #[test]
    fn ignored_directories_are_skipped_with_a_reason() {
        let temp = fixture();
        let model = discover(temp.path(), &options_with_ignores()).unwrap();
        assert!(model.skipped().iter().any(|record| {
            record.reason == SkipReason::IgnoredDirectory && record.path == "node_modules"
        }));
        assert!(model.skipped().iter().any(|record| record.path == "target"));
        assert!(model
            .files()
            .iter()
            .all(|file| !file.relative_path.starts_with("node_modules")));
    }

    #[test]
    fn language_and_extension_are_inferred() {
        let temp = fixture();
        let model = discover(temp.path(), &options_with_ignores()).unwrap();
        let cargo = model.file("Cargo.toml").unwrap();
        assert_eq!(cargo.language, Some(Language::Rust));
        assert_eq!(cargo.extension.as_deref(), Some("toml"));
        assert_eq!(
            model.file("src/main.rs").unwrap().language,
            Some(Language::Rust)
        );
        assert_eq!(model.file("README.md").unwrap().language, None);
        assert_eq!(model.files_for_language(Language::Rust).len(), 3);
    }

    #[test]
    fn binary_files_are_classified_but_not_dropped() {
        let temp = fixture();
        let model = discover(temp.path(), &DiscoveryOptions::unbounded()).unwrap();
        let binary = model.file("target/debug/binary").unwrap();
        assert_eq!(binary.kind, FileKind::Binary);
        assert!(!binary.is_text());
    }

    #[test]
    fn oversized_files_are_skipped_with_their_size_recorded() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("huge.rs"), "x".repeat(5000)).unwrap();
        let options = DiscoveryOptions {
            max_file_bytes: 1000,
            ..DiscoveryOptions::default()
        };
        let model = discover(temp.path(), &options).unwrap();
        assert!(model.files().is_empty());
        let record = &model.skipped()[0];
        assert_eq!(record.reason, SkipReason::TooLarge);
        assert!(record.detail.as_deref().unwrap().contains("5000"));
    }

    #[test]
    fn file_count_limit_is_reported_as_truncation() {
        let temp = tempfile::tempdir().unwrap();
        for index in 0..8 {
            fs::write(temp.path().join(format!("file{index}.rs")), "// x\n").unwrap();
        }
        let options = DiscoveryOptions {
            max_files: 3,
            ..DiscoveryOptions::default()
        };
        let model = discover(temp.path(), &options).unwrap();
        assert_eq!(model.files().len(), 3);
        assert!(model.truncated());
        assert!(model
            .skipped()
            .iter()
            .any(|record| record.reason == SkipReason::FileCountLimit));
    }

    #[test]
    fn total_size_limit_is_reported_as_truncation() {
        let temp = tempfile::tempdir().unwrap();
        for index in 0..4 {
            fs::write(
                temp.path().join(format!("file{index}.txt")),
                "y".repeat(100),
            )
            .unwrap();
        }
        let options = DiscoveryOptions {
            max_file_bytes: 200,
            max_total_bytes: 250,
            ..DiscoveryOptions::default()
        };
        let model = discover(temp.path(), &options).unwrap();
        assert!(model.truncated());
        assert!(model
            .skipped()
            .iter()
            .any(|record| record.reason == SkipReason::TotalSizeLimit));
        assert!(model.total_bytes() <= 250);
    }

    #[test]
    fn depth_limit_prunes_deep_directories() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("a/b/c/d")).unwrap();
        fs::write(temp.path().join("a/b/c/d/deep.rs"), "// deep\n").unwrap();
        let options = DiscoveryOptions {
            max_depth: 2,
            ..DiscoveryOptions::default()
        };
        let model = discover(temp.path(), &options).unwrap();
        assert!(model.file("a/b/c/d/deep.rs").is_none());
        assert!(model
            .skipped()
            .iter()
            .any(|record| record.reason == SkipReason::DepthExceeded));
    }

    #[test]
    #[cfg(unix)]
    fn symlinks_are_recorded_and_not_followed_by_default() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/real.rs"), "// real\n").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            temp.path().join("link.txt"),
        )
        .unwrap();
        std::os::unix::fs::symlink(temp.path().join("src"), temp.path().join("src-link")).unwrap();

        let model = discover(temp.path(), &DiscoveryOptions::unbounded()).unwrap();
        assert!(model.file("link.txt").is_none());
        assert_eq!(
            model
                .skipped()
                .iter()
                .filter(|record| record.reason == SkipReason::Symlink)
                .count(),
            2
        );
        assert_eq!(model.file("src/real.rs").unwrap().size, 8);
    }

    #[test]
    #[cfg(unix)]
    fn following_symlinks_still_refuses_to_leave_the_root() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            temp.path().join("escape.txt"),
        )
        .unwrap();

        let options = DiscoveryOptions {
            follow_symlinks: true,
            ..DiscoveryOptions::unbounded()
        };
        let model = discover(temp.path(), &options).unwrap();
        assert!(model.file("escape.txt").is_none());
        assert!(model
            .skipped()
            .iter()
            .any(|record| record.reason == SkipReason::OutsideRoot));
    }

    #[test]
    fn reading_is_bounded_and_lossy_decoding_is_tolerated() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("latin1.txt"),
            [0x47, 0x72, 0xfc, 0xdf, 0x65, b'\n'],
        )
        .unwrap();
        let model = discover(temp.path(), &DiscoveryOptions::unbounded()).unwrap();
        let text = model.read_text("latin1.txt").unwrap();
        assert!(text.contains('e'), "{text:?}");
        assert_eq!(
            model.line_count(model.file("latin1.txt").unwrap()).unwrap(),
            1
        );
    }

    #[test]
    fn reading_an_unknown_path_is_an_error() {
        let temp = fixture();
        let model = discover(temp.path(), &options_with_ignores()).unwrap();
        assert!(matches!(
            model.read_text("does/not/exist.rs"),
            Err(RepositoryError::UnknownPath(_))
        ));
    }

    #[test]
    fn model_lookup_helpers_agree_with_the_inventory() {
        let temp = fixture();
        let model = discover(temp.path(), &options_with_ignores()).unwrap();
        assert!(model.has_file("src/main.rs"));
        assert!(model.has_dir("src"));
        assert!(model.has_file_named("Cargo.toml"));
        assert_eq!(model.files_named("Cargo.toml").len(), 1);
        assert_eq!(model.files_with_extension("rs").len(), 2);
        assert_eq!(model.files_under("src/").len(), 1);
        assert_eq!(model.file_count(), 4);
        assert!(matches!(
            model.read_lines(model.file("src/main.rs").unwrap()),
            Ok(lines) if lines == vec!["fn main() {}"]
        ));
        let counts = model.language_counts();
        assert_eq!(counts.get(&Language::Rust), Some(&3));
    }

    #[test]
    fn discovery_of_a_missing_root_fails_cleanly() {
        let temp = tempfile::tempdir().unwrap();
        let error = discover(&temp.path().join("nope"), &DiscoveryOptions::default()).unwrap_err();
        assert!(matches!(error, RepositoryError::NotADirectory { .. }));
    }
}
