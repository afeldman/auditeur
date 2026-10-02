//! Repository fingerprinting and the read-only guard.
//!
//! The fingerprint is the mechanism behind the read-only guarantee: a digest
//! over every path, size, modification time and (optionally) content of the
//! audited tree. [`ReadOnlyGuard`] captures it before an audit and re-computes
//! it afterwards. Any difference is a violation, reported with the exact paths
//! that changed so the defect can be found rather than guessed at.
//!
//! Unlike discovery, the fingerprint walk applies no ignore list and no
//! per-file limit that could hide a change: it exists to see everything.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use auditeur_model::{sha256_hex, RepositoryFingerprint};

use crate::error::RepositoryError;
use crate::guard::PathGuard;

/// Bounds for the fingerprint walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintOptions {
    /// Whether file contents contribute to the digest. Slower, and it catches a
    /// rewrite that preserves size and modification time.
    pub include_content: bool,
    /// Largest file whose content is hashed. Larger files contribute metadata
    /// only, so a multi-gigabyte artefact cannot stall verification.
    pub max_content_bytes: u64,
    /// Maximum number of entries in the walk; a safety valve, not a policy.
    pub max_entries: usize,
}

impl Default for FingerprintOptions {
    fn default() -> Self {
        Self {
            include_content: true,
            max_content_bytes: 262_144,
            max_entries: 200_000,
        }
    }
}

impl FingerprintOptions {
    /// Metadata-only fingerprinting: fast, for very large trees.
    pub fn metadata_only() -> Self {
        Self {
            include_content: false,
            ..Self::default()
        }
    }
}

/// One entry contributing to a fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    /// Repository-relative, slash-separated path.
    pub relative_path: String,
    /// Whether the entry is a directory.
    pub is_dir: bool,
    /// Size in bytes.
    pub size: u64,
    /// Modification time in nanoseconds since the Unix epoch.
    pub mtime_nanos: i64,
    /// SHA-256 of the content, when hashed.
    pub content_digest: Option<String>,
}

impl TreeEntry {
    fn digest_line(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.relative_path,
            if self.is_dir { "d" } else { "f" },
            self.size,
            self.mtime_nanos,
            self.content_digest.as_deref().unwrap_or("-")
        )
    }
}

/// A fingerprint plus the entries it was computed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeFingerprint {
    /// The digest and aggregate statistics.
    pub fingerprint: RepositoryFingerprint,
    /// Contributing entries, sorted by path.
    pub entries: Vec<TreeEntry>,
}

/// What happened to a path between two fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// The path exists in the later fingerprint only.
    Added,
    /// The path exists in the earlier fingerprint only.
    Removed,
    /// The path exists in both with different metadata or content.
    Modified,
}

impl ChangeKind {
    /// Stable identifier for reports.
    pub fn id(self) -> &'static str {
        match self {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::Modified => "modified",
        }
    }
}

/// A changed path between two fingerprints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRecord {
    /// Repository-relative path.
    pub relative_path: String,
    /// What happened to it.
    pub kind: ChangeKind,
}

impl ChangeRecord {
    /// One-line description used in violation messages.
    pub fn describe(&self) -> String {
        format!("{} {}", self.kind.id(), self.relative_path)
    }
}

/// Fingerprint the tree rooted at `root`.
pub fn fingerprint_tree(
    root: &Path,
    options: &FingerprintOptions,
) -> Result<TreeFingerprint, RepositoryError> {
    let guard = PathGuard::new(root)?;
    let canonical_root = guard.root().to_path_buf();

    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(canonical_root.clone(), 0)];
    let mut visited: HashSet<PathBuf> = HashSet::new();
    visited.insert(canonical_root.clone());

    while let Some((directory, depth)) = stack.pop() {
        if entries.len() >= options.max_entries || depth > 64 {
            continue;
        }
        let read_dir = match fs::read_dir(&directory) {
            Ok(read_dir) => read_dir,
            Err(_) => continue,
        };
        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in read_dir.flatten() {
            paths.push(entry.path());
        }
        paths.sort();

        for path in paths {
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            let relative_path = match guard.relative(&path) {
                Some(relative) => relative,
                None => continue,
            };
            let file_type = metadata.file_type();

            if file_type.is_symlink() {
                // A symlink's own metadata is what matters; its target is not
                // part of this tree.
                entries.push(TreeEntry {
                    relative_path,
                    is_dir: false,
                    size: 0,
                    mtime_nanos: mtime_nanos(&metadata),
                    content_digest: None,
                });
                continue;
            }

            if file_type.is_dir() {
                let resolved = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
                if visited.insert(resolved.clone()) {
                    stack.push((resolved, depth + 1));
                }
                entries.push(TreeEntry {
                    relative_path,
                    is_dir: true,
                    size: 0,
                    mtime_nanos: mtime_nanos(&metadata),
                    content_digest: None,
                });
                continue;
            }

            let size = metadata.len();
            let content_digest = if options.include_content && size <= options.max_content_bytes {
                fs::read(&path).ok().map(|bytes| sha256_hex(&bytes))
            } else {
                None
            };
            entries.push(TreeEntry {
                relative_path,
                is_dir: false,
                size,
                mtime_nanos: mtime_nanos(&metadata),
                content_digest,
            });
        }
    }

    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    let mut material = String::new();
    for entry in &entries {
        material.push_str(&entry.digest_line());
        material.push('\n');
    }
    let total_bytes: u64 = entries
        .iter()
        .filter(|entry| !entry.is_dir)
        .map(|entry| entry.size)
        .sum();
    let files = entries.iter().filter(|entry| !entry.is_dir).count() as u32;

    Ok(TreeFingerprint {
        fingerprint: RepositoryFingerprint {
            digest: sha256_hex(material.as_bytes()),
            files,
            total_bytes,
        },
        entries,
    })
}

/// Compare two fingerprints entry by entry.
pub fn diff_fingerprints(before: &TreeFingerprint, after: &TreeFingerprint) -> Vec<ChangeRecord> {
    let mut changes = Vec::new();
    let before_map: std::collections::BTreeMap<&str, &TreeEntry> = before
        .entries
        .iter()
        .map(|entry| (entry.relative_path.as_str(), entry))
        .collect();
    let after_map: std::collections::BTreeMap<&str, &TreeEntry> = after
        .entries
        .iter()
        .map(|entry| (entry.relative_path.as_str(), entry))
        .collect();

    for (path, entry) in &after_map {
        match before_map.get(path) {
            None => changes.push(ChangeRecord {
                relative_path: (*path).to_string(),
                kind: ChangeKind::Added,
            }),
            Some(before_entry) => {
                if before_entry != entry {
                    changes.push(ChangeRecord {
                        relative_path: (*path).to_string(),
                        kind: ChangeKind::Modified,
                    });
                }
            }
        }
    }
    for path in before_map.keys() {
        if !after_map.contains_key(path) {
            changes.push(ChangeRecord {
                relative_path: (*path).to_string(),
                kind: ChangeKind::Removed,
            });
        }
    }

    changes.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    changes
}

/// Captures a fingerprint before an audit and verifies it afterwards.
#[derive(Debug, Clone)]
pub struct ReadOnlyGuard {
    root: PathBuf,
    options: FingerprintOptions,
    before: TreeFingerprint,
}

impl ReadOnlyGuard {
    /// Capture the pre-audit fingerprint of `root`.
    pub fn capture(root: &Path) -> Result<Self, RepositoryError> {
        Self::with_options(root, FingerprintOptions::default())
    }

    /// Capture the pre-audit fingerprint with explicit options.
    pub fn with_options(root: &Path, options: FingerprintOptions) -> Result<Self, RepositoryError> {
        let before = fingerprint_tree(root, &options)?;
        Ok(Self {
            root: root.to_path_buf(),
            options,
            before,
        })
    }

    /// The root being guarded.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The fingerprint captured before the audit.
    pub fn before(&self) -> &RepositoryFingerprint {
        &self.before.fingerprint
    }

    /// Changed paths since capture; empty when the tree is untouched.
    pub fn changes(&self) -> Result<Vec<ChangeRecord>, RepositoryError> {
        let after = fingerprint_tree(&self.root, &self.options)?;
        Ok(diff_fingerprints(&self.before, &after))
    }

    /// Verify the repository is unchanged, failing with the exact changes.
    pub fn verify(&self) -> Result<(), RepositoryError> {
        let changes = self.changes()?;
        if changes.is_empty() {
            return Ok(());
        }
        let described: Vec<String> = changes.iter().map(ChangeRecord::describe).collect();
        Err(RepositoryError::ReadOnlyViolation(format!(
            "{} path(s) changed during the audit: {}",
            described.len(),
            described.join(", ")
        )))
    }
}

fn mtime_nanos(metadata: &fs::Metadata) -> i64 {
    match metadata.modified() {
        Ok(modified) => match modified.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos() as i64,
            Err(error) => -(error.duration().as_nanos() as i64),
        },
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_across_identical_walks() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.txt"), "same").unwrap();
        let first = fingerprint_tree(temp.path(), &FingerprintOptions::default()).unwrap();
        let second = fingerprint_tree(temp.path(), &FingerprintOptions::default()).unwrap();
        assert_eq!(first.fingerprint, second.fingerprint);
    }

    #[test]
    fn content_changes_are_detected() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("a.txt");
        std::fs::write(&file, "first").unwrap();
        let before = fingerprint_tree(temp.path(), &FingerprintOptions::default()).unwrap();
        std::fs::write(&file, "second").unwrap();
        let after = fingerprint_tree(temp.path(), &FingerprintOptions::default()).unwrap();
        assert_ne!(before.fingerprint.digest, after.fingerprint.digest);
        let changes = diff_fingerprints(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Modified);
    }

    #[test]
    fn added_and_removed_paths_are_reported() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("keep.txt"), "keep").unwrap();
        std::fs::write(temp.path().join("gone.txt"), "gone").unwrap();
        let before = fingerprint_tree(temp.path(), &FingerprintOptions::default()).unwrap();

        std::fs::remove_file(temp.path().join("gone.txt")).unwrap();
        std::fs::write(temp.path().join("new.txt"), "new").unwrap();
        let after = fingerprint_tree(temp.path(), &FingerprintOptions::default()).unwrap();

        let changes = diff_fingerprints(&before, &after);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].kind, ChangeKind::Removed);
        assert_eq!(changes[0].relative_path, "gone.txt");
        assert_eq!(changes[1].kind, ChangeKind::Added);
        assert_eq!(changes[1].relative_path, "new.txt");
    }

    #[test]
    fn metadata_only_mode_omits_content_digests() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("a.txt");
        std::fs::write(&file, "aaaa").unwrap();

        let metadata_only =
            fingerprint_tree(temp.path(), &FingerprintOptions::metadata_only()).unwrap();
        let entry = metadata_only
            .entries
            .iter()
            .find(|entry| entry.relative_path == "a.txt")
            .unwrap();
        assert!(entry.content_digest.is_none());

        let with_content = fingerprint_tree(temp.path(), &FingerprintOptions::default()).unwrap();
        let entry = with_content
            .entries
            .iter()
            .find(|entry| entry.relative_path == "a.txt")
            .unwrap();
        assert_eq!(
            entry.content_digest.as_deref(),
            Some(auditeur_model::sha256_hex(b"aaaa").as_str())
        );

        // Rewriting the file changes both fingerprints, because the walk records
        // modification time as well as content. The new time is set explicitly:
        // two consecutive writes can land in the same filesystem timestamp tick
        // — Linux reads a coarse clock, so on ext4 and overlayfs they usually do
        // — and then nothing about the entry would have changed at all.
        let first = std::fs::metadata(&file).unwrap().modified().unwrap();

        std::fs::write(&file, "bbbb").unwrap();

        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(first + std::time::Duration::from_secs(1))
            .unwrap();
        let after = fingerprint_tree(temp.path(), &FingerprintOptions::metadata_only()).unwrap();
        assert_ne!(metadata_only.fingerprint.digest, after.fingerprint.digest);
    }

    #[test]
    fn directories_contribute_to_the_fingerprint() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("src")).unwrap();
        let with_dir = fingerprint_tree(temp.path(), &FingerprintOptions::default()).unwrap();
        assert!(with_dir
            .entries
            .iter()
            .any(|entry| entry.is_dir && entry.relative_path == "src"));
        assert!(with_dir.fingerprint.digest.len() == 64);
    }

    #[test]
    fn guard_accepts_an_untouched_tree() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.txt"), "content").unwrap();
        let guard = ReadOnlyGuard::capture(temp.path()).unwrap();
        guard.verify().unwrap();
        assert!(guard.changes().unwrap().is_empty());
    }

    #[test]
    fn guard_names_the_violating_path() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.txt"), "content").unwrap();
        let guard = ReadOnlyGuard::capture(temp.path()).unwrap();
        std::fs::write(temp.path().join("a.txt"), "tampered").unwrap();

        let error = guard.verify().unwrap_err();
        assert!(error.is_read_only_violation());
        let message = error.to_string();
        assert!(message.contains("a.txt"), "{message}");
        assert!(message.contains("modified"), "{message}");
    }

    #[test]
    fn guard_detects_a_file_created_inside_the_repository() {
        let temp = tempfile::tempdir().unwrap();
        let guard = ReadOnlyGuard::capture(temp.path()).unwrap();
        std::fs::write(temp.path().join("sneaky.txt"), "x").unwrap();
        let error = guard.verify().unwrap_err();
        assert!(error.to_string().contains("sneaky.txt"), "{error}");
    }

    #[test]
    fn large_files_are_hashed_by_metadata_only() {
        let temp = tempfile::tempdir().unwrap();
        let options = FingerprintOptions {
            include_content: true,
            max_content_bytes: 8,
            max_entries: 100,
        };
        std::fs::write(temp.path().join("big.bin"), "x".repeat(64)).unwrap();
        let fingerprint = fingerprint_tree(temp.path(), &options).unwrap();
        let entry = fingerprint
            .entries
            .iter()
            .find(|entry| entry.relative_path == "big.bin")
            .unwrap();
        assert!(entry.content_digest.is_none());
        assert_eq!(entry.size, 64);
    }
}
