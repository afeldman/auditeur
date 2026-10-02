//! Containment of every path Auditeur touches.
//!
//! The repository is untrusted input. A path built from repository content —
//! a manifest entry, a lockfile path, a symlink target — can point outside the
//! audited tree, and any read that follows it is a leak. Every path therefore
//! passes through [`PathGuard`], which canonicalises it and refuses anything
//! that is not below the canonical repository root.

use std::path::{Path, PathBuf};

use crate::error::RepositoryError;

/// Enforces that every accessed path stays inside the repository root.
#[derive(Debug, Clone)]
pub struct PathGuard {
    root: PathBuf,
}

impl PathGuard {
    /// Canonicalise `root` and prepare to guard it.
    pub fn new(root: &Path) -> Result<Self, RepositoryError> {
        let metadata = std::fs::metadata(root).map_err(|_| RepositoryError::NotADirectory {
            path: root.to_path_buf(),
        })?;
        if !metadata.is_dir() {
            return Err(RepositoryError::NotADirectory {
                path: root.to_path_buf(),
            });
        }
        let canonical =
            std::fs::canonicalize(root).map_err(|source| RepositoryError::Canonicalize {
                path: root.to_path_buf(),
                source,
            })?;
        Ok(Self { root: canonical })
    }

    /// The canonical repository root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether `path`, once resolved, is inside the root.
    pub fn contains(&self, path: &Path) -> bool {
        match std::fs::canonicalize(path) {
            Ok(resolved) => resolved.starts_with(&self.root),
            // A path that cannot be resolved is not inside the root.
            Err(_) => false,
        }
    }

    /// Resolve an existing path, rejecting anything outside the root.
    pub fn resolve_existing(&self, candidate: &Path) -> Result<PathBuf, RepositoryError> {
        let resolved =
            std::fs::canonicalize(candidate).map_err(|source| RepositoryError::Canonicalize {
                path: candidate.to_path_buf(),
                source,
            })?;
        if !resolved.starts_with(&self.root) {
            return Err(RepositoryError::EscapesRoot {
                path: candidate.to_path_buf(),
                root: self.root.clone(),
            });
        }
        Ok(resolved)
    }

    /// Resolve a repository-relative path from the repository model.
    ///
    /// The relative path is rejected outright if it is absolute or contains a
    /// parent component, before any filesystem access happens.
    pub fn resolve_relative(&self, relative: &str) -> Result<PathBuf, RepositoryError> {
        let relative_path = Path::new(relative);
        if relative_path.is_absolute() {
            return Err(RepositoryError::EscapesRoot {
                path: relative_path.to_path_buf(),
                root: self.root.clone(),
            });
        }
        if relative_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(RepositoryError::EscapesRoot {
                path: relative_path.to_path_buf(),
                root: self.root.clone(),
            });
        }
        self.resolve_existing(&self.root.join(relative_path))
    }

    /// Repository-relative, slash-separated form of an absolute path.
    pub fn relative(&self, path: &Path) -> Option<String> {
        let resolved = std::fs::canonicalize(path).ok()?;
        let stripped = resolved.strip_prefix(&self.root).ok()?;
        Some(to_slash_path(stripped))
    }
}

/// Render a path with forward slashes, for stable report output on any platform.
pub fn to_slash_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn root_must_be_a_directory() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("file.txt");
        fs::write(&file, "x").unwrap();
        assert!(PathGuard::new(&file).is_err());
        assert!(PathGuard::new(&temp.path().join("missing")).is_err());
        assert!(PathGuard::new(temp.path()).is_ok());
    }

    #[test]
    fn paths_inside_the_root_resolve() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/main.rs"), "fn main() {}").unwrap();
        let guard = PathGuard::new(temp.path()).unwrap();

        assert!(guard.contains(&temp.path().join("src/main.rs")));
        let resolved = guard.resolve_relative("src/main.rs").unwrap();
        assert!(resolved.starts_with(guard.root()));
        assert_eq!(guard.relative(&resolved).as_deref(), Some("src/main.rs"));
    }

    #[test]
    fn parent_components_in_relative_paths_are_refused_without_touching_the_fs() {
        let temp = tempfile::tempdir().unwrap();
        let guard = PathGuard::new(temp.path()).unwrap();
        let error = guard.resolve_relative("../secrets.txt").unwrap_err();
        assert!(matches!(error, RepositoryError::EscapesRoot { .. }));
        let error = guard.resolve_relative("/etc/passwd").unwrap_err();
        assert!(matches!(error, RepositoryError::EscapesRoot { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn symlinks_that_escape_the_root_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "top secret").unwrap();

        let repo = temp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret.txt"), repo.join("link.txt"))
            .unwrap();

        let guard = PathGuard::new(&repo).unwrap();
        assert!(!guard.contains(&repo.join("link.txt")));
        let error = guard.resolve_relative("link.txt").unwrap_err();
        assert!(matches!(error, RepositoryError::EscapesRoot { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn symlinks_inside_the_root_resolve_to_their_target() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::write(repo.join("src/lib.rs"), "// lib").unwrap();
        std::os::unix::fs::symlink(repo.join("src/lib.rs"), repo.join("alias.rs")).unwrap();

        let guard = PathGuard::new(&repo).unwrap();
        assert!(guard.contains(&repo.join("alias.rs")));
        assert_eq!(
            guard.relative(&repo.join("alias.rs")).as_deref(),
            Some("src/lib.rs")
        );
    }

    #[test]
    fn slash_paths_are_stable() {
        assert_eq!(to_slash_path(Path::new("a/b/c.rs")), "a/b/c.rs");
    }
}
