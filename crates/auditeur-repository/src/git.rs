//! Git metadata collection.
//!
//! Git inspection runs through the same execution boundary as every other
//! command, with a policy that permits exactly one program (`git`) and a fixed
//! set of read-only subcommands built by this module. Every invocation passes
//! `--no-optional-locks`, which stops `git` from refreshing the index because
//! that refresh would write inside the audited repository.
//!
//! A repository that cannot be probed is not an error: the audit records that
//! Git state was unavailable and continues with the evidence it can collect.

use std::path::PathBuf;
use std::time::Duration;

use auditeur_model::{redact::redact_text, GitState, ToolExecution};

use crate::exec::{CommandOutput, CommandRequest, CommandRunner, ExecPolicy};

/// Time budget for a single Git invocation.
pub const GIT_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Result of probing a repository's Git metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitProbeResult {
    /// Git state, absent when the path is not a Git work tree.
    pub state: Option<GitState>,
    /// Commands executed while probing, for the run manifest.
    pub executions: Vec<ToolExecution>,
    /// Human-readable notes about what could not be determined.
    pub notes: Vec<String>,
}

impl GitProbeResult {
    /// Whether Git metadata was obtained.
    pub fn is_git_repository(&self) -> bool {
        self.state.is_some()
    }
}

/// Probes Git metadata for a repository.
#[derive(Debug, Clone)]
pub struct GitProbe {
    runner: CommandRunner,
    boundary_note: Option<String>,
}

impl GitProbe {
    /// Create a probe for `repository_root`, using `cache_root` for scratch data.
    ///
    /// If `cache_root` lies inside the audited repository, the probe substitutes
    /// a directory in the system temporary area instead of writing into the
    /// repository, and records why. The Git probe must not be allowed to fail
    /// silently just because a cache path was configured badly — nor may it
    /// override the read-only guarantee.
    pub fn new(repository_root: impl Into<PathBuf>, cache_root: impl Into<PathBuf>) -> Self {
        let repository_root = repository_root.into();
        let cache_root = cache_root.into();
        let (effective_cache, boundary_note) = if crate::exec::is_path_inside(
            &cache_root,
            &repository_root,
        ) {
            let fallback = std::env::temp_dir().join("auditeur-git-probe");
            let note = format!(
                    "configured cache directory {} is inside the audited repository; the Git probe used {} instead",
                    cache_root.display(),
                    fallback.display()
                );
            (fallback, Some(note))
        } else {
            (cache_root, None)
        };
        let runner = CommandRunner::new(
            repository_root,
            effective_cache,
            ExecPolicy::for_programs(["git"], GIT_PROBE_TIMEOUT),
        );
        Self {
            runner,
            boundary_note,
        }
    }

    /// Collect Git metadata, recording every command that ran.
    pub fn probe(&self) -> GitProbeResult {
        let mut result = GitProbeResult::default();
        if let Some(note) = &self.boundary_note {
            result.notes.push(note.clone());
        }

        let inside = match self.git(&["rev-parse", "--is-inside-work-tree"], &mut result) {
            Some(output) if output.success() => output.stdout.trim() == "true",
            Some(_) => false,
            None => {
                result
                    .notes
                    .push("git is unavailable; Git state was not recorded".to_string());
                return result;
            }
        };
        if !inside {
            result
                .notes
                .push("path is not inside a Git work tree".to_string());
            return result;
        }

        let head_commit = self
            .git(&["rev-parse", "HEAD"], &mut result)
            .filter(CommandOutput::success)
            .map(|output| output.stdout.trim().to_string())
            .filter(|commit| !commit.is_empty());
        if head_commit.is_none() {
            result
                .notes
                .push("repository has no commit yet (unborn HEAD)".to_string());
        }

        let branch = self
            .git(&["symbolic-ref", "--short", "-q", "HEAD"], &mut result)
            .filter(CommandOutput::success)
            .map(|output| output.stdout.trim().to_string())
            .filter(|branch| !branch.is_empty());

        let describe = self
            .git(&["describe", "--tags", "--always"], &mut result)
            .filter(CommandOutput::success)
            .map(|output| output.stdout.trim().to_string())
            .filter(|describe| !describe.is_empty());

        let remote = self
            .git(&["config", "--get", "remote.origin.url"], &mut result)
            .filter(CommandOutput::success)
            .map(|output| strip_url_credentials(output.stdout.trim()))
            .filter(|remote| !remote.is_empty());

        let mut dirty = false;
        let mut modified_files = 0;
        let mut untracked_files = 0;
        if let Some(output) = self.git(
            &["status", "--porcelain=v1", "-z", "--untracked-files=normal"],
            &mut result,
        ) {
            if output.success() {
                let (modified, untracked) = count_status_entries(&output.stdout);
                modified_files = modified;
                untracked_files = untracked;
                dirty = modified + untracked > 0;
            } else {
                result
                    .notes
                    .push("git status failed; working-tree cleanliness is unknown".to_string());
            }
        }

        result.state = Some(GitState {
            head_commit,
            branch,
            describe,
            remote,
            dirty,
            modified_files,
            untracked_files,
        });
        result
    }

    /// Run one read-only Git subcommand with the global no-write flags.
    fn git(&self, args: &[&str], result: &mut GitProbeResult) -> Option<CommandOutput> {
        let mut full_args: Vec<String> = vec![
            // Prevents the index refresh that plain `git status` performs.
            "--no-optional-locks".to_string(),
            "--no-pager".to_string(),
        ];
        full_args.extend(args.iter().map(|arg| (*arg).to_string()));

        let request = CommandRequest::new("git", full_args, format!("git {}", args.join(" ")));
        match self.runner.run(&request) {
            Ok(output) => {
                result.executions.push(output.to_record());
                Some(output)
            }
            Err(_) => None,
        }
    }
}

/// Count modified and untracked entries in NUL-separated porcelain output.
///
/// Rename and copy entries carry the source path as an additional NUL-separated
/// field; that field is skipped so it is not miscounted as a separate file.
pub fn count_status_entries(porcelain: &str) -> (u32, u32) {
    let mut modified = 0u32;
    let mut untracked = 0u32;
    let mut skip_next = false;
    for field in porcelain.split('\0') {
        if field.is_empty() {
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        let code: String = field.chars().take(2).collect();
        let is_rename_or_copy = code.starts_with('R')
            || code.starts_with('C')
            || code.starts_with(" R")
            || code.starts_with(" C");
        if code == "??" {
            untracked += 1;
        } else {
            modified += 1;
        }
        if is_rename_or_copy {
            skip_next = true;
        }
    }
    (modified, untracked)
}

/// Remove userinfo (and therefore any embedded credential) from a URL.
///
/// `https://user:token@example.com/org/repo.git` becomes
/// `https://example.com/org/repo.git`. SCP-style remotes (`git@host:path`) keep
/// their user name, which is not a credential.
pub fn strip_url_credentials(url: &str) -> String {
    let stripped = match url.find("://") {
        Some(scheme_end) => {
            let authority_start = scheme_end + 3;
            let authority = &url[authority_start..];
            let authority_end = authority.find('/').unwrap_or(authority.len());
            match authority[..authority_end].find('@') {
                Some(at) => format!(
                    "{}{}",
                    &url[..authority_start],
                    &url[authority_start + at + 1..]
                ),
                None => url.to_string(),
            }
        }
        None => url.to_string(),
    };
    redact_text(&stripped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_stripped_from_https_remotes() {
        assert_eq!(
            strip_url_credentials("https://user:ghp_secrettoken@github.com/org/repo.git"),
            "https://github.com/org/repo.git"
        );
        assert_eq!(
            strip_url_credentials("https://github.com/org/repo.git"),
            "https://github.com/org/repo.git"
        );
    }

    #[test]
    fn scp_style_remotes_keep_their_user() {
        assert_eq!(
            strip_url_credentials("git@github.com:org/repo.git"),
            "git@github.com:org/repo.git"
        );
    }

    #[test]
    fn status_entries_are_counted_by_kind() {
        let porcelain = " M src/main.rs\0?? new.txt\0?? other.txt\0";
        assert_eq!(count_status_entries(porcelain), (1, 2));
        assert_eq!(count_status_entries(""), (0, 0));
    }

    #[test]
    fn rename_entries_are_not_double_counted() {
        let porcelain = "R  new.rs\0old.rs\0 M other.rs\0";
        assert_eq!(count_status_entries(porcelain), (2, 0));
    }

    #[test]
    fn probing_a_non_repository_yields_no_state_and_a_note() {
        let temp = tempfile::tempdir().unwrap();
        let probe = GitProbe::new(temp.path(), temp.path().join("cache"));
        let result = probe.probe();
        if which_git().is_none() {
            assert!(result.state.is_none());
            assert!(!result.notes.is_empty());
        } else {
            assert!(result.state.is_none(), "a bare temp dir is not a work tree");
            assert!(result
                .notes
                .iter()
                .any(|note| note.contains("not inside a Git work tree")));
        }
    }

    #[test]
    fn probing_a_real_repository_records_the_commit() {
        if which_git().is_none() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        run_git(root, &["init", "-q"]);
        run_git(root, &["config", "user.email", "auditeur@example.com"]);
        run_git(root, &["config", "user.name", "Auditeur Test"]);
        std::fs::write(root.join("file.txt"), "content\n").unwrap();
        run_git(root, &["add", "file.txt"]);
        run_git(root, &["commit", "-q", "-m", "initial"]);

        let probe = GitProbe::new(root, root.join("cache"));
        let result = probe.probe();
        let state = result.state.expect("git repository expected");
        assert!(state.head_commit.is_some());
        assert!(!state.dirty);
        assert!(!result.executions.is_empty());
        assert!(result
            .executions
            .iter()
            .all(|execution| execution.program == "git"));
        assert!(result
            .executions
            .iter()
            .flat_map(|execution| execution.args.iter())
            .any(|arg| arg == "--no-optional-locks"));

        std::fs::write(root.join("file.txt"), "changed\n").unwrap();
        let second = GitProbe::new(root, root.join("cache")).probe();
        assert!(second.state.unwrap().dirty);
    }

    #[test]
    fn probing_never_writes_into_the_repository() {
        if which_git().is_none() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        run_git(root, &["init", "-q"]);
        // Git's automatic maintenance runs after a commit and takes
        // `.git/objects/maintenance.lock` while it does. It is still in flight
        // when this test fingerprints the tree, and the check below would then
        // report the end of that pass as a change the probe made.
        run_git(root, &["config", "maintenance.auto", "false"]);
        run_git(root, &["config", "gc.auto", "0"]);
        run_git(root, &["config", "user.email", "auditeur@example.com"]);
        run_git(root, &["config", "user.name", "Auditeur Test"]);
        std::fs::write(root.join("file.txt"), "content\n").unwrap();
        run_git(root, &["add", "file.txt"]);
        run_git(root, &["commit", "-q", "-m", "initial"]);

        let options = crate::fingerprint::FingerprintOptions::default();
        let before = crate::fingerprint::fingerprint_tree(root, &options).unwrap();

        // Deliberately misconfigured: the cache path is inside the repository.
        // The probe must fall back to a location outside it and say so.
        let result = GitProbe::new(root, root.join("cache")).probe();

        let after = crate::fingerprint::fingerprint_tree(root, &options).unwrap();
        assert_eq!(
            before.fingerprint.digest,
            after.fingerprint.digest,
            "git probing must not modify the repository: {:?}",
            crate::fingerprint::diff_fingerprints(&before, &after)
        );
        assert!(
            !root.join("cache").exists(),
            "the cache must not be created in the repository"
        );
        assert!(
            result
                .notes
                .iter()
                .any(|note| note.contains("inside the audited repository")),
            "the substitution must be reported: {:?}",
            result.notes
        );
        assert!(result.is_git_repository(), "the probe must still work");
    }

    fn which_git() -> Option<PathBuf> {
        let status = std::process::Command::new("git")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?;
        status.success().then(|| PathBuf::from("git"))
    }

    fn run_git(root: &std::path::Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_DATE", "2020-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2020-01-01T00:00:00Z")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("git should be executable in this test");
        assert!(status.success(), "git {args:?} failed");
    }
}
