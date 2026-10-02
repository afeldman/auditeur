//! The read-only boundary.
//!
//! This is the promise the whole design is built around, so it is tested the way
//! a claim about data integrity should be tested: by fingerprinting every file in
//! the audited tree (path, length and SHA-256) before and after a run and
//! comparing the two maps. A weaker test — checking that `git status` is clean, or
//! that no file has a newer mtime — would miss a rewrite that preserves length, or
//! a change to a file whose mtime the filesystem does not update the way we
//! assumed.
//!
//! The tests also cover the two paths most likely to break the promise: a run with
//! a model configured, and a repository that *is* a Git work tree, where reading
//! metadata is the classic way to accidentally write to it.

mod common;

use std::path::Path;
use std::process::Command;

use common::*;

/// Fingerprint, audit, fingerprint: nothing may differ, for any fixture.
#[test]
fn an_audit_never_modifies_the_repository() {
    for (fixture, _) in FIXTURES {
        let sandbox = Sandbox::new(fixture);

        let before = digest_tree(sandbox.repo());
        assert!(!before.is_empty(), "{fixture}: the fixture is empty");

        let output = sandbox.audit();
        assert!(
            matches!(code(&output), 0 | 1),
            "{fixture}: exit code {}: {}",
            code(&output),
            stderr(&output)
        );

        let after = digest_tree(sandbox.repo());
        assert_eq!(
            before, after,
            "{fixture}: the audit changed the audited repository"
        );

        // The run must also have produced something, otherwise "nothing changed"
        // would be trivially true of a crash.
        assert!(
            sandbox.report().is_file(),
            "{fixture}: no report was written"
        );
    }
}

/// A configured model is the path with the most moving parts — a server call, a
/// prompt built from repository content — so it is fingerprinted separately.
#[test]
fn an_audit_with_a_configured_model_leaves_the_repository_untouched() {
    let sandbox = Sandbox::new("rust-app");
    sandbox.write_config(
        "model.toml",
        "backend = \"openai_compatible\"\n\
         endpoint = \"http://127.0.0.1:9/v1\"\n\
         model = \"qwen/qwen2.5-coder-14b\"\n\
         enabled = true\n\
         request_timeout_secs = 5\n",
    );

    let before = digest_tree(sandbox.repo());
    let output = sandbox.audit();
    assert!(
        matches!(code(&output), 0 | 1),
        "exit code {}: {}",
        code(&output),
        stderr(&output)
    );
    let after = digest_tree(sandbox.repo());

    assert_eq!(before, after, "the audit changed the audited repository");
    assert!(sandbox.report().is_file());
}

/// Everything the audit creates belongs to the project directory, and nothing
/// else appears on disk: no stray cache inside the repository, no output beside
/// it, no dotfile left behind.
#[test]
fn every_artefact_belongs_to_the_project_directory() {
    let sandbox = Sandbox::new("python-app");
    let before = digest_tree(sandbox.repo());

    let output = sandbox.audit();
    assert!(matches!(code(&output), 0 | 1));

    let created: Vec<String> = digest_tree(sandbox.repo())
        .keys()
        .filter(|path| !before.contains_key(*path))
        .cloned()
        .collect();
    assert!(
        created.is_empty(),
        "the audit created files inside the repository: {created:?}"
    );

    for artefact in sandbox.artifact_files() {
        assert!(
            artefact.starts_with(sandbox.state()),
            "{} is outside the project directory",
            artefact.display()
        );
    }
    assert!(sandbox.report().starts_with(sandbox.state()));

    // The cache lives in the project directory too. It may not exist yet — the
    // MVP collects no AST cache — but if it does, it must not be in the repo.
    assert!(!sandbox.repo().join("cache").exists());
    assert!(!sandbox.repo().join("runs").exists());
}

/// Reading Git metadata must not write to the work tree. Git refreshes its index
/// opportunistically, and that refresh is a write to `.git/`, so this test is the
/// one that keeps `.git/index` out of the audit's blast radius.
#[test]
fn auditing_a_git_work_tree_leaves_the_repository_and_its_head_untouched() {
    let sandbox = Sandbox::new("rust-app");
    if !git_is_available() {
        eprintln!("skipping: git is not installed");
        return;
    }

    run_git(sandbox.repo(), &["init", "--quiet"]);
    run_git(sandbox.repo(), &["add", "--all"]);
    run_git(
        sandbox.repo(),
        &[
            "-c",
            "user.email=auditeur@example.invalid",
            "-c",
            "user.name=Auditeur Test",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
    );

    let head_before = git_stdout(sandbox.repo(), &["rev-parse", "HEAD"]);
    let before = digest_tree(sandbox.repo());

    let output = sandbox.audit();
    assert!(
        matches!(code(&output), 0 | 1),
        "exit code {}: {}",
        code(&output),
        stderr(&output)
    );

    // Fingerprints first: running more git commands here could itself touch the
    // index and mask what we are trying to detect.
    let after = digest_tree(sandbox.repo());
    assert_eq!(
        before, after,
        "auditing a Git work tree modified it, most likely .git/index"
    );

    let head_after = git_stdout(sandbox.repo(), &["rev-parse", "HEAD"]);
    assert_eq!(head_before, head_after, "the audit moved HEAD");

    // The run recorded the commit it saw, which is what makes the report
    // reproducible.
    let manifest = sandbox.manifest();
    assert_eq!(
        manifest["repository"]["git"]["head_commit"]
            .as_str()
            .unwrap_or_default(),
        head_before.trim(),
        "the manifest should record the commit that was audited"
    );
}

/// A repository that tries to look like a symlink farm cannot make the audit read
/// outside its own tree, and cannot make it write.
#[test]
fn a_symlink_pointing_outside_the_repository_is_not_followed() {
    let sandbox = Sandbox::new("python-app");
    let outside = tempfile::tempdir().expect("a temporary directory");
    let target = outside.path().join("secret.txt");
    std::fs::write(&target, "outside the repository\n").unwrap();

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, sandbox.repo().join("escape.txt")).unwrap();
    }
    #[cfg(not(unix))]
    {
        eprintln!("skipping: symlinks are a Unix concern here");
        return;
    }

    let before = digest_tree(sandbox.repo());
    let output = sandbox.audit();
    assert!(matches!(code(&output), 0 | 1));

    assert_eq!(
        digest_tree(sandbox.repo()),
        before,
        "the audit changed the repository around the symlink"
    );
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "outside the repository\n",
        "the audit wrote through the symlink"
    );
    assert!(
        !sandbox.repo().join("escape.txt").is_symlink()
            || std::fs::read_link(sandbox.repo().join("escape.txt")).unwrap() == target,
        "the symlink was replaced"
    );
}

fn git_is_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run_git(cwd: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_stdout(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("git runs");
    String::from_utf8_lossy(&output.stdout).into_owned()
}
