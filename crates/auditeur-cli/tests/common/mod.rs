//! Shared harness for Auditeur's command-line integration tests.
//!
//! Every test runs the real binary against a *copy* of a fixture repository, with
//! a temporary `HOME` and a temporary project directory. Two properties follow
//! from that, and both matter:
//!
//! * a test can never reach the developer's own project state or their `~/`;
//! * the repository under audit is a copy, so a test that detects a modification
//!   has detected it in the audit process, not in the fixture.
//!
//! The environment is also scrubbed of every `AUDITEUR_*` variable, so a
//! developer who happens to have one exported cannot change what the suite
//! proves. `AUDITEUR_HOME` is then set to the sandbox's own state directory, so
//! nothing a test does can reach the developer's real `~/auditeur`.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

/// The binary under test, as built by Cargo for this test run.
pub const BIN: &str = env!("CARGO_BIN_EXE_auditeur");

/// A fixture copy, an isolated state directory, and an isolated `HOME`.
pub struct Sandbox {
    repo: PathBuf,
    state: PathBuf,
    home: PathBuf,
    _repo_temp: tempfile::TempDir,
    _home_temp: tempfile::TempDir,
}

impl Sandbox {
    /// Copy a named fixture from `tests/fixtures` into a new sandbox.
    pub fn new(fixture: &str) -> Self {
        let repo_temp = tempfile::tempdir().expect("a temporary directory");
        let home_temp = tempfile::tempdir().expect("a temporary directory");

        let repo = repo_temp.path().join(fixture);
        copy_tree(&fixture_path(fixture), &repo);

        let home = home_temp.path().to_path_buf();
        let state = home.join("auditeur");
        fs::create_dir_all(&state).expect("the state directory");

        Self {
            repo,
            state,
            home,
            _repo_temp: repo_temp,
            _home_temp: home_temp,
        }
    }

    /// The repository under audit.
    pub fn repo(&self) -> &Path {
        &self.repo
    }

    /// The Auditeur state directory, the home.
    pub fn state(&self) -> &Path {
        &self.state
    }

    /// The temporary `HOME` the sandbox runs with.
    pub fn home_dir(&self) -> &Path {
        &self.home
    }

    /// The log file of the state directory.
    pub fn log_file(&self) -> PathBuf {
        self.state.join("logs/auditeur.log")
    }

    /// Every file under the log directory, sorted.
    pub fn log_files(&self) -> Vec<PathBuf> {
        walk_files(&self.state.join("logs"))
    }

    /// The contents of the log file, or an empty string when it does not exist.
    pub fn log_text(&self) -> String {
        fs::read_to_string(self.log_file()).unwrap_or_default()
    }

    /// A command with the environment scrubbed and the working directory inside
    /// the repository, so a bare `auditeur` audits the current directory.
    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(BIN);
        command.current_dir(&self.repo);
        for (key, _) in std::env::vars() {
            if key.starts_with("AUDITEUR_") {
                command.env_remove(key);
            }
        }
        command
            .env("HOME", &self.home)
            .env("AUDITEUR_HOME", &self.state)
            .args(args);
        command
    }

    /// Run a command and collect its output.
    pub fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("the binary runs")
    }

    /// Run the bare default command: audit the current directory.
    pub fn audit(&self) -> Output {
        self.run(&[])
    }

    /// Run with extra environment variables set for the child only.
    pub fn run_with_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = self.command(args);
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().expect("the binary runs")
    }

    /// Write one of the configuration documents.
    pub fn write_config(&self, file: &str, content: &str) {
        let dir = self.state.join("config");
        fs::create_dir_all(&dir).expect("the config directory");
        fs::write(dir.join(file), content).expect("the configuration file");
    }

    /// Every report written into the project directory.
    pub fn reports(&self) -> Vec<PathBuf> {
        let mut reports: Vec<PathBuf> = walk_files(&self.state)
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().starts_with("audit_"))
                    .unwrap_or(false)
            })
            .collect();
        reports.sort();
        reports
    }

    /// The single report of a run.
    pub fn report(&self) -> PathBuf {
        let reports = self.reports();
        assert_eq!(reports.len(), 1, "expected exactly one report: {reports:?}");
        reports.into_iter().next().unwrap()
    }

    /// The report's text.
    pub fn report_text(&self) -> String {
        fs::read_to_string(self.report()).expect("the report is readable")
    }

    /// The single run directory.
    pub fn run_dir(&self) -> PathBuf {
        let dirs: Vec<PathBuf> = fs::read_dir(self.state.join("runs"))
            .expect("the runs directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect();
        assert_eq!(dirs.len(), 1, "expected exactly one run: {dirs:?}");
        dirs.into_iter().next().unwrap()
    }

    /// The run manifest.
    pub fn manifest(&self) -> serde_json::Value {
        read_json(&self.run_dir().join("manifest.json"))
    }

    /// All findings of the run.
    pub fn findings(&self) -> Vec<serde_json::Value> {
        read_json(&self.run_dir().join("findings.json"))["findings"]
            .as_array()
            .expect("findings is an array")
            .clone()
    }

    /// All evidence of the run.
    pub fn evidence(&self) -> Vec<serde_json::Value> {
        read_json(&self.run_dir().join("evidence.json"))["evidence"]
            .as_array()
            .expect("evidence is an array")
            .clone()
    }

    /// Every artifact file of the run.
    pub fn artifact_files(&self) -> Vec<PathBuf> {
        let dir = self.run_dir();
        let mut files = walk_files(&dir);
        files.sort();
        files
    }
}

/// Path of a fixture inside this crate.
pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// The fixtures used by the language-detection and read-only tests.
pub const FIXTURES: &[(&str, &str)] = &[
    ("rust-app", "rust"),
    ("go-app", "go"),
    ("python-app", "python"),
    ("node-app", "nodejs"),
    ("leaky-app", "python"),
];

/// Copy a directory tree.
pub fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("the destination directory");
    for entry in fs::read_dir(from).expect("the source directory") {
        let entry = entry.expect("a directory entry");
        let target = to.join(entry.file_name());
        let file_type = entry.file_type().expect("the entry type");
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target);
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target).expect("a copied file");
        }
        // Symlinks are not followed: the fixtures do not contain any, and
        // following them would make the sandbox able to escape its own tree.
    }
}

/// Every file under a root, recursively.
pub fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            match entry.file_type() {
                Ok(file_type) if file_type.is_dir() => stack.push(path),
                Ok(file_type) if file_type.is_file() => files.push(path),
                _ => {}
            }
        }
    }
    files.sort();
    files
}

/// A content digest of every file under a root, keyed by relative path.
///
/// Size and hash together: a change that preserves length still fails the test,
/// and a truncated file is caught even if the hash were somehow preserved.
pub fn digest_tree(root: &Path) -> BTreeMap<String, String> {
    let mut digest = BTreeMap::new();
    for path in walk_files(root) {
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "cannot read {} while fingerprinting: {error}",
                path.display()
            )
        });
        digest.insert(relative, format!("{}:{}", bytes.len(), sha256_hex(&bytes)));
    }
    digest
}

/// Hex SHA-256 of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Read a JSON file.
pub fn read_json(path: &Path) -> serde_json::Value {
    let text = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("cannot read {}: {error}", path.display());
    });
    serde_json::from_str(&text).unwrap_or_else(|error| {
        panic!("{} is not valid JSON: {error}", path.display());
    })
}

/// The exit code of a finished process.
pub fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

/// Standard output as text.
pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Standard error as text.
pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
