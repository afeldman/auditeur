//! The execution boundary.
//!
//! Auditeur executes external tools only through [`CommandRunner`], which
//! enforces every constraint the read-only guarantee needs:
//!
//! * **argv only** — no shell, so quoting and metacharacter injection are
//!   structurally impossible.
//! * **allowlist** — a program not named in the policy is refused, and the
//!   policy is built from configuration, not from repository content.
//! * **scrubbed environment** — the child inherits only `PATH` and `HOME`;
//!   every other variable of the auditor's environment (API keys, tokens,
//!   proxy credentials) is dropped rather than leaked into tool output.
//! * **cache redirection** — `CARGO_TARGET_DIR`, `GOCACHE`, `PYTHONPYCACHEPREFIX`,
//!   `PYTEST_ADDOPTS`, `npm_config_cache`, `DENO_DIR`, `UV_CACHE_DIR`,
//!   `TF_DATA_DIR` and friends are pointed at the Auditeur cache, so tools that
//!   would normally write inside the repository write outside it instead.
//! * **working directory pinned** to the repository root; **stdin closed**.
//! * **hard timeout** and **output caps**, so a hung or noisy tool cannot
//!   stall or exhaust the audit.

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use auditeur_model::redact::redact_text;
use auditeur_model::ToolExecution;

use crate::error::RepositoryError;

/// Bytes read from stdout/stderr per stream before truncation.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024;
/// Default per-command time budget.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// What may be executed, and under which bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPolicy {
    /// Master switch. When `false`, every request is refused.
    pub enabled: bool,
    /// Program names (matched on the file name) that may be executed.
    pub allowed_programs: Vec<String>,
    /// Per-command time budget.
    pub timeout: Duration,
    /// Per-stream output cap in bytes.
    pub max_output_bytes: usize,
}

impl Default for ExecPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_programs: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

impl ExecPolicy {
    /// A policy that permits exactly `programs`, for internal use by Auditeur's
    /// own read-only probes.
    pub fn for_programs<I, S>(programs: I, timeout: Duration) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            enabled: true,
            allowed_programs: programs.into_iter().map(Into::into).collect(),
            timeout,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }

    /// Whether `program` may be executed, comparing on the file name so that
    /// `/usr/bin/cargo` and `cargo` are the same program.
    pub fn allows(&self, program: &str) -> bool {
        let requested = program_file_name(program);
        self.allowed_programs
            .iter()
            .any(|allowed| program_file_name(allowed) == requested)
    }
}

/// The file name of a program path, for allowlist comparison.
fn program_file_name(program: &str) -> String {
    Path::new(program)
        .file_name()
        .map(OsStr::to_string_lossy)
        .map(|value| value.to_string())
        .unwrap_or_else(|| program.to_string())
}

/// Whether `candidate` lies inside `container`, or is `container`.
///
/// Equality counts as inside: a cache root equal to the repository root *is* the
/// audited tree, and the question this answers is "would a write here land in the
/// repository?".
///
/// Both paths are canonicalised when they exist. A path that does not exist yet
/// (a cache directory about to be created) is compared in its raw form, which
/// is a deliberate approximation: it errs towards reporting containment, and a
/// false positive here only refuses an execution rather than permitting a write.
pub fn is_path_inside(candidate: &Path, container: &Path) -> bool {
    let canonical_candidate = canonicalize_lenient(candidate);
    let canonical_container = canonicalize_lenient(container);
    canonical_candidate.starts_with(&canonical_container)
}

/// Canonicalise as far as the path exists, then re-append the missing tail.
///
/// `std::fs::canonicalize` fails for a path that does not exist yet, and on
/// macOS the system temporary directory is a symlink (`/var` → `/private/var`),
/// so comparing a raw candidate against a canonical container would silently
/// report "not contained" for exactly the paths this function must catch.
fn canonicalize_lenient(path: &Path) -> PathBuf {
    if let Ok(resolved) = std::fs::canonicalize(path) {
        return resolved;
    }
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();
    // The name is copied out before `current` is reassigned, which is what keeps
    // this a `while let` rather than a loop with a break in a match arm.
    while let Some(name) = current.file_name().map(|name| name.to_os_string()) {
        missing.push(name);
        let Some(parent) = current.parent().map(Path::to_path_buf) else {
            break;
        };
        current = parent;
        if let Ok(resolved) = std::fs::canonicalize(&current) {
            let mut result = resolved;
            for name in missing.iter().rev() {
                result.push(name);
            }
            return result;
        }
    }
    path.to_path_buf()
}

/// A request to execute one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRequest {
    /// Program to execute.
    pub program: String,
    /// Arguments, passed as an argv array.
    pub args: Vec<String>,
    /// Why this command is being run; recorded in the manifest and logs.
    pub purpose: String,
}

impl CommandRequest {
    /// Build a request.
    pub fn new<I, S>(program: impl Into<String>, args: I, purpose: impl Into<String>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            purpose: purpose.into(),
        }
    }
}

/// The captured result of an executed command.
///
/// A non-zero exit code is **not** an error: a failing test run is evidence.
/// Errors are reserved for refusal, spawn failure and timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Program that ran.
    pub program: String,
    /// Arguments it received.
    pub args: Vec<String>,
    /// Exit code, absent when killed by a signal.
    pub exit_code: Option<i32>,
    /// Captured stdout, lossily decoded.
    pub stdout: String,
    /// Captured stderr, lossily decoded.
    pub stderr: String,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Whether either stream was truncated at the cap.
    pub truncated: bool,
}

impl CommandOutput {
    /// Whether the command exited successfully.
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }

    /// Redacted stdout, limited to `max_lines` lines.
    ///
    /// Use this — never `stdout` directly — when text is about to be logged,
    /// stored as evidence or sent to a model.
    pub fn redacted_stdout(&self, max_lines: usize) -> String {
        redact_text(&take_lines(&self.stdout, max_lines))
    }

    /// Redacted stderr, limited to `max_lines` lines.
    pub fn redacted_stderr(&self, max_lines: usize) -> String {
        redact_text(&take_lines(&self.stderr, max_lines))
    }

    /// A manifest record of this execution.
    pub fn to_record(&self) -> ToolExecution {
        ToolExecution {
            program: self.program.clone(),
            args: self.args.clone(),
            exit_code: self.exit_code,
            duration_ms: self.duration_ms,
            truncated: self.truncated,
        }
    }
}

fn take_lines(text: &str, max_lines: usize) -> String {
    text.lines().take(max_lines).collect::<Vec<_>>().join("\n")
}

/// Executes external commands under a [`ExecPolicy`].
#[derive(Debug, Clone)]
pub struct CommandRunner {
    repository_root: PathBuf,
    cache_root: PathBuf,
    policy: ExecPolicy,
}

impl CommandRunner {
    /// Create a runner pinned to a repository root and a cache root.
    ///
    /// `cache_root` must be outside the audited repository; the audit engine
    /// passes the project cache directory.
    pub fn new(
        repository_root: impl Into<PathBuf>,
        cache_root: impl Into<PathBuf>,
        policy: ExecPolicy,
    ) -> Self {
        Self {
            repository_root: repository_root.into(),
            cache_root: cache_root.into(),
            policy,
        }
    }

    /// The active policy.
    pub fn policy(&self) -> &ExecPolicy {
        &self.policy
    }

    /// Whether a program may be executed under the active policy.
    pub fn is_allowed(&self, program: &str) -> bool {
        self.policy.enabled && self.policy.allows(program)
    }

    /// Whether the configured cache root would write inside the repository.
    ///
    /// Exposed so callers can report this as a configuration error before an
    /// audit starts, rather than as a per-command failure during one.
    pub fn cache_root_inside_repository(&self) -> bool {
        is_path_inside(&self.cache_root, &self.repository_root)
    }

    /// The environment a child process receives.
    ///
    /// Exposed for tests and for `doctor`, which explains the boundary.
    pub fn child_environment(&self) -> Vec<(String, String)> {
        let cache = self.cache_root.to_string_lossy().to_string();
        let mut environment = Vec::with_capacity(28);
        for inherited in ["PATH", "HOME"] {
            if let Ok(value) = std::env::var(inherited) {
                environment.push((inherited.to_string(), value));
            }
        }
        for (key, value) in [
            ("LC_ALL", "C".to_string()),
            ("LANG", "C".to_string()),
            ("TERM", "dumb".to_string()),
            ("NO_COLOR", "1".to_string()),
            ("CLICOLOR", "0".to_string()),
            ("CI", "1".to_string()),
            ("TMPDIR", format!("{cache}/tmp")),
            ("XDG_CACHE_HOME", format!("{cache}/xdg")),
            // Language-ecosystem cache redirection: keeps tool output out of
            // the repository.
            ("CARGO_TARGET_DIR", format!("{cache}/cargo-target")),
            ("CARGO_INCREMENTAL", "0".to_string()),
            ("GOCACHE", format!("{cache}/go-build")),
            ("GOTMPDIR", format!("{cache}/tmp")),
            ("PYTHONDONTWRITEBYTECODE", "1".to_string()),
            ("PYTHONPYCACHEPREFIX", format!("{cache}/pycache")),
            ("PIP_NO_CACHE_DIR", "1".to_string()),
            ("PIP_DISABLE_PIP_VERSION_CHECK", "1".to_string()),
            ("PYTEST_ADDOPTS", "-p no:cacheprovider".to_string()),
            ("npm_config_cache", format!("{cache}/npm")),
            ("NPM_CONFIG_CACHE", format!("{cache}/npm")),
            ("NODE_REPL_HISTORY", format!("{cache}/node-history")),
            ("DENO_DIR", format!("{cache}/deno")),
            ("UV_CACHE_DIR", format!("{cache}/uv")),
            ("TF_DATA_DIR", format!("{cache}/terraform")),
            ("TF_IN_AUTOMATION", "1".to_string()),
            ("CHECKPOINT_DISABLE", "1".to_string()),
            ("JULIA_DEPOT_PATH", format!("{cache}/julia")),
        ] {
            environment.push((key.to_string(), value));
        }
        environment
    }

    /// Execute a command.
    pub fn run(&self, request: &CommandRequest) -> Result<CommandOutput, RepositoryError> {
        if !self.policy.enabled {
            return Err(RepositoryError::CommandNotPermitted {
                program: request.program.clone(),
                reason: "external tool execution is disabled (audit.run_external_tools = false)"
                    .to_string(),
            });
        }
        if !self.policy.allows(&request.program) {
            return Err(RepositoryError::CommandNotPermitted {
                program: request.program.clone(),
                reason: "not listed in audit.allowed_programs".to_string(),
            });
        }
        // A cache inside the audited repository would be a write into the
        // audited repository. Refuse before anything is created.
        if self.cache_root_inside_repository() {
            return Err(RepositoryError::CommandNotPermitted {
                program: request.program.clone(),
                reason: format!(
                    "cache directory {} is inside the audited repository {}; Auditeur will not write there",
                    self.cache_root.display(),
                    self.repository_root.display()
                ),
            });
        }

        // Best effort: tools need a writable temporary directory, and it must
        // not be inside the repository.
        let temporary = self.cache_root.join("tmp");
        let _ = std::fs::create_dir_all(&temporary);

        capture_command(
            &request.program,
            &request.args,
            &self.repository_root,
            &self.child_environment(),
            self.policy.timeout,
            self.policy.max_output_bytes,
        )
    }

    /// Execute a command and capture it as evidence-ready output, refusing to
    /// proceed if the command is not permitted.
    pub fn run_checked(&self, request: &CommandRequest) -> Result<CommandOutput, RepositoryError> {
        self.run(request)
    }
}

/// Execute one program and capture its output.
///
/// This is the single implementation of "spawn a process, drain both streams
/// without deadlocking, enforce a deadline, cap the output". It is used both by
/// [`CommandRunner`] (repository tool execution, allowlisted) and by
/// [`crate::host`] (host capability probing, outside the repository).
///
/// The caller owns the policy: this function does not check allowlists, because
/// a caller that reaches it has already decided what it is allowed to run.
pub fn capture_command(
    program: &str,
    args: &[String],
    working_directory: &Path,
    environment: &[(String, String)],
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<CommandOutput, RepositoryError> {
    let started = Instant::now();
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(working_directory)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in environment {
        command.env(key, value);
    }

    let mut child = command
        .spawn()
        .map_err(|source| RepositoryError::CommandSpawn {
            program: program.to_string(),
            source,
        })?;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let cap = max_output_bytes;
    let stdout_reader = std::thread::spawn(move || read_capped(stdout_pipe, cap));
    let stderr_reader = std::thread::spawn(move || read_capped(stderr_pipe, cap));

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(source) => {
                let _ = child.kill();
                return Err(RepositoryError::CommandSpawn {
                    program: program.to_string(),
                    source,
                });
            }
        }
    };

    let (stdout, stdout_truncated) = join_reader(stdout_reader);
    let (stderr, stderr_truncated) = join_reader(stderr_reader);
    let duration_ms = started.elapsed().as_millis() as u64;

    match status {
        None => Err(RepositoryError::CommandTimeout {
            program: program.to_string(),
            seconds: timeout.as_secs(),
        }),
        Some(status) => Ok(CommandOutput {
            program: program.to_string(),
            args: args.to_vec(),
            exit_code: status.code(),
            stdout,
            stderr,
            duration_ms,
            truncated: stdout_truncated || stderr_truncated,
        }),
    }
}

type CappedRead = (String, bool);

fn read_capped<R: Read + Send + 'static>(reader: Option<R>, cap: usize) -> CappedRead {
    let Some(mut reader) = reader else {
        return (String::new(), false);
    };
    let mut kept: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if kept.len() < cap {
                    let room = cap - kept.len();
                    let take = room.min(read);
                    kept.extend_from_slice(&buffer[..take]);
                    if take < read {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (String::from_utf8_lossy(&kept).into_owned(), truncated)
}

fn join_reader(handle: std::thread::JoinHandle<CappedRead>) -> CappedRead {
    handle.join().unwrap_or_else(|_| (String::new(), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A runner whose cache directory is a sibling of the repository root.
    ///
    /// Sibling, not parent: a cache inside the repository is refused by design,
    /// which has its own test.
    fn runner_with(programs: &[&str], timeout: Duration, max_output_bytes: usize) -> CommandRunner {
        let base = std::env::temp_dir().join("auditeur-exec-boundary-tests");
        let repository = base.join("repo");
        std::fs::create_dir_all(&repository).unwrap();
        CommandRunner::new(
            repository,
            base.join("cache"),
            ExecPolicy {
                enabled: true,
                allowed_programs: programs.iter().map(|name| (*name).to_string()).collect(),
                timeout,
                max_output_bytes,
            },
        )
    }

    fn runner(programs: &[&str]) -> CommandRunner {
        runner_with(programs, Duration::from_secs(10), 4096)
    }

    #[test]
    fn disabled_policy_refuses_everything() {
        let runner = CommandRunner::new(
            std::env::temp_dir(),
            std::env::temp_dir(),
            ExecPolicy::default(),
        );
        let error = runner
            .run(&CommandRequest::new("echo", ["hi"], "test"))
            .unwrap_err();
        assert!(matches!(error, RepositoryError::CommandNotPermitted { .. }));
        assert!(!runner.is_allowed("echo"));
    }

    #[test]
    fn programs_outside_the_allowlist_are_refused() {
        let runner = runner(&["echo"]);
        let error = runner
            .run(&CommandRequest::new("rm", ["-rf", "/"], "test"))
            .unwrap_err();
        match error {
            RepositoryError::CommandNotPermitted { program, reason } => {
                assert_eq!(program, "rm");
                assert!(reason.contains("allowed_programs"), "{reason}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn allowlist_matches_on_the_file_name() {
        let runner = runner(&["echo"]);
        assert!(runner.is_allowed("/bin/echo"));
        assert!(!runner.is_allowed("/bin/rm"));
    }

    #[test]
    fn a_cache_inside_the_repository_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let repository = temp.path().join("repo");
        std::fs::create_dir_all(repository.join("src")).unwrap();
        let runner = CommandRunner::new(
            &repository,
            repository.join(".auditeur-cache"),
            ExecPolicy::for_programs(["/bin/echo"], Duration::from_secs(10)),
        );
        assert!(runner.cache_root_inside_repository());
        let error = runner
            .run(&CommandRequest::new(
                "/bin/echo",
                ["hi"],
                "would write into the repository",
            ))
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("inside the audited repository"),
            "{message}"
        );
        assert!(
            !repository.join(".auditeur-cache").exists(),
            "nothing may be created inside the audited repository"
        );
    }

    #[test]
    fn a_cache_outside_the_repository_is_accepted() {
        let repository = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let runner = CommandRunner::new(
            repository.path(),
            cache.path(),
            ExecPolicy::for_programs(["/bin/echo"], Duration::from_secs(10)),
        );
        assert!(!runner.cache_root_inside_repository());
        assert!(runner
            .run(&CommandRequest::new("/bin/echo", ["hi"], "outside cache"))
            .is_ok());
        assert!(cache.path().join("tmp").is_dir());
    }

    #[test]
    fn containment_detection_handles_siblings_and_nonexistent_paths() {
        let temp = tempfile::tempdir().unwrap();
        let repository = temp.path().join("repo");
        std::fs::create_dir_all(&repository).unwrap();
        assert!(is_path_inside(
            &repository.join("not-yet-created"),
            &repository
        ));
        assert!(!is_path_inside(&temp.path().join("sibling"), &repository));
        // Equality counts: the repository root is inside itself, which is what
        // makes a cache root equal to it a refusal rather than a hazard.
        assert!(is_path_inside(&repository, &repository));
        assert!(!is_path_inside(
            &temp.path().join("repo-other"),
            &repository
        ));
    }

    #[test]
    fn arguments_are_passed_as_argv_not_through_a_shell() {
        let runner = runner(&["/bin/echo"]);
        let output = runner
            .run(&CommandRequest::new(
                "/bin/echo",
                ["hello; echo injected", "$(whoami)"],
                "argv safety",
            ))
            .unwrap();
        assert!(output.success());
        assert!(
            output.stdout.contains("hello; echo injected"),
            "{}",
            output.stdout
        );
        assert!(output.stdout.contains("$(whoami)"), "{}", output.stdout);
    }

    #[test]
    fn a_non_zero_exit_code_is_evidence_not_an_error() {
        let runner = runner(&["sh"]);
        let output = runner
            .run(&CommandRequest::new(
                "sh",
                ["-c", "exit 3"],
                "failing test run",
            ))
            .unwrap();
        assert!(!output.success());
        assert_eq!(output.exit_code, Some(3));
    }

    #[test]
    fn the_child_environment_is_scrubbed_and_redirected() {
        let runner = runner(&["sh"]);
        let output = runner
            .run(&CommandRequest::new(
                "sh",
                ["-c", "env"],
                "environment inspection",
            ))
            .unwrap();
        let environment: Vec<&str> = output.stdout.lines().collect();
        assert!(environment
            .iter()
            .any(|line| line.starts_with("CARGO_TARGET_DIR=")));
        assert!(environment
            .iter()
            .any(|line| line.starts_with("PYTHONDONTWRITEBYTECODE=1")));
        assert!(environment.iter().any(|line| line.starts_with("LC_ALL=C")));
        // Only PATH, HOME and the explicit set: no unrelated inherited state.
        assert!(
            environment.len() < 32,
            "environment too large: {environment:?}"
        );
        assert!(environment
            .iter()
            .all(|line| !line.starts_with("BASH_FUNC")));
    }

    #[test]
    fn output_is_truncated_at_the_cap() {
        let runner = runner_with(&["sh"], Duration::from_secs(10), 64);
        let output = runner
            .run(&CommandRequest::new(
                "sh",
                ["-c", "for i in $(seq 1 200); do echo line$i; done"],
                "noisy command",
            ))
            .unwrap();
        assert!(output.truncated);
        assert!(output.stdout.len() <= 64);
    }

    #[test]
    fn a_hanging_command_is_killed_at_the_deadline() {
        let runner = runner_with(&["sleep"], Duration::from_millis(300), 1024);
        let error = runner
            .run(&CommandRequest::new("sleep", ["30"], "hang"))
            .unwrap_err();
        assert!(matches!(error, RepositoryError::CommandTimeout { .. }));
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        let runner = runner(&["definitely-not-a-real-program-xyz"]);
        let error = runner
            .run(&CommandRequest::new(
                "definitely-not-a-real-program-xyz",
                Vec::<String>::new(),
                "missing",
            ))
            .unwrap_err();
        assert!(matches!(error, RepositoryError::CommandSpawn { .. }));
    }

    #[test]
    fn output_records_are_manifest_ready() {
        let runner = runner(&["/bin/echo"]);
        let output = runner
            .run(&CommandRequest::new("/bin/echo", ["hi"], "record"))
            .unwrap();
        let record = output.to_record();
        assert_eq!(record.program, "/bin/echo");
        assert_eq!(record.exit_code, Some(0));
        assert!(!record.truncated);
    }

    #[test]
    fn redacted_output_hides_secrets() {
        let runner = runner(&["sh"]);
        let output = runner
            .run(&CommandRequest::new(
                "sh",
                ["-c", "echo 'api_key = sk-abcdef1234567890'"],
                "secret in tool output",
            ))
            .unwrap();
        let redacted = output.redacted_stdout(10);
        assert!(!redacted.contains("sk-abcdef1234567890"), "{redacted}");
        assert!(redacted.contains("[REDACTED"), "{redacted}");
    }

    #[test]
    fn line_limits_apply_after_redaction() {
        let runner = runner(&["sh"]);
        let output = runner
            .run(&CommandRequest::new(
                "sh",
                ["-c", "printf 'a\\nb\\nc\\n'"],
                "lines",
            ))
            .unwrap();
        assert_eq!(output.redacted_stdout(2), "a\nb");
    }
}
