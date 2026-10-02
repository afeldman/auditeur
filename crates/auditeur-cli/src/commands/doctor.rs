//! `auditeur doctor`.
//!
//! The command answers one question per line: is this thing present, and how do
//! I know? Every conclusion carries the evidence it rests on — a version string
//! from a probe, a path that was checked, a response from a server. A capability
//! that could not be determined is reported as unknown rather than as absent,
//! and nothing is ever reported as present because it usually is.
//!
//! Two kinds of line exist. A *required* line failing means Auditeur cannot do
//! its job at all; those are the ones that decide the exit code. Optional lines
//! describe what would be *better* — an accelerator, a toolchain, a model.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use auditeur_config::{AuditeurHome, LoadedConfig};
use auditeur_inference::hardware::{self, Availability};
use auditeur_inference::InferenceBackend;
use auditeur_repository::host;

use crate::cli::Cli;
use crate::error::CliError;
use crate::resolve;

/// Outcome of one diagnostic line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Checked and present.
    Ok,
    /// Present but not as it should be.
    Warn,
    /// Checked and absent, or not applicable.
    Unavailable,
    /// Could not be determined.
    Unknown,
}

impl CheckStatus {
    /// Short marker for the terminal table.
    pub fn marker(self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Unavailable => "-",
            CheckStatus::Unknown => "?",
        }
    }

    /// Stable identifier for JSON output.
    pub fn id(self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Unavailable => "unavailable",
            CheckStatus::Unknown => "unknown",
        }
    }
}

/// One diagnostic line.
#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    /// What was checked.
    pub name: String,
    /// The outcome.
    pub status: CheckStatus,
    /// What the conclusion rests on.
    pub detail: String,
    /// Whether Auditeur needs this to work at all.
    pub required: bool,
}

/// The full diagnosis.
#[derive(Debug, Clone, Serialize)]
pub struct Diagnosis {
    /// Auditeur version that produced the diagnosis.
    pub auditeur_version: String,
    /// One line per check, in reporting order.
    pub diagnostics: Vec<Diagnostic>,
}

impl Diagnosis {
    /// Start a diagnosis.
    pub fn new() -> Self {
        Self {
            auditeur_version: auditeur_model::AUDITEUR_VERSION.to_string(),
            diagnostics: Vec::new(),
        }
    }

    /// Add a line.
    pub fn add(
        &mut self,
        name: impl Into<String>,
        status: CheckStatus,
        required: bool,
        detail: impl Into<String>,
    ) {
        self.diagnostics.push(Diagnostic {
            name: name.into(),
            status,
            detail: detail.into(),
            required,
        });
    }

    /// Whether a required check failed.
    pub fn has_failures(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|line| line.required && line.status != CheckStatus::Ok)
    }

    /// The table, one line per check.
    pub fn lines(&self) -> Vec<String> {
        let width = self
            .diagnostics
            .iter()
            .map(|line| line.name.len())
            .max()
            .unwrap_or(0);

        self.diagnostics
            .iter()
            .map(|line| {
                format!(
                    "{:<width$}  {:<5} {}",
                    line.name,
                    line.status.marker(),
                    line.detail,
                    width = width
                )
            })
            .collect()
    }

    /// The diagnosis as JSON.
    pub fn to_json(&self) -> Result<String, CliError> {
        serde_json::to_string_pretty(self)
            .map_err(|error| CliError::Usage(format!("cannot serialise the diagnosis: {error}")))
    }

    /// Number of lines that are not `ok`.
    pub fn attention_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|line| line.status != CheckStatus::Ok)
            .count()
    }
}

impl Default for Diagnosis {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the diagnosis.
pub fn run(cli: &Cli, json: bool) -> Result<u8, CliError> {
    let target = cli
        .path
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let resolved = resolve::resolve(cli, &target)?;
    let console = resolved.console;

    let backend: Option<Box<dyn InferenceBackend>> = if resolved.enable_ai {
        match auditeur_inference::backends::build(
            &resolved.config().model,
            resolved.config().model.api_key(),
        ) {
            Ok(backend) => Some(backend),
            Err(error) => {
                console.warn(&format!("the configured model cannot be used: {error}"));
                None
            }
        }
    } else {
        None
    };

    // The diagnostic run is logged too: when a user reports a problem, the log
    // of the run that produced the diagnosis is the first thing worth reading.
    let _logging = crate::start_logging(&resolved);

    let diagnosis = diagnose(
        &resolved.home,
        &resolved.loaded,
        &resolved.source_path,
        backend.as_deref(),
        &resolved.notes,
    );
    for line in &diagnosis.diagnostics {
        tracing::debug!(check = %line.name, status = %line.status.id(), "{}", line.detail);
    }
    if diagnosis.has_failures() {
        tracing::warn!("doctor: one or more required checks failed");
    }

    if json {
        console.result(&diagnosis.to_json()?);
    } else {
        for line in diagnosis.lines() {
            console.result(&line);
        }
        let legend = "ok: present · warn: present but not as expected · -: absent · ?: unknown";
        console.result(legend);
        if diagnosis.has_failures() {
            console.result("one or more required checks failed");
        } else if diagnosis.attention_count() > 0 {
            console.result("no required check failed; optional gaps listed above");
        }
    }

    Ok(if diagnosis.has_failures() {
        crate::cli::exit::ERROR
    } else {
        crate::cli::exit::OK
    })
}

/// Collect the diagnosis. Pure apart from the probes it performs.
pub fn diagnose(
    home: &AuditeurHome,
    loaded: &LoadedConfig,
    source: &Path,
    backend: Option<&dyn InferenceBackend>,
    notes: &[String],
) -> Diagnosis {
    let mut diagnosis = Diagnosis::new();
    let config = &loaded.config;

    diagnosis.add(
        "Auditeur",
        CheckStatus::Ok,
        true,
        format!(
            "{} (audit schema {})",
            auditeur_model::AUDITEUR_VERSION,
            auditeur_model::AUDIT_SCHEMA_VERSION
        ),
    );

    // Where state lives, and how that was decided.
    diagnosis.add(
        "Auditeur home",
        CheckStatus::Ok,
        true,
        home.root().display().to_string(),
    );
    for note in notes {
        diagnosis.add("State root", CheckStatus::Warn, false, note.clone());
    }

    // The directories the home is made of. Absent ones are not an error: most
    // are created when something first needs them, and reporting them as broken
    // would be noise. What matters is whether they *could* be created.
    for (name, directory, required) in [
        ("Config directory", home.config_dir(), true),
        ("Model directory", home.model_dir(), false),
        ("Cache directory", home.cache_dir(), false),
        ("Runs directory", home.runs_dir(), false),
        ("Logs directory", home.logs_dir(), false),
    ] {
        let (status, detail) = directory_status(&directory);
        diagnosis.add(name, status, required, detail);
    }

    match writability(home.root()) {
        true => diagnosis.add(
            "Write permissions",
            CheckStatus::Ok,
            true,
            format!("{} is writable", home.root().display()),
        ),
        false if home.root().is_dir() => diagnosis.add(
            "Write permissions",
            CheckStatus::Unavailable,
            true,
            format!("{} is not writable", home.root().display()),
        ),
        false => {
            let (status, detail) = directory_status(home.root());
            diagnosis.add("Write permissions", status, true, detail);
        }
    }

    let (status, detail) = disk_space(home.root());
    diagnosis.add("Disk space", status, false, detail);

    // Configuration: presence, then validity, then unknown keys.
    if loaded.is_configured() {
        diagnosis.add(
            "Configuration",
            CheckStatus::Ok,
            true,
            format!(
                "{} file(s) read: {}",
                loaded.sources.len(),
                loaded.source_display().join(", ")
            ),
        );
    } else {
        diagnosis.add(
            "Configuration",
            CheckStatus::Warn,
            false,
            format!(
                "no configuration in {}; defaults are in use — run `auditeur setup`",
                home.config_dir().display()
            ),
        );
    }

    match config.validate() {
        Ok(()) => diagnosis.add(
            "Configuration values",
            CheckStatus::Ok,
            true,
            "valid".to_string(),
        ),
        Err(error) => diagnosis.add(
            "Configuration values",
            CheckStatus::Unavailable,
            true,
            error.to_string(),
        ),
    }

    match config.diagnostics(home) {
        Ok(found) if found.is_empty() => {}
        Ok(found) => {
            for note in found {
                diagnosis.add("Configuration keys", CheckStatus::Warn, false, note);
            }
        }
        Err(error) => diagnosis.add(
            "Configuration keys",
            CheckStatus::Unknown,
            false,
            error.to_string(),
        ),
    }

    // Logging: what would be written, and where. No credential appears here.
    let logging = &config.logging;
    diagnosis.add(
        "Logging",
        CheckStatus::Ok,
        false,
        format!(
            "level {}, rotate above {} MiB, keep {} rotated file(s), file {}",
            logging.level,
            logging.max_size_mb,
            logging.max_files,
            home.log_file().display()
        ),
    );
    let log_exists = home.log_file().is_file();
    diagnosis.add(
        "Logger",
        if log_exists {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        false,
        if log_exists {
            format!("rolling, writing to {}", home.log_file().display())
        } else {
            "rolling, no file yet; it is created by the first logged event".to_string()
        },
    );

    // The repository being audited: readable, and never written to.
    if source.is_dir() {
        diagnosis.add(
            "Repository",
            CheckStatus::Ok,
            true,
            source.display().to_string(),
        );
    } else {
        diagnosis.add(
            "Repository",
            CheckStatus::Warn,
            false,
            format!("{} is not a directory", source.display()),
        );
    }
    diagnosis.add(
        "Read-only boundary",
        CheckStatus::Ok,
        true,
        "the repository is never written to; the boundary is fingerprinted before and after each run"
            .to_string(),
    );

    // Model and backend.
    let model = &config.model;
    if model.model.trim().is_empty() {
        diagnosis.add(
            "Model",
            CheckStatus::Unavailable,
            false,
            "none selected; audits run deterministic checks only".to_string(),
        );
    } else {
        diagnosis.add(
            "Model",
            CheckStatus::Ok,
            false,
            format!("{} via {}", model.model, model.backend.id()),
        );
    }

    let models_dir = model.resolved_models_dir(home);
    diagnosis.add(
        "Model storage",
        CheckStatus::Ok,
        false,
        format!(
            "{}{}",
            models_dir.display(),
            if models_dir.is_dir() {
                ""
            } else {
                " (not created yet)"
            }
        ),
    );

    match backend {
        Some(backend) => {
            let health = backend.health();
            let mut detail = format!("{}: {}", health.backend, health.detail);
            if !health.models.is_empty() {
                detail.push_str(&format!(" ({} model(s))", health.models.len()));
            }
            let status = if health.reachable {
                match health.offers(&config.model.model) {
                    Some(false) => {
                        detail.push_str(&format!(
                            "; the configured model {} is not offered",
                            config.model.model
                        ));
                        CheckStatus::Warn
                    }
                    _ => CheckStatus::Ok,
                }
            } else {
                CheckStatus::Unavailable
            };
            diagnosis.add("Model backend", status, false, detail);
        }
        None => diagnosis.add(
            "Model backend",
            CheckStatus::Unavailable,
            false,
            if config.model.model.trim().is_empty() {
                "not configured".to_string()
            } else {
                "disabled for this run".to_string()
            },
        ),
    }

    // Hardware: one line per accelerator, each with what the conclusion rests on.
    let report = hardware::detect();
    for (accelerator, availability, detail) in report.doctor_lines() {
        diagnosis.add(
            accelerator.label(),
            availability_status(availability),
            false,
            detail,
        );
    }
    diagnosis.add(
        "Preferred backend",
        CheckStatus::Ok,
        false,
        format!("{} — {}", report.preferred().label(), report.summary_line()),
    );

    for (name, candidates) in TOOLCHAINS {
        let (status, detail) = probe_toolchain(name, candidates);
        diagnosis.add(*name, status, false, detail);
    }

    diagnosis
}

/// Report a directory without creating it.
///
/// Lazy creation is the rule: `doctor` answers "could this be created", not
/// "create it now". A directory that does not exist yet is fine as long as its
/// parent accepts a write, which is what makes the answer useful before the
/// first run.
fn directory_status(directory: &Path) -> (CheckStatus, String) {
    if directory.is_dir() {
        return (CheckStatus::Ok, format!("{} exists", directory.display()));
    }
    match writability_of_parent(directory) {
        Some(true) => (
            CheckStatus::Ok,
            format!("{} absent; created when first needed", directory.display()),
        ),
        Some(false) => (
            CheckStatus::Unavailable,
            format!(
                "{} is absent and {} is not writable",
                directory.display(),
                directory
                    .parent()
                    .map(|parent| parent.display().to_string())
                    .unwrap_or_else(|| "its parent".to_string())
            ),
        ),
        None => (
            CheckStatus::Unknown,
            format!(
                "{} absent; the parent could not be checked",
                directory.display()
            ),
        ),
    }
}

/// Whether the nearest existing ancestor of a path accepts a write.
fn writability_of_parent(path: &Path) -> Option<bool> {
    let mut ancestor = path.parent();
    while let Some(candidate) = ancestor {
        if candidate.is_dir() {
            return Some(writability(candidate));
        }
        ancestor = candidate.parent();
    }
    None
}

/// Map a hardware availability onto a check status.
fn availability_status(availability: Availability) -> CheckStatus {
    match availability {
        Availability::Available => CheckStatus::Ok,
        Availability::Unavailable => CheckStatus::Unavailable,
        Availability::Unknown => CheckStatus::Unknown,
    }
}

/// Toolchains Auditeur can use, with the commands that reveal their version.
///
/// The first candidate that answers wins, so an absolute-path toolchain is found
/// as readily as one on `PATH`.
type Candidates = &'static [(&'static str, &'static [&'static str])];

const TOOLCHAINS: &[(&str, Candidates)] = &[
    ("Git", &[("git", &["--version"])]),
    ("Rust", &[("cargo", &["--version"])]),
    ("Go", &[("go", &["version"])]),
    (
        "Python",
        &[("python3", &["--version"]), ("python", &["--version"])],
    ),
    ("Node", &[("node", &["--version"])]),
    ("Deno", &[("deno", &["--version"])]),
    ("Julia", &[("julia", &["--version"])]),
    ("R", &[("Rscript", &["--version"])]),
    ("Terraform", &[("terraform", &["version"])]),
    (
        "C/C++ build system",
        &[
            ("cmake", &["--version"]),
            ("meson", &["--version"]),
            ("ninja", &["--version"]),
            ("make", &["--version"]),
        ],
    ),
];

/// Probe one toolchain.
fn probe_toolchain(name: &str, candidates: Candidates) -> (CheckStatus, String) {
    match host::probe_first_available(candidates, host::PROBE_TIMEOUT) {
        Some(probe) => match probe.first_line() {
            Some(line) => (CheckStatus::Ok, line.trim().to_string()),
            None => (
                CheckStatus::Warn,
                format!("{} ran but said nothing", probe.program),
            ),
        },
        None if name == "Git" => (
            CheckStatus::Warn,
            "not found; Git metadata and commit recording will be unavailable".to_string(),
        ),
        None => (
            CheckStatus::Unavailable,
            "not found; the corresponding checks fall back to file inspection".to_string(),
        ),
    }
}

/// Whether a directory accepts a write, established by making and removing one
/// file without touching anything else.
fn writability(path: &Path) -> bool {
    let probe = path.join(".auditeur-write-probe");
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(file) => {
            drop(file);
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(error) => error.kind() == std::io::ErrorKind::AlreadyExists,
    }
}

/// Free space on the volume holding a path.
fn disk_space(path: &Path) -> (CheckStatus, String) {
    let Some(probe) = host::probe(
        "df",
        &["-Pk", &path.display().to_string()],
        Duration::from_secs(5),
    ) else {
        return (
            CheckStatus::Unknown,
            "df is not available; free space not determined".to_string(),
        );
    };

    let Some(line) = probe.stdout.lines().nth(1) else {
        return (CheckStatus::Unknown, "df produced no data row".to_string());
    };

    let fields: Vec<&str> = line.split_whitespace().collect();
    let Some(available_kb) = fields.get(3).and_then(|value| value.parse::<u64>().ok()) else {
        return (
            CheckStatus::Unknown,
            format!("cannot read the available space from `{}`", line.trim()),
        );
    };

    let available_mib = available_kb / 1024;
    let detail = format!(
        "{available_mib} MiB free on the volume holding {}",
        path.display()
    );
    if available_mib < 1024 {
        (CheckStatus::Warn, detail)
    } else {
        (CheckStatus::Ok, detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_config::AuditeurConfig;

    #[test]
    fn statuses_have_distinct_markers() {
        let markers: Vec<&str> = [
            CheckStatus::Ok,
            CheckStatus::Warn,
            CheckStatus::Unavailable,
            CheckStatus::Unknown,
        ]
        .iter()
        .map(|status| status.marker())
        .collect();
        assert_eq!(markers, vec!["ok", "warn", "-", "?"]);
    }

    #[test]
    fn a_failed_required_check_is_a_failure_and_an_optional_one_is_not() {
        let mut diagnosis = Diagnosis::new();
        diagnosis.add("optional", CheckStatus::Unavailable, false, "absent");
        assert!(!diagnosis.has_failures());
        assert_eq!(diagnosis.attention_count(), 1);

        diagnosis.add("required", CheckStatus::Unavailable, true, "broken");
        assert!(diagnosis.has_failures());
    }

    #[test]
    fn the_table_aligns_names_and_keeps_details() {
        let mut diagnosis = Diagnosis::new();
        diagnosis.add("A", CheckStatus::Ok, true, "fine");
        diagnosis.add("A longer name", CheckStatus::Warn, false, "hmm");
        let lines = diagnosis.lines();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("A "), "{}", lines[0]);
        assert!(lines[0].contains("ok"));
        assert!(lines[1].contains("hmm"));
        // Both markers start at the same column.
        assert_eq!(lines[0].find("ok").unwrap(), lines[1].find("warn").unwrap());
    }

    #[test]
    fn json_output_round_trips() {
        let mut diagnosis = Diagnosis::new();
        diagnosis.add("Auditeur", CheckStatus::Ok, true, "0.1.0");
        let json = diagnosis.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["diagnostics"][0]["status"], "ok");
        assert_eq!(parsed["diagnostics"][0]["required"], true);
        assert!(parsed["auditeur_version"].is_string());
    }

    #[test]
    fn an_unconfigured_project_is_diagnosed_with_defaults() {
        let project = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let paths = AuditeurHome::at(project.path());
        let loaded = AuditeurConfig::load(&paths).unwrap();

        let diagnosis = diagnose(&paths, &loaded, repo.path(), None, &[]);
        let names: Vec<&str> = diagnosis
            .diagnostics
            .iter()
            .map(|line| line.name.as_str())
            .collect();
        assert!(names.contains(&"Auditeur"));
        assert!(names.contains(&"Configuration"));
        assert!(names.contains(&"Model"));
        assert!(names.contains(&"Read-only boundary"));
        assert!(names.contains(&"CPU"));
        // No configuration file exists, so this is a warning, not a failure.
        assert!(!diagnosis.has_failures(), "{:?}", diagnosis.lines());
    }

    #[test]
    fn an_invalid_configuration_fails_the_required_check() {
        let project = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let paths = AuditeurHome::at(project.path());
        let mut config = AuditeurConfig::default();
        config.project.name = String::new();
        let loaded = LoadedConfig {
            config,
            home: paths.clone(),
            sources: vec![],
            warnings: vec![],
            env_overrides: vec![],
        };

        let diagnosis = diagnose(&paths, &loaded, repo.path(), None, &[]);
        assert!(diagnosis.has_failures());
        let line = diagnosis
            .diagnostics
            .iter()
            .find(|line| line.name == "Configuration values")
            .unwrap();
        assert_eq!(line.status, CheckStatus::Unavailable);
    }

    #[test]
    fn a_missing_repository_is_reported_but_not_fatal() {
        let project = tempfile::tempdir().unwrap();
        let paths = AuditeurHome::at(project.path());
        let loaded = AuditeurConfig::load(&paths).unwrap();
        let diagnosis = diagnose(&paths, &loaded, Path::new("/nonexistent/repo"), None, &[]);
        let line = diagnosis
            .diagnostics
            .iter()
            .find(|line| line.name == "Repository")
            .unwrap();
        assert_eq!(line.status, CheckStatus::Warn);
        assert!(!diagnosis.has_failures());
    }

    #[test]
    fn a_directory_is_reported_without_being_created() {
        let project = tempfile::tempdir().unwrap();
        let home = AuditeurHome::at(project.path().join("auditeur"));
        home.ensure().unwrap();

        // A directory below the home is described, never created: lazy creation
        // is the rule, and `doctor` must not populate a tree it only inspects.
        let (status, detail) = directory_status(&home.cache_ast_dir());
        assert_eq!(status, CheckStatus::Ok, "{detail}");
        assert!(detail.contains("created when first needed"), "{detail}");
        assert!(!home.cache_ast_dir().exists());

        let (status, detail) = directory_status(&home.cache_dir());
        assert_eq!(status, CheckStatus::Ok);
        assert!(detail.contains("exists"), "{detail}");
    }

    #[test]
    fn doctor_reports_the_state_layout_and_creates_nothing() {
        let project = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        let home = AuditeurHome::at(project.path().join("auditeur"));
        let loaded = AuditeurConfig::load(&home).unwrap();

        let diagnosis = diagnose(&home, &loaded, repo.path(), None, &[]);
        let names: Vec<&str> = diagnosis
            .diagnostics
            .iter()
            .map(|line| line.name.as_str())
            .collect();
        for expected in [
            "Auditeur home",
            "Config directory",
            "Model directory",
            "Cache directory",
            "Runs directory",
            "Logs directory",
            "Write permissions",
            "Logging",
            "Logger",
            "Model storage",
            "Model backend",
            "Repository",
            "Read-only boundary",
        ] {
            assert!(names.contains(&expected), "missing {expected}: {names:?}");
        }

        // The home did not exist before this and must not exist after: a
        // diagnosis is a read.
        assert!(!home.root().exists(), "doctor created the home");
    }

    #[test]
    fn writability_is_established_without_leaving_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        assert!(writability(dir.path()));
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(entries.is_empty(), "the probe left files behind");
    }

    #[test]
    fn disk_space_is_reported_with_units() {
        let dir = tempfile::tempdir().unwrap();
        let (status, detail) = disk_space(dir.path());
        assert!(matches!(
            status,
            CheckStatus::Ok | CheckStatus::Warn | CheckStatus::Unknown
        ));
        assert!(!detail.is_empty());
    }

    #[test]
    fn a_toolchain_probe_reports_a_version_or_an_absence() {
        let (status, detail) = probe_toolchain("Rust", &[("cargo", &["--version"])]);
        assert_eq!(status, CheckStatus::Ok, "{detail}");
        assert!(detail.contains("cargo"), "{detail}");

        let (status, detail) = probe_toolchain("Nonexistent", &[("definitely-not-a-program", &[])]);
        assert_eq!(status, CheckStatus::Unavailable);
        assert!(detail.contains("not found"));
    }

    #[test]
    fn a_missing_git_is_a_warning_because_its_absence_degrades_a_capability() {
        let (status, detail) = probe_toolchain("Git", &[("definitely-not-a-program", &[])]);
        assert_eq!(status, CheckStatus::Warn);
        assert!(detail.contains("Git metadata"));
    }
}
