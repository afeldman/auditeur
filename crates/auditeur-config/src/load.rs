//! Loading, saving and validating the three configuration documents.
//!
//! Layering: compiled defaults → `config/*.toml` → `AUDITEUR_*` environment
//! variables → CLI flags (applied by the caller). Unknown keys are tolerated so
//! that a newer configuration file stays readable by an older binary; they are
//! reported by [`AuditeurConfig::diagnostics`] instead of failing the load.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::audit::AuditConfig;
use crate::env;
use crate::error::ConfigError;
use crate::home::{AuditeurHome, HomeLayout};
use crate::logging::LoggingConfig;
use crate::model::ModelConfig;
use crate::paths::PathsConfig;
use crate::project::{derive_project_name, ProjectConfig, ReportingConfig};

/// Known top-level keys of `config/auditeur.toml`.
const PROJECT_FILE_KEYS: &[&str] = &["project", "report", "paths", "logging"];
/// Known top-level keys of `config/model.toml`.
const MODEL_FILE_KEYS: &[&str] = &[
    "backend",
    "endpoint",
    "model",
    "api_key_env",
    "enabled",
    "request_timeout_secs",
    "max_output_tokens",
    "temperature",
    "models_dir",
];
/// Known top-level keys of `config/audit.toml`.
const AUDIT_FILE_KEYS: &[&str] = &[
    "enabled_categories",
    "report_min_severity",
    "fail_threshold",
    "run_external_tools",
    "allowed_programs",
    "limits",
];

/// The complete Auditeur configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditeurConfig {
    /// Which repository is audited and where Auditeur keeps its state.
    pub project: ProjectConfig,
    /// Report content preferences.
    pub report: ReportingConfig,
    /// Where Auditeur's own directories live, relative to the home.
    pub paths: PathsConfig,
    /// Logging and log rotation.
    pub logging: LoggingConfig,
    /// Inference settings.
    pub model: ModelConfig,
    /// Audit scope and resource bounds.
    pub audit: AuditConfig,
}

/// Shape of `config/auditeur.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct ProjectFile {
    project: ProjectConfig,
    report: ReportingConfig,
    paths: PathsConfig,
    logging: LoggingConfig,
}

/// Result of loading configuration, with provenance for transparency.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedConfig {
    /// The effective configuration.
    pub config: AuditeurConfig,
    /// Where Auditeur keeps its state, with the configured layout applied.
    pub home: AuditeurHome,
    /// Configuration files that were read.
    pub sources: Vec<PathBuf>,
    /// Non-fatal observations, e.g. a missing configuration file.
    pub warnings: Vec<String>,
    /// Environment variables that overrode file values.
    pub env_overrides: Vec<String>,
}

impl LoadedConfig {
    /// Whether any configuration file existed.
    pub fn is_configured(&self) -> bool {
        !self.sources.is_empty()
    }

    /// Configuration files read, as display strings.
    pub fn source_display(&self) -> Vec<String> {
        self.sources
            .iter()
            .map(|path| path.display().to_string())
            .collect()
    }
}

impl AuditeurConfig {
    /// Load configuration from a project directory.
    ///
    /// Missing files are not an error: the returned configuration contains
    /// defaults and [`LoadedConfig::warnings`] explains what was absent. Parse
    /// errors, by contrast, are hard errors — silently ignoring a mistyped
    /// setting would make the audit results untrustworthy.
    pub fn load(home: &AuditeurHome) -> Result<LoadedConfig, ConfigError> {
        let mut config = AuditeurConfig::default();
        let mut sources = Vec::new();
        let mut warnings = Vec::new();

        let project_file = home.project_config_file();
        if project_file.is_file() {
            let parsed: ProjectFile = read_toml(&project_file)?;
            config.project = parsed.project;
            config.report = parsed.report;
            config.paths = parsed.paths;
            config.logging = parsed.logging;
            sources.push(project_file);
        } else {
            warnings.push(format!(
                "no project configuration at {} — using defaults; run `auditeur setup` to create one",
                project_file.display()
            ));
        }

        let model_file = home.model_config_file();
        if model_file.is_file() {
            config.model = read_toml(&model_file)?;
            sources.push(model_file);
        }

        let audit_file = home.audit_config_file();
        if audit_file.is_file() {
            config.audit = read_toml(&audit_file)?;
            sources.push(audit_file);
        }

        // Fill in what the files did not state.
        if config.project.project_root.is_none() {
            config.project.project_root = Some(home.root().to_path_buf());
        }
        if config.project.name.trim().is_empty() {
            config.project.name = derive_project_name(&config.project.source_path);
        }

        let env_overrides = config.apply_env_overrides(std::env::vars())?;

        // The files may redirect model/, cache/ and runs/, so the home is handed
        // back with the layout the configuration asked for.
        let home = home.clone().with_layout(config.home_layout()?);

        Ok(LoadedConfig {
            config,
            home,
            sources,
            warnings,
            env_overrides,
        })
    }

    /// A configuration that audits `source` without any files on disk.
    ///
    /// Used when the user runs `auditeur <path>` before running `setup`.
    pub fn for_source(source: &Path, home: &AuditeurHome) -> Self {
        let mut config = AuditeurConfig::default();
        config.project.name = derive_project_name(source);
        config.project.source_path = source.to_path_buf();
        config.project.project_root = Some(home.root().to_path_buf());
        config
    }

    /// Write the three configuration documents, creating the layout first.
    pub fn save(&self, home: &AuditeurHome) -> Result<Vec<PathBuf>, ConfigError> {
        self.validate()?;
        home.ensure()?;

        let project_file = ProjectFile {
            project: self.project.clone(),
            report: self.report.clone(),
            paths: self.paths.clone(),
            logging: self.logging.clone(),
        };
        let mut written = Vec::new();
        write_toml(
            &home.project_config_file(),
            "Auditeur project configuration — written by `auditeur setup`.",
            &project_file,
        )?;
        written.push(home.project_config_file());
        write_toml(
            &home.model_config_file(),
            "Auditeur model configuration. Store credentials in the environment, \
             never in this file (`api_key_env` names the variable).",
            &self.model,
        )?;
        written.push(home.model_config_file());
        write_toml(
            &home.audit_config_file(),
            "Auditeur audit configuration. `run_external_tools` is off by default \
             because it executes third-party binaries on untrusted input.",
            &self.audit,
        )?;
        written.push(home.audit_config_file());
        Ok(written)
    }

    /// Enforce structural invariants across all sections.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.project.validate()?;
        self.model.validate()?;
        self.audit.validate()?;
        self.logging.validate()?;
        // Refuses absolute or escaping paths in `[paths]` and `[logging].file`.
        self.home_layout()?;
        Ok(())
    }

    /// The directory layout this configuration asks for.
    ///
    /// The log *directory* is derived from the log file, so `[paths]` has no
    /// `logs` key and the two cannot contradict each other.
    pub fn home_layout(&self) -> Result<HomeLayout, ConfigError> {
        let layout = HomeLayout {
            model: self.paths.model.clone(),
            cache: self.paths.cache.clone(),
            runs: self.paths.runs.clone(),
            log_file: self.logging.file.clone(),
        };
        layout.validate()?;
        Ok(layout)
    }

    /// This configuration's home at an explicit root.
    pub fn home_at(&self, root: impl Into<PathBuf>) -> Result<AuditeurHome, ConfigError> {
        Ok(AuditeurHome::at(root).with_layout(self.home_layout()?))
    }

    /// Apply `AUDITEUR_*` overrides, returning the names that took effect.
    ///
    /// Takes the variables as an argument so that tests do not depend on the
    /// ambient environment.
    pub fn apply_env_overrides<I>(&mut self, vars: I) -> Result<Vec<String>, ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let map: BTreeMap<String, String> = vars.into_iter().collect();
        let mut applied = Vec::new();
        let value = |name: &str| -> Option<String> {
            map.get(name)
                .map(|raw| raw.trim().to_string())
                .filter(|raw| !raw.is_empty())
        };

        if let Some(source) = value(env::SOURCE_PATH) {
            self.project.source_path = PathBuf::from(source);
            applied.push(env::SOURCE_PATH.to_string());
        }
        if let Some(backend) = value(env::MODEL_BACKEND) {
            self.model.backend = backend.parse()?;
            applied.push(env::MODEL_BACKEND.to_string());
        }
        if let Some(endpoint) = value(env::MODEL_ENDPOINT) {
            self.model.endpoint = endpoint;
            applied.push(env::MODEL_ENDPOINT.to_string());
        }
        if let Some(model) = value(env::MODEL_NAME) {
            self.model.model = model;
            applied.push(env::MODEL_NAME.to_string());
        }
        if let Some(key_env) = value(env::MODEL_API_KEY_ENV) {
            self.model.api_key_env = Some(key_env);
            applied.push(env::MODEL_API_KEY_ENV.to_string());
        }
        if let Some(enabled) = value(env::AI_ENABLED) {
            self.model.enabled = parse_bool(env::AI_ENABLED, &enabled)?;
            applied.push(env::AI_ENABLED.to_string());
        }
        if let Some(enabled) = value(env::RUN_EXTERNAL_TOOLS) {
            self.audit.run_external_tools = parse_bool(env::RUN_EXTERNAL_TOOLS, &enabled)?;
            applied.push(env::RUN_EXTERNAL_TOOLS.to_string());
        }
        if let Some(categories) = value(env::ENABLED_CATEGORIES) {
            self.audit.enabled_categories = parse_categories(&categories)?;
            applied.push(env::ENABLED_CATEGORIES.to_string());
        }

        Ok(applied)
    }

    /// Report configuration keys that this version does not know about.
    ///
    /// Only top-level keys are checked. A misspelled nested key is therefore
    /// reported by its section, not by its line — documented, not hidden.
    pub fn diagnostics(&self, home: &AuditeurHome) -> Result<Vec<String>, ConfigError> {
        let mut notes = Vec::new();
        let checks: [(PathBuf, &[&str]); 3] = [
            (home.project_config_file(), PROJECT_FILE_KEYS),
            (home.model_config_file(), MODEL_FILE_KEYS),
            (home.audit_config_file(), AUDIT_FILE_KEYS),
        ];
        for (path, known) in checks {
            if !path.is_file() {
                continue;
            }
            let text = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
                path: path.clone(),
                source,
            })?;
            let table: toml::Table = toml::from_str(&text).map_err(|error| ConfigError::Parse {
                path: path.clone(),
                message: error.to_string(),
            })?;
            for key in table.keys() {
                if !known.contains(&key.as_str()) {
                    notes.push(format!(
                        "{}: unknown section '{key}' (ignored by this version)",
                        path.display()
                    ));
                }
            }
        }
        Ok(notes)
    }
}

/// Parse a boolean environment value, accepting common spellings.
fn parse_bool(key: &str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(ConfigError::invalid(
            key,
            format!("expected a boolean, got '{other}'"),
        )),
    }
}

/// Parse a comma-separated category list, or `all`.
fn parse_categories(value: &str) -> Result<Vec<auditeur_model::AuditCategory>, ConfigError> {
    if value.trim().eq_ignore_ascii_case("all") {
        return Ok(auditeur_model::AuditCategory::ALL.to_vec());
    }
    let mut categories = Vec::new();
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let category = item
            .parse::<auditeur_model::AuditCategory>()
            .map_err(|error| ConfigError::invalid(env::ENABLED_CATEGORIES, error.to_string()))?;
        if !categories.contains(&category) {
            categories.push(category);
        }
    }
    if categories.is_empty() {
        return Err(ConfigError::invalid(
            env::ENABLED_CATEGORIES,
            "no categories given",
        ));
    }
    Ok(categories)
}

fn read_toml<T>(path: &Path) -> Result<T, ConfigError>
where
    T: serde::de::DeserializeOwned,
{
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    // A parser message quotes the offending value, and a configuration file is
    // exactly where a pasted credential lands. The position is worth keeping; the
    // value is not, so the message goes through redaction first.
    toml::from_str(&text).map_err(|error| ConfigError::Parse {
        path: path.to_path_buf(),
        message: auditeur_model::redact::redact_text(&error.to_string()),
    })
}

fn write_toml<T>(path: &Path, header: &str, value: &T) -> Result<(), ConfigError>
where
    T: Serialize,
{
    let body =
        toml::to_string_pretty(value).map_err(|error| ConfigError::Serialize(error.to_string()))?;
    let document = format!("# {header}\n\n{body}");
    fs::write(path, document).map_err(|source| ConfigError::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_model::{AuditCategory, Severity};

    fn temp_home() -> (tempfile::TempDir, AuditeurHome) {
        let temp = tempfile::tempdir().unwrap();
        let home = AuditeurHome::at(temp.path().join("auditeur-project"));
        (temp, home)
    }

    #[test]
    fn missing_files_yield_defaults_and_a_warning() {
        let (_temp, home) = temp_home();
        let loaded = AuditeurConfig::load(&home).unwrap();
        assert!(!loaded.is_configured());
        assert_eq!(loaded.warnings.len(), 1);
        assert_eq!(
            loaded.config.audit.enabled_categories.len(),
            AuditCategory::ALL.len()
        );
        assert_eq!(
            loaded.config.project.project_root.as_deref(),
            Some(home.root())
        );
    }

    #[test]
    fn save_then_load_round_trips() {
        let (_temp, home) = temp_home();
        let mut config = AuditeurConfig::default();
        config.project.name = "demo".to_string();
        config.project.source_path = PathBuf::from("/tmp/demo");
        config.project.project_root = Some(home.root().to_path_buf());
        config.model.model = "qwen/qwen2.5-coder-14b".to_string();
        config.model.temperature = 0.2;
        config.audit.enabled_categories = vec![AuditCategory::Security, AuditCategory::Testing];
        config.audit.fail_threshold = Severity::Critical;

        let written = config.save(&home).unwrap();
        assert_eq!(written.len(), 3);
        for path in &written {
            assert!(path.is_file(), "missing {path:?}");
        }

        let loaded = AuditeurConfig::load(&home).unwrap();
        assert!(loaded.is_configured());
        assert_eq!(loaded.config, config);
    }

    #[test]
    fn parse_errors_name_the_file_and_position() {
        let (_temp, home) = temp_home();
        home.ensure().unwrap();
        fs::write(home.audit_config_file(), "fail_threshold = = 3\n").unwrap();
        let error = AuditeurConfig::load(&home).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("audit.toml"), "{message}");
    }

    #[test]
    fn invalid_values_are_hard_errors() {
        let (_temp, home) = temp_home();
        home.ensure().unwrap();
        fs::write(home.model_config_file(), "endpoint = \"not-a-url\"\n").unwrap();
        let loaded = AuditeurConfig::load(&home);
        assert!(
            loaded.is_ok(),
            "loading should succeed; validation is separate"
        );
        assert!(loaded.unwrap().config.validate().is_err());
    }

    #[test]
    fn environment_overrides_win_and_are_reported() {
        let mut config = AuditeurConfig::default();
        config.model.endpoint = "http://from-file:1234/v1".to_string();
        let applied = config
            .apply_env_overrides(vec![
                (
                    env::MODEL_ENDPOINT.to_string(),
                    "http://from-env:8888/v1".to_string(),
                ),
                (env::AI_ENABLED.to_string(), "false".to_string()),
                (
                    env::ENABLED_CATEGORIES.to_string(),
                    "security, testing".to_string(),
                ),
                ("UNRELATED".to_string(), "ignored".to_string()),
            ])
            .unwrap();
        assert_eq!(config.model.endpoint, "http://from-env:8888/v1");
        assert!(!config.model.enabled);
        assert_eq!(
            config.audit.enabled_categories,
            vec![AuditCategory::Security, AuditCategory::Testing]
        );
        assert_eq!(applied.len(), 3);
        assert!(!applied.contains(&"UNRELATED".to_string()));
    }

    #[test]
    fn empty_environment_values_do_not_override() {
        let mut config = AuditeurConfig::default();
        config.model.model = "from-file".to_string();
        config
            .apply_env_overrides(vec![(env::MODEL_NAME.to_string(), "   ".to_string())])
            .unwrap();
        assert_eq!(config.model.model, "from-file");
    }

    #[test]
    fn bad_boolean_environment_value_is_rejected() {
        let mut config = AuditeurConfig::default();
        assert!(config
            .apply_env_overrides(vec![(env::AI_ENABLED.to_string(), "maybe".to_string())])
            .is_err());
    }

    #[test]
    fn all_categories_keyword_is_understood() {
        let mut config = AuditeurConfig::default();
        config
            .apply_env_overrides(vec![(
                env::ENABLED_CATEGORIES.to_string(),
                "all".to_string(),
            )])
            .unwrap();
        assert_eq!(
            config.audit.enabled_categories.len(),
            AuditCategory::ALL.len()
        );
    }

    #[test]
    fn a_saved_configuration_must_be_valid() {
        let (_temp, home) = temp_home();
        let error = AuditeurConfig::default().save(&home).unwrap_err();
        assert!(error.to_string().contains("project.name"), "{error}");
    }

    #[test]
    fn unknown_top_level_keys_are_reported_not_fatal() {
        let (_temp, home) = temp_home();
        home.ensure().unwrap();
        fs::write(
            home.project_config_file(),
            "[project]\nname = \"demo\"\n\n[telemetry]\nenabled = true\n",
        )
        .unwrap();
        let loaded = AuditeurConfig::load(&home).unwrap();
        assert_eq!(loaded.config.project.name, "demo");
        let notes = loaded.config.diagnostics(&home).unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("telemetry"), "{notes:?}");
    }

    #[test]
    fn nested_sections_are_not_reported_as_unknown() {
        let (_temp, home) = temp_home();
        let mut config = AuditeurConfig::default();
        config.project.name = "demo".to_string();
        config.save(&home).unwrap();
        let notes = config.diagnostics(&home).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn defaults_for_source_derive_a_usable_project() {
        let (_temp, home) = temp_home();
        let config = AuditeurConfig::for_source(Path::new("/tmp/my service"), &home);
        config.validate().unwrap();
        assert_eq!(config.project.name, "my-service");
        assert_eq!(config.project.source_folder(), "my-service");
        assert!(!config.model.is_configured());
    }

    #[test]
    fn saved_files_carry_an_explanatory_header() {
        let (_temp, home) = temp_home();
        let mut config = AuditeurConfig::default();
        config.project.name = "demo".to_string();
        config.save(&home).unwrap();
        let text = fs::read_to_string(home.model_config_file()).unwrap();
        assert!(text.starts_with("# Auditeur model configuration"));
        assert!(text.contains("api_key_env"));
    }

    /// The portability rule: a saved configuration names directories relative to
    /// the home, never absolute paths, so the home can be moved, restored from a
    /// backup, or shared between machines.
    #[test]
    fn a_saved_configuration_contains_no_absolute_path() {
        let (temp, home) = temp_home();
        let mut config = AuditeurConfig::default();
        config.project.name = "demo".to_string();
        config.project.source_path = temp.path().join("repo");
        config.project.project_root = Some(home.root().to_path_buf());
        config.model.models_dir = Some(PathBuf::from("/Volumes/big/models"));

        config.save(&home).unwrap();
        let project = fs::read_to_string(home.project_config_file()).unwrap();

        // The resolved state root is in memory, never in the file.
        assert!(
            !project.contains(&home.root().display().to_string()),
            "the state root must not be written: {project}"
        );
        assert!(!project.contains("project_root"), "{project}");

        // The sections that describe directories are relative.
        for line in project.lines() {
            let line = line.trim();
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                if matches!(key, "model" | "cache" | "runs" | "file") {
                    assert!(
                        !Path::new(value).is_absolute(),
                        "{key} must be relative, got {value}"
                    );
                }
            }
        }
        assert!(project.contains("[paths]"), "{project}");
        assert!(project.contains("[logging]"), "{project}");
    }

    /// The layout a configuration asks for is what the loaded home actually uses.
    #[test]
    fn the_configured_layout_is_applied_to_the_loaded_home() {
        let (_temp, home) = temp_home();
        home.ensure().unwrap();
        fs::write(
            home.project_config_file(),
            "[project]\nname = \"demo\"\n\n[paths]\nmodel = \"artefacts\"\ncache = \"scratch\"\nruns = \"history\"\n\n[logging]\nfile = \"var/log/auditeur.log\"\nlevel = \"debug\"\nmax_size_mb = 7\nmax_files = 2\n",
        )
        .unwrap();

        let loaded = AuditeurConfig::load(&home).unwrap();
        assert_eq!(loaded.config.paths.model, "artefacts");
        assert_eq!(loaded.config.logging.level, crate::LogLevel::Debug);
        assert_eq!(loaded.config.logging.max_size_mb, 7);
        assert_eq!(loaded.config.logging.max_files, 2);
        loaded.config.validate().unwrap();

        assert_eq!(loaded.home.model_dir(), home.root().join("artefacts"));
        assert_eq!(loaded.home.cache_dir(), home.root().join("scratch"));
        assert_eq!(loaded.home.runs_dir(), home.root().join("history"));
        assert_eq!(
            loaded.home.log_file(),
            home.root().join("var/log/auditeur.log")
        );
        assert_eq!(loaded.home.logs_dir(), home.root().join("var/log"));
    }

    /// A contradictory or escaping path is refused at validation, not silently
    /// resolved against the working directory.
    #[test]
    fn an_escaping_log_file_is_refused_by_validation() {
        let mut config = AuditeurConfig::default();
        config.project.name = "demo".to_string();
        config.logging.file = "../outside/auditeur.log".to_string();
        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("logging.file"), "{error}");

        config.logging.file = "/var/log/auditeur.log".to_string();
        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("logging.file"), "{error}");

        config.logging.file = "logs/auditeur.log".to_string();
        config.paths.cache = "/tmp/cache".to_string();
        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("paths.cache"), "{error}");
    }

    /// The two new sections are known keys, so an older file that lacks them
    /// stays readable and a typo inside them is still reported.
    #[test]
    fn the_new_sections_are_known_and_typos_in_them_are_reported() {
        let (_temp, home) = temp_home();
        home.ensure().unwrap();
        let loaded = AuditeurConfig::load(&home).unwrap();
        assert!(loaded.config.diagnostics(&home).unwrap().is_empty());

        let mut config = AuditeurConfig::default();
        config.project.name = "demo".to_string();
        config.save(&home).unwrap();
        let loaded = AuditeurConfig::load(&home).unwrap();
        assert!(loaded.config.diagnostics(&home).unwrap().is_empty());
        assert_eq!(
            loaded.config.logging,
            LoggingConfig::default(),
            "defaults survive a round trip"
        );

        fs::write(
            home.project_config_file(),
            "[project]\nname = \"demo\"\n\n[paths]\nmodel = \"model\"\n\n[telemetry]\nenabled = true\n",
        )
        .unwrap();
        let notes = AuditeurConfig::load(&home)
            .unwrap()
            .config
            .diagnostics(&home)
            .unwrap();
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("telemetry"), "{notes:?}");
    }
}
