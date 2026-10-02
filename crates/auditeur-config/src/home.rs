//! The Auditeur home directory: the single root of all Auditeur state.
//!
//! Auditeur keeps its own state in one visible directory, by default
//! `~/auditeur`:
//!
//! ```text
//! ~/auditeur/
//! ├── config/           auditeur.toml, model.toml, audit.toml, definitions/
//! ├── model/            local model artefacts
//! ├── cache/            ast/, index/, analysis/ — created lazily
//! ├── runs/<run-id>/    manifest.json, findings.json, evidence.json
//! ├── logs/             auditeur.log, auditeur.log.1, …
//! └── <source-folder>/  audit_<unix-timestamp>.md, audit_<unix-timestamp>.json
//! ```
//!
//! Not hidden, and deliberately so: audit runs are artefacts a person is meant
//! to read, and a directory that holds configuration, history and logs should be
//! easy to inspect, back up, archive or delete. There is no `~/.auditeur`.
//!
//! Two rules keep this the *only* place that decides where state lives:
//!
//! * every path is derived from one root, and
//! * the root is chosen by one pure function, [`AuditeurHome::discover_with`],
//!   which takes the environment lookup and the home directory as arguments so
//!   the rule can be tested without touching the process environment.
//!
//! Resolution order, first match wins:
//!
//! 1. `AUDITEUR_HOME`, when set to a non-blank value;
//! 2. `AUDITEUR_PROJECT_ROOT`, the pre-1.0 name, honoured with a note;
//! 3. `$HOME/auditeur`.
//!
//! When none of those applies, discovery fails with a clean error rather than
//! guessing where the state should go.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::env;
use crate::error::{echo_safe, ConfigError};

/// Name of the state directory inside the user's home.
pub const HOME_DIR_NAME: &str = "auditeur";
/// Directory holding the configuration files.
pub const CONFIG_DIR: &str = "config";
/// Directory holding local model artefacts.
pub const MODEL_DIR: &str = "model";
/// Directory holding the analysis cache.
pub const CACHE_DIR: &str = "cache";
/// Directory holding machine-readable audit runs.
pub const RUNS_DIR: &str = "runs";
/// Directory holding the rolling log.
pub const LOGS_DIR: &str = "logs";
/// Directory holding user-supplied audit definitions, inside `config/`.
pub const DEFINITIONS_DIR: &str = "definitions";
/// Default log file, relative to the home.
pub const DEFAULT_LOG_FILE: &str = "logs/auditeur.log";
/// File name of the application configuration.
pub const PROJECT_CONFIG_FILE: &str = "auditeur.toml";
/// File name of the model configuration.
pub const MODEL_CONFIG_FILE: &str = "model.toml";
/// File name of the audit configuration.
pub const AUDIT_CONFIG_FILE: &str = "audit.toml";

/// Where the home came from, so a run can say how it was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeOrigin {
    /// `AUDITEUR_HOME` was set.
    Environment,
    /// `AUDITEUR_PROJECT_ROOT`, the pre-1.0 name, was set instead.
    LegacyEnvironment,
    /// `$HOME/auditeur`.
    HomeDirectory,
}

impl HomeOrigin {
    /// Stable identifier.
    pub fn id(self) -> &'static str {
        match self {
            HomeOrigin::Environment => "environment",
            HomeOrigin::LegacyEnvironment => "legacy_environment",
            HomeOrigin::HomeDirectory => "home_directory",
        }
    }

    /// How the home was chosen, for `doctor` and for log lines.
    pub fn describe(self, home: &AuditeurHome) -> String {
        match self {
            HomeOrigin::Environment => format!("{} (from {})", home.root().display(), env::HOME),
            HomeOrigin::LegacyEnvironment => format!(
                "{} (from {}, which is the pre-1.0 name for {})",
                home.root().display(),
                env::PROJECT_ROOT,
                env::HOME
            ),
            HomeOrigin::HomeDirectory => {
                format!(
                    "{} (default: $HOME/{})",
                    home.root().display(),
                    HOME_DIR_NAME
                )
            }
        }
    }
}

/// The outcome of discovery: the home, how it was chosen, and anything the user
/// should know about the choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The resolved home.
    pub home: AuditeurHome,
    /// How it was resolved.
    pub origin: HomeOrigin,
    /// Non-fatal observations, e.g. the use of a deprecated variable.
    pub notes: Vec<String>,
}

/// Directory names Auditeur uses, relative to the home.
///
/// These are relative on purpose: a configuration file that named absolute
/// paths would stop being portable, and moving or restoring the home would
/// break it. [`HomeLayout::validate`] rejects anything that is not a safe
/// relative sub-path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HomeLayout {
    /// Model artefacts directory.
    pub model: String,
    /// Cache directory.
    pub cache: String,
    /// Runs directory.
    pub runs: String,
    /// Log file, relative to the home. Its parent directory is the log
    /// directory, so one key — not two — decides where logs live.
    pub log_file: String,
}

impl Default for HomeLayout {
    fn default() -> Self {
        Self {
            model: MODEL_DIR.to_string(),
            cache: CACHE_DIR.to_string(),
            runs: RUNS_DIR.to_string(),
            log_file: DEFAULT_LOG_FILE.to_string(),
        }
    }
}

impl HomeLayout {
    /// Refuse anything that is not a plain relative sub-path of the home.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (key, value) in [
            ("paths.model", &self.model),
            ("paths.cache", &self.cache),
            ("paths.runs", &self.runs),
            ("logging.file", &self.log_file),
        ] {
            validate_relative(key, value)?;
        }
        Ok(())
    }
}

/// Check that a configured path stays inside the home.
fn validate_relative(key: &str, value: &str) -> Result<(), ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::invalid(key, "must not be empty"));
    }
    if trimmed.starts_with('~') {
        return Err(ConfigError::invalid(
            key,
            format!("'{trimmed}' must be relative to the Auditeur home, not a home-relative path"),
        ));
    }
    let path = Path::new(trimmed);
    if path.is_absolute() {
        return Err(ConfigError::invalid(
            key,
            format!("'{trimmed}' must be relative to the Auditeur home, not an absolute path"),
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigError::invalid(
            key,
            format!("'{trimmed}' must not leave the Auditeur home with '..'"),
        ));
    }
    Ok(())
}

/// Every path Auditeur writes to, under one home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditeurHome {
    root: PathBuf,
    layout: HomeLayout,
}

impl AuditeurHome {
    /// A home at an explicit root, using the default layout.
    ///
    /// The root is taken as given: callers that obtained it from the
    /// environment should use [`AuditeurHome::discover`], which validates it.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            layout: HomeLayout::default(),
        }
    }

    /// The same home with a different internal layout.
    pub fn with_layout(mut self, layout: HomeLayout) -> Self {
        self.layout = layout;
        self
    }

    /// A home at an explicit root, validated.
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(ConfigError::Layout("the home path is empty".to_string()));
        }
        if !path.is_absolute() {
            return Err(ConfigError::Layout(format!(
                "the home path '{}' is relative; give an absolute path so that a run does not \
                 depend on the working directory",
                path.display()
            )));
        }
        Ok(Self::at(path))
    }

    /// Resolve the home from the real process environment.
    pub fn discover() -> Result<Discovery, ConfigError> {
        Self::discover_with(|key| std::env::var(key).ok(), dirs::home_dir())
    }

    /// Resolve the home from an environment lookup and a home directory.
    ///
    /// Pure: nothing here reads the process state, which is what makes the rule
    /// testable in all four combinations without touching real variables.
    pub fn discover_with(
        lookup: impl Fn(&str) -> Option<String>,
        home_directory: Option<PathBuf>,
    ) -> Result<Discovery, ConfigError> {
        let mut notes = Vec::new();

        if let Some(value) = non_blank(lookup(env::HOME)) {
            let root = expand_tilde(&value, home_directory.as_deref())?;
            let root = checked_root(&root, env::HOME)?;
            return Ok(Discovery {
                home: Self::at(root),
                origin: HomeOrigin::Environment,
                notes,
            });
        }

        if let Some(value) = non_blank(lookup(env::PROJECT_ROOT)) {
            notes.push(format!(
                "{} is set; it is the pre-1.0 name for {}. Rename it when convenient.",
                env::PROJECT_ROOT,
                env::HOME
            ));
            let root = expand_tilde(&value, home_directory.as_deref())?;
            let root = checked_root(&root, env::PROJECT_ROOT)?;
            return Ok(Discovery {
                home: Self::at(root),
                origin: HomeOrigin::LegacyEnvironment,
                notes,
            });
        }

        let home_directory = home_directory.ok_or_else(|| {
            ConfigError::Layout(format!(
                "no home directory could be determined and {} is not set; set {} to choose one",
                env::HOME,
                env::HOME
            ))
        })?;
        Ok(Discovery {
            home: Self::at(home_directory.join(HOME_DIR_NAME)),
            origin: HomeOrigin::HomeDirectory,
            notes,
        })
    }

    /// The home root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory names in effect.
    pub fn layout(&self) -> &HomeLayout {
        &self.layout
    }

    /// `<root>/config`.
    pub fn config_dir(&self) -> PathBuf {
        self.root.join(CONFIG_DIR)
    }

    /// `<root>/config/auditeur.toml`.
    pub fn project_config_file(&self) -> PathBuf {
        self.config_dir().join(PROJECT_CONFIG_FILE)
    }

    /// `<root>/config/model.toml`.
    pub fn model_config_file(&self) -> PathBuf {
        self.config_dir().join(MODEL_CONFIG_FILE)
    }

    /// `<root>/config/audit.toml`.
    pub fn audit_config_file(&self) -> PathBuf {
        self.config_dir().join(AUDIT_CONFIG_FILE)
    }

    /// `<root>/config/definitions`.
    pub fn definitions_dir(&self) -> PathBuf {
        self.config_dir().join(DEFINITIONS_DIR)
    }

    /// `<root>/<paths.model>`.
    pub fn model_dir(&self) -> PathBuf {
        self.root.join(&self.layout.model)
    }

    /// `<root>/<paths.cache>`.
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join(&self.layout.cache)
    }

    /// `<root>/<paths.cache>/ast`.
    ///
    /// Created lazily: nothing creates this directory yet, because nothing
    /// writes an AST cache yet.
    pub fn cache_ast_dir(&self) -> PathBuf {
        self.cache_dir().join("ast")
    }

    /// `<root>/<paths.cache>/index`.
    pub fn cache_index_dir(&self) -> PathBuf {
        self.cache_dir().join("index")
    }

    /// `<root>/<paths.cache>/analysis`.
    pub fn cache_analysis_dir(&self) -> PathBuf {
        self.cache_dir().join("analysis")
    }

    /// `<root>/<paths.runs>`.
    pub fn runs_dir(&self) -> PathBuf {
        self.root.join(&self.layout.runs)
    }

    /// `<root>/<paths.runs>/<run_id>`.
    pub fn run_dir(&self, run_id: &str) -> PathBuf {
        self.runs_dir().join(run_id)
    }

    /// The log file, `<root>/<logging.file>`.
    pub fn log_file(&self) -> PathBuf {
        self.root.join(&self.layout.log_file)
    }

    /// The directory the log file lives in.
    ///
    /// Derived from [`AuditeurHome::log_file`] rather than configured
    /// separately: two keys pointing at one location is the kind of drift a
    /// contract exists to prevent.
    pub fn logs_dir(&self) -> PathBuf {
        match self.log_file().parent() {
            Some(parent) => parent.to_path_buf(),
            None => self.root.clone(),
        }
    }

    /// The folder a report for `source_folder` lives in.
    ///
    /// A repository whose directory name collides with one of the state
    /// directories (`logs`, `runs`, `config`, `cache`, `model`) would otherwise
    /// have its reports written *into* that state directory, mixing an audit
    /// artefact into the operational tree. Such a name is suffixed with
    /// `-reports`; the report path is printed in the run summary and recorded in
    /// the manifest, so the adjustment is visible rather than silent.
    pub fn report_folder(&self, source_folder: &str) -> String {
        if self
            .reserved_names()
            .iter()
            .any(|name| name == source_folder)
        {
            return format!("{source_folder}-reports");
        }
        source_folder.to_string()
    }

    /// The top-level names inside the home that belong to Auditeur itself.
    fn reserved_names(&self) -> Vec<String> {
        let mut names = vec![
            CONFIG_DIR.to_string(),
            self.layout.model.clone(),
            self.layout.cache.clone(),
            self.layout.runs.clone(),
        ];
        if let Some(name) = self.log_directory_name() {
            names.push(name);
        }
        names
    }

    /// The first component of the log file, relative to the home.
    fn log_directory_name(&self) -> Option<String> {
        let relative = self.log_file().strip_prefix(&self.root).ok()?.to_path_buf();
        relative
            .components()
            .next()?
            .as_os_str()
            .to_str()
            .map(str::to_string)
    }

    /// `<root>/<source_folder>`, where generated reports are written.
    pub fn source_dir(&self, source_folder: &str) -> PathBuf {
        self.root.join(self.report_folder(source_folder))
    }

    /// `<root>/<source_folder>/audit_<unix_timestamp>.md`.
    pub fn report_file(&self, source_folder: &str, unix_timestamp: i64) -> PathBuf {
        self.source_dir(source_folder)
            .join(format!("audit_{unix_timestamp}.md"))
    }

    /// Create the directories the home is made of.
    ///
    /// Exactly the directories in the documented tree, and nothing below them:
    /// `cache/ast`, `cache/index` and `cache/analysis` are created by whoever
    /// first needs them. `definitions/` is not created either — it holds
    /// user-supplied overrides, and its absence means "use the compiled-in
    /// definitions".
    ///
    /// Every path is derived from the home, which is validated separately from
    /// the audited repository, so this can never create anything inside a
    /// repository.
    pub fn ensure(&self) -> Result<Vec<PathBuf>, ConfigError> {
        self.layout.validate()?;
        let directories = vec![
            self.root.clone(),
            self.config_dir(),
            self.model_dir(),
            self.cache_dir(),
            self.runs_dir(),
            self.logs_dir(),
        ];
        for directory in &directories {
            self.ensure_dir(directory)?;
        }
        Ok(directories)
    }

    /// Create one directory, lazily, when something needs it.
    pub fn ensure_dir(&self, directory: &Path) -> Result<(), ConfigError> {
        fs::create_dir_all(directory).map_err(|source| ConfigError::CreateDir {
            path: directory.to_path_buf(),
            source,
        })
    }
}

/// Treat a blank value as unset, and trim what is left.
fn non_blank(value: Option<String>) -> Option<String> {
    value
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
}

/// Expand a leading `~` against the home directory.
///
/// A path that starts with `~` but has no home directory to expand against is an
/// error rather than a literal directory named `~`.
fn expand_tilde(value: &str, home_directory: Option<&Path>) -> Result<PathBuf, ConfigError> {
    if value == "~" || value.starts_with("~/") {
        let home = home_directory.ok_or_else(|| {
            ConfigError::Layout(format!(
                "'{value}' uses '~' but no home directory could be determined"
            ))
        })?;
        let rest = value.strip_prefix('~').unwrap_or("");
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        return Ok(if rest.is_empty() {
            home.to_path_buf()
        } else {
            home.join(rest)
        });
    }
    Ok(PathBuf::from(value))
}

/// Validate a discovered root before it is used.
fn checked_root(root: &Path, key: &str) -> Result<PathBuf, ConfigError> {
    if root.as_os_str().is_empty() {
        return Err(ConfigError::invalid(key, "must not be empty"));
    }
    if !root.is_absolute() {
        return Err(ConfigError::invalid(
            key,
            format!(
                "'{}' is relative; give an absolute path so that a run does not depend on the \
                 working directory",
                root.display()
            ),
        ));
    }
    Ok(root.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        move |key: &str| map.get(key).cloned()
    }

    fn no_env() -> impl Fn(&str) -> Option<String> {
        |_: &str| None
    }

    #[test]
    fn an_unset_environment_resolves_to_home_auditeur() {
        let discovery =
            AuditeurHome::discover_with(no_env(), Some(PathBuf::from("/Users/example"))).unwrap();
        assert_eq!(discovery.home.root(), Path::new("/Users/example/auditeur"));
        assert_eq!(discovery.origin, HomeOrigin::HomeDirectory);
        assert!(discovery.notes.is_empty());
        // The literal string the documentation pins.
        assert_eq!(HOME_DIR_NAME, "auditeur");
    }

    #[test]
    fn auditeur_home_wins_over_the_home_directory() {
        let discovery = AuditeurHome::discover_with(
            env_of(&[(env::HOME, "/tmp/state")]),
            Some(PathBuf::from("/Users/example")),
        )
        .unwrap();
        assert_eq!(discovery.home.root(), Path::new("/tmp/state"));
        assert_eq!(discovery.origin, HomeOrigin::Environment);
        assert!(discovery.notes.is_empty());
    }

    #[test]
    fn the_legacy_variable_is_honoured_with_a_note() {
        let discovery = AuditeurHome::discover_with(
            env_of(&[(env::PROJECT_ROOT, "/tmp/legacy")]),
            Some(PathBuf::from("/Users/example")),
        )
        .unwrap();
        assert_eq!(discovery.home.root(), Path::new("/tmp/legacy"));
        assert_eq!(discovery.origin, HomeOrigin::LegacyEnvironment);
        assert_eq!(discovery.notes.len(), 1);
        assert!(discovery.notes[0].contains(env::HOME));
    }

    #[test]
    fn the_new_variable_wins_over_the_legacy_one() {
        let discovery = AuditeurHome::discover_with(
            env_of(&[(env::HOME, "/tmp/new"), (env::PROJECT_ROOT, "/tmp/old")]),
            Some(PathBuf::from("/Users/example")),
        )
        .unwrap();
        assert_eq!(discovery.home.root(), Path::new("/tmp/new"));
        assert_eq!(discovery.origin, HomeOrigin::Environment);
    }

    #[test]
    fn blank_and_untrimmed_values_behave() {
        // Blank counts as unset.
        let discovery = AuditeurHome::discover_with(
            env_of(&[(env::HOME, "   ")]),
            Some(PathBuf::from("/Users/example")),
        )
        .unwrap();
        assert_eq!(discovery.origin, HomeOrigin::HomeDirectory);

        // Surrounding whitespace is not part of the path.
        let discovery = AuditeurHome::discover_with(
            env_of(&[(env::HOME, "  /tmp/padded  ")]),
            Some(PathBuf::from("/Users/example")),
        )
        .unwrap();
        assert_eq!(discovery.home.root(), Path::new("/tmp/padded"));
    }

    #[test]
    fn a_tilde_is_expanded_against_the_home_directory() {
        let discovery = AuditeurHome::discover_with(
            env_of(&[(env::HOME, "~/state")]),
            Some(PathBuf::from("/Users/example")),
        )
        .unwrap();
        assert_eq!(discovery.home.root(), Path::new("/Users/example/state"));
    }

    #[test]
    fn a_relative_home_is_refused_rather_than_resolved_against_the_cwd() {
        let error = AuditeurHome::discover_with(
            env_of(&[(env::HOME, "state")]),
            Some(PathBuf::from("/Users/example")),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("relative"),
            "the message must say why: {error}"
        );

        assert!(AuditeurHome::from_path("state").is_err());
        assert!(AuditeurHome::from_path("").is_err());
        assert!(AuditeurHome::from_path("/tmp/state").is_ok());
    }

    #[test]
    fn no_home_at_all_is_a_clean_error() {
        let error = AuditeurHome::discover_with(no_env(), None).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(env::HOME), "{message}");
        assert!(message.contains("not set"), "{message}");
    }

    #[test]
    fn a_tilde_without_a_home_directory_is_an_error() {
        let error =
            AuditeurHome::discover_with(env_of(&[(env::HOME, "~/state")]), None).unwrap_err();
        assert!(error.to_string().contains("home directory"), "{error}");
    }

    #[test]
    fn the_layout_derives_every_path_from_one_root() {
        let home = AuditeurHome::at("/tmp/auditeur-test");
        assert_eq!(home.config_dir(), Path::new("/tmp/auditeur-test/config"));
        assert_eq!(
            home.project_config_file(),
            Path::new("/tmp/auditeur-test/config/auditeur.toml")
        );
        assert_eq!(
            home.model_config_file(),
            Path::new("/tmp/auditeur-test/config/model.toml")
        );
        assert_eq!(
            home.audit_config_file(),
            Path::new("/tmp/auditeur-test/config/audit.toml")
        );
        assert_eq!(
            home.definitions_dir(),
            Path::new("/tmp/auditeur-test/config/definitions")
        );
        assert_eq!(home.model_dir(), Path::new("/tmp/auditeur-test/model"));
        assert_eq!(home.cache_dir(), Path::new("/tmp/auditeur-test/cache"));
        assert_eq!(
            home.cache_ast_dir(),
            Path::new("/tmp/auditeur-test/cache/ast")
        );
        assert_eq!(
            home.cache_index_dir(),
            Path::new("/tmp/auditeur-test/cache/index")
        );
        assert_eq!(
            home.cache_analysis_dir(),
            Path::new("/tmp/auditeur-test/cache/analysis")
        );
        assert_eq!(home.runs_dir(), Path::new("/tmp/auditeur-test/runs"));
        assert_eq!(
            home.run_dir("20261002T153012Z"),
            Path::new("/tmp/auditeur-test/runs/20261002T153012Z")
        );
        assert_eq!(
            home.log_file(),
            Path::new("/tmp/auditeur-test/logs/auditeur.log")
        );
        assert_eq!(home.logs_dir(), Path::new("/tmp/auditeur-test/logs"));
        assert_eq!(
            home.report_file("my-repo", 1_790_940_176),
            Path::new("/tmp/auditeur-test/my-repo/audit_1790940176.md")
        );
    }

    #[test]
    fn the_layout_can_be_redirected_without_touching_the_root() {
        let layout = HomeLayout {
            model: "artefacts".to_string(),
            cache: "tmp/cache".to_string(),
            runs: "history".to_string(),
            log_file: "var/log/auditeur.log".to_string(),
        };
        layout.validate().unwrap();
        let home = AuditeurHome::at("/tmp/auditeur-test").with_layout(layout);
        assert_eq!(home.root(), Path::new("/tmp/auditeur-test"));
        assert_eq!(home.model_dir(), Path::new("/tmp/auditeur-test/artefacts"));
        assert_eq!(home.cache_dir(), Path::new("/tmp/auditeur-test/tmp/cache"));
        assert_eq!(home.runs_dir(), Path::new("/tmp/auditeur-test/history"));
        assert_eq!(
            home.log_file(),
            Path::new("/tmp/auditeur-test/var/log/auditeur.log")
        );
        assert_eq!(home.logs_dir(), Path::new("/tmp/auditeur-test/var/log"));
    }

    #[test]
    fn absolute_and_escaping_layout_paths_are_refused() {
        // The key named in the error is the one a user would search for in their
        // configuration file, not the internal field name.
        for (key, value) in [
            ("paths.model", "/var/model"),
            ("paths.cache", "../cache"),
            ("paths.runs", "runs/../../escape"),
            ("logging.file", "/var/log/auditeur.log"),
        ] {
            let layout = HomeLayout {
                model: "model".to_string(),
                cache: "cache".to_string(),
                runs: "runs".to_string(),
                log_file: "logs/auditeur.log".to_string(),
            };
            let layout = match key {
                "paths.model" => HomeLayout {
                    model: value.to_string(),
                    ..layout
                },
                "paths.cache" => HomeLayout {
                    cache: value.to_string(),
                    ..layout
                },
                "paths.runs" => HomeLayout {
                    runs: value.to_string(),
                    ..layout
                },
                _ => HomeLayout {
                    log_file: value.to_string(),
                    ..layout
                },
            };
            let error = layout.validate().unwrap_err();
            let message = error.to_string();
            assert!(message.contains(key), "{key}: {message}");
        }

        // And a blank value is refused rather than silently defaulting.
        let blank = HomeLayout {
            model: "  ".to_string(),
            ..HomeLayout::default()
        };
        assert!(blank.validate().is_err());
    }

    #[test]
    fn ensure_creates_the_documented_tree_and_nothing_deeper() {
        let temp = tempfile::tempdir().unwrap();
        let home = AuditeurHome::at(temp.path().join("auditeur"));
        let created = home.ensure().unwrap();
        assert_eq!(created.len(), 6);

        for directory in [
            home.root(),
            &home.config_dir(),
            &home.model_dir(),
            &home.cache_dir(),
            &home.runs_dir(),
            &home.logs_dir(),
        ] {
            assert!(
                directory.is_dir(),
                "{} was not created",
                directory.display()
            );
        }

        // Lazy: the cache subdirectories and the definitions directory are not
        // created until something needs them.
        assert!(!home.cache_ast_dir().exists());
        assert!(!home.cache_index_dir().exists());
        assert!(!home.cache_analysis_dir().exists());
        assert!(!home.definitions_dir().exists());
    }

    #[test]
    fn ensure_is_idempotent_and_never_reaches_outside_the_home() {
        let temp = tempfile::tempdir().unwrap();
        let repository = temp.path().join("repo");
        fs::create_dir_all(&repository).unwrap();

        let home = AuditeurHome::at(temp.path().join("auditeur"));
        home.ensure().unwrap();
        home.ensure().unwrap();

        for path in [
            home.root(),
            &home.config_dir(),
            &home.model_dir(),
            &home.cache_dir(),
            &home.runs_dir(),
            &home.logs_dir(),
        ] {
            assert!(path.starts_with(home.root()));
        }
        assert_eq!(
            fs::read_dir(&repository).unwrap().count(),
            0,
            "the repository must stay empty"
        );
    }

    #[test]
    fn every_path_stays_inside_the_home() {
        let home = AuditeurHome::at("/tmp/auditeur-test");
        for path in [
            home.config_dir(),
            home.model_config_file(),
            home.definitions_dir(),
            home.model_dir(),
            home.cache_analysis_dir(),
            home.runs_dir(),
            home.run_dir("x"),
            home.log_file(),
            home.logs_dir(),
            home.report_file("repo", 1),
        ] {
            assert!(
                path.starts_with(home.root()),
                "{} escaped the home",
                path.display()
            );
        }
    }

    #[test]
    fn origins_describe_themselves_without_inventing_paths() {
        let home = AuditeurHome::at("/tmp/auditeur-test");
        let environment = HomeOrigin::Environment.describe(&home);
        assert!(environment.contains(env::HOME), "{environment}");
        let legacy = HomeOrigin::LegacyEnvironment.describe(&home);
        assert!(legacy.contains(env::PROJECT_ROOT), "{legacy}");
        assert_eq!(HomeOrigin::Environment.id(), "environment");
        assert_eq!(HomeOrigin::LegacyEnvironment.id(), "legacy_environment");
        assert_eq!(HomeOrigin::HomeDirectory.id(), "home_directory");
    }
}
