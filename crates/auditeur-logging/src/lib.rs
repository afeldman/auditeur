//! Auditeur's logging.
//!
//! One entry point, called once per process, plus a rolling file.
//!
//! Two distinctions this crate exists to enforce:
//!
//! * **Logs are operational artefacts, not audit evidence.** The evidence of an
//!   audit is written to `runs/<run-id>/{manifest,findings,evidence}.json` and
//!   is reproducible. A log line is neither: it is what the process did, useful
//!   for an operator and for debugging, and nothing in the audit model may be
//!   derived from one.
//! * **Nothing logged is un-redacted.** The writer redacts with the same
//!   component that keeps credentials out of prompts, findings and reports.
//!
//! The file lives at `~/auditeur/logs/auditeur.log` by default, rotates by size,
//! and keeps a bounded number of predecessors. Progress on the terminal stays a
//! separate channel owned by the front-end: this crate writes a file and nothing
//! else.

#![forbid(unsafe_code)]
// Test bodies build configurations field by field, which reads better than a
// twelve-field struct literal. Production code is still held to the lint.
#![cfg_attr(test, allow(clippy::field_reassign_with_default))]

mod redacting;
mod rolling;

pub use redacting::RedactingWriter;
pub use rolling::{rotated_paths, rotating_writer};

use std::path::{Path, PathBuf};

use auditeur_config::{AuditeurHome, ConfigError, HomeLayout, LogLevel, LoggingConfig};
use tracing::Dispatch;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::Registry;
use tracing_subscriber::{fmt, Layer};

/// Failures while setting up logging.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// The log directory could not be prepared.
    #[error("the log directory {path} could not be prepared: {source}")]
    Directory {
        /// Directory that failed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The log file could not be opened.
    #[error("the log file {path} could not be opened: {source}")]
    File {
        /// File that failed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The configuration is not usable.
    #[error("incompatible logging configuration: {0}")]
    Config(#[from] ConfigError),

    /// A global subscriber is already installed.
    #[error("a global logger is already installed; logging is initialised once per process")]
    AlreadyInstalled,
}

/// Keeps the logging worker alive.
///
/// Logging is asynchronous, so the writer thread and its buffered queue live
/// only as long as this value. Dropping it flushes what is pending — which is
/// why the CLI holds it until the process is about to exit, and why a test drops
/// it before reading the file.
pub struct LoggingGuard {
    worker: tracing_appender::non_blocking::WorkerGuard,
    log_file: PathBuf,
    level: LogLevel,
}

impl std::fmt::Debug for LoggingGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The worker is not printable; the path and level are what a test or an
        // error message needs.
        formatter
            .debug_struct("LoggingGuard")
            .field("log_file", &self.log_file)
            .field("level", &self.level)
            .finish_non_exhaustive()
    }
}

impl LoggingGuard {
    /// The file records are written to.
    pub fn log_file(&self) -> &Path {
        &self.log_file
    }

    /// The level in force, after the override.
    pub fn level(&self) -> LogLevel {
        self.level
    }

    /// Forget the guard without flushing, for a worker that is gone.
    ///
    /// Only used on paths where the writer thread has already stopped.
    pub fn into_inner(self) -> tracing_appender::non_blocking::WorkerGuard {
        self.worker
    }
}

/// The level in force: command line, then configuration, then the default.
///
/// The default is already the configuration default, so the third step is the
/// configuration struct's own value; stating it here keeps the order in one
/// place instead of leaving it implicit in whichever caller happens to build the
/// configuration.
pub fn effective_level(config: &LoggingConfig, override_level: Option<LogLevel>) -> LogLevel {
    override_level.unwrap_or(config.level)
}

/// Map a configured level onto `tracing`'s.
pub fn tracing_level(level: LogLevel) -> tracing::Level {
    match level {
        LogLevel::Error => tracing::Level::ERROR,
        LogLevel::Warn => tracing::Level::WARN,
        LogLevel::Info => tracing::Level::INFO,
        LogLevel::Debug => tracing::Level::DEBUG,
        LogLevel::Trace => tracing::Level::TRACE,
    }
}

/// Targets that are pinned below the application level.
///
/// A curated list, not a guess: these are the libraries in this workspace's
/// dependency tree whose records would otherwise follow the application's level
/// and write request or transport detail into an audit's log. A crate that is
/// not listed here is not pinned, which is exactly why the list is short and
/// explicit rather than a catch-all.
const PINNED_TARGETS: &[&str] = &["ureq", "rustls", "hyper", "h2", "mio", "want"];

/// Per-target level policy for a configured application level.
pub fn targets(level: LogLevel) -> Targets {
    // Third parties never become more verbose than WARN, and never more verbose
    // than the application level: `--log-level error` must silence them too.
    let pinned = if level >= LogLevel::Warn {
        tracing::Level::WARN
    } else {
        tracing_level(level)
    };

    let mut targets = Targets::new().with_default(tracing_level(level));
    for target in PINNED_TARGETS {
        targets = targets.with_target(*target, pinned);
    }
    targets
}

/// Build the subscriber without installing it.
///
/// Returned separately from [`init`] so that a test can install it for its own
/// thread with `tracing::dispatcher::with_default` instead of claiming the whole
/// process, which would make the tests order-dependent.
pub fn subscriber(
    home: &AuditeurHome,
    config: &LoggingConfig,
    override_level: Option<LogLevel>,
) -> Result<(Dispatch, LoggingGuard), LoggingError> {
    config.validate()?;

    let level = effective_level(config, override_level);

    // The log file is decided by the configuration, not by the caller's home:
    // a caller that passes a bare home still gets the configured path, and one
    // that passes an already-configured home is unaffected.
    let layout = HomeLayout {
        log_file: config.file.clone(),
        ..home.layout().clone()
    };
    // This is a public boundary: a caller that hands in a configuration directly
    // must not be able to write outside the home through an absolute or escaping
    // path, so the composed layout is validated here and not only upstream.
    layout.validate().map_err(LoggingError::Config)?;
    let home = home.clone().with_layout(layout);
    let log_file = home.log_file();
    let directory = home.logs_dir();

    home.ensure_dir(&directory).map_err(|error| match error {
        ConfigError::CreateDir { path, source } => LoggingError::Directory { path, source },
        other => LoggingError::Config(other),
    })?;

    let file = rotating_writer(&log_file, config.max_size_bytes(), config.max_files).map_err(
        |source| LoggingError::File {
            path: log_file.clone(),
            source,
        },
    )?;

    // Redaction is applied inside the appender, so no byte reaches the file
    // handle un-redacted. The writer is non-blocking: a slow disk must not stall
    // an audit.
    let (writer, worker) = tracing_appender::non_blocking(RedactingWriter::new(file));

    let layer = fmt::layer()
        .with_writer(writer)
        // A file is read by people and by `grep`; colour escapes are for
        // terminals and would corrupt both.
        .with_ansi(false)
        .with_level(true)
        .with_target(true)
        .with_filter(targets(level));

    let dispatch: Dispatch = Registry::default().with(layer).into();
    let guard = LoggingGuard {
        worker,
        log_file,
        level,
    };
    Ok((dispatch, guard))
}

/// Install the subscriber as the process-global logger.
///
/// Called once, from the binary. Returns a guard that must be held until the
/// process is about to exit, or the last lines are lost.
pub fn init(
    home: &AuditeurHome,
    config: &LoggingConfig,
    override_level: Option<LogLevel>,
) -> Result<LoggingGuard, LoggingError> {
    let (dispatch, guard) = subscriber(home, config, override_level)?;
    match tracing::dispatcher::set_global_default(dispatch) {
        Ok(()) => Ok(guard),
        Err(_) => Err(LoggingError::AlreadyInstalled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn home_in(temp: &tempfile::TempDir) -> AuditeurHome {
        AuditeurHome::at(temp.path().join("auditeur"))
    }

    /// The home whose log path the configuration asks for.
    ///
    /// Mirrors what `subscriber` does, so a test reads the file that was
    /// actually written instead of the one a bare home would imply.
    fn configured_home(home: &AuditeurHome, config: &LoggingConfig) -> AuditeurHome {
        home.clone().with_layout(HomeLayout {
            log_file: config.file.clone(),
            ..home.layout().clone()
        })
    }

    /// Run `body` with logging installed for this thread only, then return what
    /// the log file contains.
    fn logged(
        home: &AuditeurHome,
        config: &LoggingConfig,
        override_level: Option<LogLevel>,
        body: impl FnOnce(),
    ) -> String {
        let (dispatch, guard) = subscriber(home, config, override_level).unwrap();
        tracing::dispatcher::with_default(&dispatch, body);
        drop(dispatch);
        // Dropping the guard flushes the worker; reading before this sees a
        // partially written file.
        drop(guard);
        fs::read_to_string(configured_home(home, config).log_file()).unwrap_or_default()
    }

    #[test]
    fn the_command_line_beats_the_configuration_which_beats_the_default() {
        let config = LoggingConfig {
            level: LogLevel::Warn,
            ..LoggingConfig::default()
        };
        assert_eq!(effective_level(&config, None), LogLevel::Warn);
        assert_eq!(
            effective_level(&config, Some(LogLevel::Debug)),
            LogLevel::Debug
        );

        let config = LoggingConfig::default();
        assert_eq!(
            effective_level(&config, None),
            LogLevel::Info,
            "the documented default"
        );
    }

    #[test]
    fn every_level_maps_onto_tracing() {
        assert_eq!(tracing_level(LogLevel::Error), tracing::Level::ERROR);
        assert_eq!(tracing_level(LogLevel::Warn), tracing::Level::WARN);
        assert_eq!(tracing_level(LogLevel::Info), tracing::Level::INFO);
        assert_eq!(tracing_level(LogLevel::Debug), tracing::Level::DEBUG);
        assert_eq!(tracing_level(LogLevel::Trace), tracing::Level::TRACE);
    }

    #[test]
    fn the_log_file_is_created_under_the_home_and_records_the_run_id() {
        let temp = tempfile::tempdir().unwrap();
        let home = home_in(&temp);
        let config = LoggingConfig::default();

        let text = logged(&home, &config, None, || {
            let span = tracing::info_span!("audit", run_id = "1790940176");
            let _entered = span.enter();
            tracing::info!("audit started");
        });

        assert_eq!(home.log_file(), home.root().join("logs/auditeur.log"));
        assert!(home.log_file().is_file(), "the log file must be created");
        assert!(text.contains("INFO"), "{text}");
        assert!(text.contains("audit started"), "{text}");
        // Level, target and the run id are all present.
        assert!(text.contains("auditeur_logging"), "target missing: {text}");
        assert!(text.contains("run_id"), "{text}");
        assert!(text.contains("1790940176"), "{text}");
        // A timestamp, in the RFC 3339 shape.
        assert!(text.contains("T") && text.contains("Z"), "{text}");
        assert!(temp.path().join("auditeur").is_dir());
    }

    #[test]
    fn the_configured_level_decides_what_is_written() {
        let temp = tempfile::tempdir().unwrap();
        let home = home_in(&temp);
        let config = LoggingConfig {
            level: LogLevel::Info,
            ..LoggingConfig::default()
        };

        let text = logged(&home, &config, None, || {
            tracing::debug!("invisible detail");
            tracing::info!("visible progress");
            tracing::warn!("visible warning");
        });

        assert!(!text.contains("invisible detail"), "{text}");
        assert!(text.contains("visible progress"), "{text}");
        assert!(text.contains("visible warning"), "{text}");
    }

    #[test]
    fn a_command_line_level_override_is_reported_and_applies_to_this_process() {
        let temp = tempfile::tempdir().unwrap();
        let home = home_in(&temp);
        let config = LoggingConfig {
            level: LogLevel::Info,
            ..LoggingConfig::default()
        };

        let (dispatch, guard) = subscriber(&home, &config, Some(LogLevel::Debug)).unwrap();
        assert_eq!(guard.level(), LogLevel::Debug);
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::debug!("override detail");
            tracing::info!("normal progress");
        });
        drop(dispatch);
        drop(guard);

        let text = fs::read_to_string(home.log_file()).unwrap();
        assert!(text.contains("override detail"), "{text}");

        // And the opposite direction: an error override silences info.
        let temp = tempfile::tempdir().unwrap();
        let home = home_in(&temp);
        assert!(!logged(&home, &config, Some(LogLevel::Error), || {
            tracing::info!("should not appear");
            tracing::error!("should appear");
        })
        .contains("should not appear"));
        let text = fs::read_to_string(home.log_file()).unwrap();
        assert!(text.contains("should appear"), "{text}");
    }

    #[test]
    fn a_credential_never_reaches_the_log_file() {
        let temp = tempfile::tempdir().unwrap();
        let home = home_in(&temp);
        let config = LoggingConfig {
            level: LogLevel::Debug,
            ..LoggingConfig::default()
        };

        // Assembled at run time: a secret-shaped literal may be rewritten on its
        // way to disk, which would make this test prove nothing.
        let aws_key = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
        let bearer = ["abcdefghijklmn", "opqrstuvwxyz012345"].concat();
        let password = ["correct-horse", "-battery-staple"].concat();

        // The assertions keep their own copies; the logging closure owns the
        // originals.
        let expected_absent = [aws_key.clone(), bearer.clone(), password.clone()];
        let text = logged(&home, &config, None, move || {
            tracing::info!("reading configuration from {}", "/etc/app/settings.py");
            tracing::info!("found AWS_ACCESS_KEY_ID = \"{aws_key}\" while scanning");
            tracing::info!("authorising with Bearer {bearer}");
            tracing::debug!("connection string postgres://user:{password}@db.internal/app");
        });

        for secret in &expected_absent {
            assert!(
                !text.contains(secret.as_str()),
                "the log file contains a credential"
            );
        }
        // The line is still useful: the context survives.
        assert!(text.contains("while scanning"), "{text}");
        assert!(text.contains("reading configuration from"), "{text}");
        assert!(text.contains("[REDACTED"), "{text}");
    }

    #[test]
    fn a_third_party_target_cannot_outshout_the_application_level() {
        let temp = tempfile::tempdir().unwrap();
        let home = home_in(&temp);
        let config = LoggingConfig {
            level: LogLevel::Debug,
            ..LoggingConfig::default()
        };

        let text = logged(&home, &config, None, || {
            tracing::debug!(target: "ureq", "third party debug detail");
            tracing::warn!(target: "ureq", "third party warning");
            tracing::debug!("application debug detail");
        });

        assert!(
            !text.contains("third party debug detail"),
            "a pinned target must not follow the application to DEBUG: {text}"
        );
        assert!(text.contains("third party warning"), "{text}");
        assert!(text.contains("application debug detail"), "{text}");
    }

    #[test]
    fn the_log_rotates_by_size_and_keeps_only_the_configured_number_of_files() {
        let temp = tempfile::tempdir().unwrap();
        let home = home_in(&temp);
        // One mebibyte is the smallest size the configuration accepts, so this
        // exercises the real wiring rather than a test-only path.
        let config = LoggingConfig {
            level: LogLevel::Info,
            max_size_mb: 1,
            max_files: 2,
            ..LoggingConfig::default()
        };

        logged(&home, &config, None, || {
            let line = "x".repeat(100);
            for index in 0..20_000 {
                tracing::info!("{index:06} {line}");
            }
        });

        let directory = home.logs_dir();
        let mut names: Vec<String> = fs::read_dir(&directory)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();

        assert!(names.contains(&"auditeur.log".to_string()), "{names:?}");
        assert!(
            names.len() > 1,
            "the log should have rotated at 1 MiB: {names:?}"
        );
        assert!(
            names.len() <= 3,
            "max_files = 2 keeps the active file plus two: {names:?}"
        );
        assert!(
            names.iter().all(|name| name.starts_with("auditeur.log")),
            "{names:?}"
        );
    }

    #[test]
    fn the_log_directory_is_created_lazily_by_logging() {
        let temp = tempfile::tempdir().unwrap();
        let home = home_in(&temp);
        assert!(!home.root().exists());

        let config = LoggingConfig::default();
        let text = logged(&home, &config, None, || tracing::info!("first line"));

        assert!(home.logs_dir().is_dir());
        assert!(text.contains("first line"), "{text}");
        // Only the log directory was needed; nothing else was created.
        assert!(!home.cache_dir().exists());
        assert!(!home.model_dir().exists());
        assert!(!home.runs_dir().exists());
        assert!(!home.config_dir().exists());
    }

    #[test]
    fn a_custom_log_location_is_honoured() {
        let temp = tempfile::tempdir().unwrap();
        let home = home_in(&temp);
        let config = LoggingConfig {
            file: "var/log/auditeur.log".to_string(),
            ..LoggingConfig::default()
        };

        let text = logged(&home, &config, None, || tracing::info!("elsewhere"));

        // The log file comes from the configuration, so a caller that passes a
        // bare home still gets the configured location.
        assert!(home.root().join("var/log/auditeur.log").is_file());
        assert_eq!(
            configured_home(&home, &config).logs_dir(),
            home.root().join("var/log")
        );
        // The bare home is untouched: nothing was created under logs/.
        assert!(!home.logs_dir().exists());
        assert!(text.contains("elsewhere"), "{text}");
    }

    #[test]
    fn an_invalid_configuration_is_refused_before_anything_is_created() {
        let temp = tempfile::tempdir().unwrap();
        let home = home_in(&temp);
        let config = LoggingConfig {
            max_files: 0,
            ..LoggingConfig::default()
        };
        let error = subscriber(&home, &config, None).unwrap_err();
        assert!(error.to_string().contains("max_files"), "{error}");
        assert!(!home.root().exists(), "nothing may be created on a refusal");
    }

    #[test]
    fn an_unwritable_log_directory_is_an_error_not_a_panic() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("not-a-directory");
        fs::write(&file, "x").unwrap();

        let home = AuditeurHome::at(file.join("auditeur"));
        let config = LoggingConfig::default();
        let error = subscriber(&home, &config, None).unwrap_err();
        // `file-rotate` creates the parent with an `expect`, so the refusal has
        // to happen here, before it is called.
        assert!(
            matches!(error, LoggingError::Directory { .. }),
            "expected a directory error, got {error}"
        );
    }

    #[test]
    fn the_same_worker_guard_is_handed_back_for_the_caller_to_hold() {
        let temp = tempfile::tempdir().unwrap();
        let home = home_in(&temp);
        let (_dispatch, guard) = subscriber(&home, &LoggingConfig::default(), None).unwrap();
        assert_eq!(guard.log_file(), home.log_file());
        assert_eq!(guard.level(), LogLevel::Info);
        let _worker = guard.into_inner();
    }
}
