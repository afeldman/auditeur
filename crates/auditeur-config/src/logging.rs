//! The logging configuration.
//!
//! Logs are operational artefacts — what the process did, for an operator or a
//! developer debugging a run. They are deliberately **not** audit evidence: the
//! evidence of an audit lives in `runs/<run-id>/{manifest,findings,evidence}.json`.
//! Nothing in the audit model reads a log file, and nothing in the audit model
//! may be derived from one.

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::home::DEFAULT_LOG_FILE;

/// Severity threshold for the log file.
///
/// Ordered the way `tracing` orders levels — `Error` is the least verbose
/// setting and `Trace` the most — so that [`LogLevel::allows`] is a comparison
/// rather than a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Errors and warnings.
    Warn,
    /// Errors, warnings and progress. The default.
    Info,
    /// Adds developer detail.
    Debug,
    /// Adds everything, including third-party crates below their own pin.
    Trace,
}

impl LogLevel {
    /// Every level, least verbose first.
    pub const ALL: [LogLevel; 5] = [
        LogLevel::Error,
        LogLevel::Warn,
        LogLevel::Info,
        LogLevel::Debug,
        LogLevel::Trace,
    ];

    /// Stable identifier, the spelling used in configuration and on the command
    /// line.
    pub fn id(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }

    /// Whether an event at `event` is written when this level is configured.
    pub fn allows(self, event: LogLevel) -> bool {
        event <= self
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.id())
    }
}

impl std::str::FromStr for LogLevel {
    type Err = ConfigError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "error" | "err" => Ok(LogLevel::Error),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            other => Err(ConfigError::invalid(
                "logging.level",
                format!(
                    "'{other}' is not a log level; expected one of {}",
                    LogLevel::ALL
                        .iter()
                        .map(|level| level.id())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
        }
    }
}

/// Rolling log file settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Threshold written to the log file.
    pub level: LogLevel,
    /// Log file, relative to the Auditeur home. Its parent directory is the log
    /// directory.
    pub file: String,
    /// Rotate when the active file would exceed this size.
    pub max_size_mb: u64,
    /// How many rotated files to keep, in addition to the active one.
    ///
    /// With `max_files = 5` the directory holds `auditeur.log`,
    /// `auditeur.log.1` … `auditeur.log.5`.
    pub max_files: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            file: DEFAULT_LOG_FILE.to_string(),
            max_size_mb: Self::DEFAULT_MAX_SIZE_MB,
            max_files: Self::DEFAULT_MAX_FILES,
        }
    }
}

impl LoggingConfig {
    /// Default rotation size in mebibytes.
    pub const DEFAULT_MAX_SIZE_MB: u64 = 20;
    /// Default number of rotated files kept.
    pub const DEFAULT_MAX_FILES: u32 = 5;

    /// The rotation threshold in bytes.
    ///
    /// Returned as a byte count rather than a configured string on purpose: a
    /// value handed to a rotation library unchanged is how a size ends up being
    /// parsed as a duration.
    pub fn max_size_bytes(&self) -> u64 {
        self.max_size_mb * 1024 * 1024
    }

    /// Structural validation. The file path is validated with the layout, so
    /// that one rule covers every configured path.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_size_mb == 0 {
            return Err(ConfigError::invalid(
                "logging.max_size_mb",
                "must be at least 1; use a smaller max_files or level instead of no rotation",
            ));
        }
        if self.max_files == 0 {
            return Err(ConfigError::invalid(
                "logging.max_files",
                "must keep at least one rotated file",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_values() {
        let logging = LoggingConfig::default();
        assert_eq!(logging.level, LogLevel::Info);
        assert_eq!(logging.file, "logs/auditeur.log");
        assert_eq!(logging.max_size_mb, 20);
        assert_eq!(logging.max_files, 5);
        assert_eq!(logging.max_size_bytes(), 20 * 1024 * 1024);
        logging.validate().unwrap();
    }

    #[test]
    fn the_default_file_is_relative() {
        assert!(!std::path::Path::new(&LoggingConfig::default().file).is_absolute());
    }

    #[test]
    fn levels_parse_leniently_and_render_as_their_id() {
        assert_eq!("INFO".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!(" Debug ".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("warning".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        for level in LogLevel::ALL {
            assert_eq!(level.id().parse::<LogLevel>().unwrap(), level);
            assert_eq!(level.to_string(), level.id());
        }
        let error = "loud".parse::<LogLevel>().unwrap_err();
        assert!(error.to_string().contains("logging.level"), "{error}");
    }

    #[test]
    fn a_level_allows_itself_and_quieter_events_only() {
        assert!(LogLevel::Info.allows(LogLevel::Error));
        assert!(LogLevel::Info.allows(LogLevel::Info));
        assert!(!LogLevel::Info.allows(LogLevel::Debug));
        assert!(!LogLevel::Warn.allows(LogLevel::Info));
        assert!(LogLevel::Trace.allows(LogLevel::Trace));
        assert!(!LogLevel::Error.allows(LogLevel::Warn));
    }

    #[test]
    fn zero_rotation_values_are_refused() {
        let logging = LoggingConfig {
            max_size_mb: 0,
            ..LoggingConfig::default()
        };
        let error = logging.validate().unwrap_err();
        assert!(error.to_string().contains("max_size_mb"), "{error}");

        let logging = LoggingConfig {
            max_files: 0,
            ..LoggingConfig::default()
        };
        let error = logging.validate().unwrap_err();
        assert!(error.to_string().contains("max_files"), "{error}");
    }

    #[test]
    fn the_config_round_trips_through_toml_with_lowercase_levels() {
        let logging = LoggingConfig {
            level: LogLevel::Debug,
            max_size_mb: 5,
            ..LoggingConfig::default()
        };
        let text = toml::to_string(&logging).unwrap();
        assert!(text.contains("level = \"debug\""), "{text}");
        let parsed: LoggingConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed, logging);
    }
}
