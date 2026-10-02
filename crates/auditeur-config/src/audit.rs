//! Audit configuration (`config/audit.toml`).
//!
//! This is where the auditor states what an audit covers and how far it is
//! allowed to go. The limits here are the enforcement point for the resource
//! bounds described in SECURITY.md: discovery and reading take their caps from
//! [`LimitsConfig`], so a hostile repository cannot negotiate them.

use auditeur_model::{AuditCategory, Severity};
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Default directory names excluded from discovery.
///
/// These are build outputs, vendor trees and tool caches: they are large,
/// machine-generated, and inspecting them produces noise rather than findings.
pub const DEFAULT_IGNORED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".terraform",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".gradle",
    ".idea",
    ".vscode",
    "node_modules",
    "bower_components",
    "vendor",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "cmake-build-debug",
    "cmake-build-release",
    "Pods",
    "DerivedData",
    ".cache",
];

/// Programs Auditeur may execute when external tool execution is enabled.
///
/// Only analysis commands appear here. Formatters, fixers, dependency
/// installers, package managers, Git and anything that mutates repository
/// state are absent by design and cannot be added by audited content. A
/// project that needs `npm test` or `uv run` must add it explicitly via
/// configuration — and accept the residual risk documented in SECURITY.md.
pub const DEFAULT_ALLOWED_PROGRAMS: &[&str] = &[
    "cargo",
    "rustc",
    "clippy-driver",
    "go",
    "python3",
    "python",
    "ruff",
    "mypy",
    "pytest",
    "node",
    "deno",
    "terraform",
    "cmake",
    "make",
    "ninja",
    "julia",
    "Rscript",
];

/// Resource bounds applied during discovery and reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    /// Maximum size of a single inspected file, in bytes. Larger files are
    /// recorded as skipped with reason `too_large`.
    pub max_file_bytes: u64,
    /// Maximum number of files in the repository model.
    pub max_files: u32,
    /// Maximum total size of inspected files, in bytes.
    pub max_total_bytes: u64,
    /// Maximum directory depth below the repository root.
    pub max_depth: usize,
    /// Whether directory symlinks are followed. Defaults to `false`: a symlink
    /// is a way out of the repository, and the audit stays inside it.
    pub follow_symlinks: bool,
    /// Directory names excluded from discovery.
    pub ignore_dirs: Vec<String>,
    /// File names excluded from discovery, e.g. editor backups.
    pub ignore_files: Vec<String>,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: 1_048_576, // 1 MiB
            max_files: 20_000,
            max_total_bytes: 536_870_912, // 512 MiB
            max_depth: 24,
            follow_symlinks: false,
            ignore_dirs: DEFAULT_IGNORED_DIRS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            ignore_files: vec![".DS_Store".to_string(), "Thumbs.db".to_string()],
        }
    }
}

impl LimitsConfig {
    /// Whether a directory name is excluded.
    pub fn ignores_dir(&self, name: &str) -> bool {
        self.ignore_dirs.iter().any(|ignored| ignored == name)
    }

    /// Whether a file name is excluded.
    pub fn ignores_file(&self, name: &str) -> bool {
        self.ignore_files.iter().any(|ignored| ignored == name)
    }

    /// Enforce structural invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_file_bytes == 0 {
            return Err(ConfigError::invalid(
                "audit.limits.max_file_bytes",
                "must be greater than 0",
            ));
        }
        if self.max_files == 0 {
            return Err(ConfigError::invalid(
                "audit.limits.max_files",
                "must be greater than 0",
            ));
        }
        if self.max_total_bytes == 0 {
            return Err(ConfigError::invalid(
                "audit.limits.max_total_bytes",
                "must be greater than 0",
            ));
        }
        if self.max_depth == 0 {
            return Err(ConfigError::invalid(
                "audit.limits.max_depth",
                "must be greater than 0",
            ));
        }
        if self.max_total_bytes < self.max_file_bytes {
            return Err(ConfigError::invalid(
                "audit.limits.max_total_bytes",
                "must be at least audit.limits.max_file_bytes",
            ));
        }
        Ok(())
    }
}

/// How far the audit is allowed to go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Categories enabled for this project. An empty list is an error: it
    /// would produce an audit that reports nothing while appearing to succeed.
    pub enabled_categories: Vec<AuditCategory>,
    /// Findings below this severity are recorded in the manifest but omitted
    /// from the report body. Defaults to `info`, i.e. report everything.
    pub report_min_severity: Severity,
    /// A violation at or above this severity makes the run exit non-zero.
    pub fail_threshold: Severity,
    /// Whether external analysis tools may be executed. Off by default: it is
    /// the largest residual risk in the threat model.
    pub run_external_tools: bool,
    /// Programs that may be executed when `run_external_tools` is enabled.
    pub allowed_programs: Vec<String>,
    /// Resource bounds for discovery and reading.
    pub limits: LimitsConfig,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled_categories: AuditCategory::ALL.to_vec(),
            report_min_severity: Severity::Info,
            fail_threshold: Severity::High,
            run_external_tools: false,
            allowed_programs: DEFAULT_ALLOWED_PROGRAMS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            limits: LimitsConfig::default(),
        }
    }
}

impl AuditConfig {
    /// Whether a category is enabled.
    pub fn is_enabled(&self, category: AuditCategory) -> bool {
        self.enabled_categories.contains(&category)
    }

    /// Whether a finding at `severity` should appear in the report body.
    pub fn meets_report_threshold(&self, severity: Severity) -> bool {
        severity >= self.report_min_severity
    }

    /// Whether a program is allowed to be executed. Compared on the file name,
    /// so `/usr/bin/cargo` and `cargo` are the same program.
    pub fn allows_program(&self, program: &str) -> bool {
        let name = std::path::Path::new(program)
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| program.to_string());
        self.allowed_programs.iter().any(|allowed| allowed == &name)
    }

    /// Enforce structural invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled_categories.is_empty() {
            return Err(ConfigError::invalid(
                "audit.enabled_categories",
                "must enable at least one category",
            ));
        }
        if self.report_min_severity > self.fail_threshold {
            return Err(ConfigError::invalid(
                "audit.report_min_severity",
                "must not be greater than audit.fail_threshold",
            ));
        }
        self.limits.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_cover_every_category_and_execute_nothing() {
        let config = AuditConfig::default();
        assert_eq!(config.enabled_categories.len(), AuditCategory::ALL.len());
        assert!(!config.run_external_tools);
        assert_eq!(config.fail_threshold, Severity::High);
        assert_eq!(config.report_min_severity, Severity::Info);
        config.validate().unwrap();
    }

    #[test]
    fn empty_category_list_is_rejected() {
        let mut config = AuditConfig::default();
        config.enabled_categories.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn report_threshold_never_exceeds_fail_threshold() {
        let mut config = AuditConfig::default();
        config.report_min_severity = Severity::Critical;
        config.fail_threshold = Severity::Low;
        assert!(config.validate().is_err());
    }

    #[test]
    fn programs_are_matched_on_file_name_and_unknown_ones_are_refused() {
        let config = AuditConfig::default();
        assert!(config.allows_program("cargo"));
        assert!(config.allows_program("/opt/homebrew/bin/cargo"));
        assert!(!config.allows_program("git"));
        assert!(!config.allows_program("rm"));
        assert!(!config.allows_program("cargo-fix"));
    }

    #[test]
    fn ignore_lists_behave_case_sensitively() {
        let config = LimitsConfig::default();
        assert!(config.ignores_dir("node_modules"));
        assert!(config.ignores_dir("target"));
        assert!(!config.ignores_dir("src"));
        assert!(config.ignores_file(".DS_Store"));
        assert!(!config.ignores_file("main.rs"));
    }

    #[test]
    fn limits_reject_impossible_combinations() {
        let mut limits = LimitsConfig::default();
        limits.max_total_bytes = 10;
        limits.max_file_bytes = 100;
        assert!(limits.validate().is_err());

        let mut limits = LimitsConfig::default();
        limits.max_files = 0;
        assert!(limits.validate().is_err());
    }

    #[test]
    fn no_writing_program_is_in_the_default_allowlist() {
        for forbidden in [
            "rm",
            "mv",
            "cp",
            "sed",
            "git",
            "cargo-fix",
            "rustfmt",
            "prettier",
            "npm",
            "npx",
            "uv",
            "pip",
            "go-fix",
        ] {
            assert!(
                !DEFAULT_ALLOWED_PROGRAMS.contains(&forbidden),
                "{forbidden} must not be executable by default"
            );
        }
    }
}
