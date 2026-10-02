//! Auditeur configuration: strongly typed TOML settings and the project layout.
//!
//! Precedence, in increasing order of authority: compiled defaults, files in
//! `<project>/config/`, `AUDITEUR_*` environment variables, CLI flags.

// Test fixtures build configurations field by field, which reads better than a
// twelve-field struct literal. Production code is still held to the lint.
#![cfg_attr(test, allow(clippy::field_reassign_with_default))]

pub mod audit;
pub mod env;
pub mod error;
pub mod home;
pub mod load;
pub mod logging;
pub mod model;
pub mod paths;
pub mod project;

pub use audit::{AuditConfig, LimitsConfig, DEFAULT_ALLOWED_PROGRAMS, DEFAULT_IGNORED_DIRS};
pub use error::ConfigError;
pub use home::{AuditeurHome, Discovery, HomeLayout, HomeOrigin};
pub use load::{AuditeurConfig, LoadedConfig};
pub use logging::{LogLevel, LoggingConfig};
pub use model::{BackendKind, ModelConfig};
pub use paths::PathsConfig;
pub use project::{
    derive_project_name, source_folder_name, validate_project_name, ProjectConfig, ReportingConfig,
};
