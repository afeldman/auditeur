//! Environment-variable override names.
//!
//! Precedence is: compiled defaults, then configuration files, then these
//! variables, then CLI flags. Collecting the names in one module keeps the
//! documented precedence and the implementation in step.

/// Overrides the Auditeur home directory (`~/auditeur` by default).
///
/// The single authoritative override for where Auditeur keeps its state.
pub const HOME: &str = "AUDITEUR_HOME";
/// The pre-1.0 name for [`HOME`], still honoured but no longer documented.
///
/// Kept because ignoring a variable a user has already exported would silently
/// put their state somewhere else; using it prints a note instead.
pub const PROJECT_ROOT: &str = "AUDITEUR_PROJECT_ROOT";
/// Overrides the audited repository path.
pub const SOURCE_PATH: &str = "AUDITEUR_SOURCE_PATH";
/// Overrides the inference backend id.
pub const MODEL_BACKEND: &str = "AUDITEUR_MODEL_BACKEND";
/// Overrides the inference endpoint URL.
pub const MODEL_ENDPOINT: &str = "AUDITEUR_MODEL_ENDPOINT";
/// Overrides the model identifier.
pub const MODEL_NAME: &str = "AUDITEUR_MODEL_NAME";
/// Overrides the name of the environment variable holding the API key.
pub const MODEL_API_KEY_ENV: &str = "AUDITEUR_MODEL_API_KEY_ENV";
/// Enables or disables AI-assisted analysis (`true`/`false`).
pub const AI_ENABLED: &str = "AUDITEUR_AI_ENABLED";
/// Enables or disables external tool execution (`true`/`false`).
pub const RUN_EXTERNAL_TOOLS: &str = "AUDITEUR_RUN_EXTERNAL_TOOLS";
/// Overrides the enabled audit categories (comma-separated, or `all`).
pub const ENABLED_CATEGORIES: &str = "AUDITEUR_ENABLED_CATEGORIES";

/// Every variable Auditeur reads, for `doctor` output.
pub const ALL: &[&str] = &[
    HOME,
    PROJECT_ROOT,
    SOURCE_PATH,
    MODEL_BACKEND,
    MODEL_ENDPOINT,
    MODEL_NAME,
    MODEL_API_KEY_ENV,
    AI_ENABLED,
    RUN_EXTERNAL_TOOLS,
    ENABLED_CATEGORIES,
];
