//! Where Auditeur's own directories live, relative to the home.
//!
//! Every value is a **relative** path under the Auditeur home. A configuration
//! file that named absolute paths would stop being portable: moving the home, or
//! restoring it from a backup on another machine, would break it. Whether a
//! value is safe is not decided here but in
//! [`crate::home::HomeLayout::validate`], so that the same rule applies to the
//! paths section and to the log file.

use serde::{Deserialize, Serialize};

use crate::home::{CACHE_DIR, MODEL_DIR, RUNS_DIR};

/// Directory names relative to the Auditeur home.
///
/// There is no `logs` key: the log *directory* is the parent of the log file
/// configured under `[logging]`, and two keys pointing at one location drift
/// apart. One setting decides where logs go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PathsConfig {
    /// Local model artefacts.
    pub model: String,
    /// Analysis cache.
    pub cache: String,
    /// Machine-readable audit runs.
    pub runs: String,
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            model: MODEL_DIR.to_string(),
            cache: CACHE_DIR.to_string(),
            runs: RUNS_DIR.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_documented_directory_names() {
        let paths = PathsConfig::default();
        assert_eq!(paths.model, "model");
        assert_eq!(paths.cache, "cache");
        assert_eq!(paths.runs, "runs");
    }

    #[test]
    fn the_defaults_are_relative_not_absolute() {
        let paths = PathsConfig::default();
        for value in [&paths.model, &paths.cache, &paths.runs] {
            assert!(
                !std::path::Path::new(value).is_absolute(),
                "'{value}' must stay portable"
            );
        }
    }
}
