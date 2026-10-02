//! Audit categories.
//!
//! Categories are the coarse axis along which audit definitions are organised
//! and results are grouped. The set is deliberately fixed in the MVP: a
//! free-form category string would make report grouping and definition
//! selection unverifiable.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ModelError;

/// The category an audit definition and its findings belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    Architecture,
    CodeQuality,
    Security,
    Dependencies,
    Testing,
    ErrorHandling,
    ApiDesign,
    Documentation,
    CiCd,
    Configuration,
    Infrastructure,
    Performance,
    Concurrency,
    Maintainability,
    ReleaseReadiness,
}

impl AuditCategory {
    /// All categories, in report order.
    pub const ALL: [AuditCategory; 15] = [
        AuditCategory::Architecture,
        AuditCategory::CodeQuality,
        AuditCategory::Security,
        AuditCategory::Dependencies,
        AuditCategory::Testing,
        AuditCategory::ErrorHandling,
        AuditCategory::ApiDesign,
        AuditCategory::Documentation,
        AuditCategory::CiCd,
        AuditCategory::Configuration,
        AuditCategory::Infrastructure,
        AuditCategory::Performance,
        AuditCategory::Concurrency,
        AuditCategory::Maintainability,
        AuditCategory::ReleaseReadiness,
    ];

    /// Stable identifier used in configuration, definitions and reports.
    pub fn id(self) -> &'static str {
        match self {
            AuditCategory::Architecture => "architecture",
            AuditCategory::CodeQuality => "code_quality",
            AuditCategory::Security => "security",
            AuditCategory::Dependencies => "dependencies",
            AuditCategory::Testing => "testing",
            AuditCategory::ErrorHandling => "error_handling",
            AuditCategory::ApiDesign => "api_design",
            AuditCategory::Documentation => "documentation",
            AuditCategory::CiCd => "ci_cd",
            AuditCategory::Configuration => "configuration",
            AuditCategory::Infrastructure => "infrastructure",
            AuditCategory::Performance => "performance",
            AuditCategory::Concurrency => "concurrency",
            AuditCategory::Maintainability => "maintainability",
            AuditCategory::ReleaseReadiness => "release_readiness",
        }
    }

    /// Human-readable label for reports and the setup wizard.
    pub fn label(self) -> &'static str {
        match self {
            AuditCategory::Architecture => "Architecture",
            AuditCategory::CodeQuality => "Code quality",
            AuditCategory::Security => "Security",
            AuditCategory::Dependencies => "Dependencies",
            AuditCategory::Testing => "Testing",
            AuditCategory::ErrorHandling => "Error handling",
            AuditCategory::ApiDesign => "API / interface design",
            AuditCategory::Documentation => "Documentation",
            AuditCategory::CiCd => "CI / CD",
            AuditCategory::Configuration => "Configuration",
            AuditCategory::Infrastructure => "Infrastructure",
            AuditCategory::Performance => "Performance",
            AuditCategory::Concurrency => "Concurrency",
            AuditCategory::Maintainability => "Maintainability",
            AuditCategory::ReleaseReadiness => "Release readiness",
        }
    }
}

impl fmt::Display for AuditCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for AuditCategory {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalised = s.trim().to_ascii_lowercase().replace(['-', ' ', '/'], "_");
        AuditCategory::ALL
            .into_iter()
            .find(|category| category.id() == normalised)
            .ok_or_else(|| ModelError::Unknown {
                kind: "audit category",
                value: s.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_round_trip() {
        let mut seen = std::collections::HashSet::new();
        for category in AuditCategory::ALL {
            assert!(seen.insert(category.id()), "duplicate id {}", category.id());
            assert_eq!(category.id().parse::<AuditCategory>().unwrap(), category);
        }
        assert_eq!(seen.len(), 15);
    }

    #[test]
    fn parsing_is_forgiving_about_case_and_separators() {
        assert_eq!(
            "Code-Quality".parse::<AuditCategory>().unwrap(),
            AuditCategory::CodeQuality
        );
        assert_eq!(
            " CI/CD ".parse::<AuditCategory>().unwrap(),
            AuditCategory::CiCd
        );
        assert!("nonsense".parse::<AuditCategory>().is_err());
    }

    #[test]
    fn serde_representation_is_the_stable_id() {
        let json = serde_json::to_string(&AuditCategory::CiCd).unwrap();
        assert_eq!(json, "\"ci_cd\"");
    }

    #[test]
    fn labels_are_distinct_for_the_report() {
        let mut labels = std::collections::HashSet::new();
        for category in AuditCategory::ALL {
            assert!(labels.insert(category.label()));
        }
    }
}
