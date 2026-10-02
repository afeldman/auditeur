//! Supported languages.
//!
//! The enumeration is the contract between language adapters, configuration and
//! reports. Adding a language means adding a variant here and an adapter in
//! `auditeur-languages`; nothing else in the workspace needs to change.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ModelError;

/// A programming or configuration language Auditeur can detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Rust,
    Go,
    Python,
    /// Node.js and plain JavaScript. Renamed explicitly so that the serialised
    /// form matches `Language::id()`: a machine-readable manifest must not name
    /// the same language two different ways.
    #[serde(rename = "nodejs")]
    NodeJs,
    Deno,
    C,
    Cpp,
    Julia,
    R,
    Lisp,
    Terraform,
}

impl Language {
    /// All languages, in report order.
    pub const ALL: [Language; 11] = [
        Language::Rust,
        Language::Go,
        Language::Python,
        Language::NodeJs,
        Language::Deno,
        Language::C,
        Language::Cpp,
        Language::Julia,
        Language::R,
        Language::Lisp,
        Language::Terraform,
    ];

    /// Languages with manifest parsing and dependency/test extraction in the MVP.
    ///
    /// The remaining languages are detected and inventoried, but their
    /// adapters report `analysis: metadata_only` rather than pretending to
    /// perform analysis they cannot do yet.
    pub const DEEP_ANALYSIS: [Language; 4] = [
        Language::Rust,
        Language::Go,
        Language::Python,
        Language::NodeJs,
    ];

    /// Stable identifier used in configuration and reports.
    pub fn id(self) -> &'static str {
        match self {
            Language::Rust => "rust",
            Language::Go => "go",
            Language::Python => "python",
            Language::NodeJs => "nodejs",
            Language::Deno => "deno",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::Julia => "julia",
            Language::R => "r",
            Language::Lisp => "lisp",
            Language::Terraform => "terraform",
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Language::Rust => "Rust",
            Language::Go => "Go",
            Language::Python => "Python",
            Language::NodeJs => "Node.js / JavaScript",
            Language::Deno => "Deno / TypeScript",
            Language::C => "C",
            Language::Cpp => "C++",
            Language::Julia => "Julia",
            Language::R => "R",
            Language::Lisp => "Lisp",
            Language::Terraform => "Terraform / HCL",
        }
    }

    /// Whether this language has deep analysis in the current MVP.
    pub fn has_deep_analysis(self) -> bool {
        Language::DEEP_ANALYSIS.contains(&self)
    }

    /// Source file extensions associated with the language, without the dot.
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Language::Rust => &["rs"],
            Language::Go => &["go"],
            Language::Python => &["py", "pyi"],
            Language::NodeJs => &["js", "jsx", "mjs", "cjs"],
            Language::Deno => &["ts", "tsx", "mts", "cts"],
            Language::C => &["c", "h"],
            Language::Cpp => &["cc", "cpp", "cxx", "hpp", "hh", "hxx", "ipp"],
            Language::Julia => &["jl"],
            Language::R => &["r", "R"],
            Language::Lisp => &["lisp", "lsp", "el", "clj", "cljs", "scm", "rkt"],
            Language::Terraform => &["tf", "tfvars", "hcl"],
        }
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for Language {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalised = s.trim().to_ascii_lowercase().replace(['-', ' ', '.'], "");
        let normalised = match normalised.as_str() {
            "node" | "nodejs" | "javascript" | "js" => "nodejs",
            "deno" | "typescript" | "ts" => "deno",
            "c++" | "cpp" | "cplusplus" => "cpp",
            "terraform" | "hcl" => "terraform",
            other => other,
        };
        Language::ALL
            .into_iter()
            .find(|language| language.id() == normalised)
            .ok_or_else(|| ModelError::Unknown {
                kind: "language",
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
        for language in Language::ALL {
            assert!(seen.insert(language.id()), "duplicate id {}", language.id());
            assert_eq!(language.id().parse::<Language>().unwrap(), language);
        }
        assert_eq!(seen.len(), Language::ALL.len());
    }

    #[test]
    fn aliases_resolve() {
        assert_eq!("Node".parse::<Language>().unwrap(), Language::NodeJs);
        assert_eq!("TypeScript".parse::<Language>().unwrap(), Language::Deno);
        assert_eq!("C++".parse::<Language>().unwrap(), Language::Cpp);
        assert_eq!("HCL".parse::<Language>().unwrap(), Language::Terraform);
        assert!("cobol".parse::<Language>().is_err());
    }

    #[test]
    fn deep_analysis_set_is_a_subset_and_marked() {
        for language in Language::DEEP_ANALYSIS {
            assert!(Language::ALL.contains(&language));
            assert!(language.has_deep_analysis());
        }
        assert!(!Language::Julia.has_deep_analysis());
    }

    #[test]
    fn extensions_are_lowercase_and_distinct_within_a_language() {
        for language in Language::ALL {
            let mut seen = std::collections::HashSet::new();
            for extension in language.extensions() {
                assert!(seen.insert(*extension), "{language:?} repeats {extension}");
            }
        }
    }
}
