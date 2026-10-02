//! Evidence — the atomic unit of proof.
//!
//! Evidence is the only thing a finding may cite. It is either observed
//! directly by Auditeur (deterministic evidence) or cited by a model and then
//! re-verified against the repository model (AI-assisted evidence). Both cases
//! use the same structure, so a reader of `evidence.json` cannot distinguish
//! them by shape — only by `Finding::source`.

use serde::{Deserialize, Serialize};

use crate::hash::{sha256_hex, short_id};
use crate::redact::{redact_text, truncate_chars};

/// Maximum length of an evidence excerpt stored in a report.
///
/// Excerpts are for verification by a human, not for reproducing the file.
pub const MAX_EXCERPT_CHARS: usize = 600;

/// What kind of thing was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A line range inside a file.
    FileRange,
    /// A whole file (structure, presence, digest), not its content.
    FileContent,
    /// A directory or directory listing.
    Directory,
    /// Captured stdout/stderr of an executed command.
    CommandOutput,
    /// A Git object: commit, branch, tag, dirty working tree.
    GitRef,
    /// A declared dependency read from a manifest or lockfile.
    Dependency,
    /// A key/value inside a configuration file.
    ConfigValue,
    /// A structural observation from a language parser.
    AstObservation,
    /// The result of an external analysis tool.
    ToolResult,
}

impl EvidenceKind {
    /// Human-readable label used in reports.
    pub fn label(self) -> &'static str {
        match self {
            EvidenceKind::FileRange => "file range",
            EvidenceKind::FileContent => "file",
            EvidenceKind::Directory => "directory",
            EvidenceKind::CommandOutput => "command output",
            EvidenceKind::GitRef => "git reference",
            EvidenceKind::Dependency => "dependency",
            EvidenceKind::ConfigValue => "configuration value",
            EvidenceKind::AstObservation => "AST observation",
            EvidenceKind::ToolResult => "tool result",
        }
    }
}

/// Where the observation was made.
///
/// Locations are structured rather than formatted strings so that a verifier
/// (human or tool) can resolve them mechanically, and so that the report can
/// render `src/server.rs:42-57` without parsing prose.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceLocation {
    /// A file, addressed relative to the repository root.
    File { path: String },
    /// A line range inside a file. `start_line`/`end_line` are 1-based, inclusive.
    FileRange {
        path: String,
        start_line: u32,
        end_line: u32,
    },
    /// A directory, addressed relative to the repository root.
    Directory { path: String },
    /// An executed command.
    Command {
        program: String,
        args: Vec<String>,
        exit_code: Option<i32>,
    },
    /// A Git commit and optionally a symbolic reference.
    Git {
        commit: String,
        reference: Option<String>,
    },
    /// A declared dependency.
    Dependency {
        name: String,
        version: String,
        manifest: String,
    },
    /// A configuration key inside a file.
    ConfigValue { file: String, key: String },
    /// A parsed language construct.
    Ast {
        path: String,
        node: String,
        line: u32,
    },
}

impl EvidenceLocation {
    /// One-line rendering used in reports and logs.
    pub fn describe(&self) -> String {
        match self {
            EvidenceLocation::File { path } => path.clone(),
            EvidenceLocation::FileRange {
                path,
                start_line,
                end_line,
            } => {
                if start_line == end_line {
                    format!("{path}:{start_line}")
                } else {
                    format!("{path}:{start_line}-{end_line}")
                }
            }
            EvidenceLocation::Directory { path } => format!("{path}/"),
            EvidenceLocation::Command {
                program,
                args,
                exit_code,
            } => {
                let rendered = std::iter::once(program.clone())
                    .chain(args.iter().cloned())
                    .collect::<Vec<_>>()
                    .join(" ");
                match exit_code {
                    Some(code) => format!("{rendered} (exit {code})"),
                    None => rendered,
                }
            }
            EvidenceLocation::Git { commit, reference } => match reference {
                Some(reference) => format!("{reference}@{commit}"),
                None => commit.clone(),
            },
            EvidenceLocation::Dependency {
                name,
                version,
                manifest,
            } => format!("{name} {version} ({manifest})"),
            EvidenceLocation::ConfigValue { file, key } => format!("{file}#{key}"),
            EvidenceLocation::Ast { path, node, line } => format!("{path}:{line} ({node})"),
        }
    }

    /// Repository-relative path this location refers to, if any.
    pub fn path(&self) -> Option<&str> {
        match self {
            EvidenceLocation::File { path }
            | EvidenceLocation::FileRange { path, .. }
            | EvidenceLocation::Directory { path }
            | EvidenceLocation::Ast { path, .. } => Some(path),
            EvidenceLocation::ConfigValue { file, .. } => Some(file),
            EvidenceLocation::Dependency { manifest, .. } => Some(manifest),
            EvidenceLocation::Command { .. } | EvidenceLocation::Git { .. } => None,
        }
    }

    /// The line range this location refers to, if any.
    pub fn line_range(&self) -> Option<(u32, u32)> {
        match self {
            EvidenceLocation::FileRange {
                start_line,
                end_line,
                ..
            } => Some((*start_line, *end_line)),
            EvidenceLocation::Ast { line, .. } => Some((*line, *line)),
            _ => None,
        }
    }
}

/// A verified observation about the audited repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Stable content-derived identifier, referenced by findings.
    pub id: String,
    /// What kind of observation this is.
    pub kind: EvidenceKind,
    /// Where the observation was made.
    pub location: EvidenceLocation,
    /// One-line, human-readable statement of what was observed.
    pub summary: String,
    /// Bounded, redacted excerpt supporting the summary, if useful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    /// SHA-256 of the exact bytes the observation was derived from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

impl Evidence {
    /// Create evidence and derive its stable identifier.
    pub fn new(kind: EvidenceKind, location: EvidenceLocation, summary: impl Into<String>) -> Self {
        let summary = summary.into();
        let id = short_id(&[kind.label(), "|", &location.describe(), "|", &summary]);
        Self {
            id,
            kind,
            location,
            summary,
            excerpt: None,
            digest: None,
        }
    }

    /// Attach an excerpt of the source, redacted and truncated.
    ///
    /// Redaction happens here rather than at the report boundary so that there
    /// is exactly one place where repository text is allowed to enter an audit
    /// result, log line or prompt.
    pub fn with_excerpt(mut self, text: &str) -> Self {
        let redacted = redact_text(text);
        self.excerpt = Some(truncate_chars(&redacted, MAX_EXCERPT_CHARS));
        self
    }

    /// Attach the digest of the raw bytes this evidence came from.
    pub fn with_digest(mut self, bytes: &[u8]) -> Self {
        self.digest = Some(sha256_hex(bytes));
        self
    }

    /// A reference suitable for inclusion in a finding.
    pub fn reference(&self) -> EvidenceRef {
        EvidenceRef {
            evidence_id: self.id.clone(),
            note: None,
        }
    }

    /// Convenience constructor for a file-level observation.
    pub fn file(path: impl Into<String>, summary: impl Into<String>) -> Self {
        Evidence::new(
            EvidenceKind::FileContent,
            EvidenceLocation::File { path: path.into() },
            summary,
        )
    }

    /// Convenience constructor for a line-range observation.
    pub fn file_range(
        path: impl Into<String>,
        start_line: u32,
        end_line: u32,
        summary: impl Into<String>,
    ) -> Self {
        Evidence::new(
            EvidenceKind::FileRange,
            EvidenceLocation::FileRange {
                path: path.into(),
                start_line,
                end_line,
            },
            summary,
        )
    }

    /// Convenience constructor for a configuration value.
    pub fn config(
        file: impl Into<String>,
        key: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Evidence::new(
            EvidenceKind::ConfigValue,
            EvidenceLocation::ConfigValue {
                file: file.into(),
                key: key.into(),
            },
            summary,
        )
    }

    /// Convenience constructor for a dependency declaration.
    pub fn dependency(
        name: impl Into<String>,
        version: impl Into<String>,
        manifest: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Evidence::new(
            EvidenceKind::Dependency,
            EvidenceLocation::Dependency {
                name: name.into(),
                version: version.into(),
                manifest: manifest.into(),
            },
            summary,
        )
    }

    /// Convenience constructor for a directory-level observation.
    pub fn directory(path: impl Into<String>, summary: impl Into<String>) -> Self {
        Evidence::new(
            EvidenceKind::Directory,
            EvidenceLocation::Directory { path: path.into() },
            summary,
        )
    }
}

/// A pointer from a finding to evidence stored in the run evidence set.
///
/// Findings reference evidence by id rather than embedding it, so that one
/// observation can support several findings without duplication and so that
/// the verification step has exactly one set of objects to validate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// Id of the referenced [`Evidence`].
    pub evidence_id: String,
    /// Optional note explaining why this evidence supports the finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl EvidenceRef {
    /// Reference an evidence item without an explanatory note.
    pub fn to(evidence: &Evidence) -> Self {
        evidence.reference()
    }

    /// Reference an evidence item with an explanatory note.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_stable_and_location_sensitive() {
        let a = Evidence::file_range("src/main.rs", 1, 3, "three lines");
        let b = Evidence::file_range("src/main.rs", 1, 3, "three lines");
        let c = Evidence::file_range("src/main.rs", 1, 4, "three lines");
        assert_eq!(a.id, b.id);
        assert_ne!(a.id, c.id);
    }

    #[test]
    fn locations_describe_themselves_as_addresses() {
        assert_eq!(
            EvidenceLocation::FileRange {
                path: "src/server.rs".into(),
                start_line: 42,
                end_line: 57
            }
            .describe(),
            "src/server.rs:42-57"
        );
        assert_eq!(
            EvidenceLocation::FileRange {
                path: "src/server.rs".into(),
                start_line: 7,
                end_line: 7
            }
            .describe(),
            "src/server.rs:7"
        );
        assert_eq!(
            EvidenceLocation::Dependency {
                name: "serde".into(),
                version: "1.0".into(),
                manifest: "Cargo.toml".into()
            }
            .describe(),
            "serde 1.0 (Cargo.toml)"
        );
    }

    #[test]
    fn excerpts_are_redacted_at_construction() {
        let evidence = Evidence::file("config/app.toml", "configuration file")
            .with_excerpt("api_key = \"supersecretvalue123\"\n");
        let excerpt = evidence.excerpt.unwrap();
        assert!(
            !excerpt.contains("supersecretvalue123"),
            "excerpt: {excerpt}"
        );
        assert!(excerpt.contains("[REDACTED"));
    }

    #[test]
    fn excerpts_are_truncated() {
        let long = "x".repeat(MAX_EXCERPT_CHARS * 2);
        let evidence = Evidence::file("a.txt", "long file").with_excerpt(&long);
        assert!(evidence.excerpt.unwrap().chars().count() <= MAX_EXCERPT_CHARS + 1);
    }

    #[test]
    fn digest_is_the_hash_of_the_raw_bytes() {
        let evidence = Evidence::file("a.txt", "file").with_digest(b"abc");
        assert_eq!(
            evidence.digest.unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn evidence_round_trips_through_json() {
        let evidence = Evidence::file_range("src/a.rs", 1, 2, "summary")
            .with_excerpt("code")
            .with_digest(b"code");
        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, evidence);
    }
}
