//! Domain types for Auditeur.
//!
//! This crate is intentionally free of I/O. It defines the vocabulary the rest
//! of the workspace uses — languages, evidence, findings, run manifests — so
//! that no crate has to invent its own representation of an audit result.

pub mod category;
pub mod error;
pub mod evidence;
pub mod finding;
pub mod hash;
pub mod language;
pub mod manifest;
pub mod redact;
pub mod version;

pub use category::AuditCategory;
pub use error::ModelError;
pub use evidence::{Evidence, EvidenceKind, EvidenceLocation, EvidenceRef};
pub use finding::{Confidence, Finding, FindingSource, Severity, Status};
pub use hash::sha256_hex;
pub use language::Language;
pub use manifest::{
    AuditScope, DefinitionRef, FindingCounts, GitState, LimitPolicy, Limitation, ModelRef,
    RepositoryFingerprint, RepositoryInfo, RunManifest, SkipReason, SkipRecord, ToolExecution,
};
pub use version::{AUDITEUR_VERSION, AUDIT_SCHEMA_VERSION, REPORT_SCHEMA_VERSION};
