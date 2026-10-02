//! Version constants.
//!
//! Two different things are versioned here and they must not be conflated:
//!
//! * [`AUDITEUR_VERSION`] — the build version of the tool itself.
//! * [`AUDIT_SCHEMA_VERSION`] — the version of the serialised audit result
//!   (manifest / findings / evidence). Any change to those structures that a
//!   consumer could observe requires a bump, because historical runs must stay
//!   interpretable.
//! * [`REPORT_SCHEMA_VERSION`] — the version of the generated report document.

/// Version of the Auditeur build producing an audit run.
pub const AUDITEUR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the machine-readable audit result schema.
pub const AUDIT_SCHEMA_VERSION: &str = "1.0.0";

/// Version of the human-readable report document layout.
pub const REPORT_SCHEMA_VERSION: &str = "1.0.0";
