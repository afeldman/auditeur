//! Errors raised by domain-type parsing.

/// Error produced when converting a string into a domain enumeration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    /// A value did not match any known variant of the named enumeration.
    #[error("unknown {kind}: '{value}'")]
    Unknown {
        /// Which enumeration was being parsed, e.g. `"language"`.
        kind: &'static str,
        /// The offending value, as supplied by the caller.
        value: String,
    },
    /// A value matched a known variant but was structurally invalid.
    #[error("{0}")]
    Invalid(String),
}
