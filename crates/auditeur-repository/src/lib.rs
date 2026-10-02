//! The read-only repository boundary.
//!
//! This is the only crate in the workspace that touches the audited filesystem
//! or spawns a process, and it exposes no write operation on the audited tree.
//! Everything above it receives data — a [`RepositoryModel`], fingerprints,
//! command output — rather than paths to go and read for themselves.
//!
//! [`RepositoryModel`]: discovery::RepositoryModel

pub mod classify;
pub mod discovery;
pub mod error;
pub mod exec;
pub mod fingerprint;
pub mod git;
pub mod guard;
pub mod host;

pub use classify::{
    classify_file, is_binary_extension, kind_from_bytes, language_for_path, FileKind,
};
pub use discovery::{
    discover, DiscoveryOptions, RepositoryModel, SourceFile, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILES,
    DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_TOTAL_BYTES,
};
pub use error::RepositoryError;
pub use exec::{
    is_path_inside, CommandOutput, CommandRequest, CommandRunner, ExecPolicy,
    DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_TIMEOUT,
};
pub use fingerprint::{
    diff_fingerprints, fingerprint_tree, ChangeKind, ChangeRecord, FingerprintOptions,
    ReadOnlyGuard, TreeEntry, TreeFingerprint,
};
pub use git::{count_status_entries, strip_url_credentials, GitProbe, GitProbeResult};
pub use guard::{to_slash_path, PathGuard};
pub use host::{probe, probe_first_available, probe_with_environment, HostProbe, PROBE_TIMEOUT};
