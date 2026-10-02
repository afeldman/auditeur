//! Auditeur's terminal user interface.
//!
//! The TUI owns two screens — the setup wizard and the audit progress display —
//! and nothing else. It depends on configuration and on the engine's progress
//! sink, but the engine does not depend on it: a front-end is a client of the
//! core, which is what makes a second front-end (a desktop shell, later)
//! possible without touching the audit logic.
//!
//! The design that matters for maintenance: **state is separate from the
//! terminal**. [`WizardState`] is a plain state machine over
//! [`Key`](wizard::Key) values, and [`ui`] draws from that state. Only
//! [`terminal`] knows about raw mode and the alternate screen, so the interesting
//! behaviour is unit-testable against an in-memory backend.

pub mod progress;
pub mod terminal;
pub mod ui;
pub mod wizard;

pub use progress::{spawn_audit, ProgressHandle, ProgressState, RunningAudit};
pub use terminal::{run_audit_screen, run_setup_wizard, TuiError};
pub use wizard::{Action, Field, Key, Step, WizardState, WrittenConfiguration};
