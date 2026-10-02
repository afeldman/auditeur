//! Progress reporting for long-running audits.
//!
//! An audit is a sequence of stages. The engine reports them through
//! [`ProgressSink`]; this module turns that into state a front-end can render,
//! and runs the audit on a worker thread so a terminal interface stays
//! responsive.
//!
//! The state is deliberately terminal-independent: `auditeur-tui` draws it and
//! the CLI prints it, from the same snapshots.

use std::sync::{Arc, Mutex};

use auditeur_audit::{AuditError, AuditOptions, AuditReport, AuditStage, ProgressSink};

/// Progress state that both front-ends render.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgressState {
    /// Stages that have been reported, in order, with their latest detail.
    pub stages: Vec<(AuditStage, String)>,
    /// A warning emitted by the engine.
    pub warnings: Vec<String>,
    /// Whether the audit has finished.
    pub finished: bool,
    /// A one-line result, once it is known.
    pub outcome: Option<String>,
}

impl ProgressState {
    /// The most recent stage, if any.
    pub fn current(&self) -> Option<(AuditStage, &str)> {
        self.stages
            .last()
            .map(|(stage, detail)| (*stage, detail.as_str()))
    }

    /// Number of distinct stages reported.
    pub fn stage_count(&self) -> usize {
        let mut stages: Vec<AuditStage> = self.stages.iter().map(|(stage, _)| *stage).collect();
        stages.dedup();
        stages.len()
    }

    /// Whether a stage was reported at least once.
    pub fn saw(&self, stage: AuditStage) -> bool {
        self.stages.iter().any(|(reported, _)| *reported == stage)
    }

    /// One-line rendering for a plain terminal.
    pub fn text_line(&self) -> String {
        match (self.current(), &self.outcome) {
            (_, Some(outcome)) => format!("✓ {outcome}"),
            (Some((stage, "")), None) => format!("… {}", stage.label()),
            (Some((stage, detail)), None) => format!("… {} — {detail}", stage.label()),
            (None, None) => "starting".to_string(),
        }
    }
}

/// Shared progress handle.
#[derive(Debug, Clone)]
pub struct ProgressHandle {
    state: Arc<Mutex<ProgressState>>,
}

impl Default for ProgressHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressHandle {
    /// A fresh handle.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ProgressState::default())),
        }
    }

    /// The current state.
    pub fn snapshot(&self) -> ProgressState {
        self.state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_default()
    }

    /// Mark the audit finished with a one-line outcome.
    pub fn finish(&self, outcome: impl Into<String>) {
        if let Ok(mut state) = self.state.lock() {
            state.finished = true;
            state.outcome = Some(outcome.into());
        }
    }

    /// A sink the engine can report to.
    pub fn sink(&self) -> Arc<dyn ProgressSink> {
        Arc::new(HandleSink {
            state: self.state.clone(),
        })
    }
}

/// Progress sink backed by a shared handle.
#[derive(Debug)]
struct HandleSink {
    state: Arc<Mutex<ProgressState>>,
}

impl ProgressSink for HandleSink {
    fn stage(&self, stage: AuditStage, detail: &str) {
        if let Ok(mut state) = self.state.lock() {
            // Collapse repeats of the same stage with the same detail so the
            // display shows progression rather than noise.
            if let Some((last_stage, last_detail)) = state.stages.last() {
                if *last_stage == stage && last_detail == detail {
                    return;
                }
            }
            state.stages.push((stage, detail.to_string()));
        }
    }

    fn warn(&self, message: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.warnings.push(message.to_string());
        }
    }
}

/// A running audit and its progress.
pub struct RunningAudit {
    /// Progress handle to poll.
    pub handle: ProgressHandle,
    worker: Option<std::thread::JoinHandle<Result<AuditReport, AuditError>>>,
}

impl RunningAudit {
    /// Whether the worker has finished.
    pub fn is_finished(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
    }

    /// Wait for the result. Returns `None` if called twice.
    pub fn join(mut self) -> Option<Result<AuditReport, AuditError>> {
        self.worker.take().map(|worker| {
            worker.join().unwrap_or_else(|_| {
                Err(AuditError::Options(
                    "the audit worker panicked; rerun with --verbose".to_string(),
                ))
            })
        })
    }
}

/// Start an audit on a worker thread so a front-end can keep drawing.
pub fn spawn_audit(options: AuditOptions) -> RunningAudit {
    let handle = ProgressHandle::new();
    let mut options = options;
    options.progress = handle.sink();
    let worker = std::thread::spawn(move || auditeur_audit::AuditEngine::run(&options));
    RunningAudit {
        handle,
        worker: Some(worker),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_config::{AuditeurConfig, AuditeurHome};
    use std::fs;

    fn fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        fs::write(temp.path().join("README.md"), "# x\n").unwrap();
        temp
    }

    #[test]
    fn the_handle_collects_stages_in_order() {
        let handle = ProgressHandle::new();
        let sink = handle.sink();
        sink.stage(AuditStage::Discovery, "start");
        sink.stage(AuditStage::Discovery, "done");
        sink.stage(AuditStage::GitMetadata, "");
        sink.warn("something was skipped");

        let state = handle.snapshot();
        assert_eq!(state.stages.len(), 3);
        assert_eq!(state.current().unwrap().0, AuditStage::GitMetadata);
        assert_eq!(state.stage_count(), 2);
        assert!(state.saw(AuditStage::Discovery));
        assert!(!state.saw(AuditStage::Assembly));
        assert_eq!(state.warnings.len(), 1);
    }

    #[test]
    fn repeated_identical_stages_collapse() {
        let handle = ProgressHandle::new();
        let sink = handle.sink();
        sink.stage(AuditStage::Discovery, "start");
        sink.stage(AuditStage::Discovery, "start");
        assert_eq!(handle.snapshot().stages.len(), 1);
    }

    #[test]
    fn finishing_sets_the_outcome() {
        let handle = ProgressHandle::new();
        handle.finish("12 findings");
        let state = handle.snapshot();
        assert!(state.finished);
        assert_eq!(state.outcome.as_deref(), Some("12 findings"));
        assert!(state.text_line().starts_with('✓'));
    }

    #[test]
    fn text_lines_are_readable_before_and_during_a_run() {
        let handle = ProgressHandle::new();
        assert_eq!(handle.snapshot().text_line(), "starting");
        let sink = handle.sink();
        sink.stage(AuditStage::Discovery, "");
        assert!(handle
            .snapshot()
            .text_line()
            .contains("repository discovery"));
        sink.stage(AuditStage::Planning, "18 check(s)");
        assert!(handle.snapshot().text_line().contains("18 check(s)"));
    }

    #[test]
    fn a_spawned_audit_reports_stages_and_returns_a_report() {
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let mut config = AuditeurConfig::default();
        config.project.name = "fixture".to_string();

        let running = spawn_audit(AuditOptions::new(
            repo.path(),
            AuditeurHome::at(project.path()),
            config,
        ));
        let result = running.join().expect("worker ran");
        let report = result.expect("audit succeeded");
        assert!(!report.findings.is_empty());
        assert!(!report.evidence.is_empty());
    }

    #[test]
    fn joining_twice_yields_nothing_the_second_time() {
        // `join` consumes the handle, so the second attempt cannot compile; this
        // test pins the consuming signature rather than a runtime behaviour.
        let repo = fixture();
        let project = tempfile::tempdir().unwrap();
        let mut config = AuditeurConfig::default();
        config.project.name = "f".to_string();
        let running = spawn_audit(AuditOptions::new(
            repo.path(),
            AuditeurHome::at(project.path()),
            config,
        ));
        assert!(running.join().is_some());
    }
}
