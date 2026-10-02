//! The setup wizard's state machine, independent of any terminal.
//!
//! The wizard is a plain state machine over a draft configuration. Keys arrive as
//! a small [`Key`] enumeration rather than as `crossterm::event::KeyEvent`, and
//! saving goes through the configuration layer. That separation is what makes the
//! wizard testable: every transition below has a test, and the terminal code in
//! [`crate::ui`] only translates events and draws frames.

use std::path::{Path, PathBuf};

use auditeur_config::{
    validate_project_name, AuditeurConfig, AuditeurHome, BackendKind, ConfigError,
};
use auditeur_model::AuditCategory;

/// A key the wizard understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// A printable character.
    Char(char),
    /// Backspace.
    Backspace,
    /// Enter: accept, or move on.
    Enter,
    /// Tab: next field or step.
    Tab,
    /// Shift-Tab: previous field or step.
    BackTab,
    /// Up arrow.
    Up,
    /// Down arrow.
    Down,
    /// Left arrow.
    Left,
    /// Right arrow.
    Right,
    /// Space: toggle.
    Space,
    /// Escape: back a step, or quit from the first step.
    Escape,
}

/// What the wizard wants the caller to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Nothing to do; redraw.
    Redraw,
    /// A step completed; the caller may continue.
    Continue,
    /// The configuration was written; the caller should exit successfully.
    Finished(Vec<PathBuf>),
    /// The user cancelled.
    Cancelled,
    /// The wizard is showing an error the user must fix.
    Blocked(String),
}

/// Steps of the wizard, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// What the wizard is about to do.
    Welcome,
    /// Project name and project directory.
    Project,
    /// Repository to audit.
    Repository,
    /// Inference backend, endpoint and model.
    Model,
    /// Enabled audit categories.
    Categories,
    /// Resource limits.
    Limits,
    /// Report preferences.
    Report,
    /// Review before writing.
    Review,
}

impl Step {
    /// All steps, in order.
    pub const ALL: [Step; 8] = [
        Step::Welcome,
        Step::Project,
        Step::Repository,
        Step::Model,
        Step::Categories,
        Step::Limits,
        Step::Report,
        Step::Review,
    ];

    /// Title shown in the wizard frame.
    pub fn title(self) -> &'static str {
        match self {
            Step::Welcome => "Welcome",
            Step::Project => "Project",
            Step::Repository => "Repository",
            Step::Model => "Model",
            Step::Categories => "Audit categories",
            Step::Limits => "Limits",
            Step::Report => "Report",
            Step::Review => "Review and save",
        }
    }

    /// One-line explanation.
    pub fn help(self) -> &'static str {
        match self {
            Step::Welcome => "Auditeur audits a repository and writes an evidence-based report. Nothing is written inside the audited repository.",
            Step::Project => "Choose a name for this Auditeur project. Configuration, models and audit history live under it.",
            Step::Repository => "Which repository should be audited by default?",
            Step::Model => "Optional: a local OpenAI-compatible inference server. Without one, the audit runs on deterministic evidence only.",
            Step::Categories => "Which categories of checks should run? Space toggles, and nothing is removed by disabling a category: it is recorded as skipped.",
            Step::Limits => "Bounds for discovery. They are recorded in every run manifest, because they shape what the audit could see.",
            Step::Report => "What the generated report should contain.",
            Step::Review => "Review the configuration, then press Enter to write it.",
        }
    }

    /// The next step, if any.
    pub fn next(self) -> Option<Step> {
        let index = Step::ALL.iter().position(|step| *step == self)?;
        Step::ALL.get(index + 1).copied()
    }

    /// The previous step, if any.
    pub fn previous(self) -> Option<Step> {
        let index = Step::ALL.iter().position(|step| *step == self)?;
        index
            .checked_sub(1)
            .and_then(|index| Step::ALL.get(index).copied())
    }
}

/// A text field the wizard edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Project name.
    ProjectName,
    /// Repository path.
    SourcePath,
    /// Inference endpoint.
    Endpoint,
    /// Model identifier.
    Model,
    /// Maximum file size in bytes.
    MaxFileBytes,
    /// Maximum number of files.
    MaxFiles,
    /// Maximum directory depth.
    MaxDepth,
}

/// The wizard's state.
#[derive(Debug, Clone)]
pub struct WizardState {
    step: Step,
    config: AuditeurConfig,
    home: AuditeurHome,
    field_index: usize,
    category_index: usize,
    error: Option<String>,
    messages: Vec<String>,
    finished: bool,
}

impl WizardState {
    /// Start a wizard from an existing configuration.
    ///
    /// The state root is passed in rather than derived: there is one home, and it
    /// is chosen by `--home` or the environment, not by a project name.
    pub fn new(config: AuditeurConfig, home: AuditeurHome) -> Self {
        let mut messages = Vec::new();
        if config.project.name.trim().is_empty() {
            messages.push("no project name yet".to_string());
        }
        Self {
            step: Step::Welcome,
            config,
            home,
            field_index: 0,
            category_index: 0,
            error: None,
            messages,
            finished: false,
        }
    }

    /// The current step.
    pub fn step(&self) -> Step {
        self.step
    }

    /// The configuration being edited.
    pub fn config(&self) -> &AuditeurConfig {
        &self.config
    }

    /// A mutable view, for a caller that wants to preload values.
    pub fn config_mut(&mut self) -> &mut AuditeurConfig {
        &mut self.config
    }

    /// Whether the wizard has finished.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// The current error, if any.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Informational messages.
    pub fn messages(&self) -> &[String] {
        &self.messages
    }

    /// Index of the highlighted category.
    pub fn category_index(&self) -> usize {
        self.category_index
    }

    /// Index of the active text field.
    pub fn field_index(&self) -> usize {
        self.field_index
    }

    /// Which fields the current step edits.
    pub fn fields(&self) -> &'static [Field] {
        match self.step {
            Step::Project => &[Field::ProjectName],
            Step::Repository => &[Field::SourcePath],
            Step::Model => &[Field::Endpoint, Field::Model],
            Step::Limits => &[Field::MaxFileBytes, Field::MaxFiles, Field::MaxDepth],
            Step::Welcome | Step::Categories | Step::Report | Step::Review => &[],
        }
    }

    /// The current value of a field, as editable text.
    pub fn field_value(&self, field: Field) -> String {
        match field {
            Field::ProjectName => self.config.project.name.clone(),
            Field::SourcePath => self.config.project.source_path.display().to_string(),
            Field::Endpoint => self.config.model.endpoint.clone(),
            Field::Model => self.config.model.model.clone(),
            Field::MaxFileBytes => self.config.audit.limits.max_file_bytes.to_string(),
            Field::MaxFiles => self.config.audit.limits.max_files.to_string(),
            Field::MaxDepth => self.config.audit.limits.max_depth.to_string(),
        }
    }

    /// The active field, if the step has one.
    pub fn active_field(&self) -> Option<Field> {
        self.fields().get(self.field_index).copied()
    }

    /// Apply a key to the current step.
    pub fn handle_key(&mut self, key: Key) -> Action {
        if self.finished {
            return Action::Redraw;
        }
        self.error = None;

        match self.step {
            Step::Welcome => match key {
                Key::Enter | Key::Tab | Key::Space => self.advance(),
                Key::Escape => Action::Cancelled,
                _ => Action::Redraw,
            },
            Step::Categories => match key {
                Key::Up | Key::BackTab => {
                    self.category_index = self.category_index.saturating_sub(1);
                    Action::Redraw
                }
                Key::Down | Key::Tab => {
                    self.category_index =
                        (self.category_index + 1).min(AuditCategory::ALL.len() - 1);
                    Action::Redraw
                }
                Key::Space => {
                    self.toggle_category();
                    Action::Redraw
                }
                Key::Enter => self.advance(),
                Key::Escape => self.retreat(),
                _ => Action::Redraw,
            },
            Step::Report => match key {
                Key::Space | Key::Char('p') => {
                    self.config.report.include_passing = !self.config.report.include_passing;
                    Action::Redraw
                }
                Key::Char('e') => {
                    self.config.report.include_evidence_excerpts =
                        !self.config.report.include_evidence_excerpts;
                    Action::Redraw
                }
                Key::Enter => self.advance(),
                Key::Escape => self.retreat(),
                _ => Action::Redraw,
            },
            Step::Review => match key {
                Key::Enter => match self.save() {
                    Ok(paths) => {
                        self.finished = true;
                        Action::Finished(paths)
                    }
                    Err(message) => {
                        self.error = Some(message.clone());
                        Action::Blocked(message)
                    }
                },
                Key::Escape => self.retreat(),
                Key::Tab | Key::BackTab => self.advance(),
                _ => Action::Redraw,
            },
            Step::Project | Step::Repository | Step::Model | Step::Limits => self.handle_input(key),
        }
    }

    /// Text editing for the field-editing steps.
    fn handle_input(&mut self, key: Key) -> Action {
        let Some(field) = self.active_field() else {
            return match key {
                Key::Enter => self.advance(),
                Key::Escape => self.retreat(),
                _ => Action::Redraw,
            };
        };

        match key {
            Key::Char(character) => {
                let mut value = self.field_value(field);
                value.push(character);
                self.set_field_value(field, &value)
            }
            Key::Backspace => {
                let mut value = self.field_value(field);
                value.pop();
                self.set_field_value(field, &value)
            }
            Key::Tab | Key::Down => {
                self.field_index = (self.field_index + 1) % self.fields().len().max(1);
                Action::Redraw
            }
            Key::BackTab | Key::Up => {
                self.field_index = self.field_index.saturating_sub(1);
                Action::Redraw
            }
            Key::Space => {
                let mut value = self.field_value(field);
                value.push(' ');
                self.set_field_value(field, &value)
            }
            Key::Enter => self.advance(),
            Key::Escape => self.retreat(),
            Key::Left | Key::Right => Action::Redraw,
        }
    }

    /// Write a field value, reporting a parse failure as a message.
    fn set_field_value(&mut self, field: Field, value: &str) -> Action {
        match field {
            Field::ProjectName => self.config.project.name = value.to_string(),
            Field::SourcePath => self.config.project.source_path = PathBuf::from(value),
            Field::Endpoint => self.config.model.endpoint = value.to_string(),
            Field::Model => self.config.model.model = value.to_string(),
            Field::MaxFileBytes => match value.trim().parse::<u64>() {
                Ok(parsed) => self.config.audit.limits.max_file_bytes = parsed,
                Err(_) => {
                    // Keep the previous value: a half-typed number is not a value.
                    if !value.trim().is_empty() {
                        self.error = Some("max file bytes must be a number".to_string());
                    }
                }
            },
            Field::MaxFiles => match value.trim().parse::<u32>() {
                Ok(parsed) => self.config.audit.limits.max_files = parsed,
                Err(_) => {
                    if !value.trim().is_empty() {
                        self.error = Some("max files must be a number".to_string());
                    }
                }
            },
            Field::MaxDepth => match value.trim().parse::<usize>() {
                Ok(parsed) => self.config.audit.limits.max_depth = parsed,
                Err(_) => {
                    if !value.trim().is_empty() {
                        self.error = Some("max depth must be a number".to_string());
                    }
                }
            },
        }
        Action::Redraw
    }

    /// Toggle the highlighted category.
    ///
    /// The last enabled category cannot be disabled: an audit with no categories
    /// would report nothing while appearing to succeed, which configuration
    /// validation rejects anyway.
    fn toggle_category(&mut self) {
        let Some(category) = AuditCategory::ALL.get(self.category_index).copied() else {
            return;
        };
        let enabled = self.config.audit.enabled_categories.contains(&category);
        if enabled {
            if self.config.audit.enabled_categories.len() == 1 {
                self.error = Some("at least one category must stay enabled".to_string());
                return;
            }
            self.config
                .audit
                .enabled_categories
                .retain(|candidate| *candidate != category);
        } else {
            self.config.audit.enabled_categories.push(category);
            self.config
                .audit
                .enabled_categories
                .sort_by_key(|candidate| AuditCategory::ALL.iter().position(|c| c == candidate));
        }
    }

    /// Validate the current step and move on.
    fn advance(&mut self) -> Action {
        if let Err(message) = self.validate_step() {
            self.error = Some(message.clone());
            return Action::Blocked(message);
        }
        match self.step.next() {
            Some(next) => {
                self.step = next;
                self.field_index = 0;
                if next == Step::Review {
                    self.messages = self.review_lines();
                }
                Action::Continue
            }
            None => Action::Redraw,
        }
    }

    /// Move back a step, or report cancellation from the first step.
    fn retreat(&mut self) -> Action {
        match self.step.previous() {
            Some(previous) => {
                self.step = previous;
                self.field_index = 0;
                Action::Redraw
            }
            None => Action::Cancelled,
        }
    }

    /// Validate the current step's fields, recording an informational message
    /// when a step can be completed but with a caveat worth showing.
    pub fn validate_step(&mut self) -> Result<(), String> {
        match self.step {
            Step::Welcome => Ok(()),
            Step::Project => validate_project_name(&self.config.project.name)
                .map_err(|error: ConfigError| error.to_string()),
            Step::Repository => {
                let path = &self.config.project.source_path;
                if path.as_os_str().is_empty() {
                    return Err("a repository path is required".to_string());
                }
                if !path.exists() {
                    return Err(format!("{} does not exist", path.display()));
                }
                if !path.is_dir() {
                    return Err(format!("{} is not a directory", path.display()));
                }
                Ok(())
            }
            Step::Model => {
                if self.config.model.endpoint.trim().is_empty() {
                    return Err(
                        "an endpoint is required; use the default for a local server".to_string(),
                    );
                }
                if self.config.model.model.trim().is_empty() {
                    self.messages.push(
                        "no model selected: the audit will run deterministic checks only"
                            .to_string(),
                    );
                }
                Ok(())
            }
            Step::Categories => {
                if self.config.audit.enabled_categories.is_empty() {
                    return Err("enable at least one category".to_string());
                }
                Ok(())
            }
            Step::Limits | Step::Report => Ok(()),
            Step::Review => self.config.validate().map_err(|error| error.to_string()),
        }
    }

    /// Write the configuration.
    pub fn save(&self) -> Result<Vec<PathBuf>, String> {
        self.config.validate().map_err(|error| error.to_string())?;
        self.config
            .save(&self.home)
            .map_err(|error| error.to_string())
    }

    /// The state directory this wizard writes to.
    pub fn home(&self) -> &AuditeurHome {
        &self.home
    }

    /// Lines shown on the review step.
    pub fn review_lines(&self) -> Vec<String> {
        let config = &self.config;
        let categories: Vec<&str> = config
            .audit
            .enabled_categories
            .iter()
            .map(|category| category.id())
            .collect();
        vec![
            format!("project name: {}", config.project.name),
            format!("state directory: {}", self.home.root().display()),
            format!("log file: {}", self.home.log_file().display()),
            format!("repository: {}", config.project.source_path.display()),
            format!("backend: {}", config.model.backend.id()),
            format!("endpoint: {}", config.model.endpoint),
            format!(
                "model: {}",
                if config.model.model.trim().is_empty() {
                    "(none: deterministic audit only)".to_string()
                } else {
                    config.model.model.clone()
                }
            ),
            format!("categories: {}", categories.join(", ")),
            format!(
                "limits: {} byte(s)/file, {} file(s), depth {}",
                config.audit.limits.max_file_bytes,
                config.audit.limits.max_files,
                config.audit.limits.max_depth
            ),
            format!(
                "report: passing findings {}, evidence excerpts {}",
                if config.report.include_passing {
                    "included"
                } else {
                    "omitted"
                },
                if config.report.include_evidence_excerpts {
                    "included"
                } else {
                    "omitted"
                }
            ),
            format!(
                "external tools: {}",
                if config.audit.run_external_tools {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
        ]
    }

    /// The backend that will be used, for display.
    pub fn backend(&self) -> BackendKind {
        self.config.model.backend
    }

    /// Text field editing with a full replacement, used by tests and preloaders.
    pub fn set_field_text(&mut self, field: Field, value: &str) -> Action {
        self.set_field_value(field, value)
    }

    /// Whether a category is enabled.
    pub fn is_category_enabled(&self, category: AuditCategory) -> bool {
        self.config.audit.enabled_categories.contains(&category)
    }
}

/// A path that a wizard wrote, for reporting to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenConfiguration {
    /// State root the configuration was written under.
    pub state_root: PathBuf,
    /// Files written.
    pub files: Vec<PathBuf>,
}

impl WrittenConfiguration {
    /// A one-line summary.
    pub fn summary(&self) -> String {
        format!(
            "configuration written to {} ({} file(s))",
            self.state_root.display(),
            self.files.len()
        )
    }
}

/// Whether a path is a plausible repository root, with an explanation either way.
pub fn describe_repository(path: &Path) -> String {
    if !path.exists() {
        return format!("{} does not exist", path.display());
    }
    if !path.is_dir() {
        return format!("{} is not a directory", path.display());
    }
    match std::fs::read_dir(path) {
        Ok(entries) => format!(
            "{} contains {} entry/entries",
            path.display(),
            entries.count()
        ),
        Err(error) => format!("{} cannot be read: {error}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wizard() -> WizardState {
        wizard_at(AuditeurHome::at(
            std::env::temp_dir().join("auditeur-wizard-test"),
        ))
    }

    /// A wizard that writes to a state root the test controls.
    fn wizard_at(home: AuditeurHome) -> WizardState {
        let mut config = AuditeurConfig::default();
        config.project.name = "demo".to_string();
        config.project.source_path = std::env::temp_dir();
        WizardState::new(config, home)
    }

    #[test]
    fn steps_form_a_linked_list() {
        assert_eq!(Step::Welcome.previous(), None);
        assert_eq!(Step::Review.next(), None);
        for step in Step::ALL {
            if let Some(next) = step.next() {
                assert_eq!(next.previous(), Some(step));
            }
        }
        assert_eq!(Step::ALL.len(), 8);
    }

    #[test]
    fn the_wizard_starts_at_the_welcome_step() {
        let state = wizard();
        assert_eq!(state.step(), Step::Welcome);
        assert_eq!(state.error(), None);
        assert!(!state.is_finished());
    }

    #[test]
    fn enter_advances_through_every_step_to_the_review() {
        let mut state = wizard();
        for expected in [
            Step::Project,
            Step::Repository,
            Step::Model,
            Step::Categories,
            Step::Limits,
            Step::Report,
            Step::Review,
        ] {
            let action = state.handle_key(Key::Enter);
            assert!(
                matches!(action, Action::Continue | Action::Redraw),
                "unexpected action {action:?} advancing to {expected:?}"
            );
            assert_eq!(state.step(), expected);
        }
    }

    #[test]
    fn escape_cancels_from_the_first_step() {
        let mut state = wizard();
        assert_eq!(state.handle_key(Key::Escape), Action::Cancelled);
    }

    #[test]
    fn escape_steps_back_once_moving() {
        let mut state = wizard();
        state.handle_key(Key::Enter);
        assert_eq!(state.step(), Step::Project);
        state.handle_key(Key::Escape);
        assert_eq!(state.step(), Step::Welcome);
    }

    #[test]
    fn an_invalid_project_name_blocks_progress() {
        let mut state = wizard();
        state.handle_key(Key::Enter);
        state.config.project.name = String::new();
        // The name is cleared after entering the step, then Enter is pressed.
        let action = state.handle_key(Key::Enter);
        assert!(matches!(action, Action::Blocked(_)), "{action:?}");
        assert_eq!(state.step(), Step::Project);
        assert!(state.error().unwrap().contains("must not be empty"));
    }

    #[test]
    fn typing_edits_the_active_field() {
        let mut state = wizard();
        state.handle_key(Key::Enter);
        state.config.project.name = String::new();
        for character in "auditeur-demo".chars() {
            state.handle_key(Key::Char(character));
        }
        assert_eq!(state.config.project.name, "auditeur-demo");
        state.handle_key(Key::Backspace);
        assert_eq!(state.config.project.name, "auditeur-dem");
    }

    #[test]
    fn tab_moves_between_fields_without_leaving_the_step() {
        let mut state = wizard();
        state.handle_key(Key::Enter);
        assert_eq!(state.active_field(), Some(Field::ProjectName));
        state.handle_key(Key::Tab);
        // The project step edits one field, so tabbing stays on it rather than
        // wandering off; the state root is not editable here.
        assert_eq!(state.active_field(), Some(Field::ProjectName));
        assert_eq!(state.step(), Step::Project);
    }

    #[test]
    fn a_missing_repository_path_blocks_the_repository_step() {
        let mut state = wizard();
        state.handle_key(Key::Enter); // Project
        state.handle_key(Key::Enter); // Repository
        assert_eq!(state.step(), Step::Repository);
        state.config.project.source_path = PathBuf::from("/definitely/not/here");
        let action = state.handle_key(Key::Enter);
        assert!(matches!(action, Action::Blocked(_)), "{action:?}");
        assert!(state.error().unwrap().contains("does not exist"));
    }

    #[test]
    fn categories_toggle_but_never_to_zero() {
        let mut state = wizard();
        // Welcome → Project → Repository → Model → Categories.
        for _ in 0..4 {
            state.handle_key(Key::Enter);
        }
        assert_eq!(state.step(), Step::Categories);

        let first = AuditCategory::ALL[0];
        assert!(state.is_category_enabled(first));
        state.handle_key(Key::Space);
        assert!(!state.is_category_enabled(first));

        // Disable everything else, then check the last one cannot go.
        state.config.audit.enabled_categories = vec![first];
        state.handle_key(Key::Space);
        assert!(state.error().unwrap().contains("at least one category"));
        assert_eq!(state.config.audit.enabled_categories, vec![first]);
    }

    #[test]
    fn category_navigation_is_bounded() {
        let mut state = wizard();
        state.config.audit.enabled_categories = AuditCategory::ALL.to_vec();
        for _ in 0..4 {
            state.handle_key(Key::Enter);
        }
        assert_eq!(state.step(), Step::Categories);
        state.handle_key(Key::Up);
        assert_eq!(state.category_index(), 0);
        for _ in 0..100 {
            state.handle_key(Key::Down);
        }
        assert_eq!(state.category_index(), AuditCategory::ALL.len() - 1);
    }

    #[test]
    fn report_preferences_toggle() {
        let mut state = wizard();
        state.config.project.source_path = std::env::temp_dir();
        // Welcome → Project → Repository → Model → Categories → Limits → Report.
        for _ in 0..6 {
            state.handle_key(Key::Enter);
        }
        assert_eq!(state.step(), Step::Report);

        let before = state.config.report.include_passing;
        state.handle_key(Key::Space);
        assert_ne!(state.config.report.include_passing, before);

        let before = state.config.report.include_evidence_excerpts;
        state.handle_key(Key::Char('e'));
        assert_ne!(state.config.report.include_evidence_excerpts, before);
    }

    #[test]
    fn the_review_lists_what_will_be_written() {
        let mut state = wizard();
        // Seven advances reach the review step.
        for _ in 0..7 {
            state.handle_key(Key::Enter);
        }

        assert_eq!(state.step(), Step::Review);
        let review = state.messages().join("\n");
        assert!(review.contains("project name: demo"), "{review}");
        assert!(review.contains("backend: openai_compatible"), "{review}");
        assert!(
            review.contains("(none: deterministic audit only)"),
            "{review}"
        );
        assert!(review.contains("limits:"), "{review}");
    }

    #[test]
    fn saving_writes_the_configuration_and_finishes() {
        let project = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let mut state = wizard_at(AuditeurHome::at(project.path().join("auditeur-demo")));
        state.config.project.source_path = repository.path().to_path_buf();

        for _ in 0..7 {
            state.handle_key(Key::Enter);
        }
        assert_eq!(state.step(), Step::Review);

        let action = state.handle_key(Key::Enter);
        match action {
            Action::Finished(paths) => {
                assert_eq!(paths.len(), 3);
                for path in paths {
                    assert!(path.is_file(), "missing {path:?}");
                }
            }
            other => panic!("expected Finished, got {other:?}"),
        }
        assert!(state.is_finished());
        assert!(project
            .path()
            .join("auditeur-demo/config/auditeur.toml")
            .is_file());
    }

    #[test]
    fn numeric_fields_keep_their_value_when_partially_typed() {
        let mut state = wizard();
        state.config.audit.limits.max_files = 42;
        state.set_field_text(Field::MaxFiles, ""); // empty: no change, no error
        assert_eq!(state.config.audit.limits.max_files, 42);
        state.set_field_text(Field::MaxFiles, "not a number");
        assert_eq!(state.config.audit.limits.max_files, 42);
        assert!(state.error().is_some());
        state.set_field_text(Field::MaxFiles, "100");
        assert_eq!(state.config.audit.limits.max_files, 100);
    }

    #[test]
    fn a_repository_description_explains_the_failure() {
        assert!(describe_repository(Path::new("/definitely/not/here")).contains("does not exist"));
        let temp = tempfile::tempdir().unwrap();
        assert!(describe_repository(temp.path()).contains("contains 0 entry"));
    }

    #[test]
    fn every_step_has_a_title_and_help_text() {
        let mut titles = std::collections::HashSet::new();
        for step in Step::ALL {
            assert!(!step.title().is_empty());
            assert!(!step.help().is_empty());
            assert!(
                titles.insert(step.title()),
                "duplicate title {:?}",
                step.title()
            );
        }
    }
}
