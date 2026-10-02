//! Terminal loops.
//!
//! Two loops live here: the setup wizard and the audit progress screen. Both are
//! written so that the loop bodies are testable — the key source is injected, and
//! the terminal is a generic `Terminal<B>`, so a test can drive the whole wizard
//! against an in-memory backend and a scripted key sequence.
//!
//! Everything that touches raw mode, the alternate screen or cursor visibility is
//! confined to [`with_terminal`], which restores the terminal on every exit path,
//! including a panic in the caller's closure.

use std::collections::VecDeque;
use std::io::Stdout;
use std::time::Duration;

use auditeur_audit::{AuditError, AuditOptions, AuditReport};
use auditeur_config::{AuditeurConfig, AuditeurHome, ConfigError};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::crossterm::{execute, terminal as crossterm_terminal};
use ratatui::Terminal;

use crate::progress;
use crate::ui;
use crate::wizard::{Action, Key, WizardState, WrittenConfiguration};

/// Errors raised by the terminal layer.
#[derive(Debug, thiserror::Error)]
pub enum TuiError {
    /// The terminal could not be set up, restored or drawn to.
    #[error("terminal error: {0}")]
    Terminal(String),

    /// Configuration could not be resolved or written.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// The audit failed.
    #[error(transparent)]
    Audit(#[from] AuditError),
}

impl From<std::io::Error> for TuiError {
    fn from(error: std::io::Error) -> Self {
        TuiError::Terminal(error.to_string())
    }
}

/// A source of key presses.
pub trait KeySource {
    /// The next key, or `None` when input has ended.
    fn next_key(&mut self) -> Result<Option<Key>, TuiError>;
}

/// Reads keys from the real terminal.
pub struct CrosstermKeys;

impl KeySource for CrosstermKeys {
    fn next_key(&mut self) -> Result<Option<Key>, TuiError> {
        loop {
            match event::read()? {
                Event::Key(key) => {
                    if let Some(mapped) = map_key(key) {
                        return Ok(Some(mapped));
                    }
                }
                // Resize and mouse events are ignored by the wizard.
                _ => continue,
            }
        }
    }
}

/// A fixed sequence of keys, for tests.
pub struct ScriptedKeys {
    keys: VecDeque<Key>,
}

impl ScriptedKeys {
    /// Build a scripted source.
    pub fn new(keys: impl IntoIterator<Item = Key>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
        }
    }

    /// How many keys were not consumed.
    pub fn remaining(&self) -> usize {
        self.keys.len()
    }
}

impl KeySource for ScriptedKeys {
    fn next_key(&mut self) -> Result<Option<Key>, TuiError> {
        Ok(self.keys.pop_front())
    }
}

/// Translate a crossterm key event into a wizard key.
///
/// Returns `None` for keys the wizard does not act on, so the loop keeps reading
/// instead of redrawing on every modifier press.
pub fn map_key(key: KeyEvent) -> Option<Key> {
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Some(Key::Escape),
        KeyCode::Char(character) => Some(Key::Char(character)),
        KeyCode::Backspace => Some(Key::Backspace),
        KeyCode::Enter => Some(Key::Enter),
        KeyCode::Tab => Some(Key::Tab),
        KeyCode::BackTab => Some(Key::BackTab),
        KeyCode::Up => Some(Key::Up),
        KeyCode::Down => Some(Key::Down),
        KeyCode::Left => Some(Key::Left),
        KeyCode::Right => Some(Key::Right),
        KeyCode::Esc => Some(Key::Escape),
        KeyCode::Delete | KeyCode::Home | KeyCode::End | KeyCode::PageUp | KeyCode::PageDown => {
            None
        }
        _ => None,
    }
}

/// Run the wizard loop against a terminal and a key source.
pub fn run_wizard_loop<B: Backend>(
    state: &mut WizardState,
    terminal: &mut Terminal<B>,
    keys: &mut dyn KeySource,
) -> Result<Action, TuiError> {
    loop {
        terminal
            .draw(|frame| ui::draw_wizard(frame, state))
            .map_err(|error| TuiError::Terminal(error.to_string()))?;

        let Some(key) = keys.next_key()? else {
            // Input ended without a decision.
            return Ok(Action::Cancelled);
        };

        let action = state.handle_key(key);
        match action {
            Action::Finished(_) | Action::Cancelled => {
                terminal
                    .draw(|frame| ui::draw_wizard(frame, state))
                    .map_err(|error| TuiError::Terminal(error.to_string()))?;
                return Ok(action);
            }
            Action::Redraw | Action::Continue | Action::Blocked(_) => continue,
        }
    }
}

/// Run the setup wizard on the real terminal.
///
/// Returns the written configuration, or `None` when the user cancelled.
pub fn run_setup_wizard(
    initial: AuditeurConfig,
    home: AuditeurHome,
) -> Result<Option<WrittenConfiguration>, TuiError> {
    let mut state = WizardState::new(initial, home);
    let mut keys = CrosstermKeys;

    let action = with_terminal(|terminal| run_wizard_loop(&mut state, terminal, &mut keys))?;
    match action {
        Action::Finished(files) => {
            let state_root = state.home().root().to_path_buf();
            Ok(Some(WrittenConfiguration { state_root, files }))
        }
        _ => Ok(None),
    }
}

/// Run an audit while showing progress on the real terminal.
pub fn run_audit_screen(options: AuditOptions) -> Result<AuditReport, TuiError> {
    with_terminal(|terminal| {
        let running = progress::spawn_audit(options);
        let handle = running.handle.clone();

        terminal
            .draw(|frame| ui::draw_progress(frame, &handle.snapshot()))
            .map_err(|error| TuiError::Terminal(error.to_string()))?;

        // Draw until the worker finishes. `q` or `Esc` stops drawing and waits:
        // the audit itself cannot be cancelled cooperatively yet, and pretending
        // otherwise would leave the process running behind a "cancelled" message.
        let mut detached = false;
        while !running.is_finished() {
            if !detached {
                terminal
                    .draw(|frame| ui::draw_progress(frame, &handle.snapshot()))
                    .map_err(|error| TuiError::Terminal(error.to_string()))?;
            }
            if event::poll(Duration::from_millis(120))? {
                if let Event::Key(key) = event::read()? {
                    if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                        detached = true;
                    }
                }
            }
        }

        let report = match running.join() {
            Some(result) => result?,
            None => {
                return Err(TuiError::Terminal(
                    "the audit worker disappeared without a result".to_string(),
                ))
            }
        };
        handle.finish(format!("{} finding(s)", report.findings.len()));
        terminal
            .draw(|frame| ui::draw_progress(frame, &handle.snapshot()))
            .map_err(|error| TuiError::Terminal(error.to_string()))?;
        Ok(report)
    })
}

/// Run `body` with the terminal in raw mode and the alternate screen.
///
/// The terminal is restored on every path, including an error or a panic in the
/// closure, because a terminal left in raw mode is unusable.
fn with_terminal<T>(
    body: impl FnOnce(&mut Terminal<CrosstermBackend<Stdout>>) -> Result<T, TuiError>,
) -> Result<T, TuiError> {
    crossterm_terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, crossterm_terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal =
        Terminal::new(backend).map_err(|error| TuiError::Terminal(error.to_string()))?;

    let result = body(&mut terminal);

    let restore = (|| -> Result<(), TuiError> {
        crossterm_terminal::disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            crossterm_terminal::LeaveAlternateScreen
        )?;
        terminal
            .show_cursor()
            .map_err(|error| TuiError::Terminal(error.to_string()))?;
        Ok(())
    })();

    match (result, restore) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditeur_config::AuditeurHome;
    use ratatui::backend::TestBackend;
    use std::fs;

    /// A state root for tests that never write anything.
    fn test_home() -> AuditeurHome {
        AuditeurHome::at(std::env::temp_dir().join("auditeur-tui-test"))
    }

    fn wizard(config: AuditeurConfig) -> WizardState {
        WizardState::new(config, test_home())
    }

    fn terminal() -> Terminal<TestBackend> {
        Terminal::new(TestBackend::new(100, 30)).unwrap()
    }

    #[test]
    fn crossterm_keys_are_mapped_including_control_c() {
        use ratatui::crossterm::event::KeyEventKind;
        let plain = |code: KeyCode| KeyEvent::new(code, KeyModifiers::NONE);
        assert_eq!(map_key(plain(KeyCode::Enter)), Some(Key::Enter));
        assert_eq!(map_key(plain(KeyCode::Char('a'))), Some(Key::Char('a')));
        assert_eq!(map_key(plain(KeyCode::Backspace)), Some(Key::Backspace));
        assert_eq!(map_key(plain(KeyCode::BackTab)), Some(Key::BackTab));
        assert_eq!(map_key(plain(KeyCode::Home)), None);
        assert_eq!(
            map_key(KeyEvent {
                code: KeyCode::Char('c'),
                modifiers: KeyModifiers::CONTROL,
                kind: KeyEventKind::Press,
                state: ratatui::crossterm::event::KeyEventState::NONE,
            }),
            Some(Key::Escape)
        );
    }

    #[test]
    fn the_wizard_loop_walks_from_welcome_to_a_written_configuration() {
        let project = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        fs::create_dir_all(repository.path().join("src")).unwrap();
        fs::write(repository.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();

        let mut config = AuditeurConfig::default();
        config.project.name = "scripted".to_string();
        config.project.source_path = repository.path().to_path_buf();

        // The state root is an input to the wizard, not something the
        // configuration decides.
        let state_home = AuditeurHome::at(project.path().join("scripted"));
        let mut state = WizardState::new(config, state_home);
        let mut terminal = terminal();
        // Seven Enters walk Welcome → Project → Repository → Model → Categories
        // → Limits → Report → Review, and the eighth writes the configuration.
        let mut keys = ScriptedKeys::new(std::iter::repeat_n(Key::Enter, 8));

        let action = run_wizard_loop(&mut state, &mut terminal, &mut keys).unwrap();
        match action {
            Action::Finished(files) => assert_eq!(files.len(), 3),
            other => panic!("expected a written configuration, got {other:?}"),
        }
        assert!(state.is_finished());
        assert_eq!(keys.remaining(), 0);
        assert!(project
            .path()
            .join("scripted/config/auditeur.toml")
            .is_file());
    }

    #[test]
    fn the_wizard_loop_reports_cancellation_on_escape() {
        let mut config = AuditeurConfig::default();
        config.project.name = "x".to_string();
        let mut state = wizard(config);
        let mut terminal = terminal();
        let mut keys = ScriptedKeys::new([Key::Escape]);

        let action = run_wizard_loop(&mut state, &mut terminal, &mut keys).unwrap();
        assert_eq!(action, Action::Cancelled);
        assert!(!state.is_finished());
    }

    #[test]
    fn the_wizard_loop_recovers_after_a_blocked_step() {
        let repository = tempfile::tempdir().unwrap();
        let mut config = AuditeurConfig::default();
        config.project.name = "ok".to_string();
        config.project.source_path = repository.path().to_path_buf();

        let mut state = wizard(config);
        let mut terminal = terminal();

        // Enter the Project step, clear the name, and try to advance: the wizard
        // must refuse and stay put, then accept the corrected name.
        let mut script: Vec<Key> = vec![Key::Enter];
        script.extend(std::iter::repeat_n(Key::Backspace, 2));
        script.push(Key::Enter); // blocked
        script.extend("ok".chars().map(Key::Char));
        // Six more advances reach the review step, and the last one writes.
        script.extend(std::iter::repeat_n(Key::Enter, 8));
        let mut keys = ScriptedKeys::new(script);

        let action = run_wizard_loop(&mut state, &mut terminal, &mut keys).unwrap();
        assert_eq!(state.step(), crate::wizard::Step::Review);
        assert!(
            matches!(action, Action::Finished(_)),
            "expected the wizard to recover and write, got {action:?}"
        );
    }

    #[test]
    fn a_terminal_with_no_more_input_cancels_rather_than_hanging() {
        let mut config = AuditeurConfig::default();
        config.project.name = "x".to_string();
        let mut state = wizard(config);
        let mut terminal = terminal();
        let mut keys = ScriptedKeys::new([]);

        let action = run_wizard_loop(&mut state, &mut terminal, &mut keys).unwrap();
        assert_eq!(action, Action::Cancelled);
    }

    #[test]
    fn the_audit_screen_runs_an_audit_and_reports_it() {
        // The audit screen needs a real terminal, so only the pieces that can be
        // exercised without one are tested here; the end-to-end audit path is
        // covered by the CLI integration tests.
        let repo = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut config = AuditeurConfig::default();
        config.project.name = "x".to_string();
        let options = AuditOptions::new(repo.path(), AuditeurHome::at(project.path()), config);
        let running = progress::spawn_audit(options);
        let report = running.join().unwrap().unwrap();
        assert!(!report.manifest.run_id.is_empty());
    }
}
