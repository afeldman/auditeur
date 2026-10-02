//! Terminal rendering.
//!
//! Drawing is separated from input: each function takes a `Frame` and a bit of
//! state, which makes every screen testable with ratatui's `TestBackend` — an
//! 80×24 in-memory buffer — instead of a real terminal.

use auditeur_model::AuditCategory as Category;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::progress::ProgressState;
use crate::wizard::{Field, Step, WizardState};

/// Style for a highlighted value.
fn highlight() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

/// Style for muted help text.
fn muted() -> Style {
    Style::default().fg(Color::DarkGray)
}

/// Draw one wizard frame.
pub fn draw_wizard(frame: &mut Frame<'_>, state: &WizardState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(4),
        ])
        .split(area);

    draw_header(frame, chunks[0], state.step());
    draw_body(frame, chunks[1], state);
    draw_footer(frame, chunks[2], state);
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, step: Step) {
    let position = Step::ALL
        .iter()
        .position(|candidate| *candidate == step)
        .map(|index| index + 1)
        .unwrap_or(1);
    let title = format!(
        " Auditeur setup — {} ({position}/{}) ",
        step.title(),
        Step::ALL.len()
    );
    let block = Block::default().borders(Borders::ALL).title(title);
    let paragraph = Paragraph::new(step.help())
        .block(block)
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn draw_body(frame: &mut Frame<'_>, area: Rect, state: &WizardState) {
    match state.step() {
        Step::Categories => draw_categories(frame, area, state),
        Step::Review => draw_review(frame, area, state),
        Step::Report => draw_report_options(frame, area, state),
        _ => draw_fields(frame, area, state),
    }
}

fn draw_fields(frame: &mut Frame<'_>, area: Rect, state: &WizardState) {
    let fields = state.fields();
    let block = Block::default().borders(Borders::ALL).title(" Values ");
    if fields.is_empty() {
        frame.render_widget(
            Paragraph::new("Press Enter to continue.").block(block),
            area,
        );
        return;
    }

    let lines: Vec<Line> = fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let label = field_label(*field);
            let value = state.field_value(*field);
            let rendered = if value.is_empty() {
                "(empty)".to_string()
            } else {
                value
            };
            let mut span = Span::raw(rendered);
            if index == state.field_index() {
                span = span.style(highlight());
            }
            Line::from(vec![
                Span::styled(format!("{label:<22}"), Style::default().fg(Color::Gray)),
                span,
            ])
        })
        .collect();

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Human-readable label for a field.
pub fn field_label(field: Field) -> &'static str {
    match field {
        Field::ProjectName => "project name",
        Field::SourcePath => "repository path",
        Field::Endpoint => "inference endpoint",
        Field::Model => "model",
        Field::MaxFileBytes => "max bytes per file",
        Field::MaxFiles => "max files",
        Field::MaxDepth => "max depth",
    }
}

fn draw_categories(frame: &mut Frame<'_>, area: Rect, state: &WizardState) {
    let items: Vec<ListItem> = Category::ALL
        .iter()
        .enumerate()
        .map(|(index, category)| {
            let marker = if state.is_category_enabled(*category) {
                "[x]"
            } else {
                "[ ]"
            };
            let line = Line::from(format!("{marker} {}", category.label()));
            if index == state.category_index() {
                ListItem::new(line).style(highlight())
            } else {
                ListItem::new(line)
            }
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Categories (space toggles) ");
    frame.render_widget(List::new(items).block(block), area);
}

fn draw_report_options(frame: &mut Frame<'_>, area: Rect, state: &WizardState) {
    let config = state.config();
    let lines = vec![
        Line::from(format!(
            "[{}] include passing findings            (space toggles)",
            if config.report.include_passing {
                "x"
            } else {
                " "
            }
        )),
        Line::from(format!(
            "[{}] include evidence excerpts           (e toggles)",
            if config.report.include_evidence_excerpts {
                "x"
            } else {
                " "
            }
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Excerpts are redacted before they are stored, with or without this option.",
            muted(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Report ")),
        area,
    );
}

fn draw_review(frame: &mut Frame<'_>, area: Rect, state: &WizardState) {
    let lines: Vec<Line> = state
        .messages()
        .iter()
        .map(|message| Line::from(message.clone()))
        .collect();
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Review "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, state: &WizardState) {
    let text = if let Some(error) = state.error() {
        Line::from(Span::styled(
            format!("error: {error}"),
            Style::default().fg(Color::Red),
        ))
    } else {
        Line::from(Span::styled(
            "Enter: continue · Tab: next field · Space: toggle · Esc: back/quit",
            muted(),
        ))
    };
    let paragraph = Paragraph::new(vec![
        text,
        Line::from(Span::styled(
            "Auditeur never writes inside the audited repository.",
            muted(),
        )),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(paragraph, area);
}

/// Draw one progress frame.
pub fn draw_progress(frame: &mut Frame<'_>, state: &ProgressState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(4)])
        .split(frame.area());

    let items: Vec<ListItem> = state
        .stages
        .iter()
        .map(|(stage, detail)| {
            let text = if detail.is_empty() {
                format!("· {}", stage.label())
            } else {
                format!("· {} — {detail}", stage.label())
            };
            ListItem::new(Line::from(text))
        })
        .collect();

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Audit progress "),
        ),
        chunks[0],
    );

    let footer = if state.finished {
        Line::from(Span::styled(
            format!(
                "✓ {}",
                state.outcome.clone().unwrap_or_else(|| "done".to_string())
            ),
            Style::default().fg(Color::Green),
        ))
    } else {
        Line::from(vec![
            Span::styled("… ", Style::default().fg(Color::Yellow)),
            Span::raw(state.text_line()),
        ])
    };
    frame.render_widget(
        Paragraph::new(vec![footer]).block(Block::default().borders(Borders::ALL)),
        chunks[1],
    );
}

/// Draw a simple title screen used before an audit starts.
pub fn draw_start_banner(frame: &mut Frame<'_>, target: &str) {
    let lines = vec![
        Line::from(Span::styled(
            "Auditeur",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("Auditing {target}")),
        Line::from(""),
        Line::from(Span::styled(
            "Read-only: nothing inside the audited repository will be written.",
            muted(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Starting "))
            .wrap(Wrap { trim: true }),
        frame.area(),
    );
}

/// Categories enabled, for a caller that wants to show them.
pub fn enabled_categories(config: &auditeur_config::AuditeurConfig) -> Vec<Category> {
    config.audit.enabled_categories.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::ProgressHandle;
    use auditeur_audit::AuditStage;
    use auditeur_config::AuditeurConfig;
    use auditeur_config::AuditeurHome;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Render a frame to a text buffer, so assertions can look for content.
    fn render_to_text(draw: impl FnOnce(&mut Frame<'_>)) -> String {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame)).expect("frame renders");
        let buffer = terminal.backend().buffer().clone();
        buffer
            .content()
            .iter()
            .map(|cell| cell.symbol().to_string())
            .collect::<Vec<_>>()
            .join("")
    }

    fn wizard() -> WizardState {
        let mut config = AuditeurConfig::default();
        config.project.name = "demo".to_string();
        config.project.source_path = std::env::temp_dir();
        WizardState::new(
            config,
            AuditeurHome::at(std::env::temp_dir().join("auditeur-ui-test")),
        )
    }

    #[test]
    fn the_wizard_frame_shows_the_step_and_its_help() {
        let state = wizard();
        let text = render_to_text(|frame| draw_wizard(frame, &state));
        assert!(text.contains("Auditeur setup"), "{text}");
        assert!(text.contains("Welcome"));
        assert!(text.contains("Read-only") || text.contains("evidence-based"));
        assert!(text.contains("never writes inside the audited repository"));
    }

    #[test]
    fn the_project_step_shows_its_fields_and_marks_the_active_one() {
        let mut state = wizard();
        state.handle_key(crate::wizard::Key::Enter);
        let text = render_to_text(|frame| draw_wizard(frame, &state));
        assert!(text.contains("project name"), "{text}");
        assert!(text.contains("demo"));
        // The state directory is not editable here: one home, chosen by the
        // environment or the flag, and the review step is where it is shown.
        assert!(!text.contains("project directory"), "{text}");
    }

    #[test]
    fn the_review_step_names_the_state_directory() {
        let mut state = wizard();
        for _ in 0..7 {
            state.handle_key(crate::wizard::Key::Enter);
        }
        assert_eq!(state.step(), crate::wizard::Step::Review);
        let text = render_to_text(|frame| draw_wizard(frame, &state));
        assert!(text.contains("state directory"), "{text}");
        assert!(
            text.contains("auditeur.log"),
            "the log location is reviewable too: {text}"
        );
    }

    #[test]
    fn the_category_step_marks_enabled_categories() {
        let mut state = wizard();
        for _ in 0..4 {
            state.handle_key(crate::wizard::Key::Enter);
        }
        assert_eq!(state.step(), crate::wizard::Step::Categories);
        let text = render_to_text(|frame| draw_wizard(frame, &state));
        assert!(text.contains("[x] Security"), "{text}");
        assert!(text.contains("Categories"));
        assert!(text.contains("space toggles"));
    }

    #[test]
    fn the_review_step_lists_the_configuration() {
        let mut state = wizard();
        for _ in 0..7 {
            state.handle_key(crate::wizard::Key::Enter);
        }
        assert_eq!(state.step(), crate::wizard::Step::Review);
        let text = render_to_text(|frame| draw_wizard(frame, &state));
        assert!(text.contains("Review"), "{text}");
        assert!(text.contains("project name: demo"));
        assert!(text.contains("limits:"));
    }

    #[test]
    fn an_error_is_shown_in_the_footer() {
        let mut state = wizard();
        state.handle_key(crate::wizard::Key::Enter);
        state.config_mut().project.name = String::new();
        state.handle_key(crate::wizard::Key::Enter);
        let text = render_to_text(|frame| draw_wizard(frame, &state));
        assert!(text.contains("error:"), "{text}");
    }

    #[test]
    fn the_progress_frame_lists_stages_and_the_outcome() {
        let handle = ProgressHandle::new();
        let sink = handle.sink();
        sink.stage(AuditStage::Discovery, "120 file(s)");
        sink.stage(AuditStage::DeterministicChecks, "");
        let text = render_to_text(|frame| draw_progress(frame, &handle.snapshot()));
        assert!(text.contains("Audit progress"), "{text}");
        assert!(text.contains("repository discovery"));
        assert!(text.contains("120 file(s)"));

        handle.finish("7 finding(s)");
        let text = render_to_text(|frame| draw_progress(frame, &handle.snapshot()));
        assert!(text.contains("7 finding(s)"), "{text}");
    }

    #[test]
    fn the_banner_mentions_the_read_only_guarantee() {
        let text = render_to_text(|frame| draw_start_banner(frame, "/tmp/repo"));
        assert!(text.contains("/tmp/repo"));
        assert!(text.contains("Read-only"));
    }

    #[test]
    fn every_field_has_a_label() {
        let fields = [
            Field::ProjectName,
            Field::SourcePath,
            Field::Endpoint,
            Field::Model,
            Field::MaxFileBytes,
            Field::MaxFiles,
            Field::MaxDepth,
        ];
        let mut labels = std::collections::HashSet::new();
        for field in fields {
            assert!(
                labels.insert(field_label(field)),
                "duplicate label for {field:?}"
            );
        }
    }

    #[test]
    fn enabled_categories_reflects_the_configuration() {
        let mut config = AuditeurConfig::default();
        config.audit.enabled_categories = vec![Category::Security];
        assert_eq!(enabled_categories(&config), vec![Category::Security]);
    }
}
