//! Stub for the `history_cell` module.
//!
//! The real module has 36+ codex refs. This stub provides just the `HistoryCell`
//! trait that `app_event.rs` references as `Box<dyn HistoryCell>`, plus the
//! `padded_emoji` helper used by other modules.

use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;
use std::any::Any;
use std::collections::HashMap;

/// A single cell in the chat history transcript.
pub(crate) trait HistoryCell: std::fmt::Debug + Send + Sync + Any {
    fn display_lines(&self, _width: u16) -> Vec<Line<'static>>;

    fn desired_height(&self, width: u16) -> u16 {
        Paragraph::new(self.display_lines(width))
            .wrap(Wrap { trim: false })
            .line_count(width)
            .try_into()
            .unwrap_or(0)
    }

    fn transcript_lines(&self, width: u16) -> Vec<Line<'static>> {
        self.display_lines(width)
    }

    fn desired_transcript_height(&self, width: u16) -> u16 {
        self.transcript_lines(width).len() as u16
    }
}

/// Pad an emoji string.
pub(crate) fn padded_emoji(emoji: &str) -> String {
    format!("{emoji} ")
}

#[derive(Debug, Clone)]
pub(crate) struct PlainHistoryCell {
    pub(crate) lines: Vec<Line<'static>>,
}

impl PlainHistoryCell {
    pub(crate) fn new(lines: Vec<Line<'static>>) -> Self {
        Self { lines }
    }
}

impl HistoryCell for PlainHistoryCell {
    fn display_lines(&self, _width: u16) -> Vec<Line<'static>> {
        self.lines.clone()
    }
}

#[derive(Debug)]
pub(crate) struct CompositeHistoryCell {
    pub(crate) parts: Vec<Box<dyn HistoryCell>>,
}

impl CompositeHistoryCell {
    pub(crate) fn new(parts: Vec<Box<dyn HistoryCell>>) -> Self {
        Self { parts }
    }
}

impl HistoryCell for CompositeHistoryCell {
    fn display_lines(&self, width: u16) -> Vec<Line<'static>> {
        self.parts
            .iter()
            .flat_map(|part| part.display_lines(width))
            .collect()
    }
}

pub(crate) fn with_border_with_inner_width(
    lines: Vec<Line<'static>>,
    _inner_width: u16,
) -> Vec<Line<'static>> {
    lines
}

pub(crate) fn new_info_event(message: String, hint: Option<String>) -> PlainHistoryCell {
    let mut lines = vec![Line::from(vec![Span::from("info: "), Span::from(message)])];
    if let Some(hint) = hint {
        lines.push(Line::from(hint));
    }
    PlainHistoryCell { lines }
}

pub(crate) fn new_error_event(message: String) -> PlainHistoryCell {
    PlainHistoryCell {
        lines: vec![Line::from(vec![Span::from("error: "), Span::from(message)])],
    }
}

pub(crate) fn new_approval_decision_cell(
    command: Vec<String>,
    decision: crate::protocol::ReviewDecision,
) -> Box<dyn HistoryCell> {
    let command_text = command.join(" ");
    Box::new(PlainHistoryCell {
        lines: vec![Line::from(format!(
            "approval {:?}: {}",
            decision, command_text
        ))],
    })
}

#[derive(Debug, Clone)]
pub(crate) struct RequestUserInputResultCell {
    pub(crate) questions: Vec<crate::request_user_input::RequestUserInputQuestion>,
    pub(crate) answers: HashMap<String, crate::request_user_input::RequestUserInputAnswer>,
    pub(crate) interrupted: bool,
}

impl HistoryCell for RequestUserInputResultCell {
    fn display_lines(&self, _width: u16) -> Vec<Line<'static>> {
        let status = if self.interrupted {
            "interrupted"
        } else {
            "submitted"
        };
        vec![Line::from(format!(
            "request_user_input {status}: {} question(s), {} answer(s)",
            self.questions.len(),
            self.answers.len()
        ))]
    }
}
