use ratatui::style::Stylize;
use ratatui::text::Span;
use std::time::Instant;

pub(crate) const TOOL_CALL_MAX_LINES: usize = 200;

#[derive(Debug, Clone)]
pub(crate) enum CommandOutput {
    Text(String),
    Json(String),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct OutputLinesParams {
    pub(crate) _dummy: bool,
}

pub(crate) fn output_lines(_output: &CommandOutput, _params: OutputLinesParams) -> Vec<String> {
    Vec::new()
}

pub(crate) fn spinner(_start: Option<Instant>, _animations_enabled: bool) -> Span<'static> {
    "◌".dim()
}
