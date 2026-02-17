use std::time::Duration;

use codex_core::protocol::Op;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::widgets::WidgetRef;

use crate::app_event::AppEvent;
use crate::app_event_sender::AppEventSender;
use crate::render::renderable::Renderable;
use crate::tui::FrameRequester;

pub(crate) struct StatusIndicatorWidget {
    app_event_tx: AppEventSender,
    #[allow(dead_code)]
    frame_requester: FrameRequester,
    #[allow(dead_code)]
    animations_enabled: bool,
    header: String,
    details: Option<String>,
    inline_message: Option<String>,
    show_interrupt_hint: bool,
}

impl StatusIndicatorWidget {
    pub(crate) fn new(
        app_event_tx: AppEventSender,
        frame_requester: FrameRequester,
        animations_enabled: bool,
    ) -> Self {
        Self {
            app_event_tx,
            frame_requester,
            animations_enabled,
            header: "Working".to_string(),
            details: None,
            inline_message: None,
            show_interrupt_hint: true,
        }
    }

    pub(crate) fn interrupt(&self) {
        self.app_event_tx.send(AppEvent::CodexOp(Op::Interrupt));
    }

    pub(crate) fn update_header(&mut self, header: String) {
        self.header = header;
    }

    pub(crate) fn update_details(&mut self, details: Option<String>) {
        self.details = details;
    }

    pub(crate) fn set_interrupt_hint_visible(&mut self, visible: bool) {
        self.show_interrupt_hint = visible;
    }

    pub(crate) fn update_inline_message(&mut self, message: Option<String>) {
        self.inline_message = message;
    }

    pub(crate) fn pause_timer(&mut self) {}
    pub(crate) fn resume_timer(&mut self) {}
}

impl Renderable for StatusIndicatorWidget {
    fn desired_height(&self, _width: u16) -> u16 {
        1
    }

    fn render(&self, area: Rect, buf: &mut Buffer) {
        if area.is_empty() {
            return;
        }
        let mut text = self.header.clone();
        if self.show_interrupt_hint {
            text.push_str(" (esc to interrupt)");
        }
        if let Some(msg) = &self.inline_message {
            text.push_str(" · ");
            text.push_str(msg);
        }
        if let Some(details) = &self.details
            && !details.is_empty()
        {
            text.push_str(" · ");
            text.push_str(details);
        }
        WidgetRef::render_ref(&Paragraph::new(Line::from(text)), area, buf);
    }
}

#[allow(dead_code)]
pub fn fmt_elapsed_compact(elapsed_secs: u64) -> String {
    if elapsed_secs < 60 {
        format!("{elapsed_secs}s")
    } else {
        format!("{}m", elapsed_secs / 60)
    }
}
