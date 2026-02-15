use super::app_event::AppEvent;
use super::live_ui::LiveAttachTui;
use super::*;

pub(super) struct ChatWidget {
    ui: LiveAttachTui,
}

impl ChatWidget {
    pub(super) fn new(thread_id: String) -> Self {
        Self {
            ui: LiveAttachTui::new(thread_id, "active".to_string()),
        }
    }

    pub(super) fn ui_mut(&mut self) -> &mut LiveAttachTui {
        &mut self.ui
    }

    pub(super) fn session_id(&self) -> &str {
        &self.ui.session_id
    }

    pub(super) fn draw(&self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        self.ui.draw(terminal)
    }

    pub(super) fn poll_stream_updates(&mut self, state: &CliState) -> Result<bool> {
        poll_app_server_tui_stream_updates(state, &mut self.ui)
    }

    pub(super) fn on_event(
        &mut self,
        event: AppEvent,
        state: &mut CliState,
    ) -> Result<LiveTuiAction> {
        match event {
            AppEvent::Key(key_event) => {
                handle_app_server_tui_key_event(key_event, state, &mut self.ui)
            }
            AppEvent::Paste(pasted) => {
                self.ui.input_insert_str(&pasted);
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::Resize | AppEvent::Tick => Ok(LiveTuiAction::Continue),
        }
    }
}
