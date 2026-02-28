use std::path::Path;

use crate::app_event::AppEvent;
use crate::bottom_pane::SelectionItem;
use crate::bottom_pane::SelectionViewParams;
use crate::bottom_pane::popup_consts::standard_popup_hint_line;

pub(crate) fn build_theme_picker_params(
    current_name: Option<&str>,
    _codex_home: Option<&Path>,
    _terminal_width: Option<u16>,
) -> SelectionViewParams {
    let current = current_name.unwrap_or("default").to_string();
    SelectionViewParams {
        title: Some("Select Syntax Theme".to_string()),
        subtitle: Some("Theme picker preview is not available in shim mode.".to_string()),
        footer_hint: Some(standard_popup_hint_line()),
        items: vec![SelectionItem {
            name: current.clone(),
            is_current: true,
            dismiss_on_select: true,
            actions: vec![Box::new(move |tx| {
                tx.send(AppEvent::SyntaxThemeSelected {
                    name: current.clone(),
                });
            })],
            ..Default::default()
        }],
        ..Default::default()
    }
}
