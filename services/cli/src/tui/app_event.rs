#[derive(Debug)]
pub(super) enum AppEvent {
    Key(crossterm::event::KeyEvent),
    Paste(String),
    Resize,
    Tick,
}
