//! Clipboard access.

use iced::Task;

/// Put `text` on the system clipboard.
pub fn copy<M: 'static>(text: impl Into<String>) -> Task<M> {
    iced::clipboard::write(text.into())
}
