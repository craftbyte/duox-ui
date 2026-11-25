//! Read-only, selectable, monospace text area (hex dumps, logs, decoded structures).

use super::theme;
use iced::widget::text_editor;
use iced::{Element, Length};

pub struct TextView {
    content: text_editor::Content,
}

impl Default for TextView {
    fn default() -> Self {
        Self::new("")
    }
}

impl TextView {
    pub fn new(text: &str) -> Self {
        TextView { content: text_editor::Content::with_text(text) }
    }

    pub fn set_text(&mut self, text: &str) {
        self.content = text_editor::Content::with_text(text);
    }

    pub fn text(&self) -> String {
        self.content.text()
    }

    pub fn selection(&self) -> Option<String> {
        self.content.selection()
    }

    /// Move the caret (and the scroll position) to the end.
    pub fn scroll_to_end(&mut self) {
        self.content.perform(text_editor::Action::Move(text_editor::Motion::DocumentEnd));
    }

    /// Feed the widget's action back in. Edits are dropped, so the text stays read-only.
    pub fn perform(&mut self, action: text_editor::Action) {
        if !action.is_edit() {
            self.content.perform(action);
        }
    }

    pub fn view(&self) -> Element<'_, text_editor::Action> {
        text_editor(&self.content)
            .font(theme::MONO)
            .size(theme::TEXT_SMALL + 1.0)
            .height(Length::Fill)
            .on_action(|a| a)
            .into()
    }

}
