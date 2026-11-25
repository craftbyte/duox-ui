//! Small reusable view helpers: section headers, panels, key-value tables, buttons.

use super::{style, theme};
use iced::widget::{button, column, container, row, text, Button, Column, Text};
use iced::{Element, Length, Theme};

/// Section title strip. Put it above a group of controls.
pub fn section<'a, M: 'a>(title: &str) -> Element<'a, M> {
    container(text(title.to_string()).size(theme::TEXT_HEADING))
        .padding([theme::SPACE_XS, theme::SPACE_SM])
        .width(Length::Fill)
        .style(style::section_header)
        .into()
}

/// Bordered group: a header and a body.
pub fn group<'a, M: 'a>(title: &str, body: impl Into<Element<'a, M>>) -> Element<'a, M> {
    container(column![section(title), container(body).padding(theme::SPACE_MD)].spacing(theme::SPACE_XS))
        .width(Length::Fill)
        .style(style::panel)
        .into()
}

/// Plain bordered panel around any content.
pub fn panel<'a, M: 'a>(body: impl Into<Element<'a, M>>) -> Element<'a, M> {
    container(body).padding(theme::SPACE_MD).width(Length::Fill).style(style::panel).into()
}

/// Monospace text.
pub fn mono<'a>(s: impl Into<String>) -> Text<'a> {
    text(s.into()).font(theme::MONO).size(theme::TEXT_BODY - 1.0)
}

/// Muted explanatory text.
pub fn hint<'a>(s: impl Into<String>) -> Text<'a> {
    text(s.into()).size(theme::TEXT_SMALL).style(|t: &Theme| text::Style {
        color: Some(t.extended_palette().background.weak.text.scale_alpha(0.7)),
    })
}

/// Label / value rows. Values are monospace when `mono_values` is set (hex, identifiers).
pub fn kv_table<'a, M: 'a>(rows: &[(String, String)], mono_values: bool) -> Element<'a, M> {
    let mut col = Column::new().spacing(theme::SPACE_XS);
    for (k, v) in rows {
        let value: Element<'a, M> = if mono_values { mono(v.clone()).into() } else { text(v.clone()).into() };
        col = col.push(
            row![
                container(text(k.clone()).size(theme::TEXT_BODY).style(|t: &Theme| text::Style {
                    color: Some(t.extended_palette().background.weak.text.scale_alpha(0.75)),
                }))
                .width(theme::LABEL_WIDTH),
                container(value).width(Length::Fill),
            ]
            .spacing(theme::SPACE_MD),
        );
    }
    col.into()
}

/// Empty-tab placeholder.
pub fn placeholder<'a, M: 'a>(title: &str) -> Element<'a, M> {
    container(text(title.to_string()).size(theme::TEXT_TITLE)).padding(theme::SPACE_LG).into()
}

/// Filled call-to-action button.
pub fn primary<'a, M: Clone + 'a>(label: &str, on_press: M) -> Button<'a, M> {
    button(text(label.to_string())).on_press(on_press).style(button::primary).padding([5, 14])
}

/// Neutral button.
pub fn secondary<'a, M: Clone + 'a>(label: &str, on_press: M) -> Button<'a, M> {
    button(text(label.to_string())).on_press(on_press).style(button::secondary).padding([5, 14])
}

/// Destructive action (delete, format).
pub fn danger<'a, M: Clone + 'a>(label: &str, on_press: M) -> Button<'a, M> {
    button(text(label.to_string())).on_press(on_press).style(button::danger).padding([5, 14])
}
