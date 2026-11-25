//! Container and button styles.

use iced::widget::{button, container};
use iced::{border, Background, Border, Color, Shadow, Theme, Vector};

/// Raised panel with a thin border.
pub fn panel(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(p.background.weak.color)),
        border: Border { color: p.background.strong.color, width: 1.0, radius: border::radius(6) },
        text_color: Some(p.background.weak.text),
        ..Default::default()
    }
}

/// Header strip of a section.
pub fn section_header(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(p.background.strong.color)),
        border: Border { radius: border::radius(4), ..Border::default() },
        text_color: Some(p.background.strong.text),
        ..Default::default()
    }
}

/// Bar below the top bar that shows the connection / session state.
pub fn status_bar(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(p.background.weak.color)),
        border: Border { color: p.background.strong.color, width: 1.0, radius: border::radius(0) },
        ..Default::default()
    }
}

pub fn banner_error(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(p.danger.weak.color)),
        text_color: Some(p.danger.weak.text),
        border: Border { color: p.danger.base.color, width: 1.0, radius: border::radius(4) },
        ..Default::default()
    }
}

/// Dim layer behind modal dialogs.
pub fn backdrop(_: &Theme) -> container::Style {
    container::Style { background: Some(Background::Color(Color { a: 0.55, ..Color::BLACK })), ..Default::default() }
}

/// The dialog card itself.
pub fn dialog(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(p.background.base.color)),
        text_color: Some(p.background.base.text),
        border: Border { color: p.background.strong.color, width: 1.0, radius: border::radius(8) },
        shadow: Shadow { color: Color { a: 0.45, ..Color::BLACK }, offset: Vector::new(0.0, 6.0), blur_radius: 24.0 },
        ..Default::default()
    }
}

/// Coloured dot used by the status line.
pub fn dot(color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(Background::Color(color)),
        border: Border { radius: border::radius(5), ..Border::default() },
        ..Default::default()
    }
}

/// Tab strip button.
pub fn tab_button(active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        if active {
            button::primary(theme, status)
        } else {
            let mut s = button::secondary(theme, status);
            s.border.radius = border::radius(4);
            s
        }
    }
}

/// Selected / unselected row of a list or tree.
pub fn row_button(selected: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let p = theme.extended_palette();
        let mut s = button::text(theme, status);
        s.border.radius = border::radius(3);
        if selected {
            s.background = Some(Background::Color(p.primary.weak.color));
            s.text_color = p.primary.weak.text;
        } else if matches!(status, button::Status::Hovered) {
            s.background = Some(Background::Color(p.background.strong.color));
        }
        s
    }
}

/// Colour for "ok" state indicators.
pub fn ok_color(theme: &Theme) -> Color {
    theme.extended_palette().success.base.color
}
