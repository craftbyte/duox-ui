//! Desktop application for NXP MIFARE DUOX cards.

// The shared API (Shared, ui::*) is wider than the stub tabs use; tabs fill it in.
#![allow(dead_code)]

mod app;
mod log;
mod shared;
mod tabs;
mod ui;

fn main() -> iced::Result {
    iced::application(app::boot, app::update, app::view)
        .title(app::title)
        .theme(app::theme)
        .subscription(app::subscription)
        .window_size((1220.0, 900.0))
        .centered()
        .run()
}
