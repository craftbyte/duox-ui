//! Spacing, type-size and font tokens shared by every view.

use iced::Font;

pub const SPACE_XS: f32 = 4.0;
pub const SPACE_SM: f32 = 8.0;
pub const SPACE_MD: f32 = 12.0;
pub const SPACE_LG: f32 = 18.0;

pub const TEXT_SMALL: f32 = 12.0;
pub const TEXT_BODY: f32 = 14.0;
pub const TEXT_HEADING: f32 = 16.0;
pub const TEXT_TITLE: f32 = 22.0;

/// Width of the label column in forms and key-value tables.
pub const LABEL_WIDTH: f32 = 150.0;

/// Font for hex, identifiers and other machine-oriented text.
pub const MONO: Font = Font::MONOSPACE;
