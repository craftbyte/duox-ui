//! Modal dialogs: input forms, confirmations, notices and errors.
//!
//! A tab describes a form with [`FormSpec`] and hands it to `Shared::ask(spec, token)`. The
//! application shows it as a modal overlay; when the user finishes, the tab receives
//! `Message::FormDone { token, values }` where `values` is `None` on cancel. Everything the
//! user typed has been validated by then; the typed getters of [`FormValues`] only fail when
//! the key does not exist or has another type (a programming error).

use super::{clipboard, files, hex, style, theme, widgets};
use iced::widget::{
    checkbox, column, container, pick_list, row, scrollable, text, text_editor, text_input, Column, Space,
};
use iced::{Element, Length, Task};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

// ------------------------------------------------------------------ description

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    Open,
    Save,
}

/// What kind of value a field edits.
#[derive(Debug, Clone)]
pub enum Kind {
    /// Single line text; `secret` masks the input.
    Text { default: String, secret: bool },
    /// Hex bytes (spaces, `:` and `-` allowed). Length limits are in bytes.
    Hex { default: String, min: usize, max: usize },
    /// Decimal (or `0x` prefixed) signed integer.
    Int { default: i64, min: i64, max: i64 },
    /// Unsigned integer shown and entered in hex, with at least `digits` digits.
    HexInt { default: u64, min: u64, max: u64, digits: usize },
    /// One of a list of choices; `default` is an index.
    Combo { options: Vec<String>, default: usize },
    Check { default: bool },
    MultiLine { default: String },
    /// Read-only text.
    Info(String),
    /// A path chosen with a file dialog (value is the path as a string; empty when none).
    File { default: String, mode: FileMode, filters: Vec<files::Filter> },
}

#[derive(Debug, Clone)]
pub struct Field {
    /// Key used to read the value back from [`FormValues`].
    pub key: String,
    pub label: String,
    pub hint: Option<String>,
    pub kind: Kind,
}

/// A form description. Build it with the chained methods, in display order.
#[derive(Debug, Clone, Default)]
pub struct FormSpec {
    pub title: String,
    pub note: String,
    pub ok_text: String,
    pub fields: Vec<Field>,
}

impl FormSpec {
    pub fn new(title: impl Into<String>) -> Self {
        FormSpec { title: title.into(), note: String::new(), ok_text: "OK".into(), fields: Vec::new() }
    }
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }
    pub fn ok_text(mut self, t: impl Into<String>) -> Self {
        self.ok_text = t.into();
        self
    }
    pub fn field(mut self, key: &str, label: &str, kind: Kind) -> Self {
        self.fields.push(Field { key: key.into(), label: label.into(), hint: None, kind });
        self
    }
    /// Small explanatory text under the most recently added field.
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        if let Some(f) = self.fields.last_mut() {
            f.hint = Some(hint.into());
        }
        self
    }
    pub fn text(self, key: &str, label: &str, default: &str) -> Self {
        self.field(key, label, Kind::Text { default: default.into(), secret: false })
    }
    /// Masked single line (passphrases).
    pub fn secret(self, key: &str, label: &str) -> Self {
        self.field(key, label, Kind::Text { default: String::new(), secret: true })
    }
    /// Hex of any length (including empty).
    pub fn hex(self, key: &str, label: &str, default: &str) -> Self {
        self.field(key, label, Kind::Hex { default: default.into(), min: 0, max: usize::MAX })
    }
    /// Hex with a byte count in `min..=max`.
    pub fn hex_len(self, key: &str, label: &str, default: &str, min: usize, max: usize) -> Self {
        self.field(key, label, Kind::Hex { default: default.into(), min, max })
    }
    pub fn int(self, key: &str, label: &str, default: i64) -> Self {
        self.field(key, label, Kind::Int { default, min: i64::MIN, max: i64::MAX })
    }
    pub fn int_range(self, key: &str, label: &str, default: i64, min: i64, max: i64) -> Self {
        self.field(key, label, Kind::Int { default, min, max })
    }
    pub fn hex_int(self, key: &str, label: &str, default: u64, digits: usize) -> Self {
        self.field(key, label, Kind::HexInt { default, min: 0, max: u64::MAX, digits })
    }
    pub fn hex_int_range(self, key: &str, label: &str, default: u64, digits: usize, min: u64, max: u64) -> Self {
        self.field(key, label, Kind::HexInt { default, min, max, digits })
    }
    pub fn combo(self, key: &str, label: &str, options: &[&str], default: usize) -> Self {
        self.field(key, label, Kind::Combo { options: options.iter().map(|s| s.to_string()).collect(), default })
    }
    pub fn check(self, key: &str, label: &str, default: bool) -> Self {
        self.field(key, label, Kind::Check { default })
    }
    pub fn multiline(self, key: &str, label: &str, default: &str) -> Self {
        self.field(key, label, Kind::MultiLine { default: default.into() })
    }
    /// Read-only line. Not part of the result.
    pub fn info(self, label: &str, text: &str) -> Self {
        self.field("", label, Kind::Info(text.into()))
    }
    pub fn file_open(self, key: &str, label: &str, filters: Vec<files::Filter>) -> Self {
        self.field(key, label, Kind::File { default: String::new(), mode: FileMode::Open, filters })
    }
    pub fn file_save(self, key: &str, label: &str, default_name: &str, filters: Vec<files::Filter>) -> Self {
        self.field(key, label, Kind::File { default: default_name.into(), mode: FileMode::Save, filters })
    }
}

/// What `Shared` can ask the application to display.
#[derive(Debug, Clone)]
pub enum Dialog {
    Form(FormSpec),
    /// Yes/no. Delivered as `FormDone { values: Some(..) }` for yes and `None` for no.
    Confirm { title: String, text: String, ok_text: String, danger: bool },
    /// Notice with an OK button; nothing is delivered back.
    Info { title: String, text: String },
    /// Error text with a Copy button; nothing is delivered back.
    Error(String),
}

// ------------------------------------------------------------------ results

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Bytes(Vec<u8>),
    Int(i64),
    UInt(u64),
    Bool(bool),
    Choice { index: usize, text: String },
}

/// Validated form result.
#[derive(Clone, Default)]
pub struct FormValues {
    map: HashMap<String, Value>,
}

// Values may hold secrets (passphrases): print only the keys.
impl fmt::Debug for FormValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut keys: Vec<&String> = self.map.keys().collect();
        keys.sort();
        write!(f, "FormValues{keys:?}")
    }
}

impl FormValues {
    fn get(&self, key: &str) -> Result<&Value, String> {
        self.map.get(key).ok_or_else(|| format!("form has no field '{key}'"))
    }
    fn wrong(key: &str, want: &str) -> String {
        format!("field '{key}' is not {want}")
    }
    /// Text of a Text, MultiLine or File field, or the selected text of a Combo.
    pub fn get_str(&self, key: &str) -> Result<&str, String> {
        match self.get(key)? {
            Value::Str(s) => Ok(s),
            Value::Choice { text, .. } => Ok(text),
            _ => Err(Self::wrong(key, "text")),
        }
    }
    /// Bytes of a Hex field.
    pub fn get_hex(&self, key: &str) -> Result<Vec<u8>, String> {
        match self.get(key)? {
            Value::Bytes(b) => Ok(b.clone()),
            _ => Err(Self::wrong(key, "hex")),
        }
    }
    /// Value of an Int field (a HexInt field is accepted when it fits).
    pub fn get_int(&self, key: &str) -> Result<i64, String> {
        match self.get(key)? {
            Value::Int(v) => Ok(*v),
            Value::UInt(v) => i64::try_from(*v).map_err(|_| format!("field '{key}' does not fit a signed integer")),
            _ => Err(Self::wrong(key, "an integer")),
        }
    }
    /// Value of a HexInt (or non-negative Int) field.
    pub fn get_uint(&self, key: &str) -> Result<u64, String> {
        match self.get(key)? {
            Value::UInt(v) => Ok(*v),
            Value::Int(v) => u64::try_from(*v).map_err(|_| format!("field '{key}' is negative")),
            _ => Err(Self::wrong(key, "an unsigned integer")),
        }
    }
    pub fn get_bool(&self, key: &str) -> Result<bool, String> {
        match self.get(key)? {
            Value::Bool(b) => Ok(*b),
            _ => Err(Self::wrong(key, "a checkbox")),
        }
    }
    /// Selected index of a Combo.
    pub fn get_index(&self, key: &str) -> Result<usize, String> {
        match self.get(key)? {
            Value::Choice { index, .. } => Ok(*index),
            _ => Err(Self::wrong(key, "a combo box")),
        }
    }
    /// Path of a File field; `None` when left empty.
    pub fn get_path(&self, key: &str) -> Result<Option<PathBuf>, String> {
        let s = self.get_str(key)?;
        Ok(if s.is_empty() { None } else { Some(PathBuf::from(s)) })
    }
}

// ------------------------------------------------------------------ runtime state

enum Input {
    Text(String),
    Check(bool),
    Choice(usize),
    Multi(text_editor::Content),
    None,
}

pub struct FormState {
    spec: FormSpec,
    inputs: Vec<Input>,
    /// Show validation errors even for untouched fields (after a failed submit).
    submitted: bool,
}

#[derive(Debug, Clone)]
pub enum FormMsg {
    Edit(usize, String),
    Toggle(usize, bool),
    Pick(usize, String),
    Editor(usize, text_editor::Action),
    Browse(usize),
    Browsed(usize, Option<PathBuf>),
    Ok,
    Cancel,
    CopyError,
}

/// Result of feeding a message to a dialog.
pub enum Outcome {
    Pending,
    Submitted(FormValues),
    Cancelled,
}

fn parse_int(s: &str) -> Result<i128, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("a value is required".into());
    }
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i128::from_str_radix(h, 16)
    } else {
        t.parse::<i128>()
    }
    .map_err(|_| format!("'{s}' is not a number"))?;
    Ok(if neg { -v } else { v })
}

impl FormState {
    pub fn new(spec: FormSpec) -> Self {
        let inputs = spec
            .fields
            .iter()
            .map(|f| match &f.kind {
                Kind::Text { default, .. } | Kind::Hex { default, .. } | Kind::File { default, .. } => {
                    Input::Text(default.clone())
                }
                Kind::Int { default, .. } => Input::Text(default.to_string()),
                Kind::HexInt { default, digits, .. } => Input::Text(format!("{:0w$X}", default, w = *digits)),
                Kind::Combo { options, default } => Input::Choice((*default).min(options.len().saturating_sub(1))),
                Kind::Check { default } => Input::Check(*default),
                Kind::MultiLine { default } => Input::Multi(text_editor::Content::with_text(default)),
                Kind::Info(_) => Input::None,
            })
            .collect();
        FormState { spec, inputs, submitted: false }
    }

    /// Validate one field. `Ok(None)` for read-only fields.
    fn check(&self, i: usize) -> Result<Option<Value>, String> {
        let f = &self.spec.fields[i];
        Ok(Some(match (&f.kind, &self.inputs[i]) {
            (Kind::Text { .. } | Kind::File { .. }, Input::Text(s)) => Value::Str(s.clone()),
            (Kind::Hex { min, max, .. }, Input::Text(s)) => {
                let b = hex::parse(s)?;
                if b.len() < *min || b.len() > *max {
                    return Err(if min == max {
                        format!("exactly {min} bytes required, got {}", b.len())
                    } else if *max == usize::MAX {
                        format!("at least {min} bytes required, got {}", b.len())
                    } else {
                        format!("{min} to {max} bytes required, got {}", b.len())
                    });
                }
                Value::Bytes(b)
            }
            (Kind::Int { min, max, .. }, Input::Text(s)) => {
                let v = parse_int(s)?;
                if v < *min as i128 || v > *max as i128 {
                    return Err(format!("must be between {min} and {max}"));
                }
                Value::Int(v as i64)
            }
            (Kind::HexInt { min, max, .. }, Input::Text(s)) => {
                let t = s.trim();
                let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
                if t.is_empty() {
                    return Err("a value is required".into());
                }
                let v = u64::from_str_radix(t, 16).map_err(|_| format!("'{s}' is not a hex number"))?;
                if v < *min || v > *max {
                    return Err(format!("must be between {min:X} and {max:X}"));
                }
                Value::UInt(v)
            }
            (Kind::Combo { options, .. }, Input::Choice(i)) => {
                let text = options.get(*i).ok_or("nothing to choose from")?.clone();
                Value::Choice { index: *i, text }
            }
            (Kind::Check { .. }, Input::Check(b)) => Value::Bool(*b),
            (Kind::MultiLine { .. }, Input::Multi(c)) => Value::Str(c.text().trim_end_matches('\n').to_string()),
            (Kind::Info(_), _) => return Ok(None),
            _ => return Err("internal: field and input kind differ".into()),
        }))
    }

    fn collect(&self) -> Result<FormValues, ()> {
        let mut map = HashMap::new();
        for (i, f) in self.spec.fields.iter().enumerate() {
            match self.check(i) {
                Ok(Some(v)) => {
                    map.insert(f.key.clone(), v);
                }
                Ok(None) => {}
                Err(_) => return Err(()),
            }
        }
        Ok(FormValues { map })
    }

    pub fn update(&mut self, msg: FormMsg) -> (Outcome, Task<FormMsg>) {
        match msg {
            FormMsg::Edit(i, s) => {
                if let Some(Input::Text(t)) = self.inputs.get_mut(i) {
                    *t = s;
                }
            }
            FormMsg::Toggle(i, b) => {
                if let Some(Input::Check(c)) = self.inputs.get_mut(i) {
                    *c = b;
                }
            }
            FormMsg::Pick(i, s) => {
                if let (Some(Input::Choice(c)), Kind::Combo { options, .. }) =
                    (self.inputs.get_mut(i), &self.spec.fields[i].kind)
                {
                    if let Some(p) = options.iter().position(|o| *o == s) {
                        *c = p;
                    }
                }
            }
            FormMsg::Editor(i, a) => {
                if let Some(Input::Multi(c)) = self.inputs.get_mut(i) {
                    c.perform(a);
                }
            }
            FormMsg::Browse(i) => {
                if let Kind::File { mode, filters, default } = &self.spec.fields[i].kind {
                    let title = self.spec.fields[i].label.clone();
                    return (
                        Outcome::Pending,
                        match mode {
                            FileMode::Open => files::pick_open(&title, filters, move |p| FormMsg::Browsed(i, p)),
                            FileMode::Save => {
                                files::pick_save(&title, default, filters, move |p| FormMsg::Browsed(i, p))
                            }
                        },
                    );
                }
            }
            FormMsg::Browsed(i, path) => {
                if let (Some(p), Some(Input::Text(t))) = (path, self.inputs.get_mut(i)) {
                    *t = p.display().to_string();
                }
            }
            FormMsg::Ok => match self.collect() {
                Ok(v) => return (Outcome::Submitted(v), Task::none()),
                Err(()) => self.submitted = true,
            },
            FormMsg::Cancel => return (Outcome::Cancelled, Task::none()),
            FormMsg::CopyError => {}
        }
        (Outcome::Pending, Task::none())
    }

    fn view(&self) -> Element<'_, FormMsg> {
        let mut body = Column::new().spacing(theme::SPACE_MD).width(Length::Fill);
        if !self.spec.note.is_empty() {
            body = body.push(text(self.spec.note.as_str()).size(theme::TEXT_BODY));
        }
        for (i, f) in self.spec.fields.iter().enumerate() {
            body = body.push(self.field_row(i, f));
        }
        let footer = row![
            Space::new().width(Length::Fill),
            widgets::secondary("Cancel", FormMsg::Cancel),
            widgets::primary(&self.spec.ok_text, FormMsg::Ok),
        ]
        .spacing(theme::SPACE_SM);
        card(
            &self.spec.title,
            720.0,
            scrollable(container(body).padding([0.0, theme::SPACE_MD])).height(Length::Shrink),
            footer.into(),
        )
    }

    fn field_row<'a>(&'a self, i: usize, f: &'a Field) -> Element<'a, FormMsg> {
        let touched_or_bad = |s: &str| self.submitted || !s.is_empty();
        let mut feedback: Option<Element<'a, FormMsg>> = None;
        let control: Element<'a, FormMsg> = match (&f.kind, &self.inputs[i]) {
            (Kind::Text { secret, .. }, Input::Text(s)) => text_input("", s)
                .on_input(move |v| FormMsg::Edit(i, v))
                .on_submit(FormMsg::Ok)
                .secure(*secret)
                .into(),
            (Kind::Hex { .. }, Input::Text(s)) => {
                feedback = Some(match self.check(i) {
                    Ok(Some(Value::Bytes(b))) => widgets::hint(format!("{} bytes", b.len())).into(),
                    Err(e) if touched_or_bad(s) => error_text(e),
                    _ => widgets::hint("0 bytes").into(),
                });
                text_input("hex", s).font(theme::MONO).on_input(move |v| FormMsg::Edit(i, v)).on_submit(FormMsg::Ok).into()
            }
            (Kind::Int { .. } | Kind::HexInt { .. }, Input::Text(s)) => {
                if let Err(e) = self.check(i) {
                    if touched_or_bad(s) {
                        feedback = Some(error_text(e));
                    }
                }
                let ti = text_input("", s).on_input(move |v| FormMsg::Edit(i, v)).on_submit(FormMsg::Ok);
                if matches!(f.kind, Kind::HexInt { .. }) { ti.font(theme::MONO).into() } else { ti.into() }
            }
            (Kind::Combo { options, .. }, Input::Choice(c)) => {
                pick_list(options.clone(), options.get(*c).cloned(), move |s| FormMsg::Pick(i, s))
                    .width(Length::Fill)
                    .into()
            }
            (Kind::Check { .. }, Input::Check(b)) => {
                checkbox(*b).label(f.label.as_str()).on_toggle(move |v| FormMsg::Toggle(i, v)).into()
            }
            (Kind::MultiLine { .. }, Input::Multi(c)) => text_editor(c)
                .font(theme::MONO)
                .height(110)
                .on_action(move |a| FormMsg::Editor(i, a))
                .into(),
            (Kind::Info(t), _) => widgets::mono(t.clone()).into(),
            (Kind::File { .. }, Input::Text(s)) => row![
                text_input("no file chosen", s).on_input(move |v| FormMsg::Edit(i, v)).width(Length::Fill),
                widgets::secondary("Browse...", FormMsg::Browse(i)),
            ]
            .spacing(theme::SPACE_SM)
            .into(),
            _ => Space::new().into(),
        };
        let mut right = Column::new().spacing(2).push(control);
        if let Some(fb) = feedback {
            right = right.push(fb);
        }
        if let Some(h) = &f.hint {
            right = right.push(widgets::hint(h.as_str()));
        }
        let label: Element<'a, FormMsg> = if matches!(f.kind, Kind::Check { .. }) {
            Space::new().into()
        } else {
            text(f.label.as_str()).size(theme::TEXT_BODY).into()
        };
        row![container(label).width(theme::LABEL_WIDTH), container(right).width(Length::Fill)]
            .spacing(theme::SPACE_MD)
            .into()
    }
}

fn error_text<'a>(e: String) -> Element<'a, FormMsg> {
    text(e)
        .size(theme::TEXT_SMALL)
        .style(|t: &iced::Theme| text::Style { color: Some(t.extended_palette().danger.base.color) })
        .into()
}

fn card<'a>(title: &str, width: f32, body: impl Into<Element<'a, FormMsg>>, footer: Element<'a, FormMsg>) -> Element<'a, FormMsg> {
    container(
        column![
            text(title.to_string()).size(theme::TEXT_HEADING + 2.0),
            body.into(),
            footer,
        ]
        .spacing(theme::SPACE_LG),
    )
    .padding(theme::SPACE_LG + 4.0)
    .max_width(width)
    .style(style::dialog)
    .into()
}

// ------------------------------------------------------------------ dialog state

/// A dialog that is currently on screen.
pub enum DialogState {
    Form(FormState),
    Confirm { title: String, text: String, ok_text: String, danger: bool },
    Info { title: String, text: String },
    Error(String),
}

impl From<Dialog> for DialogState {
    fn from(d: Dialog) -> Self {
        match d {
            Dialog::Form(spec) => DialogState::Form(FormState::new(spec)),
            Dialog::Confirm { title, text, ok_text, danger } => DialogState::Confirm { title, text, ok_text, danger },
            Dialog::Info { title, text } => DialogState::Info { title, text },
            Dialog::Error(e) => DialogState::Error(e),
        }
    }
}

impl DialogState {
    pub fn update(&mut self, msg: FormMsg) -> (Outcome, Task<FormMsg>) {
        match self {
            DialogState::Form(f) => f.update(msg),
            DialogState::Error(e) if matches!(msg, FormMsg::CopyError) => (Outcome::Pending, clipboard::copy(e.clone())),
            _ => match msg {
                FormMsg::Ok => (Outcome::Submitted(FormValues::default()), Task::none()),
                FormMsg::Cancel => (Outcome::Cancelled, Task::none()),
                _ => (Outcome::Pending, Task::none()),
            },
        }
    }

    pub fn view(&self) -> Element<'_, FormMsg> {
        match self {
            DialogState::Form(f) => f.view(),
            DialogState::Confirm { title, text: t, ok_text, danger } => {
                let ok = if *danger { widgets::danger(ok_text, FormMsg::Ok) } else { widgets::primary(ok_text, FormMsg::Ok) };
                card(
                    title,
                    520.0,
                    text(t.as_str()).size(theme::TEXT_BODY),
                    row![Space::new().width(Length::Fill), widgets::secondary("Cancel", FormMsg::Cancel), ok]
                        .spacing(theme::SPACE_SM)
                        .into(),
                )
            }
            DialogState::Info { title, text: t } => card(
                title,
                560.0,
                scrollable(text(t.as_str()).size(theme::TEXT_BODY)).height(Length::Shrink),
                row![Space::new().width(Length::Fill), widgets::primary("OK", FormMsg::Ok)].into(),
            ),
            DialogState::Error(e) => card(
                "Error",
                640.0,
                scrollable(
                    container(text(e.as_str()).size(theme::TEXT_BODY).style(|t: &iced::Theme| text::Style {
                        color: Some(t.extended_palette().danger.base.color),
                    }))
                    .padding([0.0, theme::SPACE_MD]),
                )
                .height(Length::Shrink),
                row![
                    Space::new().width(Length::Fill),
                    widgets::secondary("Copy", FormMsg::CopyError),
                    widgets::primary("OK", FormMsg::Ok),
                ]
                .spacing(theme::SPACE_SM)
                .into(),
            ),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> FormSpec {
        FormSpec::new("t")
            .text("name", "Name", "x")
            .hex_len("key", "Key", "00 11", 2, 2)
            .int_range("n", "N", 5, 0, 10)
            .hex_int("aid", "AID", 0xAB, 6)
            .combo("c", "C", &["a", "b"], 1)
            .check("f", "F", true)
            .multiline("m", "M", "l1\nl2")
            .info("I", "read only")
    }

    #[test]
    fn defaults_validate_and_read_back() {
        let st = FormState::new(spec());
        let v = st.collect().ok().unwrap();
        assert_eq!(v.get_str("name").unwrap(), "x");
        assert_eq!(v.get_hex("key").unwrap(), vec![0, 0x11]);
        assert_eq!(v.get_int("n").unwrap(), 5);
        assert_eq!(v.get_uint("aid").unwrap(), 0xAB);
        assert_eq!(v.get_index("c").unwrap(), 1);
        assert_eq!(v.get_str("c").unwrap(), "b");
        assert!(v.get_bool("f").unwrap());
        assert_eq!(v.get_str("m").unwrap(), "l1\nl2");
        assert!(v.get_int("nope").is_err());
    }

    #[test]
    fn invalid_input_blocks_submit() {
        let mut st = FormState::new(spec());
        st.update(FormMsg::Edit(1, "0011FF".into()));
        assert!(matches!(st.update(FormMsg::Ok).0, Outcome::Pending));
        st.update(FormMsg::Edit(1, "AABB".into()));
        st.update(FormMsg::Edit(2, "11".into()));
        assert!(matches!(st.update(FormMsg::Ok).0, Outcome::Pending));
        st.update(FormMsg::Edit(2, "0x0A".into()));
        assert!(matches!(st.update(FormMsg::Ok).0, Outcome::Submitted(_)));
    }
}
