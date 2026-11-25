# duox-ui

Rust workspace for NXP MIFARE DUOX (MF3E(H)x3) cards: a protocol library and an iced desktop app.

```
crates/duox      library: everything that talks to a card or manipulates card data
  crypto         AES / CMAC / KDFs, ECDSA + ECDH on P-256 and brainpoolP256r1, EV2 session state
  error          crate-wide Error (thiserror)
  transport      `Transport` trait (+ APDU trace hook), PC/SC implementation (feature `pcsc`)
  card           `Card`: selection, authentication (AES EV2 / ECC), secure messaging, all commands
  pki            CA / certificate / CRL store, card certificate profile, chain validation
  sdm            Secure Dynamic Messaging: settings, NDEF templates, read-out + verification
  txmac          Transaction MAC / Signature
  dam            Delegated application management tickets and MACs
  evcert         EV charging certificate
crates/duox-ui   iced application (one module per tab)
```

Rules
- The data sheet (NXP MIFARE DUOX product data sheet Rev. 1.2) is the source of truth; section numbers in comments refer to it.
- Idiomatic Rust: enums/newtypes over magic numbers, `thiserror` errors, `Result` everywhere, no panics on card or user
  data, no `unsafe`, `&[u8]` in / `Vec<u8>` out, builders or option structs for commands with many parameters.
- Key material is never logged.
- Card I/O is synchronous inside the library. The UI decides where to run it.

## Writing a tab (duox-ui)

File map of `crates/duox-ui/src`:

```
main.rs        iced::application(app::boot, app::update, app::view)
app.rs         shell: top bar, status line, tab bar, log pane, modal dialogs, message routing
shared.rs      `Shared`: card, store, log, scan info, dialog requests, events
log.rs         LogBuf (APDU trace + command lines)
tabs/<name>.rs one module per tab; tabs/mod.rs holds `TabId`
ui/            form.rs (dialogs) widgets.rs tree.rs textview.rs hex.rs files.rs clipboard.rs style.rs theme.rs
```

### The tab contract

Every tab module `tabs/<name>.rs` exports exactly:

```rust
pub struct State { .. }                       // must impl Default (+ Debug)
#[derive(Debug, Clone)]
pub enum Message {
    FormDone { token: u32, values: Option<FormValues> },   // REQUIRED variants:
    Event(AppEvent),                                       //   these two
    /* your own variants */
}
impl State {
    pub fn update(&mut self, msg: Message, shared: &mut Shared) -> Task<crate::app::Message>;
    pub fn view(&self, shared: &Shared) -> Element<'_, Message>;
}
```

`app.rs` wraps the tab's message as `app::Message::<Tab>(msg)`, owns one `State` per tab and renders only the
active tab, but delivers events to all tabs. Tab state therefore survives tab switches. Tabs are `Card, Auth, Pki,
Crl, Sdm, Delegated, Transactions, Features, Tools`; you edit only your own file (plus backwards compatible
additions under `ui/`). `app.rs` never needs to change when a tab grows.

* Tasks you create must produce `crate::app::Message`, so wrap your own message yourself:
  `Task::perform(fut, |r| app::Message::Sdm(Message::Done(r)))`. Return `Task::none()` for synchronous work.
* `Task::done(app::Message::Goto(TabId::Auth))` switches tabs.
* `view` must be cheap and pure; derive from `State` and `Shared` only.
* `Message::Event(ev)` arrives for: `Connected` (after the connect-time scan), `Disconnected`, `StoreChanged`
  (someone called `shared.store_changed()` or the store was unlocked), `Activated` (this tab was selected).
  Drop cached card data on `Disconnected`; re-read store-derived lists on `StoreChanged`.

### `Shared`

```rust
pub struct Shared {
    pub card: Option<Card<Box<dyn Transport>>>,   // None while disconnected
    pub reader: Option<String>,
    pub store: PkiStore,                          // ~/.duoxtool/store.json or argv[1]
    pub log: LogBuf,
    pub scan: Option<ScanInfo>,                   // atr, version: Option<VersionInfo>, applications: Vec<Aid>
    pub store_rev: u64,                           // bumped by store_changed()
}
impl Shared {
    pub fn is_connected(&self) -> bool;
    pub fn with_card<R, E: Display>(&mut self, f: impl FnOnce(&mut DynCard) -> Result<R, E>) -> Result<R, String>;
    pub fn with_card_quiet<R, E: Display>(&mut self, f: ...) -> Result<R, String>;   // no log, no dialog
    pub fn with_store<R>(&mut self, f: impl FnOnce(&mut PkiStore) -> duox::pki::Result<R>) -> Result<R, String>;
    pub fn store_changed(&mut self);              // call after every store mutation
    pub fn report_error(&mut self, msg: impl Into<String>) -> String;   // log + error dialog
    pub fn status_text(&self) -> String;
    pub fn refresh_scan(&mut self);               // re-read version + app list; only while NOT authenticated
    pub fn ask(&mut self, spec: FormSpec, token: u32);
    pub fn confirm(&mut self, title: &str, text: &str, ok_text: &str, token: u32);
    pub fn confirm_danger(&mut self, title: &str, text: &str, ok_text: &str, token: u32);
    pub fn info(&mut self, title: &str, text: &str);
    pub fn log_info(&self, line: &str);
}
```

* **Card I/O is synchronous and runs inside `update` on the UI thread** (see the module comment in `shared.rs`).
  Always go through `with_card`; never keep a reference to the card across calls. On `Err` the message is already in
  the log and in an error dialog (`with_store` opens the unlock prompt instead when the store is locked): do not show
  it again, just stop. After a failed command the library has dropped the authentication; the status line reflects
  that automatically because it is computed from the card on every redraw.
* The log pane receives one line per command (`-- Name [mode]`, from `Card::set_log`) and, optionally, every APDU
  (`   > hex` / `   < hex`). The shell installs both hooks on connect. Use `shared.log_info("...")` for your own
  lines. Never log key material.
* Group card commands that belong together in one `with_card` closure; it gets `&mut Card`.

### Dialogs and forms (`ui::form`)

Ask, then react in `Message::FormDone`. The `token` is any `u32` constant you choose per action (`u32::MAX` is
reserved). Answers go to the tab that asked, also if the user switched tabs meanwhile. Dialogs are queued and
shown one at a time; Esc cancels, Enter in a text field submits, Tab moves focus.

```rust
shared.ask(
    FormSpec::new("New file").note("Creates a standard data file.").ok_text("Create")
        .hex_int_range("fid", "File number", 1, 2, 0, 0x1F)     // key, label, default, hex digits, min, max
        .combo("mode", "Comm. mode", &["Plain", "MAC", "Full"], 2)
        .int_range("size", "Size", 32, 1, 8192).hint("bytes")
        .hex_len("key", "Key", "", 16, 16)
        .file_open("src", "Initial data", vec![Filter::new("Binary", &["bin"])]),
    TOKEN_NEW_FILE,
);
// later, in update():
Message::FormDone { token: TOKEN_NEW_FILE, values: Some(v) } => {
    let fid = v.get_uint("fid").unwrap_or(1);
    let mode = v.get_index("mode").unwrap_or(0);
}
```

Field builders on `FormSpec` (chain in display order; `key` is what you read back and is not shown):

| builder | value | getter |
|---|---|---|
| `text(key, label, default)` / `secret(key, label)` | text (masked) | `get_str` |
| `hex(key, label, default)` / `hex_len(.., default, min, max)` | bytes (spaces, `:`, `-`, `0x` accepted; live byte count) | `get_hex -> Vec<u8>` |
| `int(key, label, default)` / `int_range(.., default, min, max)` | `i64` (decimal or `0x`) | `get_int` |
| `hex_int(key, label, default, digits)` / `hex_int_range(.., digits, min, max)` | `u64` entered in hex | `get_uint` |
| `combo(key, label, &[options], default_index)` | choice | `get_index`, `get_str` (option text) |
| `check(key, label, default)` | bool | `get_bool` |
| `multiline(key, label, default)` | text | `get_str` |
| `info(label, text)` | read-only, no value | - |
| `file_open(key, label, filters)` / `file_save(key, label, default_name, filters)` | path (file dialog) | `get_path -> Option<PathBuf>`, `get_str` |
| `.hint(text)` | small text under the last field | - |

Getters return `Result<_, String>`. The form validates everything before it returns, so they fail only on a wrong
key or type; `unwrap_or_default()` is fine. `FormValues` prints only its keys in `Debug` (values can be
passphrases). `confirm` / `confirm_danger` answer `Some(empty values)` for yes and `None` for no; cancelling a form
also gives `None`. `info` and error dialogs deliver nothing. A form with invalid fields cannot be submitted; the
invalid fields show their message inline.

Files: `ui::files::pick_open(title, &[Filter], |Option<PathBuf>| Msg) -> Task<Msg>`,
`pick_save(title, default_name, &[Filter], f)`, `read_file(&Path)`, `write_file(&Path, &[u8])`.
Clipboard: `ui::clipboard::copy(text) -> Task<M>`.

### Widgets (`ui::*`)

* `widgets::section(title)`, `group(title, body)`, `panel(body)`, `kv_table(&[(String, String)], mono_values)`,
  `mono(text)`, `hint(text)`, `primary / secondary / danger(label, msg) -> Button`, `placeholder(title)`.
* `textview::TextView`: read-only, selectable, monospace text area. Keep it in your `State`; `set_text`, `text()`,
  `selection()`; feed `text_editor::Action` into `perform` from a `Message::View(Action)`; `view()` returns
  `Element<Action>` (map it into your message). `hex::dump(&bytes)` formats dumps.
* `tree`: `Node::new(id, label).info(..).child(..)`, `TreeState` (`expanded`, `selected`, `update(TreeEvent)`,
  `expand_all`), `tree::view(&nodes, &state) -> Element<TreeEvent>`; wrap it in `scrollable`. Ids must be unique.
* `hex`: `spaced`, `compact`, `dump`, `parse`. `theme`: spacing (`SPACE_*`), text sizes, `MONO`, `LABEL_WIDTH`.
* Colours come from the iced theme palette (`theme.extended_palette()`); do not hard-code colours, so both the light
  and the dark theme stay readable.

### Worked example

```rust
use crate::app;
use crate::shared::{AppEvent, Shared};
use crate::ui::form::{FormSpec, FormValues};
use crate::ui::{clipboard, hex, widgets};
use iced::widget::{column, row, scrollable};
use iced::{Element, Length, Task};

const ASK_PATTERN: u32 = 1; // tokens identify which action asked

#[derive(Debug, Default)]
pub struct State { output: String }

#[derive(Debug, Clone)]
pub enum Message {
    FormDone { token: u32, values: Option<FormValues> },
    Event(AppEvent),
    ReadVersion,
    AskPattern,
    Copy,
}

impl State {
    pub fn update(&mut self, msg: Message, shared: &mut Shared) -> Task<app::Message> {
        match msg {
            Message::ReadVersion => {
                // On Err the error is already logged and shown; just stop.
                if let Ok(v) = shared.with_card(|card| card.get_version()) {
                    self.output = format!("UID {}\nSW {}.{}", hex::spaced(&v.uid), v.sw_version.0, v.sw_version.1);
                }
            }
            Message::AskPattern => shared.ask(
                FormSpec::new("Fill pattern").note("Bytes to repeat.").ok_text("Build")
                    .hex_len("pat", "Pattern", "AA55", 1, 8)
                    .int_range("count", "Repeat", 4, 1, 64)
                    .check("spaced", "Insert spaces", true),
                ASK_PATTERN,
            ),
            Message::FormDone { token: ASK_PATTERN, values: Some(v) } => {
                let (pat, n) = (v.get_hex("pat").unwrap_or_default(), v.get_int("count").unwrap_or(1));
                let all: Vec<u8> = pat.iter().copied().cycle().take(pat.len() * n as usize).collect();
                self.output = if v.get_bool("spaced").unwrap_or(false) { hex::spaced(&all) } else { hex::compact(&all) };
            }
            Message::Copy => return clipboard::copy(self.output.clone()),
            Message::FormDone { .. } | Message::Event(_) => {} // cancelled, or nothing to react to
        }
        Task::none()
    }

    pub fn view(&self, shared: &Shared) -> Element<'_, Message> {
        let mut read = widgets::primary("Read version", Message::ReadVersion);
        if !shared.is_connected() {
            read = iced::widget::button("Read version"); // no on_press: disabled
        }
        column![
            widgets::group("Demo", row![read, widgets::secondary("Pattern...", Message::AskPattern),
                widgets::secondary("Copy", Message::Copy)].spacing(8)),
            scrollable(widgets::mono(self.output.clone())).width(Length::Fill),
        ].spacing(12).into()
    }
}
```

### Limitations to know

* A card command blocks the UI while it runs (by design, see above).
* Dialog keyboard support is Tab / Esc / Enter only; multi-line fields swallow Tab.
