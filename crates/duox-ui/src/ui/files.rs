//! File dialogs (asynchronous, so the window keeps repainting) and plain file I/O helpers.

use iced::Task;
use std::path::{Path, PathBuf};

/// One entry of a file dialog's type filter.
#[derive(Debug, Clone)]
pub struct Filter {
    pub name: String,
    /// Extensions without the dot.
    pub exts: Vec<String>,
}

impl Filter {
    pub fn new(name: &str, exts: &[&str]) -> Self {
        Filter { name: name.into(), exts: exts.iter().map(|e| e.to_string()).collect() }
    }
}

fn dialog(title: &str, filters: &[Filter]) -> rfd::AsyncFileDialog {
    let mut d = rfd::AsyncFileDialog::new().set_title(title);
    for f in filters {
        let exts: Vec<&str> = f.exts.iter().map(String::as_str).collect();
        d = d.add_filter(&f.name, &exts);
    }
    d
}

/// Ask for an existing file. `done` receives `None` when the user cancels.
pub fn pick_open<M: Send + 'static>(
    title: &str,
    filters: &[Filter],
    done: impl Fn(Option<PathBuf>) -> M + Send + 'static,
) -> Task<M> {
    let d = dialog(title, filters);
    Task::perform(async move { d.pick_file().await.map(|h| h.path().to_path_buf()) }, done)
}

/// Ask for a file to write. `done` receives `None` when the user cancels.
pub fn pick_save<M: Send + 'static>(
    title: &str,
    default_name: &str,
    filters: &[Filter],
    done: impl Fn(Option<PathBuf>) -> M + Send + 'static,
) -> Task<M> {
    let d = dialog(title, filters).set_file_name(default_name);
    Task::perform(async move { d.save_file().await.map(|h| h.path().to_path_buf()) }, done)
}

pub fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn write_file(path: &Path, data: &[u8]) -> Result<(), String> {
    std::fs::write(path, data).map_err(|e| format!("{}: {e}", path.display()))
}
