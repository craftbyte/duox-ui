//! Shared log buffer fed by the transport trace hook and the card's command log hook.
//!
//! The hooks run on whatever thread calls into the card (the UI thread today) but must be
//! `Send`, hence the `Arc<Mutex<_>>`. Key material never reaches this buffer: the library only
//! reports wire bytes and command names.

use crate::ui::hex;
use duox::transport::{TraceDir, TraceHook};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const CAPACITY: usize = 5000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    /// Command name from the card.
    Command,
    /// APDU to the card.
    Tx,
    /// APDU from the card.
    Rx,
    Info,
    Error,
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub kind: LineKind,
    pub text: String,
}

#[derive(Default)]
struct Inner {
    lines: VecDeque<LogLine>,
    /// Bumped on every change so the view knows when to rebuild.
    revision: u64,
}

/// Cheap to clone; all clones share one buffer.
#[derive(Clone, Default)]
pub struct LogBuf(Arc<Mutex<Inner>>);

impl LogBuf {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn push(&self, kind: LineKind, text: impl Into<String>) {
        let mut g = self.lock();
        if g.lines.len() >= CAPACITY {
            g.lines.pop_front();
        }
        g.lines.push_back(LogLine { kind, text: text.into() });
        g.revision += 1;
    }

    pub fn info(&self, text: impl Into<String>) {
        self.push(LineKind::Info, text);
    }

    pub fn clear(&self) {
        let mut g = self.lock();
        g.lines.clear();
        g.revision += 1;
    }

    pub fn revision(&self) -> u64 {
        self.lock().revision
    }

    /// The log as text, one line per entry; APDU lines only when `show_apdus`.
    pub fn text(&self, show_apdus: bool) -> String {
        let g = self.lock();
        let mut out = String::new();
        for l in g.lines.iter().filter(|l| show_apdus || !matches!(l.kind, LineKind::Tx | LineKind::Rx)) {
            out.push_str(&l.text);
            out.push('\n');
        }
        out
    }

    /// Hook for `Transport::set_trace`.
    pub fn trace_hook(&self) -> TraceHook {
        let log = self.clone();
        Box::new(move |dir, bytes| match dir {
            TraceDir::Tx => log.push(LineKind::Tx, format!("   > {}", hex::spaced(bytes))),
            TraceDir::Rx => log.push(LineKind::Rx, format!("   < {}", hex::spaced(bytes))),
        })
    }

    /// Hook for `Card::set_log`.
    pub fn command_hook(&self) -> Box<dyn FnMut(&str) + Send> {
        let log = self.clone();
        Box::new(move |line| log.push(LineKind::Command, line))
    }
}
