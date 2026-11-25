//! Collapsible tree with a single selection (card contents: applications, keys, files).
//!
//! The caller owns the `Vec<Node>` (rebuilt after each scan) and a [`TreeState`] (which nodes
//! are open, which is selected), feeds [`TreeEvent`]s into [`TreeState::update`] and renders with
//! [`view`]. Node ids must be unique within the tree; the selection is reported by id.

use super::{style, theme, widgets};
use iced::widget::{button, container, row, text, Column, Space};
use iced::{Element, Length};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub label: String,
    /// Dimmed text after the label (e.g. "Standard data file, 32 bytes").
    pub info: Option<String>,
    pub children: Vec<Node>,
}

impl Node {
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Node { id: id.into(), label: label.into(), info: None, children: Vec::new() }
    }
    pub fn info(mut self, info: impl Into<String>) -> Self {
        self.info = Some(info.into());
        self
    }
    pub fn child(mut self, c: Node) -> Self {
        self.children.push(c);
        self
    }
    pub fn children(mut self, c: impl IntoIterator<Item = Node>) -> Self {
        self.children.extend(c);
        self
    }
}

#[derive(Debug, Clone)]
pub enum TreeEvent {
    Toggle(String),
    Select(String),
}

#[derive(Debug, Default, Clone)]
pub struct TreeState {
    pub expanded: HashSet<String>,
    pub selected: Option<String>,
}

impl TreeState {
    pub fn update(&mut self, ev: TreeEvent) {
        match ev {
            TreeEvent::Toggle(id) => {
                if !self.expanded.remove(&id) {
                    self.expanded.insert(id);
                }
            }
            TreeEvent::Select(id) => self.selected = Some(id),
        }
    }

    pub fn expand_all(&mut self, roots: &[Node]) {
        fn walk(n: &Node, set: &mut HashSet<String>) {
            if !n.children.is_empty() {
                set.insert(n.id.clone());
            }
            n.children.iter().for_each(|c| walk(c, set));
        }
        roots.iter().for_each(|n| walk(n, &mut self.expanded));
    }

    pub fn collapse_all(&mut self) {
        self.expanded.clear();
    }

    pub fn is_selected(&self, id: &str) -> bool {
        self.selected.as_deref() == Some(id)
    }
}

const INDENT: f32 = 18.0;

/// Render the tree. Wrap the result in a `scrollable` when it can grow.
pub fn view<'a>(roots: &'a [Node], state: &'a TreeState) -> Element<'a, TreeEvent> {
    let mut col = Column::new().spacing(1);
    for n in roots {
        col = push_node(col, n, state, 0);
    }
    col.width(Length::Fill).into()
}

fn push_node<'a>(
    mut col: Column<'a, TreeEvent>,
    n: &'a Node,
    state: &'a TreeState,
    depth: usize,
) -> Column<'a, TreeEvent> {
    let open = state.expanded.contains(&n.id);
    let toggle: Element<'a, TreeEvent> = if n.children.is_empty() {
        Space::new().width(22).into()
    } else {
        button(text(if open { "-" } else { "+" }).font(theme::MONO).size(theme::TEXT_BODY))
            .on_press(TreeEvent::Toggle(n.id.clone()))
            .style(style::row_button(false))
            .padding([2, 6])
            .width(22)
            .into()
    };
    let mut label = row![text(n.label.as_str()).size(theme::TEXT_BODY)].spacing(theme::SPACE_MD);
    if let Some(info) = &n.info {
        label = label.push(widgets::hint(info.as_str()));
    }
    let line = row![
        Space::new().width(depth as f32 * INDENT),
        toggle,
        button(label)
            .on_press(TreeEvent::Select(n.id.clone()))
            .style(style::row_button(state.is_selected(&n.id)))
            .padding([2, 8])
            .width(Length::Fill),
    ]
    .align_y(iced::Alignment::Center);
    col = col.push(container(line).width(Length::Fill));
    if open {
        for c in &n.children {
            col = push_node(col, c, state, depth + 1);
        }
    }
    col
}
