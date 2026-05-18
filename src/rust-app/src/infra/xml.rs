//! Minimal read-only XML element tree.
//!
//! The Python code parses Sophos API responses with `xmltodict` and then
//! navigates the resulting nested dictionaries. This module provides an
//! equivalent element tree so the same navigation can be reproduced.

use quick_xml::events::Event;
use quick_xml::Reader;

/// A parsed XML element.
#[derive(Debug, Clone, Default)]
pub struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Element>,
    /// Concatenated direct text content (whitespace-only runs dropped).
    pub text: String,
}

impl Element {
    /// First direct child with the given tag name.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    /// All direct children with the given tag name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Attribute value by name.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Parse an XML document into a synthetic document element (empty name) whose
/// children are the top-level element(s). This mirrors how the Python code
/// treats the whole `xmltodict` result as a dictionary.
pub fn parse(xml: &str) -> Element {
    let mut reader = Reader::from_str(xml);
    let config = reader.config_mut();
    config.trim_text(true);

    let mut stack: Vec<Element> = vec![Element::default()];

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => stack.push(make_element(&e)),
            Ok(Event::Empty(e)) => {
                let el = make_element(&e);
                push_child(&mut stack, el);
            }
            Ok(Event::End(_)) => {
                if stack.len() > 1 {
                    let el = stack.pop().unwrap();
                    push_child(&mut stack, el);
                }
            }
            Ok(Event::Text(t)) => {
                if let Ok(txt) = t.unescape() {
                    if let Some(top) = stack.last_mut() {
                        top.text.push_str(&txt);
                    }
                }
            }
            Ok(Event::CData(t)) => {
                if let Ok(txt) = std::str::from_utf8(t.as_ref()) {
                    if let Some(top) = stack.last_mut() {
                        top.text.push_str(txt);
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }

    // Collapse any unclosed elements so a malformed document still yields a tree.
    while stack.len() > 1 {
        let el = stack.pop().unwrap();
        push_child(&mut stack, el);
    }
    stack.pop().unwrap_or_default()
}

fn push_child(stack: &mut [Element], el: Element) {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(el);
    }
}

fn make_element(start: &quick_xml::events::BytesStart) -> Element {
    let name = String::from_utf8_lossy(start.name().as_ref()).into_owned();
    let mut attrs = Vec::new();
    for attr in start.attributes().flatten() {
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let value = attr
            .unescape_value()
            .map(|v| v.into_owned())
            .unwrap_or_default();
        attrs.push((key, value));
    }
    Element {
        name,
        attrs,
        children: Vec::new(),
        text: String::new(),
    }
}
