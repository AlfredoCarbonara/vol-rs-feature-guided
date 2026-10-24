//! Configuration tree implementation.
//!
//! This module provides the `HierarchicalDict` type which is the core of
//! configuration data in Volatility3, mirroring the Python implementation
//! in `volatility3.framework.interfaces.configuration`.

use crate::error::{ConfigError, ConfigResult};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The separator used in configuration paths
pub const CONFIG_SEPARATOR: char = '.';

/// Configuration value types that can be stored in the hierarchy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigValue {
    /// Integer value
    Int(i64),
    /// Boolean value
    Bool(bool),
    /// String value
    String(String),
    /// Byte array value
    Bytes(Vec<u8>),
    /// List of values
    List(Vec<ConfigValue>),
}

impl ConfigValue {
    /// Try to get the value as an integer
    pub fn as_int(&self) -> Option<i64> {
        match self {
            ConfigValue::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get the value as a boolean
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ConfigValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get the value as a string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ConfigValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Try to get the value as bytes
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            ConfigValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Try to get the value as a list
    pub fn as_list(&self) -> Option<&[ConfigValue]> {
        match self {
            ConfigValue::List(l) => Some(l),
            _ => None,
        }
    }
}

impl From<i64> for ConfigValue {
    fn from(v: i64) -> Self {
        ConfigValue::Int(v)
    }
}

impl From<i32> for ConfigValue {
    fn from(v: i32) -> Self {
        ConfigValue::Int(v as i64)
    }
}

impl From<bool> for ConfigValue {
    fn from(v: bool) -> Self {
        ConfigValue::Bool(v)
    }
}

impl From<String> for ConfigValue {
    fn from(s: String) -> Self {
        ConfigValue::String(s)
    }
}

impl From<&str> for ConfigValue {
    fn from(s: &str) -> Self {
        ConfigValue::String(s.to_string())
    }
}

impl From<Vec<u8>> for ConfigValue {
    fn from(b: Vec<u8>) -> Self {
        ConfigValue::Bytes(b)
    }
}

impl<T: Into<ConfigValue>> From<Vec<T>> for ConfigValue {
    fn from(v: Vec<T>) -> Self {
        ConfigValue::List(v.into_iter().map(Into::into).collect())
    }
}

/// The core of configuration data, a hierarchical mapping structure.
///
/// This is a faithful port of Python's `HierarchicalDict` that stores keys
/// within itself and also stores lower hierarchies, enabling nested
/// configuration paths like "automagic.LayerStacker.single_location".
#[derive(Debug, Clone, Default)]
pub struct HierarchicalDict {
    /// Local data at this level
    data: IndexMap<String, ConfigValue>,
    /// Child hierarchies
    children: HashMap<String, HierarchicalDict>,
    /// The separator character (usually '.')
    separator: char,
}

impl HierarchicalDict {
    /// Create a new empty HierarchicalDict with the default separator
    pub fn new() -> Self {
        Self {
            data: IndexMap::new(),
            children: HashMap::new(),
            separator: CONFIG_SEPARATOR,
        }
    }

    /// Create a new HierarchicalDict with a custom separator
    pub fn with_separator(separator: char) -> Self {
        Self {
            data: IndexMap::new(),
            children: HashMap::new(),
            separator,
        }
    }

    /// Create from a JSON object
    pub fn from_json(json: &str) -> ConfigResult<Self> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| ConfigError::InvalidValue {
                key: "".to_string(),
                message: e.to_string(),
            })?;

        Self::from_json_value(&value)
    }

    fn from_json_value(value: &serde_json::Value) -> ConfigResult<Self> {
        let mut dict = HierarchicalDict::new();

        if let serde_json::Value::Object(map) = value {
            for (key, val) in map {
                match val {
                    serde_json::Value::Null => {}
                    serde_json::Value::Bool(b) => {
                        dict.set(key, ConfigValue::Bool(*b));
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            dict.set(key, ConfigValue::Int(i));
                        } else if let Some(f) = n.as_f64() {
                            dict.set(key, ConfigValue::Int(f as i64));
                        }
                    }
                    serde_json::Value::String(s) => {
                        dict.set(key, ConfigValue::String(s.clone()));
                    }
                    serde_json::Value::Array(arr) => {
                        let list: Vec<ConfigValue> = arr
                            .iter()
                            .filter_map(|v| match v {
                                serde_json::Value::Bool(b) => Some(ConfigValue::Bool(*b)),
                                serde_json::Value::Number(n) => n.as_i64().map(ConfigValue::Int),
                                serde_json::Value::String(s) => {
                                    Some(ConfigValue::String(s.clone()))
                                }
                                _ => None,
                            })
                            .collect();
                        dict.set(key, ConfigValue::List(list));
                    }
                    serde_json::Value::Object(_) => {
                        let child = Self::from_json_value(val)?;
                        dict.set_subtree(key, child);
                    }
                }
            }
        }

        Ok(dict)
    }

    /// Get the separator character
    pub fn separator(&self) -> char {
        self.separator
    }

    /// Split a path into head and tail components
    fn split_path<'a>(&self, path: &'a str) -> (&'a str, &'a str) {
        match path.find(self.separator) {
            Some(idx) => (&path[..idx], &path[idx + 1..]),
            None => (path, ""),
        }
    }

    /// Get a value by path
    pub fn get(&self, path: &str) -> Option<&ConfigValue> {
        let (head, tail) = self.split_path(path);

        if tail.is_empty() {
            self.data.get(head)
        } else {
            self.children.get(head).and_then(|child| child.get(tail))
        }
    }

    /// Set a value by path, creating intermediate hierarchies as needed
    pub fn set(&mut self, path: &str, value: impl Into<ConfigValue>) {
        let (head, tail) = self.split_path(path);

        if tail.is_empty() {
            self.data.insert(head.to_string(), value.into());
        } else {
            self.children
                .entry(head.to_string())
                .or_insert_with(|| HierarchicalDict::with_separator(self.separator))
                .set(tail, value);
        }
    }

    /// Set a subtree at a path
    pub fn set_subtree(&mut self, path: &str, subtree: HierarchicalDict) {
        let (head, tail) = self.split_path(path);

        if tail.is_empty() {
            self.children.insert(head.to_string(), subtree);
        } else {
            self.children
                .entry(head.to_string())
                .or_insert_with(|| HierarchicalDict::with_separator(self.separator))
                .set_subtree(tail, subtree);
        }
    }

    /// Remove a value by path
    pub fn remove(&mut self, path: &str) -> Option<ConfigValue> {
        let (head, tail) = self.split_path(path);

        if tail.is_empty() {
            self.data.shift_remove(head)
        } else {
            self.children
                .get_mut(head)
                .and_then(|child| child.remove(tail))
        }
    }

    /// Check if a path exists
    pub fn contains(&self, path: &str) -> bool {
        self.get(path).is_some()
    }

    /// Get the local data at this level
    pub fn data(&self) -> &IndexMap<String, ConfigValue> {
        &self.data
    }

    /// Get the child hierarchies
    pub fn children(&self) -> &HashMap<String, HierarchicalDict> {
        &self.children
    }

    /// Get a child hierarchy by name
    pub fn get_child(&self, name: &str) -> Option<&HierarchicalDict> {
        self.children.get(name)
    }

    /// Iterate over all paths and values
    pub fn iter(&self) -> impl Iterator<Item = (String, &ConfigValue)> {
        HierarchicalDictIter::new(self, String::new())
    }

    /// Merge another HierarchicalDict into this one at a given path
    pub fn merge(&mut self, path: &str, other: HierarchicalDict) {
        if path.is_empty() {
            // Merge at root
            for (key, value) in other.data {
                self.data.insert(key, value);
            }
            for (key, child) in other.children {
                self.children
                    .entry(key)
                    .or_insert_with(|| HierarchicalDict::with_separator(self.separator))
                    .merge("", child);
            }
        } else {
            let (head, tail) = self.split_path(path);
            self.children
                .entry(head.to_string())
                .or_insert_with(|| HierarchicalDict::with_separator(self.separator))
                .merge(tail, other);
        }
    }

    /// Clone this HierarchicalDict (deep copy)
    pub fn deep_clone(&self) -> Self {
        self.clone()
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> ConfigResult<String> {
        let value = self.to_json_value();
        serde_json::to_string_pretty(&value).map_err(|e| ConfigError::InvalidValue {
            key: "".to_string(),
            message: e.to_string(),
        })
    }

    fn to_json_value(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();

        for (key, value) in &self.data {
            map.insert(key.clone(), config_value_to_json(value));
        }

        for (key, child) in &self.children {
            map.insert(key.clone(), child.to_json_value());
        }

        serde_json::Value::Object(map)
    }
}

fn config_value_to_json(value: &ConfigValue) -> serde_json::Value {
    match value {
        ConfigValue::Int(i) => serde_json::Value::Number((*i).into()),
        ConfigValue::Bool(b) => serde_json::Value::Bool(*b),
        ConfigValue::String(s) => serde_json::Value::String(s.clone()),
        ConfigValue::Bytes(b) => {
            // Encode bytes as base64 string
            serde_json::Value::String(base64_encode(b))
        }
        ConfigValue::List(l) => {
            serde_json::Value::Array(l.iter().map(config_value_to_json).collect())
        }
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    for byte in bytes {
        write!(buf, "{:02x}", byte).unwrap();
    }
    String::from_utf8(buf).unwrap()
}

/// Iterator over all paths in a HierarchicalDict
struct HierarchicalDictIter<'a> {
    stack: Vec<(String, &'a HierarchicalDict, usize, bool)>,
}

impl<'a> HierarchicalDictIter<'a> {
    fn new(dict: &'a HierarchicalDict, prefix: String) -> Self {
        Self {
            stack: vec![(prefix, dict, 0, false)],
        }
    }
}

impl<'a> Iterator for HierarchicalDictIter<'a> {
    type Item = (String, &'a ConfigValue);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((prefix, dict, idx, in_children)) = self.stack.pop() {
            if !in_children {
                // Still iterating over data
                let keys: Vec<_> = dict.data.keys().collect();
                if idx < keys.len() {
                    let key = keys[idx];
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}{}{}", prefix, dict.separator, key)
                    };
                    self.stack.push((prefix, dict, idx + 1, false));
                    return dict.data.get(key).map(|v| (path, v));
                } else {
                    // Move to children
                    self.stack.push((prefix, dict, 0, true));
                }
            } else {
                // Iterating over children
                let keys: Vec<_> = dict.children.keys().collect();
                if idx < keys.len() {
                    let key = keys[idx];
                    let child_prefix = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}{}{}", prefix, dict.separator, key)
                    };
                    self.stack.push((prefix, dict, idx + 1, true));
                    if let Some(child) = dict.children.get(key) {
                        self.stack.push((child_prefix, child, 0, false));
                    }
                }
            }
        }
        None
    }
}

// Path utilities

/// Join configuration paths together
pub fn path_join(parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(&CONFIG_SEPARATOR.to_string())
}

/// Returns the parent configuration path
pub fn parent_path(value: &str) -> String {
    let parts: Vec<_> = value.split(CONFIG_SEPARATOR).collect();
    if parts.len() <= 1 {
        String::new()
    } else {
        parts[..parts.len() - 1].join(&CONFIG_SEPARATOR.to_string())
    }
}

/// Return the last component of a configuration path
pub fn path_head(value: &str) -> &str {
    value.rsplit(CONFIG_SEPARATOR).next().unwrap_or(value)
}

/// Returns the path up to a certain depth
pub fn path_depth(path: &str, depth: usize) -> String {
    let parts: Vec<_> = path.split(CONFIG_SEPARATOR).collect();
    parts
        .into_iter()
        .take(depth)
        .collect::<Vec<_>>()
        .join(&CONFIG_SEPARATOR.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hierarchical_dict_basic() {
        let mut dict = HierarchicalDict::new();
        dict.set("key1", "value1");
        dict.set("key2", 42i64);

        assert_eq!(
            dict.get("key1"),
            Some(&ConfigValue::String("value1".to_string()))
        );
        assert_eq!(dict.get("key2"), Some(&ConfigValue::Int(42)));
    }

    #[test]
    fn test_hierarchical_dict_nested() {
        let mut dict = HierarchicalDict::new();
        dict.set("level1.level2.key", "nested_value");

        assert_eq!(
            dict.get("level1.level2.key"),
            Some(&ConfigValue::String("nested_value".to_string()))
        );
    }

    #[test]
    fn test_hierarchical_dict_iter() {
        let mut dict = HierarchicalDict::new();
        dict.set("a", "1");
        dict.set("b.c", "2");
        dict.set("b.d", "3");

        let paths: Vec<String> = dict.iter().map(|(p, _)| p).collect();
        assert!(paths.contains(&"a".to_string()));
        assert!(paths.contains(&"b.c".to_string()));
        assert!(paths.contains(&"b.d".to_string()));
    }

    #[test]
    fn test_path_utilities() {
        assert_eq!(path_join(&["a", "b", "c"]), "a.b.c");
        assert_eq!(path_join(&["a", "", "c"]), "a.c");
        assert_eq!(parent_path("a.b.c"), "a.b");
        assert_eq!(parent_path("a"), "");
        assert_eq!(path_head("a.b.c"), "c");
        assert_eq!(path_depth("a.b.c.d", 2), "a.b");
    }
}
