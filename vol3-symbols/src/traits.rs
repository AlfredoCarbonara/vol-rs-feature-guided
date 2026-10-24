//! Symbol table trait definitions.

use std::collections::HashMap;
use std::sync::Arc;
use vol3_core::error::SymbolResult;
use vol3_core::types::Address;

use crate::types::TypeTemplate;

/// A symbol representing a named location in memory.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// The symbol name
    pub name: String,
    /// The address/offset
    pub address: Address,
    /// The type name (if known)
    pub type_name: Option<String>,
    /// Constant data associated with the symbol
    pub constant_data: Option<String>,
}

impl Symbol {
    /// Create a new symbol
    pub fn new(name: impl Into<String>, address: Address) -> Self {
        Self {
            name: name.into(),
            address,
            type_name: None,
            constant_data: None,
        }
    }

    /// Set the type name
    pub fn with_type(mut self, type_name: impl Into<String>) -> Self {
        self.type_name = Some(type_name.into());
        self
    }

    /// Set constant data
    pub fn with_constant_data(mut self, data: String) -> Self {
        self.constant_data = Some(data);
        self
    }
}

/// An enumeration type with named values.
#[derive(Debug, Clone)]
pub struct Enumeration {
    /// The enumeration name
    pub name: String,
    /// The choices (name -> value)
    pub choices: HashMap<String, i64>,
}

impl Enumeration {
    /// Get a value by name
    pub fn get(&self, name: &str) -> Option<i64> {
        self.choices.get(name).copied()
    }

    /// Get a name by value
    pub fn get_name(&self, value: i64) -> Option<&str> {
        self.choices
            .iter()
            .find(|(_, &v)| v == value)
            .map(|(k, _)| k.as_str())
    }
}

/// Interface for symbol tables.
///
/// This trait defines the operations that all symbol tables must support.
pub trait SymbolTableInterface: Send + Sync {
    /// Get the table name
    fn name(&self) -> &str;

    /// Get a symbol by name
    fn get_symbol(&self, name: &str) -> SymbolResult<Symbol>;

    /// Get a type template by name
    fn get_type(&self, name: &str) -> SymbolResult<Arc<TypeTemplate>>;

    /// Get an enumeration by name
    fn get_enumeration(&self, name: &str) -> SymbolResult<Enumeration>;

    /// Check if a symbol exists
    fn has_symbol(&self, name: &str) -> bool;

    /// Check if a type exists
    fn has_type(&self, name: &str) -> bool;

    /// Iterate over all symbol names
    fn symbols(&self) -> Box<dyn Iterator<Item = &str> + '_>;

    /// Iterate over all type names
    fn types(&self) -> Box<dyn Iterator<Item = &str> + '_>;

    /// Iterate over all enumeration names
    fn enumerations(&self) -> Box<dyn Iterator<Item = &str> + '_>;

    /// Get symbols at a given address
    fn get_symbols_by_location(&self, offset: Address, size: u64) -> Vec<String> {
        // Default implementation - can be overridden for efficiency
        let mut results = Vec::new();
        for sym_name in self.symbols() {
            if let Ok(sym) = self.get_symbol(sym_name) {
                if sym.address >= offset && sym.address <= offset + size {
                    results.push(sym_name.to_string());
                }
            }
        }
        results
    }

    /// Get symbols by type
    fn get_symbols_by_type(&self, type_name: &str) -> Vec<String> {
        let mut results = Vec::new();
        for sym_name in self.symbols() {
            if let Ok(sym) = self.get_symbol(sym_name) {
                if sym.type_name.as_deref() == Some(type_name) {
                    results.push(sym_name.to_string());
                }
            }
        }
        results
    }

    /// Get a symbol at or near a specific address
    /// When multiple symbols share the same address, returns the one that's alphabetically first
    /// to match Python vol3 behavior
    fn get_symbol_by_address(&self, address: Address) -> Option<(String, Symbol)> {
        let mut exact_match: Option<(String, Symbol)> = None;
        let mut best_match: Option<(String, Symbol)> = None;

        for sym_name in self.symbols() {
            if let Ok(sym) = self.get_symbol(sym_name) {
                if sym.address == address {
                    // For exact matches, keep the alphabetically first symbol name
                    match &exact_match {
                        None => exact_match = Some((sym_name.to_string(), sym)),
                        Some((existing_name, _)) if sym_name < existing_name => {
                            exact_match = Some((sym_name.to_string(), sym));
                        }
                        _ => {}
                    }
                } else if sym.address < address {
                    // Track closest symbol below the address
                    match &best_match {
                        None => best_match = Some((sym_name.to_string(), sym)),
                        Some((best_name, best_sym)) => {
                            if sym.address > best_sym.address
                                || (sym.address == best_sym.address && sym_name < best_name)
                            {
                                best_match = Some((sym_name.to_string(), sym));
                            }
                        }
                    }
                }
            }
        }
        exact_match.or(best_match)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_creation() {
        let sym = Symbol::new("test_sym", 0x1000)
            .with_type("int")
            .with_constant_data("test".to_string());

        assert_eq!(sym.name, "test_sym");
        assert_eq!(sym.address, 0x1000);
        assert_eq!(sym.type_name, Some("int".to_string()));
        assert_eq!(sym.constant_data, Some("test".to_string()));
    }

    #[test]
    fn test_enumeration() {
        let mut choices = HashMap::new();
        choices.insert("RUNNING".to_string(), 0);
        choices.insert("SLEEPING".to_string(), 1);
        choices.insert("STOPPED".to_string(), 2);

        let enum_type = Enumeration {
            name: "task_state".to_string(),
            choices,
        };

        assert_eq!(enum_type.get("RUNNING"), Some(0));
        assert_eq!(enum_type.get_name(1), Some("SLEEPING"));
    }
}
