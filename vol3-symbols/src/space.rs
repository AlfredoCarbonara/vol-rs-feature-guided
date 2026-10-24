//! Symbol space container.
//!
//! A symbol space contains multiple symbol tables and provides
//! unified access to symbols and types across all tables.

use std::collections::HashMap;
use std::sync::Arc;

use crate::isf::IntermediateSymbolTable;
use crate::native::NativeTable;
use crate::traits::{Enumeration, Symbol, SymbolTableInterface};
use crate::types::TypeTemplate;
use vol3_core::error::{SymbolError, SymbolResult};
use vol3_core::types::Architecture;

/// A container for multiple symbol tables
pub struct SymbolSpace {
    /// Named symbol tables
    tables: HashMap<String, Arc<dyn SymbolTableInterface>>,
    /// Order in which tables were added (for resolution order)
    table_order: Vec<String>,
}

impl Default for SymbolSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolSpace {
    /// Create a new empty symbol space
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
            table_order: Vec::new(),
        }
    }

    /// Create a symbol space with native types for the given architecture
    pub fn with_native(architecture: Architecture) -> Self {
        let mut space = Self::new();
        let native = match architecture {
            Architecture::X64 | Architecture::Arm64 => NativeTable::x64("native"),
            Architecture::X86 | Architecture::Arm | Architecture::Unknown => {
                NativeTable::x86("native")
            }
        };
        space.add_table(Arc::new(native));
        space
    }

    /// Add a symbol table to the space
    pub fn add_table(&mut self, table: Arc<dyn SymbolTableInterface>) {
        let name = table.name().to_string();
        if !self.tables.contains_key(&name) {
            self.table_order.push(name.clone());
        }
        self.tables.insert(name, table);
    }

    /// Remove a table by name
    pub fn remove_table(&mut self, name: &str) -> Option<Arc<dyn SymbolTableInterface>> {
        if let Some(table) = self.tables.remove(name) {
            self.table_order.retain(|n| n != name);
            Some(table)
        } else {
            None
        }
    }

    /// Get a table by name
    pub fn get_table(&self, name: &str) -> Option<Arc<dyn SymbolTableInterface>> {
        self.tables.get(name).cloned()
    }

    /// Check if a table exists
    pub fn has_table(&self, name: &str) -> bool {
        self.tables.contains_key(name)
    }

    /// Get all table names
    pub fn table_names(&self) -> impl Iterator<Item = &str> {
        self.table_order.iter().map(|s| s.as_str())
    }

    /// Get a symbol, searching all tables
    pub fn get_symbol(&self, table_name: &str, symbol_name: &str) -> SymbolResult<Symbol> {
        if let Some(table) = self.tables.get(table_name) {
            table.get_symbol(symbol_name)
        } else {
            Err(SymbolError::TableNotFound(table_name.to_string()))
        }
    }

    /// Get a type from a specific table
    pub fn get_type(&self, table_name: &str, type_name: &str) -> SymbolResult<Arc<TypeTemplate>> {
        if let Some(table) = self.tables.get(table_name) {
            table.get_type(type_name)
        } else {
            Err(SymbolError::TableNotFound(table_name.to_string()))
        }
    }

    /// Find a symbol in any table
    pub fn find_symbol(&self, symbol_name: &str) -> SymbolResult<(String, Symbol)> {
        for name in &self.table_order {
            if let Some(table) = self.tables.get(name) {
                if table.has_symbol(symbol_name) {
                    let symbol = table.get_symbol(symbol_name)?;
                    return Ok((name.clone(), symbol));
                }
            }
        }
        Err(SymbolError::NotFound(symbol_name.to_string()))
    }

    /// Find a type in any table
    pub fn find_type(&self, type_name: &str) -> SymbolResult<(String, Arc<TypeTemplate>)> {
        for name in &self.table_order {
            if let Some(table) = self.tables.get(name) {
                if table.has_type(type_name) {
                    let template = table.get_type(type_name)?;
                    return Ok((name.clone(), template));
                }
            }
        }
        Err(SymbolError::TypeNotFound(type_name.to_string()))
    }

    /// Check if any table has a symbol
    pub fn has_symbol(&self, symbol_name: &str) -> bool {
        self.tables.values().any(|t| t.has_symbol(symbol_name))
    }

    /// Check if any table has a type
    pub fn has_type(&self, type_name: &str) -> bool {
        self.tables.values().any(|t| t.has_type(type_name))
    }

    /// Get all symbols from all tables
    pub fn all_symbols(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.tables.iter().flat_map(|(table_name, table)| {
            table
                .symbols()
                .map(move |sym_name| (table_name.as_str(), sym_name))
        })
    }

    /// Get all types from all tables
    pub fn all_types(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.tables.iter().flat_map(|(table_name, table)| {
            table
                .types()
                .map(move |type_name| (table_name.as_str(), type_name))
        })
    }

    /// Get the number of tables
    pub fn table_count(&self) -> usize {
        self.tables.len()
    }

    /// Clear all tables
    pub fn clear(&mut self) {
        self.tables.clear();
        self.table_order.clear();
    }
}

/// Builder for symbol space
pub struct SymbolSpaceBuilder {
    space: SymbolSpace,
}

impl Default for SymbolSpaceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolSpaceBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            space: SymbolSpace::new(),
        }
    }

    /// Add native types
    pub fn with_native(mut self, architecture: Architecture) -> Self {
        let native = match architecture {
            Architecture::X64 | Architecture::Arm64 => NativeTable::x64("native"),
            Architecture::X86 | Architecture::Arm | Architecture::Unknown => {
                NativeTable::x86("native")
            }
        };
        self.space.add_table(Arc::new(native));
        self
    }

    /// Add an ISF table from path
    pub fn with_isf_path(
        mut self,
        path: impl AsRef<std::path::Path>,
        name: impl Into<String>,
    ) -> SymbolResult<Self> {
        let table = IntermediateSymbolTable::from_path(path, name)?;
        self.space.add_table(Arc::new(table));
        Ok(self)
    }

    /// Add a custom table
    pub fn with_table(mut self, table: Arc<dyn SymbolTableInterface>) -> Self {
        self.space.add_table(table);
        self
    }

    /// Build the symbol space
    pub fn build(self) -> SymbolSpace {
        self.space
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_space_basic() {
        let mut space = SymbolSpace::with_native(Architecture::X64);

        // Native table should have types
        assert!(space.has_type("int"));
        assert!(space.has_type("pointer"));

        // Should be able to find types
        let (table_name, template) = space.find_type("int").unwrap();
        assert_eq!(table_name, "native");
        assert_eq!(template.size(), Some(4));
    }

    #[test]
    fn test_symbol_space_builder() {
        let space = SymbolSpaceBuilder::new()
            .with_native(Architecture::X64)
            .build();

        assert_eq!(space.table_count(), 1);
        assert!(space.has_table("native"));
    }
}
