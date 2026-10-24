//! Module (plugin) interface.
//!
//! Modules are the plugins that perform analysis.

use std::sync::Arc;

use vol3_core::error::Vol3Result;
use vol3_core::types::CellValue;

use crate::context::Context;
use crate::requirements::Requirements;

/// Column definition for output
#[derive(Debug, Clone)]
pub struct Column {
    /// Column name
    pub name: String,
    /// Column type hint
    pub type_hint: ColumnType,
}

/// Type hints for columns
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    /// String
    String,
    /// Integer
    Int,
    /// Hexadecimal integer
    Hex,
    /// Float
    Float,
    /// Boolean
    Bool,
    /// Date/time
    DateTime,
    /// Bytes (displayed as hex)
    Bytes,
    /// Disassembly
    Disasm,
}

impl Column {
    /// Create a new column
    pub fn new(name: impl Into<String>, type_hint: ColumnType) -> Self {
        Self {
            name: name.into(),
            type_hint,
        }
    }

    /// Create a string column
    pub fn string(name: impl Into<String>) -> Self {
        Self::new(name, ColumnType::String)
    }

    /// Create an integer column
    pub fn int(name: impl Into<String>) -> Self {
        Self::new(name, ColumnType::Int)
    }

    /// Create a hex column
    pub fn hex(name: impl Into<String>) -> Self {
        Self::new(name, ColumnType::Hex)
    }

    /// Create a boolean column
    pub fn bool(name: impl Into<String>) -> Self {
        Self::new(name, ColumnType::Bool)
    }
}

/// A row of output values
pub type Row = Vec<CellValue>;

/// Result from running a module - an iterator of rows
pub type ModuleOutput = Box<dyn Iterator<Item = Vol3Result<Row>> + Send>;

/// Requirements for a module
#[derive(Debug, Clone)]
pub struct ModuleRequirements {
    /// Plugin requirements
    pub requirements: Requirements,
    /// Plugin name
    pub name: String,
    /// Plugin description
    pub description: String,
}

/// A module that performs analysis
pub trait Module: Send + Sync {
    /// Get the module name
    fn name(&self) -> &str;

    /// Get the module description
    fn description(&self) -> &str;

    /// Get the requirements for this module
    fn requirements(&self) -> ModuleRequirements;

    /// Get the output columns
    fn columns(&self) -> Vec<Column>;

    /// Run the module
    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput>;

    /// Get supported OSes (e.g., "linux", "windows", "mac")
    fn supported_os(&self) -> Vec<&str> {
        vec!["linux", "windows", "mac"]
    }

    /// Get the version
    fn version(&self) -> &str {
        "0.1.0"
    }
}

/// Registry for modules
pub struct ModuleRegistry {
    modules: Vec<Arc<dyn Module>>,
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    /// Register a module
    pub fn register(&mut self, module: Arc<dyn Module>) {
        self.modules.push(module);
    }

    /// Get a module by name
    pub fn get(&self, name: &str) -> Option<Arc<dyn Module>> {
        self.modules.iter().find(|m| m.name() == name).cloned()
    }

    /// Get all modules
    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    /// Get all module names
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.modules.iter().map(|m| m.name())
    }

    /// Filter modules by OS
    pub fn for_os(&self, os: &str) -> Vec<Arc<dyn Module>> {
        self.modules
            .iter()
            .filter(|m| m.supported_os().contains(&os))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Example module for testing
    struct TestModule;

    impl Module for TestModule {
        fn name(&self) -> &str {
            "test"
        }

        fn description(&self) -> &str {
            "A test module"
        }

        fn requirements(&self) -> ModuleRequirements {
            ModuleRequirements {
                name: "test".to_string(),
                description: "A test module".to_string(),
                requirements: Requirements::new(),
            }
        }

        fn columns(&self) -> Vec<Column> {
            vec![Column::string("Name"), Column::int("Value")]
        }

        fn run(&self, _context: Arc<Context>) -> Vol3Result<ModuleOutput> {
            let rows: Vec<Vol3Result<Row>> = vec![Ok(vec![
                CellValue::String("test".to_string()),
                CellValue::Int(42),
            ])];
            Ok(Box::new(rows.into_iter()))
        }
    }

    #[test]
    fn test_module_registry() {
        let mut registry = ModuleRegistry::new();
        registry.register(Arc::new(TestModule));

        assert!(registry.get("test").is_some());
        assert!(registry.get("nonexistent").is_none());
    }
}
