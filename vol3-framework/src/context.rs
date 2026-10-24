//! Context implementation.
//!
//! The context holds all state needed for analysis: layers, symbols, and config.

use std::sync::Arc;

use parking_lot::RwLock;

use vol3_core::config::{ConfigValue, HierarchicalDict};
use vol3_core::error::{LayerResult, SymbolResult, Vol3Error, Vol3Result};
use vol3_core::types::{Address, Endianness};
use vol3_layers::container::LayerContainer;
use vol3_layers::traits::DataLayer;
use vol3_objects::ObjectFactory;
use vol3_symbols::{SymbolSpace, SymbolTableInterface};

/// The context holds all analysis state.
pub struct Context {
    /// Configuration tree
    config: RwLock<HierarchicalDict>,
    /// Layer container
    layers: RwLock<LayerContainer>,
    /// Symbol space
    symbols: RwLock<SymbolSpace>,
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    /// Create a new empty context
    pub fn new() -> Self {
        Self {
            config: RwLock::new(HierarchicalDict::new()),
            layers: RwLock::new(LayerContainer::new()),
            symbols: RwLock::new(SymbolSpace::new()),
        }
    }

    // ========== Configuration ==========

    /// Get a configuration value
    pub fn config_get(&self, path: &str) -> Option<ConfigValue> {
        self.config.read().get(path).cloned()
    }

    /// Set a configuration value
    pub fn config_set<V: Into<ConfigValue>>(&self, path: &str, value: V) {
        self.config.write().set(path, value.into());
    }

    /// Check if a configuration path exists
    pub fn config_contains(&self, path: &str) -> bool {
        self.config.read().contains(path)
    }

    /// Get config as string
    pub fn config_get_string(&self, path: &str) -> Option<String> {
        self.config_get(path)
            .and_then(|v| v.as_str().map(|s| s.to_string()))
    }

    /// Get config as integer
    pub fn config_get_int(&self, path: &str) -> Option<i64> {
        self.config_get(path).and_then(|v| v.as_int())
    }

    /// Get config as bool
    pub fn config_get_bool(&self, path: &str) -> Option<bool> {
        self.config_get(path).and_then(|v| v.as_bool())
    }

    // ========== Layers ==========

    /// Add a layer
    pub fn add_layer(&self, layer: Arc<dyn DataLayer>) {
        let _ = self.layers.write().add_shared_layer(layer);
    }

    /// Get a layer by name
    pub fn get_layer(&self, name: &str) -> Option<Arc<dyn DataLayer>> {
        self.layers.read().get(name).cloned()
    }

    /// Check if a layer exists
    pub fn has_layer(&self, name: &str) -> bool {
        self.layers.read().contains(name)
    }

    /// Get all layer names
    pub fn layer_names(&self) -> Vec<String> {
        self.layers.read().names().map(|s| s.to_string()).collect()
    }

    /// Remove a layer
    pub fn remove_layer(&self, name: &str) -> Option<Arc<dyn DataLayer>> {
        self.layers.write().remove(name)
    }

    // ========== Symbols ==========

    /// Add a symbol table
    pub fn add_symbol_table(&self, table: Arc<dyn SymbolTableInterface>) {
        self.symbols.write().add_table(table);
    }

    /// Get a symbol table by name
    pub fn get_symbol_table(&self, name: &str) -> Option<Arc<dyn SymbolTableInterface>> {
        self.symbols.read().get_table(name)
    }

    /// Check if a symbol table exists
    pub fn has_symbol_table(&self, name: &str) -> bool {
        self.symbols.read().has_table(name)
    }

    /// Get all symbol table names
    pub fn symbol_table_names(&self) -> Vec<String> {
        self.symbols
            .read()
            .table_names()
            .map(|s| s.to_string())
            .collect()
    }

    /// Get a symbol from a table
    pub fn get_symbol(
        &self,
        table_name: &str,
        symbol_name: &str,
    ) -> SymbolResult<vol3_symbols::Symbol> {
        self.symbols.read().get_symbol(table_name, symbol_name)
    }

    /// Get a type from a table
    pub fn get_type(
        &self,
        table_name: &str,
        type_name: &str,
    ) -> SymbolResult<Arc<vol3_symbols::TypeTemplate>> {
        self.symbols.read().get_type(table_name, type_name)
    }

    // ========== Object Creation ==========

    /// Create an object at the given address
    pub fn object(
        &self,
        layer_name: &str,
        symbol_table: &str,
        type_name: &str,
        address: Address,
    ) -> Vol3Result<Arc<dyn vol3_objects::traits::MemoryObject>> {
        use vol3_core::error::LayerError;

        let layer = self
            .get_layer(layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(layer_name.to_string())))?;

        // Get the type from the symbol table
        let template = self.get_type(symbol_table, type_name)?;

        // Build symbol space for factory - we need a snapshot
        // For now, create an empty one and add just the needed table
        // TODO: Improve this by making SymbolSpace Clone or using Arc
        let symbols = Arc::new(SymbolSpace::new());

        // Create factory
        // TODO: Get architecture from context/layer
        let factory = ObjectFactory::new(
            symbols,
            layer,
            layer_name,
            8, // pointer size - should come from context
            Endianness::Little,
        );

        factory
            .create_object(symbol_table, type_name, address)
            .map_err(|e| e.into())
    }

    /// Read bytes from a layer
    pub fn read(&self, layer_name: &str, address: Address, size: usize) -> LayerResult<Vec<u8>> {
        use vol3_core::error::LayerError;

        let layer = self
            .get_layer(layer_name)
            .ok_or_else(|| LayerError::NotFound(layer_name.to_string()))?;
        layer.read(address, size, false)
    }
}

// Note: Context Clone requires Clone implementations on LayerContainer and SymbolSpace
// For now we skip Clone impl on Context as it requires more work in vol3-layers and vol3-symbols

/// Builder for creating contexts
pub struct ContextBuilder {
    context: Context,
}

impl Default for ContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            context: Context::new(),
        }
    }

    /// Add a layer
    pub fn with_layer(self, layer: Arc<dyn DataLayer>) -> Self {
        self.context.add_layer(layer);
        self
    }

    /// Add a symbol table
    pub fn with_symbol_table(self, table: Arc<dyn SymbolTableInterface>) -> Self {
        self.context.add_symbol_table(table);
        self
    }

    /// Set a configuration value
    pub fn with_config<V: Into<ConfigValue>>(self, path: &str, value: V) -> Self {
        self.context.config_set(path, value);
        self
    }

    /// Build the context
    pub fn build(self) -> Context {
        self.context
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vol3_core::types::Architecture;
    use vol3_layers::physical::BufferLayer;
    use vol3_symbols::NativeTable;

    #[test]
    fn test_context_layers() {
        let ctx = Context::new();

        let layer = Arc::new(BufferLayer::new("test", vec![1, 2, 3, 4]));
        ctx.add_layer(layer);

        assert!(ctx.has_layer("test"));
        assert!(!ctx.has_layer("nonexistent"));

        let data = ctx.read("test", 0, 4).unwrap();
        assert_eq!(data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_context_config() {
        let ctx = Context::new();

        ctx.config_set("plugins.pslist.pid", 1234_i64);
        assert_eq!(ctx.config_get_int("plugins.pslist.pid"), Some(1234));

        ctx.config_set("plugins.enabled", true);
        assert_eq!(ctx.config_get_bool("plugins.enabled"), Some(true));
    }

    #[test]
    fn test_context_builder() {
        let layer = Arc::new(BufferLayer::new("test", vec![1, 2, 3, 4]));
        let table = Arc::new(NativeTable::x64("native"));

        let ctx = ContextBuilder::new()
            .with_layer(layer)
            .with_symbol_table(table)
            .with_config("test.value", "hello")
            .build();

        assert!(ctx.has_layer("test"));
        assert!(ctx.has_symbol_table("native"));
        assert_eq!(
            ctx.config_get_string("test.value"),
            Some("hello".to_string())
        );
    }
}
