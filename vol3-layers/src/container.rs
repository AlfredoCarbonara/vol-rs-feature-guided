//! Layer container for managing multiple layers.

use std::collections::HashMap;
use std::sync::Arc;

use vol3_core::{LayerError, LayerResult};

use crate::traits::{DataLayer, SharedLayer};

/// Container for managing multiple layers.
///
/// Provides storage and lookup for named layers, similar to Python's
/// `volatility3.framework.interfaces.context.LayerContainer`.
#[derive(Default)]
pub struct LayerContainer {
    layers: HashMap<String, SharedLayer>,
}

impl LayerContainer {
    /// Create a new empty layer container
    pub fn new() -> Self {
        Self {
            layers: HashMap::new(),
        }
    }

    /// Add a layer to the container
    pub fn add_layer(&mut self, layer: impl DataLayer + 'static) -> LayerResult<()> {
        let name = layer.name().to_string();
        if self.layers.contains_key(&name) {
            return Err(LayerError::AlreadyExists(name));
        }
        self.layers.insert(name, Arc::new(layer));
        Ok(())
    }

    /// Add a shared layer to the container
    pub fn add_shared_layer(&mut self, layer: SharedLayer) -> LayerResult<()> {
        let name = layer.name().to_string();
        if self.layers.contains_key(&name) {
            return Err(LayerError::AlreadyExists(name));
        }
        self.layers.insert(name, layer);
        Ok(())
    }

    /// Get a layer by name
    pub fn get(&self, name: &str) -> Option<&SharedLayer> {
        self.layers.get(name)
    }

    /// Check if a layer exists
    pub fn contains(&self, name: &str) -> bool {
        self.layers.contains_key(name)
    }

    /// Remove a layer by name
    pub fn remove(&mut self, name: &str) -> Option<SharedLayer> {
        self.layers.remove(name)
    }

    /// Get all layer names
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.layers.keys().map(|s| s.as_str())
    }

    /// Get the number of layers
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// Check if the container is empty
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Iterate over all layers
    pub fn iter(&self) -> impl Iterator<Item = (&str, &SharedLayer)> {
        self.layers.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Get a layer by name, returning an error if not found
    pub fn get_layer(&self, name: &str) -> LayerResult<&SharedLayer> {
        self.layers
            .get(name)
            .ok_or_else(|| LayerError::NotFound(name.to_string()))
    }
}

impl std::ops::Index<&str> for LayerContainer {
    type Output = SharedLayer;

    fn index(&self, name: &str) -> &Self::Output {
        self.layers.get(name).expect("Layer not found")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::physical::BufferLayer;

    #[test]
    fn test_container_add_get() {
        let mut container = LayerContainer::new();
        let layer = BufferLayer::new("test", vec![1, 2, 3]);
        container.add_layer(layer).unwrap();

        assert!(container.contains("test"));
        assert_eq!(container.len(), 1);

        let layer = container.get("test").unwrap();
        assert_eq!(layer.name(), "test");
    }

    #[test]
    fn test_container_duplicate() {
        let mut container = LayerContainer::new();
        container
            .add_layer(BufferLayer::new("test", vec![]))
            .unwrap();

        let result = container.add_layer(BufferLayer::new("test", vec![]));
        assert!(matches!(result, Err(LayerError::AlreadyExists(_))));
    }

    #[test]
    fn test_container_remove() {
        let mut container = LayerContainer::new();
        container
            .add_layer(BufferLayer::new("test", vec![]))
            .unwrap();

        assert!(container.contains("test"));
        container.remove("test");
        assert!(!container.contains("test"));
    }
}
