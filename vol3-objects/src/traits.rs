//! Memory object traits.
//!
//! These traits define the core interface for memory objects.

use std::any::Any;
use std::sync::Arc;

use vol3_core::error::{ObjectError, ObjectResult};
use vol3_core::types::Address;
use vol3_layers::traits::DataLayer;

/// Base interface for all memory objects.
pub trait MemoryObject: Send + Sync {
    /// Get the address of this object in memory
    fn address(&self) -> Address;

    /// Get the layer this object is read from
    fn layer_name(&self) -> &str;

    /// Get the type name
    fn type_name(&self) -> &str;

    /// Get the size of this object in bytes
    fn size(&self) -> usize;

    /// Read raw bytes from this object's location
    fn read_bytes(&self, offset: usize, size: usize) -> ObjectResult<Vec<u8>>;

    /// Check if the object is valid (readable)
    fn is_valid(&self) -> bool {
        self.read_bytes(0, self.size()).is_ok()
    }

    /// Get this object as Any for downcasting
    fn as_any(&self) -> &dyn Any;
}

/// Extended interface for struct-like objects
pub trait ObjectInterface: MemoryObject {
    /// Check if this object has a member with the given name
    fn has_member(&self, name: &str) -> bool;

    /// Get a member by name, returning a new object
    fn member(&self, name: &str) -> ObjectResult<Arc<dyn MemoryObject>>;

    /// Get all member names
    fn member_names(&self) -> Vec<String>;

    /// Cast this object to a different type
    fn cast(&self, type_name: &str) -> ObjectResult<Arc<dyn MemoryObject>>;

    /// Dereference this object (for pointers)
    fn dereference(&self) -> ObjectResult<Arc<dyn MemoryObject>> {
        Err(ObjectError::InvalidTemplate(
            "Object is not a pointer".to_string(),
        ))
    }

    /// Get array element (for arrays)
    fn get_element(&self, _index: usize) -> ObjectResult<Arc<dyn MemoryObject>> {
        Err(ObjectError::InvalidTemplate(
            "Object is not an array".to_string(),
        ))
    }

    /// Get length (for arrays and strings)
    fn len(&self) -> ObjectResult<usize> {
        Err(ObjectError::InvalidTemplate(
            "Object does not have a length".to_string(),
        ))
    }
}

/// Context for creating and reading objects
pub struct ObjectContext {
    /// The layer to read from
    pub layer: Arc<dyn DataLayer>,
    /// Symbol table name
    pub symbol_table: String,
}

impl ObjectContext {
    /// Create a new object context
    pub fn new(layer: Arc<dyn DataLayer>, symbol_table: impl Into<String>) -> Self {
        Self {
            layer,
            symbol_table: symbol_table.into(),
        }
    }

    /// Read bytes from the layer
    pub fn read(&self, address: Address, size: usize) -> ObjectResult<Vec<u8>> {
        self.layer
            .read(address, size, false)
            .map_err(ObjectError::LayerReadFailed)
    }
}

#[cfg(test)]
mod tests {
    // Tests would go here
}
