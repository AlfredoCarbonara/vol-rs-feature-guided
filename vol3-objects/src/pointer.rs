//! Pointer object type.
//!
//! Handles dereferencing pointers and reading pointer values.

use std::any::Any;
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder, LittleEndian};

use vol3_core::error::{ObjectError, ObjectResult};
use vol3_core::types::{Address, Endianness};
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::traits::{MemoryObject, ObjectInterface};

/// A pointer object that can be dereferenced
pub struct PointerObject {
    address: Address,
    layer: Arc<dyn DataLayer>,
    layer_name: String,
    type_name: String,
    pointer_size: usize,
    endianness: Endianness,
    target_type: Arc<TypeTemplate>,
    /// Symbol table name for creating target objects
    #[allow(dead_code)]
    symbol_table: String,
}

impl PointerObject {
    /// Create a new pointer object
    pub fn new(
        address: Address,
        layer: Arc<dyn DataLayer>,
        layer_name: impl Into<String>,
        pointer_size: usize,
        endianness: Endianness,
        target_type: Arc<TypeTemplate>,
        symbol_table: impl Into<String>,
    ) -> Self {
        let type_name = format!("pointer to {}", target_type.type_name());
        Self {
            address,
            layer,
            layer_name: layer_name.into(),
            type_name,
            pointer_size,
            endianness,
            target_type,
            symbol_table: symbol_table.into(),
        }
    }

    /// Read the pointer value (the address it points to)
    pub fn pointer_value(&self) -> ObjectResult<Address> {
        let bytes = self.read_bytes(0, self.pointer_size)?;

        Ok(match (self.pointer_size, self.endianness) {
            (4, Endianness::Little) => LittleEndian::read_u32(&bytes) as u64,
            (4, Endianness::Big) => BigEndian::read_u32(&bytes) as u64,
            (8, Endianness::Little) => LittleEndian::read_u64(&bytes),
            (8, Endianness::Big) => BigEndian::read_u64(&bytes),
            _ => {
                return Err(ObjectError::InvalidTemplate(format!(
                    "Unsupported pointer size: {}",
                    self.pointer_size
                )))
            }
        })
    }

    /// Check if the pointer is null
    pub fn is_null(&self) -> ObjectResult<bool> {
        Ok(self.pointer_value()? == 0)
    }

    /// Check if the pointer value is valid (non-null and readable)
    #[allow(dead_code)]
    pub fn is_valid_pointer(&self) -> bool {
        if let Ok(addr) = self.pointer_value() {
            if addr == 0 {
                return false;
            }
            // Try to read the first byte of the target
            if let Some(size) = self.target_type.size() {
                if size > 0 {
                    return self.layer.read(addr, 1, false).is_ok();
                }
            }
            true
        } else {
            false
        }
    }

    /// Get the target type
    pub fn target_type(&self) -> &TypeTemplate {
        &self.target_type
    }

    /// Get pointer size
    #[allow(dead_code)]
    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }
}

impl MemoryObject for PointerObject {
    fn address(&self) -> Address {
        self.address
    }

    fn layer_name(&self) -> &str {
        &self.layer_name
    }

    fn type_name(&self) -> &str {
        &self.type_name
    }

    fn size(&self) -> usize {
        self.pointer_size
    }

    fn read_bytes(&self, offset: usize, size: usize) -> ObjectResult<Vec<u8>> {
        self.layer
            .read(self.address + offset as u64, size, false)
            .map_err(ObjectError::LayerReadFailed)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ObjectInterface for PointerObject {
    fn has_member(&self, _name: &str) -> bool {
        false
    }

    fn member(&self, name: &str) -> ObjectResult<Arc<dyn MemoryObject>> {
        Err(ObjectError::InvalidTemplate(format!(
            "Pointers do not have members. Try dereferencing first. Member: {}",
            name
        )))
    }

    fn member_names(&self) -> Vec<String> {
        Vec::new()
    }

    fn cast(&self, _type_name: &str) -> ObjectResult<Arc<dyn MemoryObject>> {
        Err(ObjectError::InvalidTemplate(
            "Pointer casting requires ObjectFactory".to_string(),
        ))
    }

    fn dereference(&self) -> ObjectResult<Arc<dyn MemoryObject>> {
        Err(ObjectError::InvalidTemplate(
            "Pointer dereferencing requires ObjectFactory context".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vol3_layers::physical::BufferLayer;

    #[test]
    fn test_pointer_value() {
        // Create buffer with a pointer value at address 0
        let mut data = vec![0u8; 16];
        // Store 0xDEADBEEF at address 0 (little endian, 4 bytes)
        data[0] = 0xEF;
        data[1] = 0xBE;
        data[2] = 0xAD;
        data[3] = 0xDE;

        let layer = Arc::new(BufferLayer::new("test", data));
        let target_type = Arc::new(TypeTemplate::Void);

        let ptr = PointerObject::new(
            0,
            layer,
            "test",
            4,
            Endianness::Little,
            target_type,
            "symbols",
        );

        assert_eq!(ptr.pointer_value().unwrap(), 0xDEADBEEF);
        assert!(!ptr.is_null().unwrap());
    }

    #[test]
    fn test_null_pointer() {
        let data = vec![0u8; 8];
        let layer = Arc::new(BufferLayer::new("test", data));
        let target_type = Arc::new(TypeTemplate::Void);

        let ptr = PointerObject::new(
            0,
            layer,
            "test",
            8,
            Endianness::Little,
            target_type,
            "symbols",
        );

        assert!(ptr.is_null().unwrap());
    }
}
