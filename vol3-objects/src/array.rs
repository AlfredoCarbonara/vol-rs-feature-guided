//! Array object type.
//!
//! Handles fixed-size arrays and their element access.

use std::any::Any;
use std::sync::Arc;

use vol3_core::error::{ObjectError, ObjectResult};
use vol3_core::types::Address;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::traits::{MemoryObject, ObjectInterface};

/// An array object with fixed element count
pub struct ArrayObject {
    address: Address,
    layer: Arc<dyn DataLayer>,
    layer_name: String,
    type_name: String,
    element_type: Arc<TypeTemplate>,
    element_size: usize,
    count: usize,
    /// Symbol table name for creating element objects
    #[allow(dead_code)]
    symbol_table: String,
}

impl ArrayObject {
    /// Create a new array object
    pub fn new(
        address: Address,
        layer: Arc<dyn DataLayer>,
        layer_name: impl Into<String>,
        element_type: Arc<TypeTemplate>,
        count: usize,
        symbol_table: impl Into<String>,
    ) -> ObjectResult<Self> {
        let element_size = element_type.size().ok_or_else(|| {
            ObjectError::InvalidTemplate(format!(
                "Array element type '{}' has no defined size",
                element_type.type_name()
            ))
        })?;

        let type_name = format!("{}[{}]", element_type.type_name(), count);

        Ok(Self {
            address,
            layer,
            layer_name: layer_name.into(),
            type_name,
            element_type,
            element_size,
            count,
            symbol_table: symbol_table.into(),
        })
    }

    /// Get the number of elements
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get element size
    pub fn element_size(&self) -> usize {
        self.element_size
    }

    /// Get element type
    pub fn element_type(&self) -> &TypeTemplate {
        &self.element_type
    }

    /// Get the address of an element
    pub fn element_address(&self, index: usize) -> ObjectResult<Address> {
        if index >= self.count {
            return Err(ObjectError::IndexOutOfBounds {
                index,
                size: self.count,
            });
        }
        Ok(self.address + (index * self.element_size) as u64)
    }

    /// Read element bytes at the given index
    pub fn element_bytes(&self, index: usize) -> ObjectResult<Vec<u8>> {
        let addr = self.element_address(index)?;
        self.layer
            .read(addr, self.element_size, false)
            .map_err(ObjectError::LayerReadFailed)
    }

    /// Iterate over element addresses
    pub fn iter_addresses(&self) -> impl Iterator<Item = Address> + '_ {
        (0..self.count).map(move |i| self.address + (i * self.element_size) as u64)
    }

    /// Iterate over all elements as byte arrays
    pub fn iter_bytes(&self) -> impl Iterator<Item = ObjectResult<Vec<u8>>> + '_ {
        (0..self.count).map(move |i| self.element_bytes(i))
    }
}

impl MemoryObject for ArrayObject {
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
        self.element_size * self.count
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

impl ObjectInterface for ArrayObject {
    fn has_member(&self, _name: &str) -> bool {
        false
    }

    fn member(&self, name: &str) -> ObjectResult<Arc<dyn MemoryObject>> {
        // Try to parse name as an index
        if let Ok(index) = name.parse::<usize>() {
            if index >= self.count {
                return Err(ObjectError::IndexOutOfBounds {
                    index,
                    size: self.count,
                });
            }
            // Return bytes wrapper - need factory for proper object creation
            Err(ObjectError::InvalidTemplate(
                "Array element access requires ObjectFactory context".to_string(),
            ))
        } else {
            Err(ObjectError::InvalidTemplate(format!(
                "Invalid array index: '{}'. Use numeric indices.",
                name
            )))
        }
    }

    fn member_names(&self) -> Vec<String> {
        (0..self.count).map(|i| i.to_string()).collect()
    }

    fn cast(&self, _type_name: &str) -> ObjectResult<Arc<dyn MemoryObject>> {
        Err(ObjectError::InvalidTemplate(
            "Array casting requires ObjectFactory".to_string(),
        ))
    }

    fn dereference(&self) -> ObjectResult<Arc<dyn MemoryObject>> {
        Err(ObjectError::InvalidTemplate(
            "Arrays cannot be dereferenced".to_string(),
        ))
    }
}

/// A wrapper for reading strings from char arrays
pub struct StringArray {
    array: ArrayObject,
}

impl StringArray {
    /// Create a string array wrapper
    pub fn new(array: ArrayObject) -> Self {
        Self { array }
    }

    /// Read the array as a null-terminated string
    pub fn read_string(&self) -> ObjectResult<String> {
        let mut result = Vec::new();

        for i in 0..self.array.count() {
            let bytes = self.array.element_bytes(i)?;
            if bytes.is_empty() || bytes[0] == 0 {
                break;
            }
            result.push(bytes[0]);
        }

        String::from_utf8(result).map_err(|e| {
            ObjectError::InvalidTemplate(format!("Invalid UTF-8 in string array: {}", e))
        })
    }

    /// Read the array as a fixed-length string (no null termination check)
    pub fn read_fixed_string(&self) -> ObjectResult<String> {
        let mut result = Vec::with_capacity(self.array.count());

        for i in 0..self.array.count() {
            let bytes = self.array.element_bytes(i)?;
            if bytes.is_empty() {
                break;
            }
            result.push(bytes[0]);
        }

        String::from_utf8(result).map_err(|e| {
            ObjectError::InvalidTemplate(format!("Invalid UTF-8 in string array: {}", e))
        })
    }
}

impl std::ops::Deref for StringArray {
    type Target = ArrayObject;

    fn deref(&self) -> &Self::Target {
        &self.array
    }
}

/// A string object for reading null-terminated strings from memory
pub struct StringObject {
    address: Address,
    layer: Arc<dyn DataLayer>,
    layer_name: String,
    max_length: usize,
}

impl StringObject {
    /// Create a new string object
    pub fn new(
        address: Address,
        layer: Arc<dyn DataLayer>,
        layer_name: impl Into<String>,
        max_length: usize,
    ) -> Self {
        Self {
            address,
            layer,
            layer_name: layer_name.into(),
            max_length,
        }
    }

    /// Read the string from memory
    pub fn read_string(&self) -> ObjectResult<String> {
        let bytes = self
            .layer
            .read(self.address, self.max_length, false)
            .map_err(ObjectError::LayerReadFailed)?;

        // Find null terminator
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());

        String::from_utf8(bytes[..end].to_vec())
            .map_err(|e| ObjectError::InvalidTemplate(format!("Invalid UTF-8 in string: {}", e)))
    }

    /// Read the string as bytes (up to max_length or null terminator)
    pub fn read_bytes(&self) -> ObjectResult<Vec<u8>> {
        let bytes = self
            .layer
            .read(self.address, self.max_length, false)
            .map_err(ObjectError::LayerReadFailed)?;

        // Find null terminator
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());

        Ok(bytes[..end].to_vec())
    }

    /// Get the address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Get the layer name
    pub fn layer_name(&self) -> &str {
        &self.layer_name
    }

    /// Get max length
    pub fn max_length(&self) -> usize {
        self.max_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vol3_layers::physical::BufferLayer;

    #[test]
    fn test_array_basic() {
        // Create array with 4 u32 elements
        let data = vec![
            0x01, 0x00, 0x00, 0x00, // [0] = 1
            0x02, 0x00, 0x00, 0x00, // [1] = 2
            0x03, 0x00, 0x00, 0x00, // [2] = 3
            0x04, 0x00, 0x00, 0x00, // [3] = 4
        ];

        let layer = Arc::new(BufferLayer::new("test", data));
        let element_type = Arc::new(TypeTemplate::Primitive {
            name: "unsigned int".to_string(),
            size: 4,
            signed: false,
        });

        let arr = ArrayObject::new(0, layer, "test", element_type, 4, "symbols").unwrap();

        assert_eq!(arr.count(), 4);
        assert_eq!(arr.element_size(), 4);
        assert_eq!(arr.size(), 16);

        // Check element addresses
        assert_eq!(arr.element_address(0).unwrap(), 0);
        assert_eq!(arr.element_address(1).unwrap(), 4);
        assert_eq!(arr.element_address(2).unwrap(), 8);
        assert_eq!(arr.element_address(3).unwrap(), 12);
    }

    #[test]
    fn test_array_bounds() {
        let data = vec![0u8; 16];
        let layer = Arc::new(BufferLayer::new("test", data));
        let element_type = Arc::new(TypeTemplate::Primitive {
            name: "unsigned int".to_string(),
            size: 4,
            signed: false,
        });

        let arr = ArrayObject::new(0, layer, "test", element_type, 4, "symbols").unwrap();

        // Valid access
        assert!(arr.element_address(0).is_ok());
        assert!(arr.element_address(3).is_ok());

        // Out of bounds
        assert!(arr.element_address(4).is_err());
        assert!(arr.element_address(100).is_err());
    }

    #[test]
    fn test_string_array() {
        let data = b"Hello\0World".to_vec();
        let layer = Arc::new(BufferLayer::new("test", data));
        let element_type = Arc::new(TypeTemplate::Primitive {
            name: "char".to_string(),
            size: 1,
            signed: true,
        });

        let arr = ArrayObject::new(0, layer, "test", element_type, 11, "symbols").unwrap();
        let str_arr = StringArray::new(arr);

        assert_eq!(str_arr.read_string().unwrap(), "Hello");
    }
}
