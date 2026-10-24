//! Primitive object types.
//!
//! These are the basic object types for reading integers, floats, and bools.

use std::any::Any;
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder, LittleEndian};

use vol3_core::error::{ObjectError, ObjectResult};
use vol3_core::types::{Address, Endianness};
use vol3_layers::traits::DataLayer;

use crate::traits::MemoryObject;

/// A primitive object that reads raw bytes
#[allow(dead_code)]
pub struct PrimitiveObject {
    address: Address,
    layer: Arc<dyn DataLayer>,
    layer_name: String,
    type_name: String,
    size: usize,
}

impl PrimitiveObject {
    /// Create a new primitive object
    #[allow(dead_code)]
    pub fn new(
        address: Address,
        layer: Arc<dyn DataLayer>,
        layer_name: impl Into<String>,
        type_name: impl Into<String>,
        size: usize,
    ) -> Self {
        Self {
            address,
            layer,
            layer_name: layer_name.into(),
            type_name: type_name.into(),
            size,
        }
    }
}

impl MemoryObject for PrimitiveObject {
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
        self.size
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

/// An integer object that can be read as various integer types
pub struct IntegerObject {
    address: Address,
    layer: Arc<dyn DataLayer>,
    layer_name: String,
    type_name: String,
    size: usize,
    signed: bool,
    endianness: Endianness,
}

impl IntegerObject {
    /// Create a new integer object
    pub fn new(
        address: Address,
        layer: Arc<dyn DataLayer>,
        layer_name: impl Into<String>,
        type_name: impl Into<String>,
        size: usize,
        signed: bool,
        endianness: Endianness,
    ) -> Self {
        Self {
            address,
            layer,
            layer_name: layer_name.into(),
            type_name: type_name.into(),
            size,
            signed,
            endianness,
        }
    }

    /// Read as unsigned 8-bit integer
    pub fn as_u8(&self) -> ObjectResult<u8> {
        let bytes = self.read_bytes(0, 1)?;
        Ok(bytes[0])
    }

    /// Read as signed 8-bit integer
    pub fn as_i8(&self) -> ObjectResult<i8> {
        let bytes = self.read_bytes(0, 1)?;
        Ok(bytes[0] as i8)
    }

    /// Read as unsigned 16-bit integer
    pub fn as_u16(&self) -> ObjectResult<u16> {
        let bytes = self.read_bytes(0, 2)?;
        Ok(match self.endianness {
            Endianness::Little => LittleEndian::read_u16(&bytes),
            Endianness::Big => BigEndian::read_u16(&bytes),
        })
    }

    /// Read as signed 16-bit integer
    pub fn as_i16(&self) -> ObjectResult<i16> {
        let bytes = self.read_bytes(0, 2)?;
        Ok(match self.endianness {
            Endianness::Little => LittleEndian::read_i16(&bytes),
            Endianness::Big => BigEndian::read_i16(&bytes),
        })
    }

    /// Read as unsigned 32-bit integer
    pub fn as_u32(&self) -> ObjectResult<u32> {
        let bytes = self.read_bytes(0, 4)?;
        Ok(match self.endianness {
            Endianness::Little => LittleEndian::read_u32(&bytes),
            Endianness::Big => BigEndian::read_u32(&bytes),
        })
    }

    /// Read as signed 32-bit integer
    pub fn as_i32(&self) -> ObjectResult<i32> {
        let bytes = self.read_bytes(0, 4)?;
        Ok(match self.endianness {
            Endianness::Little => LittleEndian::read_i32(&bytes),
            Endianness::Big => BigEndian::read_i32(&bytes),
        })
    }

    /// Read as unsigned 64-bit integer
    pub fn as_u64(&self) -> ObjectResult<u64> {
        let bytes = self.read_bytes(0, 8)?;
        Ok(match self.endianness {
            Endianness::Little => LittleEndian::read_u64(&bytes),
            Endianness::Big => BigEndian::read_u64(&bytes),
        })
    }

    /// Read as signed 64-bit integer
    pub fn as_i64(&self) -> ObjectResult<i64> {
        let bytes = self.read_bytes(0, 8)?;
        Ok(match self.endianness {
            Endianness::Little => LittleEndian::read_i64(&bytes),
            Endianness::Big => BigEndian::read_i64(&bytes),
        })
    }

    /// Read as appropriate integer based on size and signedness
    pub fn value(&self) -> ObjectResult<i128> {
        let bytes = self.read_bytes(0, self.size)?;

        Ok(match (self.size, self.signed) {
            (1, false) => bytes[0] as i128,
            (1, true) => bytes[0] as i8 as i128,
            (2, false) => match self.endianness {
                Endianness::Little => LittleEndian::read_u16(&bytes) as i128,
                Endianness::Big => BigEndian::read_u16(&bytes) as i128,
            },
            (2, true) => match self.endianness {
                Endianness::Little => LittleEndian::read_i16(&bytes) as i128,
                Endianness::Big => BigEndian::read_i16(&bytes) as i128,
            },
            (4, false) => match self.endianness {
                Endianness::Little => LittleEndian::read_u32(&bytes) as i128,
                Endianness::Big => BigEndian::read_u32(&bytes) as i128,
            },
            (4, true) => match self.endianness {
                Endianness::Little => LittleEndian::read_i32(&bytes) as i128,
                Endianness::Big => BigEndian::read_i32(&bytes) as i128,
            },
            (8, false) => match self.endianness {
                Endianness::Little => LittleEndian::read_u64(&bytes) as i128,
                Endianness::Big => BigEndian::read_u64(&bytes) as i128,
            },
            (8, true) => match self.endianness {
                Endianness::Little => LittleEndian::read_i64(&bytes) as i128,
                Endianness::Big => BigEndian::read_i64(&bytes) as i128,
            },
            _ => {
                return Err(ObjectError::InvalidTemplate(format!(
                    "Unsupported integer size: {}",
                    self.size
                )))
            }
        })
    }

    /// Check if signed
    #[allow(dead_code)]
    pub fn is_signed(&self) -> bool {
        self.signed
    }
}

impl MemoryObject for IntegerObject {
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
        self.size
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

/// A floating-point object
pub struct FloatObject {
    address: Address,
    layer: Arc<dyn DataLayer>,
    layer_name: String,
    type_name: String,
    size: usize,
    endianness: Endianness,
}

impl FloatObject {
    /// Create a new float object
    pub fn new(
        address: Address,
        layer: Arc<dyn DataLayer>,
        layer_name: impl Into<String>,
        type_name: impl Into<String>,
        size: usize,
        endianness: Endianness,
    ) -> Self {
        Self {
            address,
            layer,
            layer_name: layer_name.into(),
            type_name: type_name.into(),
            size,
            endianness,
        }
    }

    /// Read as f32
    pub fn as_f32(&self) -> ObjectResult<f32> {
        let bytes = self.read_bytes(0, 4)?;
        Ok(match self.endianness {
            Endianness::Little => LittleEndian::read_f32(&bytes),
            Endianness::Big => BigEndian::read_f32(&bytes),
        })
    }

    /// Read as f64
    pub fn as_f64(&self) -> ObjectResult<f64> {
        let bytes = self.read_bytes(0, 8)?;
        Ok(match self.endianness {
            Endianness::Little => LittleEndian::read_f64(&bytes),
            Endianness::Big => BigEndian::read_f64(&bytes),
        })
    }

    /// Read as the appropriate float type based on size
    #[allow(dead_code)]
    pub fn value(&self) -> ObjectResult<f64> {
        match self.size {
            4 => self.as_f32().map(|v| v as f64),
            8 => self.as_f64(),
            _ => Err(ObjectError::InvalidTemplate(format!(
                "Unsupported float size: {}",
                self.size
            ))),
        }
    }
}

impl MemoryObject for FloatObject {
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
        self.size
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

/// A boolean object
pub struct BoolObject {
    address: Address,
    layer: Arc<dyn DataLayer>,
    layer_name: String,
}

impl BoolObject {
    /// Create a new bool object
    pub fn new(address: Address, layer: Arc<dyn DataLayer>, layer_name: impl Into<String>) -> Self {
        Self {
            address,
            layer,
            layer_name: layer_name.into(),
        }
    }

    /// Read the boolean value
    #[allow(dead_code)]
    pub fn value(&self) -> ObjectResult<bool> {
        let bytes = self.read_bytes(0, 1)?;
        Ok(bytes[0] != 0)
    }
}

impl MemoryObject for BoolObject {
    fn address(&self) -> Address {
        self.address
    }

    fn layer_name(&self) -> &str {
        &self.layer_name
    }

    fn type_name(&self) -> &str {
        "bool"
    }

    fn size(&self) -> usize {
        1
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

#[cfg(test)]
mod tests {
    use super::*;
    use vol3_layers::physical::BufferLayer;

    #[test]
    fn test_integer_object_u32() {
        let data = vec![0x78, 0x56, 0x34, 0x12]; // 0x12345678 in little endian
        let layer = Arc::new(BufferLayer::new("test", data));

        let int_obj = IntegerObject::new(
            0,
            layer,
            "test",
            "unsigned int",
            4,
            false,
            Endianness::Little,
        );

        assert_eq!(int_obj.as_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_bool_object() {
        let data = vec![1, 0];
        let layer = Arc::new(BufferLayer::new("test", data));

        let bool_true = BoolObject::new(0, layer.clone(), "test");
        let bool_false = BoolObject::new(1, layer, "test");

        assert!(bool_true.value().unwrap());
        assert!(!bool_false.value().unwrap());
    }
}
