//! Object factory for creating typed memory objects.
//!
//! The factory provides the integration between symbol tables,
//! layers, and object creation.

use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder, LittleEndian};

use vol3_core::error::{ObjectError, ObjectResult};
use vol3_core::types::{Address, Endianness};
use vol3_layers::traits::DataLayer;
use vol3_symbols::{SymbolSpace, TypeTemplate};

use crate::array::{ArrayObject, StringObject};
use crate::pointer::PointerObject;
use crate::primitive::{BoolObject, FloatObject, IntegerObject};
use crate::structure::{StructObject, UnionObject};
use crate::traits::MemoryObject;

/// Factory for creating memory objects with type information.
pub struct ObjectFactory {
    /// Symbol space for type lookups
    symbols: Arc<SymbolSpace>,
    /// Default layer
    default_layer: Arc<dyn DataLayer>,
    /// Default layer name
    default_layer_name: String,
    /// Endianness
    endianness: Endianness,
    /// Pointer size
    pointer_size: usize,
}

impl ObjectFactory {
    /// Create a new object factory
    pub fn new(
        symbols: Arc<SymbolSpace>,
        default_layer: Arc<dyn DataLayer>,
        default_layer_name: impl Into<String>,
        pointer_size: usize,
        endianness: Endianness,
    ) -> Self {
        Self {
            symbols,
            default_layer,
            default_layer_name: default_layer_name.into(),
            endianness,
            pointer_size,
        }
    }

    /// Get the symbol space
    pub fn symbols(&self) -> &SymbolSpace {
        &self.symbols
    }

    /// Get pointer size
    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    /// Get endianness
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Create an object from a type name
    pub fn create_object(
        &self,
        symbol_table: &str,
        type_name: &str,
        address: Address,
    ) -> ObjectResult<Arc<dyn MemoryObject>> {
        let template = self
            .symbols
            .get_type(symbol_table, type_name)
            .map_err(|e| ObjectError::InvalidTemplate(e.to_string()))?;
        self.create_from_template(address, &template, symbol_table)
    }

    /// Create an object from a type template
    pub fn create_from_template(
        &self,
        address: Address,
        template: &Arc<TypeTemplate>,
        symbol_table: &str,
    ) -> ObjectResult<Arc<dyn MemoryObject>> {
        match template.as_ref() {
            TypeTemplate::Primitive(p) => self.create_primitive(address, p.size, p.signed, &p.name),
            TypeTemplate::Struct(s) => Ok(Arc::new(StructObject::new(
                address,
                self.default_layer.clone(),
                &self.default_layer_name,
                s,
                symbol_table,
            ))),
            TypeTemplate::Union(_) => Ok(Arc::new(UnionObject::from_template(
                address,
                self.default_layer.clone(),
                &self.default_layer_name,
                template,
                symbol_table,
            )?)),
            TypeTemplate::Pointer(p) => Ok(Arc::new(PointerObject::new(
                address,
                self.default_layer.clone(),
                &self.default_layer_name,
                p.size,
                self.endianness,
                p.target.clone(),
                symbol_table,
            ))),
            TypeTemplate::Array(a) => Ok(Arc::new(ArrayObject::new(
                address,
                self.default_layer.clone(),
                &self.default_layer_name,
                a.element.clone(),
                a.count,
                symbol_table,
            )?)),
            TypeTemplate::BitField(_) => {
                // For bitfields, we read the underlying value
                self.create_primitive(address, template.size().unwrap_or(4), false, "bitfield")
            }
            TypeTemplate::Enum(e) => {
                // Enums are read as integers
                Ok(Arc::new(IntegerObject::new(
                    address,
                    self.default_layer.clone(),
                    &self.default_layer_name,
                    &e.name,
                    e.size,
                    false,
                    self.endianness,
                )))
            }
            TypeTemplate::Void => Err(ObjectError::InvalidTemplate(
                "Cannot create object of void type".to_string(),
            )),
            TypeTemplate::ForwardRef(type_name) => {
                // Forward references should be resolved by looking up the type again
                // This should rarely happen in normal operation
                Err(ObjectError::InvalidTemplate(format!(
                    "Unresolved forward reference: {}",
                    type_name
                )))
            }
        }
    }

    /// Create a primitive object
    fn create_primitive(
        &self,
        address: Address,
        size: usize,
        signed: bool,
        type_name: &str,
    ) -> ObjectResult<Arc<dyn MemoryObject>> {
        // Check if it's a float type
        if type_name.contains("float") || type_name.contains("double") {
            return Ok(Arc::new(FloatObject::new(
                address,
                self.default_layer.clone(),
                &self.default_layer_name,
                type_name,
                size,
                self.endianness,
            )));
        }

        // Check if it's a bool
        if type_name.contains("bool") || type_name == "_Bool" {
            return Ok(Arc::new(BoolObject::new(
                address,
                self.default_layer.clone(),
                &self.default_layer_name,
            )));
        }

        // Otherwise it's an integer
        Ok(Arc::new(IntegerObject::new(
            address,
            self.default_layer.clone(),
            &self.default_layer_name,
            type_name,
            size,
            signed,
            self.endianness,
        )))
    }

    /// Create a string object
    pub fn create_string(&self, address: Address, max_length: usize) -> Arc<StringObject> {
        Arc::new(StringObject::new(
            address,
            self.default_layer.clone(),
            &self.default_layer_name,
            max_length,
        ))
    }

    /// Read a pointer value at the given address
    pub fn read_pointer(&self, address: Address) -> ObjectResult<Address> {
        let bytes = self
            .default_layer
            .read(address, self.pointer_size, false)
            .map_err(ObjectError::LayerReadFailed)?;

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

    /// Read an integer value at the given address
    #[allow(dead_code)]
    pub fn read_integer(&self, address: Address, size: usize, signed: bool) -> ObjectResult<i128> {
        let int_obj = IntegerObject::new(
            address,
            self.default_layer.clone(),
            &self.default_layer_name,
            "int",
            size,
            signed,
            self.endianness,
        );
        int_obj.value()
    }

    /// Access a member of an object
    pub fn member(
        &self,
        obj: &dyn MemoryObject,
        member_name: &str,
        symbol_table: &str,
    ) -> ObjectResult<Arc<dyn MemoryObject>> {
        // Try to downcast to StructObject
        if let Some(struct_obj) = obj.as_any().downcast_ref::<StructObject>() {
            let field_type = struct_obj.field_type(member_name)?;
            let field_addr = struct_obj.field_address(member_name)?;
            return self.create_from_template(field_addr, &field_type, symbol_table);
        }

        // Try UnionObject
        if let Some(union_obj) = obj.as_any().downcast_ref::<UnionObject>() {
            if let Some(member_info) = union_obj.get_member_info(member_name) {
                let member_addr = obj.address(); // Unions have all members at offset 0
                return self.create_from_template(member_addr, &member_info.template, symbol_table);
            }
        }

        Err(ObjectError::MemberNotFound {
            type_name: obj.type_name().to_string(),
            member: member_name.to_string(),
        })
    }

    /// Dereference a pointer object
    pub fn dereference(
        &self,
        obj: &dyn MemoryObject,
        symbol_table: &str,
    ) -> ObjectResult<Arc<dyn MemoryObject>> {
        if let Some(ptr_obj) = obj.as_any().downcast_ref::<PointerObject>() {
            let target_addr = ptr_obj.pointer_value()?;
            if target_addr == 0 {
                return Err(ObjectError::NullPointer);
            }
            let target_type = Arc::new(ptr_obj.target_type().clone());
            return self.create_from_template(target_addr, &target_type, symbol_table);
        }

        Err(ObjectError::InvalidTemplate(
            "Object is not a pointer".to_string(),
        ))
    }

    /// Get an array element
    pub fn get_element(
        &self,
        obj: &dyn MemoryObject,
        index: usize,
        symbol_table: &str,
    ) -> ObjectResult<Arc<dyn MemoryObject>> {
        if let Some(array_obj) = obj.as_any().downcast_ref::<ArrayObject>() {
            let element_addr = array_obj.element_address(index)?;
            let element_type = Arc::new(array_obj.element_type().clone());
            return self.create_from_template(element_addr, &element_type, symbol_table);
        }

        Err(ObjectError::InvalidTemplate(
            "Object is not an array".to_string(),
        ))
    }

    /// Cast an object to a different type
    pub fn cast(
        &self,
        obj: &dyn MemoryObject,
        type_name: &str,
        symbol_table: &str,
    ) -> ObjectResult<Arc<dyn MemoryObject>> {
        self.create_object(symbol_table, type_name, obj.address())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vol3_core::types::Architecture;
    use vol3_layers::physical::BufferLayer;
    use vol3_symbols::SymbolSpaceBuilder;

    #[test]
    fn test_factory_create_integer() {
        let space = Arc::new(
            SymbolSpaceBuilder::new()
                .with_native(Architecture::X64)
                .build(),
        );

        // Create buffer with 0x12345678
        let data = vec![0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        let layer = Arc::new(BufferLayer::new("test", data));

        let factory = ObjectFactory::new(space, layer, "test", 8, Endianness::Little);

        let obj = factory.create_object("native", "int", 0).unwrap();

        // Downcast to IntegerObject and read value
        let int_obj = obj.as_any().downcast_ref::<IntegerObject>().unwrap();
        assert_eq!(int_obj.as_u32().unwrap(), 0x12345678);
    }
}
