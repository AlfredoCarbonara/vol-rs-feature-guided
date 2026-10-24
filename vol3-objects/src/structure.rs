//! Struct object type.
//!
//! Handles struct-like objects with named members.

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use vol3_core::error::{ObjectError, ObjectResult};
use vol3_core::types::Address;
use vol3_layers::traits::DataLayer;
use vol3_symbols::{FieldInfo, StructTemplate, TypeTemplate};

use crate::traits::{MemoryObject, ObjectInterface};

/// A struct object with named members
pub struct StructObject {
    address: Address,
    layer: Arc<dyn DataLayer>,
    layer_name: String,
    type_name: String,
    size: usize,
    fields: Vec<FieldInfo>,
    /// Field name to index map for quick lookup
    field_index: HashMap<String, usize>,
    /// Symbol table name for creating member objects
    #[allow(dead_code)]
    symbol_table: String,
}

impl StructObject {
    /// Create a new struct object from a struct template
    pub fn new(
        address: Address,
        layer: Arc<dyn DataLayer>,
        layer_name: impl Into<String>,
        template: &StructTemplate,
        symbol_table: impl Into<String>,
    ) -> Self {
        let field_index: HashMap<String, usize> = template
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| (f.name.clone(), i))
            .collect();

        Self {
            address,
            layer,
            layer_name: layer_name.into(),
            type_name: template.name.clone(),
            size: template.size,
            fields: template.fields.clone(),
            field_index,
            symbol_table: symbol_table.into(),
        }
    }

    /// Create from a type template (must be a struct)
    pub fn from_template(
        address: Address,
        layer: Arc<dyn DataLayer>,
        layer_name: impl Into<String>,
        template: &TypeTemplate,
        symbol_table: impl Into<String>,
    ) -> ObjectResult<Self> {
        match template {
            TypeTemplate::Struct(s) => Ok(Self::new(address, layer, layer_name, s, symbol_table)),
            _ => Err(ObjectError::InvalidTemplate(format!(
                "Expected struct type, got {}",
                template.type_name()
            ))),
        }
    }

    /// Get field info by name
    pub fn get_field_info(&self, name: &str) -> Option<&FieldInfo> {
        self.field_index.get(name).map(|&i| &self.fields[i])
    }

    /// Get the address of a field
    pub fn field_address(&self, name: &str) -> ObjectResult<Address> {
        let field = self
            .get_field_info(name)
            .ok_or_else(|| ObjectError::MemberNotFound {
                type_name: self.type_name.clone(),
                member: name.to_string(),
            })?;
        Ok(self.address + field.offset as u64)
    }

    /// Read raw bytes for a field
    pub fn read_field_bytes(&self, name: &str) -> ObjectResult<Vec<u8>> {
        let field = self
            .get_field_info(name)
            .ok_or_else(|| ObjectError::MemberNotFound {
                type_name: self.type_name.clone(),
                member: name.to_string(),
            })?;

        let size = field
            .template
            .size()
            .ok_or_else(|| ObjectError::InvalidTemplate(format!("Field {} has no size", name)))?;

        let addr = self.address + field.offset as u64;
        self.layer
            .read(addr, size, false)
            .map_err(ObjectError::LayerReadFailed)
    }

    /// Get field type template
    pub fn field_type(&self, name: &str) -> ObjectResult<Arc<TypeTemplate>> {
        let field = self
            .get_field_info(name)
            .ok_or_else(|| ObjectError::MemberNotFound {
                type_name: self.type_name.clone(),
                member: name.to_string(),
            })?;
        Ok(field.template.clone())
    }

    /// Get all fields
    pub fn fields(&self) -> &[FieldInfo] {
        &self.fields
    }
}

impl MemoryObject for StructObject {
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

impl ObjectInterface for StructObject {
    fn has_member(&self, name: &str) -> bool {
        self.field_index.contains_key(name)
    }

    fn member(&self, name: &str) -> ObjectResult<Arc<dyn MemoryObject>> {
        // Member access requires ObjectFactory to create the member object
        Err(ObjectError::InvalidTemplate(format!(
            "Member access requires ObjectFactory context. Field: {}",
            name
        )))
    }

    fn member_names(&self) -> Vec<String> {
        self.fields.iter().map(|f| f.name.clone()).collect()
    }

    fn cast(&self, _type_name: &str) -> ObjectResult<Arc<dyn MemoryObject>> {
        Err(ObjectError::InvalidTemplate(
            "Struct casting requires ObjectFactory".to_string(),
        ))
    }
}

/// A union object (all fields at offset 0)
pub struct UnionObject {
    address: Address,
    layer: Arc<dyn DataLayer>,
    layer_name: String,
    type_name: String,
    size: usize,
    members: Vec<FieldInfo>,
    /// Member name to index map
    member_index: HashMap<String, usize>,
    /// Symbol table name
    #[allow(dead_code)]
    symbol_table: String,
}

impl UnionObject {
    /// Create from type template
    pub fn from_template(
        address: Address,
        layer: Arc<dyn DataLayer>,
        layer_name: impl Into<String>,
        template: &TypeTemplate,
        symbol_table: impl Into<String>,
    ) -> ObjectResult<Self> {
        match template {
            TypeTemplate::Union(u) => {
                let member_index: HashMap<String, usize> = u
                    .members
                    .iter()
                    .enumerate()
                    .map(|(i, f)| (f.name.clone(), i))
                    .collect();

                Ok(Self {
                    address,
                    layer,
                    layer_name: layer_name.into(),
                    type_name: u.name.clone(),
                    size: u.size,
                    members: u.members.clone(),
                    member_index,
                    symbol_table: symbol_table.into(),
                })
            }
            _ => Err(ObjectError::InvalidTemplate(format!(
                "Expected union type, got {}",
                template.type_name()
            ))),
        }
    }

    /// Get member info by name
    #[allow(dead_code)]
    pub fn get_member_info(&self, name: &str) -> Option<&FieldInfo> {
        self.member_index.get(name).map(|&i| &self.members[i])
    }
}

impl MemoryObject for UnionObject {
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

impl ObjectInterface for UnionObject {
    fn has_member(&self, name: &str) -> bool {
        self.member_index.contains_key(name)
    }

    fn member(&self, name: &str) -> ObjectResult<Arc<dyn MemoryObject>> {
        Err(ObjectError::InvalidTemplate(format!(
            "Member access requires ObjectFactory context. Member: {}",
            name
        )))
    }

    fn member_names(&self) -> Vec<String> {
        self.members.iter().map(|f| f.name.clone()).collect()
    }

    fn cast(&self, _type_name: &str) -> ObjectResult<Arc<dyn MemoryObject>> {
        Err(ObjectError::InvalidTemplate(
            "Union casting requires ObjectFactory".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vol3_layers::physical::BufferLayer;

    #[test]
    fn test_struct_field_address() {
        let data = vec![0u8; 64];
        let layer = Arc::new(BufferLayer::new("test", data));

        // Create a simple struct template
        let int_type = Arc::new(TypeTemplate::primitive("int", 4, true));
        let fields = vec![
            FieldInfo {
                name: "field_a".to_string(),
                offset: 0,
                template: int_type.clone(),
            },
            FieldInfo {
                name: "field_b".to_string(),
                offset: 8,
                template: int_type.clone(),
            },
        ];
        let template = StructTemplate {
            name: "test_struct".to_string(),
            size: 16,
            fields,
        };

        let obj = StructObject::new(0x1000, layer, "test", &template, "symbols");

        assert!(obj.has_member("field_a"));
        assert!(obj.has_member("field_b"));
        assert!(!obj.has_member("nonexistent"));

        assert_eq!(obj.field_address("field_a").unwrap(), 0x1000);
        assert_eq!(obj.field_address("field_b").unwrap(), 0x1008);
    }
}
