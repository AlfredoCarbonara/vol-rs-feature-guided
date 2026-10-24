//! Type template definitions.
//!
//! Type templates describe the structure of types before they are instantiated
//! as actual memory objects.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Information about a struct field
#[derive(Debug, Clone)]
pub struct FieldInfo {
    /// Field name
    pub name: String,
    /// Offset from struct start
    pub offset: usize,
    /// The type template for this field
    pub template: Arc<TypeTemplate>,
}

/// A type template describes how to construct a type.
#[derive(Debug, Clone)]
pub enum TypeTemplate {
    /// A primitive/base type
    Primitive(PrimitiveTemplate),
    /// A struct type
    Struct(StructTemplate),
    /// A union type
    Union(UnionTemplate),
    /// A pointer type
    Pointer(PointerTemplate),
    /// An array type
    Array(ArrayTemplate),
    /// A bitfield type
    BitField(BitFieldTemplate),
    /// An enumeration type
    Enum(EnumTemplate),
    /// A void type (used for void pointers)
    Void,
    /// A forward reference (lazy type resolution to prevent cycles)
    ForwardRef(String),
}

impl TypeTemplate {
    /// Get the size of this type (if known)
    pub fn size(&self) -> Option<usize> {
        match self {
            TypeTemplate::Primitive(p) => Some(p.size),
            TypeTemplate::Struct(s) => Some(s.size),
            TypeTemplate::Union(u) => Some(u.size),
            TypeTemplate::Pointer(p) => Some(p.size),
            TypeTemplate::Array(a) => Some(a.count * a.element.size()?),
            TypeTemplate::BitField(b) => Some(b.size),
            TypeTemplate::Enum(e) => Some(e.size),
            TypeTemplate::Void => Some(0),
            TypeTemplate::ForwardRef(_) => None, // Size unknown until resolved
        }
    }

    /// Get the type name
    pub fn type_name(&self) -> &str {
        match self {
            TypeTemplate::Primitive(p) => &p.name,
            TypeTemplate::Struct(s) => &s.name,
            TypeTemplate::Union(u) => &u.name,
            TypeTemplate::Pointer(p) => &p.name,
            TypeTemplate::Array(a) => &a.name,
            TypeTemplate::BitField(b) => &b.name,
            TypeTemplate::Enum(e) => &e.name,
            TypeTemplate::Void => "void",
            TypeTemplate::ForwardRef(name) => name,
        }
    }

    /// Create a primitive template
    pub fn primitive(name: impl Into<String>, size: usize, signed: bool) -> Self {
        TypeTemplate::Primitive(PrimitiveTemplate {
            name: name.into(),
            size,
            signed,
        })
    }

    /// Create a struct template
    pub fn struct_type(name: impl Into<String>, size: usize, fields: Vec<FieldInfo>) -> Self {
        TypeTemplate::Struct(StructTemplate {
            name: name.into(),
            size,
            fields,
        })
    }

    /// Create a pointer template
    pub fn pointer(name: impl Into<String>, size: usize, target: Arc<TypeTemplate>) -> Self {
        TypeTemplate::Pointer(PointerTemplate {
            name: name.into(),
            size,
            target,
        })
    }

    /// Create an array template
    pub fn array(name: impl Into<String>, count: usize, element: Arc<TypeTemplate>) -> Self {
        TypeTemplate::Array(ArrayTemplate {
            name: name.into(),
            count,
            element,
        })
    }
}

/// Template for primitive types (int, char, etc.)
#[derive(Debug, Clone)]
pub struct PrimitiveTemplate {
    /// Type name
    pub name: String,
    /// Size in bytes
    pub size: usize,
    /// Whether signed
    pub signed: bool,
}

/// Template for struct types
#[derive(Debug, Clone)]
pub struct StructTemplate {
    /// Type name
    pub name: String,
    /// Total size in bytes
    pub size: usize,
    /// Fields
    pub fields: Vec<FieldInfo>,
}

impl StructTemplate {
    /// Get a field by name
    pub fn get_field(&self, name: &str) -> Option<&FieldInfo> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Check if a field exists
    pub fn has_field(&self, name: &str) -> bool {
        self.fields.iter().any(|f| f.name == name)
    }

    /// Get all field names
    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|f| f.name.as_str())
    }
}

/// Template for union types
#[derive(Debug, Clone)]
pub struct UnionTemplate {
    /// Type name
    pub name: String,
    /// Total size in bytes
    pub size: usize,
    /// Members (all at offset 0)
    pub members: Vec<FieldInfo>,
}

/// Template for pointer types
#[derive(Debug, Clone)]
pub struct PointerTemplate {
    /// Type name (e.g., "pointer")
    pub name: String,
    /// Pointer size in bytes
    pub size: usize,
    /// Target type
    pub target: Arc<TypeTemplate>,
}

/// Template for array types
#[derive(Debug, Clone)]
pub struct ArrayTemplate {
    /// Type name
    pub name: String,
    /// Number of elements
    pub count: usize,
    /// Element type
    pub element: Arc<TypeTemplate>,
}

/// Template for bitfield types
#[derive(Debug, Clone)]
pub struct BitFieldTemplate {
    /// Type name
    pub name: String,
    /// Size in bytes
    pub size: usize,
    /// Bit offset
    pub bit_offset: i64,
    /// Bit length
    pub bit_length: usize,
    /// Base type
    pub base: Arc<TypeTemplate>,
}

/// Template for enumeration types
#[derive(Debug, Clone)]
pub struct EnumTemplate {
    /// Type name
    pub name: String,
    /// Size in bytes
    pub size: usize,
    /// Base type
    pub base: Arc<TypeTemplate>,
    /// Choices
    pub choices: HashMap<String, i64>,
}

/// ISF type reference (for parsing)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ISFTypeRef {
    /// Simple type reference by name
    Named { kind: String, name: String },
    /// Pointer type
    Pointer {
        kind: String,
        subtype: Box<ISFTypeRef>,
    },
    /// Array type
    Array {
        kind: String,
        count: usize,
        subtype: Box<ISFTypeRef>,
    },
    /// Bitfield type
    BitField {
        kind: String,
        bit_position: i64,
        bit_length: usize,
        #[serde(rename = "type")]
        base_type: Box<ISFTypeRef>,
    },
    /// Inline struct/union
    InlineStruct {
        kind: String,
        #[serde(default)]
        size: usize,
        #[serde(default)]
        fields: HashMap<String, ISFField>,
    },
    /// Simple name reference (for base types)
    SimpleName(String),
}

/// ISF field definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ISFField {
    /// Field offset
    pub offset: usize,
    /// Field type
    #[serde(rename = "type")]
    pub field_type: ISFTypeRef,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_template() {
        let template = TypeTemplate::primitive("int", 4, true);
        assert_eq!(template.size(), Some(4));
        assert_eq!(template.type_name(), "int");
    }

    #[test]
    fn test_struct_template() {
        let int_type = Arc::new(TypeTemplate::primitive("int", 4, true));
        let char_type = Arc::new(TypeTemplate::primitive("char", 1, true));

        let fields = vec![
            FieldInfo {
                name: "id".to_string(),
                offset: 0,
                template: int_type.clone(),
            },
            FieldInfo {
                name: "flag".to_string(),
                offset: 4,
                template: char_type,
            },
        ];

        let struct_template = TypeTemplate::struct_type("my_struct", 8, fields);
        assert_eq!(struct_template.size(), Some(8));

        if let TypeTemplate::Struct(s) = struct_template {
            assert!(s.has_field("id"));
            assert!(s.has_field("flag"));
            assert!(!s.has_field("nonexistent"));
        }
    }
}
