//! Native type tables.
//!
//! Native type tables provide built-in types (int, char, pointer, etc.)
//! that are architecture-specific.

use std::collections::HashMap;
use std::sync::Arc;

use crate::traits::{Enumeration, Symbol, SymbolTableInterface};
use crate::types::TypeTemplate;
use vol3_core::error::{SymbolError, SymbolResult};
use vol3_core::types::{Architecture, Endianness};

/// Native type table containing primitive types
pub struct NativeTable {
    /// Table name
    name: String,
    /// Architecture
    architecture: Architecture,
    /// Endianness
    endianness: Endianness,
    /// Types
    types: HashMap<String, Arc<TypeTemplate>>,
}

impl NativeTable {
    /// Create a new native table for the given architecture
    pub fn new(
        name: impl Into<String>,
        architecture: Architecture,
        endianness: Endianness,
    ) -> Self {
        let mut table = Self {
            name: name.into(),
            architecture,
            endianness,
            types: HashMap::new(),
        };
        table.populate_types();
        table
    }

    /// Create a native table for x64
    pub fn x64(name: impl Into<String>) -> Self {
        Self::new(name, Architecture::X64, Endianness::Little)
    }

    /// Create a native table for x86
    pub fn x86(name: impl Into<String>) -> Self {
        Self::new(name, Architecture::X86, Endianness::Little)
    }

    /// Get pointer size for this architecture
    pub fn pointer_size(&self) -> usize {
        match self.architecture {
            Architecture::X64 | Architecture::Arm64 => 8,
            Architecture::X86 | Architecture::Arm | Architecture::Unknown => 4,
        }
    }

    /// Populate built-in types
    fn populate_types(&mut self) {
        let ptr_size = self.pointer_size();

        // Character types
        self.add_primitive("char", 1, true);
        self.add_primitive("signed char", 1, true);
        self.add_primitive("unsigned char", 1, false);

        // Short types
        self.add_primitive("short", 2, true);
        self.add_primitive("short int", 2, true);
        self.add_primitive("signed short", 2, true);
        self.add_primitive("signed short int", 2, true);
        self.add_primitive("unsigned short", 2, false);
        self.add_primitive("unsigned short int", 2, false);

        // Integer types
        self.add_primitive("int", 4, true);
        self.add_primitive("signed int", 4, true);
        self.add_primitive("signed", 4, true);
        self.add_primitive("unsigned int", 4, false);
        self.add_primitive("unsigned", 4, false);

        // Long types (architecture dependent)
        let long_size = ptr_size;
        self.add_primitive("long", long_size, true);
        self.add_primitive("long int", long_size, true);
        self.add_primitive("signed long", long_size, true);
        self.add_primitive("signed long int", long_size, true);
        self.add_primitive("unsigned long", long_size, false);
        self.add_primitive("unsigned long int", long_size, false);

        // Long long types
        self.add_primitive("long long", 8, true);
        self.add_primitive("long long int", 8, true);
        self.add_primitive("signed long long", 8, true);
        self.add_primitive("signed long long int", 8, true);
        self.add_primitive("unsigned long long", 8, false);
        self.add_primitive("unsigned long long int", 8, false);

        // Bool type
        self.add_primitive("bool", 1, false);
        self.add_primitive("_Bool", 1, false);

        // Floating point types
        self.add_primitive("float", 4, true);
        self.add_primitive("double", 8, true);
        self.add_primitive("long double", 16, true);

        // Size types
        self.add_primitive("size_t", ptr_size, false);
        self.add_primitive("ssize_t", ptr_size, true);
        self.add_primitive("ptrdiff_t", ptr_size, true);

        // Void pointer type
        let void_template = Arc::new(TypeTemplate::Void);
        self.types.insert("void".to_string(), void_template.clone());

        // Pointer type
        let pointer_template = Arc::new(TypeTemplate::pointer("pointer", ptr_size, void_template));
        self.types.insert("pointer".to_string(), pointer_template);

        // Add stdint types
        self.add_primitive("int8_t", 1, true);
        self.add_primitive("int16_t", 2, true);
        self.add_primitive("int32_t", 4, true);
        self.add_primitive("int64_t", 8, true);
        self.add_primitive("uint8_t", 1, false);
        self.add_primitive("uint16_t", 2, false);
        self.add_primitive("uint32_t", 4, false);
        self.add_primitive("uint64_t", 8, false);

        // Kernel-specific types
        self.add_primitive("__s8", 1, true);
        self.add_primitive("__s16", 2, true);
        self.add_primitive("__s32", 4, true);
        self.add_primitive("__s64", 8, true);
        self.add_primitive("__u8", 1, false);
        self.add_primitive("__u16", 2, false);
        self.add_primitive("__u32", 4, false);
        self.add_primitive("__u64", 8, false);

        // Linux kernel specific
        self.add_primitive("u8", 1, false);
        self.add_primitive("u16", 2, false);
        self.add_primitive("u32", 4, false);
        self.add_primitive("u64", 8, false);
        self.add_primitive("s8", 1, true);
        self.add_primitive("s16", 2, true);
        self.add_primitive("s32", 4, true);
        self.add_primitive("s64", 8, true);
    }

    /// Add a primitive type
    fn add_primitive(&mut self, name: &str, size: usize, signed: bool) {
        let template = Arc::new(TypeTemplate::primitive(name, size, signed));
        self.types.insert(name.to_string(), template);
    }

    /// Get architecture
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// Get endianness
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }
}

impl SymbolTableInterface for NativeTable {
    fn name(&self) -> &str {
        &self.name
    }

    fn get_symbol(&self, name: &str) -> SymbolResult<Symbol> {
        Err(SymbolError::NotFound(format!(
            "Native tables do not contain symbols: {}",
            name
        )))
    }

    fn get_type(&self, name: &str) -> SymbolResult<Arc<TypeTemplate>> {
        self.types
            .get(name)
            .cloned()
            .ok_or_else(|| SymbolError::TypeNotFound(name.to_string()))
    }

    fn get_enumeration(&self, name: &str) -> SymbolResult<Enumeration> {
        Err(SymbolError::EnumerationNotFound(format!(
            "Native tables do not contain enumerations: {}",
            name
        )))
    }

    fn has_symbol(&self, _name: &str) -> bool {
        false
    }

    fn has_type(&self, name: &str) -> bool {
        self.types.contains_key(name)
    }

    fn symbols(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        Box::new(std::iter::empty())
    }

    fn types(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        Box::new(self.types.keys().map(|s| s.as_str()))
    }

    fn enumerations(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        Box::new(std::iter::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_table_x64() {
        let table = NativeTable::x64("native");
        assert_eq!(table.pointer_size(), 8);
        assert!(table.has_type("int"));
        assert!(table.has_type("long"));
        assert!(table.has_type("pointer"));

        let int_type = table.get_type("int").unwrap();
        assert_eq!(int_type.size(), Some(4));

        let long_type = table.get_type("long").unwrap();
        assert_eq!(long_type.size(), Some(8)); // 8 bytes on x64
    }

    #[test]
    fn test_native_table_x86() {
        let table = NativeTable::x86("native");
        assert_eq!(table.pointer_size(), 4);

        let long_type = table.get_type("long").unwrap();
        assert_eq!(long_type.size(), Some(4)); // 4 bytes on x86
    }
}
