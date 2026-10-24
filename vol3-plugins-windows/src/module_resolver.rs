//! Loaded-kernel-module resolution shared by Windows plugins.
//!
//! Volatility's callbacks plugin first maps an absolute callback address to a
//! module from `PsLoadedModuleList`, then asks the kernel symbol table for an
//! exact symbol at the address relative to that module.  Keeping the same two
//! stages avoids labelling every non-kernel callback as unavailable.

use std::collections::HashSet;

use vol3_core::error::{PluginError, Vol3Error, Vol3Result};
use vol3_core::types::Address;
use vol3_framework::context::Context;
use vol3_layers::traits::DataLayer;
use vol3_symbols::{FieldInfo, SymbolTableInterface, TypeTemplate};

use crate::reader::{read_u64, read_unsigned};

const MAX_MODULES: usize = 4096;
const MAX_MODULE_NAME_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadedModule {
    pub base: Address,
    pub size: u64,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ModuleResolver {
    modules: Vec<LoadedModule>,
}

impl ModuleResolver {
    pub(crate) fn from_context(
        context: &Context,
        layer: &dyn DataLayer,
        symbol_table: &str,
        kernel_base: Address,
    ) -> Vol3Result<Self> {
        let entry_type = context
            .get_type(symbol_table, "_KLDR_DATA_TABLE_ENTRY")
            .or_else(|_| context.get_type(symbol_table, "_LDR_DATA_TABLE_ENTRY"))?;
        let unicode_type = context.get_type(symbol_table, "_UNICODE_STRING")?;
        let entry = structure(entry_type.as_ref(), "loader data table entry")?;
        let unicode = structure(unicode_type.as_ref(), "_UNICODE_STRING")?;
        let links = field(entry, "InLoadOrderLinks")?.offset;
        let dll_base = field(entry, "DllBase")?.offset;
        let size_field = field(entry, "SizeOfImage")?;
        let base_name = field(entry, "BaseDllName")?.offset;
        let unicode_length = field(unicode, "Length")?.offset;
        let unicode_maximum = field(unicode, "MaximumLength")?.offset;
        let unicode_buffer = field(unicode, "Buffer")?.offset;

        let symbol = context.get_symbol(symbol_table, "PsLoadedModuleList")?;
        let head = kernel_base.wrapping_add(symbol.address);
        let mut current = read_u64(layer, head)?;
        let mut seen = HashSet::new();
        let mut modules = Vec::new();
        for _ in 0..MAX_MODULES {
            if current == 0 || current == head || !seen.insert(current) {
                break;
            }
            let Some(record) = current.checked_sub(links as u64) else {
                break;
            };
            let next = read_u64(layer, current).ok();
            let base = read_u64(layer, record + dll_base as u64).unwrap_or(0);
            let size = read_unsigned(
                layer,
                record + size_field.offset as u64,
                field_size(size_field, 4),
            )
            .unwrap_or(0);
            let name = read_unicode_string(
                layer,
                record + base_name as u64,
                unicode_length,
                unicode_maximum,
                unicode_buffer,
            );
            if base != 0 && size != 0 {
                if let Some(name) = name.filter(|value| !value.is_empty()) {
                    modules.push(LoadedModule {
                        base,
                        size,
                        name: module_stem(&name),
                    });
                }
            }
            let Some(next) = next else {
                break;
            };
            current = next;
        }
        modules.sort_by_key(|module| module.base);
        Ok(Self { modules })
    }

    pub(crate) fn resolve(
        &self,
        symbols: &dyn SymbolTableInterface,
        address: Address,
    ) -> (Option<String>, Option<String>) {
        let Some(module) = self.modules.iter().find(|module| {
            address >= module.base && address < module.base.saturating_add(module.size)
        }) else {
            return (None, None);
        };
        let relative = address - module.base;
        let mut names = symbols.get_symbols_by_location(relative, 0);
        names.sort();
        (Some(module.name.clone()), names.into_iter().next())
    }
}

fn read_unicode_string(
    layer: &dyn DataLayer,
    address: Address,
    length_offset: usize,
    maximum_offset: usize,
    buffer_offset: usize,
) -> Option<String> {
    let length = read_unsigned(layer, address + length_offset as u64, 2).ok()? as usize;
    let maximum = read_unsigned(layer, address + maximum_offset as u64, 2).ok()? as usize;
    if length == 0
        || length > maximum
        || length > MAX_MODULE_NAME_BYTES
        || length % 2 != 0
    {
        return None;
    }
    let buffer = read_u64(layer, address + buffer_offset as u64).ok()?;
    let bytes = layer.read(buffer, length, false).ok()?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

fn module_stem(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(name)
        .to_string()
}

fn structure<'a>(
    template: &'a TypeTemplate,
    name: &str,
) -> Vol3Result<&'a vol3_symbols::StructTemplate> {
    match template {
        TypeTemplate::Struct(value) => Ok(value),
        _ => Err(plugin_error(format!("Windows {name} is not a structure"))),
    }
}

fn field<'a>(
    structure: &'a vol3_symbols::StructTemplate,
    name: &str,
) -> Vol3Result<&'a FieldInfo> {
    structure.get_field(name).ok_or_else(|| {
        plugin_error(format!(
            "Required module field {}.{} is absent",
            structure.name, name
        ))
    })
}

fn field_size(field: &FieldInfo, fallback: usize) -> usize {
    field
        .template
        .size()
        .filter(|size| matches!(size, 1 | 2 | 4 | 8))
        .unwrap_or(fallback)
}

fn plugin_error(message: String) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_only_the_final_module_extension() {
        assert_eq!(module_stem("ntoskrnl.exe"), "ntoskrnl");
        assert_eq!(module_stem("example.test.sys"), "example.test");
        assert_eq!(module_stem("driver"), "driver");
    }
}
