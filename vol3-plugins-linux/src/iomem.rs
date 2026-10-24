//! Linux IOMem plugin.
//!
//! Generates output similar to /proc/iomem.

use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;

use crate::helpers;

/// Iomem plugin - shows I/O memory regions
pub struct Iomem;

impl Iomem {
    pub fn new() -> Self {
        Self
    }

    fn get_iomem_resource(context: &Context, symbol_table: &str) -> Vol3Result<Address> {
        let symbol = context.get_symbol(symbol_table, "iomem_resource")?;
        let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;
        Ok(symbol.address.wrapping_add(aslr_shift))
    }

    fn parse_resources(
        layer: &dyn DataLayer,
        resource_addr: Address,
        seen: &mut std::collections::HashSet<Address>,
        depth: usize,
        entries: &mut Vec<IomemEntry>,
    ) -> Vol3Result<()> {
        if resource_addr == 0 || seen.contains(&resource_addr) {
            return Ok(());
        }
        seen.insert(resource_addr);

        // Read resource struct fields (from ISF):
        // start: 0, end: 8, name: 16, flags: 24, desc: 32, parent: 40, sibling: 48, child: 56
        let start = helpers::read_u64(layer, resource_addr)?;
        let end = helpers::read_u64(layer, resource_addr + 8)?;
        let name_ptr = helpers::read_pointer(layer, resource_addr + 16)?;

        let name = if helpers::is_valid_kernel_address(name_ptr) {
            helpers::read_string(layer, name_ptr, 128)?
        } else {
            "<unknown>".to_string()
        };

        // sibling at +48, child at +56
        let sibling_ptr = helpers::read_pointer(layer, resource_addr + 48)?;
        let child_ptr = helpers::read_pointer(layer, resource_addr + 56)?;

        entries.push(IomemEntry {
            depth,
            name,
            start,
            end,
        });

        // Recurse into child first (depth-first)
        if helpers::is_valid_kernel_address(child_ptr) {
            Self::parse_resources(layer, child_ptr, seen, depth + 1, entries)?;
        }

        // Then recurse into sibling (same depth)
        if helpers::is_valid_kernel_address(sibling_ptr) {
            Self::parse_resources(layer, sibling_ptr, seen, depth, entries)?;
        }

        Ok(())
    }

    fn list_iomem(context: &Context) -> Vol3Result<Vec<IomemEntry>> {
        use vol3_core::error::ConfigError;

        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let layer = context.get_layer(&layer_name).ok_or_else(|| {
            Vol3Error::Layer(vol3_core::error::LayerError::NotFound(layer_name.clone()))
        })?;

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        let iomem_addr = Self::get_iomem_resource(context, &symbol_table)?;

        let mut entries = Vec::new();
        let mut seen = std::collections::HashSet::new();

        Self::parse_resources(layer.as_ref(), iomem_addr, &mut seen, 0, &mut entries)?;

        Ok(entries)
    }
}

impl Default for Iomem {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct IomemEntry {
    depth: usize,
    name: String,
    start: u64,
    end: u64,
}

impl Module for Iomem {
    fn name(&self) -> &str {
        "linux.iomem.Iomem"
    }

    fn description(&self) -> &str {
        "Generates output similar to /proc/iomem"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Memory layer for the kernel")
            .symbol_table("vmlinux", "Linux kernel symbol table")
            .build();

        ModuleRequirements {
            name: self.name().to_string(),
            description: self.description().to_string(),
            requirements,
        }
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Name", ColumnType::String),
            Column::new("Start", ColumnType::Hex),
            Column::new("End", ColumnType::Hex),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_iomem(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                // TreeDepth must be first value - renderer extracts it
                Ok(vec![
                    CellValue::TreeDepth(e.depth as i64),
                    CellValue::String(e.name),
                    CellValue::Hex(e.start),
                    CellValue::Hex(e.end),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
