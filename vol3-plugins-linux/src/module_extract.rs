//! Linux ModuleExtract plugin.
//!
//! Extracts kernel modules from memory.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

/// ModuleExtract plugin - extracts kernel modules
pub struct ModuleExtract;

impl ModuleExtract {
    pub fn new() -> Self {
        Self
    }

    fn extract_modules(context: &Context) -> Vol3Result<Vec<ModuleExtractEntry>> {
        use vol3_core::error::ConfigError;

        let _layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let _layer = context.get_layer(&_layer_name).ok_or_else(|| {
            Vol3Error::Layer(vol3_core::error::LayerError::NotFound(_layer_name.clone()))
        })?;

        // Full implementation requires:
        // 1. Iterating modules list
        // 2. Reading module memory ranges
        // 3. Dumping to files

        // Placeholder - returns empty for now (file output plugin)
        Ok(Vec::new())
    }
}

impl Default for ModuleExtract {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct ModuleExtractEntry {
    name: String,
    base: u64,
    size: u64,
    file_output: String,
}

impl Module for ModuleExtract {
    fn name(&self) -> &str {
        "linux.module_extract.ModuleExtract"
    }

    fn description(&self) -> &str {
        "Extracts kernel modules from memory"
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
            Column::new("Base", ColumnType::Hex),
            Column::new("Size", ColumnType::Int),
            Column::new("File output", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::extract_modules(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::String(e.name),
                    CellValue::Hex(e.base),
                    CellValue::Int(e.size as i64),
                    CellValue::String(e.file_output),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
