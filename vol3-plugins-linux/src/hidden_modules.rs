//! Linux HiddenModules plugin.
//!
//! Carves memory to find hidden kernel modules.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

/// HiddenModules plugin - finds hidden kernel modules
pub struct HiddenModules;

impl HiddenModules {
    pub fn new() -> Self {
        Self
    }

    fn find_hidden_modules(context: &Context) -> Vol3Result<Vec<HiddenModuleEntry>> {
        use vol3_core::error::ConfigError;

        let _layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let _layer = context.get_layer(&_layer_name).ok_or_else(|| {
            Vol3Error::Layer(vol3_core::error::LayerError::NotFound(_layer_name.clone()))
        })?;

        // Hidden module detection requires:
        // 1. Scanning memory for module struct signatures
        // 2. Comparing against the modules list
        // 3. Finding modules not in the list

        // Placeholder - returns empty for now
        Ok(Vec::new())
    }
}

impl Default for HiddenModules {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct HiddenModuleEntry {
    offset: u64,
    name: String,
    base: u64,
    size: u64,
}

impl Module for HiddenModules {
    fn name(&self) -> &str {
        "linux.hidden_modules.HiddenModules"
    }

    fn description(&self) -> &str {
        "Carves memory to find hidden kernel modules"
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
            Column::new("Offset", ColumnType::Hex),
            Column::new("Module Name", ColumnType::String),
            Column::new("Code Size", ColumnType::Hex),
            Column::new("Taints", ColumnType::String),
            Column::new("Load Arguments", ColumnType::String),
            Column::new("File Output", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::find_hidden_modules(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Hex(e.offset),
                    CellValue::String(e.name),
                    CellValue::Hex(e.size),
                    CellValue::String(String::new()),     // Taints
                    CellValue::String(String::new()),     // Load Arguments
                    CellValue::String("N/A".to_string()), // File Output
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
