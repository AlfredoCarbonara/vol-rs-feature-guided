//! Linux KeyboardNotifiers plugin.
//!
//! Parses keyboard notifier call chain.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

/// KeyboardNotifiers plugin - lists keyboard notifier hooks
pub struct KeyboardNotifiers;

impl KeyboardNotifiers {
    pub fn new() -> Self {
        Self
    }

    fn list_notifiers(context: &Context) -> Vol3Result<Vec<NotifierEntry>> {
        use vol3_core::error::ConfigError;

        let _layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let _layer = context.get_layer(&_layer_name).ok_or_else(|| {
            Vol3Error::Layer(vol3_core::error::LayerError::NotFound(_layer_name.clone()))
        })?;

        // Full implementation requires:
        // 1. Reading keyboard_notifier_list
        // 2. Walking the notifier chain
        // 3. Resolving callback addresses

        // Placeholder - returns empty for now
        Ok(Vec::new())
    }
}

impl Default for KeyboardNotifiers {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct NotifierEntry {
    address: u64,
    module: String,
    symbol: String,
}

impl Module for KeyboardNotifiers {
    fn name(&self) -> &str {
        "linux.keyboard_notifiers.KeyboardNotifiers"
    }

    fn description(&self) -> &str {
        "Parses keyboard notifier call chain"
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
            Column::new("Address", ColumnType::Hex),
            Column::new("Module", ColumnType::String),
            Column::new("Symbol", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_notifiers(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Hex(e.address),
                    CellValue::String(e.module),
                    CellValue::String(e.symbol),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
