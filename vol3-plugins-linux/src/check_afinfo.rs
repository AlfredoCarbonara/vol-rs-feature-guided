//! Linux CheckAfinfo plugin.
//!
//! Verifies the operation function pointers of network protocols.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

/// CheckAfinfo plugin - checks network protocol function pointers
pub struct CheckAfinfo;

impl CheckAfinfo {
    pub fn new() -> Self {
        Self
    }

    fn check_afinfo(context: &Context) -> Vol3Result<Vec<AfinfoEntry>> {
        use vol3_core::error::ConfigError;

        let _layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let _layer = context.get_layer(&_layer_name).ok_or_else(|| {
            Vol3Error::Layer(vol3_core::error::LayerError::NotFound(_layer_name.clone()))
        })?;

        // Full implementation requires checking:
        // - tcp4_seq_afinfo
        // - tcp6_seq_afinfo
        // - udp4_seq_afinfo
        // - udp6_seq_afinfo
        // etc.

        // Placeholder - returns empty for now
        Ok(Vec::new())
    }
}

impl Default for CheckAfinfo {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct AfinfoEntry {
    symbol_name: String,
    member: String,
    handler_address: u64,
}

impl Module for CheckAfinfo {
    fn name(&self) -> &str {
        "linux.check_afinfo.CheckAfinfo"
    }

    fn description(&self) -> &str {
        "Verifies the operation function pointers of network protocols"
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
            Column::new("Symbol Name", ColumnType::String),
            Column::new("Member", ColumnType::String),
            Column::new("Handler Address", ColumnType::Hex),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::check_afinfo(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::String(e.symbol_name),
                    CellValue::String(e.member),
                    CellValue::Hex(e.handler_address),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
