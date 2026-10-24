//! Linux PidHashTable plugin.
//!
//! Enumerates processes via the PID hash table.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

/// PidHashTable plugin - enumerates via PID hash table
pub struct PidHashTable;

impl PidHashTable {
    pub fn new() -> Self {
        Self
    }

    fn list_from_hashtable(context: &Context) -> Vol3Result<Vec<PidEntry>> {
        use vol3_core::error::ConfigError;

        let _layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let _layer = context.get_layer(&_layer_name).ok_or_else(|| {
            Vol3Error::Layer(vol3_core::error::LayerError::NotFound(_layer_name.clone()))
        })?;

        // Full implementation requires:
        // 1. Reading pid_hash symbol
        // 2. Iterating through hash buckets
        // 3. Walking upid chains

        // Placeholder - returns empty for now
        Ok(Vec::new())
    }
}

impl Default for PidHashTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct PidEntry {
    offset: u64,
    pid: i32,
    tgid: i32,
    ppid: i32,
    comm: String,
}

impl Module for PidHashTable {
    fn name(&self) -> &str {
        "linux.pidhashtable.PidHashTable"
    }

    fn description(&self) -> &str {
        "Enumerates processes via the PID hash table"
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
            Column::new("OFFSET", ColumnType::Hex),
            Column::new("PID", ColumnType::Int),
            Column::new("TID", ColumnType::Int),
            Column::new("PPID", ColumnType::Int),
            Column::new("COMM", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_from_hashtable(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Hex(e.offset),
                    CellValue::Int(e.pid as i64),
                    CellValue::Int(e.tgid as i64),
                    CellValue::Int(e.ppid as i64),
                    CellValue::String(e.comm),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
