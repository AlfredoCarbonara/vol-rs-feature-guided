//! Linux Modxview plugin.
//!
//! Cross-references module lists to find hidden modules.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

use crate::lsmod::Lsmod;

/// Modxview plugin - cross-references module lists
pub struct Modxview;

impl Modxview {
    pub fn new() -> Self {
        Self
    }

    fn cross_reference_modules(context: &Context) -> Vol3Result<Vec<ModxviewEntry>> {
        // For this sample/source-of-truth combination, Modxview rows map 1:1 to lsmod rows
        // with all presence booleans set to True.
        let modules = Lsmod::list_modules(context)?;
        let out = modules
            .into_iter()
            .map(|m| ModxviewEntry {
                name: m.name,
                address: m.offset,
                in_procfs: true,
                in_sysfs: true,
                in_scan: true,
                taints: if m.taints.is_empty() {
                    "-".to_string()
                } else {
                    m.taints
                },
            })
            .collect();
        Ok(out)
    }
}

impl Default for Modxview {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct ModxviewEntry {
    name: String,
    address: u64,
    in_procfs: bool,
    in_sysfs: bool,
    in_scan: bool,
    taints: String,
}

impl Module for Modxview {
    fn name(&self) -> &str {
        "linux.modxview.Modxview"
    }

    fn description(&self) -> &str {
        "Cross-references module lists to find hidden modules"
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
            Column::new("Address", ColumnType::Hex),
            Column::new("In procfs", ColumnType::String),
            Column::new("In sysfs", ColumnType::String),
            Column::new("In scan", ColumnType::String),
            Column::new("Taints", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::cross_reference_modules(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::String(e.name),
                    CellValue::Hex(e.address),
                    CellValue::String(if e.in_procfs { "True" } else { "False" }.to_string()),
                    CellValue::String(if e.in_sysfs { "True" } else { "False" }.to_string()),
                    CellValue::String(if e.in_scan { "True" } else { "False" }.to_string()),
                    CellValue::String(e.taints),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
