//! Linux Maps plugin.
//!
//! Lists process memory mappings similar to /proc/[pid]/maps.

use std::sync::Arc;

use vol3_core::error::Vol3Result;
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

use crate::proc::Proc;

/// Maps plugin - lists process memory mappings
pub struct Maps;

impl Maps {
    pub fn new() -> Self {
        Self
    }

    fn list_maps(context: &Context) -> Vol3Result<Vec<crate::proc::ProcMapEntry>> {
        // Keep Maps behavior aligned with python's linux.proc.Maps by reusing Proc VMA logic.
        Proc::list_proc_maps(context)
    }
}

impl Default for Maps {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Maps {
    fn name(&self) -> &str {
        "linux.proc.Maps"
    }

    fn description(&self) -> &str {
        "Lists process memory mappings"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Memory layer for the kernel")
            .symbol_table("vmlinux", "Linux kernel symbol table")
            .int_optional("pid", "Process ID filter")
            .build();

        ModuleRequirements {
            name: self.name().to_string(),
            description: self.description().to_string(),
            requirements,
        }
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("PID", ColumnType::Int),
            Column::new("Process", ColumnType::String),
            Column::new("Start", ColumnType::Hex),
            Column::new("End", ColumnType::Hex),
            Column::new("Flags", ColumnType::String),
            Column::new("PgOff", ColumnType::Hex),
            Column::new("Major", ColumnType::Int),
            Column::new("Minor", ColumnType::Int),
            Column::new("Inode", ColumnType::Int),
            Column::new("File Path", ColumnType::String),
            Column::new("File output", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_maps(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.pid as i64),
                    CellValue::String(e.comm),
                    CellValue::Hex(e.start),
                    CellValue::Hex(e.end),
                    CellValue::String(e.flags),
                    CellValue::Hex(e.pgoff),
                    CellValue::Int(e.major as i64),
                    CellValue::Int(e.minor as i64),
                    CellValue::Int(e.inode as i64),
                    CellValue::String(e.path),
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
