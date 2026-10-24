//! Linux PsCallStack plugin.
//!
//! Captures the kernel call stacks for processes.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;

/// PsCallStack plugin - captures kernel call stacks
pub struct PsCallStack;

impl PsCallStack {
    pub fn new() -> Self {
        Self
    }

    fn get_call_stacks(context: &Context) -> Vol3Result<Vec<CallStackEntry>> {
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

        let init_task_addr = helpers::get_init_task(context, &symbol_table)?;
        let template = helpers::get_task_struct_template(context, &symbol_table)?;
        let tasks = helpers::collect_processes(layer.as_ref(), init_task_addr, &template)?;

        let mut entries = Vec::new();

        for task in tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(0);
            let tgid = task.tgid(layer.as_ref()).unwrap_or(pid);
            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            // Full implementation requires:
            // 1. Reading thread_info/stack pointer
            // 2. Walking stack frames
            // 3. Resolving return addresses to symbols
            entries.push(CallStackEntry {
                pid,
                tgid,
                comm,
                call_stack: "Stack walking not fully implemented".to_string(),
            });
        }

        // Return empty for now
        Ok(Vec::new())
    }
}

impl Default for PsCallStack {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct CallStackEntry {
    pid: i32,
    tgid: i32,
    comm: String,
    call_stack: String,
}

impl Module for PsCallStack {
    fn name(&self) -> &str {
        "linux.pscallstack.PsCallStack"
    }

    fn description(&self) -> &str {
        "Captures the kernel call stacks for processes"
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
            Column::new("TID", ColumnType::Int),
            Column::new("COMM", ColumnType::String),
            Column::new("CALL_STACK", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::get_call_stacks(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.pid as i64),
                    CellValue::Int(e.tgid as i64),
                    CellValue::String(e.comm),
                    CellValue::String(e.call_stack),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
