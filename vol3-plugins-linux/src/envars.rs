//! Linux Envars plugin.
//!
//! Lists processes with their environment variables.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;
use crate::process_layer;

/// Envars plugin - lists processes with their environment variables
pub struct Envars;

impl Envars {
    pub fn new() -> Self {
        Self
    }

    fn list_envars(context: &Context) -> Vol3Result<Vec<EnvarEntry>> {
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
            let ppid = task
                .parent_addr(layer.as_ref())
                .ok()
                .and_then(|parent_addr| {
                    if helpers::is_valid_kernel_address(parent_addr) {
                        TaskStruct::new(parent_addr, template.clone())
                            .ok()
                            .and_then(|parent| parent.pid(layer.as_ref()).ok())
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            // Read environment variables using process layer
            let env_vars = process_layer::get_task_env_variables(
                context,
                &layer_name,
                &task,
                &symbol_table,
                256 * 1024,
            )
            .unwrap_or_default();

            if env_vars.is_empty() {
                // Kernel thread or couldn't read env vars - skip
                continue;
            }

            for (key, value) in env_vars {
                entries.push(EnvarEntry {
                    pid,
                    ppid,
                    comm: comm.clone(),
                    key,
                    value,
                });
            }
        }

        Ok(entries)
    }
}

impl Default for Envars {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct EnvarEntry {
    pid: i32,
    ppid: i32,
    comm: String,
    key: String,
    value: String,
}

impl Module for Envars {
    fn name(&self) -> &str {
        "linux.envars.Envars"
    }

    fn description(&self) -> &str {
        "Lists processes with their environment variables"
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
            Column::new("PPID", ColumnType::Int),
            Column::new("COMM", ColumnType::String),
            Column::new("KEY", ColumnType::String),
            Column::new("VALUE", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_envars(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.pid as i64),
                    CellValue::Int(e.ppid as i64),
                    CellValue::String(e.comm),
                    CellValue::String(e.key),
                    CellValue::String(e.value),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
