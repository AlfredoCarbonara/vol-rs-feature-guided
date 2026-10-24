//! Linux PsAux plugin.
//!
//! Lists processes with their command line arguments.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;
use crate::process_layer;

/// Process with arguments
#[derive(Debug, Clone)]
struct ProcessWithArgs {
    pid: i32,
    ppid: i32,
    comm: String,
    args: String,
}

/// PsAux plugin - lists processes with command line arguments
pub struct PsAux;

impl PsAux {
    pub fn new() -> Self {
        Self
    }

    /// List processes with arguments
    fn list_processes(context: &Context) -> Vol3Result<Vec<ProcessWithArgs>> {
        use vol3_core::error::{ConfigError, LayerError};

        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let layer = context
            .get_layer(&layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(layer_name.clone())))?;

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        let init_task_addr = helpers::get_init_task(context, &symbol_table)?;
        let template = helpers::get_task_struct_template(context, &symbol_table)?;
        let tasks = helpers::collect_processes(layer.as_ref(), init_task_addr, &template)?;

        let mut processes = Vec::new();

        for task in tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(-1);
            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());
            let ppid = task
                .real_parent_addr(layer.as_ref())
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

            // Use process_layer to read command line args
            let args = match process_layer::get_task_args(
                context,
                &layer_name,
                &task,
                &symbol_table,
                &comm,
            ) {
                Ok(a) => a,
                Err(_) => format!("[{}]", comm),
            };

            processes.push(ProcessWithArgs {
                pid,
                ppid,
                comm,
                args,
            });
        }

        Ok(processes)
    }
}

impl Default for PsAux {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for PsAux {
    fn name(&self) -> &str {
        "linux.psaux.PsAux"
    }

    fn description(&self) -> &str {
        "Lists processes with their command line arguments"
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
            Column::new("ARGS", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let processes = Self::list_processes(&context)?;

        let rows: Vec<Vol3Result<Row>> = processes
            .into_iter()
            .map(|p| {
                Ok(vec![
                    CellValue::Int(p.pid as i64),
                    CellValue::Int(p.ppid as i64),
                    CellValue::String(p.comm),
                    CellValue::String(p.args),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
