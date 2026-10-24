//! Linux CheckCreds plugin.
//!
//! Checks for processes sharing credential structures.

use std::collections::HashMap;
use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;

/// CheckCreds plugin - checks for shared credentials
pub struct CheckCreds;

impl CheckCreds {
    pub fn new() -> Self {
        Self
    }

    fn check_creds(context: &Context) -> Vol3Result<Vec<CredEntry>> {
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

        // Get cred offset from task_struct
        let cred_offset = if let vol3_symbols::TypeTemplate::Struct(s) = template.as_ref() {
            s.get_field("cred").map(|f| f.offset).unwrap_or(0)
        } else {
            0
        };

        // Collect cred addresses -> list of PIDs
        let mut creds: HashMap<u64, Vec<i32>> = HashMap::new();

        for task in tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(0);

            // Read cred pointer
            if let Ok(cred_ptr) =
                helpers::read_pointer(layer.as_ref(), task.address() + cred_offset as u64)
            {
                if cred_ptr != 0 && helpers::is_valid_kernel_address(cred_ptr) {
                    creds.entry(cred_ptr).or_default().push(pid);
                }
            }
        }

        // Only output entries where multiple processes share the same cred
        let mut entries = Vec::new();
        for (cred_addr, pids) in creds {
            if pids.len() > 1 {
                let pid_str = pids
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                entries.push(CredEntry {
                    cred_vaddr: cred_addr,
                    pids: pid_str,
                });
            }
        }

        Ok(entries)
    }
}

impl Default for CheckCreds {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct CredEntry {
    cred_vaddr: u64,
    pids: String,
}

impl Module for CheckCreds {
    fn name(&self) -> &str {
        "linux.check_creds.CheckCreds"
    }

    fn description(&self) -> &str {
        "Checks for processes sharing credential structures"
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
            Column::new("CredVAddr", ColumnType::Hex),
            Column::new("PIDs", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::check_creds(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Hex(e.cred_vaddr),
                    CellValue::String(e.pids),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
