//! Linux PsList plugin.
//!
//! Lists running processes from the kernel's task list.

use std::sync::Arc;

use log::info;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{AbsentValue, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::{Requirements, RequirementsBuilder};

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;

/// PsList plugin - lists running processes
pub struct PsList;

impl PsList {
    /// Create a new PsList plugin
    pub fn new() -> Self {
        Self
    }

    /// Get processes from the task list
    fn get_processes(context: &Context) -> Vol3Result<Vec<ProcessInfo>> {
        use vol3_core::error::{ConfigError, LayerError};

        // Get primary layer name
        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        // Get layer
        let layer = context
            .get_layer(&layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(layer_name.clone())))?;

        // Get symbol table name
        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        // Get init_task address
        let init_task_addr = helpers::get_init_task(context, &symbol_table)?;
        info!("init_task at {:#x}", init_task_addr);

        // Get task_struct template
        let template = helpers::get_task_struct_template(context, &symbol_table)?;

        // Get system boottime for calculating absolute creation times
        let boottime_ns = helpers::get_boottime_ns(context, layer.as_ref(), &symbol_table);
        if let Some(bt) = boottime_ns {
            info!("System boottime: {} ns", bt);
        }

        // Collect processes - NOTE: Python vol3 does NOT include init_task itself
        let tasks = helpers::collect_processes(layer.as_ref(), init_task_addr, &template)?;

        // Convert to ProcessInfo
        // Apply address mask like Python does (48-bit for Intel64)
        // Python: mask = self._context.layers[layer_name].address_mask
        // For Intel64: (1 << 48) - 1 = 0xFFFFFFFFFFFF
        const ADDRESS_MASK: u64 = (1u64 << 48) - 1;

        let mut processes = Vec::new();
        let mut seen_offsets = std::collections::HashSet::new();

        for task in tasks {
            // Skip init_task (swapper/0) like Python does
            let raw_offset = task.address();
            let offset = raw_offset & ADDRESS_MASK; // Mask to 48 bits

            if raw_offset == init_task_addr {
                continue;
            }

            // Avoid duplicates
            if seen_offsets.contains(&offset) {
                continue;
            }
            seen_offsets.insert(offset);

            let pid = task.pid(layer.as_ref()).unwrap_or(-1); // This is TID in Linux
            let tgid = task.tgid(layer.as_ref()).unwrap_or(pid); // This is PID in Linux
            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            // Get parent PID using real_parent like Python does
            let ppid = task
                .real_parent_addr(layer.as_ref())
                .ok()
                .and_then(|parent_addr| {
                    if helpers::is_valid_kernel_address(parent_addr) {
                        TaskStruct::new(parent_addr, template.clone())
                            .ok()
                            .and_then(|parent| parent.tgid(layer.as_ref()).ok())
                    // Use tgid for parent PID
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            // Get UID/GID/EUID/EGID from cred struct
            let (uid, gid, euid, egid) = task
                .get_creds(layer.as_ref())
                .unwrap_or((None, None, None, None));

            // Get creation time as absolute UTC datetime
            let creation_time = task.get_start_time_ns(layer.as_ref()).and_then(|start_ns| {
                boottime_ns.map(|bt_ns| helpers::task_create_time_to_utc(start_ns, bt_ns))
            });

            processes.push(ProcessInfo {
                offset,
                user_pid: tgid, // PID in userspace is tgid
                user_tid: pid,  // TID in userspace is pid
                user_ppid: ppid,
                comm,
                uid,
                gid,
                euid,
                egid,
                creation_time,
            });
        }

        Ok(processes)
    }
}

impl Default for PsList {
    fn default() -> Self {
        Self::new()
    }
}

/// Process information matching Python volatility3 TaskFields
#[derive(Debug, Clone)]
struct ProcessInfo {
    offset: u64,
    user_pid: i32,  // tgid - Process ID as seen in userspace
    user_tid: i32,  // pid - Thread ID as seen in userspace
    user_ppid: i32, // Parent PID
    comm: String,
    uid: Option<u32>,
    gid: Option<u32>,
    euid: Option<u32>,
    egid: Option<u32>,
    creation_time: Option<String>,
}

impl Module for PsList {
    fn name(&self) -> &str {
        "linux.pslist.PsList"
    }

    fn description(&self) -> &str {
        "Lists the processes present in a particular linux memory image"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Memory layer for the kernel")
            .symbol_table("vmlinux", "Linux kernel symbol table")
            .int_optional("pid", "Filter by process ID")
            .build();

        ModuleRequirements {
            name: self.name().to_string(),
            description: self.description().to_string(),
            requirements,
        }
    }

    fn columns(&self) -> Vec<Column> {
        // Match Python volatility3 columns exactly
        vec![
            Column::new("OFFSET (V)", ColumnType::Hex),
            Column::new("PID", ColumnType::Int),
            Column::new("TID", ColumnType::Int),
            Column::new("PPID", ColumnType::Int),
            Column::new("COMM", ColumnType::String),
            Column::new("UID", ColumnType::Int),
            Column::new("GID", ColumnType::Int),
            Column::new("EUID", ColumnType::Int),
            Column::new("EGID", ColumnType::Int),
            Column::new("CREATION TIME", ColumnType::String),
            Column::new("File output", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        // Get PID filter if set
        let pid_filter = context
            .config_get_int("plugins.pslist.pid")
            .map(|p| p as i32);

        // Get processes
        let processes = Self::get_processes(&context)?;

        // Filter and convert to rows
        let rows: Vec<Vol3Result<Row>> = processes
            .into_iter()
            .filter(|p| {
                if let Some(filter_pid) = pid_filter {
                    p.user_pid == filter_pid
                } else {
                    true
                }
            })
            .map(|p| {
                Ok(vec![
                    CellValue::Hex(p.offset),
                    CellValue::Int(p.user_pid as i64),
                    CellValue::Int(p.user_tid as i64),
                    CellValue::Int(p.user_ppid as i64),
                    CellValue::String(p.comm),
                    p.uid
                        .map(|v| CellValue::Int(v as i64))
                        .unwrap_or(CellValue::Absent(AbsentValue::NotAvailable)),
                    p.gid
                        .map(|v| CellValue::Int(v as i64))
                        .unwrap_or(CellValue::Absent(AbsentValue::NotAvailable)),
                    p.euid
                        .map(|v| CellValue::Int(v as i64))
                        .unwrap_or(CellValue::Absent(AbsentValue::NotAvailable)),
                    p.egid
                        .map(|v| CellValue::Int(v as i64))
                        .unwrap_or(CellValue::Absent(AbsentValue::NotAvailable)),
                    p.creation_time
                        .map(|s| CellValue::String(s))
                        .unwrap_or(CellValue::Absent(AbsentValue::NotAvailable)),
                    CellValue::String("Disabled".to_string()), // File output
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pslist_columns() {
        let plugin = PsList::new();
        let columns = plugin.columns();

        assert_eq!(columns.len(), 5);
        assert_eq!(columns[0].name, "OFFSET");
        assert_eq!(columns[1].name, "PID");
    }

    #[test]
    fn test_pslist_requirements() {
        let plugin = PsList::new();
        let reqs = plugin.requirements();

        assert!(reqs.requirements.contains("primary"));
        assert!(reqs.requirements.contains("vmlinux"));
    }
}
