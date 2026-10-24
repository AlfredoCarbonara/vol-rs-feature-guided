//! Linux Capabilities plugin.
//!
//! Lists process capabilities.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;

// Capability names (Linux 5.x) - without cap_ prefix to match Python output
const CAP_NAMES: &[&str] = &[
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
];

/// Capabilities plugin - lists process capabilities
pub struct Capabilities;

impl Capabilities {
    pub fn new() -> Self {
        Self
    }

    /// Decode capability value to comma-separated names
    fn decode_cap(cap_value: u64) -> String {
        // Check if all caps (full set for 41 capabilities)
        let full_caps = (1u64 << 41) - 1;
        if cap_value == full_caps || cap_value == u64::MAX {
            return "all".to_string();
        }

        if cap_value == 0 {
            return "".to_string();
        }

        let mut caps = Vec::new();
        for (i, &name) in CAP_NAMES.iter().enumerate() {
            if cap_value & (1u64 << i) != 0 {
                caps.push(name);
            }
        }
        caps.join(", ")
    }

    /// Read kernel_cap_struct (8 bytes = 2 x u32)
    fn read_cap(layer: &dyn DataLayer, addr: u64) -> Vol3Result<u64> {
        let cap0 = helpers::read_u32(layer, addr)? as u64;
        let cap1 = helpers::read_u32(layer, addr + 4)? as u64;
        Ok(cap0 | (cap1 << 32))
    }

    fn list_capabilities(context: &Context) -> Vol3Result<Vec<CapEntry>> {
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

        // cred struct field offsets (from ISF for 5.15 kernel)
        // task_struct.real_cred offset = 2976
        let real_cred_offset = 2976u64;
        let cred_euid_offset = 24u64;
        let cred_cap_inheritable_offset = 44u64;
        let cred_cap_permitted_offset = 52u64;
        let cred_cap_effective_offset = 60u64;
        let cred_cap_bset_offset = 68u64;
        let cred_cap_ambient_offset = 76u64;

        let mut entries = Vec::new();

        for task in tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(0);

            // Skip PID 0 (swapper) like Python pslist does
            if pid == 0 {
                continue;
            }

            let tgid = task.tgid(layer.as_ref()).unwrap_or(pid);
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
            let task_addr = task.address();

            // Read real_cred pointer
            let real_cred_ptr =
                helpers::read_pointer(layer.as_ref(), task_addr + real_cred_offset).unwrap_or(0);

            let (euid, cap_inheritable, cap_permitted, cap_effective, cap_bounding, cap_ambient) =
                if helpers::is_valid_kernel_address(real_cred_ptr) {
                    let euid = helpers::read_u32(layer.as_ref(), real_cred_ptr + cred_euid_offset)
                        .unwrap_or(0) as i32;

                    let cap_inh =
                        Self::read_cap(layer.as_ref(), real_cred_ptr + cred_cap_inheritable_offset)
                            .map(Self::decode_cap)
                            .unwrap_or_else(|_| "N/A".to_string());
                    let cap_perm =
                        Self::read_cap(layer.as_ref(), real_cred_ptr + cred_cap_permitted_offset)
                            .map(Self::decode_cap)
                            .unwrap_or_else(|_| "N/A".to_string());
                    let cap_eff =
                        Self::read_cap(layer.as_ref(), real_cred_ptr + cred_cap_effective_offset)
                            .map(Self::decode_cap)
                            .unwrap_or_else(|_| "N/A".to_string());
                    let cap_bset =
                        Self::read_cap(layer.as_ref(), real_cred_ptr + cred_cap_bset_offset)
                            .map(Self::decode_cap)
                            .unwrap_or_else(|_| "N/A".to_string());
                    let cap_amb =
                        Self::read_cap(layer.as_ref(), real_cred_ptr + cred_cap_ambient_offset)
                            .map(Self::decode_cap)
                            .unwrap_or_else(|_| "N/A".to_string());

                    (euid, cap_inh, cap_perm, cap_eff, cap_bset, cap_amb)
                } else {
                    (
                        0,
                        "N/A".to_string(),
                        "N/A".to_string(),
                        "N/A".to_string(),
                        "N/A".to_string(),
                        "N/A".to_string(),
                    )
                };

            entries.push(CapEntry {
                comm,
                tid: pid,
                tgid,
                ppid,
                euid,
                cap_inheritable,
                cap_permitted,
                cap_effective,
                cap_bounding,
                cap_ambient,
            });
        }

        Ok(entries)
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct CapEntry {
    comm: String,
    tid: i32,
    tgid: i32,
    ppid: i32,
    euid: i32,
    cap_inheritable: String,
    cap_permitted: String,
    cap_effective: String,
    cap_bounding: String,
    cap_ambient: String,
}

impl Module for Capabilities {
    fn name(&self) -> &str {
        "linux.capabilities.Capabilities"
    }

    fn description(&self) -> &str {
        "Lists process capabilities"
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
            Column::new("Name", ColumnType::String),
            Column::new("Tid", ColumnType::Int),
            Column::new("Pid", ColumnType::Int),
            Column::new("PPid", ColumnType::Int),
            Column::new("EUID", ColumnType::Int),
            Column::new("cap_inheritable", ColumnType::String),
            Column::new("cap_permitted", ColumnType::String),
            Column::new("cap_effective", ColumnType::String),
            Column::new("cap_bounding", ColumnType::String),
            Column::new("cap_ambient", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_capabilities(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::String(e.comm),
                    CellValue::Int(e.tid as i64),
                    CellValue::Int(e.tgid as i64),
                    CellValue::Int(e.ppid as i64),
                    CellValue::Int(e.euid as i64),
                    CellValue::String(e.cap_inheritable),
                    CellValue::String(e.cap_permitted),
                    CellValue::String(e.cap_effective),
                    CellValue::String(e.cap_bounding),
                    CellValue::String(e.cap_ambient),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
