//! Linux PsScan plugin.
//!
//! Scans for processes by searching for sched_class pointers in memory.

use std::collections::HashSet;
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};
use log::{debug, warn};

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_layers::ByteScanner;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;

/// Exit state enum (from Linux include/linux/sched.h)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitState {
    TaskRunning,
    ExitDead,
    ExitZombie,
    ExitTrace,
    Unknown(u32),
}

impl ExitState {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0x00000000 => Self::TaskRunning,
            0x00000010 => Self::ExitDead,
            0x00000020 => Self::ExitZombie,
            0x00000030 => Self::ExitTrace, // EXIT_ZOMBIE | EXIT_DEAD
            other => Self::Unknown(other),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::TaskRunning => "TASK_RUNNING",
            Self::ExitDead => "EXIT_DEAD",
            Self::ExitZombie => "EXIT_ZOMBIE",
            Self::ExitTrace => "EXIT_TRACE",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    pub fn is_valid(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

/// PsScan plugin - scans for processes by sched_class pointers
pub struct PsScan;

impl PsScan {
    pub fn new() -> Self {
        Self
    }

    /// Find sched_class symbols and their addresses
    fn find_sched_class_needles(
        context: &Context,
        symbol_table: &str,
    ) -> Vol3Result<Vec<(String, Vec<u8>)>> {
        let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;

        // Hard-coded known sched_class symbol names
        let sched_class_names = [
            "fair_sched_class",
            "rt_sched_class",
            "dl_sched_class",
            "idle_sched_class",
            "stop_sched_class",
        ];

        let mut needles = Vec::new();

        for symbol_name in &sched_class_names {
            if let Ok(symbol) = context.get_symbol(symbol_table, symbol_name) {
                let addr = symbol.address.wrapping_add(aslr_shift);

                // Canonicalize the address (sign extend for 64-bit)
                let canonical_addr = if addr & 0x0000_8000_0000_0000 != 0 {
                    addr | 0xffff_0000_0000_0000
                } else {
                    addr
                };

                let mut buf = vec![0u8; 8];
                LittleEndian::write_u64(&mut buf, canonical_addr);

                debug!(
                    "Found sched_class {} at {:#x}, needle: {:02x?}",
                    symbol_name, canonical_addr, buf
                );
                needles.push((symbol_name.to_string(), buf));
            }
        }

        Ok(needles)
    }

    /// Get the sched_class offset in task_struct
    fn get_sched_class_offset(context: &Context, symbol_table: &str) -> Vol3Result<usize> {
        use vol3_core::error::ObjectError;

        let template = context.get_type(symbol_table, "task_struct")?;

        if let vol3_symbols::TypeTemplate::Struct(s) = template.as_ref() {
            s.get_field("sched_class").map(|f| f.offset).ok_or_else(|| {
                Vol3Error::Object(ObjectError::MemberNotFound {
                    type_name: "task_struct".to_string(),
                    member: "sched_class".to_string(),
                })
            })
        } else {
            Err(Vol3Error::Object(ObjectError::InvalidTemplate(
                "Expected struct".to_string(),
            )))
        }
    }

    /// Scan memory for processes
    fn scan_processes(context: &Context) -> Vol3Result<Vec<ScannedTask>> {
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

        // Get sched_class offset
        let sched_class_offset = Self::get_sched_class_offset(context, &symbol_table)?;
        debug!("sched_class offset: {}", sched_class_offset);

        // Find sched_class needles
        let needles = Self::find_sched_class_needles(context, &symbol_table)?;
        if needles.is_empty() {
            warn!("No sched_class symbols found");
            return Ok(Vec::new());
        }

        // Get memory layer (the underlying physical layer)
        let deps = layer.dependencies();
        let memory_layer = if !deps.is_empty() {
            context.get_layer(&deps[0]).ok_or_else(|| {
                Vol3Error::Layer(vol3_core::error::LayerError::NotFound(deps[0].clone()))
            })?
        } else {
            layer.clone()
        };

        // Get task_struct template
        let template = helpers::get_task_struct_template(context, &symbol_table)?;

        let mut tasks = Vec::new();
        let mut seen_offsets = HashSet::new();

        // Scan for each needle
        for (_needle_name, needle_bytes) in &needles {
            let scanner = ByteScanner::new(needle_bytes.clone());
            let matches = memory_layer.scan(&scanner, None, None);

            for (match_offset, _) in matches {
                // Calculate task_struct address
                let task_addr = match_offset.saturating_sub(sched_class_offset as u64);

                if seen_offsets.contains(&task_addr) {
                    continue;
                }
                seen_offsets.insert(task_addr);

                // Try to create task struct and validate
                // Use memory_layer for reading the task struct directly from physical memory
                if let Ok(task) = TaskStruct::new(task_addr, template.clone()) {
                    // Validate exit_state first (like Python does)
                    let exit_state_val = task.exit_state(memory_layer.as_ref()).unwrap_or(0);
                    let exit_state = ExitState::from_u32(exit_state_val as u32);
                    if !exit_state.is_valid() {
                        debug!(
                            "Skipping task at {:#x}: invalid exit_state {}",
                            task_addr, exit_state_val
                        );
                        continue;
                    }

                    // Validate PID
                    if let Ok(pid) = task.pid(memory_layer.as_ref()) {
                        if pid <= 0 || pid >= 65535 {
                            debug!("Skipping task at {:#x}: invalid pid {}", task_addr, pid);
                            continue;
                        }

                        let tgid = task.tgid(memory_layer.as_ref()).unwrap_or(pid);
                        // Also validate tgid like Python does
                        if tgid <= 0 || tgid >= 65535 {
                            debug!("Skipping task at {:#x}: invalid tgid {}", task_addr, tgid);
                            continue;
                        }
                        // For PPID, we need to read real_parent pointer from the task,
                        // then translate that virtual address and read from the kernel layer
                        let ppid =
                            get_ppid(&task, memory_layer.as_ref(), layer.as_ref(), &template);
                        let comm = task
                            .comm(memory_layer.as_ref())
                            .unwrap_or_else(|_| "<unknown>".to_string());

                        tasks.push(ScannedTask {
                            offset: task_addr,
                            pid,
                            tgid,
                            ppid,
                            comm,
                            exit_state,
                        });
                    }
                }
            }
        }

        // Match Python scan order (ascending by offset)
        tasks.sort_by_key(|t| t.offset);
        Ok(tasks)
    }
}

/// Helper to get parent PID - uses real_parent like Python vol3
/// memory_layer is used for reading the task's real_parent pointer
/// kernel_layer is used for dereferencing the virtual parent address
fn get_ppid(
    task: &TaskStruct,
    memory_layer: &dyn DataLayer,
    kernel_layer: &dyn DataLayer,
    template: &Arc<vol3_symbols::TypeTemplate>,
) -> i32 {
    // Python uses task.real_parent.tgid for PPID (see get_parent_pid in extensions)
    // real_parent is a virtual pointer, so we read it from task (in physical memory)
    // then dereference it using the kernel layer (which can translate virtual to physical)
    task.real_parent_addr(memory_layer)
        .ok()
        .and_then(|parent_addr| {
            if helpers::is_valid_kernel_address(parent_addr) {
                // Try to read from kernel layer using virtual address
                TaskStruct::new(parent_addr, template.clone())
                    .ok()
                    .and_then(|parent| parent.tgid(kernel_layer).ok())
            } else {
                None
            }
        })
        .unwrap_or(0)
}

impl Default for PsScan {
    fn default() -> Self {
        Self::new()
    }
}

/// Scanned task information
#[derive(Debug, Clone)]
struct ScannedTask {
    offset: Address,
    pid: i32,
    tgid: i32,
    ppid: i32,
    comm: String,
    exit_state: ExitState,
}

impl Module for PsScan {
    fn name(&self) -> &str {
        "linux.psscan.PsScan"
    }

    fn description(&self) -> &str {
        "Scans for processes present in a particular linux image"
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
            Column::new("OFFSET (P)", ColumnType::Hex),
            Column::new("PID", ColumnType::Int),
            Column::new("TID", ColumnType::Int),
            Column::new("PPID", ColumnType::Int),
            Column::new("COMM", ColumnType::String),
            Column::new("EXIT_STATE", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let tasks = Self::scan_processes(&context)?;

        let rows: Vec<Vol3Result<Row>> = tasks
            .into_iter()
            .map(|t| {
                // Python uses: PID = tgid (user_pid), TID = pid (user_tid)
                Ok(vec![
                    CellValue::Hex(t.offset),
                    CellValue::Int(t.tgid as i64), // PID = tgid
                    CellValue::Int(t.pid as i64),  // TID = pid
                    CellValue::Int(t.ppid as i64),
                    CellValue::String(t.comm),
                    CellValue::String(t.exit_state.name().to_string()),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
