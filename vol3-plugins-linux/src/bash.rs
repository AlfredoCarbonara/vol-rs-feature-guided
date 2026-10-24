//! Linux Bash plugin.
//!
//! Recovers bash command history from memory.

use std::collections::HashSet;
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};
use chrono::{TimeZone, Utc};

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::scanner::MultiPatternScanner;
use vol3_layers::traits::DataLayer;
use vol3_layers::ByteScanner;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;
use crate::process_layer;

/// Bash plugin - recovers bash command history
pub struct Bash;

impl Bash {
    pub fn new() -> Self {
        Self
    }

    fn get_bash_history(context: &Context) -> Vol3Result<Vec<BashEntry>> {
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

        let pid_filter = context.config_get_int("pid").map(|v| v as i32);

        // Determine pointer size from the symbol table
        let ptr_size = context
            .get_type(&symbol_table, "pointer")
            .ok()
            .and_then(|t| t.size())
            .unwrap_or(8);

        let ts_offset = ptr_size as u64;

        // mm_struct offsets (mmap, start_brk, brk)
        let mm_template = context.get_type(&symbol_table, "mm_struct")?;
        let (mm_offset, mmap_offset, start_brk_offset, brk_offset) =
            if let vol3_symbols::TypeTemplate::Struct(s) = mm_template.as_ref() {
                (
                    // mm offset from task_struct
                    context
                        .get_type(&symbol_table, "task_struct")
                        .ok()
                        .and_then(|t| match t.as_ref() {
                            vol3_symbols::TypeTemplate::Struct(st) => {
                                st.get_field("mm").map(|f| f.offset)
                            }
                            _ => None,
                        })
                        .unwrap_or(0),
                    s.get_field("mmap").map(|f| f.offset),
                    s.get_field("start_brk").map(|f| f.offset).unwrap_or(0),
                    s.get_field("brk").map(|f| f.offset).unwrap_or(0),
                )
            } else {
                (0, None, 0, 0)
            };

        // vm_area_struct offsets
        let vma_template = context.get_type(&symbol_table, "vm_area_struct")?;
        let (vm_start_offset, vm_end_offset, vm_next_offset) =
            if let vol3_symbols::TypeTemplate::Struct(s) = vma_template.as_ref() {
                (
                    s.get_field("vm_start").map(|f| f.offset).unwrap_or(0),
                    s.get_field("vm_end").map(|f| f.offset).unwrap_or(0),
                    s.get_field("vm_next").map(|f| f.offset).unwrap_or(0),
                )
            } else {
                (0, 0, 0)
            };

        let mut entries = Vec::new();

        for task in tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(0);
            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            if let Some(filter_pid) = pid_filter {
                if pid != filter_pid {
                    continue;
                }
            }

            // Only process bash/sh/dash processes
            if !["bash", "sh", "dash"].contains(&comm.as_str()) {
                continue;
            }

            // Create process layer
            let proc_layer = match process_layer::create_process_layer(
                context,
                &layer_name,
                &task,
                &symbol_table,
            )? {
                Some(layer) => layer,
                None => continue,
            };

            // Read mm pointer for heap bounds
            if mm_offset == 0 {
                continue;
            }
            let mm_ptr = read_ptr(layer.as_ref(), task.address() + mm_offset as u64, ptr_size)?;
            if mm_ptr == 0 {
                continue;
            }

            // Heap bounds
            let start_brk = read_ptr(layer.as_ref(), mm_ptr + start_brk_offset as u64, ptr_size)?;
            let brk = read_ptr(layer.as_ref(), mm_ptr + brk_offset as u64, ptr_size)?;
            if brk <= start_brk {
                continue;
            }

            let mmap_off = match mmap_offset {
                Some(off) => off,
                None => continue, // Maple tree not implemented yet
            };

            // Collect heap VMAs
            let vmas = collect_vmas_mmap(
                layer.as_ref(),
                mm_ptr + mmap_off as u64,
                vm_next_offset,
                ptr_size,
            )?;
            let mut heap_sections: Vec<(Address, usize)> = Vec::new();
            for vma_addr in vmas {
                let vm_start =
                    read_ptr(layer.as_ref(), vma_addr + vm_start_offset as u64, ptr_size)?;
                let vm_end = read_ptr(layer.as_ref(), vma_addr + vm_end_offset as u64, ptr_size)?;
                if vm_end <= vm_start {
                    continue;
                }
                if vm_start <= brk && vm_end >= start_brk {
                    heap_sections.push((vm_start, (vm_end - vm_start) as usize));
                }
            }
            if heap_sections.is_empty() {
                continue;
            }

            // Scan heap for '#' markers (timestamp strings)
            let bang_scanner = ByteScanner::new(vec![b'#']);
            let bang_matches = proc_layer.scan(&bang_scanner, Some(heap_sections.clone()), None);

            let mut patterns: Vec<Vec<u8>> = Vec::new();
            let mut seen_bangs = HashSet::new();
            for (addr, _) in bang_matches {
                if seen_bangs.contains(&addr) {
                    continue;
                }
                // Filter to likely timestamps (#<digits>)
                if let Ok(s) = helpers::read_string(proc_layer.as_ref(), addr, 32) {
                    if is_timestamp_string(&s) {
                        seen_bangs.insert(addr);
                        patterns.push(pack_ptr(addr, ptr_size));
                    }
                }
            }

            if patterns.is_empty() {
                continue;
            }

            // Scan heap for pointers to those timestamps
            let ptr_scanner = MultiPatternScanner::new(patterns);
            let heap_sections_scan = heap_sections.clone();
            let mut ptr_matches = proc_layer.scan(&ptr_scanner, Some(heap_sections_scan), None);
            ptr_matches.sort_by_key(|(addr, _)| *addr);

            let mut seen_entries = HashSet::new();
            let mut task_entries: Vec<BashEntryInternal> = Vec::new();

            for (ptr_addr, matched) in ptr_matches {
                if ptr_addr < ts_offset {
                    continue;
                }
                let entry_addr = ptr_addr - ts_offset;
                if !seen_entries.insert(entry_addr) {
                    continue;
                }

                let line_ptr = read_ptr(proc_layer.as_ref(), entry_addr, ptr_size)?;
                let ts_ptr = read_ptr(proc_layer.as_ref(), entry_addr + ts_offset, ptr_size)?;
                if line_ptr == 0 || ts_ptr == 0 {
                    continue;
                }
                let matched_addr = unpack_ptr(&matched, ptr_size);
                if matched_addr != 0 && ts_ptr != matched_addr {
                    continue;
                }

                let ts_str =
                    helpers::read_string(proc_layer.as_ref(), ts_ptr, 32).unwrap_or_default();
                let ts = match parse_timestamp(&ts_str) {
                    Some(v) => v,
                    None => continue,
                };

                let command =
                    helpers::read_string(proc_layer.as_ref(), line_ptr, 1024).unwrap_or_default();
                if command.is_empty() || !is_command_plausible(&command) {
                    continue;
                }

                task_entries.push(BashEntryInternal {
                    pid,
                    process: comm.clone(),
                    timestamp: ts,
                    command,
                });
            }

            // Sort by timestamp like Python
            task_entries.sort_by_key(|e| e.timestamp);
            for e in task_entries {
                entries.push(BashEntry {
                    pid: e.pid,
                    process: e.process,
                    command_time: format_timestamp(e.timestamp),
                    command: e.command,
                });
            }
        }

        Ok(entries)
    }
}

impl Default for Bash {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct BashEntry {
    pid: i32,
    process: String,
    command_time: String,
    command: String,
}

#[derive(Debug, Clone)]
struct BashEntryInternal {
    pid: i32,
    process: String,
    timestamp: i64,
    command: String,
}

impl Module for Bash {
    fn name(&self) -> &str {
        "linux.bash.Bash"
    }

    fn description(&self) -> &str {
        "Recovers bash command history from memory"
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
            Column::new("CommandTime", ColumnType::String),
            Column::new("Command", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::get_bash_history(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.pid as i64),
                    CellValue::String(e.process),
                    CellValue::String(e.command_time),
                    CellValue::String(e.command),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}

fn read_ptr(layer: &dyn DataLayer, address: Address, ptr_size: usize) -> Vol3Result<Address> {
    let bytes = layer
        .read(address, ptr_size, false)
        .map_err(Vol3Error::Layer)?;
    Ok(match ptr_size {
        4 => LittleEndian::read_u32(&bytes) as u64,
        _ => LittleEndian::read_u64(&bytes),
    })
}

fn pack_ptr(addr: Address, ptr_size: usize) -> Vec<u8> {
    match ptr_size {
        4 => (addr as u32).to_le_bytes().to_vec(),
        _ => addr.to_le_bytes().to_vec(),
    }
}

fn unpack_ptr(bytes: &[u8], ptr_size: usize) -> Address {
    if bytes.len() < ptr_size {
        return 0;
    }
    match ptr_size {
        4 => LittleEndian::read_u32(&bytes[..4]) as u64,
        _ => LittleEndian::read_u64(&bytes[..8]),
    }
}

fn is_timestamp_string(s: &str) -> bool {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('#') {
        s.len() >= 10 && !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}

fn parse_timestamp(s: &str) -> Option<i64> {
    let s = s.trim();
    let digits = s.strip_prefix('#')?;
    digits.parse::<i64>().ok()
}

fn format_timestamp(ts: i64) -> String {
    match Utc.timestamp_opt(ts, 0).single() {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string(),
        None => "N/A".to_string(),
    }
}

fn is_command_plausible(cmd: &str) -> bool {
    if cmd.contains('\u{FFFD}') {
        return false;
    }
    if !cmd.chars().any(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    cmd.chars()
        .all(|c| c.is_ascii_graphic() || c.is_whitespace())
}

fn collect_vmas_mmap(
    layer: &dyn DataLayer,
    mmap_ptr_addr: Address,
    vm_next_offset: usize,
    ptr_size: usize,
) -> Vol3Result<Vec<Address>> {
    let mut vmas = Vec::new();
    let mut seen = HashSet::new();

    let mut vma_ptr = read_ptr(layer, mmap_ptr_addr, ptr_size)?;
    let is_kernel_addr = |addr: Address| {
        if ptr_size == 8 {
            helpers::is_valid_kernel_address(addr)
        } else {
            addr != 0
        }
    };

    while vma_ptr != 0 && is_kernel_addr(vma_ptr) && !seen.contains(&vma_ptr) {
        seen.insert(vma_ptr);
        vmas.push(vma_ptr);

        if vm_next_offset == 0 {
            break;
        }
        vma_ptr = read_ptr(layer, vma_ptr + vm_next_offset as u64, ptr_size)?;
    }

    Ok(vmas)
}
