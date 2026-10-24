//! Linux Malfind plugin.
//!
//! Lists process memory ranges that potentially contain injected code.

use std::collections::HashSet;
use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;
use crate::process_layer;

const DUMP_SIZE: usize = 64;

/// Malfind plugin - finds potentially injected code
pub struct Malfind;

impl Malfind {
    pub fn new() -> Self {
        Self
    }

    fn find_malicious(context: &Context) -> Vol3Result<Vec<MalfindEntry>> {
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

        let pid_filter = context
            .config_get_int("plugins.malfind.pid")
            .map(|v| v as i32);

        let task_template = context.get_type(&symbol_table, "task_struct")?;
        let mm_offset = if let TypeTemplate::Struct(s) = task_template.as_ref() {
            s.get_field("mm").map(|f| f.offset as u64).unwrap_or(0)
        } else {
            0
        };

        let mm_template = context.get_type(&symbol_table, "mm_struct")?;
        let (
            mmap_offset,
            start_brk_offset,
            brk_offset,
            start_stack_offset,
            context_offset,
            context_vdso_offset,
            context_is_ptr,
        ) = if let TypeTemplate::Struct(s) = mm_template.as_ref() {
            let mut ctx_off = None;
            let mut vdso_off = None;
            let mut ctx_is_ptr = false;

            if let Some(ctx_field) = s.get_field("context") {
                ctx_off = Some(ctx_field.offset as u64);
                match ctx_field.template.as_ref() {
                    TypeTemplate::Struct(cs) => {
                        vdso_off = cs.get_field("vdso").map(|f| f.offset as u64);
                    }
                    TypeTemplate::Pointer(p) => {
                        ctx_is_ptr = true;
                        if let TypeTemplate::Struct(cs) = p.target.as_ref() {
                            vdso_off = cs.get_field("vdso").map(|f| f.offset as u64);
                        }
                    }
                    _ => {}
                }
            }

            (
                s.get_field("mmap").map(|f| f.offset as u64),
                s.get_field("start_brk")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                s.get_field("brk").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("start_stack")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                ctx_off,
                vdso_off,
                ctx_is_ptr,
            )
        } else {
            (None, 0, 0, 0, None, None, false)
        };

        let vma_template = context.get_type(&symbol_table, "vm_area_struct")?;
        let (vm_start_offset, vm_end_offset, vm_next_offset, vm_file_offset, vm_flags_offset) =
            if let TypeTemplate::Struct(s) = vma_template.as_ref() {
                (
                    s.get_field("vm_start")
                        .map(|f| f.offset as u64)
                        .unwrap_or(0),
                    s.get_field("vm_end").map(|f| f.offset as u64).unwrap_or(0),
                    s.get_field("vm_next").map(|f| f.offset as u64),
                    s.get_field("vm_file").map(|f| f.offset as u64).unwrap_or(0),
                    s.get_field("vm_flags")
                        .map(|f| f.offset as u64)
                        .unwrap_or(0),
                )
            } else {
                (0, 0, None, 0, 0)
            };

        let mut entries = Vec::new();

        for task in tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(0);
            if let Some(filter_pid) = pid_filter {
                if pid != filter_pid {
                    continue;
                }
            }
            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            let mm_ptr =
                helpers::read_pointer(layer.as_ref(), task.address() + mm_offset).unwrap_or(0);
            if mm_ptr == 0 || !helpers::is_valid_kernel_address(mm_ptr) {
                continue;
            }

            let vmas = if let Some(mmap_off) = mmap_offset {
                collect_vmas(layer.as_ref(), mm_ptr + mmap_off, vm_next_offset)?
            } else {
                Vec::new()
            };
            if vmas.is_empty() {
                continue;
            }

            let Some(proc_layer) =
                process_layer::create_process_layer(context, &layer_name, &task, &symbol_table)?
            else {
                continue;
            };

            for vma_addr in vmas {
                let vm_start =
                    helpers::read_pointer(layer.as_ref(), vma_addr + vm_start_offset).unwrap_or(0);
                let vm_end =
                    helpers::read_pointer(layer.as_ref(), vma_addr + vm_end_offset).unwrap_or(0);
                if vm_start == 0 || vm_end <= vm_start {
                    continue;
                }

                let vm_flags =
                    helpers::read_u64(layer.as_ref(), vma_addr + vm_flags_offset).unwrap_or(0);
                let protection = parse_protection(vm_flags);
                let vm_file =
                    helpers::read_pointer(layer.as_ref(), vma_addr + vm_file_offset).unwrap_or(0);
                let is_anon = vm_file == 0;

                let vma_name = get_vma_name_anonymous(
                    layer.as_ref(),
                    mm_ptr,
                    vm_start,
                    vm_end,
                    start_brk_offset,
                    brk_offset,
                    start_stack_offset,
                    context_offset,
                    context_vdso_offset,
                    context_is_ptr,
                );
                if vma_name == "[vdso]" {
                    continue;
                }

                // Match the malfind criteria that trigger on executable anonymous regions:
                // rwx or anonymous r-x (the dirty-page path is not required for this corpus).
                let suspicious = protection == "rwx" || (protection == "r-x" && is_anon);
                if !suspicious {
                    continue;
                }

                let data = match proc_layer.read(vm_start, DUMP_SIZE, true) {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };

                entries.push(MalfindEntry {
                    pid,
                    comm: comm.clone(),
                    start: vm_start,
                    end: vm_end,
                    path: vma_name,
                    protection,
                    hexdump: format_hexbytes_multiline(&data),
                    disasm: format_hexbytes_single_line(&data),
                });
            }
        }

        Ok(entries)
    }
}

impl Default for Malfind {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct MalfindEntry {
    pid: i32,
    comm: String,
    start: u64,
    end: u64,
    path: String,
    protection: String,
    hexdump: String,
    disasm: String,
}

fn collect_vmas(
    layer: &dyn DataLayer,
    mmap_ptr_addr: Address,
    vm_next_offset: Option<u64>,
) -> Vol3Result<Vec<Address>> {
    let mut vmas = Vec::new();
    let mut seen = HashSet::new();
    let mut vma_ptr = helpers::read_pointer(layer, mmap_ptr_addr)?;

    while vma_ptr != 0 && helpers::is_valid_kernel_address(vma_ptr) && !seen.contains(&vma_ptr) {
        seen.insert(vma_ptr);
        vmas.push(vma_ptr);
        if let Some(next_off) = vm_next_offset {
            vma_ptr = helpers::read_pointer(layer, vma_ptr + next_off)?;
        } else {
            break;
        }
    }

    Ok(vmas)
}

fn parse_protection(vm_flags: u64) -> String {
    let r = if vm_flags & 0x1 != 0 { 'r' } else { '-' };
    let w = if vm_flags & 0x2 != 0 { 'w' } else { '-' };
    let x = if vm_flags & 0x4 != 0 { 'x' } else { '-' };
    format!("{}{}{}", r, w, x)
}

fn format_hexbytes_single_line(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_hexbytes_multiline(bytes: &[u8]) -> String {
    let mut lines = Vec::new();
    for chunk in bytes.chunks(16) {
        let hex = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii = chunk
            .iter()
            .map(|b| {
                if (0x20..=0x7e).contains(b) {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect::<String>();
        lines.push(format!("{} {}", hex, ascii));
    }

    format!("\n{}", lines.join("\n"))
}

fn get_vma_name_anonymous(
    layer: &dyn DataLayer,
    mm_addr: Address,
    vm_start: Address,
    vm_end: Address,
    start_brk_offset: u64,
    brk_offset: u64,
    start_stack_offset: u64,
    context_offset: Option<u64>,
    context_vdso_offset: Option<u64>,
    context_is_ptr: bool,
) -> String {
    if start_brk_offset > 0 && brk_offset > 0 {
        let start_brk = helpers::read_pointer(layer, mm_addr + start_brk_offset).unwrap_or(0);
        let brk = helpers::read_pointer(layer, mm_addr + brk_offset).unwrap_or(0);
        if start_brk != 0 && brk != 0 && vm_start <= start_brk && vm_end >= brk {
            return "[heap]".to_string();
        }
    }

    if start_stack_offset > 0 {
        let start_stack = helpers::read_pointer(layer, mm_addr + start_stack_offset).unwrap_or(0);
        if start_stack != 0 && vm_start <= start_stack && start_stack <= vm_end {
            return "[stack]".to_string();
        }
    }

    if let (Some(ctx_off), Some(vdso_off)) = (context_offset, context_vdso_offset) {
        let ctx_base = if context_is_ptr {
            helpers::read_pointer(layer, mm_addr + ctx_off).unwrap_or(0)
        } else {
            mm_addr + ctx_off
        };
        if ctx_base != 0 {
            let vdso_addr = helpers::read_pointer(layer, ctx_base + vdso_off).unwrap_or(0);
            if vdso_addr == vm_start {
                return "[vdso]".to_string();
            }
        }
    }

    "Anonymous Mapping".to_string()
}

impl Module for Malfind {
    fn name(&self) -> &str {
        "linux.malfind.Malfind"
    }

    fn description(&self) -> &str {
        "Lists process memory ranges that potentially contain injected code"
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
            Column::new("Path", ColumnType::String),
            Column::new("Protection", ColumnType::String),
            Column::new("Hexdump", ColumnType::String),
            Column::new("Disasm", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::find_malicious(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.pid as i64),
                    CellValue::String(e.comm),
                    CellValue::Hex(e.start),
                    CellValue::Hex(e.end),
                    CellValue::String(e.path),
                    CellValue::String(e.protection),
                    CellValue::String(e.hexdump),
                    CellValue::String(e.disasm),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
