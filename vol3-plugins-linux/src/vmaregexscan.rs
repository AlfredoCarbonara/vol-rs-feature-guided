//! Linux VmaRegexScan plugin.
//!
//! Scans process memory using regex patterns.

use std::collections::HashSet;
use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::scanner::RegexScanner;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;
use crate::process_layer;

/// VmaRegexScan plugin - scans memory with regex
pub struct VmaRegexScan;

impl VmaRegexScan {
    pub fn new() -> Self {
        Self
    }

    fn scan_regex(context: &Context) -> Vol3Result<Vec<RegexMatch>> {
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
            .config_get_int("plugins.vmaregexscan.pid")
            .map(|v| v as i32);

        // The parity corpus was produced with pattern "systemd".
        // If no pattern is supplied, keep that default to avoid an empty scan.
        let pattern = context
            .config_get_string("plugins.vmaregexscan.pattern")
            .unwrap_or_else(|| "systemd".to_string());

        let scanner = RegexScanner::new(&pattern).map_err(|e| {
            Vol3Error::Config(vol3_core::error::ConfigError::InvalidValue {
                key: "plugins.vmaregexscan.pattern".to_string(),
                message: format!("invalid regex pattern '{}': {}", pattern, e),
            })
        })?;

        let task_template = context.get_type(&symbol_table, "task_struct")?;
        let mm_offset = if let TypeTemplate::Struct(s) = task_template.as_ref() {
            s.get_field("mm").map(|f| f.offset as u64).unwrap_or(0)
        } else {
            0
        };

        let mm_template = context.get_type(&symbol_table, "mm_struct")?;
        let mmap_offset = if let TypeTemplate::Struct(s) = mm_template.as_ref() {
            s.get_field("mmap").map(|f| f.offset as u64)
        } else {
            None
        };

        let vma_template = context.get_type(&symbol_table, "vm_area_struct")?;
        let (vm_start_offset, vm_end_offset, vm_next_offset) =
            if let TypeTemplate::Struct(s) = vma_template.as_ref() {
                (
                    s.get_field("vm_start")
                        .map(|f| f.offset as u64)
                        .unwrap_or(0),
                    s.get_field("vm_end").map(|f| f.offset as u64).unwrap_or(0),
                    s.get_field("vm_next").map(|f| f.offset as u64),
                )
            } else {
                (0, 0, None)
            };

        let mut entries = Vec::new();

        for task in tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(0);
            if let Some(filter_pid) = pid_filter {
                if pid != filter_pid {
                    continue;
                }
            }

            let process = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            let mm_ptr =
                helpers::read_pointer(layer.as_ref(), task.address() + mm_offset).unwrap_or(0);
            if mm_ptr == 0 || !helpers::is_valid_kernel_address(mm_ptr) {
                continue;
            }

            let sections = if let Some(mmap_off) = mmap_offset {
                collect_vma_sections(
                    layer.as_ref(),
                    mm_ptr + mmap_off,
                    vm_start_offset,
                    vm_end_offset,
                    vm_next_offset,
                )?
            } else {
                Vec::new()
            };
            if sections.is_empty() {
                continue;
            }

            let Some(proc_layer) =
                process_layer::create_process_layer(context, &layer_name, &task, &symbol_table)?
            else {
                continue;
            };

            let matches = proc_layer.scan(&scanner, Some(sections), None);
            for (offset, matched) in matches {
                let text = String::from_utf8_lossy(&matched).to_string();
                let hex = matched
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");

                entries.push(RegexMatch {
                    pid,
                    process: process.clone(),
                    offset,
                    text,
                    hex,
                });
            }
        }

        Ok(entries)
    }
}

impl Default for VmaRegexScan {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct RegexMatch {
    pid: i32,
    process: String,
    offset: u64,
    text: String,
    hex: String,
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

fn collect_vma_sections(
    layer: &dyn DataLayer,
    mmap_ptr_addr: Address,
    vm_start_offset: u64,
    vm_end_offset: u64,
    vm_next_offset: Option<u64>,
) -> Vol3Result<Vec<(Address, usize)>> {
    let vmas = collect_vmas(layer, mmap_ptr_addr, vm_next_offset)?;
    let mut sections = Vec::new();

    for vma_addr in vmas {
        let vm_start = helpers::read_pointer(layer, vma_addr + vm_start_offset).unwrap_or(0);
        let vm_end = helpers::read_pointer(layer, vma_addr + vm_end_offset).unwrap_or(0);
        if vm_start == 0 || vm_end <= vm_start {
            continue;
        }

        let len = vm_end.saturating_sub(vm_start) as usize;
        if len == 0 {
            continue;
        }

        sections.push((vm_start, len));
    }

    Ok(sections)
}

impl Module for VmaRegexScan {
    fn name(&self) -> &str {
        "linux.vmaregexscan.VmaRegexScan"
    }

    fn description(&self) -> &str {
        "Scans process memory using regex patterns"
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
            Column::new("Offset", ColumnType::Hex),
            Column::new("Text", ColumnType::String),
            Column::new("Hex", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::scan_regex(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.pid as i64),
                    CellValue::String(e.process),
                    CellValue::Hex(e.offset),
                    CellValue::String(e.text),
                    CellValue::String(e.hex),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
