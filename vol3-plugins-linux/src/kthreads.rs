//! Linux Kthreads plugin.
//!
//! Lists kernel threads.

use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

use crate::extensions::TaskStructExt;
use crate::helpers;
use crate::lsmod;

/// Module address range for lookup
#[derive(Debug, Clone)]
struct ModuleRange {
    name: String,
    start: u64,
    end: u64,
}

/// Kthreads plugin - lists kernel threads
pub struct Kthreads;

impl Kthreads {
    pub fn new() -> Self {
        Self
    }

    /// Get list of modules with their address ranges
    fn get_module_ranges(context: &Context) -> Vol3Result<Vec<ModuleRange>> {
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

        // Get modules from lsmod
        let modules_head = lsmod::Lsmod::get_modules_head(context, &symbol_table)?;
        let list_offset = lsmod::Lsmod::get_list_offset(context, &symbol_table)?;

        // Get module struct offsets
        let module_template = context.get_type(&symbol_table, "module")?;
        let name_offset = helpers::get_field_offset(&module_template, "name").unwrap_or(0) as u64;

        // Get base and size - try core_layout.base + core_layout.size first
        let (base_offset, size_offset) = if let Some(core_layout_off) =
            helpers::get_field_offset(&module_template, "core_layout")
        {
            // Get module_layout struct
            if let Ok(layout_template) = context.get_type(&symbol_table, "module_layout") {
                let base_off = helpers::get_field_offset(&layout_template, "base").unwrap_or(0);
                let size_off = helpers::get_field_offset(&layout_template, "size").unwrap_or(8);
                (core_layout_off + base_off, core_layout_off + size_off)
            } else {
                // Fallback: base is at offset 0, size at 8 within core_layout
                (core_layout_off, core_layout_off + 8)
            }
        } else {
            // Older kernels: module_core + core_size
            let base = helpers::get_field_offset(&module_template, "module_core").unwrap_or(0);
            let size = helpers::get_field_offset(&module_template, "core_size").unwrap_or(0);
            (base, size)
        };

        let address_mask: u64 = 0x0000_FFFF_FFFF_FFFF;
        let mut ranges = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let first = helpers::read_pointer(layer.as_ref(), modules_head)? & address_mask;
        if first == 0 || first == (modules_head & address_mask) {
            return Ok(ranges);
        }

        let mut current = first;

        while current != 0 && current != (modules_head & address_mask) && !seen.contains(&current) {
            seen.insert(current);
            let module_addr = (current.saturating_sub(list_offset as u64)) & address_mask;

            // Read name
            let name = helpers::read_string(layer.as_ref(), module_addr + name_offset, 64)?;

            // Read base address
            let base = if let Ok(data) = layer.read(module_addr + base_offset as u64, 8, false) {
                if data.len() >= 8 {
                    LittleEndian::read_u64(&data) & address_mask
                } else {
                    0
                }
            } else {
                0
            };

            // Read size (u32)
            let size = if let Ok(data) = layer.read(module_addr + size_offset as u64, 4, false) {
                if data.len() >= 4 {
                    LittleEndian::read_u32(&data) as u64
                } else {
                    0
                }
            } else {
                0
            };

            if !name.is_empty() && base != 0 && size != 0 {
                ranges.push(ModuleRange {
                    name,
                    start: base,
                    end: base + size,
                });
            }

            current = helpers::read_pointer(layer.as_ref(), current)? & address_mask;
        }

        Ok(ranges)
    }

    /// Look up which module contains an address
    fn lookup_module(modules: &[ModuleRange], address: u64) -> Option<&ModuleRange> {
        let masked = address & 0x0000_FFFF_FFFF_FFFF;
        modules.iter().find(|m| m.start <= masked && masked < m.end)
    }

    fn list_kthreads(context: &Context) -> Vol3Result<Vec<KthreadEntry>> {
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

        let symbols = context.get_symbol_table(&symbol_table);
        let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;

        // Get module ranges for lookup
        let module_ranges = Self::get_module_ranges(context).unwrap_or_default();

        let init_task_addr = helpers::get_init_task(context, &symbol_table)?;
        let template = helpers::get_task_struct_template(context, &symbol_table)?;
        let tasks = helpers::collect_processes(layer.as_ref(), init_task_addr, &template)?;

        // Get kthread type for reading threadfn
        let kthread_type = context.get_type(&symbol_table, "kthread").ok();
        let threadfn_offset = kthread_type
            .as_ref()
            .and_then(|t| helpers::get_field_offset(t, "threadfn"))
            .unwrap_or(0) as u64;

        // Check kernel version for worker_private vs set_child_tid
        let worker_private_offset = helpers::get_field_offset(&template, "worker_private");
        let set_child_tid_offset = helpers::get_field_offset(&template, "set_child_tid");
        let has_worker_private = worker_private_offset.is_some();

        let mut entries = Vec::new();

        for task in tasks {
            // Filter to kernel threads only (mm == NULL)
            let is_kthread = task.is_kernel_thread(layer.as_ref()).unwrap_or(false);
            if !is_kthread {
                continue;
            }

            let pid = task.pid(layer.as_ref()).unwrap_or(0);

            // Skip swapper (pid 0) and kthreadd (pid 2) - same as Python
            if pid == 0 || pid == 2 {
                continue;
            }

            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            // Get kthread struct pointer from worker_private (kernels >= 5.17)
            // or set_child_tid (kernels >= 5.8 < 5.17)
            let kthread_base_offset = if has_worker_private {
                worker_private_offset.unwrap_or(0) as u64
            } else {
                set_child_tid_offset.unwrap_or(0) as u64
            };

            let mut handler_address = 0u64;
            let mut module_name = String::new();
            let mut symbol = String::new();

            // Read kthread base pointer
            if let Ok(data) = layer.read(task.address() + kthread_base_offset, 8, false) {
                if data.len() >= 8 {
                    let kthread_ptr = LittleEndian::read_u64(&data);
                    if kthread_ptr != 0 {
                        // Read threadfn from kthread struct
                        if let Ok(fn_data) = layer.read(kthread_ptr + threadfn_offset, 8, false) {
                            if fn_data.len() >= 8 {
                                let threadfn = LittleEndian::read_u64(&fn_data);
                                if threadfn != 0 {
                                    // Apply 48-bit mask for display
                                    const ADDRESS_MASK: u64 = 0x0000ffffffffffff;
                                    handler_address = threadfn & ADDRESS_MASK;

                                    // First check if address is in any loaded module
                                    if let Some(module) =
                                        Self::lookup_module(&module_ranges, threadfn)
                                    {
                                        module_name = module.name.clone();
                                        // Don't look up symbol for module addresses
                                        symbol = "-".to_string();
                                    } else {
                                        // Look up symbol in kernel
                                        if let Some(ref syms) = symbols {
                                            if let Some((name, _)) = syms.get_symbol_by_address(
                                                threadfn.saturating_sub(aslr_shift),
                                            ) {
                                                symbol = name;
                                                module_name = "__kernel__".to_string();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            entries.push(KthreadEntry {
                tid: pid,
                thread_name: comm,
                handler_address,
                module_name,
                symbol,
            });
        }

        Ok(entries)
    }
}

impl Default for Kthreads {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct KthreadEntry {
    tid: i32,
    thread_name: String,
    handler_address: u64,
    module_name: String,
    symbol: String,
}

impl Module for Kthreads {
    fn name(&self) -> &str {
        "linux.kthreads.Kthreads"
    }

    fn description(&self) -> &str {
        "Lists kernel threads"
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
            Column::new("TID", ColumnType::Int),
            Column::new("Thread Name", ColumnType::String),
            Column::new("Handler Address", ColumnType::Hex),
            Column::new("Module", ColumnType::String),
            Column::new("Symbol", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_kthreads(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.tid as i64),
                    CellValue::String(e.thread_name),
                    CellValue::Hex(e.handler_address),
                    CellValue::String(e.module_name),
                    CellValue::String(e.symbol),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
