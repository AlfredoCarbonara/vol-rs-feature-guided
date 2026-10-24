//! Linux CheckSyscall plugin.
//!
//! Checks the system call table for hooks.

use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;

/// CheckSyscall plugin - checks syscall table for hooks
pub struct CheckSyscall;

impl CheckSyscall {
    pub fn new() -> Self {
        Self
    }

    fn check_syscall(context: &Context) -> Vol3Result<Vec<SyscallEntry>> {
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

        let symbols = context.get_symbol_table(&symbol_table).ok_or_else(|| {
            Vol3Error::Config(ConfigError::KeyNotFound("symbol_table".to_string()))
        })?;

        let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;

        // Determine pointer size (default 8 for 64-bit)
        let ptr_sz = 8usize;

        let mut entries = Vec::new();

        // Get main syscall table - keep both display and read addresses
        // display_addr is the symbol address (for output, matching Python)
        // read_addr is display_addr + aslr_shift (for memory reads)
        let (sys_call_table_display, sys_call_table_read) =
            match context.get_symbol(&symbol_table, "sys_call_table") {
                Ok(sym) => (sym.address, sym.address + aslr_shift),
                Err(_) => return Ok(entries), // No syscall table found
            };

        // Get syscall_meta count - count symbols starting with "__syscall_meta__"
        let syscall_meta_count = symbols
            .symbols()
            .filter(|name| name.starts_with("__syscall_meta__"))
            .count();

        // Determine table size from next symbol
        let table_size_next_sym = {
            // Get next symbol after sys_call_table to determine size
            let base_addr = sys_call_table_display;
            let mut next_sym_addr = u64::MAX;

            // Iterate through symbol table to find next symbol
            for sym_name in symbols.symbols() {
                if let Ok(sym) = symbols.get_symbol(sym_name) {
                    if sym.address > base_addr && sym.address < next_sym_addr {
                        next_sym_addr = sym.address;
                    }
                }
            }

            if next_sym_addr != u64::MAX {
                ((next_sym_addr - base_addr) / ptr_sz as u64) as usize
            } else {
                0
            }
        };

        // Take minimum of available size methods, like Python does
        let table_size = {
            let sizes: Vec<usize> = [syscall_meta_count, table_size_next_sym]
                .into_iter()
                .filter(|&s| s > 0)
                .collect();
            if sizes.is_empty() {
                512 // Default fallback
            } else {
                *sizes.iter().min().unwrap()
            }
        };

        let table_name = "64bit";

        // Read syscall table entries
        for i in 0..table_size {
            let entry_addr = sys_call_table_read + (i * ptr_sz) as u64;
            if let Ok(data) = layer.read(entry_addr, ptr_sz, false) {
                if data.len() < ptr_sz {
                    continue;
                }
                let handler_addr = LittleEndian::read_u64(&data);

                // Look up symbol name for handler - subtract ASLR shift to get symbol address
                let handler_symbol = {
                    let lookup_addr = handler_addr.saturating_sub(aslr_shift);
                    symbols
                        .get_symbol_by_address(lookup_addr)
                        .map(|(name, _)| name)
                        .unwrap_or_else(|| "UNKNOWN".to_string())
                };

                // Apply address mask (48-bit) for display parity with Python
                const ADDRESS_MASK: u64 = 0x0000ffffffffffff;

                entries.push(SyscallEntry {
                    table_address: sys_call_table_display & ADDRESS_MASK,
                    table_name: table_name.to_string(),
                    index: i as u32,
                    handler_address: handler_addr & ADDRESS_MASK,
                    handler_symbol,
                });
            }
        }

        // Also check ia32_sys_call_table on 64-bit systems
        if let Ok(ia32_sym) = context.get_symbol(&symbol_table, "ia32_sys_call_table") {
            let ia32_table_display = ia32_sym.address;
            let ia32_table_read = ia32_sym.address + aslr_shift;

            // Get size for ia32 table - also use min of next symbol and meta count
            let ia32_size_next_sym = {
                let base_addr = ia32_table_display;
                let mut next_sym_addr = u64::MAX;

                for sym_name in symbols.symbols() {
                    if let Ok(sym) = symbols.get_symbol(sym_name) {
                        if sym.address > base_addr && sym.address < next_sym_addr {
                            next_sym_addr = sym.address;
                        }
                    }
                }

                if next_sym_addr != u64::MAX {
                    ((next_sym_addr - base_addr) / ptr_sz as u64) as usize
                } else {
                    0
                }
            };

            // Use same approach - min of available sizes
            let ia32_size = {
                let sizes: Vec<usize> = [syscall_meta_count, ia32_size_next_sym]
                    .into_iter()
                    .filter(|&s| s > 0)
                    .collect();
                if sizes.is_empty() {
                    512
                } else {
                    *sizes.iter().min().unwrap()
                }
            };

            for i in 0..ia32_size {
                let entry_addr = ia32_table_read + (i * ptr_sz) as u64;
                if let Ok(data) = layer.read(entry_addr, ptr_sz, false) {
                    if data.len() < ptr_sz {
                        continue;
                    }
                    let handler_addr = LittleEndian::read_u64(&data);

                    let handler_symbol = {
                        let lookup_addr = handler_addr.saturating_sub(aslr_shift);
                        symbols
                            .get_symbol_by_address(lookup_addr)
                            .map(|(name, _)| name)
                            .unwrap_or_else(|| "UNKNOWN".to_string())
                    };

                    // Apply address mask (48-bit) for display parity with Python
                    const ADDRESS_MASK: u64 = 0x0000ffffffffffff;

                    entries.push(SyscallEntry {
                        table_address: ia32_table_display & ADDRESS_MASK,
                        table_name: "32bit".to_string(),
                        index: i as u32,
                        handler_address: handler_addr & ADDRESS_MASK,
                        handler_symbol,
                    });
                }
            }
        }

        Ok(entries)
    }
}

impl Default for CheckSyscall {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct SyscallEntry {
    table_address: u64,
    table_name: String,
    index: u32,
    handler_address: u64,
    handler_symbol: String,
}

impl Module for CheckSyscall {
    fn name(&self) -> &str {
        "linux.check_syscall.CheckSyscall"
    }

    fn description(&self) -> &str {
        "Checks system call table for hooks"
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
            Column::new("Table Address", ColumnType::Hex),
            Column::new("Table Name", ColumnType::String),
            Column::new("Index", ColumnType::Int),
            Column::new("Handler Address", ColumnType::Hex),
            Column::new("Handler Symbol", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::check_syscall(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Hex(e.table_address),
                    CellValue::String(e.table_name),
                    CellValue::Int(e.index as i64),
                    CellValue::Hex(e.handler_address),
                    CellValue::String(e.handler_symbol),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
