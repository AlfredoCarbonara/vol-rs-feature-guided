//! Linux CheckIdt plugin.
//!
//! Checks if the IDT has been altered.

use std::sync::Arc;

use log::debug;
use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;

/// CheckIdt plugin - checks IDT integrity
pub struct CheckIdt;

impl CheckIdt {
    pub fn new() -> Self {
        Self
    }

    fn check_idt(context: &Context) -> Vol3Result<Vec<IdtEntry>> {
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

        // Get idt_table symbol address
        let idt_table_addr = match context.get_symbol(&symbol_table, "idt_table") {
            Ok(sym) => {
                let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;
                debug!(
                    "idt_table symbol: addr={:#x}, aslr_shift={:#x}",
                    sym.address, aslr_shift
                );
                sym.address.wrapping_add(aslr_shift)
            }
            Err(e) => {
                debug!("Failed to get idt_table symbol: {:?}", e);
                return Ok(Vec::new());
            }
        };

        debug!("idt_table_addr (with ASLR): {:#x}", idt_table_addr);

        // Determine IDT entry type - try 64-bit types first
        let symbol_tbl = match context.get_symbol_table(&symbol_table) {
            Some(t) => t,
            None => {
                debug!("Failed to get symbol table {}", symbol_table);
                return Ok(Vec::new());
            }
        };

        let idt_type = if symbol_tbl.has_type("gate_struct64") {
            debug!("Using gate_struct64 type");
            "gate_struct64"
        } else if symbol_tbl.has_type("gate_struct") {
            debug!("Using gate_struct type");
            "gate_struct"
        } else if symbol_tbl.has_type("idt_desc") {
            debug!("Using idt_desc type");
            "idt_desc"
        } else {
            debug!("No IDT type found");
            return Ok(Vec::new());
        };

        // Get IDT entry size
        let entry_size = match symbol_tbl.get_type(idt_type) {
            Ok(template) => match template.size() {
                Some(sz) => {
                    debug!("{} size: {}", idt_type, sz);
                    sz as u64
                }
                None => {
                    debug!("Failed to get size for {}", idt_type);
                    return Ok(Vec::new());
                }
            },
            Err(_) => {
                debug!("Failed to get type {}", idt_type);
                return Ok(Vec::new());
            }
        };

        // Check indices: hardware handlers (0-19) + system call (128)
        let check_idxs: Vec<u32> = (0..20).chain(std::iter::once(128)).collect();

        let mut entries = Vec::new();
        let address_mask: u64 = 0x0000_FFFF_FFFF_FFFF; // 48-bit mask for display

        for idx in check_idxs {
            let entry_addr = idt_table_addr + (idx as u64 * entry_size);

            // Read IDT entry fields - get raw address first
            let raw_idt_addr = match read_idt_address(layer.as_ref(), entry_addr, idt_type) {
                Ok(addr) => {
                    debug!(
                        "IDT[{}]: entry_addr={:#x}, raw_addr={:#x}",
                        idx, entry_addr, addr
                    );
                    addr
                }
                Err(e) => {
                    debug!("Failed to read IDT[{}]: {:?}", idx, e);
                    continue;
                }
            };

            // Masked address for display
            let idt_addr = raw_idt_addr & address_mask;
            debug!("IDT[{}]: masked_addr={:#x}", idx, idt_addr);

            // For symbol lookup, we need to find the symbol at this address
            let (module, symbol) = if raw_idt_addr == 0 {
                // 0 means uninitialized
                ("N/A".to_string(), "N/A".to_string())
            } else {
                // Look up the symbol - subtract ASLR to get the ISF address
                // Use raw (unmasked) address for accurate calculation
                let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;
                let relative_addr = raw_idt_addr.wrapping_sub(aslr_shift);

                debug!(
                    "Symbol lookup: idt_addr={:#x}, aslr_shift={:#x}, relative={:#x}",
                    idt_addr, aslr_shift, relative_addr
                );

                // Check against kernel symbols
                let symbols = symbol_tbl.get_symbols_by_location(relative_addr, 0);

                if !symbols.is_empty() {
                    debug!("Found symbol by exact match: {}", symbols[0]);
                    ("__kernel__".to_string(), symbols[0].clone())
                } else {
                    // Try looking up with some tolerance for function entry points
                    let mut found_sym = None;
                    for sym_name in symbol_tbl.symbols() {
                        if let Ok(sym) = symbol_tbl.get_symbol(sym_name) {
                            // Check if our address is within a reasonable range of this symbol
                            if sym.address <= relative_addr && relative_addr < sym.address + 0x100 {
                                found_sym = Some(sym_name.to_string());
                                break;
                            }
                        }
                    }
                    if let Some(s) = found_sym {
                        debug!("Found symbol by range: {}", s);
                        ("__kernel__".to_string(), s)
                    } else {
                        debug!("No symbol found for {:#x}", relative_addr);
                        ("N/A".to_string(), "N/A".to_string())
                    }
                }
            };

            entries.push(IdtEntry {
                index: idx,
                address: idt_addr,
                module,
                symbol,
            });
        }

        Ok(entries)
    }
}

fn read_idt_address(layer: &dyn DataLayer, entry_addr: Address, idt_type: &str) -> Vol3Result<u64> {
    // For gate_struct64/gate_struct:
    // offset_low at offset 0 (u16)
    // offset_middle at offset 6 (u16)
    // offset_high at offset 8 (u32)

    let buf = layer.read(entry_addr, 16, false)?;

    let offset_low = u16::from_le_bytes([buf[0], buf[1]]) as u64;
    let offset_middle = u16::from_le_bytes([buf[6], buf[7]]) as u64;

    debug!("read_idt_address: buf={:02x?}", &buf[0..12]);
    debug!(
        "  offset_low={:#x}, offset_middle={:#x}",
        offset_low, offset_middle
    );

    let idt_addr =
        if idt_type == "gate_struct64" || idt_type == "gate_struct" || idt_type == "idt_desc" {
            let offset_high = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as u64;
            debug!("  offset_high={:#x}", offset_high);
            (offset_high << 32) | (offset_middle << 16) | offset_low
        } else {
            (offset_middle << 16) | offset_low
        };

    Ok(idt_addr)
}

impl Default for CheckIdt {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct IdtEntry {
    index: u32,
    address: u64,
    module: String,
    symbol: String,
}

impl Module for CheckIdt {
    fn name(&self) -> &str {
        "linux.check_idt.Check_idt"
    }

    fn description(&self) -> &str {
        "Checks if the IDT has been altered"
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
        // Match Python: Index, Address, Module, Symbol
        vec![
            Column::new("Index", ColumnType::Hex),
            Column::new("Address", ColumnType::Hex),
            Column::new("Module", ColumnType::String),
            Column::new("Symbol", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::check_idt(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Hex(e.index as u64),
                    CellValue::Hex(e.address),
                    CellValue::String(e.module),
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
