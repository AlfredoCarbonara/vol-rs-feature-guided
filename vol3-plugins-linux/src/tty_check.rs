//! Linux TtyCheck plugin.
//!
//! Checks TTY device handlers for hooks.

use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::helpers;

/// TtyCheck plugin - checks TTY handlers
pub struct TtyCheck;

impl TtyCheck {
    pub fn new() -> Self {
        Self
    }

    fn check_tty(context: &Context) -> Vol3Result<Vec<TtyEntry>> {
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

        let mut entries = Vec::new();

        // Get tty_drivers list head
        let tty_drivers_sym = context
            .get_symbol(&symbol_table, "tty_drivers")
            .map_err(|_| {
                Vol3Error::Config(ConfigError::KeyNotFound("tty_drivers symbol".to_string()))
            })?;
        let tty_drivers_addr = tty_drivers_sym.address + aslr_shift;

        // Get required types
        let tty_driver_type = context.get_type(&symbol_table, "tty_driver").map_err(|_| {
            Vol3Error::Config(ConfigError::KeyNotFound("tty_driver type".to_string()))
        })?;

        let tty_struct_type = context.get_type(&symbol_table, "tty_struct").map_err(|_| {
            Vol3Error::Config(ConfigError::KeyNotFound("tty_struct type".to_string()))
        })?;

        // Get field offsets
        let tty_drivers_offset =
            helpers::get_field_offset(&tty_driver_type, "tty_drivers").unwrap_or(0) as u64;
        let ttys_offset = helpers::get_field_offset(&tty_driver_type, "ttys").unwrap_or(0) as u64;
        let num_offset = helpers::get_field_offset(&tty_driver_type, "num").unwrap_or(0) as u64;

        let name_offset = helpers::get_field_offset(&tty_struct_type, "name").unwrap_or(0) as u64;
        let ldisc_offset = helpers::get_field_offset(&tty_struct_type, "ldisc").unwrap_or(0) as u64;

        // Get tty_ldisc and tty_ldisc_ops offsets
        let ops_offset = context
            .get_type(&symbol_table, "tty_ldisc")
            .ok()
            .and_then(|t| helpers::get_field_offset(&t, "ops"))
            .unwrap_or(0) as u64;

        let receive_buf_offset = context
            .get_type(&symbol_table, "tty_ldisc_ops")
            .ok()
            .and_then(|t| helpers::get_field_offset(&t, "receive_buf"))
            .unwrap_or(0) as u64;

        // Iterate tty_drivers list
        let ptr_sz = 8usize;

        // Read first list entry (next pointer from list_head)
        if let Ok(data) = layer.read(tty_drivers_addr, ptr_sz, false) {
            if data.len() < ptr_sz {
                return Ok(entries);
            }
            let mut current = LittleEndian::read_u64(&data);

            // Walk the list (max 100 entries to prevent infinite loops)
            for _ in 0..100 {
                if current == tty_drivers_addr || current == 0 {
                    break;
                }

                // Get tty_driver from list entry
                let tty_driver_addr = current.saturating_sub(tty_drivers_offset);

                // Read number of ttys
                if let Ok(num_data) = layer.read(tty_driver_addr + num_offset, 4, false) {
                    if num_data.len() < 4 {
                        continue;
                    }
                    let num_ttys = LittleEndian::read_u32(&num_data) as usize;

                    // Read ttys array pointer
                    if let Ok(ttys_ptr_data) =
                        layer.read(tty_driver_addr + ttys_offset, ptr_sz, false)
                    {
                        if ttys_ptr_data.len() < ptr_sz {
                            continue;
                        }
                        let ttys_array_ptr = LittleEndian::read_u64(&ttys_ptr_data);

                        if ttys_array_ptr != 0 {
                            // Iterate through ttys array (array of pointers)
                            for i in 0..num_ttys.min(256) {
                                if let Ok(tty_ptr_data) =
                                    layer.read(ttys_array_ptr + (i * ptr_sz) as u64, ptr_sz, false)
                                {
                                    if tty_ptr_data.len() < ptr_sz {
                                        continue;
                                    }
                                    let tty_dev_addr = LittleEndian::read_u64(&tty_ptr_data);

                                    if tty_dev_addr == 0 {
                                        continue;
                                    }

                                    // Read tty name
                                    let name = if let Ok(name_data) =
                                        layer.read(tty_dev_addr + name_offset, 64, false)
                                    {
                                        helpers::read_cstring(&name_data)
                                    } else {
                                        "".to_string()
                                    };

                                    // Read ldisc pointer
                                    if let Ok(ldisc_data) =
                                        layer.read(tty_dev_addr + ldisc_offset, ptr_sz, false)
                                    {
                                        if ldisc_data.len() < ptr_sz {
                                            continue;
                                        }
                                        let ldisc_addr = LittleEndian::read_u64(&ldisc_data);

                                        if ldisc_addr != 0 {
                                            // Read ops pointer
                                            if let Ok(ops_data) =
                                                layer.read(ldisc_addr + ops_offset, ptr_sz, false)
                                            {
                                                if ops_data.len() < ptr_sz {
                                                    continue;
                                                }
                                                let ops_addr = LittleEndian::read_u64(&ops_data);

                                                if ops_addr != 0 {
                                                    // Read receive_buf function pointer
                                                    if let Ok(recv_buf_data) = layer.read(
                                                        ops_addr + receive_buf_offset,
                                                        ptr_sz,
                                                        false,
                                                    ) {
                                                        if recv_buf_data.len() < ptr_sz {
                                                            continue;
                                                        }
                                                        let recv_buf =
                                                            LittleEndian::read_u64(&recv_buf_data);

                                                        if recv_buf != 0 {
                                                            // Apply 48-bit address mask to match Python
                                                            const ADDRESS_MASK: u64 =
                                                                0x0000ffffffffffff;
                                                            let masked_addr =
                                                                recv_buf & ADDRESS_MASK;

                                                            // Look up symbol
                                                            let symbol_name = symbols
                                                                .get_symbol_by_address(
                                                                    recv_buf
                                                                        .saturating_sub(aslr_shift),
                                                                )
                                                                .map(|(name, _)| name)
                                                                .unwrap_or_else(|| {
                                                                    "UNKNOWN".to_string()
                                                                });

                                                            // Python uses "__kernel__" for kernel symbols
                                                            entries.push(TtyEntry {
                                                                name,
                                                                address: masked_addr,
                                                                module: "__kernel__".to_string(),
                                                                symbol: symbol_name,
                                                            });
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Move to next in list
                if let Ok(next_data) = layer.read(current, ptr_sz, false) {
                    if next_data.len() < ptr_sz {
                        break;
                    }
                    current = LittleEndian::read_u64(&next_data);
                } else {
                    break;
                }
            }
        }

        Ok(entries)
    }
}

impl Default for TtyCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct TtyEntry {
    name: String,
    address: u64,
    module: String,
    symbol: String,
}

impl Module for TtyCheck {
    fn name(&self) -> &str {
        "linux.tty_check.TtyCheck"
    }

    fn description(&self) -> &str {
        "Checks TTY device handlers for hooks"
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
            Column::new("Name", ColumnType::String),
            Column::new("Address", ColumnType::Hex),
            Column::new("Module", ColumnType::String),
            Column::new("Symbol", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::check_tty(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::String(e.name),
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
