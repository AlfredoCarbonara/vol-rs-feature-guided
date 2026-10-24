//! Windows service-record scanner for Windows 10/11 x64.
//!
//! Service headers are located by their `serH` pool tag in physical memory,
//! then decoded through the `services.exe` process page table using the
//! version-appropriate Volatility services ISF.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use vol3_core::error::{ConfigError, LayerError, PluginError, Vol3Error, Vol3Result};
use vol3_core::types::{AbsentValue, Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::intel::Intel32e;
use vol3_layers::scanner::ByteScanner;
use vol3_layers::traits::DataLayer;
use vol3_symbols::{IntermediateSymbolTable, SymbolTableInterface};

use crate::layout::EprocessLayout;
use crate::pslist::PsList;
use crate::reader::{read_u64, read_unsigned};
use crate::service_layout::ServiceLayout;

const SERVICE_TABLE: &str = "services_symbols";
const KERNEL_TABLE: &str = "nt_symbols";
// Match Volatility's service extension string casts (max_length=512). Reading
// more bytes can cross an unavailable page and turn a valid BinaryPath into
// an unreadable value on otherwise equivalent service records.
const MAX_STRING_BYTES: usize = 512;
const MAX_CHAIN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInfo {
    pub offset: Address,
    pub order: u64,
    pub pid: Option<u64>,
    pub start: String,
    pub state: String,
    pub service_type: String,
    pub name: Option<String>,
    pub display: Option<String>,
    pub binary: Option<String>,
}

pub struct SvcScan;

impl SvcScan {
    pub fn new() -> Self {
        Self
    }

    pub fn scan_services(context: &Context) -> Vol3Result<Vec<ServiceInfo>> {
        ensure_service_symbols(context)?;
        let kernel_layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".into())))?;
        let physical_layer_name = context
            .config_get_string("physical")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("physical".into())))?;
        let kernel_layer = context
            .get_layer(&kernel_layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(kernel_layer_name.clone())))?;
        let physical_layer = context
            .get_layer(&physical_layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(physical_layer_name.clone())))?;
        let eprocess = EprocessLayout::from_context(context, KERNEL_TABLE)?;
        let (dtb_offset, dtb_size) = eprocess.directory_table_base.ok_or_else(|| {
            plugin_error("_KPROCESS.DirectoryTableBase is absent from the kernel ISF")
        })?;
        let services_process = PsList::list_processes(context)?
            .into_iter()
            .find(|process| process.image_file_name.eq_ignore_ascii_case("services.exe"))
            .ok_or_else(|| plugin_error("services.exe was not found in PsList"))?;
        let dtb = read_unsigned(
            kernel_layer.as_ref(),
            services_process.eprocess + dtb_offset as u64,
            dtb_size,
        )? & !0xfff;
        if dtb == 0 {
            return Err(plugin_error("services.exe has an invalid zero DTB"));
        }
        let process_layer = Intel32e::new_windows(
            format!("services_process_{}", services_process.pid),
            physical_layer.clone(),
            dtb,
            0,
        );
        let layout = ServiceLayout::from_context(context, SERVICE_TABLE)?;
        let service_table = context
            .get_symbol_table(SERVICE_TABLE)
            .ok_or_else(|| plugin_error("Services symbol table was not loaded"))?;

        let scanner = ByteScanner::new(b"serH".to_vec());
        let matches = physical_layer.scan(&scanner, None, None);
        let mut records: HashMap<Address, ServiceInfo> = HashMap::new();
        for (tag_address, _) in matches {
            if tag_address % 8 != 0 {
                continue;
            }
            let pointer_address = tag_address
                .wrapping_sub(layout.header_tag as u64)
                .wrapping_add(layout.header_record as u64);
            let Ok(first_record) = read_u64(physical_layer.as_ref(), pointer_address) else {
                continue;
            };
            if first_record == 0 || first_record >= 0x0000_8000_0000_0000 {
                continue;
            }
            traverse_chain(
                &process_layer,
                &layout,
                service_table.as_ref(),
                first_record,
                &mut records,
            );
        }
        let mut output: Vec<_> = records.into_values().collect();
        output.sort_by_key(|record| (std::cmp::Reverse(record.order), record.offset));
        Ok(output)
    }
}

impl Default for SvcScan {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for SvcScan {
    fn name(&self) -> &str {
        "windows.svcscan.SvcScan"
    }

    fn description(&self) -> &str {
        "Scans services.exe memory for Windows service records"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Windows kernel virtual memory layer")
            .symbol_table("nt_symbols", "Windows kernel ISF")
            .string(
                "service_symbols",
                "Windows services ISF for the target build",
            )
            .build();
        ModuleRequirements {
            name: self.name().into(),
            description: self.description().into(),
            requirements,
        }
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::Hex),
            Column::new("Order", ColumnType::Int),
            Column::new("PID", ColumnType::Int),
            Column::new("Start", ColumnType::String),
            Column::new("State", ColumnType::String),
            Column::new("Type", ColumnType::String),
            Column::new("Name", ColumnType::String),
            Column::new("Display", ColumnType::String),
            Column::new("Binary", ColumnType::String),
            Column::new("Binary (Registry)", ColumnType::String),
            Column::new("Dll", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let rows: Vec<Vol3Result<Row>> = Self::scan_services(&context)?
            .into_iter()
            .map(|record| {
                Ok(vec![
                    CellValue::Hex(record.offset),
                    CellValue::UInt(record.order),
                    optional_uint(record.pid),
                    CellValue::String(record.start),
                    CellValue::String(record.state),
                    CellValue::String(record.service_type),
                    optional_string(record.name),
                    optional_string(record.display),
                    optional_string(record.binary),
                    CellValue::Absent(AbsentValue::NotAvailable),
                    CellValue::Absent(AbsentValue::NotAvailable),
                ])
            })
            .collect();
        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["windows"]
    }
}

fn ensure_service_symbols(context: &Context) -> Vol3Result<()> {
    if context.has_symbol_table(SERVICE_TABLE) {
        return Ok(());
    }
    let path = context
        .config_get_string("plugins.windows.svcscan.service_symbols")
        .ok_or_else(|| {
            Vol3Error::Config(ConfigError::KeyNotFound(
                "plugins.windows.svcscan.service_symbols".into(),
            ))
        })?;
    let table = IntermediateSymbolTable::from_path(Path::new(&path), SERVICE_TABLE)?;
    context.add_symbol_table(Arc::new(table));
    Ok(())
}

fn traverse_chain(
    layer: &dyn DataLayer,
    layout: &ServiceLayout,
    symbols: &dyn SymbolTableInterface,
    first: Address,
    output: &mut HashMap<Address, ServiceInfo>,
) {
    let mut current = first;
    let mut local_seen = HashSet::new();
    for _ in 0..MAX_CHAIN {
        if current == 0 || !local_seen.insert(current) {
            break;
        }
        let Some(record) = decode_record(layer, layout, symbols, current) else {
            break;
        };
        let Ok(previous) = read_u64(layer, current + layout.prev_entry as u64) else {
            break;
        };
        output.entry(current).or_insert(record);
        current = previous;
    }
}

fn decode_record(
    layer: &dyn DataLayer,
    layout: &ServiceLayout,
    symbols: &dyn SymbolTableInterface,
    address: Address,
) -> Option<ServiceInfo> {
    let required = layout
        .record_size
        .max(layout.process_or_driver + 8)
        .max(layout.state + 4);
    let bytes = layer.read(address, required, false).ok()?;
    let integer = |offset: usize| -> Option<u64> {
        let data = bytes.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(data.try_into().ok()?) as u64)
    };
    let pointer = |offset: usize| -> Option<u64> {
        let data = bytes.get(offset..offset + 8)?;
        Some(u64::from_le_bytes(data.try_into().ok()?))
    };
    let order = integer(layout.order)?;
    let start_value = integer(layout.start)? as i64;
    let state_value = integer(layout.state)? as i64;
    if order > 0xffff || !(0..=4).contains(&start_value) || !(1..=7).contains(&state_value) {
        return None;
    }
    let service_type_value = integer(layout.service_type)?;
    let name = read_utf16_pointer(layer, pointer(layout.service_name)?);
    if name
        .as_deref()
        .map(|value| value.is_empty())
        .unwrap_or(true)
    {
        return None;
    }
    let display = read_utf16_pointer(layer, pointer(layout.display_name)?);
    let state = enum_name(symbols, "StateEnum", state_value)?;
    let start = enum_name(symbols, "StartEnum", start_value)?;
    let service_type = service_type_description(service_type_value);
    if service_type.is_empty() {
        return None;
    }
    let process_or_driver = pointer(layout.process_or_driver)?;
    let running = state == "SERVICE_RUNNING";
    let process_service = service_type.contains("PROCESS");
    let (pid, binary) = if running && process_or_driver != 0 && process_service {
        (
            read_unsigned(layer, process_or_driver + layout.process_id as u64, 4).ok(),
            read_u64(layer, process_or_driver + layout.process_binary_path as u64)
                .ok()
                .and_then(|pointer| read_utf16_pointer(layer, pointer)),
        )
    } else if running && process_or_driver != 0 {
        (None, read_utf16_pointer(layer, process_or_driver))
    } else {
        (None, None)
    };
    Some(ServiceInfo {
        offset: address,
        order,
        pid,
        start,
        state,
        service_type,
        name,
        display,
        binary,
    })
}

fn enum_name(symbols: &dyn SymbolTableInterface, name: &str, value: i64) -> Option<String> {
    symbols
        .get_enumeration(name)
        .ok()?
        .get_name(value)
        .map(str::to_string)
}

fn service_type_description(value: u64) -> String {
    const FLAGS: [(&str, u64); 7] = [
        ("SERVICE_KERNEL_DRIVER", 1),
        ("SERVICE_FILE_SYSTEM_DRIVER", 2),
        ("SERVICE_ADAPTOR", 4),
        ("SERVICE_RECOGNIZER_DRIVER", 8),
        ("SERVICE_WIN32_OWN_PROCESS", 16),
        ("SERVICE_WIN32_SHARE_PROCESS", 32),
        ("SERVICE_INTERACTIVE_PROCESS", 256),
    ];
    FLAGS
        .iter()
        .filter(|(_, flag)| value & flag != 0)
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join("|")
}

fn read_utf16_pointer(layer: &dyn DataLayer, pointer: Address) -> Option<String> {
    if pointer == 0 || pointer >= 0x0000_8000_0000_0000 {
        return None;
    }
    let bytes = layer.read(pointer, MAX_STRING_BYTES, false).ok()?;
    let mut units = Vec::new();
    for pair in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    if units.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&units))
    }
}

fn optional_uint(value: Option<u64>) -> CellValue {
    value
        .map(CellValue::UInt)
        .unwrap_or(CellValue::Absent(AbsentValue::NotApplicable))
}

fn optional_string(value: Option<String>) -> CellValue {
    value
        .map(CellValue::String)
        .unwrap_or(CellValue::Absent(AbsentValue::NotAvailable))
}

fn plugin_error(message: impl Into<String>) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_service_type_flags_in_volatility_order() {
        assert_eq!(
            service_type_description(16 | 32 | 256),
            "SERVICE_WIN32_OWN_PROCESS|SERVICE_WIN32_SHARE_PROCESS|SERVICE_INTERACTIVE_PROCESS"
        );
    }
}
