//! Windows Handles plugin.
//!
//! Enumerates `_HANDLE_TABLE_ENTRY` records for active processes and decodes
//! Windows 8+ object pointers, granted access, object-header cookies, and the
//! dynamic object-type table.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use log::{debug, warn};
use vol3_core::error::{ConfigError, LayerError, PluginError, Vol3Error, Vol3Result};
use vol3_core::types::{AbsentValue, Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;

use crate::handle_layout::{BitFieldLayout, HandleLayout, KeyNameLayout};
use crate::layout::EprocessLayout;
use crate::pslist::{ProcessInfo, PsList};
use crate::reader::{read_c_string, read_u64, read_unsigned};

const DEFAULT_SYMBOL_TABLE: &str = "nt_symbols";
const PAGE_SIZE: usize = 0x1000;
const POINTER_SIZE: usize = 8;
const HANDLE_MULTIPLIER: u64 = 4;
const LEVEL_MASK: u64 = 7;
const MAX_TABLE_LEVEL: u64 = 2;
const MAX_KEY_COMPONENTS: usize = 128;
const MAX_KEY_NAME_BYTES: usize = 0x1000;
const KEY_HIVE_ENTRY: u64 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleInfo {
    pub pid: u64,
    pub process: String,
    pub body: Address,
    pub handle_value: u64,
    pub object_type: String,
    pub granted_access: u64,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct RawHandle {
    header: Address,
    handle_value: u64,
    granted_access: u64,
}

struct DecodeContext<'a> {
    layer: &'a dyn DataLayer,
    layout: &'a HandleLayout,
    eprocess: &'a EprocessLayout,
    type_map: &'a HashMap<u8, String>,
    cookie: Option<u8>,
    info_mask_table: Option<Address>,
}

pub struct Handles;

impl Handles {
    pub fn new() -> Self {
        Self
    }

    pub fn list_handles(context: &Context) -> Vol3Result<Vec<HandleInfo>> {
        Self::list_handles_filtered(context, None)
    }

    fn list_handles_filtered(
        context: &Context,
        pid_filter: Option<u64>,
    ) -> Vol3Result<Vec<HandleInfo>> {
        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;
        let layer = context
            .get_layer(&layer_name)
            .ok_or(Vol3Error::Layer(LayerError::NotFound(layer_name)))?;
        let symbol_table = context
            .config_get_string("nt_symbols")
            .unwrap_or_else(|| DEFAULT_SYMBOL_TABLE.to_string());
        let kernel_base = context.config_get_int("kernel_virtual_offset").unwrap_or(0) as u64;

        let layout = HandleLayout::from_context(context, &symbol_table)?;
        let eprocess = EprocessLayout::from_context(context, &symbol_table)?;
        let object_table_offset = eprocess
            .object_table
            .ok_or_else(|| plugin_error("_EPROCESS.ObjectTable is missing from the Windows ISF"))?;
        let type_map = load_type_map(context, layer.as_ref(), &symbol_table, kernel_base, &layout)?;
        let cookie = context
            .get_symbol(&symbol_table, "ObHeaderCookie")
            .ok()
            .and_then(|symbol| {
                read_unsigned(layer.as_ref(), kernel_base.wrapping_add(symbol.address), 1)
                    .ok()
                    .map(|value| value as u8)
            });
        let info_mask_table = context
            .get_symbol(&symbol_table, "ObpInfoMaskToOffset")
            .ok()
            .map(|symbol| kernel_base.wrapping_add(symbol.address));

        let decode = DecodeContext {
            layer: layer.as_ref(),
            layout: &layout,
            eprocess: &eprocess,
            type_map: &type_map,
            cookie,
            info_mask_table,
        };
        let mut results = Vec::new();
        for process in PsList::list_processes(context)? {
            if pid_filter.map(|pid| process.pid != pid).unwrap_or(false) {
                continue;
            }
            let Ok(object_table) = read_u64(
                layer.as_ref(),
                process.eprocess + object_table_offset as u64,
            ) else {
                continue;
            };
            if object_table == 0 {
                continue;
            }
            enumerate_process_handles(&decode, &process, object_table, &mut results);
        }
        Ok(results)
    }
}

impl Default for Handles {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Handles {
    fn name(&self) -> &str {
        "windows.handles.Handles"
    }

    fn description(&self) -> &str {
        "Lists process handles from Windows handle tables"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Windows kernel virtual memory layer")
            .symbol_table("nt_symbols", "Windows kernel ISF symbol table")
            .int_optional("pid", "Filter by process ID")
            .string_optional("type", "Filter by object type")
            .int_optional(
                "kernel_virtual_offset",
                "Kernel virtual offset added to relative ISF symbols",
            )
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
            Column::new("HandleValue", ColumnType::Hex),
            Column::new("Type", ColumnType::String),
            Column::new("GrantedAccess", ColumnType::Hex),
            Column::new("Name", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let pid_filter = context
            .config_get_int("plugins.windows.handles.pid")
            .map(|value| value as u64);
        let type_filter = context
            .config_get_string("plugins.windows.handles.type")
            .map(|value| value.to_ascii_lowercase());
        let rows: Vec<Vol3Result<Row>> = Self::list_handles_filtered(&context, pid_filter)?
            .into_iter()
            .filter(|entry| {
                type_filter
                    .as_ref()
                    .map(|name| entry.object_type.to_ascii_lowercase() == *name)
                    .unwrap_or(true)
            })
            .map(|entry| {
                Ok(vec![
                    CellValue::UInt(entry.pid),
                    CellValue::String(entry.process),
                    CellValue::Hex(entry.body),
                    CellValue::Hex(entry.handle_value),
                    CellValue::String(entry.object_type),
                    CellValue::Hex(entry.granted_access),
                    entry
                        .name
                        .map(CellValue::String)
                        .unwrap_or(CellValue::Absent(AbsentValue::NotAvailable)),
                ])
            })
            .collect();
        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["windows"]
    }
}

fn enumerate_process_handles(
    decode: &DecodeContext<'_>,
    process: &ProcessInfo,
    object_table: Address,
    output: &mut Vec<HandleInfo>,
) {
    let Ok(table_code) = read_u64(decode.layer, object_table + decode.layout.table_code as u64)
    else {
        return;
    };
    let level = table_code & LEVEL_MASK;
    if level > MAX_TABLE_LEVEL {
        warn!(
            "Skipping PID {} handle table with unsupported level {}",
            process.pid, level
        );
        return;
    }
    let root = table_code & !LEVEL_MASK;
    let mut visited = HashSet::new();
    walk_table(decode, process, root, level, 0, &mut visited, output);
}

fn walk_table(
    decode: &DecodeContext<'_>,
    process: &ProcessInfo,
    table: Address,
    level: u64,
    leaf_base: u64,
    visited: &mut HashSet<(Address, u64)>,
    output: &mut Vec<HandleInfo>,
) {
    if table == 0 || !visited.insert((table, level)) {
        return;
    }
    let Ok(page) = decode.layer.read(table, PAGE_SIZE, false) else {
        return;
    };
    if level > 0 {
        let subtree_leaves = 512_u64.pow((level - 1) as u32);
        for (index, bytes) in page.chunks_exact(POINTER_SIZE).enumerate() {
            let child = u64::from_le_bytes(bytes.try_into().unwrap());
            if child != 0 {
                walk_table(
                    decode,
                    process,
                    child,
                    level - 1,
                    leaf_base + index as u64 * subtree_leaves,
                    visited,
                    output,
                );
            }
        }
        return;
    }

    let count = PAGE_SIZE / decode.layout.table_entry_size;
    for index in 0..count {
        let start = index * decode.layout.table_entry_size;
        let entry = &page[start..start + decode.layout.table_entry_size];
        if let Some(raw) = decode_entry(decode.layout, entry, leaf_base, index) {
            if let Some(handle) = decode_handle(decode, process, raw) {
                output.push(handle);
            }
        }
    }
}

fn decode_entry(
    layout: &HandleLayout,
    entry: &[u8],
    leaf_base: u64,
    index: usize,
) -> Option<RawHandle> {
    let pointer_bits = extract_bitfield(entry, layout.object_pointer_bits)?;
    if pointer_bits == 0 {
        return None;
    }
    let header = canonicalize_x64(pointer_bits << 4);
    let granted_access = extract_bitfield(entry, layout.granted_access_bits)?;
    let entries_per_leaf = (PAGE_SIZE / layout.table_entry_size) as u64;
    Some(RawHandle {
        header,
        handle_value: (leaf_base * entries_per_leaf + index as u64) * HANDLE_MULTIPLIER,
        granted_access,
    })
}

fn decode_handle(
    decode: &DecodeContext<'_>,
    process: &ProcessInfo,
    raw: RawHandle,
) -> Option<HandleInfo> {
    let header_size = decode.layout.object_header_body.max(
        decode
            .layout
            .object_header_info_mask
            .unwrap_or(decode.layout.object_header_type_index)
            + 1,
    );
    let header = match decode.layer.read(raw.header, header_size, false) {
        Ok(value) => value,
        Err(error) => {
            debug!(
                "Skipping handle {:#x}: cannot read object header {:#x}: {error}",
                raw.handle_value, raw.header
            );
            return None;
        }
    };
    let raw_type_index = *header.get(decode.layout.object_header_type_index)?;
    if raw_type_index == 0 {
        debug!(
            "Skipping handle {:#x}: zero object type index",
            raw.handle_value
        );
        return None;
    }
    let type_index = decode_type_index(raw.header, raw_type_index, decode.cookie);
    let Some(object_type) = decode.type_map.get(&type_index).cloned() else {
        debug!(
            "Skipping handle {:#x}: object type index {} is absent",
            raw.handle_value, type_index
        );
        return None;
    };
    let body = raw
        .header
        .checked_add(decode.layout.object_header_body as u64)?;
    let name = object_name(decode, &object_type, raw.header, body, &header);
    Some(HandleInfo {
        pid: process.pid,
        process: process.image_file_name.clone(),
        body,
        handle_value: raw.handle_value,
        object_type,
        granted_access: raw.granted_access,
        name,
    })
}

fn load_type_map(
    context: &Context,
    layer: &dyn DataLayer,
    symbol_table: &str,
    kernel_base: Address,
    layout: &HandleLayout,
) -> Vol3Result<HashMap<u8, String>> {
    let table_symbol = context
        .get_symbol(symbol_table, "ObTypeIndexTable")
        .or_else(|_| context.get_symbol(symbol_table, "ObpObjectTypes"))?;
    let table = kernel_base.wrapping_add(table_symbol.address);
    let mut result = HashMap::new();
    for index in 0_u8..100 {
        let pointer = match read_u64(layer, table + index as u64 * POINTER_SIZE as u64) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if index > 0 && pointer == 0 {
            break;
        }
        if pointer == 0 {
            continue;
        }
        if let Some(name) =
            read_unicode_string(layer, pointer + layout.object_type_name as u64, layout)
        {
            if !name.is_empty() && name.len() <= 128 {
                result.insert(index, name);
            }
        }
    }
    Ok(result)
}

fn object_name(
    decode: &DecodeContext<'_>,
    object_type: &str,
    header_address: Address,
    body: Address,
    header: &[u8],
) -> Option<String> {
    if object_type == "Process" {
        let pid = read_unsigned(
            decode.layer,
            body + decode.eprocess.unique_process_id as u64,
            decode.eprocess.unique_process_id_size,
        )
        .ok()?;
        let name = read_c_string(
            decode.layer,
            body + decode.eprocess.image_file_name as u64,
            decode.eprocess.image_file_name_size,
        )
        .ok()?;
        return Some(format!("{name} Pid {pid}"));
    }
    if object_type == "Thread" {
        let cid = decode.layout.ethread_cid?;
        let (pid_offset, pid_size) = decode.layout.client_id_process?;
        let (tid_offset, tid_size) = decode.layout.client_id_thread?;
        let pid = read_unsigned(
            decode.layer,
            body + cid as u64 + pid_offset as u64,
            pid_size,
        )
        .ok()?;
        let tid = read_unsigned(
            decode.layer,
            body + cid as u64 + tid_offset as u64,
            tid_size,
        )
        .ok()?;
        return Some(format!("Tid {tid} Pid {pid}"));
    }
    if object_type == "File" {
        let file_name = decode
            .layout
            .file_name
            .and_then(|offset| read_unicode_string(decode.layer, body + offset as u64, decode.layout))
            .unwrap_or_default();
        let device_name = decode
            .layout
            .file_device_object
            .and_then(|offset| read_u64(decode.layer, body + offset as u64).ok())
            .filter(|address| *address != 0)
            .and_then(|device| named_object_body(decode, device));
        if let Some(device) = device_name {
            return Some(format!("\\Device\\{device}{file_name}"));
        }
        if !file_name.is_empty() {
            return Some(file_name);
        }
    }

    if object_type == "Key" {
        if let Some(layout) = decode.layout.key_name {
            // Volatility uses only _CM_KEY_BODY.get_full_key_name for Key
            // objects and does not fall back to the generic object-header
            // name when the synthetic registry root has no reportable path.
            return registry_key_name(decode.layer, body, layout);
        }
        return None;
    }

    header_name(decode, header_address, header)
}

fn named_object_body(decode: &DecodeContext<'_>, body: Address) -> Option<String> {
    let header_address = body.checked_sub(decode.layout.object_header_body as u64)?;
    let required = decode
        .layout
        .object_header_info_mask?
        .saturating_add(1)
        .max(decode.layout.object_header_body);
    let header = decode.layer.read(header_address, required, false).ok()?;
    header_name(decode, header_address, &header)
}

fn header_name(
    decode: &DecodeContext<'_>,
    header_address: Address,
    header: &[u8],
) -> Option<String> {
    let info_mask_offset = decode.layout.object_header_info_mask?;
    let mask_table = decode.info_mask_table?;
    let info_mask = *header.get(info_mask_offset)?;
    let calculated_index = info_mask & 0x3;
    let header_offset =
        read_unsigned(decode.layer, mask_table + calculated_index as u64, 1).ok()?;
    if header_offset == 0 || header_offset > header_address {
        return None;
    }
    read_unicode_string(
        decode.layer,
        header_address - header_offset + decode.layout.name_info_name as u64,
        decode.layout,
    )
}

fn registry_key_name(
    layer: &dyn DataLayer,
    body: Address,
    layout: KeyNameLayout,
) -> Option<String> {
    let mut kcb = read_u64(layer, body + layout.key_control_block as u64).ok()?;
    if kcb == 0 {
        return None;
    }
    let mut components = Vec::new();
    let mut seen = HashSet::new();
    for _ in 0..MAX_KEY_COMPONENTS {
        if kcb == 0 {
            break;
        }
        if !seen.insert(kcb) {
            return None;
        }
        let parent = read_u64(layer, kcb + layout.parent_kcb as u64).ok()?;
        if parent == 0 {
            break;
        }
        let flags = read_bitfield(layer, kcb, layout.flags).unwrap_or(0);
        if layout.has_transaction_field && flags & KEY_HIVE_ENTRY != 0 {
            kcb = parent;
            continue;
        }
        let name_block = read_u64(layer, kcb + layout.name_block as u64).ok()?;
        if name_block == 0 {
            break;
        }
        let length = read_unsigned(layer, name_block + layout.name_length as u64, 2).ok()? as usize;
        if length == 0 || length > MAX_KEY_NAME_BYTES {
            break;
        }
        let bytes = layer.read(name_block + layout.name as u64, length, false).ok()?;
        components.push(String::from_utf8_lossy(&bytes).into_owned());
        kcb = parent;
    }
    if components.is_empty() {
        None
    } else {
        components.reverse();
        let name = components.join("\\");
        // Volatility does not expose the synthetic registry namespace root as
        // a key-handle name; only real paths below it are reported.
        (!name.eq_ignore_ascii_case("REGISTRY")).then_some(name)
    }
}

fn read_bitfield(
    layer: &dyn DataLayer,
    base: Address,
    field: BitFieldLayout,
) -> Option<u64> {
    let value = read_unsigned(layer, base + field.offset as u64, field.storage_size).ok()?;
    let mask = if field.bit_length >= 64 {
        u64::MAX
    } else {
        (1_u64 << field.bit_length) - 1
    };
    Some((value >> field.bit_offset) & mask)
}

fn read_unicode_string(
    layer: &dyn DataLayer,
    address: Address,
    layout: &HandleLayout,
) -> Option<String> {
    let length = read_unsigned(layer, address + layout.unicode_length as u64, 2).ok()? as usize;
    let maximum =
        read_unsigned(layer, address + layout.unicode_maximum_length as u64, 2).ok()? as usize;
    if length == 0 || length > maximum || length > 0x1_0000 || length % 2 != 0 {
        return None;
    }
    let buffer = read_u64(layer, address + layout.unicode_buffer as u64).ok()?;
    if buffer == 0 {
        return None;
    }
    let bytes = layer.read(buffer, length, false).ok()?;
    let words = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0);
    Some(
        char::decode_utf16(words)
            .map(|value| value.unwrap_or('\u{fffd}'))
            .collect(),
    )
}

fn extract_bitfield(entry: &[u8], field: BitFieldLayout) -> Option<u64> {
    let end = field.offset.checked_add(field.storage_size)?;
    let storage = entry.get(field.offset..end)?;
    let value = match field.storage_size {
        1 => storage[0] as u64,
        2 => u16::from_le_bytes(storage.try_into().ok()?) as u64,
        4 => u32::from_le_bytes(storage.try_into().ok()?) as u64,
        8 => u64::from_le_bytes(storage.try_into().ok()?),
        _ => return None,
    };
    let mask = if field.bit_length == 64 {
        u64::MAX
    } else {
        (1_u64 << field.bit_length) - 1
    };
    Some((value >> field.bit_offset) & mask)
}

fn decode_type_index(header: Address, raw: u8, cookie: Option<u8>) -> u8 {
    cookie
        .map(|value| (((header >> 8) as u8) ^ value ^ raw) & 0xff)
        .unwrap_or(raw)
}

fn canonicalize_x64(value: u64) -> u64 {
    const MASK: u64 = 0x0000_ffff_ffff_ffff;
    if value <= MASK && value & (1 << 47) != 0 {
        value | !MASK
    } else {
        value
    }
}

fn plugin_error(message: impl Into<String>) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_layout() -> HandleLayout {
        HandleLayout {
            table_code: 8,
            table_entry_size: 16,
            object_pointer_bits: BitFieldLayout {
                offset: 0,
                storage_size: 8,
                bit_offset: 20,
                bit_length: 44,
            },
            granted_access_bits: BitFieldLayout {
                offset: 8,
                storage_size: 4,
                bit_offset: 0,
                bit_length: 25,
            },
            object_header_body: 0x30,
            object_header_type_index: 0x18,
            object_header_info_mask: Some(0x1a),
            object_type_name: 0x10,
            name_info_name: 8,
            unicode_length: 0,
            unicode_maximum_length: 2,
            unicode_buffer: 8,
            ethread_cid: None,
            client_id_process: None,
            client_id_thread: None,
            file_name: None,
            file_device_object: None,
            key_name: None,
        }
    }

    #[test]
    fn decodes_windows_8_plus_handle_entry() {
        let layout = test_layout();
        let expected_header = 0xffff_d28c_53ae_d000_u64;
        let pointer_bits = (expected_header & 0x0000_ffff_ffff_ffff) >> 4;
        let mut entry = [0_u8; 16];
        entry[0..8].copy_from_slice(&(pointer_bits << 20).to_le_bytes());
        entry[8..12].copy_from_slice(&0x1f_ffff_u32.to_le_bytes());
        let decoded = decode_entry(&layout, &entry, 2, 3).unwrap();
        assert_eq!(decoded.header, expected_header);
        assert_eq!(decoded.handle_value, (2 * 256 + 3) * 4);
        assert_eq!(decoded.granted_access, 0x1f_ffff);
    }

    #[test]
    fn decodes_cookie_protected_type_index() {
        let header = 0xffff_d28c_53ae_d000;
        let cookie = 0x5a;
        let expected = 7_u8;
        let raw = ((header >> 8) as u8) ^ cookie ^ expected;
        assert_eq!(decode_type_index(header, raw, Some(cookie)), expected);
    }
}
