//! Windows VAD based suspicious executable region extractor.

use std::collections::HashSet;
use std::sync::Arc;

use vol3_core::error::{ConfigError, LayerError, PluginError, Vol3Error, Vol3Result};
use vol3_core::types::{AbsentValue, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::intel::Intel32e;
use vol3_layers::traits::DataLayer;

use crate::layout::EprocessLayout;
use crate::pslist::PsList;
use crate::reader::{read_u64, read_unsigned};
use crate::vad_layout::{Bits, VadLayout};

const TABLE: &str = "nt_symbols";
const MAX_VADS: usize = 1_000_000;
const MAX_REGION_PAGES: u64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalfindInfo {
    pub pid: u64,
    pub process: String,
    pub start: u64,
    pub end: u64,
    pub tag: String,
    pub protection: String,
    pub commit_charge: u64,
    pub private_memory: u64,
    pub notes: Option<String>,
    pub hexdump: String,
}

pub struct Malfind;

impl Malfind {
    pub fn new() -> Self {
        Self
    }

    pub fn find(context: &Context, pid_filter: Option<u64>) -> Vol3Result<Vec<MalfindInfo>> {
        let kernel_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".into())))?;
        let physical_name = context
            .config_get_string("physical")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("physical".into())))?;
        let kernel = context
            .get_layer(&kernel_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(kernel_name)))?;
        let physical = context
            .get_layer(&physical_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(physical_name)))?;
        let process_layout = EprocessLayout::from_context(context, TABLE)?;
        let (dtb_offset, dtb_size) = process_layout
            .directory_table_base
            .ok_or_else(|| error("_KPROCESS.DirectoryTableBase missing from ISF"))?;
        let vad = VadLayout::from_context(context, TABLE)?;
        let protect_symbol = context.get_symbol(TABLE, "MmProtectToValue")?;
        let kernel_base = context.config_get_int("kernel_virtual_offset").unwrap_or(0) as u64;
        let protect_addr = protect_symbol
            .address
            .checked_add(kernel_base)
            .ok_or_else(|| error("MmProtectToValue address overflow"))?;
        let mut protections = [0u64; 32];
        for (index, value) in protections.iter_mut().enumerate() {
            *value = read_unsigned(kernel.as_ref(), protect_addr + (index * 4) as u64, 4)?;
        }
        let mut output = Vec::new();
        for process in PsList::list_processes(context)? {
            if pid_filter.is_some_and(|pid| pid != process.pid) {
                continue;
            }
            let dtb = match read_unsigned(
                kernel.as_ref(),
                process.eprocess + dtb_offset as u64,
                dtb_size,
            ) {
                Ok(value) if value & !0xfff != 0 => value & !0xfff,
                _ => continue,
            };
            let process_layer = Intel32e::new_windows(
                format!("malfind_process_{}", process.pid),
                physical.clone(),
                dtb,
                0,
            );
            let root = match read_u64(kernel.as_ref(), process.eprocess + vad.root as u64) {
                Ok(value) if value != 0 => value,
                _ => continue,
            };
            let mut seen = HashSet::new();
            let mut stack = vec![(root, 0usize)];
            while let Some((address, depth)) = stack.pop() {
                if address == 0 || !seen.insert(address) {
                    continue;
                }
                if seen.len() > MAX_VADS || depth > 100 {
                    break;
                }
                if !kernel.is_valid(address, 64) {
                    continue;
                }
                let tag = match kernel.read(address.wrapping_sub(12), 4, false) {
                    Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
                    Err(_) => String::new(),
                };
                if depth > 0 && !tag.starts_with("Vad") {
                    continue;
                }
                // Volatility's VAD traversal emits the current node before its children.
                if tag.starts_with("Vad") {
                    if let Some(entry) = read_candidate(
                        kernel.as_ref(),
                        &process_layer,
                        &vad,
                        &protections,
                        address,
                        &tag,
                        process.pid,
                        &process.image_file_name,
                    ) {
                        output.push(entry);
                    }
                }
                if let Ok(right) = read_u64(kernel.as_ref(), address + vad.right as u64) {
                    if right != 0 {
                        stack.push((right, depth + 1));
                    }
                }
                if let Ok(left) = read_u64(kernel.as_ref(), address + vad.left as u64) {
                    if left != 0 {
                        stack.push((left, depth + 1));
                    }
                }
            }
        }
        Ok(output)
    }
}

impl Default for Malfind {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Malfind {
    fn name(&self) -> &str {
        "windows.malware.malfind.Malfind"
    }
    fn description(&self) -> &str {
        "Finds Windows process VADs that may contain injected code"
    }
    fn requirements(&self) -> ModuleRequirements {
        ModuleRequirements {
            name: self.name().into(),
            description: self.description().into(),
            requirements: RequirementsBuilder::new()
                .layer("primary", "Windows kernel virtual layer")
                .symbol_table("nt_symbols", "Windows kernel ISF")
                .int_optional("pid", "Filter by process ID")
                .build(),
        }
    }
    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("PID", ColumnType::Int),
            Column::new("Process", ColumnType::String),
            Column::new("Start VPN", ColumnType::Hex),
            Column::new("End VPN", ColumnType::Hex),
            Column::new("Tag", ColumnType::String),
            Column::new("Protection", ColumnType::String),
            Column::new("CommitCharge", ColumnType::Int),
            Column::new("PrivateMemory", ColumnType::Int),
            Column::new("File output", ColumnType::String),
            Column::new("Notes", ColumnType::String),
            Column::new("Hexdump", ColumnType::String),
            Column::new("Disasm", ColumnType::String),
        ]
    }
    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let pid = context
            .config_get_int("plugins.windows.malfind.pid")
            .map(|v| v as u64);
        let rows: Vec<Vol3Result<Row>> = Self::find(&context, pid)?
            .into_iter()
            .map(|entry| {
                Ok(vec![
                    CellValue::UInt(entry.pid),
                    CellValue::String(entry.process),
                    CellValue::Hex(entry.start),
                    CellValue::Hex(entry.end),
                    CellValue::String(entry.tag),
                    CellValue::String(entry.protection),
                    CellValue::UInt(entry.commit_charge),
                    CellValue::UInt(entry.private_memory),
                    CellValue::String("Disabled".into()),
                    entry
                        .notes
                        .map(CellValue::String)
                        .unwrap_or(CellValue::Absent(AbsentValue::NotApplicable)),
                    CellValue::String(entry.hexdump.clone()),
                    CellValue::String(format!("\"{}\"", entry.hexdump)),
                ])
            })
            .collect();
        Ok(Box::new(rows.into_iter()))
    }
    fn supported_os(&self) -> Vec<&str> {
        vec!["windows"]
    }
}

fn read_candidate(
    kernel: &dyn DataLayer,
    process_layer: &Intel32e,
    layout: &VadLayout,
    protections: &[u64; 32],
    address: u64,
    tag: &str,
    pid: u64,
    process: &str,
) -> Option<MalfindInfo> {
    let start_vpn = read_pair(kernel, address, layout.start, layout.start_high)?;
    let end_vpn = read_pair(kernel, address, layout.end, layout.end_high)?;
    if end_vpn < start_vpn || end_vpn - start_vpn + 1 > MAX_REGION_PAGES {
        return None;
    }
    let start = start_vpn.checked_mul(4096)?;
    let end = end_vpn.checked_add(1)?.checked_mul(4096)?.checked_sub(1)?;
    let protection_index = read_bits(kernel, address, layout.protection)? as usize;
    let protection = protection_name(*protections.get(protection_index)?);
    let write_exec = protection.contains("EXECUTE") && protection.contains("WRITE");
    if !write_exec {
        if !protection.contains("EXECUTE") {
            return None;
        }
        let mut dirty = false;
        let mut page = start;
        while page < end {
            match process_layer.is_dirty(page) {
                Ok(true) => {
                    dirty = true;
                    break;
                }
                Ok(false) => {}
                Err(_) => break,
            }
            page = page.checked_add(4096)?;
        }
        if !dirty {
            return None;
        }
    }
    let private_memory = read_bits(kernel, address, layout.private_memory)?;
    if !((private_memory == 1 && tag == "VadS")
        || (private_memory == 0 && protection != "PAGE_EXECUTE_WRITECOPY"))
    {
        return None;
    }
    if region_empty(process_layer, start, end) {
        return None;
    }
    let commit_charge = read_bits(kernel, address, layout.commit_charge)?;
    let data = process_layer.read(start, 64, true).ok()?;
    let notes = match data.get(..2)? {
        b"MZ" => Some("MZ header"),
        b"\x55\x8b" => Some("PE header"),
        b"\x55\x48" | b"\x55\x89" => Some("Function prologue"),
        _ => None,
    }
    .map(str::to_string);
    let hexdump = data
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    Some(MalfindInfo {
        pid,
        process: process.into(),
        start,
        end,
        tag: tag.into(),
        protection,
        commit_charge,
        private_memory,
        notes,
        hexdump,
    })
}

fn region_empty(layer: &dyn DataLayer, start: u64, end: u64) -> bool {
    let mut page = start;
    while page <= end {
        if layer.is_valid(page, 4096) {
            if let Ok(bytes) = layer.read(page, 4096, false) {
                if bytes.iter().any(|byte| *byte != 0) {
                    return false;
                }
            }
        }
        match page.checked_add(4096) {
            Some(next) => page = next,
            None => break,
        }
    }
    true
}

fn read_pair(
    layer: &dyn DataLayer,
    base: u64,
    low: (usize, usize),
    high: Option<(usize, usize)>,
) -> Option<u64> {
    let value = read_unsigned(layer, base + low.0 as u64, low.1).ok()?;
    let upper = high
        .map(|(offset, size)| read_unsigned(layer, base + offset as u64, size).ok())
        .flatten()
        .unwrap_or(0);
    Some(value | (upper << 32))
}

fn read_bits(layer: &dyn DataLayer, base: u64, bits: Bits) -> Option<u64> {
    let value = read_unsigned(layer, base + bits.offset as u64, bits.size).ok()?;
    let mask = if bits.length == 64 {
        u64::MAX
    } else {
        (1u64 << bits.length) - 1
    };
    Some((value >> bits.shift) & mask)
}

fn protection_name(value: u64) -> String {
    const NAMES: [(u64, &str); 12] = [
        (1, "PAGE_NOACCESS"),
        (2, "PAGE_READONLY"),
        (4, "PAGE_READWRITE"),
        (8, "PAGE_WRITECOPY"),
        (16, "PAGE_EXECUTE"),
        (32, "PAGE_EXECUTE_READ"),
        (64, "PAGE_EXECUTE_READWRITE"),
        (128, "PAGE_EXECUTE_WRITECOPY"),
        (256, "PAGE_GUARD"),
        (512, "PAGE_NOCACHE"),
        (1024, "PAGE_WRITECOMBINE"),
        (0x4000_0000, "PAGE_TARGETS_INVALID"),
    ];
    NAMES
        .iter()
        .filter_map(|(mask, name)| (value & mask != 0).then_some(*name))
        .collect::<Vec<_>>()
        .join("|")
}

fn error(message: &str) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protection_mapping_preserves_volatility_names() {
        assert_eq!(protection_name(0x40), "PAGE_EXECUTE_READWRITE");
        assert_eq!(protection_name(0x80), "PAGE_EXECUTE_WRITECOPY");
    }
}
