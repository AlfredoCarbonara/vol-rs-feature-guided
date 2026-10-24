//! Linux VmcoreInfo plugin.
//!
//! Reads the VMCOREINFO from the kernel via ELF note scanning.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;

/// VMCOREINFO magic bytes (11 bytes, with null terminator)
const VMCOREINFO_MAGIC: &[u8] = b"VMCOREINFO\x00";
/// VMCOREINFO magic aligned to 4 bytes (12 bytes)
const VMCOREINFO_MAGIC_ALIGNED: &[u8] = b"VMCOREINFO\x00\x00";
/// OSRELEASE tag for validation
const OSRELEASE_TAG: &[u8] = b"OSRELEASE=";
/// Elf64_Note size (n_namesz + n_descsz + n_type, each u32)
const ELF_NOTE_SIZE: usize = 12;

/// VmcoreInfo plugin - reads VMCOREINFO
pub struct VmcoreInfo;

impl VmcoreInfo {
    pub fn new() -> Self {
        Self
    }

    /// Parse value according to key type
    fn parse_value(key: &str, value: &str) -> String {
        if key.starts_with("SYMBOL(") || key == "KERNELOFFSET" {
            // Parse as hex and format with 0x prefix
            if let Ok(v) = u64::from_str_radix(value.trim_start_matches("0x"), 16) {
                return format!("{:#x}", v);
            }
        }
        // All other values as string
        value.to_string()
    }

    /// Convert VMCOREINFO data buffer to list of entries
    fn vmcoreinfo_data_to_entries(data: &[u8], elf_note_offset: u64) -> Option<Vec<VmcoreEntry>> {
        // Ensure all bytes are printable ASCII
        let printable: std::collections::HashSet<u8> = (0x09..=0x0D).chain(0x20..=0x7E).collect();

        if !data.iter().all(|b| printable.contains(b)) {
            return None;
        }

        let text = std::str::from_utf8(data).ok()?;
        let mut entries = Vec::new();

        for line in text.lines() {
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once('=') {
                let formatted_value = Self::parse_value(key, value);
                entries.push(VmcoreEntry {
                    offset: elf_note_offset,
                    key: key.to_string(),
                    value: formatted_value,
                });
            }
        }

        Some(entries)
    }

    /// Scan memory for VMCOREINFO ELF notes
    fn search_vmcoreinfo_elf_note(layer: &dyn DataLayer) -> Vol3Result<Vec<VmcoreEntry>> {
        let mut all_entries = Vec::new();

        let max_addr = layer.maximum_address();
        let magic_len = VMCOREINFO_MAGIC_ALIGNED.len();

        // Scan for "VMCOREINFO\x00\x00" pattern
        let mut offset = 0u64;
        const SCAN_CHUNK: usize = 0x100000; // 1MB chunks

        while offset < max_addr {
            let chunk_size = std::cmp::min(SCAN_CHUNK as u64, max_addr - offset) as usize;
            if chunk_size < magic_len {
                break;
            }

            if let Ok(chunk) = layer.read(offset, chunk_size, false) {
                // Search for magic pattern in chunk
                for i in 0..chunk.len().saturating_sub(magic_len) {
                    if &chunk[i..i + magic_len] == VMCOREINFO_MAGIC_ALIGNED {
                        let vmcoreinfo_offset = offset + i as u64;
                        let elf_note_offset =
                            vmcoreinfo_offset.saturating_sub(ELF_NOTE_SIZE as u64);

                        // Read ELF note header
                        if let Ok(note_header) = layer.read(elf_note_offset, ELF_NOTE_SIZE, false) {
                            if note_header.len() >= ELF_NOTE_SIZE {
                                let n_namesz = u32::from_le_bytes([
                                    note_header[0],
                                    note_header[1],
                                    note_header[2],
                                    note_header[3],
                                ]);
                                let n_descsz = u32::from_le_bytes([
                                    note_header[4],
                                    note_header[5],
                                    note_header[6],
                                    note_header[7],
                                ]);
                                let n_type = u32::from_le_bytes([
                                    note_header[8],
                                    note_header[9],
                                    note_header[10],
                                    note_header[11],
                                ]);

                                // Validate ELF note
                                if n_namesz != VMCOREINFO_MAGIC.len() as u32
                                    || n_type != 0
                                    || n_descsz == 0
                                {
                                    continue;
                                }

                                // Read VMCOREINFO data
                                let data_offset = vmcoreinfo_offset + magic_len as u64;
                                if let Ok(vmcoreinfo_data) =
                                    layer.read(data_offset, n_descsz as usize, false)
                                {
                                    // Validate starts with OSRELEASE=
                                    if !vmcoreinfo_data.starts_with(OSRELEASE_TAG) {
                                        continue;
                                    }

                                    // Parse and collect entries
                                    if let Some(entries) = Self::vmcoreinfo_data_to_entries(
                                        &vmcoreinfo_data,
                                        elf_note_offset,
                                    ) {
                                        all_entries.extend(entries);
                                        // Return after first valid VMCOREINFO found
                                        return Ok(all_entries);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            offset += (SCAN_CHUNK - magic_len) as u64; // Overlap to catch split patterns
        }

        Ok(all_entries)
    }

    fn get_vmcoreinfo(context: &Context) -> Vol3Result<Vec<VmcoreEntry>> {
        // Use cached VMCOREINFO data from context setup
        // The offset needs to be converted to a virtual address to match Python
        let offset_opt = context.config_get_int("vmcoreinfo_offset");
        let data_raw_opt = context.config_get_string("vmcoreinfo_raw");

        if let (Some(phys_offset), Some(raw_text)) = (offset_opt, data_raw_opt) {
            let phys_offset = phys_offset as u64;

            // Convert physical offset to virtual address using direct-map translation
            // The page_offset_base symbol tells us the direct-map base
            let virt_offset = {
                let layer_name = context
                    .config_get_string("kernel_layer")
                    .or_else(|| context.config_get_string("primary"))
                    .unwrap_or_else(|| "kernel_layer".to_string());

                if let Some(layer) = context.get_layer(&layer_name) {
                    let mut found_virt = phys_offset; // Default to physical if no translation found

                    if let Some(symbols) = context.get_symbol_table("vmlinux") {
                        if let Ok(page_offset_sym) = symbols.get_symbol("page_offset_base") {
                            let aslr_shift =
                                context.config_get_int("aslr_shift").unwrap_or(0) as u64;
                            let page_offset_vaddr = page_offset_sym.address + aslr_shift;

                            // Read the actual page_offset_base value from memory
                            if let Ok(data) = layer.read(page_offset_vaddr, 8, false) {
                                if data.len() >= 8 {
                                    let page_offset_base = u64::from_le_bytes([
                                        data[0], data[1], data[2], data[3], data[4], data[5],
                                        data[6], data[7],
                                    ]);
                                    found_virt = phys_offset + page_offset_base;
                                }
                            }
                        }
                    }

                    found_virt
                } else {
                    phys_offset
                }
            };

            // Parse raw text directly to preserve key order
            let mut entries = Vec::new();
            for line in raw_text.lines() {
                if line.is_empty() {
                    break;
                }
                if let Some((key, value)) = line.split_once('=') {
                    let formatted_value = Self::parse_value(key, value);
                    entries.push(VmcoreEntry {
                        offset: virt_offset,
                        key: key.to_string(),
                        value: formatted_value,
                    });
                }
            }
            return Ok(entries);
        }

        // Fallback: return empty (scanning translation layers is too slow)
        Ok(Vec::new())
    }
}

impl Default for VmcoreInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct VmcoreEntry {
    offset: u64,
    key: String,
    value: String,
}

impl Module for VmcoreInfo {
    fn name(&self) -> &str {
        "linux.vmcoreinfo.VmcoreInfo"
    }

    fn description(&self) -> &str {
        "Reads the VMCOREINFO from the kernel"
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
            Column::new("Offset", ColumnType::Hex),
            Column::new("Key", ColumnType::String),
            Column::new("Value", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::get_vmcoreinfo(&context)?;

        // Apply 48-bit address mask for display parity with Python
        const ADDRESS_MASK: u64 = 0x0000ffffffffffff;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Hex(e.offset & ADDRESS_MASK),
                    CellValue::String(e.key),
                    CellValue::String(e.value),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
