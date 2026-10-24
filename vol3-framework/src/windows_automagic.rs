//! Constrained Windows 10/11 x64 automagic for metadata-assisted memory cores.
//!
//! QEMU ELF notes or VMware snapshot tags expose CPU CR3 and IDTR values. CR3
//! constructs a Windows Intel32e layer; IDT handlers anchor kernel PE and PDB
//! identity discovery before the selected kernel ISF is validated.

use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};
use vol3_core::error::{PluginError, Vol3Error, Vol3Result};
use vol3_layers::intel::Intel32e;
use vol3_layers::traits::DataLayer;
use vol3_symbols::SymbolTableInterface;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const PT_NOTE: u32 = 4;
const QEMU_X64_STATE_SIZE: usize = 440;
const QEMU_CR3_OFFSET: usize = 0x1a0;
const QEMU_IDTR_BASE_OFFSET: usize = 0x180;
const KERNEL_ALIGNMENT: u64 = 0x20_0000;
const MAX_KERNEL_BACKTRACK: u64 = 0x800_0000; // 128 MiB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsCpuState {
    pub cr3: u64,
    pub idtr_base: u64,
}

pub type QemuCpuState = WindowsCpuState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelPeDiscovery {
    pub dtb: u64,
    pub kernel_base: u64,
    pub idtr_base: u64,
    pub idt_vector: u16,
    pub interrupt_handler: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbIdentity {
    pub database: String,
    pub guid: String,
    pub age: u32,
}

impl PdbIdentity {
    pub fn identifier(&self) -> String {
        format!("{}-{}", self.guid, self.age)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsDiscovery {
    pub dtb: u64,
    pub kernel_base: u64,
    pub build_number: u32,
    pub evidence: String,
}

/// Extracts x86_64 CPU state from QEMU ELF notes (version 1, 440-byte state).
pub fn qemu_cpu_states(source: &dyn DataLayer) -> Vol3Result<Vec<QemuCpuState>> {
    let header = source.read(0, ELF_HEADER_SIZE, false)?;
    if !header.starts_with(b"\x7fELF") || header[4] != 2 || header[5] != 1 {
        return Err(discovery_error("input is not a little-endian ELF64 image"));
    }
    let program_offset = LittleEndian::read_u64(&header[32..40]);
    let entry_size = LittleEndian::read_u16(&header[54..56]) as usize;
    let entry_count = LittleEndian::read_u16(&header[56..58]) as usize;
    if entry_size < PROGRAM_HEADER_SIZE || entry_count == 0 {
        return Err(discovery_error("invalid ELF64 program-header table"));
    }
    let table = source.read(program_offset, entry_size * entry_count, false)?;
    let mut states = Vec::new();
    for index in 0..entry_count {
        let entry = &table[index * entry_size..index * entry_size + PROGRAM_HEADER_SIZE];
        if LittleEndian::read_u32(&entry[0..4]) != PT_NOTE {
            continue;
        }
        let note_offset = LittleEndian::read_u64(&entry[8..16]);
        let note_size = LittleEndian::read_u64(&entry[32..40]) as usize;
        let notes = source.read(note_offset, note_size, false)?;
        parse_notes(&notes, &mut states);
    }
    states.sort_by_key(|state| (state.cr3, state.idtr_base));
    states.dedup();
    if states.is_empty() {
        Err(discovery_error(
            "no supported QEMU x86_64 CPU state was found in ELF notes",
        ))
    } else {
        Ok(states)
    }
}

fn parse_notes(notes: &[u8], output: &mut Vec<QemuCpuState>) {
    let mut cursor = 0usize;
    while cursor.checked_add(12).is_some_and(|end| end <= notes.len()) {
        let name_size = LittleEndian::read_u32(&notes[cursor..cursor + 4]) as usize;
        let desc_size = LittleEndian::read_u32(&notes[cursor + 4..cursor + 8]) as usize;
        cursor += 12;
        let Some(name_end) = cursor.checked_add(name_size) else {
            break;
        };
        if name_end > notes.len() {
            break;
        }
        let name = &notes[cursor..name_end];
        cursor = align4(name_end);
        let Some(desc_end) = cursor.checked_add(desc_size) else {
            break;
        };
        if desc_end > notes.len() {
            break;
        }
        let desc = &notes[cursor..desc_end];
        cursor = align4(desc_end);
        if !name.starts_with(b"QEMU") || desc.len() < QEMU_X64_STATE_SIZE {
            continue;
        }
        let version = LittleEndian::read_u32(&desc[0..4]);
        let declared_size = LittleEndian::read_u32(&desc[4..8]) as usize;
        if version != 1 || declared_size < QEMU_X64_STATE_SIZE {
            continue;
        }
        let cr3 = LittleEndian::read_u64(&desc[QEMU_CR3_OFFSET..QEMU_CR3_OFFSET + 8]) & !0xfff;
        let idtr_base =
            LittleEndian::read_u64(&desc[QEMU_IDTR_BASE_OFFSET..QEMU_IDTR_BASE_OFFSET + 8]);
        if cr3 != 0 && is_kernel_address(idtr_base) {
            output.push(WindowsCpuState { cr3, idtr_base });
        }
    }
}

/// Locates an AMD64 kernel PE using CPU CR3 and IDTR values, without symbols.
pub fn discover_kernel_pe(
    physical: Arc<dyn DataLayer>,
    cpu_states: &[WindowsCpuState],
) -> Vol3Result<KernelPeDiscovery> {
    for state in cpu_states {
        if !physical.is_valid(state.cr3, 0x1000) {
            continue;
        }
        let layer = Intel32e::new_windows("windows_pe_probe", physical.clone(), state.cr3, 0);
        for vector in 0..256u64 {
            let Ok(descriptor) = layer.read(state.idtr_base + vector * 16, 16, false) else {
                continue;
            };
            let handler = idt_handler(&descriptor);
            if !is_kernel_address(handler) {
                continue;
            }
            let aligned = handler & !(KERNEL_ALIGNMENT - 1);
            for delta in (0..=MAX_KERNEL_BACKTRACK).step_by(KERNEL_ALIGNMENT as usize) {
                let Some(base) = aligned.checked_sub(delta) else {
                    break;
                };
                if valid_pe64(&layer, base) {
                    return Ok(KernelPeDiscovery {
                        dtb: state.cr3,
                        kernel_base: base,
                        idtr_base: state.idtr_base,
                        idt_vector: vector as u16,
                        interrupt_handler: handler,
                    });
                }
            }
        }
    }
    Err(discovery_error(
        "CPU states were found, but no AMD64 kernel PE was reachable from the IDT",
    ))
}

/// Extracts CodeView RSDS PDB database, GUID, and age from a mapped kernel PE.
pub fn extract_pdb_identity(
    physical: Arc<dyn DataLayer>,
    dtb: u64,
    kernel_base: u64,
) -> Vol3Result<PdbIdentity> {
    let layer = Intel32e::new_windows("windows_pdb_probe", physical, dtb, 0);
    let dos = layer.read(kernel_base, 0x100, false)?;
    if !dos.starts_with(b"MZ") {
        return Err(discovery_error("kernel candidate has no DOS MZ signature"));
    }
    let pe_offset = LittleEndian::read_u32(&dos[0x3c..0x40]) as u64;
    let headers = layer.read(kernel_base + pe_offset, 0x200, false)?;
    if !headers.starts_with(b"PE\0\0") || LittleEndian::read_u16(&headers[4..6]) != 0x8664 {
        return Err(discovery_error("kernel candidate is not an AMD64 PE image"));
    }
    let optional = 24usize;
    if LittleEndian::read_u16(&headers[optional..optional + 2]) != 0x20b {
        return Err(discovery_error("kernel candidate is not PE32+"));
    }
    let debug_directory = optional + 112 + 6 * 8;
    let debug_rva = LittleEndian::read_u32(&headers[debug_directory..debug_directory + 4]) as u64;
    let debug_size = LittleEndian::read_u32(&headers[debug_directory + 4..debug_directory + 8]);
    if debug_rva == 0 || debug_size < 28 {
        return Err(discovery_error("kernel PE has no debug directory"));
    }
    for index in 0..debug_size / 28 {
        let entry = layer.read(kernel_base + debug_rva + index as u64 * 28, 28, false)?;
        let debug_type = LittleEndian::read_u32(&entry[12..16]);
        let data_size = LittleEndian::read_u32(&entry[16..20]) as usize;
        let data_rva = LittleEndian::read_u32(&entry[20..24]) as u64;
        if debug_type != 2 || data_size < 25 || data_rva == 0 {
            continue;
        }
        let codeview = layer.read(kernel_base + data_rva, data_size.min(4096), false)?;
        if let Some(identity) = parse_rsds(&codeview) {
            return Ok(identity);
        }
    }
    Err(discovery_error(
        "kernel PE debug directory contains no RSDS PDB identity",
    ))
}

fn parse_rsds(codeview: &[u8]) -> Option<PdbIdentity> {
    if codeview.len() < 25 || !codeview.starts_with(b"RSDS") {
        return None;
    }
    let guid = format_guid(&codeview[4..20]);
    let age = LittleEndian::read_u32(&codeview[20..24]);
    let database_end = codeview[24..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| 24 + offset)
        .unwrap_or(codeview.len());
    let database = String::from_utf8_lossy(&codeview[24..database_end]).to_string();
    (!database.is_empty()).then_some(PdbIdentity {
        database,
        guid,
        age,
    })
}

/// Discovers and validates CR3, kernel PE base, and Windows build number.
pub fn discover_windows_kernel(
    physical: Arc<dyn DataLayer>,
    cpu_states: &[WindowsCpuState],
    symbols: &dyn SymbolTableInterface,
) -> Vol3Result<WindowsDiscovery> {
    let nt_build_rva = symbols.get_symbol("NtBuildNumber")?.address;
    let process_head_rva = symbols.get_symbol("PsActiveProcessHead")?.address;
    let pe = discover_kernel_pe(physical.clone(), cpu_states)?;
    let layer = Intel32e::new_windows("windows_automagic_probe", physical, pe.dtb, 0);
    let build_bytes = layer.read(pe.kernel_base + nt_build_rva, 4, false)?;
    let build = LittleEndian::read_u32(&build_bytes) & 0xffff;
    if !(10_000..=40_000).contains(&build) {
        return Err(discovery_error(format!(
            "kernel ISF produced implausible Windows build {build}"
        )));
    }
    let head_bytes = layer.read(pe.kernel_base + process_head_rva, 16, false)?;
    let flink = LittleEndian::read_u64(&head_bytes[0..8]);
    let blink = LittleEndian::read_u64(&head_bytes[8..16]);
    if !is_kernel_address(flink) || !is_kernel_address(blink) {
        return Err(discovery_error(
            "kernel ISF failed PsActiveProcessHead validation",
        ));
    }
    Ok(WindowsDiscovery {
        dtb: pe.dtb,
        kernel_base: pe.kernel_base,
        build_number: build,
        evidence: format!(
            "CPU CR3 {:#x}; IDTR {:#x}; IDT vector {}; PE64 and ISF validation",
            pe.dtb, pe.idtr_base, pe.idt_vector
        ),
    })
}

fn format_guid(bytes: &[u8]) -> String {
    format!(
        "{:08X}{:04X}{:04X}{}",
        LittleEndian::read_u32(&bytes[0..4]),
        LittleEndian::read_u16(&bytes[4..6]),
        LittleEndian::read_u16(&bytes[6..8]),
        bytes[8..16]
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    )
}

fn valid_pe64(layer: &dyn DataLayer, base: u64) -> bool {
    let Ok(dos) = layer.read(base, 0x100, false) else {
        return false;
    };
    if !dos.starts_with(b"MZ") {
        return false;
    }
    let pe_offset = LittleEndian::read_u32(&dos[0x3c..0x40]) as u64;
    if pe_offset < 0x40 || pe_offset > 0x1000 {
        return false;
    }
    let Ok(pe) = layer.read(base + pe_offset, 6, false) else {
        return false;
    };
    pe.starts_with(b"PE\0\0") && LittleEndian::read_u16(&pe[4..6]) == 0x8664
}

fn idt_handler(descriptor: &[u8]) -> u64 {
    let low = LittleEndian::read_u16(&descriptor[0..2]) as u64;
    let middle = LittleEndian::read_u16(&descriptor[6..8]) as u64;
    let high = LittleEndian::read_u32(&descriptor[8..12]) as u64;
    low | (middle << 16) | (high << 32)
}

fn is_kernel_address(address: u64) -> bool {
    address >= 0xffff_8000_0000_0000
}

fn align4(value: usize) -> usize {
    value.saturating_add(3) & !3
}

fn discovery_error(message: impl Into<String>) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_idt_gate() {
        let mut gate = [0u8; 16];
        LittleEndian::write_u16(&mut gate[0..2], 0x1234);
        LittleEndian::write_u16(&mut gate[6..8], 0xabcd);
        LittleEndian::write_u32(&mut gate[8..12], 0xfffff805);
        assert_eq!(idt_handler(&gate), 0xffff_f805_abcd_1234);
    }

    #[test]
    fn parses_qemu_x64_cpu_note() {
        let mut desc = vec![0u8; QEMU_X64_STATE_SIZE];
        LittleEndian::write_u32(&mut desc[0..4], 1);
        LittleEndian::write_u32(&mut desc[4..8], QEMU_X64_STATE_SIZE as u32);
        LittleEndian::write_u64(&mut desc[QEMU_CR3_OFFSET..QEMU_CR3_OFFSET + 8], 0x1234_5abc);
        LittleEndian::write_u64(
            &mut desc[QEMU_IDTR_BASE_OFFSET..QEMU_IDTR_BASE_OFFSET + 8],
            0xffff_f805_7000_0000,
        );
        let name = b"QEMU\0";
        let mut note = vec![0u8; 12];
        LittleEndian::write_u32(&mut note[0..4], name.len() as u32);
        LittleEndian::write_u32(&mut note[4..8], desc.len() as u32);
        note.extend_from_slice(name);
        note.resize(align4(note.len()), 0);
        note.extend_from_slice(&desc);
        note.resize(align4(note.len()), 0);
        let mut states = Vec::new();
        parse_notes(&note, &mut states);
        assert_eq!(
            states,
            vec![QemuCpuState {
                cr3: 0x1234_5000,
                idtr_base: 0xffff_f805_7000_0000,
            }]
        );
    }

    #[test]
    fn parses_rsds_pdb_identity() {
        let mut data = b"RSDS".to_vec();
        data.extend_from_slice(&[
            0x0c, 0x4d, 0x28, 0x89, 0xac, 0xa6, 0x27, 0xc8, 0x4b, 0x9a, 0x44, 0xbd, 0x5a, 0xf9,
            0x29, 0x0b,
        ]);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(b"ntkrnlmp.pdb\0");
        let identity = parse_rsds(&data).unwrap();
        assert_eq!(identity.database, "ntkrnlmp.pdb");
        assert_eq!(identity.guid, "89284D0CA6ACC8274B9A44BD5AF9290B");
        assert_eq!(identity.identifier(), "89284D0CA6ACC8274B9A44BD5AF9290B-1");
    }
}
