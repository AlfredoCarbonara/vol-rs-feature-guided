//! Linux EBPF plugin.
//!
//! Enumerates eBPF programs.

use std::collections::HashSet;
use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::helpers;

/// 48-bit canonical address mask used by volatility3 renderers.
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;
const XARRAY_TAG_MASK: u64 = 0x3;
const XARRAY_TAG_INTERNAL: u64 = 0x2;

/// Ebpf plugin - enumerates eBPF programs
pub struct Ebpf;

#[derive(Debug, Clone)]
struct XaOffsets {
    idr_rt_offset: usize,
    xa_head_offset: usize,
    shift_offset: usize,
    shift_size: usize,
    slots_offset: usize,
    slots_count: usize,
    pointer_size: usize,
}

#[derive(Debug, Clone)]
struct BpfOffsets {
    prog_type_offset: Option<usize>,
    prog_type_size: usize,
    aux_offset: Option<usize>,
    aux_prog_type_offset: Option<usize>,
    aux_prog_type_size: usize,
    tag_offset: Option<usize>,
    tag_len: usize,
    aux_name_offset: Option<usize>,
    aux_name_len: usize,
}

impl Ebpf {
    pub fn new() -> Self {
        Self
    }

    fn list_ebpf(context: &Context) -> Vol3Result<Vec<EbpfEntry>> {
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

        let xa_offsets = parse_xarray_offsets(context, &symbol_table)?;
        let bpf_offsets = parse_bpf_offsets(context, &symbol_table)?;
        let entries_addrs = list_prog_entries(context, layer.as_ref(), &symbol_table, &xa_offsets)?;

        let mut entries = Vec::new();
        let prog_type_enum = context
            .get_symbol_table(&symbol_table)
            .and_then(|t| t.get_enumeration("bpf_prog_type").ok());

        for prog_addr in entries_addrs {
            if let Some(entry) = build_entry(
                layer.as_ref(),
                prog_addr,
                &bpf_offsets,
                prog_type_enum.as_ref(),
            ) {
                entries.push(entry);
            }
        }

        entries.sort_by_key(|e| e.address);
        Ok(entries)
    }
}

impl Default for Ebpf {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct EbpfEntry {
    address: u64,
    name: String,
    tag: String,
    prog_type: String,
}

fn parse_xarray_offsets(context: &Context, symbol_table: &str) -> Vol3Result<XaOffsets> {
    let pointer_size = context
        .get_type(symbol_table, "pointer")
        .ok()
        .and_then(|t| t.size())
        .unwrap_or(8);

    let idr_template = context.get_type(symbol_table, "idr")?;
    let idr_rt_offset = if let TypeTemplate::Struct(s) = idr_template.as_ref() {
        s.get_field("idr_rt").map(|f| f.offset).unwrap_or(0)
    } else {
        0
    };

    let xarray_template = context.get_type(symbol_table, "xarray")?;
    let xa_head_offset = if let TypeTemplate::Struct(s) = xarray_template.as_ref() {
        s.get_field("xa_head").map(|f| f.offset).unwrap_or(0)
    } else {
        0
    };

    let xa_node_template = context.get_type(symbol_table, "xa_node")?;
    let (shift_offset, shift_size, slots_offset, slots_count) =
        if let TypeTemplate::Struct(s) = xa_node_template.as_ref() {
            let shift = s.get_field("shift");
            let slots = s.get_field("slots");

            let slots_count = slots
                .and_then(|f| match f.template.as_ref() {
                    TypeTemplate::Array(arr) => Some(arr.count),
                    _ => None,
                })
                .unwrap_or(64);

            (
                shift.map(|f| f.offset).unwrap_or(0),
                shift.and_then(|f| f.template.size()).unwrap_or(4).max(1),
                slots.map(|f| f.offset).unwrap_or(0),
                slots_count.max(1),
            )
        } else {
            (0, 4, 0, 64)
        };

    Ok(XaOffsets {
        idr_rt_offset,
        xa_head_offset,
        shift_offset,
        shift_size,
        slots_offset,
        slots_count,
        pointer_size,
    })
}

fn parse_bpf_offsets(context: &Context, symbol_table: &str) -> Vol3Result<BpfOffsets> {
    let bpf_prog_template = context.get_type(symbol_table, "bpf_prog")?;
    let (prog_type_offset, prog_type_size, aux_offset, tag_offset, tag_len) =
        if let TypeTemplate::Struct(s) = bpf_prog_template.as_ref() {
            let prog_type_field = s.get_field("type");
            let aux_field = s.get_field("aux");
            let tag_field = s.get_field("tag");

            let tag_len = tag_field
                .and_then(|f| match f.template.as_ref() {
                    TypeTemplate::Array(arr) => Some(arr.count),
                    _ => None,
                })
                .unwrap_or(0);

            (
                prog_type_field.map(|f| f.offset),
                prog_type_field
                    .and_then(|f| f.template.size())
                    .unwrap_or(4)
                    .max(1),
                aux_field.map(|f| f.offset),
                tag_field.map(|f| f.offset),
                tag_len,
            )
        } else {
            (None, 4, None, None, 0)
        };

    let bpf_aux_template = context.get_type(symbol_table, "bpf_prog_aux").ok();
    let (aux_prog_type_offset, aux_prog_type_size, aux_name_offset, aux_name_len) =
        if let Some(template) = bpf_aux_template {
            if let TypeTemplate::Struct(s) = template.as_ref() {
                let aux_prog_type_field = s.get_field("prog_type");
                let aux_name_field = s.get_field("name");
                let aux_name_len = aux_name_field
                    .and_then(|f| match f.template.as_ref() {
                        TypeTemplate::Array(arr) => Some(arr.count),
                        _ => None,
                    })
                    .unwrap_or(0);
                (
                    aux_prog_type_field.map(|f| f.offset),
                    aux_prog_type_field
                        .and_then(|f| f.template.size())
                        .unwrap_or(4)
                        .max(1),
                    aux_name_field.map(|f| f.offset),
                    aux_name_len,
                )
            } else {
                (None, 4, None, 0)
            }
        } else {
            (None, 4, None, 0)
        };

    Ok(BpfOffsets {
        prog_type_offset,
        prog_type_size,
        aux_offset,
        aux_prog_type_offset,
        aux_prog_type_size,
        tag_offset,
        tag_len,
        aux_name_offset,
        aux_name_len,
    })
}

fn list_prog_entries(
    context: &Context,
    layer: &dyn DataLayer,
    symbol_table: &str,
    offsets: &XaOffsets,
) -> Vol3Result<Vec<Address>> {
    let prog_sym = context.get_symbol(symbol_table, "prog_idr")?;
    let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;
    let prog_idr_addr = prog_sym.address.wrapping_add(aslr_shift);

    if !layer.is_valid(prog_idr_addr, 1) {
        return Ok(Vec::new());
    }

    let idr_rt_addr = prog_idr_addr + offsets.idr_rt_offset as u64;
    let mut root = helpers::read_pointer(layer, idr_rt_addr + offsets.xa_head_offset as u64)?;
    if root == 0 {
        return Ok(Vec::new());
    }

    let was_internal = (root & XARRAY_TAG_MASK) == XARRAY_TAG_INTERNAL;
    if (root & XARRAY_TAG_MASK) != 0 {
        root &= !XARRAY_TAG_MASK;
    }

    let mut entries = Vec::new();
    let mut seen_entries = HashSet::new();
    let mut seen_nodes = HashSet::new();

    if was_internal {
        let chunk_shift = ilog2(offsets.slots_count);
        let shift = read_unsigned(
            layer,
            root + offsets.shift_offset as u64,
            offsets.shift_size,
        )
        .unwrap_or(0) as usize;
        let height = if chunk_shift > 0 {
            (shift / chunk_shift) + 1
        } else {
            1
        };

        walk_xarray_node(
            layer,
            root,
            height.max(1),
            offsets,
            &mut seen_nodes,
            &mut seen_entries,
            &mut entries,
        );
    } else if (root & XARRAY_TAG_MASK) == 0 {
        seen_entries.insert(root);
        entries.push(root);
    }

    Ok(entries)
}

fn walk_xarray_node(
    layer: &dyn DataLayer,
    node_addr: Address,
    height: usize,
    offsets: &XaOffsets,
    seen_nodes: &mut HashSet<Address>,
    seen_entries: &mut HashSet<Address>,
    entries: &mut Vec<Address>,
) {
    if node_addr == 0 || !helpers::is_valid_kernel_address(node_addr) {
        return;
    }
    if !seen_nodes.insert(node_addr) {
        return;
    }

    for idx in 0..offsets.slots_count {
        let slot_addr =
            node_addr + offsets.slots_offset as u64 + (idx * offsets.pointer_size) as u64;
        let Ok(slot) = helpers::read_pointer(layer, slot_addr) else {
            continue;
        };
        if slot == 0 {
            continue;
        }

        let mut child = slot;
        if (slot & XARRAY_TAG_MASK) == XARRAY_TAG_INTERNAL {
            child = slot & !XARRAY_TAG_MASK;
        }

        if height <= 1 {
            if (child & XARRAY_TAG_MASK) == 0 && seen_entries.insert(child) {
                entries.push(child);
            }
            continue;
        }

        walk_xarray_node(
            layer,
            child,
            height - 1,
            offsets,
            seen_nodes,
            seen_entries,
            entries,
        );
    }
}

fn build_entry(
    layer: &dyn DataLayer,
    prog_addr: Address,
    offsets: &BpfOffsets,
    prog_type_enum: Option<&vol3_symbols::Enumeration>,
) -> Option<EbpfEntry> {
    if prog_addr == 0 || !helpers::is_valid_kernel_address(prog_addr) {
        return None;
    }

    let aux_ptr = offsets
        .aux_offset
        .and_then(|off| helpers::read_pointer(layer, prog_addr + off as u64).ok())
        .unwrap_or(0);

    let prog_type_raw = offsets
        .prog_type_offset
        .and_then(|off| read_unsigned(layer, prog_addr + off as u64, offsets.prog_type_size))
        .or_else(|| {
            if aux_ptr != 0 {
                offsets.aux_prog_type_offset.and_then(|off| {
                    read_unsigned(layer, aux_ptr + off as u64, offsets.aux_prog_type_size)
                })
            } else {
                None
            }
        });

    let prog_type = prog_type_raw
        .and_then(|value| {
            prog_type_enum.and_then(|en| en.get_name(value as i64).map(|v| v.to_string()))
        })
        .unwrap_or_else(|| "-".to_string());

    let tag = if let Some(tag_off) = offsets.tag_offset {
        if offsets.tag_len > 0 {
            layer
                .read(prog_addr + tag_off as u64, offsets.tag_len, false)
                .ok()
                .map(|bytes| to_hex(&bytes))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "-".to_string())
        } else {
            "-".to_string()
        }
    } else {
        "-".to_string()
    };

    let name = if aux_ptr != 0 && helpers::is_valid_kernel_address(aux_ptr) {
        offsets
            .aux_name_offset
            .and_then(|off| {
                if offsets.aux_name_len == 0 {
                    return None;
                }
                layer
                    .read(aux_ptr + off as u64, offsets.aux_name_len, false)
                    .ok()
            })
            .map(|bytes| cstring_from_bytes(&bytes))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "-".to_string())
    } else {
        "-".to_string()
    };

    Some(EbpfEntry {
        address: prog_addr & ADDR_MASK,
        name,
        tag,
        prog_type,
    })
}

fn ilog2(mut value: usize) -> usize {
    let mut bits = 0;
    while value > 1 {
        value >>= 1;
        bits += 1;
    }
    bits
}

fn read_unsigned(layer: &dyn DataLayer, addr: Address, size: usize) -> Option<u64> {
    match size {
        1 => helpers::read_u8(layer, addr).ok().map(|v| v as u64),
        2 => helpers::read_u16(layer, addr).ok().map(|v| v as u64),
        4 => helpers::read_u32(layer, addr).ok().map(|v| v as u64),
        8 => helpers::read_u64(layer, addr).ok(),
        _ => None,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn cstring_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

impl Module for Ebpf {
    fn name(&self) -> &str {
        "linux.ebpf.Ebpf"
    }

    fn description(&self) -> &str {
        "Enumerates eBPF programs"
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
            Column::new("Address", ColumnType::Hex),
            Column::new("Name", ColumnType::String),
            Column::new("Tag", ColumnType::String),
            Column::new("Type", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_ebpf(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Hex(e.address),
                    CellValue::String(e.name),
                    CellValue::String(e.tag),
                    CellValue::String(e.prog_type),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
