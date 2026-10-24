//! Linux Kallsyms plugin.
//!
//! Enumerates kernel symbols from core and modules.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use vol3_core::error::{ConfigError, LayerError, ObjectError, Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::helpers;
use crate::lsmod::Lsmod;

const ADDRESS_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Kallsyms plugin - enumerates kernel symbols
pub struct Kallsyms;

impl Kallsyms {
    pub fn new() -> Self {
        Self
    }

    fn list_symbols(context: &Context) -> Vol3Result<Vec<KallsymsEntry>> {
        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let layer = context
            .get_layer(&layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(layer_name.clone())))?;

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;

        let mut entries = Vec::new();
        entries.extend(collect_core_symbols(
            context,
            layer.as_ref(),
            &symbol_table,
            aslr_shift,
        )?);
        entries.extend(collect_module_symbols(
            context,
            layer.as_ref(),
            &symbol_table,
        )?);
        entries.extend(collect_bpf_symbols(
            context,
            layer.as_ref(),
            &symbol_table,
            aslr_shift,
        )?);

        Ok(entries)
    }
}

impl Default for Kallsyms {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct KallsymsEntry {
    address: u64,
    sym_type: Option<String>,
    size: Option<i64>,
    exported: Option<bool>,
    subsystem: String,
    module_name: String,
    symbol_name: String,
    description: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct CoreKallsymsConfig {
    num_syms_address: u64,
    names_address: u64,
    token_table_address: u64,
    token_index_address: u64,
    offsets_address: Option<u64>,
    relative_base_address: Option<u64>,
    addresses_address: Option<u64>,
    sinittext_address: Option<u64>,
    einittext_address: Option<u64>,
    etext_address: Option<u64>,
    end_address: Option<u64>,
    num_syms_type_size: usize,
    long_size: usize,
}

#[derive(Debug, Clone, Copy)]
struct ModuleSymbolOffsets {
    kallsyms_ptr: Option<u64>,
    symtab: u64,
    num_symtab: u64,
    num_symtab_size: usize,
    strtab: u64,
    typetab: Option<u64>,
    syms: Option<u64>,
    num_syms: Option<u64>,
    num_syms_size: usize,
}

#[derive(Debug, Clone, Copy)]
struct KernelSymbolOffsets {
    entry_size: usize,
    name_offset: Option<u64>,
    name_ptr: Option<u64>,
    value_offset: Option<u64>,
    value_ptr: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct BpfKsymOffsets {
    lnode: u64,
    name: u64,
    name_len: usize,
    start: u64,
    start_size: usize,
    end: u64,
    end_size: usize,
}

impl Module for Kallsyms {
    fn name(&self) -> &str {
        "linux.kallsyms.Kallsyms"
    }

    fn description(&self) -> &str {
        "Enumerates kernel symbols"
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
            Column::new("Addr", ColumnType::Hex),
            Column::new("Type", ColumnType::String),
            Column::new("Size", ColumnType::Int),
            Column::new("Exported", ColumnType::String),
            Column::new("SubSystem", ColumnType::String),
            Column::new("ModuleName", ColumnType::String),
            Column::new("SymbolName", ColumnType::String),
            Column::new("Description", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_symbols(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                let sym_type = e
                    .sym_type
                    .map(CellValue::String)
                    .unwrap_or_else(|| CellValue::String("-".to_string()));
                let size = match e.size {
                    Some(v) if v > 0 => CellValue::Int(v),
                    _ => CellValue::String("-".to_string()),
                };
                let exported = match e.exported {
                    Some(true) => CellValue::String("True".to_string()),
                    Some(false) => CellValue::String("False".to_string()),
                    None => CellValue::String("-".to_string()),
                };
                let description = e
                    .description
                    .map(CellValue::String)
                    .unwrap_or_else(|| CellValue::String("-".to_string()));

                Ok(vec![
                    CellValue::Hex(e.address),
                    sym_type,
                    size,
                    exported,
                    CellValue::String(e.subsystem),
                    CellValue::String(e.module_name),
                    CellValue::String(e.symbol_name),
                    description,
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}

fn collect_core_symbols(
    context: &Context,
    layer: &dyn DataLayer,
    symbol_table: &str,
    aslr_shift: u64,
) -> Vol3Result<Vec<KallsymsEntry>> {
    let cfg = build_core_kallsyms_config(context, symbol_table, aslr_shift)?;

    let num_syms = read_unsigned(layer, cfg.num_syms_address, cfg.num_syms_type_size) as usize;
    if num_syms == 0 {
        return Ok(Vec::new());
    }

    let relative_base = cfg
        .relative_base_address
        .map(|addr| read_unsigned(layer, addr, cfg.long_size) & ADDRESS_MASK)
        .unwrap_or(0);

    let mut token_index = [0u16; 256];
    for (i, slot) in token_index.iter_mut().enumerate() {
        *slot = helpers::read_u16(layer, cfg.token_index_address + (i as u64 * 2)).unwrap_or(0);
    }

    // Build the 256 decompression tokens once to avoid repeated reads.
    let mut tokens: Vec<String> = vec![String::new(); 256];
    for (i, token) in tokens.iter_mut().enumerate() {
        let token_off = token_index[i] as u64;
        *token = helpers::read_string(layer, cfg.token_table_address + token_off, 64)
            .unwrap_or_default();
    }

    let mut addresses = vec![0u64; num_syms];
    for (idx, slot) in addresses.iter_mut().enumerate() {
        *slot = get_symbol_address_by_index(layer, &cfg, idx, relative_base);
    }
    let sizes = compute_core_symbol_sizes(&addresses, &cfg);

    let mut current_offset = 0usize;
    let mut entries = Vec::with_capacity(num_syms);

    for idx in 0..num_syms {
        let Some((sym_type, sym_name, compressed_len)) =
            expand_symbol(layer, cfg.names_address, current_offset, &tokens)
        else {
            break;
        };

        current_offset = current_offset.saturating_add(compressed_len + 1);

        let exported = exported_from_type(sym_type.as_deref());
        let description = sym_type
            .as_deref()
            .and_then(nm_type_description)
            .map(|s| s.to_string());

        entries.push(KallsymsEntry {
            address: addresses[idx],
            sym_type,
            size: Some(sizes[idx]),
            exported,
            subsystem: "core".to_string(),
            module_name: "kernel".to_string(),
            symbol_name: sym_name,
            description,
        });
    }

    Ok(entries)
}

fn collect_module_symbols(
    context: &Context,
    layer: &dyn DataLayer,
    symbol_table: &str,
) -> Vol3Result<Vec<KallsymsEntry>> {
    let module_offsets = match get_module_symbol_offsets(context, symbol_table) {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };

    let modules = Lsmod::list_modules(context).unwrap_or_default();
    let mut entries = Vec::new();
    let kernel_symbol_offsets = get_kernel_symbol_offsets(context, symbol_table);

    // x86_64 sample/profile path; mirrors python module.get_symbols path on this target.
    let elf_sym_size = 24u64;

    for module in modules {
        let module_addr = module.offset & ADDRESS_MASK;
        if module_addr == 0 {
            continue;
        }

        let base_addr = if let Some(kallsyms_ptr_off) = module_offsets.kallsyms_ptr {
            let ptr = helpers::read_pointer(layer, module_addr + kallsyms_ptr_off).unwrap_or(0);
            if ptr == 0 {
                continue;
            }
            ptr
        } else {
            module_addr
        };

        let symtab_ptr =
            helpers::read_pointer(layer, base_addr + module_offsets.symtab).unwrap_or(0);
        let strtab_ptr =
            helpers::read_pointer(layer, base_addr + module_offsets.strtab).unwrap_or(0);
        let typetab_ptr = module_offsets
            .typetab
            .map(|off| helpers::read_pointer(layer, base_addr + off).unwrap_or(0))
            .filter(|p| *p != 0);

        let num_symtab = read_unsigned(
            layer,
            base_addr + module_offsets.num_symtab,
            module_offsets.num_symtab_size,
        ) as usize;

        if symtab_ptr == 0 || strtab_ptr == 0 || num_symtab == 0 || num_symtab > 1_000_000 {
            continue;
        }

        let module_num_syms = module_offsets
            .num_syms
            .map(|off| {
                read_unsigned(layer, module_addr + off, module_offsets.num_syms_size) as usize
            })
            .unwrap_or(0);
        let module_syms_ptr = module_offsets
            .syms
            .and_then(|off| helpers::read_pointer(layer, module_addr + off).ok())
            .unwrap_or(0);
        let exported_symbols = if module_num_syms > 0 && module_syms_ptr != 0 {
            kernel_symbol_offsets
                .as_ref()
                .map(|ks_offsets| {
                    collect_module_exported_symbols(
                        layer,
                        module_syms_ptr,
                        module_num_syms,
                        ks_offsets,
                    )
                })
                .unwrap_or_default()
        } else {
            HashMap::new()
        };

        for sym_idx in 0..num_symtab {
            let sym_addr = symtab_ptr + (sym_idx as u64 * elf_sym_size);
            if !layer.is_valid(sym_addr, elf_sym_size as usize) {
                continue;
            }

            let st_name = helpers::read_u32(layer, sym_addr).unwrap_or(0);
            if st_name == 0 {
                continue;
            }

            let st_info = helpers::read_u8(layer, sym_addr + 4).unwrap_or(0);
            let st_value = helpers::read_u64(layer, sym_addr + 8).unwrap_or(0) & ADDRESS_MASK;
            let st_size = helpers::read_u64(layer, sym_addr + 16).unwrap_or(0) as i64;

            let symbol_name =
                read_string_padded(layer, strtab_ptr + st_name as u64, 512).unwrap_or_default();
            if symbol_name.is_empty() {
                continue;
            }

            let mut sym_type_char = typetab_ptr
                .and_then(|ptr| helpers::read_u8(layer, ptr + sym_idx as u64).ok())
                .map(|b| b as char)
                .or(Some(st_info as char));

            if let Some(c) = sym_type_char {
                if c == '\0' {
                    sym_type_char = None;
                }
            }

            // Match python's module.get_symbols + _is_symbol_exported semantics.
            let is_exported = if module_num_syms == 0 {
                Some(false)
            } else if let Some(values) = exported_symbols.get(&symbol_name) {
                Some(values.iter().any(|v| *v == st_value))
            } else {
                None
            };
            let sym_type = sym_type_char.map(|c| {
                if matches!(is_exported, Some(true)) {
                    c.to_ascii_uppercase().to_string()
                } else {
                    c.to_ascii_lowercase().to_string()
                }
            });
            let description = sym_type
                .as_deref()
                .and_then(nm_type_description)
                .map(|s| s.to_string());

            entries.push(KallsymsEntry {
                address: st_value,
                sym_type,
                size: Some(st_size),
                exported: is_exported,
                subsystem: "module".to_string(),
                module_name: module.name.clone(),
                symbol_name,
                description,
            });
        }
    }

    Ok(entries)
}

fn collect_bpf_symbols(
    context: &Context,
    layer: &dyn DataLayer,
    symbol_table: &str,
    aslr_shift: u64,
) -> Vol3Result<Vec<KallsymsEntry>> {
    let bpf_offsets = match get_bpf_ksym_offsets(context, symbol_table) {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };

    let Some(list_head_addr) =
        resolve_symbol_address(context, symbol_table, "bpf_kallsyms", aslr_shift)
    else {
        return Ok(Vec::new());
    };

    let head = list_head_addr & ADDRESS_MASK;
    let mut current = helpers::read_pointer(layer, head).unwrap_or(0) & ADDRESS_MASK;
    if current == 0 || current == head {
        return Ok(Vec::new());
    }

    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    while current != 0 && current != head && seen.insert(current) {
        let elem_addr = current.saturating_sub(bpf_offsets.lnode) & ADDRESS_MASK;
        if elem_addr == 0 {
            current = helpers::read_pointer(layer, current).unwrap_or(0) & ADDRESS_MASK;
            continue;
        }

        let sym_name =
            read_string_padded(layer, elem_addr + bpf_offsets.name, bpf_offsets.name_len)
                .unwrap_or_default();
        if sym_name.is_empty() {
            current = helpers::read_pointer(layer, current).unwrap_or(0) & ADDRESS_MASK;
            continue;
        }

        let sym_start_raw =
            read_unsigned(layer, elem_addr + bpf_offsets.start, bpf_offsets.start_size);
        let sym_end_raw = read_unsigned(layer, elem_addr + bpf_offsets.end, bpf_offsets.end_size);
        if sym_start_raw == 0 || sym_end_raw <= sym_start_raw {
            current = helpers::read_pointer(layer, current).unwrap_or(0) & ADDRESS_MASK;
            continue;
        }

        let sym_start = sym_start_raw & ADDRESS_MASK;
        let sym_size = sym_end_raw as i64 - sym_start_raw as i64;
        entries.push(KallsymsEntry {
            address: sym_start,
            sym_type: Some("t".to_string()),
            size: Some(sym_size),
            exported: Some(false),
            subsystem: "bpf".to_string(),
            module_name: "bpf".to_string(),
            symbol_name: sym_name,
            description: nm_type_description("t").map(|s| s.to_string()),
        });

        current = helpers::read_pointer(layer, current).unwrap_or(0) & ADDRESS_MASK;
    }

    Ok(entries)
}

fn build_core_kallsyms_config(
    context: &Context,
    symbol_table: &str,
    aslr_shift: u64,
) -> Vol3Result<CoreKallsymsConfig> {
    let required = |name: &str| -> Vol3Result<u64> {
        resolve_symbol_address(context, symbol_table, name, aslr_shift).ok_or_else(|| {
            Vol3Error::Object(ObjectError::MemberNotFound {
                type_name: "kallsyms".to_string(),
                member: name.to_string(),
            })
        })
    };

    let num_syms_address = required("kallsyms_num_syms")?;
    let names_address = required("kallsyms_names")?;
    let token_table_address = required("kallsyms_token_table")?;
    let token_index_address = required("kallsyms_token_index")?;

    let num_syms_type_size =
        symbol_type_size(context, symbol_table, "kallsyms_num_syms").unwrap_or(4);
    let long_size = symbol_type_size(context, symbol_table, "kallsyms_relative_base").unwrap_or(8);

    Ok(CoreKallsymsConfig {
        num_syms_address,
        names_address,
        token_table_address,
        token_index_address,
        offsets_address: resolve_symbol_address(
            context,
            symbol_table,
            "kallsyms_offsets",
            aslr_shift,
        ),
        relative_base_address: resolve_symbol_address(
            context,
            symbol_table,
            "kallsyms_relative_base",
            aslr_shift,
        ),
        addresses_address: resolve_symbol_address(
            context,
            symbol_table,
            "kallsyms_addresses",
            aslr_shift,
        ),
        sinittext_address: resolve_symbol_address(context, symbol_table, "_sinittext", aslr_shift),
        einittext_address: resolve_symbol_address(context, symbol_table, "_einittext", aslr_shift),
        etext_address: resolve_symbol_address(context, symbol_table, "_etext", aslr_shift),
        end_address: resolve_symbol_address(context, symbol_table, "_end", aslr_shift),
        num_syms_type_size,
        long_size,
    })
}

fn resolve_symbol_address(
    context: &Context,
    symbol_table: &str,
    symbol_name: &str,
    aslr_shift: u64,
) -> Option<u64> {
    context
        .get_symbol(symbol_table, symbol_name)
        .ok()
        .map(|s| s.address.wrapping_add(aslr_shift))
}

fn symbol_type_size(context: &Context, symbol_table: &str, symbol_name: &str) -> Option<usize> {
    let symbol = context.get_symbol(symbol_table, symbol_name).ok()?;
    let type_name = symbol.type_name?;
    let t = context
        .get_type(symbol_table, normalize_type_name(&type_name))
        .ok()?;
    t.size()
}

fn read_unsigned(layer: &dyn DataLayer, address: u64, size: usize) -> u64 {
    match size {
        1 => helpers::read_u8(layer, address).unwrap_or(0) as u64,
        2 => helpers::read_u16(layer, address).unwrap_or(0) as u64,
        4 => helpers::read_u32(layer, address).unwrap_or(0) as u64,
        8 => helpers::read_u64(layer, address).unwrap_or(0),
        _ => 0,
    }
}

fn get_symbol_address_by_index(
    layer: &dyn DataLayer,
    cfg: &CoreKallsymsConfig,
    index: usize,
    relative_base: u64,
) -> u64 {
    if let Some(offsets_address) = cfg.offsets_address {
        let sym_offset =
            helpers::read_i32(layer, offsets_address + (index as u64 * 4)).unwrap_or(0);
        if sym_offset < 0 {
            let rel = relative_base as i128;
            let off = sym_offset as i128;
            (rel - 1 - off) as u64
        } else {
            (sym_offset as u64) & ADDRESS_MASK
        }
    } else if let Some(addresses_address) = cfg.addresses_address {
        read_unsigned(
            layer,
            addresses_address + (index as u64 * cfg.long_size as u64),
            cfg.long_size,
        ) & ADDRESS_MASK
    } else {
        0
    }
}

fn core_symbol_fallback_end(cfg: &CoreKallsymsConfig, symbol_address: u64) -> u64 {
    if let (Some(sinit), Some(einit)) = (cfg.sinittext_address, cfg.einittext_address) {
        if sinit <= symbol_address && symbol_address < einit {
            return einit;
        }
    }
    cfg.end_address
        .or(cfg.etext_address)
        .unwrap_or(symbol_address)
}

fn compute_core_symbol_sizes(addresses: &[u64], cfg: &CoreKallsymsConfig) -> Vec<i64> {
    if addresses.is_empty() {
        return Vec::new();
    }

    let mut sizes = vec![0i64; addresses.len()];
    let mut i = 0usize;
    while i < addresses.len() {
        let start = addresses[i];
        let mut j = i + 1;
        while j < addresses.len() && addresses[j] == start {
            j += 1;
        }

        let end = if j < addresses.len() {
            addresses[j]
        } else {
            core_symbol_fallback_end(cfg, start)
        };

        let size = end as i64 - start as i64;
        for slot in sizes.iter_mut().take(j).skip(i) {
            *slot = size;
        }
        i = j;
    }

    sizes
}

fn expand_symbol(
    layer: &dyn DataLayer,
    names_address: u64,
    offset: usize,
    tokens: &[String],
) -> Option<(Option<String>, String, usize)> {
    let mut cursor = names_address + offset as u64;
    let first_len = helpers::read_u8(layer, cursor).ok()? as usize;
    cursor += 1;

    let compressed_length = if first_len & 0x80 != 0 {
        let upper = helpers::read_u8(layer, cursor).ok()? as usize;
        (upper << 7) | (first_len & 0x7f)
    } else {
        first_len
    };

    let token_indexes = layer.read(cursor, compressed_length, false).ok()?;

    let mut sym_type: Option<char> = None;
    let mut sym_name = String::new();

    for idx in token_indexes {
        let token = tokens.get(idx as usize)?;
        for ch in token.chars() {
            if sym_type.is_none() {
                sym_type = Some(ch);
            } else {
                sym_name.push(ch);
            }
        }
    }

    Some((sym_type.map(|c| c.to_string()), sym_name, compressed_length))
}

fn exported_from_type(sym_type: Option<&str>) -> Option<bool> {
    let c = sym_type.and_then(|s| s.chars().next())?;
    Some(c.is_ascii_uppercase() || matches!(c, 'u' | 'v' | 'w'))
}

fn nm_type_description(sym_type: &str) -> Option<&'static str> {
    match sym_type {
        "N" => Some("Symbol is a debugging symbol"),
        "U" => Some("Symbol is undefined"),
        "V" => Some("Symbol is a weak object, with a default value"),
        "W" => Some(
            "Symbol is a weak symbol but not marked as a weak object symbol, with a default value",
        ),
        "?" => Some("Symbol type is unknown"),
        "a" | "A" => Some("Symbol is absolute and doesn't change during linking"),
        "b" | "B" => Some(
            "Symbol in the BSS section, typically holding zero-initialized or uninitialized data",
        ),
        "c" | "C" => Some("Symbol is common, typically holding uninitialized data"),
        "d" | "D" => Some("Symbol is in the initialized data section"),
        "g" | "G" => Some("Symbol is in an initialized data section for small objects"),
        "i" | "I" => Some("Symbol is an indirect reference to another symbol"),
        "n" => Some("Symbol is in a non-data, non-code, non-debug read-only section"),
        "p" | "P" => Some("Symbol is in a stack unwind section"),
        "r" | "R" => Some("Symbol is in a read only data section"),
        "s" | "S" => {
            Some("Symbol is in an uninitialized or zero-initialized data section for small objects")
        }
        "t" | "T" => Some("Symbol is in the text (code) section"),
        "u" => Some("Symbol is a unique global symbol"),
        "v" => Some("Symbol is a weak object"),
        "w" => Some("Symbol is a weak symbol but not marked as a weak object symbol"),
        _ => None,
    }
}

fn get_module_symbol_offsets(context: &Context, symbol_table: &str) -> Option<ModuleSymbolOffsets> {
    let module_template = context.get_type(symbol_table, "module").ok()?;
    let TypeTemplate::Struct(module_struct) = module_template.as_ref() else {
        return None;
    };

    if let Some(kallsyms_field) = module_struct.get_field("kallsyms") {
        let (kallsyms_ptr, kallsyms_base) = match kallsyms_field.template.as_ref() {
            TypeTemplate::Pointer(_) => (Some(kallsyms_field.offset as u64), 0_u64),
            _ => (None, kallsyms_field.offset as u64),
        };
        let kallsyms_struct =
            resolve_struct_template(context, symbol_table, kallsyms_field.template.as_ref())?;
        let TypeTemplate::Struct(ks) = kallsyms_struct.as_ref() else {
            return None;
        };

        let symtab = kallsyms_base + ks.get_field("symtab")?.offset as u64;
        let num_symtab_field = ks.get_field("num_symtab")?;
        let num_symtab = kallsyms_base + num_symtab_field.offset as u64;
        let num_symtab_size = num_symtab_field.template.size().unwrap_or(4);
        let strtab = kallsyms_base + ks.get_field("strtab")?.offset as u64;
        let typetab = ks
            .get_field("typetab")
            .map(|f| kallsyms_base + f.offset as u64);
        let syms = module_struct.get_field("syms").map(|f| f.offset as u64);
        let num_syms_field = module_struct.get_field("num_syms");
        let num_syms = num_syms_field.map(|f| f.offset as u64);
        let num_syms_size = num_syms_field.and_then(|f| f.template.size()).unwrap_or(4);

        Some(ModuleSymbolOffsets {
            kallsyms_ptr,
            symtab,
            num_symtab,
            num_symtab_size,
            strtab,
            typetab,
            syms,
            num_syms,
            num_syms_size,
        })
    } else {
        let symtab_field = module_struct.get_field("symtab")?;
        let num_symtab_field = module_struct.get_field("num_symtab")?;
        let strtab_field = module_struct.get_field("strtab")?;
        let syms = module_struct.get_field("syms").map(|f| f.offset as u64);
        let num_syms_field = module_struct.get_field("num_syms");
        let num_syms = num_syms_field.map(|f| f.offset as u64);
        let num_syms_size = num_syms_field.and_then(|f| f.template.size()).unwrap_or(4);

        Some(ModuleSymbolOffsets {
            kallsyms_ptr: None,
            symtab: symtab_field.offset as u64,
            num_symtab: num_symtab_field.offset as u64,
            num_symtab_size: num_symtab_field.template.size().unwrap_or(4),
            strtab: strtab_field.offset as u64,
            typetab: None,
            syms,
            num_syms,
            num_syms_size,
        })
    }
}

fn get_kernel_symbol_offsets(context: &Context, symbol_table: &str) -> Option<KernelSymbolOffsets> {
    let kernel_symbol_template = context.get_type(symbol_table, "kernel_symbol").ok()?;
    let TypeTemplate::Struct(s) = kernel_symbol_template.as_ref() else {
        return None;
    };

    let entry_size = kernel_symbol_template.size().unwrap_or(24);
    let name_offset = s.get_field("name_offset").map(|f| f.offset as u64);
    let name_ptr = s.get_field("name").map(|f| f.offset as u64);
    let value_offset = s.get_field("value_offset").map(|f| f.offset as u64);
    let value_ptr = s.get_field("value").map(|f| f.offset as u64);
    if name_offset.is_none() && name_ptr.is_none() {
        return None;
    }
    if value_offset.is_none() && value_ptr.is_none() {
        return None;
    }

    Some(KernelSymbolOffsets {
        entry_size,
        name_offset,
        name_ptr,
        value_offset,
        value_ptr,
    })
}

fn get_bpf_ksym_offsets(context: &Context, symbol_table: &str) -> Option<BpfKsymOffsets> {
    let bpf_ksym_template = context.get_type(symbol_table, "bpf_ksym").ok()?;
    let TypeTemplate::Struct(s) = bpf_ksym_template.as_ref() else {
        return None;
    };

    let lnode = s.get_field("lnode")?.offset as u64;
    let name_field = s.get_field("name")?;
    let name = name_field.offset as u64;
    let name_len = match name_field.template.as_ref() {
        TypeTemplate::Array(arr) => arr.count.max(1),
        _ => 512,
    };
    let start_field = s.get_field("start")?;
    let end_field = s.get_field("end")?;

    Some(BpfKsymOffsets {
        lnode,
        name,
        name_len,
        start: start_field.offset as u64,
        start_size: start_field.template.size().unwrap_or(8).max(1),
        end: end_field.offset as u64,
        end_size: end_field.template.size().unwrap_or(8).max(1),
    })
}

fn collect_module_exported_symbols(
    layer: &dyn DataLayer,
    syms_ptr: u64,
    num_syms: usize,
    kernel_symbol_offsets: &KernelSymbolOffsets,
) -> HashMap<String, Vec<u64>> {
    let mut out: HashMap<String, Vec<u64>> = HashMap::new();
    if syms_ptr == 0 || num_syms == 0 || kernel_symbol_offsets.entry_size == 0 {
        return out;
    }

    for idx in 0..num_syms {
        let entry_addr = syms_ptr + idx as u64 * kernel_symbol_offsets.entry_size as u64;
        let Some(name) = read_kernel_symbol_name(layer, entry_addr, kernel_symbol_offsets) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let Some(value) = read_kernel_symbol_value(layer, entry_addr, kernel_symbol_offsets) else {
            continue;
        };
        out.entry(name).or_default().push(value);
    }

    out
}

fn read_kernel_symbol_name(
    layer: &dyn DataLayer,
    entry_addr: u64,
    offsets: &KernelSymbolOffsets,
) -> Option<String> {
    let name_ptr = if let Some(off) = offsets.name_offset {
        let rel = helpers::read_i32(layer, entry_addr + off).ok()? as i64;
        entry_addr.wrapping_add(rel as u64)
    } else if let Some(off) = offsets.name_ptr {
        helpers::read_pointer(layer, entry_addr + off).ok()?
    } else {
        return None;
    };

    read_string_padded(layer, name_ptr, 512)
}

fn read_kernel_symbol_value(
    layer: &dyn DataLayer,
    entry_addr: u64,
    offsets: &KernelSymbolOffsets,
) -> Option<u64> {
    if let Some(off) = offsets.value_offset {
        let rel = helpers::read_i32(layer, entry_addr + off).ok()? as i64;
        Some(entry_addr.wrapping_add(rel as u64))
    } else if let Some(off) = offsets.value_ptr {
        helpers::read_pointer(layer, entry_addr + off).ok()
    } else {
        None
    }
}

fn read_string_padded(layer: &dyn DataLayer, address: u64, max_len: usize) -> Option<String> {
    if max_len == 0 {
        return Some(String::new());
    }
    let bytes = layer.read(address, max_len, true).ok()?;
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..len]).to_string())
}

fn resolve_struct_template(
    context: &Context,
    symbol_table: &str,
    template: &TypeTemplate,
) -> Option<Arc<TypeTemplate>> {
    match template {
        TypeTemplate::Struct(_) => Some(Arc::new(template.clone())),
        TypeTemplate::ForwardRef(name) => context
            .get_type(symbol_table, normalize_type_name(name))
            .ok(),
        TypeTemplate::Pointer(p) => match p.target.as_ref() {
            TypeTemplate::Struct(_) => Some(p.target.clone()),
            TypeTemplate::ForwardRef(name) => context
                .get_type(symbol_table, normalize_type_name(name))
                .ok(),
            _ => None,
        },
        _ => context
            .get_type(symbol_table, normalize_type_name(template.type_name()))
            .ok(),
    }
}

fn normalize_type_name(name: &str) -> &str {
    name.rsplit_once('!').map(|(_, n)| n).unwrap_or(name)
}
