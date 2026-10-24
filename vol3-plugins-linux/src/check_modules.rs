//! Linux CheckModules plugin.
//!
//! Compares module list to sysfs for differences.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::helpers;

/// CheckModules plugin - compares module lists
pub struct CheckModules;

impl CheckModules {
    pub fn new() -> Self {
        Self
    }

    fn check_modules(context: &Context) -> Vol3Result<Vec<ModuleCheckEntry>> {
        use vol3_core::error::{ConfigError, LayerError, ObjectError};

        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let layer = context
            .get_layer(&layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(layer_name.clone())))?;

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        let address_mask: u64 = 0x0000_FFFF_FFFF_FFFF;
        let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;

        let module_template = context.get_type(&symbol_table, "module")?;
        let module_struct = if let TypeTemplate::Struct(s) = module_template.as_ref() {
            s
        } else {
            return Err(Vol3Error::Object(ObjectError::InvalidTemplate(
                "Expected module struct".to_string(),
            )));
        };
        let list_offset = module_struct
            .get_field("list")
            .map(|f| f.offset as u64)
            .ok_or_else(|| {
                Vol3Error::Object(ObjectError::MemberNotFound {
                    type_name: "module".to_string(),
                    member: "list".to_string(),
                })
            })?;
        let name_offset = module_struct
            .get_field("name")
            .map(|f| f.offset as u64)
            .unwrap_or(0);
        let taints_offset = module_struct
            .get_field("taints")
            .map(|f| f.offset as u64)
            .unwrap_or(0);
        let (init_size_offset, core_size_offset) = if let Some(core_layout_off) = module_struct
            .get_field("core_layout")
            .map(|f| f.offset as u64)
        {
            let init_layout_off = module_struct
                .get_field("init_layout")
                .map(|f| f.offset as u64)
                .unwrap_or(0);
            (init_layout_off + 8, core_layout_off + 8)
        } else {
            (
                module_struct
                    .get_field("init_size")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                module_struct
                    .get_field("core_size")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
            )
        };

        let lsmod_modules = get_lsmod_module_names(
            context,
            layer.as_ref(),
            &symbol_table,
            list_offset,
            name_offset,
            address_mask,
            aslr_shift,
        )?;

        let kset_modules = get_kset_modules(
            context,
            layer.as_ref(),
            &symbol_table,
            address_mask,
            aslr_shift,
        )?;

        let mut out = Vec::new();
        let mut seen_mod_ptrs = HashSet::new();

        for (kset_name, kset_module) in kset_modules {
            if lsmod_modules.contains(&kset_name) {
                continue;
            }
            if kset_module.module_ptr == 0 {
                continue;
            }
            if !seen_mod_ptrs.insert(kset_module.module_ptr) {
                continue;
            }

            let module_name =
                read_module_name(layer.as_ref(), kset_module.module_ptr + name_offset)
                    .unwrap_or(kset_name);
            let init_size =
                read_u32_or_zero(layer.as_ref(), kset_module.module_ptr + init_size_offset) as u64;
            let core_size =
                read_u32_or_zero(layer.as_ref(), kset_module.module_ptr + core_size_offset) as u64;
            let taints_raw = if taints_offset > 0 {
                read_u64_or_zero(layer.as_ref(), kset_module.module_ptr + taints_offset)
            } else {
                0
            };

            out.push(ModuleCheckEntry {
                offset: kset_module.offset,
                module_name,
                code_size: init_size + core_size,
                taints: parse_taints(taints_raw),
                load_arguments: String::new(),
                file_output: "N/A".to_string(),
            });
        }

        Ok(out)
    }
}

impl Default for CheckModules {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct ModuleCheckEntry {
    offset: u64,
    module_name: String,
    code_size: u64,
    taints: String,
    load_arguments: String,
    file_output: String,
}

impl Module for CheckModules {
    fn name(&self) -> &str {
        "linux.check_modules.CheckModules"
    }

    fn description(&self) -> &str {
        "Compares module list to sysfs"
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
            Column::new("Module Name", ColumnType::String),
            Column::new("Code Size", ColumnType::Hex),
            Column::new("Taints", ColumnType::String),
            Column::new("Load Arguments", ColumnType::String),
            Column::new("File Output", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::check_modules(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Hex(e.offset),
                    CellValue::String(e.module_name),
                    CellValue::Hex(e.code_size),
                    CellValue::String(e.taints),
                    CellValue::String(e.load_arguments),
                    CellValue::String(e.file_output),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}

fn get_lsmod_module_names(
    context: &Context,
    layer: &dyn DataLayer,
    symbol_table: &str,
    list_offset: u64,
    name_offset: u64,
    address_mask: u64,
    aslr_shift: u64,
) -> Vol3Result<HashSet<String>> {
    let mut names = HashSet::new();
    let modules_sym = context.get_symbol(symbol_table, "modules")?;
    let modules_head = modules_sym.address.wrapping_add(aslr_shift);

    let first = read_pointer(layer, modules_head)? & address_mask;
    if first == 0 || first == (modules_head & address_mask) {
        return Ok(names);
    }

    let mut seen = HashSet::new();
    let mut current = first;

    while current != 0 && current != (modules_head & address_mask) && !seen.contains(&current) {
        seen.insert(current);
        let module_addr = (current.saturating_sub(list_offset)) & address_mask;
        if let Ok(name) = read_module_name(layer, module_addr + name_offset) {
            if !name.is_empty() {
                names.insert(name);
            }
        }
        current = read_pointer(layer, current)? & address_mask;
    }

    Ok(names)
}

fn get_kset_modules(
    context: &Context,
    layer: &dyn DataLayer,
    symbol_table: &str,
    address_mask: u64,
    aslr_shift: u64,
) -> Vol3Result<HashMap<String, KsetModule>> {
    let kset_symbol = match context.get_symbol(symbol_table, "module_kset") {
        Ok(s) => s,
        Err(_) => return Ok(HashMap::new()),
    };

    let kset_template = context.get_type(symbol_table, "kset")?;
    let kset_list_offset = if let TypeTemplate::Struct(s) = kset_template.as_ref() {
        s.get_field("list").map(|f| f.offset as u64).unwrap_or(0)
    } else {
        0
    };

    // Depending on symbol handling, module_kset can require either direct use or dereference.
    let module_kset_addr = {
        let sym = kset_symbol.address;
        let candidates = [
            sym.wrapping_add(aslr_shift),
            sym,
            read_pointer(layer, sym.wrapping_add(aslr_shift)).unwrap_or(0),
            read_pointer(layer, sym).unwrap_or(0),
        ];

        let mut chosen = 0_u64;
        for cand_raw in candidates {
            let cand = cand_raw & address_mask;
            if cand == 0 {
                continue;
            }
            let list_head = cand + kset_list_offset;
            let first = read_pointer(layer, list_head).unwrap_or(0) & address_mask;
            if first != 0 && first != (list_head & address_mask) {
                chosen = cand;
                break;
            }
        }
        chosen
    };

    if module_kset_addr == 0 {
        return Ok(HashMap::new());
    }

    let kobject_template = context.get_type(symbol_table, "kobject")?;
    let (kobj_entry_offset, kobj_name_offset, kobj_kref_offset, kobj_kref_template) =
        if let TypeTemplate::Struct(s) = kobject_template.as_ref() {
            let kref_field = s.get_field("kref");
            (
                s.get_field("entry").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("name").map(|f| f.offset as u64).unwrap_or(0),
                kref_field.map(|f| f.offset as u64),
                kref_field.map(|f| f.template.clone()),
            )
        } else {
            (0, 0, None, None)
        };

    let (
        kref_refcount_offset,
        refcount_counter_offset,
        refcount_refs_offset,
        atomic_counter_offset,
    ) = if let Some(kref_template) = kobj_kref_template {
        if let TypeTemplate::Struct(kref_struct) = kref_template.as_ref() {
            if let Some(refcount_field) = kref_struct.get_field("refcount") {
                let mut counter_offset = None;
                let mut refs_offset = None;
                let mut refs_counter_offset = None;

                if let TypeTemplate::Struct(refcount_struct) = refcount_field.template.as_ref() {
                    counter_offset = refcount_struct
                        .get_field("counter")
                        .map(|f| f.offset as u64);
                    if let Some(refs_field) = refcount_struct.get_field("refs") {
                        refs_offset = Some(refs_field.offset as u64);
                        if let TypeTemplate::Struct(atomic_struct) = refs_field.template.as_ref() {
                            refs_counter_offset =
                                atomic_struct.get_field("counter").map(|f| f.offset as u64);
                        }
                    }
                }

                (
                    Some(refcount_field.offset as u64),
                    counter_offset,
                    refs_offset,
                    refs_counter_offset,
                )
            } else {
                (None, None, None, None)
            }
        } else {
            (None, None, None, None)
        }
    } else {
        (None, None, None, None)
    };

    let module_kobject_template = context.get_type(symbol_table, "module_kobject")?;
    let (mod_kobj_kobj_offset, mod_kobj_mod_offset) =
        if let TypeTemplate::Struct(s) = module_kobject_template.as_ref() {
            (
                s.get_field("kobj").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("mod").map(|f| f.offset as u64).unwrap_or(0),
            )
        } else {
            (0, 0)
        };

    let list_head = module_kset_addr + kset_list_offset;
    let first = read_pointer(layer, list_head).unwrap_or(0) & address_mask;
    if first == 0 || first == (list_head & address_mask) {
        return Ok(HashMap::new());
    }

    let mut out = HashMap::new();
    let mut seen = HashSet::new();
    let mut current = first;

    while current != 0 && current != (list_head & address_mask) && !seen.contains(&current) {
        seen.insert(current);

        let kobj_addr = (current.saturating_sub(kobj_entry_offset)) & address_mask;
        if kobj_addr == 0 {
            current = read_pointer(layer, current).unwrap_or(0) & address_mask;
            continue;
        }

        let name_ptr =
            read_pointer(layer, kobj_addr + kobj_name_offset).unwrap_or(0) & address_mask;
        let name = if name_ptr != 0 {
            helpers::read_string(layer, name_ptr, 32).unwrap_or_default()
        } else {
            String::new()
        };

        if let Some(refcount) = read_kobject_refcount(
            layer,
            kobj_addr,
            kobj_kref_offset,
            kref_refcount_offset,
            refcount_counter_offset,
            refcount_refs_offset,
            atomic_counter_offset,
        ) {
            if refcount <= 2 {
                current = read_pointer(layer, current).unwrap_or(0) & address_mask;
                continue;
            }
        }

        let module_kobj_addr = kobj_addr.saturating_sub(mod_kobj_kobj_offset);
        let module_field_addr = (module_kobj_addr + mod_kobj_mod_offset) & address_mask;
        let module_ptr =
            read_pointer(layer, module_kobj_addr + mod_kobj_mod_offset).unwrap_or(0) & address_mask;

        if !name.is_empty() && module_ptr != 0 {
            out.insert(
                name,
                KsetModule {
                    offset: module_field_addr,
                    module_ptr,
                },
            );
        }

        current = read_pointer(layer, current).unwrap_or(0) & address_mask;
    }

    Ok(out)
}

#[derive(Debug, Clone, Copy)]
struct KsetModule {
    offset: Address,
    module_ptr: Address,
}

fn read_kobject_refcount(
    layer: &dyn DataLayer,
    kobj_addr: Address,
    kobj_kref_offset: Option<u64>,
    kref_refcount_offset: Option<u64>,
    refcount_counter_offset: Option<u64>,
    refcount_refs_offset: Option<u64>,
    atomic_counter_offset: Option<u64>,
) -> Option<u64> {
    let kobj_kref_offset = kobj_kref_offset?;
    let kref_refcount_offset = kref_refcount_offset?;
    let refcount_base = kobj_addr
        .checked_add(kobj_kref_offset)?
        .checked_add(kref_refcount_offset)?;

    if let Some(counter_offset) = refcount_counter_offset {
        return Some(read_u32_or_zero(layer, refcount_base + counter_offset) as u64);
    }

    if let Some(refs_offset) = refcount_refs_offset {
        let refs_base = refcount_base.checked_add(refs_offset)?;
        if let Some(counter_offset) = atomic_counter_offset {
            return Some(read_u32_or_zero(layer, refs_base + counter_offset) as u64);
        }
        return Some(read_u32_or_zero(layer, refs_base) as u64);
    }

    None
}

fn read_pointer(layer: &dyn DataLayer, address: Address) -> Vol3Result<Address> {
    let bytes = layer.read(address, 8, false).map_err(Vol3Error::Layer)?;
    Ok(LittleEndian::read_u64(&bytes))
}

fn read_module_name(layer: &dyn DataLayer, address: Address) -> Vol3Result<String> {
    let bytes = layer.read(address, 64, false).map_err(Vol3Error::Layer)?;
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..len]).to_string())
}

fn read_u32_or_zero(layer: &dyn DataLayer, address: Address) -> u32 {
    match layer.read(address, 4, false) {
        Ok(bytes) => LittleEndian::read_u32(&bytes),
        Err(_) => 0,
    }
}

fn read_u64_or_zero(layer: &dyn DataLayer, address: Address) -> u64 {
    match layer.read(address, 8, false) {
        Ok(bytes) => LittleEndian::read_u64(&bytes),
        Err(_) => 0,
    }
}

fn parse_taints(taints: u64) -> String {
    let mut result = String::new();
    if taints != 0 {
        let flags = [('P', 0), ('O', 12), ('E', 15)];
        for (c, bit) in flags {
            if (taints >> bit) & 1 != 0 {
                result.push(c);
            }
        }
    }
    result
}
