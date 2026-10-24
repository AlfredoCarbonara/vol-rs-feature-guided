//! Linux LibraryList plugin.
//!
//! Lists libraries loaded into processes via ELF auxiliary vector.

use std::collections::HashSet;
use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::intel::Intel32e;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::extensions::TaskStructExt;
use crate::helpers;
use crate::process_layer;

#[derive(Debug, Clone, Copy)]
struct VmaValidationOffsets {
    vm_start: u64,
    vm_end: u64,
    vm_flags: u64,
    vm_file: u64,
    vm_pgoff: u64,
    f_inode: Option<u64>,
    f_path: Option<u64>,
    path_dentry: Option<u64>,
    d_inode: Option<u64>,
    inode_i_size: Option<u64>,
}

/// LibraryList plugin - lists loaded libraries
pub struct LibraryList;

impl LibraryList {
    pub fn new() -> Self {
        Self
    }

    fn list_libraries(context: &Context) -> Vol3Result<Vec<LibraryEntry>> {
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

        let init_task_addr = helpers::get_init_task(context, &symbol_table)?;
        let template = helpers::get_task_struct_template(context, &symbol_table)?;
        let tasks = helpers::collect_processes(layer.as_ref(), init_task_addr, &template)?;

        let pid_filter = context
            .config_get_int("plugins.library_list.pid")
            .map(|v| v as i32);

        let mm_template = context.get_type(&symbol_table, "mm_struct")?;
        let mmap_offset = if let TypeTemplate::Struct(s) = mm_template.as_ref() {
            s.get_field("mmap").map(|f| f.offset as u64)
        } else {
            None
        };

        let vma_template = context.get_type(&symbol_table, "vm_area_struct")?;
        let (
            vm_start_offset,
            vm_end_offset,
            vm_flags_offset,
            vm_file_offset,
            vm_pgoff_offset,
            vm_next_offset,
        ) = if let TypeTemplate::Struct(s) = vma_template.as_ref() {
            (
                s.get_field("vm_start")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                s.get_field("vm_end").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("vm_flags")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                s.get_field("vm_file").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("vm_pgoff")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                s.get_field("vm_next").map(|f| f.offset as u64),
            )
        } else {
            (0, 0, 0, 0, 0, None)
        };

        let file_template = context.get_type(&symbol_table, "file")?;
        let f_inode_offset = if let TypeTemplate::Struct(s) = file_template.as_ref() {
            s.get_field("f_inode").map(|f| f.offset as u64)
        } else {
            None
        };
        let f_path_offset = if let TypeTemplate::Struct(s) = file_template.as_ref() {
            s.get_field("f_path").map(|f| f.offset as u64)
        } else {
            None
        };

        let path_template = context.get_type(&symbol_table, "path")?;
        let path_dentry_offset = if let TypeTemplate::Struct(s) = path_template.as_ref() {
            s.get_field("dentry").map(|f| f.offset as u64)
        } else {
            None
        };

        let dentry_template = context.get_type(&symbol_table, "dentry")?;
        let d_inode_offset = if let TypeTemplate::Struct(s) = dentry_template.as_ref() {
            s.get_field("d_inode").map(|f| f.offset as u64)
        } else {
            None
        };

        let inode_i_size_offset =
            if let Ok(inode_template) = context.get_type(&symbol_table, "inode") {
                if let TypeTemplate::Struct(s) = inode_template.as_ref() {
                    s.get_field("i_size").map(|f| f.offset as u64)
                } else {
                    None
                }
            } else {
                None
            };

        let vma_validation = VmaValidationOffsets {
            vm_start: vm_start_offset,
            vm_end: vm_end_offset,
            vm_flags: vm_flags_offset,
            vm_file: vm_file_offset,
            vm_pgoff: vm_pgoff_offset,
            f_inode: f_inode_offset,
            f_path: f_path_offset,
            path_dentry: path_dentry_offset,
            d_inode: d_inode_offset,
            inode_i_size: inode_i_size_offset,
        };

        let mut entries = Vec::new();

        for task in &tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(0);
            let tgid = task.tgid(layer.as_ref()).unwrap_or(pid);
            if pid != tgid {
                continue;
            }
            if let Some(target_pid) = pid_filter {
                if tgid != target_pid {
                    continue;
                }
            }

            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            // Kernel threads do not have an mm struct.
            let mm_ptr = task.mm(layer.as_ref()).unwrap_or(0);
            if mm_ptr == 0 || !helpers::is_valid_kernel_address(mm_ptr) {
                continue;
            }

            let proc_layer = match process_layer::create_process_layer(
                context,
                &layer_name,
                task,
                &symbol_table,
            )? {
                Some(l) => l,
                None => continue,
            };

            let vmas = if let Some(mmap_off) = mmap_offset {
                collect_vmas_mmap(layer.as_ref(), mm_ptr + mmap_off, vm_next_offset)?
            } else {
                Vec::new()
            };

            let mut seen_load_addresses = HashSet::new();
            for vma_addr in vmas {
                let Some((vma_start, _vma_end)) =
                    validate_vma(layer.as_ref(), vma_addr, &vma_validation)
                else {
                    continue;
                };

                for (load_address, path) in get_vma_link_maps(proc_layer.as_ref(), vma_start) {
                    if !seen_load_addresses.insert(load_address) {
                        continue;
                    }

                    entries.push(LibraryEntry {
                        name: comm.clone(),
                        pid: tgid,
                        load_address,
                        path,
                    });
                }
            }
        }

        Ok(entries)
    }
}

fn validate_vma(
    layer: &dyn DataLayer,
    vma_addr: u64,
    offsets: &VmaValidationOffsets,
) -> Option<(u64, u64)> {
    const PAGE_SIZE: u64 = 0x1000;
    const USERSPACE_MAX: u64 = 0x0000_8000_0000_0000;
    const PAGE_SHIFT: u64 = 12;

    // vm_flags must be readable for get_protection() to work.
    let _vm_flags = helpers::read_u64(layer, vma_addr + offsets.vm_flags).ok()?;
    let vm_start = helpers::read_pointer(layer, vma_addr + offsets.vm_start).ok()?;
    let vm_end = helpers::read_pointer(layer, vma_addr + offsets.vm_end).ok()?;

    if vm_start > vm_end {
        return None;
    }

    let length = vm_end.saturating_sub(vm_start);
    if vm_start == 0 && length == 0 {
        return None;
    }

    if length == 0 || (length % PAGE_SIZE) != 0 {
        return None;
    }

    if vm_start >= USERSPACE_MAX {
        return None;
    }

    let vm_file = helpers::read_pointer(layer, vma_addr + offsets.vm_file).unwrap_or(0);
    if vm_file != 0 {
        let inode_ptr = if let Some(f_inode_off) = offsets.f_inode {
            helpers::read_pointer(layer, vm_file + f_inode_off).unwrap_or(0)
        } else if let (Some(f_path_off), Some(path_dentry_off), Some(d_inode_off)) =
            (offsets.f_path, offsets.path_dentry, offsets.d_inode)
        {
            let dentry_ptr =
                helpers::read_pointer(layer, vm_file + f_path_off + path_dentry_off).unwrap_or(0);
            if dentry_ptr != 0 {
                helpers::read_pointer(layer, dentry_ptr + d_inode_off).unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };

        if inode_ptr == 0
            || !helpers::is_valid_kernel_address(inode_ptr)
            || !layer.is_valid(inode_ptr, 1)
        {
            return None;
        }

        if let Some(i_size_off) = offsets.inode_i_size {
            let inode_size = helpers::read_i64(layer, inode_ptr + i_size_off).unwrap_or(0);
            if inode_size > 0 {
                let vm_pgoff = helpers::read_u64(layer, vma_addr + offsets.vm_pgoff).unwrap_or(0);
                let page_offset = vm_pgoff.checked_shl(PAGE_SHIFT as u32).unwrap_or(u64::MAX);
                if page_offset > inode_size as u64 {
                    return None;
                }
            }
        }
    }

    Some((vm_start, vm_end))
}

/// Collect VMA addresses from an mm_struct mmap linked list.
fn collect_vmas_mmap(
    layer: &dyn DataLayer,
    mmap_ptr_addr: u64,
    vm_next_offset: Option<u64>,
) -> Vol3Result<Vec<u64>> {
    let mut vmas = Vec::new();
    let mut seen = HashSet::new();

    let mut vma_ptr = helpers::read_pointer(layer, mmap_ptr_addr)?;
    while vma_ptr != 0 && helpers::is_valid_kernel_address(vma_ptr) && !seen.contains(&vma_ptr) {
        seen.insert(vma_ptr);
        vmas.push(vma_ptr);

        if let Some(next_off) = vm_next_offset {
            vma_ptr = helpers::read_pointer(layer, vma_ptr + next_off).unwrap_or(0);
        } else {
            break;
        }
    }

    Ok(vmas)
}

fn read_u16_le(layer: &dyn DataLayer, address: u64) -> Option<u16> {
    let bytes = layer.read(address, 2, false).ok()?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(layer: &dyn DataLayer, address: u64) -> Option<u32> {
    let bytes = layer.read(address, 4, false).ok()?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i32_le(layer: &dyn DataLayer, address: u64) -> Option<i32> {
    read_u32_le(layer, address).map(|v| v as i32)
}

fn read_u64_le(layer: &dyn DataLayer, address: u64) -> Option<u64> {
    let bytes = layer.read(address, 8, false).ok()?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_i64_le(layer: &dyn DataLayer, address: u64) -> Option<i64> {
    read_u64_le(layer, address).map(|v| v as i64)
}

fn read_cstring(layer: &dyn DataLayer, address: u64, max_len: usize) -> Option<String> {
    let bytes = layer.read(address, max_len, false).ok()?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).to_string())
}

/// Parse link maps from an ELF object at `elf_base` on the process layer.
fn get_vma_link_maps(proc_layer: &Intel32e, elf_base: u64) -> Vec<(u64, String)> {
    const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
    const PT_DYNAMIC: u32 = 2;
    const DT_NULL: i64 = 0;
    const DT_PLTGOT: i64 = 3;
    const ET_DYN: u16 = 3;
    const MAX_DYN_ENTRIES: usize = 256;
    const MAX_LINKMAP_ITER: usize = 4096;
    const USERSPACE_MAX: u64 = 0x0000_8000_0000_0000;

    let layer: &dyn DataLayer = proc_layer;
    let magic = match layer.read(elf_base, 4, false) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    if magic.as_slice() != ELF_MAGIC {
        return Vec::new();
    }

    let ei_class = match layer.read(elf_base + 4, 1, false) {
        Ok(v) if !v.is_empty() => v[0],
        _ => return Vec::new(),
    };

    let is_elf64 = match ei_class {
        1 => false,
        2 => true,
        _ => return Vec::new(),
    };

    let e_type = match read_u16_le(layer, elf_base + 16) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let (e_phoff, e_phentsize, e_phnum) = if is_elf64 {
        let phoff = match read_u64_le(layer, elf_base + 32) {
            Some(v) => v,
            None => return Vec::new(),
        };
        let phentsize = read_u16_le(layer, elf_base + 54).unwrap_or(0) as u64;
        let phnum = read_u16_le(layer, elf_base + 56).unwrap_or(0) as u64;
        (phoff, phentsize, phnum)
    } else {
        let phoff = match read_u32_le(layer, elf_base + 28) {
            Some(v) => v as u64,
            None => return Vec::new(),
        };
        let phentsize = read_u16_le(layer, elf_base + 42).unwrap_or(0) as u64;
        let phnum = read_u16_le(layer, elf_base + 44).unwrap_or(0) as u64;
        (phoff, phentsize, phnum)
    };

    if e_phoff == 0 || e_phentsize == 0 || e_phnum == 0 {
        return Vec::new();
    }

    let got_entry_size = if is_elf64 { 8_u64 } else { 4_u64 };
    let mut out = Vec::new();
    let mut seen_linkmap_offsets = HashSet::new();

    for i in 0..e_phnum {
        let phdr_addr = elf_base + e_phoff + (i * e_phentsize);
        let p_type = match read_u32_le(layer, phdr_addr) {
            Some(v) => v,
            None => continue,
        };
        if p_type != PT_DYNAMIC {
            continue;
        }

        let p_vaddr = if is_elf64 {
            read_u64_le(layer, phdr_addr + 16).unwrap_or(0)
        } else {
            read_u32_le(layer, phdr_addr + 8).unwrap_or(0) as u64
        };
        if p_vaddr == 0 {
            continue;
        }

        let dyn_start = if e_type == ET_DYN {
            elf_base + p_vaddr
        } else {
            p_vaddr
        };
        let dyn_entry_size = if is_elf64 { 16_u64 } else { 8_u64 };
        let mut got_start = 0_u64;

        for d_idx in 0..MAX_DYN_ENTRIES {
            let d_addr = dyn_start + (d_idx as u64 * dyn_entry_size);
            let (d_tag, d_ptr) = if is_elf64 {
                (
                    read_i64_le(layer, d_addr).unwrap_or(DT_NULL),
                    read_u64_le(layer, d_addr + 8).unwrap_or(0),
                )
            } else {
                (
                    read_i32_le(layer, d_addr).unwrap_or(DT_NULL as i32) as i64,
                    read_u32_le(layer, d_addr + 4).unwrap_or(0) as u64,
                )
            };

            if d_tag == DT_NULL {
                break;
            }
            if d_tag == DT_PLTGOT {
                got_start = d_ptr;
                break;
            }
        }

        if got_start == 0 {
            continue;
        }

        let link_map_ptr_addr = got_start + got_entry_size;
        let mut link_map = if is_elf64 {
            read_u64_le(layer, link_map_ptr_addr).unwrap_or(0)
        } else {
            read_u32_le(layer, link_map_ptr_addr).unwrap_or(0) as u64
        };
        let link_map_size = if is_elf64 { 40_usize } else { 20_usize };

        let mut iter_count = 0usize;
        while link_map != 0 && iter_count < MAX_LINKMAP_ITER {
            if link_map >= USERSPACE_MAX || !layer.is_valid(link_map, link_map_size) {
                break;
            }
            if !seen_linkmap_offsets.insert(link_map) {
                break;
            }
            iter_count += 1;

            let (l_addr, l_name, l_next) = if is_elf64 {
                (
                    read_u64_le(layer, link_map).unwrap_or(0),
                    read_u64_le(layer, link_map + 8).unwrap_or(0),
                    read_u64_le(layer, link_map + 24).unwrap_or(0),
                )
            } else {
                (
                    read_u32_le(layer, link_map).unwrap_or(0) as u64,
                    read_u32_le(layer, link_map + 4).unwrap_or(0) as u64,
                    read_u32_le(layer, link_map + 12).unwrap_or(0) as u64,
                )
            };

            if l_addr != 0
                && l_addr < USERSPACE_MAX
                && l_name != 0
                && l_name < USERSPACE_MAX
                && layer.is_valid(l_name, 1)
            {
                if let Some(name) = read_cstring(layer, l_name, 256) {
                    if !name.is_empty() {
                        out.push((l_addr, name));
                    }
                }
            }

            if l_next != 0 && (l_next >= USERSPACE_MAX || !layer.is_valid(l_next, link_map_size)) {
                break;
            }
            link_map = l_next;
        }
    }

    out
}

impl Default for LibraryList {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct LibraryEntry {
    name: String,
    pid: i32,
    load_address: u64,
    path: String,
}

impl Module for LibraryList {
    fn name(&self) -> &str {
        "linux.library_list.LibraryList"
    }

    fn description(&self) -> &str {
        "Lists libraries loaded into processes via ELF auxiliary vector"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Memory layer for the kernel")
            .symbol_table("vmlinux", "Linux kernel symbol table")
            .int_optional("pid", "Process ID filter")
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
            Column::new("Pid", ColumnType::Int),
            Column::new("LoadAddress", ColumnType::Hex),
            Column::new("Path", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_libraries(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::String(e.name),
                    CellValue::Int(e.pid as i64),
                    CellValue::Hex(e.load_address),
                    CellValue::String(e.path),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
