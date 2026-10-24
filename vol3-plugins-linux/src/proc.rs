//! Linux Proc plugin.
//!
//! Process memory maps similar to /proc/[pid]/maps.

use std::collections::HashSet;
use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;
use crate::lsof;

const MAPLE_NODE_TYPE_SHIFT: u64 = 0x03;
const MAPLE_NODE_TYPE_MASK: u64 = 0x0F;
const MAPLE_NODE_POINTER_MASK: u64 = 0xFF;
const MAPLE_DENSE: u64 = 0;
const MAPLE_LEAF_64: u64 = 1;
const MAPLE_RANGE_64: u64 = 2;
const MAPLE_ARANGE_64: u64 = 3;

#[derive(Debug, Clone)]
struct MapleOffsets {
    ma_root_offset: u64,
    alloc_slot_offset: u64,
    alloc_slot_count: usize,
    mr64_slot_offset: u64,
    mr64_slot_count: usize,
    ma64_slot_offset: u64,
    ma64_slot_count: usize,
}

/// Proc plugin - process memory maps
pub struct Proc;

impl Proc {
    pub fn new() -> Self {
        Self
    }

    pub(crate) fn list_proc_maps(context: &Context) -> Vol3Result<Vec<ProcMapEntry>> {
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
        let pid_filter = context.config_get_int("pid").map(|v| v as i32);

        let task_template = context.get_type(&symbol_table, "task_struct")?;
        let mm_offset = helpers::get_field_offset_recursive(task_template.as_ref(), "mm")
            .map(|v| v as u64)
            .unwrap_or(0);
        let fs_offset = helpers::get_field_offset_recursive(task_template.as_ref(), "fs")
            .map(|v| v as u64)
            .unwrap_or(0);

        let mm_template = context.get_type(&symbol_table, "mm_struct")?;
        let (
            mmap_offset,
            mm_mt_offset,
            start_brk_offset,
            brk_offset,
            start_stack_offset,
            context_offset,
            context_vdso_offset,
            context_is_ptr,
        ) = if let TypeTemplate::Struct(_) = mm_template.as_ref() {
            let mut ctx_off = None;
            let mut vdso_off = None;
            let mut ctx_is_ptr = false;

            if let TypeTemplate::Struct(s) = mm_template.as_ref() {
                if let Some(ctx_field) = s.get_field("context") {
                    ctx_off = Some(ctx_field.offset as u64);
                    match ctx_field.template.as_ref() {
                        TypeTemplate::Struct(cs) => {
                            vdso_off = helpers::get_field_offset_recursive(
                                &TypeTemplate::Struct(cs.clone()),
                                "vdso",
                            )
                            .map(|v| v as u64);
                        }
                        TypeTemplate::Pointer(p) => {
                            ctx_is_ptr = true;
                            if let TypeTemplate::Struct(cs) = p.target.as_ref() {
                                vdso_off = helpers::get_field_offset_recursive(
                                    &TypeTemplate::Struct(cs.clone()),
                                    "vdso",
                                )
                                .map(|v| v as u64);
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Some ISFs keep fields under anonymous wrappers.
            if ctx_off.is_none() {
                ctx_off = helpers::get_field_offset_recursive(mm_template.as_ref(), "context")
                    .map(|v| v as u64);
            }
            if vdso_off.is_none() {
                if let Ok(mm_ctx_template) = context.get_type(&symbol_table, "mm_context_t") {
                    vdso_off =
                        helpers::get_field_offset_recursive(mm_ctx_template.as_ref(), "vdso")
                            .map(|v| v as u64);
                }
            }

            (
                helpers::get_field_offset_recursive(mm_template.as_ref(), "mmap").map(|v| v as u64),
                helpers::get_field_offset_recursive(mm_template.as_ref(), "mm_mt")
                    .map(|v| v as u64),
                helpers::get_field_offset_recursive(mm_template.as_ref(), "start_brk")
                    .map(|v| v as u64)
                    .unwrap_or(0),
                helpers::get_field_offset_recursive(mm_template.as_ref(), "brk")
                    .map(|v| v as u64)
                    .unwrap_or(0),
                helpers::get_field_offset_recursive(mm_template.as_ref(), "start_stack")
                    .map(|v| v as u64)
                    .unwrap_or(0),
                ctx_off,
                vdso_off,
                ctx_is_ptr,
            )
        } else {
            (None, None, 0, 0, 0, None, None, false)
        };

        let vma_template = context.get_type(&symbol_table, "vm_area_struct")?;
        let (
            vm_start_offset,
            vm_end_offset,
            vm_next_offset,
            vm_file_offset,
            vm_flags_offset,
            vm_pgoff_offset,
        ) = if let TypeTemplate::Struct(_) = vma_template.as_ref() {
            (
                helpers::get_field_offset_recursive(vma_template.as_ref(), "vm_start")
                    .map(|v| v as u64)
                    .unwrap_or(0),
                helpers::get_field_offset_recursive(vma_template.as_ref(), "vm_end")
                    .map(|v| v as u64)
                    .unwrap_or(0),
                helpers::get_field_offset_recursive(vma_template.as_ref(), "vm_next")
                    .map(|v| v as u64),
                helpers::get_field_offset_recursive(vma_template.as_ref(), "vm_file")
                    .map(|v| v as u64)
                    .unwrap_or(0),
                helpers::get_field_offset_recursive(vma_template.as_ref(), "vm_flags")
                    .map(|v| v as u64)
                    .unwrap_or(0),
                helpers::get_field_offset_recursive(vma_template.as_ref(), "vm_pgoff")
                    .map(|v| v as u64)
                    .unwrap_or(0),
            )
        } else {
            (0, 0, None, 0, 0, 0)
        };
        let maple_offsets = parse_maple_offsets(context, &symbol_table);

        let fs_struct_template = context.get_type(&symbol_table, "fs_struct")?;
        let root_offset = helpers::get_field_offset_recursive(fs_struct_template.as_ref(), "root")
            .map(|v| v as u64)
            .unwrap_or(0);

        let path_template = context.get_type(&symbol_table, "path")?;
        let (path_dentry_offset, path_mnt_offset) =
            if let TypeTemplate::Struct(_) = path_template.as_ref() {
                (
                    helpers::get_field_offset_recursive(path_template.as_ref(), "dentry")
                        .map(|v| v as u64)
                        .unwrap_or(0),
                    helpers::get_field_offset_recursive(path_template.as_ref(), "mnt")
                        .map(|v| v as u64)
                        .unwrap_or(0),
                )
            } else {
                (0, 0)
            };

        let vfsmount_template = context.get_type(&symbol_table, "vfsmount")?;
        let vfs_mnt_root_offset =
            helpers::get_field_offset_recursive(vfsmount_template.as_ref(), "mnt_root")
                .map(|v| v as u64)
                .unwrap_or(0);

        let mount_offsets = if let Ok(mount_template) = context.get_type(&symbol_table, "mount") {
            if let TypeTemplate::Struct(s) = mount_template.as_ref() {
                let mnt_offset = s.get_field("mnt").map(|f| f.offset as u64).unwrap_or(0);
                let mnt_parent_offset = s
                    .get_field("mnt_parent")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0);
                let mnt_mountpoint_offset = s
                    .get_field("mnt_mountpoint")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0);
                Some((mnt_offset, mnt_parent_offset, mnt_mountpoint_offset))
            } else {
                None
            }
        } else {
            None
        };

        let file_template = context.get_type(&symbol_table, "file")?;
        let f_path_offset = helpers::get_field_offset_recursive(file_template.as_ref(), "f_path")
            .map(|v| v as u64)
            .unwrap_or(0);

        let dentry_template = context.get_type(&symbol_table, "dentry")?;
        let d_inode_offset =
            helpers::get_field_offset_recursive(dentry_template.as_ref(), "d_inode")
                .map(|v| v as u64)
                .unwrap_or(0);

        let inode_template = context.get_type(&symbol_table, "inode")?;
        let (i_ino_offset, i_sb_offset, i_size_offset) =
            if let TypeTemplate::Struct(_) = inode_template.as_ref() {
                (
                    helpers::get_field_offset_recursive(inode_template.as_ref(), "i_ino")
                        .map(|v| v as u64)
                        .unwrap_or(0),
                    helpers::get_field_offset_recursive(inode_template.as_ref(), "i_sb")
                        .map(|v| v as u64)
                        .unwrap_or(0),
                    helpers::get_field_offset_recursive(inode_template.as_ref(), "i_size")
                        .map(|v| v as u64)
                        .unwrap_or(0),
                )
            } else {
                (0, 0, 0)
            };

        let super_block_template = context.get_type(&symbol_table, "super_block")?;
        let s_dev_offset =
            helpers::get_field_offset_recursive(super_block_template.as_ref(), "s_dev")
                .map(|v| v as u64)
                .unwrap_or(0);

        let mut entries = Vec::new();

        for task in tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(0);
            if let Some(filter_pid) = pid_filter {
                if pid != filter_pid {
                    continue;
                }
            }

            let pid = task.pid(layer.as_ref()).unwrap_or(0);
            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            let mm_ptr =
                helpers::read_pointer(layer.as_ref(), task.address() + mm_offset).unwrap_or(0);
            if mm_ptr == 0 || !helpers::is_valid_kernel_address(mm_ptr) {
                continue;
            }

            let fs_ptr =
                helpers::read_pointer(layer.as_ref(), task.address() + fs_offset).unwrap_or(0);
            let (root_dentry, root_mnt) = if fs_ptr != 0 && helpers::is_valid_kernel_address(fs_ptr)
            {
                let root_path_addr = fs_ptr + root_offset;
                let rdentry =
                    helpers::read_pointer(layer.as_ref(), root_path_addr + path_dentry_offset)
                        .unwrap_or(0);
                let rmnt = helpers::read_pointer(layer.as_ref(), root_path_addr + path_mnt_offset)
                    .unwrap_or(0);
                (rdentry, rmnt)
            } else {
                (0, 0)
            };

            let vmas = if let Some(mmap_off) = mmap_offset {
                collect_vmas_mmap(layer.as_ref(), mm_ptr + mmap_off, vm_next_offset)?
            } else if let (Some(mm_mt_off), Some(maple)) = (mm_mt_offset, maple_offsets.as_ref()) {
                collect_vmas_maple(layer.as_ref(), mm_ptr + mm_mt_off, maple)?
            } else {
                Vec::new()
            };

            for vma_addr in vmas {
                let vm_start =
                    helpers::read_pointer(layer.as_ref(), vma_addr + vm_start_offset).unwrap_or(0);
                let vm_end =
                    helpers::read_pointer(layer.as_ref(), vma_addr + vm_end_offset).unwrap_or(0);
                if vm_start > vm_end {
                    continue;
                }

                let vm_len = vm_end.saturating_sub(vm_start);
                if vm_start == 0 && vm_len == 0 {
                    continue;
                }
                if vm_len % 0x1000 != 0 {
                    continue;
                }

                let vm_flags =
                    helpers::read_u64(layer.as_ref(), vma_addr + vm_flags_offset).unwrap_or(0);
                let vm_file =
                    helpers::read_pointer(layer.as_ref(), vma_addr + vm_file_offset).unwrap_or(0);
                let vm_pgoff =
                    helpers::read_u64(layer.as_ref(), vma_addr + vm_pgoff_offset).unwrap_or(0);
                let pgoff = if vm_file == 0 { 0 } else { vm_pgoff << 12 };

                let mut inode = 0_u64;
                let mut major = 0_u32;
                let mut minor = 0_u32;

                if vm_file != 0 && helpers::is_valid_kernel_address(vm_file) {
                    if let Some(inode_ptr) = get_vm_file_inode_ptr(
                        layer.as_ref(),
                        vm_file,
                        f_path_offset,
                        path_dentry_offset,
                        d_inode_offset,
                    )? {
                        inode = helpers::read_u64(layer.as_ref(), inode_ptr + i_ino_offset)
                            .unwrap_or(0);
                        let i_size = helpers::read_i64(layer.as_ref(), inode_ptr + i_size_offset)
                            .unwrap_or(0);
                        if i_size > 0 && pgoff > i_size as u64 {
                            continue;
                        }

                        let sb_ptr = helpers::read_pointer(layer.as_ref(), inode_ptr + i_sb_offset)
                            .unwrap_or(0);
                        if sb_ptr != 0 && helpers::is_valid_kernel_address(sb_ptr) {
                            let s_dev = helpers::read_u32(layer.as_ref(), sb_ptr + s_dev_offset)
                                .unwrap_or(0);
                            major = (s_dev >> 20) & 0xfff;
                            minor = s_dev & 0xfffff;
                        }
                    }
                }

                let path = if vm_file != 0 && helpers::is_valid_kernel_address(vm_file) {
                    lsof::get_file_path_with_mounts(
                        context,
                        layer.as_ref(),
                        vm_file,
                        &symbol_table,
                        f_path_offset,
                        path_dentry_offset,
                        path_mnt_offset,
                        root_dentry,
                        root_mnt,
                        vfs_mnt_root_offset,
                        mount_offsets,
                    )
                    .unwrap_or_else(|_| "Anonymous Mapping".to_string())
                } else {
                    get_vma_name_anonymous(
                        layer.as_ref(),
                        mm_ptr,
                        vm_start,
                        vm_end,
                        start_brk_offset,
                        brk_offset,
                        start_stack_offset,
                        context_offset,
                        context_vdso_offset,
                        context_is_ptr,
                    )
                    .unwrap_or_else(|_| "Anonymous Mapping".to_string())
                };

                entries.push(ProcMapEntry {
                    pid,
                    comm: comm.clone(),
                    start: vm_start,
                    end: vm_end,
                    flags: parse_protection(vm_flags),
                    pgoff,
                    major,
                    minor,
                    inode,
                    path,
                    file_output: "Disabled".to_string(),
                });
            }
        }

        Ok(entries)
    }
}

impl Default for Proc {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProcMapEntry {
    pub pid: i32,
    pub comm: String,
    pub start: u64,
    pub end: u64,
    pub flags: String,
    pub pgoff: u64,
    pub major: u32,
    pub minor: u32,
    pub inode: u64,
    pub path: String,
    pub file_output: String,
}

impl Module for Proc {
    fn name(&self) -> &str {
        "linux.proc.Proc"
    }

    fn description(&self) -> &str {
        "Process memory maps similar to /proc/[pid]/maps"
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
            Column::new("PID", ColumnType::Int),
            Column::new("Process", ColumnType::String),
            Column::new("Start", ColumnType::Hex),
            Column::new("End", ColumnType::Hex),
            Column::new("Flags", ColumnType::String),
            Column::new("PgOff", ColumnType::Hex),
            Column::new("Major", ColumnType::Int),
            Column::new("Minor", ColumnType::Int),
            Column::new("Inode", ColumnType::Int),
            Column::new("File Path", ColumnType::String),
            Column::new("File output", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_proc_maps(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.pid as i64),
                    CellValue::String(e.comm),
                    CellValue::Hex(e.start),
                    CellValue::Hex(e.end),
                    CellValue::String(e.flags),
                    CellValue::Hex(e.pgoff),
                    CellValue::Int(e.major as i64),
                    CellValue::Int(e.minor as i64),
                    CellValue::Int(e.inode as i64),
                    CellValue::String(e.path),
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

fn collect_vmas_mmap(
    layer: &dyn DataLayer,
    mmap_ptr_addr: Address,
    vm_next_offset: Option<u64>,
) -> Vol3Result<Vec<Address>> {
    let mut vmas = Vec::new();
    let mut seen = HashSet::new();
    let mut vma_ptr = helpers::read_pointer(layer, mmap_ptr_addr)?;

    while vma_ptr != 0 && helpers::is_valid_kernel_address(vma_ptr) && !seen.contains(&vma_ptr) {
        seen.insert(vma_ptr);
        vmas.push(vma_ptr);
        if let Some(next_off) = vm_next_offset {
            vma_ptr = helpers::read_pointer(layer, vma_ptr + next_off)?;
        } else {
            break;
        }
    }

    Ok(vmas)
}

fn parse_maple_offsets(context: &Context, symbol_table: &str) -> Option<MapleOffsets> {
    let maple_tree_template = context.get_type(symbol_table, "maple_tree").ok()?;
    let maple_alloc_template = context.get_type(symbol_table, "maple_alloc").ok()?;
    let maple_range_template = context.get_type(symbol_table, "maple_range_64").ok()?;
    let maple_arange_template = context.get_type(symbol_table, "maple_arange_64").ok()?;

    let ma_root_offset =
        helpers::get_field_offset_recursive(maple_tree_template.as_ref(), "ma_root")? as u64;
    let (alloc_slot_offset, alloc_slot_count) =
        helpers::get_array_field_offset_count_recursive(maple_alloc_template.as_ref(), "slot")?;
    let (mr64_slot_offset, mr64_slot_count) =
        helpers::get_array_field_offset_count_recursive(maple_range_template.as_ref(), "slot")
            .unwrap_or((128, 16));
    let (ma64_slot_offset, ma64_slot_count) =
        helpers::get_array_field_offset_count_recursive(maple_arange_template.as_ref(), "slot")
            .unwrap_or((80, 10));

    Some(MapleOffsets {
        ma_root_offset,
        alloc_slot_offset: alloc_slot_offset as u64,
        alloc_slot_count: alloc_slot_count.max(1),
        mr64_slot_offset: mr64_slot_offset as u64,
        mr64_slot_count: mr64_slot_count.max(1),
        ma64_slot_offset: ma64_slot_offset as u64,
        ma64_slot_count: ma64_slot_count.max(1),
    })
}

fn collect_vmas_maple(
    layer: &dyn DataLayer,
    mm_mt_addr: Address,
    offsets: &MapleOffsets,
) -> Vol3Result<Vec<Address>> {
    let root_entry = helpers::read_pointer(layer, mm_mt_addr + offsets.ma_root_offset).unwrap_or(0);
    if root_entry == 0 {
        return Ok(Vec::new());
    }

    let mut seen_nodes: HashSet<Address> = HashSet::new();
    let mut raw_slots: Vec<Address> = Vec::new();
    let parent = mm_mt_addr & !MAPLE_NODE_POINTER_MASK;
    parse_maple_tree_node(
        layer,
        root_entry,
        parent,
        offsets,
        &mut seen_nodes,
        &mut raw_slots,
    );

    let mut vmas = Vec::new();
    let mut seen_vmas = HashSet::new();
    for slot in raw_slots {
        let vma_ptr = slot & !MAPLE_NODE_TYPE_MASK;
        if vma_ptr >= 0x1000
            && helpers::is_valid_kernel_address(vma_ptr)
            && seen_vmas.insert(vma_ptr)
        {
            vmas.push(vma_ptr);
        }
    }

    Ok(vmas)
}

fn parse_maple_tree_node(
    layer: &dyn DataLayer,
    maple_tree_entry: Address,
    parent: Address,
    offsets: &MapleOffsets,
    seen_nodes: &mut HashSet<Address>,
    slots_out: &mut Vec<Address>,
) {
    if maple_tree_entry == 0 || !seen_nodes.insert(maple_tree_entry) {
        return;
    }

    let pointer = maple_tree_entry & !MAPLE_NODE_POINTER_MASK;
    if pointer == 0 || !helpers::is_valid_kernel_address(pointer) {
        return;
    }

    // First pointer-sized entry stores parent tagged pointer.
    let node_parent_mte = helpers::read_pointer(layer, pointer).unwrap_or(0);
    let node_parent_pointer = node_parent_mte & !MAPLE_NODE_POINTER_MASK;
    if node_parent_pointer != parent {
        return;
    }

    let node_type = (maple_tree_entry >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK;
    let read_slots = |slot_offset: u64, slot_count: usize, out: &mut Vec<Address>| {
        for idx in 0..slot_count {
            let slot_addr = pointer + slot_offset + (idx as u64 * 8);
            let slot = helpers::read_pointer(layer, slot_addr).unwrap_or(0);
            if (slot & !MAPLE_NODE_TYPE_MASK) != 0 {
                out.push(slot);
            }
        }
    };

    match node_type {
        MAPLE_DENSE => {
            read_slots(
                offsets.alloc_slot_offset,
                offsets.alloc_slot_count,
                slots_out,
            );
        }
        MAPLE_LEAF_64 => {
            read_slots(offsets.mr64_slot_offset, offsets.mr64_slot_count, slots_out);
        }
        MAPLE_RANGE_64 => {
            let mut children = Vec::new();
            read_slots(
                offsets.mr64_slot_offset,
                offsets.mr64_slot_count,
                &mut children,
            );
            for child in children {
                parse_maple_tree_node(layer, child, pointer, offsets, seen_nodes, slots_out);
            }
        }
        MAPLE_ARANGE_64 => {
            let mut children = Vec::new();
            read_slots(
                offsets.ma64_slot_offset,
                offsets.ma64_slot_count,
                &mut children,
            );
            for child in children {
                parse_maple_tree_node(layer, child, pointer, offsets, seen_nodes, slots_out);
            }
        }
        _ => {}
    }
}

fn get_vm_file_inode_ptr(
    layer: &dyn DataLayer,
    file_addr: Address,
    f_path_offset: u64,
    path_dentry_offset: u64,
    d_inode_offset: u64,
) -> Vol3Result<Option<Address>> {
    let path_addr = file_addr + f_path_offset;
    let dentry_ptr = helpers::read_pointer(layer, path_addr + path_dentry_offset).unwrap_or(0);
    if dentry_ptr == 0 || !helpers::is_valid_kernel_address(dentry_ptr) {
        return Ok(None);
    }
    let inode_ptr = helpers::read_pointer(layer, dentry_ptr + d_inode_offset).unwrap_or(0);
    if inode_ptr == 0 || !helpers::is_valid_kernel_address(inode_ptr) {
        return Ok(None);
    }
    Ok(Some(inode_ptr))
}

fn parse_protection(vm_flags: u64) -> String {
    let r = if vm_flags & 0x1 != 0 { 'r' } else { '-' };
    let w = if vm_flags & 0x2 != 0 { 'w' } else { '-' };
    let x = if vm_flags & 0x4 != 0 { 'x' } else { '-' };
    format!("{}{}{}", r, w, x)
}

fn get_vma_name_anonymous(
    layer: &dyn DataLayer,
    mm_addr: u64,
    vm_start: u64,
    vm_end: u64,
    start_brk_offset: u64,
    brk_offset: u64,
    start_stack_offset: u64,
    context_offset: Option<u64>,
    context_vdso_offset: Option<u64>,
    context_is_ptr: bool,
) -> Vol3Result<String> {
    if start_brk_offset > 0 && brk_offset > 0 {
        let start_brk = helpers::read_pointer(layer, mm_addr + start_brk_offset).unwrap_or(0);
        let brk = helpers::read_pointer(layer, mm_addr + brk_offset).unwrap_or(0);
        if start_brk != 0 && brk != 0 && vm_start <= start_brk && vm_end >= brk {
            return Ok("[heap]".to_string());
        }
    }

    if start_stack_offset > 0 {
        let start_stack = helpers::read_pointer(layer, mm_addr + start_stack_offset).unwrap_or(0);
        if start_stack != 0 && vm_start <= start_stack && start_stack <= vm_end {
            return Ok("[stack]".to_string());
        }
    }

    if let (Some(ctx_off), Some(vdso_off)) = (context_offset, context_vdso_offset) {
        let ctx_base = if context_is_ptr {
            helpers::read_pointer(layer, mm_addr + ctx_off).unwrap_or(0)
        } else {
            mm_addr + ctx_off
        };
        if ctx_base != 0 {
            let vdso_addr = helpers::read_pointer(layer, ctx_base + vdso_off).unwrap_or(0);
            if vdso_addr == vm_start {
                return Ok("[vdso]".to_string());
            }
        }
    }

    Ok("Anonymous Mapping".to_string())
}
