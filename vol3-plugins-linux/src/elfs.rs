//! Linux Elfs plugin.
//!
//! Lists all memory mapped ELF files for all processes.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;
use crate::lsof;
use crate::process_layer;

/// Elfs plugin - lists memory mapped ELF files
pub struct Elfs;

impl Elfs {
    pub fn new() -> Self {
        Self
    }

    fn list_elfs(context: &Context) -> Vol3Result<Vec<ElfEntry>> {
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

        // Get task_struct offsets
        let task_template = context.get_type(&symbol_table, "task_struct")?;
        let (mm_offset, fs_offset) = if let TypeTemplate::Struct(s) = task_template.as_ref() {
            (
                s.get_field("mm").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("fs").map(|f| f.offset as u64).unwrap_or(0),
            )
        } else {
            (0, 0)
        };

        // Get mm_struct offsets for VMA iteration
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
        ) = if let TypeTemplate::Struct(s) = mm_template.as_ref() {
            // Extract context.vdso offset if available
            let mut ctx_off = None;
            let mut vdso_off = None;
            let mut ctx_is_ptr = false;
            if let Some(ctx_field) = s.get_field("context") {
                ctx_off = Some(ctx_field.offset as u64);
                match ctx_field.template.as_ref() {
                    TypeTemplate::Struct(cs) => {
                        vdso_off = cs.get_field("vdso").map(|f| f.offset as u64);
                    }
                    TypeTemplate::Pointer(p) => {
                        ctx_is_ptr = true;
                        if let TypeTemplate::Struct(cs) = p.target.as_ref() {
                            vdso_off = cs.get_field("vdso").map(|f| f.offset as u64);
                        }
                    }
                    _ => {}
                }
            }

            (
                s.get_field("mmap").map(|f| f.offset as u64),
                s.get_field("mm_mt").map(|f| f.offset as u64),
                s.get_field("start_brk")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                s.get_field("brk").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("start_stack")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                ctx_off,
                vdso_off,
                ctx_is_ptr,
            )
        } else {
            (None, None, 0, 0, 0, None, None, false)
        };

        // fs_struct offsets for root path
        let fs_struct_template = context.get_type(&symbol_table, "fs_struct")?;
        let root_offset = if let TypeTemplate::Struct(s) = fs_struct_template.as_ref() {
            s.get_field("root").map(|f| f.offset as u64).unwrap_or(0)
        } else {
            0
        };

        // path struct offsets (dentry, mnt)
        let path_template = context.get_type(&symbol_table, "path")?;
        let (path_dentry_offset, path_mnt_offset) =
            if let TypeTemplate::Struct(s) = path_template.as_ref() {
                (
                    s.get_field("dentry").map(|f| f.offset as u64).unwrap_or(0),
                    s.get_field("mnt").map(|f| f.offset as u64).unwrap_or(0),
                )
            } else {
                (0, 0)
            };

        // vfsmount offsets
        let vfsmount_template = context.get_type(&symbol_table, "vfsmount")?;
        let vfs_mnt_root_offset = if let TypeTemplate::Struct(s) = vfsmount_template.as_ref() {
            s.get_field("mnt_root")
                .map(|f| f.offset as u64)
                .unwrap_or(0)
        } else {
            0
        };

        // mount offsets (kernels >= 3.3)
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

        // file struct offset for f_path
        let file_template = context.get_type(&symbol_table, "file")?;
        let f_path_offset = if let TypeTemplate::Struct(s) = file_template.as_ref() {
            s.get_field("f_path").map(|f| f.offset as u64).unwrap_or(0)
        } else {
            0
        };

        // Get vm_area_struct offsets
        let vma_template = context.get_type(&symbol_table, "vm_area_struct")?;
        let (vm_start_offset, vm_end_offset, vm_next_offset, vm_file_offset) =
            if let TypeTemplate::Struct(s) = vma_template.as_ref() {
                (
                    s.get_field("vm_start")
                        .map(|f| f.offset as u64)
                        .unwrap_or(0),
                    s.get_field("vm_end").map(|f| f.offset as u64).unwrap_or(0),
                    s.get_field("vm_next").map(|f| f.offset as u64),
                    s.get_field("vm_file").map(|f| f.offset as u64).unwrap_or(0),
                )
            } else {
                (0, 0, None, 0)
            };

        let mut entries = Vec::new();

        for task in &tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(0);
            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            // Get mm pointer
            let mm_ptr = helpers::read_pointer(layer.as_ref(), task.address() + mm_offset)?;
            if mm_ptr == 0 || !helpers::is_valid_kernel_address(mm_ptr) {
                continue; // Kernel thread
            }

            // Create process layer
            let proc_layer = match process_layer::create_process_layer(
                context,
                &layer_name,
                task,
                &symbol_table,
            )? {
                Some(l) => l,
                None => continue,
            };

            // Resolve task root path for mount-aware file paths
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

            // Iterate VMAs - support both mmap linked list and maple tree
            let vmas = if let Some(mmap_off) = mmap_offset {
                // Kernels < 6.1 use mmap linked list
                collect_vmas_mmap(layer.as_ref(), mm_ptr + mmap_off, vm_next_offset)?
            } else if let Some(_mm_mt_off) = mm_mt_offset {
                // Kernels >= 6.1 use maple tree - for now return empty
                // TODO: Implement maple tree iteration
                Vec::new()
            } else {
                Vec::new()
            };

            for vma_addr in vmas {
                // Read VMA fields
                let vm_start = helpers::read_pointer(layer.as_ref(), vma_addr + vm_start_offset)?;
                let vm_end = helpers::read_pointer(layer.as_ref(), vma_addr + vm_end_offset)?;

                if vm_start == 0 || vm_end <= vm_start {
                    continue;
                }

                // Read first 4 bytes to check for ELF magic
                let magic = match proc_layer.read(vm_start, 4, true) {
                    Ok(data) => data,
                    Err(_) => continue,
                };

                // ELF magic: 0x7f 'E' 'L' 'F'
                if magic != [0x7f, b'E', b'L', b'F'] {
                    continue;
                }

                // Get file path - first try vm_file, then check special regions
                let vm_file = helpers::read_pointer(layer.as_ref(), vma_addr + vm_file_offset)?;
                let file_path = if vm_file != 0 && helpers::is_valid_kernel_address(vm_file) {
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
                    .unwrap_or_default()
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
                    .unwrap_or_default()
                };

                entries.push(ElfEntry {
                    pid,
                    process: comm.clone(),
                    start: vm_start,
                    end: vm_end,
                    file_path,
                    file_output: "Disabled".to_string(),
                });
            }
        }

        Ok(entries)
    }
}

/// Get VMA name for anonymous mappings (check for [vdso])
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
    // [heap]: vm_start <= start_brk && vm_end >= brk
    if start_brk_offset > 0 && brk_offset > 0 {
        let start_brk = helpers::read_pointer(layer, mm_addr + start_brk_offset).unwrap_or(0);
        let brk = helpers::read_pointer(layer, mm_addr + brk_offset).unwrap_or(0);
        if start_brk != 0 && brk != 0 && vm_start <= start_brk && vm_end >= brk {
            return Ok("[heap]".to_string());
        }
    }

    // [stack]: vm_start <= start_stack <= vm_end
    if start_stack_offset > 0 {
        let start_stack = helpers::read_pointer(layer, mm_addr + start_stack_offset).unwrap_or(0);
        if start_stack != 0 && vm_start <= start_stack && start_stack <= vm_end {
            return Ok("[stack]".to_string());
        }
    }

    // [vdso]: mm_struct.context.vdso == vm_start
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

    // Default
    Ok("Anonymous Mapping".to_string())
}

/// Collect VMA addresses from mmap linked list (kernels < 6.1)
fn collect_vmas_mmap(
    layer: &dyn DataLayer,
    mmap_ptr_addr: u64,
    vm_next_offset: Option<u64>,
) -> Vol3Result<Vec<u64>> {
    let mut vmas = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Read first mmap pointer
    let mut vma_ptr = helpers::read_pointer(layer, mmap_ptr_addr)?;

    while vma_ptr != 0 && helpers::is_valid_kernel_address(vma_ptr) && !seen.contains(&vma_ptr) {
        seen.insert(vma_ptr);
        vmas.push(vma_ptr);

        // Move to next VMA
        if let Some(next_off) = vm_next_offset {
            vma_ptr = helpers::read_pointer(layer, vma_ptr + next_off)?;
        } else {
            break;
        }
    }

    Ok(vmas)
}

impl Default for Elfs {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct ElfEntry {
    pid: i32,
    process: String,
    start: u64,
    end: u64,
    file_path: String,
    file_output: String,
}

impl Module for Elfs {
    fn name(&self) -> &str {
        "linux.elfs.Elfs"
    }

    fn description(&self) -> &str {
        "Lists all memory mapped ELF files for all processes"
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
            Column::new("File Path", ColumnType::String),
            Column::new("File Output", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_elfs(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.pid as i64),
                    CellValue::String(e.process),
                    CellValue::Hex(e.start),
                    CellValue::Hex(e.end),
                    CellValue::String(e.file_path),
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
