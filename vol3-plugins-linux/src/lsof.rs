//! Linux Lsof plugin.
//!
//! Lists open files for each process.

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

/// Lsof plugin - lists open files for each process
pub struct Lsof;

impl Lsof {
    pub fn new() -> Self {
        Self
    }

    fn list_open_files(context: &Context) -> Vol3Result<Vec<FileDescEntry>> {
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
        // Use include_threads=true to match Python lsof behavior
        let tasks = helpers::collect_processes_with_threads(
            layer.as_ref(),
            init_task_addr,
            &template,
            true,
        )?;

        // Get task_struct offsets
        let task_template = context.get_type(&symbol_table, "task_struct")?;
        let (files_offset, fs_offset) = if let TypeTemplate::Struct(s) = task_template.as_ref() {
            (
                s.get_field("files").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("fs").map(|f| f.offset as u64).unwrap_or(0),
            )
        } else {
            (0, 0)
        };

        // Get fs_struct offsets for root path
        let fs_struct_template = context.get_type(&symbol_table, "fs_struct")?;
        let root_offset = if let TypeTemplate::Struct(s) = fs_struct_template.as_ref() {
            s.get_field("root").map(|f| f.offset as u64).unwrap_or(0)
        } else {
            0
        };

        // Get path struct offsets (dentry and mnt)
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

        // Get vfsmount.mnt_root offset
        let vfsmount_template = context.get_type(&symbol_table, "vfsmount")?;
        let vfs_mnt_root_offset = if let TypeTemplate::Struct(s) = vfsmount_template.as_ref() {
            s.get_field("mnt_root")
                .map(|f| f.offset as u64)
                .unwrap_or(0)
        } else {
            0
        };

        // Check if we have 'mount' struct (kernels >= 3.3) for traversing mount tree
        let mount_offsets = if let Ok(mount_template) = context.get_type(&symbol_table, "mount") {
            if let TypeTemplate::Struct(s) = mount_template.as_ref() {
                // vfsmount is embedded in mount at offset mnt
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

        // Get files_struct offsets - try fdt first (newer kernels), then fd
        let files_struct_template = context.get_type(&symbol_table, "files_struct")?;
        let (fdt_offset, fd_offset_direct, max_fds_offset_direct) =
            if let TypeTemplate::Struct(s) = files_struct_template.as_ref() {
                (
                    s.get_field("fdt").map(|f| f.offset as u64),
                    s.get_field("fd").map(|f| f.offset as u64),
                    s.get_field("max_fds").map(|f| f.offset as u64),
                )
            } else {
                (None, None, None)
            };

        // Get fdtable offsets (for newer kernels using fdt)
        let (fd_offset_fdt, max_fds_offset_fdt) =
            if let Ok(fdtable_template) = context.get_type(&symbol_table, "fdtable") {
                if let TypeTemplate::Struct(s) = fdtable_template.as_ref() {
                    (
                        s.get_field("fd").map(|f| f.offset as u64).unwrap_or(0),
                        s.get_field("max_fds").map(|f| f.offset as u64).unwrap_or(0),
                    )
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            };

        // Get file struct offsets
        let file_template = context.get_type(&symbol_table, "file")?;
        let f_path_offset = if let TypeTemplate::Struct(s) = file_template.as_ref() {
            s.get_field("f_path").map(|f| f.offset as u64).unwrap_or(0)
        } else {
            0
        };

        let mut entries = Vec::new();

        for task in &tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(0);
            let tgid = task.tgid(layer.as_ref()).unwrap_or(pid);
            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            // Read fs_struct pointer for root path
            let fs_ptr =
                helpers::read_pointer(layer.as_ref(), task.address() + fs_offset).unwrap_or(0);
            let (root_dentry, root_mnt) = if fs_ptr != 0 && helpers::is_valid_kernel_address(fs_ptr)
            {
                // Read root path (dentry and mnt)
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

            // Read files pointer
            let files_ptr = helpers::read_pointer(layer.as_ref(), task.address() + files_offset)?;
            if files_ptr == 0 || !helpers::is_valid_kernel_address(files_ptr) {
                continue;
            }

            // Get fd table and max_fds
            let (fd_array_ptr, max_fds) = if let Some(fdt_off) = fdt_offset {
                // Newer kernel: files_struct.fdt -> fdtable
                let fdt_ptr = helpers::read_pointer(layer.as_ref(), files_ptr + fdt_off)?;
                if fdt_ptr == 0 || !helpers::is_valid_kernel_address(fdt_ptr) {
                    continue;
                }
                let fd_ptr = helpers::read_pointer(layer.as_ref(), fdt_ptr + fd_offset_fdt)?;
                let max = helpers::read_u32(layer.as_ref(), fdt_ptr + max_fds_offset_fdt)? as usize;
                (fd_ptr, max)
            } else if let (Some(fd_off), Some(max_off)) = (fd_offset_direct, max_fds_offset_direct)
            {
                // Older kernel: files_struct.fd directly
                let fd_ptr = helpers::read_pointer(layer.as_ref(), files_ptr + fd_off)?;
                let max = helpers::read_u32(layer.as_ref(), files_ptr + max_off)? as usize;
                (fd_ptr, max)
            } else {
                continue;
            };

            if fd_array_ptr == 0 || !helpers::is_valid_kernel_address(fd_array_ptr) {
                continue;
            }

            // Limit max_fds to reasonable number
            let max_fds = std::cmp::min(max_fds, 500000);
            if max_fds == 0 {
                continue;
            }

            // Iterate file descriptors
            for fd_num in 0..max_fds {
                let file_ptr_addr = fd_array_ptr + (fd_num as u64 * 8); // pointer size = 8
                let file_ptr = match helpers::read_pointer(layer.as_ref(), file_ptr_addr) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                if file_ptr == 0 || !helpers::is_valid_kernel_address(file_ptr) {
                    continue;
                }

                // Get file path from file struct with mount traversal
                let path = get_file_path_with_mounts(
                    context,
                    layer.as_ref(),
                    file_ptr,
                    &symbol_table,
                    f_path_offset,
                    path_dentry_offset,
                    path_mnt_offset,
                    root_dentry,
                    root_mnt,
                    vfs_mnt_root_offset,
                    mount_offsets,
                )
                .unwrap_or_default();

                // Get inode information
                let (device, inode_num, file_type, mode, changed, modified, accessed, size) =
                    get_inode_info(context, layer.as_ref(), file_ptr, &symbol_table)
                        .unwrap_or_default();

                entries.push(FileDescEntry {
                    pid: tgid,
                    tid: pid,
                    process: comm.clone(),
                    fd: fd_num as i32,
                    path,
                    device,
                    inode: inode_num,
                    file_type,
                    mode,
                    changed,
                    modified,
                    accessed,
                    size,
                });
            }
        }

        Ok(entries)
    }
}

/// Get file path with mount traversal (implements do_get_path from Python)
pub(crate) fn get_file_path_with_mounts(
    context: &Context,
    layer: &dyn DataLayer,
    file_addr: u64,
    symbol_table: &str,
    f_path_offset: u64,
    path_dentry_offset: u64,
    path_mnt_offset: u64,
    root_dentry: u64,
    root_mnt: u64,
    vfs_mnt_root_offset: u64,
    mount_offsets: Option<(u64, u64, u64)>, // (mnt_offset, mnt_parent_offset, mnt_mountpoint_offset)
) -> Vol3Result<String> {
    // Read dentry and mnt pointers from f_path
    let path_addr = file_addr + f_path_offset;
    let dentry_ptr = helpers::read_pointer(layer, path_addr + path_dentry_offset)?;
    let vfsmnt_ptr = helpers::read_pointer(layer, path_addr + path_mnt_offset)?;

    if dentry_ptr == 0 || !helpers::is_valid_kernel_address(dentry_ptr) {
        return Ok(String::new());
    }

    // First check if this is a special file (socket, pipe, anon_inode)
    if let Ok(Some(special_path)) = get_special_file_path(context, layer, dentry_ptr, symbol_table)
    {
        return Ok(special_path);
    }

    // If no valid mount info, fall back to simple dentry path
    if vfsmnt_ptr == 0
        || !helpers::is_valid_kernel_address(vfsmnt_ptr)
        || root_dentry == 0
        || root_mnt == 0
    {
        return get_dentry_path(context, layer, dentry_ptr, symbol_table);
    }

    // Get dentry offsets
    let dentry_template = context.get_type(symbol_table, "dentry")?;
    let (d_parent_offset, d_name_offset, d_inode_offset) =
        if let TypeTemplate::Struct(s) = dentry_template.as_ref() {
            (
                s.get_field("d_parent")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                s.get_field("d_name").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("d_inode").map(|f| f.offset as u64).unwrap_or(0),
            )
        } else {
            return Ok("/".to_string());
        };

    // Get qstr name offset
    let qstr_template = context.get_type(symbol_table, "qstr")?;
    let name_offset = if let TypeTemplate::Struct(s) = qstr_template.as_ref() {
        s.get_field("name").map(|f| f.offset as u64).unwrap_or(0)
    } else {
        return Ok("/".to_string());
    };

    // Check if file is deleted (i_nlink == 0)
    let is_deleted = {
        let inode_ptr = helpers::read_pointer(layer, dentry_ptr + d_inode_offset).unwrap_or(0);
        if inode_ptr != 0 && helpers::is_valid_kernel_address(inode_ptr) {
            if let Ok(inode_template) = context.get_type(symbol_table, "inode") {
                if let TypeTemplate::Struct(s) = inode_template.as_ref() {
                    let i_nlink_offset = s
                        .get_field("i_nlink")
                        .or_else(|| s.get_field("__i_nlink"))
                        .map(|f| f.offset as u64)
                        .unwrap_or(0);
                    let i_nlink = helpers::read_u32(layer, inode_ptr + i_nlink_offset).unwrap_or(1);
                    i_nlink == 0
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    };

    // do_get_path: Walk up the dentry/vfsmount tree
    let mut path_parts = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current_dentry = dentry_ptr;
    let mut current_vfsmnt = vfsmnt_ptr;

    // Get mount struct info (for kernels >= 3.3)
    let (mnt_offset, mnt_parent_offset, mnt_mountpoint_offset) = mount_offsets.unwrap_or((0, 0, 0));

    while current_dentry != 0 && helpers::is_valid_kernel_address(current_dentry) {
        // Break if we've reached the root
        if current_dentry == root_dentry && current_vfsmnt == root_mnt {
            break;
        }

        // Get vfsmount's mnt_root
        let mnt_root =
            helpers::read_pointer(layer, current_vfsmnt + vfs_mnt_root_offset).unwrap_or(0);

        // Get dentry's parent
        let parent = helpers::read_pointer(layer, current_dentry + d_parent_offset).unwrap_or(0);

        // Check if dentry is root (d_parent == self) or is mount root
        let is_dentry_root = parent == 0 || parent == current_dentry;
        let is_mount_root = current_dentry == mnt_root;

        if is_mount_root || is_dentry_root {
            // If this is mount root, traverse to parent mount
            if is_mount_root {
                if mnt_offset == 0 {
                    // No mount struct (kernel < 3.3), stop here
                    break;
                }

                // Get mount struct from vfsmount (container_of)
                let mount_addr = current_vfsmnt - mnt_offset;

                // Check if mount has parent (mnt_parent != self)
                let mnt_parent =
                    helpers::read_pointer(layer, mount_addr + mnt_parent_offset).unwrap_or(0);
                if mnt_parent == 0 || mnt_parent == mount_addr {
                    // No parent, global root
                    break;
                }

                // Get parent's mountpoint dentry
                let mountpoint =
                    helpers::read_pointer(layer, mount_addr + mnt_mountpoint_offset).unwrap_or(0);
                if mountpoint == 0 || !helpers::is_valid_kernel_address(mountpoint) {
                    break;
                }

                // Get parent's vfsmount (embedded at mnt_offset)
                let parent_vfsmnt = mnt_parent + mnt_offset;

                current_dentry = mountpoint;
                current_vfsmnt = parent_vfsmnt;
                continue;
            }

            // Escaped from root (d_parent == self but not at root mount)
            if !is_mount_root {
                break;
            }
        }

        // Cycle detection
        if !seen.insert(current_dentry) {
            break;
        }

        // Read component name
        let name_ptr =
            helpers::read_pointer(layer, current_dentry + d_name_offset + name_offset).unwrap_or(0);
        if name_ptr != 0 && helpers::is_valid_kernel_address(name_ptr) {
            if let Ok(name) = helpers::read_string(layer, name_ptr, 255) {
                let clean_name = name.trim_matches('/');
                if !clean_name.is_empty() {
                    path_parts.push(clean_name.to_string());
                }
            }
        }

        current_dentry = parent;
    }

    path_parts.reverse();
    let path = if path_parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", path_parts.join("/"))
    };

    // Append deleted suffix if file is deleted
    if is_deleted {
        Ok(format!(" {} (deleted)", path))
    } else {
        Ok(path)
    }
}

/// Get file path from a file struct
pub(crate) fn get_file_path_from_file_struct(
    context: &Context,
    layer: &dyn DataLayer,
    file_addr: u64,
    symbol_table: &str,
    f_path_offset: u64,
    dentry_offset: u64,
) -> Vol3Result<String> {
    // Read dentry pointer from f_path
    let path_addr = file_addr + f_path_offset;
    let dentry_ptr = helpers::read_pointer(layer, path_addr + dentry_offset)?;

    if dentry_ptr == 0 || !helpers::is_valid_kernel_address(dentry_ptr) {
        return Ok(String::new());
    }

    // First check if this is a special file (socket, pipe, anon_inode)
    if let Ok(Some(special_path)) = get_special_file_path(context, layer, dentry_ptr, symbol_table)
    {
        return Ok(special_path);
    }

    // Get dentry path (regular file)
    get_dentry_path(context, layer, dentry_ptr, symbol_table)
}

/// Check if dentry has d_op.d_dname set and get special file path
pub(crate) fn get_special_file_path(
    context: &Context,
    layer: &dyn DataLayer,
    dentry_addr: u64,
    symbol_table: &str,
) -> Vol3Result<Option<String>> {
    let dentry_template = context.get_type(symbol_table, "dentry")?;
    let (d_op_offset, d_inode_offset) = if let TypeTemplate::Struct(s) = dentry_template.as_ref() {
        (
            s.get_field("d_op").map(|f| f.offset as u64).unwrap_or(0),
            s.get_field("d_inode").map(|f| f.offset as u64).unwrap_or(0),
        )
    } else {
        return Ok(None);
    };

    // Read d_op pointer
    let d_op_ptr = helpers::read_pointer(layer, dentry_addr + d_op_offset)?;
    if d_op_ptr == 0 || !helpers::is_valid_kernel_address(d_op_ptr) {
        return Ok(None);
    }

    // Get dentry_operations.d_dname offset
    let dentry_ops_template = context.get_type(symbol_table, "dentry_operations")?;
    let d_dname_offset = if let TypeTemplate::Struct(s) = dentry_ops_template.as_ref() {
        s.get_field("d_dname").map(|f| f.offset as u64)
    } else {
        None
    };

    let d_dname_offset = match d_dname_offset {
        Some(off) => off,
        None => return Ok(None),
    };

    // Read d_dname function pointer
    let d_dname_ptr = helpers::read_pointer(layer, d_op_ptr + d_dname_offset)?;
    if d_dname_ptr == 0 {
        return Ok(None);
    }

    // Get ASLR shift to lookup symbol (function pointers in kernel use aslr_shift)
    let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;
    let symbol_addr = d_dname_ptr.wrapping_sub(aslr_shift);

    // Look up what symbol this points to
    let symbol_name = if let Some(st) = context.get_symbol_table(symbol_table) {
        use vol3_symbols::traits::SymbolTableInterface;
        st.get_symbol_by_address(symbol_addr)
            .map(|(name, _)| name)
            .unwrap_or_default()
    } else {
        String::new()
    };

    // Determine path prefix based on d_dname symbol
    let pre_name = match symbol_name.as_str() {
        "sockfs_dname" => "socket".to_string(),
        "anon_inodefs_dname" => "anon_inode".to_string(),
        "pipefs_dname" => "pipe".to_string(),
        "simple_dname" => {
            // memfd: and similar - read dentry.d_name.name to get the filename
            // Get qstr offsets for d_name
            if let Ok(qstr_template) = context.get_type(symbol_table, "qstr") {
                if let TypeTemplate::Struct(s) = qstr_template.as_ref() {
                    let qstr_name_offset =
                        s.get_field("name").map(|f| f.offset as u64).unwrap_or(0);

                    // Get d_name offset in dentry
                    let d_name_offset = if let TypeTemplate::Struct(ds) = dentry_template.as_ref() {
                        ds.get_field("d_name").map(|f| f.offset as u64).unwrap_or(0)
                    } else {
                        0
                    };

                    // Read the name pointer from d_name.name
                    if let Ok(name_ptr) =
                        helpers::read_pointer(layer, dentry_addr + d_name_offset + qstr_name_offset)
                    {
                        if name_ptr != 0 && helpers::is_valid_kernel_address(name_ptr) {
                            if let Ok(name) = helpers::read_string(layer, name_ptr, 255) {
                                // For simple_dname, return /<name> (deleted)
                                return Ok(Some(format!("/{} (deleted)", name)));
                            }
                        }
                    }
                }
            }
            // Fallback
            return Ok(Some("/ (deleted)".to_string()));
        }
        "ns_dname" => {
            // Try to get namespace type from proc_ns_operations.name
            // via dentry.d_fsdata -> proc_ns_operations
            let d_fsdata_offset = if let TypeTemplate::Struct(s) = dentry_template.as_ref() {
                s.get_field("d_fsdata").map(|f| f.offset as u64)
            } else {
                None
            };

            if let Some(fsdata_off) = d_fsdata_offset {
                if let Ok(fsdata_ptr) = helpers::read_pointer(layer, dentry_addr + fsdata_off) {
                    if fsdata_ptr != 0 && helpers::is_valid_kernel_address(fsdata_ptr) {
                        // proc_ns_operations.name is typically at offset 0
                        if let Ok(ns_ops_template) =
                            context.get_type(symbol_table, "proc_ns_operations")
                        {
                            if let TypeTemplate::Struct(s) = ns_ops_template.as_ref() {
                                let name_offset =
                                    s.get_field("name").map(|f| f.offset as u64).unwrap_or(0);
                                if let Ok(name_ptr) =
                                    helpers::read_pointer(layer, fsdata_ptr + name_offset)
                                {
                                    if let Ok(ns_name) = helpers::read_string(layer, name_ptr, 32) {
                                        ns_name
                                    } else {
                                        "ns".to_string()
                                    }
                                } else {
                                    "ns".to_string()
                                }
                            } else {
                                "ns".to_string()
                            }
                        } else {
                            "ns".to_string()
                        }
                    } else {
                        "ns".to_string()
                    }
                } else {
                    "ns".to_string()
                }
            } else {
                "ns".to_string()
            }
        }
        _ => return Ok(None), // Unknown special file type
    };

    // Read inode number
    let inode_ptr = helpers::read_pointer(layer, dentry_addr + d_inode_offset)?;
    if inode_ptr == 0 || !helpers::is_valid_kernel_address(inode_ptr) {
        return Ok(Some(format!("{}:[?]", pre_name)));
    }

    let inode_template = context.get_type(symbol_table, "inode")?;
    let i_ino_offset = if let TypeTemplate::Struct(s) = inode_template.as_ref() {
        s.get_field("i_ino").map(|f| f.offset as u64).unwrap_or(0)
    } else {
        0
    };

    let i_ino = helpers::read_u64(layer, inode_ptr + i_ino_offset).unwrap_or(0);
    Ok(Some(format!("{}:[{}]", pre_name, i_ino)))
}

/// Get path of a dentry by walking up to root
pub(crate) fn get_dentry_path(
    context: &Context,
    layer: &dyn DataLayer,
    dentry_addr: u64,
    symbol_table: &str,
) -> Vol3Result<String> {
    // Get dentry offsets
    let dentry_template = context.get_type(symbol_table, "dentry")?;
    let (d_parent_offset, d_name_offset, d_inode_offset) =
        if let TypeTemplate::Struct(s) = dentry_template.as_ref() {
            (
                s.get_field("d_parent")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                s.get_field("d_name").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("d_inode").map(|f| f.offset as u64).unwrap_or(0),
            )
        } else {
            return Ok("/".to_string());
        };

    // Get qstr name offset
    let qstr_template = context.get_type(symbol_table, "qstr")?;
    let name_offset = if let TypeTemplate::Struct(s) = qstr_template.as_ref() {
        s.get_field("name").map(|f| f.offset as u64).unwrap_or(0)
    } else {
        return Ok("/".to_string());
    };

    // Check if file is deleted (i_nlink == 0)
    let is_deleted = {
        let inode_ptr = helpers::read_pointer(layer, dentry_addr + d_inode_offset).unwrap_or(0);
        if inode_ptr != 0 && helpers::is_valid_kernel_address(inode_ptr) {
            // Get i_nlink offset
            if let Ok(inode_template) = context.get_type(symbol_table, "inode") {
                if let TypeTemplate::Struct(s) = inode_template.as_ref() {
                    let i_nlink_offset = s
                        .get_field("i_nlink")
                        .or_else(|| s.get_field("__i_nlink"))
                        .map(|f| f.offset as u64)
                        .unwrap_or(0);
                    let i_nlink = helpers::read_u32(layer, inode_ptr + i_nlink_offset).unwrap_or(1);
                    i_nlink == 0
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    };

    let mut path_parts = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current = dentry_addr;

    while current != 0 && helpers::is_valid_kernel_address(current) && !seen.contains(&current) {
        seen.insert(current);

        // Read parent dentry
        let parent = helpers::read_pointer(layer, current + d_parent_offset)?;

        // Check if at root (parent == self)
        if parent == current {
            break;
        }

        // Read name
        let qstr_addr = current + d_name_offset;
        let name_ptr = helpers::read_pointer(layer, qstr_addr + name_offset)?;
        if name_ptr != 0 && helpers::is_valid_kernel_address(name_ptr) {
            if let Ok(name) = helpers::read_string(layer, name_ptr, 256) {
                if !name.is_empty() {
                    path_parts.push(name);
                }
            }
        }

        current = parent;
    }

    path_parts.reverse();
    let path = if path_parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", path_parts.join("/"))
    };

    // Append deleted suffix if file is deleted
    if is_deleted {
        Ok(format!("{} (deleted)", path))
    } else {
        Ok(path)
    }
}

/// Get inode information from a file struct
fn get_inode_info(
    context: &Context,
    layer: &dyn DataLayer,
    file_addr: u64,
    symbol_table: &str,
) -> Vol3Result<(String, u64, String, String, String, String, String, i64)> {
    // Get file struct offsets
    let file_template = context.get_type(symbol_table, "file")?;
    let f_inode_offset = if let TypeTemplate::Struct(s) = file_template.as_ref() {
        // Try f_inode first (newer kernels), then f_path.dentry.d_inode
        s.get_field("f_inode").map(|f| f.offset as u64)
    } else {
        None
    };

    let inode_addr = if let Some(inode_off) = f_inode_offset {
        helpers::read_pointer(layer, file_addr + inode_off)?
    } else {
        // Fall back to reading from dentry
        let f_path_offset = if let TypeTemplate::Struct(s) = file_template.as_ref() {
            s.get_field("f_path").map(|f| f.offset as u64).unwrap_or(0)
        } else {
            0
        };
        let path_template = context.get_type(symbol_table, "path")?;
        let dentry_offset = if let TypeTemplate::Struct(s) = path_template.as_ref() {
            s.get_field("dentry").map(|f| f.offset as u64).unwrap_or(0)
        } else {
            0
        };
        let dentry_template = context.get_type(symbol_table, "dentry")?;
        let d_inode_offset = if let TypeTemplate::Struct(s) = dentry_template.as_ref() {
            s.get_field("d_inode").map(|f| f.offset as u64).unwrap_or(0)
        } else {
            0
        };

        let path_addr = file_addr + f_path_offset;
        let dentry_ptr = helpers::read_pointer(layer, path_addr + dentry_offset)?;
        if dentry_ptr == 0 {
            return Ok(Default::default());
        }
        helpers::read_pointer(layer, dentry_ptr + d_inode_offset)?
    };

    if inode_addr == 0 || !helpers::is_valid_kernel_address(inode_addr) {
        return Ok(Default::default());
    }

    // Get inode struct offsets
    let inode_template = context.get_type(symbol_table, "inode")?;
    let (
        i_sb_offset,
        i_ino_offset,
        i_mode_offset,
        i_ctime_offset,
        i_mtime_offset,
        i_atime_offset,
        i_size_offset,
    ) = if let TypeTemplate::Struct(s) = inode_template.as_ref() {
        (
            s.get_field("i_sb").map(|f| f.offset as u64).unwrap_or(0),
            s.get_field("i_ino").map(|f| f.offset as u64).unwrap_or(0),
            s.get_field("i_mode").map(|f| f.offset as u64).unwrap_or(0),
            s.get_field("i_ctime")
                .or_else(|| s.get_field("__i_ctime"))
                .map(|f| f.offset as u64)
                .unwrap_or(0),
            s.get_field("i_mtime")
                .or_else(|| s.get_field("__i_mtime"))
                .map(|f| f.offset as u64)
                .unwrap_or(0),
            s.get_field("i_atime")
                .or_else(|| s.get_field("__i_atime"))
                .map(|f| f.offset as u64)
                .unwrap_or(0),
            s.get_field("i_size").map(|f| f.offset as u64).unwrap_or(0),
        )
    } else {
        return Ok(Default::default());
    };

    // Read inode fields
    let i_ino = helpers::read_u64(layer, inode_addr + i_ino_offset)?;
    let i_mode = helpers::read_u32(layer, inode_addr + i_mode_offset)? as u16;
    let i_size = helpers::read_i64(layer, inode_addr + i_size_offset)?;

    // Get device from superblock
    let sb_ptr = helpers::read_pointer(layer, inode_addr + i_sb_offset)?;
    let device = if sb_ptr != 0 && helpers::is_valid_kernel_address(sb_ptr) {
        // Read s_dev from super_block
        let sb_template = context.get_type(symbol_table, "super_block")?;
        let s_dev_offset = if let TypeTemplate::Struct(s) = sb_template.as_ref() {
            s.get_field("s_dev").map(|f| f.offset as u64).unwrap_or(0)
        } else {
            0
        };
        let s_dev = helpers::read_u32(layer, sb_ptr + s_dev_offset)?;
        // s_dev is MKDEV format: (major << 20) | minor
        let major = (s_dev >> 20) & 0xfff;
        let minor = s_dev & 0xfffff;
        format!("{}:{}", major, minor)
    } else {
        String::new()
    };

    // Get file type from i_mode
    let file_type = match (i_mode >> 12) & 0xf {
        0o01 => "FIFO",
        0o02 => "CHR",
        0o04 => "DIR",
        0o06 => "BLK",
        0o10 => "REG",
        0o12 => "LNK",
        0o14 => "SOCK",
        _ => "-",
    }
    .to_string();

    // Get file mode string
    let mode = format_file_mode(i_mode);

    // Read timestamps
    let changed = read_timestamp(context, layer, inode_addr + i_ctime_offset, symbol_table);
    let modified = read_timestamp(context, layer, inode_addr + i_mtime_offset, symbol_table);
    let accessed = read_timestamp(context, layer, inode_addr + i_atime_offset, symbol_table);

    Ok((
        device, i_ino, file_type, mode, changed, modified, accessed, i_size,
    ))
}

/// Format file mode as drwxrwxrwx string
fn format_file_mode(mode: u16) -> String {
    let file_type = match (mode >> 12) & 0xf {
        0o01 => 'p', // FIFO
        0o02 => 'c', // CHR
        0o04 => 'd', // DIR
        0o06 => 'b', // BLK
        0o10 => '-', // REG
        0o12 => 'l', // LNK
        0o14 => 's', // SOCK
        _ => '?',
    };

    let perms = [
        if mode & 0o400 != 0 { 'r' } else { '-' },
        if mode & 0o200 != 0 { 'w' } else { '-' },
        if mode & 0o100 != 0 {
            if mode & 0o4000 != 0 {
                's'
            } else {
                'x'
            }
        } else {
            if mode & 0o4000 != 0 {
                'S'
            } else {
                '-'
            }
        },
        if mode & 0o040 != 0 { 'r' } else { '-' },
        if mode & 0o020 != 0 { 'w' } else { '-' },
        if mode & 0o010 != 0 {
            if mode & 0o2000 != 0 {
                's'
            } else {
                'x'
            }
        } else {
            if mode & 0o2000 != 0 {
                'S'
            } else {
                '-'
            }
        },
        if mode & 0o004 != 0 { 'r' } else { '-' },
        if mode & 0o002 != 0 { 'w' } else { '-' },
        if mode & 0o001 != 0 {
            if mode & 0o1000 != 0 {
                't'
            } else {
                'x'
            }
        } else {
            if mode & 0o1000 != 0 {
                'T'
            } else {
                '-'
            }
        },
    ];

    format!("{}{}", file_type, perms.iter().collect::<String>())
}

/// Read a timestamp from timespec/timespec64
fn read_timestamp(
    context: &Context,
    layer: &dyn DataLayer,
    addr: u64,
    symbol_table: &str,
) -> String {
    // Try to determine timespec type
    let timespec_template = context
        .get_type(symbol_table, "timespec64")
        .or_else(|_| context.get_type(symbol_table, "timespec"))
        .ok();

    let tv_sec_offset = if let Some(t) = &timespec_template {
        if let TypeTemplate::Struct(s) = t.as_ref() {
            s.get_field("tv_sec").map(|f| f.offset as u64).unwrap_or(0)
        } else {
            0
        }
    } else {
        0
    };

    let tv_nsec_offset = if let Some(t) = &timespec_template {
        if let TypeTemplate::Struct(s) = t.as_ref() {
            s.get_field("tv_nsec").map(|f| f.offset as u64).unwrap_or(8)
        } else {
            8
        }
    } else {
        8
    };

    let tv_sec = helpers::read_i64(layer, addr + tv_sec_offset).unwrap_or(0);
    let tv_nsec = helpers::read_i64(layer, addr + tv_nsec_offset).unwrap_or(0);

    if tv_sec == 0 && tv_nsec == 0 {
        return "-".to_string();
    }

    // Convert to datetime (matching Python's behavior)
    // Python: datetime.fromtimestamp(tv_sec + tv_nsec / 1e9, timezone.utc)
    // The combined float loses precision, so we must match that exactly
    use chrono::{DateTime, NaiveDateTime, Utc};

    // Match Python's floating-point behavior:
    // 1. Combine tv_sec + tv_nsec/1e9 into single float (loses precision for large tv_sec)
    // 2. Extract fractional part and convert to microseconds
    let combined = tv_sec as f64 + tv_nsec as f64 / 1e9;
    let frac = combined - combined.floor();
    let usec = (frac * 1e6).round() as i64;
    let nsec_adjusted = usec * 1000;

    if let Some(dt) = NaiveDateTime::from_timestamp_opt(tv_sec, nsec_adjusted as u32) {
        let datetime: DateTime<Utc> = DateTime::from_naive_utc_and_offset(dt, Utc);
        datetime.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string()
    } else {
        "-".to_string()
    }
}

impl Default for Lsof {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct FileDescEntry {
    pid: i32,
    tid: i32,
    process: String,
    fd: i32,
    path: String,
    device: String,
    inode: u64,
    file_type: String,
    mode: String,
    changed: String,
    modified: String,
    accessed: String,
    size: i64,
}

impl Module for Lsof {
    fn name(&self) -> &str {
        "linux.lsof.Lsof"
    }

    fn description(&self) -> &str {
        "Lists open files for each process"
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
            Column::new("TID", ColumnType::Int),
            Column::new("Process", ColumnType::String),
            Column::new("FD", ColumnType::Int),
            Column::new("Path", ColumnType::String),
            Column::new("Device", ColumnType::String),
            Column::new("Inode", ColumnType::Int),
            Column::new("Type", ColumnType::String),
            Column::new("Mode", ColumnType::String),
            Column::new("Changed", ColumnType::String),
            Column::new("Modified", ColumnType::String),
            Column::new("Accessed", ColumnType::String),
            Column::new("Size", ColumnType::Int),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_open_files(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.pid as i64),
                    CellValue::Int(e.tid as i64),
                    CellValue::String(e.process),
                    CellValue::Int(e.fd as i64),
                    CellValue::String(e.path),
                    CellValue::String(e.device),
                    CellValue::Int(e.inode as i64),
                    CellValue::String(e.file_type),
                    CellValue::String(e.mode),
                    CellValue::String(e.changed),
                    CellValue::String(e.modified),
                    CellValue::String(e.accessed),
                    CellValue::Int(e.size),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
