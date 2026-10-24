//! Linux MountInfo plugin.
//!
//! Lists mount points on processes mount namespaces.

use std::collections::HashSet;
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};
use log::{debug, info, warn};

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_symbols;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;

/// Mount information
#[derive(Debug, Clone)]
pub struct MountData {
    pub mnt_ns_id: Option<u64>,
    pub mnt_id: i32,
    pub parent_id: i32,
    pub st_dev: String,
    pub mnt_root_path: String,
    pub path_root: String,
    pub mnt_opts: String,
    pub fields: String,
    pub mnt_type: String,
    pub devname: String,
    pub sb_opts: String,
}

/// MountInfo plugin - lists mount points
pub struct MountInfo;

impl MountInfo {
    pub fn new() -> Self {
        Self
    }

    /// Get superblocks from mount namespaces
    pub fn get_superblocks(context: &Context) -> Vol3Result<Vec<SuperblockInfo>> {
        use vol3_core::error::{ConfigError, LayerError};

        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let layer = context
            .get_layer(&layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(layer_name.clone())))?;

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        // Keep parity with volatility3: skip unreadable superblock pointers.
        let superblock_size = context
            .get_type(&symbol_table, "super_block")
            .ok()
            .and_then(|t| t.size())
            .unwrap_or(1)
            .max(1);

        let init_task_addr = helpers::get_init_task(context, &symbol_table)?;
        let template = helpers::get_task_struct_template(context, &symbol_table)?;
        let tasks = helpers::collect_processes(layer.as_ref(), init_task_addr, &template)?;

        let mut superblocks = Vec::new();
        let mut seen_sb = HashSet::new();
        let mut seen_mnt_ids = HashSet::new();

        for task in tasks {
            if let Ok(mounts) = get_task_mounts(context, layer.as_ref(), &task, &symbol_table) {
                for mount in mounts {
                    // Match volatility3 _get_tasks_mountpoints(filtered_by_pids=False):
                    // de-duplicate mount entries globally by mnt_id before further processing.
                    if seen_mnt_ids.contains(&mount.mnt_id) {
                        continue;
                    }
                    seen_mnt_ids.insert(mount.mnt_id);

                    // Match volatility3 get_superblocks: only include mounts whose path resolves.
                    if !mount.mountpoint_valid {
                        continue;
                    }
                    // Match volatility3 get_superblocks: sb_ptr must be present/readable.
                    if mount.superblock_addr == 0
                        || !helpers::is_valid_kernel_address(mount.superblock_addr)
                        || !layer.is_valid(mount.superblock_addr, superblock_size)
                    {
                        continue;
                    }
                    if !seen_sb.contains(&mount.superblock_addr) {
                        seen_sb.insert(mount.superblock_addr);
                        superblocks.push(SuperblockInfo {
                            addr: mount.superblock_addr,
                            mountpoint: mount.mountpoint,
                        });
                    }
                }
            }
        }

        Ok(superblocks)
    }

    /// List mount info entries
    fn list_mounts(context: &Context) -> Vol3Result<Vec<MountData>> {
        use vol3_core::error::{ConfigError, LayerError};

        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let layer = context
            .get_layer(&layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(layer_name.clone())))?;

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        let init_task_addr = helpers::get_init_task(context, &symbol_table)?;
        let template = helpers::get_task_struct_template(context, &symbol_table)?;
        let tasks = helpers::collect_processes(layer.as_ref(), init_task_addr, &template)?;

        let mut mounts = Vec::new();
        let mut seen_mnt_ids = HashSet::new();

        for task in tasks {
            if let Ok(task_mounts) = get_task_mounts(context, layer.as_ref(), &task, &symbol_table)
            {
                for mount in task_mounts {
                    if !seen_mnt_ids.contains(&mount.mnt_id) {
                        seen_mnt_ids.insert(mount.mnt_id);

                        mounts.push(MountData {
                            mnt_ns_id: mount.mnt_ns_id,
                            mnt_id: mount.mnt_id,
                            parent_id: mount.parent_id,
                            st_dev: mount.st_dev,
                            mnt_root_path: mount.mnt_root_path,
                            path_root: mount.path_root,
                            mnt_opts: mount.mnt_opts,
                            fields: mount.fields,
                            mnt_type: mount.mnt_type,
                            devname: mount.devname,
                            sb_opts: mount.sb_opts,
                        });
                    }
                }
            }
        }

        Ok(mounts)
    }
}

/// Internal mount info
struct MountInfoInternal {
    mnt_ns_id: Option<u64>,
    mnt_id: i32,
    parent_id: i32,
    st_dev: String,
    mnt_root_path: String,
    path_root: String,
    mnt_opts: String,
    fields: String,
    mnt_type: String,
    devname: String,
    sb_opts: String,
    superblock_addr: Address,
    mountpoint: String,
    mountpoint_valid: bool,
}

/// Superblock info
#[derive(Debug, Clone)]
pub struct SuperblockInfo {
    pub addr: Address,
    pub mountpoint: String,
}

/// Get path of a dentry by walking up to root
/// Based on __dentry_path from Linux kernel
fn get_dentry_path(
    context: &Context,
    layer: &dyn DataLayer,
    dentry_addr: Address,
    symbol_table: &str,
) -> Vol3Result<String> {
    // Get dentry offsets
    let dentry_template = context.get_type(symbol_table, "dentry")?;
    let (d_parent_offset, d_name_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = dentry_template.as_ref() {
            (
                s.get_field("d_parent").map(|f| f.offset).unwrap_or(0),
                s.get_field("d_name").map(|f| f.offset).unwrap_or(0),
            )
        } else {
            return Ok("/".to_string());
        };

    // Get qstr name offset
    let qstr_template = context.get_type(symbol_table, "qstr")?;
    let (name_offset, len_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = qstr_template.as_ref() {
            (
                s.get_field("name").map(|f| f.offset).unwrap_or(0),
                s.get_field("len").map(|f| f.offset),
            )
        } else {
            return Ok("/".to_string());
        };

    let mut path_parts = Vec::new();
    let mut seen = HashSet::new();
    let mut current = dentry_addr;

    while current != 0 && !seen.contains(&current) {
        seen.insert(current);

        // Read parent dentry
        let parent = match helpers::read_pointer(layer, current + d_parent_offset as u64) {
            Ok(p) => p,
            Err(_) => break,
        };

        // Check if at root (parent == self)
        if parent == current {
            break;
        }

        // Read name
        let qstr_addr = current + d_name_offset as u64;
        let name_ptr = match helpers::read_pointer(layer, qstr_addr + name_offset as u64) {
            Ok(p) => p,
            Err(_) => {
                current = parent;
                continue;
            }
        };
        if name_ptr != 0 {
            let mut max_len = if let Some(len_off) = len_offset {
                helpers::read_u32(layer, qstr_addr + len_off as u64).unwrap_or(0) as usize + 1
            } else {
                255
            };
            // Guard against bogus lengths
            if max_len == 0 || max_len > 255 {
                max_len = 255;
            }
            if max_len > 0 {
                if let Ok(name) = helpers::read_string(layer, name_ptr, max_len) {
                    if !name.is_empty() {
                        path_parts.push(name);
                    }
                }
            }
        }

        current = parent;
    }

    path_parts.reverse();
    if path_parts.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", path_parts.join("/")))
    }
}

/// Get the full mount path by walking up both dentry and mount hierarchy
/// This mimics Python's do_get_path/get_path_mnt functionality
pub fn get_mount_path(
    context: &Context,
    layer: &dyn DataLayer,
    mount_addr: Address,
    symbol_table: &str,
) -> Vol3Result<String> {
    // Get struct offsets
    let mount_template = context.get_type(symbol_table, "mount")?;
    let (mnt_parent_offset, mnt_mountpoint_offset, mnt_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = mount_template.as_ref() {
            (
                s.get_field("mnt_parent").map(|f| f.offset).unwrap_or(16),
                s.get_field("mnt_mountpoint")
                    .map(|f| f.offset)
                    .unwrap_or(24),
                s.get_field("mnt").map(|f| f.offset).unwrap_or(32),
            )
        } else {
            return Ok("/".to_string());
        };

    let vfsmount_template = context.get_type(symbol_table, "vfsmount")?;
    let mnt_root_offset = if let vol3_symbols::TypeTemplate::Struct(s) = vfsmount_template.as_ref()
    {
        s.get_field("mnt_root").map(|f| f.offset).unwrap_or(0)
    } else {
        0
    };

    let dentry_template = context.get_type(symbol_table, "dentry")?;
    let (d_parent_offset, d_name_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = dentry_template.as_ref() {
            (
                s.get_field("d_parent").map(|f| f.offset).unwrap_or(0),
                s.get_field("d_name").map(|f| f.offset).unwrap_or(0),
            )
        } else {
            return Ok("/".to_string());
        };

    let qstr_template = context.get_type(symbol_table, "qstr")?;
    let name_offset = if let vol3_symbols::TypeTemplate::Struct(s) = qstr_template.as_ref() {
        s.get_field("name").map(|f| f.offset).unwrap_or(0)
    } else {
        return Ok("/".to_string());
    };

    // Start from mnt_mountpoint of this mount
    // This is the dentry where this filesystem is mounted in the parent
    let mut dentry = helpers::read_pointer(layer, mount_addr + mnt_mountpoint_offset as u64)?;
    let mut current_mount = mount_addr;

    let mut path_parts = Vec::new();
    let mut seen_dentries = HashSet::new();
    let mut seen_mounts = HashSet::new();
    let max_iterations = 1000;
    let mut iterations = 0;

    // First, we need to get the parent mount since mnt_mountpoint is in the parent's filesystem
    let parent_mount = helpers::read_pointer(layer, mount_addr + mnt_parent_offset as u64)?;
    if parent_mount != 0
        && parent_mount != mount_addr
        && helpers::is_valid_kernel_address(parent_mount)
    {
        current_mount = parent_mount;
    }

    while iterations < max_iterations {
        iterations += 1;

        if dentry == 0 || !helpers::is_valid_kernel_address(dentry) {
            break;
        }

        // Read the mnt.mnt_root for current mount - this is the root dentry of current mount's filesystem
        let vfsmount_addr = current_mount + mnt_offset as u64;
        let mnt_root = helpers::read_pointer(layer, vfsmount_addr + mnt_root_offset as u64)?;

        // Read parent dentry
        let parent = helpers::read_pointer(layer, dentry + d_parent_offset as u64)?;

        // Check if at this mount's root (dentry == mnt_root or parent == self)
        let is_at_mount_root = dentry == mnt_root || parent == dentry;

        if is_at_mount_root {
            // At mount root - need to go up to parent mount
            let parent_mount =
                helpers::read_pointer(layer, current_mount + mnt_parent_offset as u64)?;

            if parent_mount == 0
                || parent_mount == current_mount
                || !helpers::is_valid_kernel_address(parent_mount)
            {
                // At global root
                break;
            }

            if seen_mounts.contains(&parent_mount) {
                break;
            }
            seen_mounts.insert(parent_mount);

            // Get the mountpoint dentry of current_mount (where it attaches in parent)
            let mountpoint_dentry =
                helpers::read_pointer(layer, current_mount + mnt_mountpoint_offset as u64)?;

            // Move to parent mount
            current_mount = parent_mount;
            dentry = mountpoint_dentry;
            continue;
        }

        if seen_dentries.contains(&dentry) {
            break;
        }
        seen_dentries.insert(dentry);

        // Read name from this dentry
        let qstr_addr = dentry + d_name_offset as u64;
        let name_ptr = helpers::read_pointer(layer, qstr_addr + name_offset as u64)?;
        if name_ptr != 0 && helpers::is_valid_kernel_address(name_ptr) {
            if let Ok(name) = helpers::read_string(layer, name_ptr, 256) {
                if !name.is_empty() {
                    path_parts.push(name);
                }
            }
        }

        dentry = parent;
    }

    path_parts.reverse();
    if path_parts.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", path_parts.join("/")))
    }
}

/// Finds a field offset on a type, including anonymous nested struct/union wrappers.
fn find_field_offset_recursive(
    template: &vol3_symbols::TypeTemplate,
    target_field: &str,
    base_offset: u64,
) -> Option<u64> {
    match template {
        vol3_symbols::TypeTemplate::Struct(s) => {
            if let Some(field) = s.get_field(target_field) {
                return Some(base_offset + field.offset as u64);
            }

            for field in &s.fields {
                if !field.name.starts_with("unnamed_field_") {
                    continue;
                }
                if let Some(offset) = find_field_offset_recursive(
                    field.template.as_ref(),
                    target_field,
                    base_offset + field.offset as u64,
                ) {
                    return Some(offset);
                }
            }

            None
        }
        vol3_symbols::TypeTemplate::Union(u) => {
            if let Some(member) = u.members.iter().find(|m| m.name == target_field) {
                return Some(base_offset + member.offset as u64);
            }

            for member in &u.members {
                if !member.name.starts_with("unnamed_field_") {
                    continue;
                }
                if let Some(offset) = find_field_offset_recursive(
                    member.template.as_ref(),
                    target_field,
                    base_offset + member.offset as u64,
                ) {
                    return Some(offset);
                }
            }

            None
        }
        _ => None,
    }
}

/// Get mounts for a task
fn get_task_mounts(
    context: &Context,
    layer: &dyn DataLayer,
    task: &TaskStruct,
    symbol_table: &str,
) -> Vol3Result<Vec<MountInfoInternal>> {
    // Get nsproxy offset in task_struct
    let task_template = context.get_type(symbol_table, "task_struct")?;
    let nsproxy_offset = if let vol3_symbols::TypeTemplate::Struct(s) = task_template.as_ref() {
        s.get_field("nsproxy").map(|f| f.offset).unwrap_or(0)
    } else {
        return Ok(Vec::new());
    };

    // Read nsproxy pointer
    let nsproxy_ptr = helpers::read_pointer(layer, task.address() + nsproxy_offset as u64)?;
    if nsproxy_ptr == 0 || !helpers::is_valid_kernel_address(nsproxy_ptr) {
        return Ok(Vec::new());
    }

    // Get mnt_ns offset in nsproxy
    let nsproxy_template = context.get_type(symbol_table, "nsproxy")?;
    let mnt_ns_offset = if let vol3_symbols::TypeTemplate::Struct(s) = nsproxy_template.as_ref() {
        s.get_field("mnt_ns").map(|f| f.offset).unwrap_or(0)
    } else {
        return Ok(Vec::new());
    };

    // Read mnt_namespace pointer
    let mnt_ns_ptr = helpers::read_pointer(layer, nsproxy_ptr + mnt_ns_offset as u64)?;
    if mnt_ns_ptr == 0 || !helpers::is_valid_kernel_address(mnt_ns_ptr) {
        return Ok(Vec::new());
    }

    // Get namespace/mount container offsets in mnt_namespace.
    let mnt_ns_template = context.get_type(symbol_table, "mnt_namespace")?;
    let (list_offset, has_ns_field, ns_offset, mounts_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = mnt_ns_template.as_ref() {
            (
                s.get_field("list").map(|f| f.offset as u64),
                s.get_field("ns").is_some(),
                s.get_field("ns").map(|f| f.offset as u64).unwrap_or(0),
                find_field_offset_recursive(mnt_ns_template.as_ref(), "mounts", 0),
            )
        } else {
            return Ok(Vec::new());
        };

    // Read the namespace ID (ns_common.inum)
    // ns_common structure: { struct list_head stashed; atomic_long_t count; unsigned int inum; }
    let ns_common_template = context.get_type(symbol_table, "ns_common");
    let inum_offset_in_ns = if let Ok(ref t) = ns_common_template {
        if let vol3_symbols::TypeTemplate::Struct(s) = t.as_ref() {
            s.get_field("inum").map(|f| f.offset).unwrap_or(16)
        } else {
            16
        }
    } else {
        16
    };

    let mnt_ns_id = if has_ns_field {
        let ns_addr = mnt_ns_ptr + ns_offset as u64;
        helpers::read_u32(layer, ns_addr + inum_offset_in_ns as u64)
            .ok()
            .map(|v| v as u64)
    } else {
        if let vol3_symbols::TypeTemplate::Struct(s) = mnt_ns_template.as_ref() {
            if let Some(field) = s.get_field("proc_inum") {
                helpers::read_u32(layer, mnt_ns_ptr + field.offset as u64)
                    .ok()
                    .map(|v| v as u64)
            } else {
                None
            }
        } else {
            None
        }
    };

    // Get mount struct offsets
    let mount_template = context.get_type(symbol_table, "mount")?;
    let (mnt_list_offset, mnt_id_offset, mnt_parent_offset, mnt_offset, mnt_node_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = mount_template.as_ref() {
            (
                s.get_field("mnt_list")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                s.get_field("mnt_id").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("mnt_parent")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                s.get_field("mnt").map(|f| f.offset as u64).unwrap_or(0),
                find_field_offset_recursive(mount_template.as_ref(), "mnt_node", 0),
            )
        } else {
            return Ok(Vec::new());
        };

    // Build mount address list from whichever namespace container this kernel uses.
    let mut mount_addrs: Vec<Address> = Vec::new();

    if let Some(list_offset) = list_offset {
        // kernels with mnt_namespace.list (or compatible profile field)
        let list_head = mnt_ns_ptr + list_offset;
        let first = helpers::read_pointer(layer, list_head).unwrap_or(0);
        let mut seen = HashSet::new();
        let mut current = first;

        while current != 0 && current != list_head && !seen.contains(&current) {
            seen.insert(current);
            let mount_addr = current.saturating_sub(mnt_list_offset);
            if mount_addr != 0 && helpers::is_valid_kernel_address(mount_addr) {
                mount_addrs.push(mount_addr);
            }
            current = helpers::read_pointer(layer, current).unwrap_or(0);
        }
    } else if let (Some(mounts_offset), Some(mnt_node_offset)) = (mounts_offset, mnt_node_offset) {
        // kernels where mounts are tracked in an rb_root ("mounts"), including anonymous wrappers.
        let rb_root_template = context.get_type(symbol_table, "rb_root")?;
        let rb_node_template = context.get_type(symbol_table, "rb_node")?;
        let rb_root_node_offset =
            if let vol3_symbols::TypeTemplate::Struct(s) = rb_root_template.as_ref() {
                s.get_field("rb_node").map(|f| f.offset as u64).unwrap_or(0)
            } else {
                0
            };
        let (rb_left_offset, rb_right_offset) =
            if let vol3_symbols::TypeTemplate::Struct(s) = rb_node_template.as_ref() {
                (
                    s.get_field("rb_left").map(|f| f.offset as u64).unwrap_or(0),
                    s.get_field("rb_right")
                        .map(|f| f.offset as u64)
                        .unwrap_or(0),
                )
            } else {
                (0, 0)
            };

        let root_node_ptr =
            helpers::read_pointer(layer, mnt_ns_ptr + mounts_offset + rb_root_node_offset)
                .unwrap_or(0);
        let mut stack: Vec<Address> = Vec::new();
        let mut seen_nodes = HashSet::new();
        if root_node_ptr != 0 {
            stack.push(root_node_ptr);
        }

        // Match volatility's rb_root.get_nodes() ordering: root, left subtree, right subtree.
        while let Some(node) = stack.pop() {
            if node == 0 || !helpers::is_valid_kernel_address(node) || !seen_nodes.insert(node) {
                continue;
            }

            let mount_addr = node.saturating_sub(mnt_node_offset);
            if mount_addr != 0 && helpers::is_valid_kernel_address(mount_addr) {
                mount_addrs.push(mount_addr);
            }

            let left = helpers::read_pointer(layer, node + rb_left_offset).unwrap_or(0);
            let right = helpers::read_pointer(layer, node + rb_right_offset).unwrap_or(0);
            if right != 0 {
                stack.push(right);
            }
            if left != 0 {
                stack.push(left);
            }
        }
    }

    if mount_addrs.is_empty() {
        return Ok(Vec::new());
    }

    let vfsmount_template = context.get_type(symbol_table, "vfsmount")?;
    let (mnt_sb_offset, mnt_root_offset, has_mnt_root, mnt_flags_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = vfsmount_template.as_ref() {
            (
                s.get_field("mnt_sb").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("mnt_root")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
                s.get_field("mnt_root").is_some(),
                s.get_field("mnt_flags")
                    .map(|f| f.offset as u64)
                    .unwrap_or(0),
            )
        } else {
            (0, 0, false, 0)
        };
    let mnt_devname_offset = if let vol3_symbols::TypeTemplate::Struct(s) = mount_template.as_ref()
    {
        s.get_field("mnt_devname")
            .map(|f| f.offset as u64)
            .unwrap_or(0)
    } else {
        0
    };
    let mnt_group_id_offset = if let vol3_symbols::TypeTemplate::Struct(s) = mount_template.as_ref()
    {
        s.get_field("mnt_group_id")
            .map(|f| f.offset as u64)
            .unwrap_or(0)
    } else {
        0
    };
    let mnt_master_offset = if let vol3_symbols::TypeTemplate::Struct(s) = mount_template.as_ref() {
        s.get_field("mnt_master")
            .map(|f| f.offset as u64)
            .unwrap_or(0)
    } else {
        0
    };

    let mut mounts = Vec::new();
    for mount_addr in mount_addrs {
        // Read mount fields
        let mnt_id = helpers::read_i32(layer, mount_addr + mnt_id_offset).unwrap_or(0);

        // Read parent mount to get parent_id
        let parent_mount = helpers::read_pointer(layer, mount_addr + mnt_parent_offset)?;
        let parent_id = if parent_mount != 0 && helpers::is_valid_kernel_address(parent_mount) {
            helpers::read_i32(layer, parent_mount + mnt_id_offset).unwrap_or(0)
        } else {
            0
        };

        // Get mountpoint path by walking up the mount hierarchy.
        // Keep a success flag so get_superblocks can mirror volatility3 filtering.
        let mountpoint_result = get_mount_path(context, layer, mount_addr, symbol_table);
        let mountpoint_valid = mountpoint_result.is_ok();
        let mountpoint = mountpoint_result.unwrap_or_else(|_| "/".to_string());

        // Get superblock via mnt.mnt_sb
        let vfsmount_addr = mount_addr + mnt_offset;
        let sb_ptr = helpers::read_pointer(layer, vfsmount_addr + mnt_sb_offset)?;

        // Get mnt_root dentry and its path
        let mnt_root_path = if has_mnt_root {
            let mnt_root_ptr = helpers::read_pointer(layer, vfsmount_addr + mnt_root_offset)?;
            if mnt_root_ptr != 0 && helpers::is_valid_kernel_address(mnt_root_ptr) {
                get_dentry_path(context, layer, mnt_root_ptr, symbol_table)
                    .unwrap_or_else(|_| "/".to_string())
            } else {
                "/".to_string()
            }
        } else {
            "/".to_string()
        };

        // Get superblock major/minor
        let (major, minor) = if sb_ptr != 0 && helpers::is_valid_kernel_address(sb_ptr) {
            get_superblock_dev(context, layer, sb_ptr, symbol_table)?
        } else {
            (0, 0)
        };

        // Read mount flags from vfsmount.mnt_flags to get mnt_opts
        let mnt_flags =
            helpers::read_i32(layer, vfsmount_addr + mnt_flags_offset).unwrap_or(0) as u32;
        let mnt_opts = get_mount_options(mnt_flags);

        // Read mnt_devname pointer from mount struct
        let devname = if mnt_devname_offset > 0 {
            let devname_ptr =
                helpers::read_pointer(layer, mount_addr + mnt_devname_offset).unwrap_or(0);
            if devname_ptr != 0 && helpers::is_valid_kernel_address(devname_ptr) {
                if let Ok(data) = layer.read(devname_ptr, 256, false) {
                    helpers::read_cstring(&data)
                } else {
                    "none".to_string()
                }
            } else {
                "none".to_string()
            }
        } else {
            "none".to_string()
        };

        // Read superblock type via s_type->name
        let mnt_type = if sb_ptr != 0 && helpers::is_valid_kernel_address(sb_ptr) {
            get_superblock_type(context, layer, sb_ptr, symbol_table)
                .unwrap_or_else(|_| "unknown".to_string())
        } else {
            "unknown".to_string()
        };

        // Read superblock flags for sb_opts
        let sb_opts = if sb_ptr != 0 && helpers::is_valid_kernel_address(sb_ptr) {
            get_superblock_options(context, layer, sb_ptr, symbol_table)
                .unwrap_or_else(|_| "rw".to_string())
        } else {
            "rw".to_string()
        };

        // Read shared/slave fields
        // Build fields list (shared, master, unbindable)
        let fields = {
            let mut parts: Vec<String> = Vec::new();

            // Check if shared (MNT_SHARED = 0x1000)
            const MNT_SHARED: u32 = 0x1000;
            if mnt_flags & MNT_SHARED != 0 && mnt_group_id_offset > 0 {
                let group_id =
                    helpers::read_i32(layer, mount_addr + mnt_group_id_offset).unwrap_or(0);
                if group_id > 0 {
                    parts.push(format!("shared:{}", group_id));
                }
            }

            // Check if slave (mnt_master is non-null)
            if mnt_master_offset > 0 {
                let master_ptr =
                    helpers::read_pointer(layer, mount_addr + mnt_master_offset).unwrap_or(0);
                if master_ptr != 0 && helpers::is_valid_kernel_address(master_ptr) {
                    // Read mnt_group_id from master
                    let master_group_id =
                        helpers::read_i32(layer, master_ptr + mnt_group_id_offset).unwrap_or(0);
                    if master_group_id > 0 {
                        parts.push(format!("master:{}", master_group_id));
                    }
                }
            }

            // Check if unbindable (MNT_UNBINDABLE = 0x20000)
            const MNT_UNBINDABLE: u32 = 0x20000;
            if mnt_flags & MNT_UNBINDABLE != 0 {
                parts.push("unbindable".to_string());
            }

            // Python uses space as separator for fields
            parts.join(" ")
        };

        mounts.push(MountInfoInternal {
            mnt_ns_id, // Use the namespace ID we read earlier
            mnt_id,
            parent_id,
            st_dev: format!("{}:{}", major, minor),
            mnt_root_path,
            path_root: mountpoint.clone(),
            mnt_opts,
            fields,
            mnt_type,
            devname,
            sb_opts,
            superblock_addr: sb_ptr,
            mountpoint,
            mountpoint_valid,
        });
    }

    Ok(mounts)
}

/// Get superblock device major/minor
fn get_superblock_dev(
    context: &Context,
    layer: &dyn DataLayer,
    sb_addr: Address,
    symbol_table: &str,
) -> Vol3Result<(u32, u32)> {
    let sb_template = context.get_type(symbol_table, "super_block")?;
    let s_dev_offset = if let vol3_symbols::TypeTemplate::Struct(s) = sb_template.as_ref() {
        s.get_field("s_dev").map(|f| f.offset).unwrap_or(0)
    } else {
        return Ok((0, 0));
    };

    // s_dev is a dev_t (u32)
    let bytes = layer
        .read(sb_addr + s_dev_offset as u64, 4, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    let s_dev = LittleEndian::read_u32(&bytes);

    // Linux: MINORBITS=20 (include/linux/kdev_t.h)
    const MINORBITS: u32 = 20;
    let major = s_dev >> MINORBITS;
    let minor = s_dev & ((1 << MINORBITS) - 1);

    Ok((major, minor))
}

/// Get mount options from mount flags
fn get_mount_options(mnt_flags: u32) -> String {
    // MNT flags from include/linux/mount.h
    const MNT_NOSUID: u32 = 0x01;
    const MNT_NODEV: u32 = 0x02;
    const MNT_NOEXEC: u32 = 0x04;
    const MNT_NOATIME: u32 = 0x08;
    const MNT_NODIRATIME: u32 = 0x10;
    const MNT_RELATIME: u32 = 0x20;
    const MNT_READONLY: u32 = 0x40;

    let mut opts = Vec::new();

    // Access mode first
    if mnt_flags & MNT_READONLY != 0 {
        opts.push("ro");
    } else {
        opts.push("rw");
    }

    // Other flags
    if mnt_flags & MNT_NOSUID != 0 {
        opts.push("nosuid");
    }
    if mnt_flags & MNT_NODEV != 0 {
        opts.push("nodev");
    }
    if mnt_flags & MNT_NOEXEC != 0 {
        opts.push("noexec");
    }
    if mnt_flags & MNT_NOATIME != 0 {
        opts.push("noatime");
    }
    if mnt_flags & MNT_NODIRATIME != 0 {
        opts.push("nodiratime");
    }
    if mnt_flags & MNT_RELATIME != 0 {
        opts.push("relatime");
    }

    opts.join(",")
}

/// Get superblock filesystem type from s_type->name
fn get_superblock_type(
    context: &Context,
    layer: &dyn DataLayer,
    sb_addr: Address,
    symbol_table: &str,
) -> Vol3Result<String> {
    let sb_template = context.get_type(symbol_table, "super_block")?;
    let (s_type_offset, s_subtype_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = sb_template.as_ref() {
            (
                s.get_field("s_type").map(|f| f.offset).unwrap_or(0),
                s.get_field("s_subtype").map(|f| f.offset),
            )
        } else {
            return Ok("unknown".to_string());
        };

    // Read s_type pointer (file_system_type*)
    let s_type_ptr = helpers::read_pointer(layer, sb_addr + s_type_offset as u64)?;
    if s_type_ptr == 0 || !helpers::is_valid_kernel_address(s_type_ptr) {
        return Ok("unknown".to_string());
    }

    // Get name offset in file_system_type
    let fst_template = context.get_type(symbol_table, "file_system_type")?;
    let name_offset = if let vol3_symbols::TypeTemplate::Struct(s) = fst_template.as_ref() {
        s.get_field("name").map(|f| f.offset).unwrap_or(0)
    } else {
        return Ok("unknown".to_string());
    };

    // Read name pointer
    let name_ptr = helpers::read_pointer(layer, s_type_ptr + name_offset as u64)?;
    if name_ptr == 0 || !helpers::is_valid_kernel_address(name_ptr) {
        return Ok("unknown".to_string());
    }

    // Read name string
    let data = layer
        .read(name_ptr, 64, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    let mut mnt_sb_type = helpers::read_cstring(&data);

    // Check for s_subtype (used by FUSE filesystems)
    if let Some(subtype_off) = s_subtype_offset {
        let s_subtype_ptr = helpers::read_pointer(layer, sb_addr + subtype_off as u64)?;
        if s_subtype_ptr != 0 && helpers::is_valid_kernel_address(s_subtype_ptr) {
            if let Ok(subtype_data) = layer.read(s_subtype_ptr, 255, false) {
                let subtype = helpers::read_cstring(&subtype_data);
                if !subtype.is_empty() {
                    mnt_sb_type = format!("{}.{}", mnt_sb_type, subtype);
                }
            }
        }
    }

    Ok(mnt_sb_type)
}

/// Get superblock options from s_flags
fn get_superblock_options(
    context: &Context,
    layer: &dyn DataLayer,
    sb_addr: Address,
    symbol_table: &str,
) -> Vol3Result<String> {
    let sb_template = context.get_type(symbol_table, "super_block")?;
    let s_flags_offset = if let vol3_symbols::TypeTemplate::Struct(s) = sb_template.as_ref() {
        s.get_field("s_flags").map(|f| f.offset).unwrap_or(0)
    } else {
        return Ok("rw".to_string());
    };

    // Read s_flags
    let s_flags_data = layer
        .read(sb_addr + s_flags_offset as u64, 8, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    let s_flags = LittleEndian::read_u64(&s_flags_data);

    // SB flags from include/linux/fs.h
    const SB_RDONLY: u64 = 1;
    const SB_SYNCHRONOUS: u64 = 16;
    const SB_DIRSYNC: u64 = 128;
    const SB_MANDLOCK: u64 = 64;
    const SB_LAZYTIME: u64 = 1 << 25;

    let mut opts = Vec::new();

    // Access mode first
    if s_flags & SB_RDONLY != 0 {
        opts.push("ro");
    } else {
        opts.push("rw");
    }

    // Other flags
    if s_flags & SB_SYNCHRONOUS != 0 {
        opts.push("sync");
    }
    if s_flags & SB_DIRSYNC != 0 {
        opts.push("dirsync");
    }
    if s_flags & SB_MANDLOCK != 0 {
        opts.push("mand");
    }
    if s_flags & SB_LAZYTIME != 0 {
        opts.push("lazytime");
    }

    Ok(opts.join(","))
}

impl Default for MountInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for MountInfo {
    fn name(&self) -> &str {
        "linux.mountinfo.MountInfo"
    }

    fn description(&self) -> &str {
        "Lists mount points on processes mount namespaces"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Memory layer for the kernel")
            .symbol_table("vmlinux", "Linux kernel symbol table")
            .int_optional("pids", "Filter by process IDs")
            .build();

        ModuleRequirements {
            name: self.name().to_string(),
            description: self.description().to_string(),
            requirements,
        }
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("MNT_NS_ID", ColumnType::Int),
            Column::new("MOUNT ID", ColumnType::Int),
            Column::new("PARENT_ID", ColumnType::Int),
            Column::new("MAJOR:MINOR", ColumnType::String),
            Column::new("ROOT", ColumnType::String),
            Column::new("MOUNT_POINT", ColumnType::String),
            Column::new("MOUNT_OPTIONS", ColumnType::String),
            Column::new("FIELDS", ColumnType::String),
            Column::new("FSTYPE", ColumnType::String),
            Column::new("MOUNT_SRC", ColumnType::String),
            Column::new("SB_OPTIONS", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let mounts = Self::list_mounts(&context)?;

        let rows: Vec<Vol3Result<Row>> = mounts
            .into_iter()
            .map(|m| {
                Ok(vec![
                    CellValue::Int(m.mnt_ns_id.unwrap_or(0) as i64),
                    CellValue::Int(m.mnt_id as i64),
                    CellValue::Int(m.parent_id as i64),
                    CellValue::String(m.st_dev),
                    CellValue::String(m.mnt_root_path),
                    CellValue::String(m.path_root),
                    CellValue::String(m.mnt_opts),
                    CellValue::String(m.fields),
                    CellValue::String(m.mnt_type),
                    CellValue::String(m.devname),
                    CellValue::String(m.sb_opts),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
