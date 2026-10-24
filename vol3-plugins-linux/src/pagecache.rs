//! Linux PageCache Files plugin.
//!
//! Lists files from memory (page cache).

use std::collections::HashSet;
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};
use chrono::{DateTime, TimeZone, Utc};
use log::warn;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;

use crate::helpers;
use crate::mountinfo::MountInfo;

/// 48-bit address mask for canonical kernel addresses
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Mirrors volatility3 pointer readability checks (`ptr and ptr.is_readable()`).
fn is_readable_pointer(layer: &dyn DataLayer, addr: Address) -> bool {
    if addr == 0 || !helpers::is_valid_kernel_address(addr) {
        return false;
    }
    layer.is_valid(addr, 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DentryWalkKind {
    ListHead,
    HList,
}

#[derive(Debug, Clone, Copy, Default)]
struct InodeTimeOffsets {
    // Kernels < 6.11: timespec/timespec64 fields (i_*time or __i_*time)
    atime_timespec_offset: Option<usize>,
    mtime_timespec_offset: Option<usize>,
    ctime_timespec_offset: Option<usize>,
    // Kernels >= 6.11: split second/nanosecond fields
    atime_sec_offset: Option<usize>,
    atime_nsec_offset: Option<usize>,
    mtime_sec_offset: Option<usize>,
    mtime_nsec_offset: Option<usize>,
    ctime_sec_offset: Option<usize>,
    ctime_nsec_offset: Option<usize>,
}

/// Inode information for output
#[derive(Debug, Clone)]
pub struct InodeInfo {
    pub superblock_addr: Address,
    pub mountpoint: String,
    pub device: String,
    pub inode_num: u64,
    pub inode_addr: Address,
    pub file_type: String,
    pub inode_pages: u64,
    pub cached_pages: u64,
    pub file_mode: String,
    pub access_time: Option<String>,
    pub modification_time: Option<String>,
    pub change_time: Option<String>,
    pub file_path: String,
    pub inode_size: u64,
}

/// PageCache Files plugin
pub struct PageCacheFiles;

impl PageCacheFiles {
    pub fn new() -> Self {
        Self
    }

    /// Get inodes from superblocks
    pub(crate) fn get_inodes(context: &Context) -> Vol3Result<Vec<InodeInfo>> {
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

        // Get superblocks from mount info
        let superblocks = MountInfo::get_superblocks(context)?;

        let mut inodes = Vec::new();
        let mut seen_inodes = HashSet::new();
        let mut seen_dentries = HashSet::new();

        for sb_info in superblocks {
            if let Ok(sb_inodes) = walk_superblock_inodes(
                context,
                layer.as_ref(),
                sb_info.addr,
                &sb_info.mountpoint,
                &symbol_table,
                &mut seen_inodes,
                &mut seen_dentries,
            ) {
                inodes.extend(sb_inodes);
            }
        }

        Ok(inodes)
    }
}

/// Walk inodes from a superblock
fn walk_superblock_inodes(
    context: &Context,
    layer: &dyn DataLayer,
    sb_addr: Address,
    mountpoint: &str,
    symbol_table: &str,
    seen_inodes: &mut HashSet<Address>,
    seen_dentries: &mut HashSet<Address>,
) -> Vol3Result<Vec<InodeInfo>> {
    use vol3_core::error::ObjectError;

    // Get super_block field offsets
    let sb_template = context.get_type(symbol_table, "super_block")?;
    let (s_root_offset, s_dev_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = sb_template.as_ref() {
            (
                s.get_field("s_root").map(|f| f.offset).unwrap_or(0),
                s.get_field("s_dev").map(|f| f.offset).unwrap_or(0),
            )
        } else {
            return Ok(Vec::new());
        };

    // Get device major/minor using Linux kernel's MINORBITS=20 convention
    // include/linux/kdev_t.h: #define MINORBITS 20
    let bytes = layer
        .read(sb_addr + s_dev_offset as u64, 4, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    let s_dev = LittleEndian::read_u32(&bytes);
    const MINORBITS: u32 = 20;
    let major = s_dev >> MINORBITS;
    let minor = s_dev & ((1 << MINORBITS) - 1);
    let device = format!("{}:{}", major, minor);

    // Get root dentry
    let root_dentry = helpers::read_pointer(layer, sb_addr + s_root_offset as u64)?;
    if !is_readable_pointer(layer, root_dentry) {
        return Ok(Vec::new());
    }

    // Get dentry field offsets and traversal mode parity with volatility3:
    //  - kernels >= 6.8 use d_children (hlist_head) + d_sib (hlist_node)
    //  - kernels 3.19..6.7 use d_subdirs (list_head) + d_child (list_head)
    //  - kernels < 3.19 use d_subdirs + d_u (union at d_child offset)
    let dentry_template = context.get_type(symbol_table, "dentry")?;
    let (d_inode_offset, d_subdirs_offset, d_child_offset, d_parent_offset, dentry_walk_kind) =
        if let vol3_symbols::TypeTemplate::Struct(s) = dentry_template.as_ref() {
            let (subdirs_offset, child_offset, walk_kind) = if let (Some(d_children), Some(d_sib)) =
                (s.get_field("d_children"), s.get_field("d_sib"))
            {
                let walk_kind = if d_children.template.type_name().contains("hlist_head")
                    || d_sib.template.type_name().contains("hlist_node")
                {
                    DentryWalkKind::HList
                } else {
                    DentryWalkKind::ListHead
                };
                (d_children.offset, d_sib.offset, walk_kind)
            } else if let (Some(d_subdirs), Some(d_child)) =
                (s.get_field("d_subdirs"), s.get_field("d_child"))
            {
                (d_subdirs.offset, d_child.offset, DentryWalkKind::ListHead)
            } else if let (Some(d_subdirs), Some(d_u)) =
                (s.get_field("d_subdirs"), s.get_field("d_u"))
            {
                (d_subdirs.offset, d_u.offset, DentryWalkKind::ListHead)
            } else {
                return Ok(Vec::new());
            };

            (
                s.get_field("d_inode").map(|f| f.offset).unwrap_or(0),
                subdirs_offset,
                child_offset,
                s.get_field("d_parent").map(|f| f.offset).unwrap_or(0),
                walk_kind,
            )
        } else {
            return Ok(Vec::new());
        };

    // Get inode field offsets (including timestamp fields and i_count for validation)
    let inode_template = context.get_type(symbol_table, "inode")?;
    let (
        i_ino_offset,
        i_mode_offset,
        i_size_offset,
        i_mapping_offset,
        i_sb_offset,
        i_count_offset,
        inode_time_offsets,
        i_link_offset,
    ) = if let vol3_symbols::TypeTemplate::Struct(s) = inode_template.as_ref() {
        // Try to get i_link offset - it's in an anonymous union at offset 584 (0x248) in 5.15 kernels
        // The i_link pointer is at offset 0 within that union
        // We need to find the union that contains i_link
        let i_link_off: usize = s
            .get_field("i_link")
            .map(|f| f.offset)
            .or_else(|| {
                // Search for anonymous union fields at expected offsets
                // In kernel 5.15, the union is at offset 584
                // Look for field named "unnamed_field_248" (hex 0x248 = 584)
                s.get_field("unnamed_field_248").map(|f| f.offset)
            })
            .unwrap_or(0);

        let inode_time_offsets = InodeTimeOffsets {
            atime_timespec_offset: s
                .get_field("i_atime")
                .or_else(|| s.get_field("__i_atime"))
                .map(|f| f.offset),
            mtime_timespec_offset: s
                .get_field("i_mtime")
                .or_else(|| s.get_field("__i_mtime"))
                .map(|f| f.offset),
            ctime_timespec_offset: s
                .get_field("i_ctime")
                .or_else(|| s.get_field("__i_ctime"))
                .map(|f| f.offset),
            atime_sec_offset: s.get_field("i_atime_sec").map(|f| f.offset),
            atime_nsec_offset: s.get_field("i_atime_nsec").map(|f| f.offset),
            mtime_sec_offset: s.get_field("i_mtime_sec").map(|f| f.offset),
            mtime_nsec_offset: s.get_field("i_mtime_nsec").map(|f| f.offset),
            ctime_sec_offset: s.get_field("i_ctime_sec").map(|f| f.offset),
            ctime_nsec_offset: s.get_field("i_ctime_nsec").map(|f| f.offset),
        };

        (
            s.get_field("i_ino").map(|f| f.offset).unwrap_or(0),
            s.get_field("i_mode").map(|f| f.offset).unwrap_or(0),
            s.get_field("i_size").map(|f| f.offset).unwrap_or(0),
            s.get_field("i_mapping").map(|f| f.offset).unwrap_or(0),
            s.get_field("i_sb").map(|f| f.offset).unwrap_or(0),
            s.get_field("i_count").map(|f| f.offset).unwrap_or(0),
            inode_time_offsets,
            i_link_off,
        )
    } else {
        return Ok(Vec::new());
    };

    // Get address_space field for nrpages
    let addr_space_template = context.get_type(symbol_table, "address_space")?;
    let nrpages_offset = if let vol3_symbols::TypeTemplate::Struct(s) = addr_space_template.as_ref()
    {
        s.get_field("nrpages").map(|f| f.offset).unwrap_or(0)
    } else {
        0
    };

    let mut inodes = Vec::new();

    // Check is_root: root_dentry.d_parent must equal root_dentry (Python: dentry.is_root())
    let d_parent = helpers::read_pointer(layer, root_dentry + d_parent_offset as u64)?;
    if d_parent != root_dentry {
        // Not a root dentry - skip this superblock
        return Ok(Vec::new());
    }

    // Process root dentry inode
    let root_inode = helpers::read_pointer(layer, root_dentry + d_inode_offset as u64)?;
    if !is_readable_pointer(layer, root_inode) {
        return Ok(Vec::new());
    }

    // Ensure inode belongs to this superblock.
    let root_i_sb = helpers::read_pointer(layer, root_inode + i_sb_offset as u64).unwrap_or(0);
    if root_i_sb != 0 && root_i_sb != sb_addr {
        return Ok(Vec::new());
    }

    // Check inode is_valid: i_ino > 0 and i_count.counter >= 0 (Python: inode.is_valid())
    let i_ino_bytes = layer
        .read(root_inode + i_ino_offset as u64, 8, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    let i_ino = LittleEndian::read_u64(&i_ino_bytes);
    if i_ino == 0 {
        return Ok(Vec::new());
    }

    // Check i_count.counter >= 0 (it's an atomic_t which is a signed 32-bit int)
    let i_count_bytes = layer
        .read(root_inode + i_count_offset as u64, 4, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    let i_count = LittleEndian::read_i32(&i_count_bytes);
    if i_count < 0 {
        return Ok(Vec::new());
    }

    // Check i_mapping is valid (Python: root_inode.i_mapping and root_inode.i_mapping.is_readable())
    let i_mapping = helpers::read_pointer(layer, root_inode + i_mapping_offset as u64)?;
    if !is_readable_pointer(layer, i_mapping) {
        return Ok(Vec::new());
    }

    if !seen_inodes.contains(&root_inode) {
        seen_inodes.insert(root_inode);

        if let Ok(info) = read_inode_info(
            layer,
            root_inode,
            sb_addr,
            &device,
            mountpoint,
            mountpoint.to_string(),
            i_ino_offset,
            i_mode_offset,
            i_size_offset,
            i_mapping_offset,
            nrpages_offset,
            inode_time_offsets,
            i_link_offset,
        ) {
            inodes.push(info);
        }
    }

    // Match volatility3 parent_dir behavior: root uses empty parent path.
    let parent_path = if mountpoint == "/" { "" } else { mountpoint };

    // Walk dentries recursively.
    walk_dentries(
        context,
        layer,
        root_dentry,
        mountpoint,  // sb_mountpoint - stays constant
        parent_path, // parent_path - changes during recursion
        sb_addr,
        &device,
        symbol_table,
        seen_inodes,
        seen_dentries,
        &mut inodes,
        d_inode_offset,
        d_subdirs_offset,
        d_child_offset,
        dentry_walk_kind,
        i_ino_offset,
        i_mode_offset,
        i_size_offset,
        i_mapping_offset,
        i_sb_offset,
        i_count_offset,
        nrpages_offset,
        inode_time_offsets,
        i_link_offset,
    )?;

    Ok(inodes)
}

/// Walk dentry children
fn walk_dentries(
    context: &Context,
    layer: &dyn DataLayer,
    dentry_addr: Address,
    sb_mountpoint: &str, // Original superblock mountpoint (constant)
    parent_path: &str,   // Current parent path (changes during recursion)
    sb_addr: Address,
    device: &str,
    symbol_table: &str,
    seen_inodes: &mut HashSet<Address>,
    seen_dentries: &mut HashSet<Address>,
    inodes: &mut Vec<InodeInfo>,
    d_inode_offset: usize,
    d_subdirs_offset: usize,
    d_child_offset: usize,
    dentry_walk_kind: DentryWalkKind,
    i_ino_offset: usize,
    i_mode_offset: usize,
    i_size_offset: usize,
    i_mapping_offset: usize,
    i_sb_offset: usize,
    i_count_offset: usize,
    nrpages_offset: usize,
    inode_time_offsets: InodeTimeOffsets,
    i_link_offset: usize,
) -> Vol3Result<()> {
    // Get subdirs list head
    let subdirs_head = dentry_addr + d_subdirs_offset as u64;
    let mut current = helpers::read_pointer(layer, subdirs_head)?;
    if current == 0 {
        return Ok(());
    }
    if matches!(dentry_walk_kind, DentryWalkKind::ListHead) && current == subdirs_head {
        return Ok(());
    }

    let mut seen_links = HashSet::new();

    while current != 0 && !seen_links.contains(&current) {
        if matches!(dentry_walk_kind, DentryWalkKind::ListHead) && current == subdirs_head {
            break;
        }
        seen_links.insert(current);

        // Calculate child dentry address from list position.
        let child_dentry = current.saturating_sub(d_child_offset as u64);
        if !is_readable_pointer(layer, child_dentry) {
            current = helpers::read_pointer(layer, current)?;
            continue;
        }

        if seen_dentries.contains(&child_dentry) || child_dentry == dentry_addr {
            current = helpers::read_pointer(layer, current)?;
            continue;
        }
        seen_dentries.insert(child_dentry);

        // Read child inode pointer.
        let child_inode = helpers::read_pointer(layer, child_dentry + d_inode_offset as u64)?;
        if !is_readable_pointer(layer, child_inode) || seen_inodes.contains(&child_inode) {
            current = helpers::read_pointer(layer, current)?;
            continue;
        }

        // Inode should belong to the same superblock we're currently walking.
        let inode_sb = helpers::read_pointer(layer, child_inode + i_sb_offset as u64).unwrap_or(0);
        if inode_sb != 0 && inode_sb != sb_addr {
            current = helpers::read_pointer(layer, current)?;
            continue;
        }

        // Validate child inode (Python: inode.is_valid()).
        let i_ino_bytes = match layer.read(child_inode + i_ino_offset as u64, 8, false) {
            Ok(b) => b,
            Err(_) => {
                current = helpers::read_pointer(layer, current)?;
                continue;
            }
        };
        let i_ino = LittleEndian::read_u64(&i_ino_bytes);
        if i_ino == 0 {
            current = helpers::read_pointer(layer, current)?;
            continue;
        }

        let i_count_bytes = match layer.read(child_inode + i_count_offset as u64, 4, false) {
            Ok(b) => b,
            Err(_) => {
                current = helpers::read_pointer(layer, current)?;
                continue;
            }
        };
        let i_count = LittleEndian::read_i32(&i_count_bytes);
        if i_count < 0 {
            current = helpers::read_pointer(layer, current)?;
            continue;
        }

        let name = read_dentry_name(layer, child_dentry, symbol_table, context)?;
        if name.is_empty() || name == "<unknown>" {
            current = helpers::read_pointer(layer, current)?;
            continue;
        }

        let file_path = if parent_path.is_empty() {
            format!("/{}", name)
        } else {
            format!("{}/{}", parent_path, name)
        };

        // Determine directory status from inode mode so recursion is independent of i_mapping.
        let mode = helpers::read_u16(layer, child_inode + i_mode_offset as u64).unwrap_or(0) as u32;
        let is_dir = (mode & 0o170000) == 0o040000;

        // Rows are emitted only when i_mapping is readable, matching volatility3 Files.get_inodes.
        let i_mapping =
            helpers::read_pointer(layer, child_inode + i_mapping_offset as u64).unwrap_or(0);
        if is_readable_pointer(layer, i_mapping) {
            seen_inodes.insert(child_inode);

            if let Ok(info) = read_inode_info(
                layer,
                child_inode,
                sb_addr,
                device,
                sb_mountpoint,
                file_path.clone(),
                i_ino_offset,
                i_mode_offset,
                i_size_offset,
                i_mapping_offset,
                nrpages_offset,
                inode_time_offsets,
                i_link_offset,
            ) {
                inodes.push(info);
            }
        }

        if is_dir {
            let _ = walk_dentries(
                context,
                layer,
                child_dentry,
                sb_mountpoint,
                &file_path,
                sb_addr,
                device,
                symbol_table,
                seen_inodes,
                seen_dentries,
                inodes,
                d_inode_offset,
                d_subdirs_offset,
                d_child_offset,
                dentry_walk_kind,
                i_ino_offset,
                i_mode_offset,
                i_size_offset,
                i_mapping_offset,
                i_sb_offset,
                i_count_offset,
                nrpages_offset,
                inode_time_offsets,
                i_link_offset,
            );
        }

        current = helpers::read_pointer(layer, current)?;
    }

    Ok(())
}

/// Read dentry name from qstr
fn read_dentry_name(
    layer: &dyn DataLayer,
    dentry_addr: Address,
    symbol_table: &str,
    context: &Context,
) -> Vol3Result<String> {
    // Get d_name offset (it's a qstr struct)
    let dentry_template = context.get_type(symbol_table, "dentry")?;
    let d_name_offset = if let vol3_symbols::TypeTemplate::Struct(s) = dentry_template.as_ref() {
        s.get_field("d_name").map(|f| f.offset).unwrap_or(0)
    } else {
        return Ok("<unknown>".to_string());
    };

    // Get qstr name pointer offset
    let qstr_template = context.get_type(symbol_table, "qstr")?;
    let (name_offset, len_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = qstr_template.as_ref() {
            (
                s.get_field("name").map(|f| f.offset).unwrap_or(0),
                s.get_field("len").map(|f| f.offset),
            )
        } else {
            return Ok("<unknown>".to_string());
        };

    // Read name pointer
    let qstr_addr = dentry_addr + d_name_offset as u64;
    let name_ptr = helpers::read_pointer(layer, qstr_addr + name_offset as u64)?;

    if name_ptr == 0 {
        return Ok("<unknown>".to_string());
    }

    // Read name string
    let max_len = if let Some(len_off) = len_offset {
        helpers::read_u32(layer, qstr_addr + len_off as u64).unwrap_or(0) as usize + 1
    } else {
        255
    };
    helpers::read_string(layer, name_ptr, max_len)
}

/// Read inode information
fn read_inode_info(
    layer: &dyn DataLayer,
    inode_addr: Address,
    sb_addr: Address,
    device: &str,
    mountpoint: &str,
    file_path: String,
    i_ino_offset: usize,
    i_mode_offset: usize,
    i_size_offset: usize,
    i_mapping_offset: usize,
    nrpages_offset: usize,
    inode_time_offsets: InodeTimeOffsets,
    i_link_offset: usize,
) -> Vol3Result<InodeInfo> {
    // Read inode number
    let bytes = layer
        .read(inode_addr + i_ino_offset as u64, 8, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    let i_ino = LittleEndian::read_u64(&bytes);

    // Read mode
    let bytes = layer
        .read(inode_addr + i_mode_offset as u64, 2, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    let i_mode = LittleEndian::read_u16(&bytes);

    // Read size
    let bytes = layer
        .read(inode_addr + i_size_offset as u64, 8, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    let i_size = LittleEndian::read_i64(&bytes) as u64;

    // Get file type from mode
    let file_type = get_inode_type(i_mode);

    // Get file mode string
    let file_mode = format_mode(i_mode);

    // Read address_space to get nrpages
    let i_mapping = helpers::read_pointer(layer, inode_addr + i_mapping_offset as u64)?;
    let cached_pages =
        if i_mapping != 0 && helpers::is_valid_kernel_address(i_mapping) && nrpages_offset > 0 {
            let bytes = layer
                .read(i_mapping + nrpages_offset as u64, 8, false)
                .unwrap_or_else(|_| vec![0u8; 8]);
            LittleEndian::read_u64(&bytes)
        } else {
            0
        };

    // Calculate inode pages (total possible pages based on size)
    let page_size = 4096u64;
    let inode_pages = (i_size + page_size - 1) / page_size;

    // Read timestamps with kernel-version-aware inode field layouts.
    let access_time = read_inode_timestamp(
        layer,
        inode_addr,
        inode_time_offsets.atime_timespec_offset,
        inode_time_offsets.atime_sec_offset,
        inode_time_offsets.atime_nsec_offset,
    );
    let modification_time = read_inode_timestamp(
        layer,
        inode_addr,
        inode_time_offsets.mtime_timespec_offset,
        inode_time_offsets.mtime_sec_offset,
        inode_time_offsets.mtime_nsec_offset,
    );
    let change_time = read_inode_timestamp(
        layer,
        inode_addr,
        inode_time_offsets.ctime_timespec_offset,
        inode_time_offsets.ctime_sec_offset,
        inode_time_offsets.ctime_nsec_offset,
    );

    // Handle symlinks - try to follow i_link (fast symlinks, kernels >= 4.2)
    let final_file_path = if file_type == "LNK" && i_link_offset > 0 {
        // Read i_link pointer
        if let Ok(i_link) = helpers::read_pointer(layer, inode_addr + i_link_offset as u64) {
            if i_link != 0 && helpers::is_valid_kernel_address(i_link) {
                // Read the symlink target string (null-terminated, max 255 chars)
                if let Ok(bytes) = layer.read(i_link, 256, false) {
                    // Find null terminator
                    let end = bytes.iter().position(|&b| b == 0).unwrap_or(255);
                    if end > 0 {
                        if let Ok(target) = String::from_utf8(bytes[..end].to_vec()) {
                            // Format as "path -> target"
                            format!("{} -> {}", file_path, target)
                        } else {
                            file_path
                        }
                    } else {
                        file_path
                    }
                } else {
                    file_path
                }
            } else {
                file_path
            }
        } else {
            file_path
        }
    } else {
        file_path
    };

    Ok(InodeInfo {
        superblock_addr: sb_addr,
        mountpoint: mountpoint.to_string(),
        device: device.to_string(),
        inode_num: i_ino,
        inode_addr,
        file_type,
        inode_pages,
        cached_pages,
        file_mode,
        access_time,
        modification_time,
        change_time,
        file_path: final_file_path,
        inode_size: i_size,
    })
}

fn read_inode_timestamp(
    layer: &dyn DataLayer,
    inode_addr: Address,
    timespec_offset: Option<usize>,
    sec_offset: Option<usize>,
    nsec_offset: Option<usize>,
) -> Option<String> {
    // Kernels >= 6.11: i_*_sec (time64_t) + i_*_nsec (u32)
    if let (Some(sec_off), Some(nsec_off)) = (sec_offset, nsec_offset) {
        let sec_bytes = layer.read(inode_addr + sec_off as u64, 8, false).ok()?;
        let tv_sec = LittleEndian::read_i64(&sec_bytes);

        // Match current Volatility3 behavior for split inode timestamps:
        // nanoseconds are effectively ignored in output formatting.
        let _ = nsec_off;
        return format_unix_time(tv_sec, 0);
    }

    // Kernels < 6.11: i_*time / __i_*time as timespec/timespec64
    if let Some(ts_off) = timespec_offset {
        return read_timespec64(layer, inode_addr + ts_off as u64);
    }

    None
}

/// Read a timespec64 and convert to formatted datetime string.
fn read_timespec64(layer: &dyn DataLayer, addr: Address) -> Option<String> {
    // timespec64 has tv_sec (8 bytes) and tv_nsec (8 bytes)
    let bytes = layer.read(addr, 16, false).ok()?;
    let tv_sec = LittleEndian::read_i64(&bytes[0..8]);
    let tv_nsec = LittleEndian::read_i64(&bytes[8..16]);
    format_unix_time(tv_sec, tv_nsec)
}

/// Convert unix timestamp parts to Python-compatible display format.
fn format_unix_time(tv_sec: i64, tv_nsec: i64) -> Option<String> {
    if tv_sec < 0 {
        return None;
    }

    // Convert to float like Python: tv_sec + tv_nsec / NSEC_PER_SEC
    // This is important for matching Python's float precision behavior
    const NSEC_PER_SEC: f64 = 1_000_000_000.0;
    let timestamp_float = tv_sec as f64 + tv_nsec as f64 / NSEC_PER_SEC;

    // Python's datetime.fromtimestamp() rounds to microseconds
    // We need to convert back to secs/microsecs matching Python's behavior
    let secs = timestamp_float.floor() as i64;
    let micros = ((timestamp_float - secs as f64) * 1_000_000.0).round() as i64;

    // Handle case where rounding micros causes overflow
    let (final_secs, final_micros) = if micros >= 1_000_000 {
        (secs + 1, 0)
    } else if micros < 0 {
        (secs - 1, (micros + 1_000_000) as u32)
    } else {
        (secs, micros as u32)
    };

    // Convert microseconds to nanoseconds for chrono
    let nsecs = final_micros * 1000;

    if let Some(dt) = Utc.timestamp_opt(final_secs, nsecs).single() {
        // Format like Python: 2026-01-23 22:01:47.604000 UTC
        Some(dt.format("%Y-%m-%d %H:%M:%S.%6f UTC").to_string())
    } else {
        None
    }
}

/// Get inode type from mode
fn get_inode_type(mode: u16) -> String {
    const S_IFMT: u16 = 0o170000;
    const S_IFDIR: u16 = 0o040000;
    const S_IFREG: u16 = 0o100000;
    const S_IFLNK: u16 = 0o120000;
    const S_IFIFO: u16 = 0o010000;
    const S_IFSOCK: u16 = 0o140000;
    const S_IFBLK: u16 = 0o060000;
    const S_IFCHR: u16 = 0o020000;

    match mode & S_IFMT {
        S_IFDIR => "DIR".to_string(),
        S_IFREG => "REG".to_string(),
        S_IFLNK => "LNK".to_string(),
        S_IFIFO => "FIFO".to_string(),
        S_IFSOCK => "SOCK".to_string(),
        S_IFBLK => "BLK".to_string(),
        S_IFCHR => "CHR".to_string(),
        _ => "UNK".to_string(),
    }
}

/// Format mode as permission string
fn format_mode(mode: u16) -> String {
    const S_IFMT: u16 = 0o170000;
    const S_IFDIR: u16 = 0o040000;
    const S_IFREG: u16 = 0o100000;
    const S_IFLNK: u16 = 0o120000;
    const S_ISUID: u16 = 0o4000; // setuid
    const S_ISGID: u16 = 0o2000; // setgid
    const S_ISVTX: u16 = 0o1000; // sticky bit

    let type_char = match mode & S_IFMT {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        S_IFREG => '-',
        0o060000 => 'b', // block
        0o020000 => 'c', // char
        0o010000 => 'p', // fifo
        0o140000 => 's', // socket
        _ => '?',
    };

    // Owner permissions
    let owner_r = if mode & 0o400 != 0 { 'r' } else { '-' };
    let owner_w = if mode & 0o200 != 0 { 'w' } else { '-' };
    let owner_x = if mode & S_ISUID != 0 {
        if mode & 0o100 != 0 {
            's'
        } else {
            'S'
        }
    } else {
        if mode & 0o100 != 0 {
            'x'
        } else {
            '-'
        }
    };

    // Group permissions
    let group_r = if mode & 0o040 != 0 { 'r' } else { '-' };
    let group_w = if mode & 0o020 != 0 { 'w' } else { '-' };
    let group_x = if mode & S_ISGID != 0 {
        if mode & 0o010 != 0 {
            's'
        } else {
            'S'
        }
    } else {
        if mode & 0o010 != 0 {
            'x'
        } else {
            '-'
        }
    };

    // Other permissions
    let other_r = if mode & 0o004 != 0 { 'r' } else { '-' };
    let other_w = if mode & 0o002 != 0 { 'w' } else { '-' };
    let other_x = if mode & S_ISVTX != 0 {
        if mode & 0o001 != 0 {
            't'
        } else {
            'T'
        }
    } else {
        if mode & 0o001 != 0 {
            'x'
        } else {
            '-'
        }
    };

    format!(
        "{}{}{}{}{}{}{}{}{}{}",
        type_char, owner_r, owner_w, owner_x, group_r, group_w, group_x, other_r, other_w, other_x
    )
}

impl Default for PageCacheFiles {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for PageCacheFiles {
    fn name(&self) -> &str {
        "linux.pagecache.Files"
    }

    fn description(&self) -> &str {
        "Lists files from memory (page cache)"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Memory layer for the kernel")
            .symbol_table("vmlinux", "Linux kernel symbol table")
            .string_optional("type", "Filter by file type (REG, DIR, LNK, etc.)")
            .string_optional("find", "Find specific file path")
            .build();

        ModuleRequirements {
            name: self.name().to_string(),
            description: self.description().to_string(),
            requirements,
        }
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("SuperblockAddr", ColumnType::Hex),
            Column::new("MountPoint", ColumnType::String),
            Column::new("Device", ColumnType::String),
            Column::new("InodeNum", ColumnType::Int),
            Column::new("InodeAddr", ColumnType::Hex),
            Column::new("FileType", ColumnType::String),
            Column::new("InodePages", ColumnType::Int),
            Column::new("CachedPages", ColumnType::Int),
            Column::new("FileMode", ColumnType::String),
            Column::new("AccessTime", ColumnType::String),
            Column::new("ModificationTime", ColumnType::String),
            Column::new("ChangeTime", ColumnType::String),
            Column::new("FilePath", ColumnType::String),
            Column::new("InodeSize", ColumnType::Int),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        // Get type filter
        let type_filter = context.config_get_string("plugins.pagecache.type");
        let find_path = context.config_get_string("plugins.pagecache.find");

        let inodes = Self::get_inodes(&context)?;

        let rows: Vec<Vol3Result<Row>> = inodes
            .into_iter()
            .filter(|i| {
                if let Some(ref t) = type_filter {
                    if !i.file_type.eq_ignore_ascii_case(t) {
                        return false;
                    }
                }
                if let Some(ref p) = find_path {
                    if i.file_path != *p {
                        return false;
                    }
                }
                true
            })
            .map(|i| {
                Ok(vec![
                    CellValue::Hex(i.superblock_addr & ADDR_MASK),
                    CellValue::String(i.mountpoint),
                    CellValue::String(i.device),
                    CellValue::Int(i.inode_num as i64),
                    CellValue::Hex(i.inode_addr & ADDR_MASK),
                    CellValue::String(i.file_type),
                    CellValue::Int(i.inode_pages as i64),
                    CellValue::Int(i.cached_pages as i64),
                    CellValue::String(i.file_mode),
                    CellValue::String(i.access_time.clone().unwrap_or_else(|| "-".to_string())),
                    CellValue::String(
                        i.modification_time
                            .clone()
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                    CellValue::String(i.change_time.clone().unwrap_or_else(|| "-".to_string())),
                    CellValue::String(i.file_path),
                    CellValue::Int(i.inode_size as i64),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
