//! Linux RecoverFs plugin.
//!
//! Recovers page-cache-backed files into a compressed tar archive.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use byteorder::{ByteOrder, LittleEndian};

use vol3_core::error::{PluginError, Vol3Error, Vol3Result};
use vol3_core::types::{AbsentValue, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::{Requirement, RequirementsBuilder};
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::helpers;
use crate::pagecache::{InodeInfo, PageCacheFiles};

const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;
const XARRAY_TAG_MASK: u64 = 0x3;
const XARRAY_TAG_INTERNAL: u64 = 0x2;
const VMEMMAP_BASE_L4: u64 = 0xFFFF_EA00_0000_0000;

#[derive(Debug, Clone, Copy)]
enum CompressionFormat {
    Gz,
    Bz2,
    Xz,
}

impl CompressionFormat {
    fn from_config(value: Option<String>) -> Self {
        match value
            .unwrap_or_else(|| "gz".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "bz2" => Self::Bz2,
            "xz" => Self::Xz,
            _ => Self::Gz,
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Gz => "gz",
            Self::Bz2 => "bz2",
            Self::Xz => "xz",
        }
    }
}

#[derive(Debug, Clone)]
struct RecoverFsLayout {
    pointer_size: usize,
    page_size: usize,
    inode_mapping_offset: usize,
    inode_link_offset: Option<usize>,
    address_space_i_pages_offset: usize,
    xa_head_offset: usize,
    xa_shift_offset: usize,
    xa_shift_size: usize,
    xa_slots_offset: usize,
    xa_slots_count: usize,
    page_struct_size: usize,
    page_mapping_offset: Option<usize>,
    page_index_offset: Option<usize>,
    page_index_size: usize,
    super_uuid_offset: Option<usize>,
    super_dev_offset: Option<usize>,
    super_type_offset: Option<usize>,
    super_subtype_offset: Option<usize>,
    fstype_name_offset: Option<usize>,
}

#[derive(Debug, Clone)]
struct SuperblockMeta {
    prefix: String,
    fs_type: Option<String>,
}

pub struct RecoverFs;

impl RecoverFs {
    pub fn new() -> Self {
        Self
    }

    fn run_inner(&self, context: Arc<Context>) -> Vol3Result<Vec<Vol3Result<Row>>> {
        use vol3_core::error::{ConfigError, LayerError};

        let kernel_layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;
        let kernel_layer = context
            .get_layer(&kernel_layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(kernel_layer_name.clone())))?;

        let physical_layer_name = kernel_layer
            .dependencies()
            .into_iter()
            .next()
            .unwrap_or_else(|| kernel_layer_name.clone());
        let physical_layer = context
            .get_layer(&physical_layer_name)
            .unwrap_or_else(|| kernel_layer.clone());

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        let compression = CompressionFormat::from_config(
            context.config_get_string("plugins.recoverfs.compression_format"),
        );
        let tmpfs_only = context
            .config_get_bool("plugins.recoverfs.tmpfs_only")
            .unwrap_or(false);

        let layout = build_layout(&context, &symbol_table)?;
        let vmemmap_start = determine_vmemmap_start(
            &context,
            kernel_layer.as_ref(),
            &symbol_table,
            layout.pointer_size,
        )?;

        let inodes = PageCacheFiles::get_inodes(&context)?;

        let output_dir = context
            .config_get_string("plugins.output_dir")
            .map(PathBuf::from)
            .unwrap_or(std::env::current_dir()?);
        std::fs::create_dir_all(&output_dir)?;

        let archive_name = format!("recovered_fs.tar.{}", compression.extension());
        let archive_path = unique_path(&output_dir, &archive_name);
        let mtime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let rows = match compression {
            CompressionFormat::Gz => {
                let file = File::create(&archive_path)?;
                let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
                let mut builder = tar::Builder::new(encoder);
                let rows = write_archive(
                    &context,
                    kernel_layer.as_ref(),
                    physical_layer.as_ref(),
                    &symbol_table,
                    &layout,
                    vmemmap_start,
                    tmpfs_only,
                    &inodes,
                    mtime,
                    &mut builder,
                )?;
                let encoder = builder.into_inner()?;
                let _ = encoder.finish()?;
                rows
            }
            CompressionFormat::Bz2 => {
                let file = File::create(&archive_path)?;
                let encoder = bzip2::write::BzEncoder::new(file, bzip2::Compression::best());
                let mut builder = tar::Builder::new(encoder);
                let rows = write_archive(
                    &context,
                    kernel_layer.as_ref(),
                    physical_layer.as_ref(),
                    &symbol_table,
                    &layout,
                    vmemmap_start,
                    tmpfs_only,
                    &inodes,
                    mtime,
                    &mut builder,
                )?;
                let encoder = builder.into_inner()?;
                let _ = encoder.finish()?;
                rows
            }
            CompressionFormat::Xz => {
                let file = File::create(&archive_path)?;
                let encoder = xz2::write::XzEncoder::new(file, 6);
                let mut builder = tar::Builder::new(encoder);
                let rows = write_archive(
                    &context,
                    kernel_layer.as_ref(),
                    physical_layer.as_ref(),
                    &symbol_table,
                    &layout,
                    vmemmap_start,
                    tmpfs_only,
                    &inodes,
                    mtime,
                    &mut builder,
                )?;
                let encoder = builder.into_inner()?;
                let _ = encoder.finish()?;
                rows
            }
        };

        log::info!("RecoverFs archive written to {}", archive_path.display());
        Ok(rows)
    }
}

impl Default for RecoverFs {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for RecoverFs {
    fn name(&self) -> &str {
        "linux.pagecache.RecoverFs"
    }

    fn description(&self) -> &str {
        "Recovers the cached filesystem into a compressed tarball"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Memory layer for the kernel")
            .symbol_table("vmlinux", "Linux kernel symbol table")
            .add(
                Requirement::bool("tmpfs_only", "Extract only tmpfs file systems")
                    .optional()
                    .with_default(serde_json::json!(false)),
            )
            .add(
                Requirement::choice(
                    "compression_format",
                    "Compression format (default: gz)",
                    vec!["gz".to_string(), "bz2".to_string(), "xz".to_string()],
                )
                .optional()
                .with_default(serde_json::json!("gz")),
            )
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
            Column::new("Recovered FileSize", ColumnType::Int),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let rows = self.run_inner(context)?;
        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}

fn plugin_error(message: impl Into<String>) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message.into()))
}

fn read_pointer_sized(layer: &dyn DataLayer, address: u64, pointer_size: usize) -> Vol3Result<u64> {
    let size = pointer_size.max(1);
    let bytes = layer.read(address, size, false).map_err(Vol3Error::Layer)?;
    let value = match size {
        1 => bytes[0] as u64,
        2 => LittleEndian::read_u16(&bytes) as u64,
        4 => LittleEndian::read_u32(&bytes) as u64,
        _ => LittleEndian::read_u64(&bytes[..8]) as u64,
    };
    Ok(value)
}

fn read_unsigned(layer: &dyn DataLayer, address: u64, size: usize) -> Option<u64> {
    let size = size.max(1);
    let bytes = layer.read(address, size, false).ok()?;
    Some(match size {
        1 => bytes[0] as u64,
        2 => LittleEndian::read_u16(&bytes) as u64,
        4 => LittleEndian::read_u32(&bytes) as u64,
        _ => LittleEndian::read_u64(&bytes[..8]) as u64,
    })
}

fn build_layout(context: &Context, symbol_table: &str) -> Vol3Result<RecoverFsLayout> {
    let pointer_size = context
        .get_type(symbol_table, "pointer")
        .ok()
        .and_then(|t| t.size())
        .unwrap_or(8)
        .max(1);

    let inode_template = context.get_type(symbol_table, "inode")?;
    let (inode_mapping_offset, inode_link_offset) =
        if let TypeTemplate::Struct(s) = inode_template.as_ref() {
            let mapping = s
                .get_field("i_mapping")
                .map(|f| f.offset)
                .ok_or_else(|| plugin_error("RecoverFs: inode.i_mapping field not found"))?;
            (mapping, s.get_field("i_link").map(|f| f.offset))
        } else {
            return Err(plugin_error("RecoverFs: inode type is not a struct"));
        };

    let address_space_template = context.get_type(symbol_table, "address_space")?;
    let address_space_i_pages_offset =
        if let TypeTemplate::Struct(s) = address_space_template.as_ref() {
            if let Some(field) = s.get_field("i_pages") {
                field.offset
            } else if let Some(field) = s.get_field("page_tree") {
                field.offset
            } else {
                return Err(plugin_error(
                    "RecoverFs: address_space.i_pages/page_tree field not found",
                ));
            }
        } else {
            return Err(plugin_error(
                "RecoverFs: address_space type is not a struct",
            ));
        };

    let xarray_template = context.get_type(symbol_table, "xarray")?;
    let xa_head_offset = if let TypeTemplate::Struct(s) = xarray_template.as_ref() {
        s.get_field("xa_head")
            .map(|f| f.offset)
            .ok_or_else(|| plugin_error("RecoverFs: xarray.xa_head field not found"))?
    } else {
        return Err(plugin_error("RecoverFs: xarray type is not a struct"));
    };

    let xa_node_template = context.get_type(symbol_table, "xa_node")?;
    let (xa_shift_offset, xa_shift_size, xa_slots_offset, xa_slots_count) =
        if let TypeTemplate::Struct(s) = xa_node_template.as_ref() {
            let shift = s.get_field("shift");
            let slots = s.get_field("slots");
            let count = slots
                .and_then(|f| match f.template.as_ref() {
                    TypeTemplate::Array(arr) => Some(arr.count),
                    _ => None,
                })
                .unwrap_or(64)
                .max(1);
            (
                shift.map(|f| f.offset).unwrap_or(0),
                shift.and_then(|f| f.template.size()).unwrap_or(4).max(1),
                slots.map(|f| f.offset).unwrap_or(0),
                count,
            )
        } else {
            return Err(plugin_error("RecoverFs: xa_node type is not a struct"));
        };

    let page_template = context.get_type(symbol_table, "page")?;
    let (page_struct_size, page_mapping_offset, page_index_offset, page_index_size) =
        if let TypeTemplate::Struct(s) = page_template.as_ref() {
            let index = s.get_field("index");
            (
                page_template.size().unwrap_or(64).max(1),
                s.get_field("mapping").map(|f| f.offset),
                index.map(|f| f.offset),
                index.and_then(|f| f.template.size()).unwrap_or(8).max(1),
            )
        } else {
            return Err(plugin_error("RecoverFs: page type is not a struct"));
        };

    let super_block_template = context.get_type(symbol_table, "super_block").ok();
    let (super_uuid_offset, super_dev_offset, super_type_offset, super_subtype_offset) =
        if let Some(t) = super_block_template {
            if let TypeTemplate::Struct(s) = t.as_ref() {
                (
                    s.get_field("s_uuid").map(|f| f.offset),
                    s.get_field("s_dev").map(|f| f.offset),
                    s.get_field("s_type").map(|f| f.offset),
                    s.get_field("s_subtype").map(|f| f.offset),
                )
            } else {
                (None, None, None, None)
            }
        } else {
            (None, None, None, None)
        };

    let fstype_name_offset = context
        .get_type(symbol_table, "file_system_type")
        .ok()
        .and_then(|t| {
            if let TypeTemplate::Struct(s) = t.as_ref() {
                s.get_field("name").map(|f| f.offset)
            } else {
                None
            }
        });

    Ok(RecoverFsLayout {
        pointer_size,
        page_size: 4096,
        inode_mapping_offset,
        inode_link_offset,
        address_space_i_pages_offset,
        xa_head_offset,
        xa_shift_offset,
        xa_shift_size,
        xa_slots_offset,
        xa_slots_count,
        page_struct_size,
        page_mapping_offset,
        page_index_offset,
        page_index_size,
        super_uuid_offset,
        super_dev_offset,
        super_type_offset,
        super_subtype_offset,
        fstype_name_offset,
    })
}

fn determine_vmemmap_start(
    context: &Context,
    layer: &dyn DataLayer,
    symbol_table: &str,
    pointer_size: usize,
) -> Vol3Result<u64> {
    let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;

    let has_mem_section = context.get_symbol(symbol_table, "mem_section").is_ok();
    if has_mem_section {
        if let Ok(sym) = context.get_symbol(symbol_table, "vmemmap_base") {
            let addr = sym.address.wrapping_add(aslr_shift);
            return read_pointer_sized(layer, addr, pointer_size);
        }
        return Ok(VMEMMAP_BASE_L4);
    }

    if let Ok(sym) = context.get_symbol(symbol_table, "mem_map") {
        let addr = sym.address.wrapping_add(aslr_shift);
        return read_pointer_sized(layer, addr, pointer_size);
    }

    if context.get_symbol(symbol_table, "node_data").is_ok() {
        return Err(plugin_error(
            "RecoverFs: NUMA systems are not currently supported",
        ));
    }

    Err(plugin_error(
        "RecoverFs: unsupported Linux memory model for page cache recovery",
    ))
}

fn canonicalize_address(addr: u64, pointer_size: usize) -> u64 {
    if pointer_size == 8 {
        let mask = (1u64 << 48) - 1;
        let sign_bit = 1u64 << 47;
        if addr & sign_bit != 0 {
            addr | !mask
        } else {
            addr & mask
        }
    } else {
        addr & 0xFFFF_FFFF
    }
}

fn page_to_paddr(
    page_addr: u64,
    vmemmap_start: u64,
    page_struct_size: usize,
    page_size: usize,
    pointer_size: usize,
) -> Option<u64> {
    if page_struct_size == 0 || page_size == 0 {
        return None;
    }
    let canonical = canonicalize_address(page_addr, pointer_size);
    if canonical < vmemmap_start {
        return None;
    }
    let pfn = (canonical - vmemmap_start) / page_struct_size as u64;
    Some(pfn * page_size as u64)
}

fn ilog2(v: usize) -> usize {
    if v <= 1 {
        return 0;
    }
    usize::BITS as usize - 1 - v.leading_zeros() as usize
}

fn get_cached_page_addrs(
    layer: &dyn DataLayer,
    layout: &RecoverFsLayout,
    mapping_addr: u64,
) -> Vol3Result<Vec<u64>> {
    let root_ptr_addr =
        mapping_addr + layout.address_space_i_pages_offset as u64 + layout.xa_head_offset as u64;
    let mut root = read_pointer_sized(layer, root_ptr_addr, layout.pointer_size)?;
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
        let chunk_shift = ilog2(layout.xa_slots_count);
        let shift = read_unsigned(
            layer,
            root + layout.xa_shift_offset as u64,
            layout.xa_shift_size,
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
            layout,
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
    node_addr: u64,
    height: usize,
    layout: &RecoverFsLayout,
    seen_nodes: &mut HashSet<u64>,
    seen_entries: &mut HashSet<u64>,
    entries: &mut Vec<u64>,
) {
    if node_addr == 0 || !helpers::is_valid_kernel_address(node_addr) {
        return;
    }
    if !seen_nodes.insert(node_addr) {
        return;
    }

    for idx in 0..layout.xa_slots_count {
        let slot_addr =
            node_addr + layout.xa_slots_offset as u64 + (idx * layout.pointer_size) as u64;
        let Ok(slot) = read_pointer_sized(layer, slot_addr, layout.pointer_size) else {
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
            if (child & XARRAY_TAG_MASK) == 0
                && helpers::is_valid_kernel_address(child)
                && seen_entries.insert(child)
            {
                entries.push(child);
            }
            continue;
        }

        walk_xarray_node(
            layer,
            child,
            height - 1,
            layout,
            seen_nodes,
            seen_entries,
            entries,
        );
    }
}

fn unique_path(output_dir: &Path, filename: &str) -> PathBuf {
    let candidate = output_dir.join(filename);
    if !candidate.exists() {
        return candidate;
    }

    // Match Python volatility3 CLIFileHandler._get_final_filename:
    // filename, extension = os.path.splitext(output_filename)
    let stem = Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    for idx in 1.. {
        let name = if ext.is_empty() {
            format!("{stem}-{idx}")
        } else {
            format!("{stem}-{idx}.{ext}")
        };
        let next = output_dir.join(name);
        if !next.exists() {
            return next;
        }
    }

    // Unreachable loop fallback.
    candidate
}

fn write_archive<W: Write>(
    _context: &Context,
    kernel_layer: &dyn DataLayer,
    physical_layer: &dyn DataLayer,
    _symbol_table: &str,
    layout: &RecoverFsLayout,
    vmemmap_start: u64,
    tmpfs_only: bool,
    inodes: &[InodeInfo],
    mtime: u64,
    builder: &mut tar::Builder<W>,
) -> Vol3Result<Vec<Vol3Result<Row>>> {
    let mut rows = Vec::with_capacity(inodes.len());
    let mut visited_paths = HashSet::new();
    let mut seen_prefixes = HashSet::new();
    let mut sb_meta_cache: HashMap<u64, SuperblockMeta> = HashMap::new();

    for inode in inodes {
        if inode.file_type != "REG" && inode.file_type != "DIR" && inode.file_type != "LNK" {
            continue;
        }

        let (source_path, mut symlink_dest) = split_symlink_repr(&inode.file_path);
        if !source_path.starts_with('/') {
            log::debug!(
                "RecoverFs: skipping potentially smeared path without leading slash: {}",
                source_path
            );
            continue;
        }

        let sb_meta = sb_meta_cache
            .entry(inode.superblock_addr)
            .or_insert_with(|| {
                read_superblock_meta(kernel_layer, layout, inode.superblock_addr, &inode.device)
            });

        if tmpfs_only && sb_meta.fs_type.as_deref() != Some("tmpfs") {
            continue;
        }

        let prefix = sb_meta.prefix.clone();
        let prefixed_path = format!("{prefix}{source_path}");

        if !visited_paths.insert(prefixed_path.clone()) {
            continue;
        }

        if seen_prefixes.insert(prefix.clone()) {
            tar_add_dir(builder, &prefix, mtime)?;
        }

        let mut output_path = source_path.clone();
        let recovered_size = match inode.file_type.as_str() {
            "REG" => Some(tar_add_reg_inode(
                kernel_layer,
                physical_layer,
                layout,
                vmemmap_start,
                inode,
                &prefixed_path,
                mtime,
                builder,
            )?),
            "DIR" => {
                if source_path != "/" {
                    tar_add_dir(builder, &prefixed_path, mtime)?;
                }
                None
            }
            "LNK" => {
                if symlink_dest.is_none() {
                    symlink_dest = read_symlink_target(kernel_layer, layout, inode.inode_addr);
                }
                if let Some(dest) = symlink_dest {
                    tar_add_lnk(builder, &source_path, &dest, &prefix, mtime)?;
                    output_path = format_symlink(&source_path, &dest);
                } else {
                    continue;
                }
                None
            }
            _ => None,
        };

        rows.push(Ok(inode_to_row(inode, output_path, recovered_size)));
    }

    Ok(rows)
}

fn read_superblock_meta(
    layer: &dyn DataLayer,
    layout: &RecoverFsLayout,
    sb_addr: u64,
    fallback_device: &str,
) -> SuperblockMeta {
    let fs_type = read_superblock_fs_type(layer, layout, sb_addr);
    let prefix = read_superblock_uuid(layer, layout, sb_addr)
        .map(|uuid| format!("/{uuid}"))
        .or_else(|| read_superblock_device(layer, layout, sb_addr).map(|dev| format!("/{dev}")))
        .unwrap_or_else(|| format!("/{fallback_device}"));

    SuperblockMeta { prefix, fs_type }
}

fn read_superblock_uuid(
    layer: &dyn DataLayer,
    layout: &RecoverFsLayout,
    sb_addr: u64,
) -> Option<String> {
    let offset = layout.super_uuid_offset?;
    let bytes = layer.read(sb_addr + offset as u64, 16, false).ok()?;
    if bytes.len() != 16 {
        return None;
    }

    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

fn read_superblock_device(
    layer: &dyn DataLayer,
    layout: &RecoverFsLayout,
    sb_addr: u64,
) -> Option<String> {
    let offset = layout.super_dev_offset?;
    let dev_t = read_unsigned(layer, sb_addr + offset as u64, 4)? as u32;
    const MINORBITS: u32 = 20;
    let major = dev_t >> MINORBITS;
    let minor = dev_t & ((1 << MINORBITS) - 1);
    Some(format!("{major}:{minor}"))
}

fn read_superblock_fs_type(
    layer: &dyn DataLayer,
    layout: &RecoverFsLayout,
    sb_addr: u64,
) -> Option<String> {
    let super_type_offset = layout.super_type_offset?;
    let fstype_name_offset = layout.fstype_name_offset?;

    let s_type_ptr_raw = read_pointer_sized(
        layer,
        sb_addr + super_type_offset as u64,
        layout.pointer_size,
    )
    .ok()?;
    let s_type_ptr = canonicalize_address(s_type_ptr_raw, layout.pointer_size);
    if s_type_ptr == 0 || !helpers::is_valid_kernel_address(s_type_ptr) {
        return None;
    }

    let name_ptr_raw = read_pointer_sized(
        layer,
        s_type_ptr + fstype_name_offset as u64,
        layout.pointer_size,
    )
    .ok()?;
    let name_ptr = canonicalize_address(name_ptr_raw, layout.pointer_size);
    if name_ptr == 0 || !helpers::is_valid_kernel_address(name_ptr) {
        return None;
    }

    let mut fs_type = read_cstring_lossy(layer, name_ptr, 64)?;
    if fs_type.is_empty() {
        return None;
    }

    if let Some(subtype_offset) = layout.super_subtype_offset {
        if let Ok(subtype_ptr_raw) =
            read_pointer_sized(layer, sb_addr + subtype_offset as u64, layout.pointer_size)
        {
            let subtype_ptr = canonicalize_address(subtype_ptr_raw, layout.pointer_size);
            if subtype_ptr != 0 && helpers::is_valid_kernel_address(subtype_ptr) {
                if let Some(subtype) = read_cstring_lossy(layer, subtype_ptr, 255) {
                    if !subtype.is_empty() {
                        fs_type = format!("{fs_type}.{subtype}");
                    }
                }
            }
        }
    }

    Some(fs_type)
}

fn read_cstring_lossy(layer: &dyn DataLayer, addr: u64, max_len: usize) -> Option<String> {
    let bytes = layer.read(addr, max_len.max(1), false).ok()?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).to_string())
}

fn split_symlink_repr(path: &str) -> (String, Option<String>) {
    if let Some((source, dest)) = path.split_once(" -> ") {
        return (source.to_string(), Some(dest.to_string()));
    }
    (path.to_string(), None)
}

fn format_symlink(source: &str, dest: &str) -> String {
    format!("{source} -> {dest}")
}

fn patch_absolute_symlink(source: &str, dest: &str) -> String {
    if !dest.starts_with('/') {
        return dest.to_string();
    }

    let relative_dest = dest.trim_start_matches('/');
    if relative_dest.is_empty() {
        return ".".to_string();
    }
    let depth = source
        .trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .count()
        .saturating_sub(1);

    if depth == 0 {
        return relative_dest.to_string();
    }

    let mut patched = "../".repeat(depth);
    patched.push_str(relative_dest);
    patched
}

fn normalize_archive_member_path(path: &str) -> Option<String> {
    let mut normalized = path.replace('\\', "/");
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }
    let trailing = normalized.ends_with('/');
    normalized = normalized.trim_start_matches('/').to_string();
    if normalized.is_empty() {
        return None;
    }
    if trailing && !normalized.ends_with('/') {
        normalized.push('/');
    }
    Some(normalized)
}

fn tar_add_dir<W: Write>(
    builder: &mut tar::Builder<W>,
    directory_path: &str,
    mtime: u64,
) -> Vol3Result<()> {
    let Some(member_path) = normalize_archive_member_path(directory_path) else {
        return Ok(());
    };

    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_mode(0o755);
    header.set_mtime(mtime);
    header.set_size(0);
    header.set_cksum();

    builder.append_data(&mut header, member_path, std::io::empty())?;
    Ok(())
}

fn tar_add_lnk<W: Write>(
    builder: &mut tar::Builder<W>,
    symlink_source: &str,
    symlink_dest: &str,
    symlink_source_prefix: &str,
    mtime: u64,
) -> Vol3Result<()> {
    let patched_dest = patch_absolute_symlink(symlink_source, symlink_dest);
    let prefixed_source = format!("{symlink_source_prefix}{symlink_source}");
    let Some(member_path) = normalize_archive_member_path(&prefixed_source) else {
        return Ok(());
    };

    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_mode(0o444);
    header.set_mtime(mtime);
    header.set_size(0);
    header.set_link_name(&patched_dest)?;
    header.set_cksum();

    builder.append_data(&mut header, member_path, std::io::empty())?;
    Ok(())
}

fn tar_add_reg_from_reader<W: Write, R: Read>(
    builder: &mut tar::Builder<W>,
    path: &str,
    reader: &mut R,
    size: u64,
    mtime: u64,
) -> Vol3Result<()> {
    let Some(member_path) = normalize_archive_member_path(path) else {
        return Ok(());
    };

    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o444);
    header.set_mtime(mtime);
    header.set_size(size);
    header.set_cksum();

    builder.append_data(&mut header, member_path, reader)?;
    Ok(())
}

fn tar_add_reg_inode<W: Write>(
    kernel_layer: &dyn DataLayer,
    physical_layer: &dyn DataLayer,
    layout: &RecoverFsLayout,
    vmemmap_start: u64,
    inode: &InodeInfo,
    prefixed_path: &str,
    mtime: u64,
    builder: &mut tar::Builder<W>,
) -> Vol3Result<u64> {
    let mapping_addr_raw = read_pointer_sized(
        kernel_layer,
        inode.inode_addr + layout.inode_mapping_offset as u64,
        layout.pointer_size,
    )
    .unwrap_or(0);
    let mapping_addr = canonicalize_address(mapping_addr_raw, layout.pointer_size);
    if mapping_addr == 0 || !helpers::is_valid_kernel_address(mapping_addr) {
        let mut empty = std::io::empty();
        tar_add_reg_from_reader(builder, prefixed_path, &mut empty, 0, mtime)?;
        return Ok(0);
    }

    let page_addrs = get_cached_page_addrs(kernel_layer, layout, mapping_addr)?;
    let inode_size = inode.inode_size;
    let mut stream_initialized = false;
    let mut tmpfile = tempfile::tempfile()?;

    for page_addr in page_addrs {
        let page_addr = canonicalize_address(page_addr, layout.pointer_size);
        if page_addr == 0 || !helpers::is_valid_kernel_address(page_addr) {
            continue;
        }

        if let Some(mapping_offset) = layout.page_mapping_offset {
            if let Ok(page_mapping_raw) = read_pointer_sized(
                kernel_layer,
                page_addr + mapping_offset as u64,
                layout.pointer_size,
            ) {
                let page_mapping =
                    canonicalize_address(page_mapping_raw & !XARRAY_TAG_MASK, layout.pointer_size);
                if page_mapping != mapping_addr {
                    continue;
                }
            }
        }

        let page_index = if let Some(index_offset) = layout.page_index_offset {
            read_unsigned(
                kernel_layer,
                page_addr + index_offset as u64,
                layout.page_index_size,
            )
            .unwrap_or(0)
        } else {
            0
        };

        let file_offset = page_index.saturating_mul(layout.page_size as u64);
        if file_offset >= inode_size {
            continue;
        }

        let Some(page_paddr) = page_to_paddr(
            page_addr,
            vmemmap_start,
            layout.page_struct_size,
            layout.page_size,
            layout.pointer_size,
        ) else {
            continue;
        };

        let page_content = match physical_layer.read(page_paddr, layout.page_size, false) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        let max_length = inode_size.saturating_sub(file_offset) as usize;
        let page_bytes_len = std::cmp::min(max_length, page_content.len());
        if page_bytes_len == 0 {
            continue;
        }
        if file_offset + page_bytes_len as u64 > inode_size {
            continue;
        }

        if !stream_initialized {
            tmpfile.set_len(inode_size)?;
            stream_initialized = true;
        }

        tmpfile.seek(SeekFrom::Start(file_offset))?;
        tmpfile.write_all(&page_content[..page_bytes_len])?;
    }

    let recovered_size = if stream_initialized { inode_size } else { 0 };
    if !stream_initialized {
        tmpfile.set_len(0)?;
    }
    tmpfile.seek(SeekFrom::Start(0))?;
    tar_add_reg_from_reader(builder, prefixed_path, &mut tmpfile, recovered_size, mtime)?;

    Ok(recovered_size)
}

fn read_symlink_target(
    kernel_layer: &dyn DataLayer,
    layout: &RecoverFsLayout,
    inode_addr: u64,
) -> Option<String> {
    let offset = layout.inode_link_offset?;
    if offset == 0 {
        return None;
    }

    let link_ptr_raw = read_pointer_sized(
        kernel_layer,
        inode_addr + offset as u64,
        layout.pointer_size,
    )
    .ok()?;
    let link_ptr = canonicalize_address(link_ptr_raw, layout.pointer_size);
    if link_ptr == 0 || !helpers::is_valid_kernel_address(link_ptr) {
        return None;
    }

    read_cstring_lossy(kernel_layer, link_ptr, 255)
}

fn to_i64_saturating(value: u64) -> i64 {
    if value > i64::MAX as u64 {
        i64::MAX
    } else {
        value as i64
    }
}

fn inode_to_row(inode: &InodeInfo, file_path: String, recovered_size: Option<u64>) -> Row {
    vec![
        CellValue::Hex(inode.superblock_addr & ADDR_MASK),
        CellValue::String(inode.mountpoint.clone()),
        CellValue::String(inode.device.clone()),
        CellValue::Int(to_i64_saturating(inode.inode_num)),
        CellValue::Hex(inode.inode_addr & ADDR_MASK),
        CellValue::String(inode.file_type.clone()),
        CellValue::Int(to_i64_saturating(inode.inode_pages)),
        CellValue::Int(to_i64_saturating(inode.cached_pages)),
        CellValue::String(inode.file_mode.clone()),
        CellValue::String(inode.access_time.clone().unwrap_or_else(|| "-".to_string())),
        CellValue::String(
            inode
                .modification_time
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ),
        CellValue::String(inode.change_time.clone().unwrap_or_else(|| "-".to_string())),
        CellValue::String(file_path),
        CellValue::Int(to_i64_saturating(inode.inode_size)),
        match recovered_size {
            Some(size) => CellValue::Int(to_i64_saturating(size)),
            None => CellValue::Absent(AbsentValue::NotApplicable),
        },
    ]
}
