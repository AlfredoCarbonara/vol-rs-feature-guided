//! VMware layer - parses .vmem and .vmsn/.vmss files
//!
//! This layer handles VMware memory snapshots, which include:
//! - .vmem files containing the raw memory data
//! - .vmsn/.vmss metadata files describing memory regions

use std::any::Any;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::physical::FileLayer;
use crate::segmented::{Segment, SegmentedLayer};
use crate::traits::DataLayer;
use vol3_core::{LayerResult, Vol3Error, Vol3Result};

/// VMware magic bytes for different versions
const VMWARE_MAGIC_V0: &[u8] = &[0xD0, 0xBE, 0xD2, 0xBE];
const VMWARE_MAGIC_V1: &[u8] = &[0xD1, 0xBA, 0xD1, 0xBA];
const VMWARE_MAGIC_V2: &[u8] = &[0xD2, 0xBE, 0xD2, 0xBE];
const VMWARE_MAGIC_V3: &[u8] = &[0xD3, 0xBE, 0xD3, 0xBE];

const PAGE_SIZE: u64 = 0x1000;

/// Tag data from VMware metadata
#[derive(Debug, Clone)]
pub enum TagValue {
    Int(u32),
    Long(u64),
    Bytes(Vec<u8>),
}

impl TagValue {
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            TagValue::Int(v) => Some(*v),
            TagValue::Long(v) => Some(*v as u32),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            TagValue::Int(v) => Some(*v as u64),
            TagValue::Long(v) => Some(*v),
            _ => None,
        }
    }
}

/// VMware metadata parser
pub struct VmwareMetadata {
    /// Groups in the metadata file
    pub groups: HashMap<String, u64>,
    /// Tags parsed from memory group
    pub tags: HashMap<(String, Vec<u32>), TagValue>,
    /// Tags parsed from the CPU group.
    pub cpu_tags: HashMap<(String, Vec<u32>), TagValue>,
    /// VMware version (0-3)
    pub version: u8,
}

impl VmwareMetadata {
    /// Parse VMware metadata from a file
    pub fn parse(path: &Path) -> Vol3Result<Self> {
        let mut file = File::open(path).map_err(|e| {
            Vol3Error::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to open VMware metadata file: {}", e),
            ))
        })?;

        // Read header: magic (4) + unknown (4) + groupCount (4) = 12 bytes
        let mut header = [0u8; 12];
        file.read_exact(&mut header).map_err(|e| {
            Vol3Error::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read VMware header: {}", e),
            ))
        })?;

        let magic = &header[0..4];
        let version = match magic {
            m if m == VMWARE_MAGIC_V0 => 0,
            m if m == VMWARE_MAGIC_V1 => 1,
            m if m == VMWARE_MAGIC_V2 => 2,
            m if m == VMWARE_MAGIC_V3 => 3,
            _ => {
                return Err(Vol3Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid VMware magic: {:02X?}", magic),
                )));
            }
        };

        let group_count = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);

        // Parse groups: each is 64 bytes name + 8 bytes offset + 8 bytes unknown = 80 bytes
        let mut groups = HashMap::new();
        for _ in 0..group_count {
            let mut group_data = [0u8; 80];
            file.read_exact(&mut group_data).map_err(|e| {
                Vol3Error::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read VMware group: {}", e),
                ))
            })?;

            // Name is null-terminated string in first 64 bytes
            let name_end = group_data[..64].iter().position(|&b| b == 0).unwrap_or(64);
            let name = String::from_utf8_lossy(&group_data[..name_end]).to_string();

            // Tag location is at offset 64-72
            let tag_location = u64::from_le_bytes([
                group_data[64],
                group_data[65],
                group_data[66],
                group_data[67],
                group_data[68],
                group_data[69],
                group_data[70],
                group_data[71],
            ]);

            groups.insert(name, tag_location);
        }

        // Find memory group
        let memory_offset = groups.get("memory").copied().ok_or_else(|| {
            Vol3Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No 'memory' group found in VMware metadata",
            ))
        })?;

        // Parse only the groups needed for memory mapping and automagic. Some
        // device groups contain very large opaque blobs and should stay lazy.
        let tags = Self::parse_tags(&mut file, memory_offset, version)?;
        let cpu_tags = if let Some(cpu_offset) = groups.get("cpu").copied() {
            Self::parse_tags(&mut file, cpu_offset, version)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            groups,
            tags,
            cpu_tags,
            version,
        })
    }

    fn parse_tags(
        file: &mut File,
        offset: u64,
        version: u8,
    ) -> Vol3Result<HashMap<(String, Vec<u32>), TagValue>> {
        file.seek(SeekFrom::Start(offset)).map_err(|e| {
            Vol3Error::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to seek to VMware tags: {}", e),
            ))
        })?;

        let mut tags = HashMap::new();

        loop {
            // Read flags and name_len
            let mut header = [0u8; 2];
            if file.read_exact(&mut header).is_err() {
                break;
            }

            let flags = header[0];
            let name_len = header[1] as usize;

            // End of tags marker
            if flags == 0 && name_len == 0 {
                break;
            }

            // Read name
            let mut name_bytes = vec![0u8; name_len];
            if let Err(e) = file.read_exact(&mut name_bytes) {
                log::warn!("Failed to read tag name: {}", e);
                break;
            }
            let name = String::from_utf8_lossy(&name_bytes).to_string();

            // Parse indices
            let indices_count = ((flags >> 6) & 3) as usize;
            let mut indices = Vec::with_capacity(indices_count);
            for _ in 0..indices_count {
                let mut idx_bytes = [0u8; 4];
                if let Err(e) = file.read_exact(&mut idx_bytes) {
                    log::warn!("Failed to read tag index: {}", e);
                    break;
                }
                indices.push(u32::from_le_bytes(idx_bytes));
            }

            // Parse data
            let data_len = (flags & 0x3F) as usize;
            let value = if data_len == 62 || data_len == 63 {
                // Variable length data
                let size_len = if version == 0 { 4 } else { 8 };
                let mut size_bytes = vec![0u8; size_len];
                if let Err(e) = file.read_exact(&mut size_bytes) {
                    log::warn!("Failed to read data size: {}", e);
                    break;
                }

                let data_size = if size_len == 4 {
                    u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]])
                        as usize
                } else {
                    u64::from_le_bytes([
                        size_bytes[0],
                        size_bytes[1],
                        size_bytes[2],
                        size_bytes[3],
                        size_bytes[4],
                        size_bytes[5],
                        size_bytes[6],
                        size_bytes[7],
                    ]) as usize
                };

                // VMware stores a repeated size followed by two reserved
                // bytes. The first size has already been consumed above.
                let skip = size_len + 2;
                if let Err(e) = file.seek(SeekFrom::Current(skip as i64)) {
                    log::warn!("Failed to skip padding: {}", e);
                    break;
                }

                // Read actual data
                let mut data = vec![0u8; data_size];
                if let Err(e) = file.read_exact(&mut data) {
                    log::warn!("Failed to read tag data: {}", e);
                    break;
                }

                TagValue::Bytes(data)
            } else if data_len <= 4 {
                let mut data = [0u8; 4];
                if data_len > 0 {
                    if let Err(e) = file.read_exact(&mut data[..data_len]) {
                        log::warn!("Failed to read tag int: {}", e);
                        break;
                    }
                }
                TagValue::Int(u32::from_le_bytes(data))
            } else if data_len <= 8 {
                let mut data = [0u8; 8];
                if let Err(e) = file.read_exact(&mut data[..data_len]) {
                    log::warn!("Failed to read tag long: {}", e);
                    break;
                }
                TagValue::Long(u64::from_le_bytes(data))
            } else {
                let mut data = vec![0u8; data_len];
                if let Err(e) = file.read_exact(&mut data) {
                    log::warn!("Failed to read tag bytes: {}", e);
                    break;
                }
                TagValue::Bytes(data)
            };

            tags.insert((name, indices), value);
        }

        Ok(tags)
    }

    /// Get a tag value
    pub fn get_tag(&self, name: &str, indices: &[u32]) -> Option<&TagValue> {
        self.tags.get(&(name.to_string(), indices.to_vec()))
    }

    /// Get a tag from the CPU metadata group.
    pub fn get_cpu_tag(&self, name: &str, indices: &[u32]) -> Option<&TagValue> {
        self.cpu_tags.get(&(name.to_string(), indices.to_vec()))
    }

    /// Decode all VMware x64 CPU states that contain CR64 and IDTR tags.
    pub fn cpu_states(&self) -> Vec<VmwareCpuState> {
        let mut cpu_indices: Vec<u32> = self
            .cpu_tags
            .keys()
            .filter_map(|(name, indices)| {
                (name == "CR64" && indices.len() == 1).then(|| indices[0])
            })
            .collect();
        cpu_indices.sort_unstable();
        cpu_indices.dedup();
        cpu_indices
            .into_iter()
            .filter_map(|cpu_index| {
                let TagValue::Bytes(cr64) = self.get_cpu_tag("CR64", &[cpu_index])? else {
                    return None;
                };
                let TagValue::Bytes(idtr) = self.get_cpu_tag("IDTR", &[cpu_index])? else {
                    return None;
                };
                if cr64.len() < 5 * 8 || idtr.len() < 10 {
                    return None;
                }
                let cr3 = u64::from_le_bytes(cr64[3 * 8..4 * 8].try_into().ok()?) & !0xfff;
                let idtr_limit = u16::from_le_bytes(idtr[0..2].try_into().ok()?);
                let idtr_base = u64::from_le_bytes(idtr[2..10].try_into().ok()?);
                (cr3 != 0 && idtr_base >= 0xffff_8000_0000_0000).then_some(VmwareCpuState {
                    cpu_index,
                    cr3,
                    idtr_base,
                    idtr_limit,
                })
            })
            .collect()
    }

    /// Get regions count
    pub fn regions_count(&self) -> Option<u32> {
        self.get_tag("regionsCount", &[])?.as_u32()
    }

    /// Get region PPN (guest physical page number)
    pub fn region_ppn(&self, region: u32) -> Option<u64> {
        self.get_tag("regionPPN", &[region])?.as_u64()
    }

    /// Get region page number (page number in the vmem file)
    pub fn region_page_num(&self, region: u32) -> Option<u64> {
        self.get_tag("regionPageNum", &[region])?.as_u64()
    }

    /// Get region size in pages
    pub fn region_size(&self, region: u32) -> Option<u64> {
        self.get_tag("regionSize", &[region])?.as_u64()
    }
}

/// Register state required by Windows automagic from one VMware vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmwareCpuState {
    pub cpu_index: u32,
    pub cr3: u64,
    pub idtr_base: u64,
    pub idtr_limit: u16,
}

/// VMware layer that combines .vmem with .vmsn/.vmss metadata
pub struct VmwareLayer {
    name: String,
    inner: SegmentedLayer,
    metadata_path: PathBuf,
    vmem_path: PathBuf,
}

impl VmwareLayer {
    /// Return the sidecar snapshot metadata path for a `.vmem` file.
    pub fn metadata_for_vmem(vmem_path: &Path) -> Option<PathBuf> {
        let stem = vmem_path.file_stem()?.to_str()?;
        let parent = vmem_path.parent().unwrap_or(Path::new("."));
        let vmsn = parent.join(format!("{stem}.vmsn"));
        let vmss = parent.join(format!("{stem}.vmss"));
        vmsn.is_file()
            .then_some(vmsn)
            .or_else(|| vmss.is_file().then_some(vmss))
    }

    /// Create a new VMware layer from a .vmem file
    /// Automatically looks for .vmsn or .vmss metadata file
    pub fn from_vmem(vmem_path: impl AsRef<Path>) -> Vol3Result<Self> {
        let vmem_path = vmem_path.as_ref().to_path_buf();

        // Look for metadata file (.vmsn or .vmss)
        let metadata_path = Self::metadata_for_vmem(&vmem_path).ok_or_else(|| {
            Vol3Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "No VMware .vmsn/.vmss metadata found for {}",
                    vmem_path.display()
                ),
            ))
        })?;

        Self::from_files(&vmem_path, &metadata_path)
    }

    /// Create VMware layer from explicit vmem and metadata paths
    pub fn from_files(vmem_path: &Path, metadata_path: &Path) -> Vol3Result<Self> {
        let base_layer = Arc::new(FileLayer::new("vmware_base", vmem_path)?);
        Self::from_files_with_base(vmem_path, metadata_path, base_layer)
    }

    /// Create a VMware layer over an already-opened `.vmem` data layer.
    ///
    /// This lets sequential scanners use `StreamingFileLayer` instead of
    /// silently opening a second mmap-backed copy of the same multi-gigabyte
    /// image.  Random-access plugins may continue to pass a `FileLayer`.
    pub fn from_files_with_base(
        vmem_path: &Path,
        metadata_path: &Path,
        base_layer: Arc<dyn DataLayer>,
    ) -> Vol3Result<Self> {
        // Parse metadata
        let metadata = VmwareMetadata::parse(metadata_path)?;

        // Build segments from metadata
        let regions_count = metadata.regions_count().ok_or_else(|| {
            Vol3Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No regionsCount in VMware metadata",
            ))
        })?;

        log::debug!(
            "VMware layer: {} regions from {}",
            regions_count,
            metadata_path.display()
        );

        let mut segmented = SegmentedLayer::new("vmware_segments", base_layer);

        for region in 0..regions_count {
            let ppn = metadata.region_ppn(region).ok_or_else(|| {
                Vol3Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Missing regionPPN for region {}", region),
                ))
            })?;

            let page_num = metadata.region_page_num(region).ok_or_else(|| {
                Vol3Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Missing regionPageNum for region {}", region),
                ))
            })?;

            let size = metadata.region_size(region).ok_or_else(|| {
                Vol3Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Missing regionSize for region {}", region),
                ))
            })?;

            // regionPPN is the guest physical page number (logical offset in this layer)
            // regionPageNum is the page number within the vmem file (offset in base layer)
            let guest_phys = ppn * PAGE_SIZE;
            let file_offset = page_num * PAGE_SIZE;
            let length = size * PAGE_SIZE;

            log::debug!(
                "VMware region {}: guest_phys={:#x}, file_offset={:#x}, length={:#x}",
                region,
                guest_phys,
                file_offset,
                length
            );

            segmented.add_segment(Segment::new(guest_phys, file_offset, length));
        }

        let name = vmem_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("VmwareLayer")
            .to_string();

        log::info!(
            "VMware layer created: {}, max_addr={:#x}",
            name,
            segmented.maximum_address()
        );

        Ok(Self {
            name,
            inner: segmented,
            metadata_path: metadata_path.to_path_buf(),
            vmem_path: vmem_path.to_path_buf(),
        })
    }

    /// Get the metadata file path
    pub fn metadata_path(&self) -> &Path {
        &self.metadata_path
    }

    /// Get the vmem file path
    pub fn vmem_path(&self) -> &Path {
        &self.vmem_path
    }

    /// Try to detect if a file is a VMware vmem file
    pub fn is_vmware_vmem(path: &Path) -> bool {
        path.extension().and_then(|ext| ext.to_str()) == Some("vmem")
            && Self::metadata_for_vmem(path).is_some()
    }
}

impl std::fmt::Debug for VmwareLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmwareLayer")
            .field("name", &self.name)
            .field("vmem", &self.vmem_path)
            .field("metadata", &self.metadata_path)
            .finish()
    }
}

impl DataLayer for VmwareLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> u64 {
        self.inner.minimum_address()
    }

    fn maximum_address(&self) -> u64 {
        self.inner.maximum_address()
    }

    fn is_valid(&self, offset: u64, length: usize) -> bool {
        self.inner.is_valid(offset, length)
    }

    fn read(&self, offset: u64, length: usize, pad: bool) -> LayerResult<Vec<u8>> {
        self.inner.read(offset, length, pad)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_vmware_v2_variable_length_tag() {
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        let data = vec![0x5a; 72];
        temp.write_all(&[0x7f, 4]).unwrap(); // one index, variable-length value
        temp.write_all(b"CR64").unwrap();
        temp.write_all(&0u32.to_le_bytes()).unwrap();
        temp.write_all(&(data.len() as u64).to_le_bytes()).unwrap();
        temp.write_all(&(data.len() as u64).to_le_bytes()).unwrap();
        temp.write_all(&[0, 0]).unwrap();
        temp.write_all(&data).unwrap();
        temp.write_all(&[0, 0]).unwrap();
        temp.flush().unwrap();
        let mut file = File::open(temp.path()).unwrap();
        let tags = VmwareMetadata::parse_tags(&mut file, 0, 2).unwrap();
        assert!(matches!(
            tags.get(&("CR64".to_string(), vec![0])),
            Some(TagValue::Bytes(value)) if value == &data
        ));
    }

    #[test]
    fn decodes_vmware_cpu_state() {
        let mut cr64 = vec![0u8; 72];
        cr64[24..32].copy_from_slice(&0x1ad002u64.to_le_bytes());
        let mut idtr = vec![0u8; 10];
        idtr[0..2].copy_from_slice(&0x0fffu16.to_le_bytes());
        idtr[2..10].copy_from_slice(&0xfffff80722268000u64.to_le_bytes());
        let metadata = VmwareMetadata {
            groups: HashMap::new(),
            tags: HashMap::new(),
            cpu_tags: [
                (("CR64".to_string(), vec![0]), TagValue::Bytes(cr64)),
                (("IDTR".to_string(), vec![0]), TagValue::Bytes(idtr)),
            ]
            .into_iter()
            .collect(),
            version: 2,
        };
        assert_eq!(
            metadata.cpu_states(),
            vec![VmwareCpuState {
                cpu_index: 0,
                cr3: 0x1ad000,
                idtr_base: 0xfffff80722268000,
                idtr_limit: 0x0fff,
            }]
        );
    }
}
