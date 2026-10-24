//! ELF64 core-dump physical-memory layer.
//!
//! Hypervisor acquisition tools can store guest physical memory as PT_LOAD
//! segments in an ELF core file.  The filename may still use `.vmem`, so the
//! file signature and program headers, rather than the extension, determine
//! whether this layer is required.

use std::any::Any;
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};
use vol3_core::{LayerError, LayerResult};

use crate::segmented::{Segment, SegmentedLayer};
use crate::traits::{DataLayer, LayerMetadata};

const ELF_HEADER_SIZE: usize = 64;
const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ET_CORE: u16 = 4;
const PT_LOAD: u32 = 1;

/// Maps ELF64 `PT_LOAD` physical-address ranges onto their file offsets.
pub struct Elf64Layer {
    inner: SegmentedLayer,
    segment_count: usize,
}

impl Elf64Layer {
    /// Returns true when the layer begins with a little-endian ELF64 core header.
    pub fn is_elf64_core(base: &dyn DataLayer) -> bool {
        let Ok(header) = base.read(0, ELF_HEADER_SIZE, false) else {
            return false;
        };
        header.starts_with(b"\x7fELF")
            && header[4] == 2
            && header[5] == 1
            && LittleEndian::read_u16(&header[16..18]) == ET_CORE
    }

    /// Parses an ELF64 core file already exposed by an underlying data layer.
    pub fn from_base(name: impl Into<String>, base: Arc<dyn DataLayer>) -> LayerResult<Self> {
        let name = name.into();
        let header = base.read(0, ELF_HEADER_SIZE, false)?;
        if !Self::is_elf64_core(base.as_ref()) {
            return Err(LayerError::InvalidFormat(
                "expected a little-endian ELF64 core file".to_string(),
            ));
        }

        let program_offset = LittleEndian::read_u64(&header[32..40]);
        let program_entry_size = LittleEndian::read_u16(&header[54..56]) as usize;
        let program_count = LittleEndian::read_u16(&header[56..58]) as usize;
        if program_entry_size < ELF64_PROGRAM_HEADER_SIZE || program_count == 0 {
            return Err(LayerError::InvalidFormat(format!(
                "invalid ELF64 program-header table: entry_size={program_entry_size}, count={program_count}"
            )));
        }

        let table_size = program_entry_size
            .checked_mul(program_count)
            .ok_or_else(|| {
                LayerError::InvalidFormat("ELF64 program-header size overflow".to_string())
            })?;
        let table = base.read(program_offset, table_size, false)?;
        let mut inner = SegmentedLayer::new(name, base.clone());
        let base_size = base.maximum_address().saturating_add(1);
        let mut segment_count = 0;

        for index in 0..program_count {
            let start = index * program_entry_size;
            let entry = &table[start..start + ELF64_PROGRAM_HEADER_SIZE];
            if LittleEndian::read_u32(&entry[0..4]) != PT_LOAD {
                continue;
            }

            let file_offset = LittleEndian::read_u64(&entry[8..16]);
            let physical_address = LittleEndian::read_u64(&entry[24..32]);
            let file_size = LittleEndian::read_u64(&entry[32..40]);
            let memory_size = LittleEndian::read_u64(&entry[40..48]);
            let length = file_size.min(memory_size);
            if length == 0 {
                continue;
            }
            let file_end = file_offset.checked_add(length).ok_or_else(|| {
                LayerError::InvalidFormat(format!("ELF64 PT_LOAD {index} file range overflow"))
            })?;
            if file_end > base_size {
                return Err(LayerError::InvalidFormat(format!(
                    "ELF64 PT_LOAD {index} extends beyond the source file"
                )));
            }
            physical_address.checked_add(length).ok_or_else(|| {
                LayerError::InvalidFormat(format!("ELF64 PT_LOAD {index} address overflow"))
            })?;

            inner.add_segment(Segment::new(physical_address, file_offset, length));
            segment_count += 1;
        }

        if segment_count == 0 {
            return Err(LayerError::InvalidFormat(
                "ELF64 core file contains no non-empty PT_LOAD segments".to_string(),
            ));
        }
        Ok(Self {
            inner,
            segment_count,
        })
    }

    pub fn segment_count(&self) -> usize {
        self.segment_count
    }
}

impl std::fmt::Debug for Elf64Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Elf64Layer")
            .field("segments", &self.segment_count)
            .field("inner", &self.inner)
            .finish()
    }
}

impl DataLayer for Elf64Layer {
    fn name(&self) -> &str {
        self.inner.name()
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

    fn dependencies(&self) -> Vec<String> {
        self.inner.dependencies()
    }

    fn metadata(&self) -> LayerMetadata {
        self.inner.metadata()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::physical::BufferLayer;

    fn sample_core() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x104];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        LittleEndian::write_u16(&mut bytes[16..18], ET_CORE);
        LittleEndian::write_u64(&mut bytes[32..40], 64);
        LittleEndian::write_u16(&mut bytes[54..56], ELF64_PROGRAM_HEADER_SIZE as u16);
        LittleEndian::write_u16(&mut bytes[56..58], 1);
        LittleEndian::write_u32(&mut bytes[64..68], PT_LOAD);
        LittleEndian::write_u64(&mut bytes[72..80], 0x100);
        LittleEndian::write_u64(&mut bytes[88..96], 0x2000);
        LittleEndian::write_u64(&mut bytes[96..104], 4);
        LittleEndian::write_u64(&mut bytes[104..112], 4);
        bytes[0x100..0x104].copy_from_slice(&[1, 2, 3, 4]);
        bytes
    }

    #[test]
    fn maps_pt_load_by_physical_address() {
        let base = Arc::new(BufferLayer::new("file", sample_core()));
        assert!(Elf64Layer::is_elf64_core(base.as_ref()));
        let layer = Elf64Layer::from_base("elf", base).unwrap();
        assert_eq!(layer.segment_count(), 1);
        assert_eq!(layer.read(0x2000, 4, false).unwrap(), [1, 2, 3, 4]);
        assert!(!layer.is_valid(0, 1));
    }
}
