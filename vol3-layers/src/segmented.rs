//! Segmented layer - base for layers with non-contiguous memory regions
//!
//! This provides the foundation for VMware, LiME, ELF, and other layers
//! that have memory organized in segments/regions.

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::traits::DataLayer;
use vol3_core::{LayerError, LayerResult};

/// A memory segment: maps virtual range to physical offset
#[derive(Debug, Clone)]
pub struct Segment {
    /// Start offset in the virtual/logical address space (guest physical)
    pub virtual_start: u64,
    /// Start offset in the underlying physical layer (file offset)
    pub physical_start: u64,
    /// Length of this segment
    pub length: u64,
}

impl Segment {
    pub fn new(virtual_start: u64, physical_start: u64, length: u64) -> Self {
        Self {
            virtual_start,
            physical_start,
            length,
        }
    }

    /// Check if an address falls within this segment
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.virtual_start && addr < self.virtual_start + self.length
    }

    /// Translate virtual address to physical offset
    pub fn translate(&self, virtual_addr: u64) -> Option<u64> {
        if self.contains(virtual_addr) {
            Some(self.physical_start + (virtual_addr - self.virtual_start))
        } else {
            None
        }
    }
}

/// Segmented layer that maps non-contiguous memory regions
pub struct SegmentedLayer {
    name: String,
    /// Segments indexed by virtual start address for binary search
    segments: BTreeMap<u64, Segment>,
    /// Underlying data layer
    base_layer: Arc<dyn DataLayer>,
    /// Total virtual address space size
    address_space_size: u64,
}

impl SegmentedLayer {
    pub fn new(name: impl Into<String>, base_layer: Arc<dyn DataLayer>) -> Self {
        Self {
            name: name.into(),
            segments: BTreeMap::new(),
            base_layer,
            address_space_size: 0,
        }
    }

    /// Add a segment to the layer
    pub fn add_segment(&mut self, segment: Segment) {
        let end = segment.virtual_start + segment.length;
        if end > self.address_space_size {
            self.address_space_size = end;
        }
        self.segments.insert(segment.virtual_start, segment);
    }

    /// Find segment containing the given address
    fn find_segment(&self, addr: u64) -> Option<&Segment> {
        // Find the segment with the largest start address <= addr
        self.segments
            .range(..=addr)
            .next_back()
            .map(|(_, seg)| seg)
            .filter(|seg| seg.contains(addr))
    }

    /// Translate guest physical address to file offset
    pub fn translate(&self, addr: u64) -> Option<u64> {
        self.find_segment(addr).and_then(|seg| seg.translate(addr))
    }

    /// Check if address is mapped
    pub fn is_mapped(&self, addr: u64) -> bool {
        self.find_segment(addr).is_some()
    }
}

impl std::fmt::Debug for SegmentedLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentedLayer")
            .field("name", &self.name)
            .field("segments", &self.segments.len())
            .field(
                "address_space_size",
                &format_args!("{:#x}", self.address_space_size),
            )
            .finish()
    }
}

impl DataLayer for SegmentedLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> u64 {
        self.segments.keys().next().copied().unwrap_or(0)
    }

    fn maximum_address(&self) -> u64 {
        self.address_space_size.saturating_sub(1)
    }

    fn is_valid(&self, offset: u64, length: usize) -> bool {
        // Check if entire range is within a single segment
        if let Some(seg) = self.find_segment(offset) {
            let end = offset + length as u64;
            end <= seg.virtual_start + seg.length
        } else {
            false
        }
    }

    fn read(&self, offset: u64, length: usize, pad: bool) -> LayerResult<Vec<u8>> {
        let mut result = Vec::with_capacity(length);
        let mut current_offset = offset;
        let end_offset = offset + length as u64;

        while current_offset < end_offset {
            let remaining = (end_offset - current_offset) as usize;

            if let Some(segment) = self.find_segment(current_offset) {
                // Calculate how much we can read from this segment
                let segment_remaining =
                    (segment.virtual_start + segment.length - current_offset) as usize;
                let to_read = remaining.min(segment_remaining);

                // Translate and read from base layer
                let physical_offset = segment.translate(current_offset).unwrap();
                let data = self.base_layer.read(physical_offset, to_read, pad)?;
                result.extend_from_slice(&data);
                current_offset += to_read as u64;
            } else if pad {
                // Find next segment or end
                let next_segment_start = self
                    .segments
                    .range(current_offset..)
                    .next()
                    .map(|(start, _)| *start)
                    .unwrap_or(end_offset);

                let pad_len =
                    ((next_segment_start.min(end_offset) - current_offset) as usize).min(remaining);
                result.extend(std::iter::repeat(0u8).take(pad_len));
                current_offset += pad_len as u64;
            } else {
                return Err(LayerError::InvalidAddress {
                    layer_name: self.name.clone(),
                    address: current_offset,
                });
            }
        }

        Ok(result)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
