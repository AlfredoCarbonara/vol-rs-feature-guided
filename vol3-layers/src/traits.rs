//! Layer trait definitions.
//!
//! This module defines the core traits for memory layers, mirroring the
//! Python interfaces in `volatility3.framework.interfaces.layers`.

use std::any::Any;
use std::sync::Arc;
use vol3_core::{Address, LayerError, LayerResult, ProgressCallback};

/// A mapped region from a translation layer.
///
/// Represents a contiguous virtual-to-physical mapping.
#[derive(Debug, Clone)]
pub struct MappedRegion {
    /// The virtual/translated address
    pub mapped_offset: Address,
    /// The size of the mapped region
    pub mapped_length: usize,
    /// The physical/underlying address
    pub layer_offset: Address,
    /// The size available at the layer offset
    pub layer_length: usize,
    /// The name of the layer containing the physical data
    pub layer_name: String,
}

/// Scanner output type
pub type ScanOutput = (Address, Vec<u8>);

/// Interface for layer scanners.
///
/// Scanners search through layer data and return locations of particular values.
/// They are designed to be given a chunk of data and return an iterator of found items.
pub trait ScannerInterface: Send + Sync {
    /// The chunk size to use when scanning
    fn chunk_size(&self) -> usize {
        vol3_core::constants::DEFAULT_SCAN_CHUNK_SIZE
    }

    /// The overlap between chunks (to handle patterns spanning chunk boundaries)
    fn overlap(&self) -> usize {
        vol3_core::constants::DEFAULT_SCAN_OVERLAP
    }

    /// Whether this scanner is thread-safe and can run in parallel
    fn thread_safe(&self) -> bool {
        false
    }

    /// Scan a chunk of data and return matches
    ///
    /// # Arguments
    /// * `data` - The data chunk to scan
    /// * `data_offset` - The offset within the layer where this data starts
    ///
    /// # Returns
    /// An iterator of (offset, matched_data) tuples
    fn scan(&self, data: &[u8], data_offset: Address) -> Vec<ScanOutput>;
}

/// Base trait for all data layers.
///
/// A layer that directly holds data and does not translate it.
/// This is effectively a leaf node in a layer tree.
pub trait DataLayer: Send + Sync {
    /// Returns the unique name of this layer
    fn name(&self) -> &str;

    /// Returns the minimum valid address in this layer
    fn minimum_address(&self) -> Address;

    /// Returns the maximum valid address in this layer
    fn maximum_address(&self) -> Address;

    /// Returns a mask for all active address bits
    fn address_mask(&self) -> Address {
        let max = self.maximum_address();
        if max == 0 {
            return 0;
        }
        let bits = 64 - max.leading_zeros();
        (1u64 << bits) - 1
    }

    /// Check if a range of addresses is valid
    fn is_valid(&self, offset: Address, length: usize) -> bool;

    /// Read data from the layer
    ///
    /// # Arguments
    /// * `offset` - The address to start reading from
    /// * `length` - The number of bytes to read
    /// * `pad` - If true, invalid regions are padded with zeros instead of erroring
    ///
    /// # Returns
    /// The read bytes, or an error if the read failed
    fn read(&self, offset: Address, length: usize, pad: bool) -> LayerResult<Vec<u8>>;

    /// Write data to the layer (if supported)
    fn write(&self, _offset: Address, _data: &[u8]) -> LayerResult<()> {
        Err(LayerError::NotWritable(self.name().to_string()))
    }

    /// Returns the names of layers this layer depends on
    fn dependencies(&self) -> Vec<String> {
        vec![]
    }

    /// Scan the layer for patterns
    fn scan(
        &self,
        scanner: &dyn ScannerInterface,
        sections: Option<Vec<(Address, usize)>>,
        progress: Option<ProgressCallback>,
    ) -> Vec<ScanOutput> {
        let sections = sections.unwrap_or_else(|| {
            vec![(
                self.minimum_address(),
                (self.maximum_address() - self.minimum_address() + 1) as usize,
            )]
        });

        let chunk_size = scanner.chunk_size();
        let overlap = scanner.overlap();
        let mut results = Vec::new();
        let mut total_scanned = 0usize;
        let total_size: usize = sections.iter().map(|(_, len)| *len).sum();

        for (section_start, section_length) in sections {
            let mut offset = section_start;
            let section_end = section_start + section_length as u64;

            while offset < section_end {
                let remaining = (section_end - offset) as usize;
                let read_size = std::cmp::min(chunk_size + overlap, remaining);

                if let Ok(data) = self.read(offset, read_size, true) {
                    let matches = scanner.scan(&data, offset);
                    results.extend(matches);
                }

                // Move forward by chunk_size (not chunk_size + overlap)
                offset += chunk_size as u64;
                total_scanned += std::cmp::min(chunk_size, remaining);

                if let Some(ref cb) = progress {
                    let pct = total_scanned as f64 / total_size as f64;
                    cb(pct, None);
                }
            }
        }

        results
    }

    /// Get metadata about this layer
    fn metadata(&self) -> LayerMetadata {
        LayerMetadata::default()
    }

    /// Convert to Any for downcasting
    fn as_any(&self) -> &dyn Any;
}

/// Translation layer trait for layers that map addresses.
///
/// Extends DataLayer with address translation capabilities.
pub trait TranslationLayer: DataLayer {
    /// Get the mapping for a virtual address range
    ///
    /// # Arguments
    /// * `offset` - The virtual address to translate
    /// * `length` - The number of bytes to map
    /// * `ignore_errors` - If true, skip invalid regions instead of erroring
    ///
    /// # Returns
    /// A list of mapped regions
    fn mapping(
        &self,
        offset: Address,
        length: usize,
        ignore_errors: bool,
    ) -> LayerResult<Vec<MappedRegion>>;

    /// Translate a single address
    ///
    /// # Returns
    /// A tuple of (physical_offset, layer_name)
    fn translate(&self, offset: Address) -> LayerResult<(Address, String)> {
        let regions = self.mapping(offset, 1, false)?;
        if let Some(region) = regions.first() {
            Ok((region.layer_offset, region.layer_name.clone()))
        } else {
            Err(LayerError::InvalidAddress {
                layer_name: self.name().to_string(),
                address: offset,
            })
        }
    }
}

/// Metadata about a layer
#[derive(Debug, Clone, Default)]
pub struct LayerMetadata {
    /// The operating system (e.g., "Linux", "Windows")
    pub os: Option<String>,
    /// The architecture (e.g., "Intel64", "Intel32")
    pub architecture: Option<String>,
    /// Additional metadata
    pub extra: std::collections::HashMap<String, String>,
}

/// Type alias for boxed layers
pub type BoxedLayer = Box<dyn DataLayer>;

/// Type alias for Arc-wrapped layers (for sharing)
pub type SharedLayer = Arc<dyn DataLayer>;

#[cfg(test)]
mod tests {
    use super::*;

    struct MockLayer {
        data: Vec<u8>,
    }

    impl DataLayer for MockLayer {
        fn name(&self) -> &str {
            "mock"
        }

        fn minimum_address(&self) -> Address {
            0
        }

        fn maximum_address(&self) -> Address {
            self.data.len() as Address - 1
        }

        fn is_valid(&self, offset: Address, length: usize) -> bool {
            offset as usize + length <= self.data.len()
        }

        fn read(&self, offset: Address, length: usize, pad: bool) -> LayerResult<Vec<u8>> {
            let start = offset as usize;
            let end = start + length;

            if end <= self.data.len() {
                Ok(self.data[start..end].to_vec())
            } else if pad {
                let mut result = vec![0u8; length];
                let valid_len = self.data.len().saturating_sub(start);
                if valid_len > 0 && start < self.data.len() {
                    result[..valid_len].copy_from_slice(&self.data[start..]);
                }
                Ok(result)
            } else {
                Err(LayerError::InvalidAddress {
                    layer_name: "mock".to_string(),
                    address: offset,
                })
            }
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_mock_layer_read() {
        let layer = MockLayer {
            data: vec![1, 2, 3, 4, 5],
        };

        assert_eq!(layer.read(0, 3, false).unwrap(), vec![1, 2, 3]);
        assert_eq!(layer.read(2, 3, false).unwrap(), vec![3, 4, 5]);
    }

    #[test]
    fn test_mock_layer_pad() {
        let layer = MockLayer {
            data: vec![1, 2, 3],
        };

        let result = layer.read(1, 5, true).unwrap();
        assert_eq!(result, vec![2, 3, 0, 0, 0]);
    }

    #[test]
    fn test_address_mask() {
        let layer = MockLayer {
            data: vec![0; 0x10000], // 64KB
        };
        assert_eq!(layer.address_mask(), 0xFFFF);
    }
}
