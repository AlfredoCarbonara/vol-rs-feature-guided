//! Physical layer implementations.
//!
//! This module provides layers that directly access physical data sources:
//! - `FileLayer` - Memory-mapped file access
//! - `BufferLayer` - In-memory buffer access

use std::any::Any;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use memmap2::Mmap;
use vol3_core::{Address, LayerError, LayerResult};

use crate::traits::{DataLayer, LayerMetadata};

/// A layer backed by a memory-mapped file.
///
/// This provides efficient read access to large memory dump files.
pub struct FileLayer {
    name: String,
    path: PathBuf,
    mmap: Mmap,
    size: u64,
}

impl FileLayer {
    /// Create a new FileLayer from a file path
    pub fn new(name: impl Into<String>, path: impl AsRef<Path>) -> LayerResult<Self> {
        let name = name.into();
        let path = path.as_ref().to_path_buf();

        let file = File::open(&path).map_err(|e| LayerError::IoError {
            layer_name: name.clone(),
            message: e.to_string(),
        })?;

        // Safety: We're mapping a read-only file
        let mmap = unsafe {
            Mmap::map(&file).map_err(|e| LayerError::IoError {
                layer_name: name.clone(),
                message: e.to_string(),
            })?
        };

        let size = mmap.len() as u64;

        Ok(Self {
            name,
            path,
            mmap,
            size,
        })
    }

    /// Get the file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get direct access to the memory-mapped data
    pub fn data(&self) -> &[u8] {
        &self.mmap
    }
}

impl DataLayer for FileLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> Address {
        0
    }

    fn maximum_address(&self) -> Address {
        if self.size == 0 {
            0
        } else {
            self.size - 1
        }
    }

    fn is_valid(&self, offset: Address, length: usize) -> bool {
        offset
            .checked_add(length as u64)
            .map(|end| end <= self.size)
            .unwrap_or(false)
    }

    fn read(&self, offset: Address, length: usize, pad: bool) -> LayerResult<Vec<u8>> {
        let start = offset as usize;

        if start >= self.mmap.len() {
            if pad {
                return Ok(vec![0u8; length]);
            } else {
                return Err(LayerError::InvalidAddress {
                    layer_name: self.name.clone(),
                    address: offset,
                });
            }
        }

        let end = start.saturating_add(length);
        let available = self.mmap.len() - start;

        if end <= self.mmap.len() {
            // Full read is possible
            Ok(self.mmap[start..end].to_vec())
        } else if pad {
            // Partial read with padding
            let mut result = vec![0u8; length];
            result[..available].copy_from_slice(&self.mmap[start..]);
            Ok(result)
        } else {
            Err(LayerError::InvalidAddress {
                layer_name: self.name.clone(),
                address: offset + available as u64,
            })
        }
    }

    fn metadata(&self) -> LayerMetadata {
        LayerMetadata {
            extra: [("path".to_string(), self.path.display().to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A layer backed by an in-memory buffer.
///
/// Useful for testing and small data operations.
pub struct BufferLayer {
    name: String,
    data: Vec<u8>,
}

impl BufferLayer {
    /// Create a new BufferLayer with the given data
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data,
        }
    }

    /// Create a new empty BufferLayer with a given size
    pub fn with_size(name: impl Into<String>, size: usize) -> Self {
        Self {
            name: name.into(),
            data: vec![0u8; size],
        }
    }

    /// Get mutable access to the underlying data
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl DataLayer for BufferLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> Address {
        0
    }

    fn maximum_address(&self) -> Address {
        if self.data.is_empty() {
            0
        } else {
            (self.data.len() - 1) as Address
        }
    }

    fn is_valid(&self, offset: Address, length: usize) -> bool {
        offset
            .checked_add(length as u64)
            .map(|end| end <= self.data.len() as u64)
            .unwrap_or(false)
    }

    fn read(&self, offset: Address, length: usize, pad: bool) -> LayerResult<Vec<u8>> {
        let start = offset as usize;

        if start >= self.data.len() {
            if pad {
                return Ok(vec![0u8; length]);
            } else {
                return Err(LayerError::InvalidAddress {
                    layer_name: self.name.clone(),
                    address: offset,
                });
            }
        }

        let end = start.saturating_add(length);
        let available = self.data.len() - start;

        if end <= self.data.len() {
            Ok(self.data[start..end].to_vec())
        } else if pad {
            let mut result = vec![0u8; length];
            result[..available].copy_from_slice(&self.data[start..]);
            Ok(result)
        } else {
            Err(LayerError::InvalidAddress {
                layer_name: self.name.clone(),
                address: offset + available as u64,
            })
        }
    }

    fn write(&self, _offset: Address, _data: &[u8]) -> LayerResult<()> {
        // BufferLayer doesn't support writing through the trait
        // Use data_mut() instead
        Err(LayerError::NotWritable(self.name.clone()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A layer that reads from a file without memory mapping.
///
/// Useful for compressed files or when mmap isn't available.
pub struct StreamingFileLayer {
    name: String,
    path: PathBuf,
    file: Mutex<File>,
    size: u64,
}

impl StreamingFileLayer {
    /// Create a new StreamingFileLayer
    pub fn new(name: impl Into<String>, path: impl AsRef<Path>) -> LayerResult<Self> {
        let name = name.into();
        let path = path.as_ref().to_path_buf();

        let mut file = File::open(&path).map_err(|e| LayerError::IoError {
            layer_name: name.clone(),
            message: e.to_string(),
        })?;

        let size = file
            .seek(SeekFrom::End(0))
            .map_err(|e| LayerError::IoError {
                layer_name: name.clone(),
                message: e.to_string(),
            })?;

        Ok(Self {
            name,
            path,
            file: Mutex::new(file),
            size,
        })
    }
}

impl DataLayer for StreamingFileLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> Address {
        0
    }

    fn maximum_address(&self) -> Address {
        if self.size == 0 {
            0
        } else {
            self.size - 1
        }
    }

    fn is_valid(&self, offset: Address, length: usize) -> bool {
        offset
            .checked_add(length as u64)
            .map(|end| end <= self.size)
            .unwrap_or(false)
    }

    fn read(&self, offset: Address, length: usize, pad: bool) -> LayerResult<Vec<u8>> {
        let mut file = self.file.lock().unwrap();

        if offset >= self.size {
            if pad {
                return Ok(vec![0u8; length]);
            } else {
                return Err(LayerError::InvalidAddress {
                    layer_name: self.name.clone(),
                    address: offset,
                });
            }
        }

        file.seek(SeekFrom::Start(offset))
            .map_err(|e| LayerError::IoError {
                layer_name: self.name.clone(),
                message: e.to_string(),
            })?;

        let available = (self.size - offset) as usize;
        let to_read = std::cmp::min(length, available);

        let mut buffer = vec![0u8; length];
        let bytes_read = file
            .read(&mut buffer[..to_read])
            .map_err(|e| LayerError::IoError {
                layer_name: self.name.clone(),
                message: e.to_string(),
            })?;

        if bytes_read < length && !pad {
            return Err(LayerError::InvalidAddress {
                layer_name: self.name.clone(),
                address: offset + bytes_read as u64,
            });
        }

        Ok(buffer)
    }

    fn metadata(&self) -> LayerMetadata {
        LayerMetadata {
            extra: [("path".to_string(), self.path.display().to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_buffer_layer() {
        let layer = BufferLayer::new("test", vec![1, 2, 3, 4, 5]);

        assert_eq!(layer.minimum_address(), 0);
        assert_eq!(layer.maximum_address(), 4);
        assert!(layer.is_valid(0, 5));
        assert!(!layer.is_valid(0, 6));

        assert_eq!(layer.read(0, 3, false).unwrap(), vec![1, 2, 3]);
        assert_eq!(layer.read(2, 3, false).unwrap(), vec![3, 4, 5]);
    }

    #[test]
    fn test_file_layer() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
        temp.flush().unwrap();

        let layer = FileLayer::new("test", temp.path()).unwrap();

        assert_eq!(layer.maximum_address(), 3);
        assert_eq!(
            layer.read(0, 4, false).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn test_padding() {
        let layer = BufferLayer::new("test", vec![1, 2]);

        let result = layer.read(0, 5, true).unwrap();
        assert_eq!(result, vec![1, 2, 0, 0, 0]);
    }
}
