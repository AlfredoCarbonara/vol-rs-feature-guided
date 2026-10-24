//! Scanner implementations for pattern matching in layers.

use vol3_core::Address;

use crate::traits::{ScanOutput, ScannerInterface};

/// A scanner that searches for byte patterns.
pub struct ByteScanner {
    pattern: Vec<u8>,
    chunk_size: usize,
}

impl ByteScanner {
    /// Create a new byte scanner
    pub fn new(pattern: Vec<u8>) -> Self {
        Self {
            pattern,
            chunk_size: 0x1000000, // 16MB default
        }
    }

    /// Set the chunk size
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }
}

impl ScannerInterface for ByteScanner {
    fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    fn overlap(&self) -> usize {
        // Overlap should be at least pattern length - 1
        std::cmp::max(self.pattern.len().saturating_sub(1), 0x1000)
    }

    fn thread_safe(&self) -> bool {
        true
    }

    fn scan(&self, data: &[u8], data_offset: Address) -> Vec<ScanOutput> {
        let mut results = Vec::new();

        if self.pattern.is_empty() || data.len() < self.pattern.len() {
            return results;
        }

        for i in memchr::memmem::find_iter(data, &self.pattern) {
            let offset = data_offset + i as u64;
            // Don't return matches in the overlap region
            if i < self.chunk_size() {
                results.push((offset, self.pattern.clone()));
            }
        }

        results
    }
}

/// A scanner that searches for regex patterns.
pub struct RegexScanner {
    regex: regex::bytes::Regex,
    chunk_size: usize,
}

impl RegexScanner {
    /// Create a new regex scanner
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            regex: regex::bytes::Regex::new(pattern)?,
            chunk_size: 0x1000000,
        })
    }

    /// Set the chunk size
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }
}

impl ScannerInterface for RegexScanner {
    fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    fn thread_safe(&self) -> bool {
        true
    }

    fn scan(&self, data: &[u8], data_offset: Address) -> Vec<ScanOutput> {
        let mut results = Vec::new();

        for mat in self.regex.find_iter(data) {
            let offset = data_offset + mat.start() as u64;
            // Don't return matches in the overlap region
            if mat.start() < self.chunk_size() {
                results.push((offset, mat.as_bytes().to_vec()));
            }
        }

        results
    }
}

/// A scanner for multiple byte patterns (like banners).
pub struct MultiPatternScanner {
    patterns: Vec<Vec<u8>>,
    chunk_size: usize,
}

impl MultiPatternScanner {
    /// Create a new multi-pattern scanner
    pub fn new(patterns: Vec<Vec<u8>>) -> Self {
        Self {
            patterns,
            chunk_size: 0x1000000,
        }
    }
}

impl ScannerInterface for MultiPatternScanner {
    fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    fn overlap(&self) -> usize {
        // Overlap should be at least max pattern length - 1
        let max_len = self.patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        std::cmp::max(max_len.saturating_sub(1), 0x1000)
    }

    fn thread_safe(&self) -> bool {
        true
    }

    fn scan(&self, data: &[u8], data_offset: Address) -> Vec<ScanOutput> {
        let mut results = Vec::new();

        for pattern in &self.patterns {
            if pattern.is_empty() || data.len() < pattern.len() {
                continue;
            }

            for i in memchr::memmem::find_iter(data, pattern) {
                let offset = data_offset + i as u64;
                if i < self.chunk_size() {
                    results.push((offset, pattern.clone()));
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_scanner() {
        let scanner = ByteScanner::new(vec![0xDE, 0xAD]);
        let data = vec![0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD];

        let results = scanner.scan(&data, 0x1000);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, 0x1001);
        assert_eq!(results[1].0, 0x1005);
    }

    #[test]
    fn test_regex_scanner() {
        let scanner = RegexScanner::new(r"Linux version \d+\.\d+").unwrap();
        let data = b"Linux version 5.15.0-generic";

        let results = scanner.scan(data, 0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 0);
    }

    #[test]
    fn test_multi_pattern_scanner() {
        let scanner = MultiPatternScanner::new(vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD]]);
        let data = vec![0xAA, 0xBB, 0x00, 0xCC, 0xDD];

        let results = scanner.scan(&data, 0);
        assert_eq!(results.len(), 2);
    }
}
