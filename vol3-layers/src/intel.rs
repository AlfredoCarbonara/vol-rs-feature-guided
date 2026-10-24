//! Intel paging layer implementations.
//!
//! This module provides address translation layers for Intel x86/x64 paging:
//! - `Intel32` - 32-bit paging (2-level)
//! - `IntelPAE` - Physical Address Extension (3-level)
//! - `Intel32e` - 64-bit (4-level) paging

use std::any::Any;
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt};
use parking_lot::RwLock;
use vol3_core::{Address, LayerError, LayerResult};

use crate::traits::{
    DataLayer, LayerMetadata, MappedRegion, ScanOutput, ScannerInterface, TranslationLayer,
};

/// Cache for page table entries
type PageCache = hashbrown::HashMap<Address, u64>;

/// 64-bit Intel paging (4-level page tables).
///
/// Implements IA-32e paging with support for:
/// - 4KB pages
/// - 2MB large pages
/// - 1GB huge pages
pub struct Intel32e {
    name: String,
    base_layer: Arc<dyn DataLayer>,
    dtb: Address,
    page_map_offset: Address,
    windows_paging: bool,
    cache: RwLock<PageCache>,
}

impl Intel32e {
    /// Page size constants
    const PAGE_SIZE_4K: usize = 0x1000;
    const PAGE_SIZE_2M: usize = 0x200000;
    const PAGE_SIZE_1G: usize = 0x40000000;

    /// Page table entry size
    const ENTRY_SIZE: usize = 8;

    /// Page level definitions
    const LEVELS: [(u32, u64, &'static str); 4] = [
        (39, 0x1FF, "PML4"),
        (30, 0x1FF, "PDPT"),
        (21, 0x1FF, "PD"),
        (12, 0x1FF, "PT"),
    ];

    /// Create a new Intel32e translation layer
    pub fn new(
        name: impl Into<String>,
        base_layer: Arc<dyn DataLayer>,
        dtb: Address,
        page_map_offset: Address,
    ) -> Self {
        Self {
            name: name.into(),
            base_layer,
            dtb,
            page_map_offset,
            windows_paging: false,
            cache: RwLock::new(PageCache::new()),
        }
    }

    /// Create a Windows Intel64 layer, including transition-PTE semantics.
    pub fn new_windows(
        name: impl Into<String>,
        base_layer: Arc<dyn DataLayer>,
        dtb: Address,
        page_map_offset: Address,
    ) -> Self {
        Self {
            name: name.into(),
            base_layer,
            dtb,
            page_map_offset,
            windows_paging: true,
            cache: RwLock::new(PageCache::new()),
        }
    }

    /// Read a page table entry
    fn read_entry(&self, address: Address) -> LayerResult<u64> {
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(&entry) = cache.get(&address) {
                return Ok(entry);
            }
        }

        // Read from base layer
        let data = self.base_layer.read(address, Self::ENTRY_SIZE, false)?;
        let mut cursor = std::io::Cursor::new(data);
        let entry = cursor
            .read_u64::<LittleEndian>()
            .map_err(|e| LayerError::IoError {
                layer_name: self.name.clone(),
                message: e.to_string(),
            })?;

        // Cache the entry
        {
            let mut cache = self.cache.write();
            cache.insert(address, entry);
        }

        Ok(entry)
    }

    /// Check if an entry is present
    #[inline]
    fn is_present(&self, entry: u64) -> bool {
        (entry & 1) != 0
            || (self.windows_paging && (entry & (1 << 11)) != 0 && (entry & (1 << 10)) == 0)
    }

    /// Check if an entry is a large page (PS bit)
    #[inline]
    fn is_large_page(entry: u64) -> bool {
        (entry & 0x80) != 0
    }

    /// Get the physical address from an entry
    #[inline]
    fn entry_to_physical(&self, entry: u64) -> Address {
        // Volatility uses MAXPHYADDR=45 for WindowsIntel32e because Windows
        // stores transition-state flags in otherwise available PFN bits.
        let mask = if self.windows_paging {
            0x0000_1FFF_FFFF_F000
        } else {
            0x000F_FFFF_FFFF_F000
        };
        entry & mask
    }

    /// Translate a virtual address to physical
    fn translate_address(&self, virtual_addr: Address) -> LayerResult<(Address, usize)> {
        let mut table_addr = self.dtb + self.page_map_offset;

        for (level_idx, (bits, mask, level_name)) in Self::LEVELS.iter().enumerate() {
            let index = (virtual_addr >> bits) & mask;
            let entry_addr = table_addr + (index * Self::ENTRY_SIZE as u64);

            let entry = self.read_entry(entry_addr)?;

            if !self.is_present(entry) {
                return Err(LayerError::InvalidAddress {
                    layer_name: self.name.clone(),
                    address: virtual_addr,
                });
            }

            // Check for large page (only at PDPT and PD levels)
            if level_idx == 1 && Self::is_large_page(entry) {
                // 1GB page
                let physical = self.entry_to_physical(entry) & !(Self::PAGE_SIZE_1G as u64 - 1);
                let page_offset = virtual_addr & (Self::PAGE_SIZE_1G as u64 - 1);
                return Ok((physical | page_offset, Self::PAGE_SIZE_1G));
            }

            if level_idx == 2 && Self::is_large_page(entry) {
                // 2MB page
                let physical = self.entry_to_physical(entry) & !(Self::PAGE_SIZE_2M as u64 - 1);
                let page_offset = virtual_addr & (Self::PAGE_SIZE_2M as u64 - 1);
                return Ok((physical | page_offset, Self::PAGE_SIZE_2M));
            }

            table_addr = self.entry_to_physical(entry);
        }

        // 4KB page
        let page_offset = virtual_addr & (Self::PAGE_SIZE_4K as u64 - 1);
        Ok((table_addr | page_offset, Self::PAGE_SIZE_4K))
    }

    /// Return the dirty flag of the page-table entry mapping a virtual page.
    /// Windows Malfind uses this for executable, non-writable VADs.
    pub fn is_dirty(&self, virtual_addr: Address) -> LayerResult<bool> {
        let mut table_addr = self.dtb + self.page_map_offset;
        for (level_idx, (bits, mask, _)) in Self::LEVELS.iter().enumerate() {
            let index = (virtual_addr >> bits) & mask;
            let entry = self.read_entry(table_addr + index * Self::ENTRY_SIZE as u64)?;
            if !self.is_present(entry) {
                return Err(LayerError::InvalidAddress {
                    layer_name: self.name.clone(), address: virtual_addr,
                });
            }
            if level_idx == 3 || (level_idx == 1 || level_idx == 2) && Self::is_large_page(entry) {
                return Ok(entry & (1 << 6) != 0);
            }
            table_addr = self.entry_to_physical(entry);
        }
        unreachable!()
    }

    /// Enumerate the virtual ranges backed by the current page tables.
    ///
    /// Pool scanners must operate on the Windows kernel virtual layer to
    /// match Volatility's semantics.  Scanning the physical image directly
    /// also visits stale/unmapped pool allocations and loses the virtual
    /// address required by a few callback fallbacks.
    pub fn mapped_sections(&self, kernel_only: bool) -> LayerResult<Vec<(Address, usize)>> {
        Ok(self
            .mapped_regions_for_scan(kernel_only)?
            .into_iter()
            .map(|region| (region.mapped_offset, region.mapped_length))
            .collect())
    }

    /// Scan mapped pages directly from their underlying physical ranges while
    /// reporting virtual addresses.  This preserves virtual-layer semantics
    /// without performing four page-table lookups for every 4 KiB read.
    pub fn scan_mapped(
        &self,
        scanner: &dyn ScannerInterface,
        kernel_only: bool,
    ) -> LayerResult<Vec<ScanOutput>> {
        let mut output = Vec::new();
        self.scan_mapped_with(scanner, kernel_only, |item| output.push(item))?;
        Ok(output)
    }

    /// Streaming variant of [`Self::scan_mapped`] that does not retain every
    /// raw pattern match before a plugin has validated it.
    pub fn scan_mapped_with<F>(
        &self,
        scanner: &dyn ScannerInterface,
        kernel_only: bool,
        mut visit: F,
    ) -> LayerResult<()>
    where
        F: FnMut(ScanOutput),
    {
        // Scan each physical page only once while retaining a virtual address
        // for decoding the containing object.  Full alias-preserving scans
        // were tested against Volatility callback output but did not recover
        // any additional records and multiplied scan time substantially.
        let mut virtual_by_physical = hashbrown::HashMap::<Address, Address>::new();
        self.for_each_mapped_region(kernel_only, |region| {
            for page_offset in (0..region.mapped_length).step_by(Self::PAGE_SIZE_4K) {
                let physical_page = region.layer_offset + page_offset as u64;
                if self.base_layer.is_valid(physical_page, Self::PAGE_SIZE_4K) {
                    virtual_by_physical
                        .entry(physical_page)
                        .or_insert(region.mapped_offset + page_offset as u64);
                }
            }
            Ok(())
        })?;
        let mut physical_pages: Vec<Address> = virtual_by_physical.keys().copied().collect();
        physical_pages.sort_unstable();
        let chunk_size = scanner.chunk_size();
        let overlap = scanner.overlap();
        let mut index = 0usize;
        while index < physical_pages.len() {
            let range_start = physical_pages[index];
            let mut range_pages = 1usize;
            while index + range_pages < physical_pages.len()
                && physical_pages[index + range_pages]
                    == range_start + (range_pages * Self::PAGE_SIZE_4K) as u64
            {
                range_pages += 1;
            }
            let range_length = range_pages * Self::PAGE_SIZE_4K;
            let mut position = 0usize;
            while position < range_length {
                let remaining = range_length - position;
                let read_size = (chunk_size + overlap).min(remaining);
                let physical_start = range_start + position as u64;
                let mut scan_data = |data: &[u8], data_start: Address| {
                    for (physical_match, value) in scanner.scan(data, data_start) {
                        let page = physical_match & !(Self::PAGE_SIZE_4K as u64 - 1);
                        if let Some(virtual_page) = virtual_by_physical.get(&page) {
                            visit((virtual_page + (physical_match - page), value));
                        }
                    }
                };
                if let Ok(data) = self.base_layer.read(physical_start, read_size, false) {
                    scan_data(&data, physical_start);
                } else {
                    for page_offset in (0..read_size).step_by(Self::PAGE_SIZE_4K) {
                        let page_start = physical_start + page_offset as u64;
                        let page_length = Self::PAGE_SIZE_4K.min(read_size - page_offset);
                        if let Ok(data) = self.base_layer.read(page_start, page_length, false) {
                            scan_data(&data, page_start);
                        }
                    }
                }
                position += chunk_size.min(remaining);
            }
            index += range_pages;
        }
        Ok(())
    }

    fn for_each_mapped_region<F>(&self, kernel_only: bool, mut visit: F) -> LayerResult<()>
    where
        F: FnMut(MappedRegion) -> LayerResult<()>,
    {
        let first_pml4 = if kernel_only { 256usize } else { 0usize };
        let root_address = self.dtb + self.page_map_offset;
        let root = self
            .base_layer
            .read(root_address, 512 * Self::ENTRY_SIZE, false)?;
        if page_table_is_repeated(&root) {
            return Ok(());
        }
        let mut seen_tables = hashbrown::HashSet::<(usize, Address)>::new();
        for pml4_index in first_pml4..512usize {
            let start = pml4_index * Self::ENTRY_SIZE;
            let entry = u64::from_le_bytes(root[start..start + 8].try_into().unwrap());
            if !self.is_present(entry) {
                continue;
            }
            let table_address = self.entry_to_physical(entry);
            if !self.base_layer.is_valid(table_address, Self::PAGE_SIZE_4K)
                || !seen_tables.insert((1, table_address))
            {
                continue;
            }
            self.walk_mapped_table_with(
                table_address,
                1,
                canonicalize_48((pml4_index as u64) << 39),
                &mut seen_tables,
                &mut visit,
            )?;
        }
        Ok(())
    }

    fn walk_mapped_table_with<F>(
        &self,
        table_address: Address,
        level: usize,
        virtual_prefix: Address,
        seen_tables: &mut hashbrown::HashSet<(usize, Address)>,
        visit: &mut F,
    ) -> LayerResult<()>
    where
        F: FnMut(MappedRegion) -> LayerResult<()>,
    {
        let (shift, leaf_size) = match level {
            1 => (30u32, Self::PAGE_SIZE_1G),
            2 => (21u32, Self::PAGE_SIZE_2M),
            3 => (12u32, Self::PAGE_SIZE_4K),
            _ => return Ok(()),
        };
        let table = self
            .base_layer
            .read(table_address, 512 * Self::ENTRY_SIZE, false)?;
        // Match Volatility's Windows Intel layer safeguard: page tables whose
        // 512 entries are identical are treated as invalid.  Windows images
        // can otherwise expose enormous repeated virtual mappings and pool
        // scanners produce both severe slowdowns and false positives.
        if page_table_is_repeated(&table) {
            return Ok(());
        }
        for index in 0..512usize {
            let start = index * Self::ENTRY_SIZE;
            let entry = u64::from_le_bytes(table[start..start + 8].try_into().unwrap());
            if !self.is_present(entry) {
                continue;
            }
            let address = virtual_prefix | ((index as u64) << shift);
            if level == 3 || (level < 3 && Self::is_large_page(entry)) {
                visit(MappedRegion {
                    mapped_offset: address,
                    mapped_length: leaf_size,
                    layer_offset: self.entry_to_physical(entry) & !(leaf_size as u64 - 1),
                    layer_length: leaf_size,
                    layer_name: self.base_layer.name().to_string(),
                })?;
            } else {
                let next_table = self.entry_to_physical(entry);
                if !self.base_layer.is_valid(next_table, Self::PAGE_SIZE_4K)
                    || !seen_tables.insert((level + 1, next_table))
                {
                    continue;
                }
                self.walk_mapped_table_with(next_table, level + 1, address, seen_tables, visit)?;
            }
        }
        Ok(())
    }

    fn mapped_regions_for_scan(&self, kernel_only: bool) -> LayerResult<Vec<MappedRegion>> {
        let mut regions = Vec::new();
        let first_pml4 = if kernel_only { 256usize } else { 0usize };
        for pml4_index in first_pml4..512usize {
            let entry = self.read_entry(
                self.dtb + self.page_map_offset + (pml4_index * Self::ENTRY_SIZE) as u64,
            )?;
            // Transition entries are meaningful for final Windows PTEs, not
            // for the upper paging structures themselves.
            if (entry & 1) == 0 {
                continue;
            }
            let virtual_prefix = canonicalize_48((pml4_index as u64) << 39);
            self.walk_mapped_table(
                self.entry_to_physical(entry),
                1,
                virtual_prefix,
                &mut regions,
            )?;
        }
        Ok(merge_mapped_regions(regions))
    }

    fn walk_mapped_table(
        &self,
        table_address: Address,
        level: usize,
        virtual_prefix: Address,
        regions: &mut Vec<MappedRegion>,
    ) -> LayerResult<()> {
        let (shift, leaf_size) = match level {
            1 => (30u32, Self::PAGE_SIZE_1G),
            2 => (21u32, Self::PAGE_SIZE_2M),
            3 => (12u32, Self::PAGE_SIZE_4K),
            _ => return Ok(()),
        };
        let table = self
            .base_layer
            .read(table_address, 512 * Self::ENTRY_SIZE, false)?;
        for index in 0..512usize {
            let start = index * Self::ENTRY_SIZE;
            let entry = u64::from_le_bytes(table[start..start + 8].try_into().unwrap());
            if (entry & 1) == 0 {
                continue;
            }
            let address = virtual_prefix | ((index as u64) << shift);
            if level == 3 || (level < 3 && Self::is_large_page(entry)) {
                regions.push(MappedRegion {
                    mapped_offset: address,
                    mapped_length: leaf_size,
                    layer_offset: self.entry_to_physical(entry) & !(leaf_size as u64 - 1),
                    layer_length: leaf_size,
                    layer_name: self.base_layer.name().to_string(),
                });
            } else {
                self.walk_mapped_table(self.entry_to_physical(entry), level + 1, address, regions)?;
            }
        }
        Ok(())
    }

    /// Get page-aligned mapping for a range
    fn get_page_mappings(
        &self,
        offset: Address,
        length: usize,
        ignore_errors: bool,
    ) -> LayerResult<Vec<MappedRegion>> {
        let mut regions = Vec::new();
        let mut current_offset = offset;
        let end_offset = offset + length as u64;

        while current_offset < end_offset {
            match self.translate_address(current_offset) {
                Ok((physical, page_size)) => {
                    let page_base = current_offset & !(page_size as u64 - 1);
                    let page_offset = current_offset - page_base;
                    let remaining_in_page = page_size - page_offset as usize;
                    let remaining_total = (end_offset - current_offset) as usize;
                    let chunk_size = std::cmp::min(remaining_in_page, remaining_total);

                    regions.push(MappedRegion {
                        mapped_offset: current_offset,
                        mapped_length: chunk_size,
                        layer_offset: physical,
                        layer_length: chunk_size,
                        layer_name: self.base_layer.name().to_string(),
                    });

                    current_offset += chunk_size as u64;
                }
                Err(e) => {
                    if ignore_errors {
                        // Skip to next page boundary
                        let next_page = (current_offset + Self::PAGE_SIZE_4K as u64)
                            & !(Self::PAGE_SIZE_4K as u64 - 1);
                        current_offset = next_page;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Ok(regions)
    }
}

fn canonicalize_48(address: Address) -> Address {
    if address & (1u64 << 47) != 0 {
        address | 0xffff_0000_0000_0000
    } else {
        address
    }
}

fn page_table_is_repeated(table: &[u8]) -> bool {
    let Some(first) = table.get(..Intel32e::ENTRY_SIZE) else {
        return false;
    };
    table
        .chunks_exact(Intel32e::ENTRY_SIZE)
        .all(|entry| entry == first)
}

fn merge_mapped_regions(mut regions: Vec<MappedRegion>) -> Vec<MappedRegion> {
    regions.sort_unstable_by_key(|region| region.mapped_offset);
    let mut merged: Vec<MappedRegion> = Vec::with_capacity(regions.len());
    for region in regions {
        if let Some(previous) = merged.last_mut() {
            let virtual_contiguous = previous
                .mapped_offset
                .checked_add(previous.mapped_length as u64)
                .is_some_and(|end| end == region.mapped_offset);
            let physical_contiguous = previous
                .layer_offset
                .checked_add(previous.layer_length as u64)
                .is_some_and(|end| end == region.layer_offset);
            if virtual_contiguous && physical_contiguous {
                previous.mapped_length += region.mapped_length;
                previous.layer_length += region.layer_length;
                continue;
            }
        }
        merged.push(region);
    }
    merged
}

impl DataLayer for Intel32e {
    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> Address {
        0
    }

    fn maximum_address(&self) -> Address {
        // 48-bit canonical address space
        0x0000_7FFF_FFFF_FFFF
    }

    fn is_valid(&self, offset: Address, _length: usize) -> bool {
        self.translate_address(offset).is_ok()
    }

    fn read(&self, offset: Address, length: usize, pad: bool) -> LayerResult<Vec<u8>> {
        let regions = self.get_page_mappings(offset, length, pad)?;

        let mut result = vec![0u8; length];
        let mut current_pos = 0usize;

        for region in regions {
            // Handle gaps in mapping
            let region_start = (region.mapped_offset - offset) as usize;
            if region_start > current_pos {
                // Gap - fill with zeros (already initialized)
                current_pos = region_start;
            }

            // Read from base layer
            let data = self
                .base_layer
                .read(region.layer_offset, region.mapped_length, pad)?;
            result[current_pos..current_pos + region.mapped_length].copy_from_slice(&data);
            current_pos += region.mapped_length;
        }

        Ok(result)
    }

    fn dependencies(&self) -> Vec<String> {
        vec![self.base_layer.name().to_string()]
    }

    fn metadata(&self) -> LayerMetadata {
        LayerMetadata {
            architecture: Some("Intel64".to_string()),
            ..Default::default()
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TranslationLayer for Intel32e {
    fn mapping(
        &self,
        offset: Address,
        length: usize,
        ignore_errors: bool,
    ) -> LayerResult<Vec<MappedRegion>> {
        self.get_page_mappings(offset, length, ignore_errors)
    }

    fn translate(&self, offset: Address) -> LayerResult<(Address, String)> {
        let (physical, _) = self.translate_address(offset)?;
        Ok((physical, self.base_layer.name().to_string()))
    }
}

/// 32-bit Intel paging (2-level page tables).
pub struct Intel32 {
    name: String,
    base_layer: Arc<dyn DataLayer>,
    dtb: Address,
    cache: RwLock<PageCache>,
}

impl Intel32 {
    const PAGE_SIZE_4K: usize = 0x1000;
    const PAGE_SIZE_4M: usize = 0x400000;
    const ENTRY_SIZE: usize = 4;

    pub fn new(name: impl Into<String>, base_layer: Arc<dyn DataLayer>, dtb: Address) -> Self {
        Self {
            name: name.into(),
            base_layer,
            dtb,
            cache: RwLock::new(PageCache::new()),
        }
    }

    fn read_entry(&self, address: Address) -> LayerResult<u32> {
        let data = self.base_layer.read(address, Self::ENTRY_SIZE, false)?;
        let mut cursor = std::io::Cursor::new(data);
        cursor
            .read_u32::<LittleEndian>()
            .map_err(|e| LayerError::IoError {
                layer_name: self.name.clone(),
                message: e.to_string(),
            })
    }

    fn translate_address(&self, virtual_addr: Address) -> LayerResult<(Address, usize)> {
        // Page Directory
        let pde_index = (virtual_addr >> 22) & 0x3FF;
        let pde_addr = self.dtb + (pde_index * Self::ENTRY_SIZE as u64);
        let pde = self.read_entry(pde_addr)?;

        if (pde & 1) == 0 {
            return Err(LayerError::InvalidAddress {
                layer_name: self.name.clone(),
                address: virtual_addr,
            });
        }

        // Check for 4MB page (PS bit)
        if (pde & 0x80) != 0 {
            let physical = (pde as u64 & 0xFFC0_0000) | (virtual_addr & 0x003F_FFFF);
            return Ok((physical, Self::PAGE_SIZE_4M));
        }

        // Page Table
        let pt_base = (pde as u64) & 0xFFFF_F000;
        let pte_index = (virtual_addr >> 12) & 0x3FF;
        let pte_addr = pt_base + (pte_index * Self::ENTRY_SIZE as u64);
        let pte = self.read_entry(pte_addr)?;

        if (pte & 1) == 0 {
            return Err(LayerError::InvalidAddress {
                layer_name: self.name.clone(),
                address: virtual_addr,
            });
        }

        let physical = ((pte as u64) & 0xFFFF_F000) | (virtual_addr & 0x0FFF);
        Ok((physical, Self::PAGE_SIZE_4K))
    }
}

impl DataLayer for Intel32 {
    fn name(&self) -> &str {
        &self.name
    }

    fn minimum_address(&self) -> Address {
        0
    }

    fn maximum_address(&self) -> Address {
        0xFFFF_FFFF
    }

    fn is_valid(&self, offset: Address, _length: usize) -> bool {
        self.translate_address(offset).is_ok()
    }

    fn read(&self, offset: Address, length: usize, pad: bool) -> LayerResult<Vec<u8>> {
        let mut result = Vec::with_capacity(length);
        let mut current = offset;
        let end = offset + length as u64;

        while current < end {
            match self.translate_address(current) {
                Ok((physical, page_size)) => {
                    let page_base = current & !(page_size as u64 - 1);
                    let page_offset = (current - page_base) as usize;
                    let remaining = (end - current) as usize;
                    let chunk = std::cmp::min(page_size - page_offset, remaining);

                    let data = self.base_layer.read(physical, chunk, pad)?;
                    result.extend_from_slice(&data);
                    current += chunk as u64;
                }
                Err(e) => {
                    if pad {
                        result.push(0);
                        current += 1;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Ok(result)
    }

    fn dependencies(&self) -> Vec<String> {
        vec![self.base_layer.name().to_string()]
    }

    fn metadata(&self) -> LayerMetadata {
        LayerMetadata {
            architecture: Some("Intel32".to_string()),
            ..Default::default()
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TranslationLayer for Intel32 {
    fn mapping(
        &self,
        offset: Address,
        length: usize,
        ignore_errors: bool,
    ) -> LayerResult<Vec<MappedRegion>> {
        let mut regions = Vec::new();
        let mut current = offset;
        let end = offset + length as u64;

        while current < end {
            match self.translate_address(current) {
                Ok((physical, page_size)) => {
                    let page_base = current & !(page_size as u64 - 1);
                    let page_offset = (current - page_base) as usize;
                    let remaining = (end - current) as usize;
                    let chunk = std::cmp::min(page_size - page_offset, remaining);

                    regions.push(MappedRegion {
                        mapped_offset: current,
                        mapped_length: chunk,
                        layer_offset: physical,
                        layer_length: chunk,
                        layer_name: self.base_layer.name().to_string(),
                    });
                    current += chunk as u64;
                }
                Err(e) => {
                    if ignore_errors {
                        current = (current + Self::PAGE_SIZE_4K as u64)
                            & !(Self::PAGE_SIZE_4K as u64 - 1);
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Ok(regions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::physical::BufferLayer;

    fn create_test_layer() -> Arc<dyn DataLayer> {
        // Create a simple test layer with page tables
        let mut data = vec![0u8; 0x10000];

        // Set up a simple identity mapping
        // PML4[0] -> PDPT at 0x1000
        let pml4_entry: u64 = 0x1003; // Present, writable, points to 0x1000
        data[0..8].copy_from_slice(&pml4_entry.to_le_bytes());

        // PDPT[0] -> PD at 0x2000
        let pdpt_entry: u64 = 0x2003;
        data[0x1000..0x1008].copy_from_slice(&pdpt_entry.to_le_bytes());

        // PD[0] -> PT at 0x3000
        let pd_entry: u64 = 0x3003;
        data[0x2000..0x2008].copy_from_slice(&pd_entry.to_le_bytes());

        // PT[0] -> Page at 0x4000
        let pt_entry: u64 = 0x4003;
        data[0x3000..0x3008].copy_from_slice(&pt_entry.to_le_bytes());

        // Write test data at physical 0x4000
        data[0x4000] = 0xDE;
        data[0x4001] = 0xAD;
        data[0x4002] = 0xBE;
        data[0x4003] = 0xEF;

        Arc::new(BufferLayer::new("physical", data))
    }

    #[test]
    fn test_intel32e_translate() {
        let base = create_test_layer();
        let layer = Intel32e::new("test", base, 0, 0);

        // Virtual address 0 should translate to physical 0x4000
        let (physical, _) = layer.translate_address(0).unwrap();
        assert_eq!(physical, 0x4000);
    }

    #[test]
    fn test_intel32e_read() {
        let base = create_test_layer();
        let layer = Intel32e::new("test", base, 0, 0);

        let data = layer.read(0, 4, false).unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn windows_layer_accepts_transition_pte() {
        let mut data = vec![0u8; 0x10000];
        data[0..8].copy_from_slice(&0x1003_u64.to_le_bytes());
        data[0x1000..0x1008].copy_from_slice(&0x2003_u64.to_le_bytes());
        data[0x2000..0x2008].copy_from_slice(&0x3003_u64.to_le_bytes());
        // Present=0, Transition=1, Prototype=0, PFN=4.
        data[0x3000..0x3008].copy_from_slice(&0x4800_u64.to_le_bytes());
        data[0x4000] = 0xA5;
        let base: Arc<dyn DataLayer> = Arc::new(BufferLayer::new("physical", data));

        let generic = Intel32e::new("generic", base.clone(), 0, 0);
        assert!(generic.read(0, 1, false).is_err());

        let windows = Intel32e::new_windows("windows", base, 0, 0);
        assert_eq!(windows.read(0, 1, false).unwrap(), vec![0xA5]);
    }
}
