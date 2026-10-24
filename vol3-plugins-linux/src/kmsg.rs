//! Linux Kmsg plugin.
//!
//! Reads the kernel log buffer.

use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;

/// Log level names - same order as kernel
const LEVELS: [&str; 8] = [
    "emerg",  // system is unusable
    "alert",  // action must be taken immediately
    "crit",   // critical conditions
    "err",    // error conditions
    "warn",   // warning conditions
    "notice", // normal but significant condition
    "info",   // informational
    "debug",  // debug-level messages
];

/// Facility names - same order as kernel
const FACILITIES: [&str; 12] = [
    "kern",     // kernel messages
    "user",     // random user-level messages
    "mail",     // mail system
    "daemon",   // system daemons
    "auth",     // security/authorization messages
    "syslog",   // messages generated internally by syslogd
    "lpr",      // line printer subsystem
    "news",     // network news subsystem
    "uucp",     // UUCP subsystem
    "cron",     // clock daemon
    "authpriv", // security/authorization messages (private)
    "ftp",      // FTP daemon
];

/// Descriptor state enum (from printk_ringbuffer.h)
#[derive(Debug, Clone, Copy, PartialEq)]
enum DescState {
    Reserved = 0,  // in use by writer
    Committed = 1, // committed by writer, could get reopened
    Finalized = 2, // committed, no further modification allowed
    Reusable = 3,  // free, not yet used by any writer
}

impl From<u64> for DescState {
    fn from(val: u64) -> Self {
        match val & 3 {
            0 => DescState::Reserved,
            1 => DescState::Committed,
            2 => DescState::Finalized,
            3 => DescState::Reusable,
            _ => DescState::Reserved,
        }
    }
}

/// Kmsg plugin - reads kernel log buffer
pub struct Kmsg;

impl Kmsg {
    pub fn new() -> Self {
        Self
    }

    fn read_kmsg(context: &Context) -> Vol3Result<Vec<KmsgEntry>> {
        use vol3_core::error::ConfigError;

        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let layer = context.get_layer(&layer_name).ok_or_else(|| {
            Vol3Error::Layer(vol3_core::error::LayerError::NotFound(layer_name.clone()))
        })?;

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        let symbols = context.get_symbol_table(&symbol_table).ok_or_else(|| {
            Vol3Error::Config(ConfigError::KeyNotFound("symbol_table".to_string()))
        })?;

        let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;
        let ptr_sz = 8usize; // 64-bit

        // Kernel 5.10+ uses printk_ringbuffer structure accessed via 'prb' pointer
        let prb_sym = match context.get_symbol(&symbol_table, "prb") {
            Ok(s) => s.address + aslr_shift,
            Err(_) => {
                // Fall back to older kernel implementation
                return Self::read_kmsg_legacy(context);
            }
        };

        // Read prb pointer (points to printk_ringbuffer structure)
        let prb_ptr = {
            let data = layer.read(prb_sym, ptr_sz, false)?;
            LittleEndian::read_u64(&data)
        };

        // Get type sizes and offsets for printk_ringbuffer
        let ringbuffer_type = symbols.get_type("printk_ringbuffer")?;
        let desc_ring_offset = Self::get_field_offset(&ringbuffer_type, "desc_ring");
        let text_data_ring_offset = Self::get_field_offset(&ringbuffer_type, "text_data_ring");

        // Get prb_desc_ring structure offsets
        let desc_ring_type = symbols.get_type("prb_desc_ring")?;
        let descs_offset = Self::get_field_offset(&desc_ring_type, "descs");
        let infos_offset = Self::get_field_offset(&desc_ring_type, "infos");
        let count_bits_offset = Self::get_field_offset(&desc_ring_type, "count_bits");
        let head_id_offset = Self::get_field_offset(&desc_ring_type, "head_id");
        let tail_id_offset = Self::get_field_offset(&desc_ring_type, "tail_id");

        // Get prb_data_ring structure offsets
        let data_ring_type = symbols.get_type("prb_data_ring")?;
        let data_offset = Self::get_field_offset(&data_ring_type, "data");
        let size_bits_offset = Self::get_field_offset(&data_ring_type, "size_bits");

        // Get prb_desc structure size and offsets
        let desc_type = symbols.get_type("prb_desc")?;
        let desc_sz = desc_type.size().unwrap_or(64);
        let state_var_offset = Self::get_field_offset(&desc_type, "state_var");
        let text_blk_lpos_offset = Self::get_field_offset(&desc_type, "text_blk_lpos");

        // Get prb_data_blk_lpos structure offsets
        let blk_lpos_type = symbols.get_type("prb_data_blk_lpos")?;
        let begin_offset = Self::get_field_offset(&blk_lpos_type, "begin");
        let next_offset = Self::get_field_offset(&blk_lpos_type, "next");

        // Get printk_info structure size and offsets
        let info_type = symbols.get_type("printk_info")?;
        let info_sz = info_type.size().unwrap_or(88);
        let info_ts_nsec_offset = Self::get_field_offset(&info_type, "ts_nsec");
        let info_text_len_offset = Self::get_field_offset(&info_type, "text_len");
        let _info_facility_offset = Self::get_field_offset(&info_type, "facility");
        let _info_level_offset = Self::get_field_offset(&info_type, "level");
        let info_caller_id_offset = Self::get_field_offset(&info_type, "caller_id");
        let info_dev_info_offset = Self::get_field_offset(&info_type, "dev_info");

        // Read desc_ring fields
        let desc_ring_addr = prb_ptr + desc_ring_offset as u64;

        // Read descs pointer
        let descs_ptr = {
            let data = layer.read(desc_ring_addr + descs_offset as u64, ptr_sz, false)?;
            LittleEndian::read_u64(&data)
        };

        // Read infos pointer
        let infos_ptr = {
            let data = layer.read(desc_ring_addr + infos_offset as u64, ptr_sz, false)?;
            LittleEndian::read_u64(&data)
        };

        // Read count_bits
        let count_bits = {
            let data = layer.read(desc_ring_addr + count_bits_offset as u64, 4, false)?;
            LittleEndian::read_u32(&data) as u64
        };
        let desc_count = 1u64 << count_bits;

        // Read tail_id and head_id (atomic_long_t -> counter member)
        let tail_id = {
            let data = layer.read(desc_ring_addr + tail_id_offset as u64, 8, false)?;
            LittleEndian::read_u64(&data)
        };
        let head_id = {
            let data = layer.read(desc_ring_addr + head_id_offset as u64, 8, false)?;
            LittleEndian::read_u64(&data)
        };

        // Read text_data_ring fields
        let text_data_ring_addr = prb_ptr + text_data_ring_offset as u64;

        // Read data pointer
        let text_data_ptr = {
            let data = layer.read(text_data_ring_addr + data_offset as u64, ptr_sz, false)?;
            LittleEndian::read_u64(&data)
        };

        // Read size_bits
        let text_size_bits = {
            let data = layer.read(text_data_ring_addr + size_bits_offset as u64, 4, false)?;
            LittleEndian::read_u32(&data) as u64
        };
        let text_data_mask = 1u64 << text_size_bits;

        // State variable bits for extracting state
        let desc_flags_shift = (ptr_sz * 8) as u64 - 2;
        let desc_id_mask = !((3u64) << desc_flags_shift);

        let mut entries = Vec::new();
        let mut cur_id = tail_id;
        let end_id = head_id;

        // Iterate through descriptors from tail to head
        loop {
            let desc_idx = cur_id % desc_count;
            let desc_addr = descs_ptr + desc_idx * desc_sz as u64;
            let info_addr = infos_ptr + desc_idx * info_sz as u64;

            // Read state_var to get descriptor state
            let state_var = {
                let data = layer.read(desc_addr + state_var_offset as u64, 8, false)?;
                LittleEndian::read_u64(&data)
            };
            let state = DescState::from(state_var >> desc_flags_shift);

            // Only process committed or finalized descriptors
            if state == DescState::Committed || state == DescState::Finalized {
                // Read text_blk_lpos
                let blk_lpos_addr = desc_addr + text_blk_lpos_offset as u64;
                let begin = {
                    let data = layer.read(blk_lpos_addr + begin_offset as u64, 8, false)?;
                    LittleEndian::read_u64(&data)
                };
                let next = {
                    let data = layer.read(blk_lpos_addr + next_offset as u64, 8, false)?;
                    LittleEndian::read_u64(&data)
                };

                // Read printk_info fields
                let ts_nsec = {
                    let data = layer.read(info_addr + info_ts_nsec_offset as u64, 8, false)?;
                    LittleEndian::read_u64(&data)
                };
                let text_len = {
                    let data = layer.read(info_addr + info_text_len_offset as u64, 2, false)?;
                    LittleEndian::read_u16(&data) as usize
                };
                // facility is at offset 18, level is a bitfield at offset 19 (bits 5-7)
                // Read two bytes at offset 18 to get both
                let (facility, level) = {
                    // Facility is u8 at offset 18
                    let facility_data = layer.read(info_addr + 18, 1, false)?;
                    let facility = facility_data[0] as usize;

                    // Level is a 3-bit bitfield at bit_position 5 within byte at offset 19
                    let level_data = layer.read(info_addr + 19, 1, false)?;
                    let level_byte = level_data[0];
                    // Extract bits 5-7 (3 bits): shift right by 5, mask with 0x7
                    let level = ((level_byte >> 5) & 0x7) as usize;

                    (facility, level)
                };
                let caller_id = if info_caller_id_offset > 0 {
                    let data = layer.read(info_addr + info_caller_id_offset as u64, 4, false)?;
                    Some(LittleEndian::read_u32(&data))
                } else {
                    None
                };

                // Calculate text position
                let begin_masked = begin % text_data_mask;
                let next_masked = next % text_data_mask;

                // Skip if this record doesn't contain text (begin & 1)
                if begin_masked & 1 != 0 {
                    cur_id = cur_id.wrapping_add(1) & desc_id_mask;
                    if cur_id == end_id.wrapping_add(1) & desc_id_mask {
                        break;
                    }
                    continue;
                }

                // Handle wrap-around
                let text_begin = if begin_masked > next_masked {
                    0
                } else {
                    begin_masked
                };

                // Each element in ringbuffer is "ID + data" (skip ID)
                let text_start = text_data_ptr + text_begin + ptr_sz as u64;
                let text_len =
                    std::cmp::min(text_len, (next_masked.saturating_sub(text_begin)) as usize);

                // Read text
                let text = if text_len > 0 && text_len < 8192 {
                    let data = layer.read(text_start, text_len, false)?;
                    String::from_utf8_lossy(&data).to_string()
                } else {
                    String::new()
                };

                // Get facility and level text
                let facility_txt = if facility < FACILITIES.len() {
                    FACILITIES[facility].to_string()
                } else {
                    facility.to_string()
                };
                let level_txt = if level < LEVELS.len() {
                    LEVELS[level].to_string()
                } else {
                    level.to_string()
                };

                // Get caller text
                let caller_txt = caller_id.map(|cid| {
                    let caller_name = if cid & 0x80000000 != 0 { "CPU" } else { "Task" };
                    format!("{}({})", caller_name, cid & !0x80000000)
                });

                // Split text into lines and yield each
                for line in text.lines() {
                    entries.push(KmsgEntry {
                        facility: facility_txt.clone(),
                        level: level_txt.clone(),
                        timestamp: ts_nsec,
                        caller: caller_txt.clone().unwrap_or_default(),
                        line: line.to_string(),
                    });
                }

                // Also check for SUBSYSTEM and DEVICE in dev_info
                // dev_printk_info: subsystem is 16 bytes at offset 0, device is 48 bytes at offset 16
                if info_dev_info_offset > 0 {
                    let dev_info_addr = info_addr + info_dev_info_offset as u64;

                    // Read subsystem (16 bytes at offset 0)
                    if let Ok(subsys_data) = layer.read(dev_info_addr, 16, false) {
                        let subsys = Self::read_cstring(&subsys_data);
                        if !subsys.is_empty() {
                            entries.push(KmsgEntry {
                                facility: facility_txt.clone(),
                                level: level_txt.clone(),
                                timestamp: ts_nsec,
                                caller: caller_txt.clone().unwrap_or_default(),
                                line: format!(" SUBSYSTEM={}", subsys),
                            });
                        }
                    }

                    // Read device (48 bytes at offset 16)
                    if let Ok(device_data) = layer.read(dev_info_addr + 16, 48, false) {
                        let device = Self::read_cstring(&device_data);
                        if !device.is_empty() {
                            entries.push(KmsgEntry {
                                facility: facility_txt.clone(),
                                level: level_txt.clone(),
                                timestamp: ts_nsec,
                                caller: caller_txt.unwrap_or_default(),
                                line: format!(" DEVICE={}", device),
                            });
                        }
                    }
                }
            }

            cur_id = cur_id.wrapping_add(1) & desc_id_mask;
            // Python: while cur_id != end_id - stop when we reach head_id
            if cur_id == end_id {
                break;
            }
        }

        Ok(entries)
    }

    fn read_kmsg_legacy(_context: &Context) -> Vol3Result<Vec<KmsgEntry>> {
        // TODO: Implement older kernel versions (pre-5.10)
        Ok(Vec::new())
    }

    fn get_field_offset(
        type_template: &vol3_symbols::types::TypeTemplate,
        field_name: &str,
    ) -> usize {
        use vol3_symbols::types::TypeTemplate;
        if let TypeTemplate::Struct(s) = type_template {
            s.get_field(field_name).map(|f| f.offset).unwrap_or(0)
        } else {
            0
        }
    }

    fn read_cstring(data: &[u8]) -> String {
        let len = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..len]).to_string()
    }
}

impl Default for Kmsg {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct KmsgEntry {
    facility: String,
    level: String,
    timestamp: u64,
    caller: String,
    line: String,
}

impl Module for Kmsg {
    fn name(&self) -> &str {
        "linux.kmsg.Kmsg"
    }

    fn description(&self) -> &str {
        "Reads the kernel log buffer"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Memory layer for the kernel")
            .symbol_table("vmlinux", "Linux kernel symbol table")
            .build();

        ModuleRequirements {
            name: self.name().to_string(),
            description: self.description().to_string(),
            requirements,
        }
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("facility", ColumnType::String),
            Column::new("level", ColumnType::String),
            Column::new("timestamp", ColumnType::String),
            Column::new("caller", ColumnType::String),
            Column::new("line", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::read_kmsg(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::String(e.facility),
                    CellValue::String(e.level),
                    CellValue::String(format!(
                        "{}.{:06}",
                        e.timestamp / 1_000_000_000,
                        (e.timestamp % 1_000_000_000) / 1000
                    )),
                    CellValue::String(e.caller),
                    CellValue::String(e.line),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
