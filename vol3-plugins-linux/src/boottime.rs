//! Linux Boottime plugin.
//!
//! Shows the time the system was started.

use std::sync::Arc;

use chrono::{TimeZone, Utc};
use vol3_core::error::{ConfigError, Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;

use crate::helpers;

/// Boottime plugin - shows system boot time
pub struct Boottime;

impl Boottime {
    pub fn new() -> Self {
        Self
    }

    fn get_boottime(context: &Context) -> Vol3Result<Vec<BoottimeEntry>> {
        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let layer = context.get_layer(&layer_name).ok_or_else(|| {
            Vol3Error::Layer(vol3_core::error::LayerError::NotFound(layer_name.clone()))
        })?;

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        // Get boottime nanoseconds from tk_core
        let boottime_ns = match helpers::get_boottime_ns(context, layer.as_ref(), &symbol_table) {
            Some(ns) => ns,
            None => {
                log::warn!("Failed to get boottime from tk_core");
                return Ok(Vec::new());
            }
        };

        // Get time namespace ID from init_time_ns symbol
        // For kernel >= 5.6, this is the root time namespace inode number
        let time_ns_id = get_init_time_ns_inum(context, layer.as_ref(), &symbol_table);
        log::debug!("init_time_ns inum: {}", time_ns_id);

        // Convert boottime_ns to UTC datetime string
        let boottime_str = boottime_ns_to_utc(boottime_ns);

        let mut entries = Vec::new();
        entries.push(BoottimeEntry {
            time_ns: time_ns_id,
            boottime: boottime_str,
        });

        Ok(entries)
    }
}

/// Get time namespace ID from task's nsproxy
fn get_time_namespace_id(
    context: &Context,
    layer: &dyn DataLayer,
    symbol_table: &str,
    task_addr: u64,
) -> u64 {
    // Get nsproxy offset in task_struct
    let nsproxy_offset = get_field_offset(context, symbol_table, "task_struct", "nsproxy");
    log::debug!("nsproxy offset in task_struct: {}", nsproxy_offset);

    // Read nsproxy pointer
    let nsproxy_addr = match helpers::read_pointer(layer, task_addr + nsproxy_offset) {
        Ok(p) => p,
        Err(e) => {
            log::debug!("Failed to read nsproxy pointer: {:?}", e);
            return 0;
        }
    };
    log::debug!("nsproxy_addr: {:#x}", nsproxy_addr);

    if nsproxy_addr == 0 || !helpers::is_valid_kernel_address(nsproxy_addr) {
        log::debug!("Invalid nsproxy_addr");
        return 0;
    }

    // Get time_ns offset in nsproxy
    // For kernels >= 5.6, nsproxy has time_ns member
    let time_ns_offset = get_field_offset(context, symbol_table, "nsproxy", "time_ns");
    log::debug!("time_ns offset in nsproxy: {}", time_ns_offset);
    if time_ns_offset == 0 {
        // Kernel < 5.6, no time namespace support
        log::debug!("time_ns offset is 0, checking init_time_ns");
        return get_init_time_ns_inum(context, layer, symbol_table);
    }

    // Read time_ns pointer
    let time_ns_addr = match helpers::read_pointer(layer, nsproxy_addr + time_ns_offset) {
        Ok(p) => p,
        Err(e) => {
            log::debug!("Failed to read time_ns pointer: {:?}", e);
            return 0;
        }
    };
    log::debug!("time_ns_addr: {:#x}", time_ns_addr);

    if time_ns_addr == 0 || !helpers::is_valid_kernel_address(time_ns_addr) {
        log::debug!("Invalid time_ns_addr");
        return 0;
    }

    // Get ns.inum offset in time_namespace
    // time_namespace has ns_common ns at offset 0, ns_common has inum
    let inum_offset = get_field_offset(context, symbol_table, "ns_common", "inum");
    log::debug!("inum offset in ns_common: {}", inum_offset);

    // Read inum (u32)
    let inum_bytes = match layer.read(time_ns_addr + inum_offset, 4, false) {
        Ok(b) => b,
        Err(e) => {
            log::debug!("Failed to read inum: {:?}", e);
            return 0;
        }
    };
    let inum = u32::from_le_bytes(inum_bytes.try_into().unwrap_or([0; 4])) as u64;
    log::debug!("inum: {}", inum);
    inum
}

/// Get field offset from type template
fn get_field_offset(
    context: &Context,
    symbol_table: &str,
    type_name: &str,
    field_name: &str,
) -> u64 {
    if let Ok(template) = context.get_type(symbol_table, type_name) {
        if let vol3_symbols::TypeTemplate::Struct(s) = template.as_ref() {
            if let Some(field) = s.get_field(field_name) {
                return field.offset as u64;
            }
        }
    }
    0
}

/// Get init_time_ns inode number for kernels < 5.6
fn get_init_time_ns_inum(context: &Context, layer: &dyn DataLayer, symbol_table: &str) -> u64 {
    // Try to read from init_time_ns symbol
    match context.get_symbol(symbol_table, "init_time_ns") {
        Ok(sym) => {
            log::debug!("init_time_ns symbol found at address: {:#x}", sym.address);
            let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;
            log::debug!("aslr_shift: {:#x}", aslr_shift);
            let addr = sym.address.wrapping_add(aslr_shift);
            log::debug!("init_time_ns addr with ASLR: {:#x}", addr);

            // time_namespace structure:
            // struct time_namespace {
            //     struct user_namespace *user_ns;  // offset 0
            //     struct ucounts *ucounts;         // offset 8
            //     struct ns_common ns;             // offset 16  <-- NOT 0!
            //     ...
            // }
            // struct ns_common {
            //     struct rb_node stashed;          // offset 0
            //     struct proc_ns_operations *ops;  // offset 8
            //     unsigned int inum;               // offset 16
            //     ...
            // }

            // Get offset of 'ns' in time_namespace
            let ns_offset = get_field_offset(context, symbol_table, "time_namespace", "ns");
            log::debug!("time_namespace.ns offset: {}", ns_offset);

            // Get offset of 'inum' in ns_common
            let inum_offset = get_field_offset(context, symbol_table, "ns_common", "inum");
            log::debug!("ns_common.inum offset: {}", inum_offset);

            // Total offset = ns_offset + inum_offset
            let total_offset = ns_offset + inum_offset;
            let read_addr = addr + total_offset;
            log::debug!(
                "Reading inum from: {:#x} (total offset: {})",
                read_addr,
                total_offset
            );

            match layer.read(read_addr, 4, false) {
                Ok(inum_bytes) => {
                    let inum = u32::from_le_bytes(inum_bytes.try_into().unwrap_or([0; 4])) as u64;
                    log::debug!("inum value: {}", inum);
                    return inum;
                }
                Err(e) => {
                    log::debug!("Failed to read inum: {:?}", e);
                }
            }
        }
        Err(e) => {
            log::debug!("init_time_ns symbol not found: {:?}", e);
        }
    }

    // Default INIT_TIME_NS_INUM
    log::debug!("Returning default INIT_TIME_NS_INUM: 0xF0000006");
    0xF0000006
}

/// Convert boottime nanoseconds to UTC datetime string
fn boottime_ns_to_utc(boottime_ns: i64) -> String {
    // boottime_ns is nanoseconds since Unix epoch.
    // Match Python path used by volatility:
    // datetime.fromtimestamp(boottime_ns / 1e9, timezone.utc)
    // which performs float conversion before microsecond rounding.
    let ts = boottime_ns as f64 / 1_000_000_000.0;
    let mut secs = ts.floor() as i64;
    let frac = ts - (secs as f64);

    let mut micros = (frac * 1_000_000.0).round() as i64;
    if micros >= 1_000_000 {
        micros = 0;
        secs += 1;
    } else if micros < 0 {
        micros = 0;
    }

    let nanos_rounded = (micros as u32) * 1_000;

    match Utc.timestamp_opt(secs, nanos_rounded) {
        chrono::LocalResult::Single(dt) => {
            // Format to match Python: "2026-01-27 17:12:29.978312 UTC"
            dt.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string()
        }
        _ => "N/A".to_string(),
    }
}

impl Default for Boottime {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct BoottimeEntry {
    time_ns: u64,
    boottime: String,
}

impl Module for Boottime {
    fn name(&self) -> &str {
        "linux.boottime.Boottime"
    }

    fn description(&self) -> &str {
        "Shows the time the system was started"
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
            Column::new("TIME NS", ColumnType::Int),
            Column::new("Boot Time", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::get_boottime(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.time_ns as i64),
                    CellValue::String(e.boottime),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
