//! Windows kernel callback enumeration for Windows 10/11 x64.
//!
//! The implementation mirrors the five data sources used by Volatility 3:
//! process/thread/image notify arrays, bugcheck lists, registry callbacks, and
//! callback-related pool allocations.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use vol3_core::error::{ConfigError, LayerError, PluginError, Vol3Error, Vol3Result};
use vol3_core::types::{AbsentValue, Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::intel::Intel32e;
use vol3_layers::scanner::MultiPatternScanner;
use vol3_layers::traits::DataLayer;
use vol3_symbols::{IntermediateSymbolTable, SymbolTableInterface};

use crate::callback_layout::{CallbackLayout, KernelCallbackLayout, ScalarFieldLayout};
use crate::module_resolver::ModuleResolver;
use crate::reader::{read_c_string, read_u64, read_unsigned};

const CALLBACK_TABLE: &str = "callback_symbols";
const KERNEL_TABLE: &str = "nt_symbols";
const MAX_LIST_ENTRIES: usize = 16_384;
const MAX_DETAIL_BYTES: usize = 1024;
const POOL_ALIGNMENT_X64: u64 = 0x10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackInfo {
    pub callback_type: String,
    pub callback: Address,
    pub module: Option<String>,
    pub symbol: Option<String>,
    pub detail: Option<String>,
}

pub struct Callbacks;

impl Callbacks {
    pub fn new() -> Self {
        Self
    }

    pub fn list_callbacks(context: &Context) -> Vol3Result<Vec<CallbackInfo>> {
        ensure_callback_symbols(context)?;
        let kernel_layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".into())))?;
        let kernel = context
            .get_layer(&kernel_layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(kernel_layer_name)))?;
        let kernel_base = context.config_get_int("kernel_virtual_offset").unwrap_or(0) as u64;
        let callback_layout = CallbackLayout::from_context(context, CALLBACK_TABLE)?;
        let kernel_layout = KernelCallbackLayout::from_context(context, KERNEL_TABLE)?;
        let kernel_symbols = context
            .get_symbol_table(KERNEL_TABLE)
            .ok_or_else(|| plugin_error("Windows kernel symbol table is not loaded"))?;
        let module_resolver = ModuleResolver::from_context(
            context,
            kernel.as_ref(),
            KERNEL_TABLE,
            kernel_base,
        )
        .unwrap_or_default();

        let mut raw = Vec::new();
        collect_notify_routines(
            kernel.as_ref(),
            kernel_symbols.as_ref(),
            kernel_base,
            &callback_layout,
            &mut raw,
        );
        collect_bugcheck_list(
            kernel.as_ref(),
            kernel_symbols.as_ref(),
            kernel_base,
            "KeBugCheckCallbackListHead",
            callback_layout.bugcheck_size,
            callback_layout.bugcheck_entry,
            callback_layout.bugcheck_routine,
            callback_layout.bugcheck_component,
            &mut raw,
        );
        collect_bugcheck_list(
            kernel.as_ref(),
            kernel_symbols.as_ref(),
            kernel_base,
            "KeBugCheckReasonCallbackListHead",
            callback_layout.bugcheck_reason_size,
            callback_layout.bugcheck_reason_entry,
            callback_layout.bugcheck_reason_routine,
            callback_layout.bugcheck_reason_component,
            &mut raw,
        );
        collect_registry_callbacks(
            kernel.as_ref(),
            kernel_symbols.as_ref(),
            kernel_base,
            &callback_layout,
            &kernel_layout,
            &mut raw,
        );
        collect_pool_callbacks(kernel.as_ref(), &callback_layout, &kernel_layout, &mut raw);
        collect_registered_io_callbacks(
            kernel.as_ref(),
            kernel_symbols.as_ref(),
            kernel_base,
            &callback_layout,
            &kernel_layout,
            &mut raw,
        );

        Ok(raw
            .into_iter()
            .map(|(callback_type, callback, detail)| {
                let (module, symbol) = module_resolver.resolve(kernel_symbols.as_ref(), callback);
                CallbackInfo {
                    callback_type,
                    callback,
                    module,
                    symbol,
                    detail,
                }
            })
            .collect())
    }
}

impl Default for Callbacks {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Callbacks {
    fn name(&self) -> &str {
        "windows.callbacks.Callbacks"
    }

    fn description(&self) -> &str {
        "Lists Windows kernel callback routines"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Windows kernel virtual memory layer")
            .symbol_table("nt_symbols", "Windows kernel ISF")
            .string("callback_symbols", "Volatility callbacks-x64 ISF")
            .build();
        ModuleRequirements {
            name: self.name().into(),
            description: self.description().into(),
            requirements,
        }
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Type", ColumnType::String),
            Column::new("Callback", ColumnType::Hex),
            Column::new("Module", ColumnType::String),
            Column::new("Symbol", ColumnType::String),
            Column::new("Detail", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let rows: Vec<Vol3Result<Row>> = Self::list_callbacks(&context)?
            .into_iter()
            .map(|entry| {
                Ok(vec![
                    CellValue::String(entry.callback_type),
                    CellValue::Hex(entry.callback),
                    optional_string(entry.module),
                    optional_string(entry.symbol),
                    optional_string(entry.detail),
                ])
            })
            .collect();
        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["windows"]
    }
}

type RawCallback = (String, Address, Option<String>);

fn collect_notify_routines(
    layer: &dyn DataLayer,
    symbols: &dyn SymbolTableInterface,
    kernel_base: Address,
    layout: &CallbackLayout,
    output: &mut Vec<RawCallback>,
) {
    for (name, count) in [
        ("PspLoadImageNotifyRoutine", 8usize),
        ("PspCreateThreadNotifyRoutine", 64usize),
        ("PspCreateProcessNotifyRoutine", 64usize),
    ] {
        let Ok(symbol) = symbols.get_symbol(name) else {
            continue;
        };
        let array = kernel_base.wrapping_add(symbol.address);
        for index in 0..count {
            let Ok(fast_ref) = read_u64(layer, array + index as u64 * 8) else {
                continue;
            };
            let block = fast_ref & !0xf;
            if block == 0 {
                continue;
            }
            let Ok(callback) = read_u64(layer, block + layout.generic_callback as u64) else {
                continue;
            };
            if callback != 0 {
                output.push((name.to_string(), callback, None));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_bugcheck_list(
    layer: &dyn DataLayer,
    symbols: &dyn SymbolTableInterface,
    kernel_base: Address,
    symbol_name: &str,
    record_size: usize,
    entry_offset: usize,
    routine_offset: usize,
    component_offset: usize,
    output: &mut Vec<RawCallback>,
) {
    let Ok(symbol) = symbols.get_symbol(symbol_name) else {
        return;
    };
    let head = kernel_base.wrapping_add(symbol.address);
    walk_list(
        layer,
        head,
        entry_offset,
        record_size,
        |record| {
            let callback = read_u64(layer, record + routine_offset as u64).ok()?;
            if callback == 0 || !layer.is_valid(callback, 64) {
                return None;
            }
            let component = if symbol_name == "KeBugCheckCallbackListHead" {
                // The reference renderer treats the classic bugcheck
                // component pointer as unavailable on the supported Windows
                // 10/11 layouts.  Do not promote a stale-but-readable string
                // to a semantic Detail value.
                None
            } else {
                read_u64(layer, record + component_offset as u64)
                    .ok()
                    .filter(|address| *address != 0)
                    .and_then(|address| read_c_string(layer, address, 64).ok())
            };
            Some((symbol_name.to_string(), callback, component))
        },
        output,
    );
}

fn collect_registry_callbacks(
    layer: &dyn DataLayer,
    symbols: &dyn SymbolTableInterface,
    kernel_base: Address,
    callback_layout: &CallbackLayout,
    kernel_layout: &KernelCallbackLayout,
    output: &mut Vec<RawCallback>,
) {
    let Ok(count_symbol) = symbols.get_symbol("CmpCallBackCount") else {
        return;
    };
    let count = read_unsigned(layer, kernel_base.wrapping_add(count_symbol.address), 4)
        .unwrap_or(0)
        .min(MAX_LIST_ENTRIES as u64) as usize;
    if count == 0 {
        return;
    }
    if let Ok(vector) = symbols.get_symbol("CmpCallBackVector") {
        let address = kernel_base.wrapping_add(vector.address);
        for index in 0..count {
            let Ok(fast_ref) = read_u64(layer, address + index as u64 * 8) else {
                continue;
            };
            let block = fast_ref & !0xf;
            let Ok(callback) = read_u64(layer, block + callback_layout.ex_callback_function as u64)
            else {
                continue;
            };
            if callback != 0 {
                output.push(("CmRegisterCallback".into(), callback, None));
            }
        }
        return;
    }
    let Ok(list_symbol) = symbols.get_symbol("CallbackListHead") else {
        return;
    };
    let head = kernel_base.wrapping_add(list_symbol.address);
    let mut taken = 0usize;
    walk_list(
        layer,
        head,
        callback_layout.cm_link,
        callback_layout.cm_altitude + 16,
        |record| {
            if taken >= count {
                return None;
            }
            taken += 1;
            let callback = read_u64(layer, record + callback_layout.cm_function as u64).ok()?;
            if callback == 0 {
                return None;
            }
            let altitude = read_unicode_string(
                layer,
                record + callback_layout.cm_altitude as u64,
                kernel_layout,
            )
            .unwrap_or_else(|| "None".to_string());
            Some((
                "CmRegisterCallbackEx".into(),
                callback,
                Some(format!("Altitude: {altitude}")),
            ))
        },
        output,
    );
}

fn walk_list<F>(
    layer: &dyn DataLayer,
    head: Address,
    entry_offset: usize,
    record_size: usize,
    mut decode: F,
    output: &mut Vec<RawCallback>,
) where
    F: FnMut(Address) -> Option<RawCallback>,
{
    let Ok(mut entry) = read_u64(layer, head) else {
        return;
    };
    let mut seen = HashSet::new();
    for _ in 0..MAX_LIST_ENTRIES {
        if entry == 0 || entry == head || !seen.insert(entry) {
            break;
        }
        let Some(record) = entry.checked_sub(entry_offset as u64) else {
            break;
        };
        if !layer.is_valid(record, record_size) {
            break;
        }
        let next = read_u64(layer, entry).ok();
        if let Some(value) = decode(record) {
            output.push(value);
        }
        let Some(next) = next else {
            break;
        };
        entry = next;
    }
}

fn collect_pool_callbacks(
    kernel: &dyn DataLayer,
    callback_layout: &CallbackLayout,
    kernel_layout: &KernelCallbackLayout,
    output: &mut Vec<RawCallback>,
) {
    let patterns = [
        b"IoFs", b"IoSh", b"Cbrb", b"DbCb", b"Pnp9", b"PnpD", b"PnpC",
    ]
    .into_iter()
    .map(|value| value.to_vec())
    .collect();
    let scanner = MultiPatternScanner::new(patterns);
    if let Some(layer) = kernel.as_any().downcast_ref::<Intel32e>() {
        // Volatility scans the complete primary Windows layer.  The System
        // DTB can contain user-half mappings too, and a few pool candidates
        // in the reference output live there.
        // Callback pool allocations are kernel objects.  Restricting the scan
        // to the canonical kernel half avoids interpreting user-process text
        // pages as pool headers while retaining all legitimate callbacks.
        let _ = layer.scan_mapped_with(&scanner, true, |(tag_address, tag)| {
            if let Some(value) =
                decode_pool_match(kernel, callback_layout, kernel_layout, tag_address, &tag)
            {
                output.push(value);
            }
        });
    } else {
        for (tag_address, tag) in kernel.scan(&scanner, None, None) {
            if let Some(value) =
                decode_pool_match(kernel, callback_layout, kernel_layout, tag_address, &tag)
            {
                output.push(value);
            }
        }
    }
}

/// Recover live I/O callbacks from their authoritative kernel lists.
///
/// Volatility discovers these records through pool scanning.  Walking the
/// lists as a complementary source recovers packets whose pool page is not
/// exposed by a simple present/transition PTE walk (notably VMware captures),
/// while the identity check prevents duplicates with pool-scan results.
fn collect_registered_io_callbacks(
    kernel: &dyn DataLayer,
    symbols: &dyn SymbolTableInterface,
    kernel_base: Address,
    callback_layout: &CallbackLayout,
    kernel_layout: &KernelCallbackLayout,
    output: &mut Vec<RawCallback>,
) {
    if let Ok(symbol) = symbols.get_symbol("IopFsNotifyChangeQueueHead") {
        let head = kernel_base.wrapping_add(symbol.address);
        let mut recovered = Vec::new();
        walk_list(
            kernel,
            head,
            callback_layout.notification_list_entry,
            callback_layout.notification_size,
            |record| {
                let callback =
                    read_u64(kernel, record + callback_layout.notification_routine as u64).ok()?;
                Some(("IoRegisterFsRegistrationChange".into(), callback, None))
            },
            &mut recovered,
        );
        append_unique(output, recovered);
    }

    for symbol_name in [
        "IopNotifyShutdownQueueHead",
        "IopNotifyLastChanceShutdownQueueHead",
    ] {
        let Ok(symbol) = symbols.get_symbol(symbol_name) else {
            continue;
        };
        let head = kernel_base.wrapping_add(symbol.address);
        let mut recovered = Vec::new();
        walk_list(
            kernel,
            head,
            callback_layout.shutdown_entry,
            callback_layout.shutdown_size,
            |record| {
                let (callback_type, callback, _detail) = decode_shutdown(
                    kernel,
                    record,
                    callback_layout,
                    kernel_layout,
                );
                // This fallback walks the authoritative list only to recover
                // records missed by pool scanning.  Volatility obtains Detail
                // from the pool object; claiming a driver name here would make
                // a recovered row look more complete than the reference row.
                Some((callback_type, callback, None))
            },
            &mut recovered,
        );
        append_unique(output, recovered);
    }
}

fn append_unique(output: &mut Vec<RawCallback>, recovered: Vec<RawCallback>) {
    for value in recovered {
        if !output
            .iter()
            .any(|existing| existing.0 == value.0 && existing.1 == value.1)
        {
            output.push(value);
        }
    }
}

fn decode_pool_match(
    kernel: &dyn DataLayer,
    callback_layout: &CallbackLayout,
    kernel_layout: &KernelCallbackLayout,
    tag_address: Address,
    tag: &[u8],
) -> Option<RawCallback> {
    let header = tag_address.checked_sub(kernel_layout.pool_tag as u64)?;
    // Volatility uses the x64 alignment to convert BlockSize into bytes, but
    // PoolHeaderScanner does not reject a hit merely because its virtual
    // address is not alignment-divisible.  Enforcing that extra condition
    // dropped real callback records in captured images.
    let block_size =
        read_scalar_field(kernel, header, kernel_layout.pool_block_size)? * POOL_ALIGNMENT_X64;
    let pool_index = read_scalar_field(kernel, header, kernel_layout.pool_index)?;
    let body = header + kernel_layout.pool_header_size as u64;
    match tag {
        b"IoFs" if block_size >= callback_layout.notification_size as u64 => {
            read_u64(kernel, body + callback_layout.notification_routine as u64)
                .ok()
                .map(|value| ("IoRegisterFsRegistrationChange".into(), value, None))
        }
        // Volatility's (0, 0) PoolIndex constraint acts as an unbounded value:
        // both bounds are falsey and therefore are not tested.  Mirroring that
        // behaviour is required for callback equivalence on real captures.
        b"IoSh" if block_size >= callback_layout.shutdown_size as u64 => Some(decode_shutdown(
            kernel,
            body,
            callback_layout,
            kernel_layout,
        )),
        b"Cbrb" if block_size >= callback_layout.generic_size as u64 => {
            read_u64(kernel, body + callback_layout.generic_callback as u64)
                .ok()
                .map(|value| ("GenericKernelCallback".into(), value, None))
        }
        b"DbCb" if (0x20..=0x40).contains(&block_size) => {
            read_u64(kernel, body + callback_layout.dbgprint_function as u64)
                .ok()
                .map(|value| ("DbgSetDebugPrintCallback".into(), value, None))
        }
        b"Pnp9" if block_size >= 0x30 && pool_index == 1 => {
            decode_pnp(kernel, body, callback_layout)
        }
        b"PnpD" if block_size >= 0x40 && pool_index == 1 => {
            decode_pnp(kernel, body, callback_layout)
        }
        b"PnpC" if block_size >= 0x38 && pool_index == 1 => {
            decode_pnp(kernel, body, callback_layout)
        }
        _ => None,
    }
}

fn decode_pnp(
    physical: &dyn DataLayer,
    body: Address,
    layout: &CallbackLayout,
) -> Option<RawCallback> {
    let category = read_unsigned(physical, body + layout.notify_event_category as u64, 4).ok()?;
    let callback = read_u64(physical, body + layout.notify_callback as u64).ok()?;
    if callback == 0 {
        return None;
    }
    let callback_type = match category {
        0 => "EventCategoryReserved",
        1 => "EventCategoryHardwareProfileChange",
        2 => "EventCategoryDeviceInterfaceChange",
        3 => "EventCategoryTargetDeviceChange",
        4 => "EventCategoryKernelSoftRestart",
        _ => return None,
    };
    Some((callback_type.into(), callback, None))
}

fn decode_shutdown(
    kernel: &dyn DataLayer,
    body: Address,
    callback_layout: &CallbackLayout,
    kernel_layout: &KernelCallbackLayout,
) -> RawCallback {
    let parsed = (|| {
        let device = read_u64(kernel, body + callback_layout.shutdown_device as u64).ok()?;
        let driver = read_u64(kernel, device + kernel_layout.device_driver as u64).ok()?;
        let callback = read_u64(
            kernel,
            driver + kernel_layout.driver_major_function as u64 + 16 * 8,
        )
        .ok()?;
        let detail = read_unicode_string(
            kernel,
            driver + kernel_layout.driver_name as u64,
            kernel_layout,
        )
        .filter(|name| name.starts_with('\\'));
        Some((callback, detail))
    })();
    let (callback, detail) = parsed.unwrap_or((body, None));
    ("IoRegisterShutdownNotification".into(), callback, detail)
}

fn read_unicode_string(
    layer: &dyn DataLayer,
    address: Address,
    layout: &KernelCallbackLayout,
) -> Option<String> {
    let length = read_unsigned(
        layer,
        address + layout.unicode_length.0 as u64,
        layout.unicode_length.1,
    )
    .ok()? as usize;
    if length == 0 || length > MAX_DETAIL_BYTES || length % 2 != 0 {
        return None;
    }
    let buffer = read_u64(layer, address + layout.unicode_buffer as u64).ok()?;
    let bytes = layer.read(buffer, length, false).ok()?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

fn read_scalar_field(
    layer: &dyn DataLayer,
    base: Address,
    field: ScalarFieldLayout,
) -> Option<u64> {
    let storage = read_unsigned(layer, base + field.offset as u64, field.storage_size).ok()?;
    let mask = if field.bit_length >= 64 {
        u64::MAX
    } else {
        (1u64 << field.bit_length) - 1
    };
    Some((storage >> field.bit_offset) & mask)
}

fn ensure_callback_symbols(context: &Context) -> Vol3Result<()> {
    if context.has_symbol_table(CALLBACK_TABLE) {
        return Ok(());
    }
    let path = context
        .config_get_string("plugins.windows.callbacks.callback_symbols")
        .ok_or_else(|| {
            Vol3Error::Config(ConfigError::KeyNotFound(
                "plugins.windows.callbacks.callback_symbols".into(),
            ))
        })?;
    let table = IntermediateSymbolTable::from_path(Path::new(&path), CALLBACK_TABLE)?;
    context.add_symbol_table(Arc::new(table));
    Ok(())
}

fn optional_string(value: Option<String>) -> CellValue {
    value
        .map(CellValue::String)
        .unwrap_or(CellValue::Absent(AbsentValue::NotAvailable))
}

fn plugin_error(message: impl Into<String>) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vol3_layers::physical::BufferLayer;

    fn callback_layout() -> CallbackLayout {
        CallbackLayout {
            generic_size: 16,
            generic_callback: 0,
            notification_size: 24,
            notification_list_entry: 0,
            notification_routine: 16,
            shutdown_size: 32,
            shutdown_entry: 0,
            shutdown_device: 16,
            dbgprint_function: 0,
            notify_event_category: 0,
            notify_callback: 8,
            notify_driver: 16,
            ex_callback_function: 0,
            cm_link: 0,
            cm_function: 16,
            cm_altitude: 24,
            bugcheck_size: 32,
            bugcheck_entry: 0,
            bugcheck_routine: 16,
            bugcheck_component: 24,
            bugcheck_reason_size: 32,
            bugcheck_reason_entry: 0,
            bugcheck_reason_routine: 16,
            bugcheck_reason_component: 24,
        }
    }

    fn kernel_layout() -> KernelCallbackLayout {
        KernelCallbackLayout {
            pool_header_size: 16,
            pool_tag: 4,
            pool_block_size: ScalarFieldLayout {
                offset: 2,
                storage_size: 1,
                bit_offset: 0,
                bit_length: 8,
            },
            pool_index: ScalarFieldLayout {
                offset: 3,
                storage_size: 1,
                bit_offset: 0,
                bit_length: 8,
            },
            unicode_length: (0, 2),
            unicode_buffer: 8,
            device_driver: 8,
            driver_start: Some(16),
            driver_name: 24,
            driver_major_function: 32,
        }
    }

    #[test]
    fn accepts_unaligned_pool_header_like_volatility() {
        let mut data = vec![0u8; 0x400];
        let header = 0x101usize;
        data[header + 2] = 2;
        let callback = 0xffff_f800_1234_5000u64;
        data[header + 16..header + 24].copy_from_slice(&callback.to_le_bytes());
        let layer = BufferLayer::new("test", data);
        let result = decode_pool_match(
            &layer,
            &callback_layout(),
            &kernel_layout(),
            (header + 4) as u64,
            b"Cbrb",
        )
        .unwrap();
        assert_eq!(result.1, callback);
    }

    #[test]
    fn zero_zero_pool_index_constraint_is_unbounded() {
        let mut data = vec![0u8; 0x400];
        let header = 0x100usize;
        data[header + 2] = 4;
        data[header + 3] = 7;
        let layer = BufferLayer::new("test", data);
        let result = decode_pool_match(
            &layer,
            &callback_layout(),
            &kernel_layout(),
            (header + 4) as u64,
            b"IoSh",
        )
        .unwrap();
        assert_eq!(result.0, "IoRegisterShutdownNotification");
    }
}
