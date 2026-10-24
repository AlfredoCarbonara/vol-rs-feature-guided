//! Windows PsList plugin.
//!
//! Enumerates `_EPROCESS` records through `PsActiveProcessHead` and
//! `_EPROCESS.ActiveProcessLinks`, matching the active-list view used by
//! Volatility's Windows PsList plugin.

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use log::{debug, warn};

use vol3_core::error::{ConfigError, LayerError, PluginError, Vol3Error, Vol3Result};
use vol3_core::types::{AbsentValue, Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;

use crate::layout::EprocessLayout;
use crate::reader::{filetime_to_utc, read_c_string, read_u64, read_unsigned};

const DEFAULT_SYMBOL_TABLE: &str = "nt_symbols";
const MAX_PROCESSES: usize = 65_536;

/// A process record extracted from an `_EPROCESS` object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub eprocess: Address,
    pub pid: u64,
    pub ppid: u64,
    pub image_file_name: String,
    pub threads: u64,
    pub handles: Option<u64>,
    pub session_id: Option<u64>,
    pub wow64: Option<bool>,
    pub create_time: Option<DateTime<Utc>>,
    pub exit_time: Option<DateTime<Utc>>,
}

/// Lists processes linked through the Windows active process list.
pub struct PsList;

impl PsList {
    pub fn new() -> Self {
        Self
    }

    /// Enumerate Windows processes for reuse by later `handles` extractors.
    pub fn list_processes(context: &Context) -> Vol3Result<Vec<ProcessInfo>> {
        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;
        let layer = context
            .get_layer(&layer_name)
            .ok_or(Vol3Error::Layer(LayerError::NotFound(layer_name)))?;
        let symbol_table = context
            .config_get_string("nt_symbols")
            .unwrap_or_else(|| DEFAULT_SYMBOL_TABLE.to_string());
        let kernel_virtual_offset =
            context.config_get_int("kernel_virtual_offset").unwrap_or(0) as u64;

        let layout = EprocessLayout::from_context(context, &symbol_table)?;
        let list_symbol = context.get_symbol(&symbol_table, "PsActiveProcessHead")?;
        let list_head = list_symbol
            .address
            .checked_add(kernel_virtual_offset)
            .ok_or_else(|| plugin_error("PsActiveProcessHead address overflow"))?;

        debug!(
            "PsActiveProcessHead symbol={:#x}, kernel offset={:#x}, list head={:#x}",
            list_symbol.address, kernel_virtual_offset, list_head
        );
        walk_active_process_list(layer.as_ref(), list_head, &layout)
    }
}

impl Default for PsList {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for PsList {
    fn name(&self) -> &str {
        "windows.pslist.PsList"
    }

    fn description(&self) -> &str {
        "Lists processes in the Windows active process linked list"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Windows kernel virtual memory layer")
            .symbol_table("nt_symbols", "Windows kernel ISF symbol table")
            .int_optional("pid", "Filter by process ID")
            .int_optional(
                "kernel_virtual_offset",
                "Kernel virtual offset added to relative ISF symbols",
            )
            .build();

        ModuleRequirements {
            name: self.name().to_string(),
            description: self.description().to_string(),
            requirements,
        }
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("PID", ColumnType::Int),
            Column::new("PPID", ColumnType::Int),
            Column::new("ImageFileName", ColumnType::String),
            Column::new("Offset(V)", ColumnType::Hex),
            Column::new("Threads", ColumnType::Int),
            Column::new("Handles", ColumnType::Int),
            Column::new("SessionId", ColumnType::Int),
            Column::new("Wow64", ColumnType::Bool),
            Column::new("CreateTime", ColumnType::DateTime),
            Column::new("ExitTime", ColumnType::DateTime),
            Column::new("File output", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let pid_filter = context
            .config_get_int("plugins.windows.pslist.pid")
            .map(|value| value as u64);
        let processes = Self::list_processes(&context)?;
        let rows: Vec<Vol3Result<Row>> = processes
            .into_iter()
            .filter(|process| pid_filter.map(|pid| process.pid == pid).unwrap_or(true))
            .map(|process| {
                Ok(vec![
                    CellValue::UInt(process.pid),
                    CellValue::UInt(process.ppid),
                    CellValue::String(process.image_file_name),
                    CellValue::Hex(process.eprocess),
                    CellValue::UInt(process.threads),
                    process
                        .handles
                        .map(CellValue::UInt)
                        .unwrap_or_else(unavailable),
                    process
                        .session_id
                        .map(CellValue::UInt)
                        .unwrap_or_else(unavailable),
                    process
                        .wow64
                        .map(CellValue::Bool)
                        .unwrap_or_else(unavailable),
                    process
                        .create_time
                        .map(CellValue::DateTime)
                        .unwrap_or_else(unavailable),
                    process
                        .exit_time
                        .map(CellValue::DateTime)
                        .unwrap_or_else(unavailable),
                    CellValue::String("Disabled".to_string()),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["windows"]
    }
}

fn walk_active_process_list(
    layer: &dyn DataLayer,
    list_head: Address,
    layout: &EprocessLayout,
) -> Vol3Result<Vec<ProcessInfo>> {
    if !layer.is_valid(list_head, 8) {
        return Err(plugin_error(format!(
            "PsActiveProcessHead is invalid in layer {}: {list_head:#x}",
            layer.name()
        )));
    }

    let mut emitted_processes = HashSet::new();
    let mut processes = Vec::new();

    // Volatility traverses both Flink and Blink and deduplicates EPROCESS
    // offsets. The reverse pass can retain records when one direction is
    // affected by acquisition smearing.
    for next_pointer_offset in [0_u64, 8_u64] {
        walk_direction(
            layer,
            list_head,
            next_pointer_offset,
            layout,
            &mut emitted_processes,
            &mut processes,
        )?;
    }

    Ok(processes)
}

fn walk_direction(
    layer: &dyn DataLayer,
    list_head: Address,
    next_pointer_offset: u64,
    layout: &EprocessLayout,
    emitted_processes: &mut HashSet<Address>,
    processes: &mut Vec<ProcessInfo>,
) -> Vol3Result<()> {
    let mut current_link = read_u64(layer, list_head + next_pointer_offset)?;
    let mut direction_seen = HashSet::new();

    while current_link != list_head {
        if current_link == 0 {
            warn!("Windows active process list ended at a null pointer");
            break;
        }
        if !direction_seen.insert(current_link) {
            // Match Volatility's LIST_ENTRY extension: acquisition smearing or
            // corruption may form a smaller cycle that never reaches the
            // symbolic list head.  Stop this direction at the first repeated
            // link, while retaining all unique records already recovered.
            warn!("Cycle in active process list stopped at repeated link {current_link:#x}");
            break;
        }
        if direction_seen.len() > MAX_PROCESSES {
            return Err(plugin_error(format!(
                "Active process list exceeded safety limit of {MAX_PROCESSES} entries"
            )));
        }

        let eprocess = current_link
            .checked_sub(layout.active_process_links as u64)
            .ok_or_else(|| plugin_error("ActiveProcessLinks underflow"))?;
        if !layer.is_valid(eprocess, layout.size.max(1)) {
            return Err(plugin_error(format!(
                "Invalid _EPROCESS address derived from list entry: {eprocess:#x}"
            )));
        }

        if emitted_processes.insert(eprocess) {
            processes.push(read_process(layer, eprocess, layout)?);
        }
        current_link = read_u64(layer, current_link + next_pointer_offset)?;
    }

    Ok(())
}

fn read_process(
    layer: &dyn DataLayer,
    eprocess: Address,
    layout: &EprocessLayout,
) -> Vol3Result<ProcessInfo> {
    let pid = read_unsigned(
        layer,
        eprocess + layout.unique_process_id as u64,
        layout.unique_process_id_size,
    )?;
    let ppid = read_unsigned(
        layer,
        eprocess + layout.inherited_from_unique_process_id as u64,
        layout.inherited_from_unique_process_id_size,
    )?;
    let image_file_name = read_c_string(
        layer,
        eprocess + layout.image_file_name as u64,
        layout.image_file_name_size,
    )?;
    let threads = read_unsigned(
        layer,
        eprocess + layout.active_threads as u64,
        layout.active_threads_size,
    )?;

    let handles = match (layout.object_table, layout.handle_count) {
        (Some(object_table_offset), Some(handle_count_offset)) => {
            let object_table = read_u64(layer, eprocess + object_table_offset as u64)?;
            if object_table == 0 || !layer.is_valid(object_table + handle_count_offset as u64, 4) {
                None
            } else {
                Some(read_unsigned(
                    layer,
                    object_table + handle_count_offset as u64,
                    4,
                )?)
            }
        }
        _ => None,
    };

    let session_id = if let Some((offset, size)) = layout.direct_session_id {
        Some(read_unsigned(layer, eprocess + offset as u64, size)?)
    } else if let (Some(session_offset), Some((id_offset, id_size))) =
        (layout.session, layout.session_space_id)
    {
        let session = read_u64(layer, eprocess + session_offset as u64)?;
        let id_address = session.saturating_add(id_offset as u64);
        if session == 0 || !layer.is_valid(id_address, id_size) {
            None
        } else {
            Some(read_unsigned(layer, id_address, id_size)?)
        }
    } else {
        None
    };
    let wow64 = layout
        .wow64_process
        .map(|offset| read_u64(layer, eprocess + offset as u64).map(|value| value != 0))
        .transpose()?;
    let create_time = layout
        .create_time
        .map(|offset| read_u64(layer, eprocess + offset as u64).map(filetime_to_utc))
        .transpose()?
        .flatten();
    let exit_time = layout
        .exit_time
        .map(|offset| read_u64(layer, eprocess + offset as u64).map(filetime_to_utc))
        .transpose()?
        .flatten();

    Ok(ProcessInfo {
        eprocess,
        pid,
        ppid,
        image_file_name,
        threads,
        handles,
        session_id,
        wow64,
        create_time,
        exit_time,
    })
}

fn unavailable() -> CellValue {
    CellValue::Absent(AbsentValue::NotAvailable)
}

fn plugin_error(message: impl Into<String>) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message.into()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use byteorder::{ByteOrder, LittleEndian};
    use vol3_core::error::{SymbolError, SymbolResult};
    use vol3_framework::module::Module;
    use vol3_layers::physical::BufferLayer;
    use vol3_symbols::{
        Enumeration, FieldInfo, StructTemplate, Symbol, SymbolTableInterface, TypeTemplate,
    };

    use super::*;

    const HEAD: usize = 0x100;
    const PROCESS_ONE: usize = 0x1000;
    const PROCESS_TWO: usize = 0x2000;
    const ACTIVE_LINKS: usize = 0x20;
    const HANDLE_TABLE_ONE: usize = 0x3000;
    const HANDLE_TABLE_TWO: usize = 0x3100;
    const WINDOWS_EPOCH: u64 = 116_444_736_000_000_000;

    struct TestSymbolTable {
        symbols: HashMap<String, Symbol>,
        types: HashMap<String, Arc<TypeTemplate>>,
    }

    impl SymbolTableInterface for TestSymbolTable {
        fn name(&self) -> &str {
            DEFAULT_SYMBOL_TABLE
        }

        fn get_symbol(&self, name: &str) -> SymbolResult<Symbol> {
            self.symbols
                .get(name)
                .cloned()
                .ok_or_else(|| SymbolError::NotFound(name.to_string()))
        }

        fn get_type(&self, name: &str) -> SymbolResult<Arc<TypeTemplate>> {
            self.types
                .get(name)
                .cloned()
                .ok_or_else(|| SymbolError::TypeNotFound(name.to_string()))
        }

        fn get_enumeration(&self, name: &str) -> SymbolResult<Enumeration> {
            Err(SymbolError::EnumerationNotFound(name.to_string()))
        }

        fn has_symbol(&self, name: &str) -> bool {
            self.symbols.contains_key(name)
        }

        fn has_type(&self, name: &str) -> bool {
            self.types.contains_key(name)
        }

        fn symbols(&self) -> Box<dyn Iterator<Item = &str> + '_> {
            Box::new(self.symbols.keys().map(String::as_str))
        }

        fn types(&self) -> Box<dyn Iterator<Item = &str> + '_> {
            Box::new(self.types.keys().map(String::as_str))
        }

        fn enumerations(&self) -> Box<dyn Iterator<Item = &str> + '_> {
            Box::new(std::iter::empty())
        }
    }

    fn primitive(name: &str, size: usize) -> Arc<TypeTemplate> {
        Arc::new(TypeTemplate::primitive(name, size, false))
    }

    fn field(name: &str, offset: usize, template: Arc<TypeTemplate>) -> FieldInfo {
        FieldInfo {
            name: name.to_string(),
            offset,
            template,
        }
    }

    fn test_symbol_table() -> Arc<TestSymbolTable> {
        let u32_type = primitive("unsigned int", 4);
        let pointer_type = primitive("pointer", 8);
        let image_type = Arc::new(TypeTemplate::array(
            "ImageFileName",
            16,
            primitive("char", 1),
        ));
        let list_entry = Arc::new(TypeTemplate::struct_type(
            "_LIST_ENTRY",
            16,
            vec![
                field("Flink", 0, pointer_type.clone()),
                field("Blink", 8, pointer_type.clone()),
            ],
        ));
        let eprocess = Arc::new(TypeTemplate::Struct(StructTemplate {
            name: "_EPROCESS".to_string(),
            size: 0x100,
            fields: vec![
                field("ActiveProcessLinks", ACTIVE_LINKS, list_entry),
                field("UniqueProcessId", 0x30, pointer_type.clone()),
                field("InheritedFromUniqueProcessId", 0x38, pointer_type.clone()),
                field("ImageFileName", 0x40, image_type),
                field("ActiveThreads", 0x50, u32_type.clone()),
                field("ObjectTable", 0x58, pointer_type.clone()),
                field("SessionId", 0x60, u32_type),
                field("WoW64Process", 0x68, pointer_type.clone()),
                field("CreateTime", 0x70, pointer_type.clone()),
                field("ExitTime", 0x78, pointer_type),
            ],
        }));
        let handle_table = Arc::new(TypeTemplate::struct_type(
            "_HANDLE_TABLE",
            0x20,
            vec![field("HandleCount", 0x10, primitive("unsigned int", 4))],
        ));

        Arc::new(TestSymbolTable {
            symbols: [(
                "PsActiveProcessHead".to_string(),
                Symbol::new("PsActiveProcessHead", HEAD as u64),
            )]
            .into_iter()
            .collect(),
            types: [
                ("_EPROCESS".to_string(), eprocess),
                ("_HANDLE_TABLE".to_string(), handle_table),
            ]
            .into_iter()
            .collect(),
        })
    }

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        LittleEndian::write_u32(&mut data[offset..offset + 4], value);
    }

    fn write_u64(data: &mut [u8], offset: usize, value: u64) {
        LittleEndian::write_u64(&mut data[offset..offset + 8], value);
    }

    #[allow(clippy::too_many_arguments)]
    fn write_process(
        data: &mut [u8],
        base: usize,
        next_link: usize,
        previous_link: usize,
        pid: u64,
        ppid: u64,
        image: &str,
        threads: u32,
        object_table: usize,
        session_id: u32,
        wow64: bool,
        create_time: u64,
    ) {
        write_u64(data, base + ACTIVE_LINKS, next_link as u64);
        write_u64(data, base + ACTIVE_LINKS + 8, previous_link as u64);
        write_u64(data, base + 0x30, pid);
        write_u64(data, base + 0x38, ppid);
        data[base + 0x40..base + 0x40 + image.len()].copy_from_slice(image.as_bytes());
        write_u32(data, base + 0x50, threads);
        write_u64(data, base + 0x58, object_table as u64);
        write_u32(data, base + 0x60, session_id);
        write_u64(data, base + 0x68, if wow64 { 0x5000 } else { 0 });
        write_u64(data, base + 0x70, create_time);
        write_u64(data, base + 0x78, 0);
    }

    fn build_test_context(forward_complete: bool) -> Context {
        let mut data = vec![0u8; 0x6000];
        let link_one = PROCESS_ONE + ACTIVE_LINKS;
        let link_two = PROCESS_TWO + ACTIVE_LINKS;
        write_u64(&mut data, HEAD, link_one as u64);
        write_u64(&mut data, HEAD + 8, link_two as u64);
        write_process(
            &mut data,
            PROCESS_ONE,
            if forward_complete { link_two } else { HEAD },
            HEAD,
            4,
            0,
            "System",
            120,
            HANDLE_TABLE_ONE,
            0,
            false,
            WINDOWS_EPOCH + 10 * 10_000_000,
        );
        write_process(
            &mut data,
            PROCESS_TWO,
            HEAD,
            if forward_complete { link_one } else { HEAD },
            4242,
            4,
            "powershell.exe",
            8,
            HANDLE_TABLE_TWO,
            1,
            true,
            WINDOWS_EPOCH + 20 * 10_000_000,
        );
        write_u32(&mut data, HANDLE_TABLE_ONE + 0x10, 500);
        write_u32(&mut data, HANDLE_TABLE_TWO + 0x10, 125);

        let context = Context::new();
        context.add_layer(Arc::new(BufferLayer::new("kernel", data)));
        context.add_symbol_table(test_symbol_table());
        context.config_set("primary", "kernel");
        context.config_set("nt_symbols", DEFAULT_SYMBOL_TABLE);
        context.config_set("kernel_virtual_offset", 0_i64);
        context
    }

    fn test_context() -> Context {
        build_test_context(true)
    }

    #[test]
    fn enumerates_synthetic_active_process_list() {
        let context = test_context();
        let processes = PsList::list_processes(&context).unwrap();

        assert_eq!(processes.len(), 2);
        assert_eq!(processes[0].pid, 4);
        assert_eq!(processes[0].image_file_name, "System");
        assert_eq!(processes[0].handles, Some(500));
        assert_eq!(processes[1].pid, 4242);
        assert_eq!(processes[1].ppid, 4);
        assert_eq!(processes[1].image_file_name, "powershell.exe");
        assert_eq!(processes[1].threads, 8);
        assert_eq!(processes[1].handles, Some(125));
        assert_eq!(processes[1].session_id, Some(1));
        assert_eq!(processes[1].wow64, Some(true));
        assert_eq!(processes[1].create_time.unwrap().timestamp(), 20);
        assert!(processes[1].exit_time.is_none());
    }

    #[test]
    fn module_pid_filter_returns_only_requested_process() {
        let context = Arc::new(test_context());
        context.config_set("plugins.windows.pslist.pid", 4242_i64);
        let rows = PsList::new()
            .run(context)
            .unwrap()
            .collect::<Vol3Result<Vec<_>>>()
            .unwrap();

        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0][0], CellValue::UInt(4242)));
        assert!(matches!(rows[0][2], CellValue::String(ref value) if value == "powershell.exe"));
    }

    #[test]
    fn reverse_walk_recovers_process_missing_from_forward_chain() {
        let context = build_test_context(false);
        let processes = PsList::list_processes(&context).unwrap();

        assert_eq!(processes.len(), 2);
        assert_eq!(processes[0].pid, 4);
        assert_eq!(processes[1].pid, 4242);
    }

    #[test]
    fn exposes_volatility_compatible_columns() {
        let columns = PsList::new().columns();
        let names: Vec<_> = columns.iter().map(|column| column.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "PID",
                "PPID",
                "ImageFileName",
                "Offset(V)",
                "Threads",
                "Handles",
                "SessionId",
                "Wow64",
                "CreateTime",
                "ExitTime",
                "File output",
            ]
        );
    }
}
