//! Symbol-derived layouts used by Windows process enumeration.

use vol3_core::error::{PluginError, Vol3Error, Vol3Result};
use vol3_framework::context::Context;
use vol3_symbols::{StructTemplate, TypeTemplate};

/// Offsets needed to traverse and render `_EPROCESS` records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EprocessLayout {
    pub size: usize,
    pub active_process_links: usize,
    pub unique_process_id: usize,
    pub unique_process_id_size: usize,
    pub inherited_from_unique_process_id: usize,
    pub inherited_from_unique_process_id_size: usize,
    pub image_file_name: usize,
    pub image_file_name_size: usize,
    pub active_threads: usize,
    pub active_threads_size: usize,
    pub object_table: Option<usize>,
    pub direct_session_id: Option<(usize, usize)>,
    pub session: Option<usize>,
    pub session_space_id: Option<(usize, usize)>,
    pub wow64_process: Option<usize>,
    pub create_time: Option<usize>,
    pub exit_time: Option<usize>,
    pub handle_count: Option<usize>,
    pub directory_table_base: Option<(usize, usize)>,
}

impl EprocessLayout {
    /// Resolve `_EPROCESS` and `_HANDLE_TABLE` offsets from a Windows ISF.
    pub fn from_context(context: &Context, symbol_table: &str) -> Vol3Result<Self> {
        let eprocess_type = context
            .get_type(symbol_table, "_EPROCESS")
            .or_else(|_| context.get_type(symbol_table, "EPROCESS"))?;
        let eprocess = as_struct(eprocess_type.as_ref(), "_EPROCESS")?;

        let active_process_links = required_field(eprocess, "ActiveProcessLinks")?;
        let unique_process_id = required_field(eprocess, "UniqueProcessId")?;
        let inherited = required_field(eprocess, "InheritedFromUniqueProcessId")?;
        let image_file_name = required_field(eprocess, "ImageFileName")?;
        let active_threads = required_field(eprocess, "ActiveThreads")?;

        let handle_count = context
            .get_type(symbol_table, "_HANDLE_TABLE")
            .or_else(|_| context.get_type(symbol_table, "HANDLE_TABLE"))
            .ok()
            .and_then(|template| match template.as_ref() {
                TypeTemplate::Struct(value) => value.get_field("HandleCount").map(|f| f.offset),
                _ => None,
            });

        let session_space_id = context
            .get_type(symbol_table, "_MM_SESSION_SPACE")
            .or_else(|_| context.get_type(symbol_table, "MM_SESSION_SPACE"))
            .ok()
            .and_then(|template| match template.as_ref() {
                TypeTemplate::Struct(value) => value
                    .get_field("SessionId")
                    .map(|field| (field.offset, field_size(field.template.as_ref(), 4))),
                _ => None,
            });

        let pcb_offset = optional_offset(eprocess, &["Pcb"]).unwrap_or(0);
        let directory_table_base = context
            .get_type(symbol_table, "_KPROCESS")
            .or_else(|_| context.get_type(symbol_table, "KPROCESS"))
            .ok()
            .and_then(|template| match template.as_ref() {
                TypeTemplate::Struct(value) => value.get_field("DirectoryTableBase").map(|field| {
                    (
                        pcb_offset + field.offset,
                        field_size(field.template.as_ref(), 8),
                    )
                }),
                _ => None,
            });

        Ok(Self {
            size: eprocess.size,
            active_process_links: active_process_links.offset,
            unique_process_id: unique_process_id.offset,
            unique_process_id_size: field_size(unique_process_id.template.as_ref(), 8),
            inherited_from_unique_process_id: inherited.offset,
            inherited_from_unique_process_id_size: field_size(inherited.template.as_ref(), 8),
            image_file_name: image_file_name.offset,
            image_file_name_size: field_size(image_file_name.template.as_ref(), 15).clamp(1, 256),
            active_threads: active_threads.offset,
            active_threads_size: field_size(active_threads.template.as_ref(), 4),
            object_table: optional_offset(eprocess, &["ObjectTable"]),
            direct_session_id: optional_field(eprocess, &["SessionId"])
                .map(|field| (field.offset, field_size(field.template.as_ref(), 4))),
            session: optional_offset(eprocess, &["Session"]),
            session_space_id,
            wow64_process: optional_offset(eprocess, &["WoW64Process", "Wow64Process"]),
            create_time: optional_offset(eprocess, &["CreateTime"]),
            exit_time: optional_offset(eprocess, &["ExitTime"]),
            handle_count,
            directory_table_base,
        })
    }
}

fn as_struct<'a>(template: &'a TypeTemplate, name: &str) -> Vol3Result<&'a StructTemplate> {
    match template {
        TypeTemplate::Struct(value) => Ok(value),
        _ => Err(plugin_error(format!(
            "Windows type {name} is not a structure"
        ))),
    }
}

fn required_field<'a>(
    structure: &'a StructTemplate,
    name: &str,
) -> Vol3Result<&'a vol3_symbols::FieldInfo> {
    structure.get_field(name).ok_or_else(|| {
        plugin_error(format!(
            "Required field {}.{} is missing from the Windows ISF",
            structure.name, name
        ))
    })
}

fn optional_field<'a>(
    structure: &'a StructTemplate,
    names: &[&str],
) -> Option<&'a vol3_symbols::FieldInfo> {
    names.iter().find_map(|name| structure.get_field(name))
}

fn optional_offset(structure: &StructTemplate, names: &[&str]) -> Option<usize> {
    optional_field(structure, names).map(|field| field.offset)
}

fn field_size(template: &TypeTemplate, fallback: usize) -> usize {
    template
        .size()
        .filter(|size| matches!(size, 1 | 2 | 4 | 8))
        .unwrap_or(fallback)
}

fn plugin_error(message: String) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message))
}
