//! Symbol-derived layouts for the user-mode Windows service database.

use vol3_core::error::{PluginError, Vol3Error, Vol3Result};
use vol3_framework::context::Context;
use vol3_symbols::{FieldInfo, StructTemplate, TypeTemplate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLayout {
    pub header_tag: usize,
    pub header_record: usize,
    pub record_size: usize,
    pub prev_entry: usize,
    pub order: usize,
    pub start: usize,
    pub service_name: usize,
    pub display_name: usize,
    pub service_type: usize,
    pub state: usize,
    pub process_or_driver: usize,
    pub process_binary_path: usize,
    pub process_id: usize,
}

impl ServiceLayout {
    pub fn from_context(context: &Context, table: &str) -> Vol3Result<Self> {
        let header_type = context.get_type(table, "_SERVICE_HEADER")?;
        let record_type = context.get_type(table, "_SERVICE_RECORD")?;
        let process_type = context.get_type(table, "_SERVICE_PROCESS")?;
        let header = as_structure(header_type.as_ref(), "_SERVICE_HEADER")?;
        let record = as_structure(record_type.as_ref(), "_SERVICE_RECORD")?;
        let process = as_structure(process_type.as_ref(), "_SERVICE_PROCESS")?;
        Ok(Self {
            header_tag: field(header, "Tag")?.offset,
            header_record: field(header, "ServiceRecord")?.offset,
            record_size: record.size,
            prev_entry: field(record, "PrevEntry")?.offset,
            order: field(record, "Order")?.offset,
            start: field(record, "Start")?.offset,
            service_name: field(record, "ServiceName")?.offset,
            display_name: field(record, "DisplayName")?.offset,
            service_type: field(record, "Type")?.offset,
            state: field(record, "State")?.offset,
            process_or_driver: field(record, "ServiceProcess")
                .or_else(|_| field(record, "DriverName"))?
                .offset,
            process_binary_path: field(process, "BinaryPath")?.offset,
            process_id: field(process, "ProcessId")?.offset,
        })
    }
}

fn as_structure<'a>(template: &'a TypeTemplate, name: &str) -> Vol3Result<&'a StructTemplate> {
    match template {
        TypeTemplate::Struct(value) => Ok(value),
        _ => Err(error(format!("Service type {name} is not a structure"))),
    }
}

fn field<'a>(structure: &'a StructTemplate, name: &str) -> Vol3Result<&'a FieldInfo> {
    structure.get_field(name).ok_or_else(|| {
        error(format!(
            "Required service field {}.{} is absent",
            structure.name, name
        ))
    })
}

fn error(message: String) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message))
}
