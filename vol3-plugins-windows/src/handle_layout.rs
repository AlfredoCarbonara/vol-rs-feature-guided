//! Symbol-derived layouts used by Windows handle enumeration.

use vol3_core::error::{PluginError, Vol3Error, Vol3Result};
use vol3_framework::context::Context;
use vol3_symbols::{FieldInfo, StructTemplate, TypeTemplate, UnionTemplate};

enum AggregateRef<'a> {
    Struct(&'a StructTemplate),
    Union(&'a UnionTemplate),
}

impl AggregateRef<'_> {
    fn size(&self) -> usize {
        match self {
            Self::Struct(value) => value.size,
            Self::Union(value) => value.size,
        }
    }

    fn get_field(&self, name: &str) -> Option<&FieldInfo> {
        match self {
            Self::Struct(value) => value.get_field(name),
            Self::Union(value) => value.members.iter().find(|field| field.name == name),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Struct(value) => &value.name,
            Self::Union(value) => &value.name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitFieldLayout {
    pub offset: usize,
    pub storage_size: usize,
    pub bit_offset: usize,
    pub bit_length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyNameLayout {
    pub key_control_block: usize,
    pub has_transaction_field: bool,
    pub parent_kcb: usize,
    pub name_block: usize,
    pub flags: BitFieldLayout,
    pub name_length: usize,
    pub name: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleLayout {
    pub table_code: usize,
    pub table_entry_size: usize,
    pub object_pointer_bits: BitFieldLayout,
    pub granted_access_bits: BitFieldLayout,
    pub object_header_body: usize,
    pub object_header_type_index: usize,
    pub object_header_info_mask: Option<usize>,
    pub object_type_name: usize,
    pub name_info_name: usize,
    pub unicode_length: usize,
    pub unicode_maximum_length: usize,
    pub unicode_buffer: usize,
    pub ethread_cid: Option<usize>,
    pub client_id_process: Option<(usize, usize)>,
    pub client_id_thread: Option<(usize, usize)>,
    pub file_name: Option<usize>,
    pub file_device_object: Option<usize>,
    pub key_name: Option<KeyNameLayout>,
}

impl HandleLayout {
    pub fn from_context(context: &Context, table: &str) -> Vol3Result<Self> {
        let handle_table_type = required_structure(context, table, "_HANDLE_TABLE")?;
        let handle_entry_type = required_structure(context, table, "_HANDLE_TABLE_ENTRY")?;
        let object_header_type = required_structure(context, table, "_OBJECT_HEADER")?;
        let object_type_type = required_structure(context, table, "_OBJECT_TYPE")?;
        let name_info_type = required_structure(context, table, "_OBJECT_HEADER_NAME_INFO")?;
        let unicode_type = required_structure(context, table, "_UNICODE_STRING")?;
        let handle_table = as_aggregate(handle_table_type.as_ref(), "_HANDLE_TABLE")?;
        let handle_entry = as_aggregate(handle_entry_type.as_ref(), "_HANDLE_TABLE_ENTRY")?;
        let object_header = as_aggregate(object_header_type.as_ref(), "_OBJECT_HEADER")?;
        let object_type = as_aggregate(object_type_type.as_ref(), "_OBJECT_TYPE")?;
        let name_info = as_aggregate(name_info_type.as_ref(), "_OBJECT_HEADER_NAME_INFO")?;
        let unicode = as_aggregate(unicode_type.as_ref(), "_UNICODE_STRING")?;

        let ethread_type = required_structure(context, table, "_ETHREAD").ok();
        let client_id_type = required_structure(context, table, "_CLIENT_ID").ok();
        let file_object_type = required_structure(context, table, "_FILE_OBJECT").ok();
        let key_body_type = required_structure(context, table, "_CM_KEY_BODY").ok();
        let key_control_block_type =
            required_structure(context, table, "_CM_KEY_CONTROL_BLOCK").ok();
        let name_control_block_type =
            required_structure(context, table, "_CM_NAME_CONTROL_BLOCK").ok();
        let ethread = ethread_type
            .as_deref()
            .and_then(|value| as_aggregate(value, "_ETHREAD").ok());
        let client_id = client_id_type
            .as_deref()
            .and_then(|value| as_aggregate(value, "_CLIENT_ID").ok());
        let file_object = file_object_type
            .as_deref()
            .and_then(|value| as_aggregate(value, "_FILE_OBJECT").ok());
        let key_body = key_body_type
            .as_deref()
            .and_then(|value| as_aggregate(value, "_CM_KEY_BODY").ok());
        let key_control_block = key_control_block_type
            .as_deref()
            .and_then(|value| as_aggregate(value, "_CM_KEY_CONTROL_BLOCK").ok());
        let name_control_block = name_control_block_type
            .as_deref()
            .and_then(|value| as_aggregate(value, "_CM_NAME_CONTROL_BLOCK").ok());
        let key_name = match (key_body.as_ref(), key_control_block.as_ref(), name_control_block.as_ref()) {
            (Some(body), Some(kcb), Some(name)) => (|| {
                Some(KeyNameLayout {
                    key_control_block: body.get_field("KeyControlBlock")?.offset,
                    has_transaction_field: body.get_field("Trans").is_some(),
                    parent_kcb: kcb.get_field("ParentKcb")?.offset,
                    name_block: kcb.get_field("NameBlock")?.offset,
                    flags: bitfield(kcb.get_field("Flags")?).ok()?,
                    name_length: name.get_field("NameLength")?.offset,
                    name: name.get_field("Name")?.offset,
                })
            })(),
            _ => None,
        };

        Ok(Self {
            table_code: required_field(&handle_table, "TableCode")?.offset,
            table_entry_size: handle_entry.size(),
            object_pointer_bits: bitfield(required_field(&handle_entry, "ObjectPointerBits")?)?,
            granted_access_bits: bitfield(required_field(&handle_entry, "GrantedAccessBits")?)?,
            object_header_body: required_field(&object_header, "Body")?.offset,
            object_header_type_index: required_field(&object_header, "TypeIndex")?.offset,
            object_header_info_mask: object_header.get_field("InfoMask").map(|f| f.offset),
            object_type_name: required_field(&object_type, "Name")?.offset,
            name_info_name: required_field(&name_info, "Name")?.offset,
            unicode_length: required_field(&unicode, "Length")?.offset,
            unicode_maximum_length: required_field(&unicode, "MaximumLength")?.offset,
            unicode_buffer: required_field(&unicode, "Buffer")?.offset,
            ethread_cid: ethread.and_then(|value| value.get_field("Cid").map(|f| f.offset)),
            client_id_process: client_id.as_ref().and_then(|value| {
                value
                    .get_field("UniqueProcess")
                    .map(|field| (field.offset, field_size(field, 8)))
            }),
            client_id_thread: client_id.as_ref().and_then(|value| {
                value
                    .get_field("UniqueThread")
                    .map(|field| (field.offset, field_size(field, 8)))
            }),
            file_name: file_object
                .as_ref()
                .and_then(|value| value.get_field("FileName").map(|field| field.offset)),
            file_device_object: file_object.as_ref().and_then(|value| {
                value
                    .get_field("DeviceObject")
                    .map(|field| field.offset)
            }),
            key_name,
        })
    }
}

fn required_structure(
    context: &Context,
    table: &str,
    name: &str,
) -> Vol3Result<std::sync::Arc<TypeTemplate>> {
    context
        .get_type(table, name)
        .or_else(|_| context.get_type(table, name.trim_start_matches('_')))
        .map_err(Into::into)
}

fn as_aggregate<'a>(template: &'a TypeTemplate, name: &str) -> Vol3Result<AggregateRef<'a>> {
    match template {
        TypeTemplate::Struct(value) => Ok(AggregateRef::Struct(value)),
        TypeTemplate::Union(value) => Ok(AggregateRef::Union(value)),
        _ => Err(plugin_error(format!(
            "Windows type {name} is not a structure or union"
        ))),
    }
}

fn required_field<'a>(structure: &'a AggregateRef<'a>, name: &str) -> Vol3Result<&'a FieldInfo> {
    structure.get_field(name).ok_or_else(|| {
        plugin_error(format!(
            "Required field {}.{} is missing from the Windows ISF",
            structure.name(),
            name
        ))
    })
}

fn bitfield(field: &FieldInfo) -> Vol3Result<BitFieldLayout> {
    match field.template.as_ref() {
        TypeTemplate::BitField(value) => Ok(BitFieldLayout {
            offset: field.offset,
            storage_size: value.size,
            bit_offset: value.bit_offset.try_into().map_err(|_| {
                plugin_error(format!("Negative bit offset for field {}", field.name))
            })?,
            bit_length: value.bit_length,
        }),
        _ => Err(plugin_error(format!(
            "Windows field {} is not a bitfield",
            field.name
        ))),
    }
}

fn field_size(field: &FieldInfo, fallback: usize) -> usize {
    field.template.size().unwrap_or(fallback)
}

fn plugin_error(message: String) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message))
}
