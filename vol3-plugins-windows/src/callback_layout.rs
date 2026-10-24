//! Symbol-derived layouts used by the Windows callbacks plugin.

use vol3_core::error::{PluginError, Vol3Error, Vol3Result};
use vol3_framework::context::Context;
use vol3_symbols::{FieldInfo, StructTemplate, TypeTemplate};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarFieldLayout {
    pub offset: usize,
    pub storage_size: usize,
    pub bit_offset: usize,
    pub bit_length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackLayout {
    pub generic_size: usize,
    pub generic_callback: usize,
    pub notification_size: usize,
    pub notification_list_entry: usize,
    pub notification_routine: usize,
    pub shutdown_size: usize,
    pub shutdown_entry: usize,
    pub shutdown_device: usize,
    pub dbgprint_function: usize,
    pub notify_event_category: usize,
    pub notify_callback: usize,
    pub notify_driver: usize,
    pub ex_callback_function: usize,
    pub cm_link: usize,
    pub cm_function: usize,
    pub cm_altitude: usize,
    pub bugcheck_size: usize,
    pub bugcheck_entry: usize,
    pub bugcheck_routine: usize,
    pub bugcheck_component: usize,
    pub bugcheck_reason_size: usize,
    pub bugcheck_reason_entry: usize,
    pub bugcheck_reason_routine: usize,
    pub bugcheck_reason_component: usize,
}

impl CallbackLayout {
    pub fn from_context(context: &Context, table: &str) -> Vol3Result<Self> {
        let generic = structure(context, table, "_GENERIC_CALLBACK")?;
        let notification = structure(context, table, "_NOTIFICATION_PACKET")?;
        let shutdown = structure(context, table, "_SHUTDOWN_PACKET")?;
        let dbgprint = structure(context, table, "_DBGPRINT_CALLBACK")?;
        let notify = structure(context, table, "_NOTIFY_ENTRY_HEADER")?;
        let ex_callback = structure(context, table, "_EX_CALLBACK_ROUTINE_BLOCK")?;
        let cm = structure(context, table, "_CM_CALLBACK_ENTRY")?;
        let bugcheck = structure(context, table, "_KBUGCHECK_CALLBACK_RECORD")?;
        let reason = structure(context, table, "_KBUGCHECK_REASON_CALLBACK_RECORD")?;
        Ok(Self {
            generic_size: generic.size,
            generic_callback: field(&generic, "Callback")?.offset,
            notification_size: notification.size,
            notification_list_entry: field(&notification, "ListEntry")?.offset,
            notification_routine: field(&notification, "NotificationRoutine")?.offset,
            shutdown_size: shutdown.size,
            shutdown_entry: field(&shutdown, "Entry")?.offset,
            shutdown_device: field(&shutdown, "DeviceObject")?.offset,
            dbgprint_function: field(&dbgprint, "Function")?.offset,
            notify_event_category: field(&notify, "EventCategory")?.offset,
            notify_callback: field(&notify, "CallbackRoutine")?.offset,
            notify_driver: field(&notify, "DriverObject")?.offset,
            ex_callback_function: field(&ex_callback, "Function")?.offset,
            cm_link: field(&cm, "Link")?.offset,
            cm_function: field(&cm, "Function")?.offset,
            cm_altitude: field(&cm, "Altitude")?.offset,
            bugcheck_size: bugcheck.size,
            bugcheck_entry: field(&bugcheck, "Entry")?.offset,
            bugcheck_routine: field(&bugcheck, "CallbackRoutine")?.offset,
            bugcheck_component: field(&bugcheck, "Component")?.offset,
            bugcheck_reason_size: reason.size,
            bugcheck_reason_entry: field(&reason, "Entry")?.offset,
            bugcheck_reason_routine: field(&reason, "CallbackRoutine")?.offset,
            bugcheck_reason_component: field(&reason, "Component")?.offset,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelCallbackLayout {
    pub pool_header_size: usize,
    pub pool_tag: usize,
    pub pool_block_size: ScalarFieldLayout,
    pub pool_index: ScalarFieldLayout,
    pub unicode_length: (usize, usize),
    pub unicode_buffer: usize,
    pub device_driver: usize,
    pub driver_start: Option<usize>,
    pub driver_name: usize,
    pub driver_major_function: usize,
}

impl KernelCallbackLayout {
    pub fn from_context(context: &Context, table: &str) -> Vol3Result<Self> {
        let pool = structure(context, table, "_POOL_HEADER")?;
        let unicode = structure(context, table, "_UNICODE_STRING")?;
        let device = structure(context, table, "_DEVICE_OBJECT")?;
        let driver = structure(context, table, "_DRIVER_OBJECT")?;
        let block_size = field(&pool, "BlockSize")?;
        let pool_index = field(&pool, "PoolIndex")?;
        Ok(Self {
            pool_header_size: pool.size,
            pool_tag: field(&pool, "PoolTag")?.offset,
            pool_block_size: scalar_field(block_size, 1)?,
            pool_index: scalar_field(pool_index, 1)?,
            unicode_length: {
                let value = field(&unicode, "Length")?;
                (value.offset, scalar_size(value, 2))
            },
            unicode_buffer: field(&unicode, "Buffer")?.offset,
            device_driver: field(&device, "DriverObject")?.offset,
            driver_start: driver.get_field("DriverStart").map(|value| value.offset),
            driver_name: field(&driver, "DriverName")?.offset,
            driver_major_function: field(&driver, "MajorFunction")?.offset,
        })
    }
}

fn structure(context: &Context, table: &str, name: &str) -> Vol3Result<StructTemplate> {
    let template = context.get_type(table, name)?;
    match template.as_ref() {
        TypeTemplate::Struct(value) => Ok(value.clone()),
        _ => Err(error(format!("Callback type {name} is not a structure"))),
    }
}

fn field<'a>(structure: &'a StructTemplate, name: &str) -> Vol3Result<&'a FieldInfo> {
    structure.get_field(name).ok_or_else(|| {
        error(format!(
            "Required callback field {}.{} is absent",
            structure.name, name
        ))
    })
}

fn scalar_size(field: &FieldInfo, fallback: usize) -> usize {
    field
        .template
        .size()
        .filter(|size| matches!(size, 1 | 2 | 4 | 8))
        .unwrap_or(fallback)
}

fn scalar_field(field: &FieldInfo, fallback: usize) -> Vol3Result<ScalarFieldLayout> {
    match field.template.as_ref() {
        TypeTemplate::BitField(value) => Ok(ScalarFieldLayout {
            offset: field.offset,
            storage_size: value.size,
            bit_offset: value.bit_offset.try_into().map_err(|_| {
                error(format!(
                    "Negative bit offset for callback field {}",
                    field.name
                ))
            })?,
            bit_length: value.bit_length,
        }),
        _ => {
            let storage_size = scalar_size(field, fallback);
            Ok(ScalarFieldLayout {
                offset: field.offset,
                storage_size,
                bit_offset: 0,
                bit_length: storage_size * 8,
            })
        }
    }
}

fn error(message: String) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message))
}
