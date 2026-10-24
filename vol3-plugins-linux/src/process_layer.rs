//! Process layer utilities for reading user-space memory.

use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::Address;
use vol3_framework::context::Context;
use vol3_layers::intel::Intel32e;
use vol3_layers::traits::{DataLayer, TranslationLayer};

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;

/// Create a process layer for reading user-space memory of a task.
///
/// This creates an Intel32e translation layer using the task's page tables.
/// Returns the new layer on success, or None if it couldn't be created.
pub fn create_process_layer(
    context: &Context,
    kernel_layer_name: &str,
    task: &TaskStruct,
    symbol_table: &str,
) -> Vol3Result<Option<Arc<Intel32e>>> {
    let layer = context.get_layer(kernel_layer_name).ok_or_else(|| {
        Vol3Error::Layer(vol3_core::error::LayerError::NotFound(
            kernel_layer_name.to_string(),
        ))
    })?;

    // Read mm pointer from task
    let task_template = context.get_type(symbol_table, "task_struct")?;
    let mm_offset = if let vol3_symbols::TypeTemplate::Struct(s) = task_template.as_ref() {
        s.get_field("mm").map(|f| f.offset).unwrap_or(0)
    } else {
        return Ok(None);
    };

    let mm_ptr = helpers::read_pointer(layer.as_ref(), task.address() + mm_offset as u64)?;
    if mm_ptr == 0 {
        // Kernel thread - no mm
        return Ok(None);
    }

    // Read pgd from mm_struct
    let mm_template = context.get_type(symbol_table, "mm_struct")?;
    let pgd_offset = if let vol3_symbols::TypeTemplate::Struct(s) = mm_template.as_ref() {
        s.get_field("pgd").map(|f| f.offset).unwrap_or(0)
    } else {
        return Ok(None);
    };

    let pgd_virtual = helpers::read_pointer(layer.as_ref(), mm_ptr + pgd_offset as u64)?;
    if pgd_virtual == 0 || !helpers::is_valid_kernel_address(pgd_virtual) {
        return Ok(None);
    }

    // Translate pgd virtual address to physical using the kernel layer
    // The kernel layer is an Intel32e layer, we need to downcast to translate
    let kernel_layer_any = layer.as_any();
    let dtb_phys = if let Some(intel_layer) = kernel_layer_any.downcast_ref::<Intel32e>() {
        // Intel layer - use its translate method
        match intel_layer.translate(pgd_virtual) {
            Ok((phys, _)) => phys,
            Err(_) => return Ok(None),
        }
    } else {
        // Not a translation layer - try to read directly (unlikely to work for virtual addresses)
        return Ok(None);
    };

    // Get the base layer (physical memory) from the kernel layer's dependencies
    let base_layer_name = layer.dependencies().first().cloned().ok_or_else(|| {
        Vol3Error::Layer(vol3_core::error::LayerError::NotFound(
            "base_layer".to_string(),
        ))
    })?;

    let base_layer = context.get_layer(&base_layer_name).ok_or_else(|| {
        Vol3Error::Layer(vol3_core::error::LayerError::NotFound(
            base_layer_name.clone(),
        ))
    })?;

    // Create Intel32e layer for process
    let pid = task.pid(layer.as_ref()).unwrap_or(0);
    let layer_name = format!("process_{}", pid);

    let process_layer = Intel32e::new(
        &layer_name,
        base_layer,
        dtb_phys,
        0, // page_map_offset for user-space is 0
    );

    Ok(Some(Arc::new(process_layer)))
}

/// Get command-line arguments for a task
pub fn get_task_args(
    context: &Context,
    kernel_layer_name: &str,
    task: &TaskStruct,
    symbol_table: &str,
    comm: &str,
) -> Vol3Result<String> {
    let layer = context.get_layer(kernel_layer_name).ok_or_else(|| {
        Vol3Error::Layer(vol3_core::error::LayerError::NotFound(
            kernel_layer_name.to_string(),
        ))
    })?;

    // Get mm pointer
    let task_template = context.get_type(symbol_table, "task_struct")?;
    let mm_offset = if let vol3_symbols::TypeTemplate::Struct(s) = task_template.as_ref() {
        s.get_field("mm").map(|f| f.offset).unwrap_or(0)
    } else {
        return Ok(format!("[{}]", comm));
    };

    let mm_ptr = helpers::read_pointer(layer.as_ref(), task.address() + mm_offset as u64)?;
    if mm_ptr == 0 {
        // Kernel thread
        return Ok(format!("[{}]", comm));
    }

    // Get mm_struct field offsets
    let mm_template = context.get_type(symbol_table, "mm_struct")?;
    let (arg_start_offset, arg_end_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = mm_template.as_ref() {
            (
                s.get_field("arg_start").map(|f| f.offset).unwrap_or(0),
                s.get_field("arg_end").map(|f| f.offset).unwrap_or(0),
            )
        } else {
            return Ok(format!("[{}]", comm));
        };

    let arg_start = helpers::read_pointer(layer.as_ref(), mm_ptr + arg_start_offset as u64)?;
    let arg_end = helpers::read_pointer(layer.as_ref(), mm_ptr + arg_end_offset as u64)?;

    if arg_end <= arg_start {
        return Ok(format!("[{}]", comm));
    }

    let arg_size = (arg_end - arg_start) as usize;
    if arg_size == 0 || arg_size > 4096 {
        return Ok(format!("[{}]", comm));
    }

    // Create process layer and read args
    let proc_layer = match create_process_layer(context, kernel_layer_name, task, symbol_table)? {
        Some(layer) => layer,
        None => return Ok(format!("[{}]", comm)),
    };

    let arg_data = match proc_layer.read(arg_start, arg_size, false) {
        Ok(data) => data,
        Err(_) => return Ok(format!("[{}]", comm)),
    };

    // Convert null-separated args to space-separated
    let args = String::from_utf8_lossy(&arg_data)
        .split('\0')
        .collect::<Vec<_>>()
        .join(" ");

    // Remove trailing space
    let args = args.trim_end().to_string();

    Ok(args)
}

/// Read environment variables from a task's user-space memory.
/// Returns a Vec of (key, value) pairs.
pub fn get_task_env_variables(
    context: &Context,
    kernel_layer_name: &str,
    task: &TaskStruct,
    symbol_table: &str,
    max_size: usize,
) -> Vol3Result<Vec<(String, String)>> {
    let layer = context.get_layer(kernel_layer_name).ok_or_else(|| {
        Vol3Error::Layer(vol3_core::error::LayerError::NotFound(
            kernel_layer_name.to_string(),
        ))
    })?;

    // Get mm_struct field offsets
    let mm_template = context.get_type(symbol_table, "mm_struct")?;
    let (env_start_offset, env_end_offset) =
        if let vol3_symbols::TypeTemplate::Struct(s) = mm_template.as_ref() {
            (
                s.get_field("env_start").map(|f| f.offset).unwrap_or(0),
                s.get_field("env_end").map(|f| f.offset).unwrap_or(0),
            )
        } else {
            return Ok(Vec::new());
        };

    // Get mm pointer
    let task_template = context.get_type(symbol_table, "task_struct")?;
    let mm_offset = if let vol3_symbols::TypeTemplate::Struct(s) = task_template.as_ref() {
        s.get_field("mm").map(|f| f.offset).unwrap_or(0)
    } else {
        return Ok(Vec::new());
    };

    let mm_ptr = helpers::read_pointer(layer.as_ref(), task.address() + mm_offset as u64)?;
    if mm_ptr == 0 {
        return Ok(Vec::new()); // Kernel thread
    }

    // Read env_start and env_end
    let env_start = helpers::read_pointer(layer.as_ref(), mm_ptr + env_start_offset as u64)?;
    let env_end = helpers::read_pointer(layer.as_ref(), mm_ptr + env_end_offset as u64)?;

    if env_end <= env_start {
        return Ok(Vec::new());
    }

    let env_size = (env_end - env_start) as usize;
    if env_size == 0 || env_size > max_size {
        return Ok(Vec::new());
    }

    // Create process layer and read environment data
    let proc_layer = match create_process_layer(context, kernel_layer_name, task, symbol_table)? {
        Some(layer) => layer,
        None => return Ok(Vec::new()),
    };

    // Read environment data from process layer
    let env_data = match proc_layer.read(env_start, env_size, false) {
        Ok(data) => data,
        Err(_) => return Ok(Vec::new()),
    };

    // Parse environment variables
    let mut result = Vec::new();

    // Remove trailing nulls
    let mut data = env_data.as_slice();
    while data.last() == Some(&0) {
        data = &data[..data.len() - 1];
    }

    for pair in data.split(|&b| b == 0) {
        let decoded = String::from_utf8_lossy(pair);
        if let Some((key, value)) = decoded.split_once('=') {
            result.push((key.to_string(), value.to_string()));
        } else {
            // Malformed - stop processing
            break;
        }
    }

    Ok(result)
}
