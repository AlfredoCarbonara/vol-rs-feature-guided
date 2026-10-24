//! Helper functions for Linux plugins.

use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::Address;
use vol3_framework::context::Context;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::extensions::{ListHeadIterator, TaskStruct, TaskStructExt};

/// Get the init_task symbol address (with ASLR shift applied)
pub fn get_init_task(context: &Context, symbol_table: &str) -> Vol3Result<Address> {
    let symbol = context.get_symbol(symbol_table, "init_task")?;

    // Apply ASLR shift (virtual address randomization)
    let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;
    let address = symbol.address.wrapping_add(aslr_shift);

    log::debug!(
        "init_task: symbol={:#x}, aslr_shift={:#x}, final={:#x}",
        symbol.address,
        aslr_shift,
        address
    );

    Ok(address)
}

/// Get the task_struct type template
pub fn get_task_struct_template(
    context: &Context,
    symbol_table: &str,
) -> Vol3Result<Arc<TypeTemplate>> {
    context
        .get_type(symbol_table, "task_struct")
        .map_err(Into::into)
}

/// Iterate over all tasks using the init_task list
pub fn iter_tasks<'a>(
    layer: &'a dyn DataLayer,
    init_task_addr: Address,
    tasks_offset: usize,
) -> impl Iterator<Item = Address> + 'a {
    // The list_head is at init_task_addr + tasks_offset
    let head = init_task_addr + tasks_offset as u64;
    ListHeadIterator::new(layer, head, tasks_offset)
}

/// Read a pointer from memory
pub fn read_pointer(layer: &dyn DataLayer, address: Address) -> Vol3Result<Address> {
    use vol3_core::error::LayerError;
    let bytes = layer
        .read(address, 8, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    Ok(LittleEndian::read_u64(&bytes))
}

/// Read an i32 from memory
pub fn read_i32(layer: &dyn DataLayer, address: Address) -> Vol3Result<i32> {
    let bytes = layer
        .read(address, 4, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    Ok(LittleEndian::read_i32(&bytes))
}

/// Read a u8 from memory
pub fn read_u8(layer: &dyn DataLayer, address: Address) -> Vol3Result<u8> {
    let bytes = layer
        .read(address, 1, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    Ok(bytes[0])
}

/// Read a u16 from memory
pub fn read_u16(layer: &dyn DataLayer, address: Address) -> Vol3Result<u16> {
    let bytes = layer
        .read(address, 2, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    Ok(LittleEndian::read_u16(&bytes))
}

/// Read a u32 from memory
pub fn read_u32(layer: &dyn DataLayer, address: Address) -> Vol3Result<u32> {
    let bytes = layer
        .read(address, 4, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    Ok(LittleEndian::read_u32(&bytes))
}

/// Read an i64 from memory
pub fn read_i64(layer: &dyn DataLayer, address: Address) -> Vol3Result<i64> {
    let bytes = layer
        .read(address, 8, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    Ok(LittleEndian::read_i64(&bytes))
}

/// Read a u64 from memory
pub fn read_u64(layer: &dyn DataLayer, address: Address) -> Vol3Result<u64> {
    let bytes = layer
        .read(address, 8, false)
        .map_err(|e| Vol3Error::Layer(e))?;
    Ok(LittleEndian::read_u64(&bytes))
}

/// Read a string from memory
pub fn read_string(layer: &dyn DataLayer, address: Address, max_len: usize) -> Vol3Result<String> {
    let bytes = layer
        .read(address, max_len, false)
        .map_err(|e| Vol3Error::Layer(e))?;

    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..len]).to_string())
}

/// Check if a virtual address looks valid
pub fn is_valid_kernel_address(address: Address) -> bool {
    // On x86_64 Linux, kernel addresses are typically in high memory
    // The canonical form requires the top 17 bits to be all 1s
    address >= 0xffff_8000_0000_0000
}

/// Collect all processes from task list
pub fn collect_processes(
    layer: &dyn DataLayer,
    init_task_addr: Address,
    template: &TypeTemplate,
) -> Vol3Result<Vec<TaskStruct>> {
    let task_struct = TaskStruct::new(init_task_addr, Arc::new(template.clone()))?;
    let tasks_offset = task_struct.offsets().tasks_next;

    let mut tasks = Vec::new();

    // Note: the init_task itself (PID 0, swapper) is not yielded, since "ps" also never shows it.
    // Python vol3's list_tasks also does not yield init_task.

    // Iterate through the task list
    for task_addr in iter_tasks(layer, init_task_addr, tasks_offset) {
        if !is_valid_kernel_address(task_addr) {
            continue;
        }

        if let Ok(task) = TaskStruct::new(task_addr, Arc::new(template.clone())) {
            tasks.push(task);
        }
    }

    Ok(tasks)
}

/// Calculate system boot time by reading tk_core from memory
/// Returns boot time as nanoseconds since Unix epoch
pub fn get_boottime_ns(
    context: &Context,
    layer: &dyn DataLayer,
    symbol_table: &str,
) -> Option<i64> {
    // Get tk_core symbol address
    let tk_core_sym = context.get_symbol(symbol_table, "tk_core").ok()?;
    let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;
    let tk_core_addr = tk_core_sym.address.wrapping_add(aslr_shift);

    log::debug!("tk_core address: {:#x}", tk_core_addr);

    // Resolve tk_core.timekeeper offset from symbols where possible (fallback preserves old behavior).
    let timekeeper_offset = context
        .get_type(symbol_table, "tk_data")
        .ok()
        .and_then(|t| get_field_offset(t.as_ref(), "timekeeper"))
        .or_else(|| {
            tk_core_sym
                .type_name
                .as_deref()
                .and_then(|tn| context.get_type(symbol_table, tn).ok())
                .and_then(|t| get_field_offset(t.as_ref(), "timekeeper"))
        })
        .unwrap_or(8) as u64;
    let timekeeper_addr = tk_core_addr + timekeeper_offset;

    // Resolve timekeeper offsets dynamically (works across kernels like 5.15 and 6.14).
    let timekeeper_type = context.get_type(symbol_table, "timekeeper").ok()?;
    let (offs_real_field, offs_boot_field) =
        if let TypeTemplate::Struct(s) = timekeeper_type.as_ref() {
            (
                s.get_field("offs_real")?.clone(),
                s.get_field("offs_boot")?.clone(),
            )
        } else {
            return None;
        };

    let offs_real = read_timekeeper_value_ns(
        layer,
        timekeeper_addr + offs_real_field.offset as u64,
        offs_real_field.template.as_ref(),
    )?;
    let offs_boot = read_timekeeper_value_ns(
        layer,
        timekeeper_addr + offs_boot_field.offset as u64,
        offs_boot_field.template.as_ref(),
    )?;

    // Python behavior: boottime_nsec = offs_real - offs_boot
    let boottime_nsec = offs_real.saturating_sub(offs_boot);

    log::debug!(
        "offs_real={}, offs_boot={}, boottime_ns={}",
        offs_real,
        offs_boot,
        boottime_nsec
    );

    Some(boottime_nsec)
}

fn read_signed_value(layer: &dyn DataLayer, addr: Address, size: usize) -> Option<i64> {
    match size {
        8 => {
            let b = layer.read(addr, 8, false).ok()?;
            Some(LittleEndian::read_i64(&b))
        }
        4 => {
            let b = layer.read(addr, 4, false).ok()?;
            Some(LittleEndian::read_i32(&b) as i64)
        }
        2 => {
            let b = layer.read(addr, 2, false).ok()?;
            Some(LittleEndian::read_i16(&b) as i64)
        }
        1 => {
            let b = layer.read(addr, 1, false).ok()?;
            Some((b[0] as i8) as i64)
        }
        _ => None,
    }
}

fn read_timespec_ns(
    layer: &dyn DataLayer,
    addr: Address,
    spec: &vol3_symbols::StructTemplate,
) -> Option<i64> {
    let tv_sec_field = spec.get_field("tv_sec")?;
    let tv_nsec_field = spec
        .get_field("tv_nsec")
        .or_else(|| spec.get_field("tv_nsec_sec"))?;
    let sec = read_signed_value(
        layer,
        addr + tv_sec_field.offset as u64,
        tv_sec_field.template.size()?,
    )?;
    let nsec = read_signed_value(
        layer,
        addr + tv_nsec_field.offset as u64,
        tv_nsec_field.template.size()?,
    )?;
    Some(sec.saturating_mul(1_000_000_000).saturating_add(nsec))
}

fn read_timekeeper_value_ns(
    layer: &dyn DataLayer,
    addr: Address,
    template: &TypeTemplate,
) -> Option<i64> {
    match template {
        TypeTemplate::Primitive(p) => read_signed_value(layer, addr, p.size),
        TypeTemplate::Enum(e) => read_signed_value(layer, addr, e.size),
        TypeTemplate::Struct(s) => {
            if let Some(tv64) = s.get_field("tv64") {
                return read_signed_value(layer, addr + tv64.offset as u64, tv64.template.size()?);
            }
            read_timespec_ns(layer, addr, s)
        }
        _ => None,
    }
}

/// Convert nanoseconds since boot to absolute UTC datetime string
pub fn task_create_time_to_utc(start_time_ns: u64, boottime_ns: i64) -> String {
    // Python truncates boottime microseconds to 0 before adding task start time
    // boottime = boottime.replace(microsecond=0)
    let boottime_secs = boottime_ns / 1_000_000_000;
    let boottime_truncated_ns = boottime_secs * 1_000_000_000;

    // Add task start time (in nanoseconds since boot)
    let absolute_ns = boottime_truncated_ns + start_time_ns as i64;

    // Convert to seconds and microseconds
    // Python uses timedelta(seconds=float) which ROUNDS to nearest microsecond
    // e.g., 543385679 ns -> 0.543385679 sec -> rounds to 543386 microseconds
    let secs = absolute_ns / 1_000_000_000;
    let remainder_ns = absolute_ns % 1_000_000_000;
    // Round to nearest microsecond: if nanosecond remainder >= 500, round up
    let micros = (remainder_ns + 500) / 1000;

    // Handle overflow if rounding pushed us to next second
    let (secs, micros) = if micros >= 1_000_000 {
        (secs + 1, micros - 1_000_000)
    } else {
        (secs, micros)
    };

    // Convert to datetime - use %6f for 6-digit microseconds like Python
    use chrono::{TimeZone, Utc};
    if let chrono::LocalResult::Single(dt) = Utc.timestamp_opt(secs, 0) {
        // Python uses strftime("%Y-%m-%d %H:%M:%S.%f %Z") which gives 6 digits for microseconds
        // chrono's %f gives 9 digits (nanoseconds), so we format manually
        let base = dt.format("%Y-%m-%d %H:%M:%S").to_string();
        format!("{}.{:06} UTC", base, micros)
    } else {
        format!("Invalid time: {} ns", absolute_ns)
    }
}

/// Get the offset of a field in a struct type
pub fn get_field_offset(type_template: &TypeTemplate, field_name: &str) -> Option<usize> {
    if let TypeTemplate::Struct(s) = type_template {
        s.get_field(field_name).map(|f| f.offset)
    } else {
        None
    }
}

/// Get the offset of a field in a struct/union, including anonymous wrapper members.
pub fn get_field_offset_recursive(type_template: &TypeTemplate, field_name: &str) -> Option<usize> {
    fn inner(template: &TypeTemplate, target: &str, base: usize) -> Option<usize> {
        match template {
            TypeTemplate::Struct(s) => {
                if let Some(field) = s.get_field(target) {
                    return Some(base + field.offset);
                }

                for field in &s.fields {
                    if !field.name.starts_with("unnamed_field_") {
                        continue;
                    }
                    if let Some(offset) =
                        inner(field.template.as_ref(), target, base + field.offset)
                    {
                        return Some(offset);
                    }
                }

                None
            }
            TypeTemplate::Union(u) => {
                if let Some(member) = u.members.iter().find(|m| m.name == target) {
                    return Some(base + member.offset);
                }

                for member in &u.members {
                    if !member.name.starts_with("unnamed_field_") {
                        continue;
                    }
                    if let Some(offset) =
                        inner(member.template.as_ref(), target, base + member.offset)
                    {
                        return Some(offset);
                    }
                }

                None
            }
            _ => None,
        }
    }

    inner(type_template, field_name, 0)
}

/// Get array field offset/count in a struct/union, including anonymous wrapper members.
pub fn get_array_field_offset_count_recursive(
    type_template: &TypeTemplate,
    field_name: &str,
) -> Option<(usize, usize)> {
    fn inner(template: &TypeTemplate, target: &str, base: usize) -> Option<(usize, usize)> {
        match template {
            TypeTemplate::Struct(s) => {
                if let Some(field) = s.get_field(target) {
                    if let TypeTemplate::Array(arr) = field.template.as_ref() {
                        return Some((base + field.offset, arr.count));
                    }
                }

                for field in &s.fields {
                    if !field.name.starts_with("unnamed_field_") {
                        continue;
                    }
                    if let Some(result) =
                        inner(field.template.as_ref(), target, base + field.offset)
                    {
                        return Some(result);
                    }
                }

                None
            }
            TypeTemplate::Union(u) => {
                if let Some(member) = u.members.iter().find(|m| m.name == target) {
                    if let TypeTemplate::Array(arr) = member.template.as_ref() {
                        return Some((base + member.offset, arr.count));
                    }
                }

                for member in &u.members {
                    if !member.name.starts_with("unnamed_field_") {
                        continue;
                    }
                    if let Some(result) =
                        inner(member.template.as_ref(), target, base + member.offset)
                    {
                        return Some(result);
                    }
                }

                None
            }
            _ => None,
        }
    }

    inner(type_template, field_name, 0)
}

/// Get field offset and field template, including anonymous wrapper members.
pub fn get_field_template_recursive(
    type_template: &TypeTemplate,
    field_name: &str,
) -> Option<(usize, Arc<TypeTemplate>)> {
    fn inner(
        template: &TypeTemplate,
        target: &str,
        base: usize,
    ) -> Option<(usize, Arc<TypeTemplate>)> {
        match template {
            TypeTemplate::Struct(s) => {
                if let Some(field) = s.get_field(target) {
                    return Some((base + field.offset, field.template.clone()));
                }

                for field in &s.fields {
                    if !field.name.starts_with("unnamed_field_") {
                        continue;
                    }
                    if let Some(result) =
                        inner(field.template.as_ref(), target, base + field.offset)
                    {
                        return Some(result);
                    }
                }

                None
            }
            TypeTemplate::Union(u) => {
                if let Some(member) = u.members.iter().find(|m| m.name == target) {
                    return Some((base + member.offset, member.template.clone()));
                }

                for member in &u.members {
                    if !member.name.starts_with("unnamed_field_") {
                        continue;
                    }
                    if let Some(result) =
                        inner(member.template.as_ref(), target, base + member.offset)
                    {
                        return Some(result);
                    }
                }

                None
            }
            _ => None,
        }
    }

    inner(type_template, field_name, 0)
}

/// Read a null-terminated string from bytes
pub fn read_cstring(data: &[u8]) -> String {
    let len = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..len]).to_string()
}

/// Iterate a task list_head where each list entry embeds a task_struct list member.
fn get_threads_from_list_head(
    layer: &dyn DataLayer,
    list_head: Address,
    member_offset: usize,
    task_addr: Address,
) -> Vec<Address> {
    let mut threads = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Read the first next pointer (no mask - these are virtual addresses)
    let first = match read_pointer(layer, list_head) {
        Ok(addr) => addr,
        Err(_) => return threads,
    };

    if first == 0 || first == list_head {
        return threads;
    }

    let mut current = first;
    let mut iterations = 0;

    // Iterate through the list
    while current != 0 && current != list_head && !seen.contains(&current) && iterations < 1000 {
        seen.insert(current);
        iterations += 1;

        // Convert list_head address back to task_struct address
        let thread_addr = current.saturating_sub(member_offset as u64);
        if is_valid_kernel_address(thread_addr) && thread_addr != task_addr {
            threads.push(thread_addr);
        }

        // Read next pointer (no mask - these are virtual addresses)
        current = match read_pointer(layer, current) {
            Ok(addr) => addr,
            Err(_) => break,
        };
    }

    threads
}

/// Iterate threads for a task via thread_group linked list
/// Returns all tasks in the same thread group
pub fn get_threads(
    layer: &dyn DataLayer,
    task: &TaskStruct,
    thread_group_offset: usize,
) -> Vec<Address> {
    let thread_group_head = task.address() + thread_group_offset as u64;
    get_threads_from_list_head(
        layer,
        thread_group_head,
        thread_group_offset,
        task.address(),
    )
}

/// Collect all processes from task list, optionally including threads
pub fn collect_processes_with_threads(
    layer: &dyn DataLayer,
    init_task_addr: Address,
    template: &TypeTemplate,
    include_threads: bool,
) -> Vol3Result<Vec<TaskStruct>> {
    let task_struct = TaskStruct::new(init_task_addr, Arc::new(template.clone()))?;
    let tasks_offset = task_struct.offsets().tasks_next;

    // Thread iteration differs by kernel:
    // - kernels < 6.7: task_struct.thread_group list / thread_group member
    // - kernels >= 6.7: task_struct.signal->thread_head list / task_struct.thread_node member
    let thread_group_offset = get_field_offset_recursive(template, "thread_group").unwrap_or(0);
    let thread_node_offset = get_field_offset_recursive(template, "thread_node").unwrap_or(0);
    let (signal_offset, signal_field_template) = get_field_template_recursive(template, "signal")
        .unwrap_or((0, Arc::new(TypeTemplate::Void)));
    let signal_struct_template = match signal_field_template.as_ref() {
        TypeTemplate::Pointer(p) => Some(p.target.clone()),
        TypeTemplate::Struct(_) => Some(signal_field_template.clone()),
        _ => None,
    };
    let signal_thread_head_offset = signal_struct_template
        .as_ref()
        .and_then(|t| get_field_offset_recursive(t.as_ref(), "thread_head"))
        .unwrap_or(0);

    let mut tasks = Vec::new();
    let mut seen_tasks = std::collections::HashSet::new();
    let template_arc = Arc::new(template.clone());

    // Iterate through the main task list
    for task_addr in iter_tasks(layer, init_task_addr, tasks_offset) {
        if !is_valid_kernel_address(task_addr) {
            continue;
        }

        if let Ok(task) = TaskStruct::new(task_addr, template_arc.clone()) {
            if seen_tasks.insert(task.address()) {
                tasks.push(task.clone());
            }

            // Include threads if requested
            if include_threads {
                let thread_addrs =
                    if signal_offset > 0 && signal_thread_head_offset > 0 && thread_node_offset > 0
                    {
                        let signal_ptr =
                            read_pointer(layer, task.address() + signal_offset as u64).unwrap_or(0);
                        if signal_ptr != 0 && is_valid_kernel_address(signal_ptr) {
                            let thread_head = signal_ptr + signal_thread_head_offset as u64;
                            get_threads_from_list_head(
                                layer,
                                thread_head,
                                thread_node_offset,
                                task.address(),
                            )
                        } else {
                            Vec::new()
                        }
                    } else if thread_group_offset > 0 {
                        get_threads(layer, &task, thread_group_offset)
                    } else {
                        Vec::new()
                    };

                for thread_addr in thread_addrs {
                    if let Ok(thread_task) = TaskStruct::new(thread_addr, template_arc.clone()) {
                        if seen_tasks.insert(thread_task.address()) {
                            tasks.push(thread_task);
                        }
                    }
                }
            }
        }
    }

    Ok(tasks)
}
