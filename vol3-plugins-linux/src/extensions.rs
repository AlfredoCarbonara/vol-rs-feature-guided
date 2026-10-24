//! Linux kernel structure extensions.
//!
//! These provide higher-level access to kernel structures like task_struct.

use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};

use vol3_core::error::{ObjectResult, Vol3Error};
use vol3_core::types::Address;
use vol3_layers::traits::DataLayer;
use vol3_objects::traits::MemoryObject;
use vol3_objects::StructObject;
use vol3_symbols::{StructTemplate, TypeTemplate};

/// Extension trait for task_struct
pub trait TaskStructExt {
    /// Get the process ID
    fn pid(&self, layer: &dyn DataLayer) -> ObjectResult<i32>;

    /// Get the thread group ID (TGID)
    fn tgid(&self, layer: &dyn DataLayer) -> ObjectResult<i32>;

    /// Get the process name (comm)
    fn comm(&self, layer: &dyn DataLayer) -> ObjectResult<String>;

    /// Get the parent task address
    fn parent_addr(&self, layer: &dyn DataLayer) -> ObjectResult<Address>;

    /// Get the real_parent task address (used for PPID calculation)
    fn real_parent_addr(&self, layer: &dyn DataLayer) -> ObjectResult<Address>;

    /// Check if this is a kernel thread
    fn is_kernel_thread(&self, layer: &dyn DataLayer) -> ObjectResult<bool>;

    /// Get the task state
    fn state(&self, layer: &dyn DataLayer) -> ObjectResult<i64>;

    /// Get the exit state
    fn exit_state(&self, layer: &dyn DataLayer) -> ObjectResult<i32>;

    /// Get the mm (memory management) pointer
    fn mm(&self, layer: &dyn DataLayer) -> ObjectResult<Address>;

    /// Get the active_mm pointer
    fn active_mm(&self, layer: &dyn DataLayer) -> ObjectResult<Address>;

    /// Get credential information (uid, gid, euid, egid)
    fn get_creds(
        &self,
        layer: &dyn DataLayer,
    ) -> ObjectResult<(Option<u32>, Option<u32>, Option<u32>, Option<u32>)>;

    /// Get creation time as a formatted string (deprecated - use get_start_time_ns)
    fn get_create_time(&self, layer: &dyn DataLayer) -> Option<String>;

    /// Get the start time in nanoseconds since boot
    fn get_start_time_ns(&self, layer: &dyn DataLayer) -> Option<u64>;
}

/// A task_struct wrapper
#[derive(Clone)]
pub struct TaskStruct {
    /// Address in memory
    address: Address,
    /// Type template
    template: Arc<TypeTemplate>,
    /// Cached field offsets
    offsets: TaskOffsets,
}

/// Cached field offsets for task_struct
#[derive(Debug, Clone)]
pub struct TaskOffsets {
    pub pid: usize,
    pub tgid: usize,
    pub comm: usize,
    pub comm_size: usize,
    pub parent: usize,
    pub real_parent: usize,
    pub state: usize,
    pub exit_state: usize,
    pub flags: usize,
    pub mm: usize,
    pub active_mm: usize,
    pub tasks_next: usize,
    pub tasks_prev: usize,
    pub thread_group_next: usize,
    pub thread_group_prev: usize,
    pub cred: usize,
    pub start_time: usize,
    pub start_boottime: usize,
}

impl TaskStruct {
    /// Create a new task_struct wrapper
    pub fn new(address: Address, template: Arc<TypeTemplate>) -> ObjectResult<Self> {
        let offsets = Self::extract_offsets(&template)?;
        Ok(Self {
            address,
            template,
            offsets,
        })
    }

    /// Extract field offsets from template
    fn extract_offsets(template: &TypeTemplate) -> ObjectResult<TaskOffsets> {
        use vol3_core::error::ObjectError;

        if let TypeTemplate::Struct(s) = template {
            let get_offset = |name: &str| -> ObjectResult<usize> {
                s.get_field(name).map(|f| f.offset).ok_or_else(|| {
                    ObjectError::MemberNotFound {
                        type_name: "task_struct".to_string(),
                        member: name.to_string(),
                    }
                    .into()
                })
            };

            let comm_field = s.get_field("comm");
            let comm_size = comm_field.and_then(|f| f.template.size()).unwrap_or(16);

            Ok(TaskOffsets {
                pid: get_offset("pid")?,
                tgid: get_offset("tgid").unwrap_or_else(|_| get_offset("pid").unwrap_or(0)),
                comm: get_offset("comm")?,
                comm_size,
                parent: get_offset("parent").unwrap_or(0),
                real_parent: get_offset("real_parent")
                    .unwrap_or_else(|_| get_offset("parent").unwrap_or(0)),
                state: get_offset("state")
                    .or_else(|_| get_offset("__state"))
                    .unwrap_or(0),
                exit_state: get_offset("exit_state").unwrap_or(0),
                flags: get_offset("flags")?,
                mm: get_offset("mm")?,
                active_mm: get_offset("active_mm").unwrap_or(0),
                tasks_next: Self::get_list_head_offset(s, "tasks")?,
                tasks_prev: Self::get_list_head_offset(s, "tasks")? + 8,
                thread_group_next: Self::get_list_head_offset(s, "thread_group").unwrap_or(0),
                thread_group_prev: Self::get_list_head_offset(s, "thread_group").unwrap_or(0) + 8,
                cred: get_offset("cred").unwrap_or(0),
                start_time: get_offset("start_time").unwrap_or(0),
                start_boottime: get_offset("start_boottime").unwrap_or(0),
            })
        } else {
            Err(ObjectError::InvalidTemplate("Expected struct type".to_string()).into())
        }
    }

    /// Get offset of a list_head field
    fn get_list_head_offset(template: &StructTemplate, name: &str) -> ObjectResult<usize> {
        use vol3_core::error::ObjectError;
        template.get_field(name).map(|f| f.offset).ok_or_else(|| {
            ObjectError::MemberNotFound {
                type_name: "task_struct".to_string(),
                member: name.to_string(),
            }
            .into()
        })
    }

    /// Get the address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Get the offsets
    pub fn offsets(&self) -> &TaskOffsets {
        &self.offsets
    }
}

impl TaskStructExt for TaskStruct {
    fn pid(&self, layer: &dyn DataLayer) -> ObjectResult<i32> {
        use vol3_core::error::ObjectError;
        let bytes = layer
            .read(self.address + self.offsets.pid as u64, 4, false)
            .map_err(ObjectError::LayerReadFailed)?;
        Ok(LittleEndian::read_i32(&bytes))
    }

    fn tgid(&self, layer: &dyn DataLayer) -> ObjectResult<i32> {
        use vol3_core::error::ObjectError;
        let bytes = layer
            .read(self.address + self.offsets.tgid as u64, 4, false)
            .map_err(ObjectError::LayerReadFailed)?;
        Ok(LittleEndian::read_i32(&bytes))
    }

    fn comm(&self, layer: &dyn DataLayer) -> ObjectResult<String> {
        use vol3_core::error::ObjectError;
        let bytes = layer
            .read(
                self.address + self.offsets.comm as u64,
                self.offsets.comm_size,
                false,
            )
            .map_err(ObjectError::LayerReadFailed)?;

        // Find null terminator
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..len]).to_string())
    }

    fn parent_addr(&self, layer: &dyn DataLayer) -> ObjectResult<Address> {
        use vol3_core::error::ObjectError;
        let bytes = layer
            .read(self.address + self.offsets.parent as u64, 8, false)
            .map_err(ObjectError::LayerReadFailed)?;
        Ok(LittleEndian::read_u64(&bytes))
    }

    fn real_parent_addr(&self, layer: &dyn DataLayer) -> ObjectResult<Address> {
        use vol3_core::error::ObjectError;
        let bytes = layer
            .read(self.address + self.offsets.real_parent as u64, 8, false)
            .map_err(ObjectError::LayerReadFailed)?;
        Ok(LittleEndian::read_u64(&bytes))
    }

    fn is_kernel_thread(&self, layer: &dyn DataLayer) -> ObjectResult<bool> {
        // A kernel thread has mm == NULL
        let mm = self.mm(layer)?;
        Ok(mm == 0)
    }

    fn state(&self, layer: &dyn DataLayer) -> ObjectResult<i64> {
        use vol3_core::error::ObjectError;
        let bytes = layer
            .read(self.address + self.offsets.state as u64, 8, false)
            .map_err(ObjectError::LayerReadFailed)?;
        Ok(LittleEndian::read_i64(&bytes))
    }

    fn exit_state(&self, layer: &dyn DataLayer) -> ObjectResult<i32> {
        use vol3_core::error::ObjectError;
        let bytes = layer
            .read(self.address + self.offsets.exit_state as u64, 4, false)
            .map_err(ObjectError::LayerReadFailed)?;
        Ok(LittleEndian::read_i32(&bytes))
    }

    fn mm(&self, layer: &dyn DataLayer) -> ObjectResult<Address> {
        use vol3_core::error::ObjectError;
        let bytes = layer
            .read(self.address + self.offsets.mm as u64, 8, false)
            .map_err(ObjectError::LayerReadFailed)?;
        Ok(LittleEndian::read_u64(&bytes))
    }

    fn active_mm(&self, layer: &dyn DataLayer) -> ObjectResult<Address> {
        use vol3_core::error::ObjectError;
        let bytes = layer
            .read(self.address + self.offsets.active_mm as u64, 8, false)
            .map_err(ObjectError::LayerReadFailed)?;
        Ok(LittleEndian::read_u64(&bytes))
    }

    fn get_creds(
        &self,
        layer: &dyn DataLayer,
    ) -> ObjectResult<(Option<u32>, Option<u32>, Option<u32>, Option<u32>)> {
        use vol3_core::error::ObjectError;

        if self.offsets.cred == 0 {
            return Ok((None, None, None, None));
        }

        // Read cred pointer
        let cred_ptr_bytes = layer
            .read(self.address + self.offsets.cred as u64, 8, false)
            .map_err(ObjectError::LayerReadFailed)?;
        let cred_ptr = LittleEndian::read_u64(&cred_ptr_bytes);

        if cred_ptr == 0 || cred_ptr < 0xffff000000000000 {
            return Ok((None, None, None, None));
        }

        // Read uid, gid, euid, egid from cred struct
        // kuid_t/kgid_t are wrappers around u32 with the actual value at offset 0
        // Offsets from ISF (kernel 5.15.x): uid=8, gid=12, euid=24, egid=28
        let uid_bytes = layer.read(cred_ptr + 8, 4, false).ok();
        let gid_bytes = layer.read(cred_ptr + 12, 4, false).ok();
        let euid_bytes = layer.read(cred_ptr + 24, 4, false).ok();
        let egid_bytes = layer.read(cred_ptr + 28, 4, false).ok();

        let uid = uid_bytes.map(|b| LittleEndian::read_u32(&b));
        let gid = gid_bytes.map(|b| LittleEndian::read_u32(&b));
        let euid = euid_bytes.map(|b| LittleEndian::read_u32(&b));
        let egid = egid_bytes.map(|b| LittleEndian::read_u32(&b));

        Ok((uid, gid, euid, egid))
    }

    fn get_create_time(&self, layer: &dyn DataLayer) -> Option<String> {
        // Try start_boottime first (newer kernels), then start_time
        let time_offset = if self.offsets.start_boottime != 0 {
            self.offsets.start_boottime
        } else if self.offsets.start_time != 0 {
            self.offsets.start_time
        } else {
            return None;
        };

        // start_time/start_boottime is typically a u64 (nanoseconds since boot)
        let time_bytes = layer
            .read(self.address + time_offset as u64, 8, false)
            .ok()?;
        let time_ns = LittleEndian::read_u64(&time_bytes);

        if time_ns == 0 {
            return None;
        }

        // For now, return as a relative timestamp
        // Full implementation would need boot time to convert to absolute time
        let secs = time_ns / 1_000_000_000;
        let nsecs = time_ns % 1_000_000_000;

        // Return in UTC format matching Python's output style
        // Note: This is relative to boot, not absolute UTC
        Some(format!("{}.{:06} UTC", secs, nsecs / 1000))
    }

    fn get_start_time_ns(&self, layer: &dyn DataLayer) -> Option<u64> {
        // Try start_boottime first (newer kernels), then start_time
        let time_offset = if self.offsets.start_boottime != 0 {
            self.offsets.start_boottime
        } else if self.offsets.start_time != 0 {
            self.offsets.start_time
        } else {
            return None;
        };

        // start_time/start_boottime is typically a u64 (nanoseconds since boot)
        let time_bytes = layer
            .read(self.address + time_offset as u64, 8, false)
            .ok()?;
        let time_ns = LittleEndian::read_u64(&time_bytes);

        if time_ns == 0 {
            return None;
        }

        Some(time_ns)
    }
}

/// Linux list_head iterator
pub struct ListHeadIterator<'a> {
    layer: &'a dyn DataLayer,
    current: Address,
    head: Address,
    offset: usize,
    first: bool,
}

impl<'a> ListHeadIterator<'a> {
    /// Create a new iterator
    pub fn new(layer: &'a dyn DataLayer, head: Address, offset: usize) -> Self {
        Self {
            layer,
            current: head,
            head,
            offset,
            first: true,
        }
    }

    /// Read the next pointer from a list_head
    fn read_next(&self, addr: Address) -> Option<Address> {
        let bytes = self.layer.read(addr, 8, false).ok()?;
        Some(LittleEndian::read_u64(&bytes))
    }
}

impl Iterator for ListHeadIterator<'_> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            self.first = false;
            let next = self.read_next(self.current)?;
            if next == 0 || next == self.head {
                return None;
            }
            self.current = next;
            // Return the containing struct address
            Some(self.current - self.offset as u64)
        } else {
            let next = self.read_next(self.current)?;
            if next == 0 || next == self.head {
                return None;
            }
            self.current = next;
            Some(self.current - self.offset as u64)
        }
    }
}
