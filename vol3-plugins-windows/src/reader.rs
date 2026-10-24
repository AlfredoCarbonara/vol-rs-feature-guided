//! Little-endian primitive readers for Windows kernel objects.

use byteorder::{ByteOrder, LittleEndian};
use chrono::{DateTime, Utc};

use vol3_core::error::{PluginError, Vol3Error, Vol3Result};
use vol3_core::types::Address;
use vol3_layers::traits::DataLayer;

/// Number of 100-nanosecond ticks between 1601-01-01 and 1970-01-01.
const WINDOWS_TO_UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
const TICKS_PER_SECOND: u64 = 10_000_000;

pub fn read_u64(layer: &dyn DataLayer, address: Address) -> Vol3Result<u64> {
    let bytes = layer.read(address, 8, false)?;
    Ok(LittleEndian::read_u64(&bytes))
}

pub fn read_unsigned(layer: &dyn DataLayer, address: Address, size: usize) -> Vol3Result<u64> {
    let bytes = layer.read(address, size, false)?;
    match size {
        1 => Ok(bytes[0] as u64),
        2 => Ok(LittleEndian::read_u16(&bytes) as u64),
        4 => Ok(LittleEndian::read_u32(&bytes) as u64),
        8 => Ok(LittleEndian::read_u64(&bytes)),
        _ => Err(Vol3Error::Plugin(PluginError::ExecutionFailed(format!(
            "Unsupported Windows integer width: {size}"
        )))),
    }
}

pub fn read_c_string(
    layer: &dyn DataLayer,
    address: Address,
    maximum_length: usize,
) -> Vol3Result<String> {
    let bytes = layer.read(address, maximum_length, false)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

/// Convert a Windows `LARGE_INTEGER` FILETIME to UTC.
///
/// Zero is treated as unavailable, matching the common meaning of a zero
/// process exit time in Windows kernel objects.
pub fn filetime_to_utc(ticks: u64) -> Option<DateTime<Utc>> {
    if ticks == 0 || ticks < WINDOWS_TO_UNIX_EPOCH_TICKS {
        return None;
    }

    let unix_ticks = ticks - WINDOWS_TO_UNIX_EPOCH_TICKS;
    let seconds = (unix_ticks / TICKS_PER_SECOND) as i64;
    let nanoseconds = ((unix_ticks % TICKS_PER_SECOND) * 100) as u32;
    DateTime::from_timestamp(seconds, nanoseconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_windows_epoch_to_unix_epoch() {
        let timestamp = filetime_to_utc(WINDOWS_TO_UNIX_EPOCH_TICKS).unwrap();
        assert_eq!(timestamp.timestamp(), 0);
        assert_eq!(timestamp.timestamp_subsec_nanos(), 0);
    }

    #[test]
    fn zero_filetime_is_unavailable() {
        assert!(filetime_to_utc(0).is_none());
    }
}
