//! Common types used throughout the Volatility3 framework.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Address type - 64-bit to handle all architectures
pub type Address = u64;

/// Size type for lengths and offsets
pub type Size = usize;

/// Progress callback type for long-running operations
pub type ProgressCallback = Box<dyn Fn(f64, Option<&str>) + Send + Sync>;

/// A value that may be absent for various reasons.
///
/// This corresponds to the Python NotAvailableValue, NotApplicableValue, etc.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AbsentValue {
    /// The value could not be read from memory
    Unreadable,
    /// The value could not be parsed/interpreted
    Unparsable,
    /// The value is not applicable in this context
    NotApplicable,
    /// The value was not available
    NotAvailable,
    /// Custom reason
    Custom(String),
}

impl fmt::Display for AbsentValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbsentValue::Unreadable => write!(f, "N/A (unreadable)"),
            AbsentValue::Unparsable => write!(f, "N/A (unparsable)"),
            AbsentValue::NotApplicable => write!(f, "-"),
            AbsentValue::NotAvailable => write!(f, "N/A"),
            AbsentValue::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// A cell value in a TreeGrid that may be present or absent.
#[derive(Debug, Clone)]
pub enum CellValue {
    /// An integer value
    Int(i64),
    /// An unsigned integer value
    UInt(u64),
    /// A hexadecimal value (for addresses, offsets)
    Hex(u64),
    /// A string value
    String(String),
    /// A floating-point value
    Float(f64),
    /// A byte array value
    Bytes(Vec<u8>),
    /// A boolean value
    Bool(bool),
    /// A datetime value
    DateTime(chrono::DateTime<chrono::Utc>),
    /// An absent/missing value
    Absent(AbsentValue),
    /// An error value
    Error(std::string::String),
    /// Tree depth for hierarchical output (special - rendered as first column)
    TreeDepth(i64),
}

impl CellValue {
    /// Returns true if this is an absent value
    pub fn is_absent(&self) -> bool {
        matches!(self, CellValue::Absent(_))
    }

    /// Try to get the value as an i64
    pub fn as_int(&self) -> Option<i64> {
        match self {
            CellValue::Int(v) => Some(*v),
            CellValue::UInt(v) => (*v).try_into().ok(),
            _ => None,
        }
    }

    /// Try to get the value as a string reference
    pub fn as_str(&self) -> Option<&str> {
        match self {
            CellValue::String(s) => Some(s),
            _ => None,
        }
    }
}

impl fmt::Display for CellValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CellValue::Int(v) => write!(f, "{}", v),
            CellValue::UInt(v) => write!(f, "{}", v),
            CellValue::Hex(v) => write!(f, "{:#x}", v),
            CellValue::String(s) => write!(f, "{}", s),
            CellValue::Float(v) => write!(f, "{}", v),
            CellValue::Bytes(b) => write!(f, "{:?}", b),
            CellValue::Bool(b) => write!(f, "{}", b),
            CellValue::DateTime(dt) => write!(f, "{}", dt.format("%Y-%m-%d %H:%M:%S UTC")),
            CellValue::Absent(a) => write!(f, "{}", a),
            CellValue::Error(e) => write!(f, "Error: {}", e),
            CellValue::TreeDepth(d) => write!(f, "{}", d),
        }
    }
}

impl From<i64> for CellValue {
    fn from(v: i64) -> Self {
        CellValue::Int(v)
    }
}

impl From<u64> for CellValue {
    fn from(v: u64) -> Self {
        CellValue::UInt(v)
    }
}

impl From<i32> for CellValue {
    fn from(v: i32) -> Self {
        CellValue::Int(v as i64)
    }
}

impl From<u32> for CellValue {
    fn from(v: u32) -> Self {
        CellValue::UInt(v as u64)
    }
}

impl From<String> for CellValue {
    fn from(s: String) -> Self {
        CellValue::String(s)
    }
}

impl From<&str> for CellValue {
    fn from(s: &str) -> Self {
        CellValue::String(s.to_string())
    }
}

impl From<f64> for CellValue {
    fn from(v: f64) -> Self {
        CellValue::Float(v)
    }
}

impl From<bool> for CellValue {
    fn from(b: bool) -> Self {
        CellValue::Bool(b)
    }
}

impl From<chrono::DateTime<chrono::Utc>> for CellValue {
    fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
        CellValue::DateTime(dt)
    }
}

impl<T: Into<CellValue>> From<Option<T>> for CellValue {
    fn from(opt: Option<T>) -> Self {
        match opt {
            Some(v) => v.into(),
            None => CellValue::Absent(AbsentValue::NotAvailable),
        }
    }
}

/// Column type definitions for TreeGrid columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColumnType {
    /// Integer column
    Int,
    /// String column
    String,
    /// Floating-point column
    Float,
    /// Byte array column
    Bytes,
    /// Boolean column
    Bool,
    /// DateTime column
    DateTime,
    /// Hex-formatted address column
    Hex,
}

/// A column definition for TreeGrid.
#[derive(Debug, Clone)]
pub struct Column {
    /// The column name
    pub name: String,
    /// The column type
    pub column_type: ColumnType,
}

impl Column {
    /// Create a new column definition
    pub fn new(name: impl Into<String>, column_type: ColumnType) -> Self {
        Self {
            name: name.into(),
            column_type,
        }
    }
}

/// Format hints for rendering values.
///
/// These correspond to the Python format_hints module.
#[derive(Debug, Clone)]
pub enum FormatHint {
    /// Display as hexadecimal
    Hex(u64),
    /// Display as binary
    Bin(Vec<u8>),
    /// Display as hexdump
    HexDump(Vec<u8>),
    /// Display with specific width
    Width(usize, Box<CellValue>),
}

impl FormatHint {
    /// Create a hex format hint
    pub fn hex(value: u64) -> CellValue {
        // Store as string with hex formatting
        CellValue::String(format!("{:#x}", value))
    }
}

/// Endianness for binary data interpretation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Endianness {
    /// Little-endian byte order
    #[default]
    Little,
    /// Big-endian byte order
    Big,
}

/// Architecture information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    /// 32-bit Intel/x86
    X86,
    /// 64-bit Intel/x86-64
    X64,
    /// 32-bit ARM
    Arm,
    /// 64-bit ARM
    Arm64,
    /// Unknown architecture
    Unknown,
}

impl Architecture {
    /// Returns the pointer size for this architecture in bytes
    pub fn pointer_size(&self) -> usize {
        match self {
            Architecture::X86 | Architecture::Arm => 4,
            Architecture::X64 | Architecture::Arm64 => 8,
            Architecture::Unknown => 8, // Default to 64-bit
        }
    }

    /// Returns true if this is a 64-bit architecture
    pub fn is_64bit(&self) -> bool {
        matches!(self, Architecture::X64 | Architecture::Arm64)
    }
}

impl Default for Architecture {
    fn default() -> Self {
        Architecture::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_value_conversions() {
        let int_val: CellValue = 42i64.into();
        assert_eq!(int_val.as_int(), Some(42));

        let str_val: CellValue = "test".into();
        assert_eq!(str_val.as_str(), Some("test"));

        let opt_val: CellValue = None::<i64>.into();
        assert!(opt_val.is_absent());
    }

    #[test]
    fn test_architecture_pointer_size() {
        assert_eq!(Architecture::X86.pointer_size(), 4);
        assert_eq!(Architecture::X64.pointer_size(), 8);
    }

    #[test]
    fn test_format_hint_hex() {
        let hint = FormatHint::hex(0xdeadbeef);
        if let CellValue::String(s) = hint {
            assert!(s.contains("deadbeef"));
        } else {
            panic!("Expected string");
        }
    }
}
