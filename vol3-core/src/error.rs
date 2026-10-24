//! Error types for the Volatility3 framework.
//!
//! This module provides a comprehensive error taxonomy that mirrors the Python
//! volatility3.framework.exceptions module, ensuring behavioral parity.

use thiserror::Error;

/// The primary error type for the Volatility3 framework.
#[derive(Error, Debug)]
pub enum Vol3Error {
    /// Errors related to layer operations
    #[error("Layer error: {0}")]
    Layer(#[from] LayerError),

    /// Errors related to symbol operations
    #[error("Symbol error: {0}")]
    Symbol(#[from] SymbolError),

    /// Errors related to object operations
    #[error("Object error: {0}")]
    Object(#[from] ObjectError),

    /// Errors related to plugin operations
    #[error("Plugin error: {0}")]
    Plugin(#[from] PluginError),

    /// Errors related to configuration
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Errors related to rendering
    #[error("Render error: {0}")]
    Render(#[from] RenderError),

    /// Generic I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Errors related to memory layer operations.
///
/// These errors correspond to volatility3.framework.exceptions.InvalidAddressException
/// and related layer errors.
#[derive(Error, Debug, Clone)]
pub enum LayerError {
    /// An invalid memory address was accessed
    #[error("Invalid address {address:#x} in layer '{layer_name}'")]
    InvalidAddress { layer_name: String, address: u64 },

    /// A paged-out address was encountered
    #[error("Paged out address {address:#x} (swap location: {swap_offset:#x})")]
    PagedOut { address: u64, swap_offset: u64 },

    /// A page fault occurred during read
    #[error("Page fault at address {address:#x} in layer '{layer_name}'")]
    PageFault { layer_name: String, address: u64 },

    /// The layer format is invalid
    #[error("Invalid layer format: {0}")]
    InvalidFormat(String),

    /// The layer does not exist
    #[error("Layer not found: {0}")]
    NotFound(String),

    /// The layer is already present
    #[error("Layer already exists: {0}")]
    AlreadyExists(String),

    /// The layer has unmet dependencies
    #[error("Layer '{layer_name}' has unmet dependencies: {dependencies:?}")]
    UnmetDependencies {
        layer_name: String,
        dependencies: Vec<String>,
    },

    /// The layer is not writable
    #[error("Layer '{0}' is not writable")]
    NotWritable(String),

    /// Generic I/O error within a layer
    #[error("I/O error in layer '{layer_name}': {message}")]
    IoError { layer_name: String, message: String },
}

/// Errors related to symbol table operations.
///
/// These errors correspond to volatility3.framework.exceptions.SymbolError
/// and related symbol errors.
#[derive(Error, Debug, Clone)]
pub enum SymbolError {
    /// A symbol was not found
    #[error("Symbol not found: {0}")]
    NotFound(String),

    /// A type was not found
    #[error("Type not found: {0}")]
    TypeNotFound(String),

    /// An enumeration was not found
    #[error("Enumeration not found: {0}")]
    EnumerationNotFound(String),

    /// The ISF format is invalid
    #[error("Invalid ISF format: {0}")]
    InvalidFormat(String),

    /// The ISF version is not supported
    #[error("Unsupported ISF version: {0}")]
    UnsupportedVersion(String),

    /// A symbol table was not found
    #[error("Symbol table not found: {0}")]
    TableNotFound(String),

    /// A symbol table already exists
    #[error("Symbol table already exists: {0}")]
    TableAlreadyExists(String),

    /// Symbol space error
    #[error("Symbol space error: {0}")]
    SpaceError(String),
}

/// Errors related to object operations.
///
/// These errors correspond to volatility3.framework.exceptions and object-related errors.
#[derive(Error, Debug, Clone)]
pub enum ObjectError {
    /// A member was not found on the object
    #[error("Member '{member}' not found on type '{type_name}'")]
    MemberNotFound { type_name: String, member: String },

    /// A null pointer was dereferenced
    #[error("Null pointer dereference")]
    NullPointer,

    /// The object is not valid
    #[error("Invalid object at offset {offset:#x}")]
    InvalidObject { offset: u64 },

    /// The array index is out of bounds
    #[error("Array index {index} out of bounds (size: {size})")]
    IndexOutOfBounds { index: usize, size: usize },

    /// The object cannot be cast to the requested type
    #[error("Cannot cast '{from}' to '{to}'")]
    InvalidCast { from: String, to: String },

    /// The object template is invalid
    #[error("Invalid object template: {0}")]
    InvalidTemplate(String),

    /// The underlying layer read failed
    #[error("Layer read failed: {0}")]
    LayerReadFailed(#[from] LayerError),
}

/// Errors related to plugin operations.
#[derive(Error, Debug)]
pub enum PluginError {
    /// A required configuration is missing
    #[error("Missing required configuration: {0}")]
    MissingRequirement(String),

    /// The plugin requirements are unsatisfied
    #[error("Unsatisfied requirements: {0:?}")]
    UnsatisfiedRequirements(Vec<String>),

    /// A plugin was not found
    #[error("Plugin not found: {0}")]
    NotFound(String),

    /// The plugin execution failed
    #[error("Plugin execution failed: {0}")]
    ExecutionFailed(String),

    /// The plugin version is incompatible
    #[error("Incompatible plugin version: {0}")]
    IncompatibleVersion(String),
}

/// Errors related to configuration operations.
#[derive(Error, Debug, Clone)]
pub enum ConfigError {
    /// A configuration key was not found
    #[error("Configuration key not found: {0}")]
    KeyNotFound(String),

    /// The configuration value is invalid
    #[error("Invalid configuration value for '{key}': {message}")]
    InvalidValue { key: String, message: String },

    /// The configuration path is invalid
    #[error("Invalid configuration path: {0}")]
    InvalidPath(String),

    /// The configuration type is mismatched
    #[error("Type mismatch for '{key}': expected {expected}, got {actual}")]
    TypeMismatch {
        key: String,
        expected: String,
        actual: String,
    },
}

/// Errors related to rendering operations.
#[derive(Error, Debug)]
pub enum RenderError {
    /// The output format is not supported
    #[error("Unsupported output format: {0}")]
    UnsupportedFormat(String),

    /// An I/O error occurred during rendering
    #[error("I/O error during rendering: {0}")]
    IoError(#[from] std::io::Error),

    /// A formatting error occurred
    #[error("Formatting error: {0}")]
    FormatError(String),
}

/// Result type alias for Vol3Error
pub type Vol3Result<T> = Result<T, Vol3Error>;

/// Result type alias for LayerError
pub type LayerResult<T> = Result<T, LayerError>;

/// Result type alias for SymbolError
pub type SymbolResult<T> = Result<T, SymbolError>;

/// Result type alias for ObjectError
pub type ObjectResult<T> = Result<T, ObjectError>;

/// Result type alias for PluginError
pub type PluginResult<T> = Result<T, PluginError>;

/// Result type alias for ConfigError
pub type ConfigResult<T> = Result<T, ConfigError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_error_display() {
        let err = LayerError::InvalidAddress {
            layer_name: "memory".to_string(),
            address: 0xdeadbeef,
        };
        assert!(err.to_string().contains("0xdeadbeef"));
        assert!(err.to_string().contains("memory"));
    }

    #[test]
    fn test_error_conversion() {
        let layer_err = LayerError::NotFound("test".to_string());
        let vol_err: Vol3Error = layer_err.into();
        assert!(matches!(vol_err, Vol3Error::Layer(_)));
    }
}
