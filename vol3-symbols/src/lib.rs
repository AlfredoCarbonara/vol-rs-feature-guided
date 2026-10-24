//! # vol3-symbols
//!
//! Symbol table implementations for the Volatility3 Rust framework.
//!
//! This crate provides:
//! - ISF (Intermediate Symbol Format) parsing
//! - Symbol table interfaces and implementations
//! - Native type definitions
//! - Type template system

pub mod isf;
pub mod native;
pub mod space;
pub mod traits;
pub mod types;

pub use isf::IntermediateSymbolTable;
pub use native::NativeTable;
pub use space::{SymbolSpace, SymbolSpaceBuilder};
pub use traits::{Enumeration, Symbol, SymbolTableInterface};
pub use types::{
    ArrayTemplate, BitFieldTemplate, EnumTemplate, FieldInfo, PointerTemplate, PrimitiveTemplate,
    StructTemplate, TypeTemplate, UnionTemplate,
};
