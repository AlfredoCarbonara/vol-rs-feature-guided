//! # vol3-objects
//!
//! Memory object implementations for the Volatility3 Rust framework.
//!
//! This crate provides:
//! - Memory object traits and base implementations
//! - Struct, pointer, array, and primitive object types
//! - Object factory for creating typed objects

pub mod array;
pub mod factory;
pub mod pointer;
pub mod primitive;
pub mod structure;
pub mod traits;

pub use array::ArrayObject;
pub use factory::ObjectFactory;
pub use pointer::PointerObject;
pub use primitive::{BoolObject, FloatObject, IntegerObject, PrimitiveObject};
pub use structure::StructObject;
pub use traits::{MemoryObject, ObjectInterface};
