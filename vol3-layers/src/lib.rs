//! # vol3-layers
//!
//! Memory layer implementations for the Volatility3 Rust framework.
//!
//! This crate provides:
//! - `DataLayer` trait for raw data access
//! - `TranslationLayer` trait for address translation
//! - Physical layer implementations (file, mmap)
//! - Intel paging implementations
//! - VMware, LiME, and other format support

pub mod container;
pub mod elf;
pub mod intel;
pub mod physical;
pub mod scanner;
pub mod segmented;
pub mod traits;
pub mod vmware;

pub use container::LayerContainer;
pub use elf::Elf64Layer;
pub use scanner::ByteScanner;
pub use segmented::{Segment, SegmentedLayer};
pub use traits::{DataLayer, MappedRegion, ScannerInterface, TranslationLayer};
pub use vmware::VmwareLayer;
