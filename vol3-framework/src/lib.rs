//! # vol3-framework
//!
//! Core framework for the Volatility3 Rust implementation.
//!
//! This crate provides:
//! - Context for managing layers, symbols, and modules
//! - Plugin interface and requirements system
//! - Automagic for automatic configuration
//! - Module infrastructure

pub mod automagic;
pub mod context;
pub mod module;
pub mod requirements;
pub mod windows_automagic;

pub use automagic::{Automagic, AutomagicResult};
pub use context::Context;
pub use module::{Module, ModuleRequirements};
pub use requirements::{Requirement, RequirementType};
