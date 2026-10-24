//! # vol3-core
//!
//! Core types, error handling, and configuration for the Volatility3 Rust framework.
//!
//! This crate provides the foundational types used throughout the Volatility3 framework:
//! - Error types (`error` module)
//! - Configuration tree (`config` module)
//! - Common types (`types` module)
//! - Constants (`constants` module)

pub mod config;
pub mod constants;
pub mod error;
pub mod types;

pub use config::HierarchicalDict;
pub use error::*;
pub use types::*;
