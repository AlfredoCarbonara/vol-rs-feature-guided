//! Automagic system.
//!
//! Automagic modules automatically configure requirements based on the input data.

use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_layers::traits::DataLayer;

use crate::context::Context;
use crate::requirements::Requirements;

/// Result from running automagic
#[derive(Debug, Clone)]
pub struct AutomagicResult {
    /// Whether automagic was successful
    pub success: bool,
    /// Message describing what was done
    pub message: String,
    /// Configuration paths that were set
    pub config_paths: Vec<String>,
}

impl AutomagicResult {
    /// Create a successful result
    pub fn success(message: impl Into<String>, config_paths: Vec<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            config_paths,
        }
    }

    /// Create a failed result
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            config_paths: Vec::new(),
        }
    }
}

/// An automagic module that configures the context
pub trait Automagic: Send + Sync {
    /// Get the automagic name
    fn name(&self) -> &str;

    /// Get the priority (higher runs first)
    fn priority(&self) -> i32 {
        0
    }

    /// Check if this automagic is applicable
    fn is_applicable(&self, context: &Context, requirements: &Requirements) -> bool;

    /// Run the automagic
    fn run(
        &self,
        context: &mut Context,
        requirements: &Requirements,
    ) -> Vol3Result<AutomagicResult>;
}

/// Registry for automagic modules
pub struct AutomagicRegistry {
    automagics: Vec<Arc<dyn Automagic>>,
}

impl Default for AutomagicRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AutomagicRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            automagics: Vec::new(),
        }
    }

    /// Register an automagic module
    pub fn register(&mut self, automagic: Arc<dyn Automagic>) {
        self.automagics.push(automagic);
        // Sort by priority (descending)
        self.automagics
            .sort_by(|a, b| b.priority().cmp(&a.priority()));
    }

    /// Get all automagic modules
    pub fn automagics(&self) -> &[Arc<dyn Automagic>] {
        &self.automagics
    }

    /// Run all applicable automagics
    pub fn run_all(
        &self,
        context: &mut Context,
        requirements: &Requirements,
    ) -> Vec<AutomagicResult> {
        let mut results = Vec::new();

        for automagic in &self.automagics {
            if automagic.is_applicable(context, requirements) {
                match automagic.run(context, requirements) {
                    Ok(result) => results.push(result),
                    Err(e) => results.push(AutomagicResult::failure(format!(
                        "{}: {}",
                        automagic.name(),
                        e
                    ))),
                }
            }
        }

        results
    }
}

/// Automagic for constructing layer stacks
pub struct LayerStacker;

impl Automagic for LayerStacker {
    fn name(&self) -> &str {
        "layer_stacker"
    }

    fn priority(&self) -> i32 {
        100
    }

    fn is_applicable(&self, context: &Context, requirements: &Requirements) -> bool {
        // Check if we have a primary layer requirement and a file path
        requirements.contains("primary") && context.config_contains("file_path")
    }

    fn run(
        &self,
        context: &mut Context,
        _requirements: &Requirements,
    ) -> Vol3Result<AutomagicResult> {
        use vol3_core::error::ConfigError;

        // Get file path from config
        let file_path = context
            .config_get_string("file_path")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("file_path".to_string())))?;

        // Create file layer
        let layer = vol3_layers::physical::FileLayer::new("file_layer", &file_path)?;
        let layer_name = layer.name().to_string();
        context.add_layer(Arc::new(layer));

        // Set config
        context.config_set("primary", layer_name.clone());

        Ok(AutomagicResult::success(
            format!("Created layer '{}' from '{}'", layer_name, file_path),
            vec!["primary".to_string()],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_automagic_result() {
        let success = AutomagicResult::success("Done", vec!["path1".to_string()]);
        assert!(success.success);

        let failure = AutomagicResult::failure("Failed");
        assert!(!failure.success);
    }

    #[test]
    fn test_automagic_registry() {
        let mut registry = AutomagicRegistry::new();
        registry.register(Arc::new(LayerStacker));

        assert_eq!(registry.automagics().len(), 1);
    }
}
