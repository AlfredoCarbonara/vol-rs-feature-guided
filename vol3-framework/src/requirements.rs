//! Requirements system for plugins.
//!
//! Requirements describe what a plugin needs to run.

use std::any::Any;
use std::collections::HashMap;

use vol3_core::error::Vol3Result;

/// Type of requirement
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementType {
    /// A string value
    String,
    /// An integer value
    Int,
    /// A boolean value
    Bool,
    /// A file path
    Path,
    /// A layer requirement
    Layer,
    /// A symbol table requirement
    SymbolTable,
    /// A list of values
    List,
    /// A choice from options
    Choice(Vec<String>),
}

/// A requirement for a plugin
#[derive(Debug, Clone)]
pub struct Requirement {
    /// Requirement name
    pub name: String,
    /// Description
    pub description: String,
    /// Requirement type
    pub req_type: RequirementType,
    /// Whether this requirement is optional
    pub optional: bool,
    /// Default value (if any)
    pub default: Option<serde_json::Value>,
}

impl Requirement {
    /// Create a new string requirement
    pub fn string(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            req_type: RequirementType::String,
            optional: false,
            default: None,
        }
    }

    /// Create a new integer requirement
    pub fn int(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            req_type: RequirementType::Int,
            optional: false,
            default: None,
        }
    }

    /// Create a new boolean requirement
    pub fn bool(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            req_type: RequirementType::Bool,
            optional: false,
            default: None,
        }
    }

    /// Create a new path requirement
    pub fn path(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            req_type: RequirementType::Path,
            optional: false,
            default: None,
        }
    }

    /// Create a new layer requirement
    pub fn layer(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            req_type: RequirementType::Layer,
            optional: false,
            default: None,
        }
    }

    /// Create a new symbol table requirement
    pub fn symbol_table(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            req_type: RequirementType::SymbolTable,
            optional: false,
            default: None,
        }
    }

    /// Create a choice requirement
    pub fn choice(
        name: impl Into<String>,
        description: impl Into<String>,
        choices: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            req_type: RequirementType::Choice(choices),
            optional: false,
            default: None,
        }
    }

    /// Make this requirement optional
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Set a default value
    pub fn with_default(mut self, value: serde_json::Value) -> Self {
        self.default = Some(value);
        self
    }
}

/// Collection of requirements
#[derive(Debug, Clone, Default)]
pub struct Requirements {
    /// List of requirements
    requirements: Vec<Requirement>,
    /// Name to index map
    by_name: HashMap<String, usize>,
}

impl Requirements {
    /// Create a new empty requirements collection
    pub fn new() -> Self {
        Self {
            requirements: Vec::new(),
            by_name: HashMap::new(),
        }
    }

    /// Add a requirement
    pub fn add(&mut self, req: Requirement) {
        let index = self.requirements.len();
        self.by_name.insert(req.name.clone(), index);
        self.requirements.push(req);
    }

    /// Get a requirement by name
    pub fn get(&self, name: &str) -> Option<&Requirement> {
        self.by_name.get(name).map(|&i| &self.requirements[i])
    }

    /// Check if a requirement exists
    pub fn contains(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// Iterate over requirements
    pub fn iter(&self) -> impl Iterator<Item = &Requirement> {
        self.requirements.iter()
    }

    /// Get the number of requirements
    pub fn len(&self) -> usize {
        self.requirements.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.requirements.is_empty()
    }

    /// Get required (non-optional) requirements
    pub fn required(&self) -> impl Iterator<Item = &Requirement> {
        self.requirements.iter().filter(|r| !r.optional)
    }

    /// Get optional requirements
    pub fn optional(&self) -> impl Iterator<Item = &Requirement> {
        self.requirements.iter().filter(|r| r.optional)
    }
}

/// Builder for requirements
pub struct RequirementsBuilder {
    requirements: Requirements,
}

impl Default for RequirementsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RequirementsBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            requirements: Requirements::new(),
        }
    }

    /// Add a requirement
    pub fn add(mut self, req: Requirement) -> Self {
        self.requirements.add(req);
        self
    }

    /// Add a string requirement
    pub fn string(self, name: impl Into<String>, description: impl Into<String>) -> Self {
        self.add(Requirement::string(name, description))
    }

    /// Add an optional string requirement
    pub fn string_optional(self, name: impl Into<String>, description: impl Into<String>) -> Self {
        self.add(Requirement::string(name, description).optional())
    }

    /// Add an integer requirement
    pub fn int(self, name: impl Into<String>, description: impl Into<String>) -> Self {
        self.add(Requirement::int(name, description))
    }

    /// Add an optional integer requirement
    pub fn int_optional(self, name: impl Into<String>, description: impl Into<String>) -> Self {
        self.add(Requirement::int(name, description).optional())
    }

    /// Add a boolean requirement
    pub fn bool(self, name: impl Into<String>, description: impl Into<String>) -> Self {
        self.add(Requirement::bool(name, description))
    }

    /// Add a path requirement
    pub fn path(self, name: impl Into<String>, description: impl Into<String>) -> Self {
        self.add(Requirement::path(name, description))
    }

    /// Add a layer requirement
    pub fn layer(self, name: impl Into<String>, description: impl Into<String>) -> Self {
        self.add(Requirement::layer(name, description))
    }

    /// Add a symbol table requirement
    pub fn symbol_table(self, name: impl Into<String>, description: impl Into<String>) -> Self {
        self.add(Requirement::symbol_table(name, description))
    }

    /// Build the requirements
    pub fn build(self) -> Requirements {
        self.requirements
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_requirements_builder() {
        let reqs = RequirementsBuilder::new()
            .layer("primary", "Primary memory layer")
            .symbol_table("vmlinux", "Kernel symbol table")
            .int_optional("pid", "Process ID filter")
            .build();

        assert_eq!(reqs.len(), 3);
        assert!(reqs.contains("primary"));
        assert!(reqs.contains("vmlinux"));
        assert!(reqs.contains("pid"));

        let pid_req = reqs.get("pid").unwrap();
        assert!(pid_req.optional);
    }

    #[test]
    fn test_requirement_types() {
        let string_req = Requirement::string("name", "A name");
        assert_eq!(string_req.req_type, RequirementType::String);

        let choice_req =
            Requirement::choice("format", "Output format", vec!["csv".into(), "json".into()]);
        if let RequirementType::Choice(choices) = choice_req.req_type {
            assert_eq!(choices, vec!["csv", "json"]);
        } else {
            panic!("Expected Choice type");
        }
    }
}
