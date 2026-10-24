//! ISF (Intermediate Symbol Format) parsing.
//!
//! This module handles parsing and loading ISF symbol files (.json.xz).

use std::collections::HashMap;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use log::{debug, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::traits::{Enumeration, Symbol, SymbolTableInterface};
use crate::types::{
    ArrayTemplate, BitFieldTemplate, EnumTemplate, FieldInfo, PointerTemplate, PrimitiveTemplate,
    StructTemplate, TypeTemplate, UnionTemplate,
};
use vol3_core::error::{SymbolError, SymbolResult, Vol3Error};
use vol3_core::types::Architecture;

/// ISF file format structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ISFFile {
    /// Metadata
    pub metadata: ISFMetadata,
    /// Base types
    #[serde(default)]
    pub base_types: HashMap<String, ISFBaseType>,
    /// User types
    #[serde(default)]
    pub user_types: HashMap<String, ISFUserType>,
    /// Symbols
    #[serde(default)]
    pub symbols: HashMap<String, ISFSymbol>,
    /// Enums
    #[serde(default)]
    pub enums: HashMap<String, ISFEnum>,
}

/// ISF metadata section
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ISFMetadata {
    /// Producer name
    #[serde(default)]
    pub producer: Option<ISFProducer>,
    /// Format version
    #[serde(default)]
    pub format: Option<String>,
    /// Linux specific
    #[serde(default)]
    pub linux: Option<ISFLinuxMetadata>,
    /// Symbol source
    #[serde(default)]
    pub source: Option<HashMap<String, Value>>,
}

/// ISF producer info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ISFProducer {
    /// Producer name
    pub name: Option<String>,
    /// Producer version
    pub version: Option<String>,
}

/// ISF Linux-specific metadata
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ISFLinuxMetadata {
    /// Kernel banner
    pub banner: Option<String>,
}

/// ISF base type definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ISFBaseType {
    /// Size in bytes
    pub size: usize,
    /// Whether signed
    #[serde(default)]
    pub signed: bool,
    /// Kind
    #[serde(default)]
    pub kind: Option<String>,
    /// Endian
    #[serde(default)]
    pub endian: Option<String>,
}

/// ISF user type (struct/union)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ISFUserType {
    /// Size in bytes
    pub size: usize,
    /// Fields
    #[serde(default)]
    pub fields: HashMap<String, ISFFieldDef>,
    /// Kind (struct or union)
    #[serde(default)]
    pub kind: Option<String>,
}

/// ISF field definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ISFFieldDef {
    /// Offset
    pub offset: usize,
    /// Type reference
    #[serde(rename = "type")]
    pub type_ref: ISFTypeReference,
    /// Whether this is an anonymous struct/union that should be flattened
    #[serde(default)]
    pub anonymous: bool,
}

/// ISF type reference
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ISFTypeReference {
    /// Struct with subtype
    WithSubtype {
        kind: String,
        #[serde(default)]
        subtype: Option<Box<ISFTypeReference>>,
        #[serde(default)]
        count: Option<usize>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        bit_position: Option<i64>,
        #[serde(default)]
        bit_length: Option<usize>,
        #[serde(rename = "type")]
        #[serde(default)]
        base_type: Option<Box<ISFTypeReference>>,
        #[serde(default)]
        size: Option<usize>,
        #[serde(default)]
        fields: Option<HashMap<String, ISFFieldDef>>,
    },
}

impl ISFTypeReference {
    /// Get the kind of this type reference
    pub fn kind(&self) -> &str {
        match self {
            ISFTypeReference::WithSubtype { kind, .. } => kind,
        }
    }
}

/// ISF symbol definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ISFSymbol {
    /// Address
    pub address: u64,
    /// Type (if specified)
    #[serde(rename = "type", default)]
    pub type_ref: Option<ISFTypeReference>,
    /// Constant data (if any)
    #[serde(default)]
    pub constant_data: Option<String>,
}

/// ISF enum definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ISFEnum {
    /// Size in bytes
    pub size: usize,
    /// Base type
    pub base: String,
    /// Constants
    pub constants: HashMap<String, i64>,
}

/// Intermediate symbol table parsed from ISF
pub struct IntermediateSymbolTable {
    /// Table name
    name: String,
    /// Architecture
    architecture: Architecture,
    /// The raw ISF data
    isf: ISFFile,
    /// Cached type templates
    type_cache: parking_lot::RwLock<HashMap<String, Arc<TypeTemplate>>>,
    /// Set of types currently being built (to detect cycles)
    building: parking_lot::RwLock<std::collections::HashSet<String>>,
    /// Native types reference
    native_types: HashMap<String, Arc<TypeTemplate>>,
}

impl IntermediateSymbolTable {
    fn default_cache_dir(cache_root: &Path) -> PathBuf {
        cache_root.join(".vol3_cache").join("isf_json")
    }

    fn cache_file_path(cache_root: &Path, source_path: &Path) -> SymbolResult<PathBuf> {
        let source_meta = fs::metadata(source_path).map_err(|e| {
            SymbolError::InvalidFormat(format!("Failed to stat ISF file for cache key: {}", e))
        })?;
        let modified = source_meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let canonical = source_path
            .canonicalize()
            .unwrap_or_else(|_| source_path.to_path_buf());

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        canonical.to_string_lossy().hash(&mut hasher);
        source_meta.len().hash(&mut hasher);
        modified.hash(&mut hasher);
        let key = hasher.finish();

        let cache_dir = Self::default_cache_dir(cache_root);
        fs::create_dir_all(&cache_dir).map_err(|e| {
            SymbolError::InvalidFormat(format!(
                "Failed to create ISF cache directory {}: {}",
                cache_dir.display(),
                e
            ))
        })?;

        Ok(cache_dir.join(format!("isf_{:016x}.json", key)))
    }

    fn read_source_json(path: &Path) -> SymbolResult<Vec<u8>> {
        let file = File::open(path)
            .map_err(|e| SymbolError::InvalidFormat(format!("Failed to open ISF file: {}", e)))?;
        let reader = BufReader::new(file);

        if path.extension().map(|e| e == "xz").unwrap_or(false) {
            Self::decompress_xz(reader)
        } else {
            let mut data = Vec::new();
            let mut direct_reader = BufReader::new(File::open(path).map_err(|e| {
                SymbolError::InvalidFormat(format!("Failed to read ISF file: {}", e))
            })?);
            direct_reader.read_to_end(&mut data).map_err(|e| {
                SymbolError::InvalidFormat(format!("Failed to read ISF file: {}", e))
            })?;
            Ok(data)
        }
    }

    fn load_json_with_cache(
        path: &Path,
        cache_root: Option<&Path>,
        clear_cache: bool,
    ) -> SymbolResult<(Vec<u8>, Option<PathBuf>)> {
        // Cache currently targets compressed ISF files where decompression dominates load time.
        if !path.extension().map(|e| e == "xz").unwrap_or(false) {
            return Ok((Self::read_source_json(path)?, None));
        }

        let Some(cache_root) = cache_root else {
            return Ok((Self::read_source_json(path)?, None));
        };

        let cache_file = Self::cache_file_path(cache_root, path)?;
        if clear_cache && cache_file.exists() {
            let _ = fs::remove_file(&cache_file);
        }

        if cache_file.exists() {
            let bytes = fs::read(&cache_file).map_err(|e| {
                SymbolError::InvalidFormat(format!(
                    "Failed to read ISF cache {}: {}",
                    cache_file.display(),
                    e
                ))
            })?;
            debug!("Loaded ISF JSON from cache: {}", cache_file.display());
            return Ok((bytes, Some(cache_file)));
        }

        let bytes = Self::read_source_json(path)?;
        fs::write(&cache_file, &bytes).map_err(|e| {
            SymbolError::InvalidFormat(format!(
                "Failed to write ISF cache {}: {}",
                cache_file.display(),
                e
            ))
        })?;
        debug!("Wrote ISF JSON cache: {}", cache_file.display());
        Ok((bytes, Some(cache_file)))
    }

    /// Load an ISF file from path
    pub fn from_path(path: impl AsRef<Path>, name: impl Into<String>) -> SymbolResult<Self> {
        Self::from_path_with_cache(path, name, None, false)
    }

    /// Load an ISF file from path with optional cache path and cache clearing.
    pub fn from_path_with_cache(
        path: impl AsRef<Path>,
        name: impl Into<String>,
        cache_root: Option<&Path>,
        clear_cache: bool,
    ) -> SymbolResult<Self> {
        let path = path.as_ref();
        let name = name.into();

        let (json_data, cache_file) = Self::load_json_with_cache(path, cache_root, clear_cache)?;
        match Self::from_json(&json_data, name.clone()) {
            Ok(table) => Ok(table),
            Err(err) => {
                if let Some(cache_file) = cache_file {
                    // Retry once from source bytes in case of stale/corrupt cache content.
                    warn!(
                        "ISF cache parse failed ({}), rebuilding cache from source: {}",
                        err,
                        cache_file.display()
                    );
                    let _ = fs::remove_file(&cache_file);
                    let fresh_json = Self::read_source_json(path)?;
                    if let Err(write_err) = fs::write(&cache_file, &fresh_json) {
                        debug!(
                            "Failed to rewrite ISF cache {} after parse retry: {}",
                            cache_file.display(),
                            write_err
                        );
                    }
                    return Self::from_json(&fresh_json, name);
                }
                Err(err)
            }
        }
    }

    /// Decompress XZ data
    fn decompress_xz<R: Read>(reader: R) -> SymbolResult<Vec<u8>> {
        let mut decoder = xz2::read::XzDecoder::new(reader);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| SymbolError::InvalidFormat(format!("Failed to decompress XZ: {}", e)))?;
        Ok(decompressed)
    }

    /// Parse ISF from JSON bytes
    pub fn from_json(data: &[u8], name: impl Into<String>) -> SymbolResult<Self> {
        let isf: ISFFile = serde_json::from_slice(data)
            .map_err(|e| SymbolError::InvalidFormat(format!("Failed to parse ISF JSON: {}", e)))?;

        let name = name.into();

        // Determine architecture from metadata
        let architecture = Self::detect_architecture(&isf);

        // Build native types
        let native_types = Self::build_native_types(architecture);

        Ok(Self {
            name,
            architecture,
            isf,
            type_cache: parking_lot::RwLock::new(HashMap::new()),
            building: parking_lot::RwLock::new(std::collections::HashSet::new()),
            native_types,
        })
    }

    /// Detect architecture from ISF metadata
    fn detect_architecture(isf: &ISFFile) -> Architecture {
        // Check pointer size in base_types
        if let Some(pointer) = isf.base_types.get("pointer") {
            if pointer.size == 8 {
                return Architecture::X64;
            } else if pointer.size == 4 {
                return Architecture::X86;
            }
        }

        // Check 'long' size
        if let Some(long_type) = isf.base_types.get("long") {
            if long_type.size == 8 {
                return Architecture::X64;
            } else if long_type.size == 4 {
                return Architecture::X86;
            }
        }

        // Default to x64
        Architecture::X64
    }

    /// Build native types for architecture
    fn build_native_types(architecture: Architecture) -> HashMap<String, Arc<TypeTemplate>> {
        let ptr_size = match architecture {
            Architecture::X64 | Architecture::Arm64 => 8,
            Architecture::X86 | Architecture::Arm | Architecture::Unknown => 4,
        };

        let mut types = HashMap::new();

        // Add common types
        let void = Arc::new(TypeTemplate::Void);
        types.insert("void".to_string(), void.clone());
        types.insert(
            "pointer".to_string(),
            Arc::new(TypeTemplate::pointer("pointer", ptr_size, void)),
        );

        types
    }

    /// Get pointer size for this architecture
    pub fn pointer_size(&self) -> usize {
        match self.architecture {
            Architecture::X64 | Architecture::Arm64 => 8,
            Architecture::X86 | Architecture::Arm | Architecture::Unknown => 4,
        }
    }

    /// Get the Linux banner from metadata
    pub fn linux_banner(&self) -> Option<&str> {
        self.isf
            .metadata
            .linux
            .as_ref()
            .and_then(|l| l.banner.as_deref())
    }

    /// Resolve a type reference to a template
    fn resolve_type(&self, type_ref: &ISFTypeReference) -> SymbolResult<Arc<TypeTemplate>> {
        match type_ref {
            ISFTypeReference::WithSubtype {
                kind,
                subtype,
                count,
                name,
                bit_position,
                bit_length,
                base_type,
                size,
                fields,
            } => {
                match kind.as_str() {
                    "struct" | "union" => {
                        if let Some(name) = name {
                            // Try to get the type, fall back to ForwardRef if not found
                            self.get_type(name)
                                .or_else(|_| Ok(Arc::new(TypeTemplate::ForwardRef(name.clone()))))
                        } else if let Some(fields) = fields {
                            // Inline struct/union
                            self.build_inline_struct(kind, size.unwrap_or(0), fields)
                        } else {
                            Err(SymbolError::InvalidFormat(
                                "Invalid struct/union type reference".to_string(),
                            ))
                        }
                    }
                    "pointer" => {
                        let target = if let Some(sub) = subtype {
                            // For pointer targets, tolerate missing types
                            self.resolve_type(sub)
                                .unwrap_or_else(|_| Arc::new(TypeTemplate::Void))
                        } else {
                            Arc::new(TypeTemplate::Void)
                        };
                        Ok(Arc::new(TypeTemplate::pointer(
                            "pointer",
                            self.pointer_size(),
                            target,
                        )))
                    }
                    "array" => {
                        let element = if let Some(sub) = subtype {
                            self.resolve_type(sub)?
                        } else {
                            return Err(SymbolError::InvalidFormat(
                                "Array without element type".to_string(),
                            ));
                        };
                        let count = count.unwrap_or(0);
                        Ok(Arc::new(TypeTemplate::array("array", count, element)))
                    }
                    "bitfield" => {
                        let base = if let Some(base_type) = base_type {
                            self.resolve_type(base_type)?
                        } else {
                            return Err(SymbolError::InvalidFormat(
                                "Bitfield without base type".to_string(),
                            ));
                        };
                        let bit_offset = bit_position.unwrap_or(0);
                        let bits = bit_length.unwrap_or(1);
                        let size = base.size().unwrap_or(4);
                        Ok(Arc::new(TypeTemplate::BitField(BitFieldTemplate {
                            name: "bitfield".to_string(),
                            size,
                            bit_offset,
                            bit_length: bits,
                            base,
                        })))
                    }
                    "base" | "enum" => {
                        if let Some(name) = name {
                            // Try to get the type, fall back to ForwardRef if not found
                            self.get_type(name)
                                .or_else(|_| Ok(Arc::new(TypeTemplate::ForwardRef(name.clone()))))
                        } else {
                            Err(SymbolError::InvalidFormat(format!("Unknown {} type", kind)))
                        }
                    }
                    "function" => {
                        // Function types are treated as void (they are callable)
                        // In practice, function pointers are more common
                        Ok(Arc::new(TypeTemplate::Void))
                    }
                    _ => Err(SymbolError::InvalidFormat(format!(
                        "Unknown type kind: {}",
                        kind
                    ))),
                }
            }
        }
    }

    /// Build an inline struct/union
    fn build_inline_struct(
        &self,
        kind: &str,
        size: usize,
        fields: &HashMap<String, ISFFieldDef>,
    ) -> SymbolResult<Arc<TypeTemplate>> {
        let mut field_infos = Vec::with_capacity(fields.len());

        for (name, field_def) in fields {
            let template = self.resolve_type(&field_def.type_ref)?;
            field_infos.push(FieldInfo {
                name: name.clone(),
                offset: field_def.offset,
                template,
            });
        }

        // Sort fields by offset
        field_infos.sort_by_key(|f| f.offset);

        if kind == "union" {
            Ok(Arc::new(TypeTemplate::Union(UnionTemplate {
                name: "anon_union".to_string(),
                size,
                members: field_infos,
            })))
        } else {
            Ok(Arc::new(TypeTemplate::Struct(StructTemplate {
                name: "anon_struct".to_string(),
                size,
                fields: field_infos,
            })))
        }
    }

    /// Build a type template from ISF user type
    fn build_user_type(
        &self,
        name: &str,
        user_type: &ISFUserType,
    ) -> SymbolResult<Arc<TypeTemplate>> {
        let mut field_infos = Vec::with_capacity(user_type.fields.len());

        // Process fields with anonymous struct flattening (like Python vol3's _reduce_fields)
        self.collect_fields(&user_type.fields, 0, &mut field_infos)?;

        // Sort fields by offset
        field_infos.sort_by_key(|f| f.offset);

        let is_union = user_type
            .kind
            .as_ref()
            .map(|k| k == "union")
            .unwrap_or(false);

        if is_union {
            Ok(Arc::new(TypeTemplate::Union(UnionTemplate {
                name: name.to_string(),
                size: user_type.size,
                members: field_infos,
            })))
        } else {
            Ok(Arc::new(TypeTemplate::Struct(StructTemplate {
                name: name.to_string(),
                size: user_type.size,
                fields: field_infos,
            })))
        }
    }

    /// Recursively collect fields, flattening anonymous structs/unions.
    /// This mirrors Python vol3's _reduce_fields behavior.
    fn collect_fields(
        &self,
        fields: &HashMap<String, ISFFieldDef>,
        parent_offset: usize,
        out: &mut Vec<FieldInfo>,
    ) -> SymbolResult<()> {
        for (field_name, field_def) in fields {
            let new_offset = parent_offset + field_def.offset;

            if field_def.anonymous {
                // Anonymous struct/union - need to get its inner fields and flatten them
                if let ISFTypeReference::WithSubtype {
                    kind,
                    name: Some(type_name),
                    ..
                } = &field_def.type_ref
                {
                    if kind == "struct" || kind == "union" {
                        // Look up the referenced type and recursively flatten its fields
                        if let Some(inner_type) = self.isf.user_types.get(type_name) {
                            self.collect_fields(&inner_type.fields, new_offset, out)?;
                            continue;
                        }
                    }
                }
            }

            // Non-anonymous or couldn't resolve - add the field directly
            let template = self.resolve_type(&field_def.type_ref)?;
            out.push(FieldInfo {
                name: field_name.clone(),
                offset: new_offset,
                template,
            });
        }
        Ok(())
    }

    /// Build a type template from ISF base type
    fn build_base_type(&self, name: &str, base_type: &ISFBaseType) -> Arc<TypeTemplate> {
        Arc::new(TypeTemplate::Primitive(PrimitiveTemplate {
            name: name.to_string(),
            size: base_type.size,
            signed: base_type.signed,
        }))
    }

    /// Build an enum type template
    fn build_enum_type(&self, name: &str, enum_def: &ISFEnum) -> SymbolResult<Arc<TypeTemplate>> {
        // Get base type
        let base = self.get_type(&enum_def.base)?;

        Ok(Arc::new(TypeTemplate::Enum(EnumTemplate {
            name: name.to_string(),
            size: enum_def.size,
            base,
            choices: enum_def.constants.clone(),
        })))
    }
}

impl SymbolTableInterface for IntermediateSymbolTable {
    fn name(&self) -> &str {
        &self.name
    }

    fn get_symbol(&self, name: &str) -> SymbolResult<Symbol> {
        self.isf
            .symbols
            .get(name)
            .map(|s| Symbol {
                name: name.to_string(),
                address: s.address,
                type_name: None, // Type extraction is complex
                constant_data: s.constant_data.clone(),
            })
            .ok_or_else(|| SymbolError::NotFound(name.to_string()))
    }

    fn get_type(&self, name: &str) -> SymbolResult<Arc<TypeTemplate>> {
        // Check cache first
        if let Some(cached) = self.type_cache.read().get(name) {
            return Ok(cached.clone());
        }

        // Check native types
        if let Some(native) = self.native_types.get(name) {
            return Ok(native.clone());
        }

        // Check if we're already building this type (cycle detection)
        // If so, return a forward reference to break the cycle
        {
            let building = self.building.read();
            if building.contains(name) {
                return Ok(Arc::new(TypeTemplate::ForwardRef(name.to_string())));
            }
        }

        // Mark this type as being built
        self.building.write().insert(name.to_string());

        // Build from ISF data
        let template = if let Some(user_type) = self.isf.user_types.get(name) {
            self.build_user_type(name, user_type)?
        } else if let Some(base_type) = self.isf.base_types.get(name) {
            self.build_base_type(name, base_type)
        } else if let Some(enum_def) = self.isf.enums.get(name) {
            self.build_enum_type(name, enum_def)?
        } else {
            // Remove from building set on failure
            self.building.write().remove(name);
            return Err(SymbolError::TypeNotFound(name.to_string()));
        };

        // Remove from building set
        self.building.write().remove(name);

        // Cache the result
        self.type_cache
            .write()
            .insert(name.to_string(), template.clone());
        Ok(template)
    }

    fn get_enumeration(&self, name: &str) -> SymbolResult<Enumeration> {
        self.isf
            .enums
            .get(name)
            .map(|e| Enumeration {
                name: name.to_string(),
                choices: e.constants.clone(),
            })
            .ok_or_else(|| SymbolError::EnumerationNotFound(name.to_string()))
    }

    fn has_symbol(&self, name: &str) -> bool {
        self.isf.symbols.contains_key(name)
    }

    fn has_type(&self, name: &str) -> bool {
        self.type_cache.read().contains_key(name)
            || self.native_types.contains_key(name)
            || self.isf.user_types.contains_key(name)
            || self.isf.base_types.contains_key(name)
            || self.isf.enums.contains_key(name)
    }

    fn symbols(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        Box::new(self.isf.symbols.keys().map(|s| s.as_str()))
    }

    fn types(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        let user_types = self.isf.user_types.keys().map(|s| s.as_str());
        let base_types = self.isf.base_types.keys().map(|s| s.as_str());
        Box::new(user_types.chain(base_types))
    }

    fn enumerations(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        Box::new(self.isf.enums.keys().map(|s| s.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isf_metadata_parse() {
        let json = r#"{
            "metadata": {
                "producer": {
                    "name": "dwarf2json",
                    "version": "0.8.0"
                },
                "format": "6.2.0",
                "linux": {
                    "banner": "Linux version 5.15.0"
                }
            },
            "base_types": {
                "int": { "size": 4, "signed": true },
                "pointer": { "size": 8, "signed": false }
            },
            "user_types": {},
            "symbols": {},
            "enums": {}
        }"#;

        let result = IntermediateSymbolTable::from_json(json.as_bytes(), "test");
        assert!(result.is_ok());

        let table = result.unwrap();
        assert_eq!(table.architecture(), Architecture::X64);
        assert_eq!(table.linux_banner(), Some("Linux version 5.15.0"));
    }
}
