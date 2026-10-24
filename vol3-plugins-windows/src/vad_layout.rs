//! ISF-derived Windows VAD offsets and bitfields.

use vol3_core::error::{PluginError, Vol3Error, Vol3Result};
use vol3_framework::context::Context;
use vol3_symbols::{FieldInfo, StructTemplate, TypeTemplate};

#[derive(Clone, Copy)]
pub struct Bits {
    pub offset: usize,
    pub size: usize,
    pub shift: u32,
    pub length: u32,
}

#[derive(Clone)]
pub struct VadLayout {
    pub root: usize,
    pub left: usize,
    pub right: usize,
    pub start: (usize, usize),
    pub start_high: Option<(usize, usize)>,
    pub end: (usize, usize),
    pub end_high: Option<(usize, usize)>,
    pub protection: Bits,
    pub private_memory: Bits,
    pub commit_charge: Bits,
}

impl VadLayout {
    pub fn from_context(context: &Context, table: &str) -> Vol3Result<Self> {
        let process = structure(context, table, "_EPROCESS")?;
        let tree = structure(context, table, "_RTL_AVL_TREE")?;
        let node = structure(context, table, "_RTL_BALANCED_NODE")?;
        let vad = structure(context, table, "_MMVAD_SHORT")?;
        let flags = structure(context, table, "_MMVAD_FLAGS")?;
        let flags1 = structure(context, table, "_MMVAD_FLAGS1")?;
        let core = vad.get_field("Core").map_or(0, |field| field.offset);
        let vad_node = vad.get_field("VadNode").map_or(0, |field| field.offset);
        let u = field(&vad, "u")?.offset;
        let u1 = field(&vad, "u1")?.offset;
        Ok(Self {
            root: field(&process, "VadRoot")?.offset + field(&tree, "Root")?.offset,
            left: core + vad_node + field(&node, "Left")?.offset,
            right: core + vad_node + field(&node, "Right")?.offset,
            start: scalar(&vad, "StartingVpn")?,
            start_high: vad.get_field("StartingVpnHigh").map(field_scalar),
            end: scalar(&vad, "EndingVpn")?,
            end_high: vad.get_field("EndingVpnHigh").map(field_scalar),
            protection: bitfield(field(&flags, "Protection")?, core + u)?,
            private_memory: bitfield(field(&flags, "PrivateMemory")?, core + u)?,
            commit_charge: bitfield(field(&flags1, "CommitCharge")?, core + u1)?,
        })
    }
}

fn structure(context: &Context, table: &str, name: &str) -> Vol3Result<StructTemplate> {
    let value = context.get_type(table, name)?;
    match value.as_ref() {
        TypeTemplate::Struct(value) => Ok(value.clone()),
        _ => Err(error(format!("{name} is not a struct in the Windows ISF"))),
    }
}

fn field<'a>(value: &'a StructTemplate, name: &str) -> Vol3Result<&'a FieldInfo> {
    value
        .get_field(name)
        .ok_or_else(|| error(format!("{}.{} missing from Windows ISF", value.name, name)))
}

fn field_scalar(field: &FieldInfo) -> (usize, usize) {
    (field.offset, field.template.size().unwrap_or(4))
}

fn scalar(value: &StructTemplate, name: &str) -> Vol3Result<(usize, usize)> {
    Ok(field_scalar(field(value, name)?))
}

fn bitfield(field: &FieldInfo, base: usize) -> Vol3Result<Bits> {
    match field.template.as_ref() {
        TypeTemplate::BitField(bits) if bits.bit_offset >= 0 && bits.bit_length <= 64 => Ok(Bits {
            offset: base + field.offset,
            size: bits.size,
            shift: bits.bit_offset as u32,
            length: bits.bit_length as u32,
        }),
        _ => Err(error(format!(
            "{} is not a supported ISF bitfield",
            field.name
        ))),
    }
}

fn error(message: String) -> Vol3Error {
    Vol3Error::Plugin(PluginError::ExecutionFailed(message))
}
