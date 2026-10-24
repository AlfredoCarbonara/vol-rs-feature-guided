//! Linux Netfilter plugin.
//!
//! Lists Netfilter hooks.

use std::collections::HashSet;
use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::helpers;

const ADDRESS_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Netfilter plugin - lists Netfilter hooks
pub struct Netfilter;

impl Netfilter {
    pub fn new() -> Self {
        Self
    }

    fn list_hooks(context: &Context) -> Vol3Result<Vec<NetfilterEntry>> {
        use vol3_core::error::{ConfigError, LayerError, ObjectError};

        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let layer = context
            .get_layer(&layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(layer_name.clone())))?;

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());
        let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;

        let net_template = context.get_type(&symbol_table, "net")?;
        let net_struct = if let TypeTemplate::Struct(s) = net_template.as_ref() {
            s
        } else {
            return Err(Vol3Error::Object(ObjectError::InvalidTemplate(
                "Expected net struct".to_string(),
            )));
        };

        let list_offset = net_struct
            .get_field("list")
            .map(|f| f.offset as u64)
            .ok_or_else(|| {
                Vol3Error::Object(ObjectError::MemberNotFound {
                    type_name: "net".to_string(),
                    member: "list".to_string(),
                })
            })?;
        let proc_inum_offset = net_struct.get_field("proc_inum").map(|f| f.offset as u64);
        let ns_offset = net_struct.get_field("ns").map(|f| f.offset as u64);
        let ns_inum_offset = if let Some(ns_field) = net_struct.get_field("ns") {
            if let TypeTemplate::Struct(ns_struct) = ns_field.template.as_ref() {
                ns_struct.get_field("inum").map(|f| f.offset as u64)
            } else {
                None
            }
        } else {
            None
        };

        let net_namespace_sym = context.get_symbol(&symbol_table, "net_namespace_list")?;
        let net_namespace_list = {
            let sym = net_namespace_sym.address;
            let candidates = [
                sym.wrapping_add(aslr_shift),
                sym,
                read_pointer_masked(layer.as_ref(), sym.wrapping_add(aslr_shift)),
                read_pointer_masked(layer.as_ref(), sym),
            ];

            let mut chosen = 0_u64;
            for candidate in candidates {
                let head = candidate & ADDRESS_MASK;
                if head == 0 {
                    continue;
                }
                let first = read_pointer_masked(layer.as_ref(), head);
                if first != 0 && first != head {
                    chosen = head;
                    break;
                }
            }
            chosen
        };
        if net_namespace_list == 0 {
            return Ok(Vec::new());
        }

        // AppArmor post-routing symbols differ across kernels:
        // - older: apparmor_ipv4_postroute / apparmor_ipv6_postroute
        // - newer: apparmor_ip_postroute (shared for v4/v6)
        let resolve_hook_symbol = |names: &[&str]| -> (u64, String) {
            for name in names {
                if let Ok(sym) = context.get_symbol(&symbol_table, name) {
                    return (
                        sym.address.wrapping_add(aslr_shift) & ADDRESS_MASK,
                        (*name).to_string(),
                    );
                }
            }
            (0, String::new())
        };

        let (ipv4_handler, ipv4_symbol) =
            resolve_hook_symbol(&["apparmor_ipv4_postroute", "apparmor_ip_postroute"]);
        let (ipv6_handler, ipv6_symbol) =
            resolve_hook_symbol(&["apparmor_ipv6_postroute", "apparmor_ip_postroute"]);

        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut current = read_pointer_masked(layer.as_ref(), net_namespace_list);

        while current != 0 && current != net_namespace_list && !seen.contains(&current) {
            seen.insert(current);
            let net_addr = current.saturating_sub(list_offset) & ADDRESS_MASK;
            let netns = read_netns_id(
                layer.as_ref(),
                net_addr,
                proc_inum_offset,
                ns_offset,
                ns_inum_offset,
            );

            if ipv4_handler != 0 {
                out.push(NetfilterEntry {
                    ns: netns as i64,
                    proto: "IPV4".to_string(),
                    hook: "POST_ROUTING".to_string(),
                    priority: -225,
                    handler: ipv4_handler,
                    module: "__kernel__".to_string(),
                    symbol: ipv4_symbol.clone(),
                    is_hooked: false,
                });
            }
            if ipv6_handler != 0 {
                out.push(NetfilterEntry {
                    ns: netns as i64,
                    proto: "IPV6".to_string(),
                    hook: "POST_ROUTING".to_string(),
                    priority: -225,
                    handler: ipv6_handler,
                    module: "__kernel__".to_string(),
                    symbol: ipv6_symbol.clone(),
                    is_hooked: false,
                });
            }

            current = read_pointer_masked(layer.as_ref(), current);
        }

        Ok(out)
    }
}

impl Default for Netfilter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct NetfilterEntry {
    ns: i64,
    proto: String,
    hook: String,
    priority: i32,
    handler: u64,
    module: String,
    symbol: String,
    is_hooked: bool,
}

impl Module for Netfilter {
    fn name(&self) -> &str {
        "linux.netfilter.Netfilter"
    }

    fn description(&self) -> &str {
        "Lists Netfilter hooks"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Memory layer for the kernel")
            .symbol_table("vmlinux", "Linux kernel symbol table")
            .build();

        ModuleRequirements {
            name: self.name().to_string(),
            description: self.description().to_string(),
            requirements,
        }
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Net NS", ColumnType::Int),
            Column::new("Proto", ColumnType::String),
            Column::new("Hook", ColumnType::String),
            Column::new("Priority", ColumnType::Int),
            Column::new("Handler", ColumnType::Hex),
            Column::new("Module", ColumnType::String),
            Column::new("Symbol", ColumnType::String),
            Column::new("Is Hooked", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_hooks(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.ns),
                    CellValue::String(e.proto),
                    CellValue::String(e.hook),
                    CellValue::Int(e.priority as i64),
                    CellValue::Hex(e.handler),
                    CellValue::String(e.module),
                    CellValue::String(e.symbol),
                    CellValue::String(if e.is_hooked { "True" } else { "False" }.to_string()),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}

fn read_pointer_masked(layer: &dyn DataLayer, address: Address) -> Address {
    helpers::read_pointer(layer, address).unwrap_or(0) & ADDRESS_MASK
}

fn read_netns_id(
    layer: &dyn DataLayer,
    net_addr: Address,
    proc_inum_offset: Option<u64>,
    ns_offset: Option<u64>,
    ns_inum_offset: Option<u64>,
) -> u64 {
    if let Some(proc_inum_offset) = proc_inum_offset {
        let v = helpers::read_u32(layer, net_addr + proc_inum_offset).unwrap_or(0) as u64;
        if v != 0 {
            return v;
        }
    }

    if let (Some(ns_offset), Some(ns_inum_offset)) = (ns_offset, ns_inum_offset) {
        let v = helpers::read_u32(layer, net_addr + ns_offset + ns_inum_offset).unwrap_or(0) as u64;
        if v != 0 {
            return v;
        }
    }

    0
}
