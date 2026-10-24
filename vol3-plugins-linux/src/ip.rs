//! Linux IP plugins.
//!
//! Lists network interface information.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use vol3_core::error::{ObjectError, Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::helpers;

const ADDRESS_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

// Fallback values from Linux's include/uapi/linux/if.h
const DEFAULT_NET_DEVICE_FLAGS: &[(&str, u64)] = &[
    ("IFF_UP", 0x1),
    ("IFF_BROADCAST", 0x2),
    ("IFF_DEBUG", 0x4),
    ("IFF_LOOPBACK", 0x8),
    ("IFF_POINTOPOINT", 0x10),
    ("IFF_NOTRAILERS", 0x20),
    ("IFF_RUNNING", 0x40),
    ("IFF_NOARP", 0x80),
    ("IFF_PROMISC", 0x100),
    ("IFF_ALLMULTI", 0x200),
    ("IFF_MASTER", 0x400),
    ("IFF_SLAVE", 0x800),
    ("IFF_MULTICAST", 0x1000),
    ("IFF_PORTSEL", 0x2000),
    ("IFF_AUTOMEDIA", 0x4000),
    ("IFF_DYNAMIC", 0x8000),
    ("IFF_LOWER_UP", 0x10000),
    ("IFF_DORMANT", 0x20000),
    ("IFF_ECHO", 0x40000),
];

/// IpAddr plugin - lists network interface addresses
pub struct IpAddr;

impl IpAddr {
    pub fn new() -> Self {
        Self
    }

    fn list_addresses(context: &Context) -> Vol3Result<Vec<IpAddrEntry>> {
        use vol3_core::error::{ConfigError, LayerError};

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

        let net_namespace_sym = context.get_symbol(&symbol_table, "net_namespace_list")?;
        let net_namespace_list = {
            let sym = net_namespace_sym.address;
            let candidates = [
                sym.wrapping_add(aslr_shift),
                sym,
                read_pointer_masked(layer.as_ref(), sym.wrapping_add(aslr_shift), ADDRESS_MASK),
                read_pointer_masked(layer.as_ref(), sym, ADDRESS_MASK),
            ];

            let mut chosen = 0_u64;
            for candidate in candidates {
                let list_head = candidate & ADDRESS_MASK;
                if list_head == 0 {
                    continue;
                }
                let first = read_pointer_masked(layer.as_ref(), list_head, ADDRESS_MASK);
                if first != 0 && first != list_head {
                    chosen = list_head;
                    break;
                }
            }
            chosen
        };
        if net_namespace_list == 0 {
            return Ok(Vec::new());
        }

        let net_template = context.get_type(&symbol_table, "net")?;
        let dev_template = context.get_type(&symbol_table, "net_device")?;
        let in_device_template = context.get_type(&symbol_table, "in_device")?;
        let in_ifaddr_template = context.get_type(&symbol_table, "in_ifaddr")?;
        let inet6_dev_template = context.get_type(&symbol_table, "inet6_dev").ok();
        let inet6_ifaddr_template = context.get_type(&symbol_table, "inet6_ifaddr").ok();

        let net_offsets = parse_net_offsets(net_template.as_ref())?;
        let dev_offsets = parse_net_device_offsets(dev_template.as_ref())?;
        let ipv4_offsets = parse_ipv4_offsets(
            dev_template.as_ref(),
            in_device_template.as_ref(),
            in_ifaddr_template.as_ref(),
        )?;
        let ipv6_offsets = match (inet6_dev_template, inet6_ifaddr_template) {
            (Some(inet6_dev_template), Some(inet6_ifaddr_template)) => parse_ipv6_offsets(
                dev_template.as_ref(),
                inet6_dev_template.as_ref(),
                inet6_ifaddr_template.as_ref(),
            )
            .ok(),
            _ => None,
        };

        let flag_choices = get_net_device_flag_choices(context, &symbol_table);
        let iff_promisc = flag_choices.get("IFF_PROMISC").copied().unwrap_or(0x100);

        let mut entries = Vec::new();
        let mut seen_ns_links = HashSet::new();

        let mut current_ns = read_pointer_masked(layer.as_ref(), net_namespace_list, ADDRESS_MASK);
        while current_ns != 0
            && current_ns != net_namespace_list
            && !seen_ns_links.contains(&current_ns)
        {
            seen_ns_links.insert(current_ns);

            let net_addr = current_ns.saturating_sub(net_offsets.list) & ADDRESS_MASK;
            let netns_id = read_net_namespace_inode(layer.as_ref(), net_addr, &net_offsets);
            let dev_head = (net_addr + net_offsets.dev_base_head) & ADDRESS_MASK;

            let mut seen_dev_links = HashSet::new();
            let mut current_dev = read_pointer_masked(layer.as_ref(), dev_head, ADDRESS_MASK);
            while current_dev != 0
                && current_dev != dev_head
                && !seen_dev_links.contains(&current_dev)
            {
                seen_dev_links.insert(current_dev);

                let dev_addr = current_dev.saturating_sub(dev_offsets.dev_list) & ADDRESS_MASK;
                if dev_addr != 0 {
                    let interface = read_cstring_at(
                        layer.as_ref(),
                        dev_addr + dev_offsets.name,
                        dev_offsets.name_size,
                    );
                    if !interface.is_empty() {
                        let mac =
                            read_mac_address(layer.as_ref(), dev_addr, &dev_offsets, ADDRESS_MASK);
                        let operstate_raw =
                            read_u8_or_zero(layer.as_ref(), dev_addr + dev_offsets.operstate);
                        let state = decode_oper_state(operstate_raw);
                        let flags_raw = read_unsigned(
                            layer.as_ref(),
                            dev_addr + dev_offsets.flags,
                            dev_offsets.flags_size,
                        );
                        let promisc = (flags_raw & iff_promisc) != 0;
                        let ifindex = read_unsigned(
                            layer.as_ref(),
                            dev_addr + ipv4_offsets.ifindex,
                            ipv4_offsets.ifindex_size,
                        ) as i32;

                        // IPv4 addresses
                        let in_dev_ptr = read_pointer_masked(
                            layer.as_ref(),
                            dev_addr + ipv4_offsets.ip_ptr,
                            ADDRESS_MASK,
                        );
                        if in_dev_ptr != 0 {
                            let mut seen_ifa = HashSet::new();
                            let mut current_ifa = read_pointer_masked(
                                layer.as_ref(),
                                in_dev_ptr + ipv4_offsets.in_device_ifa_list,
                                ADDRESS_MASK,
                            );

                            while current_ifa != 0 && !seen_ifa.contains(&current_ifa) {
                                seen_ifa.insert(current_ifa);

                                let ip_raw = read_u32_or_zero(
                                    layer.as_ref(),
                                    current_ifa + ipv4_offsets.ifa_address,
                                );
                                let ip = decode_ipv4(ip_raw);
                                let prefix = read_unsigned(
                                    layer.as_ref(),
                                    current_ifa + ipv4_offsets.ifa_prefixlen,
                                    ipv4_offsets.ifa_prefixlen_size,
                                ) as i32;
                                let scope_raw = read_unsigned(
                                    layer.as_ref(),
                                    current_ifa + ipv4_offsets.ifa_scope,
                                    ipv4_offsets.ifa_scope_size,
                                ) as u32;

                                if !ip.is_empty() {
                                    entries.push(IpAddrEntry {
                                        netns: netns_id as i64,
                                        index: ifindex,
                                        interface: interface.clone(),
                                        mac: mac.clone(),
                                        promisc,
                                        ip,
                                        prefix,
                                        scope: decode_ipv4_scope(scope_raw),
                                        state: state.clone(),
                                    });
                                }

                                current_ifa = read_pointer_masked(
                                    layer.as_ref(),
                                    current_ifa + ipv4_offsets.ifa_next,
                                    ADDRESS_MASK,
                                );
                            }
                        }

                        // IPv6 addresses
                        if let Some(ipv6_offsets) = ipv6_offsets {
                            let inet6_dev_ptr = read_pointer_masked(
                                layer.as_ref(),
                                dev_addr + ipv6_offsets.ip6_ptr,
                                ADDRESS_MASK,
                            );
                            if inet6_dev_ptr != 0 {
                                let head = (inet6_dev_ptr + ipv6_offsets.addr_list) & ADDRESS_MASK;
                                let mut seen_if6 = HashSet::new();
                                let mut current_if6 =
                                    read_pointer_masked(layer.as_ref(), head, ADDRESS_MASK);

                                while current_if6 != 0
                                    && current_if6 != head
                                    && !seen_if6.contains(&current_if6)
                                {
                                    seen_if6.insert(current_if6);
                                    let if6_addr = current_if6.saturating_sub(ipv6_offsets.if_list)
                                        & ADDRESS_MASK;
                                    if if6_addr != 0 {
                                        let ip = decode_ipv6(
                                            layer.as_ref(),
                                            if6_addr + ipv6_offsets.addr,
                                        );
                                        let prefix = read_unsigned(
                                            layer.as_ref(),
                                            if6_addr + ipv6_offsets.prefix_len,
                                            ipv6_offsets.prefix_len_size,
                                        )
                                            as i32;
                                        let scope_raw = read_unsigned(
                                            layer.as_ref(),
                                            if6_addr + ipv6_offsets.scope,
                                            ipv6_offsets.scope_size,
                                        )
                                            as u32;

                                        if !ip.is_empty() {
                                            entries.push(IpAddrEntry {
                                                netns: netns_id as i64,
                                                index: ifindex,
                                                interface: interface.clone(),
                                                mac: mac.clone(),
                                                promisc,
                                                ip,
                                                prefix,
                                                scope: decode_ipv6_scope(scope_raw),
                                                state: state.clone(),
                                            });
                                        }
                                    }

                                    current_if6 = read_pointer_masked(
                                        layer.as_ref(),
                                        current_if6,
                                        ADDRESS_MASK,
                                    );
                                }
                            }
                        }
                    }
                }

                current_dev = read_pointer_masked(layer.as_ref(), current_dev, ADDRESS_MASK);
            }

            current_ns = read_pointer_masked(layer.as_ref(), current_ns, ADDRESS_MASK);
        }

        Ok(entries)
    }
}

impl Default for IpAddr {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct IpAddrEntry {
    netns: i64,
    index: i32,
    interface: String,
    mac: String,
    promisc: bool,
    ip: String,
    prefix: i32,
    scope: String,
    state: String,
}

impl Module for IpAddr {
    fn name(&self) -> &str {
        "linux.ip.IpAddr"
    }

    fn description(&self) -> &str {
        "Lists network interface information for all devices"
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
            Column::new("NetNS", ColumnType::Int),
            Column::new("Index", ColumnType::Int),
            Column::new("Interface", ColumnType::String),
            Column::new("MAC", ColumnType::String),
            Column::new("Promiscuous", ColumnType::String),
            Column::new("IP", ColumnType::String),
            Column::new("Prefix", ColumnType::Int),
            Column::new("Scope Type", ColumnType::String),
            Column::new("State", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_addresses(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.netns),
                    CellValue::Int(e.index as i64),
                    CellValue::String(e.interface),
                    CellValue::String(e.mac),
                    CellValue::String(if e.promisc { "True" } else { "False" }.to_string()),
                    CellValue::String(e.ip),
                    CellValue::Int(e.prefix as i64),
                    CellValue::String(e.scope),
                    CellValue::String(e.state),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}

/// IpLink plugin - lists network interface link information
pub struct IpLink;

impl IpLink {
    pub fn new() -> Self {
        Self
    }

    fn list_links(context: &Context) -> Vol3Result<Vec<IpLinkEntry>> {
        use vol3_core::error::{ConfigError, LayerError};

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
        let net_namespace_sym = context.get_symbol(&symbol_table, "net_namespace_list")?;
        let net_namespace_list = {
            let sym = net_namespace_sym.address;
            let candidates = [
                sym.wrapping_add(aslr_shift),
                sym,
                read_pointer_masked(layer.as_ref(), sym.wrapping_add(aslr_shift), ADDRESS_MASK),
                read_pointer_masked(layer.as_ref(), sym, ADDRESS_MASK),
            ];

            let mut chosen = 0_u64;
            for candidate in candidates {
                let list_head = candidate & ADDRESS_MASK;
                if list_head == 0 {
                    continue;
                }
                let first = read_pointer_masked(layer.as_ref(), list_head, ADDRESS_MASK);
                if first != 0 && first != list_head {
                    chosen = list_head;
                    break;
                }
            }
            chosen
        };
        if net_namespace_list == 0 {
            return Ok(Vec::new());
        }

        let net_offsets = parse_net_offsets(context.get_type(&symbol_table, "net")?.as_ref())?;
        let dev_offsets =
            parse_net_device_offsets(context.get_type(&symbol_table, "net_device")?.as_ref())?;
        let qdisc_offsets = parse_qdisc_offsets(context, &symbol_table);
        let flag_choices = get_net_device_flag_choices(context, &symbol_table);
        let state_bits = get_netdev_state_bits(context, &symbol_table);

        let mut entries = Vec::new();
        let mut seen_ns_links = HashSet::new();

        let mut current_ns = read_pointer_masked(layer.as_ref(), net_namespace_list, ADDRESS_MASK);
        while current_ns != 0
            && current_ns != net_namespace_list
            && !seen_ns_links.contains(&current_ns)
        {
            seen_ns_links.insert(current_ns);

            let net_addr = current_ns.saturating_sub(net_offsets.list) & ADDRESS_MASK;
            let netns_id = read_net_namespace_inode(layer.as_ref(), net_addr, &net_offsets);
            let dev_head = (net_addr + net_offsets.dev_base_head) & ADDRESS_MASK;

            let mut seen_dev_links = HashSet::new();
            let mut current_dev = read_pointer_masked(layer.as_ref(), dev_head, ADDRESS_MASK);
            while current_dev != 0
                && current_dev != dev_head
                && !seen_dev_links.contains(&current_dev)
            {
                seen_dev_links.insert(current_dev);

                let dev_addr = current_dev.saturating_sub(dev_offsets.dev_list) & ADDRESS_MASK;
                if dev_addr != 0 {
                    let interface = read_cstring_at(
                        layer.as_ref(),
                        dev_addr + dev_offsets.name,
                        dev_offsets.name_size,
                    );
                    if !interface.is_empty() {
                        let mac =
                            read_mac_address(layer.as_ref(), dev_addr, &dev_offsets, ADDRESS_MASK);
                        let operstate_raw =
                            read_u8_or_zero(layer.as_ref(), dev_addr + dev_offsets.operstate);
                        let state = decode_oper_state(operstate_raw);
                        let mtu =
                            read_u32_or_zero(layer.as_ref(), dev_addr + dev_offsets.mtu) as i64;
                        let qlen =
                            read_u32_or_zero(layer.as_ref(), dev_addr + dev_offsets.tx_queue_len)
                                as i64;
                        let qdisc = read_qdisc_name(
                            layer.as_ref(),
                            dev_addr,
                            dev_offsets.qdisc,
                            qdisc_offsets.as_ref(),
                            ADDRESS_MASK,
                        );

                        let flags_raw = read_unsigned(
                            layer.as_ref(),
                            dev_addr + dev_offsets.flags,
                            dev_offsets.flags_size,
                        );
                        let gflags_raw = dev_offsets
                            .gflags
                            .map(|(off, size)| read_unsigned(layer.as_ref(), dev_addr + off, size))
                            .unwrap_or(0);
                        let state_raw = read_unsigned(
                            layer.as_ref(),
                            dev_addr + dev_offsets.state,
                            dev_offsets.state_size,
                        );
                        let flags = format_link_flags(
                            flags_raw,
                            gflags_raw,
                            state_raw,
                            &state,
                            &flag_choices,
                            state_bits,
                        );

                        entries.push(IpLinkEntry {
                            netns: netns_id as i64,
                            interface,
                            mac,
                            state,
                            mtu,
                            qdisc,
                            qlen,
                            flags,
                        });
                    }
                }

                current_dev = read_pointer_masked(layer.as_ref(), current_dev, ADDRESS_MASK);
            }

            current_ns = read_pointer_masked(layer.as_ref(), current_ns, ADDRESS_MASK);
        }

        Ok(entries)
    }
}

impl Default for IpLink {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct IpLinkEntry {
    netns: i64,
    interface: String,
    mac: String,
    state: String,
    mtu: i64,
    qdisc: String,
    qlen: i64,
    flags: String,
}

impl Module for IpLink {
    fn name(&self) -> &str {
        "linux.ip.IpLink"
    }

    fn description(&self) -> &str {
        "Lists information about network interfaces similar to `ip link show`"
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
            Column::new("NS", ColumnType::Int),
            Column::new("Interface", ColumnType::String),
            Column::new("MAC", ColumnType::String),
            Column::new("State", ColumnType::String),
            Column::new("MTU", ColumnType::Int),
            Column::new("Qdisc", ColumnType::String),
            Column::new("Qlen", ColumnType::Int),
            Column::new("Flags", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::list_links(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Int(e.netns),
                    CellValue::String(e.interface),
                    CellValue::String(e.mac),
                    CellValue::String(e.state),
                    CellValue::Int(e.mtu),
                    CellValue::String(e.qdisc),
                    CellValue::Int(e.qlen),
                    CellValue::String(e.flags),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}

#[derive(Debug, Clone, Copy)]
struct NetOffsets {
    list: u64,
    dev_base_head: u64,
    proc_inum: Option<u64>,
    ns: Option<u64>,
    ns_inum: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct NetDeviceOffsets {
    dev_list: u64,
    name: u64,
    name_size: usize,
    addr_len: u64,
    perm_addr: Option<(u64, usize)>,
    dev_addr: Option<u64>,
    flags: u64,
    flags_size: usize,
    gflags: Option<(u64, usize)>,
    state: u64,
    state_size: usize,
    operstate: u64,
    mtu: u64,
    qdisc: Option<u64>,
    tx_queue_len: u64,
}

#[derive(Debug, Clone, Copy)]
struct Ipv4Offsets {
    ifindex: u64,
    ifindex_size: usize,
    ip_ptr: u64,
    in_device_ifa_list: u64,
    ifa_next: u64,
    ifa_address: u64,
    ifa_prefixlen: u64,
    ifa_prefixlen_size: usize,
    ifa_scope: u64,
    ifa_scope_size: usize,
}

#[derive(Debug, Clone, Copy)]
struct Ipv6Offsets {
    ip6_ptr: u64,
    addr_list: u64,
    if_list: u64,
    prefix_len: u64,
    prefix_len_size: usize,
    scope: u64,
    scope_size: usize,
    addr: u64,
}

#[derive(Debug, Clone, Copy)]
struct QdiscOffsets {
    ops: u64,
    id: u64,
    id_size: usize,
}

#[derive(Debug, Clone, Copy)]
struct NetdevStateBits {
    start: u32,
    nocarrier: u32,
    dormant: u32,
}

fn parse_net_offsets(template: &TypeTemplate) -> Vol3Result<NetOffsets> {
    if let TypeTemplate::Struct(s) = template {
        let list = get_required_field_offset("net", s, "list")?;
        let dev_base_head = get_required_field_offset("net", s, "dev_base_head")?;
        let proc_inum = s.get_field("proc_inum").map(|f| f.offset as u64);

        let (ns, ns_inum) = if let Some(ns_field) = s.get_field("ns") {
            let ns_inum = if let TypeTemplate::Struct(ns_struct) = ns_field.template.as_ref() {
                ns_struct.get_field("inum").map(|f| f.offset as u64)
            } else {
                None
            };
            (Some(ns_field.offset as u64), ns_inum)
        } else {
            (None, None)
        };

        Ok(NetOffsets {
            list,
            dev_base_head,
            proc_inum,
            ns,
            ns_inum,
        })
    } else {
        Err(Vol3Error::Object(ObjectError::InvalidTemplate(
            "Expected net struct".to_string(),
        )))
    }
}

fn parse_net_device_offsets(template: &TypeTemplate) -> Vol3Result<NetDeviceOffsets> {
    if let TypeTemplate::Struct(s) = template {
        let name_field = s.get_field("name").ok_or_else(|| {
            Vol3Error::Object(ObjectError::MemberNotFound {
                type_name: "net_device".to_string(),
                member: "name".to_string(),
            })
        })?;

        Ok(NetDeviceOffsets {
            dev_list: get_required_field_offset("net_device", s, "dev_list")?,
            name: name_field.offset as u64,
            name_size: name_field.template.size().unwrap_or(16),
            addr_len: get_required_field_offset("net_device", s, "addr_len")?,
            perm_addr: s
                .get_field("perm_addr")
                .map(|f| (f.offset as u64, f.template.size().unwrap_or(32))),
            dev_addr: s.get_field("dev_addr").map(|f| f.offset as u64),
            flags: get_required_field_offset("net_device", s, "flags")?,
            flags_size: s
                .get_field("flags")
                .and_then(|f| f.template.size())
                .unwrap_or(4),
            gflags: s
                .get_field("gflags")
                .map(|f| (f.offset as u64, f.template.size().unwrap_or(4))),
            state: get_required_field_offset("net_device", s, "state")?,
            state_size: s
                .get_field("state")
                .and_then(|f| f.template.size())
                .unwrap_or(8),
            operstate: get_required_field_offset("net_device", s, "operstate")?,
            mtu: get_required_field_offset("net_device", s, "mtu")?,
            qdisc: s.get_field("qdisc").map(|f| f.offset as u64),
            tx_queue_len: get_required_field_offset("net_device", s, "tx_queue_len")?,
        })
    } else {
        Err(Vol3Error::Object(ObjectError::InvalidTemplate(
            "Expected net_device struct".to_string(),
        )))
    }
}

fn parse_ipv4_offsets(
    net_device_template: &TypeTemplate,
    in_device_template: &TypeTemplate,
    in_ifaddr_template: &TypeTemplate,
) -> Vol3Result<Ipv4Offsets> {
    let (ifindex, ifindex_size, ip_ptr) = if let TypeTemplate::Struct(s) = net_device_template {
        let ifindex_field = s.get_field("ifindex").ok_or_else(|| {
            Vol3Error::Object(ObjectError::MemberNotFound {
                type_name: "net_device".to_string(),
                member: "ifindex".to_string(),
            })
        })?;
        let ip_ptr = get_required_field_offset("net_device", s, "ip_ptr")?;
        (
            ifindex_field.offset as u64,
            ifindex_field.template.size().unwrap_or(4),
            ip_ptr,
        )
    } else {
        return Err(Vol3Error::Object(ObjectError::InvalidTemplate(
            "Expected net_device struct".to_string(),
        )));
    };

    let in_device_ifa_list = if let TypeTemplate::Struct(s) = in_device_template {
        get_required_field_offset("in_device", s, "ifa_list")?
    } else {
        return Err(Vol3Error::Object(ObjectError::InvalidTemplate(
            "Expected in_device struct".to_string(),
        )));
    };

    let (ifa_next, ifa_address, ifa_prefixlen, ifa_prefixlen_size, ifa_scope, ifa_scope_size) =
        if let TypeTemplate::Struct(s) = in_ifaddr_template {
            let ifa_prefixlen_field = s.get_field("ifa_prefixlen").ok_or_else(|| {
                Vol3Error::Object(ObjectError::MemberNotFound {
                    type_name: "in_ifaddr".to_string(),
                    member: "ifa_prefixlen".to_string(),
                })
            })?;
            let ifa_scope_field = s.get_field("ifa_scope").ok_or_else(|| {
                Vol3Error::Object(ObjectError::MemberNotFound {
                    type_name: "in_ifaddr".to_string(),
                    member: "ifa_scope".to_string(),
                })
            })?;
            (
                get_required_field_offset("in_ifaddr", s, "ifa_next")?,
                get_required_field_offset("in_ifaddr", s, "ifa_address")?,
                ifa_prefixlen_field.offset as u64,
                ifa_prefixlen_field.template.size().unwrap_or(1),
                ifa_scope_field.offset as u64,
                ifa_scope_field.template.size().unwrap_or(1),
            )
        } else {
            return Err(Vol3Error::Object(ObjectError::InvalidTemplate(
                "Expected in_ifaddr struct".to_string(),
            )));
        };

    Ok(Ipv4Offsets {
        ifindex,
        ifindex_size,
        ip_ptr,
        in_device_ifa_list,
        ifa_next,
        ifa_address,
        ifa_prefixlen,
        ifa_prefixlen_size,
        ifa_scope,
        ifa_scope_size,
    })
}

fn parse_ipv6_offsets(
    net_device_template: &TypeTemplate,
    inet6_dev_template: &TypeTemplate,
    inet6_ifaddr_template: &TypeTemplate,
) -> Vol3Result<Ipv6Offsets> {
    let ip6_ptr = if let TypeTemplate::Struct(s) = net_device_template {
        get_required_field_offset("net_device", s, "ip6_ptr")?
    } else {
        return Err(Vol3Error::Object(ObjectError::InvalidTemplate(
            "Expected net_device struct".to_string(),
        )));
    };

    let addr_list = if let TypeTemplate::Struct(s) = inet6_dev_template {
        get_required_field_offset("inet6_dev", s, "addr_list")?
    } else {
        return Err(Vol3Error::Object(ObjectError::InvalidTemplate(
            "Expected inet6_dev struct".to_string(),
        )));
    };

    if let TypeTemplate::Struct(s) = inet6_ifaddr_template {
        let prefix_field = s.get_field("prefix_len").ok_or_else(|| {
            Vol3Error::Object(ObjectError::MemberNotFound {
                type_name: "inet6_ifaddr".to_string(),
                member: "prefix_len".to_string(),
            })
        })?;
        let scope_field = s.get_field("scope").ok_or_else(|| {
            Vol3Error::Object(ObjectError::MemberNotFound {
                type_name: "inet6_ifaddr".to_string(),
                member: "scope".to_string(),
            })
        })?;
        Ok(Ipv6Offsets {
            ip6_ptr,
            addr_list,
            if_list: get_required_field_offset("inet6_ifaddr", s, "if_list")?,
            prefix_len: prefix_field.offset as u64,
            prefix_len_size: prefix_field.template.size().unwrap_or(4),
            scope: scope_field.offset as u64,
            scope_size: scope_field.template.size().unwrap_or(2),
            addr: get_required_field_offset("inet6_ifaddr", s, "addr")?,
        })
    } else {
        Err(Vol3Error::Object(ObjectError::InvalidTemplate(
            "Expected inet6_ifaddr struct".to_string(),
        )))
    }
}

fn parse_qdisc_offsets(context: &Context, symbol_table: &str) -> Option<QdiscOffsets> {
    let qdisc_template = get_type_any(context, symbol_table, &["Qdisc", "qdisc"])?;
    let qdisc_ops_template = get_type_any(context, symbol_table, &["Qdisc_ops", "qdisc_ops"])?;

    let ops_offset = if let TypeTemplate::Struct(s) = qdisc_template.as_ref() {
        s.get_field("ops").map(|f| f.offset as u64)?
    } else {
        return None;
    };

    if let TypeTemplate::Struct(s) = qdisc_ops_template.as_ref() {
        let id_field = s.get_field("id")?;
        Some(QdiscOffsets {
            ops: ops_offset,
            id: id_field.offset as u64,
            id_size: id_field.template.size().unwrap_or(16),
        })
    } else {
        None
    }
}

fn get_type_any(
    context: &Context,
    symbol_table: &str,
    names: &[&str],
) -> Option<Arc<TypeTemplate>> {
    for name in names {
        if let Ok(template) = context.get_type(symbol_table, name) {
            return Some(template);
        }
    }
    None
}

fn get_required_field_offset(
    type_name: &str,
    s: &vol3_symbols::StructTemplate,
    field_name: &str,
) -> Vol3Result<u64> {
    s.get_field(field_name)
        .map(|f| f.offset as u64)
        .ok_or_else(|| {
            Vol3Error::Object(ObjectError::MemberNotFound {
                type_name: type_name.to_string(),
                member: field_name.to_string(),
            })
        })
}

fn read_net_namespace_inode(layer: &dyn DataLayer, net_addr: Address, offsets: &NetOffsets) -> u64 {
    if let Some(proc_inum) = offsets.proc_inum {
        let val = read_u32_or_zero(layer, net_addr + proc_inum) as u64;
        if val != 0 {
            return val;
        }
    }

    if let (Some(ns), Some(inum)) = (offsets.ns, offsets.ns_inum) {
        let val = read_u32_or_zero(layer, net_addr + ns + inum) as u64;
        if val != 0 {
            return val;
        }
    }

    0
}

fn read_mac_address(
    layer: &dyn DataLayer,
    dev_addr: Address,
    offsets: &NetDeviceOffsets,
    address_mask: u64,
) -> String {
    let mut addr_len = read_u8_or_zero(layer, dev_addr + offsets.addr_len) as usize;
    if addr_len == 0 || addr_len > 32 {
        addr_len = 6;
    }

    if let Some((perm_addr_offset, perm_size)) = offsets.perm_addr {
        if let Ok(bytes) = layer.read(dev_addr + perm_addr_offset, perm_size, false) {
            let take = addr_len.min(bytes.len());
            if take > 0 && bytes[..take].iter().any(|b| *b != 0) {
                return format_mac(&bytes[..take]);
            }
        }
    }

    if let Some(dev_addr_offset) = offsets.dev_addr {
        let dev_addr_ptr = read_pointer_masked(layer, dev_addr + dev_addr_offset, address_mask);
        if dev_addr_ptr != 0 {
            if let Ok(bytes) = layer.read(dev_addr_ptr, addr_len, false) {
                if !bytes.is_empty() {
                    return format_mac(&bytes[..addr_len.min(bytes.len())]);
                }
            }
        }
    }

    format_mac(&vec![0_u8; addr_len.max(6)])
}

fn read_qdisc_name(
    layer: &dyn DataLayer,
    dev_addr: Address,
    qdisc_offset: Option<u64>,
    qdisc_offsets: Option<&QdiscOffsets>,
    address_mask: u64,
) -> String {
    let (qdisc_offset, qdisc_offsets) = match (qdisc_offset, qdisc_offsets) {
        (Some(qdisc_offset), Some(qdisc_offsets)) => (qdisc_offset, qdisc_offsets),
        _ => return "N/A".to_string(),
    };

    let qdisc_ptr = read_pointer_masked(layer, dev_addr + qdisc_offset, address_mask);
    if qdisc_ptr == 0 {
        return "N/A".to_string();
    }

    let ops_ptr = read_pointer_masked(layer, qdisc_ptr + qdisc_offsets.ops, address_mask);
    if ops_ptr == 0 {
        return "N/A".to_string();
    }

    let qdisc_name = read_cstring_at(layer, ops_ptr + qdisc_offsets.id, qdisc_offsets.id_size);
    if qdisc_name.is_empty() {
        "N/A".to_string()
    } else {
        qdisc_name
    }
}

fn get_net_device_flag_choices(context: &Context, symbol_table: &str) -> HashMap<String, u64> {
    let mut choices = HashMap::new();

    if let Some(table) = context.get_symbol_table(symbol_table) {
        if let Ok(enum_values) = table.get_enumeration("net_device_flags") {
            for (name, value) in enum_values.choices {
                if value >= 0 {
                    choices.insert(name, value as u64);
                }
            }
        }
    }

    if choices.is_empty() {
        for (name, value) in DEFAULT_NET_DEVICE_FLAGS {
            choices.insert((*name).to_string(), *value);
        }
    }

    choices
}

fn get_netdev_state_bits(context: &Context, symbol_table: &str) -> NetdevStateBits {
    let mut bits = NetdevStateBits {
        start: 0,
        nocarrier: 2,
        dormant: 4,
    };

    if let Some(table) = context.get_symbol_table(symbol_table) {
        if let Ok(enum_values) = table.get_enumeration("netdev_state_t") {
            if let Some(v) = enum_values.get("__LINK_STATE_START") {
                bits.start = v as u32;
            }
            if let Some(v) = enum_values.get("__LINK_STATE_NOCARRIER") {
                bits.nocarrier = v as u32;
            }
            if let Some(v) = enum_values.get("__LINK_STATE_DORMANT") {
                bits.dormant = v as u32;
            }
        }
    }

    bits
}

fn format_link_flags(
    flags_raw: u64,
    gflags_raw: u64,
    state_raw: u64,
    operstate: &str,
    flag_choices: &HashMap<String, u64>,
    state_bits: NetdevStateBits,
) -> String {
    let iff_promisc = flag_choices.get("IFF_PROMISC").copied().unwrap_or(0);
    let iff_allmulti = flag_choices.get("IFF_ALLMULTI").copied().unwrap_or(0);
    let iff_running = flag_choices.get("IFF_RUNNING").copied().unwrap_or(0);
    let iff_lower_up = flag_choices.get("IFF_LOWER_UP").copied().unwrap_or(0);
    let iff_dormant = flag_choices.get("IFF_DORMANT").copied().unwrap_or(0);

    let clear_flags = iff_promisc | iff_allmulti | iff_running | iff_lower_up | iff_dormant;
    let clear_gflags = iff_promisc | iff_allmulti;
    let mut flags = (flags_raw & !clear_flags) | (gflags_raw & !clear_gflags);

    let is_running = (state_raw & (1_u64 << state_bits.start)) != 0;
    let is_carrier_ok = (state_raw & (1_u64 << state_bits.nocarrier)) == 0;
    let is_dormant = (state_raw & (1_u64 << state_bits.dormant)) != 0;

    if is_running {
        if operstate == "UP" || operstate == "UNKNOWN" {
            flags |= iff_running;
        }
        if is_carrier_ok {
            flags |= iff_lower_up;
        }
        if is_dormant {
            flags |= iff_dormant;
        }
    }

    let mut flag_names: Vec<String> = flag_choices
        .iter()
        .filter_map(|(name, value)| {
            if name.starts_with("IFF_") && *value != 0 && (flags & *value) != 0 {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect();
    flag_names.sort();
    flag_names.retain(|name| name != "IFF_RUNNING");
    flag_names.retain(|name| name != "IFF_DORMANT");
    flag_names.retain(|name| name != "IFF_ECHO");

    let short_names: Vec<String> = flag_names
        .into_iter()
        .map(|name| name.trim_start_matches("IFF_").to_string())
        .collect();
    short_names.join(",")
}

fn decode_oper_state(value: u8) -> String {
    match value {
        0 => "UNKNOWN".to_string(),
        1 => "NOTPRESENT".to_string(),
        2 => "DOWN".to_string(),
        3 => "LOWERLAYERDOWN".to_string(),
        4 => "TESTING".to_string(),
        5 => "DORMANT".to_string(),
        6 => "UP".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}

fn decode_ipv4(value: u32) -> String {
    Ipv4Addr::from(value.to_le_bytes()).to_string()
}

fn decode_ipv6(layer: &dyn DataLayer, address: Address) -> String {
    let bytes = match layer.read(address, 16, false) {
        Ok(bytes) => bytes,
        Err(_) => return String::new(),
    };
    if bytes.len() < 16 {
        return String::new();
    }
    let mut ip_bytes = [0_u8; 16];
    ip_bytes.copy_from_slice(&bytes[..16]);
    Ipv6Addr::from(ip_bytes).to_string()
}

fn decode_ipv4_scope(scope: u32) -> String {
    match scope {
        0 => "global".to_string(),
        255 => "nowhere".to_string(),
        254 => "host".to_string(),
        253 => "link".to_string(),
        200 => "site".to_string(),
        _ => "unknown".to_string(),
    }
}

fn decode_ipv6_scope(scope: u32) -> String {
    if (scope & 0x10) != 0 {
        "host".to_string()
    } else if (scope & 0x20) != 0 {
        "link".to_string()
    } else if (scope & 0x40) != 0 {
        "site".to_string()
    } else {
        "global".to_string()
    }
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn read_pointer_masked(layer: &dyn DataLayer, address: Address, mask: u64) -> Address {
    helpers::read_pointer(layer, address).unwrap_or(0) & mask
}

fn read_u8_or_zero(layer: &dyn DataLayer, address: Address) -> u8 {
    helpers::read_u8(layer, address).unwrap_or(0)
}

fn read_u32_or_zero(layer: &dyn DataLayer, address: Address) -> u32 {
    helpers::read_u32(layer, address).unwrap_or(0)
}

fn read_u64_or_zero(layer: &dyn DataLayer, address: Address) -> u64 {
    helpers::read_u64(layer, address).unwrap_or(0)
}

fn read_u16_or_zero(layer: &dyn DataLayer, address: Address) -> u16 {
    helpers::read_u16(layer, address).unwrap_or(0)
}

fn read_unsigned(layer: &dyn DataLayer, address: Address, size: usize) -> u64 {
    match size {
        1 => read_u8_or_zero(layer, address) as u64,
        2 => read_u16_or_zero(layer, address) as u64,
        4 => read_u32_or_zero(layer, address) as u64,
        _ => read_u64_or_zero(layer, address),
    }
}

fn read_cstring_at(layer: &dyn DataLayer, address: Address, max_len: usize) -> String {
    helpers::read_string(layer, address, max_len).unwrap_or_default()
}
