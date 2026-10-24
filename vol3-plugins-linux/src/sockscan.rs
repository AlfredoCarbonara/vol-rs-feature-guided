//! Linux Sockscan plugin.
//!
//! Scans memory for socket objects.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use vol3_core::error::{ConfigError, LayerError, ObjectError, Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::intel::Intel32e;
use vol3_layers::scanner::MultiPatternScanner;
use vol3_layers::traits::{DataLayer, TranslationLayer};
use vol3_symbols::TypeTemplate;

use crate::helpers;

// Match Python volatility constants for formatting/parity.
const SOCK_FAMILY: &[&str] = &[
    "AF_UNSPEC",
    "AF_UNIX",
    "AF_INET",
    "AF_AX25",
    "AF_IPX",
    "AF_APPLETALK",
    "AF_NETROM",
    "AF_BRIDGE",
    "AF_ATMPVC",
    "AF_X25",
    "AF_INET6",
    "AF_ROSE",
    "AF_DECnet",
    "AF_NETBEUI",
    "AF_SECURITY",
    "AF_KEY",
    "AF_NETLINK",
    "AF_PACKET",
    "AF_ASH",
    "AF_ECONET",
    "AF_ATMSVC",
    "AF_RDS",
    "AF_SNA",
    "AF_IRDA",
    "AF_PPPOX",
    "AF_WANPIPE",
    "AF_LLC",
    "AF_IB",
    "AF_MPLS",
    "AF_CAN",
    "AF_TIPC",
    "AF_BLUETOOTH",
    "AF_IUCV",
    "AF_RXRPC",
    "AF_ISDN",
    "AF_PHONET",
    "AF_IEEE802154",
    "AF_CAIF",
    "AF_ALG",
    "AF_NFC",
    "AF_VSOCK",
    "AF_KCM",
    "AF_QIPCRTR",
    "AF_SMC",
    "AF_XDP",
];

const SOCK_TYPES: &[(u16, &str)] = &[
    (1, "STREAM"),
    (2, "DGRAM"),
    (3, "RAW"),
    (4, "RDM"),
    (5, "SEQPACKET"),
    (6, "DCCP"),
    (10, "PACKET"),
];

const SOCKET_STATES: &[&str] = &[
    "FREE",
    "UNCONNECTED",
    "CONNECTING",
    "CONNECTED",
    "DISCONNECTING",
];

const TCP_STATES: &[&str] = &[
    "",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
    "TCP_NEW_SYN_RECV",
];

const IP_PROTOCOLS: &[(u8, &str)] = &[
    (0, "IP"),
    (1, "ICMP"),
    (2, "IGMP"),
    (6, "TCP"),
    (17, "UDP"),
    (41, "IPv6"),
    (47, "GRE"),
    (50, "ESP"),
    (51, "AH"),
    (58, "ICMPv6"),
    (89, "OSPF"),
    (132, "SCTP"),
];

const NETLINK_PROTOCOLS: &[&str] = &[
    "NETLINK_ROUTE",
    "NETLINK_UNUSED",
    "NETLINK_USERSOCK",
    "NETLINK_FIREWALL",
    "NETLINK_SOCK_DIAG",
    "NETLINK_NFLOG",
    "NETLINK_XFRM",
    "NETLINK_SELINUX",
    "NETLINK_ISCSI",
    "NETLINK_AUDIT",
    "NETLINK_FIB_LOOKUP",
    "NETLINK_CONNECTOR",
    "NETLINK_NETFILTER",
    "NETLINK_IP6_FW",
    "NETLINK_DNRTMSG",
    "NETLINK_KOBJECT_UEVENT",
    "NETLINK_GENERIC",
    "NETLINK_DM",
    "NETLINK_SCSITRANSPORT",
    "NETLINK_ECRYPTFS",
    "NETLINK_RDMA",
    "NETLINK_CRYPTO",
    "NETLINK_SMC",
];

const ETH_PROTOCOLS: &[(u16, &str)] = &[
    (0x0001, "ETH_P_802_3"),
    (0x0002, "ETH_P_AX25"),
    (0x0003, "ETH_P_ALL"),
    (0x0004, "ETH_P_802_2"),
    (0x0005, "ETH_P_SNAP"),
    (0x0006, "ETH_P_DDCMP"),
    (0x0007, "ETH_P_WAN_PPP"),
    (0x0008, "ETH_P_PPP_MP"),
    (0x0009, "ETH_P_LOCALTALK"),
    (0x000c, "ETH_P_CAN"),
    (0x000f, "ETH_P_CANFD"),
    (0x0010, "ETH_P_PPPTALK"),
    (0x0011, "ETH_P_TR_802_2"),
    (0x0016, "ETH_P_CONTROL"),
    (0x0017, "ETH_P_IRDA"),
    (0x0018, "ETH_P_ECONET"),
    (0x0019, "ETH_P_HDLC"),
    (0x001a, "ETH_P_ARCNET"),
    (0x001b, "ETH_P_DSA"),
    (0x001c, "ETH_P_TRAILER"),
    (0x0060, "ETH_P_LOOP"),
    (0x00f6, "ETH_P_IEEE802154"),
    (0x00f7, "ETH_P_CAIF"),
    (0x00f8, "ETH_P_XDSA"),
    (0x00f9, "ETH_P_MAP"),
    (0x0800, "ETH_P_IP"),
    (0x0805, "ETH_P_X25"),
    (0x0806, "ETH_P_ARP"),
    (0x8035, "ETH_P_RARP"),
    (0x809b, "ETH_P_ATALK"),
    (0x80f3, "ETH_P_AARP"),
    (0x8100, "ETH_P_8021Q"),
];

const ADDRESS_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;
const UNKNOWN_SOCKET_STATE: &str = "Unknown socket state";

#[derive(Debug, Clone, Copy)]
struct SockOffsets {
    sk_common: u64,
    sk_type: u64,
    sk_protocol: u64,
    sk_socket: u64,
    sk_destruct: u64,
}

#[derive(Debug, Clone, Copy)]
struct SockCommonOffsets {
    skc_family: u64,
    skc_state: u64,
}

#[derive(Debug, Clone, Copy)]
struct SocketOffsets {
    sk: u64,
    state: u64,
}

#[derive(Debug, Clone, Copy)]
struct FileWalkOffsets {
    f_op: u64,
    f_path: u64,
    path_dentry: u64,
    d_inode: u64,
    socket_offset_in_alloc: u64,
    vfs_inode: u64,
    i_ino: u64,
}

#[derive(Default, Debug, Clone, Copy)]
struct InetSockOffsets {
    sport_offset: Option<u64>,
    dport_offset: Option<u64>,
    portpair_offset: Option<u64>,
    saddr_offset: Option<u64>,
    daddr_offset: Option<u64>,
}

#[derive(Default, Debug, Clone, Copy)]
struct UnixSockOffsets {
    addr_offset: Option<u64>,
    peer_offset: Option<u64>,
    sk_offset: u64,
}

#[derive(Default, Debug, Clone, Copy)]
struct NetlinkSockOffsets {
    portid_offset: Option<u64>,
    dst_portid_offset: Option<u64>,
    groups_offset: Option<u64>,
    dst_group_offset: Option<u64>,
    sk_offset: u64,
}

#[derive(Default, Debug, Clone, Copy)]
struct PacketSockOffsets {
    ifindex_offset: Option<u64>,
    num_offset: Option<u64>,
    sk_offset: u64,
}

#[derive(Default, Debug, Clone, Copy)]
struct SockFilterOffsets {
    sk_filter_offset: Option<u64>,
    sk_reuseport_cb_offset: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct NetNsOffsets {
    list: u64,
    dev_base_head: u64,
    proc_inum: Option<u64>,
    ns: Option<u64>,
    ns_inum: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct NetDeviceMapOffsets {
    dev_list: u64,
    name: u64,
    name_size: usize,
    ifindex: u64,
    ifindex_size: usize,
}

#[derive(Debug, Clone)]
struct SocketScanEntry {
    offset: u64,
    family: String,
    sock_type: String,
    protocol: String,
    source_addr: String,
    source_port: String,
    dest_addr: String,
    dest_port: String,
    state: String,
    filter: String,
}

/// Sockscan plugin - scans for socket structures
pub struct Sockscan;

impl Sockscan {
    pub fn new() -> Self {
        Self
    }

    fn scan_sockets(context: &Context) -> Vol3Result<Vec<SocketScanEntry>> {
        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;
        let kernel_layer = context
            .get_layer(&layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(layer_name.clone())))?;
        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;

        let memory_layer = {
            let deps = kernel_layer.dependencies();
            if let Some(name) = deps.first() {
                context
                    .get_layer(name)
                    .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(name.clone())))?
            } else {
                kernel_layer.clone()
            }
        };

        let sock_offsets = get_sock_offsets(context, &symbol_table)?;
        let sock_common_offsets = get_sock_common_offsets(context, &symbol_table)?;
        let socket_offsets = get_socket_offsets(context, &symbol_table)?;
        let file_walk_offsets = get_file_walk_offsets(context, &symbol_table)?;
        let inet_offsets = get_inet_sock_offsets(context, &symbol_table);
        let unix_offsets = get_unix_sock_offsets(context, &symbol_table);
        let netlink_offsets = get_netlink_sock_offsets(context, &symbol_table);
        let packet_offsets = get_packet_sock_offsets(context, &symbol_table);
        let filter_offsets = get_sock_filter_offsets(context, &symbol_table);

        let ifindex_to_name =
            build_ifindex_name_map(context, kernel_layer.as_ref(), &symbol_table, aslr_shift);

        let file_ops_needles = canonicalize_symbol_addrs(
            context,
            &symbol_table,
            aslr_shift,
            &["socket_file_ops", "sockfs_dentry_operations"],
        );

        let destruct_needles = canonicalize_symbol_addrs(
            context,
            &symbol_table,
            aslr_shift,
            &[
                "sock_def_destruct",
                "packet_sock_destruct",
                "unix_sock_destructor",
                "netlink_sock_destruct",
                "inet_sock_destruct",
            ],
        );

        if file_ops_needles.is_empty() && destruct_needles.is_empty() {
            return Ok(Vec::new());
        }

        let file_ops_set: HashSet<Vec<u8>> = file_ops_needles.into_iter().collect();
        let destruct_set: HashSet<Vec<u8>> = destruct_needles.into_iter().collect();

        let mut all_patterns: Vec<Vec<u8>> = file_ops_set.iter().cloned().collect();
        for needle in &destruct_set {
            if !all_patterns.iter().any(|p| p == needle) {
                all_patterns.push(needle.clone());
            }
        }

        let scanner = MultiPatternScanner::new(all_patterns);
        let mut hits = memory_layer.scan(&scanner, None, None);
        hits.sort_by_key(|(offset, _)| *offset);

        let kernel_intel = kernel_layer.as_any().downcast_ref::<Intel32e>();

        let mut entries = Vec::new();
        // Keep parity with Python sockscan dedup behavior:
        // it deduplicates on the destructor-derived sock offset and uses None for file-op-only hits.
        let mut seen_sock_keys: HashSet<Option<u64>> = HashSet::new();

        for (needle_offset, matched) in hits {
            let mut dedup_key: Option<u64> = None;
            let mut candidate_offset: Option<u64> = None;

            if destruct_set.contains(&matched) {
                if let Some(sock_offset) = needle_offset.checked_sub(sock_offsets.sk_destruct) {
                    dedup_key = Some(sock_offset);
                    candidate_offset = Some(sock_offset);
                }
            }

            if file_ops_set.contains(&matched) {
                if let Some(sock_offset) = walk_file_ops_to_sock_phys(
                    kernel_layer.as_ref(),
                    memory_layer.as_ref(),
                    kernel_intel,
                    needle_offset,
                    &file_walk_offsets,
                    &socket_offsets,
                    sock_offsets.sk_socket,
                ) {
                    // Parity note: Python keeps the previously-set dedup key from destructor path.
                    // For file-op-only hits this remains None.
                    candidate_offset = Some(sock_offset);
                }
            }

            if let Some(sock_offset) = candidate_offset {
                if !seen_sock_keys.insert(dedup_key) {
                    continue;
                }

                if let Some(entry) = parse_scanned_socket(
                    memory_layer.as_ref(),
                    kernel_layer.as_ref(),
                    sock_offset,
                    &sock_offsets,
                    &sock_common_offsets,
                    &socket_offsets,
                    &file_walk_offsets,
                    &inet_offsets,
                    &unix_offsets,
                    &netlink_offsets,
                    &packet_offsets,
                    &filter_offsets,
                    &ifindex_to_name,
                    kernel_intel,
                ) {
                    entries.push(entry);
                }
            }
        }

        entries.sort_by_key(|entry| entry.offset);
        Ok(entries)
    }
}

fn canonicalize_symbol_addrs(
    context: &Context,
    symbol_table: &str,
    aslr_shift: u64,
    symbol_names: &[&str],
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for symbol_name in symbol_names {
        let Ok(symbol) = context.get_symbol(symbol_table, symbol_name) else {
            continue;
        };
        let base_addr = symbol.address.wrapping_add(aslr_shift);
        let canonical = if base_addr & 0x0000_8000_0000_0000 != 0 {
            base_addr | 0xFFFF_0000_0000_0000
        } else {
            base_addr
        };
        let needle = canonical.to_le_bytes().to_vec();
        if seen.insert(needle.clone()) {
            out.push(needle);
        }
    }

    out
}

fn get_sock_offsets(context: &Context, symbol_table: &str) -> Vol3Result<SockOffsets> {
    let sock_template = context.get_type(symbol_table, "sock")?;
    if let TypeTemplate::Struct(s) = sock_template.as_ref() {
        let sk_destruct = s
            .get_field("sk_destruct")
            .map(|f| f.offset as u64)
            .ok_or_else(|| {
                Vol3Error::Object(ObjectError::MemberNotFound {
                    type_name: "sock".to_string(),
                    member: "sk_destruct".to_string(),
                })
            })?;

        Ok(SockOffsets {
            sk_common: s
                .get_field("__sk_common")
                .map(|f| f.offset as u64)
                .unwrap_or(0),
            sk_type: s
                .get_field("sk_type")
                .map(|f| f.offset as u64)
                .unwrap_or(546),
            sk_protocol: s
                .get_field("sk_protocol")
                .map(|f| f.offset as u64)
                .unwrap_or(548),
            sk_socket: s
                .get_field("sk_socket")
                .map(|f| f.offset as u64)
                .unwrap_or(40),
            sk_destruct,
        })
    } else {
        Err(Vol3Error::Object(ObjectError::InvalidTemplate(
            "sock must be a struct".to_string(),
        )))
    }
}

fn get_sock_common_offsets(context: &Context, symbol_table: &str) -> Vol3Result<SockCommonOffsets> {
    let common_template = context.get_type(symbol_table, "sock_common")?;
    if let TypeTemplate::Struct(s) = common_template.as_ref() {
        Ok(SockCommonOffsets {
            skc_family: s
                .get_field("skc_family")
                .map(|f| f.offset as u64)
                .unwrap_or(16),
            skc_state: s
                .get_field("skc_state")
                .map(|f| f.offset as u64)
                .unwrap_or(18),
        })
    } else {
        Err(Vol3Error::Object(ObjectError::InvalidTemplate(
            "sock_common must be a struct".to_string(),
        )))
    }
}

fn get_socket_offsets(context: &Context, symbol_table: &str) -> Vol3Result<SocketOffsets> {
    let socket_template = context.get_type(symbol_table, "socket")?;
    if let TypeTemplate::Struct(s) = socket_template.as_ref() {
        Ok(SocketOffsets {
            sk: s.get_field("sk").map(|f| f.offset as u64).unwrap_or(24),
            state: s.get_field("state").map(|f| f.offset as u64).unwrap_or(0),
        })
    } else {
        Err(Vol3Error::Object(ObjectError::InvalidTemplate(
            "socket must be a struct".to_string(),
        )))
    }
}

fn get_file_walk_offsets(context: &Context, symbol_table: &str) -> Vol3Result<FileWalkOffsets> {
    let file_template = context.get_type(symbol_table, "file")?;
    let (f_op, f_path) = if let TypeTemplate::Struct(s) = file_template.as_ref() {
        (
            s.get_field("f_op").map(|f| f.offset as u64).unwrap_or(40),
            s.get_field("f_path").map(|f| f.offset as u64).unwrap_or(16),
        )
    } else {
        (40, 16)
    };

    let path_template = context.get_type(symbol_table, "path")?;
    let path_dentry = if let TypeTemplate::Struct(s) = path_template.as_ref() {
        s.get_field("dentry").map(|f| f.offset as u64).unwrap_or(8)
    } else {
        8
    };

    let dentry_template = context.get_type(symbol_table, "dentry")?;
    let d_inode = if let TypeTemplate::Struct(s) = dentry_template.as_ref() {
        s.get_field("d_inode")
            .map(|f| f.offset as u64)
            .unwrap_or(48)
    } else {
        48
    };

    let socket_alloc_template = context.get_type(symbol_table, "socket_alloc")?;
    let (socket_offset_in_alloc, vfs_inode) =
        if let TypeTemplate::Struct(s) = socket_alloc_template.as_ref() {
            (
                s.get_field("socket").map(|f| f.offset as u64).unwrap_or(0),
                s.get_field("vfs_inode")
                    .map(|f| f.offset as u64)
                    .unwrap_or(128),
            )
        } else {
            (0, 128)
        };

    let inode_template = context.get_type(symbol_table, "inode")?;
    let i_ino = if let TypeTemplate::Struct(s) = inode_template.as_ref() {
        s.get_field("i_ino").map(|f| f.offset as u64).unwrap_or(64)
    } else {
        64
    };

    Ok(FileWalkOffsets {
        f_op,
        f_path,
        path_dentry,
        d_inode,
        socket_offset_in_alloc,
        vfs_inode,
        i_ino,
    })
}

fn get_inet_sock_offsets(context: &Context, symbol_table: &str) -> InetSockOffsets {
    let mut offsets = InetSockOffsets::default();

    if let Ok(inet_sock_template) = context.get_type(symbol_table, "inet_sock") {
        if let TypeTemplate::Struct(s) = inet_sock_template.as_ref() {
            offsets.sport_offset = s
                .get_field("inet_sport")
                .map(|f| f.offset as u64)
                .or_else(|| s.get_field("sport").map(|f| f.offset as u64));
            offsets.dport_offset = s
                .get_field("inet_dport")
                .map(|f| f.offset as u64)
                .or_else(|| s.get_field("dport").map(|f| f.offset as u64));
            offsets.saddr_offset = s
                .get_field("inet_rcv_saddr")
                .map(|f| f.offset as u64)
                .or_else(|| s.get_field("rcv_saddr").map(|f| f.offset as u64))
                .or_else(|| s.get_field("inet_saddr").map(|f| f.offset as u64));
            offsets.daddr_offset = s
                .get_field("inet_daddr")
                .map(|f| f.offset as u64)
                .or_else(|| s.get_field("daddr").map(|f| f.offset as u64));
        }
    }

    if offsets.saddr_offset.is_none() {
        offsets.saddr_offset = Some(4);
    }
    if offsets.daddr_offset.is_none() {
        offsets.daddr_offset = Some(0);
    }
    if offsets.dport_offset.is_none() {
        offsets.portpair_offset = Some(12);
    }

    offsets
}

fn get_unix_sock_offsets(context: &Context, symbol_table: &str) -> UnixSockOffsets {
    let mut offsets = UnixSockOffsets::default();
    if let Ok(unix_sock_template) = context.get_type(symbol_table, "unix_sock") {
        if let TypeTemplate::Struct(s) = unix_sock_template.as_ref() {
            offsets.addr_offset = s.get_field("addr").map(|f| f.offset as u64);
            offsets.peer_offset = s.get_field("peer").map(|f| f.offset as u64);
            offsets.sk_offset = s.get_field("sk").map(|f| f.offset as u64).unwrap_or(0);
        }
    }
    offsets
}

fn get_netlink_sock_offsets(context: &Context, symbol_table: &str) -> NetlinkSockOffsets {
    let mut offsets = NetlinkSockOffsets::default();
    if let Ok(netlink_sock_template) = context.get_type(symbol_table, "netlink_sock") {
        if let TypeTemplate::Struct(s) = netlink_sock_template.as_ref() {
            offsets.portid_offset = s
                .get_field("portid")
                .map(|f| f.offset as u64)
                .or_else(|| s.get_field("pid").map(|f| f.offset as u64));
            offsets.dst_portid_offset = s
                .get_field("dst_portid")
                .map(|f| f.offset as u64)
                .or_else(|| s.get_field("dst_pid").map(|f| f.offset as u64));
            offsets.groups_offset = s.get_field("groups").map(|f| f.offset as u64);
            offsets.dst_group_offset = s.get_field("dst_group").map(|f| f.offset as u64);
            offsets.sk_offset = s.get_field("sk").map(|f| f.offset as u64).unwrap_or(0);
        }
    }
    offsets
}

fn get_packet_sock_offsets(context: &Context, symbol_table: &str) -> PacketSockOffsets {
    let mut offsets = PacketSockOffsets::default();
    if let Ok(packet_sock_template) = context.get_type(symbol_table, "packet_sock") {
        if let TypeTemplate::Struct(s) = packet_sock_template.as_ref() {
            offsets.ifindex_offset = s.get_field("ifindex").map(|f| f.offset as u64);
            offsets.num_offset = s.get_field("num").map(|f| f.offset as u64);
            offsets.sk_offset = s.get_field("sk").map(|f| f.offset as u64).unwrap_or(0);
        }
    }
    offsets
}

fn get_sock_filter_offsets(context: &Context, symbol_table: &str) -> SockFilterOffsets {
    let mut offsets = SockFilterOffsets::default();
    if let Ok(sock_template) = context.get_type(symbol_table, "sock") {
        if let TypeTemplate::Struct(s) = sock_template.as_ref() {
            offsets.sk_filter_offset = s.get_field("sk_filter").map(|f| f.offset as u64);
            offsets.sk_reuseport_cb_offset =
                s.get_field("sk_reuseport_cb").map(|f| f.offset as u64);
        }
    }
    offsets
}

fn walk_file_ops_to_sock_phys(
    kernel_layer: &dyn DataLayer,
    memory_layer: &dyn DataLayer,
    kernel_intel: Option<&Intel32e>,
    needle_offset: u64,
    file_offsets: &FileWalkOffsets,
    socket_offsets: &SocketOffsets,
    sk_socket_offset: u64,
) -> Option<u64> {
    let translator = kernel_intel?;

    let file_phys = needle_offset.checked_sub(file_offsets.f_op)?;
    if !memory_layer.is_valid(file_phys, 8) {
        return None;
    }

    let dentry_ptr = helpers::read_pointer(
        memory_layer,
        file_phys + file_offsets.f_path + file_offsets.path_dentry,
    )
    .ok()?;

    if !helpers::is_valid_kernel_address(dentry_ptr) {
        return None;
    }

    let d_inode = helpers::read_pointer(kernel_layer, dentry_ptr + file_offsets.d_inode).ok()?;
    if !helpers::is_valid_kernel_address(d_inode) {
        return None;
    }

    let socket_alloc_addr = d_inode.checked_sub(file_offsets.vfs_inode)?;
    let socket_addr = socket_alloc_addr + file_offsets.socket_offset_in_alloc;
    let sock_vaddr = helpers::read_pointer(kernel_layer, socket_addr + socket_offsets.sk).ok()?;
    if !helpers::is_valid_kernel_address(sock_vaddr) {
        return None;
    }

    let (sock_phys, _) = translator.translate(sock_vaddr).ok()?;
    if !memory_layer.is_valid(sock_phys, sk_socket_offset as usize + 8) {
        return None;
    }
    Some(sock_phys)
}

fn get_generic_state(
    kernel_layer: &dyn DataLayer,
    socket_ptr: u64,
    socket_state_offset: u64,
) -> String {
    if socket_ptr == 0 || !helpers::is_valid_kernel_address(socket_ptr) {
        return UNKNOWN_SOCKET_STATE.to_string();
    }
    let state_idx = helpers::read_u8(kernel_layer, socket_ptr + socket_state_offset)
        .unwrap_or(u8::MAX) as usize;
    if state_idx < SOCKET_STATES.len() {
        SOCKET_STATES[state_idx].to_string()
    } else {
        UNKNOWN_SOCKET_STATE.to_string()
    }
}

fn validate_socket_backpointer(
    kernel_layer: &dyn DataLayer,
    socket_ptr: u64,
    socket_offsets: &SocketOffsets,
    sock_phys: u64,
    kernel_intel: Option<&Intel32e>,
) -> bool {
    if socket_ptr == 0 || !helpers::is_valid_kernel_address(socket_ptr) {
        return false;
    }

    let sk_ptr = match helpers::read_pointer(kernel_layer, socket_ptr + socket_offsets.sk) {
        Ok(value) => value,
        Err(_) => return false,
    };
    if sk_ptr == 0 || !helpers::is_valid_kernel_address(sk_ptr) {
        return false;
    }

    if let Some(translator) = kernel_intel {
        if let Ok((translated_phys, _)) = translator.translate(sk_ptr) {
            return translated_phys == sock_phys;
        }
        // If translation fails, keep the candidate and let later field validation decide.
        return true;
    }
    false
}

fn socket_inode_from_socket_ptr(
    kernel_layer: &dyn DataLayer,
    socket_ptr: u64,
    file_offsets: &FileWalkOffsets,
) -> u64 {
    if socket_ptr == 0 || !helpers::is_valid_kernel_address(socket_ptr) {
        return 0;
    }
    let socket_alloc_addr = socket_ptr.wrapping_sub(file_offsets.socket_offset_in_alloc);
    let vfs_inode_addr = socket_alloc_addr + file_offsets.vfs_inode;
    helpers::read_u64(kernel_layer, vfs_inode_addr + file_offsets.i_ino).unwrap_or(0)
}

fn parse_scanned_socket(
    memory_layer: &dyn DataLayer,
    kernel_layer: &dyn DataLayer,
    sock_offset: u64,
    sock_offsets: &SockOffsets,
    sock_common_offsets: &SockCommonOffsets,
    socket_offsets: &SocketOffsets,
    file_offsets: &FileWalkOffsets,
    inet_offsets: &InetSockOffsets,
    unix_offsets: &UnixSockOffsets,
    netlink_offsets: &NetlinkSockOffsets,
    packet_offsets: &PacketSockOffsets,
    filter_offsets: &SockFilterOffsets,
    ifindex_to_name: &HashMap<i32, String>,
    kernel_intel: Option<&Intel32e>,
) -> Option<SocketScanEntry> {
    if !memory_layer.is_valid(sock_offset, 8) {
        return None;
    }

    let sk_common_addr = sock_offset + sock_offsets.sk_common;
    let family_idx = helpers::read_u16(
        memory_layer,
        sk_common_addr + sock_common_offsets.skc_family,
    )
    .unwrap_or(0) as usize;
    if family_idx >= SOCK_FAMILY.len() {
        return None;
    }
    if !matches!(family_idx, 0 | 1 | 2 | 10 | 16 | 17) {
        return None;
    }
    let skc_state =
        helpers::read_u8(memory_layer, sk_common_addr + sock_common_offsets.skc_state).unwrap_or(0);
    let sk_type_value =
        helpers::read_u16(memory_layer, sock_offset + sock_offsets.sk_type).unwrap_or(0);
    let sk_protocol =
        helpers::read_u8(memory_layer, sock_offset + sock_offsets.sk_protocol).unwrap_or(0);

    let family = if family_idx < SOCK_FAMILY.len() {
        SOCK_FAMILY[family_idx].to_string()
    } else {
        format!("AF_{}", family_idx)
    };
    let sock_type = SOCK_TYPES
        .iter()
        .find(|(value, _)| *value == sk_type_value)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_default();

    let socket_ptr =
        helpers::read_pointer(memory_layer, sock_offset + sock_offsets.sk_socket).unwrap_or(0);
    let needs_generic_socket_state = family_idx == 0
        || family_idx == 16
        || family_idx == 17
        || (family_idx == 1 && sock_type != "STREAM")
        || (family_idx == 2 && sock_type != "STREAM");
    if needs_generic_socket_state
        && (socket_ptr == 0
            || !helpers::is_valid_kernel_address(socket_ptr)
            || !kernel_layer.is_valid(socket_ptr + socket_offsets.state, 1))
    {
        return None;
    }
    if matches!(family_idx, 16 | 17)
        && !validate_socket_backpointer(
            kernel_layer,
            socket_ptr,
            socket_offsets,
            sock_offset,
            kernel_intel,
        )
    {
        return None;
    }
    if family_idx != 0 && sock_type.is_empty() {
        return None;
    }
    let generic_state = get_generic_state(kernel_layer, socket_ptr, socket_offsets.state);
    let socket_inode = socket_inode_from_socket_ptr(kernel_layer, socket_ptr, file_offsets);

    let mut protocol = "-".to_string();
    let (source_addr, source_port, dest_addr, dest_port, state) = match family_idx {
        1 => parse_unix_sock(
            memory_layer,
            kernel_layer,
            sock_offset,
            unix_offsets,
            &sock_type,
            skc_state,
            &generic_state,
            socket_inode,
            file_offsets,
            sock_offsets.sk_socket,
        ),
        2 | 10 => {
            let (src_addr, src_port, dst_addr, dst_port, sock_state, proto) = parse_inet_sock(
                memory_layer,
                sock_offset,
                inet_offsets,
                family_idx,
                &sock_type,
                skc_state,
                sk_protocol,
                &generic_state,
            );
            protocol = proto;
            (src_addr, src_port, dst_addr, dst_port, sock_state)
        }
        16 => {
            let (src_addr, src_port, dst_addr, dst_port, sock_state, proto) = parse_netlink_sock(
                memory_layer,
                kernel_layer,
                sock_offset,
                netlink_offsets,
                sk_protocol,
                &generic_state,
            );
            protocol = proto;
            (src_addr, src_port, dst_addr, dst_port, sock_state)
        }
        17 => {
            let (src_addr, src_port, dst_addr, dst_port, sock_state, proto) = parse_packet_sock(
                memory_layer,
                sock_offset,
                packet_offsets,
                &generic_state,
                ifindex_to_name,
            );
            protocol = proto;
            (src_addr, src_port, dst_addr, dst_port, sock_state)
        }
        _ => (
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            UNKNOWN_SOCKET_STATE.to_string(),
        ),
    };

    let mut filter = parse_socket_filter(memory_layer, sock_offset, filter_offsets);
    if family_idx == 0 {
        filter = "-".to_string();
    }
    if family_idx == 2 && (sock_type != "STREAM" || protocol != "TCP") {
        return None;
    }
    let src_na = source_addr == "-";
    // Match Python sockscan condition exactly (it checks src-NA for both sides).
    if (source_addr == "0.0.0.0" || src_na) && (dest_addr == "0.0.0.0" || src_na) {
        if state == "UNCONNECTED" {
            return None;
        }
        if source_port == "0" && dest_port == "0" {
            return None;
        }
    }

    Some(SocketScanEntry {
        offset: sock_offset,
        family,
        sock_type,
        protocol,
        source_addr,
        source_port,
        dest_addr,
        dest_port,
        state,
        filter,
    })
}

fn parse_unix_sock(
    memory_layer: &dyn DataLayer,
    kernel_layer: &dyn DataLayer,
    sock_offset: u64,
    offsets: &UnixSockOffsets,
    sock_type: &str,
    skc_state: u8,
    generic_state: &str,
    socket_inode: u64,
    file_offsets: &FileWalkOffsets,
    sk_socket_offset: u64,
) -> (String, String, String, String, String) {
    let unix_sock_addr = sock_offset.wrapping_sub(offsets.sk_offset);

    let src_addr = if let Some(addr_off) = offsets.addr_offset {
        let addr_ptr = helpers::read_pointer(memory_layer, unix_sock_addr + addr_off).unwrap_or(0);
        if addr_ptr != 0
            && helpers::is_valid_kernel_address(addr_ptr)
            && kernel_layer.is_valid(addr_ptr, 1)
        {
            let sun_path_addr = addr_ptr + 12 + 2;
            helpers::read_string(kernel_layer, sun_path_addr, 108).unwrap_or_default()
        } else {
            "-".to_string()
        }
    } else {
        "-".to_string()
    };

    let src_port = socket_inode.to_string();

    let (mut dst_addr, mut dst_port) = if let Some(peer_off) = offsets.peer_offset {
        let peer_unix_sock_ptr =
            helpers::read_pointer(memory_layer, unix_sock_addr + peer_off).unwrap_or(0);
        if peer_unix_sock_ptr != 0 && helpers::is_valid_kernel_address(peer_unix_sock_ptr) {
            let peer_path = if let Some(addr_off) = offsets.addr_offset {
                let addr_ptr =
                    helpers::read_pointer(kernel_layer, peer_unix_sock_ptr + addr_off).unwrap_or(0);
                if addr_ptr != 0 && helpers::is_valid_kernel_address(addr_ptr) {
                    let sun_path_addr = addr_ptr + 12 + 2;
                    Some(helpers::read_string(kernel_layer, sun_path_addr, 108).unwrap_or_default())
                } else {
                    None
                }
            } else {
                None
            };

            let peer_sock_addr = peer_unix_sock_ptr + offsets.sk_offset;
            let peer_sk_socket_ptr =
                helpers::read_pointer(kernel_layer, peer_sock_addr + sk_socket_offset).unwrap_or(0);
            let peer_inode = if peer_sk_socket_ptr != 0
                && helpers::is_valid_kernel_address(peer_sk_socket_ptr)
            {
                let peer_socket_alloc_addr =
                    peer_sk_socket_ptr.wrapping_sub(file_offsets.socket_offset_in_alloc);
                let peer_vfs_inode_addr = peer_socket_alloc_addr + file_offsets.vfs_inode;
                helpers::read_u64(kernel_layer, peer_vfs_inode_addr + file_offsets.i_ino)
                    .unwrap_or(0)
            } else {
                0
            };

            let dst_addr_value = peer_path.unwrap_or_else(|| "-".to_string());
            (dst_addr_value, peer_inode.to_string())
        } else {
            ("-".to_string(), "-".to_string())
        }
    } else {
        ("-".to_string(), "-".to_string())
    };

    let state = if sock_type == "STREAM" {
        let idx = skc_state as usize;
        if idx < TCP_STATES.len() {
            TCP_STATES[idx].to_string()
        } else {
            "Unknown unix_sock stream state".to_string()
        }
    } else {
        generic_state.to_string()
    };

    (src_addr, src_port, dst_addr, dst_port, state)
}

fn parse_inet_sock(
    memory_layer: &dyn DataLayer,
    sock_offset: u64,
    offsets: &InetSockOffsets,
    family_idx: usize,
    sock_type: &str,
    skc_state: u8,
    sk_protocol: u8,
    generic_state: &str,
) -> (String, String, String, String, String, String) {
    let is_ipv6 = family_idx == 10;

    let src_port = if let Some(off) = offsets.sport_offset {
        let port_be = helpers::read_u16(memory_layer, sock_offset + off).unwrap_or(0);
        u16::from_be(port_be).to_string()
    } else {
        "-".to_string()
    };

    let dst_port = if let Some(off) = offsets.dport_offset {
        let port_be = helpers::read_u16(memory_layer, sock_offset + off).unwrap_or(0);
        u16::from_be(port_be).to_string()
    } else if let Some(off) = offsets.portpair_offset {
        let port_le = helpers::read_u16(memory_layer, sock_offset + off).unwrap_or(0);
        port_le.swap_bytes().to_string()
    } else {
        "-".to_string()
    };

    let src_addr = if is_ipv6 {
        "-".to_string()
    } else if let Some(off) = offsets.saddr_offset {
        if let Ok(bytes) = memory_layer.read(sock_offset + off, 4, false) {
            let arr: [u8; 4] = bytes.try_into().unwrap_or([0u8; 4]);
            Ipv4Addr::from(arr).to_string()
        } else {
            "-".to_string()
        }
    } else {
        "-".to_string()
    };

    let dst_addr = if is_ipv6 {
        "-".to_string()
    } else if let Some(off) = offsets.daddr_offset {
        if let Ok(bytes) = memory_layer.read(sock_offset + off, 4, false) {
            let arr: [u8; 4] = bytes.try_into().unwrap_or([0u8; 4]);
            Ipv4Addr::from(arr).to_string()
        } else {
            "-".to_string()
        }
    } else {
        "-".to_string()
    };

    let state = if sock_type == "STREAM" {
        let state_idx = skc_state as usize;
        if state_idx < TCP_STATES.len() {
            TCP_STATES[state_idx].to_string()
        } else {
            "Unknown inet_sock stream state".to_string()
        }
    } else {
        generic_state.to_string()
    };

    let protocol = get_ip_protocol(sk_protocol);
    (src_addr, src_port, dst_addr, dst_port, state, protocol)
}

fn parse_netlink_sock(
    memory_layer: &dyn DataLayer,
    kernel_layer: &dyn DataLayer,
    sock_offset: u64,
    offsets: &NetlinkSockOffsets,
    sk_protocol: u8,
    generic_state: &str,
) -> (String, String, String, String, String, String) {
    let netlink_sock_addr = sock_offset.wrapping_sub(offsets.sk_offset);

    let src_addr = if let Some(off) = offsets.groups_offset {
        let groups_ptr = helpers::read_pointer(memory_layer, netlink_sock_addr + off).unwrap_or(0);
        if groups_ptr != 0 && helpers::is_valid_kernel_address(groups_ptr) {
            let groups = helpers::read_u32(kernel_layer, groups_ptr).unwrap_or(0);
            format!("groups:0x{:08x}", groups)
        } else {
            "-".to_string()
        }
    } else {
        "-".to_string()
    };

    let src_port = if let Some(off) = offsets.portid_offset {
        helpers::read_u32(memory_layer, netlink_sock_addr + off)
            .unwrap_or(0)
            .to_string()
    } else {
        "-".to_string()
    };

    let dst_addr = if let Some(off) = offsets.dst_group_offset {
        let dst_group = helpers::read_u32(memory_layer, netlink_sock_addr + off).unwrap_or(0);
        format!("group:0x{:08x}", dst_group)
    } else {
        "-".to_string()
    };

    let dst_port = if let Some(off) = offsets.dst_portid_offset {
        helpers::read_u32(memory_layer, netlink_sock_addr + off)
            .unwrap_or(0)
            .to_string()
    } else {
        "-".to_string()
    };

    let protocol = if (sk_protocol as usize) < NETLINK_PROTOCOLS.len() {
        NETLINK_PROTOCOLS[sk_protocol as usize].to_string()
    } else {
        format!("NETLINK_{}", sk_protocol)
    };

    (
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        generic_state.to_string(),
        protocol,
    )
}

fn parse_packet_sock(
    memory_layer: &dyn DataLayer,
    sock_offset: u64,
    offsets: &PacketSockOffsets,
    generic_state: &str,
    ifindex_to_name: &HashMap<i32, String>,
) -> (String, String, String, String, String, String) {
    let packet_sock_addr = sock_offset.wrapping_sub(offsets.sk_offset);
    let ifindex = offsets
        .ifindex_offset
        .map(|off| helpers::read_u32(memory_layer, packet_sock_addr + off).unwrap_or(0) as i32)
        .unwrap_or(0);

    let src_addr = if ifindex <= 0 {
        "ANY".to_string()
    } else {
        ifindex_to_name
            .get(&ifindex)
            .cloned()
            .unwrap_or_else(|| "-".to_string())
    };

    let protocol = offsets
        .num_offset
        .map(|off| {
            let num = helpers::read_u16(memory_layer, packet_sock_addr + off).unwrap_or(0);
            let eth_proto = num.swap_bytes();
            if eth_proto == 0 {
                "-".to_string()
            } else {
                get_eth_protocol(eth_proto)
            }
        })
        .unwrap_or_else(|| "-".to_string());

    (
        src_addr,
        "-".to_string(),
        "-".to_string(),
        "-".to_string(),
        generic_state.to_string(),
        protocol,
    )
}

fn parse_socket_filter(
    memory_layer: &dyn DataLayer,
    sock_offset: u64,
    offsets: &SockFilterOffsets,
) -> String {
    let mut filter_type: Option<&'static str> = None;

    if let Some(off) = offsets.sk_filter_offset {
        let ptr = helpers::read_pointer(memory_layer, sock_offset + off).unwrap_or(0);
        if ptr != 0 {
            filter_type = Some("socket_filter");
        }
    }

    if let Some(off) = offsets.sk_reuseport_cb_offset {
        let ptr = helpers::read_pointer(memory_layer, sock_offset + off).unwrap_or(0);
        if ptr != 0 {
            filter_type = Some("reuseport_filter");
        }
    }

    if let Some(filter_type) = filter_type {
        format!("filter_type={},bpf_filter_type=cBPF", filter_type)
    } else {
        "-".to_string()
    }
}

fn get_ip_protocol(proto: u8) -> String {
    IP_PROTOCOLS
        .iter()
        .find(|(p, _)| *p == proto)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_else(|| format!("{}", proto))
}

fn get_eth_protocol(proto: u16) -> String {
    ETH_PROTOCOLS
        .iter()
        .find(|(p, _)| *p == proto)
        .map(|(_, n)| (*n).to_string())
        .unwrap_or_else(|| format!("0x{:x}", proto))
}

fn parse_net_offsets_for_device_map(context: &Context, symbol_table: &str) -> Option<NetNsOffsets> {
    let net_template = context.get_type(symbol_table, "net").ok()?;
    if let TypeTemplate::Struct(s) = net_template.as_ref() {
        let list = s.get_field("list").map(|f| f.offset as u64)?;
        let dev_base_head = s.get_field("dev_base_head").map(|f| f.offset as u64)?;
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

        Some(NetNsOffsets {
            list,
            dev_base_head,
            proc_inum,
            ns,
            ns_inum,
        })
    } else {
        None
    }
}

fn parse_net_device_map_offsets(
    context: &Context,
    symbol_table: &str,
) -> Option<NetDeviceMapOffsets> {
    let dev_template = context.get_type(symbol_table, "net_device").ok()?;
    if let TypeTemplate::Struct(s) = dev_template.as_ref() {
        let name_field = s.get_field("name")?;
        let ifindex_field = s.get_field("ifindex")?;
        Some(NetDeviceMapOffsets {
            dev_list: s.get_field("dev_list").map(|f| f.offset as u64)?,
            name: name_field.offset as u64,
            name_size: name_field.template.size().unwrap_or(16),
            ifindex: ifindex_field.offset as u64,
            ifindex_size: ifindex_field.template.size().unwrap_or(4),
        })
    } else {
        None
    }
}

fn read_pointer_masked(layer: &dyn DataLayer, address: u64) -> u64 {
    helpers::read_pointer(layer, address)
        .map(|value| value & ADDRESS_MASK)
        .unwrap_or(0)
}

fn read_unsigned(layer: &dyn DataLayer, address: u64, size: usize) -> u64 {
    match size {
        1 => helpers::read_u8(layer, address).unwrap_or(0) as u64,
        2 => helpers::read_u16(layer, address).unwrap_or(0) as u64,
        4 => helpers::read_u32(layer, address).unwrap_or(0) as u64,
        8 => helpers::read_u64(layer, address).unwrap_or(0),
        _ => 0,
    }
}

fn read_cstring_at(layer: &dyn DataLayer, address: u64, max_len: usize) -> String {
    helpers::read_string(layer, address, max_len).unwrap_or_default()
}

fn read_net_namespace_inode(layer: &dyn DataLayer, net_addr: u64, offsets: &NetNsOffsets) -> u64 {
    if let Some(proc_inum) = offsets.proc_inum {
        let val = helpers::read_u32(layer, net_addr + proc_inum).unwrap_or(0) as u64;
        if val != 0 {
            return val;
        }
    }

    if let (Some(ns), Some(inum)) = (offsets.ns, offsets.ns_inum) {
        let val = helpers::read_u32(layer, net_addr + ns + inum).unwrap_or(0) as u64;
        if val != 0 {
            return val;
        }
    }

    0
}

fn build_ifindex_name_map(
    context: &Context,
    kernel_layer: &dyn DataLayer,
    symbol_table: &str,
    aslr_shift: u64,
) -> HashMap<i32, String> {
    let mut mapping = HashMap::new();

    let net_offsets = match parse_net_offsets_for_device_map(context, symbol_table) {
        Some(offsets) => offsets,
        None => return mapping,
    };
    let dev_offsets = match parse_net_device_map_offsets(context, symbol_table) {
        Some(offsets) => offsets,
        None => return mapping,
    };

    let net_namespace_sym = match context.get_symbol(symbol_table, "net_namespace_list") {
        Ok(sym) => sym,
        Err(_) => return mapping,
    };

    let net_namespace_list = {
        let sym = net_namespace_sym.address;
        let candidates = [
            sym.wrapping_add(aslr_shift),
            sym,
            read_pointer_masked(kernel_layer, sym.wrapping_add(aslr_shift)),
            read_pointer_masked(kernel_layer, sym),
        ];

        let mut chosen = 0_u64;
        for candidate in candidates {
            let list_head = candidate & ADDRESS_MASK;
            if list_head == 0 {
                continue;
            }
            let first = read_pointer_masked(kernel_layer, list_head);
            if first != 0 && first != list_head {
                chosen = list_head;
                break;
            }
        }
        chosen
    };

    if net_namespace_list == 0 {
        return mapping;
    }

    let mut seen_ns_links = HashSet::new();
    let mut current_ns = read_pointer_masked(kernel_layer, net_namespace_list);
    while current_ns != 0
        && current_ns != net_namespace_list
        && !seen_ns_links.contains(&current_ns)
    {
        seen_ns_links.insert(current_ns);

        let net_addr = current_ns.saturating_sub(net_offsets.list) & ADDRESS_MASK;
        let _netns_id = read_net_namespace_inode(kernel_layer, net_addr, &net_offsets);
        let dev_head = (net_addr + net_offsets.dev_base_head) & ADDRESS_MASK;

        let mut seen_dev_links = HashSet::new();
        let mut current_dev = read_pointer_masked(kernel_layer, dev_head);
        while current_dev != 0 && current_dev != dev_head && !seen_dev_links.contains(&current_dev)
        {
            seen_dev_links.insert(current_dev);

            let dev_addr = current_dev.saturating_sub(dev_offsets.dev_list) & ADDRESS_MASK;
            if dev_addr != 0 {
                let ifindex = read_unsigned(
                    kernel_layer,
                    dev_addr + dev_offsets.ifindex,
                    dev_offsets.ifindex_size,
                ) as i32;
                let name = read_cstring_at(
                    kernel_layer,
                    dev_addr + dev_offsets.name,
                    dev_offsets.name_size,
                );
                if ifindex != 0 && !name.is_empty() {
                    mapping.entry(ifindex).or_insert(name);
                }
            }

            current_dev = read_pointer_masked(kernel_layer, current_dev);
        }

        current_ns = read_pointer_masked(kernel_layer, current_ns);
    }

    mapping
}

impl Default for Sockscan {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Sockscan {
    fn name(&self) -> &str {
        "linux.sockscan.Sockscan"
    }

    fn description(&self) -> &str {
        "Scans for network socket objects"
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
            Column::new("Sock Offset", ColumnType::Hex),
            Column::new("Family", ColumnType::String),
            Column::new("Type", ColumnType::String),
            Column::new("Proto", ColumnType::String),
            Column::new("Source Addr", ColumnType::String),
            Column::new("Source Port", ColumnType::String),
            Column::new("Destination Addr", ColumnType::String),
            Column::new("Destination Port", ColumnType::String),
            Column::new("State", ColumnType::String),
            Column::new("Filter", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let entries = Self::scan_sockets(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                Ok(vec![
                    CellValue::Hex(e.offset),
                    CellValue::String(e.family),
                    CellValue::String(e.sock_type),
                    CellValue::String(e.protocol),
                    CellValue::String(e.source_addr),
                    CellValue::String(e.source_port),
                    CellValue::String(e.dest_addr),
                    CellValue::String(e.dest_port),
                    CellValue::String(e.state),
                    CellValue::String(e.filter),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
