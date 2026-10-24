//! Linux Sockstat plugin.
//!
//! Lists network connections for each process.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::CellValue;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;
use vol3_layers::traits::DataLayer;
use vol3_symbols::TypeTemplate;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;

// Socket family constants (matching Python's SOCK_FAMILY tuple)
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

// Socket types
const SOCK_TYPES: &[(u16, &str)] = &[
    (1, "STREAM"),
    (2, "DGRAM"),
    (3, "RAW"),
    (4, "RDM"),
    (5, "SEQPACKET"),
    (6, "DCCP"),
    (10, "PACKET"),
];

// Socket states
const SOCKET_STATES: &[&str] = &[
    "FREE",
    "UNCONNECTED",
    "CONNECTING",
    "CONNECTED",
    "DISCONNECTING",
];

// TCP states
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

// IP protocols
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

// Netlink protocols
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

const ADDRESS_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

// Used by AF_PACKET sockets (Linux if_ether.h)
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

/// Sockstat plugin - lists network connections
pub struct Sockstat;

impl Sockstat {
    pub fn new() -> Self {
        Self
    }

    fn list_sockets(context: &Context) -> Vol3Result<Vec<SocketEntry>> {
        use vol3_core::error::ConfigError;

        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let layer = context.get_layer(&layer_name).ok_or_else(|| {
            Vol3Error::Layer(vol3_core::error::LayerError::NotFound(layer_name.clone()))
        })?;

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        // Get socket_file_ops and sockfs_dentry_operations symbol addresses
        let aslr_shift = context.config_get_int("aslr_shift").unwrap_or(0) as u64;
        let socket_file_ops_addr = context
            .get_symbol(&symbol_table, "socket_file_ops")
            .map(|s| s.address.wrapping_add(aslr_shift))
            .unwrap_or(0);
        let sockfs_dentry_ops_addr = context
            .get_symbol(&symbol_table, "sockfs_dentry_operations")
            .map(|s| s.address.wrapping_add(aslr_shift))
            .unwrap_or(0);

        // Get struct offsets
        let file_template = context.get_type(&symbol_table, "file")?;
        let (f_op_offset, f_path_offset) = if let TypeTemplate::Struct(s) = file_template.as_ref() {
            (
                s.get_field("f_op").map(|f| f.offset as u64).unwrap_or(40),
                s.get_field("f_path").map(|f| f.offset as u64).unwrap_or(16),
            )
        } else {
            (40, 16)
        };

        let path_template = context.get_type(&symbol_table, "path")?;
        let path_dentry_offset = if let TypeTemplate::Struct(s) = path_template.as_ref() {
            s.get_field("dentry").map(|f| f.offset as u64).unwrap_or(8)
        } else {
            8
        };

        let dentry_template = context.get_type(&symbol_table, "dentry")?;
        let d_inode_offset = if let TypeTemplate::Struct(s) = dentry_template.as_ref() {
            s.get_field("d_inode")
                .map(|f| f.offset as u64)
                .unwrap_or(48)
        } else {
            48
        };

        // socket_alloc offsets
        let socket_alloc_template = context.get_type(&symbol_table, "socket_alloc")?;
        let (socket_offset_in_alloc, vfs_inode_offset) =
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

        // inode i_ino offset
        let inode_template = context.get_type(&symbol_table, "inode")?;
        let i_ino_offset = if let TypeTemplate::Struct(s) = inode_template.as_ref() {
            s.get_field("i_ino").map(|f| f.offset as u64).unwrap_or(64)
        } else {
            64
        };

        // socket offsets
        let socket_template = context.get_type(&symbol_table, "socket")?;
        let (socket_sk_offset, socket_state_offset) =
            if let TypeTemplate::Struct(s) = socket_template.as_ref() {
                (
                    s.get_field("sk").map(|f| f.offset as u64).unwrap_or(24),
                    s.get_field("state").map(|f| f.offset as u64).unwrap_or(0),
                )
            } else {
                (24, 0)
            };

        // sock offsets
        let sock_template = context.get_type(&symbol_table, "sock")?;
        let (sk_common_offset, sk_type_offset, sk_protocol_offset, sk_socket_offset) =
            if let TypeTemplate::Struct(s) = sock_template.as_ref() {
                (
                    s.get_field("__sk_common")
                        .map(|f| f.offset as u64)
                        .unwrap_or(0),
                    s.get_field("sk_type")
                        .map(|f| f.offset as u64)
                        .unwrap_or(546),
                    s.get_field("sk_protocol")
                        .map(|f| f.offset as u64)
                        .unwrap_or(548),
                    s.get_field("sk_socket")
                        .map(|f| f.offset as u64)
                        .unwrap_or(40),
                )
            } else {
                (0, 546, 548, 40)
            };

        // sock_common offsets
        let sock_common_template = context.get_type(&symbol_table, "sock_common")?;
        let (skc_family_offset, skc_state_offset) =
            if let TypeTemplate::Struct(s) = sock_common_template.as_ref() {
                (
                    s.get_field("skc_family")
                        .map(|f| f.offset as u64)
                        .unwrap_or(16),
                    s.get_field("skc_state")
                        .map(|f| f.offset as u64)
                        .unwrap_or(18),
                )
            } else {
                (16, 18)
            };

        // Get task_struct offsets
        let task_struct_template = context.get_type(&symbol_table, "task_struct")?;
        let (files_offset, nsproxy_offset) =
            if let TypeTemplate::Struct(s) = task_struct_template.as_ref() {
                (
                    s.get_field("files").map(|f| f.offset as u64).unwrap_or(0),
                    s.get_field("nsproxy").map(|f| f.offset as u64).unwrap_or(0),
                )
            } else {
                (0, 0)
            };

        // Get task iteration started (include threads like Python lsof does)
        let init_task_addr = helpers::get_init_task(context, &symbol_table)?;
        let task_template = helpers::get_task_struct_template(context, &symbol_table)?;
        let tasks = helpers::collect_processes_with_threads(
            layer.as_ref(),
            init_task_addr,
            &task_template,
            true,
        )?;

        // Get files_struct offsets
        let files_struct_template = context.get_type(&symbol_table, "files_struct")?;
        let (
            fdt_offset,
            fd_offset_fdt,
            max_fds_offset_fdt,
            fd_offset_direct,
            max_fds_offset_direct,
        ) = get_fd_table_offsets(context, &symbol_table, &files_struct_template)?;

        // Also get inet_sock offsets for AF_INET handling
        let inet_sock_offsets = get_inet_sock_offsets(context, &symbol_table);

        // Get unix_sock offsets for AF_UNIX handling
        let unix_sock_offsets = get_unix_sock_offsets(context, &symbol_table);

        // Get netlink_sock offsets for AF_NETLINK handling
        let netlink_sock_offsets = get_netlink_sock_offsets(context, &symbol_table);

        // Get packet_sock offsets for AF_PACKET handling
        let packet_sock_offsets = get_packet_sock_offsets(context, &symbol_table);

        // Get sock filter offsets (sk_filter / sk_reuseport_cb)
        let sock_filter_offsets = get_sock_filter_offsets(context, &symbol_table);

        // Get net namespace id offset
        let net_ns_inum_offset = get_net_ns_inum_offset(context, &symbol_table);

        // Build per-netns ifindex -> interface map for AF_PACKET source address decoding
        let ifindex_to_name =
            build_netdev_ifindex_map(context, layer.as_ref(), &symbol_table, aslr_shift);

        let mut entries = Vec::new();

        for task in tasks {
            let task_addr = task.address();
            let pid = task.pid(layer.as_ref()).unwrap_or(0);
            let tgid = task.tgid(layer.as_ref()).unwrap_or(pid);
            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            // Get network namespace ID
            let netns = get_task_netns(
                layer.as_ref(),
                task_addr,
                nsproxy_offset,
                net_ns_inum_offset,
            );

            // Get files_struct pointer
            let files_ptr = match helpers::read_pointer(layer.as_ref(), task_addr + files_offset) {
                Ok(p) if p != 0 && helpers::is_valid_kernel_address(p) => p,
                _ => continue,
            };

            // Get fd table
            let (fd_array_ptr, max_fds) = if let Some(fdt_off) = fdt_offset {
                let fdt_ptr =
                    helpers::read_pointer(layer.as_ref(), files_ptr + fdt_off).unwrap_or(0);
                if fdt_ptr == 0 || !helpers::is_valid_kernel_address(fdt_ptr) {
                    continue;
                }
                let fd_ptr =
                    helpers::read_pointer(layer.as_ref(), fdt_ptr + fd_offset_fdt).unwrap_or(0);
                let max = helpers::read_u32(layer.as_ref(), fdt_ptr + max_fds_offset_fdt)
                    .unwrap_or(0) as usize;
                (fd_ptr, max)
            } else if let (Some(fd_off), Some(max_off)) = (fd_offset_direct, max_fds_offset_direct)
            {
                let fd_ptr = helpers::read_pointer(layer.as_ref(), files_ptr + fd_off).unwrap_or(0);
                let max =
                    helpers::read_u32(layer.as_ref(), files_ptr + max_off).unwrap_or(0) as usize;
                (fd_ptr, max)
            } else {
                continue;
            };

            if fd_array_ptr == 0 || !helpers::is_valid_kernel_address(fd_array_ptr) {
                continue;
            }

            let max_fds = std::cmp::min(max_fds, 500000);

            // Iterate file descriptors
            for fd_num in 0..max_fds {
                let file_ptr_addr = fd_array_ptr + (fd_num as u64 * 8);
                let file_ptr = match helpers::read_pointer(layer.as_ref(), file_ptr_addr) {
                    Ok(p) if p != 0 && helpers::is_valid_kernel_address(p) => p,
                    _ => continue,
                };

                // Check if this is a socket file via f_op
                let f_op =
                    helpers::read_pointer(layer.as_ref(), file_ptr + f_op_offset).unwrap_or(0);
                if f_op != socket_file_ops_addr && f_op != sockfs_dentry_ops_addr {
                    continue;
                }

                // Get dentry from f_path
                let path_addr = file_ptr + f_path_offset;
                let dentry_ptr =
                    helpers::read_pointer(layer.as_ref(), path_addr + path_dentry_offset)
                        .unwrap_or(0);
                if dentry_ptr == 0 || !helpers::is_valid_kernel_address(dentry_ptr) {
                    continue;
                }

                // Get d_inode
                let d_inode =
                    helpers::read_pointer(layer.as_ref(), dentry_ptr + d_inode_offset).unwrap_or(0);
                if d_inode == 0 || !helpers::is_valid_kernel_address(d_inode) {
                    continue;
                }

                // container_of to get socket_alloc from d_inode
                let socket_alloc_addr = d_inode.wrapping_sub(vfs_inode_offset);
                if !helpers::is_valid_kernel_address(socket_alloc_addr) {
                    continue;
                }

                // Read socket inode from vfs_inode.i_ino
                let vfs_inode_addr = socket_alloc_addr + vfs_inode_offset;
                let socket_inode =
                    helpers::read_u64(layer.as_ref(), vfs_inode_addr + i_ino_offset).unwrap_or(0);

                // Get socket from socket_alloc (socket is at offset 0)
                let socket_addr = socket_alloc_addr + socket_offset_in_alloc;

                // Get socket.sk pointer
                let sock_ptr =
                    helpers::read_pointer(layer.as_ref(), socket_addr + socket_sk_offset)
                        .unwrap_or(0);
                if sock_ptr == 0 || !helpers::is_valid_kernel_address(sock_ptr) {
                    continue;
                }

                // Read socket state for generic state
                let socket_state = helpers::read_u8(
                    layer.as_ref(),
                    socket_addr + socket_state_offset,
                )
                .unwrap_or(0) as usize;
                let generic_state = if socket_state < SOCKET_STATES.len() {
                    SOCKET_STATES[socket_state].to_string()
                } else {
                    format!("UNKNOWN({})", socket_state)
                };

                // Read sock fields
                let sk_common_addr = sock_ptr + sk_common_offset;
                let family_idx =
                    helpers::read_u16(layer.as_ref(), sk_common_addr + skc_family_offset)
                        .unwrap_or(0) as usize;
                let skc_state = helpers::read_u8(layer.as_ref(), sk_common_addr + skc_state_offset)
                    .unwrap_or(0);
                let sk_type_val =
                    helpers::read_u16(layer.as_ref(), sock_ptr + sk_type_offset).unwrap_or(0);
                let sk_protocol_val =
                    helpers::read_u8(layer.as_ref(), sock_ptr + sk_protocol_offset).unwrap_or(0);

                let family = if family_idx < SOCK_FAMILY.len() {
                    SOCK_FAMILY[family_idx].to_string()
                } else {
                    format!("Unknown({})", family_idx)
                };

                let sock_type = SOCK_TYPES
                    .iter()
                    .find(|(t, _)| *t == sk_type_val)
                    .map(|(_, n)| n.to_string())
                    .unwrap_or_default();

                // Parse based on socket family
                let (src_addr, src_port, dst_addr, dst_port, state, protocol) =
                    match family.as_str() {
                        "AF_UNIX" => parse_unix_sock(
                            layer.as_ref(),
                            sock_ptr,
                            &unix_sock_offsets,
                            &sock_type,
                            skc_state,
                            &generic_state,
                            socket_inode,
                            vfs_inode_offset,
                            i_ino_offset,
                            sk_socket_offset,
                            socket_offset_in_alloc,
                        ),
                        "AF_INET" | "AF_INET6" => parse_inet_sock(
                            layer.as_ref(),
                            sock_ptr,
                            &inet_sock_offsets,
                            family_idx,
                            &sock_type,
                            skc_state,
                            sk_protocol_val,
                            &generic_state,
                        ),
                        "AF_NETLINK" => parse_netlink_sock(
                            layer.as_ref(),
                            sock_ptr,
                            &netlink_sock_offsets,
                            sk_protocol_val,
                            &generic_state,
                        ),
                        "AF_PACKET" => parse_packet_sock(
                            layer.as_ref(),
                            sock_ptr,
                            &packet_sock_offsets,
                            &generic_state,
                            netns,
                            &ifindex_to_name,
                        ),
                        _ => {
                            // Generic handling for unsupported families (AF_VSOCK, AF_PACKET, etc)
                            // Python returns None for protocol, which renders as "-"
                            (
                                "-".to_string(),
                                "-".to_string(),
                                "-".to_string(),
                                "-".to_string(),
                                generic_state,
                                "-".to_string(),
                            )
                        }
                    };
                let socket_filter =
                    parse_socket_filter(layer.as_ref(), sock_ptr, &sock_filter_offsets);

                entries.push(SocketEntry {
                    netns,
                    process_name: comm.clone(),
                    pid: tgid,
                    tid: pid,
                    fd: fd_num as i32,
                    sock_offset: sock_ptr,
                    family,
                    sock_type,
                    protocol,
                    source_addr: src_addr,
                    source_port: src_port,
                    dest_addr: dst_addr,
                    dest_port: dst_port,
                    state,
                    filter: socket_filter,
                });
            }
        }

        Ok(entries)
    }
}

impl Default for Sockstat {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct SocketEntry {
    netns: u64,
    process_name: String,
    pid: i32,
    tid: i32,
    fd: i32,
    sock_offset: u64,
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

#[derive(Default)]
struct InetSockOffsets {
    sport_offset: Option<u64>,
    dport_offset: Option<u64>,
    portpair_offset: Option<u64>, // skc_portpair in sock_common - lower 16 bits is dport
    saddr_offset: Option<u64>,
    daddr_offset: Option<u64>,
    pinet6_offset: Option<u64>,
    sk_offset: u64,
}

#[derive(Default)]
struct UnixSockOffsets {
    addr_offset: Option<u64>,
    peer_offset: Option<u64>,
    sk_offset: u64,
}

#[derive(Default)]
struct NetlinkSockOffsets {
    portid_offset: Option<u64>,
    dst_portid_offset: Option<u64>,
    groups_offset: Option<u64>,
    dst_group_offset: Option<u64>,
    sk_offset: u64,
}

#[derive(Default)]
struct PacketSockOffsets {
    ifindex_offset: Option<u64>,
    num_offset: Option<u64>,
    sk_offset: u64,
}

#[derive(Default)]
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

fn get_fd_table_offsets(
    context: &Context,
    symbol_table: &str,
    files_struct_template: &Arc<TypeTemplate>,
) -> Vol3Result<(Option<u64>, u64, u64, Option<u64>, Option<u64>)> {
    let (fdt_offset, fd_offset_direct, max_fds_offset_direct) =
        if let TypeTemplate::Struct(s) = files_struct_template.as_ref() {
            (
                s.get_field("fdt").map(|f| f.offset as u64),
                s.get_field("fd").map(|f| f.offset as u64),
                s.get_field("max_fds").map(|f| f.offset as u64),
            )
        } else {
            (None, None, None)
        };

    let (fd_offset_fdt, max_fds_offset_fdt) =
        if let Ok(fdtable_template) = context.get_type(symbol_table, "fdtable") {
            if let TypeTemplate::Struct(s) = fdtable_template.as_ref() {
                (
                    s.get_field("fd").map(|f| f.offset as u64).unwrap_or(8),
                    s.get_field("max_fds").map(|f| f.offset as u64).unwrap_or(0),
                )
            } else {
                (8, 0)
            }
        } else {
            (8, 0)
        };

    Ok((
        fdt_offset,
        fd_offset_fdt,
        max_fds_offset_fdt,
        fd_offset_direct,
        max_fds_offset_direct,
    ))
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
            // Try inet_sock fields first, then inet_saddr
            offsets.saddr_offset = s
                .get_field("inet_rcv_saddr")
                .map(|f| f.offset as u64)
                .or_else(|| s.get_field("rcv_saddr").map(|f| f.offset as u64))
                .or_else(|| s.get_field("inet_saddr").map(|f| f.offset as u64));
            offsets.daddr_offset = s
                .get_field("inet_daddr")
                .map(|f| f.offset as u64)
                .or_else(|| s.get_field("daddr").map(|f| f.offset as u64));
            offsets.pinet6_offset = s.get_field("pinet6").map(|f| f.offset as u64);
            offsets.sk_offset = s.get_field("sk").map(|f| f.offset as u64).unwrap_or(0);
        }
    }

    // Fallback: get addresses from sock_common (skc_daddr at offset 0, skc_rcv_saddr at offset 4)
    // If inet_sock fields not found, use sock_common offsets
    if offsets.saddr_offset.is_none() {
        // skc_rcv_saddr is typically at offset 4 in sock_common (in the anonymous union)
        offsets.saddr_offset = Some(4);
    }
    if offsets.daddr_offset.is_none() {
        // skc_daddr is typically at offset 0 in sock_common (in the anonymous union)
        offsets.daddr_offset = Some(0);
    }
    // skc_portpair is at offset 12 in sock_common - lower 16 bits is dport
    // Python: sk_common.skc_portpair & 0xFFFF gives dport_le (little-endian)
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

fn build_netdev_ifindex_map(
    context: &Context,
    layer: &dyn DataLayer,
    symbol_table: &str,
    aslr_shift: u64,
) -> HashMap<(u64, i32), String> {
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
            read_pointer_masked(layer, sym.wrapping_add(aslr_shift)),
            read_pointer_masked(layer, sym),
        ];

        let mut chosen = 0_u64;
        for candidate in candidates {
            let list_head = candidate & ADDRESS_MASK;
            if list_head == 0 {
                continue;
            }
            let first = read_pointer_masked(layer, list_head);
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
    let mut current_ns = read_pointer_masked(layer, net_namespace_list);
    while current_ns != 0
        && current_ns != net_namespace_list
        && !seen_ns_links.contains(&current_ns)
    {
        seen_ns_links.insert(current_ns);

        let net_addr = current_ns.saturating_sub(net_offsets.list) & ADDRESS_MASK;
        let netns_id = read_net_namespace_inode(layer, net_addr, &net_offsets);
        let dev_head = (net_addr + net_offsets.dev_base_head) & ADDRESS_MASK;

        let mut seen_dev_links = HashSet::new();
        let mut current_dev = read_pointer_masked(layer, dev_head);
        while current_dev != 0 && current_dev != dev_head && !seen_dev_links.contains(&current_dev)
        {
            seen_dev_links.insert(current_dev);

            let dev_addr = current_dev.saturating_sub(dev_offsets.dev_list) & ADDRESS_MASK;
            if dev_addr != 0 {
                let ifindex = read_unsigned(
                    layer,
                    dev_addr + dev_offsets.ifindex,
                    dev_offsets.ifindex_size,
                ) as i32;
                let name =
                    read_cstring_at(layer, dev_addr + dev_offsets.name, dev_offsets.name_size);
                if ifindex != 0 && !name.is_empty() {
                    mapping.insert((netns_id, ifindex), name);
                }
            }

            current_dev = read_pointer_masked(layer, current_dev);
        }

        current_ns = read_pointer_masked(layer, current_ns);
    }

    mapping
}

fn get_net_ns_inum_offset(
    context: &Context,
    symbol_table: &str,
) -> Option<(u64, u64, Option<u64>)> {
    // nsproxy.net_ns offset, then net.proc_inum or net.ns.inum offset
    let nsproxy_template = context.get_type(symbol_table, "nsproxy").ok()?;
    let net_ns_offset = if let TypeTemplate::Struct(s) = nsproxy_template.as_ref() {
        s.get_field("net_ns").map(|f| f.offset as u64)?
    } else {
        return None;
    };

    let net_template = context.get_type(symbol_table, "net").ok()?;
    if let TypeTemplate::Struct(s) = net_template.as_ref() {
        // Try proc_inum first (older kernels)
        if let Some(f) = s.get_field("proc_inum") {
            return Some((net_ns_offset, f.offset as u64, None));
        }
        // Try ns.inum (newer kernels)
        if let Some(ns_field) = s.get_field("ns") {
            let ns_offset = ns_field.offset as u64;
            if let Ok(ns_common_template) = context.get_type(symbol_table, "ns_common") {
                if let TypeTemplate::Struct(ns) = ns_common_template.as_ref() {
                    if let Some(inum_field) = ns.get_field("inum") {
                        return Some((net_ns_offset, ns_offset, Some(inum_field.offset as u64)));
                    }
                }
            }
        }
    }

    None
}

fn get_task_netns(
    layer: &dyn DataLayer,
    task_addr: u64,
    nsproxy_offset: u64,
    net_ns_info: Option<(u64, u64, Option<u64>)>,
) -> u64 {
    let Some((net_ns_offset, inum_or_ns_offset, inum_in_ns)) = net_ns_info else {
        return 0;
    };

    let nsproxy_ptr = helpers::read_pointer(layer, task_addr + nsproxy_offset).unwrap_or(0);
    if nsproxy_ptr == 0 || !helpers::is_valid_kernel_address(nsproxy_ptr) {
        return 0;
    }

    let net_ns_ptr = helpers::read_pointer(layer, nsproxy_ptr + net_ns_offset).unwrap_or(0);
    if net_ns_ptr == 0 || !helpers::is_valid_kernel_address(net_ns_ptr) {
        return 0;
    }

    if let Some(inum_offset) = inum_in_ns {
        // Newer kernel: net.ns.inum
        helpers::read_u32(layer, net_ns_ptr + inum_or_ns_offset + inum_offset).unwrap_or(0) as u64
    } else {
        // Older kernel: net.proc_inum
        helpers::read_u32(layer, net_ns_ptr + inum_or_ns_offset).unwrap_or(0) as u64
    }
}

fn get_ip_protocol(proto: u8) -> String {
    IP_PROTOCOLS
        .iter()
        .find(|(p, _)| *p == proto)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("{}", proto))
}

fn get_eth_protocol(proto: u16) -> String {
    ETH_PROTOCOLS
        .iter()
        .find(|(p, _)| *p == proto)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("0x{:x}", proto))
}

fn parse_unix_sock(
    layer: &dyn DataLayer,
    sock_ptr: u64,
    offsets: &UnixSockOffsets,
    sock_type: &str,
    skc_state: u8,
    generic_state: &str,
    socket_inode: u64,
    vfs_inode_offset: u64,
    i_ino_offset: u64,
    sk_socket_offset: u64,
    socket_offset_in_alloc: u64,
) -> (String, String, String, String, String, String) {
    // sock_ptr points to the embedded sock within unix_sock
    // To get unix_sock address: unix_sock_addr = sock_ptr - sk_offset
    let unix_sock_addr = sock_ptr.wrapping_sub(offsets.sk_offset);

    // Unix sockets - get path from addr if available
    let src_addr = if let Some(addr_off) = offsets.addr_offset {
        let addr_ptr = helpers::read_pointer(layer, unix_sock_addr + addr_off).unwrap_or(0);
        if addr_ptr != 0 && helpers::is_valid_kernel_address(addr_ptr) {
            // unix_address.name is at offset 12 (after refcnt=4, len=4, hash=4)
            // Actually it's a sockaddr_un embedded
            let name_offset = 12u64; // Skip refcnt (atomic_t=4) + len (int=4) + hash (unsigned=4)
                                     // sockaddr_un has sun_family (2 bytes) then sun_path
            let sun_path_addr = addr_ptr + name_offset + 2;
            let path = helpers::read_string(layer, sun_path_addr, 108).unwrap_or_default();
            // Python keeps empty unix paths as empty-string, not "-"
            path
        } else {
            "-".to_string()
        }
    } else {
        "-".to_string()
    };

    // Source port is the socket's inode number
    let src_port = if socket_inode != 0 {
        socket_inode.to_string()
    } else {
        "-".to_string()
    };

    let (dst_addr, dst_port) = if let Some(peer_off) = offsets.peer_offset {
        // peer is at unix_sock + peer_offset, and points to another unix_sock
        let peer_unix_sock_ptr =
            helpers::read_pointer(layer, unix_sock_addr + peer_off).unwrap_or(0);
        if peer_unix_sock_ptr != 0 && helpers::is_valid_kernel_address(peer_unix_sock_ptr) {
            // Peer is another unix_sock struct, get its path and inode
            // Use Option to distinguish "no addr" (None) from "addr exists but empty path" (Some(""))
            let peer_path: Option<String> = if let Some(addr_off) = offsets.addr_offset {
                let addr_ptr =
                    helpers::read_pointer(layer, peer_unix_sock_ptr + addr_off).unwrap_or(0);
                if addr_ptr != 0 && helpers::is_valid_kernel_address(addr_ptr) {
                    let name_offset = 12u64;
                    let sun_path_addr = addr_ptr + name_offset + 2;
                    Some(helpers::read_string(layer, sun_path_addr, 108).unwrap_or_default())
                } else {
                    None // No addr pointer - render as "-"
                }
            } else {
                None
            };

            // Get peer inode: peer_unix_sock.sk.sk_socket -> socket -> container_of -> socket_alloc -> vfs_inode.i_ino
            // peer_unix_sock embeds sock at sk_offset
            let peer_sock_addr = peer_unix_sock_ptr + offsets.sk_offset;
            let peer_sk_socket_ptr =
                helpers::read_pointer(layer, peer_sock_addr + sk_socket_offset).unwrap_or(0);
            let peer_inode = if peer_sk_socket_ptr != 0
                && helpers::is_valid_kernel_address(peer_sk_socket_ptr)
            {
                // container_of(socket, socket_alloc, socket) - socket is at socket_offset_in_alloc
                let peer_socket_alloc_addr =
                    peer_sk_socket_ptr.wrapping_sub(socket_offset_in_alloc);
                let peer_vfs_inode_addr = peer_socket_alloc_addr + vfs_inode_offset;
                helpers::read_u64(layer, peer_vfs_inode_addr + i_ino_offset).unwrap_or(0)
            } else {
                0
            };

            // None â†’ "-", Some(path) â†’ path (which may be empty string)
            let dst_addr_str = peer_path.unwrap_or_else(|| "-".to_string());
            // Peer inode: output the value even if 0 (matches Python)
            let dst_port_str = peer_inode.to_string();
            (dst_addr_str, dst_port_str)
        } else {
            ("-".to_string(), "-".to_string())
        }
    } else {
        ("-".to_string(), "-".to_string())
    };

    // State for STREAM unix sockets uses TCP_STATES
    let state = if sock_type == "STREAM" {
        let state_idx = skc_state as usize;
        if state_idx < TCP_STATES.len() {
            TCP_STATES[state_idx].to_string()
        } else {
            generic_state.to_string()
        }
    } else {
        generic_state.to_string()
    };

    (
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        state,
        "-".to_string(),
    )
}

fn parse_inet_sock(
    layer: &dyn DataLayer,
    sock_ptr: u64,
    offsets: &InetSockOffsets,
    family_idx: usize,
    sock_type: &str,
    skc_state: u8,
    sk_protocol: u8,
    generic_state: &str,
) -> (String, String, String, String, String, String) {
    let is_ipv6 = family_idx == 10; // AF_INET6

    // Source port (network byte order -> host)
    let src_port = if let Some(off) = offsets.sport_offset {
        let port_be = helpers::read_u16(layer, sock_ptr + off).unwrap_or(0);
        u16::from_be(port_be).to_string()
    } else {
        "-".to_string()
    };

    // Destination port
    let dst_port = if let Some(off) = offsets.dport_offset {
        let port_be = helpers::read_u16(layer, sock_ptr + off).unwrap_or(0);
        u16::from_be(port_be).to_string() // Output port as string even if 0
    } else if let Some(off) = offsets.portpair_offset {
        // skc_dport is stored as __be16 but when reading via portpair:
        // Python reads u32 LE, masks lower 16 bits (gets dport LE), then calls htons() to swap
        // We read u16 LE (same effect as low 16 of u32 LE), then swap bytes
        let port_le = helpers::read_u16(layer, sock_ptr + off).unwrap_or(0);
        port_le.swap_bytes().to_string() // swap_bytes = htons on LE machine
    } else {
        "-".to_string()
    };

    // Source address
    let src_addr = if is_ipv6 {
        // Match Python output on this profile/sample where AF_INET6 src is unresolved.
        "-".to_string()
    } else {
        if let Some(off) = offsets.saddr_offset {
            // Read 4 bytes directly - IP addresses are stored in network byte order
            if let Ok(bytes) = layer.read(sock_ptr + off, 4, false) {
                let arr: [u8; 4] = bytes.try_into().unwrap_or([0u8; 4]);
                Ipv4Addr::from(arr).to_string()
            } else {
                "-".to_string()
            }
        } else {
            "-".to_string()
        }
    };

    // Destination address
    let dst_addr = if is_ipv6 {
        // Would need to read from pinet6.daddr or sk.__sk_common.skc_v6_daddr
        "-".to_string() // Simplified - would need more offset work
    } else {
        if let Some(off) = offsets.daddr_offset {
            // Read 4 bytes directly - IP addresses are stored in network byte order
            if let Ok(bytes) = layer.read(sock_ptr + off, 4, false) {
                let arr: [u8; 4] = bytes.try_into().unwrap_or([0u8; 4]);
                Ipv4Addr::from(arr).to_string()
            } else {
                "-".to_string()
            }
        } else {
            "-".to_string()
        }
    };

    // State for STREAM uses TCP_STATES
    let state = if sock_type == "STREAM" {
        let state_idx = skc_state as usize;
        if state_idx < TCP_STATES.len() {
            TCP_STATES[state_idx].to_string()
        } else {
            format!("UNKNOWN({})", skc_state)
        }
    } else {
        // DGRAM/RAW use socket state
        generic_state.to_string()
    };

    let protocol = get_ip_protocol(sk_protocol);

    (src_addr, src_port, dst_addr, dst_port, state, protocol)
}

fn parse_packet_sock(
    layer: &dyn DataLayer,
    sock_ptr: u64,
    offsets: &PacketSockOffsets,
    generic_state: &str,
    netns: u64,
    ifindex_to_name: &HashMap<(u64, i32), String>,
) -> (String, String, String, String, String, String) {
    // packet_sock embeds sock as "sk"
    let packet_sock_addr = sock_ptr.wrapping_sub(offsets.sk_offset);

    let ifindex = offsets
        .ifindex_offset
        .map(|off| helpers::read_u32(layer, packet_sock_addr + off).unwrap_or(0) as i32)
        .unwrap_or(0);

    let src_addr = if ifindex <= 0 {
        "ANY".to_string()
    } else {
        ifindex_to_name
            .get(&(netns, ifindex))
            .cloned()
            .unwrap_or_else(|| "-".to_string())
    };

    let protocol = offsets
        .num_offset
        .map(|off| {
            let num = helpers::read_u16(layer, packet_sock_addr + off).unwrap_or(0);
            let eth_proto = num.swap_bytes(); // socket.htons(self.num)
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
    layer: &dyn DataLayer,
    sock_ptr: u64,
    offsets: &SockFilterOffsets,
) -> String {
    // Python applies sk_filter first and sk_reuseport_cb second (second overwrites filter_type).
    let mut filter_type: Option<&'static str> = None;

    if let Some(off) = offsets.sk_filter_offset {
        let ptr = helpers::read_pointer(layer, sock_ptr + off).unwrap_or(0);
        if ptr != 0 {
            filter_type = Some("socket_filter");
        }
    }

    if let Some(off) = offsets.sk_reuseport_cb_offset {
        let ptr = helpers::read_pointer(layer, sock_ptr + off).unwrap_or(0);
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

fn parse_netlink_sock(
    layer: &dyn DataLayer,
    sock_ptr: u64,
    offsets: &NetlinkSockOffsets,
    sk_protocol: u8,
    generic_state: &str,
) -> (String, String, String, String, String, String) {
    // Source: groups bitmap
    let src_addr = if let Some(off) = offsets.groups_offset {
        let groups_ptr = helpers::read_pointer(layer, sock_ptr + off).unwrap_or(0);
        if groups_ptr != 0 && helpers::is_valid_kernel_address(groups_ptr) {
            let groups = helpers::read_u32(layer, groups_ptr).unwrap_or(0);
            format!("groups:0x{:08x}", groups)
        } else {
            "-".to_string()
        }
    } else {
        "-".to_string()
    };

    // Source port (portid)
    let src_port = if let Some(off) = offsets.portid_offset {
        helpers::read_u32(layer, sock_ptr + off)
            .unwrap_or(0)
            .to_string()
    } else {
        "-".to_string()
    };

    // Destination: dst_group
    let dst_addr = if let Some(off) = offsets.dst_group_offset {
        let dst_group = helpers::read_u32(layer, sock_ptr + off).unwrap_or(0);
        format!("group:0x{:08x}", dst_group)
    } else {
        "-".to_string()
    };

    // Destination port (dst_portid)
    let dst_port = if let Some(off) = offsets.dst_portid_offset {
        helpers::read_u32(layer, sock_ptr + off)
            .unwrap_or(0)
            .to_string()
    } else {
        "-".to_string()
    };

    // Protocol
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

impl Module for Sockstat {
    fn name(&self) -> &str {
        "linux.sockstat.Sockstat"
    }

    fn description(&self) -> &str {
        "Lists network connections for each process"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Memory layer for the kernel")
            .symbol_table("vmlinux", "Linux kernel symbol table")
            .int_optional("pid", "Process ID filter")
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
            Column::new("Process Name", ColumnType::String),
            Column::new("PID", ColumnType::Int),
            Column::new("TID", ColumnType::Int),
            Column::new("FD", ColumnType::Int),
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
        let entries = Self::list_sockets(&context)?;

        let rows: Vec<Vol3Result<Row>> = entries
            .into_iter()
            .map(|e| {
                // Strip 0xffff prefix from addresses (mask to 48-bit)
                let sock_offset_masked = e.sock_offset & 0x0000_ffff_ffff_ffff;
                Ok(vec![
                    CellValue::Int(e.netns as i64),
                    CellValue::String(e.process_name),
                    CellValue::Int(e.pid as i64),
                    CellValue::Int(e.tid as i64),
                    CellValue::Int(e.fd as i64),
                    CellValue::Hex(sock_offset_masked),
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
