//! # Mermin eBPF Packet Parser
//!
//! High-performance network packet parser implemented as a Linux eBPF TC (Traffic Control) classifier.
//! Extracts flow metadata from network packets for observability and analysis purposes.
//!
//! ## Overview
//!
//! This eBPF program attaches to network interfaces and parses packets at line rate, extracting
//! rich metadata including:
//! - Layer 2: MAC addresses, EtherType
//! - Layer 3: IPv4/IPv6 addresses, DSCP, ECN, TTL/Hop Limit, Flow Label
//! - Layer 4: TCP/UDP ports, TCP flags, ICMP type/code
//! - Tunneling: VXLAN, Geneve, GRE, IP-in-IP encapsulation details
//! - Security: IPsec (AH/ESP) SPIs, WireGuard tunnel identification
//!
//! ## Architecture
//!
//! The parser uses a state machine approach with a bounded loop (max 8 iterations) to handle
//! nested protocol headers. Parsed metadata is stored in per-CPU maps to avoid lock contention,
//! then published to a ring buffer for userspace consumption.
//!
//! **Entry Points:**
//! - `mermin_ingress`: Processes ingress traffic
//! - `mermin_egress`: Processes egress traffic
//!
//! **Data Structures:**
//! - `PACKETS_META`: Ring buffer (256 KB) for publishing parsed metadata to userspace
//! - `PACKET_META`: Per-CPU array holding the current packet's metadata during parsing
//! - `PARSER_OPTIONS`: Per-CPU array for runtime configuration (tunnel ports)
//!
//! ## Parsing Policies
//!
//! ### Flow Attributes (Innermost Wins)
//!
//! For determining the actual application flow, the parser prioritizes the **innermost** headers:
//! - IP addresses, ports, protocol, DSCP, ECN, TTL come from the innermost IP/transport headers
//! - This ensures tunnel encapsulation doesn't obscure the actual flow being observed
//!
//! ### Tunnel Attributes (Outermost Wins)
//!
//! For tunnel metadata, the parser captures the **outermost** tunnel information:
//! - Tunnel type (VXLAN/Geneve/GRE), VNI/Key, outer IPs/ports
//! - When multiple tunnels are nested, only the first (outermost) tunnel is recorded
//!
//! ### IP-in-IP Encapsulation
//!
//! The parser distinguishes between tunnel encapsulation and IP-in-IP:
//! - IP-in-IP (IPv4-in-IPv4, IPv6-in-IPv6, etc.) is tracked separately via `ipip_*` fields
//! - The outermost IP-in-IP header's addresses are captured
//!
//! ## Supported Protocols
//!
//! ### Layer 2
//!
//! - Ethernet (802.3)
//!
//! ### Layer 3
//!
//! - IPv4 (with options)
//! - IPv6 (with extension headers)
//!
//! ### Layer 4
//!
//! - TCP
//! - UDP
//! - ICMP / ICMPv6
//!
//! ### IPv6 Extension Headers
//!
//! - Hop-by-Hop Options
//! - Destination Options
//! - Routing Headers (Type 2, RPL Source Route, Segment Routing, CRH-16, CRH-32)
//! - Fragment Header
//! - Authentication Header (AH)
//! - Encapsulating Security Payload (ESP)
//! - Mobility Header
//! - Host Identity Protocol (HIP)
//! - Shim6
//!
//! ### Tunneling Protocols
//!
//! - VXLAN (port 4789, configurable)
//! - Geneve (port 6081, configurable)
//! - GRE (with optional routing/key/sequence/checksum fields)
//! - IP-in-IP (IPv4-in-IPv4, IPv6-in-IPv6, IPv4-in-IPv6, IPv6-in-IPv4)
//!
//! ### VPN/Security
//!
//! - IPsec AH (Authentication Header)
//! - IPsec ESP (Encapsulating Security Payload) - header only, payload is encrypted
//! - WireGuard (port 51820, configurable) - all message types
//!
//! ## eBPF Constraints
//!
//! This program is designed to pass the eBPF verifier with the following considerations:
//! - **Stack limit**: ~512 bytes - uses per-CPU maps instead of large stack variables
//! - **Bounded loops**: Maximum 8 header parsing iterations
//! - **Bounded header lengths**: Variable-length headers validated with reasonable limits
//! - **No unbounded recursion**: Iterative parsing only
//! - **Verifier-friendly patterns**: All memory accesses bounds-checked before use
//!
//! ## Example Packet Flow
//!
//! For a complex encapsulated packet:
//! ```text
//! Ethernet -> IPv6 -> IPv4 -> AH -> UDP -> VXLAN -> Ethernet -> IPv4 -> IPv6 -> AH -> TCP
//! ```
//! meta.src_mac_addr = 0 -> 1_ETH:SRC_MAC_ADDR -> 0 -> 2_ETH:SRC_MAC_ADDR;
//! meta.ether_type = Reserved -> 1_ETH:ETHER_TYPE_IPV6 -> 0 -> 1_<VXLAN/GRE/GENEVE>:ETHER_TYPE_ETHERNET -> 2_ETH:ETHER_TYPE_IPV4;
//! meta.proto = Reserved -> 1_IPV6:IP_PROTO_IPV4 -> 1_IPV4:IP_PROTO_AH -> 1_AH:IP_PROTO_UDP -> Reserved -> 2_IPV4:IP_PROTO_IPV6 -> 2_IPV6:IP_PROTO_AH -> 2_AH:IP_PROTO_TCP;
//! meta.ip_addr_type = Unknown -> 1_IPV4:IP_ADDR_TYPE_IPV4 -> Unknown -> 2_IPV6:IP_ADDR_TYPE_IPV6;
//! meta.src_ipv6_addr = 0 -> 2_IPV6:SRC_IPV6_ADDR;
//! meta.dst_ipv6_addr = 0 -> 2_IPV6:DST_IPV6_ADDR;
//! meta.src_ipv4_addr = 0 -> 1_IPV4:SRC_IPV4_ADDR -> 0;
//! meta.dst_ipv4_addr = 0 -> 1_IPV4:DST_IPV4_ADDR -> 0;
//! meta.l3_octet_count = 0 -> 1_IPV4:L3_OCTET_COUNT -> 0 -> 2_IPV6:L3_OCTET_COUNT;
//! meta.src_port = 0 -> 1_UDP:SRC_PORT -> 0 -> 2_TCP:SRC_PORT;
//! meta.dst_port = 0 -> 1_UDP:DST_PORT -> 0 -> 2_TCP:DST_PORT;
//! meta.ip_dscp_id = 0 -> 1_IPV4:DSCP_ID -> 0 -> 2_IPV6:DSCP_ID;
//! meta.ip_ecn_id = 0 -> 1_IPV41:ECN_ID -> 0 -> 2_IPV6:ECN_ID;
//! meta.ip_ttl = 0 -> 1_IPV4:TTL -> 0 -> 2_IPV6:TTL;
//! meta.ip_flow_label = 0 -> 2_IPV6:FLOW_LABEL;
//! meta.tcp_flags = 0 -> 1_TCP:FLAGS;
//! meta.ipsec_ah_spi = 0 -> 1_AH:SPI -> 0 -> 2_AH:SPI;
//! meta.ipsec_esp_spi = 0;
//! meta.ipsec_sender_index = 0;
//! meta.ipsec_receiver_index = 0;
//! meta.ah_exists = false -> 1_AH:TRUE -> false -> 2_AH:TRUE;
//! meta.esp_exists = false;
//! meta.wireguard_exists = false;
//!
//! meta.ipip_ether_type = Reserved -> 1_IPV6:ETHER_TYPE_IPV6;
//! meta.ipip_proto = Reserved -> 1_IPV6:IP_PROTO_IPV4;
//! meta.ipip_ip_addr_type = Unknown -> 1_IPV6:IP_ADDR_TYPE_IPV6;
//! meta.ipip_src_ipv6_addr = 0 -> 1_IPV6:SRC_IPV6_ADDR;
//! meta.ipip_dst_ipv6_addr = 0 -> 1_IPV6:DST_IPV6_ADDR;
//! meta.ipip_src_ipv4_addr = 0;
//! meta.ipip_dst_ipv4_addr = 0;
//!
//! meta.tunnel_type = None -> 1_<VXLAN/GRE/GENEVE>:TYPE;
//! meta.tunnel_src_mac_addr = 0 -> SRC_MAC_ADDR(FROM:1_ETH);
//! meta.tunnel_ether_type = Reserved -> ETHER_TYPE_IPV6(FROM:1_ETH);
//! meta.tunnel_proto = Reserved -> IP_PROTO_UDP(FROM:1_AH);
//! meta.tunnel_ip_addr_type = Unknown -> IP_ADDR_TYPE_IPV4(FROM:1_IPV4);
//! meta.tunnel_src_ipv6_addr = 0;
//! meta.tunnel_dst_ipv6_addr = 0;
//! meta.tunnel_src_ipv4_addr = 0 -> SRC_IPV4_ADDR(FROM:1_IPV4);
//! meta.tunnel_dst_ipv4_addr = 0 -> DST_IPV4_ADDR(FROM:1_IPV4);
//! meta.tunnel_src_port = 0 -> SRC_PORT(FROM:1_UDP);
//! meta.tunnel_dst_port = 0 -> DST_PORT(FROM:1_UDP);
//! meta.tunnel_id = 0 -> 1_<VXLAN/GRE/GENEVE>:VNI;
//! meta.tunnel_ah_exists = false -> TRUE(FROM:1_AH);
//! meta.tunnel_ipsec_ah_spi = 0 -> SPI(FROM:1_AH);
//! ```
//!
//! ## Performance
//!
//! The parser is optimized for minimal overhead:
//! - Single-pass parsing with no backtracking
//! - Lock-free per-CPU data structures
//! - Bounded complexity (O(1) per packet with fixed iteration limit)
//! - Early termination on encrypted payloads (ESP) or unsupported protocols
//!
//! ## Error Handling
//!
//! Parsing errors (malformed headers, out-of-bounds access) cause the packet to be passed
//! through unmodified (`TC_ACT_PIPE`). This ensures the system remains resilient and doesn't
//! drop packets due to parsing issues.

#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

#[cfg(not(feature = "test"))]
use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{PerCpuArray, RingBuf},
    programs::TcContext,
};
#[cfg(not(feature = "test"))]
use aya_log_ebpf::error;
use mermin_common::{Direction, IpAddrType, PacketMeta, TunnelType};
use network_types::{
    ah::{self, AH_LEN},
    destopts::{self},
    esp::{self, ESP_LEN},
    eth::{ETH_LEN, EtherType},
    fragment::FRAGMENT_LEN,
    geneve::{self, GENEVE_LEN},
    gre::{self, GRE_LEN, GRE_ROUTING_LEN},
    hip::{self, HIP_LEN},
    hop::{self, HOP_OPT_LEN},
    icmp::ICMP_LEN,
    ip::{
        IpProto,
        ipv4::{self, IPV4_LEN},
        ipv6::{self, IPV6_LEN},
    },
    mobility::{self, MOBILITY_LEN},
    route::{self, GENERIC_ROUTE_LEN},
    shim6::{self, SHIM6_LEN},
    tcp::TCP_LEN,
    udp::UDP_LEN,
    vxlan::{self, VXLAN_LEN},
    wireguard::{
        self, WIREGUARD_COOKIE_REPLY_LEN, WIREGUARD_INITIATION_LEN, WIREGUARD_RESPONSE_LEN,
        WIREGUARD_TRANSPORT_DATA_LEN, WireGuardType,
    },
};

// todo: verify buffer size
#[cfg(not(feature = "test"))]
#[map]
static mut PACKETS_META: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

#[cfg(not(feature = "test"))]
#[map]
static mut PACKET_META: PerCpuArray<PacketMeta> = PerCpuArray::with_max_entries(1, 0);

#[cfg(not(feature = "test"))]
#[inline(always)]
#[allow(clippy::mut_from_ref)]
fn get_packet_meta(ctx: &TcContext) -> Result<&mut PacketMeta, Error> {
    // Get PacketMeta from PerCpuArray instead of using local variables
    let meta_ptr = unsafe {
        #[allow(static_mut_refs)]
        match PACKET_META.get_ptr_mut(0) {
            Some(ptr) => ptr,
            None => {
                error!(ctx, "PACKET_META map not accessible");
                return Err(Error::InternalError);
            }
        }
    };
    Ok(unsafe { &mut *meta_ptr })
}

#[cfg(not(feature = "test"))]
#[map]
static mut PARSER_OPTIONS: PerCpuArray<ParserOptions> = PerCpuArray::with_max_entries(1, 0);

#[cfg(not(feature = "test"))]
#[inline(always)]
#[allow(clippy::mut_from_ref)]
fn get_parser_options(ctx: &TcContext) -> Result<&mut ParserOptions, Error> {
    // Get ParserOptions from PerCpuArray instead of using local variables
    let options_ptr = unsafe {
        #[allow(static_mut_refs)]
        match PARSER_OPTIONS.get_ptr_mut(0) {
            Some(ptr) => ptr,
            None => {
                error!(ctx, "PARSER_OPTIONS map not accessible");
                return Err(Error::InternalError);
            }
        }
    };
    Ok(unsafe { &mut *options_ptr })
}

// Defines what kind of header we expect to process in the current iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderType {
    Ethernet,
    Ipv4,
    Ipv6,
    Geneve,
    Vxlan,
    Wireguard,
    Proto(IpProto),
    StopProcessing, // Indicates parsing should terminate for flow key purposes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    OutOfBounds,
    MalformedHeader,
    Unsupported,
    InternalError,
}

#[cfg(not(feature = "test"))]
#[classifier]
pub fn mermin_ingress(ctx: TcContext) -> i32 {
    try_mermin(ctx, Direction::Ingress)
}

#[cfg(not(feature = "test"))]
#[classifier]
pub fn mermin_egress(ctx: TcContext) -> i32 {
    try_mermin(ctx, Direction::Egress)
}

#[cfg(not(feature = "test"))]
fn try_mermin(ctx: TcContext, direction: Direction) -> i32 {
    const MAX_HEADER_PARSE_DEPTH: usize = 8;

    // Information for building flow records (prioritizes innermost headers).
    // These fields will be updated as we parse deeper or encounter encapsulations.
    let mut parser = Parser::default();

    let meta = match get_packet_meta(&ctx) {
        Ok(m) => m,
        Err(_) => return TC_ACT_PIPE,
    };

    // Initialize the meta with default values
    meta.ifindex = unsafe { (*ctx.skb.skb).ifindex };
    meta.direction = direction;
    meta.src_mac_addr = [0; 6];
    meta.ether_type = EtherType::default();
    meta.proto = IpProto::default();
    meta.ip_addr_type = IpAddrType::default();
    meta.src_ipv6_addr = [0; 16];
    meta.dst_ipv6_addr = [0; 16];
    meta.src_ipv4_addr = [0; 4];
    meta.dst_ipv4_addr = [0; 4];
    meta.l3_octet_count = 0;
    meta.src_port = [0; 2];
    meta.dst_port = [0; 2];
    meta.ip_dscp_id = 0;
    meta.ip_ecn_id = 0;
    meta.ip_ttl = 0;
    meta.ip_flow_label = 0;
    meta.icmp_type_id = 0;
    meta.icmp_code_id = 0;
    meta.tcp_flags = 0;
    meta.ipsec_ah_spi = 0;
    meta.ipsec_esp_spi = 0;
    meta.ipsec_sender_index = 0;
    meta.ipsec_receiver_index = 0;
    meta.ah_exists = false;
    meta.esp_exists = false;
    meta.wireguard_exists = false;

    meta.ipip_ether_type = EtherType::default();
    meta.ipip_proto = IpProto::default();
    meta.ipip_ip_addr_type = IpAddrType::default();
    meta.ipip_src_ipv6_addr = [0; 16];
    meta.ipip_dst_ipv6_addr = [0; 16];
    meta.ipip_src_ipv4_addr = [0; 4];
    meta.ipip_dst_ipv4_addr = [0; 4];

    meta.tunnel_type = TunnelType::None;
    meta.tunnel_src_mac_addr = [0; 6];
    meta.tunnel_ether_type = EtherType::default();
    meta.tunnel_proto = IpProto::default();
    meta.tunnel_ip_addr_type = IpAddrType::default();
    meta.tunnel_src_ipv6_addr = [0; 16];
    meta.tunnel_dst_ipv6_addr = [0; 16];
    meta.tunnel_src_ipv4_addr = [0; 4];
    meta.tunnel_dst_ipv4_addr = [0; 4];
    meta.tunnel_src_port = [0; 2];
    meta.tunnel_dst_port = [0; 2];
    meta.tunnel_id = 0;
    meta.tunnel_ipsec_ah_spi = 0;

    for _ in 0..MAX_HEADER_PARSE_DEPTH {
        let result: Result<(), Error> = match parser.next_hdr {
            HeaderType::Ethernet => parser.parse_ethernet_header(&ctx),
            HeaderType::Ipv4 => parser.parse_ipv4_header(&ctx),
            HeaderType::Ipv6 => parser.parse_ipv6_header(&ctx),
            HeaderType::Geneve => parser.parse_geneve_header(&ctx),
            HeaderType::Vxlan => parser.parse_vxlan_header(&ctx),
            HeaderType::Wireguard => parser.parse_wireguard_header(&ctx),
            HeaderType::Proto(IpProto::HopOpt) => parser.parse_hopopt_header(&ctx),
            HeaderType::Proto(IpProto::Gre) => parser.parse_gre_header(&ctx),
            HeaderType::Proto(IpProto::Icmp) => parser.parse_icmp_header(&ctx),
            HeaderType::Proto(IpProto::Ipv6Icmp) => parser.parse_icmp_header(&ctx),
            HeaderType::Proto(IpProto::Ipv4) => parser.parse_ipv4_encap(&ctx),
            HeaderType::Proto(IpProto::Ipv6) => parser.parse_ipv6_encap(&ctx),
            HeaderType::Proto(IpProto::Tcp) => parser.parse_tcp_header(&ctx),
            HeaderType::Proto(IpProto::Udp) => parser.parse_udp_header(&ctx),
            HeaderType::Proto(IpProto::Ipv6Route) => parser.parse_generic_route_header(&ctx),
            HeaderType::Proto(IpProto::Ipv6Frag) => parser.parse_fragment_header(&ctx),
            HeaderType::Proto(IpProto::Esp) => parser.parse_esp_header(&ctx),
            HeaderType::Proto(IpProto::Ah) => parser.parse_ah_header(&ctx),
            HeaderType::Proto(IpProto::Ipv6Opts) => parser.parse_destopts_header(&ctx),
            HeaderType::Proto(IpProto::MobilityHeader) => parser.parse_mobility_header(&ctx),
            HeaderType::Proto(IpProto::Hip) => parser.parse_hip_header(&ctx),
            HeaderType::Proto(IpProto::Shim6) => parser.parse_shim6_header(&ctx),
            HeaderType::Proto(_) => {
                break;
            }
            HeaderType::StopProcessing => break, // Graceful stop
        };

        if result.is_err() {
            error!(&ctx, "mermin: parser failed");
            return TC_ACT_PIPE;
        }
    }

    unsafe {
        #[allow(static_mut_refs)]
        if PACKETS_META.output(meta, 0).is_err() {
            error!(&ctx, "mermin: failed to write packet to ring buffer");
        }
    }

    TC_ACT_PIPE
}

struct Parser {
    // The header-type to parse next at 'offset'
    next_hdr: HeaderType,
    // Current read offset from the start of the packet
    offset: usize,
}

impl Parser {
    fn default() -> Self {
        Parser {
            next_hdr: HeaderType::Ethernet,
            offset: 0,
        }
    }

    // Calculate the L3 octet count (from current offset to end of packet)
    // This should be called at the start of L3 (IP) header parsing
    #[inline(always)]
    fn calc_l3_octet_count(&self, packet_len: u32) -> u32 {
        packet_len - self.offset as u32
    }

    /// Parses the next header in the packet and updates the parser state accordingly.
    /// Returns an error if the header is not supported.
    fn parse_ethernet_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + ETH_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.src_mac_addr = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        meta.ether_type = ctx.load(self.offset + 12).map_err(|_| Error::OutOfBounds)?;

        self.offset += ETH_LEN;
        self.next_hdr = match meta.ether_type {
            EtherType::Ipv4 => HeaderType::Ipv4,
            EtherType::Ipv6 => HeaderType::Ipv6,
            _ => return Err(Error::Unsupported),
        };

        Ok(())
    }

    /// Parses the IPv4 header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_ipv4_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + IPV4_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let h_len = ipv4::ihl(
            ctx.load::<ipv4::Vihl>(self.offset)
                .map_err(|_| Error::OutOfBounds)?,
        ) as usize;
        if h_len < IPV4_LEN {
            return Err(Error::MalformedHeader);
        }

        let meta = get_packet_meta(ctx)?;
        meta.proto = ctx.load(self.offset + 9).map_err(|_| Error::OutOfBounds)?;

        // Check if this is an encapsulated packet - outermost IP header determines the ipip values
        let ipip_exists = meta.ipip_ip_addr_type != IpAddrType::default();
        if meta.proto == IpProto::Ipv4 || meta.proto == IpProto::Ipv6 {
            if !ipip_exists {
                meta.ipip_ether_type = EtherType::Ipv4;
                meta.ipip_proto = meta.proto;
                meta.ipip_ip_addr_type = IpAddrType::Ipv4;
                meta.ipip_src_ipv4_addr =
                    ctx.load(self.offset + 12).map_err(|_| Error::OutOfBounds)?;
                meta.ipip_dst_ipv4_addr =
                    ctx.load(self.offset + 16).map_err(|_| Error::OutOfBounds)?;
            }

            // ipip attributes are set (or already existed), skip to the next header
            self.offset += h_len;
            self.next_hdr = HeaderType::Proto(meta.proto);
            return Ok(());
        }

        // policy: innermost IP header determines the flow span IPs
        meta.ip_addr_type = IpAddrType::Ipv4;
        let dscp_ecn: ipv4::DscpEcn = ctx.load(self.offset + 1).map_err(|_| Error::OutOfBounds)?;
        meta.ip_dscp_id = ipv4::dscp(dscp_ecn);
        meta.ip_ecn_id = ipv4::ecn(dscp_ecn);
        meta.ip_ttl = ctx.load(self.offset + 8).map_err(|_| Error::OutOfBounds)?;
        meta.src_ipv4_addr = ctx.load(self.offset + 12).map_err(|_| Error::OutOfBounds)?;
        meta.dst_ipv4_addr = ctx.load(self.offset + 16).map_err(|_| Error::OutOfBounds)?;
        meta.l3_octet_count = self.calc_l3_octet_count(ctx.len());

        self.offset += h_len;
        self.next_hdr = match meta.proto {
            IpProto::Icmp
            | IpProto::Tcp
            | IpProto::Udp
            | IpProto::Gre
            | IpProto::Esp
            | IpProto::Ah
            | IpProto::Hip => HeaderType::Proto(meta.proto),
            _ => HeaderType::StopProcessing,
        };

        Ok(())
    }

    /// Parses the IPv4 header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_ipv4_encap(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + IPV4_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let h_len = ipv4::ihl(
            ctx.load::<ipv4::Vihl>(self.offset)
                .map_err(|_| Error::OutOfBounds)?,
        ) as usize;
        if h_len < IPV4_LEN {
            return Err(Error::MalformedHeader);
        }

        // policy: innermost IP header determines the flow span IPs
        let meta = get_packet_meta(ctx)?;
        meta.ip_addr_type = IpAddrType::Ipv4;
        meta.proto = ctx.load(self.offset + 9).map_err(|_| Error::OutOfBounds)?;
        let dscp_ecn: ipv4::DscpEcn = ctx.load(self.offset + 1).map_err(|_| Error::OutOfBounds)?;
        meta.ip_dscp_id = ipv4::dscp(dscp_ecn);
        meta.ip_ecn_id = ipv4::ecn(dscp_ecn);
        meta.ip_ttl = ctx.load(self.offset + 8).map_err(|_| Error::OutOfBounds)?;
        meta.src_ipv4_addr = ctx.load(self.offset + 12).map_err(|_| Error::OutOfBounds)?;
        meta.dst_ipv4_addr = ctx.load(self.offset + 16).map_err(|_| Error::OutOfBounds)?;
        meta.l3_octet_count = self.calc_l3_octet_count(ctx.len());

        self.offset += h_len;
        self.next_hdr = match meta.proto {
            IpProto::Icmp
            | IpProto::Tcp
            | IpProto::Udp
            | IpProto::Gre
            | IpProto::Esp
            | IpProto::Ah
            | IpProto::Hip => HeaderType::Proto(meta.proto),
            _ => HeaderType::StopProcessing,
        };

        Ok(())
    }

    /// Parses the IPv6 header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    /// This is used for parsing an IPv6 header that comes after an Ethernet header.
    fn parse_ipv6_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + IPV6_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.proto = ctx.load(self.offset + 6).map_err(|_| Error::OutOfBounds)?;

        // Check if this is an encapsulated packet - outermost IP header determines the ipip values
        let ipip_exists = meta.ipip_ip_addr_type != IpAddrType::default();
        if meta.proto == IpProto::Ipv4 || meta.proto == IpProto::Ipv6 {
            if !ipip_exists {
                meta.ipip_ether_type = EtherType::Ipv6;
                meta.ipip_proto = meta.proto;
                meta.ipip_ip_addr_type = IpAddrType::Ipv6;
                meta.ipip_src_ipv6_addr =
                    ctx.load(self.offset + 8).map_err(|_| Error::OutOfBounds)?;
                meta.ipip_dst_ipv6_addr =
                    ctx.load(self.offset + 24).map_err(|_| Error::OutOfBounds)?;
            }

            // ipip attributes are set (or already existed), skip to the next header
            self.offset += IPV6_LEN;
            self.next_hdr = HeaderType::Proto(meta.proto);
            return Ok(());
        }

        // policy: innermost IP header determines the flow span IPs
        meta.ip_addr_type = IpAddrType::Ipv6;
        let vcf: ipv6::Vcf = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        meta.ip_dscp_id = ipv6::dscp(vcf);
        meta.ip_ecn_id = ipv6::ecn(vcf);
        meta.ip_flow_label = ipv6::flow_label(vcf);
        meta.ip_ttl = ctx.load(self.offset + 7).map_err(|_| Error::OutOfBounds)?;
        meta.src_ipv6_addr = ctx.load(self.offset + 8).map_err(|_| Error::OutOfBounds)?;
        meta.dst_ipv6_addr = ctx.load(self.offset + 24).map_err(|_| Error::OutOfBounds)?;
        meta.l3_octet_count = self.calc_l3_octet_count(ctx.len());

        self.offset += IPV6_LEN;
        self.next_hdr = match meta.proto {
            IpProto::Tcp
            | IpProto::Udp
            | IpProto::Ipv6Icmp
            | IpProto::Esp
            | IpProto::Ah
            | IpProto::HopOpt
            | IpProto::Ipv6Route
            | IpProto::Ipv6Frag
            | IpProto::Ipv6Opts
            | IpProto::MobilityHeader
            | IpProto::Hip
            | IpProto::Shim6 => HeaderType::Proto(meta.proto),
            _ => HeaderType::StopProcessing,
        };

        Ok(())
    }

    /// Parses the IPv6 header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    /// This is used for parsing an IPv6 header that comes after an IP header.
    fn parse_ipv6_encap(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + IPV6_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta: &mut PacketMeta = get_packet_meta(ctx)?;

        // policy: innermost IP header determines the flow span IPs
        meta.ip_addr_type = IpAddrType::Ipv6;
        let vcf: ipv6::Vcf = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        meta.ip_dscp_id = ipv6::dscp(vcf);
        meta.ip_ecn_id = ipv6::ecn(vcf);
        meta.ip_flow_label = ipv6::flow_label(vcf);
        meta.proto = ctx.load(self.offset + 6).map_err(|_| Error::OutOfBounds)?;
        meta.ip_ttl = ctx.load(self.offset + 7).map_err(|_| Error::OutOfBounds)?;
        meta.src_ipv6_addr = ctx.load(self.offset + 8).map_err(|_| Error::OutOfBounds)?;
        meta.dst_ipv6_addr = ctx.load(self.offset + 24).map_err(|_| Error::OutOfBounds)?;
        meta.l3_octet_count = self.calc_l3_octet_count(ctx.len());

        self.offset += IPV6_LEN;
        self.next_hdr = match meta.proto {
            IpProto::Tcp
            | IpProto::Udp
            | IpProto::Ipv6Icmp
            | IpProto::Esp
            | IpProto::Ah
            | IpProto::HopOpt
            | IpProto::Ipv6Route
            | IpProto::Ipv6Frag
            | IpProto::Ipv6Opts
            | IpProto::MobilityHeader
            | IpProto::Hip
            | IpProto::Shim6 => HeaderType::Proto(meta.proto),
            _ => HeaderType::StopProcessing,
        };

        Ok(())
    }

    /// Parses the Geneve header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    ///
    /// Examples:
    /// - Ethernet -> Ipv4 -> Udp -> Geneve -> Ipv4 -> <IpProto>
    /// - Ethernet -> Ipv6 -> Udp -> Geneve -> Ipv4 -> <IpProto>
    /// - Ethernet -> Ipv4 -> Udp -> Geneve -> Ethernet -> Ipv4 -> <IpProto>
    fn parse_geneve_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + GENEVE_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta: &mut PacketMeta = get_packet_meta(ctx)?;
        if meta.tunnel_type == TunnelType::None {
            // policy: outermost determines the flow span tunnel attributes
            meta.tunnel_type = TunnelType::Geneve;
            meta.tunnel_id =
                geneve::vni(ctx.load(self.offset + 4).map_err(|_| Error::OutOfBounds)?);
        }
        // policy: innermost EtherType determines the flow span EtherType
        meta.ether_type = ctx.load(self.offset + 2).map_err(|_| Error::OutOfBounds)?;

        let ver_opt_len: geneve::VerOptLen =
            ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        let total_hdr_len = geneve::total_hdr_len(ver_opt_len);
        self.offset += total_hdr_len;
        self.next_hdr = match meta.ether_type {
            EtherType::Ethernet => HeaderType::Ethernet,
            EtherType::Ipv4 => HeaderType::Ipv4,
            EtherType::Ipv6 => HeaderType::Ipv6,
            _ => HeaderType::StopProcessing,
        };

        Ok(())
    }

    /// Parses the VXLAN header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    ///
    /// Examples:
    /// - Ethernet -> Ipv4 -> Udp -> Vxlan -> Ethernet -> Ipv4 -> <IpProto>
    /// - Ethernet -> Ipv6 -> Ipv4 -> Udp -> Vxlan -> Ethernet -> Ipv4 -> <IpProto>
    fn parse_vxlan_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + VXLAN_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        if meta.tunnel_type == TunnelType::None {
            meta.tunnel_type = TunnelType::Vxlan;
            let flags: vxlan::Flags = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
            if vxlan::flags_i_flag(flags) {
                meta.tunnel_id =
                    vxlan::vni(ctx.load(self.offset + 4).map_err(|_| Error::OutOfBounds)?);
            }
        }

        self.offset += VXLAN_LEN;
        self.next_hdr = HeaderType::Ethernet;

        Ok(())
    }

    /// Parses the WireGuard header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_wireguard_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        // Read the first byte to determine WireGuard message type
        if self.offset + 1 > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }
        let wireguard_type: u8 = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        let wg_type = WireGuardType::from(wireguard_type);
        self.next_hdr = HeaderType::StopProcessing;

        match wg_type {
            WireGuardType::HandshakeInitiation => self.parse_wireguard_init(ctx),
            WireGuardType::HandshakeResponse => self.parse_wireguard_response(ctx),
            WireGuardType::CookieReply => self.parse_wireguard_cookie_reply(ctx),
            WireGuardType::TransportData => self.parse_wireguard_transport_data(ctx),
            _ => Err(Error::Unsupported),
        }
    }

    /// Parses a WireGuard Handshake Initiation packet.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_wireguard_init(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + WIREGUARD_INITIATION_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        if !meta.wireguard_exists {
            meta.wireguard_exists = true;
            meta.ipsec_sender_index =
                wireguard::sender_idx(ctx.load(self.offset + 4).map_err(|_| Error::OutOfBounds)?);
        }

        self.offset += WIREGUARD_INITIATION_LEN;

        Ok(())
    }

    /// Parses a WireGuard Handshake Response packet.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_wireguard_response(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + WIREGUARD_RESPONSE_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        if !meta.wireguard_exists {
            meta.wireguard_exists = true;
            meta.ipsec_sender_index =
                wireguard::sender_idx(ctx.load(self.offset + 4).map_err(|_| Error::OutOfBounds)?);
            meta.ipsec_receiver_index =
                wireguard::receiver_idx(ctx.load(self.offset + 8).map_err(|_| Error::OutOfBounds)?);
        }

        self.offset += WIREGUARD_RESPONSE_LEN;

        Ok(())
    }

    /// Parses a WireGuard Cookie Reply packet.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_wireguard_cookie_reply(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + WIREGUARD_COOKIE_REPLY_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        if !meta.wireguard_exists {
            meta.wireguard_exists = true;
            meta.ipsec_receiver_index =
                wireguard::receiver_idx(ctx.load(self.offset + 4).map_err(|_| Error::OutOfBounds)?);
        }

        self.offset += WIREGUARD_COOKIE_REPLY_LEN;

        Ok(())
    }

    /// Parses a WireGuard Transport Data packet.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_wireguard_transport_data(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + WIREGUARD_TRANSPORT_DATA_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        if !meta.wireguard_exists {
            meta.wireguard_exists = true;
            meta.ipsec_receiver_index =
                wireguard::receiver_idx(ctx.load(self.offset + 4).map_err(|_| Error::OutOfBounds)?);
        }

        self.offset += WIREGUARD_TRANSPORT_DATA_LEN;

        Ok(())
    }

    /// Parses the Hop-by-Hop IPv6-extension header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_hopopt_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + HOP_OPT_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.proto = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        self.next_hdr = match meta.proto {
            IpProto::Tcp
            | IpProto::Udp
            | IpProto::Ipv6Icmp
            | IpProto::Esp
            | IpProto::Ah
            | IpProto::HopOpt
            | IpProto::Ipv6Route
            | IpProto::Ipv6Frag
            | IpProto::Ipv6Opts
            | IpProto::MobilityHeader
            | IpProto::Hip
            | IpProto::Shim6
            | IpProto::Ipv4
            | IpProto::Ipv6 => HeaderType::Proto(meta.proto),
            _ => HeaderType::StopProcessing,
        };

        let hdr_ext_len: hop::HdrExtLen =
            ctx.load(self.offset + 1).map_err(|_| Error::OutOfBounds)?;
        let total_len = hop::total_hdr_len(hdr_ext_len);
        if self.offset + total_len > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        self.offset += total_len;

        Ok(())
    }

    /// Parses the GRE header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded.
    ///
    /// Examples:
    /// - Ethernet -> Ipv4 -> Gre -> Ipv4 -> <IpProto>
    /// - Ethernet -> Ipv6 -> Gre -> Ipv4 -> <IpProto>
    /// - Ethernet -> Ipv4 -> Gre -> Ethernet -> Ipv4 -> <IpProto>
    fn parse_gre_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + GRE_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let flag_res: gre::FlgsRes0Ver = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;

        let meta = get_packet_meta(ctx)?;
        if meta.tunnel_type == TunnelType::None {
            // policy: outermost determines the flow span tunnel attributes
            meta.tunnel_type = TunnelType::Gre;
            if gre::k_flag(flag_res) {
                meta.tunnel_id =
                    gre::key(ctx.load(self.offset + 8).map_err(|_| Error::OutOfBounds)?);
            }
        }
        // policy: innermost EtherType determines the flow span EtherType
        meta.ether_type = ctx.load(self.offset + 2).map_err(|_| Error::OutOfBounds)?;

        // Increase offset to the end of the GRE header before parsing the routing field
        self.offset += gre::total_hdr_len(flag_res);
        // Handle variable-length routing field if R flag is set
        if gre::r_flag(flag_res) {
            let mut routing_len = 0;
            loop {
                if self.offset + routing_len + GRE_ROUTING_LEN > ctx.len() as usize {
                    return Err(Error::OutOfBounds);
                }

                let (address_family, sre_length) = {
                    let af: gre::AddressFamily = ctx
                        .load(self.offset + routing_len)
                        .map_err(|_| Error::OutOfBounds)?;
                    let sl: gre::SreLength = ctx
                        .load(self.offset + routing_len + 3)
                        .map_err(|_| Error::OutOfBounds)?;
                    (af, sl)
                };

                if address_family == 0 && sre_length == 0 {
                    routing_len += GRE_ROUTING_LEN;
                    break;
                }

                if sre_length < GRE_ROUTING_LEN as u8 {
                    return Err(Error::OutOfBounds);
                }

                if self.offset + routing_len + sre_length as usize > ctx.len() as usize {
                    return Err(Error::OutOfBounds);
                }

                routing_len += sre_length as usize;

                // Prevent infinite loops
                if routing_len > 64 {
                    return Err(Error::OutOfBounds);
                }
            }

            self.offset += routing_len;
        }

        self.next_hdr = match meta.ether_type {
            EtherType::Ethernet => HeaderType::Ethernet,
            EtherType::Ipv4 => HeaderType::Ipv4,
            EtherType::Ipv6 => HeaderType::Ipv6,
            _ => HeaderType::StopProcessing,
        };

        Ok(())
    }

    /// Parses the ICMP header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded.
    /// Note: ICMP does not use ports, so src_port and dst_port remain zero.
    fn parse_icmp_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + ICMP_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.icmp_type_id = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        meta.icmp_code_id = ctx.load(self.offset + 1).map_err(|_| Error::OutOfBounds)?;

        self.next_hdr = HeaderType::StopProcessing;

        Ok(())
    }

    /// Parses the TCP header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded.
    fn parse_tcp_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + TCP_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.src_port = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        meta.dst_port = ctx.load(self.offset + 2).map_err(|_| Error::OutOfBounds)?;
        meta.tcp_flags = ctx.load(self.offset + 12).map_err(|_| Error::OutOfBounds)?;

        self.next_hdr = HeaderType::StopProcessing;

        Ok(())
    }

    /// Parses the UDP header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded.
    fn parse_udp_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + UDP_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.src_port = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        meta.dst_port = ctx.load(self.offset + 2).map_err(|_| Error::OutOfBounds)?;

        let dst_port = meta.dst_port();

        let opts = get_parser_options(ctx)?;
        // IANA has assigned port 6081 as the fixed well-known destination port for Geneve and port 4789 as the fixed well-known destination port for Vxlan.
        // Although the well-known value should be used by default, it is RECOMMENDED that implementations make these configurable.
        self.next_hdr = if dst_port == opts.geneve_port {
            HeaderType::Geneve
        } else if dst_port == opts.vxlan_port {
            HeaderType::Vxlan
        } else if dst_port == opts.wireguard_port {
            HeaderType::Wireguard
        } else {
            HeaderType::StopProcessing
        };

        if meta.tunnel_type == TunnelType::None
            && (self.next_hdr == HeaderType::Geneve
                || self.next_hdr == HeaderType::Vxlan
                || self.next_hdr == HeaderType::Wireguard)
        {
            // policy: outermost determines the flow span tunnel attributes
            meta.tunnel_src_mac_addr = meta.src_mac_addr;
            meta.tunnel_ether_type = meta.ether_type;
            meta.tunnel_proto = meta.proto;
            meta.tunnel_ip_addr_type = meta.ip_addr_type;
            if meta.tunnel_ip_addr_type == IpAddrType::Ipv4 {
                meta.tunnel_src_ipv4_addr = meta.src_ipv4_addr;
                meta.tunnel_dst_ipv4_addr = meta.dst_ipv4_addr;
            } else if meta.tunnel_ip_addr_type == IpAddrType::Ipv6 {
                meta.tunnel_src_ipv6_addr = meta.src_ipv6_addr;
                meta.tunnel_dst_ipv6_addr = meta.dst_ipv6_addr;
            }
            meta.tunnel_src_port = meta.src_port;
            meta.tunnel_dst_port = meta.dst_port;
            if meta.ah_exists {
                meta.tunnel_ah_exists = true;
                meta.tunnel_ipsec_ah_spi = meta.ipsec_ah_spi;
            }

            // Reset inner headers to prepare for parsing tunneled packet
            Parser::reset_inner_meta(meta);
        }

        self.offset += UDP_LEN;

        Ok(())
    }

    /// Parses the IPv6 routing header in the packet and dispatches to the appropriate specific parser.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_generic_route_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + GENERIC_ROUTE_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.proto = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;

        self.next_hdr = HeaderType::Proto(meta.proto);
        self.offset +=
            route::total_hdr_len(ctx.load(self.offset + 1).map_err(|_| Error::OutOfBounds)?);

        Ok(())
    }

    /// Parses the IPv6 Fragment header and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_fragment_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + FRAGMENT_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.proto = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;

        self.offset += FRAGMENT_LEN;
        self.next_hdr = HeaderType::Proto(meta.proto);

        Ok(())
    }

    /// Parses the ESP IPv6-extension header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_esp_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + ESP_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        if !meta.esp_exists {
            meta.esp_exists = true;
            meta.ipsec_esp_spi = esp::spi(ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?);
        }

        self.next_hdr = HeaderType::StopProcessing; // ESP signals end of parsing headers because its payload is encrypted

        Ok(())
    }

    /// Parses the AH IPv6-extension header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_ah_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + AH_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.proto = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        if !meta.ah_exists {
            meta.ah_exists = true;
            meta.ipsec_ah_spi = ah::spi(ctx.load(self.offset + 4).map_err(|_| Error::OutOfBounds)?);
        }

        let payload_len: ah::PayloadLen =
            ctx.load(self.offset + 1).map_err(|_| Error::OutOfBounds)?;
        self.offset += ah::total_hdr_len(payload_len);
        self.next_hdr = HeaderType::Proto(meta.proto);

        Ok(())
    }

    /// Parses the Destination Options IPv6-extension header and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_destopts_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + destopts::DEST_OPTS_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.proto = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        let hdr_ext_len: destopts::HdrExtLen =
            ctx.load(self.offset + 1).map_err(|_| Error::OutOfBounds)?;

        let total_len = destopts::total_hdr_len(hdr_ext_len);
        if self.offset + total_len > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        self.offset += total_len;
        self.next_hdr = HeaderType::Proto(meta.proto);

        Ok(())
    }

    /// Parses the IPv6 Mobility header and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_mobility_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + MOBILITY_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.proto = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        let hdr_ext_len: mobility::HdrExtLen =
            ctx.load(self.offset + 1).map_err(|_| Error::OutOfBounds)?;

        self.offset += mobility::total_hdr_len(hdr_ext_len);
        self.next_hdr = HeaderType::Proto(meta.proto);

        Ok(())
    }

    /// Parses the HIP header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_hip_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + HIP_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.proto = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;
        let hdr_ext_len: u8 = ctx.load(self.offset + 1).map_err(|_| Error::OutOfBounds)?;
        if hdr_ext_len > 64 {
            // Validate header length is reasonable (max 64 * 8 = 512 bytes)
            // This prevents verifier from tracking all 256 possible u8 values but covers most common cases
            return Err(Error::MalformedHeader);
        }

        let total_hdr_len = hip::total_hdr_len(hdr_ext_len);
        if self.offset + total_hdr_len > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        self.offset += total_hdr_len;
        self.next_hdr = HeaderType::Proto(meta.proto);

        Ok(())
    }

    /// Parses the Shim6 header in the packet and updates the parser state accordingly.
    /// Returns an error if the header cannot be loaded or is malformed.
    fn parse_shim6_header(&mut self, ctx: &TcContext) -> Result<(), Error> {
        if self.offset + SHIM6_LEN > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        let meta = get_packet_meta(ctx)?;
        meta.proto = ctx.load(self.offset).map_err(|_| Error::OutOfBounds)?;

        let hdr_ext_len: u8 = ctx.load(self.offset + 1).map_err(|_| Error::OutOfBounds)?;
        if hdr_ext_len > 64 {
            // Validate header length is reasonable (max 64 * 8 = 512 bytes)
            // This prevents verifier from tracking all 256 possible u8 values but covers most common cases
            return Err(Error::MalformedHeader);
        }

        let total_hdr_len = shim6::total_hdr_len(hdr_ext_len);
        if self.offset + total_hdr_len > ctx.len() as usize {
            return Err(Error::OutOfBounds);
        }

        self.offset += total_hdr_len;
        self.next_hdr = HeaderType::Proto(meta.proto);

        Ok(())
    }

    #[inline(always)]
    fn reset_inner_meta(meta: &mut PacketMeta) {
        meta.src_mac_addr = [0; 6];
        meta.ether_type = EtherType::default();
        meta.proto = IpProto::default();
        meta.ip_addr_type = IpAddrType::default();
        meta.src_ipv6_addr = [0; 16];
        meta.dst_ipv6_addr = [0; 16];
        meta.src_ipv4_addr = [0; 4];
        meta.dst_ipv4_addr = [0; 4];
        meta.l3_octet_count = 0;
        meta.src_port = [0; 2];
        meta.dst_port = [0; 2];
        meta.ip_dscp_id = 0;
        meta.ip_ecn_id = 0;
        meta.ip_ttl = 0;
        meta.ip_flow_label = 0;
        meta.icmp_type_id = 0;
        meta.icmp_code_id = 0;
        meta.tcp_flags = 0;
        meta.ipsec_ah_spi = 0;
        meta.ipsec_esp_spi = 0;
        meta.ipsec_sender_index = 0;
        meta.ipsec_receiver_index = 0;
        meta.ah_exists = false;
        meta.esp_exists = false;
        meta.wireguard_exists = false;
    }
}

#[derive(Debug, Clone)]
struct ParserOptions {
    /// The port number to use for Geneve tunnel detection
    /// Default is 6081 as per IANA assignment
    geneve_port: u16,
    vxlan_port: u16,
    wireguard_port: u16,
}

impl Default for ParserOptions {
    fn default() -> Self {
        ParserOptions {
            geneve_port: 6081,
            vxlan_port: 4789,
            wireguard_port: 51820,
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(not(test))]
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0"; // Corrected license string length and array size

#[cfg(feature = "test")]
mod host_test_shim {
    extern crate alloc;
    use alloc::vec::Vec;
    use core::mem;

    use crate::Error;

    // Mock __sk_buff that mimics the real structure's ifindex field
    #[repr(C)]
    pub struct MockSkBuff {
        pub ifindex: u32,
        // Add other fields as needed for future testing
    }

    // Mock SkBuff that wraps the mock __sk_buff like the real one
    pub struct SkBuff {
        #[allow(dead_code)]
        pub skb: *mut MockSkBuff,
        _data: Vec<u8>,                           // Keep data alive
        _mock_skb: alloc::boxed::Box<MockSkBuff>, // Keep mock alive
    }

    impl SkBuff {
        pub fn new(data: Vec<u8>, ifindex: u32) -> Self {
            let mock_skb = alloc::boxed::Box::new(MockSkBuff { ifindex });
            let skb_ptr = mock_skb.as_ref() as *const MockSkBuff as *mut MockSkBuff;

            Self {
                skb: skb_ptr,
                _data: data,
                _mock_skb: mock_skb,
            }
        }

        pub fn len(&self) -> u32 {
            self._data.len() as u32
        }

        pub fn load<T: Copy>(&self, offset: usize) -> Result<T, Error> {
            if offset + mem::size_of::<T>() > self._data.len() {
                return Err(Error::OutOfBounds);
            }
            // Use proper memory copy to avoid alignment issues
            let mut value = core::mem::MaybeUninit::<T>::uninit();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self._data.as_ptr().add(offset),
                    value.as_mut_ptr() as *mut u8,
                    mem::size_of::<T>(),
                );
                Ok(value.assume_init())
            }
        }
    }

    // Test TcContext that mimics the real aya_ebpf TcContext interface
    pub struct TcContext {
        pub skb: SkBuff,
    }

    impl TcContext {
        pub fn new(data: Vec<u8>) -> Self {
            let skb = SkBuff::new(data, 42); // Use test ifindex of 42
            Self { skb }
        }

        pub fn len(&self) -> u32 {
            self.skb.len()
        }

        pub fn load<T: Copy>(&self, offset: usize) -> Result<T, Error> {
            self.skb.load(offset)
        }
    }

    // No-op logging macros to satisfy calls in parsing code
    #[cfg(feature = "test")]
    #[macro_export]
    macro_rules! error {
        ($($tt:tt)*) => {};
    }
}

#[cfg(feature = "test")]
use host_test_shim::TcContext;

#[cfg(feature = "test")]
#[inline(always)]
fn get_packet_meta(_ctx: &TcContext) -> Result<&'static mut PacketMeta, Error> {
    use core::{
        ptr::null_mut,
        sync::atomic::{AtomicPtr, Ordering},
    };
    extern crate alloc;
    use alloc::boxed::Box;

    static TEST_META_PTR: AtomicPtr<PacketMeta> = AtomicPtr::new(null_mut());

    let mut ptr = TEST_META_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        let new_meta = Box::into_raw(Box::new(PacketMeta {
            src_ipv6_addr: [0; 16],
            dst_ipv6_addr: [0; 16],
            tunnel_src_ipv6_addr: [0; 16],
            tunnel_dst_ipv6_addr: [0; 16],
            src_mac_addr: [0; 6],
            src_ipv4_addr: [0; 4],
            dst_ipv4_addr: [0; 4],
            ifindex: 0,
            ip_flow_label: 0,
            l3_octet_count: 0,
            tunnel_src_ipv4_addr: [0; 4],
            tunnel_dst_ipv4_addr: [0; 4],
            tunnel_id: 0,
            tunnel_sender_index: 0,
            tunnel_receiver_index: 0,
            tunnel_spi: 0,
            ether_type: EtherType::Ipv4,
            src_port: [0; 2],
            dst_port: [0; 2],
            tunnel_ether_type: EtherType::Ipv4,
            tunnel_src_port: [0; 2],
            tunnel_dst_port: [0; 2],
            ip_addr_type: IpAddrType::Ipv4,
            proto: IpProto::HopOpt,
            direction: Direction::Ingress,
            ip_dscp_id: 0,
            ip_ecn_id: 0,
            ip_ttl: 0,
            icmp_type_id: 0,
            icmp_code_id: 0,
            tcp_flags: 0,
            tunnel_ip_addr_type: IpAddrType::Ipv4,
            tunnel_proto: IpProto::HopOpt,
            tunnel_type: TunnelType::None,
        }));
        match TEST_META_PTR.compare_exchange(
            null_mut(),
            new_meta,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => ptr = new_meta,
            Err(existing) => {
                // Another thread won the race, use their pointer and free ours
                unsafe {
                    drop(Box::from_raw(new_meta));
                }
                ptr = existing;
            }
        }
    }
    Ok(unsafe { &mut *ptr })
}

#[cfg(feature = "test")]
static TEST_PARSER_OPTIONS: ParserOptions = ParserOptions {
    geneve_port: 6081,
    vxlan_port: 4789,
    wireguard_port: 51820,
};

#[cfg(feature = "test")]
#[inline(always)]
fn get_parser_options(_ctx: &TcContext) -> Result<&'static ParserOptions, Error> {
    Ok(&TEST_PARSER_OPTIONS)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::{vec, vec::Vec};

    use super::*;

    // Helper function to create an Ethernet header test packet
    fn create_eth_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Destination MAC (ff:ff:ff:ff:ff:ff)
        packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Source MAC (00:11:22:33:44:55)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // EtherType (0x0800, big-endian for IPv4)
        packet.extend_from_slice(&[0x08, 0x00]);

        packet
    }

    fn create_eth_test_packet_unsupported() -> Vec<u8> {
        let mut packet = Vec::new();

        // Destination MAC (ff:ff:ff:ff:ff:ff)
        packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Source MAC (00:11:22:33:44:55)
        packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // EtherType (0x0800, big-endian for IPv4)
        packet.extend_from_slice(&[0x89, 0x06]);

        packet
    }

    // Helper function to create an IPv4 header test packet
    fn create_ipv4_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Version (4) and IHL (5) = 0x45
        packet.push(0x45);
        // DSCP and ECN
        packet.push(0x00);
        // Total Length (20 bytes for header)
        packet.extend_from_slice(&[0x00, 0x14]);
        // Identification
        packet.extend_from_slice(&[0x00, 0x00]);
        // Flags and Fragment Offset
        packet.extend_from_slice(&[0x00, 0x00]);
        // TTL
        packet.push(0x40);
        // Protocol (TCP = 6)
        packet.push(0x06);
        // Header Checksum
        packet.extend_from_slice(&[0x00, 0x00]);
        // Source IP (192.168.1.1)
        packet.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]);
        // Destination IP (192.168.1.2)
        packet.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x02]);

        packet
    }

    // Helper function to create an IPv6 header test packet
    fn create_ipv6_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Version (6), Traffic Class, Flow Label
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        // Payload Length
        packet.extend_from_slice(&[0x00, 0x00]);
        // Next Header (TCP = 6)
        packet.push(0x06);
        // Hop Limit
        packet.push(0x40);
        // Source IP (2001:db8::1)
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        // Destination IP (2001:db8::2)
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        packet
    }

    // Helper function to create a TCP header test packet
    fn create_tcp_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Source Port (12345)
        packet.extend_from_slice(&[0x30, 0x39]);
        // Destination Port (80)
        packet.extend_from_slice(&[0x00, 0x50]);
        // Sequence Number
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Acknowledgment Number
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Data Offset (5), Reserved, Flags (SYN)
        packet.extend_from_slice(&[0x50, 0x02]);
        // Window Size
        packet.extend_from_slice(&[0x20, 0x00]);
        // Checksum
        packet.extend_from_slice(&[0x00, 0x00]);
        // Urgent Pointer
        packet.extend_from_slice(&[0x00, 0x00]);

        packet
    }

    // Helper function to create a UDP header test packet
    fn create_udp_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Source Port (12345)
        packet.extend_from_slice(&[0x30, 0x39]);
        // Destination Port (53)
        packet.extend_from_slice(&[0x00, 0x35]);
        // Length (8 bytes for header)
        packet.extend_from_slice(&[0x00, 0x08]);
        // Checksum
        packet.extend_from_slice(&[0x00, 0x00]);

        packet
    }

    // Helper function to create a UDP header test packet with Geneve port (6081)
    fn create_udp_geneve_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Source Port (12345)
        packet.extend_from_slice(&[0x30, 0x39]);
        // Destination Port (6081 - Geneve)
        packet.extend_from_slice(&[0x17, 0xC1]); // 6081 in big-endian
        // Length (8 bytes for header)
        packet.extend_from_slice(&[0x00, 0x08]);
        // Checksum
        packet.extend_from_slice(&[0x00, 0x00]);

        packet
    }

    // Helper function to create a Geneve header test packet
    fn create_geneve_test_packet(protocol_type: u16, opt_len: u8) -> Vec<u8> {
        let mut packet = Vec::new();

        // Version (0) and Option Length (opt_len)
        packet.push(opt_len & 0x3F); // Version 0, Option Length as specified
        // OAM (0), Critical (0), Reserved (0)
        packet.push(0x00);
        // Protocol Type (e.g., 0x0800 for IPv4, 0x86DD for IPv6, 0x6558 for Ethernet)
        packet.extend_from_slice(&protocol_type.to_be_bytes());
        // VNI (0x123456)
        packet.extend_from_slice(&[0x12, 0x34, 0x56]);
        // Reserved
        packet.push(0x00);

        // Add option bytes if opt_len > 0
        for _ in 0..(opt_len as usize * 4) {
            packet.push(0x00);
        }

        packet
    }

    // Helper function to create an AH (Authentication Header) test packet
    // The AH fixed header is 12 bytes; to keep it minimal we set payload_len = 1, so total is 12 bytes
    fn create_ah_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::with_capacity(AH_LEN);
        // Next Header
        packet.push(next as u8);
        // Payload Len (in 4-octet units minus 2); 1 -> (1+2)*4 = 12 total bytes
        packet.push(1);
        // Reserved (2 bytes)
        packet.extend_from_slice(&[0x00, 0x00]);
        // SPI (4 bytes)
        packet.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        // Sequence Number (4 bytes)
        packet.extend_from_slice(&[0x9a, 0xbc, 0xde, 0xf0]);
        packet
    }

    // Helper function to create an ESP (Encapsulating Security Payload) test packet
    // The ESP header is 8 bytes (SPI + Sequence Number)
    fn create_esp_test_packet() -> Vec<u8> {
        let mut packet = Vec::with_capacity(ESP_LEN);
        // SPI (4 bytes)
        packet.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        // Sequence Number (4 bytes)
        packet.extend_from_slice(&[0x9a, 0xbc, 0xde, 0xf0]);
        packet
    }

    // Helper function to create a Destination Options header test packet
    fn create_destopts_test_packet(next: IpProto, hdr_ext_len: u8) -> Vec<u8> {
        let mut packet = Vec::with_capacity(destopts::DEST_OPTS_LEN + (hdr_ext_len as usize) * 8);
        packet.push(next as u8);
        packet.push(hdr_ext_len);
        // Minimum 6 bytes to complete the first 8-octet block
        packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // If hdr_ext_len > 0, add padding to reach total length (hdr_ext_len + 1) * 8
        let total = (hdr_ext_len as usize + 1) * 8;
        let current = packet.len();
        if total > current {
            packet.extend(core::iter::repeat(0u8).take(total - current));
        }
        packet
    }

    // Helper function to create a Hop-by-Hop Options header test packet
    // Total length is (hdr_ext_len + 1) * 8 bytes
    fn create_hop_test_packet(next: IpProto, hdr_ext_len: u8) -> Vec<u8> {
        let total_len = hop::total_hdr_len(hdr_ext_len);
        let mut packet = Vec::with_capacity(total_len);
        // Next Header
        packet.push(next as u8);
        // Header Extension Length
        packet.push(hdr_ext_len);
        // Options Data (fill remaining bytes)
        for i in 0..(total_len - 2) {
            packet.push((i % 256) as u8);
        }

        packet
    }

    // Helper function to create a WireGuard Initiation test packet
    // WireGuardInitiation is 148 bytes total
    fn create_wireguard_init_test_packet() -> Vec<u8> {
        let mut packet = Vec::with_capacity(WIREGUARD_INITIATION_LEN);
        //Type = 1 (Handshake Initiation)
        packet.push(1);
        // Reserved = 0 (3 bytes)
        packet.extend_from_slice(&[0x00, 0x00, 0x00]);
        // Sender Index = 1234 (4 bytes)
        packet.extend_from_slice(&1234u32.to_le_bytes());
        // Ephemeral key (32 bytes of test data)
        packet.extend_from_slice(&[0x01; 32]);
        // Encrypted Static (48 bytes of test data)
        packet.extend_from_slice(&[0x02; 48]);
        // Encrypted Timestamp (28 bytes of test data)
        packet.extend_from_slice(&[0x03; 28]);
        // MAC 1 (16 bytes of test data)
        packet.extend_from_slice(&[0x04; 16]);
        // MAC 2 (16 bytes of test data)
        packet.extend_from_slice(&[0x05; 16]);
        packet
    }

    // Helper function to create a WireGuard Response test packet
    // WireGuardResponse is 92 bytes total
    fn create_wireguard_response_test_packet() -> Vec<u8> {
        let mut packet = Vec::with_capacity(WIREGUARD_RESPONSE_LEN);
        // Type = 2 (Handshake Response)
        packet.push(2);
        // Reserved = 0 (3 bytes)
        packet.extend_from_slice(&[0x00, 0x00, 0x00]);
        // Sender Index = 5432 (4 bytes)
        packet.extend_from_slice(&5432u32.to_le_bytes());
        // Receiver Index = 1234 (4 bytes)
        packet.extend_from_slice(&1234u32.to_le_bytes());
        // Ephemeral key (32 bytes of test data)
        packet.extend_from_slice(&[0x06; 32]);
        // Encrypted Nothing (16 bytes of test data)
        packet.extend_from_slice(&[0x07; 16]);
        // MAC 1 (16 bytes of test data)
        packet.extend_from_slice(&[0x08; 16]);
        // MAC 2 (16 bytes of test data)
        packet.extend_from_slice(&[0x09; 16]);
        packet
    }

    // Helper function to create a WireGuard Cookie Reply test packet
    // WireGuardCookieReply is 48 bytes total
    fn create_wireguard_cookie_reply_test_packet() -> Vec<u8> {
        let mut packet = Vec::with_capacity(WIREGUARD_COOKIE_REPLY_LEN);
        // Type = 3 (Cookie Reply)
        packet.push(3);
        // Reserved = 0 (3 bytes)
        packet.extend_from_slice(&[0x00, 0x00, 0x00]);
        // Receiver Index = 12345 (4 bytes)
        packet.extend_from_slice(&12345u32.to_le_bytes());
        // Nonce (24 bytes of test data)
        packet.extend_from_slice(&[0x0A; 24]);
        // Encrypted Cookie (16 bytes of test data)
        packet.extend_from_slice(&[0x0B; 16]);
        packet
    }

    // Helper function to create a WireGuard Transport Data test packet
    // WireGuardTransportData is 16 bytes total
    fn create_wireguard_transport_data_test_packet() -> Vec<u8> {
        let mut packet = Vec::with_capacity(WIREGUARD_TRANSPORT_DATA_LEN);
        // Type = 4 (Transport Data)
        packet.push(4);
        // Reserved = 0 (3 bytes)
        packet.extend_from_slice(&[0x00, 0x00, 0x00]);
        // Receiver Index = 12345 (4 bytes)
        packet.extend_from_slice(&12345u32.to_le_bytes());
        // Counter (8 bytes of test data)
        packet.extend_from_slice(&[0x0C; 8]);
        packet
    }

    // Helper function to create a Shim6 header test packet
    fn create_shim6_test_packet(next: IpProto, hdr_ext_len: u8) -> Vec<u8> {
        let total = (hdr_ext_len as usize + 1) * 8;
        let mut packet = Vec::with_capacity(total);
        // Next Header (usually NoNxt for control messages, but configurable for tests)
        packet.push(next as u8);
        // Hdr Ext Len (in 8-octet units after the first 8 bytes)
        packet.push(hdr_ext_len);
        // P (bit7)=0 and Type (7 bits)=1
        packet.push(0x01);
        // Type-specific (upper 7 bits)=0x3F, S bit (lsb)=0
        packet.push(0x7E); // 0b0111_1110 => type-specific=0x3F, S=0
        // Checksum (2 bytes) arbitrary
        packet.extend_from_slice(&[0x12, 0x34]);
        // First 2 bytes of type-specific data
        packet.extend_from_slice(&[0x56, 0x78]);
        // Pad to total length
        let current = packet.len();
        if total > current {
            packet.extend(core::iter::repeat(0u8).take(total - current));
        }
        packet
    }

    // Helper function to create a HIP header test packet
    // HipHdr LEN is 40 bytes for base; hdr_len is in 8-octet units excluding first 8 bytes
    fn create_hip_test_packet(next: IpProto, hdr_len: u8) -> Vec<u8> {
        let total = (hdr_len as usize + 1) * 8;
        let mut packet = Vec::with_capacity(total);
        // Next Header
        packet.push(next as u8);
        // Header Length
        packet.push(hdr_len);
        // Packet Type field (top bit fixed 0 per our simplified build) + 7-bit type
        packet.push(0x01);
        // Version field: version=2 (upper 4 bits), reserved=0, fixed bit=1 (lsb)
        packet.push((2u8 << 4) | 0x01);
        // Checksum
        packet.extend_from_slice(&[0x12, 0x34]);
        // Controls
        packet.extend_from_slice(&[0xAB, 0xCD]);
        // Sender HIT (16 bytes)
        packet.extend_from_slice(&[0u8; 16]);
        // Receiver HIT (16 bytes)
        packet.extend_from_slice(&[0u8; 16]);
        // Pad parameters to total length if needed
        let current = packet.len();
        if total > current {
            packet.extend(core::iter::repeat(0u8).take(total - current));
        }
        packet
    }

    // Helper function to create an ICMP header test packet (Echo Request)
    fn create_icmp_test_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Type (8 = Echo Request)
        packet.push(0x08);
        // Code (0)
        packet.push(0x00);
        // Checksum (2 bytes)
        packet.extend_from_slice(&[0x12, 0x34]);
        // Identifier (2 bytes)
        packet.extend_from_slice(&[0x56, 0x78]);
        // Sequence Number (2 bytes)
        packet.extend_from_slice(&[0x9a, 0xbc]);

        packet
    }

    // Helper to create an IPv6 Mobility header test packet
    fn create_mobility_test_packet(next: IpProto, hdr_ext_len: u8, mh_type: u8) -> Vec<u8> {
        let total = (hdr_ext_len as usize + 1) * 8;
        let mut packet = Vec::with_capacity(total);
        // Fixed 8 bytes
        packet.push(next as u8); // Payload Proto (next header)
        packet.push(hdr_ext_len); // Hdr Ext Len (in 8-octet units excluding first 8)
        packet.push(mh_type); // MH Type
        packet.push(0x00); // Reserved
        // Checksum (dummy)
        packet.extend_from_slice(&[0x12, 0x34]);
        // Reserved Message Data (2 bytes)
        packet.extend_from_slice(&[0x00, 0x00]);
        // Message Data padding to total length
        while packet.len() < total {
            packet.push(0);
        }
        packet
    }

    // Helper to create an IPv6 Fragment header test packet (8 bytes)
    fn create_fragment_test_packet(
        next: IpProto,
        offset_13bit: u16,
        m_flag: bool,
        id: u32,
    ) -> Vec<u8> {
        let mut packet = Vec::with_capacity(FRAGMENT_LEN);
        // Next Header
        packet.push(next as u8);
        // Reserved
        packet.push(0);
        // Fragment offset fields: 13-bit offset across two bytes (frag_offset byte and fo_res_m)
        let masked = offset_13bit & 0x1FFF;
        let frag_offset_byte = ((masked >> 5) & 0xFF) as u8;
        let upper5 = (masked & 0x001F) as u8;
        let mut fo_res_m = upper5 << 3; // place in bits 7..3
        // reserved2 bits are zero
        if m_flag {
            fo_res_m |= 0x01;
        }
        packet.push(frag_offset_byte);
        packet.push(fo_res_m);
        // Identification (big-endian per our Fragment::identification())
        packet.extend_from_slice(&id.to_be_bytes());
        packet
    }

    // Helper function to create a Type2 routing header test packet
    // Type2 routing header is 24 bytes total (4 bytes generic + 20 bytes fixed)
    fn create_type2_routing_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::with_capacity(24);

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(2); // Hdr Ext Len (2 * 8 = 16 bytes after first 8, total 24)
        packet.push(0); // Routing Type (Type2) - enum variant index
        packet.push(1); // Segments Left (always 1 for Type2)

        // Type2 fixed header (20 bytes)
        // Reserved (4 bytes)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Home Address (16 bytes) - 2001:db8::dead:beef
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad,
            0xbe, 0xef,
        ]);

        packet
    }

    // Helper function to create an RPL Source Route header test packet
    // This creates a minimal RPL header with 2 addresses
    fn create_rpl_source_route_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::new();

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(4); // Hdr Ext Len (4 * 8 = 32 bytes after first 8, total 40)
        packet.push(1); // Routing Type (RplSourceRoute) - enum variant index
        packet.push(2); // Segments Left

        // RPL Source fixed header (4 bytes)
        packet.push(0x24); // CmprI = 2, CmprE = 4 (0x24)
        packet.push(0x60); // Pad = 6 (0x60), Reserved bits = 0
        packet.extend_from_slice(&[0x00, 0x00]); // Reserved (remaining 2 bytes)

        // Address data (32 bytes total to match hdr_ext_len)
        // First address (14 bytes, compressed by CmprI=2)
        packet.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        ]);
        // Last address (12 bytes, compressed by CmprE=4)
        packet.extend_from_slice(&[
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        ]);
        // Padding (6 bytes)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        packet
    }

    // Helper function to create a Segment Routing Header test packet
    // This creates a minimal SRH with 2 segments based on RFC 8754 structure
    fn create_segment_routing_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::new();

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(4); // Hdr Ext Len (4 * 8 = 32 bytes after first 8, total 40)
        packet.push(2); // Routing Type (SegmentRoutingHeader) - enum variant index
        packet.push(1); // Segments Left (index of current active segment)

        // Segment Routing fixed header (4 bytes)
        packet.push(1); // Last Entry (index of last entry, 0-based, so 1 means 2 segments)
        packet.push(0x00); // Flags (8 bits)
        packet.extend_from_slice(&[0x12, 0x34]); // Tag (16 bits)

        // Segment List: 2 IPv6 addresses (16 bytes each = 32 bytes total)
        // First segment (Segment List[0])
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ]);
        // Second segment (Segment List[1])
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x01, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x35,
        ]);

        packet
    }

    // Helper function to create a CRH-16 test packet with 16-bit SIDs
    // This creates a CRH-16 header with 2 SIDs (total packet: 4 + 4 = 8 bytes)
    fn create_crh16_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::new();

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(0); // Hdr Ext Len (0 * 8 = 0 bytes after first 8, total 8 bytes - only fixed header)
        packet.push(3); // Routing Type (Crh16) - enum variant index
        packet.push(1); // Segments Left

        // Reserved bytes to make the header 8 bytes long (minimum IPv6 extension header size)
        packet.extend_from_slice(&[0; 4]);

        packet
    }

    // Helper function to create a CRH-32 test packet
    // This creates a CRH-32 header with no SIDs (minimum size)
    fn create_crh32_test_packet(next: IpProto) -> Vec<u8> {
        let mut packet = Vec::new();

        // Generic routing header (4 bytes)
        packet.push(next as u8); // Next Header
        packet.push(0); // Hdr Ext Len (0 * 8 = 0 bytes after first 8, total 8 bytes - only fixed header)
        packet.push(4); // Routing Type (Crh32) - enum variant index
        packet.push(0); // Segments Left

        // Reserved bytes to make the header 8 bytes long (minimum IPv6 extension header size)
        packet.extend_from_slice(&[0; 4]);

        packet
    }

    // Helper function to create a VXLAN test packet with VNI flag set and valid VNI
    fn create_vxlan_valid_packet() -> Vec<u8> {
        let mut packet = Vec::new();

        // Flags (0x08 to set VNI flag)
        packet.push(0x08);
        // Reserved 24 bits
        packet.extend_from_slice(&[0x00, 0x00, 0x00]);
        // VNI 24 bits (0x123456)
        packet.extend_from_slice(&[0x12, 0x34, 0x56]);
        // Reserved 8 bits
        packet.push(0x00);

        packet
    }

    // Helper function to create a GRE test packet with configurable routing
    fn create_gre_test_packet_with_routing(with_routing: bool) -> Vec<u8> {
        let mut packet = Vec::new();

        if with_routing {
            // GRE header with Routing Present flag set
            packet.push(0x40); // Routing Present: Yes (R=1), Checksum Present: No
            packet.push(0x00); // Version: 0
            packet.extend_from_slice(&[0x08, 0x00]); // Protocol Type: IPv4 (0x0800)

            // Checksum/Offset field (present when R flag is set)
            packet.extend_from_slice(&[0x00, 0x00]); // Checksum: 0 (not used when C=0)
            packet.extend_from_slice(&[0x00, 0x00]); // Offset: 0

            // Routing field with multiple SREs
            // First SRE: Address Family 0x0002 (IP), Length 8 bytes
            packet.extend_from_slice(&[0x00, 0x02]); // Address Family: IP (2)
            packet.push(0x00); // SRE Offset: 0
            packet.push(0x08); // SRE Length: 8 bytes (4 byte header + 4 byte routing info)
            packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // Routing Information (4 bytes)

            // Second SRE: Address Family 0x0003, Length 12 bytes
            packet.extend_from_slice(&[0x00, 0x03]); // Address Family: 3
            packet.push(0x00); // SRE Offset: 0
            packet.push(0x0C); // SRE Length: 12 bytes (4 byte header + 8 byte routing info)
            packet.extend_from_slice(&[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]); // Routing Information (8 bytes)

            // NULL SRE (terminator)
            packet.extend_from_slice(&[0x00, 0x00]); // Address Family: 0 (NULL)
            packet.push(0x00); // SRE Offset: 0
            packet.push(0x00); // SRE Length: 0 (indicates end)
        } else {
            // Basic GRE header without routing
            packet.push(0x00); // Checksum Present: No, Routing Present: No
            packet.push(0x00); // Version: 0
            packet.extend_from_slice(&[0x08, 0x00]); // Protocol Type: IPv4 (0x0800)
        }

        packet
    }

    // #[ignore]
    // #[test]
    // fn test_try_mermin_ipv4_in_ipv4() {
    //     // Build the packet: Eth -> IPv4 (outer) -> IPv4 (inner) -> TCP
    //     let inner_ipv4_packet = create_ipv4_test_packet(); // protocol TCP, len 20
    //     let tcp_packet = create_tcp_test_packet(); // len 20

    //     // Create outer IPv4 header from the same helper
    //     let mut outer_ipv4_packet = create_ipv4_test_packet();
    //     // Set protocol to Ipv4 for IP-in-IP
    //     outer_ipv4_packet[9] = IpProto::Ipv4 as u8;

    //     // Update total length for the outer packet to be correct.
    //     let total_len: u16 = (inner_ipv4_packet.len() + tcp_packet.len()) as u16; // 40 bytes
    //     outer_ipv4_packet[2..4].copy_from_slice(&total_len.to_be_bytes());

    //     // Use different IPs for outer header to distinguish from inner
    //     outer_ipv4_packet[12..16].copy_from_slice(&[10, 0, 0, 1]); // src: 10.0.0.1
    //     outer_ipv4_packet[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst: 10.0.0.2

    //     // Concatenate all parts to form the final packet
    //     let eth_packet = create_eth_test_packet();
    //     let packet: Vec<u8> = [
    //         eth_packet,
    //         outer_ipv4_packet,
    //         inner_ipv4_packet.clone(),
    //         tcp_packet,
    //     ]
    //     .concat();

    //     let ctx = TcContext::new(packet);

    //     // Call try_mermin and get the populated packet_meta
    //     let (_ctx, result) = try_mermin(ctx, Direction::Ingress);
    //     assert!(result.is_ok());
    //     let (_code, packet_meta) = result.unwrap();

    //     // Assert on the parsed metadata
    //     // Verify ifindex is set from test shim
    //     assert_eq!(packet_meta.ifindex, 42);

    //     // Outer IPv4 is the tunnel
    //     assert_eq!(packet_meta.tunnel_ip_addr_type, IpAddrType::Ipv4);
    //     assert_eq!(packet_meta.tunnel_src_ipv4_addr, [10, 0, 0, 1]);
    //     assert_eq!(packet_meta.tunnel_dst_ipv4_addr, [10, 0, 0, 2]);

    //     // Inner IPv4 is the main flow
    //     assert_eq!(packet_meta.ip_addr_type, IpAddrType::Ipv4);
    //     assert_eq!(packet_meta.src_ipv4_addr, [0xc0, 0xa8, 0x01, 0x01]);
    //     assert_eq!(packet_meta.dst_ipv4_addr, [0xc0, 0xa8, 0x01, 0x02]);
    //     assert_eq!(packet_meta.proto, IpProto::Tcp);

    //     // TCP ports from inner packet
    //     assert_eq!(packet_meta.src_port(), 12345);
    //     assert_eq!(packet_meta.dst_port(), 80);

    //     // Tunnel ports are captured before inner L4 header is parsed, so they are 0
    //     assert_eq!(packet_meta.tunnel_src_port(), 0);
    //     assert_eq!(packet_meta.tunnel_dst_port(), 0);
    // }

    // #[ignore]
    // #[test]
    // fn test_try_mermin_ipv4_in_ipv6() {
    //     // Build packet: Eth -> IPv6 (outer) -> IPv4 (inner) -> TCP
    //     let mut eth_for_ipv6_packet = create_eth_test_packet();
    //     eth_for_ipv6_packet[12..14].copy_from_slice(&[0x86, 0xDD]); // EtherType for IPv6

    //     // Outer IPv6 header
    //     let mut outer_ipv6_packet = create_ipv6_test_packet();
    //     outer_ipv6_packet[6] = IpProto::Ipv4 as u8; // Next Header: IPv4

    //     // Inner IPv4 and TCP packets
    //     let inner_ipv4_packet = create_ipv4_test_packet();
    //     let tcp_packet = create_tcp_test_packet();

    //     // Update payload length in outer IPv6 header
    //     let payload_len: u16 = (inner_ipv4_packet.len() + tcp_packet.len()) as u16; // 40 bytes
    //     outer_ipv6_packet[4..6].copy_from_slice(&payload_len.to_be_bytes());

    //     let packet: Vec<u8> = [
    //         eth_for_ipv6_packet,
    //         outer_ipv6_packet.clone(),
    //         inner_ipv4_packet.clone(),
    //         tcp_packet,
    //     ]
    //     .concat();

    //     let ctx = TcContext::new(packet.clone());
    //     let (_ctx, result) = try_mermin(ctx, Direction::Ingress);
    //     assert!(result.is_ok());
    //     let (_code, packet_meta) = result.unwrap();

    //     // Assert on tunnel fields
    //     assert_eq!(packet_meta.tunnel_ip_addr_type, IpAddrType::Ipv6);
    //     let outer_ipv6_hdr: Ipv6Hdr = TcContext::new(packet)
    //         .load(EthHdr::LEN)
    //         .expect("failed to load outer ipv6 header");
    //     assert_eq!(packet_meta.tunnel_src_ipv6_addr, outer_ipv6_hdr.src_addr);
    //     assert_eq!(packet_meta.tunnel_dst_ipv6_addr, outer_ipv6_hdr.dst_addr);

    //     // Assert on inner fields
    //     assert_eq!(packet_meta.ip_addr_type, IpAddrType::Ipv4);
    //     assert_eq!(packet_meta.src_ipv4_addr, [0xc0, 0xa8, 0x01, 0x01]);
    //     assert_eq!(packet_meta.dst_ipv4_addr, [0xc0, 0xa8, 0x01, 0x02]);
    //     assert_eq!(packet_meta.proto, IpProto::Tcp);

    //     // TCP ports
    //     assert_eq!(packet_meta.src_port(), 12345);
    //     assert_eq!(packet_meta.dst_port(), 80);

    //     // Tunnel ports are zero
    //     assert_eq!(packet_meta.tunnel_src_port(), 0);
    //     assert_eq!(packet_meta.tunnel_dst_port(), 0);
    // }

    #[test]
    fn test_parser_initialization() {
        let parser = Parser::default();

        assert_eq!(parser.offset, 0);
        assert!(matches!(parser.next_hdr, HeaderType::Ethernet));

        // Check that packet_meta is initialized with default values
        let packet_meta = PacketMeta::default();
        assert_eq!(packet_meta.src_ipv4_addr, [0, 0, 0, 0]);
        assert_eq!(packet_meta.dst_ipv4_addr, [0, 0, 0, 0]);
        assert_eq!(packet_meta.src_port, [0, 0]);
        assert_eq!(packet_meta.dst_port, [0, 0]);
    }

    #[test]
    fn test_parser_with_options() {
        let parser = Parser::default();
        let options = ParserOptions {
            geneve_port: 8080,
            vxlan_port: 8081,
            wireguard_port: 8082,
        };

        // Verify custom options are set
        assert_eq!(options.geneve_port, 8080);
        assert_eq!(options.vxlan_port, 8081);
        assert_eq!(options.wireguard_port, 8082);

        // Verify other fields have default values
        assert_eq!(parser.offset, 0);
        assert!(matches!(parser.next_hdr, HeaderType::Ethernet));

        // Check that packet_meta is initialized with default values
        let packet_meta = PacketMeta::default();
        assert_eq!(packet_meta.src_ipv4_addr, [0, 0, 0, 0]);
        assert_eq!(packet_meta.dst_ipv4_addr, [0, 0, 0, 0]);
        assert_eq!(packet_meta.src_port, [0, 0]);
        assert_eq!(packet_meta.dst_port, [0, 0]);

        // Test with default port as well
        let default_options = ParserOptions::default();
        assert_eq!(default_options.geneve_port, 6081);
        assert_eq!(default_options.vxlan_port, 4789);
        assert_eq!(default_options.wireguard_port, 51820);
    }

    #[test]
    fn test_parser_calculate_l3_octet_count() {
        let mut parser = Parser::default();

        parser.offset = 32;
        let l3_count = parser.calc_l3_octet_count(256);

        assert_eq!(l3_count, 224);
    }

    #[test]
    fn test_parse_ethernet_header() {
        let mut parser = Parser::default();
        let packet = create_eth_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_ethernet_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, ETH_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Ipv4));
    }

    #[test]
    fn test_parse_ethernet_header_unsupported() {
        let mut parser = Parser::default();
        let packet = create_eth_test_packet_unsupported();
        let ctx = TcContext::new(packet);

        let result = parser.parse_ethernet_header(&ctx);

        assert!(result.is_ok());
        assert!(matches!(result, Err(Error::Unsupported)));
        assert_eq!(parser.offset, ETH_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Ethernet));
    }

    #[test]
    fn test_parse_ipv4_header() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Ipv4;
        let packet = create_ipv4_test_packet();
        let ctx = TcContext::new(packet);
        let result = parser.parse_ipv4_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 20); // IPv4 header length (5 * 4 bytes)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_ipv4_header_invalid_length() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Ipv4;
        let mut packet = create_ipv4_test_packet();
        // Change IHL to invalid value (0)
        packet[0] = 0x40; // Version 4, IHL 0
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv4_header(&ctx);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ipv6_header() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Ipv6;
        let packet = create_ipv6_test_packet();
        let ctx = TcContext::new(packet);
        let result = parser.parse_ipv6_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, IPV6_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_tcp_header() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Tcp);
        let packet = create_tcp_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_tcp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, TCP_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    #[test]
    fn test_parse_udp_header() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Udp);
        let packet = create_udp_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_udp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, UDP_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    #[test]
    fn test_parse_udp_header_geneve() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Udp);
        let packet = create_udp_geneve_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_udp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, UDP_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Geneve));
    }

    #[test]
    fn test_parse_ah_header_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ah);
        let packet = create_ah_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet);

        let result = parser.parse_ah_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, AH_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_ah_header_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ah);
        let packet = create_ah_test_packet(IpProto::Udp);
        let ctx = TcContext::new(packet);

        let result = parser.parse_ah_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, AH_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    #[test]
    fn test_parse_ah_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ah);
        // Provide fewer than 12 bytes
        let packet = vec![0x06, 0x01, 0x00, 0x00, 0x12, 0x34];
        let ctx = TcContext::new(packet);

        let result = parser.parse_ah_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    #[test]
    fn test_parse_esp_header() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Esp);
        let packet = create_esp_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_esp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, ESP_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    #[test]
    fn test_parse_esp_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Esp);
        // Provide fewer than 8 bytes
        let packet = vec![0x12, 0x34, 0x56, 0x78];
        let ctx = TcContext::new(packet);

        let result = parser.parse_esp_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    #[test]
    fn test_parse_fragment_header_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Frag);
        let packet = create_fragment_test_packet(IpProto::Tcp, 0x1234, true, 0x89ABCDEF);
        let ctx = TcContext::new(packet);

        let result = parser.parse_fragment_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, FRAGMENT_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_fragment_header_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Frag);
        let packet = create_fragment_test_packet(IpProto::Udp, 0x0001, false, 0x10203040);
        let ctx = TcContext::new(packet);

        let result = parser.parse_fragment_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, FRAGMENT_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    #[test]
    fn test_parse_fragment_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Frag);
        // Provide fewer than 8 bytes
        let packet = vec![0x00, 0x00, 0x00, 0x00];
        let ctx = TcContext::new(packet);

        let result = parser.parse_fragment_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    #[test]
    fn test_parse_mobility_header_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::MobilityHeader);
        // Hdr Ext Len = 0 -> total 8 bytes
        let packet = create_mobility_test_packet(IpProto::Tcp, 0, 5);
        let ctx = TcContext::new(packet);

        let result = parser.parse_mobility_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 8);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_mobility_header_with_ext_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::MobilityHeader);
        // Hdr Ext Len = 2 -> total 24 bytes
        let packet = create_mobility_test_packet(IpProto::Udp, 2, 1);
        let ctx = TcContext::new(packet);

        let result = parser.parse_mobility_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 24);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    #[test]
    fn test_parse_mobility_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::MobilityHeader);
        // Provide fewer than 8 bytes
        let packet = vec![0x06, 0x00, 0x00, 0x00];
        let ctx = TcContext::new(packet);

        let result = parser.parse_mobility_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    #[test]
    fn test_parse_hop_header_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::HopOpt);
        let packet = create_hop_test_packet(IpProto::Tcp, 0);
        let ctx = TcContext::new(packet);

        let result = parser.parse_hopopt_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, HOP_OPT_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_hop_header_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::HopOpt);
        let packet = create_hop_test_packet(IpProto::Udp, 0);
        let ctx = TcContext::new(packet);

        let result = parser.parse_hopopt_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, HOP_OPT_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    #[test]
    fn test_parse_hop_header_with_extension() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::HopOpt);
        let packet = create_hop_test_packet(IpProto::Tcp, 1);
        let ctx = TcContext::new(packet);

        let result = parser.parse_hopopt_header(&ctx);
        assert!(result.is_ok());
        assert_eq!(parser.offset, 16);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_hop_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::HopOpt);
        // Provide fewer than 8 bytes
        let packet = vec![0x06, 0x00, 0x01, 0x02];
        let ctx = TcContext::new(packet);

        let result = parser.parse_hopopt_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    #[test]
    fn test_parse_destopts_header_tcp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Opts);
        let packet = create_destopts_test_packet(IpProto::Tcp, 0);
        let ctx = TcContext::new(packet);

        let result = parser.parse_destopts_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, destopts::total_hdr_len(0)); // hdr_ext_len=0 from packet, so total is 8
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_destopts_header_udp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Opts);
        let packet = create_destopts_test_packet(IpProto::Udp, 0);
        let ctx = TcContext::new(packet);

        let result = parser.parse_destopts_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, destopts::total_hdr_len(0)); // hdr_ext_len=0 from packet, so total is 8
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    #[test]
    fn test_parse_destopts_header_with_extension() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Opts);
        let packet = create_destopts_test_packet(IpProto::Tcp, 1);
        let ctx = TcContext::new(packet);

        let result = parser.parse_destopts_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 16); // 8 + 8 for hdr_ext_len=1
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_destopts_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Opts);
        // Provide fewer than 8 bytes
        let packet = vec![0x06, 0x00, 0x01, 0x02];
        let ctx = TcContext::new(packet);

        let result = parser.parse_destopts_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    #[test]
    fn test_parse_shim6_header_basic() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Shim6);
        let packet = create_shim6_test_packet(IpProto::Ipv6NoNxt, 0);
        let ctx = TcContext::new(packet);

        let result = parser.parse_shim6_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, SHIM6_LEN);
        assert!(matches!(
            parser.next_hdr,
            HeaderType::Proto(IpProto::Ipv6NoNxt)
        ));
    }

    #[test]
    fn test_parse_shim6_header_with_extension() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Shim6);
        let packet = create_shim6_test_packet(IpProto::Tcp, 2); // total 24 bytes
        let ctx = TcContext::new(packet);

        let result = parser.parse_shim6_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 24);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_shim6_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Shim6);
        // fewer than 8 bytes
        let packet = vec![0x00, 0x00, 0x00, 0x00];
        let ctx = TcContext::new(packet);

        let result = parser.parse_shim6_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    #[test]
    fn test_parse_geneve_header_ipv4() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x0800, 0); // IPv4 protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, GENEVE_LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::Ipv4));
    }

    #[test]
    fn test_parse_geneve_header_ipv6() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x86DD, 0); // IPv6 protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, GENEVE_LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::Ipv6));
    }

    #[test]
    fn test_parse_geneve_header_ethernet() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x6558, 0); // Ethernet protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, GENEVE_LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::Ethernet));
    }

    #[test]
    fn test_parse_geneve_header_with_options() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x0800, 2); // IPv4 protocol type, 2 option units (8 bytes)
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, GENEVE_LEN + 8); // Header length + 8 bytes of options
        assert!(matches!(parser.next_hdr, HeaderType::Ipv4));
    }

    #[test]
    fn test_parse_geneve_header_unsupported_protocol() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        let packet = create_geneve_test_packet(0x1234, 0); // Unsupported protocol type, no options
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, GENEVE_LEN); // No options, so offset is just the header length
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    #[test]
    fn test_parse_geneve_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Geneve;
        // Provide fewer than 8 bytes (Geneve header length)
        let packet = vec![0x00, 0x00, 0x08, 0x00, 0x12, 0x34];
        let ctx = TcContext::new(packet);

        let result = parser.parse_geneve_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    #[test]
    fn test_parse_hip_header_basic() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Hip);
        // Base HIP header is 40 bytes => hdr_len = 4
        let packet = create_hip_test_packet(IpProto::Ipv6NoNxt, 4);
        let ctx = TcContext::new(packet);

        let result = parser.parse_hip_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, HIP_LEN);
        assert!(matches!(
            parser.next_hdr,
            HeaderType::Proto(IpProto::Ipv6NoNxt)
        ));
    }

    #[test]
    fn test_parse_hip_header_with_params() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Hip);
        // Add 16 bytes of params => hdr_len = ((40+16)/8)-1 = 6
        let packet = create_hip_test_packet(IpProto::Tcp, 6);
        let ctx = TcContext::new(packet);

        let result = parser.parse_hip_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, (6 + 1) * 8);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_hip_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Hip);
        // fewer than required to load HipHdr (40 bytes)
        let packet = vec![0u8; 16];
        let ctx = TcContext::new(packet);

        let result = parser.parse_hip_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    #[test]
    fn test_parse_icmp_header() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Icmp);
        let packet = create_icmp_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_icmp_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, ICMP_LEN);
        // ICMP doesn't use ports, so they should remain zero
        // Note: ICMP doesn't modify packet_meta ports, they remain default [0, 0]
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    #[test]
    fn test_parse_icmp_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Icmp);
        // Provide fewer than 8 bytes (ICMP header length)
        let packet = vec![0x08, 0x00, 0x12, 0x34];
        let ctx = TcContext::new(packet);

        let result = parser.parse_icmp_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    #[test]
    fn test_parse_ipv4_header_with_icmp() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Ipv4;
        let mut packet = create_ipv4_test_packet();
        // Change protocol from TCP (6) to ICMP (1)
        packet[9] = 0x01; // Protocol field in IPv4 header
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv4_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 20); // IPv4 header length (5 * 4 bytes)
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Icmp)));
        // IPv4 header parsing validation removed - parse functions no longer populate packet_meta
    }

    #[test]
    fn test_parse_ipv6_header_with_icmpv6() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Ipv6;
        let mut packet = create_ipv6_test_packet();
        // Change next header from TCP (6) to ICMPv6 (58)
        packet[6] = 58; // Next Header field in IPv6 header
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv6_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, IPV6_LEN);
        assert!(matches!(
            parser.next_hdr,
            HeaderType::Proto(IpProto::Ipv6Icmp)
        ));
        // IPv6 header parsing validation removed - parse functions no longer populate packet_meta
    }

    #[test]
    fn test_parse_vxlan_valid_header() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Vxlan;

        let packet = create_vxlan_valid_packet();
        let ctx = TcContext::new(packet);
        let result = parser.parse_vxlan_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, VXLAN_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Ethernet));
    }

    #[test]
    fn test_parse_generic_header_type2() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_type2_routing_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet);

        let result = parser.parse_generic_route_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 24);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_generic_header_rpl() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_rpl_source_route_test_packet(IpProto::Udp);
        let ctx = TcContext::new(packet);

        let result = parser.parse_generic_route_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 40);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    #[test]
    fn test_parse_generic_header_segment_routing() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_segment_routing_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet);

        let result = parser.parse_generic_route_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 40);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_generic_header_crh16() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_crh16_test_packet(IpProto::Tcp);
        let ctx = TcContext::new(packet);

        let result = parser.parse_generic_route_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 8);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_generic_header_crh32() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        let packet = create_crh32_test_packet(IpProto::Udp);
        let ctx = TcContext::new(packet);

        let result = parser.parse_generic_route_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, 8);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Udp)));
    }

    #[test]
    fn test_parse_generic_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6Route);
        // Provide fewer than 4 bytes (GenericRoute::LEN)
        let packet = vec![0x06, 0x01];
        let ctx = TcContext::new(packet);

        let result = parser.parse_generic_route_header(&ctx);
        assert!(matches!(result, Err(Error::OutOfBounds)));
    }

    #[test]
    fn test_ip_addr_type_usage() {
        // Test IpAddrType usage to cover the import
        let ipv4_type = IpAddrType::Ipv4;
        let ipv6_type = IpAddrType::Ipv6;
        let default_type = IpAddrType::default();

        assert!(matches!(ipv4_type, IpAddrType::Ipv4));
        assert!(matches!(ipv6_type, IpAddrType::Ipv6));
        assert!(matches!(default_type, IpAddrType::Ipv4)); // Default is Ipv4

        // Test in PacketMeta context
        let mut packet_meta = PacketMeta::default();
        packet_meta.ip_addr_type = ipv4_type;
        assert!(matches!(packet_meta.ip_addr_type, IpAddrType::Ipv4));

        packet_meta.tunnel_ip_addr_type = ipv6_type;
        assert!(matches!(packet_meta.tunnel_ip_addr_type, IpAddrType::Ipv6));
    }

    #[test]
    fn test_parse_gre_header() {
        {
            let mut parser = Parser::default();
            parser.next_hdr = HeaderType::Proto(IpProto::Gre);
            let packet = create_gre_test_packet_with_routing(false);
            let ctx = TcContext::new(packet);

            let result = parser.parse_gre_header(&ctx);

            assert!(result.is_ok());
            assert_eq!(parser.offset, GRE_LEN); // Only fixed header
            assert!(matches!(parser.next_hdr, HeaderType::Ipv4));
        }

        {
            let mut parser = Parser::default();
            parser.next_hdr = HeaderType::Proto(IpProto::Gre);
            let packet = create_gre_test_packet_with_routing(true);
            let ctx = TcContext::new(packet.clone());

            let result = parser.parse_gre_header(&ctx);

            assert!(result.is_ok());
            // Expected offset: 4 (fixed header) + 4 (checksum/offset) + 8 (first SRE) + 12 (second SRE) + 4 (NULL SRE) = 32
            assert_eq!(parser.offset, 32);
            assert!(matches!(parser.next_hdr, HeaderType::Ipv4));

            // Verify the packet structure matches our expectations
            assert_eq!(packet.len(), 32);
            assert_eq!(packet[0], 0x40); // R flag set
            assert_eq!(packet[4], 0x00); // Checksum field start
            assert_eq!(packet[8], 0x00); // First SRE address family high byte
            assert_eq!(packet[9], 0x02); // First SRE address family low byte (IP)
            assert_eq!(packet[11], 0x08); // First SRE length
        }
    }

    // #[ignore]
    // #[test]
    // fn test_try_mermin_ipv6_in_ipv6() {
    //     // Eth (IPv6) -> IPv6 (outer, Next=IPv6) -> IPv6 (inner, Next=TCP) -> TCP
    //     let mut eth = create_eth_test_packet();
    //     // Set EtherType to IPv6
    //     eth[12..14].copy_from_slice(&[0x86, 0xDD]);

    //     let mut outer_v6 = create_ipv6_test_packet();
    //     outer_v6[6] = IpProto::Ipv6 as u8; // Next header: IPv6

    //     let mut inner_v6 = create_ipv6_test_packet();
    //     inner_v6[6] = IpProto::Tcp as u8; // ensure inner says TCP
    //     let tcp = create_tcp_test_packet();

    //     // Update payload lengths
    //     let inner_payload_len: u16 = (inner_v6.len() + tcp.len()) as u16; // 40 + 20
    //     inner_v6[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    //     outer_v6[4..6].copy_from_slice(&inner_payload_len.to_be_bytes());

    //     let packet: Vec<u8> = [eth, outer_v6.clone(), inner_v6.clone(), tcp].concat();
    //     let ctx = TcContext::new(packet.clone());
    //     let (_ctx, result) = try_mermin(ctx, Direction::Ingress);
    //     assert!(result.is_ok());
    //     let (_code, packet_meta) = result.unwrap();

    //     // Tunnel is outer IPv6
    //     let outer_hdr: Ipv6Hdr = TcContext::new(packet).load(EthHdr::LEN).unwrap();
    //     assert_eq!(packet_meta.tunnel_ip_addr_type, IpAddrType::Ipv6);
    //     assert_eq!(packet_meta.tunnel_src_ipv6_addr, outer_hdr.src_addr);
    //     assert_eq!(packet_meta.tunnel_dst_ipv6_addr, outer_hdr.dst_addr);

    //     // Flow is inner IPv6
    //     assert_eq!(packet_meta.ip_addr_type, IpAddrType::Ipv6);
    //     assert_eq!(packet_meta.src_ipv6_addr, inner_v6[8..24]);
    //     assert_eq!(packet_meta.dst_ipv6_addr, inner_v6[24..40]);
    //     assert_eq!(packet_meta.proto, IpProto::Tcp);
    //     assert_eq!(packet_meta.src_port(), 12345);
    //     assert_eq!(packet_meta.dst_port(), 80);

    //     // Tunnel L4 ports are not set for IP-in-IP
    //     assert_eq!(packet_meta.tunnel_src_port(), 0);
    //     assert_eq!(packet_meta.tunnel_dst_port(), 0);
    // }

    // #[ignore]
    // #[test]
    // fn test_try_mermin_ipv6_in_ipv4() {
    //     // Eth (IPv4) -> IPv4 (outer, proto=IPv6) -> IPv6 (inner, Next=TCP) -> TCP
    //     let eth = create_eth_test_packet(); // EtherType already IPv4

    //     let mut outer_v4 = create_ipv4_test_packet();
    //     outer_v4[9] = IpProto::Ipv6 as u8; // Protocol: IPv6
    //     // Give outer different addresses
    //     outer_v4[12..16].copy_from_slice(&[10, 0, 0, 1]);
    //     outer_v4[16..20].copy_from_slice(&[10, 0, 0, 2]);

    //     let mut inner_v6 = create_ipv6_test_packet();
    //     inner_v6[6] = IpProto::Tcp as u8;
    //     let tcp = create_tcp_test_packet();

    //     // lengths
    //     inner_v6[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    //     let total_len_v4: u16 = (inner_v6.len() + tcp.len()) as u16;
    //     outer_v4[2..4].copy_from_slice(&total_len_v4.to_be_bytes());

    //     let packet: Vec<u8> = [eth, outer_v4.clone(), inner_v6.clone(), tcp].concat();
    //     let ctx = TcContext::new(packet);
    //     let (_ctx, result) = try_mermin(ctx, Direction::Ingress);
    //     assert!(result.is_ok());
    //     let (_code, packet_meta) = result.unwrap();

    //     // Tunnel is outer IPv4
    //     assert_eq!(packet_meta.tunnel_ip_addr_type, IpAddrType::Ipv4);
    //     assert_eq!(packet_meta.tunnel_src_ipv4_addr, [10, 0, 0, 1]);
    //     assert_eq!(packet_meta.tunnel_dst_ipv4_addr, [10, 0, 0, 2]);

    //     // Flow is inner IPv6
    //     assert_eq!(packet_meta.ip_addr_type, IpAddrType::Ipv6);
    //     assert_eq!(
    //         packet_meta.src_ipv6_addr,
    //         [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    //     );
    //     assert_eq!(
    //         packet_meta.dst_ipv6_addr,
    //         [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    //     );
    //     assert_eq!(packet_meta.proto, IpProto::Tcp);
    //     assert_eq!(packet_meta.src_port(), 12345);
    //     assert_eq!(packet_meta.dst_port(), 80);
    //     assert_eq!(packet_meta.tunnel_src_port(), 0);
    //     assert_eq!(packet_meta.tunnel_dst_port(), 0);
    // }

    // #[ignore]
    // #[test]
    // fn test_try_mermin_ipv6_in_ipv6_in_ipv6() {
    //     // Eth (IPv6) -> v6 outer (Next=IPv6) -> v6 middle (Next=IPv6) -> v6 inner (Next=TCP) -> TCP
    //     let mut eth = create_eth_test_packet();
    //     eth[12..14].copy_from_slice(&[0x86, 0xDD]);

    //     let mut outer = create_ipv6_test_packet();
    //     outer[6] = IpProto::Ipv6 as u8;
    //     // Outer addresses different for clarity
    //     outer[8..24].copy_from_slice(&[
    //         0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11,
    //     ]);
    //     outer[24..40].copy_from_slice(&[
    //         0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22,
    //     ]);

    //     let mut middle = create_ipv6_test_packet();
    //     middle[6] = IpProto::Ipv6 as u8;
    //     middle[8..24].copy_from_slice(&[
    //         0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x33,
    //     ]);
    //     middle[24..40].copy_from_slice(&[
    //         0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44,
    //     ]);

    //     let mut inner = create_ipv6_test_packet();
    //     inner[6] = IpProto::Tcp as u8;
    //     let tcp = create_tcp_test_packet();

    //     // Set lengths
    //     inner[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    //     let middle_payload: u16 = (inner.len() + tcp.len()) as u16;
    //     middle[4..6].copy_from_slice(&middle_payload.to_be_bytes());
    //     // More simply, outer payload is middle header + payload that follows it
    //     let outer_payload: u16 = (middle.len() + inner.len() + tcp.len()) as u16; // middle + inner + tcp
    //     outer[4..6].copy_from_slice(&outer_payload.to_be_bytes());

    //     let packet: Vec<u8> = [eth, outer.clone(), middle.clone(), inner.clone(), tcp].concat();
    //     let ctx = TcContext::new(packet);
    //     let (_ctx, result) = try_mermin(ctx, Direction::Ingress);
    //     assert!(result.is_ok());
    //     let (_code, packet_meta) = result.unwrap();

    //     // Tunnel from outer
    //     assert_eq!(packet_meta.tunnel_ip_addr_type, IpAddrType::Ipv6);
    //     assert_eq!(packet_meta.tunnel_src_ipv6_addr, &outer[8..24]);
    //     assert_eq!(packet_meta.tunnel_dst_ipv6_addr, &outer[24..40]);
    //     // Flow from inner; middle ignored
    //     assert_eq!(packet_meta.ip_addr_type, IpAddrType::Ipv6);
    //     assert_eq!(packet_meta.src_ipv6_addr, &inner[8..24]);
    //     assert_eq!(packet_meta.dst_ipv6_addr, &inner[24..40]);
    //     assert_eq!(packet_meta.proto, IpProto::Tcp);
    // }

    // #[ignore]
    // #[test]
    // fn test_try_mermin_ipv4_in_ipv4_in_ipv4() {
    //     // Eth (IPv4) -> v4 outer (proto=IPv4) -> v4 middle (proto=IPv4) -> v4 inner (proto=TCP) -> TCP
    //     let eth = create_eth_test_packet();

    //     let mut outer = create_ipv4_test_packet();
    //     outer[9] = IpProto::Ipv4 as u8;
    //     outer[12..16].copy_from_slice(&[10, 0, 0, 1]);
    //     outer[16..20].copy_from_slice(&[10, 0, 0, 2]);

    //     let mut middle = create_ipv4_test_packet();
    //     middle[9] = IpProto::Ipv4 as u8;
    //     middle[12..16].copy_from_slice(&[172, 16, 0, 1]);
    //     middle[16..20].copy_from_slice(&[172, 16, 0, 2]);

    //     let inner = create_ipv4_test_packet(); // proto=TCP
    //     let tcp = create_tcp_test_packet();

    //     // lengths
    //     let middle_len: u16 = (inner.len() + tcp.len()) as u16;
    //     middle[2..4].copy_from_slice(&middle_len.to_be_bytes());
    //     let outer_len: u16 = (middle.len() + inner.len() + tcp.len()) as u16;
    //     outer[2..4].copy_from_slice(&outer_len.to_be_bytes());

    //     let packet: Vec<u8> = [eth, outer.clone(), middle, inner.clone(), tcp].concat();
    //     let ctx = TcContext::new(packet);
    //     let (_ctx, result) = try_mermin(ctx, Direction::Ingress);
    //     assert!(result.is_ok());
    //     let (_code, packet_meta) = result.unwrap();

    //     // Tunnel from outer
    //     assert_eq!(packet_meta.tunnel_ip_addr_type, IpAddrType::Ipv4);
    //     assert_eq!(packet_meta.tunnel_src_ipv4_addr, [10, 0, 0, 1]);
    //     assert_eq!(packet_meta.tunnel_dst_ipv4_addr, [10, 0, 0, 2]);
    //     // Flow from inner
    //     assert_eq!(packet_meta.ip_addr_type, IpAddrType::Ipv4);
    //     assert_eq!(packet_meta.src_ipv4_addr, [0xc0, 0xa8, 0x01, 0x01]);
    //     assert_eq!(packet_meta.dst_ipv4_addr, [0xc0, 0xa8, 0x01, 0x02]);
    //     assert_eq!(packet_meta.proto, IpProto::Tcp);
    //     assert_eq!(packet_meta.src_port(), 12345);
    //     assert_eq!(packet_meta.dst_port(), 80);
    // }

    // #[ignore]
    // #[test]
    // fn test_try_mermin_vxlan_tunnel() {
    //     // Eth (IPv4) -> IPv4 (proto=UDP) -> UDP(dst=4789) -> VXLAN -> Eth(inner) -> IPv4 -> TCP
    //     let eth = create_eth_test_packet(); // IPv4 outer

    //     let mut outer_v4 = create_ipv4_test_packet();
    //     outer_v4[9] = IpProto::Udp as u8;
    //     // Outer IPs
    //     outer_v4[12..16].copy_from_slice(&[192, 0, 2, 1]);
    //     outer_v4[16..20].copy_from_slice(&[192, 0, 2, 2]);

    //     // UDP with dst port 4789
    //     let mut udp = vec![0u8; 8];
    //     udp[0..2].copy_from_slice(&[0x30, 0x39]); // src 12345
    //     udp[2..4].copy_from_slice(&[0x12, 0xB5]); // 4789
    //     udp[4..6].copy_from_slice(&(8u16).to_be_bytes());
    //     // checksum left 0

    //     // VXLAN header (valid)
    //     let vxlan = create_vxlan_valid_packet();

    //     // Inner Ethernet + IPv4 + TCP
    //     let inner_eth = create_eth_test_packet(); // already IPv4 EtherType
    //     let inner_v4 = create_ipv4_test_packet();
    //     let tcp = create_tcp_test_packet();

    //     // Fix outer IPv4 total length = UDP + VXLAN + inner_eth + inner_v4 + tcp
    //     let tot_len =
    //         (udp.len() + vxlan.len() + inner_eth.len() + inner_v4.len() + tcp.len()) as u16;
    //     outer_v4[2..4].copy_from_slice(&tot_len.to_be_bytes());

    //     let packet: Vec<u8> = [
    //         eth,
    //         outer_v4.clone(),
    //         udp.clone(),
    //         vxlan.clone(),
    //         inner_eth,
    //         inner_v4.clone(),
    //         tcp,
    //     ]
    //     .concat();
    //     let ctx = TcContext::new(packet);
    //     let (_ctx, result) = try_mermin(ctx, Direction::Ingress);
    //     assert!(result.is_ok());
    //     let (_code, packet_meta) = result.unwrap();

    //     // Tunnel should be outer IPv4 + UDP ports
    //     assert_eq!(packet_meta.tunnel_ip_addr_type, IpAddrType::Ipv4);
    //     assert_eq!(packet_meta.tunnel_src_ipv4_addr, [192, 0, 2, 1]);
    //     assert_eq!(packet_meta.tunnel_dst_ipv4_addr, [192, 0, 2, 2]);
    //     assert_eq!(packet_meta.tunnel_src_port(), 12345);
    //     assert_eq!(packet_meta.tunnel_dst_port(), 4789);

    //     // Flow should be inner IPv4/TCP
    //     assert_eq!(packet_meta.ip_addr_type, IpAddrType::Ipv4);
    //     assert_eq!(packet_meta.src_ipv4_addr, [0xc0, 0xa8, 0x01, 0x01]);
    //     assert_eq!(packet_meta.dst_ipv4_addr, [0xc0, 0xa8, 0x01, 0x02]);
    //     assert_eq!(packet_meta.proto, IpProto::Tcp);
    //     assert_eq!(packet_meta.src_port(), 12345);
    //     assert_eq!(packet_meta.dst_port(), 80);
    // }

    // #[ignore]
    // #[test]
    // fn test_try_mermin_geneve_tunnel() {
    //     // Eth (IPv4) -> IPv4 (proto=UDP) -> UDP(dst=6081) -> Geneve(proto=IPv4) -> IPv4 -> TCP
    //     let eth = create_eth_test_packet();

    //     let mut outer_v4 = create_ipv4_test_packet();
    //     outer_v4[9] = IpProto::Udp as u8;
    //     outer_v4[12..16].copy_from_slice(&[198, 51, 100, 1]);
    //     outer_v4[16..20].copy_from_slice(&[198, 51, 100, 2]);

    //     // UDP with dst = 6081
    //     let mut udp = vec![0u8; 8];
    //     udp[0..2].copy_from_slice(&[0x30, 0x39]); // src 12345
    //     udp[2..4].copy_from_slice(&[0x17, 0xC1]); // 6081
    //     udp[4..6].copy_from_slice(&(8u16).to_be_bytes());

    //     // Geneve header declaring inner IPv4, no options
    //     let geneve = create_geneve_test_packet(0x0800, 0);

    //     let inner_v4 = create_ipv4_test_packet();
    //     let tcp = create_tcp_test_packet();

    //     // outer length = UDP + Geneve + inner_v4 + tcp
    //     let tot_len = (udp.len() + geneve.len() + inner_v4.len() + tcp.len()) as u16;
    //     outer_v4[2..4].copy_from_slice(&tot_len.to_be_bytes());

    //     let packet: Vec<u8> = [
    //         eth,
    //         outer_v4.clone(),
    //         udp.clone(),
    //         geneve.clone(),
    //         inner_v4.clone(),
    //         tcp,
    //     ]
    //     .concat();
    //     let ctx = TcContext::new(packet);
    //     let (_ctx, result) = try_mermin(ctx, Direction::Ingress);
    //     assert!(result.is_ok());
    //     let (_code, packet_meta) = result.unwrap();

    //     // Tunnel is outer IPv4 + UDP ports
    //     assert_eq!(packet_meta.tunnel_ip_addr_type, IpAddrType::Ipv4);
    //     assert_eq!(packet_meta.tunnel_src_ipv4_addr, [198, 51, 100, 1]);
    //     assert_eq!(packet_meta.tunnel_dst_ipv4_addr, [198, 51, 100, 2]);
    //     assert_eq!(packet_meta.tunnel_src_port(), 12345);
    //     assert_eq!(packet_meta.tunnel_dst_port(), 6081);

    //     // Flow is inner IPv4/TCP
    //     assert_eq!(packet_meta.ip_addr_type, IpAddrType::Ipv4);
    //     assert_eq!(packet_meta.src_ipv4_addr, [0xc0, 0xa8, 0x01, 0x01]);
    //     assert_eq!(packet_meta.dst_ipv4_addr, [0xc0, 0xa8, 0x01, 0x02]);
    //     assert_eq!(packet_meta.proto, IpProto::Tcp);
    //     assert_eq!(packet_meta.src_port(), 12345);
    //     assert_eq!(packet_meta.dst_port(), 80);
    // }

    // #[test]
    // fn test_try_mermin_vxlan_tcp_flags() {
    //     // Test different TCP flags within VXLAN tunnels
    //     let tcp_flags = [0x02, 0x10, 0x12, 0x18, 0x01]; // SYN, ACK, SYN+ACK, PSH+ACK, FIN

    //     for flags in tcp_flags {
    //         // Eth -> IPv4 -> UDP -> VXLAN -> Eth -> IPv4 -> TCP
    //         let eth = create_eth_test_packet();

    //         let mut outer_ipv4 = create_ipv4_test_packet();
    //         outer_ipv4[9] = IpProto::Udp as u8;
    //         outer_ipv4[12..16].copy_from_slice(&[192, 0, 2, 1]);
    //         outer_ipv4[16..20].copy_from_slice(&[192, 0, 2, 2]);

    //         // UDP with VXLAN port
    //         let mut udp = vec![0u8; 8];
    //         udp[0..2].copy_from_slice(&[0x30, 0x39]); // src 12345
    //         udp[2..4].copy_from_slice(&[0x12, 0xB5]); // dst 4789 (VXLAN)
    //         udp[4..6].copy_from_slice(&(8u16).to_be_bytes());

    //         let vxlan = create_vxlan_valid_packet();

    //         // Inner Ethernet
    //         let mut inner_eth = create_eth_test_packet();
    //         inner_eth[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4

    //         // Inner IPv4
    //         let inner_ipv4 = create_ipv4_test_packet();

    //         // Inner TCP with specific flags
    //         let mut inner_tcp = create_tcp_test_packet();
    //         inner_tcp[13] = flags;

    //         // Update lengths
    //         let inner_payload_len = inner_ipv4.len() + inner_tcp.len();
    //         let inner_eth_len = inner_eth.len() + inner_payload_len;
    //         let vxlan_payload_len = inner_eth_len;
    //         let udp_len = 8 + 8 + vxlan_payload_len; // UDP header + VXLAN header + payload
    //         let outer_ipv4_len = 20 + udp_len;

    //         // Update packet lengths
    //         let mut outer_ipv4_copy = outer_ipv4.clone();
    //         outer_ipv4_copy[2..4].copy_from_slice(&(outer_ipv4_len as u16).to_be_bytes());
    //         udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());

    //         let packet: Vec<u8> = [
    //             eth,
    //             outer_ipv4_copy,
    //             udp,
    //             vxlan,
    //             inner_eth,
    //             inner_ipv4,
    //             inner_tcp,
    //         ]
    //         .concat();

    //         let ctx = TcContext::new(packet);
    //         let (_ctx, result) = try_mermin(ctx, Direction::Ingress);

    //         assert!(result.is_ok(), "Failed for TCP flags: 0x{:02x}", flags);
    //         let (action, packet_meta) = result.unwrap();
    //         assert_eq!(action, TC_ACT_PIPE);
    //         assert_eq!(packet_meta.tcp_flags, flags);
    //     }
    // }
    // }

    #[test]
    fn test_parse_wireguard_init() {
        let mut parser = Parser::default();
        let packet = create_wireguard_init_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_init(&ctx);
        assert!(result.is_ok());
        assert_eq!(parser.offset, WIREGUARD_INITIATION_LEN);
        // Note: Function now returns () to reduce stack usage
        // Detailed field validation has been removed to optimize for eBPF verification
    }

    #[test]
    fn test_parse_wireguard_response() {
        let mut parser = Parser::default();
        let packet = create_wireguard_response_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_response(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, WIREGUARD_RESPONSE_LEN);
        // Note: Function now returns () to reduce stack usage
        // Detailed field validation has been removed to optimize for eBPF verification
    }

    #[test]
    fn test_parse_wireguard_cookie_reply() {
        let mut parser = Parser::default();
        let packet = create_wireguard_cookie_reply_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_cookie_reply(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, WIREGUARD_COOKIE_REPLY_LEN);
        // Note: Function now returns () to reduce stack usage
        // Detailed field validation has been removed to optimize for eBPF verification
    }

    #[test]
    fn test_parse_wireguard_transport_data() {
        let mut parser = Parser::default();
        let packet = create_wireguard_transport_data_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_transport_data(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, WIREGUARD_TRANSPORT_DATA_LEN);
        // Note: Function now returns () to reduce stack usage
        // Detailed field validation has been removed to optimize for eBPF verification
    }

    #[test]
    fn test_parse_wireguard_init_out_of_bounds() {
        let mut parser = Parser::default();
        // Create a packet that's too short for WireGuard Initiation
        let packet = vec![0u8; 10]; // Much shorter than 148 bytes needed
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_init(&ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::OutOfBounds);
    }

    #[test]
    fn test_parse_wireguard_response_out_of_bounds() {
        let mut parser = Parser::default();
        // Create a packet that's too short for WireGuard Response
        let packet = vec![0u8; 10]; // Much shorter than 92 bytes needed
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_response(&ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::OutOfBounds);
    }

    #[test]
    fn test_parse_wireguard_cookie_reply_out_of_bounds() {
        let mut parser = Parser::default();
        // Create a packet that's too short for WireGuard Cookie Reply
        let packet = vec![0u8; 10]; // Much shorter than 48 bytes needed
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_cookie_reply(&ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::OutOfBounds);
    }

    #[test]
    fn test_parse_wireguard_transport_data_out_of_bounds() {
        let mut parser = Parser::default();
        // Create a packet that's too short for WireGuard Transport Data
        let packet = vec![0u8; 10]; // Much shorter than 16 bytes needed
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_transport_data(&ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::OutOfBounds);
    }

    #[test]
    fn test_parse_ipv4_encap() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv4);
        let packet = create_ipv4_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv4_encap(&ctx);

        assert!(result.is_ok());
        // IHL=5 means 5*4=20 bytes header length
        assert_eq!(parser.offset, 20);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_ipv4_encap_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv4);
        let packet = vec![0u8; 10]; // Too short for IPv4 header
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv4_encap(&ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::OutOfBounds);
    }

    #[test]
    fn test_parse_ipv4_encap_invalid_header_length() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv4);
        let mut packet = create_ipv4_test_packet();
        // Set IHL to 3 (12 bytes), which is less than minimum 20 bytes
        packet[0] = 0x43;
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv4_encap(&ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::MalformedHeader);
    }

    #[test]
    fn test_parse_ipv6_encap() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6);
        let packet = create_ipv6_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv6_encap(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, IPV6_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::Proto(IpProto::Tcp)));
    }

    #[test]
    fn test_parse_ipv6_encap_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Proto(IpProto::Ipv6);
        let packet = vec![0u8; 20]; // Too short for IPv6 header (needs 40 bytes)
        let ctx = TcContext::new(packet);

        let result = parser.parse_ipv6_encap(&ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::OutOfBounds);
    }

    #[test]
    fn test_parse_wireguard_header_initiation() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Wireguard;
        let packet = create_wireguard_init_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, WIREGUARD_INITIATION_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    #[test]
    fn test_parse_wireguard_header_response() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Wireguard;
        let packet = create_wireguard_response_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, WIREGUARD_RESPONSE_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    #[test]
    fn test_parse_wireguard_header_cookie_reply() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Wireguard;
        let packet = create_wireguard_cookie_reply_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, WIREGUARD_COOKIE_REPLY_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    #[test]
    fn test_parse_wireguard_header_transport_data() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Wireguard;
        let packet = create_wireguard_transport_data_test_packet();
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_header(&ctx);

        assert!(result.is_ok());
        assert_eq!(parser.offset, WIREGUARD_TRANSPORT_DATA_LEN);
        assert!(matches!(parser.next_hdr, HeaderType::StopProcessing));
    }

    #[test]
    fn test_parse_wireguard_header_out_of_bounds() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Wireguard;
        let packet = vec![0u8; 0]; // Empty packet
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_header(&ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::OutOfBounds);
    }

    #[test]
    fn test_parse_wireguard_header_unsupported_type() {
        let mut parser = Parser::default();
        parser.next_hdr = HeaderType::Wireguard;
        let mut packet = vec![0u8; 16];
        packet[0] = 0xFF; // Invalid WireGuard type
        let ctx = TcContext::new(packet);

        let result = parser.parse_wireguard_header(&ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::Unsupported);
    }
}
