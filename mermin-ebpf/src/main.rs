//! # Mermin eBPF Flow Aggregator
//!
//! High-performance network flow aggregation implemented as a Linux eBPF TC (Traffic Control) classifier.
//! Processes packets at line rate, aggregating them into bidirectional flows with rich metadata for
//! network observability and telemetry.
//!
//! ## Overview
//!
//! This eBPF program attaches to network interfaces via TC (Traffic Control) and performs:
//! - **Flow Key Extraction**: Parses Ethernet, IP, and L4 headers to extract 5-tuple (src IP, dst IP, src port, dst port, protocol)
//! - **Bidirectional Aggregation**: Normalizes flow keys for bidirectional flow tracking (compatible with Community ID)
//! - **Metadata Collection**: Captures MACs, DSCP, ECN, TTL, TCP flags, ICMP type/code from first packet
//! - **Statistics Tracking**: Counts packets/bytes per direction, timestamps (first/last seen)
//! - **Event Notification**: Signals userspace about new flows via ring buffer with unparsed packet data for deep inspection
//!
//! ## Supported Protocols
//!
//! ### Layer 2
//! - Ethernet II (DIX)
//!
//! ### Layer 3
//! - IPv4 (with variable-length options via IHL)
//! - IPv6 (fixed 40-byte header, no extension header parsing)
//!
//! ### Layer 4
//! - **TCP**: Ports + flag accumulation
//! - **UDP**: Ports only
//! - **ICMP/ICMPv6**: Type + Code (encoded as ports for Community ID compatibility)
//!
//! ## Userspace Integration
//!
//! Userspace consumers poll `FLOW_EVENTS` ring buffer for new flows, then:
//! 1. Perform deep parsing on the unparsed packet data (tunnels, application protocols, etc.)
//! 2. Periodically read `FLOW_STATS_MAP` for statistics updates (active/idle timeouts)
//! 3. Export aggregated flows to telemetry systems (OpenTelemetry, etc.)
//! 4. Remove expired flows from the map
//!
//! ## Architecture Diagram
//!
//! ┌──────────────────────────────────────────────────────────────┐
//! │  Network Interface (TC Hook)                                 │
//! └──────────────────┬───────────────────────────────────────────┘
//!                    │ Packet
//!                    ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  eBPF TC Classifier (mermin_flow_ingress / mermin_flow_egress)  │
//! │                                                                 │
//! │  1. Parse minimal flow key (Eth + IP + L4)                      │
//! │  2. Normalize (src < dst) for bidirectional aggregation         │
//! │  3. Lookup/create flow in FLOW_STATS map                        │
//! │  4. Update forward/reverse packet/byte counters                 │
//! │  5. Signal userspace if new flow                                │
//! │  6. Return TC_ACT_UNSPEC (pass packet)                          │
//! └──────────────────┬──────────────────────┬───────────────────────┘
//!                    │                      │
//!          ┌─────────▼────────┐             │
//!          │  FLOW_STATS Map  │             │ New flow event
//!          │  (1M flows max)  │             ▼
//!          │                  │  ┌──────────────────────┐
//!          │  FlowKey →       │  │  FLOW_EVENTS RingBuf │
//!          │  FlowStats       │  │  (256 KB)            │
//!          │                  │  └──────────┬───────────┘
//!          │  - packets       │             │
//!          │  - bytes         │             │
//!          │  - reverse_*     │             │
//!          │  - timestamps    │             │
//!          │  - metadata      │             │
//!          └──────────────────┘             │
//!                    ▲                      │
//!                    │                      │
//!                    │ Periodic polling     │ Event-driven
//!                    │ (30s intervals)      │ (new flows only)
//!                    │                      │
//!          ┌─────────┴──────────────────────▼─────────────────┐
//!          │  Userspace (FlowSpanProducer)                    │
//!          │                                                  │
//!          │  - React to new flow events from ring buffer     │
//!          │  - Pull stats from FLOW_STATS map periodically   │
//!          │  - Calculate deltas (packets/bytes since last)   │
//!          │  - Generate Community ID from FlowKey            │
//!          │  - Export flow telemetry (OTLP)                  │
//!          └──────────────────────────────────────────────────┘

#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

#[cfg(not(feature = "test"))]
use aya_ebpf::{
    bindings::TC_ACT_UNSPEC,
    helpers::bpf_ktime_get_boot_ns,
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TcContext,
};
#[cfg(not(feature = "test"))]
use aya_log_ebpf::{error, trace};
#[cfg(not(feature = "test"))]
use mermin_common::{Direction, FlowEvent};
use mermin_common::{FlowKey, FlowStats, IpVersion};
use network_types::{
    eth,
    eth::EtherType,
    icmp,
    ip::{IpProto, ipv4, ipv6},
    tcp, udp,
};

// New eBPF map aggregation architecture
// Flow statistics map: normalized FlowKey -> FlowStats
#[cfg(not(feature = "test"))]
#[map]
static mut FLOW_STATS_MAP: HashMap<FlowKey, FlowStats> = HashMap::with_max_entries(1_000_000, 0);

// Flow events ring buffer: signals userspace about new flows
// Size: 256 KB (~10K flow events before overflow)
#[cfg(not(feature = "test"))]
#[map]
static mut FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Per-CPU scratch space for FlowStats initialization
// Used to avoid stack overflow (FlowStats is 232 bytes, eBPF stack limit is 512 bytes)
#[cfg(not(feature = "test"))]
#[map]
static mut FLOW_STATS: PerCpuArray<FlowStats> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU scratch space for building FlowEvent (avoids stack overflow).
#[cfg(not(feature = "test"))]
#[map]
static mut FLOW_EVENT_SCRATCH: PerCpuArray<FlowEvent> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU scratch space for FlowKey parsing (avoids stack overflow).
#[cfg(not(feature = "test"))]
#[map]
static mut FLOW_KEY_SCRATCH: PerCpuArray<FlowKey> = PerCpuArray::with_max_entries(1, 0);

/// Error types that can occur during packet parsing.
///
/// Error logs are emitted with human-readable descriptions including the specific header type
/// and error reason (e.g., "parser failed: IPv4 header out of bounds").
///
/// ## Error Types
///
/// - **OutOfBounds** - Packet data access beyond available length
/// - **MalformedHeader** - Header structure is invalid or corrupted
/// - **Unsupported** - Protocol/header type not currently supported
/// - **InternalError** - Map access failure or internal state error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    OutOfBounds,
    MalformedHeader,
    UnsupportedEtherType,
    UnsupportedProtocol,
    InternalError,
}

/// Log errors based on severity level
#[cfg(not(feature = "test"))]
#[inline(always)]
fn log_error(ctx: &TcContext, err: Error, direction: Direction) {
    match err {
        Error::OutOfBounds => {
            error!(ctx, "out of bounds error in direction={}", direction as u8);
        }
        Error::MalformedHeader => {
            error!(
                ctx,
                "malformed header error in direction={}", direction as u8
            );
        }
        Error::InternalError => {
            error!(ctx, "internal error in direction={}", direction as u8);
        }
        Error::UnsupportedEtherType => {
            trace!(
                ctx,
                "unsupported ether type in direction={}", direction as u8
            );
        }
        Error::UnsupportedProtocol => {
            trace!(ctx, "unsupported protocol in direction={}", direction as u8);
        }
    }
}

#[cfg(not(feature = "test"))]
#[classifier]
pub fn mermin_flow_ingress(ctx: TcContext) -> i32 {
    run_flow_stats(&ctx, Direction::Ingress)
}

#[cfg(not(feature = "test"))]
#[classifier]
pub fn mermin_flow_egress(ctx: TcContext) -> i32 {
    run_flow_stats(&ctx, Direction::Egress)
}

/// Helper to handle flow stats with error logging
#[cfg(not(feature = "test"))]
#[inline(always)]
fn run_flow_stats(ctx: &TcContext, direction: Direction) -> i32 {
    match try_flow_stats(ctx, direction) {
        Ok(ret) => ret,
        Err(e) => {
            log_error(ctx, e, direction);
            TC_ACT_UNSPEC
        }
    }
}

#[cfg(not(feature = "test"))]
#[inline(always)]
fn try_flow_stats(ctx: &TcContext, direction: Direction) -> Result<i32, Error> {
    // Use per-CPU scratch space for FlowKey parsing (avoids stack overflow)
    #[allow(static_mut_refs)]
    let flow_key_ptr = unsafe { FLOW_KEY_SCRATCH.get_ptr_mut(0).ok_or(Error::OutOfBounds)? };
    let flow_key = unsafe { &mut *flow_key_ptr };
    let eth_type = parse_flow_key(ctx, flow_key)?;

    // Normalize the flow key for map lookup (bidirectional aggregation)
    let normalized_key = flow_key.normalize();
    let is_new_flow = unsafe {
        #[allow(static_mut_refs)]
        FLOW_STATS_MAP.get(&normalized_key).is_none()
    };

    let timestamp = unsafe { bpf_ktime_get_boot_ns() };

    // Get or create flow stats entry
    #[allow(static_mut_refs)]
    let stats_ptr = if is_new_flow {
        let ifindex = unsafe { (*ctx.skb.skb).ifindex };

        // Use per-CPU scratch space to initialize FlowStats (avoids stack overflow)
        #[allow(static_mut_refs)]
        let flow_stats = unsafe { FLOW_STATS.get_ptr_mut(0).ok_or(Error::OutOfBounds)? };
        unsafe { core::ptr::write_bytes(flow_stats, 0, 1) };
        let stats = unsafe { &mut *flow_stats };
        stats.first_seen_ns = timestamp;
        stats.last_seen_ns = timestamp;
        stats.ifindex = ifindex;
        stats.direction = direction;
        stats.ether_type = eth_type;
        stats.ip_version = flow_key.ip_version;
        stats.protocol = flow_key.protocol;
        stats.src_ip = flow_key.src_ip;
        stats.dst_ip = flow_key.dst_ip;
        stats.src_port = flow_key.src_port;
        stats.dst_port = flow_key.dst_port;
        stats.forward_metadata_seen = 1;
        stats.reverse_metadata_seen = 0;

        let parsed_offset = parse_metadata(ctx, stats)?;

        unsafe {
            #[allow(static_mut_refs)]
            FLOW_STATS_MAP
                .insert(&normalized_key, &*stats, 0)
                .map_err(|_| Error::OutOfBounds)?;
        }

        #[allow(static_mut_refs)]
        if let Some(mut event) = unsafe { FLOW_EVENTS.reserve::<FlowEvent>(0) } {
            // Use per-CPU scratch space to build FlowEvent (avoids stack overflow)
            #[allow(static_mut_refs)]
            let flow_event_ptr = unsafe { FLOW_EVENT_SCRATCH.get_ptr_mut(0) };
            let Some(flow_event_ptr) = flow_event_ptr else {
                // Must discard the ring buffer reservation before returning error
                event.discard(0);
                return Err(Error::OutOfBounds);
            };
            unsafe { core::ptr::write_bytes(flow_event_ptr, 0, 1) };
            let flow_event = unsafe { &mut *flow_event_ptr };

            flow_event.flow_key = normalized_key;
            flow_event.snaplen = ctx.len() as u16;
            flow_event.parsed_offset = parsed_offset as u16;

            // Copy unparsed data (if any) for userspace deep parsing.
            // Load bytes one at a time until we hit the end of the packet or reach 192 bytes.
            // The verifier can track this bounded loop easily.
            for i in 0..192 {
                let offset = parsed_offset + i;
                if let Ok(byte) = ctx.load::<u8>(offset) {
                    flow_event.packet_data[i] = byte;
                } else {
                    break;
                }
            }

            event.write(*flow_event);
            event.submit(0);
        } else {
            error!(
                ctx,
                "ebpf - ring buffer full - dropping flow event for new flow (protocol={})",
                flow_key.protocol as u8
            );
        }

        // Get pointer to the entry we just inserted
        #[allow(static_mut_refs)]
        unsafe {
            FLOW_STATS_MAP.get_ptr_mut(&normalized_key)
        }
    } else {
        // Get pointer to existing entry
        #[allow(static_mut_refs)]
        unsafe {
            FLOW_STATS_MAP.get_ptr_mut(&normalized_key)
        }
    };

    // Update stats for current packet (works for both new and existing flows)
    #[allow(static_mut_refs)]
    if let Some(stats_ptr) = stats_ptr {
        let stats = unsafe { &mut *stats_ptr };
        stats.last_seen_ns = timestamp;

        let is_forward = flow_key.src_ip == stats.src_ip && flow_key.dst_ip == stats.dst_ip;
        if is_forward {
            stats.packets += 1;
            stats.bytes = stats.bytes.saturating_add(ctx.len() as u64);
        } else {
            stats.reverse_packets += 1;
            stats.reverse_bytes = stats.reverse_bytes.saturating_add(ctx.len() as u64);
        }

        let mut l4_offset = eth::ETH_LEN;
        if eth_type == EtherType::Ipv4 {
            let vihl: ipv4::Vihl = ctx.load(l4_offset).map_err(|_| Error::OutOfBounds)?;
            l4_offset += ipv4::ihl(vihl) as usize;
        } else if eth_type == EtherType::Ipv6 {
            l4_offset += ipv6::IPV6_LEN;
        }

        if is_forward && stats.forward_metadata_seen == 0 {
            match eth_type {
                EtherType::Ipv4 => {
                    let dscp_ecn: ipv4::DscpEcn = ctx
                        .load(eth::ETH_LEN + ipv4::IPV4_DSCP_ECN_OFFSET)
                        .map_err(|_| Error::OutOfBounds)?;
                    stats.ip_dscp = ipv4::dscp(dscp_ecn);
                    stats.ip_ecn = ipv4::ecn(dscp_ecn);

                    let ttl: ipv4::Ttl = ctx
                        .load(eth::ETH_LEN + ipv4::IPV4_TTL_OFFSET)
                        .map_err(|_| Error::OutOfBounds)?;
                    stats.ip_ttl = ttl;
                }
                EtherType::Ipv6 => {
                    let vtcfl: ipv6::Vcf =
                        ctx.load(eth::ETH_LEN).map_err(|_| Error::OutOfBounds)?;
                    stats.ip_dscp = ipv6::dscp(vtcfl);
                    stats.ip_ecn = ipv6::ecn(vtcfl);
                    stats.ip_flow_label = ipv6::flow_label(vtcfl);

                    let hop_limit: ipv6::HopLimit = ctx
                        .load(eth::ETH_LEN + ipv6::IPV6_HOP_LIMIT_OFFSET)
                        .map_err(|_| Error::OutOfBounds)?;
                    stats.ip_ttl = hop_limit;
                }
                _ => {}
            }

            if stats.protocol == IpProto::Icmp || stats.protocol == IpProto::Ipv6Icmp {
                let icmp_type: u8 = ctx
                    .load(l4_offset + icmp::ICMP_TYPE_OFFSET)
                    .map_err(|_| Error::OutOfBounds)?;
                stats.icmp_type = icmp_type;

                let icmp_code: u8 = ctx
                    .load(l4_offset + icmp::ICMP_CODE_OFFSET)
                    .map_err(|_| Error::OutOfBounds)?;
                stats.icmp_code = icmp_code;
            }

            stats.forward_metadata_seen = 1;
        } else if !is_forward && stats.reverse_metadata_seen == 0 {
            match eth_type {
                EtherType::Ipv4 => {
                    let dscp_ecn: ipv4::DscpEcn = ctx
                        .load(eth::ETH_LEN + ipv4::IPV4_DSCP_ECN_OFFSET)
                        .map_err(|_| Error::OutOfBounds)?;
                    stats.reverse_ip_dscp = ipv4::dscp(dscp_ecn);
                    stats.reverse_ip_ecn = ipv4::ecn(dscp_ecn);

                    let ttl: ipv4::Ttl = ctx
                        .load(eth::ETH_LEN + ipv4::IPV4_TTL_OFFSET)
                        .map_err(|_| Error::OutOfBounds)?;
                    stats.reverse_ip_ttl = ttl;
                }
                EtherType::Ipv6 => {
                    let vtcfl: ipv6::Vcf =
                        ctx.load(eth::ETH_LEN).map_err(|_| Error::OutOfBounds)?;
                    stats.reverse_ip_dscp = ipv6::dscp(vtcfl);
                    stats.reverse_ip_ecn = ipv6::ecn(vtcfl);
                    stats.reverse_ip_flow_label = ipv6::flow_label(vtcfl);

                    let hop_limit: ipv6::HopLimit = ctx
                        .load(eth::ETH_LEN + ipv6::IPV6_HOP_LIMIT_OFFSET)
                        .map_err(|_| Error::OutOfBounds)?;
                    stats.reverse_ip_ttl = hop_limit;
                }
                _ => {}
            }

            if stats.protocol == IpProto::Icmp || stats.protocol == IpProto::Ipv6Icmp {
                let icmp_type: u8 = ctx
                    .load(l4_offset + icmp::ICMP_TYPE_OFFSET)
                    .map_err(|_| Error::OutOfBounds)?;
                stats.reverse_icmp_type = icmp_type;

                let icmp_code: u8 = ctx
                    .load(l4_offset + icmp::ICMP_CODE_OFFSET)
                    .map_err(|_| Error::OutOfBounds)?;
                stats.reverse_icmp_code = icmp_code;
            }

            stats.reverse_metadata_seen = 1;
        }

        if stats.protocol == IpProto::Tcp {
            let current_flags: tcp::Flags = ctx
                .load(l4_offset + tcp::TCP_FLAGS_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            stats.tcp_flags |= current_flags;
        }
    }

    Ok(TC_ACT_UNSPEC)
}

/// Parse L2 + L3 + L4 headers to extract flow key (Ethernet, IP, Transport/ICMP)
///
/// Parses 3 layers:
/// - Layer 2: Ethernet (EtherType)
/// - Layer 3: IPv4/IPv6 (addresses, protocol)
/// - Layer 4: TCP/UDP ports or ICMP type/code
///
/// This function uses bounded loops to satisfy old kernel verifiers (5.14+).
#[inline(never)]
fn parse_flow_key(ctx: &TcContext, key: &mut FlowKey) -> Result<EtherType, Error> {
    if eth::ETH_LEN > ctx.len() as usize {
        return Err(Error::MalformedHeader);
    }

    // Initialize the key
    key.src_ip = [0u8; 16];
    key.dst_ip = [0u8; 16];
    key.ip_version = IpVersion::Unknown;
    key.protocol = IpProto::default();
    key.src_port = 0;
    key.dst_port = 0;

    let mut offset = 0;

    let eth_type: EtherType = ctx
        .load(eth::ETH_ETHER_TYPE_OFFSET)
        .map_err(|_| Error::OutOfBounds)?;
    offset += eth::ETH_LEN;

    offset = match eth_type {
        EtherType::Ipv4 => {
            if offset + ipv4::IPV4_LEN > ctx.len() as usize {
                return Err(Error::OutOfBounds);
            }
            let ihl = ipv4::ihl(
                ctx.load::<ipv4::Vihl>(offset)
                    .map_err(|_| Error::OutOfBounds)?,
            ) as usize;
            if ihl < ipv4::IPV4_LEN {
                return Err(Error::MalformedHeader);
            }

            key.ip_version = IpVersion::V4;
            key.protocol = ctx
                .load(offset + ipv4::IPV4_PROTOCOL_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;

            let src_ipv4: [u8; 4] = ctx
                .load(offset + ipv4::IPV4_SRC_ADDR_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            key.src_ip[0..4].copy_from_slice(&src_ipv4);
            let dst_ipv4: [u8; 4] = ctx
                .load(offset + ipv4::IPV4_DST_ADDR_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            key.dst_ip[0..4].copy_from_slice(&dst_ipv4);

            offset + ihl
        }
        EtherType::Ipv6 => {
            if offset + ipv6::IPV6_LEN > ctx.len() as usize {
                return Err(Error::OutOfBounds);
            }

            key.ip_version = IpVersion::V6;
            key.protocol = ctx
                .load(offset + ipv6::IPV6_NEXT_HDR_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            key.src_ip = ctx
                .load(offset + ipv6::IPV6_SRC_ADDR_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            key.dst_ip = ctx
                .load(offset + ipv6::IPV6_DST_ADDR_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            offset + ipv6::IPV6_LEN
        }
        _ => return Err(Error::UnsupportedEtherType),
    };

    match key.protocol {
        IpProto::Tcp => {
            if offset + tcp::TCP_LEN > ctx.len() as usize {
                return Err(Error::OutOfBounds);
            }

            key.src_port = tcp::src_port(
                ctx.load(offset + tcp::TCP_SRC_PORT_OFFSET)
                    .map_err(|_| Error::OutOfBounds)?,
            );
            key.dst_port = tcp::dst_port(
                ctx.load(offset + tcp::TCP_DST_PORT_OFFSET)
                    .map_err(|_| Error::OutOfBounds)?,
            );
        }
        IpProto::Udp => {
            if offset + udp::UDP_LEN > ctx.len() as usize {
                return Err(Error::OutOfBounds);
            }

            key.src_port = udp::src_port(
                ctx.load(offset + udp::UDP_SRC_PORT_OFFSET)
                    .map_err(|_| Error::OutOfBounds)?,
            );
            key.dst_port = udp::dst_port(
                ctx.load(offset + udp::UDP_DST_PORT_OFFSET)
                    .map_err(|_| Error::OutOfBounds)?,
            );
        }
        IpProto::Icmp | IpProto::Ipv6Icmp => {
            if offset + icmp::ICMP_LEN > ctx.len() as usize {
                return Err(Error::OutOfBounds);
            }

            // ICMP has no ports, so map type/code to port fields for Community ID compatibility
            // Per Community ID spec: src_port = type, dst_port = code
            // Reference: https://github.com/corelight/community-id-spec
            let icmp_type: u8 = ctx
                .load(offset + icmp::ICMP_TYPE_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            let icmp_code: u8 = ctx
                .load(offset + icmp::ICMP_CODE_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;

            key.src_port = icmp_type as u16;
            key.dst_port = icmp_code as u16;
        }
        _ => {
            return Err(Error::UnsupportedProtocol);
        }
    }

    Ok(eth_type)
}

/// Parse full packet metadata into FlowStats (MACs, DSCP, TTL, ICMP type/code, etc.)
/// TCP flags are accumulated separately in try_packet_monitor() for all packets.
/// Returns the offset where parsing stopped (= start of unparsed data for FlowEvent).
/// Returns Error if parsing fails (bounds check, load failure, etc.)
#[inline(never)]
fn parse_metadata(ctx: &TcContext, stats: &mut FlowStats) -> Result<usize, Error> {
    let mut offset = 0usize;

    stats.src_mac = ctx
        .load::<eth::SrcMacAddr>(offset + eth::ETH_SRC_MAC_ADDR_OFFSET)
        .map_err(|_| Error::OutOfBounds)?;
    offset += eth::ETH_LEN;

    // Parse IP metadata (DSCP, ECN, TTL, flow label) - first packet is always forward direction
    offset = match stats.ether_type {
        EtherType::Ipv4 => {
            let ihl = ipv4::ihl(
                ctx.load::<ipv4::Vihl>(offset)
                    .map_err(|_| Error::OutOfBounds)?,
            ) as usize;

            let dscp_ecn: ipv4::DscpEcn = ctx
                .load(offset + ipv4::IPV4_DSCP_ECN_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            stats.ip_dscp = ipv4::dscp(dscp_ecn);
            stats.ip_ecn = ipv4::ecn(dscp_ecn);

            let ttl: ipv4::Ttl = ctx
                .load(offset + ipv4::IPV4_TTL_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            stats.ip_ttl = ttl;

            offset + ihl
        }
        EtherType::Ipv6 => {
            let vtcfl: ipv6::Vcf = ctx.load(offset).map_err(|_| Error::OutOfBounds)?;
            stats.ip_dscp = ipv6::dscp(vtcfl);
            stats.ip_ecn = ipv6::ecn(vtcfl);
            stats.ip_flow_label = ipv6::flow_label(vtcfl);

            let hop_limit: ipv6::HopLimit = ctx
                .load(offset + ipv6::IPV6_HOP_LIMIT_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            stats.ip_ttl = hop_limit;

            offset + ipv6::IPV6_LEN
        }
        _ => return Err(Error::UnsupportedEtherType),
    };

    match stats.protocol {
        IpProto::Tcp => {
            // TCP flags are accumulated in try_packet_monitor() for all packets
            // No need to capture here - accumulation handles both first and subsequent packets
            let data_offset: tcp::OffRes = ctx
                .load(offset + tcp::TCP_OFF_RES_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            let tcp_hdr_len = tcp::hdr_len(data_offset);

            offset += tcp_hdr_len;
        }
        IpProto::Udp => {
            offset += udp::UDP_LEN;
        }
        IpProto::Icmp | IpProto::Ipv6Icmp => {
            let icmp_type: u8 = ctx
                .load(offset + icmp::ICMP_TYPE_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            let icmp_code: u8 = ctx
                .load(offset + icmp::ICMP_CODE_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            stats.icmp_type = icmp_type;
            stats.icmp_code = icmp_code;

            offset += icmp::ICMP_LEN;
        }
        _ => {
            return Err(Error::UnsupportedProtocol);
        }
    }

    Ok(offset)
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
        ($ctx:expr, $($arg:tt)*) => {{
            let _ = &$ctx;
            let _ = format_args!($($arg)*);
        }};
    }

    #[cfg(feature = "test")]
    #[macro_export]
    macro_rules! debug {
        ($ctx:expr, $($arg:tt)*) => {{
            let _ = &$ctx;
            let _ = format_args!($($arg)*);
        }};
    }
}

#[cfg(feature = "test")]
use host_test_shim::TcContext;

#[cfg(test)]
mod tests {
    use mermin_common::{Direction, IpVersion};
    use network_types::{eth::EtherType, ip::IpProto};

    use super::*;

    // Helper to create test FlowStats
    fn create_test_flow_stats(ether_type: EtherType, protocol: IpProto) -> FlowStats {
        FlowStats {
            first_seen_ns: 0,
            last_seen_ns: 0,
            ifindex: 0,
            direction: Direction::Ingress,
            ether_type,
            ip_version: IpVersion::Unknown,
            protocol,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            packets: 0,
            bytes: 0,
            reverse_packets: 0,
            reverse_bytes: 0,
            src_mac: [0; 6],
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 0,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
            ip_flow_label: 0,
            reverse_ip_flow_label: 0,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
            forward_metadata_seen: 0,
            reverse_metadata_seen: 0,
        }
    }

    // Helper to build Ethernet + IPv4 + TCP packet
    fn build_ipv4_tcp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();

        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // Dst MAC
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // Src MAC
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes, no options)
        pkt.push(0x45); // Version=4, IHL=5 (20 bytes)
        pkt.push(0xB8); // DSCP=46 (0xB8 = 10111000, DSCP=101110=46), ECN=0
        pkt.extend_from_slice(&[0x00, 0x3C]); // Total length: 60 bytes
        pkt.extend_from_slice(&[0x1C, 0x46]); // Identification
        pkt.extend_from_slice(&[0x40, 0x00]); // Flags + Fragment offset
        pkt.push(64); // TTL
        pkt.push(6); // Protocol: TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum (ignore)
        pkt.extend_from_slice(&[192, 168, 1, 10]); // Src IP: 192.168.1.10
        pkt.extend_from_slice(&[10, 0, 0, 5]); // Dst IP: 10.0.0.5

        // TCP header (20 bytes, no options)
        pkt.extend_from_slice(&[0x30, 0x39]); // Src port: 12345
        pkt.extend_from_slice(&[0x01, 0xBB]); // Dst port: 443
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq number
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack number
        pkt.push(0x50); // Data offset: 5 (20 bytes)
        pkt.push(0x02); // Flags: SYN
        pkt.extend_from_slice(&[0x71, 0x10]); // Window size
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

        // Payload (6 bytes to reach 60 total)
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        pkt
    }

    // Helper to build Ethernet + IPv4 + UDP packet
    fn build_ipv4_udp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();

        // Ethernet header
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4

        // IPv4 header
        pkt.push(0x45); // IHL=5
        pkt.push(0x00); // DSCP=0, ECN=0
        pkt.extend_from_slice(&[0x00, 0x24]); // Total length: 36 bytes
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ID + Flags
        pkt.push(128); // TTL
        pkt.push(17); // Protocol: UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        pkt.extend_from_slice(&[10, 0, 0, 2]); // Dst IP

        // UDP header
        pkt.extend_from_slice(&[0x04, 0xD2]); // Src port: 1234
        pkt.extend_from_slice(&[0x16, 0x2E]); // Dst port: 5678
        pkt.extend_from_slice(&[0x00, 0x10]); // Length: 16 bytes
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum

        // Payload (8 bytes)
        pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        pkt
    }

    // Helper to build Ethernet + IPv4 + ICMP packet
    fn build_ipv4_icmp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();

        // Ethernet header
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4

        // IPv4 header
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x1C]); // Total length: 28 bytes
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.push(64);
        pkt.push(1); // Protocol: ICMP
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        pkt.extend_from_slice(&[8, 8, 8, 8]); // Dst IP

        // ICMP header
        pkt.push(8); // Type: Echo Request
        pkt.push(0); // Code: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        pkt.extend_from_slice(&[0x12, 0x34]); // ID
        pkt.extend_from_slice(&[0x00, 0x01]); // Sequence

        pkt
    }

    // Helper to build Ethernet + IPv6 + TCP packet
    fn build_ipv6_tcp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();

        // Ethernet header
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0x86, 0xDD]); // EtherType: IPv6

        // IPv6 header (40 bytes)
        // Version (4 bits) = 6, Traffic Class (8 bits) = 0x0E (DSCP=3, ECN=2)
        // Bits layout: |Version(4)|TC_upper(4)||TC_lower(4)|FlowLabel_upper(4)||FlowLabel_mid(8)||FlowLabel_lower(8)|
        pkt.push(0x60); // Version=6 (bits 0-3), TC upper 4 bits=0 (bits 4-7)
        pkt.push(0xE1); // TC lower 4 bits=0xE (bits 0-3), Flow Label upper 4 bits=1 (bits 4-7)
        pkt.extend_from_slice(&[0x23, 0x45]); // Flow Label remaining 16 bits = 0x2345, total FL=0x12345
        pkt.extend_from_slice(&[0x00, 0x14]); // Payload length: 20 bytes (TCP)
        pkt.push(6); // Next Header: TCP
        pkt.push(255); // Hop Limit
        // Src IPv6: 2001:db8::1
        pkt.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        // Dst IPv6: 2001:db8::2
        pkt.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        // TCP header (20 bytes)
        pkt.extend_from_slice(&[0x1F, 0x90]); // Src port: 8080
        pkt.extend_from_slice(&[0x00, 0x50]); // Dst port: 80
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack
        pkt.push(0x50); // Data offset: 5
        pkt.push(0x12); // Flags: SYN+ACK
        pkt.extend_from_slice(&[0x71, 0x10]); // Window
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Checksum + Urgent

        pkt
    }

    #[test]
    fn test_parse_flow_key_ipv4_tcp() {
        let pkt = build_ipv4_tcp_packet();
        let ctx = TcContext::new(pkt);

        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);
        assert!(result.is_ok());

        let ether_type = result.unwrap();
        assert_eq!(ether_type, EtherType::Ipv4);
        assert_eq!(flow_key.ip_version, IpVersion::V4);
        assert_eq!(flow_key.protocol, IpProto::Tcp);

        // Check IP addresses (should be in [u8; 16] format)
        let expected_src = [192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let expected_dst = [10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(flow_key.src_ip, expected_src);
        assert_eq!(flow_key.dst_ip, expected_dst);

        // Check ports
        assert_eq!(flow_key.src_port, 12345);
        assert_eq!(flow_key.dst_port, 443);
    }

    #[test]
    fn test_parse_flow_key_ipv4_udp() {
        let pkt = build_ipv4_udp_packet();
        let ctx = TcContext::new(pkt);

        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);
        assert!(result.is_ok());

        let ether_type = result.unwrap();
        assert_eq!(ether_type, EtherType::Ipv4);
        assert_eq!(flow_key.protocol, IpProto::Udp);
        assert_eq!(flow_key.src_port, 1234);
        assert_eq!(flow_key.dst_port, 5678);
    }

    #[test]
    fn test_parse_flow_key_ipv4_icmp() {
        let pkt = build_ipv4_icmp_packet();
        let ctx = TcContext::new(pkt);

        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);
        if result.is_err() {
            panic!(
                "parse_flow_key failed with error: {:?}",
                result.unwrap_err()
            );
        }

        let ether_type = result.unwrap();
        assert_eq!(ether_type, EtherType::Ipv4);
        assert_eq!(flow_key.protocol, IpProto::Icmp);
        // ICMP: type=8, code=0 encoded as ports
        assert_eq!(flow_key.src_port, 8); // Type
        assert_eq!(flow_key.dst_port, 0); // Code
    }

    #[test]
    fn test_parse_flow_key_ipv6_tcp() {
        let pkt = build_ipv6_tcp_packet();
        let ctx = TcContext::new(pkt);

        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);
        assert!(result.is_ok());

        let ether_type = result.unwrap();
        assert_eq!(ether_type, EtherType::Ipv6);
        assert_eq!(flow_key.ip_version, IpVersion::V6);
        assert_eq!(flow_key.protocol, IpProto::Tcp);
        assert_eq!(flow_key.src_port, 8080);
        assert_eq!(flow_key.dst_port, 80);
    }

    #[test]
    fn test_parse_flow_key_truncated_ethernet() {
        let pkt = vec![0x00, 0x01, 0x02]; // Only 3 bytes
        let ctx = TcContext::new(pkt);

        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::MalformedHeader);
    }

    #[test]
    fn test_parse_flow_key_truncated_ipv4() {
        let mut pkt = Vec::new();
        // Ethernet header
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        // Only 10 bytes of IPv4 header (should be 20)
        pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x06]);

        let ctx = TcContext::new(pkt);
        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_flow_key_invalid_ihl() {
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        // IPv4 with IHL=2 (invalid, minimum is 5)
        pkt.push(0x42); // Version=4, IHL=2
        pkt.extend_from_slice(&[0x00; 19]); // Rest of header

        let ctx = TcContext::new(pkt);
        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::MalformedHeader);
    }

    #[test]
    fn test_parse_flow_key_unsupported_ethertype() {
        let mut pkt = Vec::new();
        // Ethernet with ARP EtherType
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0x08, 0x06]); // ARP

        let ctx = TcContext::new(pkt);
        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::UnsupportedEtherType);
    }

    #[test]
    fn test_parse_metadata_ipv4_tcp() {
        let pkt = build_ipv4_tcp_packet();
        let ctx = TcContext::new(pkt);

        // Parse flow key first
        let mut flow_key = FlowKey::default();
        let ether_type = parse_flow_key(&ctx, &mut flow_key).unwrap();

        // Create FlowStats
        let mut stats = create_test_flow_stats(ether_type, flow_key.protocol);

        let result = parse_metadata(&ctx, &mut stats);
        assert!(result.is_ok());

        let parsed_offset = result.unwrap();

        // Check MACs
        assert_eq!(stats.src_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        // Check DSCP/ECN (DSCP=46, ECN=0)
        assert_eq!(stats.ip_dscp, 46);
        assert_eq!(stats.ip_ecn, 0);

        // Check TTL
        assert_eq!(stats.ip_ttl, 64);

        // Check Flow Label (IPv4 = 0)
        assert_eq!(stats.ip_flow_label, 0);

        // Check TCP flags (not parsed in parse_metadata, but should be 0)
        assert_eq!(stats.tcp_flags, 0);

        // Check parsed offset (Ethernet 14 + IPv4 20 + TCP 20 = 54)
        assert_eq!(parsed_offset, 54);
    }

    #[test]
    fn test_parse_metadata_ipv6_tcp() {
        let pkt = build_ipv6_tcp_packet();
        let ctx = TcContext::new(pkt);

        let mut flow_key = FlowKey::default();
        let ether_type = parse_flow_key(&ctx, &mut flow_key).unwrap();

        let mut stats = create_test_flow_stats(ether_type, flow_key.protocol);

        let result = parse_metadata(&ctx, &mut stats);
        assert!(result.is_ok());

        let parsed_offset = result.unwrap();

        // Check MACs
        assert_eq!(stats.src_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        // Check DSCP/ECN (Traffic Class = 0xE = 00001110, DSCP=000011=3, ECN=10=2)
        assert_eq!(stats.ip_dscp, 3);
        assert_eq!(stats.ip_ecn, 2);

        // Check Hop Limit (TTL equivalent)
        assert_eq!(stats.ip_ttl, 255);

        // Check Flow Label (0x012345 & 0xFFFFF = 0x12345)
        assert_eq!(stats.ip_flow_label, 0x12345);

        // Check parsed offset (Ethernet 14 + IPv6 40 + TCP 20 = 74)
        assert_eq!(parsed_offset, 74);
    }

    #[test]
    fn test_parse_metadata_ipv4_udp() {
        let pkt = build_ipv4_udp_packet();
        let ctx = TcContext::new(pkt);

        let mut flow_key = FlowKey::default();
        let ether_type = parse_flow_key(&ctx, &mut flow_key).unwrap();

        let mut stats = create_test_flow_stats(ether_type, flow_key.protocol);

        let result = parse_metadata(&ctx, &mut stats);
        assert!(result.is_ok());

        let parsed_offset = result.unwrap();

        // Check TTL
        assert_eq!(stats.ip_ttl, 128);

        // Check parsed offset (Ethernet 14 + IPv4 20 + UDP 8 = 42)
        assert_eq!(parsed_offset, 42);
    }

    #[test]
    fn test_parse_metadata_ipv4_icmp() {
        let pkt = build_ipv4_icmp_packet();
        let ctx = TcContext::new(pkt);

        let mut flow_key = FlowKey::default();
        let ether_type = parse_flow_key(&ctx, &mut flow_key).unwrap();

        let mut stats = create_test_flow_stats(ether_type, flow_key.protocol);

        let result = parse_metadata(&ctx, &mut stats);
        assert!(result.is_ok());

        let parsed_offset = result.unwrap();

        // Check ICMP type/code
        assert_eq!(stats.icmp_type, 8); // Echo Request
        assert_eq!(stats.icmp_code, 0);

        // Check parsed offset (Ethernet 14 + IPv4 20 + ICMP 8 = 42)
        assert_eq!(parsed_offset, 42);
    }

    #[test]
    fn test_parse_metadata_tcp_with_options() {
        let mut pkt = Vec::new();

        // Ethernet
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0x08, 0x00]);

        // IPv4
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x40]); // Total length: 64 bytes
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.push(64);
        pkt.push(6); // TCP
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[192, 168, 1, 1, 10, 0, 0, 1]);

        // TCP with options (data offset = 8, meaning 32 bytes)
        pkt.extend_from_slice(&[0x00, 0x50, 0x01, 0xBB]); // Ports
        pkt.extend_from_slice(&[0x00; 8]); // Seq + Ack
        pkt.push(0x80); // Data offset: 8 (32 bytes)
        pkt.push(0x02); // Flags
        pkt.extend_from_slice(&[0x71, 0x10, 0x00, 0x00, 0x00, 0x00]); // Window + Checksum + Urgent
        // 12 bytes of options
        pkt.extend_from_slice(&[0x00; 12]);

        let ctx = TcContext::new(pkt);
        let mut flow_key = FlowKey::default();
        let ether_type = parse_flow_key(&ctx, &mut flow_key).unwrap();

        let mut stats = create_test_flow_stats(ether_type, flow_key.protocol);

        let result = parse_metadata(&ctx, &mut stats);
        assert!(result.is_ok());

        let parsed_offset = result.unwrap();

        // Check parsed offset (Ethernet 14 + IPv4 20 + TCP 32 = 66)
        assert_eq!(parsed_offset, 66);
    }
}
