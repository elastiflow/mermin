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
//! 2. Periodically read `FLOW_STATS` for statistics updates (active/idle timeouts)
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
//!          │ (100K-1M flows)  │             ▼
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
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns},
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TcContext,
};
#[cfg(not(feature = "test"))]
use aya_log_ebpf::{error, trace};
#[cfg(not(feature = "test"))]
use mermin_common::FlowEvent;
use mermin_common::{ConnectionState, Direction, FlowKey, FlowStats, IpVersion};
use network_types::{
    eth,
    eth::EtherType,
    icmp,
    ip::{IpProto, ipv4, ipv6},
    tcp, udp,
};

/// Size of unparsed packet data captured per flow event (in bytes).
///
/// Limited to 192 bytes to balance deep packet inspection needs with ring buffer capacity.
/// This captures most application headers while keeping FlowEvent structure under 256 bytes.
#[cfg(not(feature = "test"))]
const FLOW_EVENT_PACKET_DATA_SIZE: usize = 192;

/// Maximum number of flows to track in the eBPF map.
///
/// This is an upper bound that can be overridden at runtime by the userspace
/// loader using aya's `set_max_entries()` API. The actual size is configured
/// via the `pipeline.ebpf_max_flows` config field (see runtime/conf.rs).
///
/// Default at runtime: 100,000 flows (~23 MB)
/// Configurable in config.hcl:
///   pipeline {
///     ebpf_max_flows = 500000  # For high-traffic (500K flows, ~116 MB)
///   }
///
/// Memory calculation: flows × 232 bytes
#[cfg(not(feature = "test"))]
const MAX_FLOWS: u32 = 10_000_000; // Upper bound, overridden at runtime

// New eBPF map aggregation architecture
// Flow statistics map: normalized FlowKey -> FlowStats
#[cfg(not(feature = "test"))]
#[map]
static mut FLOW_STATS: HashMap<FlowKey, FlowStats> = HashMap::with_max_entries(MAX_FLOWS, 0);

// Size: 256 KB (~1,120 FlowEvent entries, each 234 bytes)
// Provides buffering for new flow bursts while worker channels absorb backpressure.
// In normal operation, ring buffer stays nearly empty due to event-driven polling.
// When full, new flow events are dropped (flow still tracked in FLOW_STATS, but userspace
// won't get initial packet data for deep inspection).
#[cfg(not(feature = "test"))]
const RING_BUF_SIZE_BYTES: u32 = 256 * 1024;

// Flow events ring buffer: signals userspace about new flows
#[cfg(not(feature = "test"))]
#[map]
static mut FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE_BYTES, 0);

// Per-CPU scratch space for FlowStats initialization
// Used to avoid stack overflow (FlowStats is 232 bytes, eBPF stack limit is 512 bytes)
#[cfg(not(feature = "test"))]
#[map]
static mut FLOW_STATS_SCRATCH: PerCpuArray<FlowStats> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU scratch space for building FlowEvent (avoids stack overflow).
#[cfg(not(feature = "test"))]
#[map]
static mut FLOW_EVENT_SCRATCH: PerCpuArray<FlowEvent> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU scratch space for FlowKey parsing (avoids stack overflow).
#[cfg(not(feature = "test"))]
#[map]
static mut FLOW_KEY_SCRATCH: PerCpuArray<FlowKey> = PerCpuArray::with_max_entries(1, 0);

/// Map to track listening ports for client/server direction inference.
/// Key: ListeningPortKey (port + protocol), Value: 1 (presence marker)
/// Max entries: 65536 (all possible ports, though typically < 1000 in practice)
#[cfg(not(feature = "test"))]
#[map]
static mut LISTENING_PORTS: HashMap<mermin_common::ListeningPortKey, u8> =
    HashMap::with_max_entries(65536, 0);

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

/// Log errors at appropriate severity levels.
///
/// Uses `error!` for critical errors (OutOfBounds, MalformedHeader, InternalError)
/// and `trace!` for expected non-critical errors (unsupported protocols/ethertypes).
/// This prevents log spam from legitimate non-IP traffic (ARP, LLDP, etc.).
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

/// Helper for calculating/applying tcp timing stats
#[inline(always)]
fn update_tcp_timing(stats: &mut FlowStats, is_forward: bool, has_payload: bool, timestamp: u64) {
    if stats.syn() && !stats.ack() {
        stats.tcp_syn_ns = timestamp;
    }

    if stats.syn() && stats.ack() {
        stats.tcp_syn_ack_ns = timestamp;
    }

    if !has_payload {
        return;
    }

    if is_forward {
        stats.tcp_last_payload_fwd_ns = timestamp;
        return;
    }

    stats.tcp_last_payload_rev_ns = timestamp;

    // Only calculate latency if we've seen a corresponding request packet
    let last_request_ts = stats.tcp_last_payload_fwd_ns;
    if last_request_ts == 0 {
        return; // No request seen yet; cannot calculate RTT
    }

    let delta = timestamp.saturating_sub(last_request_ts);
    stats.tcp_txn_sum_ns += delta;
    stats.tcp_txn_count += 1;

    stats.tcp_last_payload_fwd_ns = 0;

    // Calculate the moving average of the jitter following RFC 1889/3550
    // Formula: J = J + (|D| - J) / 16
    let current_sample = delta as u32;

    if current_sample > stats.tcp_jitter_avg_ns {
        let diff = current_sample - stats.tcp_jitter_avg_ns;
        stats.tcp_jitter_avg_ns += diff / 16;
    } else {
        let diff = stats.tcp_jitter_avg_ns - current_sample;
        stats.tcp_jitter_avg_ns -= diff / 16;
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
        FLOW_STATS.get(&normalized_key).is_none()
    };

    let timestamp = unsafe { bpf_ktime_get_boot_ns() };

    #[allow(static_mut_refs)]
    let stats_ptr = if is_new_flow {
        let ifindex = unsafe { (*ctx.skb.skb).ifindex };

        // Use per-CPU scratch space to initialize FlowStats (avoids stack overflow)
        #[allow(static_mut_refs)]
        let flow_stats = unsafe {
            FLOW_STATS_SCRATCH
                .get_ptr_mut(0)
                .ok_or(Error::OutOfBounds)?
        };
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
            FLOW_STATS
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

            // Extract PID associated with the socket/process handling this packet.
            // bpf_get_current_pid_tgid() returns u64: upper 32 bits = TGID (process ID), lower 32 bits = PID (thread ID).
            // If unavailable, for forwarded traffic, or for kernel-generated packets, this will be 0.
            let pid_tgid = bpf_get_current_pid_tgid();
            flow_event.pid = (pid_tgid >> 32) as u32;

            // Capture process name (comm) synchronously in-kernel.
            // bpf_get_current_comm() returns the current task's comm field (up to 15 chars + null terminator).
            // If unavailable or fails, the comm field will remain zero-initialized.
            if let Ok(comm) = bpf_get_current_comm() {
                flow_event.comm = comm;
            }

            // Copy unparsed data (if any) for userspace deep parsing.
            // Load bytes one at a time until we hit the end of the packet or reach 192 bytes.
            // The verifier can track this bounded loop easily.
            for i in 0..FLOW_EVENT_PACKET_DATA_SIZE {
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

        #[allow(static_mut_refs)]
        unsafe {
            FLOW_STATS.get_ptr_mut(&normalized_key)
        }
    } else {
        #[allow(static_mut_refs)]
        unsafe {
            FLOW_STATS.get_ptr_mut(&normalized_key)
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

        // Capture metadata if userspace has reset the flags for re-capture
        // (userspace resets flags after each recording interval to detect changes in DSCP, TTL, etc.)
        if is_forward && stats.forward_metadata_seen == 0 {
            capture_direction_metadata(ctx, stats, eth_type, l4_offset, true)?;
            stats.forward_metadata_seen = 1;
        } else if !is_forward && stats.reverse_metadata_seen == 0 {
            capture_direction_metadata(ctx, stats, eth_type, l4_offset, false)?;
            stats.reverse_metadata_seen = 1;
        }

        if stats.protocol == IpProto::Tcp {
            let current_flags: tcp::Flags = ctx
                .load(l4_offset + tcp::TCP_FLAGS_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            stats.tcp_flags |= current_flags;

            let new_state = determine_tcp_state(stats.tcp_state, current_flags, direction);
            stats.tcp_state = new_state;

            let data_offset: tcp::OffRes = ctx
                .load(l4_offset + tcp::TCP_OFF_RES_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            let tcp_hdr_len = tcp::hdr_len(data_offset);
            let tcp_payload_offset = (l4_offset + tcp_hdr_len) as u32;

            if is_forward && stats.forward_tcp_flags == 0 {
                stats.forward_tcp_flags = current_flags;
            } else if !is_forward && stats.reverse_tcp_flags == 0 {
                stats.reverse_tcp_flags = current_flags;
            }

            let has_payload = ctx.len() > tcp_payload_offset;
            update_tcp_timing(stats, is_forward, has_payload, timestamp);
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

/// Capture metadata (DSCP, ECN, TTL, flow label, ICMP type/code) for a specific direction.
/// Used both during initial flow creation and when userspace resets metadata flags for re-capture.
#[inline(always)]
fn capture_direction_metadata(
    ctx: &TcContext,
    stats: &mut FlowStats,
    eth_type: EtherType,
    l4_offset: usize,
    is_forward: bool,
) -> Result<(), Error> {
    match eth_type {
        EtherType::Ipv4 => {
            let dscp_ecn: ipv4::DscpEcn = ctx
                .load(eth::ETH_LEN + ipv4::IPV4_DSCP_ECN_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            let ttl: ipv4::Ttl = ctx
                .load(eth::ETH_LEN + ipv4::IPV4_TTL_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;

            if is_forward {
                stats.ip_dscp = ipv4::dscp(dscp_ecn);
                stats.ip_ecn = ipv4::ecn(dscp_ecn);
                stats.ip_ttl = ttl;
            } else {
                stats.reverse_ip_dscp = ipv4::dscp(dscp_ecn);
                stats.reverse_ip_ecn = ipv4::ecn(dscp_ecn);
                stats.reverse_ip_ttl = ttl;
            }
        }
        EtherType::Ipv6 => {
            let vtcfl: ipv6::Vcf = ctx.load(eth::ETH_LEN).map_err(|_| Error::OutOfBounds)?;
            let hop_limit: ipv6::HopLimit = ctx
                .load(eth::ETH_LEN + ipv6::IPV6_HOP_LIMIT_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;

            if is_forward {
                stats.ip_dscp = ipv6::dscp(vtcfl);
                stats.ip_ecn = ipv6::ecn(vtcfl);
                stats.ip_flow_label = ipv6::flow_label(vtcfl);
                stats.ip_ttl = hop_limit;
            } else {
                stats.reverse_ip_dscp = ipv6::dscp(vtcfl);
                stats.reverse_ip_ecn = ipv6::ecn(vtcfl);
                stats.reverse_ip_flow_label = ipv6::flow_label(vtcfl);
                stats.reverse_ip_ttl = hop_limit;
            }
        }
        _ => {}
    }

    if stats.protocol == IpProto::Icmp || stats.protocol == IpProto::Ipv6Icmp {
        let icmp_type: u8 = ctx
            .load(l4_offset + icmp::ICMP_TYPE_OFFSET)
            .map_err(|_| Error::OutOfBounds)?;
        let icmp_code: u8 = ctx
            .load(l4_offset + icmp::ICMP_CODE_OFFSET)
            .map_err(|_| Error::OutOfBounds)?;

        if is_forward {
            stats.icmp_type = icmp_type;
            stats.icmp_code = icmp_code;
        } else {
            stats.reverse_icmp_type = icmp_type;
            stats.reverse_icmp_code = icmp_code;
        }
    }

    Ok(())
}

/// Parse full packet metadata into FlowStats (MACs, DSCP, TTL, ICMP type/code, etc.)
///
/// TCP flags are accumulated separately in `try_flow_stats()` for all packets.
/// Returns the offset where parsing stopped (= start of unparsed data for FlowEvent).
///
/// # Errors
///
/// Returns [`Error::OutOfBounds`] if packet data cannot be read, or
/// [`Error::UnsupportedProtocol`] for unsupported L4 protocols.
#[inline(never)]
fn parse_metadata(ctx: &TcContext, stats: &mut FlowStats) -> Result<usize, Error> {
    let mut offset = 0usize;

    stats.src_mac = ctx
        .load::<eth::SrcMacAddr>(offset + eth::ETH_SRC_MAC_ADDR_OFFSET)
        .map_err(|_| Error::OutOfBounds)?;
    offset += eth::ETH_LEN;

    // Calculate L4 offset for metadata capture
    let l4_offset = match stats.ether_type {
        EtherType::Ipv4 => {
            let ihl = ipv4::ihl(
                ctx.load::<ipv4::Vihl>(offset)
                    .map_err(|_| Error::OutOfBounds)?,
            ) as usize;
            offset + ihl
        }
        EtherType::Ipv6 => offset + ipv6::IPV6_LEN,
        _ => return Err(Error::UnsupportedEtherType),
    };

    // Parse IP and ICMP metadata (DSCP, ECN, TTL, flow label, ICMP type/code)
    // First packet is always forward direction
    capture_direction_metadata(ctx, stats, stats.ether_type, l4_offset, true)?;

    // Calculate final offset (start of unparsed payload data)
    let offset = match stats.protocol {
        IpProto::Tcp => {
            // TCP flags are accumulated in try_flow_stats() for all packets
            // No need to capture here - accumulation handles both first and subsequent packets
            let data_offset: tcp::OffRes = ctx
                .load(l4_offset + tcp::TCP_OFF_RES_OFFSET)
                .map_err(|_| Error::OutOfBounds)?;
            let tcp_hdr_len = tcp::hdr_len(data_offset);
            l4_offset + tcp_hdr_len
        }
        IpProto::Udp => l4_offset + udp::UDP_LEN,
        IpProto::Icmp | IpProto::Ipv6Icmp => l4_offset + icmp::ICMP_LEN,
        _ => return Err(Error::UnsupportedProtocol),
    };

    Ok(offset)
}

/// Determines TCP connection state using hybrid stateless/stateful approach.
///
/// # Examples
///
/// ```ignore
/// // Normal handshake progression
/// let state = determine_tcp_state(
///     ConnectionState::Closed,
///     tcp::TCP_FLAG_SYN,
///     Direction::Egress
/// );
/// assert_eq!(state, ConnectionState::SynSent);
///
/// // Receiving SYN+ACK response
/// let state = determine_tcp_state(
///     ConnectionState::SynSent,
///     tcp::TCP_FLAG_SYN | tcp::TCP_FLAG_ACK,
///     Direction::Ingress
/// );
/// assert_eq!(state, ConnectionState::Established);
///
/// // RST always closes connection from any state
/// let state = determine_tcp_state(
///     ConnectionState::Established,
///     tcp::TCP_FLAG_RST,
///     Direction::Egress
/// );
/// assert_eq!(state, ConnectionState::Closed);
/// ```
///
/// # TCP Connection State Machine from RFC 9293: https://datatracker.ietf.org/doc/html/rfc9293#section-3.3.2
///
///                             +---------+ ---------\      active OPEN
///                             |  CLOSED |            \    -----------
///                             +---------+<---------\   \   create TCB
///                               |     ^              \   \  snd SYN
///                  passive OPEN |     |   CLOSE        \   \
///                  ------------ |     | ----------       \   \
///                   create TCB  |     | delete TCB         \   \
///                               V     |                      \   \
///           rcv RST (note 1)  +---------+            CLOSE    |    \
///        -------------------->|  LISTEN |          ---------- |     |
///       /                     +---------+          delete TCB |     |
///      /           rcv SYN      |     |     SEND              |     |
///     /           -----------   |     |    -------            |     V
/// +--------+      snd SYN,ACK  /       \   snd SYN          +--------+
/// |        |<-----------------           ------------------>|        |
/// |  SYN   |                    rcv SYN                     |  SYN   |
/// |  RCVD  |<-----------------------------------------------|  SENT  |
/// |        |                  snd SYN,ACK                   |        |
/// |        |------------------           -------------------|        |
/// +--------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +--------+
///    |         --------------   |     |   -----------
///    |                x         |     |     snd ACK
///    |                          V     V
///    |  CLOSE                 +---------+
///    | -------                |  ESTAB  |
///    | snd FIN                +---------+
///    |                 CLOSE    |     |    rcv FIN
///    V                -------   |     |    -------
/// +---------+         snd FIN  /       \   snd ACK         +---------+
/// |  FIN    |<----------------          ------------------>|  CLOSE  |
/// | WAIT-1  |------------------                            |   WAIT  |
/// +---------+          rcv FIN  \                          +---------+
///   | rcv ACK of FIN   -------   |                          CLOSE  |
///   | --------------   snd ACK   |                         ------- |
///   V        x                   V                         snd FIN V
/// +---------+               +---------+                    +---------+
/// |FINWAIT-2|               | CLOSING |                    | LAST-ACK|
/// +---------+               +---------+                    +---------+
///   |              rcv ACK of FIN |                 rcv ACK of FIN |
///   |  rcv FIN     -------------- |    Timeout=2MSL -------------- |
///   |  -------            x       V    ------------        x       V
///    \ snd ACK              +---------+delete TCB          +---------+
///      -------------------->|TIME-WAIT|------------------->| CLOSED  |
///                           +---------+                    +---------+
#[inline(always)]
#[must_use]
fn determine_tcp_state(
    current_state: ConnectionState,
    flags: u8,
    direction: Direction,
) -> ConnectionState {
    if matches!(
        current_state,
        ConnectionState::Closed | ConnectionState::SynSent | ConnectionState::SynReceived
    ) && let Some(new_state) = infer_initial_state(flags, direction)
    {
        return new_state;
    }

    if matches!(
        current_state,
        ConnectionState::Established
            | ConnectionState::FinWait1
            | ConnectionState::FinWait2
            | ConnectionState::CloseWait
            | ConnectionState::Closing
            | ConnectionState::LastAck
            | ConnectionState::TimeWait
    ) {
        return advance_closing_state(current_state, flags, direction);
    }

    current_state
}

/// Infers initial TCP state from a single packet without prior context.
///
/// Based on RFC 9293 section 3.3.2: https://datatracker.ietf.org/doc/html/rfc9293#section-3.3.2
///
/// This stateless approach handles:
/// - Connection establishment: SYN → SYN_SENT, SYN+ACK → ESTABLISHED
/// - Late-start scenarios: First packet seen is ACK/FIN/RST
/// - Reset handling: RST → CLOSED
///
/// Returns None if the packet doesn't provide enough information to infer state,
/// allowing the caller to fall back to stateful logic.
///
/// # Examples
///
/// ```ignore
/// // SYN packet on egress initiates connection
/// let state = infer_initial_state(tcp::TCP_FLAG_SYN, Direction::Egress);
/// assert_eq!(state, Some(ConnectionState::SynSent));
///
/// // Late-start: seeing ACK packet assumes established connection
/// let state = infer_initial_state(tcp::TCP_FLAG_ACK, Direction::Ingress);
/// assert_eq!(state, Some(ConnectionState::Established));
///
/// // RST packet closes connection
/// let state = infer_initial_state(tcp::TCP_FLAG_RST, Direction::Egress);
/// assert_eq!(state, Some(ConnectionState::Closed));
///
/// // Late-start FIN: assumes connection was established
/// let state = infer_initial_state(tcp::TCP_FLAG_FIN, Direction::Egress);
/// assert_eq!(state, Some(ConnectionState::FinWait1));
/// ```
#[inline(always)]
#[must_use]
fn infer_initial_state(flags: u8, direction: Direction) -> Option<ConnectionState> {
    let syn = tcp::syn_flag(flags);
    let ack = tcp::ack_flag(flags);
    let fin = tcp::fin_flag(flags);
    let rst = tcp::rst_flag(flags);

    // RST always closes connection immediately
    if rst {
        return Some(ConnectionState::Closed);
    }

    // Handle FIN packets for late-start scenarios
    // If we see FIN as first packet, assume connection was established and transition to closing state
    if fin {
        match direction {
            Direction::Egress => {
                // This node is sending FIN (active close from established)
                return Some(ConnectionState::FinWait1);
            }
            Direction::Ingress => {
                // This node is receiving FIN (passive close from established)
                return Some(ConnectionState::CloseWait);
            }
        }
    }

    // Stateless inference based on current packet only
    // Note: RST and FIN are already handled above, so they're not set when we reach here
    match (syn, ack, direction) {
        // Pure SYN on egress = this node is initiating connection
        (true, false, Direction::Egress) => Some(ConnectionState::SynSent),

        // Pure SYN on ingress = this node is receiving connection attempt
        (true, false, Direction::Ingress) => Some(ConnectionState::SynReceived),

        // SYN+ACK on egress = this node is responding to SYN
        (true, true, Direction::Egress) => Some(ConnectionState::SynReceived),

        // SYN+ACK on ingress = late-start, receiving SYN+ACK response
        // Jump directly to ESTABLISHED as this is the final handshake packet
        (true, true, Direction::Ingress) => Some(ConnectionState::Established),

        // Pure ACK (no SYN/FIN/RST) = late-start, connection already established
        // RST and FIN are guaranteed to be unset due to early returns above
        (false, true, _) if !fin && !rst => Some(ConnectionState::Established),

        // No recognizable establishment pattern - return None to use stateful logic
        _ => None,
    }
}

/// Advances through the TCP closing handshake states (RFC 9293 FIN handshake).
///
/// Maintains granular states: FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT
///
/// Tracks state from THIS NODE's perspective (where Mermin is running):
/// - Egress: This node sent the packet
/// - Ingress: This node received the packet
///
/// # Examples
///
/// ```ignore
/// // Active close: this node sends FIN
/// let state = advance_closing_state(
///     ConnectionState::Established,
///     tcp::TCP_FLAG_FIN | tcp::TCP_FLAG_ACK,
///     Direction::Egress
/// );
/// assert_eq!(state, ConnectionState::FinWait1);
///
/// // Peer ACKs our FIN
/// let state = advance_closing_state(
///     ConnectionState::FinWait1,
///     tcp::TCP_FLAG_ACK,
///     Direction::Ingress
/// );
/// assert_eq!(state, ConnectionState::FinWait2);
///
/// // Peer sends their FIN
/// let state = advance_closing_state(
///     ConnectionState::FinWait2,
///     tcp::TCP_FLAG_FIN,
///     Direction::Ingress
/// );
/// assert_eq!(state, ConnectionState::TimeWait);
/// ```
#[inline(always)]
#[must_use]
fn advance_closing_state(
    current_state: ConnectionState,
    flags: u8,
    direction: Direction,
) -> ConnectionState {
    let ack = tcp::ack_flag(flags);
    let fin = tcp::fin_flag(flags);
    let rst = tcp::rst_flag(flags);

    // RST always closes connection immediately
    if rst {
        return ConnectionState::Closed;
    }

    match (current_state, fin, ack, direction) {
        // ESTABLISHED state transitions
        (ConnectionState::Established, true, _, Direction::Egress) => ConnectionState::FinWait1, // Active close
        (ConnectionState::Established, true, _, Direction::Ingress) => ConnectionState::CloseWait, // Passive close

        // FIN_WAIT_1 state transitions (we sent FIN, waiting for peer's response)
        (ConnectionState::FinWait1, true, true, Direction::Ingress) => ConnectionState::TimeWait, // Received FIN+ACK from peer (RFC 9293 Note 2)
        (ConnectionState::FinWait1, true, false, Direction::Ingress) => ConnectionState::Closing, // Received FIN from peer (simultaneous close)
        (ConnectionState::FinWait1, false, true, Direction::Ingress) => ConnectionState::FinWait2, // Received ACK of our FIN

        // FIN_WAIT_2 state transitions (waiting for peer's FIN)
        (ConnectionState::FinWait2, true, _, Direction::Ingress) => ConnectionState::TimeWait,

        // CLOSING state transitions (simultaneous close: waiting for peer's ACK)
        (ConnectionState::Closing, _, true, Direction::Ingress) => ConnectionState::TimeWait,

        // CLOSE_WAIT state transitions (peer closed, we're now closing our side)
        (ConnectionState::CloseWait, true, _, Direction::Egress) => ConnectionState::LastAck,

        // LAST_ACK state transitions (waiting for peer's ACK of our FIN)
        (ConnectionState::LastAck, _, true, Direction::Ingress) => ConnectionState::Closed,

        // TIME_WAIT and default cases
        _ => current_state,
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
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(feature = "test")]
mod host_test_shim {
    extern crate alloc;
    use alloc::vec::Vec;
    use core::mem;

    use crate::Error;

    #[repr(C)]
    pub struct MockSkBuff {
        pub ifindex: u32,
    }

    pub struct SkBuff {
        #[allow(dead_code)]
        pub skb: *mut MockSkBuff,
        _data: Vec<u8>,
        _mock_skb: alloc::boxed::Box<MockSkBuff>,
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
            let skb = SkBuff::new(data, 42);
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
            tcp_syn_ns: 0,
            tcp_syn_ack_ns: 0,
            tcp_last_payload_fwd_ns: 0,
            tcp_last_payload_rev_ns: 0,
            tcp_txn_sum_ns: 0,
            tcp_txn_count: 0,
            tcp_jitter_avg_ns: 0,
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
            tcp_state: ConnectionState::Closed,
            forward_tcp_flags: 0,
            reverse_tcp_flags: 0,
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

        // Ethernet header
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
        let ether_type = result.unwrap();
        let expected_src = [192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let expected_dst = [10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert!(result.is_ok());
        assert_eq!(ether_type, EtherType::Ipv4);
        assert_eq!(flow_key.ip_version, IpVersion::V4);
        assert_eq!(flow_key.protocol, IpProto::Tcp);
        assert_eq!(flow_key.src_ip, expected_src);
        assert_eq!(flow_key.dst_ip, expected_dst);
        assert_eq!(flow_key.src_port, 12345);
        assert_eq!(flow_key.dst_port, 443);
    }

    #[test]
    fn test_parse_flow_key_ipv4_udp() {
        let pkt = build_ipv4_udp_packet();
        let ctx = TcContext::new(pkt);
        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);
        let ether_type = result.unwrap();

        assert!(result.is_ok());
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
        let ether_type = result.unwrap();

        assert!(result.is_ok());
        assert_eq!(ether_type, EtherType::Ipv4);
        assert_eq!(flow_key.protocol, IpProto::Icmp);
        assert_eq!(flow_key.src_port, 8);
        assert_eq!(flow_key.dst_port, 0);
    }

    #[test]
    fn test_parse_flow_key_ipv6_tcp() {
        let pkt = build_ipv6_tcp_packet();
        let ctx = TcContext::new(pkt);
        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);
        let ether_type = result.unwrap();

        assert!(result.is_ok());
        assert_eq!(ether_type, EtherType::Ipv6);
        assert_eq!(flow_key.ip_version, IpVersion::V6);
        assert_eq!(flow_key.protocol, IpProto::Tcp);
        assert_eq!(flow_key.src_port, 8080);
        assert_eq!(flow_key.dst_port, 80);
    }

    #[test]
    fn test_parse_flow_key_truncated_ethernet() {
        let pkt = vec![0x00, 0x01, 0x02];
        let ctx = TcContext::new(pkt);
        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::MalformedHeader);
    }

    #[test]
    fn test_parse_flow_key_truncated_ipv4() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x06]);
        let ctx = TcContext::new(pkt);
        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::OutOfBounds);
    }

    #[test]
    fn test_parse_flow_key_invalid_ihl() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        pkt.push(0x42);
        pkt.extend_from_slice(&[0x00; 19]);
        let ctx = TcContext::new(pkt);
        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::MalformedHeader);
    }

    #[test]
    fn test_parse_flow_key_unsupported_ethertype() {
        let mut pkt = Vec::new();
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
        let mut flow_key = FlowKey::default();
        let ether_type = parse_flow_key(&ctx, &mut flow_key).unwrap();
        let mut stats = create_test_flow_stats(ether_type, flow_key.protocol);
        let result = parse_metadata(&ctx, &mut stats);
        let parsed_offset = result.unwrap();

        assert!(result.is_ok());
        assert_eq!(stats.src_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(stats.ip_dscp, 46);
        assert_eq!(stats.ip_ecn, 0);
        assert_eq!(stats.ip_ttl, 64);
        assert_eq!(stats.ip_flow_label, 0);
        assert_eq!(stats.tcp_flags, 0);
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
        let parsed_offset = result.unwrap();

        assert!(result.is_ok());
        assert_eq!(stats.src_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(stats.ip_dscp, 3);
        assert_eq!(stats.ip_ecn, 2);
        assert_eq!(stats.ip_ttl, 255);
        assert_eq!(stats.ip_flow_label, 0x12345);
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
        let parsed_offset = result.unwrap();

        assert!(result.is_ok());
        assert_eq!(stats.ip_ttl, 128);
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
        let parsed_offset = result.unwrap();

        assert!(result.is_ok());
        assert_eq!(stats.icmp_type, 8);
        assert_eq!(stats.icmp_code, 0);
        assert_eq!(parsed_offset, 42);
    }

    #[test]
    fn test_parse_metadata_tcp_with_options() {
        let mut pkt = Vec::new();

        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x40]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.push(64);
        pkt.push(6);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[192, 168, 1, 1, 10, 0, 0, 1]);
        pkt.extend_from_slice(&[0x00, 0x50, 0x01, 0xBB]);
        pkt.extend_from_slice(&[0x00; 8]);
        pkt.push(0x80);
        pkt.push(0x02);
        pkt.extend_from_slice(&[0x71, 0x10, 0x00, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&[0x00; 12]);

        let ctx = TcContext::new(pkt);
        let mut flow_key = FlowKey::default();
        let ether_type = parse_flow_key(&ctx, &mut flow_key).unwrap();
        let mut stats = create_test_flow_stats(ether_type, flow_key.protocol);
        let result = parse_metadata(&ctx, &mut stats);
        let parsed_offset = result.unwrap();

        assert!(result.is_ok());
        assert_eq!(parsed_offset, 66);
    }

    #[test]
    fn test_capture_direction_metadata_forward_ipv4() {
        let pkt = build_ipv4_tcp_packet();
        let ctx = TcContext::new(pkt);
        let mut stats = create_test_flow_stats(EtherType::Ipv4, IpProto::Tcp);
        let result = capture_direction_metadata(&ctx, &mut stats, EtherType::Ipv4, 34, true);

        assert!(result.is_ok());
        assert_eq!(stats.ip_dscp, 46);
        assert_eq!(stats.ip_ecn, 0);
        assert_eq!(stats.ip_ttl, 64);
        assert_eq!(stats.ip_flow_label, 0);
        assert_eq!(stats.reverse_ip_dscp, 0);
        assert_eq!(stats.reverse_ip_ecn, 0);
        assert_eq!(stats.reverse_ip_ttl, 0);
        assert_eq!(stats.reverse_ip_flow_label, 0);
    }

    #[test]
    fn test_capture_direction_metadata_reverse_ipv4() {
        let pkt = build_ipv4_tcp_packet();
        let ctx = TcContext::new(pkt);
        let mut stats = create_test_flow_stats(EtherType::Ipv4, IpProto::Tcp);
        let result = capture_direction_metadata(&ctx, &mut stats, EtherType::Ipv4, 34, false);

        assert!(result.is_ok());
        assert_eq!(stats.ip_dscp, 0);
        assert_eq!(stats.ip_ecn, 0);
        assert_eq!(stats.ip_ttl, 0);
        assert_eq!(stats.reverse_ip_dscp, 46);
        assert_eq!(stats.reverse_ip_ecn, 0);
        assert_eq!(stats.reverse_ip_ttl, 64);
    }

    #[test]
    fn test_capture_direction_metadata_forward_ipv6() {
        let pkt = build_ipv6_tcp_packet();
        let ctx = TcContext::new(pkt);
        let mut stats = create_test_flow_stats(EtherType::Ipv6, IpProto::Tcp);
        let result = capture_direction_metadata(&ctx, &mut stats, EtherType::Ipv6, 54, true);

        assert!(result.is_ok());
        assert_eq!(stats.ip_dscp, 3);
        assert_eq!(stats.ip_ecn, 2);
        assert_eq!(stats.ip_ttl, 255);
        assert_eq!(stats.ip_flow_label, 0x12345);
        assert_eq!(stats.reverse_ip_dscp, 0);
        assert_eq!(stats.reverse_ip_ecn, 0);
        assert_eq!(stats.reverse_ip_ttl, 0);
        assert_eq!(stats.reverse_ip_flow_label, 0);
    }

    #[test]
    fn test_capture_direction_metadata_reverse_ipv6() {
        let pkt = build_ipv6_tcp_packet();
        let ctx = TcContext::new(pkt);
        let mut stats = create_test_flow_stats(EtherType::Ipv6, IpProto::Tcp);
        let result = capture_direction_metadata(&ctx, &mut stats, EtherType::Ipv6, 54, false);

        assert!(result.is_ok());
        assert_eq!(stats.ip_dscp, 0);
        assert_eq!(stats.ip_ecn, 0);
        assert_eq!(stats.ip_ttl, 0);
        assert_eq!(stats.ip_flow_label, 0);
        assert_eq!(stats.reverse_ip_dscp, 3);
        assert_eq!(stats.reverse_ip_ecn, 2);
        assert_eq!(stats.reverse_ip_ttl, 255);
        assert_eq!(stats.reverse_ip_flow_label, 0x12345);
    }

    #[test]
    fn test_capture_direction_metadata_icmp_forward() {
        let pkt = build_ipv4_icmp_packet();
        let ctx = TcContext::new(pkt);
        let mut stats = create_test_flow_stats(EtherType::Ipv4, IpProto::Icmp);
        let result = capture_direction_metadata(&ctx, &mut stats, EtherType::Ipv4, 34, true);

        assert!(result.is_ok());
        assert_eq!(stats.icmp_type, 8); // Echo Request
        assert_eq!(stats.icmp_code, 0);
        assert_eq!(stats.reverse_icmp_type, 0);
        assert_eq!(stats.reverse_icmp_code, 0);
    }

    #[test]
    fn test_capture_direction_metadata_icmp_reverse() {
        let pkt = build_ipv4_icmp_packet();
        let ctx = TcContext::new(pkt);
        let mut stats = create_test_flow_stats(EtherType::Ipv4, IpProto::Icmp);
        let result = capture_direction_metadata(&ctx, &mut stats, EtherType::Ipv4, 34, false);

        assert!(result.is_ok());
        assert_eq!(stats.icmp_type, 0);
        assert_eq!(stats.icmp_code, 0);
        assert_eq!(stats.reverse_icmp_type, 8);
        assert_eq!(stats.reverse_icmp_code, 0);
    }

    #[test]
    fn test_parse_flow_key_unsupported_protocol() {
        let mut pkt = Vec::new();

        // Ethernet header
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 header with protocol 255 (Reserved)
        pkt.push(0x45); // IHL=5
        pkt.push(0x00); // DSCP=0, ECN=0
        pkt.extend_from_slice(&[0x00, 0x28]); // Total length: 40 bytes
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ID + Flags
        pkt.push(64); // TTL
        pkt.push(255); // Protocol: 255 (Reserved)
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        pkt.extend_from_slice(&[192, 168, 1, 1]); // Src IP
        pkt.extend_from_slice(&[192, 168, 1, 2]); // Dst IP
        // Some payload
        pkt.extend_from_slice(&[0x00; 20]);

        let ctx = TcContext::new(pkt);
        let mut flow_key = FlowKey::default();
        let result = parse_flow_key(&ctx, &mut flow_key);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::UnsupportedProtocol);
    }

    #[test]
    fn test_tcp_timing_logic() {
        let mut stats = create_test_flow_stats(EtherType::Ipv4, IpProto::Tcp);

        stats.tcp_flags = FlowStats::TCP_FLAG_SYN;
        update_tcp_timing(&mut stats, true, false, 1_000);
        assert_eq!(stats.tcp_syn_ns, 1_000);
        assert_eq!(stats.tcp_syn_ack_ns, 0);

        // Once ACK is also present, SYN timestamp should NOT be overwritten, but SYN/ACK should be set.
        stats.tcp_flags |= FlowStats::TCP_FLAG_ACK;
        update_tcp_timing(&mut stats, false, false, 1_200);
        assert_eq!(stats.tcp_syn_ns, 1_000);
        assert_eq!(stats.tcp_syn_ack_ns, 1_200);

        // --------------------------------------------------------------------
        // Payload timing:
        // - forward payload sets tcp_last_payload_fwd_ns
        // - reverse payload sets tcp_last_payload_rev_ns
        // - if there was a forward payload timestamp, reverse computes delta, updates sum/count,
        //   resets tcp_last_payload_fwd_ns to 0, and updates jitter avg.
        // --------------------------------------------------------------------

        update_tcp_timing(&mut stats, true, true, 2_000);
        assert_eq!(stats.tcp_last_payload_fwd_ns, 2_000);
        assert_eq!(stats.tcp_last_payload_rev_ns, 0);
        assert_eq!(stats.tcp_txn_sum_ns, 0);
        assert_eq!(stats.tcp_txn_count, 0);
        assert_eq!(stats.tcp_jitter_avg_ns, 0);

        // Reverse payload closes the "transaction": delta=100, sum+=100, count+=1, fwd_ts reset to 0.
        update_tcp_timing(&mut stats, false, true, 2_100);
        assert_eq!(stats.tcp_last_payload_rev_ns, 2_100);
        assert_eq!(stats.tcp_txn_sum_ns, 100);
        assert_eq!(stats.tcp_txn_count, 1);
        assert_eq!(stats.tcp_last_payload_fwd_ns, 0);
        assert_eq!(stats.tcp_jitter_avg_ns, 6);

        // Another forward payload starts a new pair.
        update_tcp_timing(&mut stats, true, true, 3_000);
        assert_eq!(stats.tcp_last_payload_fwd_ns, 3_000);

        // Reverse payload delta=116 -> sum=216, count=2, jitter: J=6 + |116-6|/16 = 6 + 110/16 = 12
        update_tcp_timing(&mut stats, false, true, 3_116);
        assert_eq!(stats.tcp_txn_sum_ns, 216);
        assert_eq!(stats.tcp_txn_count, 2);
        assert_eq!(stats.tcp_last_payload_fwd_ns, 0);
        assert_eq!(stats.tcp_jitter_avg_ns, 12);

        // - payload_len == 0 should not touch payload timestamps / txn counters
        // - saturating_sub: if reverse timestamp < forward timestamp, delta becomes 0
        let snap_sum = stats.tcp_txn_sum_ns;
        let snap_cnt = stats.tcp_txn_count;
        let snap_jit = stats.tcp_jitter_avg_ns;
        let snap_fwd = stats.tcp_last_payload_fwd_ns;
        let snap_rev = stats.tcp_last_payload_rev_ns;

        update_tcp_timing(&mut stats, true, false, 9_999);
        update_tcp_timing(&mut stats, false, false, 9_999);

        assert_eq!(stats.tcp_txn_sum_ns, snap_sum);
        assert_eq!(stats.tcp_txn_count, snap_cnt);
        assert_eq!(stats.tcp_jitter_avg_ns, snap_jit);
        assert_eq!(stats.tcp_last_payload_fwd_ns, snap_fwd);
        assert_eq!(stats.tcp_last_payload_rev_ns, snap_rev);
    }

    #[test]
    fn test_rst_resets_connection() {
        let states = [
            ConnectionState::SynSent,
            ConnectionState::Established,
            ConnectionState::FinWait1,
            ConnectionState::TimeWait,
        ];

        for state in states {
            assert_eq!(
                determine_tcp_state(state, tcp::TCP_FLAG_RST, Direction::Egress),
                ConnectionState::Closed,
                "State {:?} did not reset on RST",
                state
            );
        }
    }

    #[test]
    fn test_handshake_transitions() {
        // This node sends SYN (egress) from CLOSED state (RFC 9293: initial state)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Closed,
                tcp::TCP_FLAG_SYN,
                Direction::Egress,
            ),
            ConnectionState::SynSent
        );

        // Receives SYN+ACK (ingress) - jump directly to ESTABLISHED
        assert_eq!(
            determine_tcp_state(
                ConnectionState::SynSent,
                tcp::TCP_FLAG_SYN | tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::Established
        );

        // This node sends final ACK (egress) - stays ESTABLISHED
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Established,
                tcp::TCP_FLAG_ACK,
                Direction::Egress,
            ),
            ConnectionState::Established
        );
    }

    #[test]
    fn test_simultaneous_open() {
        // Receive SYN from peer while in SYN_SENT (simultaneous open)
        // Stateless logic sees SYN on ingress → SYN_RECEIVED
        assert_eq!(
            determine_tcp_state(
                ConnectionState::SynSent,
                tcp::TCP_FLAG_SYN,
                Direction::Ingress,
            ),
            ConnectionState::SynReceived
        );
    }

    #[test]
    fn test_active_close() {
        // This node initiates close with FIN+ACK (egress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Established,
                tcp::TCP_FLAG_FIN | tcp::TCP_FLAG_ACK,
                Direction::Egress,
            ),
            ConnectionState::FinWait1
        );

        // Peer ACKs the FIN (ingress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::FinWait1,
                tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::FinWait2
        );

        // Peer sends its own FIN+ACK (ingress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::FinWait2,
                tcp::TCP_FLAG_FIN | tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::TimeWait
        );
    }

    #[test]
    fn test_passive_close() {
        // Peer initiates close with FIN+ACK (ingress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Established,
                tcp::TCP_FLAG_FIN | tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::CloseWait
        );

        // This node sends its own FIN+ACK (egress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::CloseWait,
                tcp::TCP_FLAG_FIN | tcp::TCP_FLAG_ACK,
                Direction::Egress,
            ),
            ConnectionState::LastAck
        );

        // Peer ACKs our FIN (ingress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::LastAck,
                tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::Closed
        );
    }

    #[test]
    fn test_simultaneous_close() {
        // This node sends FIN+ACK (egress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Established,
                tcp::TCP_FLAG_FIN | tcp::TCP_FLAG_ACK,
                Direction::Egress,
            ),
            ConnectionState::FinWait1
        );

        // Peer also sends FIN before ACKing our FIN (ingress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::FinWait1,
                tcp::TCP_FLAG_FIN,
                Direction::Ingress,
            ),
            ConnectionState::Closing
        );

        // Peer ACKs our FIN (ingress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Closing,
                tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::TimeWait
        );
    }

    #[test]
    fn test_noise_ignored() {
        // Pure ACK in ESTABLISHED stays ESTABLISHED (egress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Established,
                tcp::TCP_FLAG_ACK,
                Direction::Egress,
            ),
            ConnectionState::Established
        );

        // PSH+ACK (data packets) stay ESTABLISHED (ingress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Established,
                tcp::TCP_FLAG_PSH | tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::Established
        );
    }

    // Late-start scenario tests: mermin starts observing mid-connection

    #[test]
    fn test_late_start_syn_ack() {
        // Late-start: First packet seen is SYN+ACK (ingress) from CLOSED state
        // Should infer we're in handshake and jump to ESTABLISHED
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Closed,
                tcp::TCP_FLAG_SYN | tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::Established
        );
    }

    #[test]
    fn test_late_start_ack_only() {
        // Late-start: First packet seen is pure ACK from CLOSED state (data transfer already happening)
        // Should infer connection is ESTABLISHED
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Closed,
                tcp::TCP_FLAG_ACK,
                Direction::Egress,
            ),
            ConnectionState::Established
        );
    }

    #[test]
    fn test_late_start_psh_ack() {
        // Late-start: First packet seen is PSH+ACK from CLOSED state (data transfer)
        // Should infer connection is ESTABLISHED
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Closed,
                tcp::TCP_FLAG_PSH | tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::Established
        );
    }

    #[test]
    fn test_late_start_fin_ingress() {
        // Late-start: First packet seen is FIN+ACK (ingress) from CLOSED state - peer is closing
        // Assume connection was established, transition directly to CLOSE_WAIT
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Closed,
                tcp::TCP_FLAG_FIN | tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::CloseWait
        );

        // This node sends its own FIN (egress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::CloseWait,
                tcp::TCP_FLAG_FIN,
                Direction::Egress,
            ),
            ConnectionState::LastAck
        );

        // Peer ACKs our FIN (ingress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::LastAck,
                tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::Closed
        );
    }

    #[test]
    fn test_late_start_fin_egress() {
        // Late-start: First packet seen is FIN (egress) from CLOSED state - this node is closing
        // Assume connection was established, transition directly to FIN_WAIT_1
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Closed,
                tcp::TCP_FLAG_FIN,
                Direction::Egress,
            ),
            ConnectionState::FinWait1
        );

        // Peer ACKs our FIN (ingress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::FinWait1,
                tcp::TCP_FLAG_ACK,
                Direction::Ingress,
            ),
            ConnectionState::FinWait2
        );

        // Peer sends its own FIN (ingress)
        assert_eq!(
            determine_tcp_state(
                ConnectionState::FinWait2,
                tcp::TCP_FLAG_FIN,
                Direction::Ingress,
            ),
            ConnectionState::TimeWait
        );
    }

    #[test]
    fn test_syn_on_egress() {
        // This node initiating connection on egress from CLOSED should be SYN_SENT
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Closed,
                tcp::TCP_FLAG_SYN,
                Direction::Egress,
            ),
            ConnectionState::SynSent
        );
    }

    #[test]
    fn test_closed_state_with_no_flags() {
        // Verify that CLOSED state (RFC 9293: "no connection state at all")
        // doesn't incorrectly transition on packets with no flags
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Closed,
                0, // No flags
                Direction::Egress,
            ),
            ConnectionState::Closed
        );
    }

    #[test]
    fn test_rst_from_closed() {
        // RST from CLOSED state should stay CLOSED
        assert_eq!(
            determine_tcp_state(
                ConnectionState::Closed,
                tcp::TCP_FLAG_RST,
                Direction::Egress,
            ),
            ConnectionState::Closed
        );
    }
}
