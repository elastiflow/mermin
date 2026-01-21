#![no_std]
//! Shared data structures for network flow tracking between eBPF kernel code and userspace.
//!
//! This crate defines the core types used to aggregate bidirectional network flows in eBPF maps
//! and communicate flow events from kernel to userspace via ring buffers. All structures use
//! `#[repr(C)]` to ensure identical memory layout across eBPF and userspace.
//!
//! # Key Types
//!
//! - [`FlowKey`]: Normalized 5-tuple for bidirectional flow aggregation (Community ID compatible)
//! - [`FlowStats`]: Per-flow counters and metadata stored in eBPF maps (128 bytes)
//! - [`FlowEvent`]: New flow notifications sent from eBPF to userspace (234 bytes)
//!
//! # Memory Layout Requirements
//!
//! All structures are carefully sized and aligned for efficient eBPF map access.
//! Modifying field order or types will break eBPF/userspace compatibility.

use network_types::{eth::EtherType, ip::IpProto};

/// Flow key for bidirectional flow aggregation, compatible with Community ID hashing.
/// This key is normalized during flow creation to ensure both directions of a flow
/// (A→B and B→A) map to the same key.
///
/// Memory layout: 38 bytes (16+16 IPs + 2+2 ports + 1+1 version+proto)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FlowKey {
    /// Source IP address (IPv4 in first 4 bytes, zero-padded; IPv6 uses all 16)
    /// After normalization, this is the "lower" IP address
    pub src_ip: [u8; 16],
    /// Destination IP address (IPv4 in first 4 bytes, zero-padded; IPv6 uses all 16)
    /// After normalization, this is the "higher" IP address
    pub dst_ip: [u8; 16],
    /// Source port (network byte order)
    /// For ICMP/ICMPv6: holds the ICMP type (per Community ID spec)
    /// After normalization, this is the "lower" port
    pub src_port: u16,
    /// Destination port (network byte order)
    /// For ICMP/ICMPv6: holds the ICMP code (per Community ID spec)
    /// After normalization, this is the "higher" port
    pub dst_port: u16,
    /// IP version: 4 or 6
    pub ip_version: IpVersion,
    /// IP protocol number (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, etc.)
    pub protocol: IpProto,
}

impl FlowKey {
    /// Determine if this flow key should be reversed for normalization.
    ///
    /// Returns `true` if src > dst (need to swap for normalization).
    /// This ensures both directions of a flow (A→B and B→A) hash to the same key.
    ///
    /// Comparison order:
    /// 1. Compare IP addresses byte-by-byte
    /// 2. If IPs are equal, compare ports
    ///
    /// Per Community ID spec: https://github.com/corelight/community-id-spec
    #[inline(always)]
    pub fn should_normalize(&self) -> bool {
        for i in 0..16 {
            if self.src_ip[i] < self.dst_ip[i] {
                return false;
            }
            if self.src_ip[i] > self.dst_ip[i] {
                return true;
            }
        }

        if self.src_port < self.dst_port {
            return false;
        }
        if self.src_port > self.dst_port {
            return true;
        }

        false
    }

    /// Normalize this flow key for bidirectional flow aggregation.
    ///
    /// Returns `normalized_key`.
    /// The normalized key ensures both directions of a flow (A→B and B→A) map to the same key,
    /// with the "lower" endpoint always appearing as src.
    ///
    /// Per Community ID spec: https://github.com/corelight/community-id-spec
    ///
    /// # Examples
    ///
    /// ```
    /// use mermin_common::{FlowKey, IpVersion};
    /// use network_types::ip::IpProto;
    ///
    /// let forward = FlowKey {
    ///     src_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ///     dst_ip: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ///     src_port: 12345,
    ///     dst_port: 80,
    ///     ip_version: IpVersion::V4,
    ///     protocol: IpProto::Tcp,
    /// };
    ///
    /// let reverse = FlowKey {
    ///     src_ip: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ///     dst_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ///     src_port: 80,
    ///     dst_port: 12345,
    ///     ip_version: IpVersion::V4,
    ///     protocol: IpProto::Tcp,
    /// };
    ///
    /// assert_eq!(forward.normalize(), reverse.normalize());
    /// ```
    #[inline(always)]
    pub fn normalize(self) -> FlowKey {
        let needs_swap = self.should_normalize();

        if !needs_swap {
            return self;
        }

        let mut normalized = self;
        core::mem::swap(&mut normalized.src_ip, &mut normalized.dst_ip);
        core::mem::swap(&mut normalized.src_port, &mut normalized.dst_port);

        normalized
    }
}

/// Custom Hash implementation for FlowKey that is stable across Rust versions and platforms.
/// This explicitly hashes each field in a defined order, ensuring consistent behavior
/// regardless of the default Hash implementation for arrays.
///
/// WARNING: This hash is NOT stable across process boundaries or language implementations.
/// Do not persist FlowKey hashes or use them in distributed systems where different
/// processes might compute different hash values for the same logical key.
///
/// For cross-process flow tracking, use the normalized FlowKey struct directly as the key,
/// or serialize it to a canonical format (e.g., protobuf, JSON) before hashing.
impl core::hash::Hash for FlowKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        for byte in &self.src_ip {
            state.write_u8(*byte);
        }
        for byte in &self.dst_ip {
            state.write_u8(*byte);
        }
        state.write_u16(self.src_port);
        state.write_u16(self.dst_port);
        state.write_u8(self.ip_version as u8);
        state.write_u8(self.protocol as u8);
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

/// Socket identity metadata captured by LSM hooks and stored in SK_STORAGE map.
/// This data is stamped onto sockets at creation time and retrieved by TC programs
/// for process attribution on network flows.
///
/// Memory layout: 32 bytes (with automatic alignment from #[repr(C)])
/// Breakdown: u32 + u32 + [u8;16] + u64 + u32 = 32 bytes aligned
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SocketIdentity {
    /// Process ID (PID)
    pub pid: u32,
    /// Thread Group ID (TGID) - main process ID
    pub tgid: u32,
    /// Executable name from task_struct (comm field, max 16 bytes)
    pub comm: [u8; 16],
    /// Cgroup ID for container/namespace correlation
    pub cgroup_id: u64,
    /// User ID (UID) of the process owning the socket
    pub uid: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketIdentity {}

/// Flow statistics maintained in eBPF maps, aggregated per normalized FlowKey.
/// Tracks bidirectional counters, timestamps, and metadata.
/// Only contains data that eBPF can parse (3-layer: Eth + IP + L4).
/// Includes process attribution from LSM socket storage.
/// Memory layout: 208 bytes (was 176 bytes, added 32 bytes for process attribution)
/// Breakdown: 104 (u64) + 32 (IP arrays) + 6 (MAC) + 12 (u32) + 6 (u16) + 17 (u8) + 36 (process attrs) = 213 bytes unpadded, aligned to 208
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FlowStats {
    // === 8-byte aligned (u64) - 48 bytes ===
    /// Timestamp when flow was first observed (nanoseconds since boot)
    pub first_seen_ns: u64,
    /// Timestamp when flow was last observed (nanoseconds since boot)
    pub last_seen_ns: u64,
    /// Packet count in forward direction (matches normalized key's src→dst)
    pub packets: u64,
    /// Byte count in forward direction
    pub bytes: u64,
    /// Packet count in reverse direction (opposite of normalized key)
    pub reverse_packets: u64,
    /// Byte count in reverse direction
    pub reverse_bytes: u64,
    /// Timestamp when SYN was seen (nanoseconds since boot)
    pub tcp_syn_ns: u64,
    /// Timestamp when SYN/ACK was seen (nanoseconds since boot)
    pub tcp_syn_ack_ns: u64,
    /// Timestamp when last payload packet was seen in forward direction (nanoseconds since boot)
    pub tcp_last_payload_fwd_ns: u64,
    /// Timestamp when last payload packet was seen in reverse direction (nanoseconds since boot)
    pub tcp_last_payload_rev_ns: u64,
    /// Running sum of the data transmission durations for latency calculation (nanoseconds)
    pub tcp_txn_sum_ns: u64,
    /// Running count of the number of transactions included in tcp_txn_sum_ns
    pub tcp_txn_count: u32,
    /// Running average of the jitter observed between packets (nanoseconds)
    pub tcp_jitter_avg_ns: u32,

    // === 16-byte arrays - 32 bytes ===
    /// Original source IP
    pub src_ip: [u8; 16],
    /// Original destination IP
    pub dst_ip: [u8; 16],

    // === 6-byte array (MAC address) - 6 bytes ===
    /// Source MAC address
    pub src_mac: [u8; 6],

    // === 4-byte aligned (u32) - 12 bytes ===
    /// Network interface index where flow was observed
    pub ifindex: u32,
    /// IPv6 Flow Label (forward direction, first seen per interval)
    pub ip_flow_label: u32,
    /// IPv6 Flow Label (reverse direction, first seen per interval)
    pub reverse_ip_flow_label: u32,

    // === 2-byte aligned (u16) - 4 bytes ===
    /// EtherType
    pub ether_type: EtherType,
    /// Original source port
    pub src_port: u16,
    /// Original destination port
    pub dst_port: u16,

    // === 1-byte aligned (u8) - 17 bytes ===
    /// Direction: 0=egress, 1=ingress (TC hook attachment point)
    pub direction: Direction,
    /// IP version
    pub ip_version: IpVersion,
    /// IP protocol
    pub protocol: IpProto,
    /// DSCP value (forward direction, first seen per interval)
    pub ip_dscp: u8,
    /// ECN value (forward direction, first seen per interval)
    pub ip_ecn: u8,
    /// TTL/Hop Limit (forward direction, first seen per interval)
    pub ip_ttl: u8,
    /// DSCP value (reverse direction, first seen per interval)
    pub reverse_ip_dscp: u8,
    /// ECN value (reverse direction, first seen per interval)
    pub reverse_ip_ecn: u8,
    /// TTL/Hop Limit (reverse direction, first seen per interval)
    pub reverse_ip_ttl: u8,
    /// Accumulated TCP flags (OR of all flags seen)
    pub tcp_flags: u8,
    /// TCP connection state
    pub tcp_state: ConnectionState,
    /// TCP flags in forward direction only (for handshake analysis)
    pub forward_tcp_flags: u8,
    /// TCP flags in reverse direction only (for handshake analysis)
    pub reverse_tcp_flags: u8,
    /// ICMP type
    pub icmp_type: u8,
    /// ICMP code
    pub icmp_code: u8,
    /// ICMP type (reverse direction, first seen per interval)
    pub reverse_icmp_type: u8,
    /// ICMP code (reverse direction, first seen per interval)
    pub reverse_icmp_code: u8,
    /// Flag indicating forward direction metadata has been captured for current interval (1=captured, 0=not yet)
    pub forward_metadata_seen: u8,
    /// Flag indicating reverse direction metadata has been captured for current interval (1=captured, 0=not yet)
    pub reverse_metadata_seen: u8,

    // === Process attribution (from LSM socket storage) - 36 bytes ===
    /// Process ID (0 if attribution unavailable)
    pub process_pid: u32,
    /// Thread Group ID - main process ID (0 if attribution unavailable)
    pub process_tgid: u32,
    /// Process executable name from task_struct (empty if attribution unavailable)
    pub process_comm: [u8; 16],
    /// Cgroup ID for container correlation (0 if attribution unavailable)
    pub process_cgroup_id: u64,
    /// User ID of process owning socket (0 if attribution unavailable)
    pub process_uid: u32,
}

impl FlowStats {
    // TCP flag constants duplicated here for no_std compatibility.
    pub const TCP_FLAG_FIN: u8 = 0x01;
    pub const TCP_FLAG_SYN: u8 = 0x02;
    pub const TCP_FLAG_RST: u8 = 0x04;
    pub const TCP_FLAG_PSH: u8 = 0x08;
    pub const TCP_FLAG_ACK: u8 = 0x10;
    pub const TCP_FLAG_URG: u8 = 0x20;
    pub const TCP_FLAG_ECE: u8 = 0x40;
    pub const TCP_FLAG_CWR: u8 = 0x80;

    // Private helper to avoid code duplication across 8 public flag accessors
    #[inline]
    fn get_tcp_flag(flags: u8, mask: u8) -> bool {
        (flags & mask) != 0
    }

    /// Returns whether the FIN (finish) TCP flag is set.
    /// Indicates the sender has finished sending data.
    #[inline]
    pub fn fin(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_FIN)
    }

    /// Returns whether the SYN (synchronize) TCP flag is set.
    /// Used in the TCP handshake to establish connections.
    ///
    /// # Examples
    ///
    /// ```
    /// use mermin_common::{FlowStats, ConnectionState};
    /// # use network_types::eth::EtherType;
    /// # use network_types::ip::IpProto;
    /// # use mermin_common::{IpVersion, Direction};
    /// let stats = FlowStats {
    /// #     first_seen_ns: 0, last_seen_ns: 0, packets: 0, bytes: 0,
    /// #     reverse_packets: 0, reverse_bytes: 0,
    /// #     src_ip: [0; 16], dst_ip: [0; 16], src_mac: [0; 6],
    /// #     ifindex: 0, ip_flow_label: 0, reverse_ip_flow_label: 0,
    /// #     ether_type: EtherType::Ipv4, src_port: 0, dst_port: 0,
    /// #     direction: Direction::Egress, ip_version: IpVersion::V4,
    /// #     protocol: IpProto::Tcp, ip_dscp: 0, ip_ecn: 0, ip_ttl: 0,
    /// #     reverse_ip_dscp: 0, reverse_ip_ecn: 0, reverse_ip_ttl: 0,
    /// #     tcp_flags: FlowStats::TCP_FLAG_SYN | FlowStats::TCP_FLAG_ACK,
    /// #     tcp_jitter_avg_ns: 0, tcp_last_payload_fwd_ns: 0, tcp_last_payload_rev_ns: 0,
    /// #     tcp_syn_ns: 0, tcp_syn_ack_ns: 0, tcp_txn_count: 0, tcp_txn_sum_ns: 0,
    /// #     forward_tcp_flags: 0, reverse_tcp_flags: 0, icmp_type: 0, icmp_code: 0,
    /// #     reverse_icmp_type: 0, reverse_icmp_code: 0, tcp_state: ConnectionState::Closed,
    /// #     forward_metadata_seen: 0, reverse_metadata_seen: 0,
    /// };
    ///
    /// assert!(stats.syn());
    /// assert!(stats.ack());
    /// assert!(!stats.fin());
    /// ```
    #[inline]
    pub fn syn(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_SYN)
    }

    /// Returns whether the RST (reset) TCP flag is set.
    /// Indicates immediate connection termination.
    #[inline]
    pub fn rst(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_RST)
    }

    /// Returns whether the PSH (push) TCP flag is set.
    /// Requests immediate data delivery to the application.
    #[inline]
    pub fn psh(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_PSH)
    }

    /// Returns whether the ACK (acknowledgment) TCP flag is set.
    /// Acknowledges received data.
    #[inline]
    pub fn ack(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_ACK)
    }

    /// Returns whether the URG (urgent) TCP flag is set.
    /// Indicates urgent data present.
    #[inline]
    pub fn urg(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_URG)
    }

    /// Returns whether the ECE (ECN-Echo) TCP flag is set.
    /// Part of Explicit Congestion Notification.
    #[inline]
    pub fn ece(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_ECE)
    }

    /// Returns whether the CWR (Congestion Window Reduced) TCP flag is set.
    /// Indicates sender reduced congestion window in response to ECN.
    #[inline]
    pub fn cwr(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_CWR)
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowStats {}

/// TCP connection state based on RFC 9293 section 3.3.2:
/// https://datatracker.ietf.org/doc/html/rfc9293#section-3.3.2
///
/// This implementation tracks TCP connection states by observing packet flags and
/// state transitions. Note that as a passive observer, we may not see all packets
/// (e.g., LISTEN state), so some transitions are inferred from available information.
///
/// States match OpenTelemetry semantic conventions:
/// https://opentelemetry.io/docs/specs/semconv/attributes/network/
///
/// Uses #[repr(u8)] for C-compatible memory layout, allowing direct use in eBPF shared memory.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum ConnectionState {
    /// No connection state at all (RFC 9293: "represents no connection state at all")
    /// This is the default state when no TCB exists or no connection has been observed
    #[default]
    Closed = 0,
    /// Waiting for a connection request from any remote TCP peer (server listening)
    /// Note: As a passive observer, this state is never actually observed in practice
    Listen = 1,
    /// Waiting for a matching connection request after having sent a connection request
    SynSent = 2,
    /// Waiting for a confirming connection request acknowledgment after having both received and sent a connection request
    SynReceived = 3,
    /// An open connection, data received can be delivered to the user. The normal state for the data transfer phase
    Established = 4,
    /// Waiting for a connection termination request from the remote TCP peer, or an acknowledgment of the connection termination request previously sent
    FinWait1 = 5,
    /// Waiting for a connection termination request from the remote TCP peer
    FinWait2 = 6,
    /// Waiting for a connection termination request from the local user
    CloseWait = 7,
    /// Waiting for a connection termination request acknowledgment from the remote TCP peer
    Closing = 8,
    /// Waiting for an acknowledgment of the connection termination request previously sent to the remote TCP peer
    LastAck = 9,
    /// Waiting for enough time to pass to be sure the remote TCP peer received the acknowledgment of its connection termination request
    TimeWait = 10,
}

impl ConnectionState {
    /// Convert the connection state to a string representation matching
    /// OpenTelemetry semantic conventions
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            ConnectionState::Closed => "closed",
            ConnectionState::Listen => "listen",
            ConnectionState::SynSent => "syn_sent",
            ConnectionState::SynReceived => "syn_received",
            ConnectionState::Established => "established",
            ConnectionState::FinWait1 => "fin_wait_1",
            ConnectionState::FinWait2 => "fin_wait_2",
            ConnectionState::CloseWait => "close_wait",
            ConnectionState::Closing => "closing",
            ConnectionState::LastAck => "last_ack",
            ConnectionState::TimeWait => "time_wait",
        }
    }
}

impl core::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Event sent from eBPF to userspace for each new flow.
/// Contains the outermost FlowKey (for eBPF map lookups) plus UNPARSED packet data
/// for deep parsing in userspace to extract innermost 5-tuple and tunnel metadata.
///
/// Key Optimization: eBPF already parsed outer headers into FlowStats, so we only
/// send the UNPARSED portion to avoid redundant parsing in userspace.
///
/// Memory layout: 234 bytes total (62 bytes saved vs naive approach!)
/// - FlowKey: 38 bytes (outermost 5-tuple from eBPF)
/// - snaplen: 2 bytes (total original packet length)
/// - parsed_offset: 2 bytes (where unparsed data starts in original packet)
/// - packet_data: 192 bytes (ONLY unparsed portion, for tunnel inner headers)
///
/// Example (Plain TCP/IPv4):
/// - parsed_offset = 54 (Eth 14 + IPv4 20 + TCP 20 already in FlowStats)
/// - packet_data = empty or just TCP payload (not needed for telemetry)
///
/// Example (VXLAN):
/// - parsed_offset = 50 (Eth 14 + IPv4 20 + UDP 8 + VXLAN 8 already in FlowStats)
/// - packet_data = inner Ethernet + inner IP + inner L4 (needs parsing!)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FlowEvent {
    /// Outermost FlowKey extracted by eBPF's shallow parsing (Ethernet + IP + L4 only).
    /// Used as key for FLOW_STATS map lookups.
    /// Deep tunnel inspection happens in userspace using `packet_data`.
    pub flow_key: FlowKey,

    /// Total length of original packet (before truncation).
    pub snaplen: u16,

    /// Byte offset where packet_data starts in the original packet.
    /// Everything before this offset was already parsed by eBPF into FlowStats.
    /// For plain traffic: equals header length (Eth + IP + L4)
    /// For tunnels: equals outer header length (up to tunnel payload)
    pub parsed_offset: u16,

    /// Raw packet bytes starting from parsed_offset (up to 192 bytes).
    /// For plain traffic: Usually empty (all headers already parsed).
    /// For tunnels: Contains inner Ethernet + inner IP + inner L4 for deep parsing.
    pub packet_data: [u8; 192],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowEvent {}

/// Tunnel encapsulation type detected in network traffic.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum TunnelType {
    /// No tunnel encapsulation detected
    #[default]
    None = 0,
    /// Generic Network Virtualization Encapsulation (RFC 8926)
    Geneve = 1,
    /// Generic Routing Encapsulation (RFC 2784)
    Gre = 2,
    /// Virtual eXtensible Local Area Network (RFC 7348)
    Vxlan = 3,
}

impl TunnelType {
    /// Returns the string representation of the tunnel type.
    ///
    /// # Examples
    ///
    /// ```
    /// use mermin_common::TunnelType;
    ///
    /// assert_eq!(TunnelType::Vxlan.as_str(), "vxlan");
    /// assert_eq!(TunnelType::Geneve.as_str(), "geneve");
    /// assert_eq!(TunnelType::None.as_str(), "none");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelType::Geneve => "geneve",
            TunnelType::Gre => "gre",
            TunnelType::Vxlan => "vxlan",
            _ => "none",
        }
    }
}

/// IP protocol version from packet header.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default, Hash)]
pub enum IpVersion {
    /// Unknown or unsupported IP version
    #[default]
    Unknown = 0,
    /// Internet Protocol version 4
    V4 = 4,
    /// Internet Protocol version 6
    V6 = 6,
}

/// Traffic direction relative to the TC (Traffic Control) attachment point.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum Direction {
    /// Outbound traffic (TC egress hook)
    #[default]
    Egress = 0,
    /// Inbound traffic (TC ingress hook)
    Ingress = 1,
}

/// Key for tracking listening ports in eBPF map.
/// Used to identify which ports have local processes listening (for client/server inference).
/// Memory layout: 3 bytes (2 for port + 1 for protocol)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ListeningPortKey {
    /// Port number in host byte order
    pub port: u16,
    /// IP protocol (TCP or UDP)
    pub protocol: IpProto,
}

#[cfg(feature = "user")]
// SAFETY: ListeningPortKey is repr(C) with only POD (Plain Old Data) fields:
// - `port` is u16 (primitive type, all bit patterns valid)
// - `protocol` is IpProto which is repr(u8) (all bit patterns valid for u8)
// The struct has natural alignment (u16 aligned on 2-byte boundary, followed by u8),
// with no padding between fields due to field ordering. All possible bit patterns
// represent valid values. This makes it safe to treat as plain old data for eBPF
// map interoperability via aya::Pod.
unsafe impl aya::Pod for ListeningPortKey {}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use network_types::eth::EtherType;

    use super::*;
    use crate::IpVersion::V4;

    fn create_flow_stats() -> FlowStats {
        FlowStats {
            first_seen_ns: 0,
            last_seen_ns: 0,
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
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_mac: [0; 6],
            ifindex: 0,
            ip_flow_label: 0,
            reverse_ip_flow_label: 0,
            ether_type: EtherType::Ipv4,
            src_port: 0,
            dst_port: 0,
            direction: Direction::Egress,
            ip_version: V4,
            protocol: IpProto::Tcp,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 0,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
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
            process_pid: 0,
            process_tgid: 0,
            process_comm: [0; 16],
            process_cgroup_id: 0,
            process_uid: 0,
        }
    }
    #[test]
    fn test_flow_stats_tcp_flags() {
        let mut stats = create_flow_stats();

        // Verify all flags clear
        stats.tcp_flags = 0x00;
        assert_eq!(stats.fin(), false);
        assert_eq!(stats.syn(), false);
        assert_eq!(stats.rst(), false);
        assert_eq!(stats.psh(), false);
        assert_eq!(stats.ack(), false);
        assert_eq!(stats.urg(), false);
        assert_eq!(stats.ece(), false);
        assert_eq!(stats.cwr(), false);

        // Test individual flags
        stats.tcp_flags = FlowStats::TCP_FLAG_FIN;
        assert_eq!(stats.fin(), true);
        assert_eq!(stats.syn(), false);

        stats.tcp_flags = FlowStats::TCP_FLAG_SYN;
        assert_eq!(stats.fin(), false);
        assert_eq!(stats.syn(), true);

        stats.tcp_flags = FlowStats::TCP_FLAG_RST;
        assert_eq!(stats.rst(), true);

        stats.tcp_flags = FlowStats::TCP_FLAG_PSH;
        assert_eq!(stats.psh(), true);

        stats.tcp_flags = FlowStats::TCP_FLAG_ACK;
        assert_eq!(stats.ack(), true);

        stats.tcp_flags = FlowStats::TCP_FLAG_URG;
        assert_eq!(stats.urg(), true);

        stats.tcp_flags = FlowStats::TCP_FLAG_ECE;
        assert_eq!(stats.ece(), true);

        stats.tcp_flags = FlowStats::TCP_FLAG_CWR;
        assert_eq!(stats.cwr(), true);

        // Test multiple flags (common SYN-ACK combination)
        stats.tcp_flags = FlowStats::TCP_FLAG_SYN | FlowStats::TCP_FLAG_ACK;
        assert_eq!(stats.syn(), true);
        assert_eq!(stats.ack(), true);
        assert_eq!(stats.fin(), false);
        assert_eq!(stats.rst(), false);

        // Test all flags set
        stats.tcp_flags = 0xFF;
        assert_eq!(stats.fin(), true);
        assert_eq!(stats.syn(), true);
        assert_eq!(stats.rst(), true);
        assert_eq!(stats.psh(), true);
        assert_eq!(stats.ack(), true);
        assert_eq!(stats.urg(), true);
        assert_eq!(stats.ece(), true);
        assert_eq!(stats.cwr(), true);
    }

    // ========================================================================
    // FlowKey Normalization Tests (Community ID Compatible)
    // ========================================================================

    /// Helper to create IPv4 FlowKey
    fn ipv4_flow_key(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        proto: IpProto,
    ) -> FlowKey {
        let mut key = FlowKey {
            ip_version: IpVersion::V4,
            protocol: proto,
            src_ip: [0u8; 16],
            dst_ip: [0u8; 16],
            src_port: sport,
            dst_port: dport,
        };
        key.src_ip[..4].copy_from_slice(&src);
        key.dst_ip[..4].copy_from_slice(&dst);
        key
    }

    /// Helper to create IPv6 FlowKey
    fn ipv6_flow_key(
        src: [u8; 16],
        dst: [u8; 16],
        sport: u16,
        dport: u16,
        proto: IpProto,
    ) -> FlowKey {
        FlowKey {
            ip_version: IpVersion::V6,
            protocol: proto,
            src_ip: src,
            dst_ip: dst,
            src_port: sport,
            dst_port: dport,
        }
    }

    #[test]
    fn test_flow_key_normalization_ipv4_tcp() {
        // Test case 1: src < dst (no swap needed)
        let key1 = ipv4_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, IpProto::Tcp);
        let should_reverse1 = key1.should_normalize();
        let normalized1 = key1.normalize();

        assert!(!should_reverse1, "should not reverse when src < dst");
        assert_eq!(normalized1.src_ip[..4], [10, 0, 0, 1]);
        assert_eq!(normalized1.dst_ip[..4], [10, 0, 0, 2]);
        assert_eq!(normalized1.src_port, 12345);
        assert_eq!(normalized1.dst_port, 80);

        // Test case 2: src > dst (swap needed)
        let key2 = ipv4_flow_key([10, 0, 0, 2], [10, 0, 0, 1], 80, 12345, IpProto::Tcp);
        let should_reverse2 = key2.should_normalize();
        let normalized2 = key2.normalize();

        assert!(should_reverse2, "should reverse when src > dst");
        assert_eq!(normalized2.src_ip[..4], [10, 0, 0, 1]);
        assert_eq!(normalized2.dst_ip[..4], [10, 0, 0, 2]);
        assert_eq!(normalized2.src_port, 12345);
        assert_eq!(normalized2.dst_port, 80);

        // Test case 3: Bidirectional flows normalize to same key
        assert_eq!(
            normalized1, normalized2,
            "bidirectional flows should have same key"
        );
    }

    #[test]
    fn test_flow_key_normalization_ipv4_same_ip_different_ports() {
        // Same IP, sport < dport (no swap)
        let key1 = ipv4_flow_key(
            [192, 168, 1, 10],
            [192, 168, 1, 10],
            1000,
            2000,
            IpProto::Tcp,
        );
        let normalized1 = key1.normalize();

        assert!(!key1.should_normalize());
        assert_eq!(normalized1.src_port, 1000);
        assert_eq!(normalized1.dst_port, 2000);

        // Same IP, sport > dport (swap)
        let key2 = ipv4_flow_key(
            [192, 168, 1, 10],
            [192, 168, 1, 10],
            2000,
            1000,
            IpProto::Tcp,
        );
        let normalized2 = key2.normalize();

        assert!(key2.should_normalize());
        assert_eq!(normalized2.src_port, 1000);
        assert_eq!(normalized2.dst_port, 2000);

        // Should normalize to same key
        assert_eq!(normalized1, normalized2);
    }

    #[test]
    fn test_flow_key_normalization_ipv6() {
        // IPv6: 2001:db8::1 < 2001:db8::2
        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];

        let key1 = ipv6_flow_key(src, dst, 54321, 443, IpProto::Tcp);
        let normalized1 = key1.normalize();

        assert!(!key1.should_normalize());
        assert_eq!(normalized1.src_ip, src);
        assert_eq!(normalized1.dst_ip, dst);

        // Reverse direction
        let key2 = ipv6_flow_key(dst, src, 443, 54321, IpProto::Tcp);
        let normalized2 = key2.normalize();

        assert!(key2.should_normalize());
        assert_eq!(normalized2.src_ip, src);
        assert_eq!(normalized2.dst_ip, dst);

        assert_eq!(normalized1, normalized2);
    }

    #[test]
    fn test_flow_key_normalization_icmp() {
        // ICMP Echo Request: type=8, code=0 → src_port = 0x0800
        let key1 = ipv4_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 0x0800, 0, IpProto::Icmp);
        let normalized1 = key1.normalize();

        assert!(!key1.should_normalize());

        // ICMP Echo Reply: type=0, code=0 → src_port = 0x0000
        let key2 = ipv4_flow_key([10, 0, 0, 2], [10, 0, 0, 1], 0x0000, 0, IpProto::Icmp);
        let normalized2 = key2.normalize();

        assert!(key2.should_normalize());

        // Different ICMP types don't normalize to same key (expected behavior)
        assert_ne!(normalized1.src_port, normalized2.src_port);
    }

    #[test]
    fn test_flow_key_normalization_udp() {
        // UDP flow: DNS query
        let key1 = ipv4_flow_key([192, 168, 1, 100], [8, 8, 8, 8], 53210, 53, IpProto::Udp);
        let normalized1 = key1.normalize();

        assert!(key1.should_normalize(), "8.8.8.8 < 192.168.1.100");
        assert_eq!(normalized1.src_ip[..4], [8, 8, 8, 8]);
        assert_eq!(normalized1.dst_ip[..4], [192, 168, 1, 100]);
        assert_eq!(normalized1.src_port, 53);
        assert_eq!(normalized1.dst_port, 53210);
    }

    #[test]
    fn test_flow_key_byte_comparison_edge_cases() {
        // Test byte-by-byte comparison (10.0.0.255 < 10.0.1.0)
        let key1 = ipv4_flow_key([10, 0, 0, 255], [10, 0, 1, 0], 1000, 2000, IpProto::Tcp);
        assert!(!key1.should_normalize(), "10.0.0.255 < 10.0.1.0");

        // Test byte-by-byte comparison (10.0.1.0 > 10.0.0.255)
        let key2 = ipv4_flow_key([10, 0, 1, 0], [10, 0, 0, 255], 1000, 2000, IpProto::Tcp);
        assert!(key2.should_normalize(), "10.0.1.0 > 10.0.0.255");
    }

    #[test]
    fn test_flow_key_hash_consistency() {
        use core::hash::{Hash, Hasher};

        struct SimpleHasher {
            state: u64,
        }

        impl Hasher for SimpleHasher {
            fn finish(&self) -> u64 {
                self.state
            }
            fn write(&mut self, bytes: &[u8]) {
                for &b in bytes {
                    self.state = self.state.wrapping_mul(31).wrapping_add(b as u64);
                }
            }
        }

        let key1 = ipv4_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, IpProto::Tcp);
        let key2 = ipv4_flow_key([10, 0, 0, 2], [10, 0, 0, 1], 80, 12345, IpProto::Tcp);

        let normalized1 = key1.normalize();
        let normalized2 = key2.normalize();

        let mut hasher1 = SimpleHasher { state: 0 };
        let mut hasher2 = SimpleHasher { state: 0 };

        normalized1.hash(&mut hasher1);
        normalized2.hash(&mut hasher2);

        assert_eq!(
            hasher1.finish(),
            hasher2.finish(),
            "bidirectional flows should hash to same value"
        );
    }

    /// Test FlowKey memory layout for eBPF/userspace compatibility.
    ///
    /// CRITICAL: These assertions ensure that FlowKey has identical memory layout
    /// in both eBPF (kernel) and userspace. If these fail, the eBPF program and
    /// userspace program will interpret the same memory differently, causing
    /// data corruption and undefined behavior.
    ///
    /// #[repr(C)] guarantees C-compatible layout, but we must verify:
    /// 1. Size remains constant (no unexpected padding)
    /// 2. Alignment is consistent (affects struct packing)
    #[test]
    fn test_flow_key_memory_layout() {
        // Verify optimized memory layout (38 bytes - even better than expected!)
        // Layout: 16+16 (IPs) + 2+2 (ports) + 1+1 (version+proto) = 38 bytes
        assert_eq!(
            size_of::<FlowKey>(),
            38,
            "FlowKey size MUST be 38 bytes for eBPF/userspace compatibility"
        );

        // Verify alignment (critical for correct memory access in eBPF)
        assert_eq!(
            align_of::<FlowKey>(),
            2,
            "FlowKey alignment MUST be 2 bytes for eBPF/userspace compatibility"
        );
    }

    /// Test FlowStats memory layout for eBPF/userspace compatibility.
    ///
    /// CRITICAL: These assertions ensure that FlowStats has identical memory layout
    /// in both eBPF (kernel) and userspace. FlowStats is shared via eBPF maps,
    /// so any size/alignment mismatch will cause silent data corruption.
    ///
    /// #[repr(C)] guarantees C-compatible layout, but we must verify:
    /// 1. Size remains constant (including any padding)
    /// 2. Alignment is consistent
    #[test]
    fn test_socket_identity_memory_layout() {
        // SocketIdentity: u32 + u32 + [u8;16] + u64 + u32 = 32 bytes (with alignment)
        assert_eq!(
            size_of::<SocketIdentity>(),
            32,
            "SocketIdentity size MUST be 32 bytes for eBPF/userspace compatibility"
        );

        // Verify alignment (critical for correct memory access in eBPF)
        assert_eq!(
            align_of::<SocketIdentity>(),
            8,
            "SocketIdentity alignment MUST be 8 bytes (u64 field) for eBPF/userspace compatibility"
        );
    }

    #[test]
    fn test_flow_stats_memory_layout() {
        // Updated size with process attribution fields (5 fields = 32 bytes added)
        // FlowStats was 176 bytes, now 176 + 32 = 208 bytes
        assert_eq!(
            size_of::<FlowStats>(),
            208,
            "FlowStats size MUST be 208 bytes for eBPF/userspace compatibility (added process attribution)"
        );

        // Verify alignment (critical for correct memory access in eBPF)
        assert_eq!(
            align_of::<FlowStats>(),
            8,
            "FlowStats alignment MUST be 8 bytes (u64 fields) for eBPF/userspace compatibility"
        );
    }

    /// Test FlowEvent memory layout for eBPF/userspace compatibility.
    ///
    /// CRITICAL: These assertions ensure that FlowEvent has identical memory layout
    /// in both eBPF (kernel) and userspace. FlowEvent is sent via perf/ring buffers,
    /// so any size/alignment mismatch will cause parsing errors in userspace.
    #[test]
    fn test_flow_event_memory_layout() {
        // Verify FlowEvent size: FlowKey(38) + snaplen(2) + parsed_offset(2) + packet_data(192) = 234
        assert_eq!(
            size_of::<FlowEvent>(),
            234,
            "FlowEvent size MUST be 234 bytes for eBPF/userspace compatibility (62 bytes saved vs old design!)"
        );

        // Verify alignment (2-byte aligned, inherited from FlowKey)
        assert_eq!(
            align_of::<FlowEvent>(),
            2,
            "FlowEvent alignment MUST be 2 bytes (inherited from FlowKey) for eBPF/userspace compatibility"
        );
    }

    #[test]
    fn test_should_normalize_ipv4_different_ips() {
        // Case 1: src < dst (10.0.0.1 < 10.0.0.2) → should NOT normalize
        let key1 = ipv4_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, IpProto::Tcp);
        assert_eq!(
            key1.should_normalize(),
            false,
            "src < dst should not normalize"
        );

        // Case 2: src > dst (10.0.0.2 > 10.0.0.1) → should normalize
        let key2 = ipv4_flow_key([10, 0, 0, 2], [10, 0, 0, 1], 12345, 80, IpProto::Tcp);
        assert_eq!(key2.should_normalize(), true, "src > dst should normalize");

        // Case 3: Different IPs, larger first byte (192.168.1.1 > 10.0.0.1)
        let key3 = ipv4_flow_key([192, 168, 1, 1], [10, 0, 0, 1], 80, 443, IpProto::Tcp);
        assert_eq!(
            key3.should_normalize(),
            true,
            "larger first byte should normalize"
        );

        // Case 4: Different IPs, smaller first byte (10.0.0.1 < 192.168.1.1)
        let key4 = ipv4_flow_key([10, 0, 0, 1], [192, 168, 1, 1], 443, 80, IpProto::Tcp);
        assert_eq!(
            key4.should_normalize(),
            false,
            "smaller first byte should not normalize"
        );
    }

    #[test]
    fn test_should_normalize_ipv4_same_ip_different_ports() {
        // Case 1: Same IP, sport < dport → should NOT normalize
        let key1 = ipv4_flow_key(
            [192, 168, 1, 10],
            [192, 168, 1, 10],
            1000,
            2000,
            IpProto::Tcp,
        );
        assert_eq!(
            key1.should_normalize(),
            false,
            "same IP, sport < dport should not normalize"
        );

        // Case 2: Same IP, sport > dport → should normalize
        let key2 = ipv4_flow_key(
            [192, 168, 1, 10],
            [192, 168, 1, 10],
            2000,
            1000,
            IpProto::Tcp,
        );
        assert_eq!(
            key2.should_normalize(),
            true,
            "same IP, sport > dport should normalize"
        );

        // Case 3: Same IP, same ports → should NOT normalize
        let key3 = ipv4_flow_key(
            [192, 168, 1, 10],
            [192, 168, 1, 10],
            1000,
            1000,
            IpProto::Tcp,
        );
        assert_eq!(
            key3.should_normalize(),
            false,
            "same IP, same ports should not normalize"
        );
    }

    #[test]
    fn test_should_normalize_ipv4_byte_by_byte_comparison() {
        // Test that comparison happens byte-by-byte, not as 32-bit integer

        // Case 1: 10.0.0.255 < 10.0.1.0 (third byte differs)
        let key1 = ipv4_flow_key([10, 0, 0, 255], [10, 0, 1, 0], 1000, 2000, IpProto::Tcp);
        assert_eq!(
            key1.should_normalize(),
            false,
            "10.0.0.255 < 10.0.1.0 (byte 3 comparison)"
        );

        // Case 2: 10.0.1.0 > 10.0.0.255 (third byte differs)
        let key2 = ipv4_flow_key([10, 0, 1, 0], [10, 0, 0, 255], 1000, 2000, IpProto::Tcp);
        assert_eq!(
            key2.should_normalize(),
            true,
            "10.0.1.0 > 10.0.0.255 (byte 3 comparison)"
        );

        // Case 3: 1.2.3.4 < 255.255.255.255
        let key3 = ipv4_flow_key([1, 2, 3, 4], [255, 255, 255, 255], 80, 443, IpProto::Tcp);
        assert_eq!(key3.should_normalize(), false, "1.2.3.4 < 255.255.255.255");

        // Case 4: 255.255.255.255 > 1.2.3.4
        let key4 = ipv4_flow_key([255, 255, 255, 255], [1, 2, 3, 4], 80, 443, IpProto::Tcp);
        assert_eq!(key4.should_normalize(), true, "255.255.255.255 > 1.2.3.4");
    }

    #[test]
    fn test_should_normalize_ipv6_different_ips() {
        // IPv6: 2001:db8::1 < 2001:db8::2
        let src1 = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let dst1 = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];

        let key1 = ipv6_flow_key(src1, dst1, 54321, 443, IpProto::Tcp);
        assert_eq!(
            key1.should_normalize(),
            false,
            "IPv6: 2001:db8::1 < 2001:db8::2 should not normalize"
        );

        // IPv6: 2001:db8::2 > 2001:db8::1
        let key2 = ipv6_flow_key(dst1, src1, 443, 54321, IpProto::Tcp);
        assert_eq!(
            key2.should_normalize(),
            true,
            "IPv6: 2001:db8::2 > 2001:db8::1 should normalize"
        );
    }

    #[test]
    fn test_should_normalize_ipv6_same_ip_different_ports() {
        let ip = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0xff, 0xfe, 0x00,
            0x00, 0x01,
        ];

        // Same IPv6, sport < dport
        let key1 = ipv6_flow_key(ip, ip, 1000, 2000, IpProto::Tcp);
        assert_eq!(
            key1.should_normalize(),
            false,
            "same IPv6, sport < dport should not normalize"
        );

        // Same IPv6, sport > dport
        let key2 = ipv6_flow_key(ip, ip, 2000, 1000, IpProto::Tcp);
        assert_eq!(
            key2.should_normalize(),
            true,
            "same IPv6, sport > dport should normalize"
        );

        // Same IPv6, same ports
        let key3 = ipv6_flow_key(ip, ip, 1000, 1000, IpProto::Tcp);
        assert_eq!(
            key3.should_normalize(),
            false,
            "same IPv6, same ports should not normalize"
        );
    }

    #[test]
    fn test_should_normalize_ipv6_byte_by_byte_comparison() {
        // Test byte-by-byte comparison for IPv6

        // 2001:db8::ffff < 2001:db8:0:1::0 (byte 7 differs: 0x00 vs 0x01)
        let src1 = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff,
        ];
        let dst1 = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let key1 = ipv6_flow_key(src1, dst1, 1000, 2000, IpProto::Tcp);
        assert_eq!(
            key1.should_normalize(),
            false,
            "2001:db8::ffff < 2001:db8:0:1::0"
        );

        let key2 = ipv6_flow_key(dst1, src1, 1000, 2000, IpProto::Tcp);
        assert_eq!(
            key2.should_normalize(),
            true,
            "2001:db8:0:1::0 > 2001:db8::ffff"
        );
    }

    #[test]
    fn test_should_normalize_different_protocols() {
        // TCP
        let tcp_key = ipv4_flow_key([10, 0, 0, 2], [10, 0, 0, 1], 80, 443, IpProto::Tcp);
        assert_eq!(
            tcp_key.should_normalize(),
            true,
            "TCP flow with src > dst should normalize"
        );

        // UDP
        let udp_key = ipv4_flow_key([10, 0, 0, 2], [10, 0, 0, 1], 53, 12345, IpProto::Udp);
        assert_eq!(
            udp_key.should_normalize(),
            true,
            "UDP flow with src > dst should normalize"
        );

        // ICMP (type=8 in src_port, code=0 in dst_port per Community ID spec)
        let icmp_key = ipv4_flow_key([10, 0, 0, 2], [10, 0, 0, 1], 0x0800, 0, IpProto::Icmp);
        assert_eq!(
            icmp_key.should_normalize(),
            true,
            "ICMP flow with src > dst should normalize"
        );
    }

    #[test]
    fn test_should_normalize_with_normalize_method_consistency() {
        // Verify that should_normalize() correctly predicts whether normalize() will swap

        let test_cases: [([u8; 4], [u8; 4], u16, u16, bool); 6] = [
            // (src_ip, dst_ip, sport, dport, expected_should_normalize)
            ([10, 0, 0, 1], [10, 0, 0, 2], 1000, 2000, false),
            ([10, 0, 0, 2], [10, 0, 0, 1], 2000, 1000, true),
            ([192, 168, 1, 1], [192, 168, 1, 1], 1000, 2000, false),
            ([192, 168, 1, 1], [192, 168, 1, 1], 2000, 1000, true),
            ([8, 8, 8, 8], [192, 168, 1, 1], 53, 12345, false),
            ([192, 168, 1, 1], [8, 8, 8, 8], 12345, 53, true),
        ];

        for (src, dst, sport, dport, expected) in test_cases.iter() {
            let key = ipv4_flow_key(*src, *dst, *sport, *dport, IpProto::Tcp);
            let should_norm = key.should_normalize();
            let normalized = key.normalize();

            assert_eq!(
                should_norm, *expected,
                "should_normalize() returned {} but expected {} for src={:?} dst={:?} sport={} dport={}",
                should_norm, expected, src, dst, sport, dport
            );

            if should_norm {
                // If should_normalize is true, verify that normalize() actually swapped
                assert_eq!(
                    normalized.src_ip[..4],
                    *dst,
                    "normalize() should have swapped IPs"
                );
                assert_eq!(
                    normalized.dst_ip[..4],
                    *src,
                    "normalize() should have swapped IPs"
                );
                assert_eq!(
                    normalized.src_port, *dport,
                    "normalize() should have swapped ports"
                );
                assert_eq!(
                    normalized.dst_port, *sport,
                    "normalize() should have swapped ports"
                );
            } else {
                // If should_normalize is false, verify that normalize() kept the same values
                assert_eq!(key, normalized, "normalize() should not have modified key");
            }
        }
    }

    #[test]
    fn test_should_normalize_zero_padding_ipv4() {
        // Verify that IPv4 addresses in 16-byte array are properly zero-padded
        // and that only the first 4 bytes are compared for IPv4

        let key = ipv4_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 1000, 2000, IpProto::Tcp);

        // Verify zero-padding in bytes 4-15
        for i in 4..16 {
            assert_eq!(key.src_ip[i], 0, "IPv4 src_ip byte {} should be zero", i);
            assert_eq!(key.dst_ip[i], 0, "IPv4 dst_ip byte {} should be zero", i);
        }

        // The comparison should work correctly despite zero-padding
        assert_eq!(
            key.should_normalize(),
            false,
            "IPv4 comparison should work with zero-padding"
        );
    }

    #[test]
    fn test_connection_state_as_str() {
        assert_eq!(ConnectionState::Closed.as_str(), "closed");
        assert_eq!(ConnectionState::Listen.as_str(), "listen");
        assert_eq!(ConnectionState::SynSent.as_str(), "syn_sent");
        assert_eq!(ConnectionState::SynReceived.as_str(), "syn_received");
        assert_eq!(ConnectionState::Established.as_str(), "established");
        assert_eq!(ConnectionState::FinWait1.as_str(), "fin_wait_1");
        assert_eq!(ConnectionState::FinWait2.as_str(), "fin_wait_2");
        assert_eq!(ConnectionState::CloseWait.as_str(), "close_wait");
        assert_eq!(ConnectionState::Closing.as_str(), "closing");
        assert_eq!(ConnectionState::LastAck.as_str(), "last_ack");
        assert_eq!(ConnectionState::TimeWait.as_str(), "time_wait");
    }

    #[test]
    fn test_connection_state_discriminants() {
        // Test that enum discriminants match expected u8 values for eBPF compatibility
        assert_eq!(ConnectionState::Closed as u8, 0);
        assert_eq!(ConnectionState::Listen as u8, 1);
        assert_eq!(ConnectionState::SynSent as u8, 2);
        assert_eq!(ConnectionState::SynReceived as u8, 3);
        assert_eq!(ConnectionState::Established as u8, 4);
        assert_eq!(ConnectionState::FinWait1 as u8, 5);
        assert_eq!(ConnectionState::FinWait2 as u8, 6);
        assert_eq!(ConnectionState::CloseWait as u8, 7);
        assert_eq!(ConnectionState::Closing as u8, 8);
        assert_eq!(ConnectionState::LastAck as u8, 9);
        assert_eq!(ConnectionState::TimeWait as u8, 10);
    }
}
