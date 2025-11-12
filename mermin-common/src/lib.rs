#![no_std]

use network_types::{eth::EtherType, ip::IpProto};

/// Flow key for bidirectional flow aggregation, compatible with Community ID hashing.
/// This key is normalized during flow creation to ensure both directions of a flow
/// (A→B and B→A) map to the same key.
/// Memory layout optimized: 40 bytes (down from 44 bytes)
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
                return false; // src < dst, keep order
            }
            if self.src_ip[i] > self.dst_ip[i] {
                return true; // src > dst, reverse
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
        // Hash IP addresses byte-by-byte for explicit, stable behavior
        for byte in &self.src_ip {
            state.write_u8(*byte);
        }
        for byte in &self.dst_ip {
            state.write_u8(*byte);
        }

        // Hash ports
        state.write_u16(self.src_port);
        state.write_u16(self.dst_port);

        // Hash version and protocol as u8
        state.write_u8(self.ip_version as u8);
        state.write_u8(self.protocol as u8);
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

/// Flow statistics maintained in eBPF maps, aggregated per normalized FlowKey.
/// Tracks bidirectional counters, timestamps, and metadata.
/// Only contains data that eBPF can parse (3-layer: Eth + IP + L4).
/// Memory layout optimized: 48 (u64) + 32 (IP arrays) + 6 (MAC) + 12 (u32) + 6 (u16) + 17 (u8) = 121 bytes
/// Note: Compiler may add padding to align to 8 bytes = 128 bytes actual
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
    /// ICMP type
    pub icmp_type: u8,
    /// ICMP code
    pub icmp_code: u8,
    /// Flag indicating forward direction metadata has been captured for current interval (1=captured, 0=not yet)
    pub forward_metadata_seen: u8,
    /// Flag indicating reverse direction metadata has been captured for current interval (1=captured, 0=not yet)
    pub reverse_metadata_seen: u8,
}

impl FlowStats {
    // TCP flag constants (same as in tcp.rs)
    pub const TCP_FLAG_FIN: u8 = 0x01;
    pub const TCP_FLAG_SYN: u8 = 0x02;
    pub const TCP_FLAG_RST: u8 = 0x04;
    pub const TCP_FLAG_PSH: u8 = 0x08;
    pub const TCP_FLAG_ACK: u8 = 0x10;
    pub const TCP_FLAG_URG: u8 = 0x20;
    pub const TCP_FLAG_ECE: u8 = 0x40;
    pub const TCP_FLAG_CWR: u8 = 0x80;

    // Helper methods for flag manipulation
    #[inline]
    fn get_tcp_flag(flags: u8, mask: u8) -> bool {
        (flags & mask) != 0
    }

    // Innermost TCP flag methods
    #[inline]
    pub fn fin(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_FIN)
    }

    #[inline]
    pub fn syn(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_SYN)
    }

    #[inline]
    pub fn rst(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_RST)
    }

    #[inline]
    pub fn psh(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_PSH)
    }

    #[inline]
    pub fn ack(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_ACK)
    }

    #[inline]
    pub fn urg(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_URG)
    }

    #[inline]
    pub fn ece(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_ECE)
    }

    #[inline]
    pub fn cwr(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_CWR)
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowStats {}

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
    /// Outermost FlowKey extracted by eBPF (2-layer parsing only).
    /// Used as key for FLOW_STATS map lookups.
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

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum TunnelType {
    #[default]
    None = 0,
    Geneve = 1,
    Gre = 2,
    Vxlan = 3,
}

impl TunnelType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelType::Geneve => "geneve",
            TunnelType::Gre => "gre",
            TunnelType::Vxlan => "vxlan",
            _ => "none",
        }
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default, Hash)]
pub enum IpVersion {
    #[default]
    Unknown = 0,
    V4 = 4,
    V6 = 6,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum Direction {
    #[default]
    Egress = 0,
    Ingress = 1,
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use network_types::eth::EtherType;

    use super::*;
    use crate::IpVersion::V4;

    // Test FlowStats creation and field access
    #[test]
    fn test_flow_stats_creation() {
        let mut src_ip = [0u8; 16];
        src_ip[..4].copy_from_slice(&[10, 0, 0, 1]);
        let mut dst_ip = [0u8; 16];
        dst_ip[..4].copy_from_slice(&[192, 168, 1, 1]);
        let src_mac: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        // Set some TCP flags - SYN|ACK|RST|URG|CWR (0x02 | 0x10 | 0x04 | 0x20 | 0x80 = 0xB6)
        let tcp_flags: u8 = 0xB6;

        let mut stats = FlowStats {
            first_seen_ns: 1_000_000_000,
            last_seen_ns: 1_005_000_000,
            packets: 10,
            bytes: 5000,
            reverse_packets: 8,
            reverse_bytes: 4000,
            src_ip,
            dst_ip,
            src_mac,
            ifindex: 1,
            ip_flow_label: 0x12345,
            reverse_ip_flow_label: 0x54321,
            ether_type: EtherType::Ipv4,
            src_port: 12345,
            dst_port: 80,
            direction: Direction::Egress,
            ip_version: V4,
            protocol: IpProto::Tcp,
            ip_dscp: 46,
            ip_ecn: 2,
            ip_ttl: 64,
            reverse_ip_dscp: 32,
            reverse_ip_ecn: 1,
            reverse_ip_ttl: 128,
            tcp_flags,
            icmp_type: 8,
            icmp_code: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 1,
        };

        // Test field access
        assert_eq!(stats.ifindex, 1);
        assert_eq!(stats.src_ip[..4], [10, 0, 0, 1]);
        assert_eq!(stats.dst_ip[..4], [192, 168, 1, 1]);
        assert_eq!(stats.src_mac, src_mac);
        assert_eq!(stats.packets, 10);
        assert_eq!(stats.bytes, 5000);
        assert_eq!(stats.ether_type, EtherType::Ipv4);
        assert_eq!(stats.src_port, 12345);
        assert_eq!(stats.dst_port, 80);
        assert_eq!(stats.ip_version, V4);
        assert_eq!(stats.protocol, IpProto::Tcp);

        // Test IP header fields
        assert_eq!(stats.ip_flow_label, 0x12345);
        assert_eq!(stats.ip_dscp, 46);
        assert_eq!(stats.ip_ecn, 2);
        assert_eq!(stats.ip_ttl, 64);

        // Test ICMP fields
        assert_eq!(stats.icmp_type, 8);
        assert_eq!(stats.icmp_code, 0);

        // Test TCP flag accessors - flags set are SYN|ACK|RST|URG|CWR (0xB6)
        assert_eq!(stats.syn(), true); // SYN flag is set
        assert_eq!(stats.ack(), true); // ACK flag is set
        assert_eq!(stats.fin(), false); // FIN flag is not set
        assert_eq!(stats.rst(), true); // RST flag is set
        assert_eq!(stats.psh(), false); // PSH flag is not set
        assert_eq!(stats.urg(), true); // URG flag is set
        assert_eq!(stats.ece(), false); // ECE flag is not set
        assert_eq!(stats.cwr(), true); // CWR flag is set

        // Test direction functionality
        assert_eq!(stats.direction, Direction::Egress);

        // Change direction and test
        stats.direction = Direction::Ingress;
        assert_eq!(stats.direction, Direction::Ingress);
    }

    #[test]
    fn test_direction_enum() {
        // Test Direction enum values and default
        assert_eq!(Direction::default(), Direction::Egress);
        assert_eq!(Direction::Egress as u8, 0);
        assert_eq!(Direction::Ingress as u8, 1);

        // Test that different directions are not equal
        assert_ne!(Direction::Ingress, Direction::Egress);
    }

    #[test]
    fn test_flow_stats_tcp_flags() {
        let mut stats = FlowStats {
            first_seen_ns: 0,
            last_seen_ns: 0,
            packets: 0,
            bytes: 0,
            reverse_packets: 0,
            reverse_bytes: 0,
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
            icmp_type: 0,
            icmp_code: 0,
            forward_metadata_seen: 0,
            reverse_metadata_seen: 0,
        };

        // Test all flags clear
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

    /// Normalization logic (matching eBPF implementation)
    fn should_reverse(key: &FlowKey) -> bool {
        // Compare IPs byte-by-byte
        for i in 0..16 {
            if key.src_ip[i] < key.dst_ip[i] {
                return false;
            }
            if key.src_ip[i] > key.dst_ip[i] {
                return true;
            }
        }
        // IPs equal, compare ports
        if key.src_port < key.dst_port {
            return false;
        }
        if key.src_port > key.dst_port {
            return true;
        }
        false
    }

    fn normalize_flow_key(key: FlowKey) -> (FlowKey, bool) {
        let is_reversed = should_reverse(&key);

        if !is_reversed {
            return (key, false);
        }

        let mut normalized = key;

        // Swap IPs
        for i in 0..16 {
            let tmp = normalized.src_ip[i];
            normalized.src_ip[i] = normalized.dst_ip[i];
            normalized.dst_ip[i] = tmp;
        }

        // Swap ports
        let tmp_port = normalized.src_port;
        normalized.src_port = normalized.dst_port;
        normalized.dst_port = tmp_port;

        (normalized, true)
    }

    #[test]
    fn test_flow_key_normalization_ipv4_tcp() {
        // Test case 1: src < dst (no swap needed)
        let key1 = ipv4_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, IpProto::Tcp);
        let (normalized1, is_reversed1) = normalize_flow_key(key1);
        assert!(!is_reversed1, "should not reverse when src < dst");
        assert_eq!(normalized1.src_ip[..4], [10, 0, 0, 1]);
        assert_eq!(normalized1.dst_ip[..4], [10, 0, 0, 2]);
        assert_eq!(normalized1.src_port, 12345);
        assert_eq!(normalized1.dst_port, 80);

        // Test case 2: src > dst (swap needed)
        let key2 = ipv4_flow_key([10, 0, 0, 2], [10, 0, 0, 1], 80, 12345, IpProto::Tcp);
        let (normalized2, is_reversed2) = normalize_flow_key(key2);
        assert!(is_reversed2, "should reverse when src > dst");
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
        let (normalized1, is_reversed1) = normalize_flow_key(key1);
        assert!(!is_reversed1);
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
        let (normalized2, is_reversed2) = normalize_flow_key(key2);
        assert!(is_reversed2);
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
        let (normalized1, is_reversed1) = normalize_flow_key(key1);
        assert!(!is_reversed1);
        assert_eq!(normalized1.src_ip, src);
        assert_eq!(normalized1.dst_ip, dst);

        // Reverse direction
        let key2 = ipv6_flow_key(dst, src, 443, 54321, IpProto::Tcp);
        let (normalized2, is_reversed2) = normalize_flow_key(key2);
        assert!(is_reversed2);
        assert_eq!(normalized2.src_ip, src);
        assert_eq!(normalized2.dst_ip, dst);

        assert_eq!(normalized1, normalized2);
    }

    #[test]
    fn test_flow_key_normalization_icmp() {
        // ICMP Echo Request: type=8, code=0 → src_port = 0x0800
        let key1 = ipv4_flow_key([10, 0, 0, 1], [10, 0, 0, 2], 0x0800, 0, IpProto::Icmp);
        let (normalized1, is_reversed1) = normalize_flow_key(key1);
        assert!(!is_reversed1);

        // ICMP Echo Reply: type=0, code=0 → src_port = 0x0000
        let key2 = ipv4_flow_key([10, 0, 0, 2], [10, 0, 0, 1], 0x0000, 0, IpProto::Icmp);
        let (normalized2, is_reversed2) = normalize_flow_key(key2);
        assert!(is_reversed2);

        // Different ICMP types don't normalize to same key (expected behavior)
        assert_ne!(normalized1.src_port, normalized2.src_port);
    }

    #[test]
    fn test_flow_key_normalization_udp() {
        // UDP flow: DNS query
        let key1 = ipv4_flow_key([192, 168, 1, 100], [8, 8, 8, 8], 53210, 53, IpProto::Udp);
        let (normalized1, is_reversed1) = normalize_flow_key(key1);
        assert!(is_reversed1, "8.8.8.8 < 192.168.1.100");
        assert_eq!(normalized1.src_ip[..4], [8, 8, 8, 8]);
        assert_eq!(normalized1.dst_ip[..4], [192, 168, 1, 100]);
        assert_eq!(normalized1.src_port, 53);
        assert_eq!(normalized1.dst_port, 53210);
    }

    #[test]
    fn test_flow_key_byte_comparison_edge_cases() {
        // Test byte-by-byte comparison (10.0.0.255 < 10.0.1.0)
        let key1 = ipv4_flow_key([10, 0, 0, 255], [10, 0, 1, 0], 1000, 2000, IpProto::Tcp);
        let (_, is_reversed1) = normalize_flow_key(key1);
        assert!(!is_reversed1, "10.0.0.255 < 10.0.1.0");

        // Test byte-by-byte comparison (10.0.1.0 > 10.0.0.255)
        let key2 = ipv4_flow_key([10, 0, 1, 0], [10, 0, 0, 255], 1000, 2000, IpProto::Tcp);
        let (_, is_reversed2) = normalize_flow_key(key2);
        assert!(is_reversed2, "10.0.1.0 > 10.0.0.255");
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

        let (normalized1, _) = normalize_flow_key(key1);
        let (normalized2, _) = normalize_flow_key(key2);

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
    fn test_flow_stats_memory_layout() {
        // Verify optimized memory layout (128 bytes)
        // 48 (u64) + 32 (IP arrays) + 6 (MAC) + 2 (padding) + 12 (u32) + 6 (u16) + 14 (u8) = 120 bytes
        // Compiler adds padding to align to 8 bytes = 128 bytes
        assert_eq!(
            size_of::<FlowStats>(),
            128,
            "FlowStats size MUST be 128 bytes for eBPF/userspace compatibility"
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
}
