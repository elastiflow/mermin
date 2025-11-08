#![no_std]

use network_types::{eth::EtherType, ip::IpProto};

/// Represents a record containing flow metrics and identifiers.
///
/// This struct is designed with a specific memory layout (`#[repr(C)]`)
/// and field ordering to ensure compatibility with eBPF programs, which
/// require predictable structure layouts and proper memory alignment.
/// Fields are ordered from largest alignment (8 bytes) to smallest (1 byte)
/// to minimize internal padding.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketMeta {
    // Fields with 16-byte alignment
    // ---
    /// Source IPv6 address (innermost)
    pub src_ipv6_addr: [u8; 16],
    /// Destination IPv6 address (innermost)
    pub dst_ipv6_addr: [u8; 16],
    /// Ip-in-Ip Source IPv6 address (outermost)
    pub ipip_src_ipv6_addr: [u8; 16],
    /// Ip-in-Ip Destination IPv6 address (outermost)
    pub ipip_dst_ipv6_addr: [u8; 16],
    /// Tunnel Source IPv6 address (outermost)
    pub tunnel_src_ipv6_addr: [u8; 16],
    /// Tunnel Destination IPv6 address (outermost)
    pub tunnel_dst_ipv6_addr: [u8; 16],

    // Fields with 8-byte alignment
    // ---
    /// Timestamp in nanoseconds when the packet was captured
    pub capture_time: u64,

    /// Fields with 6-byte alignment
    /// ---
    /// Source MAC address (innermost)
    pub src_mac_addr: [u8; 6],
    /// Tunnel Source MAC address (outermost)
    pub tunnel_src_mac_addr: [u8; 6],

    // Fields with 4-byte alignment
    // ---
    /// Source IPv4 address (innermost)
    pub src_ipv4_addr: [u8; 4],
    /// Destination IPv4 address (innermost)
    pub dst_ipv4_addr: [u8; 4],
    /// Interface index
    pub ifindex: u32,
    /// Flow Label from the IPv6 header
    pub ip_flow_label: u32,
    /// Total count of bytes in a packet
    pub l3_byte_count: u32,
    /// Tunnel Security Parameter Index
    pub ipsec_ah_spi: u32,
    /// Tunnel Security Parameter Index
    pub ipsec_esp_spi: u32,
    /// Tunnel sender index
    pub ipsec_sender_index: u32,
    /// Tunnel receiver index
    pub ipsec_receiver_index: u32,
    /// Ip-in-Ip Source IPv4 address (outermost)
    pub ipip_src_ipv4_addr: [u8; 4],
    /// Ip-in-Ip Destination IPv4 address (outermost)
    pub ipip_dst_ipv4_addr: [u8; 4],
    /// Tunnel Source IPv4 address (outermost)
    pub tunnel_src_ipv4_addr: [u8; 4],
    /// Tunnel Destination IPv4 address (outermost)
    pub tunnel_dst_ipv4_addr: [u8; 4],
    /// Tunnel id, typically a VNI or Key ID
    pub tunnel_id: u32,
    /// Tunnel Security Parameter Index
    pub tunnel_ipsec_ah_spi: u32,

    // Fields with 2-byte alignment
    // ---
    /// EtherType (innermost). Bytes represents a u16 value
    pub ether_type: EtherType,
    /// Source transport layer port number (innermost). Bytes represents a u16 value
    pub src_port: [u8; 2],
    /// Destination transport layer port number (innermost). Bytes represents a u16 value
    pub dst_port: [u8; 2],
    /// Ip-in-Ip EtherType (outermost). Bytes represents a u16 value
    pub ipip_ether_type: EtherType,
    /// EtherType (outermost). Bytes represents a u16 value
    pub tunnel_ether_type: EtherType,
    /// Source transport layer port number (outermost). Bytes represents a u16 value
    pub tunnel_src_port: [u8; 2],
    /// Destination transport layer port number (outermost). Bytes represents a u16 value
    pub tunnel_dst_port: [u8; 2],

    // Fields with 1-byte alignment
    // ---
    /// Indicates whether the flow record uses IPv4 or IPv6 addressing (innermost)
    pub ip_addr_type: IpAddrType,
    /// Network protocol identifier (innermost, e.g., TCP = 6, UDP = 17)
    pub proto: IpProto,
    /// Packet direction: Ingress (incoming) or Egress (outgoing)
    pub direction: Direction,
    /// Differentiated Services Code Point (DSCP) value from the IP header
    pub ip_dscp_id: u8,
    /// Explicit Congestion Notification (ECN) value from the IP header
    pub ip_ecn_id: u8,
    /// Time to Live (IPv4) or Hop Limit (IPv6) value from the IP header
    pub ip_ttl: u8,
    /// ICMP message type id
    pub icmp_type_id: u8,
    /// ICMP message code id
    pub icmp_code_id: u8,
    /// TCP flags (innermost) - bitfield: FIN|SYN|RST|PSH|ACK|URG|ECE|CWR
    pub tcp_flags: u8,
    /// Indicates whether the packet uses AH headers (outermost after tunnel)
    pub ah_exists: bool,
    /// Indicates whether the packet uses ESP headers (outermost after tunnel)
    pub esp_exists: bool,
    /// Indicates whether the packet uses Wireguard headers (outermost after tunnel)
    pub wireguard_exists: bool,
    /// Indicates whether the flow record uses IPv4 or IPv6 addressing (outermost)
    pub ipip_ip_addr_type: IpAddrType,
    /// Ip-in-Ip protocol identifier (outermost, e.g., IPv4 = 4, IPv6 = 41)
    pub ipip_proto: IpProto,
    /// Indicates whether the flow record uses IPv4 or IPv6 addressing (outermost)
    pub tunnel_ip_addr_type: IpAddrType,
    /// Tunnel type
    pub tunnel_type: TunnelType,
    /// Network protocol identifier (outermost, e.g., TCP = 6, UDP = 17)
    pub tunnel_proto: IpProto,
    /// Indicates whether the packet uses AH headers (outermost)
    pub tunnel_ah_exists: bool,
}

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

impl PacketMeta {
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src_port)
    }

    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dst_port)
    }

    #[inline]
    pub fn tunnel_src_port(&self) -> u16 {
        u16::from_be_bytes(self.tunnel_src_port)
    }

    #[inline]
    pub fn tunnel_dst_port(&self) -> u16 {
        u16::from_be_bytes(self.tunnel_dst_port)
    }

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

    // Direction convenience methods
    #[inline]
    pub fn is_ingress(&self) -> bool {
        self.direction == Direction::Ingress
    }

    #[inline]
    pub fn is_egress(&self) -> bool {
        self.direction == Direction::Egress
    }
}

/// Parser options for configuring tunnel port detection and protocol parsing in eBPF
/// Configuration for tunnel port detection
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TunnelPorts {
    /// The port number to use for Geneve tunnel detection
    /// Default is 6081 as per IANA assignment
    pub geneve_port: u16,
    /// The port number to use for VXLAN tunnel detection
    /// Default is 4789 as per IANA assignment
    pub vxlan_port: u16,
    /// The port number to use for WireGuard tunnel detection
    /// Default is 51820 as per IANA assignment
    pub wireguard_port: u16,
}

impl Default for TunnelPorts {
    fn default() -> Self {
        TunnelPorts {
            geneve_port: 6081,
            vxlan_port: 4789,
            wireguard_port: 51820,
        }
    }
}

/// Configuration for protocol parsing behavior
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ParserOptions {
    /// Bit flags for protocol parsing (see PARSE_* constants in eBPF code)
    /// Default is 0x0000 (all optional protocols disabled)
    pub protocol_flags: u16,
    /// Maximum header parse depth (number of nested headers to parse)
    /// Default is 6, range: 1-8
    pub max_header_depth: u16,
}

impl Default for ParserOptions {
    fn default() -> Self {
        ParserOptions {
            protocol_flags: 0x0000, // all optional protocols disabled by default
            max_header_depth: 6,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum IpAddrType {
    #[default]
    Unknown = 0,
    Ipv4 = 4,
    Ipv6 = 6,
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
    use crate::IpAddrType::{Ipv4, Ipv6};

    // Test PacketMeta size and alignment
    #[test]
    fn test_packet_meta_layout() {
        let expected_size = 208;
        let actual_size = size_of::<PacketMeta>();

        assert_eq!(
            actual_size, expected_size,
            "Size of PacketMeta should be {expected_size} bytes, but was {actual_size} bytes"
        );

        let expected_alignment = 8;
        let actual_alignment = align_of::<PacketMeta>();

        assert_eq!(
            actual_alignment, expected_alignment,
            "Alignment of PacketMeta should be {expected_alignment} bytes, but was {actual_alignment} bytes"
        );
    }

    // Test basic PacketMeta instantiation and field access
    #[test]
    fn test_packet_meta_creation() {
        let src_ipv4_val: [u8; 4] = 0x0A000001u32.to_be_bytes();
        let src_ipv6_val: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let dst_ipv4_val: [u8; 4] = 0xC0A80101u32.to_be_bytes();
        let dst_ipv6_val: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let src_mac_addr: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let octet_count: u32 = 15000;
        let src_port: u16 = 12345;
        let dst_port: u16 = 80;
        let tunnel_src_ipv4_val: [u8; 4] = 0x0A000002u32.to_be_bytes();
        let tunnel_dst_ipv4_val: [u8; 4] = 0xC0A80102u32.to_be_bytes();
        let tunnel_src_ipv6_val: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ];
        let tunnel_dst_ipv6_val: [u8; 16] =
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
        let tunnel_src_port: u16 = 12346;
        let tunnel_dst_port: u16 = 81;

        // Test values for IP fields
        let flow_label: u32 = 0x12345; // 20-bit flow label
        let dscp_id: u8 = 46; // EF (Expedited Forwarding) DSCP value
        let ecn_id: u8 = 2; // ECT(0) - ECN Capable Transport
        let ttl: u8 = 64; // Common default TTL value

        // Test values for ICMP fields
        let icmp_type: u8 = 8; // Echo Request
        let icmp_code: u8 = 0; // Echo Request code

        // Set some TCP flags - SYN|ACK|RST|URG|CWR (0x02 | 0x10 | 0x04 | 0x20 | 0x80 = 0xB6)
        let tcp_flags: u8 = 0xB6;

        let mut record = PacketMeta {
            capture_time: 0,
            ifindex: 1,
            src_ipv6_addr: src_ipv6_val,
            dst_ipv6_addr: dst_ipv6_val,
            src_ipv4_addr: src_ipv4_val,
            dst_ipv4_addr: dst_ipv4_val,
            l3_byte_count: octet_count,
            src_mac_addr: src_mac_addr,
            ether_type: EtherType::Ipv4,
            src_port: src_port.to_be_bytes(),
            dst_port: dst_port.to_be_bytes(),
            ip_addr_type: Ipv4,
            proto: IpProto::Tcp,
            tunnel_src_ipv6_addr: tunnel_src_ipv6_val,
            tunnel_dst_ipv6_addr: tunnel_dst_ipv6_val,
            tunnel_src_ipv4_addr: tunnel_src_ipv4_val,
            tunnel_dst_ipv4_addr: tunnel_dst_ipv4_val,
            tunnel_ether_type: EtherType::Ipv6,
            tunnel_src_port: tunnel_src_port.to_be_bytes(),
            tunnel_dst_port: tunnel_dst_port.to_be_bytes(),
            tunnel_ip_addr_type: Ipv6,
            tunnel_id: 0,
            tunnel_ipsec_ah_spi: 0,
            tunnel_type: TunnelType::None,
            tunnel_proto: IpProto::Udp,
            ip_flow_label: flow_label,
            ip_dscp_id: dscp_id,
            ip_ecn_id: ecn_id,
            ip_ttl: ttl,
            icmp_type_id: icmp_type,
            icmp_code_id: icmp_code,
            tcp_flags: tcp_flags,
            direction: Direction::Egress,
            ..Default::default()
        };

        // Test field access
        assert_eq!(record.ifindex, 1);
        assert_eq!(record.src_ipv4_addr, src_ipv4_val);
        assert_eq!(record.dst_ipv4_addr, dst_ipv4_val);
        assert_eq!(record.src_ipv6_addr, src_ipv6_val);
        assert_eq!(record.dst_ipv6_addr, dst_ipv6_val);
        assert_eq!(record.src_mac_addr, src_mac_addr);
        assert_eq!(record.l3_byte_count, octet_count);
        assert_eq!(record.ether_type, EtherType::Ipv4);
        assert_eq!(record.src_port(), 12345);
        assert_eq!(record.dst_port(), 80);
        assert_eq!(record.ip_addr_type, Ipv4);
        assert_eq!(record.proto, IpProto::Tcp);
        assert_eq!(record.tunnel_src_ipv4_addr, tunnel_src_ipv4_val);
        assert_eq!(record.tunnel_dst_ipv4_addr, tunnel_dst_ipv4_val);
        assert_eq!(record.tunnel_src_ipv6_addr, tunnel_src_ipv6_val);
        assert_eq!(record.tunnel_dst_ipv6_addr, tunnel_dst_ipv6_val);
        assert_eq!(record.tunnel_ether_type, EtherType::Ipv6);
        assert_eq!(record.tunnel_src_port, tunnel_src_port.to_be_bytes());
        assert_eq!(record.tunnel_dst_port, tunnel_dst_port.to_be_bytes());
        assert_eq!(record.tunnel_ip_addr_type, Ipv6);
        assert_eq!(record.tunnel_proto, IpProto::Udp);

        // Test IP header fields
        assert_eq!(record.ip_flow_label, flow_label);
        assert_eq!(record.ip_dscp_id, dscp_id);
        assert_eq!(record.ip_ecn_id, ecn_id);
        assert_eq!(record.ip_ttl, ttl);

        // Test ICMP fields
        assert_eq!(record.icmp_type_id, icmp_type);
        assert_eq!(record.icmp_code_id, icmp_code);

        // Test TCP flag accessors - flags set are SYN|ACK|RST|URG|CWR (0xB6)
        assert_eq!(record.syn(), true); // SYN flag is set
        assert_eq!(record.ack(), true); // ACK flag is set
        assert_eq!(record.fin(), false); // FIN flag is not set
        assert_eq!(record.rst(), true); // RST flag is set
        assert_eq!(record.psh(), false); // PSH flag is not set
        assert_eq!(record.urg(), true); // URG flag is set
        assert_eq!(record.ece(), false); // ECE flag is not set
        assert_eq!(record.cwr(), true); // CWR flag is set

        // Test direction functionality
        assert_eq!(record.direction, Direction::Egress);
        assert_eq!(record.is_egress(), true);
        assert_eq!(record.is_ingress(), false);

        // Change direction and test
        record.direction = Direction::Ingress;
        assert_eq!(record.is_ingress(), true);
        assert_eq!(record.is_egress(), false);
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
    fn test_packet_meta_default() {
        let packet = PacketMeta::default();

        // Test that all fields are initialized to their expected default values
        assert_eq!(packet.capture_time, 0);
        assert_eq!(packet.src_ipv6_addr, [0u8; 16]);
        assert_eq!(packet.dst_ipv6_addr, [0u8; 16]);
        assert_eq!(packet.tunnel_src_ipv6_addr, [0u8; 16]);
        assert_eq!(packet.tunnel_dst_ipv6_addr, [0u8; 16]);
        assert_eq!(packet.src_mac_addr, [0u8; 6]);
        assert_eq!(packet.src_ipv4_addr, [0u8; 4]);
        assert_eq!(packet.dst_ipv4_addr, [0u8; 4]);
        assert_eq!(packet.l3_byte_count, 0);
        assert_eq!(packet.tunnel_src_ipv4_addr, [0u8; 4]);
        assert_eq!(packet.tunnel_dst_ipv4_addr, [0u8; 4]);
        assert_eq!(packet.ifindex, 0);
        assert_eq!(packet.ip_flow_label, 0);
        assert_eq!(packet.ether_type, EtherType::default());
        assert_eq!(packet.src_port, [0u8; 2]);
        assert_eq!(packet.dst_port, [0u8; 2]);
        assert_eq!(packet.tunnel_ether_type, EtherType::default());
        assert_eq!(packet.tunnel_src_port, [0u8; 2]);
        assert_eq!(packet.tunnel_dst_port, [0u8; 2]);
        assert_eq!(packet.ip_addr_type, IpAddrType::default());
        assert_eq!(packet.proto, IpProto::default());
        assert_eq!(packet.tunnel_ip_addr_type, IpAddrType::default());
        assert_eq!(packet.tunnel_proto, IpProto::default());
        assert_eq!(packet.direction, Direction::default());
        assert_eq!(packet.ip_dscp_id, 0);
        assert_eq!(packet.ip_ecn_id, 0);
        assert_eq!(packet.ip_ttl, 0);
        assert_eq!(packet.icmp_type_id, 0);
        assert_eq!(packet.icmp_code_id, 0);
        assert_eq!(packet.tcp_flags, 0);

        // Test default values for enums
        assert_eq!(packet.ip_addr_type, IpAddrType::Unknown);
        assert_eq!(packet.tunnel_ip_addr_type, IpAddrType::Unknown);
        assert_eq!(packet.direction, Direction::Egress);
    }

    #[test]
    fn test_packet_meta_direction_integration() {
        let mut packet = PacketMeta::default();

        // Test default direction
        assert_eq!(packet.direction, Direction::Egress);
        assert_eq!(packet.is_ingress(), false);
        assert_eq!(packet.is_egress(), true);

        // Test setting egress direction
        packet.direction = Direction::Egress;
        assert_eq!(packet.is_ingress(), false);
        assert_eq!(packet.is_egress(), true);

        // Test setting back to ingress
        packet.direction = Direction::Ingress;
        assert_eq!(packet.is_ingress(), true);
        assert_eq!(packet.is_egress(), false);
    }

    #[test]
    fn test_tcp_flags() {
        let mut packet = PacketMeta::default();

        // Test all flags clear
        packet.tcp_flags = 0x00;
        assert_eq!(packet.fin(), false);
        assert_eq!(packet.syn(), false);
        assert_eq!(packet.rst(), false);
        assert_eq!(packet.psh(), false);
        assert_eq!(packet.ack(), false);
        assert_eq!(packet.urg(), false);
        assert_eq!(packet.ece(), false);
        assert_eq!(packet.cwr(), false);

        // Test individual flags
        packet.tcp_flags = PacketMeta::TCP_FLAG_FIN;
        assert_eq!(packet.fin(), true);
        assert_eq!(packet.syn(), false);

        packet.tcp_flags = PacketMeta::TCP_FLAG_SYN;
        assert_eq!(packet.fin(), false);
        assert_eq!(packet.syn(), true);

        packet.tcp_flags = PacketMeta::TCP_FLAG_RST;
        assert_eq!(packet.rst(), true);

        packet.tcp_flags = PacketMeta::TCP_FLAG_PSH;
        assert_eq!(packet.psh(), true);

        packet.tcp_flags = PacketMeta::TCP_FLAG_ACK;
        assert_eq!(packet.ack(), true);

        packet.tcp_flags = PacketMeta::TCP_FLAG_URG;
        assert_eq!(packet.urg(), true);

        packet.tcp_flags = PacketMeta::TCP_FLAG_ECE;
        assert_eq!(packet.ece(), true);

        packet.tcp_flags = PacketMeta::TCP_FLAG_CWR;
        assert_eq!(packet.cwr(), true);

        // Test multiple flags (common SYN-ACK combination)
        packet.tcp_flags = PacketMeta::TCP_FLAG_SYN | PacketMeta::TCP_FLAG_ACK;
        assert_eq!(packet.syn(), true);
        assert_eq!(packet.ack(), true);
        assert_eq!(packet.fin(), false);
        assert_eq!(packet.rst(), false);

        // Test all flags set
        packet.tcp_flags = 0xFF;
        assert_eq!(packet.fin(), true);
        assert_eq!(packet.syn(), true);
        assert_eq!(packet.rst(), true);
        assert_eq!(packet.psh(), true);
        assert_eq!(packet.ack(), true);
        assert_eq!(packet.urg(), true);
        assert_eq!(packet.ece(), true);
        assert_eq!(packet.cwr(), true);
    }

    #[test]
    fn test_ip_fields() {
        let mut packet = PacketMeta::default();

        // Test flow label (20-bit value)
        packet.ip_flow_label = 0xFFFFF; // Max 20-bit value
        assert_eq!(packet.ip_flow_label, 0xFFFFF);

        packet.ip_flow_label = 0x12345;
        assert_eq!(packet.ip_flow_label, 0x12345);

        // Test DSCP (6-bit value, max 63)
        packet.ip_dscp_id = 0; // Best Effort
        assert_eq!(packet.ip_dscp_id, 0);

        packet.ip_dscp_id = 46; // Expedited Forwarding
        assert_eq!(packet.ip_dscp_id, 46);

        packet.ip_dscp_id = 63; // Max value
        assert_eq!(packet.ip_dscp_id, 63);

        // Test ECN (2-bit value, max 3)
        packet.ip_ecn_id = 0; // Not ECT
        assert_eq!(packet.ip_ecn_id, 0);

        packet.ip_ecn_id = 1; // ECT(1)
        assert_eq!(packet.ip_ecn_id, 1);

        packet.ip_ecn_id = 2; // ECT(0)
        assert_eq!(packet.ip_ecn_id, 2);

        packet.ip_ecn_id = 3; // CE
        assert_eq!(packet.ip_ecn_id, 3);

        // Test TTL
        packet.ip_ttl = 0; // Min value
        assert_eq!(packet.ip_ttl, 0);

        packet.ip_ttl = 64; // Common default
        assert_eq!(packet.ip_ttl, 64);

        packet.ip_ttl = 255; // Max value
        assert_eq!(packet.ip_ttl, 255);
    }

    #[test]
    fn test_icmp_fields() {
        let mut packet = PacketMeta::default();

        // Test common ICMP types and codes
        // Echo Request
        packet.icmp_type_id = 8;
        packet.icmp_code_id = 0;
        assert_eq!(packet.icmp_type_id, 8);
        assert_eq!(packet.icmp_code_id, 0);

        // Echo Reply
        packet.icmp_type_id = 0;
        packet.icmp_code_id = 0;
        assert_eq!(packet.icmp_type_id, 0);
        assert_eq!(packet.icmp_code_id, 0);

        // Destination Unreachable - Network Unreachable
        packet.icmp_type_id = 3;
        packet.icmp_code_id = 0;
        assert_eq!(packet.icmp_type_id, 3);
        assert_eq!(packet.icmp_code_id, 0);

        // Destination Unreachable - Port Unreachable
        packet.icmp_type_id = 3;
        packet.icmp_code_id = 3;
        assert_eq!(packet.icmp_type_id, 3);
        assert_eq!(packet.icmp_code_id, 3);

        // Time Exceeded - TTL Expired
        packet.icmp_type_id = 11;
        packet.icmp_code_id = 0;
        assert_eq!(packet.icmp_type_id, 11);
        assert_eq!(packet.icmp_code_id, 0);

        // Test boundary values
        packet.icmp_type_id = 255;
        packet.icmp_code_id = 255;
        assert_eq!(packet.icmp_type_id, 255);
        assert_eq!(packet.icmp_code_id, 255);
    }
}
