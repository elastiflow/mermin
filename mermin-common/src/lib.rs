#![no_std]

use network_types::{eth::EtherType, ip::IpProto};

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum IpAddrType {
    #[default]
    Ipv4 = 4,
    Ipv6 = 6,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum Direction {
    #[default]
    Ingress = 0,
    Egress = 1,
}

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
    pub ifindex: u32,
    // Fields with 16-byte alignment
    // ---
    /// Source IPv6 address (innermost)
    pub src_ipv6_addr: [u8; 16],
    /// Destination IPv6 address (innermost)
    pub dst_ipv6_addr: [u8; 16],
    /// Source IPv6 address (outermost)
    pub tunnel_src_ipv6_addr: [u8; 16],
    /// Destination IPv6 address (outermost)
    pub tunnel_dst_ipv6_addr: [u8; 16],

    // Fields with 4-byte alignment
    // ---
    /// Source IPv4 address (innermost)
    pub src_ipv4_addr: [u8; 4],
    /// Destination IPv4 address (innermost)
    pub dst_ipv4_addr: [u8; 4],
    /// Total count of bytes in a packet.
    pub l3_octet_count: u32,
    /// Source IPv4 address (outermost)
    pub tunnel_src_ipv4_addr: [u8; 4],
    /// Destination IPv4 address (outermost)
    pub tunnel_dst_ipv4_addr: [u8; 4],

    // Fields with 2-byte alignment
    // ---
    /// EtherType (innermost). Bytes represents a u16 value.
    pub ether_type: EtherType,
    /// Source transport layer port number (innermost). Bytes represents a u16 value.
    pub src_port: [u8; 2],
    /// Destination transport layer port number (innermost). Bytes represents a u16 value.
    pub dst_port: [u8; 2],
    /// EtherType (outermost). Bytes represents a u16 value.
    pub tunnel_ether_type: EtherType,
    /// Source transport layer port number (outermost). Bytes represents a u16 value.
    pub tunnel_src_port: [u8; 2],
    /// Destination transport layer port number (outermost). Bytes represents a u16 value.
    pub tunnel_dst_port: [u8; 2],

    // Fields with 1-byte alignment
    // ---
    /// Indicates whether the flow record uses IPv4 or IPv6 addressing (innermost).
    pub ip_addr_type: IpAddrType,
    /// Network protocol identifier (innermost, e.g., TCP = 6, UDP = 17).
    pub proto: IpProto,
    /// TCP flags (innermost) - bitfield: FIN|SYN|RST|PSH|ACK|URG|ECE|CWR
    pub tcp_flags: u8,
    /// Indicates whether the flow record uses IPv4 or IPv6 addressing (outermost).
    pub tunnel_ip_addr_type: IpAddrType,
    /// Network protocol identifier (outermost, e.g., TCP = 6, UDP = 17).
    pub tunnel_proto: IpProto,
    /// TCP flags (outermost) - bitfield: FIN|SYN|RST|PSH|ACK|URG|ECE|CWR
    pub tunnel_tcp_flags: u8,
    /// Packet direction: Ingress (incoming) or Egress (outgoing)
    pub direction: Direction,
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
    const TCP_FLAG_FIN: u8 = 0x01;
    const TCP_FLAG_SYN: u8 = 0x02;
    const TCP_FLAG_RST: u8 = 0x04;
    const TCP_FLAG_PSH: u8 = 0x08;
    const TCP_FLAG_ACK: u8 = 0x10;
    const TCP_FLAG_URG: u8 = 0x20;
    const TCP_FLAG_ECE: u8 = 0x40;
    const TCP_FLAG_CWR: u8 = 0x80;

    // Helper methods for flag manipulation
    #[inline]
    fn get_tcp_flag(flags: u8, mask: u8) -> bool {
        (flags & mask) != 0
    }

    #[inline]
    fn set_tcp_flag(flags: &mut u8, mask: u8, value: bool) {
        if value {
            *flags |= mask;
        } else {
            *flags &= !mask;
        }
    }

    // Innermost TCP flag methods
    #[inline]
    pub fn fin(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_FIN)
    }

    #[inline]
    pub fn set_fin(&mut self, fin: bool) {
        Self::set_tcp_flag(&mut self.tcp_flags, Self::TCP_FLAG_FIN, fin)
    }

    #[inline]
    pub fn syn(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_SYN)
    }

    #[inline]
    pub fn set_syn(&mut self, syn: bool) {
        Self::set_tcp_flag(&mut self.tcp_flags, Self::TCP_FLAG_SYN, syn)
    }

    #[inline]
    pub fn rst(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_RST)
    }

    #[inline]
    pub fn set_rst(&mut self, rst: bool) {
        Self::set_tcp_flag(&mut self.tcp_flags, Self::TCP_FLAG_RST, rst)
    }

    #[inline]
    pub fn psh(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_PSH)
    }

    #[inline]
    pub fn set_psh(&mut self, psh: bool) {
        Self::set_tcp_flag(&mut self.tcp_flags, Self::TCP_FLAG_PSH, psh)
    }

    #[inline]
    pub fn ack(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_ACK)
    }

    #[inline]
    pub fn set_ack(&mut self, ack: bool) {
        Self::set_tcp_flag(&mut self.tcp_flags, Self::TCP_FLAG_ACK, ack)
    }

    #[inline]
    pub fn urg(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_URG)
    }

    #[inline]
    pub fn set_urg(&mut self, urg: bool) {
        Self::set_tcp_flag(&mut self.tcp_flags, Self::TCP_FLAG_URG, urg)
    }

    #[inline]
    pub fn ece(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_ECE)
    }

    #[inline]
    pub fn set_ece(&mut self, ece: bool) {
        Self::set_tcp_flag(&mut self.tcp_flags, Self::TCP_FLAG_ECE, ece)
    }

    #[inline]
    pub fn cwr(&self) -> bool {
        Self::get_tcp_flag(self.tcp_flags, Self::TCP_FLAG_CWR)
    }

    #[inline]
    pub fn set_cwr(&mut self, cwr: bool) {
        Self::set_tcp_flag(&mut self.tcp_flags, Self::TCP_FLAG_CWR, cwr)
    }

    // Outermost Tunnel TCP flag methods
    #[inline]
    pub fn tunnel_fin(&self) -> bool {
        Self::get_tcp_flag(self.tunnel_tcp_flags, Self::TCP_FLAG_FIN)
    }

    #[inline]
    pub fn set_tunnel_fin(&mut self, fin: bool) {
        Self::set_tcp_flag(&mut self.tunnel_tcp_flags, Self::TCP_FLAG_FIN, fin)
    }

    #[inline]
    pub fn tunnel_syn(&self) -> bool {
        Self::get_tcp_flag(self.tunnel_tcp_flags, Self::TCP_FLAG_SYN)
    }

    #[inline]
    pub fn set_tunnel_syn(&mut self, syn: bool) {
        Self::set_tcp_flag(&mut self.tunnel_tcp_flags, Self::TCP_FLAG_SYN, syn)
    }

    #[inline]
    pub fn tunnel_rst(&self) -> bool {
        Self::get_tcp_flag(self.tunnel_tcp_flags, Self::TCP_FLAG_RST)
    }

    #[inline]
    pub fn set_tunnel_rst(&mut self, rst: bool) {
        Self::set_tcp_flag(&mut self.tunnel_tcp_flags, Self::TCP_FLAG_RST, rst)
    }

    #[inline]
    pub fn tunnel_psh(&self) -> bool {
        Self::get_tcp_flag(self.tunnel_tcp_flags, Self::TCP_FLAG_PSH)
    }

    #[inline]
    pub fn set_tunnel_psh(&mut self, psh: bool) {
        Self::set_tcp_flag(&mut self.tunnel_tcp_flags, Self::TCP_FLAG_PSH, psh)
    }

    #[inline]
    pub fn tunnel_ack(&self) -> bool {
        Self::get_tcp_flag(self.tunnel_tcp_flags, Self::TCP_FLAG_ACK)
    }

    #[inline]
    pub fn set_tunnel_ack(&mut self, ack: bool) {
        Self::set_tcp_flag(&mut self.tunnel_tcp_flags, Self::TCP_FLAG_ACK, ack)
    }

    #[inline]
    pub fn tunnel_urg(&self) -> bool {
        Self::get_tcp_flag(self.tunnel_tcp_flags, Self::TCP_FLAG_URG)
    }

    #[inline]
    pub fn set_tunnel_urg(&mut self, urg: bool) {
        Self::set_tcp_flag(&mut self.tunnel_tcp_flags, Self::TCP_FLAG_URG, urg)
    }

    #[inline]
    pub fn tunnel_ece(&self) -> bool {
        Self::get_tcp_flag(self.tunnel_tcp_flags, Self::TCP_FLAG_ECE)
    }

    #[inline]
    pub fn set_tunnel_ece(&mut self, ece: bool) {
        Self::set_tcp_flag(&mut self.tunnel_tcp_flags, Self::TCP_FLAG_ECE, ece)
    }

    #[inline]
    pub fn tunnel_cwr(&self) -> bool {
        Self::get_tcp_flag(self.tunnel_tcp_flags, Self::TCP_FLAG_CWR)
    }

    #[inline]
    pub fn set_tunnel_cwr(&mut self, cwr: bool) {
        Self::set_tcp_flag(&mut self.tunnel_tcp_flags, Self::TCP_FLAG_CWR, cwr)
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

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use network_types::eth::EtherType;

    use super::*;
    use crate::IpAddrType::{Ipv4, Ipv6};

    // Test FlowRecord size and alignment
    #[test]
    fn test_flow_record_layout() {
        let expected_size = 112; // Size remains 112 due to struct padding/alignment
        let actual_size = size_of::<PacketMeta>();

        assert_eq!(
            actual_size, expected_size,
            "Size of FlowRecord should be {expected_size} bytes, but was {actual_size} bytes"
        );

        // Verify the alignment (should be the max alignment of members)
        // For this struct, the largest alignment would be for u64 fields (8 bytes)
        let expected_alignment = 8;
        let actual_alignment = align_of::<PacketMeta>();

        assert_eq!(
            actual_alignment, expected_alignment,
            "Alignment of FlowRecord should be {expected_alignment} bytes, but was {actual_alignment} bytes"
        );
    }

    // Test basic FlowRecord instantiation and field access
    #[test]
    fn test_flow_record_creation() {
        let src_ipv4_val: [u8; 4] = 0x0A000001u32.to_be_bytes();
        let src_ipv6_val: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let dst_ipv4_val: [u8; 4] = 0xC0A80101u32.to_be_bytes();
        let dst_ipv6_val: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
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

        // Set some TCP flags for both outer and tunnel
        let mut record = PacketMeta {
            ifindex: 1,
            src_ipv6_addr: src_ipv6_val,
            dst_ipv6_addr: dst_ipv6_val,
            src_ipv4_addr: src_ipv4_val,
            dst_ipv4_addr: dst_ipv4_val,
            l3_octet_count: octet_count,
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
            tunnel_proto: IpProto::Udp,
            tcp_flags: 0,
            tunnel_tcp_flags: 0,
            direction: Direction::Egress,
        };

        // Set TCP flags for outer header
        record.set_syn(true);
        record.set_ack(true);
        record.set_fin(false);
        record.set_rst(true);
        record.set_psh(false);
        record.set_urg(true);
        record.set_ece(false);
        record.set_cwr(true);

        // Set TCP flags for tunnel header
        record.set_tunnel_syn(false);
        record.set_tunnel_ack(true);
        record.set_tunnel_fin(true);
        record.set_tunnel_rst(false);
        record.set_tunnel_psh(true);
        record.set_tunnel_urg(false);
        record.set_tunnel_ece(true);
        record.set_tunnel_cwr(false);

        // Test field access
        assert_eq!(record.ifindex, 1);
        assert_eq!(record.src_ipv4_addr, src_ipv4_val);
        assert_eq!(record.dst_ipv4_addr, dst_ipv4_val);
        assert_eq!(record.src_ipv6_addr, src_ipv6_val);
        assert_eq!(record.dst_ipv6_addr, dst_ipv6_val);
        assert_eq!(record.l3_octet_count, octet_count);
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

        // Test TCP flag accessors for outer header
        assert_eq!(record.syn(), true);
        assert_eq!(record.ack(), true);
        assert_eq!(record.fin(), false);
        assert_eq!(record.rst(), true);
        assert_eq!(record.psh(), false);
        assert_eq!(record.urg(), true);
        assert_eq!(record.ece(), false);
        assert_eq!(record.cwr(), true);

        // Test TCP flag accessors for tunnel header
        assert_eq!(record.tunnel_syn(), false);
        assert_eq!(record.tunnel_ack(), true);
        assert_eq!(record.tunnel_fin(), true);
        assert_eq!(record.tunnel_rst(), false);
        assert_eq!(record.tunnel_psh(), true);
        assert_eq!(record.tunnel_urg(), false);
        assert_eq!(record.tunnel_ece(), true);
        assert_eq!(record.tunnel_cwr(), false);

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
        assert_eq!(Direction::default(), Direction::Ingress);
        assert_eq!(Direction::Ingress as u8, 0);
        assert_eq!(Direction::Egress as u8, 1);

        // Test that different directions are not equal
        assert_ne!(Direction::Ingress, Direction::Egress);
    }

    #[test]
    fn test_packet_meta_direction_integration() {
        let mut packet = PacketMeta::default();

        // Test default direction
        assert_eq!(packet.direction, Direction::Ingress);
        assert_eq!(packet.is_ingress(), true);
        assert_eq!(packet.is_egress(), false);

        // Test setting egress direction
        packet.direction = Direction::Egress;
        assert_eq!(packet.is_ingress(), false);
        assert_eq!(packet.is_egress(), true);

        // Test setting back to ingress
        packet.direction = Direction::Ingress;
        assert_eq!(packet.is_ingress(), true);
        assert_eq!(packet.is_egress(), false);
    }
}
