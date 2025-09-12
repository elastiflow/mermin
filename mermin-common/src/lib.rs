#![no_std]

use network_types::ip::IpProto;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum IpAddrType {
    #[default]
    Ipv4 = 4,
    Ipv6 = 6,
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
    /// Source transport layer port number (innermost). Bytes represents a u16 value.
    pub src_port: [u8; 2],
    /// Destination transport layer port number (innermost). Bytes represents a u16 value.
    pub dst_port: [u8; 2],
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
    /// Indicates whether the flow record uses IPv4 or IPv6 addressing (outermost).
    pub tunnel_ip_addr_type: IpAddrType,
    /// Network protocol identifier (outermost, e.g., TCP = 6, UDP = 17).
    pub tunnel_proto: IpProto,
    /// Wireguard identifier
    pub wireguard: bool,
}

impl PacketMeta {
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src_port)
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dst_port)
    }

    pub fn tunnel_src_port(&self) -> u16 {
        u16::from_be_bytes(self.tunnel_src_port)
    }

    pub fn tunnel_dst_port(&self) -> u16 {
        u16::from_be_bytes(self.tunnel_dst_port)
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;
    use crate::IpAddrType::{Ipv4, Ipv6};

    // Test FlowRecord size and alignment
    #[test]
    fn test_flow_record_layout() {
        let expected_size = 104;
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

        let record = PacketMeta {
            ifindex: 1,
            src_ipv6_addr: src_ipv6_val,
            dst_ipv6_addr: dst_ipv6_val,
            src_ipv4_addr: src_ipv4_val,
            dst_ipv4_addr: dst_ipv4_val,
            l3_octet_count: octet_count,
            src_port: src_port.to_be_bytes(),
            dst_port: dst_port.to_be_bytes(),
            ip_addr_type: Ipv4,
            proto: IpProto::Tcp,
            tunnel_src_ipv6_addr: tunnel_src_ipv6_val,
            tunnel_dst_ipv6_addr: tunnel_dst_ipv6_val,
            tunnel_src_ipv4_addr: tunnel_src_ipv4_val,
            tunnel_dst_ipv4_addr: tunnel_dst_ipv4_val,
            tunnel_src_port: tunnel_src_port.to_be_bytes(),
            tunnel_dst_port: tunnel_dst_port.to_be_bytes(),
            tunnel_ip_addr_type: Ipv6,
            tunnel_proto: IpProto::Udp,
            wireguard: false,
        };

        // Test field access
        assert_eq!(record.ifindex, 1);
        assert_eq!(record.src_ipv4_addr, src_ipv4_val);
        assert_eq!(record.dst_ipv4_addr, dst_ipv4_val);
        assert_eq!(record.src_ipv6_addr, src_ipv6_val);
        assert_eq!(record.dst_ipv6_addr, dst_ipv6_val);
        assert_eq!(record.l3_octet_count, octet_count);
        assert_eq!(record.src_port(), 12345);
        assert_eq!(record.dst_port(), 80);
        assert_eq!(record.ip_addr_type, Ipv4);
        assert_eq!(record.proto, IpProto::Tcp);
        assert_eq!(record.tunnel_src_ipv4_addr, tunnel_src_ipv4_val);
        assert_eq!(record.tunnel_dst_ipv4_addr, tunnel_dst_ipv4_val);
        assert_eq!(record.tunnel_src_ipv6_addr, tunnel_src_ipv6_val);
        assert_eq!(record.tunnel_dst_ipv6_addr, tunnel_dst_ipv6_val);
        assert_eq!(record.tunnel_src_port, tunnel_src_port.to_be_bytes());
        assert_eq!(record.tunnel_dst_port, tunnel_dst_port.to_be_bytes());
        assert_eq!(record.tunnel_ip_addr_type, Ipv6);
        assert_eq!(record.tunnel_proto, IpProto::Udp);
    }
}
