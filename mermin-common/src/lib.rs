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
    // Fields with 16-byte alignment
    /// Source IPv6 address.
    pub src_ipv6_addr: [u8; 16],
    /// Destination IPv6 address.
    pub dst_ipv6_addr: [u8; 16],

    // Fields with 4-byte alignment
    /// Source IPv4 address.
    pub src_ipv4_addr: [u8; 4],
    /// Destination IPv4 address.
    pub dst_ipv4_addr: [u8; 4],
    /// Total count of bytes in a packet.
    pub l3_octet_count: u32,

    // Fields with 2-byte alignment
    /// Source transport layer port number. Bytes represents a u16 value.
    pub src_port: [u8; 2],
    /// Destination transport layer port number. Bytes represents a u16 value.
    pub dst_port: [u8; 2],

    // Fields with 1-byte alignment
    /// Indicates whether the flow record uses IPv4 or IPv6 addressing.
    pub ip_addr_type: IpAddrType,
    /// Network protocol identifier (e.g., TCP = 6, UDP = 17).
    pub proto: IpProto,
}

impl PacketMeta {
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src_port)
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dst_port)
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*; // Import items from the parent module (lib.rs)
    use crate::IpAddrType::Ipv4;

    // Test FlowRecord size and alignment
    #[test]
    fn test_flow_record_layout() {
        // Calculate expected size:
        // src_ipv6_addr: [u8; 16] = 16 bytes
        // dst_ipv6_addr: [u8; 16] = 16 bytes
        // src_ipv4_addr: u32 = 4 bytes
        // dst_ipv4_addr: u32 = 4 bytes
        // octet_total_count: u32 = 4 bytes
        // src_port: u16 = 2 bytes
        // dst_port: u16 = 2 bytes
        // ip_addr_type: u8 = 1 byte
        // protocol: u8 = 1 byte
        // + padding for alignment = 7 bytes (to make total a multiple of 8)
        // Total = 64 bytes

        let expected_size = 56;
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
        let src_ipv4_val: [u8; 4] = 0x0A000001u32.to_be_bytes(); // 10.0.0.1
        let src_ipv6_val: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let dst_ipv4_val: [u8; 4] = 0xC0A80101u32.to_be_bytes(); // 192.168.1.1
        let dst_ipv6_val: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let octet_count: u32 = 15000;
        let src_port: u16 = 12345;
        let dst_port: u16 = 80;

        let record = PacketMeta {
            src_ipv6_addr: src_ipv6_val,
            dst_ipv6_addr: dst_ipv6_val,
            src_ipv4_addr: src_ipv4_val,
            dst_ipv4_addr: dst_ipv4_val,
            l3_octet_count: octet_count,
            src_port: src_port.to_be_bytes(),
            dst_port: dst_port.to_be_bytes(),
            ip_addr_type: Ipv4,
            proto: IpProto::Tcp,
        };

        // Test field access
        assert_eq!(record.src_ipv4_addr, src_ipv4_val);
        assert_eq!(record.dst_ipv4_addr, dst_ipv4_val);
        assert_eq!(record.src_ipv6_addr, src_ipv6_val);
        assert_eq!(record.dst_ipv6_addr, dst_ipv6_val);
        assert_eq!(record.l3_octet_count, octet_count);
        assert_eq!(record.src_port(), 12345);
        assert_eq!(record.dst_port(), 80);
        assert_eq!(record.ip_addr_type, Ipv4);
        assert_eq!(record.proto, IpProto::Tcp);
    }
}
