#![no_std]

/// Tag constant representing an IPv4 address type.
pub const IPV4_TAG: u8 = 4;
/// Tag constant representing an IPv6 address type.
pub const IPV6_TAG: u8 = 6;

/// Represents a standard Rust IP address, either IPv4 or IPv6.
/// This enum provides a safe way to work with IP addresses after reading
/// them from potentially unsafe contexts like `CReprIpAddr`.
pub enum IpAddr {
    /// An IPv4 address represented as a `u32`.
    V4(u32),
    /// An IPv6 address represented as a `[u8; 16]`.
    V6([u8; 16]),
}

/// A C-compatible union to hold either an IPv4 (`u32`) or IPv6 (`[u8; 16]`) address.
///
/// This union is marked `#[repr(C)]` to ensure a defined memory layout suitable
/// for C interoperability or eBPF contexts.
/// Direct access to union fields is inherently `unsafe` in Rust because the
/// compiler cannot guarantee which variant is active. This union is primarily
/// intended to be used within the `CReprIpAddr` struct, which provides a
/// discriminant `tag` to safely determine the active variant.
#[repr(C)]
pub union IpAddrUnion {
    /// Storage for an IPv4 address (4 bytes).
    pub v4: u32,
    /// Storage for an IPv6 address (16 bytes).
    pub v6: [u8; 16],
}

/// A C-compatible representation of an IP address (either IPv4 or IPv6).
///
/// This struct is designed for scenarios requiring a fixed layout, such as
/// interfacing with C code or eBPF programs. It uses a `tag` field to
/// discriminate which address type is currently stored in the `addr` union.
#[repr(C)]
pub struct CReprIpAddr {
    /// Discriminant tag indicating the type of IP address stored.
    /// Use `IPV4_TAG` for IPv4 or `IPV6_TAG` for IPv6.
    pub tag: u8,
    /// Padding to ensure the `addr` field is aligned correctly.
    /// Given the `tag` is `u8`, this padding ensures `addr` starts at offset 4.
    _padding: [u8; 3],
    /// The raw IP address bytes, stored in a union. Access should be
    /// controlled based on the value of the `tag` field. See `IpAddrUnion`.
    pub addr: IpAddrUnion,
}

/// Represents a record containing network flow metrics and identifiers.
///
/// This struct is designed with a specific memory layout (`#[repr(C)]`)
/// and field ordering to ensure compatibility with eBPF programs, which
/// require predictable structure layouts and proper memory alignment.
/// Fields are ordered from largest alignment (8 bytes) to smallest (1 byte)
/// to minimize internal padding.
#[repr(C)]
pub struct FlowRecord {
    /// Source IPv6 address.
    pub src_ipv6_addr: [u8; 16],
    /// Destination IPv6 address.
    pub dst_ipv6_addr: [u8; 16],

    // /// Total number of packets observed for this flow since its start.
    pub packet_total_count: u64,
    // /// Total number of bytes (octets) observed for this flow since its start.
    pub octet_total_count: u64,
    // /// Number of packets observed in the last measurement interval.
    // pub packet_delta_count: u64,
    // /// Number of bytes (octets) observed in the last measurement interval.
    // pub octet_delta_count: u64,

    // // Fields with 4-byte alignment
    // /// Timestamp (seconds since epoch) when the flow was first observed.
    // pub flow_start_seconds: u32,
    // /// Timestamp (seconds since epoch) when the flow was last observed or ended.
    // pub flow_end_seconds: u32,
    /// Source IPv4 address.
    pub src_ipv4_addr: u32,
    /// Destination IPv4 address.
    pub dst_ipv4_addr: u32,

    // Fields with 2-byte alignment
    /// Source transport layer port number.
    pub src_port: u16,
    /// Destination transport layer port number.
    pub dst_port: u16,

    // Fields with 1-byte alignment
    /// Network protocol identifier (e.g., TCP = 6, UDP = 17).
    pub protocol: u8,
    // /// Reason code indicating why the flow record was generated or ended.
    // /// (e.g., 1 = Active Timeout, 2 = End of Flow detected, etc. - specific values depend on the system).
    // pub flow_end_reason: u8,
    // Implicit padding (2 bytes) is added here by the compiler to ensure
    // the total struct size (88 bytes) is a multiple of the maximum alignment (8 bytes).
}

// Provide helper functions to safely create CReprIpAddr
impl CReprIpAddr {
    /// Creates a new `CReprIpAddr` containing an IPv4 address.
    /// Sets the tag to `IPV4_TAG`.
    pub fn new_v4(addr_v4: u32) -> Self {
        Self {
            tag: IPV4_TAG,
            _padding: [0; 3], // Ensure padding is zeroed
            addr: IpAddrUnion { v4: addr_v4 },
        }
    }

    /// Creates a new `CReprIpAddr` containing an IPv6 address.
    /// Sets the tag to `IPV6_TAG`.
    pub fn new_v6(addr_v6: [u8; 16]) -> Self {
        Self {
            tag: IPV6_TAG,
            _padding: [0; 3], // Ensure padding is zeroed
            addr: IpAddrUnion { v6: addr_v6 },
        }
    }

    /// Safely reads the IP address from the union based on the tag.
    ///
    /// Returns `Some(IpAddr)` if the tag is valid (`IPV4_TAG` or `IPV6_TAG`),
    /// containing the appropriate `IpAddr` variant. Returns `None` if the tag
    /// is unrecognized.
    ///
    /// # Safety
    ///
    /// This function is marked `unsafe` because it reads from a `union`. The caller
    /// must ensure that the `CReprIpAddr` was created correctly (e.g., via `new_v4`
    /// or `new_v6`) such that the `tag` accurately reflects the active union variant
    /// and the corresponding data in `addr` is valid. Reading the inactive union
    /// field is undefined behavior.
    pub unsafe fn ip_address(&self) -> Option<IpAddr> {
        match self.tag {
            IPV4_TAG => Some(IpAddr::V4(self.addr.v4)),
            IPV6_TAG => Some(IpAddr::V6(self.addr.v6)),
            _ => None, // Invalid tag
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from the parent module (lib.rs)
    use core::mem::{align_of, size_of};

    // Test CReprIpAddr::new_v4 constructor
    #[test]
    fn test_new_v4() {
        let ip_val: u32 = 0x01020304; // 1.2.3.4
        let c_repr_ip = CReprIpAddr::new_v4(ip_val);

        assert_eq!(c_repr_ip.tag, IPV4_TAG);
        assert_eq!(c_repr_ip._padding, [0; 3]);
        // Reading from a union requires unsafe
        unsafe {
            assert_eq!(c_repr_ip.addr.v4, ip_val);
        }
    }

    // Test CReprIpAddr::new_v6 constructor
    #[test]
    fn test_new_v6() {
        let ip_val: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let c_repr_ip = CReprIpAddr::new_v6(ip_val);

        assert_eq!(c_repr_ip.tag, IPV6_TAG);
        assert_eq!(c_repr_ip._padding, [0; 3]);
        // Reading from a union requires unsafe
        unsafe {
            assert_eq!(c_repr_ip.addr.v6, ip_val);
        }
    }

    // Test CReprIpAddr::ip_address helper function
    #[test]
    fn test_ip_address_helper() {
        let ipv4_val: u32 = 0xC0A80101; // 192.168.1.1
        let ipv6_val: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];

        let c_repr_v4 = CReprIpAddr::new_v4(ipv4_val);
        let c_repr_v6 = CReprIpAddr::new_v6(ipv6_val);

        // Safe access using the helper function (still needs unsafe block)
        unsafe {
            // Use match to compare Option values
            match c_repr_v4.ip_address() {
                Some(IpAddr::V4(addr)) => assert_eq!(addr, ipv4_val),
                _ => panic!("Expected Some(IpAddr::V4)"),
            }

            match c_repr_v6.ip_address() {
                Some(IpAddr::V6(addr)) => assert_eq!(addr, ipv6_val),
                _ => panic!("Expected Some(IpAddr::V6)"),
            }
        }

        // Test invalid tag case (manually construct - normally avoided)
        let invalid_repr = CReprIpAddr {
            tag: 99, // Invalid tag
            _padding: [0; 3],
            addr: IpAddrUnion { v4: 0 }, // Content doesn't matter here
        };
        unsafe {
            // Use match to check for None
            match invalid_repr.ip_address() {
                None => (), // This is what we expect
                Some(_) => panic!("Expected None for invalid tag"),
            }
        }
    }

    // Test FlowRecord size and alignment
    #[test]
    fn test_flow_record_layout() {
        // Calculate expected size:
        // src_ipv6_addr: [u8; 16] = 16 bytes
        // dst_ipv6_addr: [u8; 16] = 16 bytes
        // packet_total_count: u64 = 8 bytes
        // octet_total_count: u64 = 8 bytes
        // src_ipv4_addr: u32 = 4 bytes
        // dst_ipv4_addr: u32 = 4 bytes
        // src_port: u16 = 2 bytes
        // dst_port: u16 = 2 bytes
        // protocol: u8 = 1 byte
        // + padding for alignment = 3 bytes (to make total a multiple of 8)
        // Total = 64 bytes

        let expected_size = 64;
        let actual_size = size_of::<FlowRecord>();

        assert_eq!(
            actual_size, expected_size,
            "Size of FlowRecord should be {} bytes, but was {} bytes",
            expected_size, actual_size
        );

        // Verify the alignment (should be the max alignment of members)
        // For this struct, the largest alignment would be for u64 fields (8 bytes)
        let expected_alignment = 8;
        let actual_alignment = align_of::<FlowRecord>();

        assert_eq!(
            actual_alignment, expected_alignment,
            "Alignment of FlowRecord should be {} bytes, but was {} bytes",
            expected_alignment, actual_alignment
        );
    }

    // Test basic FlowRecord instantiation and field access
    #[test]
    fn test_flow_record_creation() {
        let src_ipv4_val: u32 = 0x0A000001; // 10.0.0.1
        let src_ipv6_val: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let dst_ipv4_val: u32 = 0xC0A80101; // 192.168.1.1
        let dst_ipv6_val: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let packet_count: u64 = 100;
        let octet_count: u64 = 15000;

        let record = FlowRecord {
            src_ipv6_addr: src_ipv6_val,
            dst_ipv6_addr: dst_ipv6_val,
            packet_total_count: packet_count,
            octet_total_count: octet_count,
            src_ipv4_addr: src_ipv4_val,
            dst_ipv4_addr: dst_ipv4_val,
            src_port: 12345,
            dst_port: 80,
            protocol: 6, // TCP
        };

        // Test field access
        assert_eq!(record.src_ipv4_addr, src_ipv4_val);
        assert_eq!(record.dst_ipv4_addr, dst_ipv4_val);
        assert_eq!(record.src_ipv6_addr, src_ipv6_val);
        assert_eq!(record.dst_ipv6_addr, dst_ipv6_val);
        assert_eq!(record.src_port, 12345);
        assert_eq!(record.dst_port, 80);
        assert_eq!(record.protocol, 6);

        // Test packet and octet count fields
        assert_eq!(record.packet_total_count, packet_count);
        assert_eq!(record.octet_total_count, octet_count);
    }
}
