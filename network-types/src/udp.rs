//! UDP header, which is present after the IP header.
//!
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |          Source Port          |       Destination Port        |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |          PDU Length           |           Checksum            |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                             data                              |
//!  /                              ...                              /
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! This struct represents the User Datagram Protocol (UDP) header as defined in RFC 768.
//! The UDP header is 8 bytes long and contains source and destination ports, length, and checksum fields.
//! All fields are stored in network byte order (big-endian).

pub const UDP_LEN: usize = 8;

/// Source port field (16 bits).
pub type SrcPort = [u8; 2];
/// Destination port field (16 bits).
pub type DstPort = [u8; 2];
/// Length field (16 bits).
pub type Len = [u8; 2];
/// Checksum field (16 bits).
pub type Checksum = [u8; 2];

/// Returns the source port number.
///
/// This method converts the source port from network byte order (big-endian)
/// to host byte order.
///
/// # Returns
/// The source port as a u16 value.
#[inline]
pub fn src_port(src: SrcPort) -> u16 {
    u16::from_be_bytes(src)
}

/// Returns the destination port number.
///
/// This method converts the destination port from network byte order (big-endian)
/// to host byte order.
///
/// # Returns
/// The destination port as a u16 value.
#[inline]
pub fn dst_port(dst: DstPort) -> u16 {
    u16::from_be_bytes(dst)
}

/// Returns the length of the UDP datagram in bytes.
///
/// The length includes both the UDP header (8 bytes) and the UDP payload.
/// This method converts the length from network byte order (big-endian)
/// to host byte order.
///
/// # Returns
/// The length as a u16 value.
#[inline]
pub fn len(len: Len) -> u16 {
    u16::from_be_bytes(len)
}

/// Returns true if the UDP length field is zero.
///
/// A zero length indicates an invalid or empty UDP datagram, as the minimum valid length
/// is 8 bytes (the size of the UDP header).
///
/// # Returns
/// `true` if length is zero, `false` otherwise.
pub fn is_empty(len: Len) -> bool {
    len == [0, 0]
}

/// Returns the UDP checksum.
///
/// The checksum is calculated over the UDP header, the UDP payload, and a pseudo-header
/// derived from the IP header. This method converts the checksum from network byte order
/// (big-endian) to host byte order.
///
/// # Returns
/// The checksum as a u16 value.
#[inline]
pub fn checksum(check: Checksum) -> u16 {
    u16::from_be_bytes(check)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_udp_constants() {
        // UDP header should be exactly 8 bytes
        assert_eq!(UDP_LEN, 8);
    }

    #[test]
    fn test_src_port() {
        // Test with a standard value
        let src_bytes = [0x30, 0x39]; // 12345 in big-endian
        assert_eq!(src_port(src_bytes), 12345);

        // Test with zero
        let zero_bytes = [0, 0];
        assert_eq!(src_port(zero_bytes), 0);

        // Test with max value
        let max_bytes = [0xFF, 0xFF];
        assert_eq!(src_port(max_bytes), u16::MAX);
    }

    #[test]
    fn test_dst_port() {
        // Test with a standard value
        let dst_bytes = [0x00, 0x50]; // 80 in big-endian
        assert_eq!(dst_port(dst_bytes), 80);

        // Test with zero
        let zero_bytes = [0, 0];
        assert_eq!(dst_port(zero_bytes), 0);

        // Test with max value
        let max_bytes = [0xFF, 0xFF];
        assert_eq!(dst_port(max_bytes), u16::MAX);
    }

    #[test]
    fn test_len() {
        // Test with a standard value (8 bytes header + 20 bytes payload)
        let len_bytes = [0x00, 0x1C]; // 28 in big-endian
        assert_eq!(len(len_bytes), 28);

        // Test with minimum valid value (just the header)
        let min_bytes = [0x00, 0x08]; // 8 in big-endian
        assert_eq!(len(min_bytes), 8);

        // Test with max value
        let max_bytes = [0xFF, 0xFF];
        assert_eq!(len(max_bytes), u16::MAX);
    }

    #[test]
    fn test_is_empty() {
        // Test with zero length (empty)
        let empty_bytes = [0, 0];
        assert!(is_empty(empty_bytes));

        // Test with non-zero length (not empty)
        let non_empty_bytes = [0x00, 0x08]; // 8 in big-endian
        assert!(!is_empty(non_empty_bytes));

        // Test with another non-zero length
        let another_non_empty = [0x00, 0x1C]; // 28 in big-endian
        assert!(!is_empty(another_non_empty));
    }

    #[test]
    fn test_checksum() {
        // Test with a standard value
        let checksum_bytes = [0x12, 0x34]; // 0x1234 in big-endian
        assert_eq!(checksum(checksum_bytes), 0x1234);

        // Test with zero (indicating checksum not used in IPv4)
        let zero_bytes = [0, 0];
        assert_eq!(checksum(zero_bytes), 0);

        // Test with max value
        let max_bytes = [0xFF, 0xFF];
        assert_eq!(checksum(max_bytes), u16::MAX);
    }

    #[test]
    fn test_type_aliases() {
        // Test that type aliases work correctly
        let src: SrcPort = [0x30, 0x39];
        let dst: DstPort = [0x00, 0x50];
        let len_field: Len = [0x00, 0x1C];
        let check: Checksum = [0x12, 0x34];

        assert_eq!(src_port(src), 12345);
        assert_eq!(dst_port(dst), 80);
        assert_eq!(len(len_field), 28);
        assert_eq!(checksum(check), 0x1234);
    }

    #[test]
    fn test_byte_order_conversion() {
        // Test that functions correctly convert from network byte order (big-endian)
        // to host byte order

        // Test various port values
        assert_eq!(src_port(12345u16.to_be_bytes()), 12345);
        assert_eq!(dst_port(80u16.to_be_bytes()), 80);
        assert_eq!(len(28u16.to_be_bytes()), 28);
        assert_eq!(checksum(0x1234u16.to_be_bytes()), 0x1234);

        // Test edge cases
        assert_eq!(src_port(1u16.to_be_bytes()), 1);
        assert_eq!(dst_port(65535u16.to_be_bytes()), 65535);
        assert_eq!(len(0u16.to_be_bytes()), 0);
        assert_eq!(checksum(0xFFFFu16.to_be_bytes()), 0xFFFF);
    }
}
