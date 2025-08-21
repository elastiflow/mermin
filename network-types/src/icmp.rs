use core::mem;

/// ICMP header for IPv4, which is present after the IP header.
/// 
/// ICMP (Internet Control Message Protocol) is used for diagnostic and error
/// reporting purposes. Unlike TCP and UDP, ICMP does not use port numbers.
/// 
/// Basic ICMP Header Format:
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |     Type      |     Code      |          Checksum             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                             Data                              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// This struct represents the basic ICMP header as defined in RFC 792.
/// The ICMP header is 8 bytes long (including the 4-byte data field).
/// All fields are stored in network byte order (big-endian).
///
/// # Example
/// ```
/// use network_types::icmp::IcmpHdr;
///
/// let mut icmp_header = IcmpHdr {
///     icmp_type: 8,  // Echo Request
///     code: 0,       // Code 0 for Echo Request
///     checksum: [0, 0],
///     data: [0, 0, 0, 0],
/// };
///
/// icmp_header.set_checksum(0x1234);
/// assert_eq!(icmp_header.checksum(), 0x1234);
/// ```
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct IcmpHdr {
    /// ICMP message type (8 bits)
    pub icmp_type: u8,
    /// ICMP message code (8 bits)
    pub code: u8,
    /// ICMP checksum in network byte order (big-endian)
    pub checksum: [u8; 2],
    /// ICMP data field - varies by message type (4 bytes)
    pub data: [u8; 4],
}

/// Common ICMP message types
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IcmpType {
    /// Echo Reply
    EchoReply = 0,
    /// Destination Unreachable
    DestinationUnreachable = 3,
    /// Source Quench (deprecated)
    SourceQuench = 4,
    /// Redirect
    Redirect = 5,
    /// Echo Request (ping)
    EchoRequest = 8,
    /// Time Exceeded
    TimeExceeded = 11,
    /// Parameter Problem
    ParameterProblem = 12,
    /// Timestamp Request
    TimestampRequest = 13,
    /// Timestamp Reply
    TimestampReply = 14,
    /// Information Request (deprecated)
    InformationRequest = 15,
    /// Information Reply (deprecated)
    InformationReply = 16,
}

impl IcmpHdr {
    /// The size of the ICMP header in bytes (8 bytes).
    pub const LEN: usize = mem::size_of::<IcmpHdr>();

    /// Returns the ICMP message type.
    ///
    /// # Returns
    /// The ICMP message type as a u8 value.
    #[inline]
    pub fn icmp_type(&self) -> u8 {
        self.icmp_type
    }

    /// Sets the ICMP message type.
    ///
    /// # Parameters
    /// * `icmp_type` - The ICMP message type to set.
    #[inline]
    pub fn set_icmp_type(&mut self, icmp_type: u8) {
        self.icmp_type = icmp_type;
    }

    /// Returns the ICMP message code.
    ///
    /// # Returns
    /// The ICMP message code as a u8 value.
    #[inline]
    pub fn code(&self) -> u8 {
        self.code
    }

    /// Sets the ICMP message code.
    ///
    /// # Parameters
    /// * `code` - The ICMP message code to set.
    #[inline]
    pub fn set_code(&mut self, code: u8) {
        self.code = code;
    }

    /// Returns the ICMP checksum.
    ///
    /// This method converts the checksum from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The checksum as a u16 value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the ICMP checksum.
    ///
    /// This method converts the checksum from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `checksum` - The checksum to set.
    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be_bytes();
    }

    /// Returns the ICMP data field as a u32.
    ///
    /// This method converts the data field from network byte order (big-endian)
    /// to host byte order. The interpretation of this field depends on the ICMP type.
    ///
    /// # Returns
    /// The data field as a u32 value.
    #[inline]
    pub fn data(&self) -> u32 {
        u32::from_be_bytes(self.data)
    }

    /// Sets the ICMP data field.
    ///
    /// This method converts the data field from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `data` - The data field to set.
    #[inline]
    pub fn set_data(&mut self, data: u32) {
        self.data = data.to_be_bytes();
    }

    /// Returns the identifier field for Echo Request/Reply messages.
    ///
    /// For Echo Request and Echo Reply messages, the first 2 bytes of the data
    /// field contain an identifier that can be used to match requests with replies.
    ///
    /// # Returns
    /// The identifier as a u16 value.
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    /// Sets the identifier field for Echo Request/Reply messages.
    ///
    /// # Parameters
    /// * `id` - The identifier to set.
    #[inline]
    pub fn set_identifier(&mut self, id: u16) {
        let bytes = id.to_be_bytes();
        self.data[0] = bytes[0];
        self.data[1] = bytes[1];
    }

    /// Returns the sequence number field for Echo Request/Reply messages.
    ///
    /// For Echo Request and Echo Reply messages, the last 2 bytes of the data
    /// field contain a sequence number that can be used to match requests with replies.
    ///
    /// # Returns
    /// The sequence number as a u16 value.
    #[inline]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Sets the sequence number field for Echo Request/Reply messages.
    ///
    /// # Parameters
    /// * `seq` - The sequence number to set.
    #[inline]
    pub fn set_sequence(&mut self, seq: u16) {
        let bytes = seq.to_be_bytes();
        self.data[2] = bytes[0];
        self.data[3] = bytes[1];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_hdr_size() {
        // IcmpHdr should be exactly 8 bytes
        assert_eq!(IcmpHdr::LEN, 8);
        assert_eq!(IcmpHdr::LEN, mem::size_of::<IcmpHdr>());
    }

    #[test]
    fn test_icmp_type_and_code() {
        let mut icmp_hdr = IcmpHdr {
            icmp_type: 0,
            code: 0,
            checksum: [0, 0],
            data: [0, 0, 0, 0],
        };

        // Test Echo Request
        icmp_hdr.set_icmp_type(8);
        icmp_hdr.set_code(0);
        assert_eq!(icmp_hdr.icmp_type(), 8);
        assert_eq!(icmp_hdr.code(), 0);

        // Test Echo Reply
        icmp_hdr.set_icmp_type(0);
        icmp_hdr.set_code(0);
        assert_eq!(icmp_hdr.icmp_type(), 0);
        assert_eq!(icmp_hdr.code(), 0);

        // Test Destination Unreachable
        icmp_hdr.set_icmp_type(3);
        icmp_hdr.set_code(1); // Host Unreachable
        assert_eq!(icmp_hdr.icmp_type(), 3);
        assert_eq!(icmp_hdr.code(), 1);
    }

    #[test]
    fn test_checksum() {
        let mut icmp_hdr = IcmpHdr {
            icmp_type: 8,
            code: 0,
            checksum: [0, 0],
            data: [0, 0, 0, 0],
        };

        // Test with a standard value
        let test_checksum: u16 = 0x1234;
        icmp_hdr.set_checksum(test_checksum);
        assert_eq!(icmp_hdr.checksum(), test_checksum);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(icmp_hdr.checksum, [0x12, 0x34]);

        // Test with zero
        icmp_hdr.set_checksum(0);
        assert_eq!(icmp_hdr.checksum(), 0);
        assert_eq!(icmp_hdr.checksum, [0, 0]);

        // Test with max value
        icmp_hdr.set_checksum(u16::MAX);
        assert_eq!(icmp_hdr.checksum(), u16::MAX);
        assert_eq!(icmp_hdr.checksum, [0xFF, 0xFF]);
    }

    #[test]
    fn test_data_field() {
        let mut icmp_hdr = IcmpHdr {
            icmp_type: 8,
            code: 0,
            checksum: [0, 0],
            data: [0, 0, 0, 0],
        };

        // Test with a standard value
        let test_data: u32 = 0x12345678;
        icmp_hdr.set_data(test_data);
        assert_eq!(icmp_hdr.data(), test_data);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(icmp_hdr.data, [0x12, 0x34, 0x56, 0x78]);

        // Test with zero
        icmp_hdr.set_data(0);
        assert_eq!(icmp_hdr.data(), 0);
        assert_eq!(icmp_hdr.data, [0, 0, 0, 0]);

        // Test with max value
        icmp_hdr.set_data(u32::MAX);
        assert_eq!(icmp_hdr.data(), u32::MAX);
        assert_eq!(icmp_hdr.data, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_echo_request_reply_fields() {
        let mut icmp_hdr = IcmpHdr {
            icmp_type: 8,
            code: 0,
            checksum: [0, 0],
            data: [0, 0, 0, 0],
        };

        // Test identifier
        let test_id: u16 = 0x1234;
        icmp_hdr.set_identifier(test_id);
        assert_eq!(icmp_hdr.identifier(), test_id);
        assert_eq!(icmp_hdr.data[0], 0x12);
        assert_eq!(icmp_hdr.data[1], 0x34);

        // Test sequence number
        let test_seq: u16 = 0x5678;
        icmp_hdr.set_sequence(test_seq);
        assert_eq!(icmp_hdr.sequence(), test_seq);
        assert_eq!(icmp_hdr.data[2], 0x56);
        assert_eq!(icmp_hdr.data[3], 0x78);

        // Verify identifier is still intact
        assert_eq!(icmp_hdr.identifier(), test_id);

        // Test combined data field
        assert_eq!(icmp_hdr.data(), 0x12345678);
    }

    #[test]
    fn test_icmp_type_enum() {
        assert_eq!(IcmpType::EchoReply as u8, 0);
        assert_eq!(IcmpType::DestinationUnreachable as u8, 3);
        assert_eq!(IcmpType::EchoRequest as u8, 8);
        assert_eq!(IcmpType::TimeExceeded as u8, 11);
    }
}