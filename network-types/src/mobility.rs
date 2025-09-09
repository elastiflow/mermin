use crate::ip::IpProto;

/// # Mobility Header Format Section 6.1.1 - https://datatracker.ietf.org/doc/html/rfc3775
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Payload Proto |  Hdr Ext Len  |   MH Type     |   Reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |    Reserved Message Data      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                                                               .
/// .                       Message Data                            .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Fields
///
/// * **Payload Proto (8 bits)**: An 8-bit selector identifying the type of header immediately following the Mobility Header.
///
/// * **Hdr Ext Len (8 bits)**: An 8-bit unsigned integer representing the length of the Mobility Header in units of 8 octets, **excluding the first 8 octets**.
///
/// * **MH Type (8 bits)**: An 8-bit selector that identifies the specific mobility message.
///
/// * **Reserved (8 bits)**: Reserved for future use. Should be 0
///
/// * **Checksum (16 bits)**: A 16-bit unsigned integer containing the checksum of the Mobility Header.
///
/// * **Message Data (variable length)**: A variable-length field containing data specific to the `MH Type` indicated.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MobilityHdr {
    pub nxt_hdr: IpProto,
    pub hdr_ext_len: u8,
    pub mh_type: u8,
    pub reserved: u8,
    pub checksum: [u8; 2],
    pub reserved_data: [u8; 2], // Captures last two bytes of standard mobility header length, typically reserved and set to 0
}

impl MobilityHdr {
    /// The total size in bytes of the fixed part of the Mobility Header
    pub const LEN: usize = 8; // Fixed size of the Mobility Header (first 8 bytes)

    /// Gets the Payload Proto value.
    #[inline]
    pub fn next_hdr(&self) -> IpProto {
        self.nxt_hdr
    }

    /// Sets the Payload Proto value.
    #[inline]
    pub fn set_next_hdr(&mut self, payload_proto: IpProto) {
        self.nxt_hdr = payload_proto;
    }

    /// Gets the Header Len value.
    /// This value is the length of the Mobility Header in units of 8 octets, excluding the first 8 octets.
    #[inline]
    pub fn hdr_ext_len(&self) -> u8 {
        self.hdr_ext_len
    }

    /// Sets the Header Len value.
    #[inline]
    pub fn set_hdr_ext_len(&mut self, header_len: u8) {
        self.hdr_ext_len = header_len;
    }

    /// Gets the MH Type value.
    #[inline]
    pub fn mh_type(&self) -> u8 {
        self.mh_type
    }

    /// Sets the MH Type value.
    #[inline]
    pub fn set_mh_type(&mut self, mh_type: u8) {
        self.mh_type = mh_type;
    }

    /// Gets the Reserved field.
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.reserved
    }

    /// Sets the Reserved field.
    #[inline]
    pub fn set_reserved(&mut self, reserved: u8) {
        self.reserved = reserved;
    }

    /// Gets the Checksum as a 16-bit value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the Checksum from a 16-bit value.
    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be_bytes();
    }

    /// Gets the Message Data Start as a 16-bit value.
    #[inline]
    pub fn reserved_data(&self) -> u16 {
        u16::from_be_bytes(self.reserved_data)
    }

    /// Sets the Message Data Start from a 16-bit value.
    #[inline]
    pub fn set_reserved_data(&mut self, reserved_data: u16) {
        self.reserved_data = reserved_data.to_be_bytes();
    }

    /// Calculates the total length of the Hop-by-Hop header in bytes.
    /// The Hdr Ext Len is in 8-octet units, *excluding* the first 8 octets.
    /// So, total length = (hdr_ext_len + 1) * 8.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        (self.hdr_ext_len as usize + 1) << 3
    }

    /// Calculates the length of the Message Data in bytes.
    /// Message Data length = Total Header Length - Fixed Header Length.
    #[inline]
    pub fn message_data_len(&self) -> usize {
        self.total_hdr_len().saturating_sub(MobilityHdr::LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobilityhdr_size() {
        assert_eq!(MobilityHdr::LEN, 8);
        assert_eq!(MobilityHdr::LEN, core::mem::size_of::<MobilityHdr>());
    }

    #[test]
    fn test_mobilityhdr_getters_and_setters() {
        let mut mobility_hdr = MobilityHdr {
            nxt_hdr: IpProto::Stream,
            hdr_ext_len: 0,
            mh_type: 0,
            reserved: 0,
            checksum: [0, 0],
            reserved_data: [0, 0],
        };

        // Test payload_proto
        mobility_hdr.set_next_hdr(IpProto::Stream); // Example: TCP
        assert_eq!(mobility_hdr.next_hdr(), IpProto::Stream);
        assert_eq!(mobility_hdr.nxt_hdr, IpProto::Stream);

        // Test header_len
        mobility_hdr.set_hdr_ext_len(2); // Example: 2 * 8 = 16 bytes of additional data
        assert_eq!(mobility_hdr.hdr_ext_len(), 2);
        assert_eq!(mobility_hdr.hdr_ext_len, 2);

        // Test mh_type
        mobility_hdr.set_mh_type(5);
        assert_eq!(mobility_hdr.mh_type(), 5);
        assert_eq!(mobility_hdr.mh_type, 5);

        // Test reserved
        mobility_hdr.set_reserved(0);
        assert_eq!(mobility_hdr.reserved(), 0);
        assert_eq!(mobility_hdr.reserved, 0);

        // Test checksum
        mobility_hdr.set_checksum(0x1234);
        assert_eq!(mobility_hdr.checksum(), 0x1234);
        assert_eq!(mobility_hdr.checksum, [0x12, 0x34]);

        // Test msg_data_start
        mobility_hdr.set_reserved_data(0x5678);
        assert_eq!(mobility_hdr.reserved_data(), 0x5678);
        assert_eq!(mobility_hdr.reserved_data, [0x56, 0x78]);
    }

    #[test]
    fn test_mobilityhdr_length_calculation_methods() {
        let mut mobility_hdr = MobilityHdr {
            nxt_hdr: IpProto::Stream,
            hdr_ext_len: 0,
            mh_type: 0,
            reserved: 0,
            checksum: [0, 0],
            reserved_data: [0, 0],
        };

        // Test with header_len = 0
        mobility_hdr.set_hdr_ext_len(0);
        assert_eq!(mobility_hdr.total_hdr_len(), 8);
        assert_eq!(mobility_hdr.message_data_len(), 0);

        // Test with header_len = 1
        mobility_hdr.set_hdr_ext_len(1);
        assert_eq!(mobility_hdr.total_hdr_len(), 16);
        assert_eq!(mobility_hdr.message_data_len(), 8);

        // Test with header_len = 3
        mobility_hdr.set_hdr_ext_len(3);
        assert_eq!(mobility_hdr.total_hdr_len(), 32);
        assert_eq!(mobility_hdr.message_data_len(), 24);

        // Test with header_len = 255 (max value)
        mobility_hdr.set_hdr_ext_len(255);
        assert_eq!(mobility_hdr.total_hdr_len(), 8 + (255 * 8));
        assert_eq!(
            mobility_hdr.message_data_len(),
            8 + (255 * 8) - MobilityHdr::LEN
        );
    }
}
