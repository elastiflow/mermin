//! # Mobility Header Format Section 6.1.1 - https://datatracker.ietf.org/doc/html/rfc3775
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Payload Proto |  Hdr Ext Len  |   MH Type     |   Reserved    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Checksum            |    Reserved Message Data      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! .                                                               .
//! .                       Message Data                            .
//! .                                                               .
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
use crate::ip::IpProto;

/// The Next Header field (8 bits)
pub type NextHdr = IpProto;
/// The Header Length field (8 bits). This is the length of the Mobility Header in 8-octet units, not including the first 8 octets.
pub type HdrExtLen = u8;
/// The Mobility Header Type field (8 bits)
pub type MhType = u8;
/// The Reserved field (8 bits). Reserved for future use. Should be 0
pub type Reserved = u8;
/// The Checksum field (16 bits)
pub type Checksum = [u8; 2];
/// The Reserved Message Data field (16 bits). Captures last two bytes of standard mobility header length, typically reserved and set to 0
pub type ReservedData = [u8; 2];

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MobilityHdr {
    /// The Next Header field (8 bits)
    pub next_hdr: IpProto,
    /// The Header Length field (8 bits). This is the length of the Mobility Header in 8-octet units, not including the first 8 octets.
    pub hdr_ext_len: u8,
    /// The Mobility Header Type field (8 bits)
    pub mh_type: u8,
    /// The Reserved field (8 bits). Reserved for future use. Should be 0
    pub reserved: u8,
    /// The Checksum field (16 bits)
    pub checksum: [u8; 2],
    /// The Reserved Message Data field (16 bits). Captures last two bytes of standard mobility header length, typically reserved and set to 0
    pub reserved_data: [u8; 2],
}

impl MobilityHdr {
    /// The total size in bytes of the fixed part of the Mobility Header
    pub const LEN: usize = mem::size_of::<MobilityHdr>();

    /// Gets the Checksum as a 16-bit value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Gets the Message Data Start as a 16-bit value.
    #[inline]
    pub fn reserved_data(&self) -> u16 {
        u16::from_be_bytes(self.reserved_data)
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
            next_hdr: IpProto::Stream,
            hdr_ext_len: 0,
            mh_type: 0,
            reserved: 0,
            checksum: [0, 0],
            reserved_data: [0, 0],
        };

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
            next_hdr: IpProto::Stream,
            hdr_ext_len: 0,
            mh_type: 0,
            reserved: 0,
            checksum: [0, 0],
            reserved_data: [0, 0],
        };

        // Test with header_len = 0
        mobility_hdr.hdr_ext_len = 0;
        assert_eq!(mobility_hdr.total_hdr_len(), 8);
        assert_eq!(mobility_hdr.message_data_len(), 0);

        // Test with header_len = 1
        mobility_hdr.hdr_ext_len = 1;
        assert_eq!(mobility_hdr.total_hdr_len(), 16);
        assert_eq!(mobility_hdr.message_data_len(), 8);

        // Test with header_len = 3
        mobility_hdr.hdr_ext_len = 3;
        assert_eq!(mobility_hdr.total_hdr_len(), 32);
        assert_eq!(mobility_hdr.message_data_len(), 24);

        // Test with header_len = 255 (max value)
        mobility_hdr.hdr_ext_len = 255;
        assert_eq!(mobility_hdr.total_hdr_len(), 8 + (255 * 8));
        assert_eq!(
            mobility_hdr.message_data_len(),
            8 + (255 * 8) - MobilityHdr::LEN
        );
    }
}
