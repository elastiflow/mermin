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
use core::mem;

/// The total size in bytes of the fixed part of the Mobility Header
pub const MOBILITY_LEN: usize = 8;

/// The total size in bytes of the fixed part of the Mobility Header
pub const MOBILITY_LEN: usize = 8;

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

/// Gets the Checksum as a 16-bit value.
#[inline]
pub fn checksum(checksum: Checksum) -> u16 {
    u16::from_be_bytes(checksum)
}

/// Gets the Message Data Start as a 16-bit value.
#[inline]
pub fn reserved_data(reserved_data: ReservedData) -> u16 {
    u16::from_be_bytes(reserved_data)
}

/// Calculates the total length of the Hop-by-Hop header in bytes.
/// The Hdr Ext Len is in 8-octet units, *excluding* the first 8 octets.
/// So, total length = (hdr_ext_len + 1) * 8.
#[inline]
pub fn total_hdr_len(hdr_ext_len: HdrExtLen) -> usize {
    (hdr_ext_len as usize + 1) << 3
}

/// Calculates the length of the Message Data in bytes.
/// Message Data length = Total Header Length - Fixed Header Length.
#[inline]
pub fn message_data_len(hdr_ext_len: HdrExtLen) -> usize {
    total_hdr_len(hdr_ext_len).saturating_sub(MOBILITY_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobility_len_constant() {
        assert_eq!(MOBILITY_LEN, 8);
    }

    #[test]
    fn test_checksum_conversion() {
        assert_eq!(checksum([0x12, 0x34]), 0x1234);
        assert_eq!(checksum([0x00, 0x00]), 0x0000);
        assert_eq!(checksum([0xFF, 0xFF]), 0xFFFF);
    }

    #[test]
    fn test_reserved_data_conversion() {
        assert_eq!(reserved_data([0x56, 0x78]), 0x5678);
        assert_eq!(reserved_data([0x00, 0x00]), 0x0000);
        assert_eq!(reserved_data([0xAB, 0xCD]), 0xABCD);
    }

    #[test]
    fn test_total_hdr_len() {
        // Test with hdr_ext_len = 0 (minimum valid value)
        assert_eq!(total_hdr_len(0), 8);

        // Test with hdr_ext_len = 1
        assert_eq!(total_hdr_len(1), 16);

        // Test with hdr_ext_len = 3
        assert_eq!(total_hdr_len(3), 32);

        // Test with hdr_ext_len = 255 (max value)
        assert_eq!(total_hdr_len(255), 2048);
    }

    #[test]
    fn test_message_data_len() {
        // Test with hdr_ext_len = 0 (no message data)
        assert_eq!(message_data_len(0), 0);

        // Test with hdr_ext_len = 1
        assert_eq!(message_data_len(1), 8);

        // Test with hdr_ext_len = 3
        assert_eq!(message_data_len(3), 24);

        // Test with hdr_ext_len = 255 (max value)
        assert_eq!(message_data_len(255), 2040);
    }
}
