//! Authentication Header Format
//!
//!  0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    Next Header   |   Payload Len  |          Reserved         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                Security Parameters Index                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Sequence Number                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! ~                Integrity Check Value (variable)               ~
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use crate::ip::IpProto;

pub const AH_LEN: usize = 12;

/// Identifies the type of the next header,
pub type NextHdr = IpProto;
/// The length of this Authentication Header in 4-octet units, not including the ICV.
pub type PayloadLen = u8;
/// Reserved for future use and initialized to all zeroes.
pub type Reserved = [u8; 2];
/// Identifies the security association of the receiving party.
pub type Spi = [u8; 4];
/// A monotonic, strictly increasing sequence number to prevent replay attacks.
pub type SeqNum = [u8; 4];

/// Calculates the total length of the Authentication Header in bytes.
/// The Payload Length is in 4-octet units, minus 2.
/// So, total length = (payload_len + 2) * 4.
#[inline]
pub fn total_hdr_len(payload_len: PayloadLen) -> usize {
    (payload_len as usize + 2) << 2
}

/// Gets the Reserved field as a 16-bit value.
#[inline]
pub fn reserved(reserved: Reserved) -> u16 {
    u16::from_be_bytes(reserved)
}

/// Gets the Security Parameters Index as a 32-bit value.
#[inline]
pub fn spi(spi: Spi) -> u32 {
    u32::from_be_bytes(spi)
}

/// Gets the Sequence Number as a 32-bit value.
#[inline]
pub fn seq_num(seq_num: SeqNum) -> u32 {
    u32::from_be_bytes(seq_num)
}

/// Calculates the length of the Integrity Check Value in bytes.
/// ICV length = Total Header Length - Fixed Header Length.
#[inline]
pub fn icv_len(payload_len: PayloadLen) -> usize {
    total_hdr_len(payload_len).saturating_sub(AH_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ahhdr_getters_and_setters() {
        // Test reserved
        let resv = 0x1234u16.to_be_bytes();
        assert_eq!(reserved(resv), 0x1234);
        assert_eq!(resv, [0x12, 0x34]);

        // Test spi
        let s = 0x12345678u32.to_be_bytes();
        assert_eq!(spi(s), 0x12345678);
        assert_eq!(s, [0x12, 0x34, 0x56, 0x78]);

        // Test seq_num
        let num = 0x87654321u32.to_be_bytes();
        assert_eq!(seq_num(num), 0x87654321);
        assert_eq!(num, [0x87, 0x65, 0x43, 0x21]);
    }

    #[test]
    fn test_ahhdr_size() {
        // AuthHdr fixed header should be exactly 12 bytes
        assert_eq!(AH_LEN, 12);
    }

    #[test]
    fn test_ahhdr_length_calculation_methods() {
        // Test with payload_len = 0
        let payload_len = 0;
        assert_eq!(total_hdr_len(payload_len), 8);
        assert_eq!(icv_len(payload_len), 0);

        // Test with payload_len = 1
        let payload_len = 1;
        assert_eq!(total_hdr_len(payload_len), 12);
        assert_eq!(icv_len(payload_len), 0);

        // Test with payload_len = 3
        let payload_len = 3;
        assert_eq!(total_hdr_len(payload_len), 20);
        assert_eq!(icv_len(payload_len), 8);

        // Test with payload_len = 255 (max value)
        let payload_len = 255;
        assert_eq!(total_hdr_len(payload_len), (255 + 2) * 4);
        assert_eq!(icv_len(payload_len), (255 + 2) * 4 - AH_LEN);
    }
}
