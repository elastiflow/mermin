//! The Shim6 Control Header is a common header format used for various control messages within the Shim6 protocol.
//! All Shim6 headers are designed to be a multiple of 8 octets in length, with a minimum size of 8 octets.
//!
//! Shim6 Control Message Header Format
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Next Header   | Hdr Ext Len   |P|      Type     |Type-specific|S|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Checksum            |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//! |                                                               |
//! .                     Type-specific format                      .
//! .                                                               .
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

/// The size of the fixed part of the Shim6 Header in bytes.
pub const SHIM6_LEN: usize = 8;

/// The Next Header field (8 bits)
pub type NextHdr = IpProto;
/// The Header Length field (8 bits). This is the length of the Shim6 header
/// in 8-octet units, not including the first 8 octets.
pub type HdrExtLen = u8;
/// The P bit (1) + Message Type (7)
pub type PType = u8;
/// The Type-specific (7) + S bit (1)
pub type TypeS = u8;
/// The Checksum field (16 bits)
pub type Checksum = [u8; 2];
/// The first 2 bytes of the Type-Specific data, part of the 8-octet base header.
pub type TypeData = [u8; 2];

use crate::ip::IpProto;

/// Gets the P (Payload Flag) bit.
#[inline]
pub fn p(ptype: PType) -> bool {
    (ptype >> 7) & 1 != 0
}

/// Gets the message Type value (7 bits).
#[inline]
pub fn msg_type(p_type: PType) -> u8 {
    p_type & 0x7F
}

/// Gets the Type-specific bits (7 bits).
#[inline]
pub fn type_specific_bits(type_s: TypeS) -> u8 {
    type_s >> 1
}

/// Gets the S (Shim6/HIP Distinction) bit.
#[inline]
pub fn s(type_s: TypeS) -> bool {
    (type_s & 1) != 0
}

/// Gets the Checksum as a 16-bit value.
#[inline]
pub fn checksum(checksum: Checksum) -> u16 {
    u16::from_be_bytes(checksum)
}

/// Gets the Type-specific data as a 16-bit value.
#[inline]
pub fn type_specific_data(data: TypeData) -> u16 {
    u16::from_be_bytes(data)
}

/// Calculates the total length of the Shim6 header in bytes.
/// Total length = (hdr_ext_len + 1) * 8.
#[inline]
pub fn total_hdr_len(len: HdrExtLen) -> usize {
    (len as usize + 1) << 3
}

/// Calculates the length of the variable-length part of the header in bytes.
#[inline]
pub fn variable_len(hdr_ext_len: HdrExtLen) -> usize {
    total_hdr_len(hdr_ext_len).saturating_sub(SHIM6_LEN)
}

/// Calculates the total length of the Shim6 header in bytes.
/// Total length = (hdr_ext_len + 1) * 8.
#[inline]
pub fn calc_total_hdr_len(hdr_ext_len: u8) -> usize {
    (hdr_ext_len as usize + 1) << 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shim6_constant() {
        assert_eq!(SHIM6_LEN, 8);
    }

    #[test]
    fn test_p_bit_extraction() {
        // P bit is 0
        assert!(!p(0b00000000));
        assert!(!p(0b01111111)); // Max type value, P=0

        // P bit is 1
        assert!(p(0b10000000));
        assert!(p(0b11111111)); // Max type value, P=1
    }

    #[test]
    fn test_msg_type_extraction() {
        // Test various type values
        assert_eq!(msg_type(0b00000000), 0);
        assert_eq!(msg_type(0b01111111), 0x7F); // Max type value
        assert_eq!(msg_type(0b10000000), 0); // P=1, Type=0
        assert_eq!(msg_type(0b11001010), 0x4A); // P=1, Type=74
        assert_eq!(msg_type(0b01001010), 0x4A); // P=0, Type=74
    }

    #[test]
    fn test_type_specific_bits_extraction() {
        // Test various type-specific values
        assert_eq!(type_specific_bits(0b00000000), 0);
        assert_eq!(type_specific_bits(0b11111110), 0x7F); // Max type-specific value, S=0
        assert_eq!(type_specific_bits(0b11111111), 0x7F); // Max type-specific value, S=1
        assert_eq!(type_specific_bits(0b11101010), 0x75); // type-specific=117, S=0
        assert_eq!(type_specific_bits(0b11101011), 0x75); // type-specific=117, S=1
    }

    #[test]
    fn test_s_bit_extraction() {
        // S bit is 0
        assert!(!s(0b00000000));
        assert!(!s(0b11111110)); // Max type-specific value, S=0

        // S bit is 1
        assert!(s(0b00000001));
        assert!(s(0b11111111)); // Max type-specific value, S=1
    }

    #[test]
    fn test_checksum_conversion() {
        assert_eq!(checksum([0x00, 0x00]), 0x0000);
        assert_eq!(checksum([0x12, 0x34]), 0x1234);
        assert_eq!(checksum([0xFF, 0xFF]), 0xFFFF);
        assert_eq!(checksum([0xAB, 0xCD]), 0xABCD);
    }

    #[test]
    fn test_type_specific_data_conversion() {
        assert_eq!(type_specific_data([0x00, 0x00]), 0x0000);
        assert_eq!(type_specific_data([0x56, 0x78]), 0x5678);
        assert_eq!(type_specific_data([0xFF, 0xFF]), 0xFFFF);
        assert_eq!(type_specific_data([0x12, 0x34]), 0x1234);
    }

    #[test]
    fn test_total_hdr_len_calculation() {
        // Test with hdr_ext_len = 0 (minimum)
        assert_eq!(total_hdr_len(0), 8);

        // Test with hdr_ext_len = 1
        assert_eq!(total_hdr_len(1), 16);

        // Test with hdr_ext_len = 3
        assert_eq!(total_hdr_len(3), 32);

        // Test with hdr_ext_len = 255 (maximum)
        assert_eq!(total_hdr_len(255), (255 + 1) * 8);
        assert_eq!(total_hdr_len(255), 2048);
    }

    #[test]
    fn test_variable_len_calculation() {
        // Test with hdr_ext_len = 0 (no variable part)
        assert_eq!(variable_len(0), 0);

        // Test with hdr_ext_len = 1
        assert_eq!(variable_len(1), 8);

        // Test with hdr_ext_len = 3
        assert_eq!(variable_len(3), 24);

        // Test with hdr_ext_len = 255 (maximum)
        assert_eq!(variable_len(255), 255 * 8);
        assert_eq!(variable_len(255), 2040);
    }

    #[test]
    fn test_combined_field_operations() {
        // Test P and Type together
        let p_type: PType = 0xCA; // P=1, Type=74
        assert!(p(p_type));
        assert_eq!(msg_type(p_type), 0x4A);

        // Test Type-specific and S together
        let type_s: TypeS = 0xEB; // Type-specific=117, S=1
        assert_eq!(type_specific_bits(type_s), 0x75);
        assert!(s(type_s));

        // Test checksum conversion
        let chksum: Checksum = [0x12, 0x34];
        assert_eq!(checksum(chksum), 0x1234);

        // Test type-specific data conversion
        let data: TypeData = [0x56, 0x78];
        assert_eq!(type_specific_data(data), 0x5678);

        // Test length calculations with hdr_ext_len = 2
        let hdr_len: HdrExtLen = 2;
        assert_eq!(total_hdr_len(hdr_len), 24);
        assert_eq!(variable_len(hdr_len), 16);
    }
}
