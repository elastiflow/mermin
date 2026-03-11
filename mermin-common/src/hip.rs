//! Represents the Host Identity Protocol (HIP) version 2 header.
//!
//! HIP is used to separate the identifier and locator roles of IP addresses.
//! The HIP header is defined in RFC 7401.
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Next Header   | Header Length |0| Packet Type |Version| RES.|1|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Checksum            |           Controls            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |             Sender's Host Identity Tag (HIT)                  |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |           Receiver's Host Identity Tag (HIT)                  |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! /                          HIP Parameters                       /
//! /                                                               /
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
use crate::ip::IpProto;

/// The size of the fixed part of the HIP Header in bytes.
pub const HIP_LEN: usize = 40;

/// Next Header field (8 bits)
pub type NextHdr = IpProto;
/// Header Length field (8 bits)
pub type HdrLen = u8;
/// Fixed bit (1 bit) + Packet Type (7 bits)
pub type PacketType = u8;
/// Version (4 bits) + Reserved (3 bits) + Fixed bit (1 bit)
pub type Version = u8;
/// Checksum field (16 bits)
pub type Checksum = [u8; 2];
/// Controls field (16 bits)
pub type Controls = [u8; 2];
/// Sender's Host Identity Tag (HIT) (16 bytes)
pub type SenderHit = [u8; 16];
/// Receiver's Host Identity Tag (HIT) (16 bytes)
pub type ReceiverHit = [u8; 16];

/// Gets the Packet Type value (7 bits).
#[inline]
pub fn packet_type(packet_type: PacketType) -> u8 {
    packet_type & 0x7F
}

/// Gets the Version value (4 bits).
#[inline]
pub fn version(ver: Version) -> u8 {
    ver >> 4
}

/// Gets the Checksum as a 16-bit value.
#[inline]
pub fn checksum(checksum: Checksum) -> u16 {
    u16::from_be_bytes(checksum)
}

/// Gets the Controls as a 16-bit value.
#[inline]
pub fn controls(controls: Controls) -> u16 {
    u16::from_be_bytes(controls)
}

/// Gets the Sender's HIT as a 128-bit value.
#[inline]
pub fn sender_hit(sender_hit: SenderHit) -> u128 {
    u128::from_be_bytes(sender_hit)
}

/// Gets the Receiver's HIT as a 128-bit value.
#[inline]
pub fn receiver_hit(receiver_hit: ReceiverHit) -> u128 {
    u128::from_be_bytes(receiver_hit)
}

/// Calculates the total length of the HIP header in bytes.
/// Total length = (hdr_len + 1) * 8.
#[inline]
pub fn total_hdr_len(hdr_len: HdrLen) -> usize {
    (hdr_len as usize + 1) << 3
}

/// Calculates the length of the HIP parameters in bytes.
#[inline]
pub fn params_len(hdr_len: HdrLen) -> usize {
    total_hdr_len(hdr_len).saturating_sub(HIP_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hip_constant() {
        assert_eq!(HIP_LEN, 40);
    }

    #[test]
    fn test_packet_type_extraction() {
        // Test various packet type values
        assert_eq!(packet_type(0b00000000), 0);
        assert_eq!(packet_type(0b01111111), 0x7F); // Max packet type value
        assert_eq!(packet_type(0b10000100), 4); // Fixed bit set, Type=4 (R2)
        assert_eq!(packet_type(0b00000100), 4); // Fixed bit clear, Type=4
    }

    #[test]
    fn test_version_extraction() {
        // Test various version values
        assert_eq!(version(0b00000000), 0);
        assert_eq!(version(0b00100000), 2); // Version 2
        assert_eq!(version(0b11110000), 15); // Max version value
        assert_eq!(version(0b00100001), 2); // Version 2, fixed bit set
    }

    #[test]
    fn test_checksum_conversion() {
        assert_eq!(checksum([0x00, 0x00]), 0x0000);
        assert_eq!(checksum([0x12, 0x34]), 0x1234);
        assert_eq!(checksum([0xFF, 0xFF]), 0xFFFF);
        assert_eq!(checksum([0xAB, 0xCD]), 0xABCD);
    }

    #[test]
    fn test_controls_conversion() {
        assert_eq!(controls([0x00, 0x00]), 0x0000);
        assert_eq!(controls([0xAB, 0xCD]), 0xABCD);
        assert_eq!(controls([0xFF, 0xFF]), 0xFFFF);
        assert_eq!(controls([0x12, 0x34]), 0x1234);
    }

    #[test]
    fn test_sender_hit_conversion() {
        let hit_bytes: SenderHit = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let expected: u128 = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210;
        assert_eq!(sender_hit(hit_bytes), expected);

        // Test all zeros
        assert_eq!(sender_hit([0; 16]), 0);

        // Test all ones
        assert_eq!(sender_hit([0xFF; 16]), u128::MAX);
    }

    #[test]
    fn test_receiver_hit_conversion() {
        let hit_bytes: ReceiverHit = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
            0x22, 0x11,
        ];
        let expected: u128 = 0x1122_3344_5566_7788_8877_6655_4433_2211;
        assert_eq!(receiver_hit(hit_bytes), expected);

        // Test all zeros
        assert_eq!(receiver_hit([0; 16]), 0);

        // Test all ones
        assert_eq!(receiver_hit([0xFF; 16]), u128::MAX);
    }

    #[test]
    fn test_total_hdr_len_calculation() {
        // If total length is 40 (base header), hdr_len = (40/8)-1 = 4
        assert_eq!(total_hdr_len(4), 40);

        // Test with hdr_len = 5 (one 8-octet parameter)
        assert_eq!(total_hdr_len(5), 48);

        // Test with hdr_len = 0 (minimum)
        assert_eq!(total_hdr_len(0), 8);

        // Test with hdr_len = 255 (maximum)
        assert_eq!(total_hdr_len(255), (255 + 1) * 8);
        assert_eq!(total_hdr_len(255), 2048);
    }

    #[test]
    fn test_params_len_calculation() {
        // If total length is 40 (base header only), params_len = 0
        assert_eq!(params_len(4), 0);

        // Test with hdr_len = 5 (one 8-octet parameter)
        assert_eq!(params_len(5), 8);

        // Test with hdr_len = 6 (two 8-octet parameters)
        assert_eq!(params_len(6), 16);

        // Test with hdr_len = 255 (maximum)
        assert_eq!(params_len(255), (255 + 1) * 8 - HIP_LEN);
        assert_eq!(params_len(255), 2008);

        // Test edge case where header length is less than HIP_LEN
        // (should saturate to 0 due to saturating_sub)
        assert_eq!(params_len(0), 0); // 8 - 40 saturates to 0
        assert_eq!(params_len(1), 0); // 16 - 40 saturates to 0
        assert_eq!(params_len(2), 0); // 24 - 40 saturates to 0
        assert_eq!(params_len(3), 0); // 32 - 40 saturates to 0
    }

    #[test]
    fn test_combined_field_operations() {
        // Test packet type
        let pkt_type: PacketType = 0x84; // Fixed bit + Type 4 (R2)
        assert_eq!(packet_type(pkt_type), 4);

        // Test version
        let ver: Version = 0x21; // Version 2 + fixed bit
        assert_eq!(version(ver), 2);

        // Test checksum
        let chksum: Checksum = [0x12, 0x34];
        assert_eq!(checksum(chksum), 0x1234);

        // Test controls
        let ctrl: Controls = [0xAB, 0xCD];
        assert_eq!(controls(ctrl), 0xABCD);

        // Test sender HIT
        let s_hit: SenderHit = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        assert_eq!(sender_hit(s_hit), 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210);

        // Test receiver HIT
        let r_hit: ReceiverHit = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
            0x22, 0x11,
        ];
        assert_eq!(
            receiver_hit(r_hit),
            0x1122_3344_5566_7788_8877_6655_4433_2211
        );

        // Test length calculations with hdr_len = 5
        let hdr_len: HdrLen = 5;
        assert_eq!(total_hdr_len(hdr_len), 48);
        assert_eq!(params_len(hdr_len), 8);
    }
}
