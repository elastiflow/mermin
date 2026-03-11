//! //! Represents a GRE (Generic Routing Encapsulation) header.
//!
//! This struct contains the fixed part of the GRE header, which includes
//! flags, reserved bits, version, and protocol type.
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      Checksum (optional)      |       Offset (optional)       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Key (optional)                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Sequence Number (optional)                 |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Routing (optional)
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use crate::eth::EtherType;

/// The length of the GRE header base structure.
pub const GRE_LEN: usize = 4;
/// Combined field: Flags (4 bits), Reserved0 (3 bits), Version (3 bits).
pub type FlgsRes0Ver = [u8; 2];
/// Protocol Type field (16 bits).
pub type ProtocolType = EtherType;
/// Key field (32 bits).
pub type Key = [u8; 4];
/// Sequence Number field (32 bits).
pub type SequenceNumber = [u8; 4];
/// The length of the GRE routing header (SRE header).
pub const GRE_ROUTING_LEN: usize = 4;
/// Address Family field (16 bits) - indicates syntax/semantics of routing info.
pub type AddressFamily = u16;
/// SRE Offset field (8 bits) - offset to active entry in routing info.
pub type SreOffset = u8;
/// SRE Length field (8 bits) - total length of this SRE in bytes.
pub type SreLength = u8;

/// Flag masks for GRE header
pub const C_FLAG_MASK: u8 = 0x80;
pub const R_FLAG_MASK: u8 = 0x40;
pub const K_FLAG_MASK: u8 = 0x20;
pub const S_FLAG_MASK: u8 = 0x10;
pub const VER_MASK: u8 = 0x07;

/// Returns the Checksum Present flag (C) from the flags field.
#[inline]
pub fn c_flag(flgs_res0_ver: FlgsRes0Ver) -> bool {
    flgs_res0_ver[0] & C_FLAG_MASK != 0
}

/// Returns the Routing Present flag (R) from the flags field.
#[inline]
pub fn r_flag(flgs_res0_ver: FlgsRes0Ver) -> bool {
    flgs_res0_ver[0] & R_FLAG_MASK != 0
}

/// Returns the Key Present flag (K) from the flags field.
#[inline]
pub fn k_flag(flgs_res0_ver: FlgsRes0Ver) -> bool {
    flgs_res0_ver[0] & K_FLAG_MASK != 0
}

/// Returns the Sequence Number Present flag (S) from the flags field.
#[inline]
pub fn s_flag(flgs_res0_ver: FlgsRes0Ver) -> bool {
    flgs_res0_ver[0] & S_FLAG_MASK != 0
}

/// Returns the GRE version (3 bits) from the flags field.
#[inline]
pub fn version(flgs_res0_ver: FlgsRes0Ver) -> u8 {
    flgs_res0_ver[1] & VER_MASK
}

#[inline]
pub fn key(key: Key) -> u32 {
    u32::from_le_bytes(key)
}

/// Calculates the total GRE header length based on flags.
///
/// The GRE header has a fixed 4-byte part, plus optional fields:
/// - Checksum/Offset: 4 bytes (if C or R flag is set)
/// - Key: 4 bytes (if K flag is set)
/// - Sequence Number: 4 bytes (if S flag is set)
#[inline]
pub fn total_hdr_len(flgs_res0_ver: FlgsRes0Ver) -> usize {
    let mut len = GRE_LEN; // Fixed 4 bytes

    // If either C or R flag is set, both Checksum and Offset fields are present
    if c_flag(flgs_res0_ver) || r_flag(flgs_res0_ver) {
        len += 4; // Checksum/Offset field
    }
    if k_flag(flgs_res0_ver) {
        len += 4; // Key field
    }
    if s_flag(flgs_res0_ver) {
        len += 4; // Sequence Number field
    }

    len
}

/// Returns the total length of the SRE including the routing information.
#[inline]
pub fn total_sre_len(sre_length: SreLength) -> usize {
    sre_length as usize
}

/// Checks if this is a NULL SRE (terminator) based on address family and SRE length.
#[inline]
pub fn is_null_sre(address_family: AddressFamily, sre_length: SreLength) -> bool {
    address_family == 0 && sre_length == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gre_len_constant() {
        assert_eq!(GRE_LEN, 4);
    }

    #[test]
    fn test_gre_routing_len_constant() {
        assert_eq!(GRE_ROUTING_LEN, 4);
    }

    #[test]
    fn test_flag_masks() {
        assert_eq!(C_FLAG_MASK, 0x80);
        assert_eq!(R_FLAG_MASK, 0x40);
        assert_eq!(K_FLAG_MASK, 0x20);
        assert_eq!(S_FLAG_MASK, 0x10);
        assert_eq!(VER_MASK, 0x07);
    }

    #[test]
    fn test_c_flag() {
        // C flag set
        assert_eq!(c_flag([0x80, 0x00]), true);
        // C flag not set
        assert_eq!(c_flag([0x00, 0x00]), false);
        // Other flags set
        assert_eq!(c_flag([0x70, 0x00]), false);
    }

    #[test]
    fn test_r_flag() {
        // R flag set
        assert_eq!(r_flag([0x40, 0x00]), true);
        // R flag not set
        assert_eq!(r_flag([0x00, 0x00]), false);
        // Other flags set
        assert_eq!(r_flag([0xB0, 0x00]), false);
    }

    #[test]
    fn test_k_flag() {
        // K flag set
        assert_eq!(k_flag([0x20, 0x00]), true);
        // K flag not set
        assert_eq!(k_flag([0x00, 0x00]), false);
        // Other flags set
        assert_eq!(k_flag([0xD0, 0x00]), false);
    }

    #[test]
    fn test_s_flag() {
        // S flag set
        assert_eq!(s_flag([0x10, 0x00]), true);
        // S flag not set
        assert_eq!(s_flag([0x00, 0x00]), false);
        // Other flags set
        assert_eq!(s_flag([0xE0, 0x00]), false);
    }

    #[test]
    fn test_version() {
        // Version 0
        assert_eq!(version([0x00, 0x00]), 0);
        // Version 1
        assert_eq!(version([0x00, 0x01]), 1);
        // Version 7 (max 3-bit value)
        assert_eq!(version([0x00, 0x07]), 7);
        // Version with flags set
        assert_eq!(version([0xF0, 0x05]), 5);
    }

    #[test]
    fn test_multiple_flags() {
        // All flags set, version 5
        let flgs_res0_ver: FlgsRes0Ver = [0xF0, 0x05];
        assert_eq!(c_flag(flgs_res0_ver), true);
        assert_eq!(r_flag(flgs_res0_ver), true);
        assert_eq!(k_flag(flgs_res0_ver), true);
        assert_eq!(s_flag(flgs_res0_ver), true);
        assert_eq!(version(flgs_res0_ver), 5);
    }

    #[test]
    fn test_total_hdr_len_no_flags() {
        // No flags set - just fixed header
        assert_eq!(total_hdr_len([0x00, 0x00]), 4);
    }

    #[test]
    fn test_total_hdr_len_c_flag() {
        // C flag set - adds 4 bytes
        assert_eq!(total_hdr_len([0x80, 0x00]), 8);
    }

    #[test]
    fn test_total_hdr_len_r_flag() {
        // R flag set - adds 4 bytes
        assert_eq!(total_hdr_len([0x40, 0x00]), 8);
    }

    #[test]
    fn test_total_hdr_len_k_flag() {
        // K flag set - adds 4 bytes
        assert_eq!(total_hdr_len([0x20, 0x00]), 8);
    }

    #[test]
    fn test_total_hdr_len_s_flag() {
        // S flag set - adds 4 bytes
        assert_eq!(total_hdr_len([0x10, 0x00]), 8);
    }

    #[test]
    fn test_total_hdr_len_c_and_r_flags() {
        // Both C and R flags set - still only adds 4 bytes (shared Checksum/Offset field)
        assert_eq!(total_hdr_len([0xC0, 0x00]), 8);
    }

    #[test]
    fn test_total_hdr_len_c_and_k_flags() {
        // C and K flags set
        assert_eq!(total_hdr_len([0xA0, 0x00]), 12); // 4 + 4 + 4
    }

    #[test]
    fn test_total_hdr_len_c_k_s_flags() {
        // C, K, and S flags set
        assert_eq!(total_hdr_len([0xB0, 0x00]), 16); // 4 + 4 + 4 + 4
    }

    #[test]
    fn test_total_hdr_len_r_and_k_flags() {
        // R and K flags set
        assert_eq!(total_hdr_len([0x60, 0x00]), 12); // 4 + 4 + 4
    }

    #[test]
    fn test_total_hdr_len_all_flags() {
        // All flags set
        assert_eq!(total_hdr_len([0xF0, 0x00]), 16); // 4 + 4 + 4 + 4
    }

    #[test]
    fn test_total_sre_len() {
        assert_eq!(total_sre_len(0), 0);
        assert_eq!(total_sre_len(4), 4);
        assert_eq!(total_sre_len(8), 8);
        assert_eq!(total_sre_len(255), 255);
    }

    #[test]
    fn test_is_null_sre() {
        // NULL SRE (both address family and length are 0)
        assert_eq!(is_null_sre(0, 0), true);

        // Non-zero address family
        assert_eq!(is_null_sre(0x0800, 0), false);

        // Non-zero SRE length
        assert_eq!(is_null_sre(0, 4), false);

        // Both non-zero
        assert_eq!(is_null_sre(0x0800, 4), false);
        assert_eq!(is_null_sre(0x86DD, 8), false);
    }

    #[test]
    fn test_type_aliases() {
        // Test FlgsRes0Ver type alias
        let flgs_res0_ver: FlgsRes0Ver = [0x80, 0x00];
        assert_eq!(flgs_res0_ver, [0x80, 0x00]);

        // Test ProtocolType type alias
        let protocol_type: ProtocolType = EtherType::Ipv4;
        assert_eq!(protocol_type, EtherType::Ipv4);

        // Test AddressFamily type alias
        let address_family: AddressFamily = 0x0800;
        assert_eq!(address_family, 0x0800);

        // Test SreOffset type alias
        let sre_offset: SreOffset = 4;
        assert_eq!(sre_offset, 4);

        // Test SreLength type alias
        let sre_length: SreLength = 8;
        assert_eq!(sre_length, 8);
    }
}
