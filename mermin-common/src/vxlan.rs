//! ## VXLAN (Virtual eXtensible Local Area Network) Header
//!
//! Encapsulates OSI layer 2 Ethernet frames within layer 4 UDP packets.
//! Uses a 24-bit VXLAN Network Identifier (VNI) for traffic segregation.
//! Header length: 8 bytes.
//! Reference: RFC 7348.
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |R|R|R|R|I|R|R|R|            Reserved                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                VXLAN Network Identifier (VNI) |   Reserved    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

/// Length of the VXLAN header in bytes (8 bytes).
pub const VXLAN_LEN: usize = 8;

/// Mask for the I-flag (VNI Present flag, bit 3) in the `flags` field.
pub const VXLAN_I_FLAG_MASK: u8 = 0x08;

/// Flags (8 bits). Bit 3 (I flag) must be 1 if VNI is present. Other bits are reserved (R).
pub type Flags = u8;
/// Reserved field (24 bits). Must be zero on transmission.
pub type Reserved1 = [u8; 3];
/// Contains the 24-bit VNI (upper 3 bytes) and an 8-bit reserved field (the lowest byte).
/// The reserved field (the lowest byte) must be zero on transmission.
pub type Vni = [u8; 3];
/// Reserved field (8 bits). Must be zero on transmission.
pub type Reserved2 = u8;

pub fn flags_i_flag(flags: Flags) -> bool {
    (flags & VXLAN_I_FLAG_MASK) != 0
}

/// Returns the VXLAN Network Identifier (VNI).
#[inline]
pub fn vni(vni: Vni) -> u32 {
    u32::from_be_bytes([0, vni[0], vni[1], vni[2]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlan_len_constant() {
        assert_eq!(VXLAN_LEN, 8, "VXLAN header length should be 8 bytes");
    }

    #[test]
    fn test_vxlan_vni_helpers() {
        let vni_bytes: Vni = [0x12, 0x34, 0x56];
        assert_eq!(vni(vni_bytes), 0x123456, "VNI should be 0x123456");

        let zero_vni: Vni = [0, 0, 0];
        assert_eq!(vni(zero_vni), 0, "VNI should be 0");
    }

    #[test]
    fn test_vxlan_flags_i_flag() {
        // I flag is bit 3 (0x08)
        assert_eq!(flags_i_flag(0x08), true, "I flag should be set");
        assert_eq!(flags_i_flag(0x00), false, "I flag should not be set");
        assert_eq!(flags_i_flag(0xFF), true, "I flag should be set");
    }
}
