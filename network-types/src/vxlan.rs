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
use core::mem;

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

/// VXLAN (Virtual eXtensible Local Area Network) header.
///
/// Encapsulates OSI layer 2 Ethernet frames within layer 4 UDP packets.
/// Uses a 24-bit VXLAN Network Identifier (VNI) for traffic segregation.
/// Header length: 8 bytes.
/// Reference: RFC 7348.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct VxlanHdr {
    /// Flags (8 bits). Bit 3 (I flag) must be 1 if VNI is present. Other bits are reserved (R).
    pub flags: u8,
    /// Reserved field (24 bits). Must be zero on transmission.
    pub _reserved1: [u8; 3],
    /// Contains the 24-bit VNI (upper 3 bytes) and an 8-bit reserved field (the lowest byte).
    /// The reserved field (the lowest byte) must be zero on transmission.
    pub vni: [u8; 3],
    pub _reserved2: u8,
}

impl VxlanHdr {
    /// Length of the VXLAN header in bytes (8 bytes).
    pub const LEN: usize = mem::size_of::<VxlanHdr>();

    /// Returns the raw flags' byte.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the VXLAN Network Identifier (VNI).
    #[inline]
    pub fn vni(&self) -> u32 {
        u32::from_be_bytes([0, self.vni[0], self.vni[1], self.vni[2]])
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlanhdr_len() {
        assert_eq!(VxlanHdr::LEN, 8, "VXLAN header length should be 8 bytes");
    }

    #[test]
    fn test_vxlanhdr_vni() {
        let mut hdr = VxlanHdr {
            flags: 0,
            _reserved1: [0; 3],
            vni: [0, 0, 0],
            _reserved2: 0,
        };
        assert_eq!(hdr.vni(), 0, "VNI should be 0 by default");
        hdr.set_vni(0x123456);
        assert_eq!(hdr.vni(), 0x123456, "VNI should be 0x123456");
    }
}
