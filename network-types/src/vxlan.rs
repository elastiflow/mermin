use core::mem;

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

/// Mask for the I-flag (VNI Present flag, bit 3) in the `flags` field.
pub const VXLAN_I_FLAG_MASK: u8 = 0x08;

impl VxlanHdr {
    /// Length of the VXLAN header in bytes (8 bytes).
    pub const LEN: usize = mem::size_of::<VxlanHdr>();

    /// Returns the raw flags' byte.
    ///
    /// # Returns
    /// The 8-bit flags field.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Sets the raw flags byte.
    ///
    /// # Parameters
    /// - `flags`: The 8-bit value to set for the flags field.
    #[inline]
    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
    }

    /// Returns the VXLAN Network Identifier (VNI).
    ///
    /// # Returns
    /// The 24-bit VNI as a `u32`.
    #[inline]
    pub fn vni(&self) -> u32 {
        u32::from_be_bytes([0, self.vni[0], self.vni[1], self.vni[2]])
    }

    /// Sets the VXLAN Network Identifier (VNI).
    ///
    /// Masks the input `vni` to 24 bits. Preserves the `reserved2` field.
    ///
    /// # Parameters
    /// - `vni`: The 24-bit VNI value.
    #[inline]
    pub fn set_vni(&mut self, vni: u32) {
        let vni_24bit = vni & 0x00FF_FFFF;
        let vni_bytes = vni_24bit.to_be_bytes();
        self.vni[0] = vni_bytes[1];
        self.vni[1] = vni_bytes[2];
        self.vni[2] = vni_bytes[3];
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
