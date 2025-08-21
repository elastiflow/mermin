/// # VXLAN (Virtual Extensible LAN) Header Frame:
///   0               1               2               3
///   0 1 2 3 4 5 6 7 8 9 ...
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |R|R|R|R|I|R|R|R|            Reserved                           |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                VXLAN Network Identifier (VNI) |   Reserved    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Fields
/// * **I Flag (1 bit)**: When set to 1, indicates that the VNI field is valid.
/// * **VNI (24 bits)**: VXLAN Network Identifier.
///
/// The header is always 8 bytes long and is immediately followed by the inner
/// Ethernet frame.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct VxlanHdr {
    /// Flags byte – only bit 3 (I flag) is currently defined.
    pub flags: u8,
    /// Reserved field – MUST be zero on transmit and ignored on receipt.
    pub reserved1: [u8; 3],
    /// VXLAN Network Identifier (VNI) – 24 bits, network byte order.
    pub vni: [u8; 3],
    /// Reserved field – MUST be zero on transmit and ignored on receipt.
    pub reserved2: u8,
}

impl VxlanHdr {
    /// The fixed length of a VXLAN header, in bytes.
    pub const LEN: usize = core::mem::size_of::<VxlanHdr>();

    /// Returns true if the "I" flag is set, which indicates that the VNI is valid.
    #[inline]
    pub fn valid_vni(&self) -> bool {
        (self.flags & 0x08) == 0x08
    }

    /// Returns the VXLAN Network Identifier (VNI) as a 24-bit value.
    #[inline]
    pub fn vni(&self) -> u32 {
        u32::from_be_bytes([0, self.vni[0], self.vni[1], self.vni[2]])
    }
}