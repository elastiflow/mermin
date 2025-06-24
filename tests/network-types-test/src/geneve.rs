/// Represents a Geneve (Generic Network Virtualization Encapsulation) header, according to RFC 8926.
/// Geneve is an encapsulation protocol designed for network virtualization.

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]

pub struct GeneveHdr {
    /// Combined field: Version (2 bits) and Option Length (6 bits).
    pub ver_opt_len: u8,
    /// Combined field: OAM flag (1 bit), Critical flag (1 bit), Reserved (6 bits).
    pub o_c_rsvd: u8,
    /// Protocol Type of the encapsulated payload (16 bits).
    pub protocol_type: [u8; 2],
    /// Virtual Network Identifier (VNI) (24 bits).
    pub vni: [u8; 3],
    /// Reserved field (8 bits). MUST be zero on transmission.
    pub reserved2: u8,
}

impl GeneveHdr {
    /// The length of the Geneve header in bytes.
    pub const LEN: usize = core::mem::size_of::<GeneveHdr>();

    /// Returns the Geneve protocol version (2 bits).
    ///
    /// According to RFC 8926, the current version is 0.
    #[inline]
    pub fn ver(&self) -> u8 {
        (self.ver_opt_len >> 6) & 0x03
    }

    /// Sets the Geneve protocol version (2 bits).
    ///
    /// `ver` should be a 2-bit value (0-3).
    #[inline]
    pub fn set_ver(&mut self, ver: u8) {
        let preserved_bits = self.ver_opt_len & 0x3F;
        self.ver_opt_len = preserved_bits | ((ver & 0x03) << 6);
    }

    /// Returns the length of the option fields in 4-byte multiples (6 bits).
    #[inline]
    pub fn opt_len(&self) -> u8 {
        self.ver_opt_len & 0x3F
    }

    /// Sets the length of the option fields (6 bits).
    ///
    /// `opt_len` should be a 6-bit value (0-63).
    #[inline]
    pub fn set_opt_len(&mut self, opt_len: u8) {
        let preserved_bits = self.ver_opt_len & 0xC0;
        self.ver_opt_len = preserved_bits | (opt_len & 0x3F);
    }

    /// Returns the OAM (Operations, Administration, and Maintenance) packet flag (1 bit).
    ///
    /// If set (1), this packet is an OAM packet. Referred to as 'O' bit in RFC 8926.
    #[inline]
    pub fn o_flag(&self) -> u8 {
        (self.o_c_rsvd >> 7) & 0x01
    }

    /// Sets the OAM packet flag (1 bit).
    ///
    /// `o_flag` should be a 1-bit value (0 or 1).
    #[inline]
    pub fn set_o_flag(&mut self, o_flag: u8) {
        let preserved_bits = self.o_c_rsvd & 0x7F;
        self.o_c_rsvd = preserved_bits | ((o_flag & 0x01) << 7);
    }

    /// Returns the Critical Options Present flag (1 bit).
    ///
    /// If set (1), one or more options are marked as critical. Referred to as 'C' bit in RFC 8926.
    #[inline]
    pub fn c_flag(&self) -> u8 {
        (self.o_c_rsvd >> 6) & 0x01
    }

    /// Sets the Critical Options Present flag (1 bit).
    ///
    /// `c_flag` should be a 1-bit value (0 or 1).
    #[inline]
    pub fn set_c_flag(&mut self, c_flag: u8) {
        let preserved_bits = self.o_c_rsvd & 0xBF;
        self.o_c_rsvd = preserved_bits | ((c_flag & 0x01) << 6);
    }

    /// Returns the Protocol Type of the encapsulated payload (16 bits, network byte order).
    ///
    /// This follows the Ethertype convention.
    #[inline]
    pub fn protocol_type(&self) -> u16 {
        u16::from_be_bytes(self.protocol_type)
    }

    /// Sets the Protocol Type (16 bits).
    ///
    /// The value is stored in network byte order.
    #[inline]
    pub fn set_protocol_type(&mut self, protocol_type: u16) {
        self.protocol_type = protocol_type.to_be_bytes();
    }

    /// Returns the Virtual Network Identifier (VNI) (24 bits).
    #[inline]
    pub fn vni(&self) -> u32 {
        u32::from_be_bytes([0, self.vni[0], self.vni[1], self.vni[2]])
    }

    /// Sets the Virtual Network Identifier (VNI) (24 bits).
    ///
    /// `vni` should be a 24-bit value. Higher bits are masked.
    /// The value is stored in network byte order.
    #[inline]
    pub fn set_vni(&mut self, vni: u32) {
        let vni_val = vni & 0x00FFFFFF;
        let bytes = vni_val.to_be_bytes();
        self.vni[0] = bytes[1];
        self.vni[1] = bytes[2];
        self.vni[2] = bytes[3]
    }
}
