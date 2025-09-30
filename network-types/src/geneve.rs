//! ## Geneve (Generic Network Virtualization Encapsulation) Header Frame:
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |        Virtual Network Identifier (VNI)       |    Reserved   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! ~                    Variable-Length Options                    ~
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
use crate::eth::EtherType;

/// The length of the Geneve header.
pub const GENEVE_LEN: usize = 8;

/// Combined field: Version (2 bits) and Option Length (6 bits).
pub type VerOptLen = u8;
/// Combined field: OAM flag (1 bit), Critical flag (1 bit), Reserved (6 bits).
pub type OCRsvd = u8;
/// Protocol Type of the encapsulated payload (16 bits).
pub type ProtocolType = EtherType;
/// Virtual Network Identifier (VNI) (24 bits).
pub type Vni = [u8; 3];
/// Reserved field (8 bits). MUST be zero on transmission.
pub type Reserved2 = u8;

/// Returns the Geneve protocol version (2 bits).
///
/// According to RFC 8926, the current version is 0.
#[inline]
pub fn ver(ver_opt_len: VerOptLen) -> u8 {
    (ver_opt_len >> 6) & 0x03
}

/// Returns the length of the option fields in 4-byte multiples (6 bits).
#[inline]
pub fn opt_len(ver_opt_len: VerOptLen) -> u8 {
    ver_opt_len & 0x3F
}

/// Returns the OAM (Operations, Administration, and Maintenance) packet flag (1 bit).
///
/// If set (1), this packet is an OAM packet. Referred to as 'O' bit in RFC 8926.
#[inline]
pub fn o_flag(o_c_rsvd: OCRsvd) -> u8 {
    (o_c_rsvd >> 7) & 0x01
}

/// Returns the Critical Options Present flag (1 bit).
///
/// If set (1), one or more options are marked as critical. Referred to as 'C' bit in RFC 8926.
#[inline]
pub fn c_flag(o_c_rsvd: OCRsvd) -> u8 {
    (o_c_rsvd >> 6) & 0x01
}

/// Returns the Virtual Network Identifier (VNI) (24 bits).
#[inline]
pub fn vni(vni: Vni) -> u32 {
    u32::from_be_bytes([0, vni[0], vni[1], vni[2]])
}

/// Returns the total header length including variable options.
#[inline]
pub fn total_hdr_len(ver_opt_len: VerOptLen) -> usize {
    GENEVE_LEN + opt_len(ver_opt_len) as usize * 4
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
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
        self.vni[2] = bytes[3];
    }

    /// Returns the total header length including variable options.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        GeneveHdr::LEN + self.opt_len() as usize * 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geneve_len() {
        assert_eq!(GENEVE_LEN, 8);
    }

    #[test]
    fn test_ver() {
        // Test version 0 (default)
        let ver_opt_len: VerOptLen = 0b00000000;
        assert_eq!(ver(ver_opt_len), 0);

        // Test version 2
        let ver_opt_len: VerOptLen = 0b10000000;
        assert_eq!(ver(ver_opt_len), 0b10);

        // Test version 3
        let ver_opt_len: VerOptLen = 0b11000000;
        assert_eq!(ver(ver_opt_len), 0b11);

        // Test version extraction with opt_len bits set
        let ver_opt_len: VerOptLen = 0b10111111; // Version 2, opt_len all set
        assert_eq!(ver(ver_opt_len), 0b10);
    }

    #[test]
    fn test_opt_len() {
        // Test opt_len 0
        let ver_opt_len: VerOptLen = 0b00000000;
        assert_eq!(opt_len(ver_opt_len), 0);

        // Test opt_len 42
        let ver_opt_len: VerOptLen = 0b00101010;
        assert_eq!(opt_len(ver_opt_len), 42);

        // Test opt_len 63 (max 6-bit value)
        let ver_opt_len: VerOptLen = 0b00111111;
        assert_eq!(opt_len(ver_opt_len), 63);

        // Test opt_len extraction with version bits set
        let ver_opt_len: VerOptLen = 0b11101010; // Version 3, opt_len 42
        assert_eq!(opt_len(ver_opt_len), 42);
    }

    #[test]
    fn test_o_flag() {
        // Test O flag not set
        let o_c_rsvd: OCRsvd = 0b00000000;
        assert_eq!(o_flag(o_c_rsvd), 0);

        // Test O flag set
        let o_c_rsvd: OCRsvd = 0b10000000;
        assert_eq!(o_flag(o_c_rsvd), 1);

        // Test O flag extraction with C flag and reserved bits set
        let o_c_rsvd: OCRsvd = 0b10111111; // O set, C set, reserved bits set
        assert_eq!(o_flag(o_c_rsvd), 1);

        // Test O flag not set but other bits set
        let o_c_rsvd: OCRsvd = 0b01111111; // O not set, C set, reserved bits set
        assert_eq!(o_flag(o_c_rsvd), 0);
    }

    #[test]
    fn test_c_flag() {
        // Test C flag not set
        let o_c_rsvd: OCRsvd = 0b00000000;
        assert_eq!(c_flag(o_c_rsvd), 0);

        // Test C flag set
        let o_c_rsvd: OCRsvd = 0b01000000;
        assert_eq!(c_flag(o_c_rsvd), 1);

        // Test C flag extraction with O flag and reserved bits set
        let o_c_rsvd: OCRsvd = 0b11111111; // O set, C set, reserved bits set
        assert_eq!(c_flag(o_c_rsvd), 1);

        // Test C flag not set but other bits set
        let o_c_rsvd: OCRsvd = 0b10111111; // O set, C not set, reserved bits set
        assert_eq!(c_flag(o_c_rsvd), 0);
    }

    #[test]
    fn test_vni() {
        // Test VNI 0
        let vni_bytes: Vni = [0x00, 0x00, 0x00];
        assert_eq!(vni(vni_bytes), 0x00000000);

        // Test VNI with specific value
        let vni_bytes: Vni = [0x12, 0x34, 0x56];
        assert_eq!(vni(vni_bytes), 0x00123456);

        // Test VNI max value (24 bits)
        let vni_bytes: Vni = [0xFF, 0xFF, 0xFF];
        assert_eq!(vni(vni_bytes), 0x00FFFFFF);

        // Test VNI endianness
        let vni_bytes: Vni = [0x01, 0x02, 0x03];
        assert_eq!(vni(vni_bytes), 0x00010203);
    }

    #[test]
    fn test_total_hdr_len() {
        // Test with no options (opt_len = 0)
        let ver_opt_len: VerOptLen = 0b00000000;
        assert_eq!(total_hdr_len(ver_opt_len), 8);

        // Test with opt_len = 1 (4 bytes of options)
        let ver_opt_len: VerOptLen = 0b00000001;
        assert_eq!(total_hdr_len(ver_opt_len), 12);

        // Test with opt_len = 10 (40 bytes of options)
        let ver_opt_len: VerOptLen = 0b00001010;
        assert_eq!(total_hdr_len(ver_opt_len), 48);

        // Test with max opt_len = 63 (252 bytes of options)
        let ver_opt_len: VerOptLen = 0b00111111;
        assert_eq!(total_hdr_len(ver_opt_len), 260); // 8 + 63*4

        // Test with version bits set (should not affect calculation)
        let ver_opt_len: VerOptLen = 0b11000101; // Version 3, opt_len 5
        assert_eq!(total_hdr_len(ver_opt_len), 28); // 8 + 5*4
    }

    #[test]
    fn test_protocol_type_is_ethertype() {
        // Verify that ProtocolType is an EtherType
        let protocol_type: ProtocolType = EtherType::Ipv4;
        assert_eq!(protocol_type, EtherType::Ipv4);

        let protocol_type: ProtocolType = EtherType::Ipv6;
        assert_eq!(protocol_type, EtherType::Ipv6);
    }
}
