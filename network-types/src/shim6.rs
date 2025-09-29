use core::mem;

use crate::ip::IpProto;

/// The Shim6 Control Header is a common header format used for various control messages within the Shim6 protocol.
/// All Shim6 headers are designed to be a multiple of 8 octets in length, with a minimum size of 8 octets.
///
/// Shim6 Control Message Header Format
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Header   | Hdr Ext Len   |P|      Type     |Type-specific|S|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
/// |                                                               |
/// .                     Type-specific format                      .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///
/// Fields
///
/// * **Next Header (8 bits)**: Identifies the type of header immediately following this one.
/// * **Hdr Ext Len (8 bits)**: The length of this header in 8-octet units, not including the first 8 octets.
/// * **P (Payload Flag) (1 bit)**: Distinguishes between Shim6 Control and Payload Extension headers. Always 0.
/// * **Type (7 bits)**: Identifies the specific Shim6 control message type.
/// * **Type-specific (7 bits)**: A field whose interpretation depends on the message `Type`.
/// * **S (Shim6/HIP Distinction) (1 bit)**: Distinguishes between Shim6 and HIP messages. Always 0.
/// * **Checksum (16 bits)**: A checksum computed over the entire Shim6 message.
/// * **Type-specific format (variable length)**: A variable-length portion whose structure depends on the message `Type`.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Shim6Hdr {
    /// Next Header field (8 bits)
    pub next_hdr: IpProto,
    /// Header Length field (8 bits). This is the length of the Shim6 header
    /// in 8-octet units, not including the first 8 octets.
    pub hdr_ext_len: u8,
    /// P bit (1) + Message Type (7)
    pub p_and_type: u8,
    /// Type-specific (7) + S bit (1)
    pub type_specific_and_s: u8,
    /// Checksum field (16 bits)
    pub checksum: [u8; 2],
    /// The first 2 bytes of the Type-Specific data, part of the 8-octet base header.
    pub type_specific_data: [u8; 2],
}

impl Shim6Hdr {
    /// The size of the fixed part of the Shim6 Header in bytes.
    pub const LEN: usize = mem::size_of::<Shim6Hdr>();

    /// Gets the P (Payload Flag) bit.
    #[inline]
    pub fn p(&self) -> bool {
        (self.p_and_type >> 7) & 1 != 0
    }

    /// Sets the P (Payload Flag) bit.
    #[inline]
    pub fn set_p(&mut self, p: bool) {
        self.p_and_type = (self.p_and_type & 0x7F) | ((p as u8) << 7);
    }

    /// Gets the message Type value (7 bits).
    #[inline]
    pub fn msg_type(&self) -> u8 {
        self.p_and_type & 0x7F
    }

    /// Sets the message Type value (7 bits).
    #[inline]
    pub fn set_msg_type(&mut self, msg_type: u8) {
        self.p_and_type = (self.p_and_type & 0x80) | (msg_type & 0x7F);
    }

    /// Gets the Type-specific bits (7 bits).
    #[inline]
    pub fn type_specific_bits(&self) -> u8 {
        self.type_specific_and_s >> 1
    }

    /// Sets the Type-specific bits (7 bits).
    #[inline]
    pub fn set_type_specific_bits(&mut self, bits: u8) {
        self.type_specific_and_s = (self.type_specific_and_s & 0x01) | (bits << 1);
    }

    /// Gets the S (Shim6/HIP Distinction) bit.
    #[inline]
    pub fn s(&self) -> bool {
        (self.type_specific_and_s & 1) != 0
    }

    /// Sets the S (Shim6/HIP Distinction) bit.
    #[inline]
    pub fn set_s(&mut self, s: bool) {
        self.type_specific_and_s = (self.type_specific_and_s & 0xFE) | (s as u8);
    }

    /// Gets the Checksum as a 16-bit value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the Checksum from a 16-bit value.
    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be_bytes();
    }

    /// Gets the Type-specific data as a 16-bit value.
    #[inline]
    pub fn type_specific_data(&self) -> u16 {
        u16::from_be_bytes(self.type_specific_data)
    }

    /// Sets the Type-specific data from a 16-bit value.
    #[inline]
    pub fn set_type_specific_data(&mut self, data: u16) {
        self.type_specific_data = data.to_be_bytes();
    }

    /// Calculates the total length of the Shim6 header in bytes.
    /// Total length = (hdr_ext_len + 1) * 8.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        (self.hdr_ext_len as usize + 1) << 3
    }

    /// Calculates the length of the variable-length part of the header in bytes.
    #[inline]
    pub fn variable_len(&self) -> usize {
        self.total_hdr_len().saturating_sub(Self::LEN)
    }
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
    fn test_shim6hdr_size() {
        assert_eq!(Shim6Hdr::LEN, 8);
        assert_eq!(Shim6Hdr::LEN, mem::size_of::<Shim6Hdr>());
    }

    #[test]
    fn test_shim6hdr_getters_and_setters() {
        let mut shim_hdr = Shim6Hdr {
            next_hdr: IpProto::Ipv6NoNxt,
            hdr_ext_len: 0,
            p_and_type: 0,
            type_specific_and_s: 0,
            checksum: [0; 2],
            type_specific_data: [0; 2],
        };

        // Test P and Type fields
        shim_hdr.set_p(true);
        assert!(shim_hdr.p());
        assert_eq!(shim_hdr.p_and_type, 0x80);
        shim_hdr.set_msg_type(0x4A); // 74
        assert_eq!(shim_hdr.msg_type(), 0x4A);
        assert_eq!(shim_hdr.p_and_type, 0xCA); // 11001010
        shim_hdr.set_p(false);
        assert!(!shim_hdr.p());
        assert_eq!(shim_hdr.msg_type(), 0x4A);
        assert_eq!(shim_hdr.p_and_type, 0x4A);

        // Test Type-specific and S fields
        shim_hdr.set_s(true);
        assert!(shim_hdr.s());
        assert_eq!(shim_hdr.type_specific_and_s, 0x01);
        shim_hdr.set_type_specific_bits(0x75); // 1110101
        assert_eq!(shim_hdr.type_specific_bits(), 0x75);
        assert_eq!(shim_hdr.type_specific_and_s, 0xEB); // 11101011
        shim_hdr.set_s(false);
        assert!(!shim_hdr.s());
        assert_eq!(shim_hdr.type_specific_bits(), 0x75);
        assert_eq!(shim_hdr.type_specific_and_s, 0xEA); // 11101010

        // Test checksum
        shim_hdr.set_checksum(0x1234);
        assert_eq!(shim_hdr.checksum(), 0x1234);
        assert_eq!(shim_hdr.checksum, [0x12, 0x34]);

        // Test type_specific_data
        shim_hdr.set_type_specific_data(0x5678);
        assert_eq!(shim_hdr.type_specific_data(), 0x5678);
        assert_eq!(shim_hdr.type_specific_data, [0x56, 0x78]);
    }

    #[test]
    fn test_shim6hdr_length_calculation() {
        let mut shim_hdr = Shim6Hdr {
            next_hdr: IpProto::Ipv6NoNxt,
            hdr_ext_len: 0,
            p_and_type: 0,
            type_specific_and_s: 0,
            checksum: [0; 2],
            type_specific_data: [0; 2],
        };

        // Test with hdr_ext_len = 0
        shim_hdr.hdr_ext_len = 0;
        assert_eq!(shim_hdr.total_hdr_len(), 8);
        assert_eq!(shim_hdr.variable_len(), 0);

        // Test with hdr_ext_len = 1
        shim_hdr.hdr_ext_len = 1;
        assert_eq!(shim_hdr.total_hdr_len(), 16);
        assert_eq!(shim_hdr.variable_len(), 8);

        // Test with hdr_ext_len = 3
        shim_hdr.hdr_ext_len = 3;
        assert_eq!(shim_hdr.total_hdr_len(), 32);
        assert_eq!(shim_hdr.variable_len(), 24);

        // Test with hdr_ext_len = 255 (max value)
        shim_hdr.hdr_ext_len = 255;
        assert_eq!(shim_hdr.total_hdr_len(), (255 + 1) * 8);
        assert_eq!(shim_hdr.variable_len(), 255 * 8);
    }
}
