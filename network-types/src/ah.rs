use core::mem;

use crate::ip::IpProto;

/// Authentication Header Format
///
///  0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Next Header   |   Payload Len  |          Reserved         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                Security Parameters Index                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Sequence Number                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                Integrity Check Value (variable)               ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Fields
///
/// * **Next Header (8 bits)**: Identifies the type of the next header,
/// * **Payload Len (8 bits)**: The length of this Authentication Header in 4-octet units,
/// * **Reserved (16 bits)**: Reserved for future use and initialized to all zeroes.
/// * **Security Parameters Index (32 bits)**: Identifies the security association of the receiving party.
/// * **Sequence Number (32 bits)**: A monotonic, strictly increasing sequence number to prevent replay attacks.
/// * **Integrity Check Value (multiple of 32 bits)**: A variable-length check value.
///   Authentication Header
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AuthHdr {
    pub next_hdr: IpProto,
    pub payload_len: u8,
    pub reserved: [u8; 2],
    pub spi: [u8; 4],
    pub seq_num: [u8; 4],
}

impl AuthHdr {
    /// The total size in bytes of the fixed part of the Authentication Header
    pub const LEN: usize = mem::size_of::<AuthHdr>();

    /// Gets the Reserved field as a 16-bit value.
    #[inline]
    pub fn reserved(&self) -> u16 {
        u16::from_be_bytes(self.reserved)
    }

    /// Sets the Reserved field from a 16-bit value.
    #[inline]
    pub fn set_reserved(&mut self, reserved: u16) {
        self.reserved = reserved.to_be_bytes();
    }

    /// Gets the Security Parameters Index as a 32-bit value.
    #[inline]
    pub fn spi(&self) -> u32 {
        u32::from_be_bytes(self.spi)
    }

    /// Sets the Security Parameters Index from a 32-bit value.
    #[inline]
    pub fn set_spi(&mut self, spi: u32) {
        self.spi = spi.to_be_bytes();
    }

    /// Gets the Sequence Number as a 32-bit value.
    #[inline]
    pub fn seq_num(&self) -> u32 {
        u32::from_be_bytes(self.seq_num)
    }

    /// Sets the Sequence Number from a 32-bit value.
    #[inline]
    pub fn set_seq_num(&mut self, seq_num: u32) {
        self.seq_num = seq_num.to_be_bytes();
    }

    /// Calculates the total length of the Authentication Header in bytes.
    /// The Payload Length is in 4-octet units, minus 2.
    /// So, total length = (payload_len + 2) * 4.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        (self.payload_len as usize + 2) << 2
    }

    /// Calculates the length of the Integrity Check Value in bytes.
    /// ICV length = Total Header Length - Fixed Header Length.
    #[inline]
    pub fn icv_len(&self) -> usize {
        self.total_hdr_len().saturating_sub(AuthHdr::LEN)
    }
}

#[cfg(test)]
mod tests {
    use core::mem;

    use super::*;

    #[test]
    fn test_ahhdr_getters_and_setters() {
        let mut auth_hdr = AuthHdr {
            next_hdr: IpProto::HopOpt,
            payload_len: 0,
            reserved: [0; 2],
            spi: [0; 4],
            seq_num: [0; 4],
        };

        // Test reserved
        auth_hdr.set_reserved(0x1234);
        assert_eq!(auth_hdr.reserved(), 0x1234);
        assert_eq!(auth_hdr.reserved, [0x12, 0x34]);

        // Test spi
        auth_hdr.set_spi(0x12345678);
        assert_eq!(auth_hdr.spi(), 0x12345678);
        assert_eq!(auth_hdr.spi, [0x12, 0x34, 0x56, 0x78]);

        // Test seq_num
        auth_hdr.set_seq_num(0x87654321);
        assert_eq!(auth_hdr.seq_num(), 0x87654321);
        assert_eq!(auth_hdr.seq_num, [0x87, 0x65, 0x43, 0x21]);
    }

    #[test]
    fn test_ahhdr_size() {
        // AuthHdr fixed header should be exactly 12 bytes
        assert_eq!(AuthHdr::LEN, 12);
        assert_eq!(AuthHdr::LEN, mem::size_of::<AuthHdr>());
    }

    #[test]
    fn test_ahhdr_length_calculation_methods() {
        let mut auth_hdr = AuthHdr {
            next_hdr: IpProto::HopOpt,
            payload_len: 0,
            reserved: [0; 2],
            spi: [0; 4],
            seq_num: [0; 4],
        };

        // Test with payload_len = 0
        auth_hdr.payload_len = 0;
        assert_eq!(auth_hdr.total_hdr_len(), 8);
        assert_eq!(auth_hdr.icv_len(), 0);

        // Test with payload_len = 1
        auth_hdr.payload_len = 1;
        assert_eq!(auth_hdr.total_hdr_len(), 12);
        assert_eq!(auth_hdr.icv_len(), 0);

        // Test with payload_len = 3
        auth_hdr.payload_len = 3;
        assert_eq!(auth_hdr.total_hdr_len(), 20);
        assert_eq!(auth_hdr.icv_len(), 8);

        // Test with payload_len = 255 (max value)
        auth_hdr.payload_len = 255;
        assert_eq!(auth_hdr.total_hdr_len(), (255 + 2) * 4);
        assert_eq!(auth_hdr.icv_len(), (255 + 2) * 4 - AuthHdr::LEN);
    }
}
