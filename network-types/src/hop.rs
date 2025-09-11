use core::mem;

use crate::ip::IpProto;
/// # IPv6 Hop-by-Hop Options Extension Header
///
///  0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Next Header  |  Hdr Ext Len  |     Always Present Options    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-                                /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// .                                                               .
/// .                      Options Cont.                            .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Fields
///
/// * **Next Header (8 bits)**: Identifies the type of the next header.
/// * **Hdr Ext Len (8 bits)**: The length of this header in 8-octet units, not including the first 8 octets.
/// * **Options (variable)**: Contains one or more TLV-encoded options.
///
/// This struct can also be used to represent IPv6 Destination Options Extension Header
/// as both headers share the same format. The only difference is in the Next Header value
/// and their position in the IPv6 extension header chain.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct HopOptHdr {
    pub next_hdr: IpProto,
    pub hdr_ext_len: u8,
    /// The first 6 bytes of the options field.
    /// If hdr_ext_len is 0, these are all the options.
    /// If hdr_ext_len > 0, additional options follow these 6 bytes.
    pub opt_data: [u8; 6], // These 6 octets options are always present
}

impl HopOptHdr {
    /// The total size in bytes of default length HbH header
    pub const LEN: usize = mem::size_of::<HopOptHdr>();

    /// Gets a slice to the first 6 bytes of options data
    #[inline]
    pub fn opt_data(&self) -> &[u8; 6] {
        &self.opt_data
    }

    /// Calculates the total length of the Hop-by-Hop header in bytes.
    /// The Hdr Ext Len is in 8-octet units, *excluding* the first 8 octets.
    /// So, total length = (hdr_ext_len + 1) * 8.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        (self.hdr_ext_len as usize + 1) << 3
    }

    /// Calculates the total length of the options field in bytes.
    /// Options field = Total Header Length - 2 bytes (for next_hdr and hdr_ext_len).
    #[inline]
    pub fn total_opts_len(&self) -> usize {
        self.total_hdr_len().saturating_sub(2)
    }
}

#[cfg(test)]
mod tests {
    use core::mem;

    use super::*;

    #[test]
    fn test_hopopthdr_getters_and_setters() {
        let mut hop_hdr = HopOptHdr {
            next_hdr: IpProto::HopOpt,
            hdr_ext_len: 0,
            opt_data: [0; 6],
        };

        // Test opt_data
        hop_hdr.opt_data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        assert_eq!(hop_hdr.opt_data(), &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
    }

    #[test]
    fn test_hopopthdr_size() {
        // HopOptHdr should be exactly 8 bytes
        assert_eq!(HopOptHdr::LEN, 8);
        assert_eq!(HopOptHdr::LEN, mem::size_of::<HopOptHdr>());
    }

    #[test]
    fn test_hopopthdr_length_calculation_methods() {
        let mut hop_hdr = HopOptHdr {
            next_hdr: IpProto::HopOpt,
            hdr_ext_len: 0,
            opt_data: [0; 6],
        };

        // Test with hdr_ext_len = 0
        hop_hdr.hdr_ext_len = 0;
        assert_eq!(hop_hdr.total_hdr_len(), 8);
        assert_eq!(hop_hdr.total_opts_len(), 6);

        // Test with hdr_ext_len = 1
        hop_hdr.hdr_ext_len = 1;
        assert_eq!(hop_hdr.total_hdr_len(), 16);
        assert_eq!(hop_hdr.total_opts_len(), 14);

        // Test with hdr_ext_len = 3
        hop_hdr.hdr_ext_len = 3;
        assert_eq!(hop_hdr.total_hdr_len(), 32);
        assert_eq!(hop_hdr.total_opts_len(), 30);

        // Test with hdr_ext_len = 255 (max value)
        hop_hdr.hdr_ext_len = 255;
        assert_eq!(hop_hdr.total_hdr_len(), (255 + 1) * 8);
        assert_eq!(hop_hdr.total_opts_len(), (255 + 1) * 8 - 2);
    }
}
