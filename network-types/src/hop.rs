//! # IPv6 Hop-by-Hop Options Extension Header
//!
//! This struct can also be used to represent IPv6 Destination Options Extension Header
//! as both headers share the same format. The only difference is in the Next Header value
//! and their position in the IPv6 extension header chain.
//!
//!  0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |     Always Present Options    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-                                /
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! .                                                               .
//! .                      Options Cont.                            .
//! .                                                               .
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use crate::ip::IpProto;

/// The length of the Hop-by-Hop options header base structure.
pub const HOP_OPT_LEN: usize = 8;

/// Next Header field (8 bits).
pub type NextHdr = IpProto;
/// Header Extension Length field (8 bits).
pub type HdrExtLen = u8;
/// Options data field (6 bytes minimum).
pub type OptData = [u8; 6];

/// Returns the total length of the Hop-by-Hop header in bytes.
/// The Hdr Ext Len is in 8-octet units, *excluding* the first 8 octets.
/// So, total length = (hdr_ext_len + 1) * 8.
#[inline]
pub fn total_hdr_len(hdr_ext_len: HdrExtLen) -> usize {
    (hdr_ext_len as usize + 1) << 3
}

/// Returns the total length of the options field in bytes.
/// Options field = Total Header Length - 2 bytes (for next_hdr and hdr_ext_len).
#[inline]
pub fn total_opts_len(hdr_ext_len: HdrExtLen) -> usize {
    total_hdr_len(hdr_ext_len).saturating_sub(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_opt_len_constant() {
        assert_eq!(HOP_OPT_LEN, 8);
    }

    #[test]
    fn test_public_type_aliases() {
        // Test NextHdr type alias
        let next_hdr: NextHdr = IpProto::HopOpt;
        assert_eq!(next_hdr, IpProto::HopOpt);

        // Test HdrExtLen type alias
        let hdr_ext_len: HdrExtLen = 5;
        assert_eq!(hdr_ext_len, 5);

        // Test OptData type alias
        let opt_data: OptData = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        assert_eq!(opt_data, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
    }

    #[test]
    fn test_public_helper_functions() {
        // Test total_hdr_len function
        assert_eq!(total_hdr_len(0), 8);
        assert_eq!(total_hdr_len(1), 16);
        assert_eq!(total_hdr_len(3), 32);
        assert_eq!(total_hdr_len(255), (255 + 1) * 8);

        // Test total_opts_len function
        assert_eq!(total_opts_len(0), 6);
        assert_eq!(total_opts_len(1), 14);
        assert_eq!(total_opts_len(3), 30);
        assert_eq!(total_opts_len(255), (255 + 1) * 8 - 2);
    }
}
