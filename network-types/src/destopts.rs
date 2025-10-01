//! Destination Options Header - RFC 8200
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//! |                                                               |
//! .                                                               .
//! .                            Options                            .
//! .                                                               .
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use crate::ip::IpProto;

pub const DEST_OPTS_LEN: usize = 2;

/// Next Header field (8 bits).
pub type NextHdr = IpProto;
/// Header Extension Length field (8 bits).
pub type HdrExtLen = u8;

/// Calculates the total length of the Destination Options Header in bytes.
/// The Hdr Ext Len is in 8-octet units, not including the first 8 octets.
/// So, total length = (hdr_ext_len + 1) * 8.
#[inline]
pub fn total_hdr_len(hdr_ext_len: HdrExtLen) -> usize {
    (hdr_ext_len as usize + 1) << 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_len_constant() {
        // And is at least 8 bytes (minimum header size)
        assert_eq!(DEST_OPTS_LEN, 2);
    }
}
