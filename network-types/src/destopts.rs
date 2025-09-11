use core::mem;

use crate::ip::IpProto;

/// Destination Options Header - RFC 8200
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Next Header  |  Hdr Ext Len  |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
/// |                                                               |
/// .                                                               .
/// .                            Options                            .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Fields
///
/// * **Next Header (8 bits)**: 8-bit selector. Identifies the type of header
///   immediately following the Destination Options header. Uses the same
///   values as the IPv4 Protocol field [IANA-PN].
///
/// * **Hdr Ext Len (8 bits)**: 8-bit unsigned integer. Length of the
///   Destination Options header in 8-octet units, not including the first 8
///   octets.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct DestOptsHdr {
    pub next_hdr: IpProto,
    pub hdr_ext_len: u8,
    pub opt_data: [u8; 6], // Minimum needed for 8 bytes of padding if options is empty
}

impl DestOptsHdr {
    /// The size of the fixed part of the Destination Options Header, in bytes.
    pub const LEN: usize = mem::size_of::<DestOptsHdr>();

    /// Calculates the total length of the Destination Options Header in bytes.
    /// The Hdr Ext Len is in 8-octet units, not including the first 8 octets.
    /// So, total length = (hdr_ext_len + 1) * 8.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        (self.hdr_ext_len as usize + 1) << 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_len_constant() {
        // Ensure LEN equals size_of::<DestOptsHdr>()
        assert_eq!(DestOptsHdr::LEN, core::mem::size_of::<DestOptsHdr>());
        // And is at least 8 bytes (minimum header size)
        assert!(DestOptsHdr::LEN >= 8);
    }
}
