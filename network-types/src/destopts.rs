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

    /// Gets the Next Header value.
    #[inline]
    pub fn next_hdr(&self) -> IpProto {
        self.next_hdr
    }

    /// Sets the Next Header value.
    #[inline]
    pub fn set_next_hdr(&mut self, next_hdr: IpProto) {
        self.next_hdr = next_hdr;
    }

    /// Gets the Hdr Ext Len value.
    #[inline]
    pub fn hdr_ext_len(&self) -> u8 {
        self.hdr_ext_len
    }

    /// Sets the Hdr Ext Len value.
    #[inline]
    pub fn set_hdr_ext_len(&mut self, hdr_ext_len: u8) {
        self.hdr_ext_len = hdr_ext_len;
    }

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

    fn default_hdr() -> DestOptsHdr {
        DestOptsHdr {
            next_hdr: IpProto::Tcp,
            hdr_ext_len: 0,
            opt_data: [0; 6],
        }
    }

    #[test]
    fn test_getters_setters() {
        let mut hdr = default_hdr();
        assert_eq!(hdr.next_hdr(), IpProto::Tcp);
        hdr.set_next_hdr(IpProto::Udp);
        assert_eq!(hdr.next_hdr(), IpProto::Udp);

        assert_eq!(hdr.hdr_ext_len(), 0);
        hdr.set_hdr_ext_len(3);
        assert_eq!(hdr.hdr_ext_len(), 3);
    }

    #[test]
    fn test_total_hdr_len_various() {
        let mut hdr = default_hdr();
        // hdr_ext_len = 0 -> (0+1)*8 = 8
        hdr.set_hdr_ext_len(0);
        assert_eq!(hdr.total_hdr_len(), 8);
        // 1 -> 16
        hdr.set_hdr_ext_len(1);
        assert_eq!(hdr.total_hdr_len(), 16);
        // 2 -> 24
        hdr.set_hdr_ext_len(2);
        assert_eq!(hdr.total_hdr_len(), 24);
        // 7 -> 64
        hdr.set_hdr_ext_len(7);
        assert_eq!(hdr.total_hdr_len(), 64);
        // 255 -> 2048
        hdr.set_hdr_ext_len(255);
        assert_eq!(hdr.total_hdr_len(), (255usize + 1) * 8);
    }

    #[test]
    fn test_len_constant() {
        // Ensure LEN equals size_of::<DestOptsHdr>()
        assert_eq!(DestOptsHdr::LEN, core::mem::size_of::<DestOptsHdr>());
        // And is at least 8 bytes (minimum header size)
        assert!(DestOptsHdr::LEN >= 8);
    }
}
