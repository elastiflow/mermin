//! IPv6 Routing Extension Header Format
//!
//!  0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left | <- Generic Header
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! .                                                               .
//! .                       type-specific data                      .
//! .                                                               .
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! Fields
//!
//! * **Next Header (8 bits)**: Identifies the type of the next header.
//! * **Hdr Ext Len (8 bits)**: The length of the Routing header in 8-octet units, not including the first 8 octets.
//! * **Routing Type (8 bits)**: Identifies the variant of the Routing header.
//! * **Segments Left (8 bits)**: Number of route segments remaining.
//! * **Type-specific data (variable)**: Format depends on the Routing Type value.

//! Type 2 Routing Header (Mobile IPv6) - RFC 6275
//!
//! This routing header is used in Mobile IPv6 to allow a packet to be routed from a
//! mobile node's home address to its current location (care-of address).
//!
//!  0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left | <- Generic Header
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           Reserved                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                                                               |
//! |                                                               |
//! |                         Home Address                          |
//! |                                                               |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! Fields
//!
//! * **Reserved (32 bits)**: Reserved for future use and initialized to all zeroes.
//! * **Home Address (128 bits)**: The home address of the mobile node.

//! Type 3 RPL Source Route Header - RFC 6554
//!
//! This routing header is used in the Routing Protocol for Low-Power and Lossy Networks (RPL)
//! for source routing in constrained environments like sensor networks.
//!
//!  0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left | <- Generic Header
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | CmprI | CmprE |  Pad  |               Reserved                | <- RPL Fixed Header
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! .                                                               .
//! .                        Addresses[1..n]                        . <-
//! .                                                               .
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! Fields
//!
//! * **CmprI (4 bits)**: Number of prefix octets elided from addresses in the Addresses field.
//! * **CmprE (4 bits)**: Number of prefix octets elided from the last address in the Addresses field.
//! * **Pad (4 bits)**: Number of octets that are used for padding after Address
//! * **Reserved (20 bits)**: Set to 0 by the sender and ignored by the receiver.
//! * **Addresses[1..n] (variable)**: Vector of addresses, each of variable size depending on CmprI and CmprE.

//! Type 4 Segment Routing Header (SRH) - RFC 8754
//!
//! This routing header is used for Segment Routing over IPv6 (SRv6). It allows a source
//! to specify a path for a packet to traverse by listing an ordered set of segments.
//!
//!  0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Last Entry   |     Flags     |              Tag              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |            Segment List[0] (128 bits IPv6 address)            |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                                                               |
//! ...                                                           ...
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |            Segment List[n] (128 bits IPv6 address)            |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! //                                                             //
//! //         Optional Type Length Value objects (variable)       //
//! //                                                             //
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! Fields
//!
//! * **Last Entry (8 bits)**: Index of the last entry in the Segment List.
//! * **Flags (8 bits)**: 8 bits of flags.
//! * **Tag (16 bits)**: Tag a packet as part of a class or group of packets.
//! * **Segment List[0..n]**: List of 128-bit IPv6 addresses representing the segments.
//! * **Optional TLVs**: Type-Length-Value objects for additional information.

//! Type 5 Compact Routing Header with 16-bit SIDs (CRH-16) - RFC 9631
//!
//! This routing header is an experimental alternative to SRH, designed to be more space-efficient
//! by using 16-bit Segment Identifiers (SIDs) instead of full IPv6 addresses.
//!
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |              SID[0]           |              SID[1]           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |              ...              |              ...              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |              ...              |              SID[n]           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! Fields
//!
//! * **Next Header (8 bits)**: Identifies the type of the next header.
//! * **Hdr Ext Len (8 bits)**: The length of the Routing header in 8-octet units, not including the first 8 octets.
//! * **Routing Type (8 bits)**: Identifies the variant of the Routing header. For CRH-16, this is 5.
//! * **Segments Left (8 bits)**: Index of the current active segment in the SID List.
//! * **SID List[0..n]**: List of 16-bit Segment Identifiers.
//!
//! Type 6 Compact Routing Header with 32-bit SIDs (CRH-32) - RFC 9631
//!
//! This routing header is an experimental alternative to SRH, designed to be more space-efficient
//! by using 32-bit Segment Identifiers (SIDs) instead of full IPv6 addresses.
//!
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              SID[0]                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              ...                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              SID[n]                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! Fields
//!
//! * **Next Header (8 bits)**: Identifies the type of the next header.
//! * **Hdr Ext Len (8 bits)**: The length of the Routing header in 8-octet units, not including the first 8 octets.
//! * **Routing Type (8 bits)**: Identifies the variant of the Routing header. For CRH-32, this is 6.
//! * **Segments Left (8 bits)**: Index of the current active segment in the SID List.
//! * **SID List[0..n]**: List of 32-bit Segment Identifiers.
use core::mem;

use crate::ip::IpProto;

/// Maximum number of addresses we can read at a time from a RPL Source Route Header
pub const MAX_RPL_ADDRESSES: usize = 32;

/// Maximum number of segments in a Type 4 Segment Routing Header
pub const MAX_SRH_SEGMENTS: usize = 128;

/// Maximum number of SIDs in a Type 5 or 6 CRH Header
pub const MAX_CRH_SIDS: usize = 128;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RoutingHeaderType {
    /// Type 2 Routing Header - [RFC6275]
    Type2,
    /// RPL Source Route Header - [RFC6554]
    RplSourceRoute,
    /// Segment Routing Header (SRH) - [RFC8754]
    SegmentRoutingHeader,
    /// CRH-16 - [RFC9631]
    Crh16,
    /// CRH-32 - [RFC9631]
    Crh32,
    /// RFC3692-style Experiment 1 [2] - [RFC4727]
    Experiment1,
    /// RFC3692-style Experiment 2 [2] - [RFC4727]
    Experiment2,
    /// Reserved
    Reserved,
}

#[derive(Debug, Clone, Copy)]
pub enum Ipv6RoutingHeader {
    /// Type 2 Routing Header - [RFC6275]
    Type2(Type2RoutingHeader),
    /// RPL Source Route Header - [RFC6554]
    RplSourceRoute(RplSourceRouteHeader),
    /// Segment Routing Header (SRH) - [RFC8754]
    SegmentRouting(SegmentRoutingHeader),
    /// CRH-16 - [RFC9631]
    Crh16(CrhHeader),
    /// CRH-32 - [RFC9631]
    Crh32(CrhHeader),
    /// RFC3692-style Experiment 1 [2] - [RFC4727]
    Experiment1(GenericRoute),
    /// RFC3692-style Experiment 2 [2] - [RFC4727]
    Experiment2(GenericRoute),
    /// A reserved routing type was encountered.
    Reserved,
    /// An unknown or unassigned routing type was encountered.
    Unknown(GenericRoute),
}


pub const GENERIC_ROUTE_LEN: usize = 4; // next_hdr (1) + hdr_ext_len (1) + type_ (1) + sgmt_left (1)

pub type NextHdr = IpProto;
pub type HdrExtLen = u8;
pub type Type_ = RoutingHeaderType;
pub type SgmtLeft = u8;

#[inline]
pub fn total_hdr_len(hdr_ext_len: HdrExtLen) -> usize {
    (hdr_ext_len as usize + 1) << 3
}

/// Calculates the total length of the Type-specific data field in bytes.
/// Total Header Length - 4 bytes (for next_hdr, hdr_ext_len, type_, and sgmt_left)
#[inline]
pub fn total_type_data_len(hdr_ext_len: HdrExtLen) -> usize {
    total_hdr_len(hdr_ext_len).saturating_sub(4)
}


#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct GenericRoute {
    pub next_hdr: IpProto,
    pub hdr_ext_len: u8,
    pub type_: RoutingHeaderType,
    pub sgmt_left: u8,
}

impl GenericRoute {
    /// The total size in bytes of default length Routing header
    pub const LEN: usize = mem::size_of::<GenericRoute>();

    /// Calculates the total length of the Routing header in bytes.
    /// The Hdr Ext Len is in 8-octet units, *excluding* the first 8 octets.
    /// So, total length = (hdr_ext_len + 1) * 8.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        (self.hdr_ext_len as usize + 1) << 3
    }

    /// Calculates the total length of the Type-specific data field in bytes.
    /// Total Header Length - 4 bytes (for next_hdr, hdr_ext_len, type_, and sgmt_left)
    #[inline]
    pub fn total_type_data_len(&self) -> usize {
        self.total_hdr_len().saturating_sub(4)
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Type2FixedHeader {
    pub reserved: [u8; 4],
    pub home_address: [u8; 16],
}

impl Type2FixedHeader {
    /// The total size in bytes of the fixed part of the Type 2 Routing Header
    pub const LEN: usize = mem::size_of::<Type2FixedHeader>();
    /// Gets the Reserved field as a 32-bit value.
    #[inline]
    pub fn reserved(&self) -> u32 {
        u32::from_be_bytes(self.reserved)
    }

    /// Sets the Reserved field from a 32-bit value.
    #[inline]
    pub fn set_reserved(&mut self, reserved: u32) {
        self.reserved = reserved.to_be_bytes()
    }

    /// Gets the Home Address as a 16-byte array.
    #[inline]
    pub fn home_address(&self) -> u128 {
        u128::from_be_bytes(self.home_address)
    }

    /// Sets the Home Address from a 16-byte array.
    #[inline]
    pub fn set_home_address(&mut self, home_address: u128) {
        self.home_address = home_address.to_be_bytes();
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Type2RoutingHeader {
    pub generic_route: GenericRoute,
    pub fixed_hdr: Type2FixedHeader,
}

impl Type2RoutingHeader {
    /// The total size in bytes of the Type 2 Routing Header
    pub const LEN: usize = mem::size_of::<Type2RoutingHeader>();
}


#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RplSourceFixedHeader {
    pub cmpr: u8, // High 4 bits: CmprI, low 4 bits: CmprE
    pub pad_reserved: [u8; 3],
}

impl RplSourceFixedHeader {
    /// The total size in bytes of the fixed part of the RPL Source Route Header
    pub const LEN: usize = mem::size_of::<RplSourceFixedHeader>();

    /// Gets the CmprI value (number of prefix octets elided from addresses).
    #[inline]
    pub fn cmpr_i(&self) -> u8 {
        (self.cmpr >> 4) & 0x0F
    }

    /// Gets the CmprE value (number of prefix octets elided from the last address).
    #[inline]
    pub fn cmpr_e(&self) -> u8 {
        self.cmpr & 0x0F
    }

    /// Sets the CmprI and CmprE values.
    #[inline]
    pub fn set_cmpr(&mut self, cmpr_i: u8, cmpr_e: u8) {
        self.cmpr = ((cmpr_i & 0x0F) << 4) | (cmpr_e & 0x0F);
    }

    /// Gets the Pad value (number of octets that are used for padding after Address).
    #[inline]
    pub fn pad(&self) -> u8 {
        (self.pad_reserved[0] >> 4) & 0x0F
    }

    /// Sets the Pad value.
    #[inline]
    pub fn set_pad(&mut self, pad: u8) {
        self.pad_reserved[0] = (pad & 0x0F) << 4 | (self.pad_reserved[0] & 0x0F);
    }

    /// Gets the Reserved field as a 20-bit value, taking into account the padding bits.
    /// The first 4 bits of the first byte are padding bits and are masked out.
    #[inline]
    pub fn reserved(&self) -> u32 {
        // Create a 4-byte array with the 3 bytes from reserved
        let mut bytes = [0u8; 4];
        bytes[1..4].copy_from_slice(&self.pad_reserved);

        // Mask out the padding bits (first 4 bits of the first byte)
        bytes[1] &= 0x0F;

        // Convert to u32
        u32::from_be_bytes(bytes)
    }

    /// Sets the Reserved field from a 20-bit value, preserving the padding bits.
    /// The first 4 bits of the first byte are padding bits and are preserved.
    #[inline]
    pub fn set_reserved(&mut self, reserved: u32) {
        // Convert to bytes
        let bytes = reserved.to_be_bytes();

        // Copy the last 3 bytes to reserved, preserving the padding bits
        self.pad_reserved[0] = (self.pad_reserved[0] & 0xF0) | (bytes[1] & 0x0F);
        self.pad_reserved[1] = bytes[2];
        self.pad_reserved[2] = bytes[3];
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RplSourceRouteHeader {
    pub generic_route: GenericRoute,
    pub fixed_hdr: RplSourceFixedHeader,
}

impl RplSourceRouteHeader {
    /// The total size in bytes of the RPL Source Route Header struct
    pub const LEN: usize = mem::size_of::<RplSourceRouteHeader>();

    /// Calculates the total length of the Segment Routing Header in bytes.
    /// The Hdr Ext Len is in 8-octet units, *excluding* the first 8 octets.
    /// So, total length = (hdr_ext_len + 1) * 8.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        self.generic_route.total_hdr_len()
    }

    /// Calculates the size of each address in the Addresses field based on CmprI.
    #[inline]
    pub fn address_size(&self) -> usize {
        16 - self.fixed_hdr.cmpr_i() as usize
    }

    /// Calculates the size of the last address in the Addresses field based on CmprE.
    #[inline]
    pub fn last_address_size(&self) -> usize {
        16 - self.fixed_hdr.cmpr_e() as usize
    }

    /// Calculates the number of addresses in the RPL Source Route Header.
    /// This function relies on the immutable header fields (Hdr Ext Len, Pad,
    /// CmprI, CmprE) to derive the address count.
    ///
    /// Compute n, the number of addresses in the Routing header:
    /// n = (((Hdr Ext Len * 8) - Pad - (16 - CmprE)) / (16 - CmprI)) + 1
    #[inline]
    pub fn num_addresses(&self) -> usize {
        // Get the total length of the variable part of the header.
        let variable_len = (self.generic_route.hdr_ext_len as usize) << 3;
        let pad = self.fixed_hdr.pad() as usize;

        if variable_len < pad {
            return 0;
        }

        let addresses_len = variable_len - pad;
        if addresses_len == 0 {
            return 0;
        }

        let size_inter = self.address_size();
        let size_final = self.last_address_size();

        if size_inter == 0 {
            // This case should be impossible if CmprI is a 4-bit value (0-15),
            // making address_size() always > 0.
            // If it were possible, we could only have one address.
            return if addresses_len == size_final { 1 } else { 0 };
        }

        if addresses_len < size_final {
            // Malformed header: not enough space for the final address.
            return 0;
        }

        if (addresses_len - size_final) % size_inter != 0 {
            // Malformed header: the total length of intermediate addresses
            // is not a multiple of the intermediate address size.
            return 0;
        }

        ((addresses_len - size_final) / size_inter) + 1
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SegmentFixedHeader {
    pub last_entry: u8,
    pub flags: u8,
    pub tag: [u8; 2],
}

impl SegmentFixedHeader {
    /// The total size in bytes of the fixed part of the Segment Routing Header
    pub const LEN: usize = mem::size_of::<SegmentFixedHeader>();

    /// Gets the Tag field as a 16-bit value.
    #[inline]
    pub fn tag(&self) -> u16 {
        u16::from_be_bytes(self.tag)
    }

    /// Sets the Tag field from a 16-bit value.
    #[inline]
    pub fn set_tag(&mut self, tag: u16) {
        self.tag = tag.to_be_bytes()
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SegmentRoutingHeader {
    pub generic_route: GenericRoute,
    pub fixed_hdr: SegmentFixedHeader,
}

impl SegmentRoutingHeader {
    /// The total size in bytes of the fixed part of the Segment Routing Header
    pub const LEN: usize = mem::size_of::<SegmentRoutingHeader>();

    /// Size of each segment (IPv6 address) in bytes
    pub const SEGMENT_SIZE: usize = 16;

    /// Maximum number of segments that can be included in the header
    pub const MAX_SEGMENTS: usize = MAX_SRH_SEGMENTS;

    /// Calculates the total length available for the Segment List and TLVs in bytes.
    /// Total Header Length - Fixed Header Length.
    #[inline]
    pub fn segments_and_tlvs_len(&self) -> usize {
        self.generic_route
            .total_hdr_len()
            .saturating_sub(SegmentRoutingHeader::LEN)
    }

    /// Calculates the number of segments in the Segment List.
    #[inline]
    pub fn num_segments(&self) -> usize {
        (self.fixed_hdr.last_entry as usize) + 1
    }

    /// Calculates the total length of the Segment List in bytes.
    #[inline]
    pub fn segment_list_len(&self) -> usize {
        self.num_segments() * Self::SEGMENT_SIZE
    } // Consider switching to bitshifting by 4

    /// Calculates the total length available for TLVs in bytes.
    #[inline]
    pub fn tlvs_len(&self) -> usize {
        self.segments_and_tlvs_len()
            .saturating_sub(self.segment_list_len())
    }
}


#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct CrhHeader {
    pub generic_route: GenericRoute,
}

impl CrhHeader {
    /// The total size in bytes of the fixed part of the CRH-16 Header
    pub const LEN: usize = mem::size_of::<CrhHeader>();

    /// Maximum number of SIDs that can be included in the header
    pub const MAX_SIDS: usize = MAX_CRH_SIDS;

    /// Calculates the total length available for the SID List in bytes.
    /// Total Header Length - Fixed Header Length.
    #[inline]
    pub fn sid_list_len(&self) -> usize {
        self.generic_route
            .total_hdr_len()
            .saturating_sub(CrhHeader::LEN)
    }

    /// Calculates the number of SIDs in the SID List.
    #[inline]
    pub fn num_sids(&self) -> usize {
        let sid_size = match self.generic_route.type_ {
            RoutingHeaderType::Crh16 => 2,
            RoutingHeaderType::Crh32 => 4,
            _ => return 0,
        };
        self.sid_list_len() / sid_size
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::ip::IpProto;

    #[test]
    fn test_generic_route_len_constant() {
        assert_eq!(GenericRoute::LEN, 4); // next_hdr (1) + hdr_ext_len (1) + type_ (1) + sgmt_left (1)
        assert_eq!(GenericRoute::LEN, mem::size_of::<GenericRoute>());
    }

    #[test]
    fn test_type2_fixed_header_len_constant() {
        assert_eq!(Type2FixedHeader::LEN, 20); // reserved (4) + home_address (16)
        assert_eq!(Type2FixedHeader::LEN, mem::size_of::<Type2FixedHeader>());
    }

    #[test]
    fn test_type2_routing_header_len_constant() {
        assert_eq!(Type2RoutingHeader::LEN, 24); // GenericRoute (4) + Type2FixedHeader (20)
        assert_eq!(
            Type2RoutingHeader::LEN,
            mem::size_of::<Type2RoutingHeader>()
        );
    }

    #[test]
    fn test_rpl_source_fixed_header_len_constant() {
        assert_eq!(RplSourceFixedHeader::LEN, 4); // cmpr (1) + pad_reserved (3)
        assert_eq!(
            RplSourceFixedHeader::LEN,
            mem::size_of::<RplSourceFixedHeader>()
        );
    }

    #[test]
    fn test_generic_route_getters_setters() {
        let header = GenericRoute {
            next_hdr: IpProto::Udp,
            hdr_ext_len: 2,
            type_: RoutingHeaderType::Type2,
            sgmt_left: 1,
        };

        // Test total_hdr_len calculation
        assert_eq!(header.total_hdr_len(), 24); // (2 + 1) * 8 = 24

        // Test total_type_data_len calculation
        assert_eq!(header.total_type_data_len(), 20); // 24 - 4 = 20
    }

    #[test]
    fn test_type2_fixed_header_getters_setters() {
        let mut header = Type2FixedHeader {
            reserved: [0; 4],
            home_address: [0; 16],
        };

        // Test reserved field
        header.set_reserved(0x12345678);
        assert_eq!(header.reserved(), 0x12345678);
        assert_eq!(header.reserved, [0x12, 0x34, 0x56, 0x78]);

        // Test home_address field
        let test_address = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        header.set_home_address(u128::from_be_bytes(test_address));
        assert_eq!(header.home_address(), u128::from_be_bytes(test_address));
        assert_eq!(header.home_address, test_address);
    }

    #[test]
    fn test_rpl_source_fixed_header_getters_setters() {
        let mut header = RplSourceFixedHeader {
            cmpr: 0,
            pad_reserved: [0; 3],
        };

        // Test cmpr_i and cmpr_e
        header.set_cmpr(0x5, 0x3); // CmprI = 5, CmprE = 3
        assert_eq!(header.cmpr_i(), 0x5);
        assert_eq!(header.cmpr_e(), 0x3);
        assert_eq!(header.cmpr, 0x53);

        // Test pad
        header.set_pad(0x7);
        assert_eq!(header.pad(), 0x7);

        // Test reserved field
        header.set_reserved(0x12345);
        assert_eq!(header.reserved(), 0x12345);
    }

    #[test]
    fn test_rpl_source_route_header_calculations() {
        let gen_route = GenericRoute {
            next_hdr: IpProto::Tcp,
            hdr_ext_len: 4, // 5 * 8 = 40 bytes total
            type_: RoutingHeaderType::RplSourceRoute,
            sgmt_left: 2,
        };

        let mut fixed_hdr = RplSourceFixedHeader {
            cmpr: 0,
            pad_reserved: [0; 3],
        };
        fixed_hdr.set_cmpr(0x2, 0x4); // CmprI = 2, CmprE = 4
        fixed_hdr.set_pad(0x6); //two addresses, 6 bytes of compression = 6 padding bytyes

        let header = RplSourceRouteHeader {
            generic_route: gen_route,
            fixed_hdr,
        };

        // Test address size calculations
        assert_eq!(header.address_size(), 14); // 16 - 2 = 14
        assert_eq!(header.last_address_size(), 12); // 16 - 4 = 12

        // Test total header length
        assert_eq!(header.generic_route.total_hdr_len(), 40); // (4 + 1) * 8 = 40

        // Test num_addresses calculation
        // n = (((Hdr Ext Len * 8) - Pad - (16 - CmprE)) / (16 - CmprI)) + 1
        // n = (((4 * 8) - 0 - (16 - 4)) / (16 - 2)) + 1
        // n = ((32 - 0 - 12) / 14) + 1 = (20 / 14) + 1 = 1 + 1 = 2
        assert_eq!(header.num_addresses(), 2);
    }

    #[test]
    fn test_segment_fixed_header_len_constant() {
        assert_eq!(SegmentFixedHeader::LEN, 4); // last_entry (1) + flags (1) + tag (2)
        assert_eq!(
            SegmentFixedHeader::LEN,
            mem::size_of::<SegmentFixedHeader>()
        );
    }

    #[test]
    fn test_segment_routing_header_len_constant() {
        assert_eq!(SegmentRoutingHeader::LEN, 8); // GenericRoute (4) + SegmentFixedHeader (4)
        assert_eq!(
            SegmentRoutingHeader::LEN,
            mem::size_of::<SegmentRoutingHeader>()
        );
    }

    #[test]
    fn test_segment_routing_header_constants() {
        assert_eq!(SegmentRoutingHeader::SEGMENT_SIZE, 16); // IPv6 address size
        assert_eq!(SegmentRoutingHeader::MAX_SEGMENTS, MAX_SRH_SEGMENTS);
        assert_eq!(MAX_SRH_SEGMENTS, 128);
    }

    #[test]
    fn test_segment_fixed_header_getters_setters() {
        let mut header = SegmentFixedHeader {
            last_entry: 0,
            flags: 0,
            tag: [0; 2],
        };

        // Test tag field
        header.set_tag(0x1234);
        assert_eq!(header.tag(), 0x1234);
        assert_eq!(header.tag, [0x12, 0x34]);
    }

    #[test]
    fn test_segment_routing_header_length_calculations() {
        let gen_route = GenericRoute {
            next_hdr: IpProto::Ipv6,
            hdr_ext_len: 6, // 7 * 8 = 56 bytes total
            type_: RoutingHeaderType::SegmentRoutingHeader,
            sgmt_left: 2,
        };

        let fixed_hdr = SegmentFixedHeader {
            last_entry: 2, // 3 segments (0, 1, 2)
            flags: 0,
            tag: [0; 2],
        };

        let header = SegmentRoutingHeader {
            generic_route: gen_route,
            fixed_hdr,
        };

        // Test total header length
        assert_eq!(header.generic_route.total_hdr_len(), 56); // (6 + 1) * 8 = 56

        // Test segments and TLVs length
        assert_eq!(header.segments_and_tlvs_len(), 48); // 56 - 8 = 48

        // Test number of segments
        assert_eq!(header.num_segments(), 3); // last_entry + 1 = 2 + 1 = 3

        // Test segment list length
        assert_eq!(header.segment_list_len(), 48); // 3 * 16 = 48

        // Test TLVs length
        assert_eq!(header.tlvs_len(), 0); // 48 - 48 = 0
    }

    #[test]
    fn test_segment_routing_header_with_tlvs() {
        let gen_route = GenericRoute {
            next_hdr: IpProto::Tcp,
            hdr_ext_len: 8, // 9 * 8 = 72 bytes total
            type_: RoutingHeaderType::SegmentRoutingHeader,
            sgmt_left: 1,
        };

        let fixed_hdr = SegmentFixedHeader {
            last_entry: 1, // 2 segments (0, 1)
            flags: 0,
            tag: [0; 2],
        };

        let header = SegmentRoutingHeader {
            generic_route: gen_route,
            fixed_hdr,
        };

        // Test total header length
        assert_eq!(header.generic_route.total_hdr_len(), 72); // (8 + 1) * 8 = 72

        // Test segments and TLVs length
        assert_eq!(header.segments_and_tlvs_len(), 64); // 72 - 8 = 64

        // Test number of segments
        assert_eq!(header.num_segments(), 2); // last_entry + 1 = 1 + 1 = 2

        // Test segment list length
        assert_eq!(header.segment_list_len(), 32); // 2 * 16 = 32

        // Test TLVs length
        assert_eq!(header.tlvs_len(), 32); // 64 - 32 = 32
    }

    #[test]
    fn test_segment_routing_header_edge_cases() {
        // Test with zero segments (should not happen in practice but test edge case)
        let gen_route = GenericRoute {
            next_hdr: IpProto::Tcp,
            hdr_ext_len: 0,
            type_: RoutingHeaderType::SegmentRoutingHeader,
            sgmt_left: 0,
        };

        // last_entry of 255 would mean 256 segments (edge case)
        let fixed_hdr = SegmentFixedHeader {
            last_entry: 255,
            flags: 0xFF,
            tag: [0xFF, 0xFF],
        };

        let header = SegmentRoutingHeader {
            generic_route: gen_route,
            fixed_hdr,
        };

        // Test number of segments with maximum last_entry
        assert_eq!(header.num_segments(), 256); // 255 + 1 = 256

        // Test segment list length
        assert_eq!(header.segment_list_len(), 4096); // 256 * 16 = 4096

        // Test with zero hdr_ext_len
        assert_eq!(header.generic_route.total_hdr_len(), 8); // (0 + 1) * 8 = 8
        assert_eq!(header.segments_and_tlvs_len(), 0); // 8 - 8 = 0 (saturating_sub)
        assert_eq!(header.tlvs_len(), 0); // 0 - 4096 = 0 (saturating_sub)
    }

    #[test]
    fn test_segment_routing_header_minimum_valid_header() {
        // Test minimum valid header with 1 segment
        let gen_route = GenericRoute {
            next_hdr: IpProto::Tcp,
            hdr_ext_len: 2, // Minimum for 1 segment: (8 + 16 - 8) / 8 = 2
            type_: RoutingHeaderType::SegmentRoutingHeader,
            sgmt_left: 0,
        };

        let fixed_hdr = SegmentFixedHeader {
            last_entry: 0, // 1 segment
            flags: 0,
            tag: [0; 2],
        };

        let header = SegmentRoutingHeader {
            generic_route: gen_route,
            fixed_hdr,
        };

        assert_eq!(header.generic_route.total_hdr_len(), 24); // (2 + 1) * 8 = 24
        assert_eq!(header.segments_and_tlvs_len(), 16); // 24 - 8 = 16
        assert_eq!(header.num_segments(), 1); // 0 + 1 = 1
        assert_eq!(header.segment_list_len(), 16); // 1 * 16 = 16
        assert_eq!(header.tlvs_len(), 0); // 16 - 16 = 0
    }

    #[test]
    fn test_crh_header_len_constant() {
        assert_eq!(CrhHeader::LEN, 4); // GenericRoute (4)
        assert_eq!(CrhHeader::LEN, mem::size_of::<CrhHeader>());
    }

    #[test]
    fn test_crh_header_constants() {
        assert_eq!(CrhHeader::MAX_SIDS, MAX_CRH_SIDS);
        assert_eq!(MAX_CRH_SIDS, 128);
    }

    #[test]
    fn test_crh16_header_calculations() {
        // Test CRH-16 with 4 SIDs
        let generic_route = GenericRoute {
            next_hdr: IpProto::Ipv6,
            hdr_ext_len: 1, // 2 * 8 = 16 bytes total, 16 - 4 = 12 bytes for SIDs
            type_: RoutingHeaderType::Crh16, // CRH-16
            sgmt_left: 2,
        };

        let header = CrhHeader { generic_route };

        // Test total header length
        assert_eq!(header.generic_route.total_hdr_len(), 16); // (1 + 1) * 8 = 16

        // Test SID list length
        assert_eq!(header.sid_list_len(), 12); // 16 - 4 = 12

        // Test number of SIDs for CRH-16 (2 bytes per SID)
        assert_eq!(header.num_sids(), 6); // 12 / 2 = 6
    }

    #[test]
    fn test_crh32_header_calculations() {
        // Test CRH-32 with 2 SIDs
        let generic_route = GenericRoute {
            next_hdr: IpProto::Tcp,
            hdr_ext_len: 1, // 2 * 8 = 16 bytes total, 16 - 4 = 12 bytes for SIDs
            type_: RoutingHeaderType::Crh32, // CRH-32
            sgmt_left: 1,
        };

        let header = CrhHeader { generic_route };

        // Test total header length
        assert_eq!(header.generic_route.total_hdr_len(), 16); // (1 + 1) * 8 = 16

        // Test SID list length
        assert_eq!(header.sid_list_len(), 12); // 16 - 4 = 12

        // Test number of SIDs for CRH-32 (4 bytes per SID)
        assert_eq!(header.num_sids(), 3); // 12 / 4 = 3
    }

    #[test]
    fn test_crh16_header_with_multiple_sids() {
        // Test CRH-16 with more SIDs
        let generic_route = GenericRoute {
            next_hdr: IpProto::Udp,
            hdr_ext_len: 4, // 5 * 8 = 40 bytes total, 40 - 4 = 36 bytes for SIDs
            type_: RoutingHeaderType::Crh16, // CRH-16
            sgmt_left: 15,
        };

        let header = CrhHeader { generic_route };

        // Test total header length
        assert_eq!(header.generic_route.total_hdr_len(), 40); // (4 + 1) * 8 = 40

        // Test SID list length
        assert_eq!(header.sid_list_len(), 36); // 40 - 4 = 36

        // Test number of SIDs for CRH-16 (2 bytes per SID)
        assert_eq!(header.num_sids(), 18); // 36 / 2 = 18
    }

    #[test]
    fn test_crh32_header_with_multiple_sids() {
        // Test CRH-32 with more SIDs
        let generic_route = GenericRoute {
            next_hdr: IpProto::Icmp,
            hdr_ext_len: 7, // 8 * 8 = 64 bytes total, 64 - 4 = 60 bytes for SIDs
            type_: RoutingHeaderType::Crh32, // CRH-32
            sgmt_left: 10,
        };

        let header = CrhHeader { generic_route };

        // Test total header length
        assert_eq!(header.generic_route.total_hdr_len(), 64); // (7 + 1) * 8 = 64

        // Test SID list length
        assert_eq!(header.sid_list_len(), 60); // 64 - 4 = 60

        // Test number of SIDs for CRH-32 (4 bytes per SID)
        assert_eq!(header.num_sids(), 15); // 60 / 4 = 15
    }

    #[test]
    fn test_crh_header_edge_cases() {
        // Test with zero hdr_ext_len
        let generic_route = GenericRoute {
            next_hdr: IpProto::Tcp,
            hdr_ext_len: 0,
            type_: RoutingHeaderType::Crh16, // CRH-16
            sgmt_left: 0,
        };

        let header = CrhHeader { generic_route };

        // Test with zero hdr_ext_len
        assert_eq!(header.generic_route.total_hdr_len(), 8); // (0 + 1) * 8 = 8
        assert_eq!(header.sid_list_len(), 4); // 8 - 4 = 4
        assert_eq!(header.num_sids(), 2); // 4 / 2 = 2 for CRH-16
    }

    #[test]
    fn test_crh_header_maximum_sids() {
        // Test maximum possible SIDs for CRH-16
        let generic_route = GenericRoute {
            next_hdr: IpProto::Tcp,
            hdr_ext_len: 31, // 32 * 8 = 256 bytes total, 256 - 4 = 252 bytes for SIDs
            type_: RoutingHeaderType::Crh16, // CRH-16
            sgmt_left: 0,
        };

        let header = CrhHeader { generic_route };

        assert_eq!(header.generic_route.total_hdr_len(), 256); // (31 + 1) * 8 = 256
        assert_eq!(header.sid_list_len(), 252); // 256 - 4 = 252
        assert_eq!(header.num_sids(), 126); // 252 / 2 = 126 for CRH-16

        // Test maximum possible SIDs for CRH-32
        let generic_route_32 = GenericRoute {
            next_hdr: IpProto::Tcp,
            hdr_ext_len: 31, // 32 * 8 = 256 bytes total, 256 - 4 = 252 bytes for SIDs
            type_: RoutingHeaderType::Crh32, // CRH-32
            sgmt_left: 0,
        };

        let header_32 = CrhHeader {
            generic_route: generic_route_32,
        };

        assert_eq!(header_32.generic_route.total_hdr_len(), 256); // (31 + 1) * 8 = 256
        assert_eq!(header_32.sid_list_len(), 252); // 256 - 4 = 252
        assert_eq!(header_32.num_sids(), 63); // 252 / 4 = 63 for CRH-32
    }
}
