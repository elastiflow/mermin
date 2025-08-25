use core::mem;

use crate::ip::IpProto;

/// Maximum number of addresses we can read at a time from a RPL Source Route Header
pub const MAX_RPL_ADDRESSES: usize = 32;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RoutingHeaderType {
    /// Type 2 Routing Header - [RFC6275]
    Type2,
    /// RPL Source Route Header - [RFC6554]
    RplSourceRoute,
    // /// Segment Routing Header (SRH) - [RFC8754]
    // SegmentRoutingHeader,
    // /// CRH-16 - [RFC9631]
    // Crh16,
    // /// CRH-32 - [RFC9631]
    // Crh32,
    // /// RFC3692-style Experiment 1 [2] - [RFC4727]
    // Experiment1,
    // /// RFC3692-style Experiment 2 [2] - [RFC4727]
    // Experiment2,
    // /// Reserved
    // Reserved,
    /// Represents an unknown or unassigned routing header type
    #[doc(hidden)]
    Unknown(u8),
}

impl RoutingHeaderType {
    /// Converts a `u8` value into a `RoutingHeaderType`.
    #[inline]
    pub fn from_u8(value: u8) -> Self {
        match value {
            2 => RoutingHeaderType::Type2,
            3 => RoutingHeaderType::RplSourceRoute,
            // 4 => RoutingHeaderType::SegmentRoutingHeader,
            // 5 => RoutingHeaderType::Crh16,
            // 6 => RoutingHeaderType::Crh32,
            // 253 => RoutingHeaderType::Experiment1,
            // 254 => RoutingHeaderType::Experiment2,
            // 255 => RoutingHeaderType::Reserved,
            v => RoutingHeaderType::Unknown(v),
        }
    }

    /// Returns the `u8` representation of the `RoutingHeaderType`.
    #[inline]
    pub fn as_u8(&self) -> u8 {
        match self {
            RoutingHeaderType::Type2 => 2,
            RoutingHeaderType::RplSourceRoute => 3,
            // RoutingHeaderType::SegmentRoutingHeader => 4,
            // RoutingHeaderType::Crh16 => 5,
            // RoutingHeaderType::Crh32 => 6,
            // RoutingHeaderType::Experiment1 => 253,
            // RoutingHeaderType::Experiment2 => 254,
            // RoutingHeaderType::Reserved => 255,
            RoutingHeaderType::Unknown(val) => *val,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Ipv6RoutingHeader {
    /// Type 2 Routing Header - [RFC6275]
    Type2(Type2RoutingHeader),
    /// RPL Source Route Header - [RFC6554]
    RplSourceRoute(RplSourceRouteHeader),
    // /// Segment Routing Header (SRH) - [RFC8754]
    // SegmentRouting(SegmentRoutingHeader),
    // /// CRH-16 - [RFC9631]
    // Crh16(Crh16Header),
    // /// CRH-32 - [RFC9631]
    // Crh32(Crh32Header),
    // /// RFC3692-style Experiment 1 [2] - [RFC4727]
    // Experiment1(GenericRoute),
    // /// RFC3692-style Experiment 2 [2] - [RFC4727]
    // Experiment2(GenericRoute),
    // /// A reserved routing type was encountered.
    // Reserved,
    /// An unknown or unassigned routing type was encountered.
    Unknown(GenericRoute),
}

/// # IPv6 Routing Extension Header Format
///
///  0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left | <- Generic Header
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                                                               .
/// .                       type-specific data                      .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Fields
///
/// * **Next Header (8 bits)**: Identifies the type of the next header.
/// * **Hdr Ext Len (8 bits)**: The length of the Routing header in 8-octet units, not including the first 8 octets.
/// * **Routing Type (8 bits)**: Identifies the variant of the Routing header.
/// * **Segments Left (8 bits)**: Number of route segments remaining.
/// * **Type-specific data (variable)**: Format depends on the Routing Type value.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct GenericRoute {
    pub next_hdr: IpProto,
    pub hdr_ext_len: u8,
    pub type_: u8,
    pub sgmt_left: u8,
}

impl GenericRoute {
    /// The total size in bytes of default length Routing header
    pub const LEN: usize = mem::size_of::<GenericRoute>();

    /// Gets the Next Header value.
    #[inline]
    pub fn next_hdr(&self) -> IpProto {
        self.next_hdr
    }

    /// Sets the Next Header value.
    #[inline]
    pub fn set_next_hdr(&mut self, next_hdr: IpProto) {
        self.next_hdr = next_hdr
    }

    /// Gets the Header Extension Length value.
    /// This value is the length of the Routing header
    /// in 8-octet units, not including the first 8 octets.
    #[inline]
    pub fn hdr_ext_len(&self) -> u8 {
        self.hdr_ext_len
    }

    /// Sets the Header Extension Length value.
    #[inline]
    pub fn set_hdr_ext_len(&mut self, hdr_ext_len: u8) {
        self.hdr_ext_len = hdr_ext_len
    }

    /// Gets Rounting Header type casting value to RoutingHeaderType enum
    #[inline]
    pub fn type_(&self) -> RoutingHeaderType {
        RoutingHeaderType::from_u8(self.type_)
    }

    /// Sets the Routing Header type converting value from RoutingHeaderType enum
    #[inline]
    pub fn set_type(&mut self, type_: RoutingHeaderType) {
        self.type_ = type_.as_u8()
    }

    /// Gets the Segments Left value
    #[inline]
    pub fn sgmt_left(&self) -> u8 {
        self.sgmt_left
    }

    /// Sets the Segments Left value
    #[inline]
    pub fn set_sgmt_left(&mut self, sgmt_left: u8) {
        self.sgmt_left = sgmt_left
    }

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

/// # Type 2 Routing Header (Mobile IPv6) - RFC 6275
///
/// This routing header is used in Mobile IPv6 to allow a packet to be routed from a
/// mobile node's home address to its current location (care-of address).
///
///  0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left | <- Generic Header
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                                                               |
/// |                                                               |
/// |                         Home Address                          |
/// |                                                               |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Fields
///
/// * **Next Header (8 bits)**: Identifies the type of the next header.
/// * **Hdr Ext Len (8 bits)**: The length of the Routing header in 8-octet units, not including the first 8 octets. For Type 2, this is always 2.
/// * **Routing Type (8 bits)**: Identifies the variant of the Routing header. For Type 2, this is 2.
/// * **Segments Left (8 bits)**: Number of route segments remaining. For Type 2, this is always 1.
/// * **Reserved (32 bits)**: Reserved for future use and initialized to all zeroes.
/// * **Home Address (128 bits)**: The home address of the mobile node.
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
    pub fn reserved(&self) -> u32 {
        u32::from_be_bytes(self.reserved)
    }

    /// Sets the Reserved field from a 32-bit value.
    pub fn set_reserved(&mut self, reserved: u32) {
        self.reserved = reserved.to_be_bytes()
    }

    /// Gets the Home Address as a 16-byte array.
    pub fn home_address(&self) -> [u8; 16] {
        self.home_address
    }

    /// Sets the Home Address from a 16-byte array.
    pub fn set_home_address(&mut self, home_address: [u8; 16]) {
        self.home_address = home_address
    }
}
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Type2RoutingHeader {
    pub gen_route: GenericRoute,
    pub fixed_hdr: Type2FixedHeader,
}

impl Type2RoutingHeader {
    /// Creates a new `Type2RoutingHeader` instance.
    ///
    /// # Parameters
    /// * `gen_route`: The pre-constructed generic routing header.
    ///
    /// # Returns
    /// A new `Type2RoutingHeader` instance with reserved field set to 0 and home_address set to all zeros.
    #[inline]
    pub fn new(gen_route: GenericRoute, fixed_hdr: Type2FixedHeader) -> Self {
        Self {
            gen_route,
            fixed_hdr,
        }
    }

    /// The total size in bytes of the Type 2 Routing Header
    pub const LEN: usize = mem::size_of::<Type2RoutingHeader>();
}

/// # Type 3 RPL Source Route Header - RFC 6554
///
/// This routing header is used in the Routing Protocol for Low-Power and Lossy Networks (RPL)
/// for source routing in constrained environments like sensor networks.
///
///  0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left | <- Generic Header
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | CmprI | CmprE |  Pad  |               Reserved                | <- RPL Fixed Header
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                                                               .
/// .                        Addresses[1..n]                        . <-
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// ## Fields
///
/// * **Next Header (8 bits)**: Identifies the type of the next header.
/// * **Hdr Ext Len (8 bits)**: The length of the Routing header in 8-octet units, not including the first 8 octets.
/// * **Routing Type (8 bits)**: Identifies the variant of the Routing header. For Type 3, this is 3.
/// * **Segments Left (8 bits)**: Number of route segments remaining.
/// * **CmprI (4 bits)**: Number of prefix octets elided from addresses in the Addresses field.
/// * **CmprE (4 bits)**: Number of prefix octets elided from the last address in the Addresses field.
/// * **Pad (4 bits)**: Number of octets that are used for padding after Address
/// * **Reserved (20 bits)**: Set to 0 by the sender and ignored by the receiver.
/// * **Addresses[1..n] (variable)**: Vector of addresses, each of variable size depending on CmprI and CmprE.
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
    pub gen_route: GenericRoute,
    pub fixed_hdr: RplSourceFixedHeader,
    pub addresses: [u8; MAX_RPL_ADDRESSES],
}

impl RplSourceRouteHeader {
    /// Creates a new `RplSourceRouteHeader` instance from a `GenericRoute` and `RplSourceFixedHeader`.
    ///
    /// # Parameters
    /// * `gen_route`: The generic routing header containing basic fields like next header and routing type.
    /// * `fixed_hdr`: The RPL specific fixed header containing the cmpr, pad, and reserved fields.
    ///
    /// # Returns
    /// A new `RplSourceRouteHeader` instance with the provided headers.
    #[inline]
    pub fn new(gen_route: GenericRoute, fixed_hdr: RplSourceFixedHeader) -> Self {
        Self {
            gen_route,
            fixed_hdr,
            addresses: [0; MAX_RPL_ADDRESSES],
        }
    }

    /// The total size in bytes of the RPL Source Route Header struct
    pub const LEN: usize = mem::size_of::<RplSourceRouteHeader>();

    /// Calculates the total length of the RPL Source Route Header in bytes.
    /// The Hdr Ext Len is in 8-octet units, *excluding* the first 8 octets.
    /// So, total length = (hdr_ext_len + 1) * 8.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        (self.gen_route.hdr_ext_len() as usize + 1) << 3
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
    /// Taken from RFC 6554, please validate :)
    /// compute n, the number of addresses in the Routing header:
    /// n = (((Hdr Ext Len * 8) - Pad - (16 - CmprE)) / (16 - CmprI)) + 1
    #[inline]
    pub fn num_addresses(&self) -> usize {
        // Get the total length of the variable part of the header.
        let variable_len = (self.gen_route.hdr_ext_len() as usize) << 3;
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

/// Parses an IPv6 routing header from a buffer context using the provided offset.
///
/// On success, it returns `Ok(Ipv6RoutingHeader)` and advances the offset `$off`
/// past the parsed header. On failure, it returns `Err(())`.
#[macro_export]
macro_rules! parse_ipv6_routing_hdr {
    ($ctx:expr, $off:ident) => {
        (|| -> Result<$crate::route::Ipv6RoutingHeader, ()> {
            use $crate::route::{
                Ipv6RoutingHeader, GenericRoute, RoutingHeaderType,
                // Import the specific header data structs
                Type2RoutingHeader, RplSourceRouteHeader,
            };
            use $crate::read_var_buf;

            // Load the common part of the header to get the routing type.
            let gen_hdr: GenericRoute = $ctx.load($off).map_err(|_| ())?;
            $off += GenericRoute::LEN;
            let total_header_len = gen_hdr.total_hdr_len();

            // Convert the type and match to parse the rest of the header.
            let routing_type: RoutingHeaderType = RoutingHeaderType::from_u8(gen_hdr.type_);
            match routing_type {
                RoutingHeaderType::Type2 => {
                    //Type2 is static so parse remaining fixed portion and pass back
                    let fixed_data: Type2FixedHeader = $ctx.load($off).map_err(|_| ())?;
                    $off += Type2FixedHeader::LEN;
                    let result = Type2RoutingHeader::new(gen_hdr,fixed_data);
                    Ok(Ipv6RoutingHeader::Type2(result))
                }
                RoutingHeaderType::RplSourceRoute => {
                    let fixed_data: RplSourceFixedHeader = $ctx.load($off).map_err(|_| ())?;
                    $off += RplSourceFixedHeader::LEN;
                    let mut result = RplSourceRouteHeader::new(gen_hdr,fixed_data);
                    let num_int = result.num_addresses().saturating_sub(1);
                    let mut len = result.address_size()*num_int;
                    for _ in 0..16{
                        if len == 0 {
                            break;
                        }
                        let bytes_read = read_var_buf!($ctx, $off, result.addresses, result.last_address_size(), result.last_address_size())
                        .map_err(|_| ())?;
                        _ = len.saturating_sub(bytes_read);
                    } // I'd say its pretty unlikely we receive a RPL header with more than 512 addresses,
                    // But if we do we need to add some logic here, or just another loop to support up to 1024
                    let bytes_read = read_var_buf!($ctx, $off,
                    result.addresses, result.last_address_size(), result.last_address_size())
                    .map_err(|_| ())?;
                    Ok(Ipv6RoutingHeader::RplSourceRoute(result))
                }
                RoutingHeaderType::Unknown(type_val) => {
                    // TODO: Handle the unknown header, e.g., by loading its payload
                     Err(())
                }
            }

        })()
    };
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
        let mut header = GenericRoute {
            next_hdr: IpProto::Tcp,
            hdr_ext_len: 0,
            type_: 0,
            sgmt_left: 0,
        };

        // Test next_hdr
        header.set_next_hdr(IpProto::Udp);
        assert_eq!(header.next_hdr(), IpProto::Udp);

        // Test hdr_ext_len
        header.set_hdr_ext_len(2);
        assert_eq!(header.hdr_ext_len(), 2);

        // Test type_
        header.set_type(RoutingHeaderType::Type2);
        assert_eq!(header.type_(), RoutingHeaderType::Type2);

        // Test sgmt_left
        header.set_sgmt_left(1);
        assert_eq!(header.sgmt_left(), 1);

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
        header.set_home_address(test_address);
        assert_eq!(header.home_address(), test_address);
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
            type_: 3,
            sgmt_left: 2,
        };

        let mut fixed_hdr = RplSourceFixedHeader {
            cmpr: 0,
            pad_reserved: [0; 3],
        };
        fixed_hdr.set_cmpr(0x2, 0x4); // CmprI = 2, CmprE = 4
        fixed_hdr.set_pad(0x6); //two addresses, 6 bytes of compression = 6 padding bytyes

        let header = RplSourceRouteHeader::new(gen_route, fixed_hdr);

        // Test address size calculations
        assert_eq!(header.address_size(), 14); // 16 - 2 = 14
        assert_eq!(header.last_address_size(), 12); // 16 - 4 = 12

        // Test total header length
        assert_eq!(header.total_hdr_len(), 40); // (4 + 1) * 8 = 40

        // Test num_addresses calculation
        // n = (((Hdr Ext Len * 8) - Pad - (16 - CmprE)) / (16 - CmprI)) + 1
        // n = (((4 * 8) - 0 - (16 - 4)) / (16 - 2)) + 1
        // n = ((32 - 0 - 12) / 14) + 1 = (20 / 14) + 1 = 1 + 1 = 2
        assert_eq!(header.num_addresses(), 2);
    }

    #[test]
    fn test_routing_header_type_conversion() {
        // Test from_u8
        assert_eq!(RoutingHeaderType::from_u8(2), RoutingHeaderType::Type2);
        assert_eq!(
            RoutingHeaderType::from_u8(3),
            RoutingHeaderType::RplSourceRoute
        );

        // Test unknown type
        if let RoutingHeaderType::Unknown(val) = RoutingHeaderType::from_u8(99) {
            assert_eq!(val, 99);
        } else {
            panic!("Expected Unknown variant");
        }

        // Test as_u8
        assert_eq!(RoutingHeaderType::Type2.as_u8(), 2);
        assert_eq!(RoutingHeaderType::RplSourceRoute.as_u8(), 3);
        assert_eq!(RoutingHeaderType::Unknown(99).as_u8(), 99);
    }
}
