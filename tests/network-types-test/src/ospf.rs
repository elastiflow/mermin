use core::mem;

/// Represents the OSPF Version 2 (OSPFv2) packet header, according to RFC 2328.
/// This struct is designed to match the on-wire format of an OSPFv2 header.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]

pub struct OspfV2Hdr {
    /// OSPF protocol version (e.g., 2 for OSPFv2).
    pub version: u8,
    /// Type of the OSPF packet (e.g., Hello, DB Description, LS Request).
    pub type_: u8,
    /// Total length of the OSPF packet, including the header, in bytes.
    pub len: [u8; 2],
    /// The Router ID of the packet's sender.
    pub router_id: [u8; 4],
    /// The Area ID of the packet's origin.
    pub area_id: [u8; 4],
    /// Standard IP checksum of the entire OSPF packet.
    pub checksum: [u8; 2],
    /// Authentication type (e.g., 0 for Null, 1 for Simple Password, 2 for MD5).
    pub au_type: [u8; 2],
    /// Authentication data. The content varies based on `au_type`.
    /// For Null authentication, this field is zeroed.
    pub authentication: [u8; 8]
}


impl OspfV2Hdr {
    /// The fixed length of the OSPFv2 header in bytes.
    pub const LEN: usize = mem::size_of::<OspfV2Hdr>();

    /// Returns the OSPF version field.
    #[inline]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Sets the OSPF version field.
    ///
    /// # Arguments
    ///
    /// * `version_value` - The value to set for the version field.
    #[inline]
    pub fn set_version(&mut self, version_value: u8) {
        self.version = version_value;
    }

    /// Returns the OSPF packet type field.
    #[inline]
    pub fn type_(&self) -> u8 {
        self.type_
    }

    /// Sets the OSPF packet type field.
    ///
    /// # Arguments
    ///
    /// * `type_value` - The value to set for the type field.
    #[inline]
    pub fn set_type_(&mut self, type_value: u8) {
        self.type_ = type_value
    }

    /// Returns the total length of the OSPF packet in host byte order.
    #[inline]
    pub fn len(&self) -> u16 {
        u16::from_be_bytes(self.len)
    }

    /// Sets the total length of the OSPF packet, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `len_value` - The length value to set.
    #[inline]
    pub fn set_len(&mut self, len_value: u16) {
        self.len = len_value.to_be_bytes();
    }

    /// Returns the Router ID in host byte order.
    #[inline]
    pub fn router_id(&self) -> u32 {
        u32::from_be_bytes(self.router_id)
    }

    /// Sets the Router ID, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `router_id_value` - The Router ID value to set.
    #[inline]
    pub fn set_router_id(&mut self, router_id_value: u32) {
        self.router_id = router_id_value.to_be_bytes()
    }

    /// Returns the Area ID in host byte order.
    #[inline]
    pub fn area_id(&self) -> u32 {
        u32::from_be_bytes(self.area_id)
    }

    /// Sets the Area ID, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `area_id_value` - The Area ID value to set.
    #[inline]
    pub fn set_area_id(&mut self, area_id_value: u32) {
        self.area_id = area_id_value.to_be_bytes()
    }

    /// Returns the checksum in host byte order.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the checksum, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `checksum_value` - The checksum value to set.
    #[inline]
    pub fn set_checksum(&mut self, checksum_value: u16) {
        self.checksum = checksum_value.to_be_bytes();
    }

    /// Returns the authentication type in host byte order.
    #[inline]
    pub fn au_type(&self) -> u16 {
        u16::from_be_bytes(self.au_type)
    }

    /// Sets the authentication type, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `au_type_value` - The authentication type value to set.
    #[inline]
    pub fn set_au_type(&mut self, au_type_value: u16) {
        self.au_type = au_type_value.to_be_bytes();
    }

    /// Returns the authentication data.
    #[inline]
    pub fn authentication(&self) -> [u8; 8] {
        self.authentication
    }

    /// Sets the authentication data.
    ///
    /// # Arguments
    ///
    /// * `value` - The 8-byte array of authentication data.
    #[inline]
    pub fn set_authentication(&mut self, value: [u8; 8]) {
        self.authentication = value;
    }
}

/// Represents the OSPF Version 3 (OSPFv3) packet header, according to RFC 5340.
/// This struct is designed to match the on-wire format of an OSPFv3 header.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]

pub struct OspfV3Hdr {
    /// OSPF protocol version (e.g., 3 for OSPFv3).
    pub version: u8,
    /// Type of the OSPF packet (e.g., Hello, DB Description, LS Request).
    pub type_: u8,
    /// Total length of the OSPF packet, including the header, in bytes.
    pub len: [u8; 2],
    /// The Router ID of the packet's sender.
    pub router_id: [u8; 4],
    /// The Area ID of the packet's origin.
    pub area_id: [u8; 4],
    /// Standard IP checksum of the entire OSPF packet.
    pub checksum: [u8; 2],
    /// Instance ID for OSPFv3, allowing multiple OSPF processes on the same link.
    pub instance_id: u8,
    /// Reserved field. As per RFC 5340, Section A.3.1, this field MUST be set to 0.
    pub reserved: u8,
}


impl OspfV3Hdr {
    /// The fixed length of the OSPFv3 header in bytes.
    pub const LEN: usize = mem::size_of::<OspfV3Hdr>();

    /// Returns the OSPF version field.
    #[inline]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Sets the OSPF version field.
    ///
    /// # Arguments
    ///
    /// * `version_value` - The value to set for the version field.
    #[inline]
    pub fn set_version(&mut self, version_value: u8) {
        self.version = version_value;
    }

    /// Returns the OSPF packet type field.
    #[inline]
    pub fn type_(&self) -> u8 {
        self.type_
    }

    /// Sets the OSPF packet type field.
    ///
    /// # Arguments
    ///
    /// * `type_value` - The value to set for the type field.
    #[inline]
    pub fn set_type_(&mut self, type_value: u8) {
        self.type_ = type_value
    }

    /// Returns the total length of the OSPF packet in host byte order.
    #[inline]
    pub fn len(&self) -> u16 {
        u16::from_be_bytes(self.len)
    }

    /// Sets the total length of the OSPF packet, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `len_value` - The length value to set.
    #[inline]
    pub fn set_len(&mut self, len_value: u16) {
        self.len = len_value.to_be_bytes();
    }

    /// Returns the Router ID in host byte order.
    #[inline]
    pub fn router_id(&self) -> u32 {
        u32::from_be_bytes(self.router_id)
    }

    /// Sets the Router ID, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `router_id_value` - The Router ID value to set.
    #[inline]
    pub fn set_router_id(&mut self, router_id_value: u32) {
        self.router_id = router_id_value.to_be_bytes()
    }

    /// Returns the Area ID in host byte order.
    #[inline]
    pub fn area_id(&self) -> u32 {
        u32::from_be_bytes(self.area_id)
    }

    /// Sets the Area ID, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `area_id_value` - The Area ID value to set.
    #[inline]
    pub fn set_area_id(&mut self, area_id_value: u32) {
        self.area_id = area_id_value.to_be_bytes()
    }

    /// Returns the checksum in host byte order.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the checksum, converting it to network byte order (big-endian).
    ///
    /// # Arguments
    ///
    /// * `checksum_value` - The checksum value to set.
    #[inline]
    pub fn set_checksum(&mut self, checksum_value: u16) {
        self.checksum = checksum_value.to_be_bytes();
    }

    /// Returns the Instance ID field.
    #[inline]
    pub fn instance_id(&self) -> u8 {
        self.instance_id
    }

    /// Sets the Instance ID field.
    ///
    /// # Arguments
    ///
    /// * `instance_id_value` - The value to set for the Instance ID field.
    #[inline]
    pub fn set_instance_id(&mut self, instance_id_value: u8) {
        self.instance_id = instance_id_value;
    }

    /// Returns the reserved field.
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.reserved
    }

    /// Sets the reserved field.
    /// As per RFC 5340, Section A.3.1, this field MUST be set to 0.
    ///
    /// # Arguments
    ///
    /// * `reserved_value` - The value to set for the reserved field.
    #[inline]
    pub fn set_reserved(&mut self, reserved_value: u8) {
        self.reserved = reserved_value;
    }
}