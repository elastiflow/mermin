use crate::eth::EtherType;

pub const C_FLAG_MASK: u8 = 0x80;
pub const R_FLAG_MASK: u8 = 0x40;
pub const K_FLAG_MASK: u8 = 0x20;
pub const S_FLAG_MASK: u8 = 0x10;
pub const VER_MASK: u8 = 0x07;

/// Represents a GRE (Generic Routing Encapsulation) header.
///
/// This struct contains the fixed part of the GRE header, which includes
/// flags, reserved bits, version, and protocol type.
///
/// # Fields
/// * `flgs_res0_ver`: A 2-byte array containing flags, reserved bits, and version.
/// * `proto`: A 2-byte array containing the protocol type.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct GreHdr {
    pub flgs_res0_ver: [u8; 2],
    pub proto: u16,
}

impl GreHdr {
    /// The size of the fixed GRE header in bytes.
    pub const LEN: usize = core::mem::size_of::<GreHdr>();

    /// Calculates the total header length based on the flags set in the header.
    ///
    /// The GRE header has a fixed 4-byte part, plus optional fields:
    /// - Checksum/Offset: 4 bytes (if C or R flag is set)
    /// - Key: 4 bytes (if K flag is set)
    /// - Sequence Number: 4 bytes (if S flag is set)
    ///
    /// Note: This method only calculates the length of the fixed optional fields.
    /// When the Routing Present flag (R) is set, there is also a variable-length
    /// routing field that must be parsed separately using packet data.
    /// Use the parse_gre_header function for complete header parsing including routing.
    ///
    /// # Returns
    /// The length of the fixed GRE header fields in bytes (excluding variable-length routing data).
    pub fn total_hdr_len(&self) -> usize {
        let mut len = Self::LEN; // Fixed 4 bytes

        // If either C or R flag is set, both Checksum and Offset fields are present
        if self.ck_flg() || self.r_flg() {
            len += 4; // Checksum/Offset field
        }
        if self.key_flg() {
            len += 4; // Key field
        }
        if self.seq_flg() {
            len += 4; // Sequence Number field
        }

        len
    }

    /// Checks if the Checksum Present flag (C) is set.
    ///
    /// # Returns
    /// `true` if the Checksum Present flag is set, `false` otherwise.
    #[inline]
    pub fn ck_flg(&self) -> bool {
        self.flgs_res0_ver[0] & C_FLAG_MASK != 0
    }

    /// Sets or clears the Checksum Present flag (C).
    ///
    /// # Parameters
    /// * `ck_flg`: `true` to set the flag, `false` to clear it.
    #[inline]
    pub fn set_ck_flg(&mut self, ck_flg: bool) {
        if ck_flg {
            self.flgs_res0_ver[0] |= C_FLAG_MASK;
        } else {
            self.flgs_res0_ver[0] &= !C_FLAG_MASK;
        }
    }

    /// Checks if the Routing Present flag (R) is set.
    ///
    /// # Returns
    /// `true` if the Routing Present flag is set, `false` otherwise.
    #[inline]
    pub fn r_flg(&self) -> bool {
        self.flgs_res0_ver[0] & R_FLAG_MASK != 0
    }

    /// Sets or clears the Routing Present flag (R).
    ///
    /// # Parameters
    /// * `r_flg`: `true` to set the flag, `false` to clear it.
    #[inline]
    pub fn set_r_flg(&mut self, r_flg: bool) {
        if r_flg {
            self.flgs_res0_ver[0] |= R_FLAG_MASK;
        } else {
            self.flgs_res0_ver[0] &= !R_FLAG_MASK;
        }
    }

    /// Checks if the Key Present flag (K) is set.
    ///
    /// # Returns
    /// `true` if the Key Present flag is set, `false` otherwise.
    #[inline]
    pub fn key_flg(&self) -> bool {
        self.flgs_res0_ver[0] & K_FLAG_MASK != 0
    }

    /// Sets or clears the Key Present flag (K).
    ///
    /// # Parameters
    /// * `key_flg`: `true` to set the flag, `false` to clear it.
    #[inline]
    pub fn set_key_flg(&mut self, key_flg: bool) {
        if key_flg {
            self.flgs_res0_ver[0] |= K_FLAG_MASK;
        } else {
            self.flgs_res0_ver[0] &= !K_FLAG_MASK;
        }
    }

    /// Checks if the Sequence Number Present flag (S) is set.
    ///
    /// # Returns
    /// `true` if the Sequence Number Present flag is set, `false` otherwise.
    #[inline]
    pub fn seq_flg(&self) -> bool {
        self.flgs_res0_ver[0] & S_FLAG_MASK != 0
    }

    /// Sets or clears the Sequence Number Present flag (S).
    ///
    /// # Parameters
    /// * `seq_flg`: `true` to set the flag, `false` to clear it.
    #[inline]
    pub fn set_seq_flg(&mut self, seq_flg: bool) {
        if seq_flg {
            self.flgs_res0_ver[0] |= S_FLAG_MASK;
        } else {
            self.flgs_res0_ver[0] &= !S_FLAG_MASK;
        }
    }

    /// Reads the version number from the header bytes.
    /// This method is left as-is to allow validation of incoming packets.
    #[inline]
    pub fn version(&self) -> u8 {
        self.flgs_res0_ver[1] & VER_MASK
    }

    /// Sets the GRE version. Per RFC 2784, the version MUST be 0.
    /// This method enforces this by ignoring the input and always setting the version to 0.
    #[inline]
    pub fn set_version(&mut self, _version: u8) {
        // This clears the version bits in the flag byte, enforcing version 0.
        self.flgs_res0_ver[1] &= !VER_MASK;
    }

    /// Gets the Protocol Type field from the GRE header.
    ///
    /// This field indicates the protocol type of the payload packet.
    /// Common values include 0x0800 for IPv4 and 0x86DD for IPv6.
    ///
    /// # Returns
    /// The protocol type as a Result containing either EtherType or the raw u16 value.
    #[inline]
    pub fn protocol(&self) -> Result<EtherType, u16> {
        EtherType::try_from(self.proto)
    }

    /// Sets the Protocol Type field in the GRE header.
    ///
    /// # Parameters
    /// * `proto`: The protocol type as a 16-bit unsigned integer in host byte order.
    ///
    /// Common values include 0x0800 for IPv4 and 0x86DD for IPv6.
    #[inline]
    pub fn set_protocol(&mut self, proto: u16) {
        self.proto = proto;
    }

    /// Calculates the total length of the routing field by parsing SREs.
    /// This requires access to the packet data to read the variable-length routing information.
    ///
    /// # Parameters
    /// * `data`: Slice containing the routing field data (starting after checksum/offset field)
    ///
    /// # Returns
    /// Total length of the routing field in bytes, or an error if parsing fails
    pub fn calculate_routing_len(data: &[u8]) -> Result<usize, &'static str> {
        let mut offset = 0;
        let mut total_len = 0;

        loop {
            // Ensure we have enough bytes for the SRE header
            if offset + GreRoutingHeader::LEN > data.len() {
                return Err("Insufficient data for SRE header");
            }

            // Parse the SRE header
            let sre_header = unsafe {
                core::ptr::read_unaligned(data.as_ptr().add(offset) as *const GreRoutingHeader)
            };

            // Convert from network byte order
            let address_family = u16::from_be(sre_header.address_family);
            let sre_length = sre_header.sre_length;

            // Check for NULL SRE (terminator)
            if address_family == 0 && sre_length == 0 {
                total_len += GreRoutingHeader::LEN;
                break;
            }

            // Validate SRE length
            if sre_length < GreRoutingHeader::LEN as u8 {
                return Err("Invalid SRE length");
            }

            // Ensure we have enough data for the complete SRE
            if offset + sre_length as usize > data.len() {
                return Err("Insufficient data for complete SRE");
            }

            total_len += sre_length as usize;
            offset += sre_length as usize;
        }

        Ok(total_len)
    }
}

/// Represents the static part of a GRE Source Route Entry (SRE).
/// Each SRE contains a 4-byte header followed by variable-length routing information.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct GreRoutingHeader {
    /// Address Family (2 bytes) - indicates syntax/semantics of routing info
    pub address_family: u16,
    /// SRE Offset (1 byte) - offset to active entry in routing info
    pub sre_offset: u8,
    /// SRE Length (1 byte) - total length of this SRE in bytes
    /// If 0, this indicates the last SRE (NULL terminator)
    pub sre_length: u8,
}

impl GreRoutingHeader {
    /// The size of the SRE header in bytes (Address Family + SRE Offset + SRE Length)
    pub const LEN: usize = core::mem::size_of::<GreRoutingHeader>();

    /// Checks if this is a NULL SRE (terminator)
    #[inline]
    pub fn is_null_sre(&self) -> bool {
        self.address_family == 0 && self.sre_length == 0
    }

    /// Gets the total length of this SRE including the routing information
    #[inline]
    pub fn total_sre_len(&self) -> usize {
        self.sre_length as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a default GreHdr for tests
    fn default_gre_hdr() -> GreHdr {
        GreHdr {
            flgs_res0_ver: [0; 2],
            proto: EtherType::Ipv4 as u16,
        }
    }

    #[test]
    fn test_gre_hdr_size() {
        assert_eq!(GreHdr::LEN, 4); // 4 bytes fixed header only
    }

    #[test]
    fn test_total_hdr_len() {
        let mut hdr = default_gre_hdr();

        // Initially just the fixed header
        assert_eq!(hdr.total_hdr_len(), 4);

        // With checksum flag
        hdr.set_ck_flg(true);
        assert_eq!(hdr.total_hdr_len(), 8); // 4 + 4

        // With checksum and key flags
        hdr.set_key_flg(true);
        assert_eq!(hdr.total_hdr_len(), 12); // 4 + 4 + 4

        // With all flags (C, K, S)
        hdr.set_seq_flg(true);
        assert_eq!(hdr.total_hdr_len(), 16); // 4 + 4 + 4 + 4

        // Reset and test individual flags
        hdr = default_gre_hdr();
        hdr.set_key_flg(true);
        assert_eq!(hdr.total_hdr_len(), 8); // 4 + 4

        hdr = default_gre_hdr();
        hdr.set_seq_flg(true);
        assert_eq!(hdr.total_hdr_len(), 8); // 4 + 4

        // Test routing flag
        hdr = default_gre_hdr();
        hdr.set_r_flg(true);
        assert_eq!(hdr.total_hdr_len(), 8); // 4 + 4 (Checksum/Offset field)

        // Test routing flag with key
        hdr.set_key_flg(true);
        assert_eq!(hdr.total_hdr_len(), 12); // 4 + 4 + 4

        // Test routing flag with sequence
        hdr = default_gre_hdr();
        hdr.set_r_flg(true);
        hdr.set_seq_flg(true);
        assert_eq!(hdr.total_hdr_len(), 12); // 4 + 4 + 4

        // Test both checksum and routing flags (should still be 8 bytes for Checksum/Offset)
        hdr = default_gre_hdr();
        hdr.set_ck_flg(true);
        hdr.set_r_flg(true);
        assert_eq!(hdr.total_hdr_len(), 8); // 4 + 4 (not 4 + 4 + 4)

        // Test all flags including routing
        hdr.set_key_flg(true);
        hdr.set_seq_flg(true);
        assert_eq!(hdr.total_hdr_len(), 16); // 4 + 4 + 4 + 4
    }

    #[test]
    fn test_ck_flg() {
        let mut hdr = default_gre_hdr();

        // Initially false
        assert_eq!(hdr.ck_flg(), false);

        // Set to true
        hdr.set_ck_flg(true);
        assert_eq!(hdr.ck_flg(), true);
        assert_eq!(hdr.flgs_res0_ver[0] & C_FLAG_MASK, C_FLAG_MASK);

        // Set to false
        hdr.set_ck_flg(false);
        assert_eq!(hdr.ck_flg(), false);
        assert_eq!(hdr.flgs_res0_ver[0] & C_FLAG_MASK, 0);
    }

    #[test]
    fn test_r_flg() {
        let mut hdr = default_gre_hdr();

        // Initially false
        assert_eq!(hdr.r_flg(), false);

        // Set to true
        hdr.set_r_flg(true);
        assert_eq!(hdr.r_flg(), true);
        assert_eq!(hdr.flgs_res0_ver[0] & R_FLAG_MASK, R_FLAG_MASK);

        // Set to false
        hdr.set_r_flg(false);
        assert_eq!(hdr.r_flg(), false);
        assert_eq!(hdr.flgs_res0_ver[0] & R_FLAG_MASK, 0);
    }

    #[test]
    fn test_key_flg() {
        let mut hdr = default_gre_hdr();

        // Initially false
        assert_eq!(hdr.key_flg(), false);

        // Set to true
        hdr.set_key_flg(true);
        assert_eq!(hdr.key_flg(), true);
        assert_eq!(hdr.flgs_res0_ver[0] & K_FLAG_MASK, K_FLAG_MASK);

        // Set to false
        hdr.set_key_flg(false);
        assert_eq!(hdr.key_flg(), false);
        assert_eq!(hdr.flgs_res0_ver[0] & K_FLAG_MASK, 0);
    }

    #[test]
    fn test_seq_flg() {
        let mut hdr = default_gre_hdr();

        // Initially false
        assert_eq!(hdr.seq_flg(), false);

        // Set to true
        hdr.set_seq_flg(true);
        assert_eq!(hdr.seq_flg(), true);
        assert_eq!(hdr.flgs_res0_ver[0] & S_FLAG_MASK, S_FLAG_MASK);

        // Set to false
        hdr.set_seq_flg(false);
        assert_eq!(hdr.seq_flg(), false);
        assert_eq!(hdr.flgs_res0_ver[0] & S_FLAG_MASK, 0);
    }

    #[test]
    fn test_version() {
        let mut hdr = default_gre_hdr();

        // Initially 0
        assert_eq!(hdr.version(), 0);

        // Set version (should be ignored and remain 0)
        hdr.set_version(3);
        assert_eq!(hdr.version(), 0);
    }

    #[test]
    fn test_protocol() {
        let mut hdr = default_gre_hdr();

        // Test initial protocol
        assert_eq!(hdr.protocol(), Ok(EtherType::Ipv4));
        assert_eq!(hdr.protocol(), Ok(EtherType::Ipv4)); // legacy method

        // Test setting protocol
        hdr.set_protocol(EtherType::Ipv6 as u16);
        assert_eq!(hdr.protocol(), Ok(EtherType::Ipv6));

        // Test legacy setter
        hdr.set_protocol(EtherType::Ipv4 as u16);
        assert_eq!(hdr.protocol(), Ok(EtherType::Ipv4));
    }

    #[test]
    fn test_requirements_compliance() {
        // This test verifies all requirements from the issue are met
        let mut hdr = default_gre_hdr();

        // Requirement: total_hdr_len function
        assert_eq!(hdr.total_hdr_len(), 4); // Fixed header only

        // Requirement: protocol/set_protocol functions
        assert_eq!(hdr.protocol(), Ok(EtherType::Ipv4));
        hdr.set_protocol(EtherType::Ipv6 as u16);
        assert_eq!(hdr.protocol(), Ok(EtherType::Ipv6));

        // Requirement: flag extraction functions are public
        assert!(!hdr.ck_flg());
        assert!(!hdr.r_flg());
        assert!(!hdr.key_flg());
        assert!(!hdr.seq_flg());

        // Test total_hdr_len with different flag combinations
        hdr.set_ck_flg(true);
        assert_eq!(hdr.total_hdr_len(), 8); // 4 + 4

        hdr.set_key_flg(true);
        assert_eq!(hdr.total_hdr_len(), 12); // 4 + 4 + 4

        hdr.set_seq_flg(true);
        assert_eq!(hdr.total_hdr_len(), 16); // 4 + 4 + 4 + 4

        // Test routing flag compliance with RFC specification
        hdr = default_gre_hdr();
        hdr.set_r_flg(true);
        assert_eq!(hdr.total_hdr_len(), 8); // 4 + 4 (Checksum/Offset field)

        // Test that both C and R flags result in same Checksum/Offset field (not double-counted)
        hdr.set_ck_flg(true);
        assert_eq!(hdr.total_hdr_len(), 8); // Still 4 + 4, not 4 + 4 + 4

        // Verify structure is simplified (no optional fields in struct)
        assert_eq!(core::mem::size_of::<GreHdr>(), 4); // Only fixed header
    }
}
