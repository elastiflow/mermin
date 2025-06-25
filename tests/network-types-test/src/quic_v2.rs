use core::mem;

const HEADER_FORM_BIT: u8 = 0x80;
const FIXED_BIT_MASK: u8 = 0x40;
const LONG_PACKET_TYPE_MASK: u8 = 0x30;
const LONG_PACKET_TYPE_SHIFT: u8 = 4;
const RESERVED_BITS_LONG_MASK: u8 = 0x0C;
const RESERVED_BITS_LONG_SHIFT: u8 = 2;
const SHORT_SPIN_BIT_MASK: u8 = 0x20;
const SHORT_SPIN_BIT_SHIFT: u8 = 5;
const SHORT_RESERVED_BITS_MASK: u8 = 0x18;
const SHORT_RESERVED_BITS_SHIFT: u8 = 3;
const SHORT_KEY_PHASE_BIT_MASK: u8 = 0x04;
const SHORT_KEY_PHASE_BIT_SHIFT: u8 = 2;

const PN_LENGTH_BITS_MASK: u8 = 0x03;

pub const QUIC_MAX_CID_LEN: usize = 20;

pub const QUIC_SHORT_DEFAULT_DC_ID_LEN: u8 = 0x08;

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum QuicHdr {
    Long(QuicLongHdr),
    Short(QuicShortHdr),
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuicLongHdr {
    pub first_byte: QuicFixedHdr,
    pub fixed_hdr: QuicFixedLongHdr,
    pub dc_id: [u8; QUIC_MAX_CID_LEN],
    pub sc_id_len: u8,
    pub sc_id: [u8; QUIC_MAX_CID_LEN],
    pub pn: [u8; 4],
}

impl QuicLongHdr {
    /// Length of the `QuicHdr` struct, relevant for Long Headers.
    pub const LEN: usize = mem::size_of::<QuicLongHdr>();

    pub fn new(
        fixed: QuicFixedHdr, 
        fixed_long: QuicFixedLongHdr,
        //dc_id: [u8; QUIC_MAX_CID_LEN],
        //sc_id_len: u8,
        //sc_id: [u8; QUIC_MAX_CID_LEN],
        //pn: [u8; 4],
    ) -> Self {
        Self {
            first_byte: fixed,
            fixed_hdr: fixed_long,

            dc_id: [0; QUIC_MAX_CID_LEN],
            sc_id_len: 0,
            sc_id: [0; QUIC_MAX_CID_LEN],
            pn: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuicShortHdr {
    pub dc_id_len: u8,
    pub first_byte: QuicFixedHdr,
    pub dc_id: [u8; QUIC_MAX_CID_LEN],
    pub pn: [u8; 4],
}

impl QuicShortHdr {
    /// Length of the `QuicHdr` struct, relevant for Long Headers.
    pub const LEN: usize = mem::size_of::<QuicShortHdr>();

    pub fn new(
        dc_id_len: u8,
        first_byte: QuicFixedHdr,
        //dc_id: [u8; QUIC_MAX_CID_LEN],
        //pn: [u8; 4],
    ) -> Self {
        Self {
            dc_id_len,
            first_byte,
            dc_id: [0; QUIC_MAX_CID_LEN],
            pn: [0; 4],
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuicFixedLongHdr {
    /// QUIC version (e.g., 0x00000001 for QUIC v1). Network byte order. Only in Long Headers.
    pub version: [u8; 4],
    /// Destination Connection ID Length. Only in Long Headers (explicitly). For Short Headers,
    /// this field might be used by application logic to store the known DCID length.
    pub dc_id_len: u8,
}

impl QuicFixedLongHdr {
    /// Length of the `QuicHdr` struct, relevant for Long Headers.
    pub const LEN: usize = mem::size_of::<QuicFixedLongHdr>();

    /// Creates a `QuicHdr` for a Long Header, configured as an Initial packet.
    ///
    /// The first byte is set for Long Header (form bit = 1), Fixed Bit = 1,
    /// Long Packet Type = Initial (0b00), and Reserved Bits = 0.
    ///
    /// # Parameters
    /// - `version` - QUIC version (e.g., `0x00000001` for v1), host byte order.
    /// - `dc_id_len` - Destination Connection ID length.
    /// - `sc_id_len` - Source Connection ID length.
    /// - `pn_len_bits` - Encoded Packet Number Length (actual length - 1, value 0-3).
    ///
    /// # Returns
    /// A new `QuicHdr` instance.
    pub fn new(version: u32, dc_id_len: u8) -> Self {
        Self {
            version: version.to_be_bytes(),
            dc_id_len,
        }
    }
    /// Returns the QUIC version from the header (host byte order). Long Headers only.
    ///
    /// # Returns
    /// The QUIC version. Panics or returns garbage if called on a Short Header's `QuicHdr`.
    #[inline]
    pub fn version(&self) -> u32 {
        u32::from_be_bytes(self.version)
    }

    /// Sets the QUIC version in the header. `version` should be host byte order. Long Headers only.
    ///
    /// # Parameters
    /// - `version` - The QUIC version (host byte order).
    #[inline]
    pub fn set_version(&mut self, version: u32) {
        self.version = version.to_be_bytes();
    }

    /// Returns Destination Connection ID Length. For Long Headers, this is from the header.
    /// For Short Headers, this field in the struct is not from the wire's first byte.
    ///
    /// # Returns
    /// The DCID length.
    #[inline]
    pub fn dc_id_len(&self) -> u8 {
        self.dc_id_len
    }

    /// Sets Destination Connection ID Length.
    ///
    /// # Parameters
    /// - `len` - The new DCID length.
    #[inline]
    pub fn set_dc_id_len(&mut self, len: u8) {
        self.dc_id_len = len;
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuicFixedHdr {
    /// The first byte of the QUIC header. Its interpretation depends on the Header Form bit.
    /// - Bit 7: Header Form (1 for Long, 0 for Short)
    /// - Bit 6: Fixed Bit (usually 1)
    /// - Bits 5-0: Type/Flag specific bits.
    pub first_byte: u8,
}

impl QuicFixedHdr {
    /// Length of the `QuicHdr` struct, relevant for Long Headers.
    pub const LEN: usize = mem::size_of::<QuicFixedHdr>();

    /// Creates a `QuicHdr` for a Long Header, configured as an Initial packet.
    ///
    /// The first byte is set for Long Header (form bit = 1), Fixed Bit = 1,
    /// Long Packet Type = Initial (0b00), and Reserved Bits = 0.
    ///
    /// # Parameters
    /// - `version` - QUIC version (e.g., `0x00000001` for v1), host byte order.
    /// - `dc_id_len` - Destination Connection ID length.
    /// - `sc_id_len` - Source Connection ID length.
    /// - `pn_len_bits` - Encoded Packet Number Length (actual length - 1, value 0-3).
    ///
    /// # Returns
    /// A new `QuicHdr` instance.
    pub fn new(pn_len_bits: u8) -> Self {
        let first_byte = HEADER_FORM_BIT
            | FIXED_BIT_MASK
            | (0b00 << LONG_PACKET_TYPE_SHIFT)
            | (0b00 << RESERVED_BITS_LONG_SHIFT)
            | (pn_len_bits & PN_LENGTH_BITS_MASK);
        Self { first_byte }
    }

    /// Creates the first byte for a QUIC Short Header.
    ///
    /// Sets Header Form to 0, Fixed Bit to 1, and specified Short Header flags.
    /// Reserved bits (4-3) are set to 0.
    ///
    /// # Parameters
    /// - `spin_bit` - The value of the Spin bit (0 or 1).
    /// - `key_phase` - The value of the Key Phase bit (0 or 1).
    /// - `pn_len_bits` - The encoded Packet Number Length (actual length - 1, value 0-3).
    ///
    /// # Returns
    /// The constructed `first_byte` for a Short Header.
    pub fn new_short_header_first_byte(spin_bit: bool, key_phase: bool, pn_len_bits: u8) -> u8 {
        let spin_val = if spin_bit { 1 } else { 0 };
        let key_phase_val = if key_phase { 1 } else { 0 };
        FIXED_BIT_MASK
            | (spin_val << SHORT_SPIN_BIT_SHIFT)
            | (key_phase_val << SHORT_KEY_PHASE_BIT_SHIFT)
            | (pn_len_bits & PN_LENGTH_BITS_MASK)
    }

    /// Returns the raw first byte of the header.
    ///
    /// # Returns
    /// The `first_byte` field.
    #[inline]
    pub fn first_byte(&self) -> u8 {
        self.first_byte
    }

    /// Sets the raw first byte of the header.
    ///
    /// # Parameters
    /// - `first_byte` - The new value for the first byte.
    #[inline]
    pub fn set_first_byte(&mut self, first_byte: u8) {
        self.first_byte = first_byte;
    }

    /// Checks if the Header Form bit (bit 7 of `first_byte`) indicates a Long Header.
    ///
    /// # Returns
    /// `true` if it's a Long Header (bit 7 is 1), `false` otherwise (Short Header).
    #[inline]
    pub fn is_long_header(&self) -> bool {
        (self.first_byte & HEADER_FORM_BIT) == HEADER_FORM_BIT
    }

    /// Sets the Header Form bit (bit 7 of `first_byte`).
    ///
    /// # Parameters
    /// - `is_long` - If `true`, sets for Long Header (bit 7 = 1); if `false`, sets for Short Header (bit 7 = 0).
    #[inline]
    pub fn set_header_form(&mut self, is_long: bool) {
        if is_long {
            self.first_byte |= HEADER_FORM_BIT;
        } else {
            self.first_byte &= !HEADER_FORM_BIT;
        }
    }

    /// Gets the Fixed Bit (bit 6 of `first_byte`).
    ///
    /// In QUIC v1 (RFC 9000):
    /// - For Long Headers: `1` for Initial, 0-RTT, Handshake, Retry. `0` for Version Negotiation.
    /// - For Short Headers: Must be `1`.
    ///
    /// # Returns
    /// The value of the Fixed Bit (0 or 1).
    #[inline]
    pub fn fixed_bit(&self) -> u8 {
        (self.first_byte & FIXED_BIT_MASK) >> 6
    }

    /// Sets the Fixed Bit (bit 6 of `first_byte`).
    ///
    /// # Parameters
    /// - `val` - The new value for the Fixed Bit (0 or 1). Input is masked to 1 bit.
    #[inline]
    pub fn set_fixed_bit(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !FIXED_BIT_MASK) | ((val & 0x01) << 6);
    }

    /// Gets the Long Packet Type (bits 5-4 of `first_byte`). Assumes Long Header.
    /// Common QUIC v1 types (RFC 9000): 00 (Initial), 01 (0-RTT), 10 (Handshake), 11 (Retry).
    ///
    /// # Returns
    /// The Long Packet Type value (0-3). Only valid if `is_long_header()` is `true` and `fixed_bit()` is `1`.
    #[inline]
    pub fn long_packet_type(&self) -> u8 {
        (self.first_byte & LONG_PACKET_TYPE_MASK) >> LONG_PACKET_TYPE_SHIFT
    }

    /// Sets the Long Packet Type (bits 5-4 of `first_byte`). Assumes Long Header.
    ///
    /// # Parameters
    /// - `lptype` - The Long Packet Type (0-3). Input is masked to 2 bits.
    #[inline]
    pub fn set_long_packet_type(&mut self, lptype: u8) {
        self.first_byte = (self.first_byte & !LONG_PACKET_TYPE_MASK)
            | ((lptype << LONG_PACKET_TYPE_SHIFT) & LONG_PACKET_TYPE_MASK);
    }

    /// Gets the Reserved Bits (bits 3-2 of `first_byte`) for common Long Headers.
    /// Must be 0 for Initial, 0-RTT, Handshake packets in QUIC v1.
    ///
    /// # Returns
    /// The Reserved Bits value (0-3). Only valid for certain Long Header types.
    #[inline]
    pub fn reserved_bits_long(&self) -> u8 {
        (self.first_byte & RESERVED_BITS_LONG_MASK) >> RESERVED_BITS_LONG_SHIFT
    }

    /// Sets the Reserved Bits (bits 3-2 of `first_byte`) for common Long Headers.
    /// `val` MUST be 0 for Initial, 0-RTT, Handshake packets in QUIC v1.
    ///
    /// # Parameters
    /// - `val` - The Reserved Bits value (0-3). Input is masked to 2 bits.
    #[inline]
    pub fn set_reserved_bits_long(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !RESERVED_BITS_LONG_MASK)
            | ((val << RESERVED_BITS_LONG_SHIFT) & RESERVED_BITS_LONG_MASK);
    }

    /// Gets the Packet Number Length bits (bits 1-0 of `first_byte`) for common Long Headers.
    /// Encoded length (actual length - 1).
    ///
    /// # Returns
    /// The encoded Packet Number Length value (0-3). Valid for certain Long Header types.
    #[inline]
    pub fn pn_length_bits_long(&self) -> u8 {
        self.first_byte & PN_LENGTH_BITS_MASK
    }

    /// Sets the Packet Number Length bits (bits 1-0 of `first_byte`) for common Long Headers.
    ///
    /// # Parameters
    /// - `val` - Encoded 2-bit value (0-3, for actual lengths 1-4 bytes). Masked to 2 bits.
    #[inline]
    pub fn set_pn_length_bits_long(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !PN_LENGTH_BITS_MASK) | (val & PN_LENGTH_BITS_MASK);
    }

    /// Gets actual Packet Number Length (bytes) for common Long Headers. (`pn_length_bits_long() + 1`).
    ///
    /// # Returns
    /// Actual Packet Number Length (1 to 4 bytes).
    #[inline]
    pub fn packet_number_length_long(&self) -> usize {
        (self.pn_length_bits_long() + 1) as usize
    }

    /// Sets Packet Number Length for common Long Headers, using actual length (1-4 bytes).
    /// Clamped if `len` is out of range.
    ///
    /// # Parameters
    /// - `len` - Actual length in bytes (1-4).
    #[inline]
    pub fn set_packet_number_length_long(&mut self, len: usize) {
        let encoded_val = match len {
            1 => 0b00,
            2 => 0b01,
            3 => 0b10,
            4 => 0b11,
            _ if len < 1 => 0b00,
            _ => 0b11,
        };
        self.set_pn_length_bits_long(encoded_val);
    }

    /// Gets the Spin Bit (bit 5 of `first_byte`). Assumes Short Header.
    ///
    /// # Returns
    /// `true` if Spin Bit is 1, `false` if 0. Only valid if `!is_long_header()`.
    #[inline]
    pub fn short_spin_bit(&self) -> bool {
        (self.first_byte & SHORT_SPIN_BIT_MASK) != 0
    }

    /// Sets the Spin Bit (bit 5 of `first_byte`). Assumes Short Header.
    ///
    /// # Parameters
    /// - `spin` - Value for the Spin Bit (`true` for 1, `false` for 0).
    #[inline]
    pub fn set_short_spin_bit(&mut self, spin: bool) {
        if spin {
            self.first_byte |= SHORT_SPIN_BIT_MASK;
        } else {
            self.first_byte &= !SHORT_SPIN_BIT_MASK;
        }
    }

    /// Gets the Reserved Bits (bits 4-3 of `first_byte`). Assumes Short Header.
    /// These bits MUST be 0 in QUIC v1.
    ///
    /// # Returns
    /// The value of the Reserved Bits (0-3). Only valid if `!is_long_header()`.
    #[inline]
    pub fn short_reserved_bits(&self) -> u8 {
        (self.first_byte & SHORT_RESERVED_BITS_MASK) >> SHORT_RESERVED_BITS_SHIFT
    }

    /// Sets the Reserved Bits (bits 4-3 of `first_byte`). Assumes Short Header.
    /// These bits MUST be set to 0 (0b00) in QUIC v1. This method enforces this.
    ///
    /// # Parameters
    /// - `reserved` - The value for the Reserved Bits. If not 0, they will be set to 0.
    #[inline]
    pub fn set_short_reserved_bits(&mut self, _reserved: u8) {
        self.first_byte &= !SHORT_RESERVED_BITS_MASK;
    }

    /// Gets the Key Phase Bit (bit 2 of `first_byte`). Assumes Short Header.
    ///
    /// # Returns
    /// `true` if Key Phase Bit is 1, `false` if 0. Only valid if `!is_long_header()`.
    #[inline]
    pub fn short_key_phase(&self) -> bool {
        (self.first_byte & SHORT_KEY_PHASE_BIT_MASK) != 0
    }

    /// Sets the Key Phase Bit (bit 2 of `first_byte`). Assumes Short Header.
    ///
    /// # Parameters
    /// - `key_phase` - Value for the Key Phase Bit (`true` for 1, `false` for 0).
    #[inline]
    pub fn set_short_key_phase(&mut self, key_phase: bool) {
        if key_phase {
            self.first_byte |= SHORT_KEY_PHASE_BIT_MASK;
        } else {
            self.first_byte &= !SHORT_KEY_PHASE_BIT_MASK;
        }
    }

    /// Gets the Packet Number Length bits (bits 1-0 of `first_byte`). Assumes Short Header.
    /// Encoded length (actual length - 1).
    ///
    /// # Returns
    /// The encoded Packet Number Length value (0-3). Only valid if `!is_long_header()`.
    #[inline]
    pub fn short_pn_length_bits(&self) -> u8 {
        self.first_byte & PN_LENGTH_BITS_MASK
    }

    /// Sets the Packet Number Length bits (bits 1-0 of `first_byte`). Assumes Short Header.
    ///
    /// # Parameters
    /// - `val` - Encoded 2-bit value (0-3, for actual lengths 1-4 bytes). Masked to 2 bits.
    #[inline]
    pub fn set_short_pn_length_bits(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !PN_LENGTH_BITS_MASK) | (val & PN_LENGTH_BITS_MASK);
    }

    /// Gets actual Packet Number Length (bytes) for Short Headers. (`short_pn_length_bits() + 1`).
    ///
    /// # Returns
    /// Actual Packet Number Length (1 to 4 bytes).
    #[inline]
    pub fn short_packet_number_length(&self) -> usize {
        (self.short_pn_length_bits() + 1) as usize
    }

    /// Sets Packet Number Length for Short Headers, using actual length (1-4 bytes).
    /// Clamped if `len` is out of range.
    ///
    /// # Parameters
    /// - `len` - Actual length in bytes (1-4).
    #[inline]
    pub fn set_short_packet_number_length(&mut self, len: usize) {
        let encoded_val = match len {
            1 => 0b00,
            2 => 0b01,
            3 => 0b10,
            4 => 0b11,
            _ if len < 1 => 0b00,
            _ => 0b11,
        };
        self.set_short_pn_length_bits(encoded_val);
    }
}
