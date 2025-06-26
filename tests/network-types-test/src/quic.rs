use core::mem;

pub const QUIC_MAX_CID_LEN: usize = 20;
pub const QUIC_MAX_TOKEN_LEN: usize = 4;
pub const QUIC_MAX_LENGTH: usize = 8;
pub const QUIC_SHORT_DEFAULT_DC_ID_LEN: u8 = 8;
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

/// An enum representing errors that can occur while processing Quic headers.
///
/// # Variants
/// - `InvalidQuicType`: Indicates an attempt to access a field with an incompatible Quic message type.
///   For example, trying to access echo fields on a redirect message.
#[derive(Debug)]
pub enum QuicError {
    InvalidQuicType,
}

#[macro_export]
macro_rules! parse_quic_hdr {
    ($ctx:expr, $off:ident, $short_dc_id_len:expr) => {
        (|| -> Result<$crate::quic::QuicHdr, ()> {
            use $crate::{read_var_buf_32, read_var_buf_from_len_byte_16};
            use $crate::quic;
            let quic_fixed_hdr: quic::QuicFirstByteHdr = $ctx.load($off).map_err(|_| ())?;
            $off += quic::QuicFirstByteHdr::LEN;
            match quic_fixed_hdr.is_long_header() {
                true => {
                    let quic_fixed_long_hdr: quic::QuicFixedLongHdr = $ctx.load($off).map_err(|_| ())?;
                    $off += quic::QuicFixedLongHdr::LEN;
                    let mut quic_long_hdr = quic::QuicLongHdr::new(quic_fixed_hdr, quic_fixed_long_hdr);
                    read_var_buf_32!(
                        $ctx,
                        $off,
                        quic_long_hdr.dc_id,
                        quic_long_hdr.fixed_hdr.dc_id_len as usize,
                        quic::QUIC_MAX_CID_LEN
                    )
                    .map_err(|_| ())?;
                    quic_long_hdr.sc_id_len = $ctx.load($off).map_err(|_| ())?;
                    $off += 1;
                    read_var_buf_32!(
                        $ctx,
                        $off,
                        quic_long_hdr.sc_id,
                        quic_long_hdr.sc_id_len  as usize,
                        quic::QUIC_MAX_CID_LEN
                    )
                    .map_err(|_| ())?;
                     if quic_fixed_hdr.long_packet_type() == 0 {
                        let token_len_byte: u8 = $ctx.load($off).map_err(|_| ())?;
                        $off += 1;
                        read_var_buf_from_len_byte_16!(
                            $ctx,
                            $off,
                            quic_long_hdr.token_len,
                            token_len_byte,
                            quic::QUIC_MAX_TOKEN_LEN
                        )
                        .map_err(|_| ())?;
                        let token_len_val = quic_long_hdr.token_len().map_err(|_| ())?;
                        $off += token_len_val;
                    }
                    if quic_fixed_hdr.long_packet_type() < 3 {
                        let len_byte: u8 = $ctx.load($off).map_err(|_| ())?;
                        $off += 1;
                        read_var_buf_from_len_byte_16!(
                            $ctx,
                            $off,
                            quic_long_hdr.length,
                            len_byte,
                            quic::QUIC_MAX_LENGTH
                        )
                        .map_err(|_| ())?;
                    }
                    read_var_buf_32!(
                        $ctx,
                        $off,
                        quic_long_hdr.pn,
                        quic_long_hdr.first_byte.packet_number_length_long(),
                        4
                    )
                    .map_err(|_| ())?;
                    Ok(quic::QuicHdr::Long(quic_long_hdr))
                }
                false => {
                    let mut quic_short_hdr =
                        quic::QuicShortHdr::new($short_dc_id_len, quic_fixed_hdr);
                    read_var_buf_32!(
                        $ctx,
                        $off,
                        quic_short_hdr.dc_id,
                        quic_short_hdr.dc_id_len as usize,
                        quic::QUIC_MAX_CID_LEN
                    )
                    .map_err(|_| ())?;
                    read_var_buf_32!(
                        $ctx,
                        $off,
                        quic_short_hdr.pn,
                        quic_short_hdr.first_byte.short_packet_number_length(),
                        4
                    )
                    .map_err(|_| ())?;
                    Ok(quic::QuicHdr::Short(quic_short_hdr))
                }
            }
        })()
    };
}


#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Debug, PartialEq)]
pub enum QuicHdr {
    Long(QuicLongHdr),
    Short(QuicShortHdr),
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuicLongHdr {
    pub first_byte: QuicFirstByteHdr,
    pub fixed_hdr: QuicFixedLongHdr,
    pub dc_id: [u8; QUIC_MAX_CID_LEN],
    pub sc_id_len: u8,
    pub sc_id: [u8; QUIC_MAX_CID_LEN],
    pub token_len: [u8; QUIC_MAX_TOKEN_LEN],
    pub length: [u8; QUIC_MAX_LENGTH],
    pub pn: [u8; 4],
}

impl QuicLongHdr {
    pub const LEN: usize = mem::size_of::<QuicLongHdr>();

    pub fn new(
        first_byte: QuicFirstByteHdr,
        fixed_hdr: QuicFixedLongHdr,
    ) -> Self {
        Self {
            first_byte,
            fixed_hdr,
            dc_id: [0; QUIC_MAX_CID_LEN],
            sc_id_len: 0,
            sc_id: [0; QUIC_MAX_CID_LEN],
            token_len: [0; QUIC_MAX_TOKEN_LEN],
            length: [0; QUIC_MAX_LENGTH],
            pn: [0; 4],
        }
    }

    #[inline]
    pub fn packet_type(&self) -> u8 {
        self.first_byte.long_packet_type()
    }

    #[inline]
    pub fn version(&self) -> u32 {
        self.fixed_hdr.version()
    }

    #[inline]
    pub fn set_version(&mut self, version: u32) {
        self.fixed_hdr.set_version(version)
    }

    #[inline]
    pub fn dc_id_len(&self) -> u8 {
        self.fixed_hdr.dc_id_len()
    }

    #[inline]
    pub fn set_dc_id_len(&mut self, dc_id_len: u8) {
        self.fixed_hdr.set_dc_id_len(dc_id_len)
    }

    #[inline]
    pub fn dc_id(&self) ->  [u8; QUIC_MAX_CID_LEN] {
        self.dc_id
    }

    #[inline]
    pub fn set_dc_id(&mut self, dc_id: [u8; QUIC_MAX_CID_LEN]) {
        self.dc_id = dc_id;
    }

    #[inline]
    pub fn sc_id_len(&self) -> u8 {
        self.sc_id_len
    }

    #[inline]
    pub fn set_sc_id_len(&mut self, sc_id_len: u8) {
        self.sc_id_len = sc_id_len;
    }

    #[inline]
    pub fn sc_id(&self) -> [u8; QUIC_MAX_CID_LEN] {
        self.sc_id
    }

    #[inline]
    pub fn set_sc_id(&mut self, sc_id: [u8; QUIC_MAX_CID_LEN]) {
        self.sc_id = sc_id;
    }

    #[inline]
    pub fn set_length(&mut self, length: usize) {
        self.length = (length as u64).to_be_bytes();
    }

    #[inline]
    pub fn set_token_len(&mut self, token_len: usize) -> Result<(), QuicError> {
        if self.packet_type() != 0 {
            return Err(QuicError::InvalidQuicType);
        }
        let token_len = token_len as u64;
        self.token_len = [0; QUIC_MAX_TOKEN_LEN];
        if token_len < (1 << 6) {
            self.token_len[0] = token_len as u8;
        } else if token_len < (1 << 14) {
            self.token_len[0] = (0b01 << 6) | (token_len >> 8) as u8;
            self.token_len[1] = token_len as u8;
        } else if token_len < (1 << 30) {
            self.token_len[0] = (0b10 << 6) | (token_len >> 24) as u8;
            self.token_len[1] = (token_len >> 16) as u8;
            self.token_len[2] = (token_len >> 8) as u8;
            self.token_len[3] = token_len as u8;
        }
        Ok(())
    }

    #[inline]
    pub fn token_len(&self) -> Result<usize, QuicError> {
        if self.packet_type() != 0 {
            return Err(QuicError::InvalidQuicType);
        }
        let first_byte = self.token_len[0];
        let len = 1 << (first_byte >> 6);
        let mut val = (first_byte & 0x3F) as u64;
        for i in 1..len {
            val = (val << 8) + self.token_len[i as usize] as u64;
        }
        Ok(val as usize)
    }

    #[inline]
    pub fn length(&self) -> Result<usize, QuicError> {
        if self.packet_type() >= 3 {
            return Err(QuicError::InvalidQuicType);
        }
        Ok(u64::from_be_bytes(self.length) as usize)
    }

    #[inline]
    pub fn pn(&self) -> Result<u32, QuicError> {
        if self.packet_type() == 3 {
            return Err(QuicError::InvalidQuicType);
        }
        Ok(u32::from_be_bytes(self.pn))
    }

    #[inline]
    pub fn set_pn(&mut self, pn: u32) -> Result<(), QuicError> {
        if self.packet_type() == 3 {
            return Err(QuicError::InvalidQuicType);
        }
        self.pn = pn.to_be_bytes();
        Ok(())
    }
}

#[repr(C,packed)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuicShortHdr {
    pub dc_id_len: u8,
    pub first_byte: QuicFirstByteHdr,
    pub dc_id: [u8; QUIC_MAX_CID_LEN],
    pub pn: [u8; 4],
}

impl QuicShortHdr {
    pub const LEN: usize = mem::size_of::<QuicShortHdr>();

    pub fn new(
        dc_id_len: u8,
        first_byte: QuicFirstByteHdr,
    ) -> Self {
        Self {
            dc_id_len,
            first_byte,
            dc_id: [0; QUIC_MAX_CID_LEN],
            pn: [0; 4],
        }
    }

    #[inline]
    pub fn dc_id_len(&self) -> u8 {
        self.dc_id_len
    }

    #[inline]
    pub fn set_dc_id_len(&mut self, dc_id_len: u8) {
        self.dc_id_len = dc_id_len;
    }

    #[inline]
    pub fn dc_id(&self) -> [u8; QUIC_MAX_CID_LEN] {
        self.dc_id
    }

    #[inline]
    pub fn set_dc_id(&mut self, dc_id: [u8; QUIC_MAX_CID_LEN]) {
        self.dc_id = dc_id;
    }

    #[inline]
    pub fn pn(&self) -> u32 {
        u32::from_be_bytes(self.pn)
    }

    #[inline]
    pub fn set_pn(&mut self, pn: u32) {
        self.pn = pn.to_be_bytes();
    }

    #[inline]
    pub fn spin_bit(&self) -> bool {
        self.first_byte.short_spin_bit()
    }

    #[inline]
    pub fn set_spin_bit(&mut self, spin_bit: bool) {
        self.first_byte.set_short_spin_bit(spin_bit);
    }

    #[inline]
    pub fn key_phase(&self) -> bool {
        self.first_byte.short_key_phase()
    }

    #[inline]
    pub fn set_key_phase(&mut self, key_phase: bool) {
        self.first_byte.set_short_key_phase(key_phase);
    }

    #[inline]
    pub fn packet_number_length(&self) -> usize {
        self.first_byte.short_packet_number_length()
    }

    #[inline]
    pub fn set_packet_number_length(&mut self, len: usize) {
        self.first_byte.set_short_packet_number_length(len);
    }

}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuicFixedLongHdr {
    pub version: [u8; 4],
    pub dc_id_len: u8,
}

impl QuicFixedLongHdr {
    pub const LEN: usize = mem::size_of::<QuicFixedLongHdr>();

    pub fn new(version: u32, dc_id_len: u8) -> Self {
        Self {
            version: version.to_be_bytes(),
            dc_id_len,
        }
    }
    #[inline]
    pub fn version(&self) -> u32 {
        u32::from_be_bytes(self.version)
    }

    #[inline]
    pub fn set_version(&mut self, version: u32) {
        self.version = version.to_be_bytes();
    }

    #[inline]
    pub fn dc_id_len(&self) -> u8 {
        self.dc_id_len
    }

    #[inline]
    pub fn set_dc_id_len(&mut self, len: u8) {
        self.dc_id_len = len;
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuicFirstByteHdr {
    pub first_byte: u8,
}

impl QuicFirstByteHdr {
    pub const LEN: usize = mem::size_of::<QuicFirstByteHdr>();

    pub fn new(packet_type: u8, reserved_bits: u8, pn_len_bits: u8) -> Self {
        let first_byte = HEADER_FORM_BIT
            | FIXED_BIT_MASK
            | ((packet_type & 0b11) << LONG_PACKET_TYPE_SHIFT)
            | ((reserved_bits & 0b11) << RESERVED_BITS_LONG_SHIFT)
            | (pn_len_bits & PN_LENGTH_BITS_MASK);
        Self {
            first_byte,
        }
    }

    pub fn new_short_header_first_byte(spin_bit: bool, key_phase: bool, pn_len_bits: u8) -> u8 {
        let spin_val = if spin_bit { 1 } else { 0 };
        let key_phase_val = if key_phase { 1 } else { 0 };
        FIXED_BIT_MASK
            | (spin_val << SHORT_SPIN_BIT_SHIFT)
            | (key_phase_val << SHORT_KEY_PHASE_BIT_SHIFT)
            | (pn_len_bits & PN_LENGTH_BITS_MASK)
    }

    #[inline]
    pub fn first_byte(&self) -> u8 {
        self.first_byte
    }

    #[inline]
    pub fn set_first_byte(&mut self, first_byte: u8) {
        self.first_byte = first_byte;
    }

    #[inline]
    pub fn is_long_header(&self) -> bool {
        (self.first_byte & HEADER_FORM_BIT) == HEADER_FORM_BIT
    }

    #[inline]
    pub fn set_header_form(&mut self, is_long: bool) {
        if is_long {
            self.first_byte |= HEADER_FORM_BIT;
        } else {
            self.first_byte &= !HEADER_FORM_BIT;
        }
    }

    #[inline]
    pub fn fixed_bit(&self) -> u8 {
        (self.first_byte & FIXED_BIT_MASK) >> 6
    }

    #[inline]
    pub fn set_fixed_bit(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !FIXED_BIT_MASK) | ((val & 0x01) << 6);
    }

    #[inline]
    pub fn long_packet_type(&self) -> u8 {
        (self.first_byte & LONG_PACKET_TYPE_MASK) >> LONG_PACKET_TYPE_SHIFT
    }

    #[inline]
    pub fn set_long_packet_type(&mut self, lptype: u8) {
        self.first_byte = (self.first_byte & !LONG_PACKET_TYPE_MASK)
            | ((lptype << LONG_PACKET_TYPE_SHIFT) & LONG_PACKET_TYPE_MASK);
    }

    #[inline]
    pub fn reserved_bits_long(&self) -> u8 {
        (self.first_byte & RESERVED_BITS_LONG_MASK) >> RESERVED_BITS_LONG_SHIFT
    }

    #[inline]
    pub fn set_reserved_bits_long(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !RESERVED_BITS_LONG_MASK)
            | ((val << RESERVED_BITS_LONG_SHIFT) & RESERVED_BITS_LONG_MASK);
    }

    #[inline]
    pub fn pn_length_bits_long(&self) -> u8 {
        self.first_byte & PN_LENGTH_BITS_MASK
    }

    #[inline]
    pub fn set_pn_length_bits_long(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !PN_LENGTH_BITS_MASK) | (val & PN_LENGTH_BITS_MASK);
    }

    #[inline]
    pub fn packet_number_length_long(&self) -> usize {
        (self.pn_length_bits_long() + 1) as usize
    }

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

    #[inline]
    pub fn short_spin_bit(&self) -> bool {
        (self.first_byte & SHORT_SPIN_BIT_MASK) != 0
    }

    #[inline]
    pub fn set_short_spin_bit(&mut self, spin: bool) {
        if spin {
            self.first_byte |= SHORT_SPIN_BIT_MASK;
        } else {
            self.first_byte &= !SHORT_SPIN_BIT_MASK;
        }
    }

    #[inline]
    pub fn short_reserved_bits(&self) -> u8 {
        (self.first_byte & SHORT_RESERVED_BITS_MASK) >> SHORT_RESERVED_BITS_SHIFT
    }

    #[inline]
    pub fn set_short_reserved_bits(&mut self, _reserved: u8) {
        self.first_byte &= !SHORT_RESERVED_BITS_MASK;
    }

    #[inline]
    pub fn short_key_phase(&self) -> bool {
        (self.first_byte & SHORT_KEY_PHASE_BIT_MASK) != 0
    }

    #[inline]
    pub fn set_short_key_phase(&mut self, key_phase: bool) {
        if key_phase {
            self.first_byte |= SHORT_KEY_PHASE_BIT_MASK;
        } else {
            self.first_byte &= !SHORT_KEY_PHASE_BIT_MASK;
        }
    }

    #[inline]
    pub fn short_pn_length_bits(&self) -> u8 {
        self.first_byte & PN_LENGTH_BITS_MASK
    }

    #[inline]
    pub fn set_short_pn_length_bits(&mut self, val: u8) {
        self.first_byte = (self.first_byte & !PN_LENGTH_BITS_MASK) | (val & PN_LENGTH_BITS_MASK);
    }

    #[inline]
    pub fn short_packet_number_length(&self) -> usize {
        (self.short_pn_length_bits() + 1) as usize
    }

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

impl TryFrom<u8> for QuicFirstByteHdr {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if (value & FIXED_BIT_MASK) == 0 {
            return Err(value);
        }
        if (value & HEADER_FORM_BIT) != 0 {
            if (value & RESERVED_BITS_LONG_MASK) != 0 {
                return Err(value);
            }
        } else {
            if (value & SHORT_RESERVED_BITS_MASK) != 0 {
                return Err(value);
            }
        }
        Ok(QuicFirstByteHdr { first_byte: value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_long_hdr_accessors() {
        let first_byte = QuicFirstByteHdr::new(0, 0, 3);
        let fixed_hdr = QuicFixedLongHdr::new(1, 8);
        let mut hdr = QuicLongHdr::new(first_byte, fixed_hdr);
        assert!(hdr.set_token_len(10).is_ok());
        assert_eq!(hdr.token_len().unwrap(), 10);
        let mut hdr_invalid = hdr;
        hdr_invalid.first_byte.set_long_packet_type(1);
        assert!(hdr_invalid.set_token_len(10).is_err());
        assert!(hdr_invalid.token_len().is_err());
        assert_eq!(hdr.length().unwrap(), 0);
        let mut hdr_retry = hdr;
        hdr_retry.first_byte.set_long_packet_type(3);
        assert!(hdr_retry.length().is_err());
        assert!(hdr.set_pn(12345).is_ok());
        assert_eq!(hdr.pn().unwrap(), 12345);
        assert!(hdr_retry.set_pn(54321).is_err());
        assert!(hdr_retry.pn().is_err());
    }

    #[test]
    fn test_short_hdr_accessors() {
        let first_byte = QuicFirstByteHdr { first_byte: 0 };
        let mut hdr = QuicShortHdr::new(8, first_byte);
        hdr.set_dc_id_len(10);
        assert_eq!(hdr.dc_id_len(), 10);
        let dc_id = [1; QUIC_MAX_CID_LEN];
        hdr.set_dc_id(dc_id);
        assert_eq!(hdr.dc_id(), dc_id);
        hdr.set_pn(12345);
        assert_eq!(hdr.pn(), 12345);
        hdr.set_spin_bit(true);
        assert!(hdr.spin_bit());
        hdr.set_spin_bit(false);
        assert!(!hdr.spin_bit());
        hdr.set_key_phase(true);
        assert!(hdr.key_phase());
        hdr.set_key_phase(false);
        assert!(!hdr.key_phase());
        hdr.set_packet_number_length(4);
        assert_eq!(hdr.packet_number_length(), 4);
    }

    #[test]
    fn test_first_byte_new() {
        let packet_type = 0b01;
        let reserved_bits = 0b10;
        let pn_len_bits = 0b11;
        let hdr = QuicFirstByteHdr::new(packet_type, reserved_bits, pn_len_bits);
        assert_eq!(
            hdr.first_byte,
            HEADER_FORM_BIT
                | FIXED_BIT_MASK
                | (packet_type << LONG_PACKET_TYPE_SHIFT)
                | (reserved_bits << RESERVED_BITS_LONG_SHIFT)
                | pn_len_bits
        );
        assert!(hdr.is_long_header());
        assert_eq!(hdr.long_packet_type(), packet_type);
        assert_eq!(hdr.reserved_bits_long(), reserved_bits);
        assert_eq!(hdr.pn_length_bits_long(), pn_len_bits);
        assert_eq!(hdr.packet_number_length_long(), (pn_len_bits + 1) as usize);
    }

    #[test]
    fn test_first_byte_new_short_header() {
        let first_byte = QuicFirstByteHdr::new_short_header_first_byte(true, true, 0b11);
        let hdr = QuicFirstByteHdr { first_byte };
        assert!(!hdr.is_long_header());
        assert!(hdr.short_spin_bit());
        assert!(hdr.short_key_phase());
        assert_eq!(hdr.short_pn_length_bits(), 0b11);
        assert_eq!(hdr.short_packet_number_length(), 4);
    }

    #[test]
    fn test_first_byte_accessors() {
        let mut hdr = QuicFirstByteHdr::new(0, 0, 0);
        assert!(hdr.is_long_header());
        hdr.set_header_form(false);
        assert!(!hdr.is_long_header());
        hdr.set_header_form(true);
        assert!(hdr.is_long_header());
        hdr.set_first_byte(42);
        assert_eq!(hdr.first_byte(), 42);
    }

    #[test]
    fn test_first_byte_long_header_accessors() {
        let mut hdr = QuicFirstByteHdr::new(0, 0, 0);
        assert!(hdr.is_long_header());
        hdr.set_long_packet_type(0b11);
        assert_eq!(hdr.long_packet_type(), 0b11);
        hdr.set_reserved_bits_long(0b01);
        assert_eq!(hdr.reserved_bits_long(), 0b01);
        hdr.set_pn_length_bits_long(0b01);
        assert_eq!(hdr.pn_length_bits_long(), 0b01);
        assert_eq!(hdr.packet_number_length_long(), 2);
    }

    #[test]
    fn test_first_byte_short_header_accessors() {
        let mut hdr = QuicFirstByteHdr {
            first_byte: FIXED_BIT_MASK,
        };
        assert!(!hdr.is_long_header());
        hdr.set_short_spin_bit(true);
        assert!(hdr.short_spin_bit());
        hdr.set_short_spin_bit(false);
        assert!(!hdr.short_spin_bit());
        hdr.set_short_key_phase(true);
        assert!(hdr.short_key_phase());
        hdr.set_short_key_phase(false);
        assert!(!hdr.short_key_phase());
        hdr.set_short_pn_length_bits(0b01);
        assert_eq!(hdr.short_pn_length_bits(), 0b01);
        assert_eq!(hdr.short_packet_number_length(), 2);
    }

    #[test]
    fn test_fixed_long_hdr_accessors() {
        let mut hdr = QuicFixedLongHdr::new(0xaaaaaaaa, 8);
        assert_eq!(hdr.version(), 0xaaaaaaaa);
        assert_eq!(hdr.dc_id_len(), 8);
        hdr.set_version(0xbbbbbbbb);
        assert_eq!(hdr.version(), 0xbbbbbbbb);
        hdr.set_dc_id_len(4);
        assert_eq!(hdr.dc_id_len(), 4);
    }

    #[test]
    fn test_long_hdr_new() {
        let first_byte = QuicFirstByteHdr::new(0, 0, 0);
        let fixed_hdr = QuicFixedLongHdr::new(1, 8);
        let long_hdr = QuicLongHdr::new(first_byte, fixed_hdr);
        assert_eq!(long_hdr.first_byte, first_byte);
        assert_eq!(long_hdr.fixed_hdr, fixed_hdr);
        assert_eq!(long_hdr.dc_id, [0; QUIC_MAX_CID_LEN]);
        assert_eq!(long_hdr.sc_id_len, 0);
        assert_eq!(long_hdr.sc_id, [0; QUIC_MAX_CID_LEN]);
        assert_eq!(long_hdr.pn, [0; 4]);
    }

    #[test]
    fn test_short_hdr_new() {
        let first_byte = QuicFirstByteHdr {
            first_byte: QuicFirstByteHdr::new_short_header_first_byte(false, false, 0),
        };
        let dc_id_len = 8;
        let short_hdr = QuicShortHdr::new(dc_id_len, first_byte);
        assert_eq!(short_hdr.dc_id_len, dc_id_len);
        assert_eq!(short_hdr.first_byte, first_byte);
        assert_eq!(short_hdr.dc_id, [0; QUIC_MAX_CID_LEN]);
        assert_eq!(short_hdr.pn, [0; 4]);
    }

    struct MockCtx<'a> {
        buf: &'a [u8],
    }

    impl<'a> MockCtx<'a> {
        fn load<T: Sized + Copy>(&self, offset: usize) -> Result<T, ()> {
            if offset + mem::size_of::<T>() > self.buf.len() {
                return Err(());
            }
            let mut t = mem::MaybeUninit::<T>::uninit();
            unsafe {
                let ptr = self.buf.as_ptr().add(offset) as *const u8;
                core::ptr::copy_nonoverlapping(ptr, t.as_mut_ptr() as *mut u8, mem::size_of::<T>());
                Ok(t.assume_init())
            }
        }
    }

    #[test]
    fn test_parse_long_initial_header() {
        let buf = [
            0xc3, // Long Header, Type Initial, PN len 4
            0x00, 0x00, 0x00, 0x01, // Version 1
            0x08, // DCID Len
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // DCID
            0x08, // SCID Len
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // SCID
            0x00, // Token Length (0)
            0x0a, // Length (10)
            0x0a, 0x0b, 0x0c, 0x0d, // Packet Number
        ];
        let ctx = MockCtx { buf: &buf };
        let mut offset = 0;
        let hdr = parse_quic_hdr!(&ctx, offset, 8).unwrap();
        let mut expected: QuicLongHdr = unsafe { mem::zeroed() };
        expected.first_byte.first_byte = 0xc3;
        expected.fixed_hdr.version = [0x00, 0x00, 0x00, 0x01];
        expected.fixed_hdr.dc_id_len = 8;
        expected.dc_id[..8].copy_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        expected.sc_id_len = 8;
        expected.sc_id[..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        expected.token_len[0] = 0;
        expected.length[0] = 10;
        expected.pn.copy_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d]);
        if let QuicHdr::Long(long_hdr) = hdr {
            assert_eq!(long_hdr, expected);
        } else {
            panic!("Expected Long Header");
        }
    }

    #[test]
    fn test_parse_long_retry_header() {
        let buf = [
            0xf0, // Long Header, Type Retry, PN len 1 (unused)
            0x00, 0x00, 0x00, 0x01, // Version 1
            0x08, // DCID Len
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // DCID
            0x08, // SCID Len
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // SCID
            0xAA, // "Packet Number" but actually first byte of Retry Token
        ];
        let ctx = MockCtx { buf: &buf };
        let mut offset = 0;
        let hdr = parse_quic_hdr!(&ctx, offset, 8).unwrap();
        let mut expected: QuicLongHdr = unsafe { mem::zeroed() };
        expected.first_byte.first_byte = 0xf0;
        expected.fixed_hdr.version = [0x00, 0x00, 0x00, 0x01];
        expected.fixed_hdr.dc_id_len = 8;
        expected.dc_id[..8].copy_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        expected.sc_id_len = 8;
        expected.sc_id[..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        expected.pn[0] = 0xAA; // Parser reads first byte of token as PN
        if let QuicHdr::Long(long_hdr) = hdr {
            assert_eq!(long_hdr, expected);
        } else {
            panic!("Expected Long Header");
        }
    }

    #[test]
    fn test_parse_long_handshake_header() {
        let buf = [
            0xe2, // Long Header, Type Handshake, PN len 3
            0x00, 0x00, 0x00, 0x01, // Version 1
            0x08, // DCID Len
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // DCID
            0x08, // SCID Len
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // SCID
            0x0a, // Length (10)
            0x0a, 0x0b, 0x0c, // Packet Number
        ];
        let ctx = MockCtx { buf: &buf };
        let mut offset = 0;
        let hdr = parse_quic_hdr!(&ctx, offset, 8).unwrap();
        let mut expected: QuicLongHdr = unsafe { mem::zeroed() };
        expected.first_byte.first_byte = 0xe2;
        expected.fixed_hdr.version = [0x00, 0x00, 0x00, 0x01];
        expected.fixed_hdr.dc_id_len = 8;
        expected.dc_id[..8].copy_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        expected.sc_id_len = 8;
        expected.sc_id[..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        expected.length[0] = 10;
        expected.pn[..3].copy_from_slice(&[0x0a, 0x0b, 0x0c]);
        if let QuicHdr::Long(long_hdr) = hdr {
            assert_eq!(long_hdr, expected);
        } else {
            panic!("Expected Long Header");
        }
    }

    #[test]
    fn test_parse_long_rtt_header() {
        let buf = [
            0xd1, // Long Header, Type 0-RTT, PN len 2
            0x00, 0x00, 0x00, 0x01, // Version 1
            0x08, // DCID Len
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // DCID
            0x08, // SCID Len
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // SCID
            0x0a, // Length (10)
            0x0a, 0x0b, // Packet Number
        ];
        let ctx = MockCtx { buf: &buf };
        let mut offset = 0;
        let hdr = parse_quic_hdr!(&ctx, offset, 8).unwrap();
        let mut expected: QuicLongHdr = unsafe { mem::zeroed() };
        expected.first_byte.first_byte = 0xd1;
        expected.fixed_hdr.version = [0x00, 0x00, 0x00, 0x01];
        expected.fixed_hdr.dc_id_len = 8;
        expected.dc_id[..8].copy_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        expected.sc_id_len = 8;
        expected.sc_id[..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        expected.length[0] = 10;
        expected.pn[..2].copy_from_slice(&[0x0a, 0x0b]);
        if let QuicHdr::Long(long_hdr) = hdr {
            assert_eq!(long_hdr, expected);
        } else {
            panic!("Expected Long Header");
        }
    }

    #[test]
    fn test_parse_short_header() {
        let mut payload = [0u8; 16];
        let mut len = 0;
        payload[len] = 0b0100_0001; // Short Header, PN Len: 2
        len += 1;
        let dcid = [0xAA; 8];
        payload[len..len + dcid.len()].copy_from_slice(&dcid);
        len += dcid.len();
        let pn = [0x1, 0x2];
        payload[len..len + pn.len()].copy_from_slice(&pn);
        len += pn.len();
        let ctx = MockCtx { buf: &payload[..len] };
        let mut offset = 0;
        let hdr = parse_quic_hdr!(&ctx, offset, 8).unwrap();
        if let QuicHdr::Short(short_hdr) = hdr {
            assert_eq!(&short_hdr.dc_id[..dcid.len()], &dcid[..]);
            assert_eq!(&short_hdr.pn[..pn.len()], &pn[..]);
        } else {
            panic!("Expected Short Header");
        }
    }

    #[test]
    fn test_parse_header_too_short() {
        let payload = [0b1100_0000]; // Just a single byte
        let ctx = MockCtx { buf: &payload };
        let mut offset = 0;
        let result = parse_quic_hdr!(&ctx, offset, 8);
        assert!(result.is_err());
    }
}