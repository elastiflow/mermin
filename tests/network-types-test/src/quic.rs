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

#[macro_export]
macro_rules! parse_quic_hdr {
    ($ctx:expr, $off:ident, $short_dc_id_len:expr) => {
        (|| -> Result<$crate::quic::QuicHdr, ()> {
            use $crate::read_var_buf_32;
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
                        quic_long_hdr.fixed_hdr.dc_id_len,
                        quic::QUIC_MAX_CID_LEN
                    )
                    .map_err(|_| ())?;
                    quic_long_hdr.sc_id_len = $ctx.load($off).map_err(|_| ())?;
                    $off += 1;
                    read_var_buf_32!(
                        $ctx,
                        $off,
                        quic_long_hdr.sc_id,
                        quic_long_hdr.sc_id_len,
                        quic::QUIC_MAX_CID_LEN
                    )
                    .map_err(|_| ())?;
                    read_var_buf_32!(
                        $ctx,
                        $off,
                        quic_long_hdr.pn,
                        quic_long_hdr.first_byte.packet_number_length_long() as u8,
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
                        quic_short_hdr.dc_id_len,
                        quic::QUIC_MAX_CID_LEN
                    )
                    .map_err(|_| ())?;
                    read_var_buf_32!(
                        $ctx,
                        $off,
                        quic_short_hdr.pn,
                        quic_short_hdr.first_byte.short_packet_number_length() as u8,
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
            pn: [0; 4],
        }
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
            // Long Header
            if (value & RESERVED_BITS_LONG_MASK) != 0 {
                return Err(value);
            }
        } else {
            // Short Header
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
            let ptr = self.buf.as_ptr();
            Ok(unsafe { core::ptr::read_unaligned(ptr.add(offset) as *const T) })
        }
    }

    #[test]
    fn test_parse_long_header() {
        let first_byte = QuicFirstByteHdr::new(0b01, 0, 0b11); // type 1, pn_len=4
        let version = 0x01020304u32;
        let dc_id_len = 8;
        let sc_id_len = 4;
        let dc_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let sc_id = [9, 10, 11, 12];
        let pn = [0xAA, 0xBB, 0xCC, 0xDD];

        let mut buf = [0u8; 1 + 4 + 1 + 8 + 1 + 4 + 4];
        let mut current_offset = 0;
        buf[current_offset] = first_byte.first_byte;
        current_offset += 1;
        buf[current_offset..current_offset + 4].copy_from_slice(&version.to_be_bytes());
        current_offset += 4;
        buf[current_offset] = dc_id_len;
        current_offset += 1;
        buf[current_offset..current_offset + dc_id_len as usize].copy_from_slice(&dc_id);
        current_offset += dc_id_len as usize;
        buf[current_offset] = sc_id_len;
        current_offset += 1;
        buf[current_offset..current_offset + sc_id_len as usize].copy_from_slice(&sc_id);
        current_offset += sc_id_len as usize;
        buf[current_offset..current_offset + 4].copy_from_slice(&pn);

        let ctx = MockCtx { buf: &buf };
        let mut off = 0;

        let hdr = parse_quic_hdr!(&ctx, off, QUIC_SHORT_DEFAULT_DC_ID_LEN).unwrap();
        if let QuicHdr::Long(long_hdr) = hdr {
            assert_eq!(long_hdr.first_byte, first_byte);
            assert_eq!(long_hdr.fixed_hdr.version(), version);
            assert_eq!(long_hdr.fixed_hdr.dc_id_len(), dc_id_len);
            assert_eq!(&long_hdr.dc_id[..dc_id_len as usize], &dc_id);
            assert_eq!(long_hdr.sc_id_len, sc_id_len);
            assert_eq!(&long_hdr.sc_id[..sc_id_len as usize], &sc_id);
            assert_eq!(long_hdr.pn, pn);
        } else {
            panic!("Expected Long Header");
        }
    }

    #[test]
    fn test_parse_short_header() {
        let first_byte_val = QuicFirstByteHdr::new_short_header_first_byte(true, true, 0b01); // spin, key_phase, pn_len=2
        let first_byte = QuicFirstByteHdr {
            first_byte: first_byte_val,
        };
        let dc_id_len = QUIC_SHORT_DEFAULT_DC_ID_LEN;
        let dc_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let pn = [0xAA, 0xBB];

        let mut buf = [0u8; 1 + 8 + 2];
        buf[0] = first_byte.first_byte;
        buf[1..1 + dc_id_len as usize].copy_from_slice(&dc_id);
        buf[1 + dc_id_len as usize..].copy_from_slice(&pn);

        let ctx = MockCtx { buf: &buf };
        let mut off = 0;

        let hdr = parse_quic_hdr!(&ctx, off, dc_id_len).unwrap();
        if let QuicHdr::Short(short_hdr) = hdr {
            assert_eq!(short_hdr.first_byte, first_byte);
            assert_eq!(short_hdr.dc_id_len, dc_id_len);
            assert_eq!(&short_hdr.dc_id[..dc_id_len as usize], &dc_id);
            assert_eq!(&short_hdr.pn[..2], &pn);
        } else {
            panic!("Expected Short Header");
        }
    }

    #[test]
    fn test_parse_header_too_short() {
        let ctx = MockCtx { buf: &[] };
        let mut off = 0;
        assert!(parse_quic_hdr!(&ctx, off, QUIC_SHORT_DEFAULT_DC_ID_LEN).is_err());

        let ctx = MockCtx { buf: &[0xc3] };
        let mut off = 0;
        assert!(parse_quic_hdr!(&ctx, off, QUIC_SHORT_DEFAULT_DC_ID_LEN).is_err());

        let buf = {
            let mut arr = [0u8; 1 + 4 + 1 + 7];
            arr[0] = 0xc3; // Long header, pn_len=4
            arr[1..5].copy_from_slice(&0x01020304u32.to_be_bytes());
            arr[5] = 8; // dc_id_len = 8
            arr[6..].copy_from_slice(&[1; 7]); // but only 7 bytes for dc_id
            arr
        };
        let ctx = MockCtx { buf: &buf };
        let mut off = 0;
        assert!(parse_quic_hdr!(&ctx, off, QUIC_SHORT_DEFAULT_DC_ID_LEN).is_err());

        let buf = {
            let mut arr = [0u8; 1 + 7];
            arr[0] = QuicFirstByteHdr::new_short_header_first_byte(false, false, 0); // pn_len=1
            arr[1..].copy_from_slice(&[1; 7]); // dc_id_len=8, but only 7 bytes
            arr
        };
        let ctx = MockCtx { buf: &buf };
        let mut off = 0;
        assert!(parse_quic_hdr!(&ctx, off, 8).is_err());
    }
}