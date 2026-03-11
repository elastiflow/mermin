//! Fragment Extension Header Format
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Identification                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use crate::ip::IpProto;

/// The length of the Fragment header base structure.
pub const FRAGMENT_LEN: usize = 8;

/// The Next Header field (8 bits)
pub type NextHdr = IpProto;
/// The Reserved field (8 bits)
pub type Reserved = u8;
/// The Fragment Offset field (13 bits)
pub type FragOffset = u8;
/// This is a combined field containing:
/// - 5-bit end of fragment offset field
/// - 2-bit reserved field
/// - 1-bit M flag
pub type FoResM = u8;
/// The Identification field (32 bits)
pub type Id = [u8; 4];

// --- Constants for bit manipulation within fo_res_m ---
// FFFFFRM (F = fragment offset high bits, R = reserved, M = more fragments flag)
const FRAG_OFFSET_UPPER_MASK_IN_BYTE: u8 = 0b11111000;
const FRAG_OFFSET_UPPER_SHIFT: u8 = 3;
const FRAG_OFFSET_UPPER_VALUE_MASK: u16 = 0x001F;

const RESERVED2_MASK_IN_BYTE: u8 = 0b00000110;
const RESERVED2_SHIFT: u8 = 1;

const M_FLAG_MASK_IN_BYTE: u8 = 0b00000001;

/// Gets the 13-bit Fragment Offset value.
#[inline]
pub fn fragment_offset(frag_offset: FragOffset, fo_res_m: FoResM) -> u16 {
    // First 8 bits from frag_offset
    let lower_bits = (frag_offset as u16) << 5;
    // Upper 5 bits from fo_res_m
    let upper_bits = (((fo_res_m & FRAG_OFFSET_UPPER_MASK_IN_BYTE) >> FRAG_OFFSET_UPPER_SHIFT)
        as u16)
        & FRAG_OFFSET_UPPER_VALUE_MASK;
    lower_bits | upper_bits
}

/// Gets the 2-bit Reserved2 value.
#[inline]
pub fn reserved2(fo_res_m: FoResM) -> u8 {
    (fo_res_m & RESERVED2_MASK_IN_BYTE) >> RESERVED2_SHIFT
}

/// Gets the M Flag (More Fragments) value.
#[inline]
pub fn m_flag(fo_res_m: FoResM) -> bool {
    (fo_res_m & M_FLAG_MASK_IN_BYTE) != 0
}

/// Gets the 32-bit Identification value.
#[inline]
pub fn identification(id: Id) -> u32 {
    let b0 = (id[0] as u32) << 24;
    let b1 = (id[1] as u32) << 16;
    let b2 = (id[2] as u32) << 8;
    let b3 = id[3] as u32;
    b0 | b1 | b2 | b3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_offset() {
        // Test with lower 8 bits in frag_offset and upper 5 bits in fo_res_m
        // frag_offset = 0xFF (all 8 bits set), fo_res_m = 0xF8 (upper 5 bits set)
        let result = fragment_offset(0xFF, 0xF8);
        assert_eq!(result, 0x1FFF); // Max 13-bit value

        // Test with specific values
        let result = fragment_offset(0x34, 0x12); // 0x34 << 5 | (0x12 & 0xF8) >> 3
        let expected = (0x34 << 5) | (((0x12 & 0xF8) >> 3) as u16);
        assert_eq!(result, expected);

        // Test with zero values
        let result = fragment_offset(0x00, 0x00);
        assert_eq!(result, 0x0000);

        // Test with just lower bits set
        let result = fragment_offset(0x80, 0x00);
        assert_eq!(result, 0x1000); // 0x80 << 5
    }

    #[test]
    fn test_reserved2() {
        // Test extracting 2-bit reserved field from fo_res_m
        let result = reserved2(0x06); // bits 1-2 set (0b00000110)
        assert_eq!(result, 3); // (0x06 & 0x06) >> 1 = 3

        let result = reserved2(0x04); // bit 2 set (0b00000100)
        assert_eq!(result, 2); // (0x04 & 0x06) >> 1 = 2

        let result = reserved2(0x02); // bit 1 set (0b00000010)
        assert_eq!(result, 1); // (0x02 & 0x06) >> 1 = 1

        let result = reserved2(0x00); // no bits set
        assert_eq!(result, 0); // (0x00 & 0x06) >> 1 = 0

        // Test with higher bits set (should be masked out)
        let result = reserved2(0xFF); // all bits set
        assert_eq!(result, 3); // (0xFF & 0x06) >> 1 = 3
    }

    #[test]
    fn test_m_flag() {
        // Test M flag (bit 0) extraction from fo_res_m
        let result = m_flag(0x01); // bit 0 set
        assert_eq!(result, true);

        let result = m_flag(0x00); // bit 0 not set
        assert_eq!(result, false);

        // Test with other bits set
        let result = m_flag(0x03); // bits 0 and 1 set
        assert_eq!(result, true);

        let result = m_flag(0x02); // bit 1 set, bit 0 not set
        assert_eq!(result, false);

        // Test with higher bits set
        let result = m_flag(0xFF); // all bits set
        assert_eq!(result, true);
    }

    #[test]
    fn test_identification() {
        // Test 32-bit identification value from byte array
        let id: Id = [0xFF, 0xFF, 0xFF, 0xFF];
        let result = identification(id);
        assert_eq!(result, 0xFFFFFFFF);

        let id: Id = [0x12, 0x34, 0x56, 0x78];
        let result = identification(id);
        assert_eq!(result, 0x12345678);

        let id: Id = [0x00, 0x00, 0x00, 0x00];
        let result = identification(id);
        assert_eq!(result, 0x00000000);

        let id: Id = [0x80, 0x00, 0x00, 0x00];
        let result = identification(id);
        assert_eq!(result, 0x80000000);

        let id: Id = [0x00, 0x00, 0x00, 0x01];
        let result = identification(id);
        assert_eq!(result, 0x00000001);
    }

    #[test]
    fn test_combined_fo_res_m_extraction() {
        // Test that we can extract multiple fields from the same fo_res_m byte
        // fo_res_m = 0xFA = 0b11111010
        // - Fragment offset upper bits: (0xFA & 0xF8) >> 3 = 0x1F
        // - Reserved2: (0xFA & 0x06) >> 1 = 0x01
        // - M flag: (0xFA & 0x01) != 0 = true

        let fo_res_m: FoResM = 0xFA;

        // Test fragment offset with this fo_res_m
        let frag_offset_result = fragment_offset(0xFF, fo_res_m);
        let expected_offset = (0xFF << 5) | (((fo_res_m & 0xF8) >> 3) as u16);
        assert_eq!(frag_offset_result, expected_offset);

        // Test reserved2 extraction
        let reserved2_result = reserved2(fo_res_m);
        assert_eq!(reserved2_result, 1);

        // Test M flag extraction
        let m_flag_result = m_flag(fo_res_m);
        assert_eq!(m_flag_result, false); // bit 0 is 0 in 0xFA

        // Test with M flag set
        let fo_res_m_with_m: FoResM = 0xFB; // 0b11111011
        let m_flag_result = m_flag(fo_res_m_with_m);
        assert_eq!(m_flag_result, true); // bit 0 is 1 in 0xFB
    }
}
