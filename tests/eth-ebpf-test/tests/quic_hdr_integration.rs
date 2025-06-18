//! User‑space checks for the `QuicHdr` type
//!
//! * Compile‑time layout (packed + size sanity)
//! * Basic round‑trip construction for the Long‑ and Short‑header variants
//!   using ONLY the public API.

use std::mem::{align_of, size_of};

use network_types::quic::{
    QuicHdr, QuicHdrError, QuicHdrLong, QuicHdrShort, QuicHeaderType, QuicPacketType,
    QUIC_MAX_CID_LEN,
};

/// The header structs must stay `#[repr(C, packed)]` so they can be dropped
/// into eBPF maps / helpers without unexpected padding.
#[test]
fn quichdr_layout_is_packed() {
    assert_eq!(
        align_of::<QuicHdr>(),
        1,
        "QuicHdr must be `#[repr(packed)]`"
    );
    assert_eq!(
        align_of::<QuicHdrLong>(),
        1,
        "QuicHdrLong must be `#[repr(packed)]`"
    );
    assert_eq!(
        align_of::<QuicHdrShort>(),
        1,
        "QuicHdrShort must be `#[repr(packed)]`"
    );

    // Calculated size: 1 (first_byte) + 46 (QuicHdrLong) = 47 bytes
    let expected_size = 1 + size_of::<QuicHdrLong>();
    assert_eq!(
        size_of::<QuicHdr>(),
        expected_size,
        "QuicHdr has unexpected size"
    );
}

/// Build a Long‑header packet buffer and parse it, then verify
/// that all observable fields match the expected values.
#[test]
fn long_header_roundtrip() {
    // --- Input values ------------------------------------------------------
    let version = 1u32;
    let dcid = [0xAA, 0xBB, 0xCC, 0xDD];
    let scid = [0x11, 0x22, 0x33, 0x44];

    // --- Build packet buffer to match struct memory layout ---
    let mut buf = Vec::new();

    // First byte: Long header (bit 7 = 1), Fixed bit (bit 6 = 1), Initial packet (bits 5-4 = 00)
    let first_byte = 0x80 | 0x40 | ((QuicPacketType::Initial as u8) << 4);
    buf.push(first_byte); // QuicHdr.first_byte

    // Version (4 bytes, big endian)
    buf.extend_from_slice(&version.to_be_bytes()); // QuicHdr.inner.long.version

    // QuicHdr.inner.long.dst (QuicDstConnLong)
    buf.push(dcid.len() as u8); // QuicDstConnLong.len
    buf.extend_from_slice(&dcid); // QuicDstConnLong.bytes (partial)
    buf.resize(buf.len() + (QUIC_MAX_CID_LEN - dcid.len()), 0); // Pad rest of .bytes array

    // QuicHdr.inner.long.src (QuicSrcConnLong)
    buf.push(scid.len() as u8); // QuicSrcConnLong.len
    buf.extend_from_slice(&scid); // QuicSrcConnLong.bytes (partial)
                                  // No need to pad the end of the buffer, as copy will handle it.

    // --- Parse the header --------------------------------------------------
    // Simulate loading bytes into the struct, then parsing.
    let mut hdr_storage = QuicHdr::default();
    let copy_len = std::cmp::min(buf.len(), size_of::<QuicHdr>());
    unsafe {
        std::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            &mut hdr_storage as *mut _ as *mut u8,
            copy_len,
        );
    }
    let hdr = hdr_storage.parse(0).expect("Failed to parse long header");

    // --- Assertions --------------------------------------------------------
    // General
    assert!(hdr.is_long_header(), "header form mismatch");
    assert_eq!(hdr.first_byte(), first_byte, "first‑byte flags differ");

    // Version
    assert_eq!(hdr.version().unwrap(), version, "version incorrect");

    // DCID + length
    assert_eq!(
        hdr.dc_id_len_on_wire().unwrap(),
        dcid.len() as u8,
        "DCID len on wire"
    );
    assert_eq!(hdr.dc_id(), &dcid[..], "DCID bytes do not match input");

    // SCID + length
    assert_eq!(
        hdr.sc_id_len_on_wire().unwrap(),
        scid.len() as u8,
        "SCID len on wire"
    );
    assert_eq!(
        hdr.sc_id().unwrap(),
        &scid[..],
        "SCID bytes do not match input"
    );

    // Packet type
    assert_eq!(
        hdr.long_packet_type().unwrap(),
        QuicPacketType::Initial,
        "packet type mismatch"
    );
}

/// Build a Short‑header packet buffer and parse it, then verify
/// that all observable fields match the expected values.
#[test]
fn short_header_roundtrip() {
    // --- Input values ------------------------------------------------------
    const DCID: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let dcid_len = DCID.len() as u8;
    let key_phase = true;

    // --- Build packet buffer to match struct memory layout ---
    let mut buf = Vec::new();

    // First byte: Short header (bit 7 = 0), Fixed bit (bit 6 = 1), Key phase (bit 2 = 1)
    let first_byte = 0x40 | if key_phase { 0x04 } else { 0x00 };
    buf.push(first_byte); // QuicHdr.first_byte

    // The QuicDstConnShort struct has a `len` field that is not on the wire.
    // We must account for it in the buffer we construct for the memory copy.
    buf.push(dcid_len);

    // DCID
    buf.extend_from_slice(&DCID);

    // --- Parse the header --------------------------------------------------
    let mut hdr_storage = QuicHdr::default();
    let copy_len = std::cmp::min(buf.len(), size_of::<QuicHdr>());
    unsafe {
        std::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            &mut hdr_storage as *mut _ as *mut u8,
            copy_len,
        );
    }
    let hdr = hdr_storage
        .parse(dcid_len)
        .expect("Failed to parse short header");

    // --- Assertions --------------------------------------------------------
    // General
    assert!(!hdr.is_long_header(), "header form mismatch");
    assert_eq!(hdr.first_byte(), first_byte, "first‑byte flags differ");

    // DCID
    assert_eq!(hdr.dc_id(), &DCID[..], "DCID bytes do not match input");

    // Key‑phase bit
    assert_eq!(
        hdr.short_key_phase().unwrap(),
        key_phase,
        "key‑phase bit incorrect"
    );
}

/// Test that parsing handles invalid inputs correctly
#[test]
fn parse_error_handling() {
    // Case 1: Long header with an invalid on-wire DCID length.
    // Simulate a malformed packet being loaded into the struct.
    let malformed_packet_bytes: &[u8] = &[
        0xC0, // First Byte: Long Header
        0x00,
        0x00,
        0x00,
        0x01,                         // Version
        (QUIC_MAX_CID_LEN + 1) as u8, // Invalid DCID Length
        0x00,                         // SCID Length (0)
    ];
    let mut long_hdr_storage = QuicHdr::default();
    let copy_len = std::cmp::min(malformed_packet_bytes.len(), size_of::<QuicHdr>());
    unsafe {
        std::ptr::copy_nonoverlapping(
            malformed_packet_bytes.as_ptr(),
            &mut long_hdr_storage as *mut _ as *mut u8,
            copy_len,
        );
    }
    // Assert that parsing this invalid state fails as expected.
    assert_eq!(
        long_hdr_storage.parse(0).unwrap_err(),
        QuicHdrError::InvalidLength
    );

    // Case 2: Short header where the contextual DCID length is invalid.
    let mut short_hdr_storage = QuicHdr::new(QuicHeaderType::QuicShort { dc_id_len: 0 });
    assert_eq!(
        short_hdr_storage
            .parse((QUIC_MAX_CID_LEN + 1) as u8)
            .unwrap_err(),
        QuicHdrError::InvalidLength
    );
}

/// Test minimum header lengths
#[test]
fn minimum_header_lengths() {
    assert_eq!(QuicHdr::MIN_LONG_HDR_LEN_ON_WIRE, 7); // 1 + 4 + 1 + 1
    assert_eq!(QuicHdr::MIN_SHORT_HDR_LEN_ON_WIRE, 1); // 1
}
