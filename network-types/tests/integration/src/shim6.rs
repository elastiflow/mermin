use integration_common::{PacketType, ParsedHeader, Shim6TestData};
use network_types::{ip::IpProto, shim6::SHIM6_LEN};

// Helper for constructing Shim6 header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_shim6_test_packet() -> ([u8; SHIM6_LEN + 1], Shim6TestData) {
    let mut request_data = [0u8; SHIM6_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Shim6 as u8;

    // Bytes 1-8: Shim6 header (8 bytes)
    request_data[1..9].copy_from_slice(&[
        // Byte 1: Next Header (next_hdr field - extracted at offset 0 from data)
        IpProto::Tcp as u8,
        // Byte 2: Header Extension Length (hdr_ext_len field - extracted at offset 1 from data)
        1, // (1+1)*8 = 16 bytes total
        // Byte 3: P field & Type (not extracted)
        0,
        // Bytes 4-5: Checksum (not extracted)
        0,
        0,
        // Bytes 6-8: Type-specific data (not extracted)
        0,
        0,
        0,
    ]);

    let expected_header = Shim6TestData {
        next_hdr: IpProto::Tcp as u8,
        hdr_ext_len: 1,
    };

    (request_data, expected_header)
}

// Helper for verifying Shim6 header test results
pub fn verify_shim6_header(received: ParsedHeader, expected: Shim6TestData) {
    assert_eq!(received.type_, PacketType::Shim6);
    let parsed_header = unsafe { received.data.shim6 };

    assert_eq!(
        parsed_header.next_hdr, expected.next_hdr,
        "Next Header mismatch: got {}, expected {}",
        parsed_header.next_hdr, expected.next_hdr
    );

    assert_eq!(
        parsed_header.hdr_ext_len, expected.hdr_ext_len,
        "Header Extension Length mismatch: got {}, expected {}",
        parsed_header.hdr_ext_len, expected.hdr_ext_len
    );
}

// Helper for Shim6 with extension - same as basic since we only extract next_hdr
pub fn create_shim6_with_extension_test_packet() -> ([u8; SHIM6_LEN + 1], Shim6TestData) {
    create_shim6_test_packet()
}
