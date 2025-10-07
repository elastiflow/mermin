use integration_common::{MobilityTestData, PacketType, ParsedHeader};
use network_types::{ip::IpProto, mobility::MOBILITY_LEN};

// Helper for constructing Mobility header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_mobility_test_packet() -> ([u8; MOBILITY_LEN + 1], MobilityTestData) {
    let mut request_data = [0u8; MOBILITY_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Mobility as u8;

    // Bytes 1-8: Mobility header (8 bytes)
    request_data[1..9].copy_from_slice(&[
        // Byte 1: Next Header (next_hdr field - extracted at offset 0 from data)
        IpProto::Tcp as u8,
        // Byte 2: Header Extension Length (hdr_ext_len field - extracted at offset 1 from data)
        1,
        // Byte 3: MH Type (not extracted)
        0,
        // Byte 4: Reserved (not extracted)
        0,
        // Bytes 5-6: Checksum (not extracted)
        0,
        0,
        // Bytes 7-8: Reserved Message Data (not extracted)
        0,
        0,
    ]);

    let expected_header = MobilityTestData {
        next_hdr: IpProto::Tcp as u8,
        hdr_ext_len: 1,
    };

    (request_data, expected_header)
}

// Helper for verifying Mobility header test results
pub fn verify_mobility_header(received: ParsedHeader, expected: MobilityTestData) {
    assert_eq!(received.type_, PacketType::Mobility);
    let parsed_header = unsafe { received.data.mobility };

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
