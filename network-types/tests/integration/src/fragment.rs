use integration_common::{FragmentTestData, PacketType, ParsedHeader};
use network_types::{fragment::FRAGMENT_LEN, ip::IpProto};

// Helper for constructing Fragment header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_fragment_test_packet() -> ([u8; FRAGMENT_LEN + 1], FragmentTestData) {
    let mut request_data = [0u8; FRAGMENT_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Fragment as u8;

    // Bytes 1-8: Fragment header (8 bytes)
    request_data[1..9].copy_from_slice(&[
        // Byte 1: Next Header (next_hdr field - extracted at offset 0 from data)
        IpProto::Tcp as u8,
        // Byte 2: Reserved (not extracted)
        0x00,
        // Bytes 3-4: Fragment Offset & Flags (not extracted)
        0x12,
        0x34,
        // Bytes 5-8: Identification (not extracted)
        0x56,
        0x78,
        0x9A,
        0xBC,
    ]);

    let expected_header = FragmentTestData {
        next_hdr: IpProto::Tcp as u8,
    };

    (request_data, expected_header)
}

// Helper for verifying Fragment header test results
pub fn verify_fragment_header(received: ParsedHeader, expected: FragmentTestData) {
    assert_eq!(received.type_, PacketType::Fragment);
    let parsed_header = unsafe { received.data.fragment };

    assert_eq!(
        parsed_header.next_hdr, expected.next_hdr,
        "Next Header mismatch: got {}, expected {}",
        parsed_header.next_hdr, expected.next_hdr
    );
}
