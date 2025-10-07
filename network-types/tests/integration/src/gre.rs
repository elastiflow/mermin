use integration_common::{GreTestData, PacketType, ParsedHeader};
use network_types::gre::GRE_LEN;

// Helper for constructing GRE header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_gre_test_packet() -> ([u8; GRE_LEN + 1], GreTestData) {
    let mut request_data = [0u8; GRE_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Gre as u8;

    // Bytes 1-5: GRE header (4 bytes)
    request_data[1..5].copy_from_slice(&[
        // Byte 1: Flags/Reserved/Version (flag_res field - extracted at offset 0 from data)
        0x00, 0x00, // No flags set, version 0
        // Bytes 3-4: Protocol Type (ether_type field - extracted at offset 2 from data)
        0x08, 0x00, // IPv4 (0x0800)
    ]);

    let expected_header = GreTestData {
        flag_res: [0x00, 0x00],   // No flags, version 0
        ether_type: [0x08, 0x00], // IPv4
    };

    (request_data, expected_header)
}

// Helper for verifying GRE header test results
pub fn verify_gre_header(received: ParsedHeader, expected: GreTestData) {
    assert_eq!(received.type_, PacketType::Gre);
    let parsed_header = unsafe { received.data.gre };

    assert_eq!(
        parsed_header.flag_res,
        expected.flag_res,
        "Flags/Reserved/Version mismatch: got [{:#x}, {:#x}], expected [{:#x}, {:#x}]",
        parsed_header.flag_res[0],
        parsed_header.flag_res[1],
        expected.flag_res[0],
        expected.flag_res[1]
    );

    assert_eq!(
        parsed_header.ether_type,
        expected.ether_type,
        "EtherType mismatch: got [{:#x}, {:#x}], expected [{:#x}, {:#x}]",
        parsed_header.ether_type[0],
        parsed_header.ether_type[1],
        expected.ether_type[0],
        expected.ether_type[1]
    );
}
