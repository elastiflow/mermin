use integration_common::{GeneveTestData, PacketType, ParsedHeader};
use network_types::geneve::GENEVE_LEN;

// Helper for constructing Geneve header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_geneve_test_packet() -> ([u8; GENEVE_LEN + 1], GeneveTestData) {
    let mut request_data = [0u8; GENEVE_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Geneve as u8;

    // Bytes 1-8: Geneve header (8 bytes)
    request_data[1..9].copy_from_slice(&[
        // Byte 1: Version + Option Length (ver_opt_len field - extracted at offset 0 from data)
        0b00000010, // Version 0, Option Length 2
        // Byte 2: OAM/Critical/Reserved (not extracted)
        0b10000000, // OAM flag set, Critical flag clear
        // Bytes 3-4: Protocol Type (tunnel_ether_type field - extracted at offset 2 from data)
        0x08, 0x00, // IPv4 (0x0800)
        // Bytes 5-7: VNI (vni field - extracted at offset 4 from data)
        0x12, 0x34, 0x56, // VNI: 0x123456
        // Byte 8: Reserved (not extracted)
        0x00,
    ]);

    let expected_header = GeneveTestData {
        ver_opt_len: 0b00000010,
        tunnel_ether_type: [0x08, 0x00],
        vni: [0x12, 0x34, 0x56],
    };

    (request_data, expected_header)
}

// Helper for verifying Geneve header test results
pub fn verify_geneve_header(received: ParsedHeader, expected: GeneveTestData) {
    assert_eq!(received.type_, PacketType::Geneve);
    let parsed_header = unsafe { received.data.geneve };

    assert_eq!(
        parsed_header.ver_opt_len, expected.ver_opt_len,
        "Version + Option Length mismatch: got {:#x}, expected {:#x}",
        parsed_header.ver_opt_len, expected.ver_opt_len
    );

    assert_eq!(
        parsed_header.tunnel_ether_type,
        expected.tunnel_ether_type,
        "Tunnel EtherType mismatch: got [{:#x}, {:#x}], expected [{:#x}, {:#x}]",
        parsed_header.tunnel_ether_type[0],
        parsed_header.tunnel_ether_type[1],
        expected.tunnel_ether_type[0],
        expected.tunnel_ether_type[1]
    );

    assert_eq!(
        parsed_header.vni,
        expected.vni,
        "VNI mismatch: got [{:#x}, {:#x}, {:#x}], expected [{:#x}, {:#x}, {:#x}]",
        parsed_header.vni[0],
        parsed_header.vni[1],
        parsed_header.vni[2],
        expected.vni[0],
        expected.vni[1],
        expected.vni[2]
    );
}
